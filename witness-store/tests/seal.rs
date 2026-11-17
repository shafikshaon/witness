#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use witness_store::anchor::{read_anchors, AnchorSink, CommandSink, FileSink};
use witness_store::chain::{self, Hash, GENESIS};
use witness_store::disk::DiskPolicy;
use witness_store::seal::SealState;
use witness_store::segment;
use witness_store::verify::{verify_with, BreakKind, Options};
use witness_store::{Config, Store};

fn rec(i: u64) -> Map<String, Value> {
    json!({"type": "test", "n": i}).as_object().unwrap().clone()
}

struct Env {
    _t: tempfile::TempDir,
    root: PathBuf,
    seg_dir: PathBuf,
    key_path: PathBuf,
    k0: Hash,
}

/// One big segment so attacker rewrites stay single-file.
fn env() -> Env {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    let key_path = root.join("seal.key");
    fs::create_dir_all(&root).unwrap();
    let k0 = SealState::init(&key_path).unwrap();
    Env {
        seg_dir: root.join("segments"),
        root,
        key_path,
        k0,
        _t: t,
    }
}

fn open(e: &Env) -> Store {
    let (mut s, _) = Store::open(
        &e.root,
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    s.enable_sealing(&e.key_path).unwrap();
    s
}

/// 4 epochs of: 5 records then a seal.
fn populate(e: &Env, sinks: &mut [Box<dyn AnchorSink>]) {
    let mut s = open(e);
    for epoch in 0..4 {
        for i in 0..5 {
            s.append(rec(epoch * 10 + i)).unwrap();
        }
        s.seal_now().unwrap().unwrap();
        s.anchor_now(sinks).unwrap();
    }
    s.sync().unwrap();
}

fn keyed(e: &Env) -> Options {
    Options {
        seal_key: Some(e.k0),
        ..Default::default()
    }
}

fn only_segment(e: &Env) -> PathBuf {
    let mut v = segment::list_segments(&e.seg_dir).unwrap();
    assert_eq!(v.len(), 1);
    v.remove(0).path
}

/// What a root attacker can do: edit lines, then recompute every hash after the edit.
/// Seal MACs inside the records are left as they were (the attacker lacks the old keys).
fn rewrite(path: &Path, mut edit: impl FnMut(usize, String) -> Option<String>) {
    let text = fs::read_to_string(path).unwrap();
    let mut prev = GENESIS;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let (body, _) = chain::decode_line(line.as_bytes()).unwrap();
        let Some(body) = edit(i, String::from_utf8(body).unwrap()) else {
            continue; // line dropped
        };
        let (l, h) = chain::encode_line(&prev, body.as_bytes()).unwrap();
        prev = h;
        out.push(String::from_utf8(l).unwrap());
    }
    fs::write(path, out.join("\n") + "\n").unwrap();
}

#[test]
fn sealed_store_verifies_with_and_without_key() {
    let e = env();
    populate(&e, &mut []);
    let plain = verify_with(&e.seg_dir, &Options::default()).unwrap();
    assert!(plain.is_ok());
    assert_eq!(plain.seals, 4);
    assert!(!plain.macs_checked);

    let r = verify_with(&e.seg_dir, &keyed(&e)).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    assert!(r.macs_checked);
    assert_eq!(r.last_seal_epoch, Some(4));
    // 5 records after segment_open per epoch, plus earlier seals/anchors.
    assert!(r.sealed_through_seq.unwrap() < r.head_seq);
}

#[test]
fn key_file_never_holds_k0() {
    let e = env();
    let on_disk: Value = serde_json::from_slice(&fs::read(&e.key_path).unwrap()).unwrap();
    assert_eq!(on_disk["epoch"], 1);
    assert_ne!(on_disk["key"], chain::to_hex(&e.k0));
    assert!(SealState::init(&e.key_path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&e.key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn history_rewrite_with_recomputed_hashes_is_caught_by_the_mac() {
    let e = env();
    populate(&e, &mut []);
    let seg = only_segment(&e);
    // Attacker edits a record sealed by epoch 1 and recomputes the whole chain.
    rewrite(&seg, |_, b| Some(b.replacen("\"n\":2,", "\"n\":99,", 1)));
    let text = fs::read_to_string(&seg).unwrap();
    assert!(text.contains("\"n\":99"));

    // The bare chain is consistent again: this is exactly the weakness sealing addresses.
    assert!(verify_with(&e.seg_dir, &Options::default())
        .unwrap()
        .is_ok());

    // With K_0 the stale seal MAC no longer matches the rewritten head.
    let b = verify_with(&e.seg_dir, &keyed(&e)).unwrap().broken.unwrap();
    assert_eq!(b.kind, BreakKind::BadSealMac { epoch: 1 });
}

#[test]
fn removing_a_seal_is_an_epoch_gap_even_without_the_key() {
    let e = env();
    populate(&e, &mut []);
    let seg = only_segment(&e);
    // A careful attacker drops the 2nd seal and renumbers seq/covers_seq so the chain,
    // sequence numbers and seal structure are all self-consistent.
    let (mut seals, mut shift) = (0, 0u64);
    rewrite(&seg, |_, b| {
        let mut v: Value = serde_json::from_str(&b).unwrap();
        if v["type"] == "seal" {
            seals += 1;
            if seals == 2 {
                shift += 1;
                return None;
            }
        }
        let seq = v["seq"].as_u64().unwrap();
        v["seq"] = json!(seq - shift);
        if v["type"] == "seal" {
            let c = v["covers_seq"].as_u64().unwrap();
            v["covers_seq"] = json!(c - shift);
        }
        Some(serde_json::to_string(&v).unwrap())
    });
    let b = verify_with(&e.seg_dir, &Options::default())
        .unwrap()
        .broken
        .unwrap();
    assert_eq!(
        b.kind,
        BreakKind::SealEpochGap {
            expected: 2,
            found: 3
        }
    );
}

#[test]
fn tail_truncation_needs_anchors() {
    let e = env();
    let anchors = e.root.join("anchors.log");
    populate(&e, &mut [Box::new(FileSink::new(&anchors))]);
    let seg = only_segment(&e);
    let text = fs::read_to_string(&seg).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // Cut the last 3 lines cleanly.
    fs::write(&seg, lines[..lines.len() - 3].join("\n") + "\n").unwrap();

    // Without anchors a clean tail cut is undetectable. Documented limit.
    assert!(verify_with(&e.seg_dir, &Options::default())
        .unwrap()
        .is_ok());

    let opts = Options {
        anchors: read_anchors(&anchors).unwrap(),
        ..Default::default()
    };
    let b = verify_with(&e.seg_dir, &opts).unwrap().broken.unwrap();
    assert!(
        matches!(b.kind, BreakKind::AnchorBeyondHead { .. }),
        "{:?}",
        b.kind
    );
}

#[test]
fn anchors_catch_a_consistent_rewrite() {
    let e = env();
    let anchors = e.root.join("anchors.log");
    populate(&e, &mut [Box::new(FileSink::new(&anchors))]);
    let seg = only_segment(&e);
    rewrite(&seg, |_, b| Some(b.replacen("\"n\":2,", "\"n\":99,", 1)));
    let opts = Options {
        anchors: read_anchors(&anchors).unwrap(),
        ..Default::default()
    };
    let r = verify_with(&e.seg_dir, &opts).unwrap();
    assert!(matches!(
        r.broken.unwrap().kind,
        BreakKind::AnchorMismatch { .. }
    ));
}

#[test]
fn anchors_pass_on_an_untouched_store() {
    let e = env();
    let anchors = e.root.join("anchors.log");
    populate(&e, &mut [Box::new(FileSink::new(&anchors))]);
    let opts = Options {
        anchors: read_anchors(&anchors).unwrap(),
        ..keyed(&e)
    };
    let r = verify_with(&e.seg_dir, &opts).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    assert_eq!(r.anchors_checked, 4);
}

#[test]
fn require_seals_flags_a_stripped_store() {
    let e = env();
    let (mut s, _) = Store::open(
        &e.root,
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    s.append(rec(1)).unwrap();
    s.sync().unwrap();
    let opts = Options {
        require_seals: true,
        ..Default::default()
    };
    let b = verify_with(&e.seg_dir, &opts).unwrap().broken.unwrap();
    assert_eq!(b.kind, BreakKind::NoSeals);
}

#[test]
fn crash_between_seal_and_key_evolution_never_reuses_an_epoch() {
    let e = env();
    let mut s = open(&e);
    s.append(rec(1)).unwrap();
    s.seal_now().unwrap().unwrap(); // epoch 1 durable, key advanced to 2
    s.append(rec(2)).unwrap();

    // Simulate the crash window: record durable, key file still at the old epoch.
    let stale = fs::read(&e.key_path).unwrap();
    s.seal_now().unwrap().unwrap(); // epoch 2
    drop(s);
    fs::write(&e.key_path, stale).unwrap(); // key file says epoch 2 again

    let mut s = open(&e); // must reconcile to epoch 3
    s.append(rec(3)).unwrap();
    s.seal_now().unwrap().unwrap();
    s.sync().unwrap();
    let r = verify_with(&e.seg_dir, &keyed(&e)).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    assert_eq!(r.last_seal_epoch, Some(3));
}

#[test]
fn stale_key_file_is_refused() {
    let e = env();
    let mut s = open(&e);
    let old = fs::read(&e.key_path).unwrap(); // epoch 1
    for i in 0..3 {
        s.append(rec(i)).unwrap();
        s.seal_now().unwrap().unwrap();
    }
    drop(s);
    fs::write(&e.key_path, old).unwrap(); // restored from an old backup
    let (mut s, _) = Store::open(
        &e.root,
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(s.enable_sealing(&e.key_path).is_err());
}

#[test]
fn command_sink_receives_the_anchor() {
    let e = env();
    let out = e.root.join("hook.out");
    let script = format!(
        "echo \"$WITNESS_ANCHOR_SEQ $WITNESS_ANCHOR_HASH\" > {}",
        out.display()
    );
    let mut sinks: Vec<Box<dyn AnchorSink>> = vec![Box::new(CommandSink::new(
        "/bin/sh",
        vec!["-c".into(), script],
    ))];
    let mut s = open(&e);
    s.append(rec(1)).unwrap();
    let (a, failures) = s.anchor_now(&mut sinks).unwrap();
    assert!(failures.is_empty());
    let got = fs::read_to_string(&out).unwrap();
    assert_eq!(got.trim(), format!("{} {}", a.seq, chain::to_hex(&a.hash)));
}

#[test]
fn failing_sink_does_not_block_evidence() {
    let e = env();
    let mut sinks: Vec<Box<dyn AnchorSink>> = vec![Box::new(CommandSink::new(
        "/bin/sh",
        vec!["-c".into(), "exit 3".into()],
    ))];
    let mut s = open(&e);
    let (a, failures) = s.anchor_now(&mut sinks).unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(s.head().0, a.seq);
}
