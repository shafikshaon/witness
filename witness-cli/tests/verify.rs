#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::process::Command;

use serde_json::{json, Map, Value};
use witness_store::disk::DiskPolicy;
use witness_store::{Config, Store};

fn witness(dir: &std::path::Path, extra: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_witness"))
        .args(["verify", "--json", "--dir"])
        .arg(dir)
        .args(extra)
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap();
    (out.status.code().unwrap(), v)
}

#[test]
fn verify_exit_codes_and_location() {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            max_segment_bytes: 1500,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    for i in 0..40u64 {
        let mut m = Map::new();
        m.insert("type".into(), json!("t"));
        m.insert("n".into(), json!(i));
        s.append(m).unwrap();
    }
    s.sync().unwrap();
    drop(s);

    let (code, v) = witness(t.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(v["ok"], true);

    let seg = witness_store::segment::list_segments(&t.path().join("segments"))
        .unwrap()
        .remove(0);
    let text = fs::read_to_string(&seg.path).unwrap();
    fs::write(&seg.path, text.replacen("\"n\":1,", "\"n\":9,", 1)).unwrap();

    let (code, v) = witness(t.path(), &[]);
    assert_eq!(code, 1);
    assert_eq!(v["ok"], false);
    assert_eq!(v["broken"]["kind"], "BadHash");
    assert_eq!(v["broken"]["segment_id"], seg.id);
}

#[test]
fn init_seal_anchor_and_keyed_verify() {
    use std::process::Command;
    let t = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_witness");
    let run = |args: &[&str]| {
        Command::new(bin)
            .args(args)
            .arg("--dir")
            .arg(t.path())
            .output()
            .unwrap()
    };

    let out = run(&["init", "--seal"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let k0 = text
        .lines()
        .find_map(|l| l.strip_prefix("Verification key (K_0): "))
        .unwrap()
        .to_string();
    assert_eq!(k0.len(), 64);
    // Re-running must not clobber the key.
    assert!(!run(&["init", "--seal"]).status.success());

    let (mut s, _) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    s.enable_sealing(&t.path().join("seal.key")).unwrap();
    for i in 0..5u64 {
        s.append(json!({"type": "t", "n": i}).as_object().unwrap().clone())
            .unwrap();
    }
    s.seal_now().unwrap().unwrap();
    let mut sinks: Vec<Box<dyn witness_store::anchor::AnchorSink>> = vec![Box::new(
        witness_store::anchor::FileSink::new(t.path().join("anchors.log")),
    )];
    s.anchor_now(&mut sinks).unwrap();
    s.sync().unwrap();
    drop(s);

    let head = String::from_utf8(run(&["anchor"]).stdout).unwrap();
    assert!(head.starts_with("seq="));

    let ok = run(&["verify", "--json", "--seal-key", &k0, "--require-seals"]);
    let v: Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(ok.status.code(), Some(0));
    assert_eq!(v["macs_checked"], true);
    assert_eq!(v["anchors_checked"], 1);

    let wrong = "0".repeat(64);
    let bad = run(&["verify", "--json", "--seal-key", &wrong]);
    assert_eq!(bad.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert!(v["broken"]["kind"]
        .as_str()
        .unwrap()
        .starts_with("BadSealMac"));
}

#[test]
fn archive_prune_flow_through_the_cli() {
    use std::process::Command;
    let t = tempfile::tempdir().unwrap();
    let data = t.path().join("data");
    let dest = t.path().join("archive");
    let bin = env!("CARGO_BIN_EXE_witness");
    let run = |args: &[&str]| Command::new(bin).args(args).output().unwrap();
    let d = data.to_str().unwrap();
    let a = dest.to_str().unwrap();

    {
        let (mut s, _) = Store::open(
            &data,
            Config {
                max_segment_bytes: 2000,
                disk: DiskPolicy::disabled(),
            },
        )
        .unwrap();
        for i in 0..150u64 {
            s.append(
                json!({"type": "t", "n": i, "pad": "p".repeat(50)})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        }
        s.sync().unwrap();
    }

    // Copy-only archive, then verify the archive on its own.
    let out = run(&["archive", "--dir", d, "--to", a]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("originals kept"));
    let v: Value = serde_json::from_slice(&run(&["verify", "--json", "--dir", a]).stdout).unwrap();
    assert_eq!(v["ok"], true);

    // Prune: dry run deletes nothing; a blind delete is refused; a confirmed one works.
    let dry = run(&["prune", "--dir", d, "--before", "2500-01-01"]);
    let text = String::from_utf8(dry.stdout).unwrap();
    assert!(text.contains("dry run"), "{text}");
    let n: usize = text
        .split("--expect ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|x| x.parse().ok())
        .unwrap();
    let blind = run(&[
        "prune",
        "--dir",
        d,
        "--before",
        "2500-01-01",
        "--yes-delete-evidence",
    ]);
    assert!(!blind.status.success());
    let wrong = run(&[
        "prune",
        "--dir",
        d,
        "--before",
        "2500-01-01",
        "--yes-delete-evidence",
        "--expect",
        &(n + 1).to_string(),
    ]);
    assert!(!wrong.status.success());
    let ok = run(&[
        "prune",
        "--dir",
        d,
        "--before",
        "2500-01-01",
        "--yes-delete-evidence",
        "--expect",
        &n.to_string(),
    ]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // The deliberate removal verifies and is flagged as explained; with the archive the
    // whole chain verifies from the start.
    let v: Value = serde_json::from_slice(&run(&["verify", "--json", "--dir", d]).stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["partial_explained"], true);
    let v: Value =
        serde_json::from_slice(&run(&["verify", "--json", "--dir", d, "--include", a]).stdout)
            .unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["partial_start"], false);

    let r = run(&["reindex", "--dir", d, "--include", a]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
}

#[test]
fn archive_refuses_while_another_writer_holds_the_store() {
    use std::process::Command;
    let t = tempfile::tempdir().unwrap();
    let (_live, _) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_witness"))
        .args(["archive", "--dir"])
        .arg(t.path())
        .arg("--to")
        .arg(t.path().join("out"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("in use by another writer"));
}

#[test]
fn config_check_and_show() {
    use std::process::Command;
    let t = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_witness"))
            .args(args)
            .output()
            .unwrap()
    };
    let good = t.path().join("good.toml");
    fs::write(&good, "[storage]\non_full = \"stop\"\n").unwrap();
    let out = run(&["config", "check", "--file", good.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().starts_with("OK:"));

    let bad = t.path().join("bad.toml");
    fs::write(
        &bad,
        "[capture]\nring_volume_mib = 33\n[daemon]\nlog_level = \"loud\"\n",
    )
    .unwrap();
    let out = run(&["config", "check", "--file", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("ring_volume_mib") && err.contains("log_level"),
        "{err}"
    );

    let out = run(&["config", "show", "--file", good.to_str().unwrap()]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("on_full = \"stop\"") && text.contains("[seal]"));
    // A missing file means defaults, with a note.
    let out = run(&[
        "config",
        "show",
        "--file",
        t.path().join("none.toml").to_str().unwrap(),
    ]);
    assert!(out.status.success());
}
