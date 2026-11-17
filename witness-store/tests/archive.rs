#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use witness_store::archive::{plan_prefix, segment_meta};
use witness_store::disk::DiskPolicy;
use witness_store::index::{Filter, Index};
use witness_store::segment::{self, fidx_path};
use witness_store::verify::{verify_dirs, verify_with, Options};
use witness_store::{Config, Store, StoreError};

fn cfg() -> Config {
    Config {
        max_segment_bytes: 2500,
        disk: DiskPolicy::disabled(),
    }
}

fn rec(i: u64) -> Map<String, Value> {
    json!({"type": "t", "n": i, "pad": "p".repeat(60)})
        .as_object()
        .unwrap()
        .clone()
}

struct Env {
    _t: tempfile::TempDir,
    root: PathBuf,
    seg: PathBuf,
    dest: PathBuf,
    store: Store,
}

fn env(n: u64) -> Env {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    let dest = t.path().join("archive");
    let (mut store, _) = Store::open(&root, cfg()).unwrap();
    for i in 0..n {
        store.append(rec(i)).unwrap();
    }
    store.sync().unwrap();
    Env {
        seg: root.join("segments"),
        root,
        dest,
        store,
        _t: t,
    }
}

fn records(dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    for s in segment::list_segments(dir).unwrap() {
        for l in segment::open_reader(&s).unwrap().lines() {
            out.push(serde_json::from_str(&l.unwrap()).unwrap());
        }
    }
    out
}

fn ok(dirs: &[PathBuf]) -> witness_store::verify::Report {
    let r = verify_dirs(dirs, &Options::default()).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    r
}

#[test]
fn copy_only_archive_leaves_originals_and_verifies_standalone() {
    let mut e = env(120);
    let before = segment::list_segments(&e.seg).unwrap();
    assert!(before.len() >= 4);

    let rep = e.store.archive(&e.dest, None, false).unwrap();
    assert_eq!(
        rep.segments.len(),
        before.len() - 1,
        "newest segment is never archived"
    );
    assert_eq!(rep.copied, rep.segments.len());
    assert_eq!(segment::list_segments(&e.seg).unwrap().len(), before.len());

    // The archive is a self-contained, verifiable prefix of the chain.
    let r = ok(&[e.dest.join("segments")]);
    assert!(!r.partial_start);
    // The live chain now contains the archive record.
    e.store.sync().unwrap();
    let recs = records(&e.seg);
    let a = recs.iter().find(|v| v["type"] == "archive").unwrap();
    assert_eq!(a["moved"], false);
    assert_eq!(a["segments"].as_array().unwrap().len(), rep.segments.len());
    ok(&[e.seg.clone()]);

    // Re-running is idempotent for the files.
    let again = e.store.archive(&e.dest, None, false).unwrap();
    assert_eq!(again.copied, 0);
}

#[test]
fn move_removes_originals_and_the_gap_is_explained() {
    let mut e = env(120);
    let all = segment::list_segments(&e.seg).unwrap();
    let rep = e.store.archive(&e.dest, None, true).unwrap();
    assert!(rep.moved);
    e.store.sync().unwrap();
    let left = segment::list_segments(&e.seg).unwrap();
    assert_eq!(left.len(), all.len() - rep.segments.len());

    // Live data alone: the missing prefix is accounted for by the chained archive record.
    let r = ok(&[e.seg.clone()]);
    assert!(r.partial_start && r.partial_explained);
    // With the archive attached the whole chain verifies from seq 1.
    let r = ok(&[e.seg.clone(), e.dest.join("segments")]);
    assert!(!r.partial_start);
    assert_eq!(r.head_seq, r.records);
}

#[test]
fn archived_events_stay_searchable_and_fetchable() {
    let mut e = env(120);
    let mut ix = Index::open(&e.root.join("index.db")).unwrap();
    ix.catch_up(&e.seg).unwrap();
    e.store.archive(&e.dest, None, true).unwrap();
    e.store.sync().unwrap();

    let dirs = [e.seg.clone(), e.dest.join("segments")];
    // Raw fetch of an early event now comes from the archive directory.
    let early = ix
        .query(&Filter {
            before_seq: Some(4),
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    let raw = ix.raw_in(&dirs, early[0].seq).unwrap();
    assert!(String::from_utf8(raw).unwrap().contains("\"seq\":"));
    assert!(ix.raw(&e.seg, early[0].seq).is_err());

    // A fresh index over live + archive reaches the same head as one over the original.
    let mut fresh = Index::open(&e.root.join("fresh.db")).unwrap();
    fresh.catch_up_dirs(&dirs).unwrap();
    assert!(fresh.position().unwrap().0 >= ix.position().unwrap().0);
}

#[test]
fn before_filter_selects_only_older_segments() {
    let mut e = env(120);
    let segs = segment::list_segments(&e.seg).unwrap();
    let third = segment_meta(&segs[2]).unwrap().seal_ts_ns.unwrap();
    let plan = plan_prefix(&e.seg, Some(third)).unwrap();
    // Only segments sealed strictly before `third`: the first two (timestamps are ns apart,
    // so allow equal stamps to shrink the set but never grow it).
    assert!(plan.len() <= 2);
    assert!(plan.iter().all(|(_, m)| m.seal_ts_ns.unwrap() < third));
    let rep = e.store.archive(&e.dest, Some(third), false).unwrap();
    assert_eq!(rep.segments.len(), plan.len());
}

#[test]
fn a_conflicting_destination_file_aborts_without_a_record() {
    let mut e = env(120);
    let first = segment::list_segments(&e.seg).unwrap().remove(0);
    let name = first.path.file_name().unwrap();
    fs::create_dir_all(e.dest.join("segments")).unwrap();
    fs::write(e.dest.join("segments").join(name), b"not the same bytes\n").unwrap();

    let err = e.store.archive(&e.dest, None, true).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
    e.store.sync().unwrap();
    // Nothing was removed and nothing was logged.
    assert!(first.path.exists());
    assert!(records(&e.seg).iter().all(|v| v["type"] != "archive"));
}

#[test]
fn compressed_segments_archive_with_their_frame_table() {
    let mut e = env(120);
    e.store.rotate().unwrap();
    e.store.compress_sealed().unwrap();
    let rep = e.store.archive(&e.dest, None, true).unwrap();
    assert!(!rep.segments.is_empty());
    e.store.sync().unwrap();
    let packed: Vec<_> = segment::list_segments(&e.dest.join("segments")).unwrap();
    assert!(packed.iter().all(|s| s.compressed));
    assert!(packed.iter().all(|s| fidx_path(&s.path).exists()));
    ok(&[e.seg.clone(), e.dest.join("segments")]);
}

#[test]
fn prune_requires_the_confirmed_count_and_logs_before_deleting() {
    let mut e = env(120);
    let far_future = u64::MAX;
    let plan = plan_prefix(&e.seg, Some(far_future)).unwrap();
    let n = plan.len();
    assert!(n >= 3);
    let seg_count = segment::list_segments(&e.seg).unwrap().len();

    // Wrong confirmation: refused, nothing deleted, nothing logged.
    assert!(e.store.prune(far_future, n - 1).is_err());
    assert_eq!(segment::list_segments(&e.seg).unwrap().len(), seg_count);
    e.store.sync().unwrap();
    assert!(records(&e.seg).iter().all(|v| v["type"] != "prune"));

    let gone = e.store.prune(far_future, n).unwrap();
    assert_eq!(gone.len(), n);
    e.store.sync().unwrap();
    let left = segment::list_segments(&e.seg).unwrap();
    assert_eq!(left.len(), seg_count - n);
    assert!(!left.is_empty(), "the newest segment always survives");

    let recs = records(&e.seg);
    let p = recs.iter().find(|v| v["type"] == "prune").unwrap();
    assert_eq!(p["segments"].as_array().unwrap().len(), n);
    assert_eq!(p["through_seq"], gone.last().unwrap().last_seq);
    assert!(p["segments"][0]["sha256_file"].as_str().unwrap().len() == 64);

    // Deliberate removal verifies, and says so; sealed history after it still checks out.
    let r = ok(&[e.seg.clone()]);
    assert!(r.partial_start && r.partial_explained);
    assert!(verify_with(&e.seg, &Options::default()).unwrap().is_ok());
}

#[test]
fn prune_only_removes_the_oldest_contiguous_run() {
    let mut e = env(120);
    let segs = segment::list_segments(&e.seg).unwrap();
    let cutoff = segment_meta(&segs[1]).unwrap().seal_ts_ns.unwrap() + 1;
    let n = plan_prefix(&e.seg, Some(cutoff)).unwrap().len();
    assert!((1..=2).contains(&n));
    e.store.prune(cutoff, n).unwrap();
    e.store.sync().unwrap();
    let left = segment::list_segments(&e.seg).unwrap();
    assert_eq!(
        left[0].id, segs[n].id,
        "removal starts at the oldest and stays contiguous"
    );
    ok(&[e.seg.clone()]);
}

#[test]
fn a_single_segment_is_never_pruned_or_archived() {
    let mut e = env(3);
    assert_eq!(segment::list_segments(&e.seg).unwrap().len(), 1);
    assert!(e
        .store
        .archive(&e.dest, None, true)
        .unwrap()
        .segments
        .is_empty());
    assert!(e.store.prune(u64::MAX, 0).unwrap().is_empty());
    assert_eq!(segment::list_segments(&e.seg).unwrap().len(), 1);
}
