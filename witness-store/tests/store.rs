#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use witness_store::disk::DiskPolicy;
use witness_store::segment::{self, SegmentInfo};
use witness_store::verify::{verify_dir, BreakKind};
use witness_store::{Config, Store};

fn rec(i: u64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!("test"));
    m.insert("n".into(), json!(i));
    m.insert(
        "cmdline".into(),
        json!(["ls", "-la", format!("/tmp/file{i}")]),
    );
    m
}

/// Writes `n` records with a small segment size so several segments are produced.
fn fill(root: &Path, n: u64) -> PathBuf {
    let (mut s, rec_) = Store::open(
        root,
        Config {
            max_segment_bytes: 2000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    assert!(rec_.is_empty());
    for i in 0..n {
        s.append(rec(i)).unwrap();
    }
    s.sync().unwrap();
    s.segment_dir().to_path_buf()
}

fn segs(dir: &Path) -> Vec<SegmentInfo> {
    segment::list_segments(dir).unwrap()
}

fn lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn write_lines(p: &Path, l: &[String]) {
    fs::write(p, l.join("\n") + "\n").unwrap();
}

#[test]
fn clean_store_verifies_across_rotation() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    assert!(segs(&dir).len() > 2);
    let r = verify_dir(&dir).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    assert_eq!(r.head_seq, r.records);
    assert!(!r.partial_start);
}

#[test]
fn reopen_resumes_chain() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 30);
    let (mut s, rc) = Store::open(
        t.path(),
        Config {
            max_segment_bytes: 2000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    assert!(rc.is_empty());
    let before = s.head().0;
    let a = s.append(rec(999)).unwrap();
    assert_eq!(a.seq, before + 1);
    s.sync().unwrap();
    assert!(verify_dir(&dir).unwrap().is_ok());
}

#[test]
fn compressed_segments_verify_and_resume() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            max_segment_bytes: 2000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    s.rotate().unwrap();
    let done = s.compress_sealed().unwrap();
    assert!(done.len() > 2);
    assert!(segs(&dir).iter().all(|x| x.compressed));
    assert!(verify_dir(&dir).unwrap().is_ok());
    // Writing after everything is compressed starts a fresh, correctly linked segment.
    s.append(rec(1)).unwrap();
    s.sync().unwrap();
    assert!(verify_dir(&dir).unwrap().is_ok());
    drop(s);
    let (mut s2, _) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    s2.append(rec(2)).unwrap();
    s2.sync().unwrap();
    assert!(verify_dir(&dir).unwrap().is_ok());
}

#[test]
fn modification_is_located() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 50);
    let seg = segs(&dir)[1].clone();
    let mut l = lines(&seg.path);
    l[3] = l[3].replace("/tmp/file", "/tmp/evil_");
    write_lines(&seg.path, &l);
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert_eq!(b.kind, BreakKind::BadHash);
    assert_eq!(b.segment_id, seg.id);
    assert_eq!(b.line, 4);
    assert_eq!(b.seq, Some(seg.first_seq + 3));
}

#[test]
fn deleted_record_is_located() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 50);
    let seg = segs(&dir)[1].clone();
    let mut l = lines(&seg.path);
    l.remove(4);
    write_lines(&seg.path, &l);
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert_eq!(
        b.kind,
        BreakKind::SeqMismatch {
            expected: seg.first_seq + 4,
            found: seg.first_seq + 5
        }
    );
    assert_eq!(b.line, 5);
}

#[test]
fn reordered_records_are_detected() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 50);
    let seg = segs(&dir)[1].clone();
    let mut l = lines(&seg.path);
    l.swap(2, 3);
    write_lines(&seg.path, &l);
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert!(matches!(b.kind, BreakKind::SeqMismatch { .. }));
    assert_eq!(b.line, 3);
}

#[test]
fn missing_middle_segment_is_detected() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    let all = segs(&dir);
    fs::remove_file(&all[1].path).unwrap();
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert_eq!(
        b.kind,
        BreakKind::MissingSegment {
            expected_id: all[1].id,
            found_id: all[2].id
        }
    );
}

#[test]
fn replaced_segment_breaks_next_segments_link() {
    // Rewrite a whole sealed segment consistently (as a root attacker could); the
    // neighbour's recorded hashes no longer match.
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    let seg = segs(&dir)[1].clone();
    let mut l = lines(&seg.path);
    l[2] = l[2].replace("file", "fiXe");
    write_lines(&seg.path, &l);
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert_eq!(b.kind, BreakKind::BadHash);
}

#[test]
fn truncated_tail_is_reported_and_recovered() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 30);
    let last = segs(&dir).pop().unwrap();
    let mut bytes = fs::read(&last.path).unwrap();
    let full = bytes.len();
    bytes.truncate(full - 20);
    fs::write(&last.path, &bytes).unwrap();

    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert_eq!(b.kind, BreakKind::TornTail);

    let (mut s, recs) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(recs.len(), 1);
    assert!(fs::metadata(&recs[0].quarantined_to).unwrap().len() > 0);
    s.append(rec(1)).unwrap();
    s.sync().unwrap();
    assert!(verify_dir(&dir).unwrap().is_ok());
}

#[test]
fn unsealed_middle_segment_is_detected() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    let seg = segs(&dir)[1].clone();
    let mut l = lines(&seg.path);
    l.pop(); // drop the seal line
    write_lines(&seg.path, &l);
    let b = verify_dir(&dir).unwrap().broken.unwrap();
    assert!(matches!(
        b.kind,
        BreakKind::UnsealedMidStore | BreakKind::SeqMismatch { .. }
    ));
}

#[test]
fn pruned_prefix_verifies_as_partial() {
    let t = tempfile::tempdir().unwrap();
    let dir = fill(t.path(), 100);
    let first = segs(&dir)[0].clone();
    fs::remove_file(&first.path).unwrap();
    let r = verify_dir(&dir).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
    assert!(r.partial_start);
}

#[test]
fn reserved_keys_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut m = rec(1);
    m.insert("seq".into(), json!(5));
    assert!(s.append(m).is_err());
}
