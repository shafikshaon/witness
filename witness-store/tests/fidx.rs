#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use serde_json::{json, Map, Value};
use witness_store::disk::DiskPolicy;
use witness_store::index::{Filter, Index};
use witness_store::segment::{self, fidx_path, FRAME_BYTES};
use witness_store::{Config, Store, StoreError};

fn cfg() -> Config {
    Config {
        max_segment_bytes: 64 << 20,
        disk: DiskPolicy::disabled(),
    }
}

fn big(i: u64) -> Map<String, Value> {
    json!({"type": "t", "n": i, "pad": "x".repeat(900)})
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn second_writer_is_refused_until_the_first_is_dropped() {
    let t = tempfile::tempdir().unwrap();
    let (s, _) = Store::open(t.path(), cfg()).unwrap();
    assert!(matches!(
        Store::open(t.path(), cfg()),
        Err(StoreError::Locked)
    ));
    drop(s);
    assert!(Store::open(t.path(), cfg()).is_ok());
}

#[test]
fn random_access_into_compressed_segment_and_fidx_rebuild() {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(t.path(), cfg()).unwrap();
    for i in 0..4000 {
        s.append(big(i)).unwrap();
    }
    s.rotate().unwrap();
    s.compress_sealed().unwrap();
    drop(s);
    let dir = t.path().join("segments");
    let seg = segment::list_segments(&dir).unwrap().remove(0);
    assert!(seg.compressed);
    assert!(
        fs::metadata(&seg.path).unwrap().len() > 0
            && fs::read_to_string(fidx_path(&seg.path))
                .unwrap()
                .lines()
                .count()
                >= 3,
        "4000 x ~1 KB spans several {FRAME_BYTES}-byte frames"
    );

    let mut ix = Index::open(&t.path().join("index.db")).unwrap();
    ix.catch_up(&dir).unwrap();

    let check = |ix: &Index| {
        for seq in [2u64, 1500, 2100, 3999, 4001] {
            let rows = ix
                .query(&Filter {
                    before_seq: Some(seq + 1),
                    limit: 1,
                    ..Default::default()
                })
                .unwrap();
            let raw = ix.raw(&dir, rows[0].seq).unwrap();
            let v: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(v["seq"], rows[0].seq);
        }
    };
    check(&ix);

    // The sidecar is derived data: delete it and it is rebuilt on demand.
    fs::remove_file(fidx_path(&seg.path)).unwrap();
    check(&ix);
    assert!(fidx_path(&seg.path).exists());
}

#[test]
fn range_spanning_a_frame_boundary() {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(t.path(), cfg()).unwrap();
    for i in 0..3000 {
        s.append(big(i)).unwrap();
    }
    s.rotate().unwrap();
    let dir = t.path().join("segments");
    let plain = segment::list_segments(&dir).unwrap().remove(0);
    let want = fs::read(&plain.path).unwrap();
    s.compress_sealed().unwrap();
    let packed = segment::list_segments(&dir).unwrap().remove(0);
    let off = FRAME_BYTES as u64 - 100;
    let got = segment::read_range(&packed, off, 300).unwrap();
    assert_eq!(got, want[off as usize..off as usize + 300]);
}
