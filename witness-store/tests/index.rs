#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{json, Map, Value};
use witness_store::disk::DiskPolicy;
use witness_store::index::{Filter, Index};
use witness_store::{Config, Store};

fn event(i: u64) -> Map<String, Value> {
    let v = json!({
        "type": if i % 3 == 0 { "proc_exec" } else { "file_create" },
        "boot_ns": i * 1000,
        "wall_ns": 1_700_000_000_000_000_000u64 + i,
        "actor": {"pid": 100 + i % 5, "uid": if i % 2 == 0 { 0 } else { 1000 },
                  "puid": format!("p{}", i % 5), "cmdline": ["curl", format!("http://host{i}.example")]},
        "data": {"path": format!("/etc/conf{i}.d/file")}
    });
    v.as_object().unwrap().clone()
}

fn setup(n: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            max_segment_bytes: 4000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    for i in 0..n {
        s.append(event(i)).unwrap();
    }
    s.sync().unwrap();
    let dir = s.segment_dir().to_path_buf();
    (t, dir)
}

#[test]
fn index_query_and_raw() {
    let (t, dir) = setup(200);
    let mut ix = Index::open(&t.path().join("index.db")).unwrap();
    let n = ix.catch_up(&dir).unwrap();
    assert!(n >= 200);

    let f = Filter {
        kinds: vec!["proc_exec".into()],
        limit: 10,
        ..Default::default()
    };
    let rows = ix.query(&f).unwrap();
    assert_eq!(rows.len(), 10);
    assert!(rows.windows(2).all(|w| w[0].seq > w[1].seq));

    // Keyset pagination continues strictly below the cursor.
    let next = ix
        .query(&Filter {
            before_seq: Some(rows[9].seq),
            ..f.clone()
        })
        .unwrap();
    assert!(next[0].seq < rows[9].seq);

    let fts = ix
        .query(&Filter {
            text: Some("host42".into()),
            limit: 5,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(fts.len(), 1);
    let raw = ix.raw(&dir, fts[0].seq).unwrap();
    assert!(String::from_utf8(raw).unwrap().contains("host42.example"));

    let by_proc = ix
        .query(&Filter {
            puid: Some("p1".into()),
            uid: Some(1000),
            limit: 1000,
            ..Default::default()
        })
        .unwrap();
    assert!(!by_proc.is_empty() && by_proc.iter().all(|r| r.puid.as_deref() == Some("p1")));
}

#[test]
fn incremental_and_rebuild_agree() {
    let (t, dir) = setup(100);
    let db = t.path().join("index.db");
    let mut ix = Index::open(&db).unwrap();
    ix.catch_up(&dir).unwrap();
    let first = ix.position().unwrap();

    // More events, then resume incrementally.
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            max_segment_bytes: 4000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    for i in 100..150 {
        s.append(event(i)).unwrap();
    }
    s.sync().unwrap();
    let added = ix.catch_up(&dir).unwrap();
    assert!(added >= 50);
    assert!(ix.position().unwrap().0 > first.0);

    // A fresh index built from scratch reaches the identical position.
    let mut fresh = Index::open(&t.path().join("fresh.db")).unwrap();
    fresh.catch_up(&dir).unwrap();
    assert_eq!(fresh.position().unwrap(), ix.position().unwrap());
    assert_eq!(ix.catch_up(&dir).unwrap(), 0);
}

#[test]
fn tampered_segment_fails_indexing() {
    let (t, dir) = setup(60);
    let seg = witness_store::segment::list_segments(&dir)
        .unwrap()
        .remove(0);
    let text = std::fs::read_to_string(&seg.path).unwrap();
    std::fs::write(
        &seg.path,
        text.replacen("host3.example", "hostX.example", 1),
    )
    .unwrap();
    let mut ix = Index::open(&t.path().join("index.db")).unwrap();
    assert!(ix.catch_up(&dir).is_err());
}
