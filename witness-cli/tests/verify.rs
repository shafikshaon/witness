#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::process::Command;

use serde_json::{json, Map, Value};
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
