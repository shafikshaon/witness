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

    let (mut s, _) = Store::open(t.path(), Config::default()).unwrap();
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
