#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use witness_store::bundle::{build, BundleOptions};
use witness_store::chain;
use witness_store::disk::DiskPolicy;
use witness_store::{Config, Store};

fn rec(i: u64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "type".into(),
        json!(if i % 7 == 0 { "alert" } else { "test" }),
    );
    m.insert(
        "data".into(),
        json!({"n": i, "rule_id": "r", "title": "t", "severity": "high"}),
    );
    m
}

fn fill(root: &Path, n: u64) {
    let (mut s, _) = Store::open(
        root,
        Config {
            max_segment_bytes: 3000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    for i in 0..n {
        s.append(rec(i)).unwrap();
    }
    // A triage action for one of the alerts, recorded after it.
    let mut t = Map::new();
    t.insert("type".into(), json!("triage_action"));
    t.insert(
        "data".into(),
        json!({"alert_seq": 8, "status": "false_positive", "note": "n", "actor_uid": 0}),
    );
    s.append(t).unwrap();
    s.sync().unwrap();
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_bundle_extracts_and_every_hash_checks_out_independently() {
    let t = tempfile::tempdir().unwrap();
    fill(t.path(), 40);
    let seg = t.path().join("segments");
    let tar = build(
        std::slice::from_ref(&seg),
        t.path(),
        &BundleOptions {
            from_seq: Some(10),
            to_seq: Some(25),
            tool_version: "test".into(),
            exported_wall_ns: 1_700_000_000_000_000_000,
        },
    )
    .unwrap();
    let file = t.path().join("b.tar");
    fs::write(&file, &tar).unwrap();
    let out = t.path().join("x");
    fs::create_dir(&out).unwrap();
    // The system tar is the independent check that the archive is well formed.
    assert!(Command::new("tar")
        .arg("-xf")
        .arg(&file)
        .arg("-C")
        .arg(&out)
        .status()
        .unwrap()
        .success());
    let names: Vec<String> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    for n in [
        "events.ndjson",
        "alerts.json",
        "chain-proof.json",
        "anchors.json",
        "verify-report.json",
        "manifest.json",
    ] {
        assert!(names.iter().any(|x| x == n), "missing {n}: {names:?}");
    }

    // Manifest hashes match the extracted bytes.
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    for f in manifest["files"].as_array().unwrap() {
        let data = fs::read(out.join(f["name"].as_str().unwrap())).unwrap();
        assert_eq!(f["sha256"], hex(&Sha256::digest(&data)), "{}", f["name"]);
        assert_eq!(f["bytes"], data.len());
    }
    assert_eq!(manifest["range"]["first_seq"], 10);
    assert_eq!(manifest["range"]["last_seq"], 25);

    // Recompute the chain from the proof's starting hash over the verbatim lines.
    let proof: Value =
        serde_json::from_slice(&fs::read(out.join("chain-proof.json")).unwrap()).unwrap();
    let mut prev = chain::from_hex(proof["prev_hash"].as_str().unwrap().as_bytes()).unwrap();
    let events = fs::read_to_string(out.join("events.ndjson")).unwrap();
    let mut n = 0;
    for line in events.lines() {
        let l = line.as_bytes();
        // Body = the line without its final 72 bytes, plus `}` (the documented algorithm).
        let mut body = l[..l.len() - 72].to_vec();
        body.push(b'}');
        prev = chain::link(&prev, &body);
        let recorded = line[line.len() - 66..line.len() - 2].to_string();
        assert_eq!(hex(&prev), recorded);
        n += 1;
    }
    assert_eq!(n, 16);
    assert_eq!(proof["last_hash"], hex(&prev));
    assert_eq!(proof["lines"].as_array().unwrap().len(), 16);

    // The first record's predecessor is the real record 9's hash.
    let nine = fs::read_dir(&seg)
        .unwrap()
        .flat_map(|e| {
            fs::read_to_string(e.unwrap().path())
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .find(|l| l.contains("\"seq\":9,"))
        .unwrap();
    assert_eq!(proof["prev_hash"], nine[nine.len() - 66..nine.len() - 2]);

    // Alerts in range (seq 14 and 21, multiples of 7 among n=seq-1... types by n) carry triage state.
    let alerts: Vec<Value> =
        serde_json::from_slice(&fs::read(out.join("alerts.json")).unwrap()).unwrap();
    assert!(!alerts.is_empty());
    assert!(alerts.iter().all(|a| a["type"] == "alert"));
    let by_seq: HashMap<u64, &Value> = alerts
        .iter()
        .map(|a| (a["seq"].as_u64().unwrap(), a))
        .collect();
    if let Some(a) = by_seq.get(&8) {
        assert_eq!(a["triage"]["status"], "false_positive");
    }
    let report: Value =
        serde_json::from_slice(&fs::read(out.join("verify-report.json")).unwrap()).unwrap();
    assert_eq!(report["state"], "ok");
}

#[test]
fn a_tampered_store_is_refused_not_bundled() {
    let t = tempfile::tempdir().unwrap();
    fill(t.path(), 20);
    let seg = t.path().join("segments");
    // Alter one byte inside a record body of the first segment.
    let first = fs::read_dir(&seg)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
        .min()
        .unwrap();
    let mut bytes = fs::read(&first).unwrap();
    let at = bytes
        .windows(6)
        .position(|w| w == b"\"n\":3,")
        .or_else(|| bytes.windows(6).position(|w| w == b"\"n\":2,"))
        .unwrap_or(40);
    bytes[at + 4] ^= 1;
    fs::write(&first, bytes).unwrap();
    let r = build(&[seg], t.path(), &BundleOptions::default());
    assert!(
        r.is_err(),
        "a bundle must not be produced from a modified store"
    );
}

#[test]
fn empty_range_and_oversized_names_are_errors() {
    let t = tempfile::tempdir().unwrap();
    fill(t.path(), 5);
    let seg = t.path().join("segments");
    let o = BundleOptions {
        from_seq: Some(1000),
        ..BundleOptions::default()
    };
    assert!(build(&[seg], t.path(), &o).is_err());
    let mut v = Vec::new();
    assert!(witness_store::bundle::tar_entry(&mut v, &"x".repeat(101), b"", 0).is_err());
}
