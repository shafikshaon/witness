#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Map, Value};
use witness_store::disk::DiskPolicy;
use witness_store::{Config, Store};

fn witness(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_witness"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn fill(root: &Path) {
    let (mut s, _) = Store::open(
        root,
        Config {
            max_segment_bytes: 4000,
            disk: DiskPolicy::disabled(),
        },
    )
    .unwrap();
    for i in 0..40u64 {
        let mut m: Map<String, Value> = Map::new();
        m.insert("type".into(), json!("test"));
        m.insert("data".into(), json!({"n": i}));
        s.append(m).unwrap();
    }
    s.sync().unwrap();
}

#[test]
fn keygen_sign_verify_and_tamper_through_the_command_line() {
    let t = tempfile::tempdir().unwrap();
    fill(t.path());
    let key = t.path().join("signing.key");
    let key_s = key.to_str().unwrap();

    // keygen: writes a 0600 key, prints the public half, and refuses to overwrite.
    let (code, out, _) = witness(&["keygen", key_s]);
    assert_eq!(code, 0, "{out}");
    let pubkey = out
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(pubkey.len(), 64);
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_ne!(
        witness(&["keygen", key_s]).0,
        0,
        "an existing key is never overwritten"
    );

    // A signed bundle verifies, with and without naming the expected signer.
    let tar = t.path().join("b.tar");
    let tar_s = tar.to_str().unwrap();
    let dir = t.path().to_str().unwrap();
    let (code, _, err) = witness(&[
        "bundle",
        "--dir",
        dir,
        "--from-seq",
        "5",
        "--to-seq",
        "25",
        "-o",
        tar_s,
        "--sign-key",
        key_s,
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = witness(&["bundle-verify", tar_s, "--pubkey", &pubkey]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("OK: 21 records (#5..#25) verify, signed by"),
        "{out}"
    );
    assert_eq!(witness(&["bundle-verify", tar_s]).0, 0);

    // Wrong signer, tampered archive, unsigned bundle with a required signer: all rejected.
    assert_eq!(
        witness(&["bundle-verify", tar_s, "--pubkey", &"0".repeat(64)]).0,
        1
    );
    let mut bytes = fs::read(&tar).unwrap();
    let at = bytes.windows(6).position(|w| w == b"\"test\"").unwrap();
    bytes[at + 1] ^= 1;
    let bad = t.path().join("bad.tar");
    fs::write(&bad, bytes).unwrap();
    let (code, _, err) = witness(&["bundle-verify", bad.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("FAILED"), "{err}");
    let plain = t.path().join("plain.tar");
    assert_eq!(
        witness(&["bundle", "--dir", dir, "-o", plain.to_str().unwrap()]).0,
        0
    );
    assert_eq!(
        witness(&["bundle-verify", plain.to_str().unwrap()]).0,
        0,
        "unsigned verifies by hash and chain"
    );
    assert_eq!(
        witness(&[
            "bundle-verify",
            plain.to_str().unwrap(),
            "--pubkey",
            &pubkey
        ])
        .0,
        1
    );
    // A bad key file is a clear error, not a silent unsigned bundle.
    fs::write(t.path().join("short.key"), "abc").unwrap();
    let (code, _, err) = witness(&[
        "bundle",
        "--dir",
        dir,
        "-o",
        plain.to_str().unwrap(),
        "--sign-key",
        t.path().join("short.key").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("64 hex digits"), "{err}");
}
