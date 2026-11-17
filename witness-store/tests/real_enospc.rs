#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Disk-full behaviour on a *real* full filesystem. Needs a small, writable mount:
//!
//! ```sh
//! sudo mkdir -p /mnt/witness-small && sudo mount -t tmpfs -o size=1m tmpfs /mnt/witness-small
//! sudo chown $USER /mnt/witness-small
//! WITNESS_SMALL_FS=/mnt/witness-small cargo test -p witness-store --test real_enospc -- --ignored
//! ```

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use witness_store::disk::{DiskPolicy, DiskState, OnFull, Priority};
use witness_store::store::Append;
use witness_store::verify::verify_dir;
use witness_store::{Config, Store, StoreError};

fn small_fs(name: &str) -> PathBuf {
    let base = PathBuf::from(std::env::var("WITNESS_SMALL_FS").expect("set WITNESS_SMALL_FS"));
    let d = base.join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn rec(i: u64) -> Map<String, Value> {
    json!({"type": "t", "n": i, "pad": "x".repeat(400)})
        .as_object()
        .unwrap()
        .clone()
}

fn policy(on_full: OnFull) -> DiskPolicy {
    DiskPolicy {
        warn_pcts: vec![80, 90],
        min_free_bytes: 200 * 1024,
        reserve_bytes: 64 * 1024,
        on_full,
        probe_every_bytes: 8 * 1024,
        drop_report_interval: std::time::Duration::ZERO,
    }
}

fn open(root: &std::path::Path, p: DiskPolicy) -> Store {
    Store::open(
        root,
        Config {
            max_segment_bytes: 64 * 1024,
            disk: p,
        },
    )
    .unwrap()
    .0
}

#[test]
#[ignore = "needs WITNESS_SMALL_FS pointing at a ~1 MiB filesystem"]
fn shed_mode_survives_a_really_full_disk() {
    let root = small_fs("shed");
    let filler = root.join("filler.bin");
    let mut s = open(&root, policy(OnFull::Shed));
    assert!(
        s.disk_status().reserve_present,
        "reserve is preallocated (fallocate)"
    );

    // Fill the disk with a file we can delete later, then keep writing events at every
    // priority until the real ENOSPC path has been exercised.
    fs::write(&filler, vec![0u8; 600 * 1024]).unwrap();
    let mut written = [0u64; 4];
    let mut dropped = [0u64; 4];
    for i in 0..4000u64 {
        for (idx, prio) in [Priority::P3, Priority::P2, Priority::P1, Priority::P0]
            .into_iter()
            .enumerate()
        {
            match s.append_prio(prio, rec(i)) {
                Ok(Append::Written(_)) => written[3 - idx] += 1,
                Ok(Append::Dropped) => dropped[3 - idx] += 1,
                Err(e) => panic!("append must never error in shed mode: {e}"),
            }
        }
        if i % 50 == 0 {
            s.tick().unwrap();
        }
    }
    s.sync().unwrap();
    let st = s.disk_status();
    eprintln!(
        "state {:?} written {written:?} dropped {dropped:?}",
        st.state
    );
    assert!(dropped[3] > 0, "P3 must have been shed under real pressure");
    assert!(written[0] > 0, "P0 keeps being written");

    // No torn line: the chain verifies despite real ENOSPC mid-write.
    let r = verify_dir(&root.join("segments")).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);

    // Free space returns: back to normal and writing resumes.
    fs::remove_file(&filler).unwrap();
    s.tick().unwrap();
    s.tick().unwrap();
    assert_eq!(s.disk_status().state, DiskState::Normal);
    assert!(matches!(
        s.append_prio(Priority::P3, rec(1)).unwrap(),
        Append::Written(_)
    ));
    s.sync().unwrap();
    assert!(verify_dir(&root.join("segments")).unwrap().is_ok());
}

#[test]
#[ignore = "needs WITNESS_SMALL_FS pointing at a ~1 MiB filesystem"]
fn stop_mode_records_a_gap_on_a_really_full_disk() {
    let root = small_fs("stop");
    let filler = root.join("filler.bin");
    let mut s = open(&root, policy(OnFull::Stop));
    fs::write(&filler, vec![0u8; 600 * 1024]).unwrap();
    for i in 0..400u64 {
        let _ = s.append(rec(i));
        if i % 20 == 0 {
            s.tick().unwrap();
        }
    }
    assert_eq!(s.disk_status().state, DiskState::Stopped);
    assert!(matches!(s.append(rec(0)), Err(StoreError::DiskFull)));
    s.sync().unwrap();
    assert!(verify_dir(&root.join("segments")).unwrap().is_ok());

    fs::remove_file(&filler).unwrap();
    s.tick().unwrap();
    assert_eq!(s.disk_status().state, DiskState::Normal);
    s.append(rec(1)).unwrap();
    s.sync().unwrap();
    let text: String = witness_store::segment::list_segments(&root.join("segments"))
        .unwrap()
        .iter()
        .map(|g| fs::read_to_string(&g.path).unwrap_or_default())
        .collect();
    assert!(text.contains("\"phase\":\"start\"") && text.contains("\"phase\":\"end\""));
    assert!(verify_dir(&root.join("segments")).unwrap().is_ok());
}
