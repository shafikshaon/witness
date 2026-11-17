#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, BufRead};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};
use witness_store::disk::{DiskPolicy, DiskState, OnFull, Priority, Space, SpaceProbe};
use witness_store::segment;
use witness_store::store::{Append, DiskEvent};
use witness_store::verify::verify_dir;
use witness_store::{Config, Store, StoreError};

const TOTAL: u64 = 10_000;

#[derive(Clone)]
struct Fake(Arc<Mutex<u64>>);

impl Fake {
    fn new(avail: u64) -> Self {
        Fake(Arc::new(Mutex::new(avail)))
    }
    fn set(&self, avail: u64) {
        *self.0.lock().unwrap() = avail;
    }
}

impl SpaceProbe for Fake {
    fn probe(&mut self) -> io::Result<Space> {
        Ok(Space {
            total: TOTAL,
            avail: *self.0.lock().unwrap(),
        })
    }
}

fn policy(on_full: OnFull) -> DiskPolicy {
    DiskPolicy {
        warn_pcts: vec![80, 90],
        min_free_bytes: 900,
        reserve_bytes: 0,
        on_full,
        probe_every_bytes: 1 << 40, // only tick() probes, keeping tests deterministic
        drop_report_interval: std::time::Duration::ZERO,
    }
}

fn open(root: &Path, p: DiskPolicy, probe: &Fake) -> Store {
    let cfg = Config {
        max_segment_bytes: 1 << 20,
        disk: p,
    };
    Store::open_with_probe(root, cfg, Box::new(probe.clone()))
        .unwrap()
        .0
}

fn rec(kind: &str) -> Map<String, Value> {
    json!({"type": kind}).as_object().unwrap().clone()
}

fn records(seg_dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    for s in segment::list_segments(seg_dir).unwrap() {
        for line in segment::open_reader(&s).unwrap().lines() {
            out.push(serde_json::from_str(&line.unwrap()).unwrap());
        }
    }
    out
}

fn of_type<'a>(r: &'a [Value], t: &str) -> Vec<&'a Value> {
    r.iter().filter(|v| v["type"] == t).collect()
}

fn written(a: Append) -> bool {
    matches!(a, Append::Written(_))
}

#[test]
fn shedding_is_graded_by_priority_and_p0_is_never_shed() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(5000);
    let mut s = open(t.path(), policy(OnFull::Shed), &fake);
    let all = [Priority::P0, Priority::P1, Priority::P2, Priority::P3];
    let try_all = |s: &mut Store| -> Vec<bool> {
        all.iter()
            .map(|&p| written(s.append_prio(p, rec("e")).unwrap()))
            .collect()
    };

    assert_eq!(try_all(&mut s), [true, true, true, true]);

    fake.set(800); // level 1: P3 shed
    s.tick().unwrap();
    assert_eq!(try_all(&mut s), [true, true, true, false]);

    fake.set(500); // level 2: P2, P3 shed
    s.tick().unwrap();
    assert_eq!(try_all(&mut s), [true, true, false, false]);

    fake.set(100); // level 3: only P0
    s.tick().unwrap();
    assert_eq!(try_all(&mut s), [true, false, false, false]);
    assert_eq!(s.disk_status().state, DiskState::Shedding(3));
    // `append` is P0 and keeps working at the deepest level.
    s.append(rec("p0")).unwrap();

    // Each tick reports and resets the window (interval is zero here), so only the level-3
    // round is still pending; the earlier rounds are in the chain.
    assert_eq!(s.disk_status().dropped, [0, 1, 1, 1]);
    s.tick().unwrap();
    s.sync().unwrap();
    let r = records(s.segment_dir());
    let mut total = [0u64; 4];
    for d in of_type(&r, "capture_drop") {
        for (i, n) in d["dropped"].as_array().unwrap().iter().enumerate() {
            total[i] += n.as_u64().unwrap();
        }
    }
    assert_eq!(total, [0, 1, 2, 3], "no shed event goes unaccounted");
}

#[test]
fn drops_are_reported_in_the_chain_when_space_returns() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(5000);
    let mut s = open(t.path(), policy(OnFull::Shed), &fake);
    fake.set(100);
    s.tick().unwrap();
    for _ in 0..4 {
        s.append_prio(Priority::P3, rec("e")).unwrap();
    }
    s.append_prio(Priority::P1, rec("e")).unwrap();

    fake.set(5000);
    let ev = s.tick().unwrap();
    assert!(ev.contains(&DiskEvent::Dropped {
        counts: [0, 1, 0, 4]
    }));
    assert_eq!(s.disk_status().state, DiskState::Normal);
    assert_eq!(s.disk_status().dropped, [0; 4]);
    s.append(rec("after")).unwrap();
    s.sync().unwrap();

    let r = records(s.segment_dir());
    let drops = of_type(&r, "capture_drop");
    assert_eq!(drops.len(), 1);
    assert_eq!(drops[0]["dropped"], json!([0, 1, 0, 4]));
    assert_eq!(drops[0]["reason"], "disk");
    assert!(!of_type(&r, "disk_state").is_empty());
    assert!(verify_dir(s.segment_dir()).unwrap().is_ok());
}

#[test]
fn warnings_fire_once_per_crossing_and_again_after_recovery() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000); // 10 % used
    let mut s = open(t.path(), policy(OnFull::Shed), &fake);
    let warnings = |ev: &[DiskEvent]| -> Vec<u8> {
        ev.iter()
            .filter_map(|e| match e {
                DiskEvent::Warning { pct, .. } => Some(*pct),
                _ => None,
            })
            .collect()
    };
    fake.set(2500); // 75 %
    assert!(warnings(&s.tick().unwrap()).is_empty());
    fake.set(1500); // 85 %
    assert_eq!(warnings(&s.tick().unwrap()), [80]);
    assert!(
        warnings(&s.tick().unwrap()).is_empty(),
        "no repeat while still above"
    );
    fake.set(500); // 95 %
    assert_eq!(warnings(&s.tick().unwrap()), [90]);
    fake.set(6000);
    s.tick().unwrap();
    fake.set(1500);
    assert_eq!(
        warnings(&s.tick().unwrap()),
        [80],
        "crossing again warns again"
    );
    s.sync().unwrap();
    assert_eq!(of_type(&records(s.segment_dir()), "disk_warning").len(), 3);
}

#[test]
fn stop_mode_seals_records_a_gap_and_resumes() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000);
    let mut p = policy(OnFull::Stop);
    p.reserve_bytes = 4096;
    p.min_free_bytes = 900;
    let mut s = open(t.path(), p, &fake);
    assert!(
        s.disk_status().reserve_present,
        "reserve is preallocated at start"
    );
    s.append(rec("before")).unwrap();

    fake.set(800);
    let ev = s.tick().unwrap();
    assert!(ev.contains(&DiskEvent::GapStarted));
    assert_eq!(s.disk_status().state, DiskState::Stopped);
    assert!(
        !s.disk_status().reserve_present,
        "reserve released to write the gap"
    );

    // Everything is refused, and counted by priority.
    assert!(matches!(s.append(rec("x")), Err(StoreError::DiskFull)));
    assert!(!written(s.append_prio(Priority::P3, rec("x")).unwrap()));
    assert!(!written(s.append_prio(Priority::P1, rec("x")).unwrap()));

    // Not enough yet: needs min_free + reserve + hysteresis headroom.
    fake.set(1000);
    s.tick().unwrap();
    assert_eq!(s.disk_status().state, DiskState::Stopped);

    fake.set(9000);
    let ev = s.tick().unwrap();
    assert!(ev.contains(&DiskEvent::GapEnded {
        dropped: [1, 1, 0, 1]
    }));
    assert!(s.disk_status().reserve_present);
    s.append(rec("after")).unwrap();
    s.sync().unwrap();

    let r = records(s.segment_dir());
    let gaps = of_type(&r, "capture_gap");
    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0]["phase"], "start");
    assert_eq!(gaps[1]["phase"], "end");
    assert_eq!(gaps[1]["start_recorded"], true);
    assert_eq!(gaps[1]["dropped"], json!([1, 1, 0, 1]));
    // The stopped segment was sealed and the resumed capture opened a new one.
    assert!(segment::list_segments(s.segment_dir()).unwrap().len() >= 2);
    let report = verify_dir(s.segment_dir()).unwrap();
    assert!(report.is_ok(), "{:?}", report.broken);
}

#[test]
fn partial_write_is_rolled_back_and_p0_uses_the_reserve() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000);
    let mut p = policy(OnFull::Shed);
    p.reserve_bytes = 4096;
    let mut s = open(t.path(), p, &fake);
    s.append(rec("one")).unwrap();
    s.append(rec("two")).unwrap();

    s.inject_partial_write_failure(25); // a torn line hits the file, then ENOSPC
    let a = s.append_prio(Priority::P0, rec("critical")).unwrap();
    assert!(written(a), "P0 retries into the released reserve");
    assert!(!s.disk_status().reserve_present);
    assert_eq!(s.disk_status().state, DiskState::Shedding(3));
    s.append(rec("three")).unwrap();
    s.sync().unwrap();

    let report = verify_dir(s.segment_dir()).unwrap();
    assert!(
        report.is_ok(),
        "torn bytes must not survive: {:?}",
        report.broken
    );
    let r = records(s.segment_dir());
    assert_eq!(of_type(&r, "critical").len(), 1);
}

#[test]
fn partial_write_without_reserve_stops_capture_but_never_corrupts() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000);
    let mut s = open(t.path(), policy(OnFull::Shed), &fake); // reserve_bytes = 0
    s.append(rec("one")).unwrap();

    s.inject_partial_write_failure(30);
    let res = s.append(rec("critical"));
    assert!(matches!(res, Err(StoreError::DiskFull)));
    assert_eq!(s.disk_status().state, DiskState::Stopped);
    s.sync().unwrap();

    let report = verify_dir(s.segment_dir()).unwrap();
    assert!(report.is_ok(), "{:?}", report.broken);
    // A fresh open sees a clean tail (nothing torn to quarantine).
    drop(s);
    let (_, recov) = Store::open_with_probe(
        t.path(),
        Config {
            max_segment_bytes: 1 << 20,
            disk: policy(OnFull::Shed),
        },
        Box::new(fake.clone()),
    )
    .unwrap();
    assert!(recov.is_empty());
}

#[test]
fn failed_segment_open_leaves_no_empty_segment() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000);
    let mut s = open(t.path(), policy(OnFull::Shed), &fake);
    s.inject_partial_write_failure(5); // the very first record (segment_open) fails
    let _ = s.append(rec("first"));
    s.append(rec("second")).ok();
    s.sync().unwrap();
    for seg in segment::list_segments(s.segment_dir()).unwrap() {
        assert!(
            std::fs::metadata(&seg.path).unwrap().len() > 0,
            "empty segment left behind"
        );
    }
    let report = verify_dir(s.segment_dir()).unwrap();
    assert!(report.is_ok(), "{:?}", report.broken);
}

#[test]
fn compression_is_deferred_when_space_is_short() {
    let t = tempfile::tempdir().unwrap();
    let fake = Fake::new(9000);
    let mut s = open(t.path(), policy(OnFull::Shed), &fake);
    for i in 0..50 {
        let mut m = rec("e");
        m.insert("n".into(), json!(i));
        s.append(m).unwrap();
    }
    s.rotate().unwrap();
    fake.set(10);
    assert!(s.compress_sealed().unwrap().is_empty());
    assert!(segment::list_segments(s.segment_dir())
        .unwrap()
        .iter()
        .all(|x| !x.compressed));
    fake.set(9000);
    assert_eq!(s.compress_sealed().unwrap().len(), 1);
    assert!(verify_dir(s.segment_dir()).unwrap().is_ok());
}

#[test]
fn invalid_policy_is_rejected() {
    let t = tempfile::tempdir().unwrap();
    let mut p = policy(OnFull::Shed);
    p.warn_pcts = vec![90, 80];
    let cfg = Config {
        max_segment_bytes: 1000,
        disk: p,
    };
    assert!(Store::open_with_probe(t.path(), cfg, Box::new(Fake::new(1))).is_err());
}
