#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use witness_common::schema::*;
use witness_store::anchor::{read_anchors, AnchorSink, FileSink};
use witness_store::disk::DiskPolicy;
use witness_store::index::{Filter, Index};
use witness_store::seal::SealState;
use witness_store::segment;
use witness_store::verify::{verify_with, Options};
use witness_store::Config;
use witnessd::pipeline::{Clock, Pipeline, Settings};

const BOOT_A: &str = "aaaaaaaa-0000-0000-0000-000000000000";
const BOOT_B: &str = "bbbbbbbb-0000-0000-0000-000000000000";

#[derive(Clone)]
struct Fake(Arc<AtomicU64>); // milliseconds since start

impl Fake {
    fn new() -> Self {
        Fake(Arc::new(AtomicU64::new(0)))
    }
    fn advance(&self, d: Duration) {
        self.0.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
    fn ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Clock for Fake {
    fn boot_ns(&self) -> u64 {
        5_000_000_000_000 + self.ms() * 1_000_000
    }
    fn wall_ns(&self) -> u64 {
        1_700_000_000_000_000_000 + self.ms() * 1_000_000
    }
    fn mono(&self) -> Duration {
        Duration::from_millis(self.ms())
    }
}

fn settings(boot: &str, sealing: bool) -> Settings {
    Settings {
        boot_id: boot.into(),
        version: "test".into(),
        kernel: "5.15.0-test".into(),
        btf: true,
        pid: 4242,
        config_sha256: "c0".repeat(32),
        bpf_object_sha256: "b0".repeat(32),
        group_commit: Duration::from_millis(500),
        anchor_interval: Duration::from_secs(60),
        seal_interval: Duration::from_secs(60),
        sealing,
    }
}

fn cfg() -> Config {
    Config {
        max_segment_bytes: 1 << 20,
        disk: DiskPolicy::disabled(),
    }
}

fn open(
    dir: &Path,
    boot: &str,
    sealing: bool,
    clock: &Fake,
    sinks: Vec<Box<dyn AnchorSink>>,
) -> Pipeline {
    Pipeline::open(
        dir,
        cfg(),
        sinks,
        settings(boot, sealing),
        Box::new(clock.clone()),
    )
    .unwrap()
}

fn records(dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    for s in segment::list_segments(&dir.join("segments")).unwrap() {
        for l in segment::open_reader(&s).unwrap().lines() {
            out.push(serde_json::from_str(&l.unwrap()).unwrap());
        }
    }
    out
}

fn types(r: &[Value]) -> Vec<String> {
    r.iter()
        .map(|v| v["type"].as_str().unwrap().to_string())
        .collect()
}

fn exec_event(clock: &Fake, pid: u32, prio_body: bool) -> Event {
    let exec = ProcExec {
        filename: "/bin/true".into(),
        exe: "/bin/true".into(),
        argv: vec!["true".into(), format!("job-{pid}").as_str().into()],
        argv_truncated: false,
        cwd: None,
        env: None,
        stdio: None,
        interactive: false,
    };
    let body = if prio_body {
        Body::ProcExec(exec)
    } else {
        Body::FileActivitySummary(FileActivitySummary {
            dir: "/tmp".into(),
            opens_for_write: 3,
            creates: 1,
            deletes: 0,
            interval_ns: 1,
        })
    };
    Event {
        v: SCHEMA_VERSION,
        seq: 0,
        boot_id: BOOT_A.into(),
        boot_ns: clock.boot_ns(),
        wall_ns: clock.wall_ns(),
        wall_uncertain: false,
        src: Source::Ebpf,
        prio: body.priority() as u8,
        actor: Some(Actor {
            puid: puid(BOOT_A, pid, 1),
            pid,
            tid: pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            user: None,
            auid: None,
            ses: None,
            cgroup_id: 1,
            comm: "true".into(),
            exe: Some("/bin/true".into()),
            cmdline: Some(vec!["true".into(), format!("job-{pid}").as_str().into()]),
            tty: None,
        }),
        body,
        h: None,
    }
}

fn verify(dir: &Path) {
    let r = verify_with(&dir.join("segments"), &Options::default()).unwrap();
    assert!(r.is_ok(), "{:?}", r.broken);
}

#[test]
fn first_start_and_clean_stop() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let p = open(t.path(), BOOT_A, false, &clock, vec![]);
    clock.advance(Duration::from_secs(2));
    p.stop("sigterm", Some(15)).unwrap();

    let r = records(t.path());
    assert_eq!(
        types(&r),
        [
            "segment_open",
            "daemon_start",
            "anchor",
            "daemon_stop",
            "segment_seal"
        ]
    );
    assert_eq!(r[1]["data"]["prev_shutdown"], "none");
    assert_eq!(r[1]["data"]["kernel"], "5.15.0-test");
    assert_eq!(r[3]["data"]["clean"], true);
    assert_eq!(r[3]["data"]["signal"], 15);
    assert!(
        !types(&r).contains(&"capture_gap".to_string()),
        "no gap on a first start"
    );
    verify(t.path());
}

#[test]
fn clean_restart_records_the_gap() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    open(t.path(), BOOT_A, false, &clock, vec![])
        .stop("sigterm", None)
        .unwrap();
    let stopped_at = clock.wall_ns();
    clock.advance(Duration::from_secs(30));
    let p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.stop("sigterm", None).unwrap();

    let r = records(t.path());
    let gap = r.iter().find(|v| v["type"] == "capture_gap").unwrap();
    assert_eq!(gap["data"]["kind"], "restart_same_boot");
    assert_eq!(gap["data"]["prev_shutdown"], "clean");
    assert!(gap["data"]["from_wall_ns"].as_u64().unwrap() >= stopped_at);
    assert!(
        gap["data"]["to_wall_ns"].as_u64().unwrap() > gap["data"]["from_wall_ns"].as_u64().unwrap()
    );
    // Each run seals its own segment, so the second start opens a fresh one.
    assert_eq!(
        segment::list_segments(&t.path().join("segments"))
            .unwrap()
            .len(),
        2
    );
    verify(t.path());
}

#[test]
fn crash_is_detected_and_the_gap_starts_at_the_last_event() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let mut p = open(t.path(), BOOT_A, false, &clock, vec![]);
    for pid in 1..=5 {
        clock.advance(Duration::from_millis(100));
        p.ingest(&exec_event(&clock, pid, true)).unwrap();
    }
    let last_event_wall = clock.wall_ns();
    drop(p); // killed: no daemon_stop, no seal

    clock.advance(Duration::from_secs(10));
    let p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.stop("sigterm", None).unwrap();

    let r = records(t.path());
    let gap = r.iter().find(|v| v["type"] == "capture_gap").unwrap();
    assert_eq!(gap["data"]["prev_shutdown"], "unclean");
    assert_eq!(gap["data"]["kind"], "restart_same_boot");
    assert_eq!(gap["data"]["from_wall_ns"], last_event_wall);
    let starts: Vec<_> = r.iter().filter(|v| v["type"] == "daemon_start").collect();
    assert_eq!(starts[1]["data"]["prev_shutdown"], "unclean");
    verify(t.path());
}

#[test]
fn a_reboot_is_a_new_boot_gap() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let mut p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.ingest(&exec_event(&clock, 1, true)).unwrap();
    drop(p);
    let p = open(t.path(), BOOT_B, false, &clock, vec![]);
    p.stop("sigterm", None).unwrap();
    let r = records(t.path());
    let gap = r.iter().find(|v| v["type"] == "capture_gap").unwrap();
    assert_eq!(gap["data"]["kind"], "new_boot");
    assert!(
        gap["data"]["from_boot_ns"].is_null(),
        "boot clocks are not comparable across boots"
    );
    verify(t.path());
}

#[test]
fn a_torn_tail_is_repaired_and_recorded() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let mut p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.ingest(&exec_event(&clock, 1, true)).unwrap();
    drop(p);
    // A crash mid-write leaves half a line.
    let seg = segment::list_segments(&t.path().join("segments"))
        .unwrap()
        .pop()
        .unwrap();
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&seg.path)
        .unwrap()
        .write_all(br#"{"v":1,"seq":99,"type":"proc_ex"#)
        .unwrap();

    let p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.stop("sigterm", None).unwrap();
    let r = records(t.path());
    let rec = r
        .iter()
        .find(|v| v["type"] == "recovery")
        .expect("recovery recorded");
    assert!(rec["data"]["bytes"].as_u64().unwrap() > 10);
    assert!(Path::new(rec["data"]["quarantined_to"].as_str().unwrap()).exists());
    verify(t.path());
}

#[test]
fn events_are_stored_indexed_and_searchable() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let mut p = open(t.path(), BOOT_A, false, &clock, vec![]);
    for pid in 1..=200 {
        clock.advance(Duration::from_millis(10));
        p.ingest(&exec_event(&clock, pid, pid % 5 != 0)).unwrap();
        p.tick().unwrap();
    }
    assert_eq!(p.stats.ingested, 200);
    p.stop("sigterm", None).unwrap();
    verify(t.path());

    let mut ix = Index::open(&t.path().join("index.db")).unwrap();
    ix.catch_up(&t.path().join("segments")).unwrap();
    let f = |f: Filter| ix.query(&Filter { limit: 1000, ..f }).unwrap();
    assert_eq!(
        f(Filter {
            kinds: vec!["proc_exec".into()],
            ..Default::default()
        })
        .len(),
        160
    );
    assert_eq!(
        f(Filter {
            kinds: vec!["file_activity_summary".into()],
            ..Default::default()
        })
        .len(),
        40
    );
    assert_eq!(
        f(Filter {
            text: Some("job-77".into()),
            ..Default::default()
        })
        .len(),
        1
    );
    assert_eq!(
        f(Filter {
            pid: Some(150),
            ..Default::default()
        })
        .len(),
        1
    );
}

#[test]
fn kernel_ring_drops_are_recorded() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let mut p = open(t.path(), BOOT_A, false, &clock, vec![]);
    p.kernel_drops(17, 100, 200).unwrap();
    assert_eq!(p.stats.kernel_drops, 17);
    p.stop("sigterm", None).unwrap();
    let r = records(t.path());
    let d = r.iter().find(|v| v["type"] == "capture_drop").unwrap();
    assert_eq!(d["data"]["dropped"], serde_json::json!([17, 0, 0, 0]));
    assert_eq!(d["data"]["reason"], "ring_overflow");
    verify(t.path());
}

#[test]
fn anchors_and_seals_follow_their_schedules() {
    let t = tempfile::tempdir().unwrap();
    let k0 = SealState::init(&t.path().join("seal.key")).unwrap();
    let anchors = t.path().join("anchors.log");
    let clock = Fake::new();
    let mut p = open(
        t.path(),
        BOOT_A,
        true,
        &clock,
        vec![Box::new(FileSink::new(&anchors))],
    );
    for minute in 0..3 {
        for pid in 0..10 {
            clock.advance(Duration::from_secs(5));
            p.ingest(&exec_event(&clock, minute * 100 + pid, true))
                .unwrap();
            p.tick().unwrap();
        }
        clock.advance(Duration::from_secs(11));
        p.tick().unwrap();
    }
    p.stop("sigterm", None).unwrap();

    let r = records(t.path());
    let seals = r.iter().filter(|v| v["type"] == "seal").count();
    let anchors_in_chain = r.iter().filter(|v| v["type"] == "anchor").count();
    assert!(
        seals >= 3,
        "a seal about every 60 s plus the final one, got {seals}"
    );
    assert!(anchors_in_chain >= 3);

    // The whole chain verifies with the verification key, and the published anchors agree.
    let opts = Options {
        seal_key: Some(k0),
        anchors: read_anchors(&anchors).unwrap(),
        require_seals: true,
        ..Default::default()
    };
    let rep = verify_with(&t.path().join("segments"), &opts).unwrap();
    assert!(rep.is_ok(), "{:?}", rep.broken);
    assert!(rep.macs_checked);
    assert_eq!(rep.anchors_checked as usize, anchors_in_chain);
}

#[test]
fn restart_with_sealing_continues_the_epochs() {
    let t = tempfile::tempdir().unwrap();
    let k0 = SealState::init(&t.path().join("seal.key")).unwrap();
    let clock = Fake::new();
    open(t.path(), BOOT_A, true, &clock, vec![])
        .stop("sigterm", None)
        .unwrap();
    clock.advance(Duration::from_secs(5));
    open(t.path(), BOOT_A, true, &clock, vec![])
        .stop("sigterm", None)
        .unwrap();
    let opts = Options {
        seal_key: Some(k0),
        ..Default::default()
    };
    let rep = verify_with(&t.path().join("segments"), &opts).unwrap();
    assert!(rep.is_ok(), "{:?}", rep.broken);
    assert_eq!(rep.last_seal_epoch, Some(2));
}

#[test]
fn sealing_without_a_key_refuses_to_start() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let e = Pipeline::open(
        t.path(),
        cfg(),
        vec![],
        settings(BOOT_A, true),
        Box::new(clock),
    )
    .err()
    .expect("must fail");
    assert!(format!("{e:#}").contains("witness init --seal"), "{e:#}");
}

#[test]
fn a_second_daemon_is_refused_with_a_clear_message() {
    let t = tempfile::tempdir().unwrap();
    let clock = Fake::new();
    let _first = open(t.path(), BOOT_A, false, &clock, vec![]);
    let e = Pipeline::open(
        t.path(),
        cfg(),
        vec![],
        settings(BOOT_A, false),
        Box::new(clock),
    )
    .err()
    .expect("must fail");
    assert!(format!("{e:#}").contains("another witnessd"), "{e:#}");
}
