#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The baseline collector against a fabricated `/proc`, `/sys` and `/run`.

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::Path;

use serde_json::Value;
use witness_common::schema::{puid, Body};
use witnessd::baseline::{collect, Context, Roots};

const BOOT: &str = "4f2a9c1e-1111-2222-3333-444455556666";

fn w(p: &Path, text: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

/// A stat line: pid, comm, ppid, start ticks.
fn stat(pid: u32, comm: &str, ppid: u32, start: u64) -> String {
    format!("{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0 0")
}

#[allow(clippy::too_many_arguments)]
fn proc_entry(
    root: &Path,
    pid: u32,
    comm: &str,
    ppid: u32,
    start: u64,
    uid: u32,
    cmdline: &[&str],
    exe: Option<&str>,
) {
    let d = root.join("proc").join(pid.to_string());
    w(&d.join("stat"), &stat(pid, comm, ppid, start));
    w(
        &d.join("status"),
        &format!(
            "Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        ),
    );
    let mut raw = Vec::new();
    for a in cmdline {
        raw.extend_from_slice(a.as_bytes());
        raw.push(0);
    }
    fs::write(d.join("cmdline"), raw).unwrap();
    w(&d.join("comm"), &format!("{comm}\n"));
    if let Some(e) = exe {
        symlink(e, d.join("exe")).unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, Roots) {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    proc_entry(
        r,
        1,
        "systemd",
        0,
        100,
        0,
        &["/sbin/init", "splash"],
        Some("/usr/lib/systemd/systemd"),
    );
    proc_entry(r, 2, "kthreadd", 0, 100, 0, &[], None);
    proc_entry(r, 3, "rcu_gp", 2, 101, 0, &[], None);
    proc_entry(
        r,
        812,
        "sshd",
        1,
        5_000,
        0,
        &["/usr/sbin/sshd", "-D"],
        Some("/usr/sbin/sshd"),
    );
    proc_entry(
        r,
        4001,
        "bash",
        812,
        9_000_000,
        1000,
        &["-bash"],
        Some("/usr/bin/bash"),
    );
    w(&r.join("proc/4001/loginuid"), "1000\n");
    w(&r.join("proc/4001/sessionid"), "7\n");
    w(&r.join("proc/812/loginuid"), "4294967295\n");
    // sshd owns the listening socket with inode 5555
    fs::create_dir_all(r.join("proc/812/fd")).unwrap();
    symlink("socket:[5555]", r.join("proc/812/fd/3")).unwrap();
    symlink("/dev/null", r.join("proc/812/fd/0")).unwrap();
    let ip = |a: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(a));
    w(
        &r.join("proc/net/tcp"),
        &format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {}:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5555 1 0 100 0 0 10 0\n   1: {}:C350 {}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 6666 1 0 100 0 0 10 0\n",
            ip([0, 0, 0, 0]), ip([10, 0, 0, 5]), ip([93, 184, 216, 34])
        ),
    );
    w(
        &r.join("proc/net/udp"),
        &format!("  sl  local_address rem_address st\n   0: {}:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 7777 2 0 0\n", ip([127, 0, 0, 53])),
    );
    w(&r.join("proc/modules"), "e1000 155648 0 - Live 0xffffffffc0001000\nnf_tables 262144 12 nft_ct,nft_chain_nat, Live 0xffffffffc0100000\n");
    w(
        &r.join("proc/self/mountinfo"),
        "26 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n40 26 0:35 / /mnt/with\\040space rw - tmpfs tmpfs rw\n",
    );
    w(&r.join("run/systemd/sessions/7"), "UID=1000\nUSER=alice\nACTIVE=1\nSTATE=active\nREMOTE=1\nREMOTE_HOST=10.0.0.9\nSERVICE=sshd\nTTY=pts/0\nLEADER=4001\n");
    w(&r.join("run/systemd/sessions/7.ref"), "ignore\n");
    w(&r.join("sys/block/sda/size"), "2097152\n");
    w(&r.join("sys/block/sda/removable"), "1\n");
    w(&r.join("sys/block/sda/device/model"), "Flash Disk  \n");
    w(&r.join("sys/block/loop0/size"), "1\n");
    w(&r.join("sys/bus/usb/devices/1-1/idVendor"), "0781\n");
    w(&r.join("sys/bus/usb/devices/1-1/idProduct"), "5567\n");
    w(&r.join("sys/bus/usb/devices/1-1/serial"), "AA0123\n");
    w(&r.join("sys/bus/usb/devices/usb1/bDeviceClass"), "09\n"); // a hub without idVendor: skipped
    let roots = Roots {
        proc_: r.join("proc"),
        sys: r.join("sys"),
        run: r.join("run"),
    };
    (t, roots)
}

fn ctx(gap_from: Option<u64>) -> Context {
    Context {
        boot_id: BOOT.into(),
        boot_ns: 123,
        wall_ns: 456,
        gap_from_boot_ns: gap_from,
    }
}

fn items(events: &[witness_common::schema::Event], kind: &str) -> Vec<Value> {
    events
        .iter()
        .filter_map(|e| match &e.body {
            Body::Baseline(b) if b.item == kind => Some(serde_json::json!({
                "detail": b.detail, "gap": b.discovered_in_gap,
                "actor": e.actor.as_ref().map(|a| serde_json::to_value(a).unwrap()),
            })),
            _ => None,
        })
        .collect()
}

#[test]
fn processes_carry_identity_ownership_and_the_tree() {
    let (_t, roots) = fixture();
    let ev = collect(&roots, &ctx(None));
    let procs = items(&ev, "process");
    assert_eq!(procs.len(), 5);

    let bash = procs.iter().find(|p| p["actor"]["pid"] == 4001).unwrap();
    assert_eq!(bash["actor"]["uid"], 1000);
    assert_eq!(bash["actor"]["auid"], 1000);
    assert_eq!(bash["actor"]["ses"], 7);
    assert_eq!(bash["actor"]["comm"], "bash");
    assert_eq!(bash["actor"]["exe"], "/usr/bin/bash");
    // Identity matches what the live path would compute from the exact kernel start time.
    let start_ns = 9_000_000u64 * 10_000_000;
    assert_eq!(
        bash["actor"]["puid"],
        puid(BOOT, 4001, start_ns + 1_234_567)
    );
    assert_eq!(
        bash["detail"]["parent_puid"],
        puid(BOOT, 812, 5_000 * 10_000_000)
    );

    // Unset login uid (-1) is "none", not a huge number.
    let sshd = procs.iter().find(|p| p["actor"]["pid"] == 812).unwrap();
    assert!(sshd["actor"].get("auid").is_none());
    assert_eq!(
        sshd["actor"]["cmdline"],
        serde_json::json!(["/usr/sbin/sshd", "-D"])
    );

    // Kernel threads are flagged, user processes are not.
    let flag = |pid: u64| {
        procs.iter().find(|p| p["actor"]["pid"] == pid).unwrap()["detail"]["kernel_thread"].clone()
    };
    assert_eq!(
        (flag(2), flag(3), flag(812), flag(1)),
        (true.into(), true.into(), false.into(), false.into())
    );
}

#[test]
fn processes_started_during_a_gap_are_marked() {
    let (_t, roots) = fixture();
    // Gap began at 1 s after boot (= 100 ticks); only bash (start 9_000_000 ticks) is later.
    let ev = collect(&roots, &ctx(Some(6_000 * 10_000_000)));
    let procs = items(&ev, "process");
    let in_gap: Vec<u64> = procs
        .iter()
        .filter(|p| p["gap"] == true)
        .map(|p| p["actor"]["pid"].as_u64().unwrap())
        .collect();
    assert_eq!(in_gap, vec![4001]);
}

#[test]
fn listening_sockets_are_attributed_to_their_process() {
    let (_t, roots) = fixture();
    let socks = items(&collect(&roots, &ctx(None)), "listen_socket");
    assert_eq!(
        socks.len(),
        2,
        "the established connection (state 01) is not a listener"
    );
    let ssh = socks.iter().find(|s| s["detail"]["port"] == 22).unwrap();
    assert_eq!(ssh["detail"]["proto"], "tcp");
    assert_eq!(ssh["detail"]["addr"], Ipv4Addr::UNSPECIFIED.to_string());
    assert_eq!(ssh["detail"]["pid"], 812);
    assert_eq!(ssh["detail"]["comm"], "sshd");
    let dns = socks.iter().find(|s| s["detail"]["port"] == 53).unwrap();
    assert_eq!(dns["detail"]["proto"], "udp");
    assert!(
        dns["detail"]["pid"].is_null(),
        "no process holds inode 7777 in the fixture"
    );
}

#[test]
fn sessions_modules_mounts_and_devices() {
    let (_t, roots) = fixture();
    let ev = collect(&roots, &ctx(None));

    let s = items(&ev, "session");
    assert_eq!(s.len(), 1, "the .ref bookkeeping file is skipped");
    assert_eq!(s[0]["detail"]["user"], "alice");
    assert_eq!(s[0]["detail"]["remote_host"], "10.0.0.9");

    let m = items(&ev, "module");
    assert_eq!(m.len(), 2);
    assert_eq!(
        m[1]["detail"]["used_by"],
        serde_json::json!(["nft_ct", "nft_chain_nat"])
    );
    assert_eq!(m[0]["detail"]["used_by"], serde_json::json!([]));

    let mt = items(&ev, "mount");
    assert_eq!(mt.len(), 2);
    assert_eq!(mt[1]["detail"]["mount_point"], "/mnt/with space");
    assert_eq!(mt[0]["detail"]["fstype"], "ext4");

    let b = items(&ev, "block_device");
    assert_eq!(b.len(), 1, "loop devices are skipped");
    assert_eq!(b[0]["detail"]["size_bytes"], 2_097_152u64 * 512);
    assert_eq!(b[0]["detail"]["removable"], true);
    assert_eq!(b[0]["detail"]["model"], "Flash Disk");

    let u = items(&ev, "usb_device");
    assert_eq!(
        u.len(),
        1,
        "entries without idVendor (root hubs) are skipped"
    );
    assert_eq!(u[0]["detail"]["vendor_id"], "0781");
    assert_eq!(u[0]["detail"]["serial"], "AA0123");
}

#[test]
fn the_summary_closes_the_snapshot_with_counts() {
    let (_t, roots) = fixture();
    let ev = collect(&roots, &ctx(None));
    let last = ev.last().unwrap();
    let Body::Baseline(b) = &last.body else {
        panic!()
    };
    assert_eq!(b.item, "summary");
    assert_eq!(b.detail["processes"], 5);
    assert_eq!(b.detail["listen_sockets"], 2);
    assert_eq!(b.detail["usb_devices"], 1);
    // Every record is a baseline-sourced, never-shed (P0) event.
    assert!(ev
        .iter()
        .all(|e| e.src == witness_common::schema::Source::Baseline && e.prio == 0));
}

#[test]
fn a_missing_tree_yields_just_the_summary() {
    let t = tempfile::tempdir().unwrap();
    let roots = Roots {
        proc_: t.path().join("nope/proc"),
        sys: t.path().join("nope/sys"),
        run: t.path().join("nope/run"),
    };
    let ev = collect(&roots, &ctx(None));
    assert_eq!(ev.len(), 1);
}
