#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real-kernel tests: they start `witnessd tail` as root, generate activity, and assert on
//! the events the eBPF programs produced. Run privileged (see CLAUDE.md):
//!
//! ```sh
//! cargo test -p witnessd --test integration --no-run
//! sudo target/debug/deps/integration-<hash> --ignored --test-threads=1 --nocapture
//! ```

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Stdio};

use serde_json::Value;

/// Runs the daemon for `seconds`, calls `activity` once it is attached, returns all events.
fn capture(seconds: u32, activity: impl FnOnce()) -> (Vec<Value>, u32) {
    assert!(
        rustix::process::geteuid().is_root(),
        "these tests load eBPF: run them with sudo"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_witnessd"))
        .args(["tail", "--seconds", &seconds.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon_pid = child.id();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            err.read_line(&mut line).unwrap() > 0,
            "daemon exited before attaching"
        );
        if line.contains("attached") {
            break;
        }
        assert!(!line.contains("error"), "{line}");
    }
    activity();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "daemon failed");
    let events = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (events, daemon_pid)
}

fn argv(e: &Value) -> Vec<String> {
    e["data"]["argv"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn find_exec<'a>(events: &'a [Value], marker: &str) -> &'a Value {
    events
        .iter()
        .find(|e| e["type"] == "proc_exec" && argv(e).iter().any(|a| a.contains(marker)))
        .unwrap_or_else(|| panic!("no exec event mentioning {marker}"))
}

#[test]
#[ignore = "needs root and a kernel with BTF"]
fn exec_fork_exit_are_captured_and_linked() {
    let marker = format!("witness-it-{}", std::process::id());
    let m = marker.clone();
    let (events, _) = capture(6, move || {
        let st = Command::new("/bin/sh")
            .args(["-c", &format!("exit 7 # {m}")])
            .status()
            .unwrap();
        assert_eq!(st.code(), Some(7));
    });

    let exec = find_exec(&events, &marker);
    let puid = exec["actor"]["puid"].as_str().unwrap();
    assert_eq!(exec["actor"]["ppid"], std::process::id());
    assert_eq!(exec["actor"]["uid"], 0, "the test runs as root");
    assert!(exec["actor"]["exe"].as_str().unwrap().ends_with("sh"));
    assert!(exec["actor"]["cgroup_id"].as_u64().unwrap() > 0);

    // The fork that created it names the same process identity.
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "proc_fork" && e["data"]["child_puid"] == puid),
        "no fork event for {puid}"
    );
    // And its exit carries the exit code and the same identity.
    let exit = events
        .iter()
        .find(|e| e["type"] == "proc_exit" && e["actor"]["puid"] == puid)
        .expect("no exit event");
    assert_eq!(exit["data"]["exit_code"], 7);
    assert!(exit["data"]["runtime_ns"].as_u64().unwrap() > 0);
    // Ordering by kernel time: fork < exec < exit.
    let t = |k: &str| -> u64 {
        events
            .iter()
            .find(|e| {
                e["type"] == k && (e["actor"]["puid"] == puid || e["data"]["child_puid"] == puid)
            })
            .unwrap()["boot_ns"]
            .as_u64()
            .unwrap()
    };
    assert!(t("proc_fork") <= t("proc_exec") && t("proc_exec") <= t("proc_exit"));
}

#[test]
#[ignore = "needs root and a kernel with BTF"]
fn signals_and_long_and_binary_arguments() {
    let marker = format!("witness-sig-{}", std::process::id());
    let (m1, m2) = (marker.clone(), marker.clone());
    let (events, _) = capture(6, move || {
        // Killed by a signal.
        let st = Command::new("/bin/sh")
            .args(["-c", &format!("kill -9 $$ # {m1}")])
            .status()
            .unwrap();
        assert!(!st.success());
        // Argument far larger than the capture cap, plus a non-UTF-8 argument.
        let long = format!("{m2}-{}", "x".repeat(8000));
        Command::new("/bin/true")
            .arg(&long)
            .arg(OsString::from_vec(vec![b'b', 0xff, 0xfe]))
            .status()
            .unwrap();
    });

    let killed = find_exec(&events, &format!("kill -9 $$ # {marker}"));
    let kp = killed["actor"]["puid"].as_str().unwrap();
    let exit = events
        .iter()
        .find(|e| e["type"] == "proc_exit" && e["actor"]["puid"] == kp)
        .unwrap();
    assert_eq!(exit["data"]["signal"], 9);
    assert!(exit["data"].get("exit_code").is_none());

    let long = events
        .iter()
        .find(|e| {
            e["type"] == "proc_exec"
                && e["data"]["argv"].as_array().is_some_and(|a| {
                    a.iter().any(|x| {
                        x.as_str()
                            .is_some_and(|s| s.starts_with(&format!("{marker}-xx")))
                    })
                })
        })
        .expect("long-argument exec not captured");
    assert_eq!(
        long["data"]["argv_truncated"], true,
        "8 KB of arguments exceeds the cap"
    );
}

#[test]
#[ignore = "needs root and a kernel with BTF"]
fn the_daemons_own_processes_are_not_recorded() {
    let (events, daemon_pid) = capture(5, || {
        Command::new("/bin/true").status().unwrap();
    });
    assert!(
        events.iter().any(|e| e["type"] == "proc_exec"),
        "sanity: something was captured"
    );
    assert!(
        events.iter().all(|e| e["actor"]["pid"] != daemon_pid),
        "self-exclusion failed: the daemon's own activity was recorded"
    );
}

#[test]
#[ignore = "needs root and a kernel with BTF"]
fn a_burst_of_processes_loses_nothing() {
    let marker = format!("witness-burst-{}", std::process::id());
    let m = marker.clone();
    let (events, _) = capture(8, move || {
        let st = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("i=0; while [ $i -lt 500 ]; do /bin/true {m}; i=$((i+1)); done"),
            ])
            .status()
            .unwrap();
        assert!(st.success());
    });
    let execs = events
        .iter()
        .filter(|e| e["type"] == "proc_exec" && argv(e).iter().any(|a| a == &marker))
        .count();
    assert_eq!(execs, 500, "every one of 500 execs must be captured");
}
