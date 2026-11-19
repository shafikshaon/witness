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
    // 8 KB is over one record's 3 KiB, but the kernel sends the rest as continuation chunks,
    // so the command line arrives whole. (`argv_truncated` is omitted when false.)
    assert!(
        !long["data"]["argv_truncated"].as_bool().unwrap_or(false),
        "an 8 KB command line must not be truncated: {long:?}"
    );
    let arg = long["data"]["argv"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .find(|s| s.starts_with(&format!("{marker}-xx")))
        })
        .unwrap();
    assert!(
        arg.len() >= 8000,
        "the argument arrived in full: {} bytes",
        arg.len()
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

// ---- the daemon with the tamper-evident store ------------------------------------------

mod store_mode {
    use std::io::BufRead;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    use serde_json::Value;
    use witness_common::schema::{Body, Event};
    use witness_store::index::{Filter, Index};
    use witness_store::segment;
    use witness_store::verify::{verify_with, Options};

    // The child is handed to the caller, which always waits on or kills it.
    #[allow(clippy::zombie_processes)]
    pub(super) fn spawn(
        data: &Path,
        seconds: u32,
    ) -> (Child, std::io::BufReader<std::process::ChildStderr>) {
        spawn_cfg(data, seconds, Path::new("/nonexistent/witness.toml"))
    }

    // The child is handed to the caller, which always waits on or kills it.
    #[allow(clippy::zombie_processes)]
    pub(super) fn spawn_cfg(
        data: &Path,
        seconds: u32,
        config: &Path,
    ) -> (Child, std::io::BufReader<std::process::ChildStderr>) {
        assert!(rustix::process::geteuid().is_root(), "run with sudo");
        let mut child = Command::new(env!("CARGO_BIN_EXE_witnessd"))
            .args(["run", "--config"])
            .arg(config)
            .arg("--data-dir")
            .arg(data)
            .args(["--seconds", &seconds.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut err = std::io::BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                err.read_line(&mut line).unwrap() > 0,
                "daemon exited before attaching"
            );
            if line.contains("attached") {
                return (child, err);
            }
        }
    }

    pub(super) fn records(data: &Path) -> Vec<Value> {
        let mut out = Vec::new();
        for s in segment::list_segments(&data.join("segments")).unwrap() {
            for l in segment::open_reader(&s).unwrap().lines() {
                out.push(serde_json::from_str(&l.unwrap()).unwrap());
            }
        }
        out
    }

    pub(super) fn verify(data: &Path) {
        let r = verify_with(&data.join("segments"), &Options::default()).unwrap();
        assert!(r.is_ok(), "chain broken: {:?}", r.broken);
    }

    fn run_marker(marker: &str) {
        Command::new("/bin/true").arg(marker).status().unwrap();
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn captured_activity_lands_in_a_verifiable_chain_and_the_index() {
        let t = tempfile::tempdir().unwrap();
        let marker = format!("witness-store-{}", std::process::id());
        let (child, _err) = spawn(t.path(), 5);
        run_marker(&marker);
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());

        verify(t.path());
        let recs = records(t.path());
        let kinds: Vec<&str> = recs.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"daemon_start") && kinds.contains(&"daemon_stop"));
        assert_eq!(recs.last().unwrap()["type"], "segment_seal");

        // Searchable through the index the daemon maintained.
        let mut ix = Index::open(&t.path().join("index.db")).unwrap();
        ix.catch_up(&t.path().join("segments")).unwrap();
        let hits = ix
            .query(&Filter {
                text: Some(marker.clone()),
                kinds: vec!["proc_exec".into()],
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1, "exactly the one exec carries the marker");
        assert_eq!(hits[0].kind, "proc_exec");

        // And the stored line deserializes back into the typed schema.
        let raw = ix.raw(&t.path().join("segments"), hits[0].seq).unwrap();
        let ev: Event = serde_json::from_slice(&raw).unwrap();
        let Body::ProcExec(x) = ev.body else {
            panic!("not an exec")
        };
        assert!(x.argv.iter().any(|a| a.to_string_lossy() == marker));
        assert_eq!(ev.actor.unwrap().uid, 0);
    }

    fn baseline_items<'a>(recs: &'a [Value], kind: &str) -> Vec<&'a Value> {
        recs.iter()
            .filter(|v| v["type"] == "baseline" && v["data"]["item"] == kind)
            .collect()
    }

    /// The point of the baseline: a process that existed *before* the daemon started is
    /// described, and when it later exits, the live event names it with the same identity.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_preexisting_process_keeps_one_identity_from_baseline_to_exit() {
        let t = tempfile::tempdir().unwrap();
        let mut old = Command::new("/bin/sleep").arg("300").spawn().unwrap();
        let old_pid = old.id();
        std::thread::sleep(std::time::Duration::from_millis(300));

        let (child, _err) = spawn(t.path(), 6);
        std::thread::sleep(std::time::Duration::from_millis(1500)); // baseline is stored
        old.kill().unwrap();
        old.wait().unwrap();
        assert!(child.wait_with_output().unwrap().status.success());

        let recs = records(t.path());
        let base = baseline_items(&recs, "process")
            .into_iter()
            .find(|v| v["actor"]["pid"] == old_pid)
            .expect("the pre-existing sleep must be in the baseline");
        assert_eq!(base["actor"]["comm"], "sleep");
        assert_eq!(base["actor"]["cmdline"][1], "300");
        assert_eq!(base["actor"]["uid"], 0);
        let puid = base["actor"]["puid"].as_str().unwrap();
        // Its parent (this test process) is described with the identity the tree points at.
        let parent = baseline_items(&recs, "process")
            .into_iter()
            .find(|v| v["actor"]["pid"] == std::process::id())
            .expect("the parent is in the baseline");
        assert_eq!(
            base["data"]["detail"]["parent_puid"],
            parent["actor"]["puid"]
        );

        let exit = recs
            .iter()
            .find(|v| v["type"] == "proc_exit" && v["actor"]["pid"] == old_pid)
            .expect("the live exit must be captured");
        assert_eq!(exit["data"]["signal"], 9);
        assert_eq!(
            exit["actor"]["puid"], puid,
            "baseline and live capture must name the same process identically"
        );
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn the_baseline_describes_the_running_system() {
        let t = tempfile::tempdir().unwrap();
        let (child, _err) = spawn(t.path(), 4);
        assert!(child.wait_with_output().unwrap().status.success());
        let recs = records(t.path());

        let procs = baseline_items(&recs, "process");
        assert!(
            procs.len() > 10,
            "a running system has many processes, got {}",
            procs.len()
        );
        let init = procs
            .iter()
            .find(|v| v["actor"]["pid"] == 1)
            .expect("pid 1");
        assert!(
            init["actor"]["comm"].as_str().unwrap().contains("systemd")
                || init["actor"]["comm"] == "init"
        );
        assert!(
            procs
                .iter()
                .any(|v| v["data"]["detail"]["kernel_thread"] == true),
            "kernel threads are flagged"
        );
        let mounts = baseline_items(&recs, "mount");
        assert!(mounts
            .iter()
            .any(|v| v["data"]["detail"]["mount_point"] == "/"));
        assert!(
            !baseline_items(&recs, "module").is_empty(),
            "loaded kernel modules"
        );

        let summary = baseline_items(&recs, "summary");
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0]["data"]["detail"]["processes"], procs.len());
        // The summary closes the snapshot: it comes after every baseline process record.
        let pos = |v: &Value| v["seq"].as_u64().unwrap();
        assert!(procs.iter().all(|p| pos(p) < pos(summary[0])));
        verify(t.path());
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn sigterm_is_a_clean_stop() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 60);
        run_marker("witness-term");
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "SIGTERM must exit 0 after a clean stop, got {status}"
        );
        verify(t.path());
        let recs = records(t.path());
        let stop = recs.iter().find(|v| v["type"] == "daemon_stop").unwrap();
        assert_eq!(stop["data"]["clean"], true);
        assert_eq!(stop["data"]["reason"], "signal");
    }

    /// SIGTERM can land anywhere in the loop, including inside `poll()` (EINTR). Every stop,
    /// whenever the signal arrives, must exit 0 with a clean `signal` stop record.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn sigterm_at_any_moment_is_a_clean_stop() {
        for delay_ms in [0u64, 20, 70, 130, 210, 333] {
            let t = tempfile::tempdir().unwrap();
            let (mut child, mut err) = spawn(t.path(), 60);
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            let started = std::time::Instant::now();
            let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
            rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
            let status = child.wait().unwrap();
            let took = started.elapsed();
            let mut log = String::new();
            let _ = std::io::Read::read_to_string(&mut err, &mut log);
            assert!(
                status.success(),
                "delay {delay_ms} ms: exit {status}\n{log}"
            );
            assert!(
                took < std::time::Duration::from_secs(5),
                "delay {delay_ms} ms: took {took:?} to stop after SIGTERM\n{log}"
            );
            let recs = records(t.path());
            let stop = recs.iter().find(|v| v["type"] == "daemon_stop").unwrap();
            assert_eq!(
                stop["data"]["reason"], "signal",
                "delay {delay_ms} ms\n{log}"
            );
            verify(t.path());
        }
    }

    /// SIGTERM sent while the daemon is still starting (before it has attached) must not
    /// be lost and must not kill it ungracefully: it finishes starting, then stops cleanly.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn sigterm_during_startup_is_not_lost() {
        for delay_ms in [0u64, 5, 15, 30, 50, 80, 110, 150] {
            let t = tempfile::tempdir().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_witnessd"))
                .args(["run", "--config", "/nonexistent/witness.toml", "--data-dir"])
                .arg(t.path())
                .args(["--seconds", "60"])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
            rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
            let started = std::time::Instant::now();
            let out = child.wait_with_output().unwrap();
            let log = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() {
                // The only acceptable failure: killed before `main` could block the signal
                // (exec / loader / runtime init). Nothing has been written at that point.
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(
                    out.status.signal(),
                    Some(15),
                    "delay {delay_ms} ms: {}\n{log}",
                    out.status
                );
                assert!(
                    !t.path().join("segments").exists() || records(t.path()).is_empty(),
                    "delay {delay_ms} ms: killed after it had started writing\n{log}"
                );
                continue;
            }
            // A stop during startup waits for the kernel verifier jobs already in flight (they
            // cannot be interrupted): about 2-4 s on an idle machine, around 30 s when the CPUs
            // are saturated (reproduced with six busy loops on four CPUs). This bound only
            // catches a hang; the property under test is that the signal is not lost.
            assert!(
                started.elapsed() < std::time::Duration::from_secs(45),
                "delay {delay_ms} ms: slow stop\n{log}"
            );
            let recs = records(t.path());
            let stop = recs
                .iter()
                .find(|v| v["type"] == "daemon_stop")
                .unwrap_or_else(|| panic!("delay {delay_ms} ms: no daemon_stop record\n{log}"));
            assert_eq!(
                stop["data"]["reason"], "signal",
                "delay {delay_ms} ms\n{log}"
            );
            verify(t.path());
        }
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn kill_9_then_restart_records_an_unclean_gap_and_keeps_the_events() {
        let t = tempfile::tempdir().unwrap();
        let marker = format!("witness-crash-{}", std::process::id());
        let (mut child, _err) = spawn(t.path(), 60);
        run_marker(&marker);
        std::thread::sleep(std::time::Duration::from_millis(800)); // let it store the exec
        child.kill().unwrap(); // SIGKILL: no stop record, no seal
        child.wait().unwrap();

        let (child2, _err2) = spawn(t.path(), 3);
        assert!(child2.wait_with_output().unwrap().status.success());

        verify(t.path());
        let recs = records(t.path());
        let starts: Vec<&Value> = recs
            .iter()
            .filter(|v| v["type"] == "daemon_start")
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0]["data"]["prev_shutdown"], "none");
        assert_eq!(starts[1]["data"]["prev_shutdown"], "unclean");
        let gap = recs.iter().find(|v| v["type"] == "capture_gap").unwrap();
        assert_eq!(gap["data"]["kind"], "restart_same_boot");
        assert_eq!(gap["data"]["prev_shutdown"], "unclean");
        assert!(
            gap["data"]["from_wall_ns"].as_u64().unwrap()
                < gap["data"]["to_wall_ns"].as_u64().unwrap()
        );
        // The activity captured before the kill survived it.
        assert!(
            recs.iter().any(|v| v["type"] == "proc_exec"
                && v["data"]["argv"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x == marker.as_str()))),
            "the exec captured before SIGKILL must still be in the chain"
        );
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_second_daemon_on_the_same_data_dir_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let (mut first, _err) = spawn(t.path(), 30);
        let second = Command::new(env!("CARGO_BIN_EXE_witnessd"))
            .args(["run", "--config", "/nonexistent/witness.toml", "--data-dir"])
            .arg(t.path())
            .args(["--seconds", "5"])
            .output()
            .unwrap();
        assert!(!second.status.success());
        assert!(String::from_utf8_lossy(&second.stderr).contains("another witnessd"));
        first.kill().unwrap();
        first.wait().unwrap();
        verify(t.path());
    }
}

// ---- file events -----------------------------------------------------------------------

mod files {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use super::capture;

    /// A unique directory name so each test finds only its own events.
    fn marker(tag: &str) -> String {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("witness-it-{tag}-{}-{n}", std::process::id())
    }

    /// Every string-ish path field of a file event.
    fn paths(e: &Value) -> Vec<String> {
        ["path", "old", "new", "target"]
            .iter()
            .filter_map(|k| e["data"][k].as_str().map(String::from))
            .collect()
    }

    fn about<'a>(ev: &'a [Value], m: &str) -> Vec<&'a Value> {
        ev.iter()
            .filter(|e| {
                e["type"].as_str().is_some_and(|t| t.starts_with("file_"))
                    && paths(e).iter().any(|p| p.contains(m))
            })
            .collect()
    }

    fn of<'a>(ev: &[&'a Value], t: &str) -> Vec<&'a Value> {
        ev.iter().copied().filter(|e| e["type"] == t).collect()
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_files_whole_life_is_captured_with_attribution() {
        let m = marker("life");
        let base = PathBuf::from("/tmp").join(&m);
        let b = base.clone();
        let (ev, _) = capture(8, move || {
            fs::create_dir(&b).unwrap();
            let f = b.join("a.txt");
            fs::write(&f, b"hello").unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(0o4755)).unwrap();
            let g = b.join("b.txt");
            fs::rename(&f, &g).unwrap();
            fs::hard_link(&g, b.join("hard.txt")).unwrap();
            symlink("../etc/passwd", b.join("sym")).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&g)
                .unwrap()
                .set_len(0)
                .unwrap();
            fs::remove_file(b.join("hard.txt")).unwrap();
            fs::remove_file(b.join("sym")).unwrap();
            fs::remove_file(&g).unwrap();
            fs::remove_dir(&b).unwrap();
        });
        let mine = about(&ev, &m);
        let t = |name: &str| of(&mine, name);

        assert!(
            t("file_create")
                .iter()
                .any(|e| e["data"]["path"] == base.to_str().unwrap()),
            "the directory creation"
        );
        assert!(t("file_create")
            .iter()
            .any(|e| e["data"]["path"] == format!("{}/a.txt", base.display())));
        assert!(t("file_open_write")
            .iter()
            .any(|e| e["data"]["path"] == format!("{}/a.txt", base.display())));

        let attr = t("file_attr");
        let suid = attr
            .iter()
            .find(|e| e["data"]["suid_set"] == true)
            .expect("SUID chmod");
        assert_eq!(suid["data"]["new_mode"], 0o4755);

        let rename = t("file_rename");
        assert_eq!(rename.len(), 1);
        assert_eq!(
            rename[0]["data"]["old"],
            format!("{}/a.txt", base.display())
        );
        assert_eq!(
            rename[0]["data"]["new"],
            format!("{}/b.txt", base.display())
        );

        let links = t("file_link");
        let hard = links
            .iter()
            .find(|e| e["data"]["kind"] == "hard")
            .expect("hard link");
        assert_eq!(hard["data"]["target"], format!("{}/b.txt", base.display()));
        let sym = links
            .iter()
            .find(|e| e["data"]["kind"] == "symbolic")
            .expect("symlink");
        assert_eq!(sym["data"]["target"], "../etc/passwd");

        assert!(!t("file_truncate").is_empty(), "ftruncate");
        let deletes = t("file_delete");
        assert!(
            deletes.len() >= 4,
            "three files and the directory, got {}",
            deletes.len()
        );

        // Everything is attributed to this process and its user.
        for e in &mine {
            assert_eq!(e["actor"]["pid"], std::process::id(), "{}", e["type"]);
            assert_eq!(e["actor"]["uid"], 0);
            assert!(
                e["actor"]["exe"]
                    .as_str()
                    .is_some_and(|x| x.contains("integration")),
                "{e}"
            );
            // The hook saw the call; its outcome is not observed.
            assert_eq!(e["data"]["result"], "attempted");
        }
    }

    #[test]
    #[ignore = "needs root, a kernel with BTF and the ability to mount"]
    fn paths_through_bind_mounts_of_subdirectories_are_reported_as_the_process_sees_them() {
        // The root of a *mount* is not always the root of its filesystem: a bind mount of a
        // subdirectory (containers, btrfs subvolumes) starts mid-tree. The path must be the
        // one through the mount, not the one inside the filesystem.
        let m = marker("bind");
        let src = format!("/var/tmp/{m}-src");
        let mnt = format!("/var/tmp/{m}-mnt");
        fs::create_dir_all(format!("{src}/inner")).unwrap();
        fs::create_dir_all(&mnt).unwrap();
        let (s2, m2) = (src.clone(), mnt.clone());
        let (ev, _) = capture(8, move || {
            let ok = std::process::Command::new("mount")
                .args(["--bind", &format!("{s2}/inner"), &m2])
                .status()
                .unwrap()
                .success();
            assert!(ok, "mount --bind failed");
            fs::write(format!("{m2}/through-the-mount"), b"x").unwrap();
            fs::write(format!("{s2}/inner/direct"), b"x").unwrap();
            std::process::Command::new("umount")
                .arg(&m2)
                .status()
                .unwrap();
        });
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&mnt).ok();
        let mine = about(&ev, &m);
        let paths: Vec<_> = of(&mine, "file_create")
            .iter()
            .map(|e| e["data"]["path"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(
            paths.contains(&format!("{mnt}/through-the-mount")),
            "a file made through the bind mount is reported at the mount path: {paths:?}"
        );
        assert!(
            paths.contains(&format!("{src}/inner/direct")),
            "the same directory reached directly keeps its own path: {paths:?}"
        );
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn paths_cross_mounts_and_deep_nesting_correctly() {
        let m = marker("deep");
        let shm = format!("/dev/shm/{m}");
        let deep20: String = (1..=20).map(|i| format!("/d{i}")).collect();
        let deep_dir = PathBuf::from(format!("/tmp/{m}")).join(deep20.trim_start_matches('/'));
        let (s2, d2) = (shm.clone(), deep_dir.clone());
        let (ev, _) = capture(8, move || {
            fs::write(&s2, b"x").unwrap(); // a different mount (tmpfs)
            fs::create_dir_all(&d2).unwrap();
            fs::write(d2.join("leaf.txt"), b"x").unwrap();
            fs::remove_file(d2.join("leaf.txt")).unwrap();
            fs::remove_file(&s2).unwrap();
            fs::remove_dir_all(format!("/tmp/{}", s2.rsplit('/').next().unwrap())).ok();
            fs::remove_dir_all(PathBuf::from(format!(
                "/tmp/{}",
                s2.rsplit('/').next().unwrap()
            )))
            .ok();
        });
        let mine = about(&ev, &m);
        assert!(
            of(&mine, "file_create")
                .iter()
                .any(|e| e["data"]["path"] == shm),
            "the tmpfs file keeps its full /dev/shm path across the mount point"
        );
        let leaf = format!("{}/leaf.txt", deep_dir.display());
        assert!(
            of(&mine, "file_open_write")
                .iter()
                .any(|e| e["data"]["path"] == leaf),
            "a 23-component path is reported exactly: {leaf}"
        );
        for e in &mine {
            if e["data"]["path"] == leaf {
                assert!(e["data"].get("path_truncated").is_none());
            }
        }
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_path_deeper_than_the_walk_limit_is_flagged_and_keeps_its_leaf() {
        let m = marker("toodeep");
        let deep: String = (1..=40).map(|i| format!("/q{i}")).collect();
        let dir = PathBuf::from(format!("/tmp/{m}{deep}"));
        let d = dir.clone();
        let (ev, _) = capture(8, move || {
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("end.txt"), b"x").unwrap();
            fs::remove_dir_all(format!(
                "/tmp/{}",
                d.components().nth(2).unwrap().as_os_str().to_str().unwrap()
            ))
            .ok();
        });
        let hit = ev
            .iter()
            .find(|e| {
                e["type"] == "file_open_write"
                    && e["data"]["path"]
                        .as_str()
                        .is_some_and(|p| p.ends_with("/q40/end.txt"))
            })
            .expect("the write is still reported");
        assert_eq!(
            hit["data"]["path_truncated"], true,
            "the walk gave up before the root"
        );
        assert!(hit["data"]["path"].as_str().unwrap().starts_with('/'));
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn awkward_names_survive() {
        let m = marker("names");
        let dir = PathBuf::from(format!("/tmp/{m}"));
        let long = "n".repeat(255);
        let weird = OsString::from_vec(vec![b'w', 0xff, 0xfe, b'z']);
        let (d, l, w) = (dir.clone(), long.clone(), weird.clone());
        let (ev, _) = capture(8, move || {
            fs::create_dir(&d).unwrap();
            fs::write(d.join(&l), b"x").unwrap();
            fs::write(d.join(&w), b"x").unwrap();
            fs::remove_dir_all(&d).unwrap();
        });
        let mine = about(&ev, &m);
        assert!(
            of(&mine, "file_create")
                .iter()
                .any(|e| e["data"]["path"] == format!("{}/{long}", dir.display())),
            "a 255-byte name is intact"
        );
        // Non-UTF-8 bytes arrive base64-wrapped rather than mangled.
        let wrapped = ev
            .iter()
            .filter(|e| e["type"] == "file_create")
            .find(|e| e["data"]["path"]["b64"].is_string())
            .expect("non-UTF-8 path kept as base64");
        let b64 = wrapped["data"]["path"]["b64"].as_str().unwrap();
        assert!(!b64.is_empty());
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn pseudo_filesystems_are_not_reported_and_a_burst_loses_nothing() {
        let m = marker("burst");
        let dir = PathBuf::from(format!("/tmp/{m}"));
        let d = dir.clone();
        let (ev, _) = capture(10, move || {
            // Writes to procfs/sysfs are noise, not host file activity.
            fs::write("/proc/self/comm", b"witness-t").ok();
            fs::create_dir(&d).unwrap();
            for i in 0..500 {
                fs::write(d.join(format!("f{i}")), b"x").unwrap();
            }
            fs::remove_dir_all(&d).unwrap();
        });
        assert!(
            !ev.iter().any(
                |e| e["type"].as_str().is_some_and(|t| t.starts_with("file_"))
                    && paths(e).iter().any(|p| p.starts_with("/proc/"))
            ),
            "procfs writes must be filtered in the kernel"
        );
        let creates = of(&about(&ev, &m), "file_create")
            .iter()
            .filter(|e| e["data"]["path"].as_str().is_some_and(|p| p.contains("/f")))
            .count();
        assert_eq!(creates, 500, "every one of 500 creations is captured");
    }

    /// A critical file's content is hashed once it settles; a real change names the previous
    /// hash, an identical rewrite produces nothing, and non-critical paths are not hashed.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn critical_files_are_hashed_after_they_settle_and_only_on_change() {
        use super::store_mode::{records, spawn, verify};
        use sha2::{Digest, Sha256};
        let hex = |b: &[u8]| {
            witness_store::chain::to_hex(
                &<[u8; 32]>::try_from(Sha256::digest(b).as_slice()).unwrap(),
            )
        };
        let t = tempfile::tempdir_in("/tmp").unwrap();
        let m = marker("hash");
        let critical = format!("/etc/{m}");
        let ordinary = format!("/tmp/{m}");
        let (child, _err) = spawn(t.path(), 22);
        let settle = std::time::Duration::from_millis(3500); // debounce (2 s) + hashing + a loop tick
        fs::write(&critical, b"version one").unwrap();
        fs::write(&ordinary, b"version one").unwrap();
        std::thread::sleep(settle);
        fs::write(&critical, b"version two").unwrap();
        std::thread::sleep(settle);
        fs::write(&critical, b"version two").unwrap(); // same bytes: touched, not changed
        std::thread::sleep(settle);
        fs::remove_file(&critical).unwrap();
        fs::remove_file(&ordinary).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());

        verify(t.path());
        let recs = records(t.path());
        let hashes: Vec<&Value> = recs
            .iter()
            .filter(|v| v["type"] == "file_hash" && v["data"]["path"] == critical.as_str())
            .collect();
        assert_eq!(
            hashes.len(),
            2,
            "first sighting and one real change, got {hashes:#?}"
        );
        assert_eq!(hashes[0]["data"]["sha256"], hex(b"version one"));
        assert!(
            hashes[0]["data"].get("prev_sha256").is_none(),
            "no previous hash the first time"
        );
        assert_eq!(hashes[1]["data"]["sha256"], hex(b"version two"));
        assert_eq!(hashes[1]["data"]["prev_sha256"], hex(b"version one"));
        assert_eq!(hashes[1]["data"]["size"], 11);
        // The hash event names who made the change.
        assert_eq!(hashes[1]["actor"]["uid"], 0);
        assert!(hashes[1]["actor"]["exe"]
            .as_str()
            .is_some_and(|e| e.contains("integration")));
        assert!(
            !recs
                .iter()
                .any(|v| v["type"] == "file_hash" && v["data"]["path"] == ordinary.as_str()),
            "/tmp is watched, not critical: not hashed"
        );
    }

    /// Reads of files on the sensitive list are reported (matched by inode in the kernel),
    /// ordinary reads are not, and a replaced file (new inode) is tracked.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn sensitive_file_reads_are_reported_including_after_replacement() {
        use super::store_mode::{records, spawn_cfg, verify};
        let t = tempfile::tempdir_in("/tmp").unwrap();
        let m = marker("secret");
        let secret = format!("/etc/{m}");
        fs::write(&secret, b"s3cret v1").unwrap();
        let cfg = t.path().join("config.toml");
        fs::write(
            &cfg,
            format!("[files]\nsensitive_read = [\"{secret}\", \"/etc/shadow\"]\n"),
        )
        .unwrap();
        let (child, _err) = spawn_cfg(&t.path().join("data"), 14, &cfg);
        std::thread::sleep(std::time::Duration::from_millis(1200)); // the set is loaded
        fs::read(&secret).unwrap(); // sensitive
        fs::read("/etc/hostname").unwrap(); // ordinary
        fs::read("/etc/shadow").unwrap(); // sensitive (the real one)
                                          // Replace the secret the way `passwd` replaces /etc/shadow: new file, rename over.
        let new = format!("{secret}.new");
        fs::write(&new, b"s3cret v2").unwrap();
        fs::rename(&new, &secret).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2500)); // refresh settles
        fs::read(&secret).unwrap(); // sensitive again, on the new inode
        std::thread::sleep(std::time::Duration::from_millis(800));
        fs::remove_file(&secret).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());

        verify(&t.path().join("data"));
        let recs = records(&t.path().join("data"));
        let reads = |p: &str| {
            recs.iter()
                .filter(|v| v["type"] == "file_open_read" && v["data"]["path"] == p)
                .count()
        };
        assert_eq!(
            reads(&secret),
            2,
            "once before and once after the replacement"
        );
        assert!(reads("/etc/shadow") >= 1, "the real /etc/shadow");
        assert_eq!(reads("/etc/hostname"), 0, "ordinary files are not reported");
        let r = recs
            .iter()
            .find(|v| v["type"] == "file_open_read" && v["data"]["path"] == secret.as_str())
            .unwrap();
        assert_eq!(r["actor"]["uid"], 0);
        assert!(r["actor"]["exe"]
            .as_str()
            .is_some_and(|e| e.contains("integration")));
        assert_eq!(r["prio"], 1, "sensitive reads are never first to be shed");
    }

    /// In store mode the path policy applies: watched and critical paths are kept, the rest
    /// is counted rather than stored, and the daemon never records its own writes.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn store_mode_applies_the_path_policy_and_excludes_itself() {
        use super::store_mode::{records, spawn, verify};
        let t = tempfile::tempdir_in("/tmp").unwrap();
        let (watched, quiet) = (marker("kept"), marker("dropped"));
        let (child, _err) = spawn(t.path(), 6);
        fs::write(format!("/tmp/{watched}"), b"x").unwrap();
        let q = Path::new("/root").join(&quiet);
        fs::write(&q, b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(800));
        fs::remove_file(format!("/tmp/{watched}")).unwrap();
        fs::remove_file(&q).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());

        verify(t.path());
        let recs = records(t.path());
        let has = |m: &str| {
            recs.iter().any(|v| {
                v["type"].as_str().is_some_and(|t| t.starts_with("file_"))
                    && v["data"]["path"].as_str().is_some_and(|p| p.contains(m))
            })
        };
        assert!(has(&watched), "/tmp is watched");
        assert!(
            !has(&quiet),
            "/root is neither critical nor watched: counted, not stored"
        );
        let datadir = t.path().to_str().unwrap();
        assert!(
            !recs.iter().any(
                |v| v["type"].as_str().is_some_and(|t| t.starts_with("file_"))
                    && v["data"]["path"]
                        .as_str()
                        .is_some_and(|p| p.starts_with(datadir))
            ),
            "the daemon's own segment writes must not be recorded"
        );
    }
}

// ---- network events --------------------------------------------------------------------

mod net {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    use serde_json::Value;

    use super::capture;

    fn mine<'a>(ev: &'a [Value], t: &str) -> Vec<&'a Value> {
        ev.iter()
            .filter(|e| e["type"] == t && e["actor"]["pid"] == std::process::id())
            .collect()
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn tcp_connection_lifecycle_is_attributed_with_byte_counts() {
        let ports = Arc::new(Mutex::new((0u16, 0u16)));
        let p2 = Arc::clone(&ports);
        let (ev, _) = capture(8, move || {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let srv = std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).unwrap();
                s.write_all(b"world!!!").unwrap();
            });
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.write_all(b"hello").unwrap();
            let mut b = [0u8; 8];
            c.read_exact(&mut b).unwrap();
            drop(c);
            srv.join().unwrap();
            // A port nobody listens on: the connection is refused.
            let closed = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            TcpStream::connect(("127.0.0.1", closed)).unwrap_err();
            *p2.lock().unwrap() = (port, closed);
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        let (port, closed) = *ports.lock().unwrap();
        assert!(port != 0 && closed != 0);
        let port = u64::from(port);
        let closed = u64::from(closed);

        let listens = mine(&ev, "net_listen");
        assert!(
            listens.iter().any(|e| e["data"]["port"] == port),
            "the server's listen()"
        );

        let connects = mine(&ev, "net_connect");
        let ok = connects
            .iter()
            .find(|e| e["data"]["rport"] == port && e["data"]["outcome"] == "established")
            .expect("the established connection");
        assert_eq!(ok["data"]["raddr"], "127.0.0.1");
        assert_eq!(ok["data"]["proto"], "tcp");
        assert!(ok["actor"]["exe"]
            .as_str()
            .is_some_and(|x| x.contains("integration")));
        assert_eq!(ok["actor"]["uid"], 0);

        let failed = connects
            .iter()
            .find(|e| e["data"]["rport"] == closed)
            .expect("the refused connection is recorded");
        assert_eq!(failed["data"]["outcome"], "failed");

        let accepts = mine(&ev, "net_accept");
        let acc = accepts
            .iter()
            .find(|e| e["data"]["lport"] == port)
            .expect("the accept");
        assert_eq!(acc["data"]["raddr"], "127.0.0.1");

        // Closes carry the byte counts: the client sent 5 and received 8; the server the reverse.
        let closes = mine(&ev, "net_close");
        let client = closes
            .iter()
            .find(|e| e["data"]["conn"]["rport"] == port && e["data"]["bytes_sent"] == 5)
            .expect("the client's close");
        assert_eq!(client["data"]["bytes_recv"], 8);
        assert!(client["data"]["duration_ns"].as_u64().unwrap() > 0);
        let server = closes
            .iter()
            .find(|e| e["data"]["conn"]["lport"] == port && e["data"]["bytes_sent"] == 8)
            .expect("the server's close");
        assert_eq!(server["data"]["bytes_recv"], 5);

        assert!(
            !mine(&ev, "net_listen_close").is_empty(),
            "the listener closed when the test dropped it"
        );
    }

    /// A connection is attributed to the process that made it, not to whoever happened to be
    /// running when the kernel reported the state change.
    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_child_processs_connection_is_attributed_to_the_child() {
        let port = Arc::new(Mutex::new(0u16));
        let p2 = Arc::clone(&port);
        let (ev, _) = capture(8, move || {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let pt = l.local_addr().unwrap().port();
            *p2.lock().unwrap() = pt;
            let st = Command::new("/bin/bash")
                .args([
                    "-c",
                    &format!("exec 3<>/dev/tcp/127.0.0.1/{pt}; echo hi >&3"),
                ])
                .status()
                .unwrap();
            assert!(st.success());
            let _ = l.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        let port = u64::from(*port.lock().unwrap());
        let conn = ev
            .iter()
            .find(|e| e["type"] == "net_connect" && e["data"]["rport"] == port)
            .expect("the child's connect");
        assert_eq!(conn["actor"]["comm"], "bash");
        assert_ne!(conn["actor"]["pid"], std::process::id(), "not the parent");
        assert_eq!(conn["actor"]["ppid"], std::process::id());
        assert!(conn["actor"]["exe"]
            .as_str()
            .is_some_and(|x| x.ends_with("bash")));
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn dns_queries_and_responses_are_captured_and_parsed() {
        use std::net::UdpSocket;
        let (ev, _) = capture(8, || {
            // A fake resolver on port 53 that answers every query with 93.184.216.34.
            let srv = UdpSocket::bind("127.0.0.1:53").unwrap();
            srv.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let t = std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                let (n, from) = srv.recv_from(&mut buf).unwrap();
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                r[3] = 0x80;
                r[7] = 1;
                r.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34]);
                srv.send_to(&r, from).unwrap();
            });
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            c.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut q = vec![0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for l in ["witness-test", "example"] {
                q.push(l.len() as u8);
                q.extend(l.as_bytes());
            }
            q.extend([0, 0, 1, 0, 1]);
            c.send_to(&q, "127.0.0.1:53").unwrap();
            let mut b = [0u8; 512];
            c.recv_from(&mut b).unwrap();
            t.join().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        let dns = mine(&ev, "dns");
        let query = dns
            .iter()
            .find(|e| e["data"]["direction"] == "query")
            .expect("the query");
        assert_eq!(query["data"]["qname"], "witness-test.example");
        assert_eq!(query["data"]["qtype"], "A");
        assert_eq!(query["data"]["id"], 0xABCD);
        assert_eq!(query["data"]["server"], "127.0.0.1");
        assert_eq!(query["data"]["server_port"], 53);
        let resp = dns
            .iter()
            .find(|e| e["data"]["direction"] == "response")
            .expect("the response");
        assert_eq!(resp["data"]["rcode"], "NOERROR");
        assert_eq!(resp["data"]["answers"][0]["data"], "93.184.216.34");
        assert_eq!(resp["data"]["answers"][0]["ttl"], 300);
    }
}

mod auth {
    use std::process::Command;

    use super::store_mode::{records, spawn, verify};

    fn sh(cmd: &str) {
        let _ = Command::new("sh").args(["-c", cmd]).status();
    }

    #[test]
    #[ignore = "needs root, journald and sshd"]
    fn auth_and_account_activity_is_recorded_from_real_sources() {
        let t = tempfile::tempdir().unwrap();
        let user = format!("wt{}", std::process::id() % 100_000);
        sh(&format!("userdel -r {user} 2>/dev/null"));
        let (mut child, _err) = spawn(t.path(), 25);
        // Give the journal follower time to reach the end of the journal.
        std::thread::sleep(std::time::Duration::from_secs(3));

        // sudo policy decision, logged by sudo itself.
        sh("sudo -n /usr/bin/id -u >/dev/null 2>&1");
        // A failed ssh login against the local sshd.
        sh(
            "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 witness-no-such-user@127.0.0.1 true >/dev/null 2>&1",
        );
        // An account and an authorized key appear, then the key changes, then the user goes.
        sh(&format!("useradd -m {user}"));
        sh(&format!(
            "mkdir -p /home/{user}/.ssh && echo 'ssh-ed25519 \
             AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x' \
             > /home/{user}/.ssh/authorized_keys"
        ));
        std::thread::sleep(std::time::Duration::from_secs(4));
        sh(&format!(
            "usermod -s /bin/bash -p '$6$witnesssalt$notarealhashnotarealhash' {user}"
        ));
        std::thread::sleep(std::time::Duration::from_secs(4));
        sh(&format!("userdel -r {user} 2>/dev/null"));
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let of = |ty: &str| -> Vec<&serde_json::Value> {
            ev.iter().filter(|e| e["type"] == ty).collect()
        };
        let sudo = of("sudo");
        assert!(
            sudo.iter()
                .any(|e| e["data"]["command"] == "/usr/bin/id -u"),
            "sudo events: {sudo:?}"
        );
        let fails = of("auth_fail");
        assert!(
            fails
                .iter()
                .any(|e| e["data"]["user"] == "witness-no-such-user"),
            "auth_fail events: {fails:?}"
        );
        let acct = of("account_change");
        assert!(acct
            .iter()
            .any(|e| e["data"]["name"] == user.as_str() && e["data"]["change"] == "created"));
        assert!(acct
            .iter()
            .any(|e| e["data"]["name"] == user.as_str() && e["data"]["password_changed"] == true));
        assert!(acct
            .iter()
            .any(|e| e["data"]["name"] == user.as_str() && e["data"]["change"] == "deleted"));
        let keys = of("authorized_key_change");
        assert!(
            keys.iter().any(|e| e["data"]["user"] == user.as_str()
                && e["data"]["change"] == "created"
                && e["data"]["fingerprint"]
                    == "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"),
            "key events: {keys:?}"
        );
        assert!(
            !serde_json::to_string(&acct).unwrap().contains("$6$"),
            "a password hash leaked"
        );
    }

    #[test]
    #[ignore = "needs root and loop devices"]
    fn block_device_attach_and_detach_are_recorded() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 12);
        // Creating and destroying a loop device through /dev/loop-control produces the same
        // kernel `add` and `remove` uevents as a hot-plugged disk. (Attaching a file to an
        // existing loop device only produces `change`, which is deliberately not reported.)
        let ok = Command::new("python3")
            .args([
                "-c",
                "import os,fcntl,time\nfd=os.open('/dev/loop-control',os.O_RDWR)\n\
                 fcntl.ioctl(fd,0x4C80,97)\ntime.sleep(1.5)\nfcntl.ioctl(fd,0x4C81,97)",
            ])
            .status()
            .unwrap()
            .success();
        assert!(ok, "could not create a loop device");
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let blocks: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "block_device" && e["data"]["name"] == "loop97")
            .collect();
        assert!(
            blocks.iter().any(|e| e["data"]["action"] == "add"),
            "block events: {blocks:?}"
        );
        assert!(
            blocks.iter().any(|e| e["data"]["action"] == "remove"),
            "block events: {blocks:?}"
        );
    }

    #[test]
    #[ignore = "needs root and a loadable module"]
    fn module_load_and_unload_are_attributed_to_the_loader() {
        let t = tempfile::tempdir().unwrap();
        // `dummy` is a small network driver shipped with every distribution kernel.
        let have = Command::new("modinfo")
            .arg("dummy")
            .output()
            .unwrap()
            .status
            .success();
        if !have {
            eprintln!("skipped: no `dummy` module on this kernel");
            return;
        }
        Command::new("rmmod").arg("dummy").status().ok();
        let (mut child, _err) = spawn(t.path(), 10);
        assert!(Command::new("modprobe")
            .arg("dummy")
            .status()
            .unwrap()
            .success());
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(Command::new("rmmod")
            .arg("dummy")
            .status()
            .unwrap()
            .success());
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let load = ev
            .iter()
            .find(|e| e["type"] == "module_load" && e["data"]["name"] == "dummy")
            .expect("module_load");
        assert_eq!(load["actor"]["comm"], "modprobe");
        assert!(ev
            .iter()
            .any(|e| e["type"] == "module_unload" && e["data"]["name"] == "dummy"));
    }

    #[test]
    #[ignore = "needs root; briefly changes the system clock"]
    fn a_clock_step_is_recorded_with_its_size() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 9);
        let date = |args: &[&str]| Command::new("date").args(args).status().unwrap();
        let before = std::time::SystemTime::now();
        date(&["-s", "@1900000000"]);
        std::thread::sleep(std::time::Duration::from_secs(1));
        // Put it back, accounting for the time that really passed.
        let back = before
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2;
        date(&["-s", &format!("@{back}")]);
        let _ = child.wait();
        let ev = records(t.path());
        let steps: Vec<_> = ev.iter().filter(|e| e["type"] == "clock_change").collect();
        // Two sets happened (forward, then back), so there are step records. The size is
        // measured when the daemon next runs: if the host undoes the step first (VM time sync;
        // a slow emulated CPU) the recorded delta is small, so only the fact is asserted.
        assert!(
            steps.iter().any(|e| e["data"]["kind"] == "step"),
            "clock events: {steps:?}"
        );
    }
}

mod rules {
    use std::fs;
    use std::process::Command;
    use std::time::Duration;

    use super::store_mode::{records, spawn_cfg, verify};

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn the_pack_alerts_on_real_activity_and_reloads_without_a_restart() {
        let t = tempfile::tempdir().unwrap();
        let rules = t.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        let pack = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
        for e in fs::read_dir(&pack).unwrap() {
            let p = e.unwrap().path();
            fs::copy(&p, rules.join(p.file_name().unwrap())).unwrap();
        }
        let cfg = t.path().join("config.toml");
        fs::write(&cfg, format!("[rules]\ndir = \"{}\"\n", rules.display())).unwrap();
        let data = t.path().join("data");
        let (mut child, _err) = spawn_cfg(&data, 20, &cfg);

        // 1. Execution from /dev/shm, with a recognisable name.
        let dropped = "/dev/shm/witness-rule-test";
        fs::copy("/bin/true", dropped).unwrap();
        Command::new(dropped).status().unwrap();
        // 2. Hot reload: a new rule, then a broken one, while the daemon runs.
        std::thread::sleep(Duration::from_secs(3));
        fs::write(
            rules.join("added.yml"),
            "id: test.added\ntitle: Added live\nseverity: low\nevent: proc_exec\n\
             match: { field: data.exe, op: endswith, value: /uname }\n",
        )
        .unwrap();
        fs::write(rules.join("broken.yml"), "id: broken\nseverity: nope\n").unwrap();
        std::thread::sleep(Duration::from_secs(4));
        Command::new("/bin/uname").output().unwrap();
        let _ = fs::remove_file(dropped);
        let _ = child.wait();

        let ev = records(&data);
        verify(&data);
        let alerts: Vec<_> = ev.iter().filter(|e| e["type"] == "alert").collect();
        let tmp = alerts
            .iter()
            .find(|a| {
                a["data"]["rule_id"] == "witness.exec.from-tmp"
                    && a["data"]["detail"]["data.exe"] == dropped
            })
            .unwrap_or_else(|| panic!("no from-tmp alert; alerts: {alerts:?}"));
        // The alert names the stored record that triggered it.
        let seq = tmp["data"]["trigger_seqs"][0].as_u64().unwrap();
        let trigger = ev.iter().find(|e| e["seq"] == seq).unwrap();
        assert_eq!(trigger["type"], "proc_exec");
        assert_eq!(trigger["data"]["exe"], dropped);

        assert!(
            alerts.iter().any(|a| a["data"]["rule_id"] == "test.added"),
            "the live-added rule never fired; alerts: {alerts:?}"
        );
        let changes: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "rule_set_change")
            .collect();
        assert!(changes.len() >= 2, "initial load and reload: {changes:?}");
        assert!(changes[0]["data"]["rejected"]
            .as_array()
            .is_none_or(Vec::is_empty));
        assert!(
            changes.iter().any(|c| c["data"]["added"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == "test.added"))),
            "{changes:?}"
        );
        assert!(changes
            .iter()
            .any(|c| c["data"]["rejected"].as_array().is_some_and(|r| r
                .iter()
                .any(|x| x.as_str().is_some_and(|s| s.starts_with("broken.yml"))))));
    }
}

mod api {
    use std::fs;
    use std::process::Command;
    use std::time::Duration;

    use serde_json::json;
    use witness_client::Client;

    use super::store_mode::spawn_cfg;

    fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..60 {
            if let Some(v) = f() {
                return v;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn the_api_serves_events_search_streams_triage_integrity_and_rules() {
        let t = tempfile::tempdir().unwrap();
        let rules = t.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        let pack = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
        fs::copy(
            pack.join("exec-from-tmp.yml"),
            rules.join("exec-from-tmp.yml"),
        )
        .unwrap();
        let sock = t.path().join("run/witness.sock");
        let cfg = t.path().join("config.toml");
        fs::write(
            &cfg,
            format!(
                "[rules]\ndir = \"{}\"\n[api]\nsocket = \"{}\"\ngroup = \"witness-no-such-group\"\n",
                rules.display(),
                sock.display()
            ),
        )
        .unwrap();
        let (mut child, _err) = spawn_cfg(&t.path().join("data"), 40, &cfg);
        let c = Client::new(&sock);

        assert_eq!(c.get("/v1/health").unwrap()["ok"], true);
        let st = c.get("/v1/status").unwrap();
        assert_eq!(st["tier"], "admin");
        assert!(st["head_seq"].as_u64().unwrap() > 0);

        // A live stream opened now must see activity that happens afterwards.
        let (tx, rx) = std::sync::mpsc::channel();
        let sc = c.clone();
        let streamer = std::thread::spawn(move || {
            let _ = sc.stream("/v1/stream?kind=proc_exec", |v| {
                if v["data"]["exe"]
                    .as_str()
                    .is_some_and(|e| e.ends_with("witness-api-marker"))
                {
                    let _ = tx.send(v);
                    return false;
                }
                true
            });
        });
        std::thread::sleep(Duration::from_secs(1));
        let marker = "/dev/shm/witness-api-marker";
        fs::copy("/bin/true", marker).unwrap();
        Command::new(marker).status().unwrap();
        fs::remove_file(marker).unwrap();
        let streamed = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the stream delivered the exec");
        assert_eq!(streamed["type"], "proc_exec");
        streamer.join().unwrap();

        // Search finds it, by FTS text and by kind; the event is fetchable by seq and raw.
        let found = wait_for("the event to be indexed", || {
            let r = c
                .get("/v1/events?kind=proc_exec&q=witness-api-marker&limit=5")
                .ok()?;
            (!r["events"].as_array()?.is_empty()).then_some(r)
        });
        let seq = found["events"][0]["seq"].as_u64().unwrap();
        let one = c.get(&format!("/v1/events/{seq}")).unwrap();
        assert_eq!(one["data"]["exe"], marker);
        let raw = c.get_text(&format!("/v1/events/{seq}/raw")).unwrap();
        assert!(raw.contains(&format!("\"seq\":{seq}")) && raw.contains("\"h\":\""));
        assert!(c.get("/v1/events/999999999").is_err());
        assert!(c.get("/v1/events?limit=abc").is_err());

        // The alert exists and can be triaged; the list reflects the new state.
        let alert = wait_for("the alert", || {
            let r = c.get("/v1/alerts?limit=10").ok()?;
            r["events"].as_array()?.first().cloned()
        });
        assert_eq!(alert["triage"]["status"], "new");
        let aseq = alert["seq"].as_u64().unwrap();
        c.post(
            &format!("/v1/alerts/{aseq}/triage"),
            &json!({"status": "false_positive", "note": "test"}),
        )
        .unwrap();
        wait_for("the triage to be recorded", || {
            let r = c.get("/v1/alerts?limit=10").ok()?;
            let a = r["events"]
                .as_array()?
                .iter()
                .find(|e| e["seq"] == aseq)?
                .clone();
            (a["triage"]["status"] == "false_positive").then_some(a)
        });
        assert!(
            c.post("/v1/alerts/1/triage", &json!({"status": "acknowledged"}))
                .is_err(),
            "triaging a non-alert is refused"
        );

        // Timeline, dashboard, sessions.
        let tl = c.get("/v1/timeline?buckets=10").unwrap();
        assert_eq!(tl["buckets"], 10);
        assert!(tl["series"].as_object().is_some_and(|m| !m.is_empty()));
        let d = c.get("/v1/dashboard").unwrap();
        assert!(d["by_kind"].as_array().is_some_and(|a| !a.is_empty()));
        assert!(c.get("/v1/sessions").is_ok());

        // Integrity verification runs in the background and reports a good chain.
        c.post("/v1/integrity/verify", &json!({})).unwrap();
        let v = wait_for("verification", || {
            let r = c.get("/v1/integrity").ok()?;
            (r["state"] != "running" && r["state"] != "never_run").then_some(r)
        });
        assert_eq!(v["state"], "ok", "{v}");

        // Rules: list, validate, save (hot reloaded), disable, delete.
        assert!(
            c.get("/v1/rules").unwrap()["rules"]
                .as_array()
                .unwrap()
                .len()
                == 1
        );
        let bad = c
            .post(
                "/v1/rules/validate",
                &json!({"yaml": "id: x\nseverity: nope\n"}),
            )
            .unwrap();
        assert_eq!(bad["ok"], false);
        let yaml = "id: api.added\ntitle: Added\nseverity: low\nevent: proc_exec\n";
        assert_eq!(
            c.post("/v1/rules/validate", &json!({"yaml": yaml}))
                .unwrap()["ok"],
            true
        );
        c.put("/v1/rules/api.added", &json!({"yaml": yaml}))
            .unwrap();
        assert!(
            c.put("/v1/rules/other.id", &json!({"yaml": yaml})).is_err(),
            "id must match"
        );
        assert_eq!(
            c.get("/v1/rules").unwrap()["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        c.post("/v1/rules/api.added/disable", &json!({})).unwrap();
        assert_eq!(
            c.get("/v1/rules").unwrap()["disabled_files"][0],
            "api.added.yml.off"
        );
        c.delete("/v1/rules/api.added").unwrap();
        assert!(c
            .put("/v1/rules/..%2Fevil", &json!({"yaml": yaml}))
            .is_err());

        // Export in each format.
        let nd = c.get_text("/v1/export?max=5&format=ndjson").unwrap();
        assert_eq!(nd.lines().count(), 5);
        let js: serde_json::Value =
            serde_json::from_str(&c.get_text("/v1/export?max=3&format=json").unwrap()).unwrap();
        assert_eq!(js.as_array().unwrap().len(), 3);
        assert!(c
            .get_text("/v1/export?max=3&format=csv")
            .unwrap()
            .starts_with("seq,wall_ns"));
        assert!(c.get("/v1/nonsense").is_err());

        // The caller's access was itself recorded.
        let access = wait_for("api_access", || {
            let r = c.get("/v1/events?kind=api_access&limit=5").ok()?;
            (!r["events"].as_array()?.is_empty()).then_some(r)
        });
        assert_eq!(access["events"][0]["data"]["uid"], 0);
        let _ = child.kill();
        let _ = child.wait();
    }
}

mod system {
    use std::process::Command;

    use super::store_mode::{records, spawn, verify};

    fn sh(cmd: &str) -> bool {
        Command::new("sh")
            .args(["-c", cmd])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    #[ignore = "needs root, systemd, journald and sshd"]
    fn service_restarts_and_ssh_sessions_are_recorded() {
        let t = tempfile::tempdir().unwrap();
        let user = format!("ws{}", std::process::id() % 100_000);
        let key = t.path().join("id");
        assert!(sh(&format!(
            "ssh-keygen -q -t ed25519 -N '' -f {}",
            key.display()
        )));
        sh(&format!("userdel -r {user} 2>/dev/null"));
        assert!(sh(&format!("useradd -m {user}")));
        assert!(sh(&format!(
            "mkdir -p /home/{user}/.ssh && cp {}.pub /home/{user}/.ssh/authorized_keys && \
             chown -R {user}: /home/{user}/.ssh && chmod 700 /home/{user}/.ssh",
            key.display()
        )));
        let (mut child, _err) = spawn(&t.path().join("data"), 30);
        std::thread::sleep(std::time::Duration::from_secs(3));
        sh("systemctl restart cron.service");
        let ssh_ok = sh(&format!(
            "ssh -i {} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=10 {user}@127.0.0.1 true",
            key.display()
        ));
        std::thread::sleep(std::time::Duration::from_secs(5));
        sh(&format!("userdel -r {user} 2>/dev/null"));
        let _ = child.wait();

        let ev = records(&t.path().join("data"));
        verify(&t.path().join("data"));
        let svc: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "service_change" && e["data"]["unit"] == "cron.service")
            .map(|e| e["data"]["action"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(
            svc.iter().any(|a| a == "stop") && svc.iter().any(|a| a == "start"),
            "service events: {svc:?}"
        );
        assert!(ssh_ok, "the test's own ssh login failed");
        // One ssh login is one record: sshd's method and remote address merged with logind's
        // session id.
        let logins: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "login" && e["data"]["user"] == user.as_str())
            .collect();
        assert_eq!(logins.len(), 1, "one login record expected: {logins:?}");
        let login = logins[0];
        assert_eq!(login["data"]["service"], "sshd");
        assert_eq!(login["data"]["remote_addr"], "127.0.0.1");
        let sid = login["data"]["session_id"].clone();
        assert!(
            sid.as_u64().is_some_and(|n| n > 0),
            "no session id: {login:?}"
        );
        assert!(
            ev.iter().any(|e| e["type"] == "logout"
                && e["data"]["user"] == user.as_str()
                && e["data"]["session_id"] == sid),
            "no matching logout"
        );
    }
}

mod integrity {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::store_mode::{records, spawn};

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn a_modified_store_is_detected_by_the_scheduled_check_and_alerts() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().join("data");
        // Run 1: create some evidence, stop cleanly.
        let (mut c1, _e) = spawn(&data, 7);
        Command::new("/bin/true").status().unwrap();
        let _ = c1.wait();

        // Tamper with a record in the middle of a stored segment (any plain one).
        let seg = data.join("segments");
        let mut target = None;
        for e in fs::read_dir(&seg).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "ndjson") {
                target = Some(p);
            }
        }
        let p = target.expect("a plain segment to modify");
        let mut b = fs::read(&p).unwrap();
        let at = b
            .windows(7)
            .position(|w| w == b"\"type\":")
            .expect("a record");
        b[at + 8] ^= 0x01; // flip a bit inside a record body
        fs::write(&p, b).unwrap();

        // Run 2: the scheduled check runs every 3 s and must notice.
        let rules = t.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        let pack = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
        fs::copy(
            pack.join("integrity-failed.yml"),
            rules.join("integrity-failed.yml"),
        )
        .unwrap();
        let cfg = t.path().join("c.toml");
        fs::write(
            &cfg,
            format!(
                "[rules]\ndir = \"{}\"\n[api]\nsocket = \"{}\"\n",
                rules.display(),
                t.path().join("s/witness.sock").display()
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_witnessd"))
            .args(["run", "--config"])
            .arg(&cfg)
            .arg("--data-dir")
            .arg(&data)
            .args(["--seconds", "16"])
            .env("WITNESS_VERIFY_EVERY_SECS", "3")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_secs(1));
        let _ = child.wait();
        let ev = records(&data);
        let checks: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "integrity_check")
            .collect();
        assert!(
            checks.iter().any(|e| e["data"]["state"] == "broken"),
            "no broken integrity_check: {checks:?}"
        );
        assert!(
            ev.iter()
                .any(|e| e["type"] == "alert"
                    && e["data"]["rule_id"] == "witness.self.integrity-failed"),
            "no alert for the failed check"
        );
    }
}

mod net2 {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::time::Duration;

    use super::store_mode::{records, spawn, verify};

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn udp_flows_are_summarised_per_process_with_byte_counts() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 24);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cport = client.local_addr().unwrap().port();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let srv = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..5 {
                let (_, from) = server.recv_from(&mut buf).unwrap();
                server.send_to(&[7u8; 40], from).unwrap();
            }
        });
        for _ in 0..5 {
            client.send_to(&[1u8; 100], ("127.0.0.1", sport)).unwrap();
            let mut b = [0u8; 64];
            client.recv_from(&mut b).unwrap();
        }
        srv.join().unwrap();
        // The next flush is within 10 s; keep the sockets open until after it.
        std::thread::sleep(Duration::from_secs(13));
        drop((client,));
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let mine: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "udp_flow" && e["actor"]["pid"] == std::process::id())
            .collect();
        let sum = |lp: u64, rp: u64, f: &str| -> u64 {
            mine.iter()
                .filter(|e| e["data"]["lport"] == lp && e["data"]["rport"] == rp)
                .map(|e| e["data"][f].as_u64().unwrap())
                .sum()
        };
        let (cp, sp) = (cport as u64, sport as u64);
        // The client's view: sent 5 x 100, received 5 x 40.
        assert_eq!(sum(cp, sp, "bytes_tx"), 500, "flows: {mine:?}");
        assert_eq!(sum(cp, sp, "packets_tx"), 5);
        assert_eq!(sum(cp, sp, "bytes_rx"), 200);
        assert_eq!(sum(cp, sp, "packets_rx"), 5);
        // The server's view of the same conversation, from the other socket.
        assert_eq!(sum(sp, cp, "bytes_tx"), 200);
        assert_eq!(sum(sp, cp, "bytes_rx"), 500);
        assert!(mine[0]["actor"]["exe"].as_str().is_some());
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn dns_over_tcp_is_captured_and_parsed() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 12);
        let srv = TcpListener::bind("127.0.0.1:53").unwrap();
        let th = std::thread::spawn(move || {
            let (mut s, _) = srv.accept().unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut q).unwrap();
            // Answer in one write: length prefix + response with a single A record.
            let mut r = q.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            r[7] = 1;
            r.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
            let mut out = (r.len() as u16).to_be_bytes().to_vec();
            out.extend(r);
            s.write_all(&out).unwrap();
        });
        let mut c = TcpStream::connect("127.0.0.1:53").unwrap();
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["tcp-witness", "example"] {
            q.push(l.len() as u8);
            q.extend(l.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        let mut out = (q.len() as u16).to_be_bytes().to_vec();
        out.extend(&q);
        c.write_all(&out).unwrap();
        let mut resp = [0u8; 256];
        let n = c.read(&mut resp).unwrap();
        assert!(n > 14);
        th.join().unwrap();
        std::thread::sleep(Duration::from_millis(800));
        let _ = child.wait();

        let ev = records(t.path());
        let dns: Vec<_> = ev
            .iter()
            .filter(|e| e["type"] == "dns" && e["actor"]["pid"] == std::process::id())
            .collect();
        let query = dns
            .iter()
            .find(|e| e["data"]["direction"] == "query")
            .unwrap_or_else(|| panic!("no tcp query; dns events: {dns:?}"));
        assert_eq!(query["data"]["transport"], "tcp");
        assert_eq!(query["data"]["qname"], "tcp-witness.example");
        let resp = dns
            .iter()
            .find(|e| e["data"]["direction"] == "response")
            .unwrap_or_else(|| panic!("no tcp response; dns events: {dns:?}"));
        assert_eq!(resp["data"]["transport"], "tcp");
        assert_eq!(resp["data"]["answers"][0]["data"], "10.1.2.3");
    }
}

mod features {
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::store_mode::{records, spawn, spawn_cfg, verify};

    /// A config whose rules directory holds the named rules from the pack.
    fn cfg_with_rules(t: &Path, rules: &[&str]) -> PathBuf {
        let dir = t.join("rules.d");
        fs::create_dir_all(&dir).unwrap();
        let pack = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
        for r in rules {
            fs::copy(pack.join(r), dir.join(r)).unwrap();
        }
        let cfg = t.join("config.toml");
        fs::write(&cfg, format!("[rules]\ndir = \"{}\"\n", dir.display())).unwrap();
        cfg
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn exec_records_the_whole_argv_cwd_and_stdio_and_a_shell_on_a_socket_alerts() {
        let t = tempfile::tempdir().unwrap();
        let cfg = cfg_with_rules(t.path(), &["reverse-shell-stdio.yml"]);
        let data = t.path().join("data");
        let cwd = fs::canonicalize(t.path()).unwrap();
        let (mut child, _err) = spawn_cfg(&data, 14, &cfg);

        // 1. A command line far over the kernel's 3 KiB capture limit.
        let long = format!("witness-long-arg-{}", "x".repeat(10_000));
        Command::new("/bin/true")
            .arg(&long)
            .current_dir(&cwd)
            .status()
            .unwrap();

        // 2. A shell whose stdin and stdout are a socket: the shape of a reverse shell.
        let (a, _b) = UnixStream::pair().unwrap();
        let (a2, a3) = (a.try_clone().unwrap(), a.try_clone().unwrap());
        Command::new("/bin/sh")
            .args(["-c", "exit 0", "witness-sock-shell"])
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(a)))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(a2)))
            .stderr(Stdio::from(std::os::fd::OwnedFd::from(a3)))
            .status()
            .unwrap();
        // 3. An ordinary shell on pipes does not alert.
        Command::new("/bin/sh")
            .args(["-c", "exit 0", "witness-pipe-shell"])
            .output()
            .unwrap();
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.wait();

        let ev = records(&data);
        verify(&data);
        let exec_with = |needle: &str| {
            ev.iter()
                .find(|e| {
                    e["type"] == "proc_exec" && e["data"]["argv"].to_string().contains(needle)
                })
                .unwrap_or_else(|| panic!("no exec containing {needle}"))
        };
        let e = exec_with("witness-long-arg-");
        assert!(
            !e["data"]["argv_truncated"].as_bool().unwrap_or(false),
            "the whole command line was recovered (the field is omitted when false)"
        );
        let arg = e["data"]["argv"][1].as_str().unwrap();
        assert_eq!(
            arg.len(),
            long.len(),
            "no byte of the long argument was lost"
        );
        assert_eq!(e["data"]["cwd"], cwd.to_str().unwrap());

        let sock = exec_with("witness-sock-shell");
        assert_eq!(sock["data"]["stdio"][0], "socket");
        assert_eq!(sock["data"]["stdio"][1], "socket");
        let pipe = exec_with("witness-pipe-shell");
        assert_eq!(pipe["data"]["stdio"][1], "pipe");

        let alerts: Vec<_> = ev
            .iter()
            .filter(|e| {
                e["type"] == "alert" && e["data"]["rule_id"] == "witness.exec.shell-on-socket"
            })
            .collect();
        assert_eq!(
            alerts.len(),
            1,
            "exactly the socket shell alerts: {alerts:?}"
        );
        let trig = alerts[0]["data"]["trigger_seqs"][0].as_u64().unwrap();
        assert!(ev
            .iter()
            .any(|e| e["seq"] == trig
                && e["data"]["argv"].to_string().contains("witness-sock-shell")));
    }

    #[test]
    #[ignore = "needs root and systemd"]
    fn enabling_disabling_and_masking_a_unit_are_recorded() {
        let t = tempfile::tempdir().unwrap();
        let unit = "witness-feature-test.service";
        let path = format!("/etc/systemd/system/{unit}");
        fs::write(&path, "[Unit]\nDescription=witness test\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n").unwrap();
        let sh = |c: &str| {
            Command::new("sh")
                .args(["-c", c])
                .status()
                .unwrap()
                .success()
        };
        let (mut child, _err) = spawn(t.path(), 22);
        std::thread::sleep(Duration::from_secs(1));
        assert!(sh(&format!("systemctl enable {unit} >/dev/null 2>&1")));
        std::thread::sleep(Duration::from_millis(600));
        assert!(sh(&format!("systemctl disable {unit} >/dev/null 2>&1")));
        std::thread::sleep(Duration::from_millis(600));
        // systemd will not mask over a real unit file, so remove ours first.
        fs::remove_file(&path).unwrap();
        assert!(sh(&format!("systemctl mask {unit} >/dev/null 2>&1")));
        std::thread::sleep(Duration::from_millis(600));
        assert!(sh(&format!("systemctl unmask {unit} >/dev/null 2>&1")));
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let actions: Vec<String> = ev
            .iter()
            .filter(|e| e["type"] == "service_change" && e["data"]["unit"] == unit)
            .map(|e| e["data"]["action"].as_str().unwrap_or("").to_string())
            .collect();
        for want in ["enable", "disable", "mask", "unmask"] {
            assert!(
                actions.iter().any(|a| a == want),
                "missing {want}; got {actions:?}"
            );
        }
        // In the order they were done.
        let pos = |w: &str| actions.iter().position(|a| a == w).unwrap();
        assert!(
            pos("enable") < pos("disable")
                && pos("disable") < pos("mask")
                && pos("mask") < pos("unmask")
        );
    }

    #[test]
    #[ignore = "needs root and a USB host controller"]
    fn a_kernel_usb_add_event_is_recorded_once_and_an_unknown_device_alerts_once() {
        let hub = Path::new("/sys/bus/usb/devices/usb1");
        if !hub.exists() {
            eprintln!("skipped: no USB host controller on this machine");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let cfg = cfg_with_rules(t.path(), &["usb-unknown.yml"]);
        let data = t.path().join("data");
        let (mut child, _err) = spawn_cfg(&data, 12, &cfg);
        // Ask the kernel to re-announce the device: a real `add` uevent for a real device
        // (not a hot-plug). Twice, to see that a known device alerts only once.
        for _ in 0..2 {
            fs::write(hub.join("uevent"), "add").unwrap();
            std::thread::sleep(Duration::from_millis(800));
        }
        let _ = child.wait();
        let read = |f: &str| {
            fs::read_to_string(hub.join(f))
                .map(|s| s.trim().to_string())
                .ok()
        };
        let (vid, pid) = (read("idVendor").unwrap(), read("idProduct").unwrap());

        let ev = records(&data);
        verify(&data);
        let usb: Vec<_> = ev
            .iter()
            .filter(|e| {
                e["type"] == "usb_device"
                    && e["data"]["action"] == "add"
                    && e["data"]["vendor_id"]
                        .as_str()
                        .is_some_and(|v| v.trim_start_matches('0') == vid.trim_start_matches('0'))
            })
            .collect();
        assert!(usb.len() >= 2, "both re-announcements recorded: {usb:?}");
        assert_eq!(
            usb[0]["data"]["product_id"]
                .as_str()
                .unwrap()
                .trim_start_matches('0'),
            pid.trim_start_matches('0')
        );
        assert_eq!(
            usb[0]["data"]["product"].as_str().map(str::to_string),
            read("product")
        );
        let alerts = ev
            .iter()
            .filter(|e| {
                e["type"] == "alert" && e["data"]["rule_id"] == "witness.device.usb-unknown"
            })
            .count();
        assert_eq!(alerts, 1, "a device alerts the first time only");
        // The learned set was saved for the next run.
        let learned = fs::read_to_string(data.join("learned.json")).unwrap();
        assert!(learned.contains("witness.device.usb-unknown"), "{learned}");
    }

    #[test]
    #[ignore = "needs root, a package manager and network access to its repository"]
    fn installing_and_removing_a_package_is_recorded_from_the_real_package_log() {
        let have = |c: &str| {
            Command::new("sh")
                .args(["-c", &format!("command -v {c} >/dev/null")])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        let (install, remove, manager) = if have("dnf") {
            ("dnf -y -q install hello", "dnf -y -q remove hello", "dnf")
        } else if have("apt-get") {
            (
                "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq hello",
                "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 remove -y -qq hello",
                "dpkg",
            )
        } else {
            eprintln!("skipped: no supported package manager");
            return;
        };
        let sh = |c: &str| {
            Command::new("sh")
                .args(["-c", c])
                .status()
                .unwrap()
                .success()
        };
        // Start from a known state: hello not installed.
        sh(remove);
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 70);
        std::thread::sleep(Duration::from_secs(2));
        assert!(sh(install), "could not install hello (no network?)");
        std::thread::sleep(Duration::from_secs(3));
        assert!(sh(remove));
        std::thread::sleep(Duration::from_secs(4));
        let _ = child.kill();
        let _ = child.wait();

        let ev = records(t.path());
        let actions: Vec<String> = ev
            .iter()
            .filter(|e| e["type"] == "package_change" && e["data"]["name"] == "hello")
            .map(|e| e["data"]["action"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(
            actions.iter().any(|a| a == "install"),
            "{manager}: {actions:?}"
        );
        assert!(
            actions.iter().any(|a| a == "remove"),
            "{manager}: {actions:?}"
        );
        let first = ev
            .iter()
            .find(|e| {
                e["type"] == "package_change"
                    && e["data"]["name"] == "hello"
                    && e["data"]["action"] == "install"
            })
            .unwrap();
        assert_eq!(first["data"]["manager"], manager);
        assert!(first["data"]["version"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF"]
    fn the_first_start_on_a_boot_records_the_boot() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 6);
        let _ = child.wait();
        let ev = records(t.path());
        let boot = ev
            .iter()
            .find(|e| e["type"] == "system_boot")
            .expect("a system_boot record");
        let uname =
            String::from_utf8(Command::new("uname").arg("-r").output().unwrap().stdout).unwrap();
        assert_eq!(boot["data"]["kernel"], uname.trim());
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
        assert_eq!(boot["data"]["cmdline"], cmdline.trim());
    }
}

mod load {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::store_mode::{records, spawn, verify};

    /// `(cpu ticks, resident KiB)` of a process, from /proc.
    fn usage(pid: u32) -> (u64, u64) {
        let stat = fs_read(&format!("/proc/{pid}/stat"));
        let rest = &stat[stat.rfind(')').unwrap() + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks = f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap();
        let rss_pages: u64 = fs_read(&format!("/proc/{pid}/statm"))
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (ticks, rss_pages * 4)
    }

    fn fs_read(p: &str) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    #[ignore = "needs root and a kernel with BTF; takes about a minute"]
    fn sustained_load_is_either_captured_or_reported_as_dropped_never_silently_lost() {
        let t = tempfile::tempdir().unwrap();
        let (mut child, _err) = spawn(t.path(), 45);
        let dpid = child.id();
        std::thread::sleep(Duration::from_secs(2));
        let (cpu0, _) = usage(dpid);
        let t0 = Instant::now();

        let stop = Arc::new(AtomicBool::new(false));
        let execs = Arc::new(AtomicU64::new(0));
        let marker = format!("witness-load-{}", std::process::id());
        let mut workers = Vec::new();
        // Process churn: as fast as `fork+exec+wait` allows, on several threads.
        for _ in 0..4 {
            let (stop, execs, m) = (stop.clone(), execs.clone(), marker.clone());
            workers.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if Command::new("/bin/true").arg(&m).status().is_ok() {
                        execs.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        // File churn: create, write, rename, delete.
        {
            let (stop, dir) = (stop.clone(), t.path().join("churn"));
            std::fs::create_dir_all(&dir).unwrap();
            workers.push(std::thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let a = dir.join(format!("f{}", i % 64));
                    let b = dir.join(format!("g{}", i % 64));
                    let _ = std::fs::write(&a, b"data");
                    let _ = std::fs::rename(&a, &b);
                    let _ = std::fs::remove_file(&b);
                    i += 1;
                }
            }));
        }
        // Network churn: many short TCP connections and UDP datagrams on loopback.
        {
            let stop = stop.clone();
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            l.set_nonblocking(true).unwrap();
            let stop2 = stop.clone();
            workers.push(std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    if let Ok((mut c, _)) = l.accept() {
                        let mut b = [0u8; 16];
                        let _ = c.read(&mut b);
                        let _ = c.write_all(b"pong");
                    } else {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }));
            workers.push(std::thread::spawn(move || {
                let u = UdpSocket::bind("127.0.0.1:0").unwrap();
                let v = UdpSocket::bind("127.0.0.1:0").unwrap();
                let vaddr = v.local_addr().unwrap();
                v.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                let mut b = [0u8; 64];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) {
                        let _ = c.write_all(b"ping");
                        let _ = c.read(&mut b);
                    }
                    let _ = u.send_to(b"x", vaddr);
                    let _ = v.recv_from(&mut b);
                }
            }));
        }

        std::thread::sleep(Duration::from_secs(20));
        stop.store(true, Ordering::Relaxed);
        for w in workers {
            w.join().unwrap();
        }
        let elapsed = t0.elapsed().as_secs_f64();
        let (cpu1, rss) = usage(dpid);
        let done = execs.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(3));
        let cpu_pct = (cpu1 - cpu0) as f64 / 100.0 / elapsed * 100.0;
        let _ = child.wait();

        let ev = records(t.path());
        verify(t.path());
        let seen = ev
            .iter()
            .filter(|e| e["type"] == "proc_exec" && e["data"]["argv"].to_string().contains(&marker))
            .count() as u64;
        let dropped: u64 = ev
            .iter()
            .filter(|e| e["type"] == "capture_drop")
            // `dropped` is `[p0, p1, p2, p3]`: execs are P0, the first class.
            .map(|e| e["data"]["dropped"][0].as_u64().unwrap_or(0))
            .sum();
        let lost = done.saturating_sub(seen);
        eprintln!(
            "LOAD RESULT: {done} execs in {elapsed:.0}s = {:.0}/s; {seen} captured, {lost} lost, {dropped} drops reported; daemon CPU {cpu_pct:.0}% of one core, RSS {} MiB; {} records stored",
            done as f64 / elapsed,
            rss / 1024,
            ev.len()
        );
        assert!(done > 1000, "the generator did too little work: {done}");
        // The invariant: a lost exec must be accounted for by a reported kernel drop.
        assert!(
            lost <= dropped,
            "{lost} execs went missing but only {dropped} drops were reported: silent loss"
        );
        // A healthy daemon under this load does not run away with memory.
        assert!(rss / 1024 < 1024, "RSS {} MiB", rss / 1024);
    }
}
