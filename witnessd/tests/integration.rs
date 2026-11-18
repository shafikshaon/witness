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
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
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
