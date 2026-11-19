//! Command implementations for the `witnessd` binary (Linux).

use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use rustix::time::{clock_gettime, ClockId};
use sd_notify::NotifyState;
use sha2::{Digest, Sha256};
use witness_config::Config;
use witness_store::anchor::{AnchorSink, CommandSink, FileSink};
use witness_store::index::Index;

use crate::btf::Btf;
use crate::decode::Decoder;
use crate::filepolicy::{content_changed_path, Class, FilePolicy};
use crate::hasher::{Hasher, Settings as HashSettings};
use crate::loader::Collector;
use crate::pipeline::{Pipeline, Settings, SystemClock};
use crate::sensitive::Sensitive;

/// Kernel functions the planned hooks attach to (DESIGN.md §2); `doctor` reports which
/// exist on this kernel.
const HOOK_FUNCS: &[&str] = &[
    "commit_creds",
    "security_file_open",
    "security_file_free",
    "security_path_mknod",
    "security_path_mkdir",
    "security_path_unlink",
    "security_path_rmdir",
    "security_path_rename",
    "security_path_chmod",
    "security_path_chown",
    "security_path_link",
    "security_path_symlink",
    "security_path_truncate",
    "tcp_v4_connect",
    "tcp_v6_connect",
    "inet_csk_accept",
    "tcp_sendmsg",
    "tcp_recvmsg",
    "udp_sendmsg",
    "udpv6_sendmsg",
    "udp_recvmsg",
    "udpv6_recvmsg",
];

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn clock_offset_ns() -> i64 {
    let ns = |c: ClockId| {
        let t = clock_gettime(c);
        t.tv_sec as i64 * 1_000_000_000 + t.tv_nsec as i64
    };
    ns(ClockId::Realtime) - ns(ClockId::Boottime)
}

pub fn doctor() -> Result<()> {
    println!("kernel      {}", kernel_release());
    println!("boot id     {}", boot_id());
    let btf = Btf::from_sys_fs().context("this kernel exposes no BTF (/sys/kernel/btf/vmlinux)")?;
    println!("BTF         present");
    let r = btf.resolve_offsets().context("resolving struct offsets")?;
    println!("offsets     resolved ({} optional missing)", r.notes.len());
    for n in &r.notes {
        println!("  note: {n}");
    }
    println!("hook functions (fentry/fexit candidates), with BTF parameter counts:");
    let missing = btf.missing_funcs(HOOK_FUNCS);
    for f in HOOK_FUNCS {
        match btf.func_param_count(f) {
            Some(n) => println!("  {f:<24}ok ({n} params)"),
            None => println!(
                "  {f:<24}{}",
                if missing.contains(f) { "MISSING" } else { "?" }
            ),
        }
    }
    Ok(())
}

/// Ring buffer size for P0 events when no config is loaded.
const RING_CRITICAL_BYTES: u32 = 8 << 20;

/// Captures and prints one JSON event per line; stores nothing.
pub fn tail(seconds: Option<u64>) -> Result<()> {
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let offsets = btf.resolve_offsets()?.offsets;
    let (mut collector, hooks) = Collector::start(
        offsets,
        &btf,
        RING_CRITICAL_BYTES,
        32 << 20,
        crate::loader::Groups {
            files: true,
            network: true,
            dns: true,
            system: true,
        },
        &|| false,
    )?;
    for h in &hooks {
        if let Err(why) = &h.status {
            tracing::warn!(hook = h.hook, %why, "hook not active");
        }
    }
    tracing::info!(kernel = %kernel_release(), "attached; capturing (ctrl-c to stop)");

    let mut decoder = Decoder::new(boot_id());
    let resolve = |pid: u32| {
        use std::os::unix::ffi::OsStrExt;
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.as_os_str().as_bytes().to_vec())
    };
    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut last_drops = 0;
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        decoder.set_clock_offset(clock_offset_ns());
        collector.poll(Duration::from_millis(250), &[], |rec| {
            match decoder.decode(rec, &resolve) {
                Ok(ev) => {
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(out, "{line}");
                    }
                }
                Err(e) => tracing::warn!("undecodable record: {e}"),
            }
        })?;
        let _ = out.flush();
        let drops: u64 = collector.dropped()?.iter().sum();
        if drops != last_drops {
            tracing::warn!(
                dropped = drops - last_drops,
                "kernel ring buffer overflowed"
            );
            last_drops = drops;
        }
    }
    Ok(())
}

/// Whether a (blocked) signal is waiting on the signalfd, without consuming it.
fn signal_pending(fd: std::os::fd::BorrowedFd<'_>) -> bool {
    let mut fds = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    let zero = rustix::time::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(rustix::event::poll(&mut fds, Some(&zero)), Ok(n) if n > 0)
}

/// Tells systemd; a missing `NOTIFY_SOCKET` (not run by systemd) is not an error.
fn notify(state: &[NotifyState<'_>]) {
    if let Err(e) = sd_notify::notify(state) {
        tracing::debug!(error = %e, "sd_notify failed");
    }
}

fn hex(bytes: &[u8]) -> String {
    witness_store::chain::to_hex(&<[u8; 32]>::try_from(bytes).unwrap_or([0; 32]))
}

fn load_config(path: &Path) -> Result<(Config, String)> {
    if path.exists() {
        let (cfg, sha) =
            Config::load(path).with_context(|| format!("loading {}", path.display()))?;
        Ok((cfg, hex(&sha)))
    } else {
        tracing::warn!(path = %path.display(), "no config file; running on defaults");
        Ok((Config::default(), hex(&Sha256::digest(b""))))
    }
}

/// Runs the index in the background: it only reads the segments, never blocks capture, and
/// can always be rebuilt (`witness reindex`).
fn spawn_indexer(data_dir: PathBuf, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let seg_dir = data_dir.join("segments");
        let mut ix = match Index::open(&data_dir.join("index.db")) {
            Ok(ix) => ix,
            Err(e) => {
                tracing::error!(error = %e, "cannot open the index; search is unavailable");
                return;
            }
        };
        let mut last_err = Instant::now() - Duration::from_secs(3600);
        loop {
            let stopping = stop.load(Ordering::SeqCst);
            if let Err(e) = ix.catch_up(&seg_dir) {
                if last_err.elapsed() > Duration::from_secs(30) {
                    tracing::error!(error = %e, "indexing failed (will retry)");
                    last_err = Instant::now();
                }
            }
            if stopping {
                return;
            }
            for _ in 0..10 {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    })
}

/// The daemon: capture into the tamper-evident store until SIGTERM/SIGINT (or `seconds`).
pub fn run(config: &Path, data_dir: Option<PathBuf>, seconds: Option<u64>) -> Result<()> {
    // Block SIGTERM/SIGINT before anything else (and before any thread exists, so every
    // thread inherits the mask) and read them from a signalfd. A blocked signal stays
    // pending until read, so none can be lost or kill us mid-startup, and a stop request
    // that arrives while starting is honoured as soon as capture is running.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()
        .context("blocking termination signals")?;
    let sigfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .context("creating the signalfd")?;

    let (cfg, config_sha) = load_config(config)?;
    let data_dir = data_dir.unwrap_or_else(|| cfg.daemon.data_dir.clone());

    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let offsets = btf.resolve_offsets()?.offsets;

    let mut sinks: Vec<Box<dyn AnchorSink>> =
        vec![Box::new(FileSink::new(data_dir.join("anchors.log")))];
    if let Some(cmd) = &cfg.storage.anchor_command {
        if let Some((prog, args)) = cmd.split_first() {
            sinks.push(Box::new(CommandSink::new(prog.clone(), args.to_vec())));
        }
    }
    let settings = Settings {
        boot_id: boot_id(),
        version: env!("CARGO_PKG_VERSION").into(),
        kernel: kernel_release(),
        btf: true,
        pid: std::process::id(),
        config_sha256: config_sha,
        bpf_object_sha256: crate::loader::object_sha256(),
        group_commit: Duration::from_millis(cfg.storage.group_commit_ms),
        anchor_interval: Duration::from_secs(cfg.storage.anchor_interval_secs),
        seal_interval: Duration::from_secs(cfg.seal.interval_secs),
        sealing: cfg.seal.enabled,
    };
    let boot = settings.boot_id.clone();
    let mut pipeline = Pipeline::open(
        &data_dir,
        cfg.store_config(),
        sinks,
        settings,
        Box::new(SystemClock::default()),
    )?;

    let (mut collector, hooks) = Collector::start(
        offsets,
        &btf,
        cfg.capture.ring_critical_mib << 20,
        cfg.capture.ring_volume_mib << 20,
        crate::loader::Groups {
            files: cfg.capture.files,
            network: cfg.capture.network,
            dns: cfg.capture.dns,
            system: cfg.capture.auth,
        },
        &|| signal_pending(sigfd.as_fd()),
    )?;
    let failed: Vec<String> = hooks
        .iter()
        .filter_map(|h| h.status.as_ref().err().map(|e| format!("{}: {e}", h.hook)))
        .collect();
    for f in &failed {
        tracing::warn!(reason = %f, "file hook not active");
    }
    pipeline.source_health("ebpf.process", "active", None)?;
    let (status, reason) = match (failed.len(), hooks.len()) {
        (0, _) => ("active", None),
        (n, total) if n == total => ("unavailable", Some(failed.join("; "))),
        _ => ("degraded", Some(failed.join("; "))),
    };
    pipeline.source_health("ebpf.files", status, reason)?;
    match pipeline.set_rules(&cfg.rules.dir) {
        Ok(n) => tracing::info!(rules = n, dir = %cfg.rules.dir.display(), "rule engine active"),
        Err(e) => tracing::warn!(error = %e, "rule engine not started"),
    }
    let integrity = {
        let (first, every) = crate::integrity::intervals_from_env();
        crate::integrity::Scheduler::start(data_dir.join("segments"), first, every)
    };
    let api = match crate::api::Api::start(crate::api::ApiConfig {
        socket: cfg.api.socket.clone(),
        group: cfg.api.group.clone(),
        admin_group: cfg.api.admin_group.clone(),
        data_dir: data_dir.clone(),
        rules_dir: cfg.rules.dir.clone(),
    }) {
        Ok(a) => {
            tracing::info!(socket = %cfg.api.socket.display(), "api listening");
            pipeline.source_health("api", "active", None)?;
            Some(a)
        }
        Err(e) => {
            tracing::warn!(error = %e, "api not available");
            pipeline.source_health("api", "unavailable", Some(e.to_string()))?;
            None
        }
    };
    let sources = cfg
        .capture
        .auth
        .then(|| crate::sources::Sources::start(crate::sources::Roots::default(), true));
    match &sources {
        Some(s) if s.unavailable.is_empty() => pipeline.source_health("auth", "active", None)?,
        Some(s) => {
            let why = s
                .unavailable
                .iter()
                .map(|(n, e)| format!("{n}: {e}"))
                .collect::<Vec<_>>()
                .join("; ");
            tracing::warn!(reason = %why, "auth source degraded");
            pipeline.source_health("auth", "degraded", Some(why))?
        }
        None => pipeline.source_health("auth", "disabled", None)?,
    }
    tracing::info!(
        kernel = %kernel_release(),
        data_dir = %data_dir.display(),
        "attached; capturing into the tamper-evident store"
    );

    // READY only now: programs are attached, so services ordered after us start under capture.
    notify(&[NotifyState::Ready, NotifyState::Status("capturing")]);
    // Ping the watchdog from the main loop only: a stalled pipeline stops pinging and systemd
    // restarts the service.
    let watchdog_every = sd_notify::watchdog_enabled().map(|d| d / 3);
    let mut last_ping = Instant::now();

    let mut signalled: Option<u8> = None;
    let index_stop = Arc::new(AtomicBool::new(false));
    let indexer = spawn_indexer(data_dir.clone(), Arc::clone(&index_stop));

    // What already exists, so pre-existing activity is attributable. Done after READY so it
    // never delays the services ordered after us, and after attach so nothing can be missed
    // between the snapshot and live capture (duplicates are harmless).
    let snap_ctx = crate::baseline::Context {
        boot_id: boot.clone(),
        boot_ns: pipeline.boot_ns(),
        wall_ns: pipeline.wall_ns(),
        gap_from_boot_ns: pipeline.gap_from_boot_ns(),
    };
    let t0 = Instant::now();
    let snapshot = crate::baseline::collect(&crate::baseline::Roots::default(), &snap_ctx);
    let n = snapshot.len();
    for ev in &snapshot {
        pipeline.ingest(ev)?;
    }
    tracing::info!(
        records = n,
        took_ms = t0.elapsed().as_millis() as u64,
        "baseline snapshot stored"
    );

    let mut decoder = Decoder::new(boot.clone());
    for ev in &snapshot {
        decoder.learn(ev);
    }
    let mut policy = FilePolicy::new(
        &cfg.files.critical_extra,
        &cfg.files.watch,
        &cfg.files.exclude,
    );
    let mut hasher = Hasher::start(HashSettings {
        max_bytes: cfg.files.hash_max_mib << 20,
        rate_bps: cfg.files.hash_rate_mib_per_sec << 20,
        debounce: Duration::from_millis(cfg.files.hash_debounce_ms),
        queue: 256,
    });
    let mut sensitive = Sensitive::new(&cfg.files.sensitive_read);
    let summary_every = Duration::from_secs(60);
    // UDP flow summaries (the kernel keeps running counters; this reads and clears them).
    let flows_every = Duration::from_secs(10);
    let mut last_flows = Instant::now();
    let mut last_summary = Instant::now();
    let resolve = |pid: u32| {
        use std::os::unix::ffi::OsStrExt;
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.as_os_str().as_bytes().to_vec())
    };
    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let clock = SystemClock::default();
    let mut last_drops = [0u64; 2];
    let mut drops_since = crate::pipeline::Clock::boot_ns(&clock);
    let mut failure: Option<anyhow::Error> = None;

    'main: loop {
        if let Some(info) = sigfd.read_signal().context("reading the signalfd")? {
            signalled = Some(info.ssi_signo as u8);
            break;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        decoder.set_clock_offset(clock_offset_ns());
        let mut err: Option<anyhow::Error> = None;
        let polled = collector.poll(Duration::from_millis(250), &[sigfd.as_fd()], |rec| {
            if err.is_some() {
                return;
            }
            match decoder.decode(rec, &resolve) {
                Ok(ev) => {
                    if let Some(ev) = policy.apply(ev) {
                        // A change under a critical path starts that file's quiet period;
                        // it is hashed once it has settled.
                        for p in crate::filepolicy::touched_paths(&ev) {
                            sensitive.note_change(&p.to_string_lossy(), Instant::now());
                        }
                        if let Some(path) = content_changed_path(&ev) {
                            if policy.classify(&path.to_string_lossy()) == Class::Critical {
                                hasher.note(path, ev.actor.clone(), Instant::now());
                            }
                        }
                        if let Err(e) = pipeline.ingest(&ev) {
                            err = Some(e);
                        }
                    }
                }
                Err(e) => tracing::warn!("undecodable record: {e}"),
            }
        });
        if let Err(e) = polled.and_then(|_| err.map_or(Ok(()), Err)) {
            failure = Some(e);
            break 'main;
        }
        let drops = collector.dropped()?;
        for (class, (now_n, was)) in drops.iter().zip(last_drops.iter_mut()).enumerate() {
            if now_n != was {
                let now = crate::pipeline::Clock::boot_ns(&clock);
                tracing::warn!(
                    class,
                    dropped = *now_n - *was,
                    "kernel ring buffer overflowed"
                );
                if let Err(e) = pipeline.kernel_drops(class, *now_n - *was, drops_since, now) {
                    failure = Some(e);
                    break 'main;
                }
                *was = *now_n;
            }
        }
        if last_drops == drops {
            drops_since = crate::pipeline::Clock::boot_ns(&clock);
        }
        if sensitive.due(Instant::now()) {
            let delta = sensitive.refresh(Instant::now());
            if let Err(e) = collector.sync_sensitive(&delta.add, &delta.remove) {
                tracing::warn!(error = %e, "could not update the sensitive-file set");
            }
        }
        hasher.tick(Instant::now());
        let hashed = hasher.drain(
            &boot,
            crate::pipeline::Clock::boot_ns(&clock),
            crate::pipeline::Clock::wall_ns(&clock),
        );
        for ev in &hashed {
            if let Err(e) = pipeline.ingest(ev) {
                failure = Some(e);
                break 'main;
            }
        }
        if let Some(s) = &sources {
            let (b, w) = (
                crate::pipeline::Clock::boot_ns(&clock),
                crate::pipeline::Clock::wall_ns(&clock),
            );
            for ev in s.drain(&boot, b, w) {
                if let Err(e) = pipeline.ingest(&ev) {
                    failure = Some(e);
                    break 'main;
                }
            }
        }
        for c in integrity.drain() {
            if c.state != "ok" {
                tracing::error!(state = %c.state, problem = ?c.problem, "INTEGRITY CHECK FAILED");
            }
            if let Err(e) = pipeline.record(witness_common::schema::Body::IntegrityCheck(c)) {
                failure = Some(e);
                break 'main;
            }
        }
        if let Some(a) = &api {
            for cmd in a.drain() {
                let body = match cmd {
                    crate::api::ApiCmd::Triage {
                        alert_seq,
                        status,
                        note,
                        uid,
                    } => witness_common::schema::Body::TriageAction(
                        witness_common::schema::TriageAction {
                            alert_seq,
                            status,
                            note,
                            actor_uid: uid,
                        },
                    ),
                    crate::api::ApiCmd::Access(a) => witness_common::schema::Body::ApiAccess(a),
                    crate::api::ApiCmd::Integrity(c) => {
                        witness_common::schema::Body::IntegrityCheck(c)
                    }
                };
                if let Err(e) = pipeline.record(body) {
                    failure = Some(e);
                    break 'main;
                }
            }
        }
        if last_flows.elapsed() >= flows_every {
            last_flows = Instant::now();
            let now = crate::pipeline::Clock::boot_ns(&clock);
            for rec in collector.take_flows(now) {
                match decoder.decode(&rec, &resolve) {
                    Ok(ev) => {
                        if let Err(e) = pipeline.ingest(&ev) {
                            failure = Some(e);
                            break 'main;
                        }
                    }
                    Err(e) => tracing::warn!("undecodable flow record: {e}"),
                }
            }
        }
        if last_summary.elapsed() >= summary_every {
            let interval = last_summary.elapsed().as_nanos() as u64;
            last_summary = Instant::now();
            let (b, w) = (
                crate::pipeline::Clock::boot_ns(&clock),
                crate::pipeline::Clock::wall_ns(&clock),
            );
            for ev in policy.take_summaries(&boot, b, w, interval) {
                if let Err(e) = pipeline.ingest(&ev) {
                    failure = Some(e);
                    break 'main;
                }
            }
        }
        match pipeline.tick() {
            Ok(events) => {
                for e in events {
                    tracing::warn!(event = ?e, "disk policy");
                }
            }
            Err(e) => {
                failure = Some(e);
                break 'main;
            }
        }
        if watchdog_every.is_some_and(|every| last_ping.elapsed() >= every) {
            let st = format!(
                "capturing: {} events stored, {} shed, {} lost in kernel",
                pipeline.stats.ingested - pipeline.stats.shed,
                pipeline.stats.shed,
                pipeline.stats.kernel_drops
            );
            notify(&[NotifyState::Watchdog, NotifyState::Status(&st)]);
            last_ping = Instant::now();
        }
    }
    notify(&[NotifyState::Stopping]);

    // Detach from the kernel first so nothing new arrives while we finish.
    drop(collector);
    if let Some(s) = sources {
        s.stop();
    }
    if let Some(a) = api {
        a.stop();
    }
    integrity.stop();
    let reason = match (&failure, signalled) {
        (Some(_), _) => "error",
        (None, Some(_)) => "signal",
        (None, None) => "finished",
    };
    let stats = pipeline.stop(reason, signalled)?;
    index_stop.store(true, Ordering::SeqCst);
    let _ = indexer.join();
    tracing::info!(
        ingested = stats.ingested,
        shed = stats.shed,
        kernel_drops = stats.kernel_drops,
        "stopped cleanly"
    );
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
