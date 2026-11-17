//! Command implementations for the `witnessd` binary (Linux).

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustix::time::{clock_gettime, ClockId};

use crate::btf::Btf;
use crate::decode::Decoder;
use crate::loader::Collector;

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
    println!("hook functions (fentry/fexit candidates):");
    let missing = btf.missing_funcs(HOOK_FUNCS);
    for f in HOOK_FUNCS {
        println!(
            "  {:<24}{}",
            f,
            if missing.contains(f) { "MISSING" } else { "ok" }
        );
    }
    Ok(())
}

/// Ring buffer size for P0 events.
const RING_CRITICAL_BYTES: u32 = 8 << 20;

pub fn run(seconds: Option<u64>) -> Result<()> {
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let offsets = btf.resolve_offsets()?.offsets;
    let mut collector = Collector::start(offsets, RING_CRITICAL_BYTES)?;
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
        collector.poll(Duration::from_millis(250), |rec| {
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
        let drops = collector.dropped()?;
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
