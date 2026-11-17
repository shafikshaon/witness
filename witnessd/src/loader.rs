//! Loads the eBPF object, hands it the BTF-resolved offsets, attaches the programs and reads
//! the ring buffer. Linux only.

use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, FExit, KProbe};
use aya::{Btf as AyaBtf, EbpfLoader, VerifierLogLevel};
use witness_common::{Offsets, UNAVAILABLE};

use crate::btf::Btf;

/// The compiled eBPF object (empty placeholder if it was not built; see `build.rs`).
static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/witness-ebpf"));

/// SHA-256 of the embedded eBPF object, recorded in `daemon_start`.
pub fn object_sha256() -> String {
    use sha2::{Digest, Sha256};
    witness_store::chain::to_hex(&Sha256::digest(OBJECT).into())
}

/// `Offsets` made loadable as a global.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct OffsetsPod(Offsets);

// SAFETY: `Offsets` is `repr(C)`, made only of `u32` fields (no padding, no invalid bit
// patterns), so copying its bytes into the program's global is sound.
unsafe impl aya::Pod for OffsetsPod {}

/// Process-lifecycle programs: `(program name, kernel tracepoint)`; failure to attach any is fatal.
const PROGRAMS: [&str; 3] = [
    "sched_process_exec",
    "sched_process_exit",
    "sched_process_fork",
];

/// File hooks: `(program, kernel function, expected parameter count)`. The count is checked
/// against the running kernel's BTF so a changed signature degrades the hook instead of
/// letting the program read the wrong argument.
/// `true` marks a kprobe (used where the signature has by-value struct arguments, which
/// fexit cannot carry); all others are fexit.
const FILE_HOOKS: [(&str, &str, usize, bool); 11] = [
    ("file_open", "security_file_open", 1, true),
    ("path_mknod", "security_path_mknod", 4, true),
    ("path_mkdir", "security_path_mkdir", 3, true),
    ("path_unlink", "security_path_unlink", 2, true),
    ("path_rmdir", "security_path_rmdir", 2, true),
    ("path_chmod", "security_path_chmod", 2, true),
    ("path_chown", "security_path_chown", 3, true),
    ("path_truncate", "security_path_truncate", 1, true),
    ("path_rename", "security_path_rename", 5, true),
    ("path_link", "security_path_link", 3, true),
    ("path_symlink", "security_path_symlink", 3, true),
];

/// Outcome of attaching one optional hook.
#[derive(Debug, Clone)]
pub struct HookReport {
    pub hook: &'static str,
    /// `Err` carries why it is not active; capture continues without it.
    pub status: Result<(), String>,
}

/// Offsets the file hooks need; if any is missing the whole file source is degraded.
fn missing_file_offsets(o: &Offsets) -> Vec<&'static str> {
    [
        ("file.f_path", o.file_f_path),
        ("file.f_mode", o.file_f_mode),
        ("file.f_flags", o.file_f_flags),
        ("path.mnt", o.path_mnt),
        ("path.dentry", o.path_dentry),
        ("dentry.d_parent", o.dentry_d_parent),
        ("dentry.d_name", o.dentry_d_name),
        ("dentry.d_inode", o.dentry_d_inode),
        ("dentry.d_sb", o.dentry_d_sb),
        ("qstr.name", o.qstr_name),
        ("qstr.len", o.qstr_len),
        ("mount.mnt_parent", o.mount_mnt_parent),
        ("mount.mnt_mountpoint", o.mount_mnt_mountpoint),
        ("mount.mnt", o.mount_mnt),
        ("inode.i_mode", o.inode_i_mode),
        ("inode.i_ino", o.inode_i_ino),
        ("super_block.s_dev", o.sb_s_dev),
        ("super_block.s_magic", o.sb_s_magic),
    ]
    .into_iter()
    .filter(|(_, v)| *v == UNAVAILABLE)
    .map(|(n, _)| n)
    .collect()
}

/// The kernel programs read `d_parent`/`d_name` and `mnt_parent`/`mnt_mountpoint` as
/// contiguous blocks; refuse file capture on a kernel whose layout differs.
fn layout_problem(o: &Offsets) -> Option<String> {
    if o.dentry_d_name != o.dentry_d_parent.wrapping_add(8) {
        return Some("dentry.d_name does not directly follow d_parent".into());
    }
    if o.qstr_len != 4 || o.qstr_name != 8 {
        return Some(format!(
            "qstr layout differs (len at {}, name at {}; expected 4 and 8)",
            o.qstr_len, o.qstr_name
        ));
    }
    if o.mount_mnt_mountpoint != o.mount_mnt_parent.wrapping_add(8) {
        return Some("mount.mnt_mountpoint does not directly follow mnt_parent".into());
    }
    None
}

pub struct Collector {
    critical: RingBuf<MapData>,
    volume: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    // Dropping `Ebpf` detaches the programs, so it must outlive the readers.
    _ebpf: aya::Ebpf,
}

impl Collector {
    pub fn start(
        offsets: Offsets,
        btf: &Btf,
        critical_bytes: u32,
        volume_bytes: u32,
        files: bool,
    ) -> Result<(Collector, Vec<HookReport>)> {
        if OBJECT.is_empty() {
            bail!("this build has no eBPF object (built off Linux or with WITNESS_SKIP_EBPF=1)");
        }
        let self_tgid = std::process::id();
        // Stats-only by default: a rejected program then costs one fast attempt instead of
        // aya's retry-with-a-bigger-buffer loop over a multi-megabyte trace. Set
        // WITNESS_VERIFIER_LOG=debug (or verbose) for the full trace when diagnosing.
        let log_level = match std::env::var("WITNESS_VERIFIER_LOG").as_deref() {
            Ok("debug") => VerifierLogLevel::DEBUG | VerifierLogLevel::STATS,
            Ok("verbose") => VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS,
            _ => VerifierLogLevel::STATS,
        };
        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(log_level)
            .override_global("OFFSETS", &OffsetsPod(offsets), true)
            .override_global("SELF_TGID", &self_tgid, true)
            .map_max_entries("CRITICAL", critical_bytes)
            .map_max_entries("VOLUME", volume_bytes)
            .load(OBJECT)
            .context("loading the eBPF object")?;

        let kbtf = AyaBtf::from_sys_fs().context("reading /sys/kernel/btf/vmlinux")?;
        for name in PROGRAMS {
            let prog: &mut BtfTracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} missing from the object"))?
                .try_into()?;
            prog.load(name, &kbtf)
                .with_context(|| format!("loading {name}"))?;
            prog.attach().with_context(|| format!("attaching {name}"))?;
        }

        let mut reports = Vec::new();
        let missing = missing_file_offsets(&offsets);
        // Diagnostic: attach only the named hook (e.g. WITNESS_ONLY_HOOK=security_file_open).
        let only = std::env::var("WITNESS_ONLY_HOOK").ok();
        for (prog_name, func, params, kprobe) in FILE_HOOKS {
            if only.as_deref().is_some_and(|o| o != func) {
                continue;
            }
            let status: Result<(), String> = (|| {
                if !files {
                    return Err("file capture disabled in the configuration".into());
                }
                if !missing.is_empty() {
                    return Err(format!("kernel BTF lacks {}", missing.join(", ")));
                }
                if let Some(why) = layout_problem(&offsets) {
                    return Err(why);
                }
                match btf.func_param_count(func) {
                    None => return Err(format!("{func} is not in the kernel's BTF")),
                    Some(n) if n != params => {
                        return Err(format!("{func} has {n} parameters, expected {params}"))
                    }
                    Some(_) => {}
                }
                let program = ebpf
                    .program_mut(prog_name)
                    .ok_or_else(|| format!("program {prog_name} missing from the object"))?;
                if kprobe {
                    let prog: &mut KProbe = program.try_into().map_err(|e| format!("{e}"))?;
                    prog.load().map_err(|e| format!("load: {e}"))?;
                    prog.attach(func, 0).map_err(|e| format!("attach: {e}"))?;
                } else {
                    let prog: &mut FExit = program.try_into().map_err(|e| format!("{e}"))?;
                    prog.load(func, &kbtf).map_err(|e| format!("load: {e}"))?;
                    prog.attach().map_err(|e| format!("attach: {e}"))?;
                }
                Ok(())
            })();
            reports.push(HookReport { hook: func, status });
        }

        let take = |ebpf: &mut aya::Ebpf, n: &str| {
            ebpf.take_map(n).ok_or_else(|| anyhow!("map {n} missing"))
        };
        let critical = RingBuf::try_from(take(&mut ebpf, "CRITICAL")?)?;
        let volume = RingBuf::try_from(take(&mut ebpf, "VOLUME")?)?;
        let drops = PerCpuArray::try_from(take(&mut ebpf, "DROPS")?)?;
        Ok((
            Collector {
                critical,
                volume,
                drops,
                _ebpf: ebpf,
            },
            reports,
        ))
    }

    /// Waits up to `timeout` for data on either ring (or for any of `wake` to become
    /// readable, e.g. a signalfd), then calls `f` with each pending record: process
    /// lifecycle first, then the high-volume ring.
    pub fn poll(
        &mut self,
        timeout: Duration,
        wake: &[std::os::fd::BorrowedFd<'_>],
        mut f: impl FnMut(&[u8]),
    ) -> Result<usize> {
        let (cfd, vfd) = (self.critical.as_fd(), self.volume.as_fd());
        let mut fds = vec![
            rustix::event::PollFd::new(&cfd, rustix::event::PollFlags::IN),
            rustix::event::PollFd::new(&vfd, rustix::event::PollFlags::IN),
        ];
        fds.extend(
            wake.iter()
                .map(|w| rustix::event::PollFd::new(w, rustix::event::PollFlags::IN)),
        );
        let ts = rustix::time::Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(_) => {}
            // A signal interrupted the wait. That is not an error: return and let the
            // caller carry on; the data is read next round.
            Err(rustix::io::Errno::INTR) => return Ok(0),
            Err(e) => return Err(e).context("poll on the ring buffers"),
        }
        let mut n = 0;
        while let Some(item) = self.critical.next() {
            f(&item);
            n += 1;
        }
        while let Some(item) = self.volume.next() {
            f(&item);
            n += 1;
        }
        Ok(n)
    }

    /// Events lost in the kernel because a ring buffer was full, `[critical, volume]`.
    pub fn dropped(&self) -> Result<[u64; 2]> {
        let mut out = [0u64; 2];
        for (i, slot) in out.iter_mut().enumerate() {
            let v = self
                .drops
                .get(&(i as u32), 0)
                .context("reading a drop counter")?;
            *slot = v.iter().sum();
        }
        Ok(out)
    }
}
