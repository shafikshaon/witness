//! Loads the eBPF object, hands it the BTF-resolved offsets, attaches the programs and reads
//! the ring buffer. Linux only.

use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::BtfTracePoint;
use aya::{Btf as AyaBtf, EbpfLoader, VerifierLogLevel};
use witness_common::{FlowKey, FlowVal, InodeKey, Offsets, UdpBody, UNAVAILABLE};

use crate::btf::Btf;

/// The compiled eBPF object (empty placeholder if it was not built; see `build.rs`).
static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/witness-ebpf"));

/// `InodeKey` made usable as a map key.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct KeyPod(InodeKey);

// SAFETY: `InodeKey` is `repr(C)`, fully initialised (explicit pad field, no implicit
// padding) and made of integers, so any bytes copied to or from the kernel are valid.
unsafe impl aya::Pod for KeyPod {}

/// UDP flow key/value made usable as map types.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct FlowKeyPod(FlowKey);
#[repr(transparent)]
#[derive(Clone, Copy)]
struct FlowValPod(FlowVal);

// SAFETY: both are `repr(C)`, integer-only and fully initialised by the kernel programs
// (explicit padding fields, no implicit padding; `RawHdr` has the same properties), so any
// bytes exchanged with the kernel are valid values.
unsafe impl aya::Pod for FlowKeyPod {}
// SAFETY: as above.
unsafe impl aya::Pod for FlowValPod {}

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

/// Which capture source a hook belongs to; each has its own pre-checks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Files,
    Net,
    Dns,
    System,
}

#[derive(Clone, Copy)]
enum Attach {
    /// kprobe or kretprobe on a kernel function (both load as `KProbe`).
    KProbe,
    /// BTF raw tracepoint.
    BtfTp,
}

struct Hook {
    prog: &'static str,
    /// Kernel function (kprobe) or tracepoint name.
    target: &'static str,
    /// Expected parameter count, checked against the running kernel's BTF so a changed
    /// signature degrades the hook instead of letting the program read the wrong argument.
    /// `None` for tracepoints (their arguments are typed by BTF).
    params: Option<usize>,
    /// Highest accepted count (with `params` as the lowest). Functions whose signature grew or
    /// shrank at the end between kernel versions (`*_recvmsg` lost `nonblock` in 5.19 and
    /// `addr_len` later) still have the arguments the program reads in the same places.
    params_max: Option<usize>,
    attach: Attach,
    group: Group,
}

const fn hook(
    prog: &'static str,
    target: &'static str,
    params: Option<usize>,
    attach: Attach,
    group: Group,
) -> Hook {
    Hook {
        prog,
        target,
        params,
        params_max: None,
        attach,
        group,
    }
}

/// Like [`hook`], accepting any parameter count from `min` to `max`: for functions whose
/// trailing parameters changed across kernels while the leading ones this program reads did not.
const fn hook_range(
    prog: &'static str,
    target: &'static str,
    min: usize,
    max: usize,
    attach: Attach,
    group: Group,
) -> Hook {
    Hook {
        prog,
        target,
        params: Some(min),
        params_max: Some(max),
        attach,
        group,
    }
}

/// All optional hooks. File hooks are kprobes (no fentry/fexit on arm64 before 6.0, and
/// `kuid_t` by-value arguments); TCP uses kprobes on connect/accept plus the
/// `inet_sock_set_state` tracepoint.
const HOOKS: [Hook; 27] = [
    hook(
        "file_open",
        "security_file_open",
        Some(1),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_mknod",
        "security_path_mknod",
        Some(4),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_mkdir",
        "security_path_mkdir",
        Some(3),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_unlink",
        "security_path_unlink",
        Some(2),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_rmdir",
        "security_path_rmdir",
        Some(2),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_chmod",
        "security_path_chmod",
        Some(2),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_chown",
        "security_path_chown",
        Some(3),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_truncate",
        "security_path_truncate",
        Some(1),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_rename",
        "security_path_rename",
        Some(5),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_link",
        "security_path_link",
        Some(3),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "path_symlink",
        "security_path_symlink",
        Some(3),
        Attach::KProbe,
        Group::Files,
    ),
    hook(
        "tcp_v4_connect",
        "tcp_v4_connect",
        Some(3),
        Attach::KProbe,
        Group::Net,
    ),
    hook(
        "tcp_v6_connect",
        "tcp_v6_connect",
        Some(3),
        Attach::KProbe,
        Group::Net,
    ),
    // Only the return value is read, so the parameter count (4 before 6.10, 2 after) is
    // immaterial.
    hook_range(
        "tcp_accept",
        "inet_csk_accept",
        2,
        4,
        Attach::KProbe,
        Group::Net,
    ),
    hook(
        "tcp_state",
        "inet_sock_set_state",
        None,
        Attach::BtfTp,
        Group::Net,
    ),
    hook(
        "tcp_listen",
        "inet_sock_set_state",
        None,
        Attach::BtfTp,
        Group::Net,
    ),
    hook(
        "module_load",
        "module_load",
        None,
        Attach::BtfTp,
        Group::System,
    ),
    hook(
        "module_free",
        "module_free",
        None,
        Attach::BtfTp,
        Group::System,
    ),
    hook(
        "udp_send4",
        "udp_sendmsg",
        Some(3),
        Attach::KProbe,
        Group::Dns,
    ),
    hook(
        "udp_send6",
        "udpv6_sendmsg",
        Some(3),
        Attach::KProbe,
        Group::Dns,
    ),
    hook_range(
        "udp_recv4_enter",
        "udp_recvmsg",
        4,
        6,
        Attach::KProbe,
        Group::Dns,
    ),
    hook_range(
        "udp_recv6_enter",
        "udpv6_recvmsg",
        4,
        6,
        Attach::KProbe,
        Group::Dns,
    ),
    hook(
        "udp_recv4_ret",
        "udp_recvmsg",
        None,
        Attach::KProbe,
        Group::Dns,
    ),
    hook(
        "udp_recv6_ret",
        "udpv6_recvmsg",
        None,
        Attach::KProbe,
        Group::Dns,
    ),
    // DNS over TCP. tcp_sendmsg/tcp_recvmsg are hot paths; the programs return after one
    // port comparison unless the peer is port 53.
    hook(
        "tcp_dns_send",
        "tcp_sendmsg",
        Some(3),
        Attach::KProbe,
        Group::Dns,
    ),
    hook_range(
        "tcp_dns_recv_enter",
        "tcp_recvmsg",
        4,
        6,
        Attach::KProbe,
        Group::Dns,
    ),
    hook(
        "tcp_dns_recv_ret",
        "tcp_recvmsg",
        None,
        Attach::KProbe,
        Group::Dns,
    ),
];

/// Outcome of attaching one optional hook.
#[derive(Debug, Clone)]
pub struct HookReport {
    pub hook: &'static str,
    /// `Err` carries why it is not active; capture continues without it.
    pub status: Result<(), String>,
}

/// A poisoned lock only means another loader thread panicked; the data is still usable.
fn relock<T>(e: std::sync::PoisonError<T>) -> T {
    e.into_inner()
}

/// Loads one hook program into the kernel (running the verifier) and attaches it.
fn load_attach(
    program: &mut aya::programs::Program,
    target: &str,
    attach: Attach,
    kbtf: &AyaBtf,
) -> Result<(), String> {
    use aya::programs::Program;
    match (program, attach) {
        (Program::KProbe(p), Attach::KProbe) => {
            p.load().map_err(|e| format!("load: {e}"))?;
            p.attach(target, 0).map_err(|e| format!("attach: {e}"))?;
            Ok(())
        }
        (Program::BtfTracePoint(p), Attach::BtfTp) => {
            p.load(target, kbtf).map_err(|e| format!("load: {e}"))?;
            p.attach().map_err(|e| format!("attach: {e}"))?;
            Ok(())
        }
        _ => Err("program type does not match the hook table".into()),
    }
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

/// Offsets the TCP hooks need.
fn missing_net_offsets(o: &Offsets) -> Vec<&'static str> {
    [
        ("sock_common.skc_daddr", o.sock_skc_daddr),
        ("sock_common.skc_rcv_saddr", o.sock_skc_rcv_saddr),
        ("sock_common.skc_dport", o.sock_skc_dport),
        ("sock_common.skc_num", o.sock_skc_num),
        ("sock_common.skc_family", o.sock_skc_family),
        ("sock_common.skc_v6_daddr", o.sock_skc_v6_daddr),
        ("sock_common.skc_v6_rcv_saddr", o.sock_skc_v6_rcv_saddr),
        ("tcp_sock.bytes_sent", o.tcp_bytes_sent),
        ("tcp_sock.bytes_received", o.tcp_bytes_received),
    ]
    .into_iter()
    .filter(|(_, v)| *v == UNAVAILABLE)
    .map(|(n, _)| n)
    .collect()
}

/// Offsets the DNS hooks need, beyond the socket ones.
fn missing_dns_offsets(o: &Offsets) -> Vec<&'static str> {
    let mut m = missing_net_offsets(o);
    m.extend(
        [
            ("msghdr.msg_name", o.msghdr_msg_name),
            ("msghdr.msg_iter", o.msghdr_msg_iter),
            ("iov_iter.iter_type", o.iov_iter_type),
            ("iov_iter.iov", o.iov_iter_iov),
            ("iov_iter.count", o.iov_iter_count),
        ]
        .into_iter()
        .filter(|(_, v)| *v == UNAVAILABLE)
        .map(|(n, _)| n),
    );
    m
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
    sensitive: BpfHashMap<MapData, KeyPod, u8>,
    flows: BpfHashMap<MapData, FlowKeyPod, FlowValPod>,
    // Dropping `Ebpf` detaches the programs, so it must outlive the readers.
    _ebpf: aya::Ebpf,
}

/// Which optional hook groups to load.
#[derive(Clone, Copy, Debug)]
pub struct Groups {
    pub files: bool,
    pub network: bool,
    pub dns: bool,
    pub system: bool,
}

/// `(hook index, program name, outcome)` for one hook load.
type LoadOutcome = (usize, &'static str, Result<(), String>);

impl Collector {
    pub fn start(
        offsets: Offsets,
        btf: &Btf,
        critical_bytes: u32,
        volume_bytes: u32,
        groups: Groups,
        // Polled between batches of hook loads so a stop request during a slow start (the
        // kernel verifier takes seconds for the file hooks) is honoured promptly.
        interrupted: &dyn Fn() -> bool,
    ) -> Result<(Collector, Vec<HookReport>)> {
        let Groups {
            files,
            network,
            dns,
            system,
        } = groups;
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

        // Pre-checks run first and only hooks that pass them are verified. Verification of each
        // program is independent and CPU-bound (the kernel verifier walks every path), so the
        // programs are loaded concurrently: serial loading took ~6 s on a 4-CPU VM, which would
        // delay every service ordered after us at boot.
        let mut reports: Vec<Option<HookReport>> = (0..HOOKS.len()).map(|_| None).collect();
        let missing_files = missing_file_offsets(&offsets);
        let missing_net = missing_net_offsets(&offsets);
        let missing_dns = missing_dns_offsets(&offsets);
        let missing_system: Vec<&'static str> = [
            ("module.name", offsets.module_name),
            ("module.taints", offsets.module_taints),
        ]
        .into_iter()
        .filter(|(_, v)| *v == UNAVAILABLE)
        .map(|(n, _)| n)
        .collect();
        // Diagnostic: attach only the named hook (e.g. WITNESS_ONLY_HOOK=security_file_open).
        let only = std::env::var("WITNESS_ONLY_HOOK").ok();
        let mut by_name: std::collections::HashMap<String, &mut aya::programs::Program> = ebpf
            .programs_mut()
            .map(|(n, p)| (n.to_string(), p))
            .collect();
        let mut jobs: Vec<(usize, &'static str, Attach, &mut aya::programs::Program)> = Vec::new();
        for (idx, h) in HOOKS.iter().enumerate() {
            if only.as_deref().is_some_and(|o| o != h.target) {
                reports[idx] = Some(HookReport {
                    hook: h.target,
                    status: Err("skipped (WITNESS_ONLY_HOOK)".into()),
                });
                continue;
            }
            let pre: Result<(), String> = (|| {
                let (enabled, missing, layout) = match h.group {
                    Group::Files => (files, &missing_files, layout_problem(&offsets)),
                    Group::Net => (network, &missing_net, None),
                    Group::Dns => (dns && network, &missing_dns, None),
                    Group::System => (system, &missing_system, None),
                };
                if !enabled {
                    return Err("capture of this kind is disabled in the configuration".into());
                }
                if !missing.is_empty() {
                    return Err(format!("kernel BTF lacks {}", missing.join(", ")));
                }
                if let Some(why) = layout {
                    return Err(why);
                }
                match (h.params, btf.func_param_count(h.target)) {
                    (None, _) => Ok(()),
                    (Some(_), None) => Err(format!("{} is not in the kernel's BTF", h.target)),
                    (Some(want), Some(n)) if n < want || n > h.params_max.unwrap_or(want) => {
                        Err(format!(
                            "{} has {n} parameters, expected {}",
                            h.target,
                            match h.params_max {
                                Some(max) if max != want => format!("{want} to {max}"),
                                _ => want.to_string(),
                            }
                        ))
                    }
                    (Some(_), Some(_)) => Ok(()),
                }
            })();
            match (pre, by_name.remove(h.prog)) {
                (Err(e), _) => {
                    reports[idx] = Some(HookReport {
                        hook: h.target,
                        status: Err(e),
                    })
                }
                (Ok(()), None) => {
                    reports[idx] = Some(HookReport {
                        hook: h.target,
                        status: Err(format!("program {} missing from the object", h.prog)),
                    })
                }
                (Ok(()), Some(prog)) => jobs.push((idx, h.target, h.attach, prog)),
            }
        }
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8);
        let kbtf_ref = &kbtf;
        // A work queue, heaviest programs first: the kernel verifier's time per program varies
        // from 0.2 s (TCP) to 4 s (rename walks two paths), so fixed batches would leave most
        // CPUs idle behind the slowest program in each.
        let weight = |idx: usize| match HOOKS[idx].prog {
            "path_rename" | "path_link" | "path_symlink" => 3,
            _ if HOOKS[idx].group == Group::Files => 2,
            _ => 1,
        };
        jobs.sort_by_key(|(idx, ..)| std::cmp::Reverse(weight(*idx)));
        let total = jobs.len();
        let queue = std::sync::Mutex::new(std::collections::VecDeque::from(jobs));
        let results: std::sync::Mutex<Vec<LoadOutcome>> = std::sync::Mutex::new(Vec::new());
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let job = queue.lock().unwrap_or_else(relock).pop_front();
                    let Some((idx, func, attach, prog)) = job else {
                        break;
                    };
                    let status = if stop.load(std::sync::atomic::Ordering::SeqCst) {
                        Err("startup interrupted by a stop request".to_string())
                    } else {
                        load_attach(prog, func, attach, kbtf_ref)
                    };
                    results
                        .lock()
                        .unwrap_or_else(relock)
                        .push((idx, func, status));
                });
            }
            // Watch for a stop request while the workers run; they finish what they have
            // started and skip the rest.
            while results.lock().unwrap_or_else(relock).len() < total {
                if interrupted() {
                    stop.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let outcomes = results.into_inner().unwrap_or_else(relock);
        for (idx, func, status) in outcomes {
            reports[idx] = Some(HookReport { hook: func, status });
        }
        let reports: Vec<HookReport> = reports.into_iter().flatten().collect();

        let take = |ebpf: &mut aya::Ebpf, n: &str| {
            ebpf.take_map(n).ok_or_else(|| anyhow!("map {n} missing"))
        };
        let critical = RingBuf::try_from(take(&mut ebpf, "CRITICAL")?)?;
        let volume = RingBuf::try_from(take(&mut ebpf, "VOLUME")?)?;
        let drops = PerCpuArray::try_from(take(&mut ebpf, "DROPS")?)?;
        let sensitive = BpfHashMap::try_from(take(&mut ebpf, "SENSITIVE")?)?;
        let flows = BpfHashMap::try_from(take(&mut ebpf, "FLOWS")?)?;
        Ok((
            Collector {
                critical,
                volume,
                drops,
                sensitive,
                flows,
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
        // Both rings' pending records, in the order the kernel produced them. Draining one ring
        // then the other would hand a short-lived process's `exit` to the decoder before its
        // own network records, so records are merged by their kernel timestamp (header bytes
        // 8..16). A bounded batch keeps one poll from holding the whole backlog in memory.
        const BATCH: usize = 8192;
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::new();
        for ring in [&mut self.critical, &mut self.volume] {
            let mut taken = 0;
            while taken < BATCH {
                let Some(item) = ring.next() else { break };
                let ts = item
                    .get(8..16)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map_or(0, u64::from_ne_bytes);
                batch.push((ts, item.to_vec()));
                taken += 1;
            }
        }
        batch.sort_by_key(|(ts, _)| *ts);
        let n = batch.len();
        for (_, rec) in &batch {
            f(rec);
        }
        Ok(n)
    }

    /// Updates the set of files whose reads are reported.
    pub fn sync_sensitive(&mut self, add: &[InodeKey], remove: &[InodeKey]) -> Result<()> {
        for k in add {
            self.sensitive
                .insert(&KeyPod(*k), &1, 0)
                .context("adding a sensitive file")?;
        }
        for k in remove {
            // Already gone is fine.
            let _ = self.sensitive.remove(&KeyPod(*k));
        }
        Ok(())
    }

    /// Reads and clears the UDP flow table, returning one decoder-ready record per flow.
    /// `now_boot_ns` stamps the records (the summary is as of now).
    pub fn take_flows(&mut self, now_boot_ns: u64) -> Vec<Vec<u8>> {
        let keys: Vec<FlowKeyPod> = self.flows.keys().filter_map(Result::ok).collect();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let Ok(v) = self.flows.get(&k, 0) else {
                continue;
            };
            // Removing before the next update is racy by a few packets; that is accepted.
            let _ = self.flows.remove(&k);
            let (k, v) = (k.0, v.0);
            let body = UdpBody {
                family: k.family,
                lport: k.lport,
                rport: k.rport,
                laddr: k.laddr,
                raddr: k.raddr,
                pkts_tx: v.pkts_tx,
                bytes_tx: v.bytes_tx,
                pkts_rx: v.pkts_rx,
                bytes_rx: v.bytes_rx,
                first_boot_ns: v.first_boot_ns,
                comm: v.comm,
            };
            out.push(body.to_record(&v.hdr, now_boot_ns));
        }
        out
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
