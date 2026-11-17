//! Loads the eBPF object, hands it the BTF-resolved offsets, attaches the programs and reads
//! the ring buffer. Linux only.

use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::BtfTracePoint;
use aya::{Btf as AyaBtf, EbpfLoader};
use witness_common::{Offsets, DROP_CLASS_CRITICAL};

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

/// Programs attached for M1: (program name, kernel tracepoint).
const PROGRAMS: [&str; 3] = [
    "sched_process_exec",
    "sched_process_exit",
    "sched_process_fork",
];

pub struct Collector {
    ring: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    // Dropping `Ebpf` detaches the programs, so it must outlive the reader.
    _ebpf: aya::Ebpf,
}

impl Collector {
    pub fn start(offsets: Offsets, ring_critical_bytes: u32) -> Result<Collector> {
        if OBJECT.is_empty() {
            bail!("this build has no eBPF object (built off Linux or with AYA_BUILD_SKIP=1)");
        }
        let self_tgid = std::process::id();
        let mut ebpf = EbpfLoader::new()
            .override_global("OFFSETS", &OffsetsPod(offsets), true)
            .override_global("SELF_TGID", &self_tgid, true)
            .map_max_entries("CRITICAL", ring_critical_bytes)
            .load(OBJECT)
            .context("loading the eBPF object")?;

        let btf = AyaBtf::from_sys_fs().context("reading /sys/kernel/btf/vmlinux")?;
        for name in PROGRAMS {
            let prog: &mut BtfTracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} missing from the object"))?
                .try_into()?;
            prog.load(name, &btf)
                .with_context(|| format!("loading {name}"))?;
            prog.attach().with_context(|| format!("attaching {name}"))?;
        }

        let ring = RingBuf::try_from(
            ebpf.take_map("CRITICAL")
                .ok_or_else(|| anyhow!("map CRITICAL missing"))?,
        )?;
        let drops = PerCpuArray::try_from(
            ebpf.take_map("DROPS")
                .ok_or_else(|| anyhow!("map DROPS missing"))?,
        )?;
        Ok(Collector {
            ring,
            drops,
            _ebpf: ebpf,
        })
    }

    /// Waits up to `timeout` for data, then calls `f` with each pending record.
    pub fn poll(&mut self, timeout: Duration, mut f: impl FnMut(&[u8])) -> Result<usize> {
        let fd = self.ring.as_fd();
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let ts = rustix::time::Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        rustix::event::poll(&mut fds, Some(&ts)).context("poll on the ring buffer")?;
        let mut n = 0;
        while let Some(item) = self.ring.next() {
            f(&item);
            n += 1;
        }
        Ok(n)
    }

    /// Events lost in the kernel because the ring buffer was full (all CPUs).
    pub fn dropped(&self) -> Result<u64> {
        let v = self
            .drops
            .get(&DROP_CLASS_CRITICAL, 0)
            .context("reading the drop counter")?;
        Ok(v.iter().sum())
    }
}
