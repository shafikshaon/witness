//! Types shared between the eBPF programs and `witnessd`.
//!
//! Everything here is `#[repr(C)]`, fixed-width, and padding-explicit so the
//! kernel side and userspace agree on the exact byte layout (DESIGN.md §4.3).
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "schema")]
pub mod schema;

/// Bumped on any incompatible change to the wire structs below.
pub const ABI_VERSION: u32 = 1;

/// Event kinds carried in [`RawHdr::kind`].
pub mod kind {
    pub const PROC_EXEC: u16 = 1;
    pub const PROC_FORK: u16 = 2;
    pub const PROC_EXIT: u16 = 3;
}

/// Flags carried in [`RawHdr::flags`].
pub mod flags {
    pub const TRUNCATED: u16 = 1 << 0;
    pub const CHUNKED: u16 = 1 << 1;
}

/// Fixed header at the start of every ring-buffer record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawHdr {
    pub kind: u16,
    pub flags: u16,
    /// Total record length in bytes, header included.
    pub len: u32,
    /// CLOCK_BOOTTIME (`bpf_ktime_get_boot_ns`).
    pub boot_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub _pad0: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// `u32::MAX` when the login uid is unset.
    pub auid: u32,
    pub ses: u32,
    pub cgroup_id: u64,
    /// Actor start time; with the boot ID and pid this forms the process UID.
    pub start_boot_ns: u64,
}

impl RawHdr {
    pub const SIZE: usize = 72;

    /// Parses a header from the start of `buf`. Returns `None` if `buf` is too short.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u16_at = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[o..o + 8]);
            u64::from_ne_bytes(a)
        };
        Some(Self {
            kind: u16_at(0),
            flags: u16_at(2),
            len: u32_at(4),
            boot_ns: u64_at(8),
            pid: u32_at(16),
            tid: u32_at(20),
            ppid: u32_at(24),
            _pad0: u32_at(28),
            uid: u32_at(32),
            gid: u32_at(36),
            euid: u32_at(40),
            egid: u32_at(44),
            auid: u32_at(48),
            ses: u32_at(52),
            cgroup_id: u64_at(56),
            start_boot_ns: u64_at(64),
        })
    }
}

const _: () = assert!(core::mem::size_of::<RawHdr>() == RawHdr::SIZE);
const _: () = assert!(core::mem::align_of::<RawHdr>() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let hdr = RawHdr {
            kind: kind::PROC_EXEC,
            flags: flags::TRUNCATED,
            len: 72,
            boot_ns: 42,
            pid: 1,
            tid: 2,
            ppid: 3,
            _pad0: 0,
            uid: 1000,
            gid: 1000,
            euid: 0,
            egid: 0,
            auid: u32::MAX,
            ses: 7,
            cgroup_id: 99,
            start_boot_ns: 5,
        };
        // SAFETY: RawHdr is repr(C), Copy, has no padding bytes (all gaps are explicit
        // fields) and no invalid bit patterns; viewing it as bytes is sound.
        let bytes =
            unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, RawHdr::SIZE) };
        assert_eq!(RawHdr::parse(bytes), Some(hdr));
    }

    #[test]
    fn short_buffer_is_rejected() {
        assert_eq!(RawHdr::parse(&[0u8; RawHdr::SIZE - 1]), None);
    }
}
