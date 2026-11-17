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
    /// One-path file operation ([`super::FileEvent`]).
    pub const FILE_OP: u16 = 10;
    /// Two-path file operation: rename, link, symlink ([`super::FileTwoEvent`]).
    pub const FILE_TWO: u16 = 11;
}

/// File operations carried in [`FileBody::op`] / [`FileTwoBody::op`].
pub mod fop {
    pub const OPEN_WRITE: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const MKDIR: u32 = 3;
    pub const UNLINK: u32 = 4;
    pub const RMDIR: u32 = 5;
    pub const CHMOD: u32 = 6;
    pub const CHOWN: u32 = 7;
    pub const TRUNCATE: u32 = 8;
    pub const RENAME: u32 = 20;
    pub const LINK: u32 = 21;
    pub const SYMLINK: u32 = 22;
}

/// Marks an offset the running kernel does not provide (see [`Offsets`]).
pub const UNAVAILABLE: u32 = u32::MAX;

pub const COMM_LEN: usize = 16;
pub const TTY_LEN: usize = 16;
pub const FILENAME_CAP: usize = 256;
/// Bytes of argv copied per exec. Longer argument areas set [`flags::TRUNCATED`].
pub const ARGV_CAP: usize = 3072;

/// Byte offsets of the kernel struct fields the programs read, resolved by userspace from
/// the running kernel's BTF and handed to the programs as a read-only global (DESIGN.md
/// §3.2). A field the kernel lacks is [`UNAVAILABLE`] and the program skips it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    pub task_pid: u32,
    pub task_tgid: u32,
    pub task_real_parent: u32,
    pub task_group_leader: u32,
    pub task_cred: u32,
    pub task_mm: u32,
    pub task_signal: u32,
    pub task_loginuid: u32,
    pub task_sessionid: u32,
    pub task_start_boottime: u32,
    pub task_exit_code: u32,
    pub cred_euid: u32,
    pub cred_egid: u32,
    pub mm_arg_start: u32,
    pub mm_arg_end: u32,
    pub signal_tty: u32,
    pub tty_name: u32,
    pub binprm_filename: u32,
    pub file_f_path: u32,
    pub file_f_mode: u32,
    pub file_f_flags: u32,
    pub path_mnt: u32,
    pub path_dentry: u32,
    pub dentry_d_parent: u32,
    pub dentry_d_name: u32,
    pub dentry_d_inode: u32,
    pub dentry_d_sb: u32,
    pub qstr_name: u32,
    pub qstr_len: u32,
    pub mount_mnt_parent: u32,
    pub mount_mnt_mountpoint: u32,
    pub mount_mnt: u32,
    pub inode_i_mode: u32,
    pub inode_i_ino: u32,
    pub sb_s_dev: u32,
    pub sb_s_magic: u32,
}

impl Offsets {
    pub const fn unavailable() -> Self {
        Offsets {
            task_pid: UNAVAILABLE,
            task_tgid: UNAVAILABLE,
            task_real_parent: UNAVAILABLE,
            task_group_leader: UNAVAILABLE,
            task_cred: UNAVAILABLE,
            task_mm: UNAVAILABLE,
            task_signal: UNAVAILABLE,
            task_loginuid: UNAVAILABLE,
            task_sessionid: UNAVAILABLE,
            task_start_boottime: UNAVAILABLE,
            task_exit_code: UNAVAILABLE,
            cred_euid: UNAVAILABLE,
            cred_egid: UNAVAILABLE,
            mm_arg_start: UNAVAILABLE,
            mm_arg_end: UNAVAILABLE,
            signal_tty: UNAVAILABLE,
            tty_name: UNAVAILABLE,
            binprm_filename: UNAVAILABLE,
            file_f_path: UNAVAILABLE,
            file_f_mode: UNAVAILABLE,
            file_f_flags: UNAVAILABLE,
            path_mnt: UNAVAILABLE,
            path_dentry: UNAVAILABLE,
            dentry_d_parent: UNAVAILABLE,
            dentry_d_name: UNAVAILABLE,
            dentry_d_inode: UNAVAILABLE,
            dentry_d_sb: UNAVAILABLE,
            qstr_name: UNAVAILABLE,
            qstr_len: UNAVAILABLE,
            mount_mnt_parent: UNAVAILABLE,
            mount_mnt_mountpoint: UNAVAILABLE,
            mount_mnt: UNAVAILABLE,
            inode_i_mode: UNAVAILABLE,
            inode_i_ino: UNAVAILABLE,
            sb_s_dev: UNAVAILABLE,
            sb_s_magic: UNAVAILABLE,
        }
    }
}

/// Body of a [`kind::PROC_EXEC`] record, following the [`RawHdr`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecBody {
    /// Valid bytes in `argv` (NUL-separated arguments).
    pub argv_len: u32,
    /// Size of the whole argument area; larger than `argv_len` when truncated.
    pub argv_total: u32,
    pub filename_len: u32,
    pub tty_len: u32,
    pub comm: [u8; COMM_LEN],
    pub tty: [u8; TTY_LEN],
    pub filename: [u8; FILENAME_CAP],
    pub argv: [u8; ARGV_CAP],
}

/// Body of a [`kind::PROC_EXIT`] record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitBody {
    /// Raw `task->exit_code` (`status << 8 | signal`, `0x80` = core dumped).
    pub exit_code: i32,
    pub flags: u32,
    pub comm: [u8; COMM_LEN],
}

/// Body of a [`kind::PROC_FORK`] record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkBody {
    pub child_pid: u32,
    pub child_tgid: u32,
    pub child_start_boot_ns: u64,
    pub flags: u32,
    pub _pad: u32,
}

/// Longest path recorded; a longer one keeps its tail (the leaf end) and sets `trunc`.
pub const PATH_CAP: usize = 1024;
/// Longest single path component copied.
pub const COMP_CAP: usize = 255;
/// Deepest nesting (directories plus mount crossings) walked before the path is cut.
pub const MAX_COMPONENTS: usize = 40;
/// The per-CPU buffer the kernel walks paths into, right to left. Large enough that
/// `MAX_COMPONENTS` components of `COMP_CAP + 1` bytes can never wrap it, which is what lets
/// the walk avoid any overflow bookkeeping the verifier would have to track per path.
pub const SCRATCH_LEN: usize = 16384;
/// `SCRATCH_LEN` plus slack so the final bounded copy is provably in range.
pub const SCRATCH_BUF: usize = SCRATCH_LEN + PATH_CAP;

/// Body of a [`kind::FILE_OP`] record. The path is `path[..path_len]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileBody {
    pub op: u32,
    /// Return value of the security hook (0 = allowed, negative errno = denied).
    pub result: i32,
    /// `open` flags for opens; unused otherwise.
    pub flags: u32,
    /// Mode: new mode for create/mkdir/chmod.
    pub mode: u32,
    /// Mode of the file before the operation (chmod): lets userspace see a newly set SUID/SGID bit.
    pub old_mode: u32,
    pub dev: u32,
    pub new_uid: u32,
    pub new_gid: u32,
    pub ino: u64,
    pub path_len: u32,
    /// Non-zero if the path or a component was cut, or the walk hit its depth limit.
    pub trunc: u32,
    pub path: [u8; PATH_CAP],
}

/// Body of a [`kind::FILE_TWO`] record (rename, link, symlink): `old` and `new`, where for a
/// symlink `new` is the link path and `old` holds the target string.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileTwoBody {
    pub op: u32,
    pub result: i32,
    pub flags: u32,
    pub dev: u32,
    pub ino: u64,
    pub old_len: u32,
    pub new_len: u32,
    pub trunc: u32,
    pub _pad: u32,
    pub old: [u8; PATH_CAP],
    pub new: [u8; PATH_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub hdr: RawHdr,
    pub body: FileBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileTwoEvent {
    pub hdr: RawHdr,
    pub body: FileTwoBody,
}

/// `result` value meaning the hook's outcome was not observed (kprobes see the call, not
/// its return value).
pub const RESULT_UNKNOWN: i32 = i32::MAX;

/// Index of the high-volume ring's drop counter (`DROPS` map).
pub const DROP_CLASS_VOLUME: u32 = 1;

impl FileBody {
    pub const SIZE: usize = 48 + PATH_CAP;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut ino = [0u8; 8];
        ino.copy_from_slice(&b[32..40]);
        let mut path = [0u8; PATH_CAP];
        path.copy_from_slice(&b[48..Self::SIZE]);
        Some(Self {
            op: u32_at(0),
            result: u32_at(4) as i32,
            flags: u32_at(8),
            mode: u32_at(12),
            old_mode: u32_at(16),
            dev: u32_at(20),
            new_uid: u32_at(24),
            new_gid: u32_at(28),
            ino: u64::from_ne_bytes(ino),
            path_len: u32_at(40),
            trunc: u32_at(44),
            path,
        })
    }

    /// The recorded path bytes.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..(self.path_len as usize).min(PATH_CAP)]
    }
}

impl FileTwoBody {
    pub const SIZE: usize = 40 + 2 * PATH_CAP;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut ino = [0u8; 8];
        ino.copy_from_slice(&b[16..24]);
        let mut old = [0u8; PATH_CAP];
        old.copy_from_slice(&b[40..40 + PATH_CAP]);
        let mut new = [0u8; PATH_CAP];
        new.copy_from_slice(&b[40 + PATH_CAP..Self::SIZE]);
        Some(Self {
            op: u32_at(0),
            result: u32_at(4) as i32,
            flags: u32_at(8),
            dev: u32_at(12),
            ino: u64::from_ne_bytes(ino),
            old_len: u32_at(24),
            new_len: u32_at(28),
            trunc: u32_at(32),
            _pad: 0,
            old,
            new,
        })
    }

    pub fn old_bytes(&self) -> &[u8] {
        &self.old[..(self.old_len as usize).min(PATH_CAP)]
    }

    pub fn new_bytes(&self) -> &[u8] {
        &self.new[..(self.new_len as usize).min(PATH_CAP)]
    }
}

/// A complete exec record as written into the ring buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub hdr: RawHdr,
    pub body: ExecBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub hdr: RawHdr,
    pub body: ExitBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub hdr: RawHdr,
    pub body: ForkBody,
}

/// Indexes into the per-class drop counters (`DROPS` map).
pub const DROP_CLASS_CRITICAL: u32 = 0;

/// [`ForkBody::flags`]: the child is a thread, not a new process.
pub const FORK_THREAD: u32 = 1;

impl ExecBody {
    pub const SIZE: usize = 16 + COMM_LEN + TTY_LEN + FILENAME_CAP + ARGV_CAP;

    /// Parses an exec body (the bytes after the header). Returns `None` if too short.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut comm = [0u8; COMM_LEN];
        comm.copy_from_slice(&b[16..16 + COMM_LEN]);
        let mut tty = [0u8; TTY_LEN];
        tty.copy_from_slice(&b[32..32 + TTY_LEN]);
        let mut filename = [0u8; FILENAME_CAP];
        filename.copy_from_slice(&b[48..48 + FILENAME_CAP]);
        let mut argv = [0u8; ARGV_CAP];
        argv.copy_from_slice(&b[48 + FILENAME_CAP..Self::SIZE]);
        Some(Self {
            argv_len: u32_at(0),
            argv_total: u32_at(4),
            filename_len: u32_at(8),
            tty_len: u32_at(12),
            comm,
            tty,
            filename,
            argv,
        })
    }
}

impl ExitBody {
    pub const SIZE: usize = 8 + COMM_LEN;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let mut comm = [0u8; COMM_LEN];
        comm.copy_from_slice(&b[8..8 + COMM_LEN]);
        Some(Self {
            exit_code: i32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            flags: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            comm,
        })
    }
}

impl ForkBody {
    pub const SIZE: usize = 24;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut ns = [0u8; 8];
        ns.copy_from_slice(&b[8..16]);
        Some(Self {
            child_pid: u32_at(0),
            child_tgid: u32_at(4),
            child_start_boot_ns: u64::from_ne_bytes(ns),
            flags: u32_at(16),
            _pad: 0,
        })
    }
}

const _: () = assert!(core::mem::size_of::<ExecBody>() == ExecBody::SIZE);
const _: () = assert!(core::mem::size_of::<ExitBody>() == ExitBody::SIZE);
const _: () = assert!(core::mem::size_of::<ForkBody>() == ForkBody::SIZE);
const _: () = assert!(core::mem::size_of::<Offsets>() == 36 * 4);
const _: () = assert!(core::mem::size_of::<FileBody>() == FileBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileTwoBody>() == FileTwoBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileEvent>() == RawHdr::SIZE + FileBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileTwoEvent>() == RawHdr::SIZE + FileTwoBody::SIZE);
const _: () = assert!(FileBody::SIZE % 8 == 0 && FileTwoBody::SIZE % 8 == 0);
const _: () = assert!(PATH_CAP.is_power_of_two());
const _: () = assert!(MAX_COMPONENTS * (COMP_CAP + 1) <= SCRATCH_LEN);
const _: () = assert!(SCRATCH_LEN.is_power_of_two());
const _: () = assert!(core::mem::size_of::<ExecEvent>() == RawHdr::SIZE + ExecBody::SIZE);
const _: () = assert!(core::mem::size_of::<ExitEvent>() == RawHdr::SIZE + ExitBody::SIZE);
const _: () = assert!(core::mem::size_of::<ForkEvent>() == RawHdr::SIZE + ForkBody::SIZE);
const _: () =
    assert!(ExecBody::SIZE % 8 == 0 && ExitBody::SIZE % 8 == 0 && ForkBody::SIZE % 8 == 0);

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

    /// Native-endian bytes in wire order (the inverse of [`RawHdr::parse`]).
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..2].copy_from_slice(&self.kind.to_ne_bytes());
        b[2..4].copy_from_slice(&self.flags.to_ne_bytes());
        b[4..8].copy_from_slice(&self.len.to_ne_bytes());
        b[8..16].copy_from_slice(&self.boot_ns.to_ne_bytes());
        for (i, v) in [
            self.pid, self.tid, self.ppid, self._pad0, self.uid, self.gid, self.euid, self.egid,
            self.auid, self.ses,
        ]
        .into_iter()
        .enumerate()
        {
            b[16 + i * 4..20 + i * 4].copy_from_slice(&v.to_ne_bytes());
        }
        b[56..64].copy_from_slice(&self.cgroup_id.to_ne_bytes());
        b[64..72].copy_from_slice(&self.start_boot_ns.to_ne_bytes());
        b
    }

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

    fn bytes_of<T>(v: &T) -> &[u8] {
        // SAFETY: only used in tests with padding-free repr(C) plain-data structs.
        unsafe {
            core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>())
        }
    }

    #[test]
    fn exec_body_roundtrip() {
        let mut b = ExecBody {
            argv_len: 9,
            argv_total: 5000,
            filename_len: 8,
            tty_len: 5,
            comm: [0; COMM_LEN],
            tty: [0; TTY_LEN],
            filename: [0; FILENAME_CAP],
            argv: [0; ARGV_CAP],
        };
        b.comm[..4].copy_from_slice(b"curl");
        b.tty[..5].copy_from_slice(b"pts/0");
        b.filename[..8].copy_from_slice(b"/bin/ls\0");
        b.argv[..9].copy_from_slice(b"ls\0-la\0\0\0");
        let p = ExecBody::parse(bytes_of(&b)).unwrap();
        assert_eq!(
            (p.argv_len, p.argv_total, p.filename_len, p.tty_len),
            (9, 5000, 8, 5)
        );
        assert_eq!(&p.comm[..4], b"curl");
        assert_eq!(&p.tty[..5], b"pts/0");
        assert_eq!(&p.filename[..7], b"/bin/ls");
        assert_eq!(&p.argv[..8], b"ls\0-la\0\0");
        assert!(ExecBody::parse(&bytes_of(&b)[..ExecBody::SIZE - 1]).is_none());
    }

    #[test]
    fn exit_and_fork_bodies_roundtrip() {
        let e = ExitBody {
            exit_code: 0x0b80,
            flags: 1,
            comm: *b"sleep\0\0\0\0\0\0\0\0\0\0\0",
        };
        let p = ExitBody::parse(bytes_of(&e)).unwrap();
        assert_eq!((p.exit_code, p.flags), (0x0b80, 1));
        assert_eq!(&p.comm[..5], b"sleep");
        let f = ForkBody {
            child_pid: 7,
            child_tgid: 7,
            child_start_boot_ns: 123_456_789,
            flags: FORK_THREAD,
            _pad: 0,
        };
        let p = ForkBody::parse(bytes_of(&f)).unwrap();
        assert_eq!(
            (p.child_pid, p.child_tgid, p.child_start_boot_ns, p.flags),
            (7, 7, 123_456_789, FORK_THREAD)
        );
        assert!(ForkBody::parse(&[0u8; 23]).is_none());
    }

    #[test]
    fn short_buffer_is_rejected() {
        assert_eq!(RawHdr::parse(&[0u8; RawHdr::SIZE - 1]), None);
    }
}
