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
    /// TCP connection lifecycle ([`super::NetEvent`]).
    pub const NET_TCP: u16 = 20;
    /// A DNS packet over UDP ([`super::DnsEvent`]).
    pub const DNS: u16 = 21;
    /// A kernel module load or free ([`super::ModuleEvent`]).
    pub const MODULE: u16 = 22;
    /// A UDP flow summary ([`super::UdpBody`]), assembled in userspace from the flow table.
    pub const NET_UDP: u16 = 23;
    /// One more chunk of an exec's arguments ([`super::ArgvChunk`]), emitted *before* the
    /// exec record it belongs to when the arguments do not fit in one record.
    pub const PROC_ARGV: u16 = 24;
    /// What an exec inherited that is gone once the process exits ([`super::ExecExtra`]):
    /// emitted *before* the exec record it belongs to.
    pub const PROC_EXTRA: u16 = 25;
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
    /// A read-only open of a file on the sensitive list (matched by inode in the kernel).
    pub const OPEN_READ: u32 = 9;
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
    pub sock_skc_daddr: u32,
    pub sock_skc_rcv_saddr: u32,
    pub sock_skc_dport: u32,
    pub sock_skc_num: u32,
    pub sock_skc_family: u32,
    pub sock_skc_v6_daddr: u32,
    pub sock_skc_v6_rcv_saddr: u32,
    pub tcp_bytes_sent: u32,
    pub tcp_bytes_received: u32,
    pub sock_sk_shutdown: u32,
    pub msghdr_msg_name: u32,
    pub msghdr_msg_namelen: u32,
    pub msghdr_msg_iter: u32,
    pub iov_iter_type: u32,
    pub iov_iter_iov: u32,
    pub iov_iter_ubuf: u32,
    pub iov_iter_count: u32,
    pub module_name: u32,
    pub module_taints: u32,
    pub task_fs: u32,
    pub fs_pwd: u32,
    pub task_files: u32,
    pub files_fdt: u32,
    pub fdt_fd: u32,
    pub file_f_inode: u32,
    pub inode_i_rdev: u32,
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
            sock_skc_daddr: UNAVAILABLE,
            sock_skc_rcv_saddr: UNAVAILABLE,
            sock_skc_dport: UNAVAILABLE,
            sock_skc_num: UNAVAILABLE,
            sock_skc_family: UNAVAILABLE,
            sock_skc_v6_daddr: UNAVAILABLE,
            sock_skc_v6_rcv_saddr: UNAVAILABLE,
            tcp_bytes_sent: UNAVAILABLE,
            tcp_bytes_received: UNAVAILABLE,
            sock_sk_shutdown: UNAVAILABLE,
            msghdr_msg_name: UNAVAILABLE,
            msghdr_msg_namelen: UNAVAILABLE,
            msghdr_msg_iter: UNAVAILABLE,
            iov_iter_type: UNAVAILABLE,
            iov_iter_iov: UNAVAILABLE,
            iov_iter_ubuf: UNAVAILABLE,
            iov_iter_count: UNAVAILABLE,
            module_name: UNAVAILABLE,
            module_taints: UNAVAILABLE,
            task_fs: UNAVAILABLE,
            fs_pwd: UNAVAILABLE,
            task_files: UNAVAILABLE,
            files_fdt: UNAVAILABLE,
            fdt_fd: UNAVAILABLE,
            file_f_inode: UNAVAILABLE,
            inode_i_rdev: UNAVAILABLE,
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
pub const MAX_COMPONENTS: usize = 24;
/// Levels walked per path by hooks that report one path; two-path hooks (rename, link) walk two
/// paths in one program and get fewer each so the verifier accepts them.
pub const PATH_LEVELS: usize = 24;
pub const PATH_LEVELS_TWO: usize = 16;
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

/// Identity of a file for the in-kernel sensitive-file filter: the superblock's kernel-format
/// `dev_t` (`major << 20 | minor`) and the inode number.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InodeKey {
    pub dev: u32,
    pub _pad: u32,
    pub ino: u64,
}

/// Capacity of the sensitive-inode map.
pub const SENSITIVE_MAX: u32 = 512;

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

/// [`NetBody::flags`]: the peer's FIN had been received.
pub const NET_PEER_FIN: u32 = 1;

/// TCP operations carried in [`NetBody::op`].
pub mod nop {
    /// Outbound connection established (SYN_SENT -> ESTABLISHED).
    pub const CONNECT: u32 = 1;
    /// Outbound connection failed (SYN_SENT -> CLOSE).
    pub const CONNECT_FAILED: u32 = 2;
    /// Inbound connection accepted by a process.
    pub const ACCEPT: u32 = 3;
    /// A connection closed.
    pub const CLOSE: u32 = 4;
    /// A socket started listening.
    pub const LISTEN: u32 = 5;
    /// A listening socket closed.
    pub const LISTEN_CLOSE: u32 = 6;
}

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

/// A connection's addresses and ports. Snapshotted while the socket is live because the
/// kernel clears the local port (`skc_num`) when the socket closes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetAddrs {
    /// 0 until captured.
    pub family: u32,
    pub lport: u16,
    pub rport: u16,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
}

impl NetAddrs {
    pub const ZERO: NetAddrs = NetAddrs {
        family: 0,
        lport: 0,
        rport: 0,
        laddr: [0; 16],
        raddr: [0; 16],
    };
}

/// What the kernel remembers about the process that owns a socket, so later state changes
/// (reported from softirq, where "current" is arbitrary) can be attributed to it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfo {
    /// The owner's header, captured at `connect()`/`accept()`/`listen()` time.
    pub hdr: RawHdr,
    pub comm: [u8; COMM_LEN],
    /// `CLOCK_BOOTTIME` when the socket was first seen, for the connection's duration.
    pub since_ns: u64,
    pub net: NetAddrs,
}

/// Body of a [`kind::NET_TCP`] record. Addresses are 16 bytes: IPv4 uses the first four.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetBody {
    pub op: u32,
    pub family: u32,
    pub lport: u16,
    pub rport: u16,
    /// Bit 0: the peer's FIN had been received. The kernel's `bytes_received` counts in
    /// sequence space, so it includes one for that FIN; userspace corrects for it.
    pub flags: u32,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub duration_ns: u64,
    pub old_state: u32,
    pub new_state: u32,
    pub comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub hdr: RawHdr,
    pub body: NetBody,
}

impl NetBody {
    pub const SIZE: usize = 96;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u16_at = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let u64_at = |o: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[o..o + 8]);
            u64::from_ne_bytes(a)
        };
        let mut laddr = [0u8; 16];
        laddr.copy_from_slice(&b[16..32]);
        let mut raddr = [0u8; 16];
        raddr.copy_from_slice(&b[32..48]);
        let mut comm = [0u8; COMM_LEN];
        comm.copy_from_slice(&b[80..96]);
        Some(Self {
            op: u32_at(0),
            family: u32_at(4),
            lport: u16_at(8),
            rport: u16_at(10),
            flags: u32_at(12),
            laddr,
            raddr,
            bytes_sent: u64_at(48),
            bytes_recv: u64_at(56),
            duration_ns: u64_at(64),
            old_state: u32_at(72),
            new_state: u32_at(76),
            comm,
        })
    }
}

/// [`ModuleBody::op`] values.
pub mod modop {
    pub const LOAD: u32 = 1;
    pub const FREE: u32 = 2;
}

/// `MODULE_NAME_LEN` in the kernel.
pub const MODULE_NAME_LEN: usize = 56;

/// Body of a [`kind::MODULE`] record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleBody {
    pub op: u32,
    pub _pad: u32,
    /// `struct module::taints` bit mask.
    pub taints: u64,
    pub name: [u8; MODULE_NAME_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleEvent {
    pub hdr: RawHdr,
    pub body: ModuleBody,
}

impl ModuleBody {
    pub const SIZE: usize = 16 + MODULE_NAME_LEN;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let mut t = [0u8; 8];
        t.copy_from_slice(&b[8..16]);
        let mut name = [0u8; MODULE_NAME_LEN];
        name.copy_from_slice(&b[16..]);
        Some(Self {
            op: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            _pad: 0,
            taints: u64::from_ne_bytes(t),
            name,
        })
    }
}

const _: () = assert!(core::mem::size_of::<ModuleBody>() == ModuleBody::SIZE);

/// DNS packet direction carried in [`DnsBody::dir`].
pub const DNS_QUERY: u32 = 1;
pub const DNS_RESPONSE: u32 = 2;
/// Bytes of each DNS packet copied out of the kernel (a typical response fits; larger ones are
/// flagged truncated).
pub const DNS_CAP: usize = 512;

/// Body of a [`kind::DNS`] record: the raw packet; parsing happens in userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsBody {
    pub dir: u32,
    pub family: u32,
    pub lport: u16,
    pub rport: u16,
    /// Bytes of `payload` that are valid.
    pub len: u32,
    /// 0 = UDP, 1 = TCP (the 2-byte length prefix is already removed).
    pub proto: u32,
    pub _pad: u32,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    pub payload: [u8; DNS_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub hdr: RawHdr,
    pub body: DnsBody,
}

impl DnsBody {
    pub const SIZE: usize = 56 + DNS_CAP;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u16_at = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let mut laddr = [0u8; 16];
        laddr.copy_from_slice(&b[24..40]);
        let mut raddr = [0u8; 16];
        raddr.copy_from_slice(&b[40..56]);
        let mut payload = [0u8; DNS_CAP];
        payload.copy_from_slice(&b[56..Self::SIZE]);
        Some(Self {
            dir: u32_at(0),
            family: u32_at(4),
            lport: u16_at(8),
            rport: u16_at(10),
            len: u32_at(12),
            proto: u32_at(16),
            _pad: 0,
            laddr,
            raddr,
            payload,
        })
    }

    pub fn packet(&self) -> &[u8] {
        &self.payload[..(self.len as usize).min(DNS_CAP)]
    }
}

/// Body of a [`kind::PROC_EXTRA`] record: the working directory and what descriptors 0-2 are.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecExtra {
    pub path_len: u32,
    pub trunc: u32,
    /// `inode->i_mode` of fd 0, 1, 2 (0 if the fd is not open).
    pub mode: [u32; 3],
    /// `inode->i_rdev` of fd 0, 1, 2 (device number, for character devices).
    pub rdev: [u32; 3],
    pub path: [u8; PATH_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecExtraEvent {
    pub hdr: RawHdr,
    pub body: ExecExtra,
}

impl ExecExtra {
    pub const SIZE: usize = 32 + PATH_CAP;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut path = [0u8; PATH_CAP];
        path.copy_from_slice(&b[32..]);
        Some(Self {
            path_len: u32_at(0),
            trunc: u32_at(4),
            mode: [u32_at(8), u32_at(12), u32_at(16)],
            rdev: [u32_at(20), u32_at(24), u32_at(28)],
            path,
        })
    }

    /// The working directory (empty if the kernel could not read it).
    pub fn cwd(&self) -> &[u8] {
        &self.path[..(self.path_len as usize).min(PATH_CAP)]
    }
}

const _: () = assert!(core::mem::size_of::<ExecExtra>() == ExecExtra::SIZE);

/// Chunks after the first that the kernel emits per exec: with [`ARGV_CAP`] bytes each, argv
/// is captured up to `ARGV_CAP * (1 + MAX_ARGV_CHUNKS)` (about 63 KiB).
pub const MAX_ARGV_CHUNKS: u64 = 20;

/// Body of a [`kind::PROC_ARGV`] record: bytes `idx * ARGV_CAP ..` of the argument area.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgvChunk {
    /// 1-based: chunk 0 is inside the exec record itself.
    pub idx: u32,
    /// Bytes of `data` that are valid.
    pub len: u32,
    pub data: [u8; ARGV_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgvEvent {
    pub hdr: RawHdr,
    pub body: ArgvChunk,
}

impl ArgvChunk {
    pub const SIZE: usize = 8 + ARGV_CAP;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let mut data = [0u8; ARGV_CAP];
        data.copy_from_slice(&b[8..]);
        Some(Self {
            idx: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            len: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            data,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data[..(self.len as usize).min(ARGV_CAP)]
    }
}

const _: () = assert!(core::mem::size_of::<ArgvChunk>() == ArgvChunk::SIZE);

/// Flows tracked at once in the kernel (per process and socket pair).
pub const FLOWS_MAX: u32 = 8192;

/// Key of a UDP flow: one process talking between two socket addresses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub family: u32,
    pub lport: u16,
    pub rport: u16,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    pub tgid: u32,
    pub _pad: u32,
}

/// Counters for a flow, with the owning process's header taken when the flow was first seen.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowVal {
    pub hdr: RawHdr,
    pub pkts_tx: u64,
    pub bytes_tx: u64,
    pub pkts_rx: u64,
    pub bytes_rx: u64,
    pub first_boot_ns: u64,
    pub comm: [u8; COMM_LEN],
}

/// Body of a [`kind::NET_UDP`] record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpBody {
    pub family: u32,
    pub lport: u16,
    pub rport: u16,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    pub pkts_tx: u64,
    pub bytes_tx: u64,
    pub pkts_rx: u64,
    pub bytes_rx: u64,
    pub first_boot_ns: u64,
    pub comm: [u8; COMM_LEN],
}

impl UdpBody {
    pub const SIZE: usize = 96;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..Self::SIZE)?;
        let u64_at = |o: usize| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[o..o + 8]);
            u64::from_ne_bytes(x)
        };
        let mut laddr = [0u8; 16];
        laddr.copy_from_slice(&b[8..24]);
        let mut raddr = [0u8; 16];
        raddr.copy_from_slice(&b[24..40]);
        let mut comm = [0u8; COMM_LEN];
        comm.copy_from_slice(&b[80..80 + COMM_LEN]);
        Some(Self {
            family: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            lport: u16::from_ne_bytes([b[4], b[5]]),
            rport: u16::from_ne_bytes([b[6], b[7]]),
            laddr,
            raddr,
            pkts_tx: u64_at(40),
            bytes_tx: u64_at(48),
            pkts_rx: u64_at(56),
            bytes_rx: u64_at(64),
            first_boot_ns: u64_at(72),
            comm,
        })
    }

    /// The record the decoder reads: `hdr` (the flow owner's) followed by this body.
    #[cfg(feature = "std")]
    pub fn to_record(&self, hdr: &RawHdr, now_boot_ns: u64) -> Vec<u8> {
        let mut h = *hdr;
        h.kind = kind::NET_UDP;
        h.len = (RawHdr::SIZE + Self::SIZE) as u32;
        h.boot_ns = now_boot_ns;
        let mut out = Vec::with_capacity(RawHdr::SIZE + Self::SIZE);
        out.extend_from_slice(&h.to_bytes());
        out.extend_from_slice(&self.family.to_ne_bytes());
        out.extend_from_slice(&self.lport.to_ne_bytes());
        out.extend_from_slice(&self.rport.to_ne_bytes());
        out.extend_from_slice(&self.laddr);
        out.extend_from_slice(&self.raddr);
        for v in [
            self.pkts_tx,
            self.bytes_tx,
            self.pkts_rx,
            self.bytes_rx,
            self.first_boot_ns,
        ] {
            out.extend_from_slice(&v.to_ne_bytes());
        }
        out.extend_from_slice(&self.comm);
        out
    }
}

const _: () = assert!(core::mem::size_of::<UdpBody>() == UdpBody::SIZE);
const _: () = assert!(core::mem::size_of::<FlowKey>() == 48);
const _: () = assert!(core::mem::size_of::<FlowVal>() == RawHdr::SIZE + 40 + COMM_LEN);

/// What `udp_recvmsg` was asked to fill, remembered at entry: by the time it returns the
/// kernel has advanced the iterator past the data, so the buffer must be saved up front.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvCtx {
    pub sk: u64,
    pub msg_name: u64,
    pub buf: u64,
    pub buf_len: u64,
}

pub const RECV_MAX: u32 = 4096;

/// Capacity of the socket-owner map.
pub const CONNS_MAX: u32 = 65_536;

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
const _: () = assert!(core::mem::size_of::<Offsets>() == 62 * 4);
const _: () = assert!(core::mem::size_of::<FileBody>() == FileBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileTwoBody>() == FileTwoBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileEvent>() == RawHdr::SIZE + FileBody::SIZE);
const _: () = assert!(core::mem::size_of::<FileTwoEvent>() == RawHdr::SIZE + FileTwoBody::SIZE);
const _: () = assert!(FileBody::SIZE % 8 == 0 && FileTwoBody::SIZE % 8 == 0);
const _: () = assert!(core::mem::size_of::<InodeKey>() == 16);
const _: () = assert!(core::mem::size_of::<DnsBody>() == DnsBody::SIZE);
const _: () = assert!(core::mem::size_of::<DnsEvent>() == RawHdr::SIZE + DnsBody::SIZE);
const _: () = assert!(core::mem::size_of::<NetAddrs>() == 40);
const _: () = assert!(core::mem::size_of::<NetBody>() == NetBody::SIZE);
const _: () = assert!(core::mem::size_of::<NetEvent>() == RawHdr::SIZE + NetBody::SIZE);
const _: () = assert!(core::mem::size_of::<ConnInfo>() == RawHdr::SIZE + COMM_LEN + 8 + 40);
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

    /// An all-zero header, written as plain constants (a `zeroed()` call can compile to a
    /// byte-loop `memset` that the BPF verifier then explores iteration by iteration).
    pub const ZERO: RawHdr = RawHdr {
        kind: 0,
        flags: 0,
        len: 0,
        boot_ns: 0,
        pid: 0,
        tid: 0,
        ppid: 0,
        _pad0: 0,
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
        auid: 0,
        ses: 0,
        cgroup_id: 0,
        start_boot_ns: 0,
    };

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
