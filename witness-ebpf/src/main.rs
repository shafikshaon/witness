//! Kernel-side programs: process exec, fork and exit (DESIGN.md §2.1).
//!
//! Struct fields are read with `bpf_probe_read_kernel` at offsets that userspace resolved
//! from the running kernel's BTF and passed in as the read-only `OFFSETS` global (§3.2),
//! so one object works across kernels without compiler-emitted CO-RE relocations.
#![no_std]
#![no_main]

use core::ptr::{addr_of_mut, null, read_volatile};

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{btf_tracepoint, kprobe, kretprobe, map},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{BtfTracePointContext, ProbeContext, RetProbeContext},
};
use witness_common::{
    nop, ConnInfo, InodeKey, NetEvent, AF_INET, CONNS_MAX, RESULT_UNKNOWN, SENSITIVE_MAX, fop, kind, ExecEvent, ExitEvent, FileEvent, FileTwoEvent, ForkEvent, Offsets, RawHdr,
    ARGV_CAP, DROP_CLASS_CRITICAL, DROP_CLASS_VOLUME, FILENAME_CAP, FORK_THREAD,
    MAX_COMPONENTS, PATH_CAP, SCRATCH_BUF, SCRATCH_LEN, TTY_LEN, UNAVAILABLE,
};

/// P0 events: process lifecycle. Sized by the loader (`map_max_entries`).
#[map]
static CRITICAL: RingBuf = RingBuf::with_byte_size(8 << 20, 0);

/// High-volume events (file, later network). Separate from `CRITICAL` so a flood here can
/// never evict process lifecycle records.
#[map]
static VOLUME: RingBuf = RingBuf::with_byte_size(32 << 20, 0);

/// Files whose *reads* are reported, keyed by `(dev, ino)`. Filled by the loader from the
/// configured sensitive list; matching by inode means no path walk for ordinary opens.
#[map]
static SENSITIVE: HashMap<InodeKey, u8> = HashMap::with_max_entries(SENSITIVE_MAX, 0);

/// Owner of each TCP socket we have seen start (`connect`, `accept`, `listen`), keyed by the
/// kernel `struct sock *`. Later state changes arrive in softirq context where "the current
/// process" is arbitrary, so they are attributed from here. LRU keeps it bounded.
#[map]
static CONNS: LruHashMap<u64, ConnInfo> = LruHashMap::with_max_entries(CONNS_MAX, 0);

/// Where paths are assembled before the final bounded copy into a record (one per CPU).
#[map]
static SCRATCH: PerCpuArray<[u8; SCRATCH_BUF]> = PerCpuArray::with_max_entries(1, 0);

/// Events lost because the ring buffer was full, per class. Never blocks the kernel side.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

/// Field offsets from the running kernel's BTF; set by the loader before attach.
#[no_mangle]
static OFFSETS: Offsets = Offsets::unavailable();

/// Thread-group id of `witnessd`; its own activity is not recorded. Set by the loader.
#[no_mangle]
static SELF_TGID: u32 = 0;

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[inline(always)]
fn offsets() -> Offsets {
    // SAFETY: a plain read of a read-only global; volatile stops the compiler from folding
    // the placeholder value in before the loader rewrites it.
    unsafe { read_volatile(&OFFSETS) }
}

/// Reads a `T` at `base + off`; `default` if the read fails.
///
/// Deliberately **branch-free**: `default` is stored first and the helper overwrites it on
/// success, and nothing tests the helper's result. A conditional here would leave two live
/// outcomes (read, or default) per call whose register values differ, so the verifier could
/// never merge them; a dozen reads in a row would multiply into thousands of distinct paths,
/// each re-verifying all the code after it. An unavailable offset (`UNAVAILABLE`) just makes
/// the read fault harmlessly and yield `default`.
#[inline(always)]
unsafe fn rd_or<T: Copy>(base: *const u8, off: u32, default: T) -> T {
    let mut v = default;
    let _ = generated::bpf_probe_read_kernel(
        (&mut v as *mut T).cast(),
        core::mem::size_of::<T>() as u32,
        base.wrapping_add(off as usize).cast(),
    );
    v
}

/// `comm` of the current task; zeros on failure (no branch on the helper's result).
#[inline(always)]
fn comm_or_zero() -> [u8; 16] {
    let mut c = [0u8; 16];
    // SAFETY: `c` is a valid 16-byte buffer for the helper to fill.
    unsafe {
        let _ = generated::bpf_get_current_comm(c.as_mut_ptr().cast(), 16);
    }
    c
}

#[inline(always)]
fn count_drop(class: u32) {
    if let Some(p) = DROPS.get_ptr_mut(class) {
        // SAFETY: per-CPU slot, only this CPU touches it.
        unsafe { *p += 1 };
    }
}

#[inline(always)]
fn is_self() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: read-only global, see `offsets`.
    tgid == unsafe { read_volatile(&SELF_TGID) }
}

/// Fills the common header from the current task.
#[inline(always)]
unsafe fn fill_hdr(h: *mut RawHdr, kind: u16, len: usize, task: *const u8, o: &Offsets) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let parent: *const u8 = rd_or(task, o.task_real_parent, null());
    let cred: *const u8 = rd_or(task, o.task_cred, null());
    let leader: *const u8 = rd_or(task, o.task_group_leader, null());

    (*h).kind = kind;
    (*h).flags = 0;
    (*h).len = len as u32;
    (*h).boot_ns = bpf_ktime_get_boot_ns();
    (*h).pid = (pid_tgid >> 32) as u32;
    (*h).tid = pid_tgid as u32;
    (*h).ppid = rd_or::<u32>(parent, o.task_tgid, 0);
    (*h)._pad0 = 0;
    (*h).uid = uid;
    (*h).gid = gid;
    (*h).euid = rd_or::<u32>(cred, o.cred_euid, uid);
    (*h).egid = rd_or::<u32>(cred, o.cred_egid, gid);
    (*h).auid = rd_or::<u32>(task, o.task_loginuid, u32::MAX);
    (*h).ses = rd_or::<u32>(task, o.task_sessionid, u32::MAX);
    (*h).cgroup_id = bpf_get_current_cgroup_id();
    (*h).start_boot_ns = rd_or::<u64>(leader, o.task_start_boottime, 0);
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: kernel pointers are only dereferenced through `bpf_probe_read_kernel`.
    let _ = unsafe { try_exec(&ctx) };
    0
}

unsafe fn try_exec(ctx: &BtfTracePointContext) -> Result<(), ()> {
    if is_self() {
        return Ok(());
    }
    // sched_process_exec(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
    let task: *const u8 = ctx.arg(0);
    let bprm: *const u8 = ctx.arg(2);
    let o = offsets();

    let Some(mut entry) = CRITICAL.reserve::<ExecEvent>(0) else {
        count_drop(DROP_CLASS_CRITICAL);
        return Err(());
    };
    let ev = entry.as_mut_ptr();
    fill_hdr(
        addr_of_mut!((*ev).hdr),
        kind::PROC_EXEC,
        core::mem::size_of::<ExecEvent>(),
        task,
        &o,
    );

    let body = addr_of_mut!((*ev).body);
    (*body).comm = comm_or_zero();

    // Program path as passed to execve (resolved path comes from userspace for now).
    let fname: *const u8 = rd_or(bprm, o.binprm_filename, null());
    (*body).filename_len = 0;
    if !fname.is_null() {
        let dst = core::slice::from_raw_parts_mut(
            addr_of_mut!((*body).filename).cast::<u8>(),
            FILENAME_CAP,
        );
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(fname, dst) {
            (*body).filename_len = s.len() as u32;
        }
    }

    // Controlling terminal: task->signal->tty->name.
    (*body).tty_len = 0;
    let signal: *const u8 = rd_or(task, o.task_signal, null());
    let tty: *const u8 = rd_or(signal, o.signal_tty, null());
    if !tty.is_null() && o.tty_name != UNAVAILABLE {
        let dst =
            core::slice::from_raw_parts_mut(addr_of_mut!((*body).tty).cast::<u8>(), TTY_LEN);
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(tty.add(o.tty_name as usize), dst) {
            (*body).tty_len = s.len() as u32;
        }
    }

    // Arguments: the new mm's [arg_start, arg_end) holds NUL-separated argv.
    (*body).argv_len = 0;
    (*body).argv_total = 0;
    let mm: *const u8 = rd_or(task, o.task_mm, null());
    let start: u64 = rd_or(mm, o.mm_arg_start, 0);
    let end: u64 = rd_or(mm, o.mm_arg_end, 0);
    if end > start {
        let total = end - start;
        let mut n = total;
        if n > ARGV_CAP as u64 {
            n = ARGV_CAP as u64;
            (*ev).hdr.flags |= witness_common::flags::TRUNCATED;
        }
        (*body).argv_total = total as u32;
        let r = generated::bpf_probe_read_user(
            addr_of_mut!((*body).argv).cast(),
            n as u32,
            start as *const core::ffi::c_void,
        );
        if r == 0 {
            (*body).argv_len = n as u32;
        }
    }

    entry.submit(0);
    Ok(())
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: as above.
    let _ = unsafe { try_exit(&ctx) };
    0
}

unsafe fn try_exit(ctx: &BtfTracePointContext) -> Result<(), ()> {
    if is_self() {
        return Ok(());
    }
    // Only the thread-group leader's exit, once per process (see DESIGN.md §2.1 gaps).
    let pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid >> 32) as u32 != pid_tgid as u32 {
        return Ok(());
    }
    // sched_process_exit(struct task_struct *p)
    let task: *const u8 = ctx.arg(0);
    let o = offsets();
    let Some(mut entry) = CRITICAL.reserve::<ExitEvent>(0) else {
        count_drop(DROP_CLASS_CRITICAL);
        return Err(());
    };
    let ev = entry.as_mut_ptr();
    fill_hdr(
        addr_of_mut!((*ev).hdr),
        kind::PROC_EXIT,
        core::mem::size_of::<ExitEvent>(),
        task,
        &o,
    );
    (*ev).body.exit_code = rd_or::<i32>(task, o.task_exit_code, 0);
    (*ev).body.flags = 0;
    (*ev).body.comm = comm_or_zero();
    entry.submit(0);
    Ok(())
}

#[btf_tracepoint(function = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: as above.
    let _ = unsafe { try_fork(&ctx) };
    0
}

unsafe fn try_fork(ctx: &BtfTracePointContext) -> Result<(), ()> {
    if is_self() {
        return Ok(());
    }
    // sched_process_fork(struct task_struct *parent, struct task_struct *child)
    let parent: *const u8 = ctx.arg(0);
    let child: *const u8 = ctx.arg(1);
    let o = offsets();
    let child_tgid = rd_or::<u32>(child, o.task_tgid, 0);
    // New threads are counted elsewhere, not stored (DESIGN.md §2.1).
    if child_tgid == (bpf_get_current_pid_tgid() >> 32) as u32 {
        return Ok(());
    }
    let Some(mut entry) = CRITICAL.reserve::<ForkEvent>(0) else {
        count_drop(DROP_CLASS_CRITICAL);
        return Err(());
    };
    let ev = entry.as_mut_ptr();
    fill_hdr(
        addr_of_mut!((*ev).hdr),
        kind::PROC_FORK,
        core::mem::size_of::<ForkEvent>(),
        parent,
        &o,
    );
    (*ev).body.child_pid = rd_or::<u32>(child, o.task_pid, 0);
    (*ev).body.child_tgid = child_tgid;
    (*ev).body.child_start_boot_ns = rd_or::<u64>(child, o.task_start_boottime, 0);
    (*ev).body.flags = if child_tgid == 0 { FORK_THREAD } else { 0 };
    (*ev).body._pad = 0;
    entry.submit(0);
    Ok(())
}

// ---- file hooks --------------------------------------------------------------------------

/// Diagnostic switch for bisecting verifier cost (0 = normal). Non-zero values disable parts
/// of the path walk; never ship non-zero.
const EXP: u32 = 0;

const FMODE_WRITE: u32 = 0x2;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
/// Pseudo filesystems whose writes are not interesting host activity.
#[inline(always)]
fn noisy_fs(magic: u64) -> bool {
    matches!(
        magic,
        0x9fa0            // proc
        | 0x6265_6572     // sysfs
        | 0x1cd1          // devpts
        | 0x27e0eb        // cgroup
        | 0x6367_7270     // cgroup2
        | 0x6462_6720     // debugfs
        | 0x7472_6163     // tracefs
        | 0xcafe_4a11     // bpf
        | 0x7363_6673     // securityfs
        | 0x5049_5045     // pipefs
        | 0x534f_434b     // sockfs
        | 0x0904_1934     // anon inodes
    )
}

/// `d_parent`, then `d_name` (`hash`, `len`, `name`) as they sit in `struct dentry`. The
/// loader refuses to enable file capture unless the running kernel's layout is exactly this
/// (`d_name` right after `d_parent`, `qstr.len` at +4, `qstr.name` at +8), so one read per
/// directory level replaces four branchy ones, which is what keeps the verifier's state
/// space small enough to accept the walk.
#[repr(C)]
#[derive(Clone, Copy)]
struct DentryHead {
    parent: u64,
    hash: u32,
    len: u32,
    name: u64,
}

/// `mnt_parent` then `mnt_mountpoint` from `struct mount` (adjacent; checked by the loader).
#[repr(C)]
#[derive(Clone, Copy)]
struct MountHead {
    parent: u64,
    mountpoint: u64,
}

/// Reads a [`DentryHead`] at `src`; a failed read leaves zeros. No branch on the helper's
/// result, and the zeros are plain field stores: `MaybeUninit::zeroed()` would call
/// `compiler_builtins`' byte-loop `memset`, which the verifier then explores iteration by
/// iteration for every directory level.
#[inline(always)]
unsafe fn read_dentry_head(src: *const u8) -> DentryHead {
    let mut v = DentryHead {
        parent: 0,
        hash: 0,
        len: 0,
        name: 0,
    };
    let _ = generated::bpf_probe_read_kernel(
        (&mut v as *mut DentryHead).cast(),
        core::mem::size_of::<DentryHead>() as u32,
        src.cast(),
    );
    v
}

#[inline(always)]
unsafe fn read_mount_head(src: *const u8) -> MountHead {
    let mut v = MountHead {
        parent: 0,
        mountpoint: 0,
    };
    let _ = generated::bpf_probe_read_kernel(
        (&mut v as *mut MountHead).cast(),
        core::mem::size_of::<MountHead>() as u32,
        src.cast(),
    );
    v
}

/// Builds the absolute path of `dentry` under mount `mnt` (a `struct vfsmount *`) and copies
/// it into `dst` (`PATH_CAP` bytes), left-aligned. Returns `(length, truncated)`.
///
/// The walk assembles the path right-to-left in the per-CPU `scratch` buffer. The buffer is
/// sized so `MAX_COMPONENTS` components can never wrap it, so the loop needs no overflow
/// bookkeeping: the offset is only masked, never compared with another variable range, which
/// is what lets the verifier prune equivalent states instead of exploring every path. One
/// bounded copy at the end moves at most `PATH_CAP` trailing bytes (the leaf end of a path
/// that is too long) into the record.
#[inline(always)]
unsafe fn build_path(
    scratch: *mut u8,
    dst: *mut u8,
    mnt: *const u8,
    dentry: *const u8,
    o: &Offsets,
) -> (u32, u32) {
    if EXP == 1 {
        return (0, 0);
    }
    let max = if EXP == 2 {
        1
    } else if EXP == 3 {
        4
    } else {
        MAX_COMPONENTS
    };
    let mut off: usize = SCRATCH_LEN;
    let mut wide = 0u32;
    // Set when the walk reaches the namespace root; only then is the path complete.
    let mut at_root = false;
    let mut dentry = dentry;
    let mut mnt = mnt;

    let mut i = 0;
    while i < max {
        i += 1;
        let head = read_dentry_head(dentry.add(o.dentry_d_parent as usize));
        if head.parent == dentry as u64 || head.parent == 0 {
            // Root of this filesystem: continue at its mount point in the parent mount.
            if mnt.is_null() || EXP == 4 {
                at_root = true;
                break;
            }
            let mount = mnt.sub(o.mount_mnt as usize);
            let m = read_mount_head(mount.add(o.mount_mnt_parent as usize));
            if m.parent == 0 || m.parent == mount as u64 {
                at_root = true; // the namespace root
                break;
            }
            dentry = m.mountpoint as *const u8;
            mnt = (m.parent as *const u8).add(o.mount_mnt as usize);
            continue;
        }
        if head.len == 0 || head.name == 0 {
            break;
        }
        // NAME_MAX is 255, so masking changes nothing for any real name; it replaces a
        // clamp branch whose two outcomes would both stay live through every later level.
        // Oversized-name evidence is OR-ed into `wide` and tested once after the loop.
        wide |= head.len >> 8;
        let len = (head.len & 0xff) as usize;
        // Never actually wraps (see above); the mask is for the verifier.
        off = off.wrapping_sub(len + 1) & (SCRATCH_LEN - 1);
        *scratch.add(off) = b'/';
        let _ = generated::bpf_probe_read_kernel(
            scratch.add(off + 1).cast(),
            len as u32,
            (head.name as *const u8).cast(),
        );
        dentry = head.parent as *const u8;
    }
    let mut trunc = (wide != 0) as u32;
    if !at_root {
        trunc = 1;
    }
    let mut n = SCRATCH_LEN - off;
    if n == 0 {
        // Nothing but the root.
        *scratch.add(SCRATCH_LEN - 1) = b'/';
        n = 1;
    }
    if n > PATH_CAP {
        n = PATH_CAP;
        trunc = 1;
    }
    let _ = generated::bpf_probe_read_kernel(
        dst.cast(),
        n as u32,
        scratch.add(SCRATCH_LEN - n).cast(),
    );
    (n as u32, trunc)
}

/// `(noisy filesystem, dev, ino, i_mode)` for a dentry; zeros if a read fails.
#[inline(always)]
unsafe fn file_identity(dentry: *const u8, o: &Offsets) -> (bool, u32, u64, u32) {
    let inode: *const u8 = rd_or(dentry, o.dentry_d_inode, null());
    let sb: *const u8 = rd_or(dentry, o.dentry_d_sb, null());
    let magic: u64 = rd_or(sb, o.sb_s_magic, 0);
    let dev: u32 = rd_or(sb, o.sb_s_dev, 0);
    let ino: u64 = rd_or(inode, o.inode_i_ino, 0);
    let mode: u16 = rd_or(inode, o.inode_i_mode, 0);
    (noisy_fs(magic), dev, ino, mode as u32)
}

/// Emits a one-path file operation. `old_mode` is read from the inode when the caller
/// passes `u32::MAX`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn emit_file(
    op: u32,
    ret: i32,
    mnt: *const u8,
    dentry: *const u8,
    flags: u32,
    mode: u32,
    uid: u32,
    gid: u32,
) {
    if is_self() || dentry.is_null() {
        return;
    }
    let o = offsets();
    let (noisy, dev, ino, cur_mode) = file_identity(dentry, &o);
    if noisy {
        return;
    }
    let Some(scratch) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let Some(mut entry) = VOLUME.reserve::<FileEvent>(0) else {
        count_drop(DROP_CLASS_VOLUME);
        return;
    };
    let ev = entry.as_mut_ptr();
    let task = generated::bpf_get_current_task() as *const u8;
    fill_hdr(
        addr_of_mut!((*ev).hdr),
        kind::FILE_OP,
        core::mem::size_of::<FileEvent>(),
        task,
        &o,
    );
    let b = addr_of_mut!((*ev).body);
    (*b).op = op;
    (*b).result = ret;
    (*b).flags = flags;
    (*b).mode = mode;
    (*b).old_mode = cur_mode;
    (*b).dev = dev;
    (*b).new_uid = uid;
    (*b).new_gid = gid;
    (*b).ino = ino;
    let (len, trunc) = build_path(
        scratch.cast(),
        addr_of_mut!((*b).path).cast::<u8>(),
        mnt,
        dentry,
        &o,
    );
    (*b).path_len = len;
    (*b).trunc = trunc;
    entry.submit(0);
}

/// Emits a two-path operation. For `SYMLINK`, `old_dentry` is null and `target` is the link
/// target string (copied left-aligned, NUL-terminated).
#[inline(always)]
unsafe fn emit_two(
    op: u32,
    ret: i32,
    old_mnt: *const u8,
    old_dentry: *const u8,
    new_mnt: *const u8,
    new_dentry: *const u8,
    target: *const u8,
    flags: u32,
) {
    if is_self() || new_dentry.is_null() {
        return;
    }
    let o = offsets();
    let (noisy, dev, ino, _) = file_identity(new_dentry, &o);
    if noisy {
        return;
    }
    let Some(scratch) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let Some(mut entry) = VOLUME.reserve::<FileTwoEvent>(0) else {
        count_drop(DROP_CLASS_VOLUME);
        return;
    };
    let ev = entry.as_mut_ptr();
    let task = generated::bpf_get_current_task() as *const u8;
    fill_hdr(
        addr_of_mut!((*ev).hdr),
        kind::FILE_TWO,
        core::mem::size_of::<FileTwoEvent>(),
        task,
        &o,
    );
    let b = addr_of_mut!((*ev).body);
    (*b).op = op;
    (*b).result = ret;
    (*b).flags = flags;
    (*b).dev = dev;
    (*b).ino = ino;
    (*b)._pad = 0;
    let mut trunc = 0;
    (*b).old_len = 0;
    if op == fop::SYMLINK {
        // The link target is a plain string: copy it as-is.
        let dst = core::slice::from_raw_parts_mut(addr_of_mut!((*b).old).cast::<u8>(), PATH_CAP);
        if !target.is_null() {
            if let Ok(t) = bpf_probe_read_kernel_str_bytes(target, dst) {
                (*b).old_len = t.len() as u32;
            }
        }
    } else {
        let (len, t) = build_path(
            scratch.cast(),
            addr_of_mut!((*b).old).cast::<u8>(),
            old_mnt,
            old_dentry,
            &o,
        );
        (*b).old_len = len;
        trunc |= t;
    }
    let (len, t) = build_path(
        scratch.cast(),
        addr_of_mut!((*b).new).cast::<u8>(),
        new_mnt,
        new_dentry,
        &o,
    );
    (*b).new_len = len;
    (*b).trunc = trunc | t;
    entry.submit(0);
}

#[inline(always)]
unsafe fn path_parts(path: *const u8, o: &Offsets) -> (*const u8, *const u8) {
    (
        rd_or(path, o.path_mnt, null()),
        rd_or(path, o.path_dentry, null()),
    )
}

/// security_file_open(struct file *file): a file opened for writing.
#[kprobe(function = "security_file_open")]
pub fn file_open(ctx: ProbeContext) -> u32 {
    // SAFETY: kernel pointers are only read through `bpf_probe_read_kernel`.
    unsafe {
        let file: *const u8 = ctx.arg(0).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let mode: u32 = rd_or(file, o.file_f_mode, 0);
        let flags: u32 = rd_or(file, o.file_f_flags, 0);
        let fpath = file.add(o.file_f_path as usize);
        let (mnt, dentry) = path_parts(fpath, &o);
        if dentry.is_null() {
            return 0;
        }
        // Regular files only: directories, devices and sockets are not file accesses.
        let (_, dev, ino, imode) = file_identity(dentry, &o);
        if imode & S_IFMT != S_IFREG {
            return 0;
        }
        if mode & FMODE_WRITE == 0 {
            // A read-only open matters only for files on the sensitive list.
            let key = InodeKey { dev, _pad: 0, ino };
            if SENSITIVE.get_ptr(&key).is_some() {
                emit_file(fop::OPEN_READ, ret, mnt, dentry, flags, 0, 0, 0);
            }
            return 0;
        }
        emit_file(fop::OPEN_WRITE, ret, mnt, dentry, flags, 0, 0, 0);
    }
    0
}

/// security_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned dev)
#[kprobe(function = "security_path_mknod")]
pub fn path_mknod(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let mode: u32 = ctx.arg::<u32>(2).unwrap_or(0) & 0xffff;
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::CREATE, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
#[kprobe(function = "security_path_mkdir")]
pub fn path_mkdir(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let mode: u32 = ctx.arg::<u32>(2).unwrap_or(0) & 0xffff;
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::MKDIR, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_unlink(const struct path *dir, struct dentry *dentry)
#[kprobe(function = "security_path_unlink")]
pub fn path_unlink(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::UNLINK, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_rmdir(const struct path *dir, struct dentry *dentry)
#[kprobe(function = "security_path_rmdir")]
pub fn path_rmdir(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::RMDIR, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_chmod(const struct path *path, umode_t mode)
#[kprobe(function = "security_path_chmod")]
pub fn path_chmod(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let path: *const u8 = ctx.arg(0).unwrap_or(null());
        let mode: u32 = ctx.arg::<u32>(1).unwrap_or(0) & 0xffff;
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, dentry) = path_parts(path, &o);
        emit_file(fop::CHMOD, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
///
/// All file hooks are kprobes: fentry/fexit trampolines do not exist on arm64 before 6.0,
/// and `kuid_t`/`kgid_t` are structs passed by value, which trampolines cannot carry on 5.15
/// anyway. A kprobe sees the call, not its result (`RESULT_UNKNOWN`).
#[kprobe(function = "security_path_chown")]
pub fn path_chown(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let (Some(path), Some(uid), Some(gid)) = (
            ctx.arg::<*const u8>(0),
            ctx.arg::<u32>(1),
            ctx.arg::<u32>(2),
        ) else {
            return 0;
        };
        let o = offsets();
        let (mnt, dentry) = path_parts(path, &o);
        emit_file(fop::CHOWN, RESULT_UNKNOWN, mnt, dentry, 0, 0, uid, gid);
    }
    0
}

/// security_path_truncate(const struct path *path)
#[kprobe(function = "security_path_truncate")]
pub fn path_truncate(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let path: *const u8 = ctx.arg(0).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, dentry) = path_parts(path, &o);
        emit_file(fop::TRUNCATE, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_rename(old_dir, old_dentry, new_dir, new_dentry, unsigned int flags)
#[kprobe(function = "security_path_rename")]
pub fn path_rename(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let old_dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let old_dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let new_dir: *const u8 = ctx.arg(2).unwrap_or(null());
        let new_dentry: *const u8 = ctx.arg(3).unwrap_or(null());
        let flags: u32 = ctx.arg(4).unwrap_or(0);
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (old_mnt, _) = path_parts(old_dir, &o);
        let (new_mnt, _) = path_parts(new_dir, &o);
        emit_two(fop::RENAME, ret, old_mnt, old_dentry, new_mnt, new_dentry, null(), flags);
    }
    0
}

/// security_path_link(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
#[kprobe(function = "security_path_link")]
pub fn path_link(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let old_dentry: *const u8 = ctx.arg(0).unwrap_or(null());
        let new_dir: *const u8 = ctx.arg(1).unwrap_or(null());
        let new_dentry: *const u8 = ctx.arg(2).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(new_dir, &o);
        // A hard link stays on one mount, so the new directory's mount names the old path too.
        emit_two(fop::LINK, ret, mnt, old_dentry, mnt, new_dentry, null(), 0);
    }
    0
}

/// security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)
#[kprobe(function = "security_path_symlink")]
pub fn path_symlink(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0).unwrap_or(null());
        let dentry: *const u8 = ctx.arg(1).unwrap_or(null());
        let target: *const u8 = ctx.arg(2).unwrap_or(null());
        let ret: i32 = RESULT_UNKNOWN;
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_two(fop::SYMLINK, ret, null(), null(), mnt, dentry, target, 0);
    }
    0
}

// ---- TCP --------------------------------------------------------------------------------

const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const TCP_CLOSE: i32 = 7;
const TCP_LISTEN: i32 = 10;

/// Copies a header field by field. A whole-struct copy compiles to `memcpy`, which in BPF is
/// a byte loop the verifier would walk iteration by iteration.
#[inline(always)]
unsafe fn copy_hdr(dst: *mut RawHdr, src: &RawHdr) {
    (*dst).kind = src.kind;
    (*dst).flags = src.flags;
    (*dst).len = src.len;
    (*dst).boot_ns = src.boot_ns;
    (*dst).pid = src.pid;
    (*dst).tid = src.tid;
    (*dst).ppid = src.ppid;
    (*dst)._pad0 = 0;
    (*dst).uid = src.uid;
    (*dst).gid = src.gid;
    (*dst).euid = src.euid;
    (*dst).egid = src.egid;
    (*dst).auid = src.auid;
    (*dst).ses = src.ses;
    (*dst).cgroup_id = src.cgroup_id;
    (*dst).start_boot_ns = src.start_boot_ns;
}

/// Captures the current process as a socket owner.
#[inline(always)]
unsafe fn current_owner(o: &Offsets) -> ConnInfo {
    let mut info = ConnInfo {
        hdr: RawHdr::ZERO,
        comm: comm_or_zero(),
        since_ns: bpf_ktime_get_boot_ns(),
    };
    let task = generated::bpf_get_current_task() as *const u8;
    fill_hdr(
        &mut info.hdr,
        kind::NET_TCP,
        core::mem::size_of::<NetEvent>(),
        task,
        o,
    );
    info
}

/// Emits one TCP lifecycle record for socket `sk`, attributed to `owner`.
#[inline(always)]
unsafe fn emit_net(op: u32, sk: *const u8, owner: &ConnInfo, old: i32, new: i32, o: &Offsets) {
    let Some(mut entry) = VOLUME.reserve::<NetEvent>(0) else {
        count_drop(DROP_CLASS_VOLUME);
        return;
    };
    let ev = entry.as_mut_ptr();
    copy_hdr(addr_of_mut!((*ev).hdr), &owner.hdr);
    (*ev).hdr.boot_ns = bpf_ktime_get_boot_ns();
    let b = addr_of_mut!((*ev).body);
    let family = rd_or::<u16>(sk, o.sock_skc_family, 0) as u32;
    (*b).op = op;
    (*b).family = family;
    (*b).lport = rd_or::<u16>(sk, o.sock_skc_num, 0);
    (*b).rport = u16::from_be(rd_or::<u16>(sk, o.sock_skc_dport, 0));
    // Bit 0 of `sk_shutdown` is RCV_SHUTDOWN: set when the peer's FIN arrives.
    (*b).flags = (rd_or::<u8>(sk, o.sock_sk_shutdown, 0) & 1) as u32;
    // Read the IPv6 pair unconditionally, then overwrite the first four bytes for IPv4.
    (*b).laddr = rd_or::<[u8; 16]>(sk, o.sock_skc_v6_rcv_saddr, [0; 16]);
    (*b).raddr = rd_or::<[u8; 16]>(sk, o.sock_skc_v6_daddr, [0; 16]);
    if family == AF_INET {
        let l = rd_or::<[u8; 4]>(sk, o.sock_skc_rcv_saddr, [0; 4]);
        let r = rd_or::<[u8; 4]>(sk, o.sock_skc_daddr, [0; 4]);
        (*b).laddr = [l[0], l[1], l[2], l[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        (*b).raddr = [r[0], r[1], r[2], r[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
    (*b).bytes_sent = rd_or::<u64>(sk, o.tcp_bytes_sent, 0);
    (*b).bytes_recv = rd_or::<u64>(sk, o.tcp_bytes_received, 0);
    (*b).duration_ns = (*ev).hdr.boot_ns.wrapping_sub(owner.since_ns);
    (*b).old_state = old as u32;
    (*b).new_state = new as u32;
    (*b).comm = owner.comm;
    entry.submit(0);
}

/// tcp_v4_connect / tcp_v6_connect(struct sock *sk, ...): remember who is connecting.
#[inline(always)]
unsafe fn on_connect(ctx: &ProbeContext) {
    if is_self() {
        return;
    }
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    let o = offsets();
    let info = current_owner(&o);
    let _ = CONNS.insert(&sk, &info, 0);
}

#[kprobe(function = "tcp_v4_connect")]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    // SAFETY: kernel memory is only read through the probe-read helper.
    unsafe { on_connect(&ctx) };
    0
}

#[kprobe(function = "tcp_v6_connect")]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe { on_connect(&ctx) };
    0
}

/// inet_csk_accept(...) returns the new `struct sock *`; the accepting process is current.
#[kretprobe(function = "inet_csk_accept")]
pub fn tcp_accept(ctx: RetProbeContext) -> u32 {
    // SAFETY: as above.
    unsafe {
        if is_self() {
            return 0;
        }
        let sk: u64 = ctx.ret();
        if sk == 0 {
            return 0;
        }
        let o = offsets();
        let info = current_owner(&o);
        let _ = CONNS.insert(&sk, &info, 0);
        emit_net(nop::ACCEPT, sk as *const u8, &info, TCP_LISTEN, TCP_ESTABLISHED, &o);
    }
    0
}

/// inet_sock_set_state(const struct sock *sk, int oldstate, int newstate)
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn tcp_state(ctx: BtfTracePointContext) -> i32 {
    // SAFETY: as above.
    unsafe { on_state(&ctx) };
    0
}

#[inline(always)]
unsafe fn on_state(ctx: &BtfTracePointContext) {
    let sk: *const u8 = ctx.arg(0);
    let old: i32 = ctx.arg(1);
    let new: i32 = ctx.arg(2);
    let key = sk as u64;
    let o = offsets();

    if new == TCP_LISTEN {
        // listen() runs in the owning process.
        if is_self() {
            return;
        }
        let info = current_owner(&o);
        let _ = CONNS.insert(&key, &info, 0);
        emit_net(nop::LISTEN, sk, &info, old, new, &o);
    } else if new == TCP_CLOSE {
        // Copy the owner out of the map before removing it.
        let Some(found) = CONNS.get(&key) else {
            return;
        };
        let owner = *found;
        let _ = CONNS.remove(&key);
        let op = if old == TCP_SYN_SENT {
            nop::CONNECT_FAILED
        } else if old == TCP_LISTEN {
            nop::LISTEN_CLOSE
        } else {
            nop::CLOSE
        };
        emit_net(op, sk, &owner, old, new, &o);
    } else if new == TCP_ESTABLISHED && old == TCP_SYN_SENT {
        let Some(found) = CONNS.get(&key) else {
            return;
        };
        let owner = *found;
        emit_net(nop::CONNECT, sk, &owner, old, new, &o);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
