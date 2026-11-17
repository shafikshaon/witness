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
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{btf_tracepoint, fexit, kprobe, map},
    maps::{PerCpuArray, RingBuf},
    programs::{BtfTracePointContext, FExitContext, ProbeContext},
};
use witness_common::{
    fop, kind, ExecEvent, ExitEvent, FileEvent, FileTwoEvent, ForkEvent, Offsets, RawHdr,
    ARGV_CAP, COMP_CAP, DROP_CLASS_CRITICAL, DROP_CLASS_VOLUME, FILENAME_CAP, FORK_THREAD,
    PATH_CAP, TTY_LEN, UNAVAILABLE,
};

/// P0 events: process lifecycle. Sized by the loader (`map_max_entries`).
#[map]
static CRITICAL: RingBuf = RingBuf::with_byte_size(8 << 20, 0);

/// High-volume events (file, later network). Separate from `CRITICAL` so a flood here can
/// never evict process lifecycle records.
#[map]
static VOLUME: RingBuf = RingBuf::with_byte_size(32 << 20, 0);

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

/// Reads a `T` at `base + off`, or `None` if the offset is unavailable or the read fails.
#[inline(always)]
unsafe fn field<T>(base: *const u8, off: u32) -> Option<T> {
    if base.is_null() || off == UNAVAILABLE {
        return None;
    }
    bpf_probe_read_kernel::<T>(base.add(off as usize).cast()).ok()
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

    let parent: *const u8 = field(task, o.task_real_parent).unwrap_or(null());
    let cred: *const u8 = field(task, o.task_cred).unwrap_or(null());
    let leader: *const u8 = field(task, o.task_group_leader).unwrap_or(null());

    (*h).kind = kind;
    (*h).flags = 0;
    (*h).len = len as u32;
    (*h).boot_ns = bpf_ktime_get_boot_ns();
    (*h).pid = (pid_tgid >> 32) as u32;
    (*h).tid = pid_tgid as u32;
    (*h).ppid = field::<u32>(parent, o.task_tgid).unwrap_or(0);
    (*h)._pad0 = 0;
    (*h).uid = uid;
    (*h).gid = gid;
    (*h).euid = field::<u32>(cred, o.cred_euid).unwrap_or(uid);
    (*h).egid = field::<u32>(cred, o.cred_egid).unwrap_or(gid);
    (*h).auid = field::<u32>(task, o.task_loginuid).unwrap_or(u32::MAX);
    (*h).ses = field::<u32>(task, o.task_sessionid).unwrap_or(u32::MAX);
    (*h).cgroup_id = bpf_get_current_cgroup_id();
    (*h).start_boot_ns = field::<u64>(leader, o.task_start_boottime).unwrap_or(0);
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
    (*body).comm = bpf_get_current_comm().unwrap_or([0; 16]);

    // Program path as passed to execve (resolved path comes from userspace for now).
    let fname: *const u8 = field(bprm, o.binprm_filename).unwrap_or(null());
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
    let signal: *const u8 = field(task, o.task_signal).unwrap_or(null());
    let tty: *const u8 = field(signal, o.signal_tty).unwrap_or(null());
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
    let mm: *const u8 = field(task, o.task_mm).unwrap_or(null());
    let start: u64 = field(mm, o.mm_arg_start).unwrap_or(0);
    let end: u64 = field(mm, o.mm_arg_end).unwrap_or(0);
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
    (*ev).body.exit_code = field::<i32>(task, o.task_exit_code).unwrap_or(0);
    (*ev).body.flags = 0;
    (*ev).body.comm = bpf_get_current_comm().unwrap_or([0; 16]);
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
    let child_tgid = field::<u32>(child, o.task_tgid).unwrap_or(0);
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
    (*ev).body.child_pid = field::<u32>(child, o.task_pid).unwrap_or(0);
    (*ev).body.child_tgid = child_tgid;
    (*ev).body.child_start_boot_ns = field::<u64>(child, o.task_start_boottime).unwrap_or(0);
    (*ev).body.flags = if child_tgid == 0 { FORK_THREAD } else { 0 };
    (*ev).body._pad = 0;
    entry.submit(0);
    Ok(())
}

// ---- file hooks --------------------------------------------------------------------------

const FMODE_WRITE: u32 = 0x2;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
/// Deepest directory nesting walked before the path is cut and flagged.
const MAX_COMPONENTS: usize = 40;

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

/// Builds the absolute path of `dentry` under mount `mnt` (a `struct vfsmount *`) into
/// `buf`, right-to-left, walking parents and stepping over mount points. Returns
/// `(offset, truncated)`; the path is `buf[offset..PATH_CAP]`.
///
/// Verifier notes: every dereference goes through `bpf_probe_read_kernel`; the write offset
/// only ever decreases from `PATH_CAP`, and each copy is at most `COMP_CAP` bytes into a
/// buffer with `PATH_SLACK` spare bytes, so `offset + length` is provably in range.
#[inline(always)]
unsafe fn build_path(buf: *mut u8, mnt: *const u8, dentry: *const u8, o: &Offsets) -> (u32, u32) {
    let mut off: usize = PATH_CAP;
    let mut trunc = 0u32;
    let mut dentry = dentry;
    let mut mnt = mnt;

    let mut i = 0;
    while i < MAX_COMPONENTS {
        i += 1;
        if dentry.is_null() {
            break;
        }
        let parent: *const u8 = field(dentry, o.dentry_d_parent).unwrap_or(null());
        if parent.is_null() || parent == dentry {
            // Root of this filesystem: continue at its mount point in the parent mount.
            if mnt.is_null() || o.mount_mnt == UNAVAILABLE {
                break;
            }
            let mount = mnt.sub(o.mount_mnt as usize);
            let up: *const u8 = field(mount, o.mount_mnt_parent).unwrap_or(null());
            if up.is_null() || up == mount {
                break; // the namespace root
            }
            dentry = field(mount, o.mount_mnt_mountpoint).unwrap_or(null());
            mnt = up.add(o.mount_mnt as usize);
            continue;
        }
        let name: *const u8 = field(dentry, o.dentry_d_name + o.qstr_name).unwrap_or(null());
        let mut len = field::<u32>(dentry, o.dentry_d_name + o.qstr_len).unwrap_or(0) as usize;
        if name.is_null() || len == 0 {
            break;
        }
        if len > COMP_CAP {
            len = COMP_CAP;
            trunc = 1;
        }
        // Room for "/" + name?
        if off < len + 1 {
            trunc = 1;
            break;
        }
        // The guard above makes this non-negative, but the verifier tracks value ranges, not
        // that relation: masking proves `off` lies within the buffer.
        off = (off - (len + 1)) & (PATH_CAP - 1);
        *buf.add(off) = b'/';
        // `off + 1 + len` is at most PATH_CAP, so the copy cannot leave the buffer.
        let _ = generated::bpf_probe_read_kernel(
            buf.add(off + 1).cast(),
            len as u32,
            name.cast(),
        );
        dentry = parent;
    }
    if i >= MAX_COMPONENTS {
        trunc = 1;
    }
    if off == PATH_CAP && off > 0 {
        off -= 1;
        *buf.add(off) = b'/';
    }
    (off as u32, trunc)
}

/// True if the file's filesystem should be ignored; also returns `(dev, ino, i_mode)`.
#[inline(always)]
unsafe fn file_identity(dentry: *const u8, o: &Offsets) -> Option<(bool, u32, u64, u32)> {
    let inode: *const u8 = field(dentry, o.dentry_d_inode)?;
    let sb: *const u8 = field(dentry, o.dentry_d_sb)?;
    let magic: u64 = field(sb, o.sb_s_magic)?;
    let dev: u32 = field(sb, o.sb_s_dev).unwrap_or(0);
    let ino: u64 = field(inode, o.inode_i_ino).unwrap_or(0);
    let mode: u16 = field(inode, o.inode_i_mode).unwrap_or(0);
    Some((noisy_fs(magic), dev, ino, mode as u32))
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
    let Some((noisy, dev, ino, cur_mode)) = file_identity(dentry, &o) else {
        return;
    };
    if noisy {
        return;
    }
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
    let (off, trunc) = build_path(addr_of_mut!((*b).path).cast::<u8>(), mnt, dentry, &o);
    (*b).path_off = off;
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
    let Some((noisy, dev, ino, _)) = file_identity(new_dentry, &o) else {
        return;
    };
    if noisy {
        return;
    }
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
    if op == fop::SYMLINK {
        (*b).old_off = 0;
        let dst = core::slice::from_raw_parts_mut(addr_of_mut!((*b).old).cast::<u8>(), PATH_CAP);
        if target.is_null() || bpf_probe_read_kernel_str_bytes(target, dst).is_err() {
            dst[0] = 0;
        }
    } else {
        let (off, t) = build_path(addr_of_mut!((*b).old).cast::<u8>(), old_mnt, old_dentry, &o);
        (*b).old_off = off;
        trunc |= t;
    }
    let (off, t) = build_path(addr_of_mut!((*b).new).cast::<u8>(), new_mnt, new_dentry, &o);
    (*b).new_off = off;
    (*b).trunc = trunc | t;
    entry.submit(0);
}

#[inline(always)]
unsafe fn path_parts(path: *const u8, o: &Offsets) -> (*const u8, *const u8) {
    (
        field(path, o.path_mnt).unwrap_or(null()),
        field(path, o.path_dentry).unwrap_or(null()),
    )
}

/// security_file_open(struct file *file): a file opened for writing.
#[fexit(function = "security_file_open")]
pub fn file_open(ctx: FExitContext) -> i32 {
    // SAFETY: kernel pointers are only read through `bpf_probe_read_kernel`.
    unsafe {
        let file: *const u8 = ctx.arg(0);
        let ret: i32 = ctx.arg(1);
        let o = offsets();
        let mode: u32 = field(file, o.file_f_mode).unwrap_or(0);
        if mode & FMODE_WRITE == 0 {
            return 0;
        }
        let flags: u32 = field(file, o.file_f_flags).unwrap_or(0);
        let fpath = file.add(o.file_f_path as usize);
        let (mnt, dentry) = path_parts(fpath, &o);
        if dentry.is_null() {
            return 0;
        }
        // Regular files only: directories, devices and sockets are not file writes.
        let Some((_, _, _, imode)) = file_identity(dentry, &o) else {
            return 0;
        };
        if imode & S_IFMT != S_IFREG {
            return 0;
        }
        emit_file(fop::OPEN_WRITE, ret, mnt, dentry, flags, 0, 0, 0);
    }
    0
}

/// security_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned dev)
#[fexit(function = "security_path_mknod")]
pub fn path_mknod(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0);
        let dentry: *const u8 = ctx.arg(1);
        let mode: u32 = ctx.arg::<u32>(2) & 0xffff;
        let ret: i32 = ctx.arg(4);
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::CREATE, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
#[fexit(function = "security_path_mkdir")]
pub fn path_mkdir(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0);
        let dentry: *const u8 = ctx.arg(1);
        let mode: u32 = ctx.arg::<u32>(2) & 0xffff;
        let ret: i32 = ctx.arg(3);
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::MKDIR, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_unlink(const struct path *dir, struct dentry *dentry)
#[fexit(function = "security_path_unlink")]
pub fn path_unlink(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0);
        let dentry: *const u8 = ctx.arg(1);
        let ret: i32 = ctx.arg(2);
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::UNLINK, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_rmdir(const struct path *dir, struct dentry *dentry)
#[fexit(function = "security_path_rmdir")]
pub fn path_rmdir(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0);
        let dentry: *const u8 = ctx.arg(1);
        let ret: i32 = ctx.arg(2);
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_file(fop::RMDIR, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_chmod(const struct path *path, umode_t mode)
#[fexit(function = "security_path_chmod")]
pub fn path_chmod(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let path: *const u8 = ctx.arg(0);
        let mode: u32 = ctx.arg::<u32>(1) & 0xffff;
        let ret: i32 = ctx.arg(2);
        let o = offsets();
        let (mnt, dentry) = path_parts(path, &o);
        emit_file(fop::CHMOD, ret, mnt, dentry, 0, mode, 0, 0);
    }
    0
}

/// security_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
///
/// `kuid_t`/`kgid_t` are structs passed by value, which BPF trampolines (fentry/fexit)
/// cannot carry on 5.15, so this one is a kprobe. A kprobe sees the call, not its result.
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
        emit_file(fop::CHOWN, 0, mnt, dentry, 0, 0, uid, gid);
    }
    0
}

/// security_path_truncate(const struct path *path)
#[fexit(function = "security_path_truncate")]
pub fn path_truncate(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let path: *const u8 = ctx.arg(0);
        let ret: i32 = ctx.arg(1);
        let o = offsets();
        let (mnt, dentry) = path_parts(path, &o);
        emit_file(fop::TRUNCATE, ret, mnt, dentry, 0, 0, 0, 0);
    }
    0
}

/// security_path_rename(old_dir, old_dentry, new_dir, new_dentry, unsigned int flags)
#[fexit(function = "security_path_rename")]
pub fn path_rename(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let old_dir: *const u8 = ctx.arg(0);
        let old_dentry: *const u8 = ctx.arg(1);
        let new_dir: *const u8 = ctx.arg(2);
        let new_dentry: *const u8 = ctx.arg(3);
        let flags: u32 = ctx.arg(4);
        let ret: i32 = ctx.arg(5);
        let o = offsets();
        let (old_mnt, _) = path_parts(old_dir, &o);
        let (new_mnt, _) = path_parts(new_dir, &o);
        emit_two(fop::RENAME, ret, old_mnt, old_dentry, new_mnt, new_dentry, null(), flags);
    }
    0
}

/// security_path_link(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
#[fexit(function = "security_path_link")]
pub fn path_link(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let old_dentry: *const u8 = ctx.arg(0);
        let new_dir: *const u8 = ctx.arg(1);
        let new_dentry: *const u8 = ctx.arg(2);
        let ret: i32 = ctx.arg(3);
        let o = offsets();
        let (mnt, _) = path_parts(new_dir, &o);
        // A hard link stays on one mount, so the new directory's mount names the old path too.
        emit_two(fop::LINK, ret, mnt, old_dentry, mnt, new_dentry, null(), 0);
    }
    0
}

/// security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)
#[fexit(function = "security_path_symlink")]
pub fn path_symlink(ctx: FExitContext) -> i32 {
    // SAFETY: as above.
    unsafe {
        let dir: *const u8 = ctx.arg(0);
        let dentry: *const u8 = ctx.arg(1);
        let target: *const u8 = ctx.arg(2);
        let ret: i32 = ctx.arg(3);
        let o = offsets();
        let (mnt, _) = path_parts(dir, &o);
        emit_two(fop::SYMLINK, ret, null(), null(), mnt, dentry, target, 0);
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
