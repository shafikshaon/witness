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
    macros::{btf_tracepoint, map},
    maps::{PerCpuArray, RingBuf},
    programs::BtfTracePointContext,
};
use witness_common::{
    kind, ExecEvent, ExitEvent, ForkEvent, Offsets, RawHdr, ARGV_CAP, DROP_CLASS_CRITICAL,
    FILENAME_CAP, FORK_THREAD, TTY_LEN, UNAVAILABLE,
};

/// P0 events: process lifecycle. Sized by the loader (`map_max_entries`).
#[map]
static CRITICAL: RingBuf = RingBuf::with_byte_size(8 << 20, 0);

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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
