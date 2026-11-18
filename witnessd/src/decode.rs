//! Turns raw ring-buffer records from the kernel programs into schema [`Event`]s.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use witness_common::schema::{
    puid, Actor, AttrOp, Body, ConnOutcome, Event, FileAttr, FileLink, FileOp, FileRename,
    HookResult, LinkKind, NetClose, NetConn, NetListen, OsBytes, Priority, ProcExec, ProcExit,
    ProcFork, Proto, Source, SCHEMA_VERSION,
};
use witness_common::{
    flags, fop, kind, nop, ExecBody, ExitBody, FileBody, FileTwoBody, ForkBody, NetBody, RawHdr,
    AF_INET,
};

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IFDIR: u32 = 0o040000;
/// Processes remembered for attributing later events; cleared wholesale if exceeded.
const PROC_TABLE_CAP: usize = 200_000;

/// What we know about a running process, for enriching events that only carry its identity.
#[derive(Clone)]
struct ProcInfo {
    comm: String,
    exe: Option<OsBytes>,
    cmdline: Option<Vec<OsBytes>>,
    tty: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("record shorter than its header or declared length")]
    Short,
    #[error("unknown event kind {0}")]
    UnknownKind(u16),
}

fn ip(family: u32, a: &[u8; 16]) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*a))
    }
}

fn net_conn(b: &NetBody, outcome: ConnOutcome) -> NetConn {
    NetConn {
        proto: Proto::Tcp,
        laddr: ip(b.family, &b.laddr),
        lport: b.lport,
        raddr: ip(b.family, &b.raddr),
        rport: b.rport,
        outcome,
        errno: None,
    }
}

fn net_body(b: &NetBody) -> Body {
    match b.op {
        nop::CONNECT => Body::NetConnect(net_conn(b, ConnOutcome::Established)),
        nop::CONNECT_FAILED => Body::NetConnect(net_conn(b, ConnOutcome::Failed)),
        nop::ACCEPT => Body::NetAccept(net_conn(b, ConnOutcome::Accepted)),
        nop::LISTEN | nop::LISTEN_CLOSE => {
            let l = NetListen {
                proto: Proto::Tcp,
                addr: ip(b.family, &b.laddr),
                port: b.lport,
            };
            if b.op == nop::LISTEN {
                Body::NetListen(l)
            } else {
                Body::NetListenClose(l)
            }
        }
        // CLOSE, and anything newer we do not recognise: keep it as a close.
        _ => Body::NetClose(NetClose {
            conn: net_conn(b, ConnOutcome::Established),
            bytes_sent: Some(b.bytes_sent),
            bytes_recv: Some(b.bytes_recv),
            duration_ns: b.duration_ns,
        }),
    }
}

fn hook_result(r: i32) -> HookResult {
    match r {
        witness_common::RESULT_UNKNOWN => HookResult::Attempted,
        0 => HookResult::Allowed,
        _ => HookResult::Denied,
    }
}

fn file_op(b: &FileBody, mode: Option<u32>, flags: Option<u32>) -> FileOp {
    FileOp {
        path: OsBytes(b.path_bytes().to_vec()),
        path_resolved: true,
        path_truncated: b.trunc != 0,
        dev: u64::from(b.dev),
        ino: b.ino,
        mode,
        flags,
        result: hook_result(b.result),
    }
}

fn file_body(b: &FileBody) -> Body {
    match b.op {
        fop::OPEN_WRITE => Body::FileOpenWrite(file_op(b, None, Some(b.flags))),
        fop::OPEN_READ => Body::FileOpenRead(file_op(b, None, Some(b.flags))),
        fop::CREATE => Body::FileCreate(file_op(b, Some(b.mode), None)),
        fop::MKDIR => Body::FileCreate(file_op(b, Some(b.mode | S_IFDIR), None)),
        fop::UNLINK => Body::FileDelete(file_op(b, None, None)),
        fop::RMDIR => Body::FileDelete(file_op(b, Some(S_IFDIR), None)),
        fop::TRUNCATE => Body::FileTruncate(file_op(b, None, None)),
        fop::CHMOD => {
            let (old, new) = (b.old_mode & 0o7777, b.mode & 0o7777);
            Body::FileAttr(FileAttr {
                op: AttrOp::Chmod,
                path: OsBytes(b.path_bytes().to_vec()),
                old_mode: Some(old),
                new_mode: Some(new),
                new_uid: None,
                new_gid: None,
                suid_set: new & S_ISUID != 0 && old & S_ISUID == 0,
                sgid_set: new & S_ISGID != 0 && old & S_ISGID == 0,
                result: hook_result(b.result),
            })
        }
        fop::CHOWN => Body::FileAttr(FileAttr {
            op: AttrOp::Chown,
            path: OsBytes(b.path_bytes().to_vec()),
            old_mode: Some(b.old_mode & 0o7777),
            new_mode: None,
            // (uid_t)-1 means "leave unchanged"
            new_uid: (b.new_uid != u32::MAX).then_some(b.new_uid),
            new_gid: (b.new_gid != u32::MAX).then_some(b.new_gid),
            suid_set: false,
            sgid_set: false,
            result: hook_result(b.result),
        }),
        // Unknown operation from a newer kernel program: keep it visible rather than dropping it.
        _ => Body::FileTruncate(file_op(b, None, Some(b.op))),
    }
}

fn file_two_body(b: &FileTwoBody) -> Body {
    match b.op {
        fop::RENAME => Body::FileRename(FileRename {
            old: OsBytes(b.old_bytes().to_vec()),
            new: OsBytes(b.new_bytes().to_vec()),
            dev: u64::from(b.dev),
            ino: b.ino,
            result: hook_result(b.result),
        }),
        fop::LINK => Body::FileLink(FileLink {
            kind: LinkKind::Hard,
            path: OsBytes(b.new_bytes().to_vec()),
            target: OsBytes(b.old_bytes().to_vec()),
            result: hook_result(b.result),
        }),
        _ => {
            // Symlink: `old` holds the link target string.
            Body::FileLink(FileLink {
                kind: LinkKind::Symbolic,
                path: OsBytes(b.new_bytes().to_vec()),
                target: OsBytes(b.old_bytes().to_vec()),
                result: hook_result(b.result),
            })
        }
    }
}

/// Context needed to turn kernel records into events.
pub struct Decoder {
    boot_id: String,
    /// `CLOCK_REALTIME - CLOCK_BOOTTIME`, refreshed by the caller (DESIGN.md §3.4).
    clock_offset_ns: i64,
    procs: HashMap<String, ProcInfo>,
}

fn cstr(buf: &[u8], len: u32) -> Vec<u8> {
    let n = (len as usize).min(buf.len());
    let mut v = buf[..n].to_vec();
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

impl Decoder {
    pub fn new(boot_id: impl Into<String>) -> Self {
        Decoder {
            boot_id: boot_id.into(),
            clock_offset_ns: 0,
            procs: HashMap::new(),
        }
    }

    fn remember(&mut self, a: &Actor) {
        if self.procs.len() >= PROC_TABLE_CAP {
            self.procs.clear();
        }
        self.procs.insert(
            a.puid.clone(),
            ProcInfo {
                comm: a.comm.clone(),
                exe: a.exe.clone(),
                cmdline: a.cmdline.clone(),
                tty: a.tty.clone(),
            },
        );
    }

    /// Learns a process from an event decoded elsewhere (the baseline snapshot).
    pub fn learn(&mut self, ev: &Event) {
        if let Some(a) = &ev.actor {
            if matches!(ev.body, Body::Baseline(_) | Body::ProcExec(_)) {
                self.remember(a);
            }
        }
    }

    /// Fills in what the kernel record did not carry from what we know of the process.
    fn enrich(&self, a: &mut Actor) {
        if let Some(i) = self.procs.get(&a.puid) {
            if a.comm.is_empty() {
                a.comm = i.comm.clone();
            }
            if a.exe.is_none() {
                a.exe = i.exe.clone();
            }
            if a.cmdline.is_none() {
                a.cmdline = i.cmdline.clone();
            }
            if a.tty.is_none() {
                a.tty = i.tty.clone();
            }
        }
    }

    pub fn set_clock_offset(&mut self, realtime_minus_boottime_ns: i64) {
        self.clock_offset_ns = realtime_minus_boottime_ns;
    }

    fn wall_ns(&self, boot_ns: u64) -> u64 {
        (boot_ns as i64).saturating_add(self.clock_offset_ns).max(0) as u64
    }

    /// `resolve_exe(pid)` returns the resolved executable path if it can still be found.
    pub fn decode(
        &mut self,
        rec: &[u8],
        resolve_exe: &dyn Fn(u32) -> Option<Vec<u8>>,
    ) -> Result<Event, DecodeError> {
        let hdr = RawHdr::parse(rec).ok_or(DecodeError::Short)?;
        if (hdr.len as usize) > rec.len() || (hdr.len as usize) < RawHdr::SIZE {
            return Err(DecodeError::Short);
        }
        let body = &rec[RawHdr::SIZE..hdr.len as usize];
        let mut actor = Actor {
            puid: puid(&self.boot_id, hdr.pid, hdr.start_boot_ns),
            pid: hdr.pid,
            tid: hdr.tid,
            ppid: hdr.ppid,
            uid: hdr.uid,
            gid: hdr.gid,
            euid: hdr.euid,
            egid: hdr.egid,
            user: None,
            auid: (hdr.auid != u32::MAX).then_some(hdr.auid),
            ses: (hdr.ses != u32::MAX).then_some(hdr.ses),
            cgroup_id: hdr.cgroup_id,
            comm: String::new(),
            exe: None,
            cmdline: None,
            tty: None,
        };

        let body = match hdr.kind {
            kind::PROC_EXEC => {
                let b = ExecBody::parse(body).ok_or(DecodeError::Short)?;
                let filename = OsBytes(cstr(&b.filename, b.filename_len));
                let argv_bytes = &b.argv[..(b.argv_len as usize).min(b.argv.len())];
                let mut argv: Vec<OsBytes> = argv_bytes
                    .split(|&c| c == 0)
                    .map(|a| OsBytes(a.to_vec()))
                    .collect();
                // Arguments are NUL-terminated, so a complete area ends in one empty chunk.
                if argv_bytes.last() == Some(&0) {
                    argv.pop();
                }
                let truncated = hdr.flags & flags::TRUNCATED != 0;
                let exe = resolve_exe(hdr.pid)
                    .map(OsBytes)
                    .unwrap_or_else(|| filename.clone());
                let tty = String::from_utf8_lossy(&cstr(&b.tty, b.tty_len)).into_owned();
                actor.comm = String::from_utf8_lossy(&cstr(&b.comm, 16)).into_owned();
                actor.exe = Some(exe.clone());
                actor.cmdline = Some(argv.clone());
                actor.tty = (!tty.is_empty()).then(|| tty.clone());
                self.remember(&actor);
                Body::ProcExec(ProcExec {
                    filename,
                    exe,
                    argv,
                    argv_truncated: truncated,
                    cwd: None,
                    env: None,
                    stdio: None,
                    interactive: !tty.is_empty(),
                })
            }
            kind::PROC_EXIT => {
                let b = ExitBody::parse(body).ok_or(DecodeError::Short)?;
                actor.comm = String::from_utf8_lossy(&cstr(&b.comm, 16)).into_owned();
                self.enrich(&mut actor);
                self.procs.remove(&actor.puid);
                let code = b.exit_code;
                let signal = (code & 0x7f) as u8;
                Body::ProcExit(ProcExit {
                    exit_code: (signal == 0).then_some((code >> 8) & 0xff),
                    signal: (signal != 0).then_some(signal),
                    core_dumped: code & 0x80 != 0,
                    runtime_ns: (hdr.start_boot_ns != 0)
                        .then(|| hdr.boot_ns.saturating_sub(hdr.start_boot_ns)),
                })
            }
            kind::PROC_FORK => {
                let b = ForkBody::parse(body).ok_or(DecodeError::Short)?;
                // Until it execs, the child is its parent's image.
                self.enrich(&mut actor);
                let child = puid(&self.boot_id, b.child_tgid, b.child_start_boot_ns);
                if let Some(parent) = self.procs.get(&actor.puid).cloned() {
                    if self.procs.len() >= PROC_TABLE_CAP {
                        self.procs.clear();
                    }
                    self.procs.insert(child, parent);
                }
                Body::ProcFork(ProcFork {
                    child_pid: b.child_tgid,
                    child_puid: puid(&self.boot_id, b.child_tgid, b.child_start_boot_ns),
                    is_thread: b.flags & witness_common::FORK_THREAD != 0,
                })
            }
            kind::FILE_OP => {
                let b = FileBody::parse(body).ok_or(DecodeError::Short)?;
                self.enrich(&mut actor);
                if actor.exe.is_none() {
                    actor.exe = resolve_exe(hdr.pid).map(OsBytes);
                }
                file_body(&b)
            }
            kind::FILE_TWO => {
                let b = FileTwoBody::parse(body).ok_or(DecodeError::Short)?;
                self.enrich(&mut actor);
                if actor.exe.is_none() {
                    actor.exe = resolve_exe(hdr.pid).map(OsBytes);
                }
                file_two_body(&b)
            }
            kind::NET_TCP => {
                let b = NetBody::parse(body).ok_or(DecodeError::Short)?;
                actor.comm = String::from_utf8_lossy(&cstr(&b.comm, 16)).into_owned();
                self.enrich(&mut actor);
                if actor.exe.is_none() {
                    actor.exe = resolve_exe(hdr.pid).map(OsBytes);
                }
                net_body(&b)
            }
            other => return Err(DecodeError::UnknownKind(other)),
        };

        let prio: Priority = body.priority();
        Ok(Event {
            v: SCHEMA_VERSION,
            seq: 0,
            boot_id: self.boot_id.clone(),
            boot_ns: hdr.boot_ns,
            wall_ns: self.wall_ns(hdr.boot_ns),
            wall_uncertain: false,
            src: Source::Ebpf,
            prio: prio as u8,
            actor: Some(actor),
            body,
            h: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_common::{ARGV_CAP, FILENAME_CAP};

    fn hdr(kind: u16, len: usize) -> RawHdr {
        RawHdr {
            kind,
            flags: 0,
            len: len as u32,
            boot_ns: 5_000,
            pid: 321,
            tid: 321,
            ppid: 1,
            _pad0: 0,
            uid: 1000,
            gid: 1000,
            euid: 0,
            egid: 0,
            auid: 1000,
            ses: u32::MAX,
            cgroup_id: 9,
            start_boot_ns: 1_000,
        }
    }

    fn exec_record(filename: &[u8], argv: &[u8], total: u32, flags: u16, tty: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; ExecBody::SIZE];
        body[0..4].copy_from_slice(&(argv.len() as u32).to_ne_bytes());
        body[4..8].copy_from_slice(&total.to_ne_bytes());
        body[8..12].copy_from_slice(&(filename.len() as u32).to_ne_bytes());
        body[12..16].copy_from_slice(&(tty.len() as u32).to_ne_bytes());
        body[16..16 + 4].copy_from_slice(b"curl");
        body[32..32 + tty.len()].copy_from_slice(tty);
        body[48..48 + filename.len()].copy_from_slice(filename);
        body[48 + FILENAME_CAP..48 + FILENAME_CAP + argv.len()].copy_from_slice(argv);
        let mut h = hdr(kind::PROC_EXEC, RawHdr::SIZE + body.len());
        h.flags = flags;
        let mut rec = h.to_bytes().to_vec();
        rec.extend(body);
        rec
    }

    fn dec() -> Decoder {
        let mut d = Decoder::new("4f2a9c1e-0000-0000-0000-000000000000");
        d.set_clock_offset(1_700_000_000_000_000_000);
        d
    }

    #[test]
    fn exec_becomes_a_proc_exec_event() {
        let rec = exec_record(b"/usr/bin/curl", b"curl\0-s\0http://x\0", 17, 0, b"pts/0");
        let e = dec()
            .decode(&rec, &|_| Some(b"/usr/bin/curl".to_vec()))
            .unwrap();
        assert_eq!(e.wall_ns, 1_700_000_000_000_005_000);
        assert_eq!(e.prio, 0);
        let a = e.actor.unwrap();
        assert_eq!(a.puid, "4f2a9c1e-321-0");
        assert_eq!((a.auid, a.ses), (Some(1000), None));
        assert_eq!(a.comm, "curl");
        assert_eq!(a.tty.as_deref(), Some("pts/0"));
        assert_eq!(a.cmdline.unwrap().len(), 3);
        match e.body {
            Body::ProcExec(x) => {
                assert_eq!(x.argv[2], OsBytes::from("http://x"));
                assert!(x.interactive && !x.argv_truncated);
                assert_eq!(x.exe, OsBytes::from("/usr/bin/curl"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unresolved_exe_falls_back_to_the_filename() {
        let rec = exec_record(b"./run.sh", b"./run.sh\0", 9, 0, b"");
        let e = dec().decode(&rec, &|_| None).unwrap();
        let Body::ProcExec(x) = e.body else { panic!() };
        assert_eq!(x.exe, OsBytes::from("./run.sh"));
        assert!(!x.interactive);
        assert_eq!(e.actor.unwrap().tty, None);
    }

    #[test]
    fn truncated_argv_is_flagged_and_keeps_the_partial_tail() {
        let argv = vec![b'a'; ARGV_CAP];
        let rec = exec_record(b"/bin/x", &argv, 100_000, flags::TRUNCATED, b"");
        let e = dec().decode(&rec, &|_| None).unwrap();
        let Body::ProcExec(x) = e.body else { panic!() };
        assert!(x.argv_truncated);
        assert_eq!(x.argv.len(), 1);
        assert_eq!(x.argv[0].0.len(), ARGV_CAP);
    }

    #[test]
    fn non_utf8_arguments_survive() {
        let rec = exec_record(b"/bin/x", b"x\0\xff\xfe\0", 5, 0, b"");
        let e = dec().decode(&rec, &|_| None).unwrap();
        let Body::ProcExec(x) = e.body else { panic!() };
        assert_eq!(x.argv[1], OsBytes(vec![0xff, 0xfe]));
        // And it serializes (as base64) without loss.
        let json = serde_json::to_string(&dec().decode(&rec, &|_| None).unwrap()).unwrap();
        assert!(json.contains("b64"));
    }

    #[test]
    fn exit_codes_and_signals() {
        let mk = |code: i32| {
            let mut body = vec![0u8; ExitBody::SIZE];
            body[0..4].copy_from_slice(&code.to_ne_bytes());
            body[8..8 + 5].copy_from_slice(b"sleep");
            let mut rec = hdr(kind::PROC_EXIT, RawHdr::SIZE + body.len())
                .to_bytes()
                .to_vec();
            rec.extend(body);
            rec
        };
        let ex = |rec: &[u8]| match dec().decode(rec, &|_| None).unwrap().body {
            Body::ProcExit(x) => x,
            other => panic!("{other:?}"),
        };
        let clean = ex(&mk(3 << 8));
        assert_eq!(
            (clean.exit_code, clean.signal, clean.core_dumped),
            (Some(3), None, false)
        );
        assert_eq!(clean.runtime_ns, Some(4_000));
        let killed = ex(&mk(9));
        assert_eq!((killed.exit_code, killed.signal), (None, Some(9)));
        let core = ex(&mk(11 | 0x80));
        assert!(core.core_dumped && core.signal == Some(11));
    }

    #[test]
    fn fork_links_child_identity() {
        let mut body = vec![0u8; ForkBody::SIZE];
        body[0..4].copy_from_slice(&700u32.to_ne_bytes());
        body[4..8].copy_from_slice(&700u32.to_ne_bytes());
        body[8..16].copy_from_slice(&2_000u64.to_ne_bytes());
        let mut rec = hdr(kind::PROC_FORK, RawHdr::SIZE + body.len())
            .to_bytes()
            .to_vec();
        rec.extend(body);
        let e = dec().decode(&rec, &|_| None).unwrap();
        let Body::ProcFork(f) = e.body else { panic!() };
        assert_eq!(
            (f.child_pid, f.child_puid.as_str()),
            (700, "4f2a9c1e-700-0")
        );
        assert_eq!(e.prio, 1);
    }

    #[test]
    fn bad_records_are_errors_not_panics() {
        let mut d = dec();
        assert_eq!(
            d.decode(&[0u8; 10], &|_| None).unwrap_err(),
            DecodeError::Short
        );
        let mut rec = exec_record(b"/bin/x", b"x\0", 2, 0, b"");
        rec.truncate(200);
        assert_eq!(d.decode(&rec, &|_| None).unwrap_err(), DecodeError::Short);
        let rec = hdr(99, RawHdr::SIZE).to_bytes();
        assert_eq!(
            d.decode(&rec, &|_| None).unwrap_err(),
            DecodeError::UnknownKind(99)
        );
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use witness_common::PATH_CAP;

    fn hdr(kind: u16, len: usize, pid: u32) -> RawHdr {
        RawHdr {
            kind,
            flags: 0,
            len: len as u32,
            boot_ns: 9_000_000_000,
            pid,
            tid: pid,
            ppid: 1,
            _pad0: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            auid: 1000,
            ses: 3,
            cgroup_id: 1,
            start_boot_ns: 50_000_000,
        }
    }

    /// A FILE_OP record whose path is right-aligned, as the kernel writes it.
    fn file_rec(
        pid: u32,
        op: u32,
        path: &str,
        mode: u32,
        old_mode: u32,
        result: i32,
        uid_gid: (u32, u32),
    ) -> Vec<u8> {
        let mut body = vec![0u8; FileBody::SIZE];
        body[0..4].copy_from_slice(&op.to_ne_bytes());
        body[4..8].copy_from_slice(&result.to_ne_bytes());
        body[8..12].copy_from_slice(&0o101u32.to_ne_bytes()); // flags
        body[12..16].copy_from_slice(&mode.to_ne_bytes());
        body[16..20].copy_from_slice(&old_mode.to_ne_bytes());
        body[20..24].copy_from_slice(&259u32.to_ne_bytes()); // dev
        body[24..28].copy_from_slice(&uid_gid.0.to_ne_bytes());
        body[28..32].copy_from_slice(&uid_gid.1.to_ne_bytes());
        body[32..40].copy_from_slice(&777u64.to_ne_bytes());
        body[40..44].copy_from_slice(&(path.len() as u32).to_ne_bytes());
        body[48..48 + path.len()].copy_from_slice(path.as_bytes());
        let mut rec = hdr(kind::FILE_OP, RawHdr::SIZE + body.len(), pid)
            .to_bytes()
            .to_vec();
        rec.extend(body);
        rec
    }

    fn two_rec(op: u32, old: &str, new: &str) -> Vec<u8> {
        let mut body = vec![0u8; FileTwoBody::SIZE];
        body[0..4].copy_from_slice(&op.to_ne_bytes());
        body[12..16].copy_from_slice(&259u32.to_ne_bytes());
        let (old_at, new_at) = (40, 40 + PATH_CAP);
        body[old_at..old_at + old.len()].copy_from_slice(old.as_bytes());
        body[new_at..new_at + new.len()].copy_from_slice(new.as_bytes());
        body[24..28].copy_from_slice(&(old.len() as u32).to_ne_bytes());
        body[28..32].copy_from_slice(&(new.len() as u32).to_ne_bytes());
        let mut rec = hdr(kind::FILE_TWO, RawHdr::SIZE + body.len(), 55)
            .to_bytes()
            .to_vec();
        rec.extend(body);
        rec
    }

    fn dec() -> Decoder {
        Decoder::new("4f2a9c1e-0000-0000-0000-000000000000")
    }

    #[test]
    fn open_for_write_is_attributed_to_the_known_process() {
        let mut d = dec();
        // The process is known from an earlier exec.
        let mut exec_body = vec![0u8; ExecBody::SIZE];
        exec_body[0..4].copy_from_slice(&5u32.to_ne_bytes());
        exec_body[8..12].copy_from_slice(&8u32.to_ne_bytes());
        exec_body[16..20].copy_from_slice(b"vim\0");
        exec_body[48..56].copy_from_slice(b"/bin/vim");
        exec_body[48 + witness_common::FILENAME_CAP..48 + witness_common::FILENAME_CAP + 5]
            .copy_from_slice(b"vim\0x");
        let mut rec = hdr(kind::PROC_EXEC, RawHdr::SIZE + exec_body.len(), 321)
            .to_bytes()
            .to_vec();
        rec.extend(exec_body);
        d.decode(&rec, &|_| Some(b"/usr/bin/vim".to_vec())).unwrap();

        let e = d
            .decode(
                &file_rec(321, fop::OPEN_WRITE, "/etc/passwd", 0, 0, 0, (0, 0)),
                &|_| None,
            )
            .unwrap();
        let a = e.actor.as_ref().unwrap();
        assert_eq!(a.comm, "vim");
        assert_eq!(a.exe, Some(OsBytes::from("/usr/bin/vim")));
        assert!(a.cmdline.is_some());
        assert_eq!(a.auid, Some(1000));
        match e.body {
            Body::FileOpenWrite(f) => {
                assert_eq!(f.path, OsBytes::from("/etc/passwd"));
                assert_eq!(
                    (f.dev, f.ino, f.flags, f.result),
                    (259, 777, Some(0o101), HookResult::Allowed)
                );
                assert!(f.path_resolved && !f.path_truncated);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_process_falls_back_to_the_resolver() {
        let mut d = dec();
        let e = d
            .decode(
                &file_rec(999, fop::CREATE, "/tmp/x", 0o100755, 0, 0, (0, 0)),
                &|pid| (pid == 999).then(|| b"/usr/bin/curl".to_vec()),
            )
            .unwrap();
        assert_eq!(e.actor.unwrap().exe, Some(OsBytes::from("/usr/bin/curl")));
        let Body::FileCreate(f) = e.body else {
            panic!()
        };
        assert_eq!(f.mode, Some(0o100755));
    }

    #[test]
    fn chmod_reports_a_newly_set_suid_bit_but_not_an_existing_one() {
        let mut d = dec();
        let new_suid = d
            .decode(
                &file_rec(1, fop::CHMOD, "/tmp/p", 0o4755, 0o100755, 0, (0, 0)),
                &|_| None,
            )
            .unwrap();
        let Body::FileAttr(a) = new_suid.body else {
            panic!()
        };
        assert!(a.suid_set && !a.sgid_set);
        assert_eq!((a.old_mode, a.new_mode), (Some(0o0755), Some(0o4755)));
        let already = d
            .decode(
                &file_rec(1, fop::CHMOD, "/tmp/p", 0o4711, 0o104755, 0, (0, 0)),
                &|_| None,
            )
            .unwrap();
        let Body::FileAttr(a) = already.body else {
            panic!()
        };
        assert!(!a.suid_set, "SUID was already set");
        let sgid = d
            .decode(
                &file_rec(1, fop::CHMOD, "/tmp/p", 0o2755, 0o100755, 0, (0, 0)),
                &|_| None,
            )
            .unwrap();
        let Body::FileAttr(a) = sgid.body else {
            panic!()
        };
        assert!(a.sgid_set && !a.suid_set);
    }

    #[test]
    fn chown_treats_minus_one_as_unchanged_and_denied_results_are_kept() {
        let mut d = dec();
        let e = d
            .decode(
                &file_rec(1, fop::CHOWN, "/etc/x", 0, 0o100644, 0, (0, u32::MAX)),
                &|_| None,
            )
            .unwrap();
        let Body::FileAttr(a) = e.body else { panic!() };
        assert_eq!((a.new_uid, a.new_gid), (Some(0), None));
        let denied = d
            .decode(
                &file_rec(1, fop::UNLINK, "/etc/shadow", 0, 0, -13, (0, 0)),
                &|_| None,
            )
            .unwrap();
        let Body::FileDelete(f) = denied.body else {
            panic!()
        };
        assert_eq!(f.result, HookResult::Denied);
    }

    #[test]
    fn rename_link_and_symlink() {
        let mut d = dec();
        let e = d
            .decode(&two_rec(fop::RENAME, "/tmp/a", "/etc/cron.d/a"), &|_| None)
            .unwrap();
        let Body::FileRename(r) = e.body else {
            panic!()
        };
        assert_eq!(
            (r.old, r.new),
            (OsBytes::from("/tmp/a"), OsBytes::from("/etc/cron.d/a"))
        );
        let e = d
            .decode(&two_rec(fop::LINK, "/etc/shadow", "/tmp/s"), &|_| None)
            .unwrap();
        let Body::FileLink(l) = e.body else { panic!() };
        assert_eq!(l.kind, LinkKind::Hard);
        assert_eq!(
            (l.path, l.target),
            (OsBytes::from("/tmp/s"), OsBytes::from("/etc/shadow"))
        );
        let e = d
            .decode(
                &two_rec(fop::SYMLINK, "../../etc/passwd", "/tmp/link"),
                &|_| None,
            )
            .unwrap();
        let Body::FileLink(l) = e.body else { panic!() };
        assert_eq!(l.kind, LinkKind::Symbolic);
        assert_eq!(l.target, OsBytes::from("../../etc/passwd"));
    }

    #[test]
    fn a_forked_child_inherits_its_parents_identity_until_it_execs() {
        let mut d = dec();
        d.decode(
            &{
                let mut body = vec![0u8; ExecBody::SIZE];
                body[8..12].copy_from_slice(&5u32.to_ne_bytes());
                body[16..20].copy_from_slice(b"bash");
                body[48..53].copy_from_slice(b"/bash");
                let mut r = hdr(kind::PROC_EXEC, RawHdr::SIZE + body.len(), 100)
                    .to_bytes()
                    .to_vec();
                r.extend(body);
                r
            },
            &|_| None,
        )
        .unwrap();
        let mut fb = vec![0u8; ForkBody::SIZE];
        fb[0..4].copy_from_slice(&200u32.to_ne_bytes());
        fb[4..8].copy_from_slice(&200u32.to_ne_bytes());
        fb[8..16].copy_from_slice(&70_000_000u64.to_ne_bytes());
        let mut fr = hdr(kind::PROC_FORK, RawHdr::SIZE + fb.len(), 100)
            .to_bytes()
            .to_vec();
        fr.extend(fb);
        d.decode(&fr, &|_| None).unwrap();
        // The child (pid 200, start 70_000_000) writes before exec'ing.
        let mut rec = file_rec(200, fop::OPEN_WRITE, "/tmp/f", 0, 0, 0, (0, 0));
        rec[64..72].copy_from_slice(&70_000_000u64.to_ne_bytes()); // header start_boot_ns
        let e = d.decode(&rec, &|_| None).unwrap();
        assert_eq!(e.actor.unwrap().comm, "bash");
    }

    #[test]
    fn exit_forgets_the_process() {
        let mut d = dec();
        d.decode(
            &{
                let mut body = vec![0u8; ExecBody::SIZE];
                body[16..19].copy_from_slice(b"foo");
                let mut r = hdr(kind::PROC_EXEC, RawHdr::SIZE + body.len(), 7)
                    .to_bytes()
                    .to_vec();
                r.extend(body);
                r
            },
            &|_| None,
        )
        .unwrap();
        let mut xb = vec![0u8; ExitBody::SIZE];
        xb[8..11].copy_from_slice(b"foo");
        let mut xr = hdr(kind::PROC_EXIT, RawHdr::SIZE + xb.len(), 7)
            .to_bytes()
            .to_vec();
        xr.extend(xb);
        d.decode(&xr, &|_| None).unwrap();
        assert!(d.procs.is_empty());
    }
}

#[cfg(test)]
mod net_tests {
    use super::*;
    use witness_common::AF_INET6;

    fn rec(
        op: u32,
        family: u32,
        l: ([u8; 16], u16),
        r: ([u8; 16], u16),
        sent: u64,
        recv: u64,
        dur: u64,
    ) -> Vec<u8> {
        let mut b = vec![0u8; NetBody::SIZE];
        b[0..4].copy_from_slice(&op.to_ne_bytes());
        b[4..8].copy_from_slice(&family.to_ne_bytes());
        b[8..10].copy_from_slice(&l.1.to_ne_bytes());
        b[10..12].copy_from_slice(&r.1.to_ne_bytes());
        b[16..32].copy_from_slice(&l.0);
        b[32..48].copy_from_slice(&r.0);
        b[48..56].copy_from_slice(&sent.to_ne_bytes());
        b[56..64].copy_from_slice(&recv.to_ne_bytes());
        b[64..72].copy_from_slice(&dur.to_ne_bytes());
        b[80..84].copy_from_slice(b"curl");
        let hdr = RawHdr {
            kind: kind::NET_TCP,
            flags: 0,
            len: (RawHdr::SIZE + b.len()) as u32,
            boot_ns: 9,
            pid: 77,
            tid: 77,
            ppid: 1,
            _pad0: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            auid: 1000,
            ses: 4,
            cgroup_id: 3,
            start_boot_ns: 20_000_000,
        };
        let mut out = hdr.to_bytes().to_vec();
        out.extend(b);
        out
    }

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut x = [0u8; 16];
        x[..4].copy_from_slice(&a);
        x
    }

    fn dec() -> Decoder {
        Decoder::new("4f2a9c1e-0000-0000-0000-000000000000")
    }

    #[test]
    fn outbound_connect_close_and_failure() {
        let mut d = dec();
        let c = d
            .decode(
                &rec(
                    nop::CONNECT,
                    AF_INET,
                    (v4([10, 0, 0, 5]), 51234),
                    (v4([93, 184, 216, 34]), 443),
                    0,
                    0,
                    0,
                ),
                &|_| None,
            )
            .unwrap();
        assert_eq!(c.prio, 1);
        assert_eq!(c.actor.as_ref().unwrap().comm, "curl");
        let Body::NetConnect(n) = c.body else {
            panic!()
        };
        assert_eq!(n.raddr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(
            (n.lport, n.rport, n.outcome),
            (51234, 443, ConnOutcome::Established)
        );

        let f = d
            .decode(
                &rec(
                    nop::CONNECT_FAILED,
                    AF_INET,
                    (v4([0; 4]), 0),
                    (v4([127, 0, 0, 1]), 9),
                    0,
                    0,
                    0,
                ),
                &|_| None,
            )
            .unwrap();
        let Body::NetConnect(n) = f.body else {
            panic!()
        };
        assert_eq!(n.outcome, ConnOutcome::Failed);

        let x = d
            .decode(
                &rec(
                    nop::CLOSE,
                    AF_INET,
                    (v4([10, 0, 0, 5]), 51234),
                    (v4([93, 184, 216, 34]), 443),
                    1200,
                    56000,
                    3_000_000_000,
                ),
                &|_| None,
            )
            .unwrap();
        assert_eq!(x.prio, 2);
        let Body::NetClose(c) = x.body else { panic!() };
        assert_eq!(
            (c.bytes_sent, c.bytes_recv, c.duration_ns),
            (Some(1200), Some(56000), 3_000_000_000)
        );
        assert_eq!(c.conn.rport, 443);
    }

    #[test]
    fn accept_and_ipv6_listen() {
        let mut d = dec();
        let a = d
            .decode(
                &rec(
                    nop::ACCEPT,
                    AF_INET,
                    (v4([10, 0, 0, 5]), 22),
                    (v4([192, 168, 1, 9]), 40022),
                    0,
                    0,
                    0,
                ),
                &|_| None,
            )
            .unwrap();
        let Body::NetAccept(n) = a.body else { panic!() };
        assert_eq!(
            (n.lport, n.raddr, n.outcome),
            (
                22,
                "192.168.1.9".parse::<IpAddr>().unwrap(),
                ConnOutcome::Accepted
            )
        );

        let lo = std::net::Ipv6Addr::LOCALHOST.octets();
        let l = d
            .decode(
                &rec(nop::LISTEN, AF_INET6, (lo, 8080), ([0; 16], 0), 0, 0, 0),
                &|_| None,
            )
            .unwrap();
        let Body::NetListen(n) = l.body else { panic!() };
        assert_eq!(
            (n.addr, n.port),
            (IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 8080)
        );
        let lc = d
            .decode(
                &rec(
                    nop::LISTEN_CLOSE,
                    AF_INET6,
                    (lo, 8080),
                    ([0; 16], 0),
                    0,
                    0,
                    0,
                ),
                &|_| None,
            )
            .unwrap();
        assert!(matches!(lc.body, Body::NetListenClose(_)));
    }
}
