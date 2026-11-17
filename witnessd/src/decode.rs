//! Turns raw ring-buffer records from the kernel programs into schema [`Event`]s.

use witness_common::schema::{
    puid, Actor, Body, Event, OsBytes, Priority, ProcExec, ProcExit, ProcFork, Source,
    SCHEMA_VERSION,
};
use witness_common::{flags, kind, ExecBody, ExitBody, ForkBody, RawHdr};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("record shorter than its header or declared length")]
    Short,
    #[error("unknown event kind {0}")]
    UnknownKind(u16),
}

/// Context needed to turn kernel records into events.
pub struct Decoder {
    boot_id: String,
    /// `CLOCK_REALTIME - CLOCK_BOOTTIME`, refreshed by the caller (DESIGN.md §3.4).
    clock_offset_ns: i64,
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
        &self,
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
                Body::ProcFork(ProcFork {
                    child_pid: b.child_tgid,
                    child_puid: puid(&self.boot_id, b.child_tgid, b.child_start_boot_ns),
                    is_thread: b.flags & witness_common::FORK_THREAD != 0,
                })
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
        assert_eq!(a.puid, "4f2a9c1e-321-1000");
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
            (700, "4f2a9c1e-700-2000")
        );
        assert_eq!(e.prio, 1);
    }

    #[test]
    fn bad_records_are_errors_not_panics() {
        let d = dec();
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
