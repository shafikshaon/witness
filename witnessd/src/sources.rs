//! Userspace event sources for auth and system activity (DESIGN.md §2.4): the journal
//! (sshd/sudo/su), account and `authorized_keys` changes, and the dpkg log.
//!
//! Each source runs on its own thread and sends [`Pending`] bodies; the main loop calls
//! [`Sources::drain`] to stamp them with the boot id and clocks and hand them to the pipeline.
//! A source that cannot start (no `journalctl`, no readable log) is reported, not fatal.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;
use witness_common::schema::{Body, ClockChange, ClockKind, Event, Source, SCHEMA_VERSION};

use crate::accounts::{self, Accounts, Key};

/// Largest file any source will read (a hostile multi-GB `authorized_keys` must not stall us).
const MAX_READ: u64 = 4 << 20;

/// Where the file-based sources look. Overridable so tests can use a scratch tree.
#[derive(Clone, Debug)]
pub struct Roots {
    pub passwd: PathBuf,
    pub group: PathBuf,
    pub shadow: PathBuf,
    pub dpkg_log: PathBuf,
    /// dnf's transaction log (Fedora/RHEL family).
    pub dnf_log: PathBuf,
    pub poll: Duration,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            passwd: "/etc/passwd".into(),
            group: "/etc/group".into(),
            shadow: "/etc/shadow".into(),
            dpkg_log: "/var/log/dpkg.log".into(),
            dnf_log: "/var/log/dnf.rpm.log".into(),
            poll: Duration::from_secs(1),
        }
    }
}

/// A body waiting to be stamped, with the time the source observed it if it knows better than
/// "now" (the journal carries its own timestamps).
pub struct Pending {
    src: Source,
    body: Body,
    wall_ns: Option<u64>,
}

/// How long a login waits for its counterpart from the other source before it is emitted alone.
const MERGE_WINDOW: Duration = Duration::from_secs(3);

/// One ssh login is reported twice: by sshd (method, remote address, no session id) and by
/// logind (the session id, no remote address). Logins are held briefly and combined, in either
/// order, into one record that has both. A login with no counterpart is emitted unchanged.
#[derive(Default)]
struct Merger {
    held: Vec<(std::time::Instant, Pending)>,
}

impl Merger {
    fn push(&mut self, p: Pending, now: std::time::Instant) -> Vec<Pending> {
        let (user, service) = match &p.body {
            Body::Login(l) => (l.user.clone(), l.service.clone()),
            _ => return vec![p],
        };
        let other = if service == "sshd" { "logind" } else { "sshd" };
        let found = self.held.iter().position(|(t, h)| {
            now.duration_since(*t) < MERGE_WINDOW
                && matches!(&h.body, Body::Login(hl) if hl.user == user && hl.service == other)
        });
        let Some(i) = found else {
            if service == "sshd" || service == "logind" {
                self.held.push((now, p));
                return Vec::new();
            }
            return vec![p];
        };
        let (_, held) = self.held.remove(i);
        // The sshd record is the base (it knows how the user authenticated and from where);
        // the logind record supplies the session.
        let (mut base, session) = if service == "sshd" {
            (p, held)
        } else {
            (held, p)
        };
        if let (Body::Login(b), Body::Login(sess)) = (&mut base.body, &session.body) {
            b.session_id = sess.session_id;
            b.session = sess.session.clone();
        }
        vec![base]
    }

    /// Emits what has waited out the window.
    fn flush(&mut self, now: std::time::Instant) -> Vec<Pending> {
        let mut out = Vec::new();
        let mut keep = Vec::new();
        for (t, p) in self.held.drain(..) {
            if now.duration_since(t) >= MERGE_WINDOW {
                out.push(p);
            } else {
                keep.push((t, p));
            }
        }
        self.held = keep;
        out
    }
}

pub struct Sources {
    merger: std::sync::Mutex<Merger>,
    rx: Receiver<Pending>,
    stop: Arc<AtomicBool>,
    journal_pid: Arc<AtomicU32>,
    threads: Vec<JoinHandle<()>>,
    /// `(source, problem)` for sources that could not start.
    pub unavailable: Vec<(&'static str, String)>,
}

impl Sources {
    pub fn start(roots: Roots, journal: bool) -> Sources {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let journal_pid = Arc::new(AtomicU32::new(0));
        let mut threads = Vec::new();
        let mut unavailable = Vec::new();

        if journal {
            match Command::new("journalctl").arg("--version").output() {
                Ok(_) => {
                    let (tx, stop, pid) = (tx.clone(), stop.clone(), journal_pid.clone());
                    threads.push(std::thread::spawn(move || journal_loop(tx, stop, pid)));
                }
                Err(e) => unavailable.push(("journal", format!("journalctl: {e}"))),
            }
        }
        {
            let (tx, stop, r) = (tx.clone(), stop.clone(), roots.clone());
            threads.push(std::thread::spawn(move || account_loop(tx, stop, r)));
        }
        {
            for (path, parse) in [
                (
                    roots.dpkg_log.clone(),
                    crate::pkglog::parse_dpkg as fn(&str) -> Option<Body>,
                ),
                (roots.dnf_log.clone(), crate::pkglog::parse_dnf),
            ] {
                let (tx, stop, poll) = (tx.clone(), stop.clone(), roots.poll);
                threads.push(std::thread::spawn(move || {
                    tail_log_loop(tx, stop, path, poll, parse)
                }));
            }
        }
        {
            let (tx, stop) = (tx.clone(), stop.clone());
            threads.push(std::thread::spawn(move || clock_loop(tx, stop)));
        }
        #[cfg(target_os = "linux")]
        match uevent_socket() {
            Ok(sock) => {
                let stop = stop.clone();
                threads.push(std::thread::spawn(move || uevent_loop(tx, stop, sock)));
            }
            Err(e) => unavailable.push(("uevent", e.to_string())),
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = tx;
            unavailable.push(("uevent", "Linux only".into()));
        }
        Sources {
            merger: Default::default(),
            rx,
            stop,
            journal_pid,
            threads,
            unavailable,
        }
    }

    /// Stamps everything the sources have produced since the last call.
    pub fn drain(&self, boot_id: &str, boot_ns: u64, wall_ns: u64) -> Vec<Event> {
        let mut out = Vec::new();
        let now = std::time::Instant::now();
        let mut ready: Vec<Pending> = Vec::new();
        if let Ok(mut m) = self.merger.lock() {
            while let Ok(p) = self.rx.try_recv() {
                ready.extend(m.push(p, now));
            }
            ready.extend(m.flush(now));
        }
        for p in ready {
            let (b, w) = match p.wall_ns {
                // Keep the observed time, and place it on the boot clock by the same offset.
                Some(w) if w <= wall_ns => (boot_ns.saturating_sub(wall_ns - w), w),
                _ => (boot_ns, wall_ns),
            };
            out.push(Event {
                v: SCHEMA_VERSION,
                seq: 0,
                boot_id: boot_id.into(),
                boot_ns: b,
                wall_ns: w,
                wall_uncertain: false,
                src: p.src,
                prio: p.body.priority() as u8,
                actor: None,
                body: p.body,
                h: None,
            });
        }
        out
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let pid = self.journal_pid.load(Ordering::SeqCst);
        if pid != 0 {
            if let Ok(p) = i32::try_from(pid) {
                // A pid that has already exited just returns an error.
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(p),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn sleep_unless_stopped(stop: &AtomicBool, d: Duration) {
    let step = Duration::from_millis(50);
    let mut left = d;
    while !left.is_zero() && !stop.load(Ordering::SeqCst) {
        let s = left.min(step);
        std::thread::sleep(s);
        left -= s;
    }
}

// ---- journal --------------------------------------------------------------------------

/// One `journalctl -o json` line → a pending event, if it is an auth message we understand.
pub fn journal_line(line: &str) -> Option<Pending> {
    let v: Value = serde_json::from_str(line).ok()?;
    let ident = v.get("SYSLOG_IDENTIFIER")?.as_str()?;
    let body = crate::authlog::parse_fields(&v)
        .or_else(|| crate::authlog::parse(ident, &crate::authlog::journal_text(&v)?))?;
    let wall_ns = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|us| us.saturating_mul(1000));
    Some(Pending {
        src: Source::Journald,
        body,
        wall_ns,
    })
}

fn journal_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>, pid: Arc<AtomicU32>) {
    while !stop.load(Ordering::SeqCst) {
        let child = Command::new("journalctl")
            .args(["-f", "-n", "0", "-o", "json", "--no-pager"])
            .args(["_COMM=sshd", "_COMM=sudo", "_COMM=su", "_COMM=sshd-session"])
            .args(["_COMM=systemd-logind", "_COMM=systemd"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "cannot start journalctl; retrying");
                sleep_unless_stopped(&stop, Duration::from_secs(10));
                continue;
            }
        };
        pid.store(child.id(), Ordering::SeqCst);
        if let Some(out) = child.stdout.take() {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if let Some(p) = journal_line(&line) {
                    if tx.send(p).is_err() {
                        return;
                    }
                }
            }
        }
        let _ = child.wait();
        pid.store(0, Ordering::SeqCst);
        if !stop.load(Ordering::SeqCst) {
            tracing::warn!("journalctl exited; restarting");
            sleep_unless_stopped(&stop, Duration::from_secs(5));
        }
    }
}

// ---- files ----------------------------------------------------------------------------

/// Reads a regular file without following a final symlink, capped at [`MAX_READ`].
fn read_capped(path: &Path) -> Option<String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_READ {
        return None;
    }
    let mut s = String::new();
    f.take(MAX_READ).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Cheap change detector: re-read a file only when this differs.
fn signature(path: &Path) -> Option<(u64, u64, u64, u64)> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime_nsec() as u64 ^ (m.mtime() as u64) << 20,
    ))
}

fn snapshot_accounts(r: &Roots) -> Accounts {
    Accounts {
        users: read_capped(&r.passwd)
            .map(|t| accounts::parse_passwd(&t))
            .unwrap_or_default(),
        groups: read_capped(&r.group)
            .map(|t| accounts::parse_group(&t))
            .unwrap_or_default(),
        shadow: read_capped(&r.shadow)
            .map(|t| accounts::parse_shadow(&t))
            .unwrap_or_default(),
    }
}

fn key_paths(users: &BTreeMap<String, accounts::Entry>) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    for (name, e) in users {
        let Some(home) = e
            .home
            .as_deref()
            .filter(|h| h.starts_with('/') && *h != "/")
        else {
            continue;
        };
        for f in ["authorized_keys", "authorized_keys2"] {
            v.push((name.clone(), Path::new(home).join(".ssh").join(f)));
        }
    }
    v
}

fn account_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>, r: Roots) {
    let send = |body: Body| {
        tx.send(Pending {
            src: Source::Daemon,
            body,
            wall_ns: None,
        })
        .is_ok()
    };
    let mut prev = snapshot_accounts(&r);
    let mut sigs: HashMap<PathBuf, _> = HashMap::new();
    let mut keys: HashMap<PathBuf, Vec<Key>> = HashMap::new();
    // The starting state is the baseline: record it silently, report only what changes.
    for (_, p) in key_paths(&prev.users) {
        sigs.insert(p.clone(), signature(&p));
        if let Some(t) = read_capped(&p) {
            keys.insert(p, accounts::parse_authorized_keys(&t));
        }
    }
    let acct_files = [r.passwd.clone(), r.group.clone(), r.shadow.clone()];
    let mut acct_sigs: Vec<_> = acct_files.iter().map(|p| signature(p)).collect();
    while !stop.load(Ordering::SeqCst) {
        sleep_unless_stopped(&stop, r.poll);
        let now: Vec<_> = acct_files.iter().map(|p| signature(p)).collect();
        let users = if now != acct_sigs {
            acct_sigs = now;
            let cur = snapshot_accounts(&r);
            for b in accounts::diff(&prev, &cur) {
                if !send(b) {
                    return;
                }
            }
            prev = cur;
            &prev.users
        } else {
            &prev.users
        };
        for (user, p) in key_paths(users) {
            let sig = signature(&p);
            if sigs.get(&p) == Some(&sig) {
                continue;
            }
            sigs.insert(p.clone(), sig);
            let new = read_capped(&p)
                .map(|t| accounts::parse_authorized_keys(&t))
                .unwrap_or_default();
            let old = keys.remove(&p).unwrap_or_default();
            for b in accounts::diff_keys(&user, p.as_os_str().as_bytes(), &old, &new) {
                if !send(b) {
                    return;
                }
            }
            if !new.is_empty() {
                keys.insert(p, new);
            }
        }
    }
}

/// Follows a text log (new whole lines only, rotation-aware) and turns lines into bodies.
fn tail_log_loop(
    tx: Sender<Pending>,
    stop: Arc<AtomicBool>,
    path: PathBuf,
    poll: Duration,
    parse: fn(&str) -> Option<Body>,
) {
    let mut pos = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut ino = std::fs::metadata(&path).map(|m| m.ino()).unwrap_or(0);
    while !stop.load(Ordering::SeqCst) {
        sleep_unless_stopped(&stop, poll);
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(m) = f.metadata() else { continue };
        if m.ino() != ino || m.len() < pos {
            // Rotated or truncated: the new file is read from its start.
            ino = m.ino();
            pos = 0;
        }
        if m.len() == pos {
            continue;
        }
        let mut f = f;
        if f.seek(SeekFrom::Start(pos)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if f.take(MAX_READ).read_to_end(&mut buf).is_err() {
            continue;
        }
        // Only whole lines: a half-written one is picked up next time.
        let Some(end) = buf.iter().rposition(|&b| b == b'\n') else {
            continue;
        };
        pos += end as u64 + 1;
        for line in String::from_utf8_lossy(&buf[..end]).lines() {
            if let Some(body) = parse(line) {
                let p = Pending {
                    src: Source::Daemon,
                    body,
                    wall_ns: None,
                };
                if tx.send(p).is_err() {
                    return;
                }
            }
        }
    }
}

// ---- clock ----------------------------------------------------------------------------

/// `CLOCK_REALTIME - CLOCK_BOOTTIME` in nanoseconds. Steady time passing leaves it constant;
/// someone setting the clock moves it by exactly the step.
fn clock_offset_ns() -> i128 {
    use rustix::time::{clock_gettime, ClockId};
    let ns = |c| {
        let t = clock_gettime(c);
        t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128
    };
    #[cfg(target_os = "linux")]
    let boot = ClockId::Boottime;
    #[cfg(not(target_os = "linux"))]
    let boot = ClockId::Monotonic;
    ns(ClockId::Realtime) - ns(boot)
}

/// Steps smaller than this are scheduler noise or NTP slewing, not tampering.
const CLOCK_STEP_NS: i128 = 500_000_000;

fn clock_event(delta: i128, tx: &Sender<Pending>) -> bool {
    tx.send(Pending {
        src: Source::Daemon,
        body: Body::ClockChange(ClockChange {
            kind: ClockKind::Step,
            delta_ns: delta.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            syscall: None,
        }),
        wall_ns: None,
    })
    .is_ok()
}

/// A `timerfd` on `CLOCK_REALTIME` with `TFD_TIMER_CANCEL_ON_SET` is cancelled (`ECANCELED`)
/// every time the clock is *set* (settimeofday, clock_settime, ADJ_SETOFFSET), but not by NTP
/// slewing. Unlike polling, it also sees a step that is undone moments later (time
/// synchronisation on a VM can revert one within milliseconds), because each set wakes us.
#[cfg(target_os = "linux")]
fn clock_timerfd() -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::time::{timerfd_create, TimerfdClockId, TimerfdFlags};
    Ok(timerfd_create(
        TimerfdClockId::Realtime,
        TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
    )?)
}

#[cfg(target_os = "linux")]
fn arm_on_set(fd: &std::os::fd::OwnedFd) -> std::io::Result<()> {
    use rustix::time::{timerfd_settime, Itimerspec, TimerfdTimerFlags, Timespec};
    // Absolute and far in the future: it never expires, it only reports clock sets.
    let never = Timespec {
        tv_sec: i64::MAX / 4,
        tv_nsec: 0,
    };
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    timerfd_settime(
        fd,
        TimerfdTimerFlags::ABSTIME | TimerfdTimerFlags::CANCEL_ON_SET,
        &Itimerspec {
            it_interval: zero,
            it_value: never,
        },
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn clock_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>) {
    use rustix::event::{poll, PollFd, PollFlags};
    let fd = match clock_timerfd().and_then(|fd| arm_on_set(&fd).map(|()| fd)) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!(error = %e, "timerfd clock watch unavailable; polling instead");
            return clock_poll_loop(tx, stop);
        }
    };
    let mut last = clock_offset_ns();
    while !stop.load(Ordering::SeqCst) {
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(
            &mut fds,
            Some(&rustix::time::Timespec {
                tv_sec: 0,
                tv_nsec: 250_000_000,
            }),
        ) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => {}
            Err(_) => return clock_poll_loop(tx, stop),
        }
        let mut buf = [0u8; 8];
        // ECANCELED is the signal; anything else readable is not a clock set.
        if matches!(
            rustix::io::read(&fd, &mut buf),
            Err(rustix::io::Errno::CANCELED)
        ) {
            // Re-arm first so a second set (the revert) is not missed, then measure.
            if arm_on_set(&fd).is_err() {
                return clock_poll_loop(tx, stop);
            }
            let now = clock_offset_ns();
            if !clock_event(now - last, &tx) {
                return;
            }
            last = now;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn clock_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>) {
    clock_poll_loop(tx, stop)
}

/// Fallback: compare the realtime/boottime offset every 250 ms. Misses a step that is undone
/// within one interval.
fn clock_poll_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>) {
    let mut last = clock_offset_ns();
    while !stop.load(Ordering::SeqCst) {
        sleep_unless_stopped(&stop, Duration::from_millis(250));
        let now = clock_offset_ns();
        let delta = now - last;
        if delta.abs() >= CLOCK_STEP_NS && !clock_event(delta, &tx) {
            return;
        }
        last = now;
    }
}

// ---- uevent ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn uevent_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::net::netlink::{self, SocketAddrNetlink};
    use rustix::net::{AddressFamily, SocketType};
    let fd = rustix::net::socket(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        Some(netlink::KOBJECT_UEVENT),
    )?;
    // Group 1: events straight from the kernel.
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 1))?;
    // A timeout lets the loop notice a stop request.
    rustix::net::sockopt::set_socket_timeout(
        &fd,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_millis(250)),
    )?;
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn uevent_loop(tx: Sender<Pending>, stop: Arc<AtomicBool>, sock: std::os::fd::OwnedFd) {
    let mut buf = vec![0u8; 16 * 1024];
    while !stop.load(Ordering::SeqCst) {
        let n = match rustix::net::recv(&sock, &mut buf[..], rustix::net::RecvFlags::empty()) {
            Ok((n, _total)) => n,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "uevent socket failed; device events stop");
                return;
            }
        };
        let Some(ev) = crate::uevent::parse(&buf[..n]) else {
            continue;
        };
        if let Some(body) = crate::uevent::to_body(&ev, Path::new("/sys")) {
            let p = Pending {
                src: Source::Uevent,
                body,
                wall_ns: None,
            };
            if tx.send(p).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_json_becomes_an_event_with_its_own_time() {
        let line = r#"{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2","__REALTIME_TIMESTAMP":"1700000000123456"}"#;
        let p = journal_line(line).unwrap();
        assert!(matches!(p.body, Body::AuthFail(_)));
        assert_eq!(p.wall_ns, Some(1_700_000_000_123_456_000));
        // Non-UTF-8 messages arrive as byte arrays and must not be dropped.
        let bytes = r#"{"SYSLOG_IDENTIFIER":"su","MESSAGE":[40,116,111,32,114,111,111,116,41,32,97,32,111,110,32,112,116,115,47,48]}"#;
        assert!(matches!(journal_line(bytes).unwrap().body, Body::Su(_)));
        assert!(journal_line("not json").is_none());
        assert!(journal_line(r#"{"SYSLOG_IDENTIFIER":"cron","MESSAGE":"x"}"#).is_none());
    }

    #[test]
    fn drain_keeps_an_observed_time_on_the_boot_clock() {
        let (tx, rx) = mpsc::channel();
        tx.send(Pending {
            src: Source::Journald,
            body: crate::authlog::parse("su", "(to root) a on pts/0").unwrap(),
            wall_ns: Some(900),
        })
        .unwrap();
        let s = Sources {
            merger: Default::default(),
            rx,
            stop: Arc::new(AtomicBool::new(false)),
            journal_pid: Arc::new(AtomicU32::new(0)),
            threads: vec![],
            unavailable: vec![],
        };
        let ev = s.drain("b", 5_000, 1_000);
        assert_eq!((ev[0].wall_ns, ev[0].boot_ns), (900, 4_900));
    }

    #[test]
    fn file_sources_report_changes_but_not_the_starting_state() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let r = Roots {
            passwd: d.path().join("passwd"),
            group: d.path().join("group"),
            shadow: d.path().join("shadow"),
            dpkg_log: d.path().join("dpkg.log"),
            dnf_log: d.path().join("dnf.rpm.log"),
            poll: Duration::from_millis(30),
        };
        std::fs::write(
            &r.passwd,
            format!("alice:x:1000:1000::{}:/bin/bash\n", home.display()),
        )
        .unwrap();
        std::fs::write(&r.group, "").unwrap();
        std::fs::write(&r.shadow, "alice:$6$a:1::::::\n").unwrap();
        std::fs::write(
            &r.dpkg_log,
            "2026-01-01 00:00:00 install old:arm64 <none> 1\n",
        )
        .unwrap();
        std::fs::write(&r.dnf_log, "").unwrap();
        let s = Sources::start(r.clone(), false);
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            s.drain("b", 0, 0).is_empty(),
            "the starting state is not an event"
        );

        std::fs::write(home.join(".ssh/authorized_keys"), key).unwrap();
        std::fs::write(&r.shadow, "alice:$6$b:2::::::\n").unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&r.dpkg_log)
            .unwrap();
        f.write_all(b"2026-01-01 00:00:01 install nginx:arm64 <none> 2\n2026-01-01 00:00:02 inst")
            .unwrap();
        let mut d = std::fs::OpenOptions::new()
            .append(true)
            .open(&r.dnf_log)
            .unwrap();
        d.write_all(b"2026-01-01T00:00:03Z SUBDEBUG Installed: curl-8.0.1-1.fc39.x86_64\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(400));
        let ev = s.drain("b", 0, 0);
        let kinds: Vec<String> = ev
            .iter()
            .map(|e| {
                serde_json::to_value(e).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        s.stop();
        assert!(
            kinds.iter().any(|k| k == "authorized_key_change"),
            "{kinds:?}"
        );
        assert!(kinds.iter().any(|k| k == "account_change"), "{kinds:?}");
        // One from dpkg (its half-written second line must wait for its newline) and one dnf.
        assert_eq!(
            kinds.iter().filter(|k| *k == "package_change").count(),
            2,
            "{kinds:?}"
        );
    }

    fn login(service: &str, user: &str, session_id: u32, remote: Option<&str>) -> Pending {
        Pending {
            src: Source::Journald,
            body: Body::Login(witness_common::schema::Login {
                user: user.into(),
                service: service.into(),
                method: remote.map(|_| "publickey".to_string()),
                remote_addr: remote.and_then(|r| r.parse().ok()),
                remote_port: None,
                tty: None,
                session_id,
                session: None,
            }),
            wall_ns: None,
        }
    }

    #[test]
    fn one_ssh_login_becomes_one_record_in_either_order() {
        let t0 = std::time::Instant::now();
        for sshd_first in [true, false] {
            let mut m = Merger::default();
            let (a, b) = (
                login("sshd", "alice", 0, Some("10.0.0.5")),
                login("logind", "alice", 7, None),
            );
            let (first, second) = if sshd_first { (a, b) } else { (b, a) };
            assert!(m.push(first, t0).is_empty(), "held for its counterpart");
            let out = m.push(second, t0 + Duration::from_millis(40));
            assert_eq!(out.len(), 1);
            let Body::Login(l) = &out[0].body else {
                panic!()
            };
            assert_eq!(l.service, "sshd", "sshd is the base: it knows the address");
            assert_eq!((l.session_id, l.remote_addr), (7, "10.0.0.5".parse().ok()));
            assert!(
                m.flush(t0 + Duration::from_secs(10)).is_empty(),
                "nothing left held"
            );
        }
    }

    #[test]
    fn unmatched_logins_are_emitted_alone_after_the_window_and_others_pass_through() {
        let t0 = std::time::Instant::now();
        let mut m = Merger::default();
        // A console login has only logind's record; another user's records never combine.
        assert!(m.push(login("logind", "bob", 3, None), t0).is_empty());
        assert!(m
            .push(login("sshd", "carol", 0, Some("1.2.3.4")), t0)
            .is_empty());
        assert!(
            m.flush(t0 + Duration::from_secs(1)).is_empty(),
            "still inside the window"
        );
        let out = m.flush(t0 + Duration::from_secs(4));
        assert_eq!(out.len(), 2);
        // Non-login records are not held at all.
        let su = Pending {
            src: Source::Journald,
            body: crate::authlog::parse("su", "(to root) a on pts/0").unwrap(),
            wall_ns: None,
        };
        assert_eq!(m.push(su, t0).len(), 1);
        // A logind login does not merge with an sshd login of the same user outside the window.
        let mut m = Merger::default();
        assert!(m
            .push(login("sshd", "alice", 0, Some("9.9.9.9")), t0)
            .is_empty());
        assert!(m
            .push(
                login("logind", "alice", 5, None),
                t0 + Duration::from_secs(5)
            )
            .is_empty());
        assert_eq!(
            m.flush(t0 + Duration::from_secs(5)).len(),
            1,
            "the stale sshd record, alone"
        );
    }
}
