//! SHA-256 of critical files after they change (DESIGN.md §2.2).
//!
//! The kernel reports that a file was written; this decides *when* to hash it (after it has
//! been quiet for a while, so a burst of writes costs one hash), does the reading on a
//! separate thread under a byte-rate limit and a size cap, and emits a `file_hash` event
//! only when the content differs from the last hash we took. The event carries the previous
//! hash and the actor of the change that triggered it.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use witness_common::schema::{Actor, Body, Event, FileHash, OsBytes, Source, SCHEMA_VERSION};

/// Remembered hashes and pending paths are bounded so a hostile file churn cannot grow us.
const MAX_TRACKED: usize = 100_000;
const CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Settings {
    pub max_bytes: u64,
    /// Bytes per second the hasher may read; `0` means unlimited.
    pub rate_bps: u64,
    pub debounce: Duration,
    /// Jobs queued to the worker before new ones wait.
    pub queue: usize,
}

/// Paces reads to a byte rate. Time is injected so the pacing is testable.
pub struct Throttle {
    rate_bps: u64,
    next_free: Option<Instant>,
}

impl Throttle {
    pub fn new(rate_bps: u64) -> Throttle {
        Throttle {
            rate_bps,
            next_free: None,
        }
    }

    /// How long to wait before reading `bytes` more, as of `now`.
    pub fn delay(&mut self, now: Instant, bytes: u64) -> Duration {
        if self.rate_bps == 0 {
            return Duration::ZERO;
        }
        let start = self.next_free.map_or(now, |t| t.max(now));
        let cost = Duration::from_secs_f64(bytes as f64 / self.rate_bps as f64);
        self.next_free = Some(start + cost);
        start.saturating_duration_since(now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Hashed {
        sha256: [u8; 32],
        size: u64,
        dev: u64,
        ino: u64,
        mtime_ns: i64,
    },
    Skipped(String),
}

/// Hashes `path` if it is a regular file no larger than `max_bytes`. `pace` is called with
/// each chunk size before it is read and may sleep.
pub fn hash_file(path: &Path, max_bytes: u64, pace: &mut dyn FnMut(u64)) -> Outcome {
    // O_NOFOLLOW: never hash whatever a symlink points at; it is the link that was written.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return Outcome::Skipped(format!("cannot open: {e}")),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Outcome::Skipped(format!("cannot stat: {e}")),
    };
    if !meta.is_file() {
        return Outcome::Skipped("not a regular file".into());
    }
    if meta.len() > max_bytes {
        return Outcome::Skipped(format!("larger than the {max_bytes}-byte limit"));
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut f = file;
    loop {
        pace(CHUNK as u64);
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Outcome::Skipped(format!("read failed: {e}")),
        };
        total += n as u64;
        // The file may have grown since the stat; stop rather than read without bound.
        if total > max_bytes {
            return Outcome::Skipped(format!("grew beyond the {max_bytes}-byte limit"));
        }
        hasher.update(&buf[..n]);
    }
    Outcome::Hashed {
        sha256: hasher.finalize().into(),
        size: total,
        dev: meta.dev(),
        ino: meta.ino(),
        mtime_ns: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
    }
}

struct Job {
    path: Vec<u8>,
}

struct Done {
    path: Vec<u8>,
    outcome: Outcome,
}

struct Pending {
    due: Instant,
    actor: Option<Actor>,
}

pub struct Hasher {
    set: Settings,
    pending: HashMap<Vec<u8>, Pending>,
    /// Actor of the change behind each in-flight job.
    inflight: HashMap<Vec<u8>, Option<Actor>>,
    prev: HashMap<Vec<u8>, [u8; 32]>,
    tx: Option<SyncSender<Job>>,
    rx: Receiver<Done>,
    worker: Option<JoinHandle<()>>,
    /// Notes dropped because too many paths were already tracked.
    pub overflowed: u64,
}

impl Hasher {
    pub fn start(set: Settings) -> Hasher {
        let (tx, jobs) = mpsc::sync_channel::<Job>(set.queue.max(1));
        let (done_tx, rx) = mpsc::channel::<Done>();
        let (max, rate) = (set.max_bytes, set.rate_bps);
        let worker = std::thread::spawn(move || {
            let mut throttle = Throttle::new(rate);
            while let Ok(job) = jobs.recv() {
                let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&job.path));
                let outcome = hash_file(&path, max, &mut |bytes| {
                    let d = throttle.delay(Instant::now(), bytes);
                    if !d.is_zero() {
                        std::thread::sleep(d);
                    }
                });
                if done_tx
                    .send(Done {
                        path: job.path,
                        outcome,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Hasher {
            set,
            pending: HashMap::new(),
            inflight: HashMap::new(),
            prev: HashMap::new(),
            tx: Some(tx),
            rx,
            worker: Some(worker),
            overflowed: 0,
        }
    }

    /// A change to `path` was seen; (re)start its quiet period.
    pub fn note(&mut self, path: &OsBytes, actor: Option<Actor>, now: Instant) {
        if self.pending.len() >= MAX_TRACKED && !self.pending.contains_key(&path.0) {
            self.overflowed += 1;
            return;
        }
        self.pending.insert(
            path.0.clone(),
            Pending {
                due: now + self.set.debounce,
                actor,
            },
        );
    }

    /// Queues the paths whose quiet period has ended. Paths the full queue refuses stay
    /// pending and are retried on the next call.
    pub fn tick(&mut self, now: Instant) {
        let Some(tx) = &self.tx else { return };
        let due: Vec<Vec<u8>> = self
            .pending
            .iter()
            .filter(|(p, v)| v.due <= now && !self.inflight.contains_key(*p))
            .map(|(p, _)| p.clone())
            .collect();
        for path in due {
            match tx.try_send(Job { path: path.clone() }) {
                Ok(()) => {
                    if let Some(p) = self.pending.remove(&path) {
                        self.inflight.insert(path, p.actor);
                    }
                }
                Err(TrySendError::Full(_)) => break,
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }

    /// Turns finished hashes into events. A file whose content matches its last recorded hash
    /// produces nothing; a first sighting, a change, or a skip does. `envelope` supplies the
    /// event framing (boot id and clocks).
    pub fn drain(&mut self, boot_id: &str, boot_ns: u64, wall_ns: u64) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(done) = self.rx.try_recv() {
            let actor = self.inflight.remove(&done.path).flatten();
            let path = OsBytes(done.path.clone());
            let body = match done.outcome {
                Outcome::Hashed {
                    sha256,
                    size,
                    dev,
                    ino,
                    mtime_ns,
                } => {
                    let prev = self.prev.get(&done.path).copied();
                    if prev == Some(sha256) {
                        continue; // written, but the content is the same
                    }
                    if self.prev.len() >= MAX_TRACKED {
                        self.prev.clear();
                    }
                    self.prev.insert(done.path.clone(), sha256);
                    FileHash {
                        path,
                        dev,
                        ino,
                        size,
                        mtime_ns,
                        sha256: Some(witness_store::chain::to_hex(&sha256)),
                        prev_sha256: prev.map(|p| witness_store::chain::to_hex(&p)),
                        skipped: None,
                    }
                }
                Outcome::Skipped(why) => {
                    // A vanished file is itself informative: forget its hash.
                    self.prev.remove(&done.path);
                    FileHash {
                        path,
                        dev: 0,
                        ino: 0,
                        size: 0,
                        mtime_ns: 0,
                        sha256: None,
                        prev_sha256: None,
                        skipped: Some(why),
                    }
                }
            };
            let body = Body::FileHash(body);
            out.push(Event {
                v: SCHEMA_VERSION,
                seq: 0,
                boot_id: boot_id.into(),
                boot_ns,
                wall_ns,
                wall_uncertain: false,
                src: Source::Daemon,
                prio: body.priority() as u8,
                actor,
                body,
                h: None,
            });
        }
        out
    }

    /// Paths waiting or being hashed.
    pub fn backlog(&self) -> usize {
        self.pending.len() + self.inflight.len()
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        self.tx = None; // closes the job channel: the worker's `recv` ends
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn no_pace() -> impl FnMut(u64) {
        |_| {}
    }

    #[test]
    fn hashes_match_known_vectors() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        let Outcome::Hashed { sha256, size, .. } = hash_file(&p, 1 << 20, &mut no_pace()) else {
            panic!()
        };
        assert_eq!(
            witness_store::chain::to_hex(&sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(size, 3);
        // The empty file has a defined hash too.
        std::fs::write(&p, b"").unwrap();
        let Outcome::Hashed { sha256, .. } = hash_file(&p, 1 << 20, &mut no_pace()) else {
            panic!()
        };
        assert_eq!(
            witness_store::chain::to_hex(&sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn files_spanning_many_chunks_hash_correctly() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("big");
        let data: Vec<u8> = (0..(CHUNK * 3 + 17)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let Outcome::Hashed { sha256, size, .. } = hash_file(&p, 10 << 20, &mut no_pace()) else {
            panic!()
        };
        assert_eq!(size as usize, data.len());
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&data)), sha256);
    }

    #[test]
    fn oversized_special_and_missing_files_are_skipped_not_hashed() {
        let d = tempfile::tempdir().unwrap();
        let big = d.path().join("big");
        std::fs::write(&big, vec![0u8; 5000]).unwrap();
        assert!(
            matches!(hash_file(&big, 1000, &mut no_pace()), Outcome::Skipped(w) if w.contains("larger"))
        );
        assert!(
            matches!(hash_file(d.path(), 1000, &mut no_pace()), Outcome::Skipped(w) if w.contains("regular"))
        );
        assert!(
            matches!(hash_file(&d.path().join("gone"), 1000, &mut no_pace()), Outcome::Skipped(w) if w.contains("cannot open"))
        );
        // A symlink is never followed.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&big, &link).unwrap();
        assert!(matches!(
            hash_file(&link, 1 << 20, &mut no_pace()),
            Outcome::Skipped(_)
        ));
        // Nor does a FIFO block us.
        let fifo = d.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(matches!(
            hash_file(&fifo, 1 << 20, &mut no_pace()),
            Outcome::Skipped(_)
        ));
    }

    #[test]
    fn the_throttle_spaces_reads_to_the_rate() {
        let mut t = Throttle::new(1000); // 1000 B/s
        let t0 = Instant::now();
        assert_eq!(t.delay(t0, 500), Duration::ZERO, "the first read is free");
        // Next 500 B may start only once the first 500 B's worth of time has passed.
        assert_eq!(t.delay(t0, 500), Duration::from_millis(500));
        assert_eq!(t.delay(t0, 500), Duration::from_millis(1000));
        // If we arrive late the debt is already paid.
        assert_eq!(t.delay(t0 + Duration::from_secs(10), 500), Duration::ZERO);
        assert_eq!(
            Throttle::new(0).delay(t0, 1 << 30),
            Duration::ZERO,
            "0 = unlimited"
        );
    }

    fn wait_for(h: &mut Hasher, n: usize) -> Vec<Event> {
        let mut got = Vec::new();
        let end = Instant::now() + Duration::from_secs(5);
        while got.len() < n && Instant::now() < end {
            got.extend(h.drain("boot", 1, 2));
            std::thread::sleep(Duration::from_millis(10));
        }
        got
    }

    fn settings() -> Settings {
        Settings {
            max_bytes: 1 << 20,
            rate_bps: 0,
            debounce: Duration::from_millis(100),
            queue: 8,
        }
    }

    fn fh(e: &Event) -> &FileHash {
        match &e.body {
            Body::FileHash(f) => f,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn debounce_then_one_hash_per_burst_and_changes_chain_through_prev() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("conf");
        let path = OsBytes(p.as_os_str().as_bytes().to_vec());
        let mut h = Hasher::start(settings());
        let actor = None;

        std::fs::write(&p, b"v1").unwrap();
        let t0 = Instant::now();
        // A burst of notes within the quiet period...
        for i in 0..5 {
            h.note(&path, actor.clone(), t0 + Duration::from_millis(i * 10));
        }
        h.tick(t0 + Duration::from_millis(60));
        assert_eq!(h.backlog(), 1, "still quiet-waiting: nothing queued yet");
        h.tick(t0 + Duration::from_millis(500));
        let first = wait_for(&mut h, 1);
        assert_eq!(first.len(), 1, "...costs a single hash");
        assert!(fh(&first[0]).prev_sha256.is_none());
        let h1 = fh(&first[0]).sha256.clone().unwrap();

        // Rewritten with the same bytes: touched, not changed: no event.
        std::fs::write(&p, b"v1").unwrap();
        h.note(&path, None, t0 + Duration::from_secs(1));
        h.tick(t0 + Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(150));
        assert!(h.drain("b", 1, 2).is_empty());
        assert_eq!(h.backlog(), 0);

        // Genuinely changed: an event naming the old hash.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"+more").unwrap();
        drop(f);
        h.note(&path, None, t0 + Duration::from_secs(3));
        h.tick(t0 + Duration::from_secs(4));
        let second = wait_for(&mut h, 1);
        assert_eq!(second.len(), 1);
        assert_eq!(fh(&second[0]).prev_sha256.as_deref(), Some(h1.as_str()));
        assert_ne!(fh(&second[0]).sha256.as_deref(), Some(h1.as_str()));
        assert_eq!(fh(&second[0]).size, 7);
    }

    #[test]
    fn the_hash_event_carries_the_changing_actor_and_skips_are_reported() {
        let d = tempfile::tempdir().unwrap();
        let path = OsBytes::from(d.path().join("missing").to_str().unwrap());
        let actor = Actor {
            puid: "p-1-2".into(),
            pid: 1,
            tid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            user: None,
            auid: Some(1000),
            ses: None,
            cgroup_id: 0,
            comm: "vim".into(),
            exe: None,
            cmdline: None,
            tty: None,
        };
        let mut h = Hasher::start(settings());
        let t0 = Instant::now();
        h.note(&path, Some(actor), t0);
        h.tick(t0 + Duration::from_secs(1));
        let ev = wait_for(&mut h, 1);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].actor.as_ref().unwrap().comm, "vim");
        assert_eq!(ev[0].actor.as_ref().unwrap().auid, Some(1000));
        assert!(fh(&ev[0])
            .skipped
            .as_deref()
            .unwrap()
            .contains("cannot open"));
        assert!(fh(&ev[0]).sha256.is_none());
    }

    #[test]
    fn tracking_is_bounded() {
        let mut h = Hasher::start(settings());
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED + 10) {
            h.note(
                &OsBytes::from(format!("/nope/{i}").as_str()),
                None,
                t0 + Duration::from_secs(3600),
            );
        }
        assert_eq!(h.backlog(), MAX_TRACKED);
        assert_eq!(h.overflowed, 10);
        // An already-tracked path can still be refreshed at the limit.
        h.note(&OsBytes::from("/nope/0"), None, t0);
        assert_eq!(h.overflowed, 10);
    }
}
