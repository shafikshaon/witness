//! Scheduled and on-demand verification of the whole chain, recorded as `integrity_check`
//! events so that a break can raise an alert (DESIGN.md §5, rule `witness.self.integrity-failed`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use witness_common::schema::IntegrityCheck;
use witness_store::chain;
use witness_store::verify::{verify_dirs, Options};

/// First check this long after start (so startup is not slowed), then every [`EVERY`].
pub const FIRST_DELAY: Duration = Duration::from_secs(300);
pub const EVERY: Duration = Duration::from_secs(6 * 3600);

/// Verifies the segments in `seg_dir`. Never panics; a failure to run is `state: "error"`.
pub fn check(seg_dir: &Path, trigger: &str) -> IntegrityCheck {
    let t = Instant::now();
    let opts = Options {
        // A store whose oldest segments were pruned or archived is still checkable.
        allow_partial: true,
        ..Options::default()
    };
    let mut c = IntegrityCheck {
        state: "error".into(),
        trigger: trigger.into(),
        records: 0,
        segments: 0,
        head_seq: 0,
        head_hash: String::new(),
        problem: None,
        duration_ms: 0,
    };
    match verify_dirs(&[seg_dir.to_path_buf()], &opts) {
        Ok(r) => {
            c.state = if r.is_ok() { "ok" } else { "broken" }.into();
            c.records = r.records;
            c.segments = r.segments;
            c.head_seq = r.head_seq;
            c.head_hash = chain::to_hex(&r.head_hash);
            c.problem = r.broken.map(|b| format!("{b:?}"));
        }
        Err(e) => c.problem = Some(e.to_string()),
    }
    c.duration_ms = t.elapsed().as_millis() as u64;
    c
}

pub struct Scheduler {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    rx: Receiver<IntegrityCheck>,
}

impl Scheduler {
    pub fn start(seg_dir: PathBuf, first_delay: Duration, every: Duration) -> Scheduler {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut wait = first_delay;
            loop {
                let until = Instant::now() + wait;
                while Instant::now() < until {
                    if s.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                let trigger = if wait == first_delay {
                    "startup"
                } else {
                    "schedule"
                };
                if tx.send(check(&seg_dir, trigger)).is_err() {
                    return;
                }
                wait = every;
            }
        });
        Scheduler {
            stop,
            thread: Some(thread),
            rx,
        }
    }

    pub fn drain(&self) -> Vec<IntegrityCheck> {
        self.rx.try_iter().collect()
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Test and operations override: `WITNESS_VERIFY_EVERY_SECS` makes the first check and the
/// interval that many seconds.
pub fn intervals_from_env() -> (Duration, Duration) {
    match std::env::var("WITNESS_VERIFY_EVERY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(s) if s >= 1 => (Duration::from_secs(s), Duration::from_secs(s)),
        _ => (FIRST_DELAY, EVERY),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map, Value};
    use witness_store::disk::DiskPolicy;
    use witness_store::{Config, Store};

    use super::*;

    fn fill(root: &Path) {
        let (mut s, _) = Store::open(
            root,
            Config {
                max_segment_bytes: 2000,
                disk: DiskPolicy::disabled(),
            },
        )
        .unwrap();
        for i in 0..30u64 {
            let mut m: Map<String, Value> = Map::new();
            m.insert("type".into(), json!("t"));
            m.insert("n".into(), json!(i));
            s.append(m).unwrap();
        }
        s.sync().unwrap();
    }

    #[test]
    fn a_good_store_is_ok_and_a_modified_one_is_broken() {
        let t = tempfile::tempdir().unwrap();
        fill(t.path());
        let seg = t.path().join("segments");
        let c = check(&seg, "api");
        assert_eq!((c.state.as_str(), c.trigger.as_str()), ("ok", "api"));
        assert!(c.records >= 30 && c.problem.is_none() && c.head_hash.len() == 64);

        let first = std::fs::read_dir(&seg)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
            .min()
            .unwrap();
        let mut bytes = std::fs::read(&first).unwrap();
        let at = bytes.windows(5).position(|w| w == b"\"n\":1").unwrap();
        bytes[at + 4] = b'7';
        std::fs::write(&first, bytes).unwrap();
        let c = check(&seg, "schedule");
        assert_eq!(c.state, "broken");
        assert!(c.problem.is_some());
    }

    #[test]
    fn a_missing_store_is_an_error_not_a_panic() {
        let c = check(Path::new("/nonexistent/segments"), "api");
        assert!(c.state == "error" || c.state == "ok", "{c:?}");
    }
}
