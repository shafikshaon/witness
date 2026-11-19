//! Runs the rule engine inside the daemon: loads `rules.d`, evaluates stored events, and
//! reloads when the directory changes (DESIGN.md §8.3).
//!
//! Deviation from the design: evaluation is inline, right after an event is stored, rather
//! than on worker threads with a drop-oldest queue. The engine's cost is measured in
//! `witness-rules/tests/bench.rs`; if it ever has to shed load, that must be recorded.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use witness_common::schema::{Alert, Event, RuleSetChange};
use witness_rules::{load_dir, Engine, LoadResult};

/// Directory fingerprint: `(file name, size, mtime)` of every rule file.
type Signature = Vec<(String, u64, Option<SystemTime>)>;

pub struct RuleRunner {
    engine: Engine,
    dir: PathBuf,
    /// Where `first_seen` rules keep what they have learned.
    learned: PathBuf,
    sig: Signature,
    /// Rule files that failed to load at the last (re)load.
    pub rejected: Vec<String>,
}

fn signature(dir: &Path) -> Signature {
    let mut v: Signature = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x == "yml" || x == "yaml")
        })
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                m.len(),
                m.modified().ok(),
            ))
        })
        .collect();
    v.sort();
    v
}

fn change(old: &[(String, String)], new: &LoadResult) -> RuleSetChange {
    let old_map: std::collections::HashMap<&str, &str> =
        old.iter().map(|(i, h)| (i.as_str(), h.as_str())).collect();
    let mut added = Vec::new();
    let mut modified = Vec::new();
    for r in &new.set.rules {
        match old_map.get(r.id.as_str()) {
            None => added.push(r.id.clone()),
            Some(h) if *h != r.sha256 => modified.push(r.id.clone()),
            _ => {}
        }
    }
    let removed = old
        .iter()
        .filter(|(i, _)| !new.set.rules.iter().any(|r| &r.id == i))
        .map(|(i, _)| i.clone())
        .collect();
    RuleSetChange {
        set_sha256: new.set.sha256.clone(),
        added,
        removed,
        modified,
        rejected: new.errors.iter().map(ToString::to_string).collect(),
    }
}

impl RuleRunner {
    /// Loads the rules in `dir`. A missing directory is an empty rule set, not an error.
    pub fn start(dir: &Path, learned: &Path) -> (RuleRunner, RuleSetChange) {
        let loaded = load_dir(dir).unwrap_or_default();
        let ch = change(&[], &loaded);
        let rejected = ch.rejected.clone();
        let mut engine = Engine::new(loaded.set);
        match std::fs::read(learned) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(m) => engine.import_seen(&m),
                Err(e) => {
                    tracing::warn!(file = %learned.display(), error = %e, "ignoring unreadable learned.json")
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(file = %learned.display(), error = %e, "cannot read learned.json")
            }
        }
        (
            RuleRunner {
                engine,
                dir: dir.into(),
                learned: learned.into(),
                sig: signature(dir),
                rejected,
            },
            ch,
        )
    }

    /// Writes the learned sets if they changed (atomically; readable by root only).
    pub fn persist_if_dirty(&mut self) {
        if !self.engine.take_seen_dirty() {
            return;
        }
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(json) = serde_json::to_vec_pretty(&self.engine.export_seen()) else {
            return;
        };
        let tmp = self.learned.with_extension("json.tmp");
        let write = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&json)?;
                f.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, &self.learned));
        if let Err(e) = write {
            tracing::warn!(error = %e, "could not save learned.json; it will be retried");
            // Try again on the next tick rather than losing the change.
            self.engine.mark_seen_dirty();
        }
    }

    pub fn rule_count(&self) -> usize {
        self.engine.rules().rules.len()
    }

    pub fn stats(&self) -> witness_rules::Stats {
        self.engine.stats
    }

    pub fn process(&mut self, seq: u64, ev: &Event) -> Vec<Alert> {
        self.engine.process(seq, ev)
    }

    /// Reloads if the directory changed. Returns the change record to store, if any.
    pub fn reload_if_changed(&mut self) -> Option<RuleSetChange> {
        let sig = signature(&self.dir);
        if sig == self.sig {
            return None;
        }
        self.sig = sig;
        let loaded = load_dir(&self.dir).unwrap_or_default();
        let old: Vec<(String, String)> = self
            .engine
            .rules()
            .rules
            .iter()
            .map(|r| (r.id.clone(), r.sha256.clone()))
            .collect();
        let ch = change(&old, &loaded);
        self.rejected = ch.rejected.clone();
        self.engine.swap(loaded.set);
        let quiet = ch.added.is_empty()
            && ch.removed.is_empty()
            && ch.modified.is_empty()
            && ch.rejected.is_empty();
        (!quiet).then_some(ch)
    }
}

/// How often the directory is checked for edits.
pub const RELOAD_EVERY: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_event(serial: &str) -> Event {
        serde_json::from_value(serde_json::json!({
            "v": 1, "seq": 0, "boot_id": "b", "boot_ns": 1, "wall_ns": 1, "wall_uncertain": false,
            "src": "uevent", "prio": 0, "type": "usb_device",
            "data": {"action": "add", "devpath": "/d", "vendor_id": "0781", "product_id": "5581", "serial": serial}
        }))
        .unwrap()
    }

    #[test]
    fn learned_devices_survive_a_restart_through_the_file() {
        let t = tempfile::tempdir().unwrap();
        let rules = t.path().join("rules.d");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("u.yml"),
            "id: usb.unknown\ntitle: t\nseverity: medium\nevent: usb_device\ncorrelate:\n  type: first_seen\n  group_by: [data.serial]\n",
        )
        .unwrap();
        let learned = t.path().join("learned.json");

        let (mut r, _) = RuleRunner::start(&rules, &learned);
        assert_eq!(r.process(1, &usb_event("A")).len(), 1);
        assert!(r.process(2, &usb_event("A")).is_empty());
        r.persist_if_dirty();
        assert!(learned.exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&learned).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // New process, same file: A is known, B is new.
        let (mut r2, _) = RuleRunner::start(&rules, &learned);
        assert!(r2.process(3, &usb_event("A")).is_empty());
        assert_eq!(r2.process(4, &usb_event("B")).len(), 1);

        // A corrupt file is ignored, not fatal: everything is "new" again.
        std::fs::write(&learned, b"{not json").unwrap();
        let (mut r3, _) = RuleRunner::start(&rules, &learned);
        assert_eq!(r3.process(5, &usb_event("A")).len(), 1);
    }
}
