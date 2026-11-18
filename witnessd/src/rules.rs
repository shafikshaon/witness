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
    pub fn start(dir: &Path) -> (RuleRunner, RuleSetChange) {
        let loaded = load_dir(dir).unwrap_or_default();
        let ch = change(&[], &loaded);
        let rejected = ch.rejected.clone();
        (
            RuleRunner {
                engine: Engine::new(loaded.set),
                dir: dir.into(),
                sig: signature(dir),
                rejected,
            },
            ch,
        )
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
