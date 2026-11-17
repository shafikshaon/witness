//! Which file activity is stored (DESIGN.md §2.2). The kernel programs report every
//! file write, create, delete, rename and attribute change on real filesystems; this keeps
//! the ones under critical or watched paths and *counts* the rest per directory, so volume
//! is bounded without silently ignoring anything.

use std::collections::BTreeMap;

use globset::{Glob, GlobSet, GlobSetBuilder};
use witness_common::schema::{
    Body, Event, FileActivitySummary, OsBytes, Priority, Source, SCHEMA_VERSION,
};

/// Paths whose every change matters (DESIGN.md §2.2), plus the Witness data directory.
pub const CRITICAL: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/boot",
    "/root/.ssh",
    "/home/*/.ssh",
    "/var/spool/cron",
    "/usr/lib/systemd",
    "/lib/systemd",
    "/run/systemd/system",
    "/lib/modules",
    "/usr/lib/modules",
    "/var/lib/dpkg/status",
    "/var/lib/rpm",
    "/var/lib/witness",
];

/// Where payloads are dropped and run from: creations here are recorded, plain writes are
/// lower priority.
pub const WATCHED: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Not stored; counted in the per-directory summary.
    Drop,
    Watched,
    Critical,
}

pub struct FilePolicy {
    critical: GlobSet,
    watched: GlobSet,
    exclude: GlobSet,
    /// Dropped activity per directory bucket: `(opens_for_write, creates, deletes)`.
    counts: BTreeMap<String, (u64, u64, u64)>,
}

fn build(patterns: impl IntoIterator<Item = String>) -> GlobSet {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let p = p.trim_end_matches('/');
        for g in [p.to_string(), format!("{p}/**")] {
            if let Ok(glob) = Glob::new(&g) {
                b.add(glob);
            }
        }
    }
    b.build().unwrap_or_else(|_| GlobSet::empty())
}

/// Directory bucket for the summary: the first two path components (`/var/log`).
fn bucket(path: &str) -> String {
    let mut parts = path.split('/').filter(|s| !s.is_empty());
    match (parts.next(), parts.next()) {
        (Some(a), Some(_)) => format!(
            "/{a}/{}",
            path.split('/')
                .filter(|s| !s.is_empty())
                .nth(1)
                .unwrap_or("")
        ),
        (Some(a), None) => format!("/{a}"),
        _ => "/".to_string(),
    }
}

impl FilePolicy {
    pub fn new(extra_critical: &[String], watch: &[String], exclude: &[String]) -> FilePolicy {
        let crit = CRITICAL
            .iter()
            .map(|s| s.to_string())
            .chain(extra_critical.iter().cloned());
        let watched = WATCHED
            .iter()
            .map(|s| s.to_string())
            .chain(watch.iter().cloned());
        FilePolicy {
            critical: build(crit),
            watched: build(watched),
            exclude: build(exclude.iter().cloned()),
            counts: BTreeMap::new(),
        }
    }

    pub fn classify(&self, path: &str) -> Class {
        if self.exclude.is_match(path) {
            return Class::Drop;
        }
        if self.critical.is_match(path) {
            Class::Critical
        } else if self.watched.is_match(path) {
            Class::Watched
        } else {
            Class::Drop
        }
    }

    /// Decides whether to keep a decoded file event. Kept events may have their priority
    /// adjusted; dropped ones are counted. Non-file events pass through untouched.
    pub fn apply(&mut self, mut ev: Event) -> Option<Event> {
        let (paths, kind): (Vec<&OsBytes>, Kind) = match &ev.body {
            Body::FileOpenWrite(f) => (vec![&f.path], Kind::Open),
            Body::FileCreate(f) => (vec![&f.path], Kind::Create),
            Body::FileDelete(f) => (vec![&f.path], Kind::Delete),
            Body::FileTruncate(f) => (vec![&f.path], Kind::Open),
            Body::FileAttr(f) => (vec![&f.path], Kind::Other),
            Body::FileRename(f) => (vec![&f.old, &f.new], Kind::Other),
            Body::FileLink(f) => (vec![&f.path], Kind::Other),
            _ => return Some(ev),
        };
        let classes: Vec<Class> = paths
            .iter()
            .map(|p| self.classify(&p.to_string_lossy()))
            .collect();
        let best = classes
            .iter()
            .copied()
            .max_by_key(|c| match c {
                Class::Drop => 0,
                Class::Watched => 1,
                Class::Critical => 2,
            })
            .unwrap_or(Class::Drop);
        match best {
            Class::Drop => {
                let b = bucket(&paths[0].to_string_lossy());
                let c = self.counts.entry(b).or_default();
                match kind {
                    Kind::Open => c.0 += 1,
                    Kind::Create => c.1 += 1,
                    Kind::Delete => c.2 += 1,
                    Kind::Other => {}
                }
                None
            }
            // Plain writes in watched (non-critical) places are the first thing shed.
            Class::Watched if kind == Kind::Open => {
                ev.prio = Priority::P2 as u8;
                Some(ev)
            }
            _ => Some(ev),
        }
    }

    /// Summaries of what was counted but not stored; resets the counters.
    pub fn take_summaries(
        &mut self,
        boot_id: &str,
        boot_ns: u64,
        wall_ns: u64,
        interval_ns: u64,
    ) -> Vec<Event> {
        std::mem::take(&mut self.counts)
            .into_iter()
            .filter(|(_, (o, c, d))| o + c + d > 0)
            .map(|(dir, (opens, creates, deletes))| {
                let body = Body::FileActivitySummary(FileActivitySummary {
                    dir: dir.as_str().into(),
                    opens_for_write: opens,
                    creates,
                    deletes,
                    interval_ns,
                });
                Event {
                    v: SCHEMA_VERSION,
                    seq: 0,
                    boot_id: boot_id.into(),
                    boot_ns,
                    wall_ns,
                    wall_uncertain: false,
                    src: Source::Ebpf,
                    prio: body.priority() as u8,
                    actor: None,
                    body,
                    h: None,
                }
            })
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Open,
    Create,
    Delete,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FilePolicy {
        FilePolicy::new(&[], &[], &["/etc/witness-noise/**".into()])
    }

    #[test]
    fn classification() {
        let p = policy();
        assert_eq!(p.classify("/etc/passwd"), Class::Critical);
        assert_eq!(p.classify("/etc"), Class::Critical);
        assert_eq!(p.classify("/usr/bin/ls"), Class::Critical);
        assert_eq!(
            p.classify("/home/alice/.ssh/authorized_keys"),
            Class::Critical
        );
        assert_eq!(p.classify("/home/alice/.bashrc"), Class::Drop);
        assert_eq!(p.classify("/var/lib/witness/segments/x"), Class::Critical);
        assert_eq!(p.classify("/tmp/x.sh"), Class::Watched);
        assert_eq!(p.classify("/dev/shm/payload"), Class::Watched);
        assert_eq!(p.classify("/var/log/syslog"), Class::Drop);
        // A prefix match respects directory boundaries.
        assert_eq!(p.classify("/etcetera/x"), Class::Drop);
        assert_eq!(p.classify("/tmpfoo/x"), Class::Drop);
        // Explicit excludes beat everything.
        assert_eq!(p.classify("/etc/witness-noise/a"), Class::Drop);
    }

    #[test]
    fn config_extras_extend_the_sets() {
        let p = FilePolicy::new(&["/srv/app/conf".into()], &["/srv/uploads".into()], &[]);
        assert_eq!(p.classify("/srv/app/conf/x.toml"), Class::Critical);
        assert_eq!(p.classify("/srv/uploads/f"), Class::Watched);
    }

    #[test]
    fn buckets() {
        assert_eq!(bucket("/var/log/syslog"), "/var/log");
        assert_eq!(bucket("/home/alice/x/y"), "/home/alice");
        assert_eq!(bucket("/x"), "/x");
        assert_eq!(bucket("/"), "/");
    }
}
