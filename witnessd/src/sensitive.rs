//! The set of files whose *reads* are reported (`files.sensitive_read`).
//!
//! The kernel matches opens by `(dev, inode)` in a BPF hash map, so ordinary opens cost one
//! lookup and no path walk. This resolves the configured paths to those keys and keeps them
//! current: tools like `passwd` replace `/etc/shadow` with a new file, which has a new inode.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use witness_common::InodeKey;

/// Converts a `st_dev` (glibc encoding) to the kernel's internal `dev_t` (`major << 20 | minor`),
/// which is what the kernel programs read from `super_block.s_dev`.
pub fn kernel_dev(st_dev: u64) -> u32 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfff);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xff);
    ((major << 20) | (minor & 0xfffff)) as u32
}

/// The key for `path` (symlinks followed: the file that gets opened is what matters).
pub fn key_for(path: &Path) -> Option<InodeKey> {
    let m = std::fs::metadata(path).ok()?;
    m.is_file().then(|| InodeKey {
        dev: kernel_dev(m.dev()),
        _pad: 0,
        ino: m.ino(),
    })
}

/// What to change in the kernel map after a refresh.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delta {
    pub add: Vec<InodeKey>,
    pub remove: Vec<InodeKey>,
}

pub struct Sensitive {
    paths: Vec<String>,
    current: HashSet<InodeKey>,
    dirty_since: Option<Instant>,
    last_refresh: Option<Instant>,
}

/// Re-resolve at least this often even if nothing was noticed.
const PERIODIC: Duration = Duration::from_secs(30);
/// After a change to a sensitive path, wait this long so a rename's new file is in place.
const SETTLE: Duration = Duration::from_millis(500);

impl Sensitive {
    pub fn new(paths: &[String]) -> Sensitive {
        Sensitive {
            paths: paths.to_vec(),
            current: HashSet::new(),
            dirty_since: None,
            last_refresh: None,
        }
    }

    /// A file event touched `path`; if it is on the list the keys may have changed.
    pub fn note_change(&mut self, path: &str, now: Instant) {
        if self.paths.iter().any(|p| p == path) {
            self.dirty_since.get_or_insert(now);
        }
    }

    /// Whether `refresh` is due.
    pub fn due(&self, now: Instant) -> bool {
        if self.paths.is_empty() {
            return false;
        }
        match (self.last_refresh, self.dirty_since) {
            (None, _) => true,
            (_, Some(d)) if now.duration_since(d) >= SETTLE => true,
            (Some(l), _) => now.duration_since(l) >= PERIODIC,
        }
    }

    /// Re-resolves the paths and reports what changed against the previous resolution.
    pub fn refresh(&mut self, now: Instant) -> Delta {
        let fresh: HashSet<InodeKey> = self
            .paths
            .iter()
            .filter_map(|p| key_for(Path::new(p)))
            .collect();
        let delta = Delta {
            add: fresh.difference(&self.current).copied().collect(),
            remove: self.current.difference(&fresh).copied().collect(),
        };
        self.current = fresh;
        self.last_refresh = Some(now);
        self.dirty_since = None;
        delta
    }

    pub fn len(&self) -> usize {
        self.current.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers_convert_to_the_kernel_encoding() {
        // st_dev for (major 8, minor 1) is 0x801; the kernel's is 8 << 20 | 1.
        assert_eq!(kernel_dev(0x801), (8 << 20) | 1);
        // (major 259, minor 3): glibc packs major bits 8..19, minor low byte + bits 20..
        let st = (259u64 << 8) | 3;
        assert_eq!(kernel_dev(st), (259 << 20) | 3);
        // A minor above 255 spills into the high bits of the glibc encoding.
        let st = ((0x12345u64 & !0xff) << 12) | (0x12345 & 0xff) | (8u64 << 8);
        assert_eq!(kernel_dev(st), (8 << 20) | 0x12345);
        assert_eq!(kernel_dev(0), 0);
    }

    #[test]
    fn keys_follow_the_file_and_change_when_it_is_replaced() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("shadow");
        std::fs::write(&p, b"root:x").unwrap();
        let mut s = Sensitive::new(&[p.to_str().unwrap().into(), "/no/such/file".into()]);
        let t0 = Instant::now();
        assert!(s.due(t0), "the first resolution is always due");
        let first = s.refresh(t0);
        assert_eq!(first.add.len(), 1, "the missing file is simply absent");
        assert!(first.remove.is_empty());
        assert!(!s.due(t0 + Duration::from_secs(1)));
        assert_eq!(
            s.refresh(t0 + Duration::from_secs(1)),
            Delta::default(),
            "no change, no delta"
        );

        // `passwd`-style replacement: write a new file and rename it over the old one.
        let new = d.path().join("shadow.new");
        std::fs::write(&new, b"root:y").unwrap();
        std::fs::rename(&new, &p).unwrap();
        s.note_change(p.to_str().unwrap(), t0 + Duration::from_secs(2));
        assert!(
            !s.due(t0 + Duration::from_secs(2)),
            "wait for the rename to settle"
        );
        assert!(s.due(t0 + Duration::from_secs(3)));
        let d2 = s.refresh(t0 + Duration::from_secs(3));
        assert_eq!(
            (d2.add.len(), d2.remove.len()),
            (1, 1),
            "new inode in, old inode out"
        );
        assert_ne!(d2.add[0].ino, d2.remove[0].ino);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn unrelated_paths_do_not_trigger_a_refresh_and_the_list_refreshes_periodically() {
        let mut s = Sensitive::new(&["/etc/shadow".into()]);
        let t0 = Instant::now();
        s.refresh(t0);
        s.note_change("/etc/hostname", t0);
        assert!(!s.due(t0 + Duration::from_secs(5)));
        assert!(
            s.due(t0 + Duration::from_secs(31)),
            "periodic re-resolution as a backstop"
        );
        assert!(
            !Sensitive::new(&[]).due(t0),
            "an empty list never refreshes"
        );
    }

    #[test]
    fn directories_are_not_sensitive_files() {
        let d = tempfile::tempdir().unwrap();
        assert!(key_for(d.path()).is_none());
    }
}
