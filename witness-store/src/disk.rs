//! Disk-full policy (DESIGN.md §5.6): graded shedding by priority, or a hard stop with a
//! recorded gap, plus a preallocated reserve so the final records can always be written.
//! Existing segments are never truncated, rewritten or deleted to make room.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Event priority. `P0` is never shed: process exec/exit/creds, auth, alerts, integrity
/// and daemon records. Lower numbers are more valuable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    P0 = 0,
    /// Network and file mutations.
    P1 = 1,
    /// File reads, hash records.
    P2 = 2,
    /// File-activity summaries, UDP flows, low-value opens.
    P3 = 3,
}

impl Priority {
    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFull {
    /// Drop events by priority as space shrinks; P0 keeps being written.
    Shed,
    /// Stop writing everything, seal, record a gap, and resume when space returns.
    Stop,
}

#[derive(Debug, Clone)]
pub struct DiskPolicy {
    /// Used-space percentages that raise a warning, ascending.
    pub warn_pcts: Vec<u8>,
    /// Below this much free space the policy engages.
    pub min_free_bytes: u64,
    /// Preallocated bytes released only to write the final records.
    pub reserve_bytes: u64,
    pub on_full: OnFull,
    /// Re-check free space after this many bytes have been appended.
    pub probe_every_bytes: u64,
    /// Minimum spacing between `capture_drop` reports while shedding.
    pub drop_report_interval: Duration,
}

impl Default for DiskPolicy {
    fn default() -> Self {
        DiskPolicy {
            warn_pcts: vec![80, 90],
            min_free_bytes: 1 << 30,
            reserve_bytes: 256 << 20,
            on_full: OnFull::Shed,
            probe_every_bytes: 8 << 20,
            drop_report_interval: Duration::from_secs(60),
        }
    }
}

impl DiskPolicy {
    /// No thresholds, no reserve: the policy never engages. For tests and tooling.
    pub fn disabled() -> Self {
        DiskPolicy {
            warn_pcts: Vec::new(),
            min_free_bytes: 0,
            reserve_bytes: 0,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.warn_pcts.iter().any(|&p| p == 0 || p > 100) {
            return Err("warn_pcts must be within 1..=100");
        }
        if self.warn_pcts.windows(2).any(|w| w[0] >= w[1]) {
            return Err("warn_pcts must be strictly ascending");
        }
        if self.probe_every_bytes == 0 {
            return Err("probe_every_bytes must be non-zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub total: u64,
    /// Free bytes available to this process.
    pub avail: u64,
}

impl Space {
    pub fn used_pct(&self) -> u8 {
        if self.total == 0 {
            return 0;
        }
        let used = self.total.saturating_sub(self.avail);
        ((used as u128 * 100) / self.total as u128).min(100) as u8
    }
}

pub trait SpaceProbe: Send {
    fn probe(&mut self) -> io::Result<Space>;
}

/// Reads free space of the filesystem holding `path` via `statvfs`.
pub struct StatvfsProbe(pub PathBuf);

impl SpaceProbe for StatvfsProbe {
    fn probe(&mut self) -> io::Result<Space> {
        let s = rustix::fs::statvfs(&self.0)?;
        let unit = if s.f_frsize != 0 {
            s.f_frsize
        } else {
            s.f_bsize
        };
        Ok(Space {
            total: s.f_blocks.saturating_mul(unit),
            avail: s.f_bavail.saturating_mul(unit),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskState {
    Normal,
    /// Level 1 sheds P3; level 2 also P2; level 3 also P1.
    Shedding(u8),
    Stopped,
}

impl DiskState {
    pub fn label(&self) -> String {
        match self {
            DiskState::Normal => "normal".into(),
            DiskState::Shedding(l) => format!("shedding-{l}"),
            DiskState::Stopped => "stopped".into(),
        }
    }
}

/// Free-space threshold at which `level` engages.
fn engage_below(level: u8, min_free: u64) -> u64 {
    match level {
        1 => min_free,
        2 => min_free / 3 * 2,
        _ => min_free / 3,
    }
}

/// Shedding level for `avail`, with hysteresis so the level does not flap: leaving the
/// `current` level needs 10 % of `min_free` more headroom than entering it did.
pub fn level_for(avail: u64, min_free: u64, current: u8) -> u8 {
    let raw = (1..=3u8)
        .rev()
        .find(|&l| avail < engage_below(l, min_free))
        .unwrap_or(0);
    if raw < current && avail < engage_below(current, min_free) + min_free / 10 {
        current
    } else {
        raw
    }
}

pub fn sheds(level: u8, prio: Priority) -> bool {
    level > 0 && prio.index() as u8 >= 4 - level.min(3)
}

pub const RESERVE_FILE: &str = "reserve.bin";

/// Preallocates `bytes` at `path`. On Linux this reserves real blocks with `fallocate`;
/// elsewhere it writes zeros (compressing or copy-on-write filesystems may still defeat
/// any reserve; documented limitation).
pub fn create_reserve(path: &Path, bytes: u64) -> io::Result<()> {
    if bytes == 0 || path.exists() {
        return Ok(());
    }
    let tmp = path.with_extension("tmp");
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        rustix::fs::fallocate(&f, rustix::fs::FallocateFlags::empty(), 0, bytes)?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let chunk = vec![0u8; 1 << 20];
            let mut left = bytes;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                f.write_all(&chunk[..n])?;
                left -= n as u64;
            }
        }
        f.flush()?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Deletes the reserve, freeing its blocks. Returns whether anything was released.
pub fn release_reserve(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                File::open(dir)?.sync_all()?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 900;

    #[test]
    fn levels_grade_with_free_space() {
        assert_eq!(level_for(5000, MIN, 0), 0);
        assert_eq!(level_for(899, MIN, 0), 1);
        assert_eq!(level_for(599, MIN, 0), 2);
        assert_eq!(level_for(299, MIN, 0), 3);
        assert_eq!(level_for(0, MIN, 0), 3);
    }

    #[test]
    fn hysteresis_prevents_flapping() {
        // Entered level 1 at 899; stays there until 10 % of MIN above the threshold.
        assert_eq!(level_for(950, MIN, 1), 1);
        assert_eq!(level_for(989, MIN, 1), 1);
        assert_eq!(level_for(990, MIN, 1), 0);
        // Level 3 holds until 10 % above its threshold (300 + 90), then relaxes to the raw level.
        assert_eq!(level_for(350, MIN, 3), 3);
        assert_eq!(level_for(390, MIN, 3), 2);
        assert_eq!(level_for(700, MIN, 3), 1);
    }

    #[test]
    fn shedding_matrix() {
        use Priority::*;
        assert!(!sheds(0, P3));
        assert!(sheds(1, P3) && !sheds(1, P2));
        assert!(sheds(2, P2) && sheds(2, P3) && !sheds(2, P1));
        assert!(sheds(3, P1) && sheds(3, P2) && sheds(3, P3));
        for l in 0..=3 {
            assert!(!sheds(l, P0), "P0 must never be shed");
        }
    }

    #[test]
    fn used_pct_and_validation() {
        assert_eq!(
            Space {
                total: 1000,
                avail: 200
            }
            .used_pct(),
            80
        );
        assert_eq!(Space { total: 0, avail: 0 }.used_pct(), 0);
        assert!(DiskPolicy::default().validate().is_ok());
        let bad = DiskPolicy {
            warn_pcts: vec![90, 80],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn reserve_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(RESERVE_FILE);
        create_reserve(&p, 64 * 1024).unwrap();
        assert!(fs::metadata(&p).unwrap().len() >= 64 * 1024);
        create_reserve(&p, 64 * 1024).unwrap(); // idempotent
        assert!(release_reserve(&p).unwrap());
        assert!(!release_reserve(&p).unwrap());
    }
}
