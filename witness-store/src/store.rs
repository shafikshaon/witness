//! Append-only writer with crash recovery and rotation (DESIGN.md §5.1).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::anchor::{Anchor, AnchorSink, TYPE_ANCHOR};
use crate::chain::{self, Hash, GENESIS};
use crate::disk::{
    self, DiskPolicy, DiskState, OnFull, Priority, Space, SpaceProbe, StatvfsProbe, RESERVE_FILE,
};
use crate::error::{Result, StoreError};
use crate::seal::{SealState, TYPE_SEAL_MAC};
use crate::segment::{self, SegmentInfo};
use crate::{SCHEMA_VERSION, TYPE_OPEN, TYPE_SEAL};

/// Longest line we are prepared to look back for while recovering a tail.
const TAIL_WINDOW: u64 = 8 << 20;

#[derive(Debug, Clone)]
pub struct Config {
    /// An active segment is sealed once it reaches this size.
    pub max_segment_bytes: u64,
    pub disk: DiskPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_segment_bytes: 256 << 20,
            disk: DiskPolicy::default(),
        }
    }
}

/// Result of [`Store::append_prio`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Append {
    Written(Appended),
    /// Not written because of the disk-full policy; counted and later reported.
    Dropped,
}

/// Something the disk policy did or noticed, for the caller to log and surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskEvent {
    Warning {
        pct: u8,
        used_pct: u8,
        free_bytes: u64,
    },
    StateChanged {
        from: String,
        to: String,
        free_bytes: u64,
    },
    /// Capture stopped (`on_full = "stop"`, or writes failed with no space left).
    GapStarted,
    GapEnded {
        dropped: [u64; 4],
    },
    /// Periodic report of events shed by priority (`[p0, p1, p2, p3]`).
    Dropped {
        counts: [u64; 4],
    },
}

#[derive(Debug, Clone)]
pub struct DiskStatus {
    pub state: DiskState,
    pub space: Option<Space>,
    pub used_pct: u8,
    pub dropped: [u64; 4],
    pub reserve_present: bool,
    /// Policy records that could not be written for lack of space (they are still returned
    /// as [`DiskEvent`]s so the caller can log them).
    pub unrecorded_notes: u64,
}

/// A torn (unterminated) tail removed while opening. The bytes are preserved on disk
/// so no evidence is destroyed; the caller should record a `recovery` event.
#[derive(Debug, Clone)]
pub struct Recovery {
    pub segment: PathBuf,
    pub bytes: u64,
    pub sha256: Hash,
    pub quarantined_to: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub seq: u64,
    pub hash: Hash,
}

struct Active {
    file: File,
    id: u64,
    first_seq: u64,
    bytes: u64,
}

pub struct Store {
    seg_dir: PathBuf,
    quarantine_dir: PathBuf,
    cfg: Config,
    next_seq: u64,
    head: Hash,
    last_id: u64,
    active: Option<Active>,
    seal: Option<SealState>,
    /// Held for the life of the store; releasing it lets another writer in.
    _lock: File,
    probe: Box<dyn SpaceProbe>,
    state: DiskState,
    level: u8,
    space: Option<Space>,
    bytes_since_probe: u64,
    warned: usize,
    dropped: [u64; 4],
    drop_window_start_ns: Option<u64>,
    last_drop_report: Option<Instant>,
    gap_start_ns: Option<u64>,
    gap_unrecorded: bool,
    unrecorded_notes: u64,
    pending: Vec<DiskEvent>,
    inject_partial: Option<usize>,
}

impl Store {
    /// Opens (or creates) a store rooted at `root`, resuming after the last record.
    pub fn open(root: &Path, cfg: Config) -> Result<(Self, Vec<Recovery>)> {
        Self::open_with_probe(root, cfg, Box::new(StatvfsProbe(root.to_path_buf())))
    }

    /// Like [`Store::open`] with an explicit free-space source (used by tests).
    pub fn open_with_probe(
        root: &Path,
        cfg: Config,
        probe: Box<dyn SpaceProbe>,
    ) -> Result<(Self, Vec<Recovery>)> {
        cfg.disk.validate().map_err(StoreError::Invalid)?;
        let seg_dir = root.join("segments");
        let quarantine_dir = root.join("quarantine");
        for d in [root, &seg_dir, &quarantine_dir] {
            fs::create_dir_all(d)?;
        }
        restrict(root)?;
        let lock = lock_exclusive(&root.join("store.lock"))?;
        let mut store = Store {
            seg_dir,
            quarantine_dir,
            cfg,
            next_seq: 1,
            head: GENESIS,
            last_id: 0,
            active: None,
            seal: None,
            _lock: lock,
            probe,
            state: DiskState::Normal,
            level: 0,
            space: None,
            bytes_since_probe: 0,
            warned: 0,
            dropped: [0; 4],
            drop_window_start_ns: None,
            last_drop_report: None,
            gap_start_ns: None,
            gap_unrecorded: false,
            unrecorded_notes: 0,
            pending: Vec::new(),
            inject_partial: None,
        };
        let recoveries = store.resume()?;
        store.init_disk();
        Ok((store, recoveries))
    }

    /// `(last assigned seq, chain head)`. Seq 0 means the store is empty.
    pub fn head(&self) -> (u64, Hash) {
        (self.next_seq - 1, self.head)
    }

    pub fn segment_dir(&self) -> &Path {
        &self.seg_dir
    }

    fn resume(&mut self) -> Result<Vec<Recovery>> {
        let mut recoveries = Vec::new();
        loop {
            let Some(last) = segment::list_segments(&self.seg_dir)?.pop() else {
                return Ok(recoveries);
            };
            let (line, sealed_ok) = if last.compressed {
                (last_line_streaming(&last)?, true)
            } else {
                let tail = scan_plain_tail(&last.path)?;
                if let Some((start, bytes)) = &tail.torn {
                    recoveries.push(self.quarantine(&last, *start, bytes)?);
                }
                match tail.last_line {
                    Some(l) => (Some(l), false),
                    None => {
                        // Nothing complete was ever written; no evidence lost by removing it.
                        fs::remove_file(&last.path)?;
                        segment::sync_dir(&self.seg_dir)?;
                        continue;
                    }
                }
            };
            let line =
                line.ok_or_else(|| StoreError::Corrupt("empty compressed segment".into()))?;
            let (body, h) = chain::decode_line(&line)?;
            let v: Value = serde_json::from_slice(&body)?;
            let seq = v["seq"]
                .as_u64()
                .ok_or_else(|| StoreError::Corrupt("last record has no seq".into()))?;
            self.next_seq = seq + 1;
            self.head = h;
            self.last_id = last.id;
            let sealed = v["type"] == TYPE_SEAL;
            if sealed_ok && !sealed {
                return Err(StoreError::Corrupt(format!(
                    "compressed segment {} is not sealed",
                    last.path.display()
                )));
            }
            if !sealed {
                let file = OpenOptions::new().append(true).open(&last.path)?;
                let bytes = file.metadata()?.len();
                self.active = Some(Active {
                    file,
                    id: last.id,
                    first_seq: last.first_seq,
                    bytes,
                });
            }
            return Ok(recoveries);
        }
    }

    fn quarantine(&self, seg: &SegmentInfo, start: u64, bytes: &[u8]) -> Result<Recovery> {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = seg
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("segment");
        let dest = self.quarantine_dir.join(format!("{name}.torn-{secs}"));
        let mut q = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?;
        q.write_all(bytes)?;
        q.sync_all()?;
        let f = OpenOptions::new().write(true).open(&seg.path)?;
        f.set_len(start)?;
        f.sync_all()?;
        segment::sync_dir(&self.quarantine_dir)?;
        Ok(Recovery {
            segment: seg.path.clone(),
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            quarantined_to: dest,
        })
    }

    /// Appends one P0 record. Fails with [`StoreError::DiskFull`] if capture is stopped.
    pub fn append(&mut self, fields: Map<String, Value>) -> Result<Appended> {
        match self.append_prio(Priority::P0, fields)? {
            Append::Written(a) => Ok(a),
            Append::Dropped => Err(StoreError::DiskFull),
        }
    }

    /// Appends one record at `prio`, subject to the disk-full policy. `fields` must not
    /// contain `seq` or `h`; both are assigned here.
    pub fn append_prio(
        &mut self,
        prio: Priority,
        mut fields: Map<String, Value>,
    ) -> Result<Append> {
        if fields.contains_key("seq") || fields.contains_key("h") {
            return Err(StoreError::Invalid("`seq` and `h` are reserved"));
        }
        self.maybe_probe();
        if self.state == DiskState::Stopped || disk::sheds(self.level, prio) {
            self.count_drop(prio);
            return Ok(Append::Dropped);
        }
        let written = match self.write_with_segment(&mut fields) {
            Ok(a) => a,
            Err(StoreError::Io(e)) if is_full(&e) => return self.on_write_full(prio, &mut fields),
            Err(e) => return Err(e),
        };
        let full = self
            .active
            .as_ref()
            .is_some_and(|a| a.bytes >= self.cfg.max_segment_bytes);
        if full {
            // The record is already durable-bound; failing to seal for lack of space only
            // defers rotation to the next append.
            match self.rotate() {
                Err(StoreError::Io(e)) if is_full(&e) => {}
                other => other?,
            }
        }
        Ok(Append::Written(written))
    }

    fn write_with_segment(&mut self, fields: &mut Map<String, Value>) -> Result<Appended> {
        if self.active.is_none() {
            self.start_segment()?;
        }
        self.write_record(fields)
    }

    fn count_drop(&mut self, prio: Priority) {
        self.dropped[prio.index()] += 1;
        self.drop_window_start_ns.get_or_insert_with(now_ns);
    }

    /// Turns on forward-secure sealing using the evolving key stored at `key_path`.
    ///
    /// If the process died after a seal record was made durable but before the key was
    /// evolved, the key is advanced here so an epoch is never reused.
    pub fn enable_sealing(&mut self, key_path: &Path) -> Result<()> {
        let mut st = SealState::load(key_path)?;
        for line in recent_lines(&self.seg_dir)? {
            let (body, _) = chain::decode_line(&line)?;
            let v: Value = serde_json::from_slice(&body)?;
            if v["type"] != TYPE_SEAL_MAC {
                continue;
            }
            let epoch = v["epoch"]
                .as_u64()
                .ok_or_else(|| StoreError::Corrupt("seal record without epoch".into()))?;
            if epoch > st.epoch() {
                return Err(StoreError::Corrupt(format!(
                    "seal key is at epoch {} but the chain already has epoch {epoch}; \
                     the key file is stale or was restored from a backup",
                    st.epoch()
                )));
            }
            if epoch == st.epoch() {
                st.advance(1)?;
            }
        }
        self.seal = Some(st);
        Ok(())
    }

    /// Writes a seal record for the current head, then evolves and erases the key.
    /// Returns `None` when sealing is not enabled.
    pub fn seal_now(&mut self) -> Result<Option<Appended>> {
        if self.seal.is_none() {
            return Ok(None);
        }
        if self.active.is_none() {
            self.start_segment()?;
        }
        let (covers_seq, head) = self.head();
        let (epoch, tag) = match &self.seal {
            Some(st) => (st.epoch(), st.mac(covers_seq, &head)?),
            None => return Ok(None),
        };
        let mut f = Map::new();
        f.insert("type".into(), TYPE_SEAL_MAC.into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("epoch".into(), epoch.into());
        f.insert("covers_seq".into(), covers_seq.into());
        f.insert("mac".into(), chain::to_hex(&tag).into());
        let appended = self.append(f)?;
        // The record must be durable before the key that made it is destroyed.
        self.sync()?;
        if let Some(st) = self.seal.as_mut() {
            st.advance(1)?;
        }
        Ok(Some(appended))
    }

    /// Writes an `anchor` record and publishes `(seq, hash)` of that record to every sink.
    /// Sink failures are returned, never raised: evidence writing must not depend on them.
    pub fn anchor_now(
        &mut self,
        sinks: &mut [Box<dyn AnchorSink>],
    ) -> Result<(Anchor, Vec<(String, std::io::Error)>)> {
        let (prev_seq, prev_head) = self.head();
        let mut f = Map::new();
        f.insert("type".into(), TYPE_ANCHOR.into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("head_seq".into(), prev_seq.into());
        f.insert("head_hash".into(), chain::to_hex(&prev_head).into());
        let a = self.append(f)?;
        self.sync()?;
        let anchor = Anchor {
            seq: a.seq,
            hash: a.hash,
        };
        let mut failures = Vec::new();
        for sink in sinks.iter_mut() {
            if let Err(e) = sink.publish(&anchor) {
                failures.push((sink.name(), e));
            }
        }
        Ok((anchor, failures))
    }

    /// Flushes the active segment to stable storage (group-commit point).
    pub fn sync(&mut self) -> Result<()> {
        if let Some(a) = &self.active {
            a.file.sync_data()?;
        }
        Ok(())
    }

    /// Seals the active segment (if any); the next append starts a new one.
    pub fn rotate(&mut self) -> Result<()> {
        let Some(first_seq) = self.active.as_ref().map(|a| a.first_seq) else {
            return Ok(());
        };
        let mut f = Map::new();
        f.insert("type".into(), TYPE_SEAL.into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("records".into(), (self.next_seq - first_seq).into());
        self.write_record(&mut f)?;
        if let Some(a) = self.active.take() {
            a.file.sync_all()?;
        }
        Ok(())
    }

    /// Compresses every sealed, still-plain segment.
    pub fn compress_sealed(&mut self) -> Result<Vec<SegmentInfo>> {
        let active_id = self.active.as_ref().map(|a| a.id);
        let mut done = Vec::new();
        for s in segment::list_segments(&self.seg_dir)? {
            if s.compressed || Some(s.id) == active_id {
                continue;
            }
            // Compression needs room for the new file before the plain one can go.
            let size = fs::metadata(&s.path)?.len();
            if let Ok(space) = self.probe.probe() {
                if space.avail < size.saturating_add(self.cfg.disk.min_free_bytes / 4) {
                    continue;
                }
            }
            done.push(segment::compress_segment(&s)?);
        }
        Ok(done)
    }

    fn start_segment(&mut self) -> Result<()> {
        let prev_sha = match segment::list_segments(&self.seg_dir)?.pop() {
            Some(prev) => segment::file_sha256(&prev)?,
            None => GENESIS,
        };
        let id = self.last_id + 1;
        let first_seq = self.next_seq;
        let path = self.seg_dir.join(segment::file_name(id, first_seq, false));
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)?;
        restrict_file(&path)?;
        self.active = Some(Active {
            file,
            id,
            first_seq,
            bytes: 0,
        });
        self.last_id = id;
        let mut f = Map::new();
        f.insert("type".into(), TYPE_OPEN.into());
        f.insert("v".into(), SCHEMA_VERSION.into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("seg".into(), id.into());
        f.insert("prev_seg_sha256".into(), chain::to_hex(&prev_sha).into());
        f.insert("prev_head".into(), chain::to_hex(&self.head).into());
        let opened = self.write_record(&mut f).and_then(|_| {
            if let Some(a) = &self.active {
                a.file.sync_all()?;
            }
            segment::sync_dir(&self.seg_dir).map_err(StoreError::from)
        });
        if let Err(e) = opened {
            // Leave no half-born segment behind; the id is reused by the next attempt.
            self.active = None;
            self.last_id = id - 1;
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(())
    }

    fn write_record(&mut self, fields: &mut Map<String, Value>) -> Result<Appended> {
        let seq = self.next_seq;
        fields.insert("seq".into(), json!(seq));
        let body = serde_json::to_vec(&*fields)?;
        let (mut line, hash) = chain::encode_line(&self.head, &body)?;
        line.push(b'\n');
        let inject = self.inject_partial.take();
        let active = self
            .active
            .as_mut()
            .ok_or(StoreError::Invalid("no active segment"))?;
        let before = active.bytes;
        if let Err(e) = write_line(&mut active.file, &line, inject) {
            // A partial line must never stay in the chain: put the file back exactly as it was.
            active.file.set_len(before).map_err(|te| {
                StoreError::Corrupt(format!(
                    "could not roll back a failed write ({te}); original error: {e}"
                ))
            })?;
            return Err(e.into());
        }
        active.bytes += line.len() as u64;
        self.bytes_since_probe += line.len() as u64;
        self.next_seq = seq + 1;
        self.head = hash;
        Ok(Appended { seq, hash })
    }

    // ---- disk-full policy ------------------------------------------------------------

    fn reserve_path(&self) -> PathBuf {
        self.seg_dir
            .parent()
            .unwrap_or(&self.seg_dir)
            .join(RESERVE_FILE)
    }

    fn init_disk(&mut self) {
        if let Ok(space) = self.probe.probe() {
            self.space = Some(space);
            let need = self.cfg.disk.reserve_bytes + self.cfg.disk.min_free_bytes;
            if space.avail >= need {
                let _ = disk::create_reserve(&self.reserve_path(), self.cfg.disk.reserve_bytes);
            }
            let mut ev = Vec::new();
            self.apply_space(space, &mut ev);
            self.pending.extend(ev);
        }
    }

    fn maybe_probe(&mut self) {
        if self.bytes_since_probe < self.cfg.disk.probe_every_bytes {
            return;
        }
        self.bytes_since_probe = 0;
        if let Ok(space) = self.probe.probe() {
            let mut ev = Vec::new();
            self.apply_space(space, &mut ev);
            self.pending.extend(ev);
        }
    }

    /// Polls free space, advances the policy state machine and returns what happened.
    /// The daemon should call this about every second.
    pub fn tick(&mut self) -> Result<Vec<DiskEvent>> {
        let mut events = std::mem::take(&mut self.pending);
        self.bytes_since_probe = 0;
        let space = self.probe.probe()?;
        self.apply_space(space, &mut events);
        self.flush_drop_report(&mut events, false);
        Ok(events)
    }

    pub fn disk_status(&self) -> DiskStatus {
        DiskStatus {
            state: self.state,
            space: self.space,
            used_pct: self.space.map_or(0, |s| s.used_pct()),
            dropped: self.dropped,
            reserve_present: self.reserve_path().exists(),
            unrecorded_notes: self.unrecorded_notes,
        }
    }

    fn apply_space(&mut self, space: Space, events: &mut Vec<DiskEvent>) {
        self.space = Some(space);
        let used = space.used_pct();
        let crossed = self
            .cfg
            .disk
            .warn_pcts
            .iter()
            .filter(|&&p| used >= p)
            .count();
        for idx in self.warned..crossed {
            let pct = self.cfg.disk.warn_pcts[idx];
            self.note("disk_warning", |f| {
                f.insert("threshold_pct".into(), pct.into());
                f.insert("used_pct".into(), used.into());
                f.insert("free_bytes".into(), space.avail.into());
            });
            events.push(DiskEvent::Warning {
                pct,
                used_pct: used,
                free_bytes: space.avail,
            });
        }
        self.warned = crossed;

        let min_free = self.cfg.disk.min_free_bytes;
        match self.cfg.disk.on_full {
            OnFull::Shed => {
                let new = disk::level_for(space.avail, min_free, self.level);
                if new != self.level {
                    self.transition(new, space, events);
                    if new == 0 {
                        self.flush_drop_report(events, true);
                    }
                }
            }
            OnFull::Stop => match self.state {
                DiskState::Stopped => {
                    let headroom = self.cfg.disk.reserve_bytes + min_free + min_free / 10;
                    if space.avail >= headroom {
                        self.resume_from_stop(space, events);
                    }
                }
                _ if space.avail < min_free => self.enter_stopped(space, events),
                _ => {}
            },
        }
    }

    fn transition(&mut self, new_level: u8, space: Space, events: &mut Vec<DiskEvent>) {
        let from = self.state.label();
        self.level = new_level;
        self.state = if new_level == 0 {
            DiskState::Normal
        } else {
            DiskState::Shedding(new_level)
        };
        let to = self.state.label();
        let (f, t) = (from.clone(), to.clone());
        self.note("disk_state", |m| {
            m.insert("from".into(), f.into());
            m.insert("to".into(), t.into());
            m.insert("free_bytes".into(), space.avail.into());
        });
        events.push(DiskEvent::StateChanged {
            from,
            to,
            free_bytes: space.avail,
        });
    }

    /// Stops capture: frees the reserve, records the gap start, and seals the segment.
    fn enter_stopped(&mut self, space: Space, events: &mut Vec<DiskEvent>) {
        let from = self.state.label();
        let _ = disk::release_reserve(&self.reserve_path());
        self.state = DiskState::Stopped;
        self.level = 3;
        let start = now_ns();
        self.gap_start_ns = Some(start);
        self.gap_unrecorded = !self.note_checked("capture_gap", |f| {
            f.insert("kind".into(), "disk_full".into());
            f.insert("phase".into(), "start".into());
            f.insert("free_bytes".into(), space.avail.into());
        });
        let _ = self.rotate();
        events.push(DiskEvent::StateChanged {
            from,
            to: "stopped".into(),
            free_bytes: space.avail,
        });
        events.push(DiskEvent::GapStarted);
    }

    fn resume_from_stop(&mut self, space: Space, events: &mut Vec<DiskEvent>) {
        if disk::create_reserve(&self.reserve_path(), self.cfg.disk.reserve_bytes).is_err() {
            return; // not enough real room yet
        }
        self.state = DiskState::Normal;
        self.level = 0;
        let counts = self.dropped;
        let (from_ns, to_ns) = (self.gap_start_ns.take().unwrap_or(0), now_ns());
        let start_recorded = !self.gap_unrecorded;
        self.gap_unrecorded = false;
        self.note("capture_gap", |f| {
            f.insert("kind".into(), "disk_full".into());
            f.insert("phase".into(), "end".into());
            f.insert("from_ns".into(), from_ns.into());
            f.insert("to_ns".into(), to_ns.into());
            f.insert("start_recorded".into(), start_recorded.into());
            f.insert("dropped".into(), json!(counts));
        });
        self.dropped = [0; 4];
        self.drop_window_start_ns = None;
        events.push(DiskEvent::StateChanged {
            from: "stopped".into(),
            to: "normal".into(),
            free_bytes: space.avail,
        });
        events.push(DiskEvent::GapEnded { dropped: counts });
    }

    /// A write hit ENOSPC despite the free-space estimate.
    fn on_write_full(&mut self, prio: Priority, fields: &mut Map<String, Value>) -> Result<Append> {
        let space = self.space.unwrap_or(Space { total: 0, avail: 0 });
        let mut ev = Vec::new();
        if self.cfg.disk.on_full == OnFull::Stop {
            self.enter_stopped(space, &mut ev);
            self.pending.extend(ev);
            self.count_drop(prio);
            return Ok(Append::Dropped);
        }
        if self.level < 3 {
            self.transition(3, space, &mut ev);
        }
        self.pending.extend(ev);
        if prio != Priority::P0 {
            self.count_drop(prio);
            return Ok(Append::Dropped);
        }
        // P0 may use the reserve.
        let released = disk::release_reserve(&self.reserve_path()).unwrap_or(false);
        if released {
            if let Ok(a) = self.write_with_segment(fields) {
                return Ok(Append::Written(a));
            }
        }
        let mut ev = Vec::new();
        self.enter_stopped(space, &mut ev);
        self.pending.extend(ev);
        self.count_drop(prio);
        Ok(Append::Dropped)
    }

    fn flush_drop_report(&mut self, events: &mut Vec<DiskEvent>, force: bool) {
        let shed: u64 = self.dropped.iter().sum();
        if shed == 0 || self.state == DiskState::Stopped {
            return; // a stop reports its counts when the gap ends
        }
        let due = self
            .last_drop_report
            .is_none_or(|t| t.elapsed() >= self.cfg.disk.drop_report_interval);
        if !(force || due) {
            return;
        }
        let counts = self.dropped;
        let from_ns = self.drop_window_start_ns.unwrap_or_else(now_ns);
        let to_ns = now_ns();
        self.note("capture_drop", |f| {
            f.insert("reason".into(), "disk".into());
            f.insert("from_ns".into(), from_ns.into());
            f.insert("to_ns".into(), to_ns.into());
            f.insert("dropped".into(), json!(counts));
        });
        self.dropped = [0; 4];
        self.drop_window_start_ns = None;
        self.last_drop_report = Some(Instant::now());
        events.push(DiskEvent::Dropped { counts });
    }

    /// Writes a policy record at P0, bypassing shedding. Failure is counted, not raised:
    /// the same fact is returned to the caller as a [`DiskEvent`].
    fn note(&mut self, kind: &str, fill: impl FnOnce(&mut Map<String, Value>)) {
        let _ = self.note_checked(kind, fill);
    }

    fn note_checked(&mut self, kind: &str, fill: impl FnOnce(&mut Map<String, Value>)) -> bool {
        let mut f = Map::new();
        f.insert("type".into(), kind.into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        fill(&mut f);
        match self.write_with_segment(&mut f) {
            Ok(_) => true,
            Err(_) => {
                self.unrecorded_notes += 1;
                false
            }
        }
    }

    /// Test hook: the next write stores `accept_bytes` of the line and then fails as if the
    /// disk filled up.
    #[cfg(feature = "fault-injection")]
    pub fn inject_partial_write_failure(&mut self, accept_bytes: usize) {
        self.inject_partial = Some(accept_bytes);
    }
}

fn write_line(f: &mut File, line: &[u8], inject: Option<usize>) -> io::Result<()> {
    match inject {
        Some(n) => {
            let k = n.min(line.len().saturating_sub(1));
            f.write_all(&line[..k])?;
            Err(io::Error::from(io::ErrorKind::StorageFull))
        }
        None => f.write_all(line),
    }
}

/// True for "no space left" and quota errors.
fn is_full(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    )
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn restrict(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict_file(_: &Path) -> Result<()> {
    Ok(())
}

struct Tail {
    last_line: Option<Vec<u8>>,
    /// The complete line before `last_line`, if it lies within the scanned window.
    prev_line: Option<Vec<u8>>,
    /// `(offset, bytes)` of an unterminated tail, if any.
    torn: Option<(u64, Vec<u8>)>,
}

fn scan_plain_tail(path: &Path) -> Result<Tail> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let base = len.saturating_sub(TAIL_WINDOW);
    f.seek(SeekFrom::Start(base))?;
    let mut buf = Vec::with_capacity((len - base) as usize);
    f.read_to_end(&mut buf)?;

    let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else {
        if base == 0 {
            let torn = (!buf.is_empty()).then_some((0, buf));
            return Ok(Tail {
                last_line: None,
                prev_line: None,
                torn,
            });
        }
        return Err(StoreError::Corrupt(
            "no line terminator within the tail window".into(),
        ));
    };
    let torn =
        (last_nl + 1 < buf.len()).then(|| (base + last_nl as u64 + 1, buf[last_nl + 1..].to_vec()));
    let complete = &buf[..last_nl];
    let start = match complete.iter().rposition(|&b| b == b'\n') {
        Some(p) => p + 1,
        None if base == 0 => 0,
        None => {
            return Err(StoreError::Corrupt(
                "last line exceeds the tail window".into(),
            ))
        }
    };
    let prev_line = if start >= 1 {
        let before = &complete[..start - 1];
        match before.iter().rposition(|&b| b == b'\n') {
            Some(p) => Some(before[p + 1..].to_vec()),
            None if base == 0 => Some(before.to_vec()),
            None => None,
        }
    } else {
        None
    };
    Ok(Tail {
        last_line: Some(complete[start..].to_vec()),
        prev_line,
        torn,
    })
}

fn last_line_streaming(info: &SegmentInfo) -> Result<Option<Vec<u8>>> {
    use std::io::BufRead;
    let mut r = segment::open_reader(info)?;
    let mut last = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            return Ok(last);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            last = Some(line.clone());
        }
    }
}

/// Up to the last two complete lines of the newest segment, oldest first.
fn recent_lines(seg_dir: &Path) -> Result<Vec<Vec<u8>>> {
    let Some(last) = segment::list_segments(seg_dir)?.pop() else {
        return Ok(Vec::new());
    };
    if last.compressed {
        return Ok(last_line_streaming(&last)?.into_iter().collect());
    }
    let tail = scan_plain_tail(&last.path)?;
    Ok(tail.prev_line.into_iter().chain(tail.last_line).collect())
}

/// Read-only `(last seq, chain head)` of a store; `(0, GENESIS)` if it has no records.
/// Safe to call while the daemon is writing (it never modifies anything).
pub fn read_head(seg_dir: &Path) -> Result<(u64, Hash)> {
    let Some(line) = recent_lines(seg_dir)?.pop() else {
        return Ok((0, GENESIS));
    };
    let (body, h) = chain::decode_line(&line)?;
    let v: Value = serde_json::from_slice(&body)?;
    let seq = v["seq"]
        .as_u64()
        .ok_or_else(|| StoreError::Corrupt("last record has no seq".into()))?;
    Ok((seq, h))
}

/// Takes the single-writer lock. Only one `Store` (the daemon, or an offline tool such as
/// `witness archive`) may append to a data directory at a time.
fn lock_exclusive(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(f),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(StoreError::Locked),
        Err(e) => Err(StoreError::Io(e.into())),
    }
}
