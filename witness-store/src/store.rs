//! Append-only writer with crash recovery and rotation (DESIGN.md §5.1).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::anchor::{Anchor, AnchorSink, TYPE_ANCHOR};
use crate::chain::{self, Hash, GENESIS};
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_segment_bytes: 256 << 20,
        }
    }
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
}

impl Store {
    /// Opens (or creates) a store rooted at `root`, resuming after the last record.
    pub fn open(root: &Path, cfg: Config) -> Result<(Self, Vec<Recovery>)> {
        let seg_dir = root.join("segments");
        let quarantine_dir = root.join("quarantine");
        for d in [root, &seg_dir, &quarantine_dir] {
            fs::create_dir_all(d)?;
        }
        restrict(root)?;
        let mut store = Store {
            seg_dir,
            quarantine_dir,
            cfg,
            next_seq: 1,
            head: GENESIS,
            last_id: 0,
            active: None,
            seal: None,
        };
        let recoveries = store.resume()?;
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

    /// Appends one record. `fields` must not contain `seq` or `h`; both are assigned here.
    pub fn append(&mut self, fields: Map<String, Value>) -> Result<Appended> {
        if fields.contains_key("seq") || fields.contains_key("h") {
            return Err(StoreError::Invalid("`seq` and `h` are reserved"));
        }
        if self.active.is_none() {
            self.start_segment()?;
        }
        let appended = self.write_record(fields)?;
        let full = self
            .active
            .as_ref()
            .is_some_and(|a| a.bytes >= self.cfg.max_segment_bytes);
        if full {
            self.rotate()?;
        }
        Ok(appended)
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
        self.write_record(f)?;
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
            if !s.compressed && Some(s.id) != active_id {
                done.push(segment::compress_segment(&s)?);
            }
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
        self.write_record(f)?;
        if let Some(a) = &self.active {
            a.file.sync_all()?;
        }
        segment::sync_dir(&self.seg_dir)?;
        Ok(())
    }

    fn write_record(&mut self, mut fields: Map<String, Value>) -> Result<Appended> {
        let seq = self.next_seq;
        fields.insert("seq".into(), json!(seq));
        let body = serde_json::to_vec(&Value::Object(fields))?;
        let (mut line, hash) = chain::encode_line(&self.head, &body)?;
        line.push(b'\n');
        let active = self
            .active
            .as_mut()
            .ok_or(StoreError::Invalid("no active segment"))?;
        active.file.write_all(&line)?;
        active.bytes += line.len() as u64;
        self.next_seq = seq + 1;
        self.head = hash;
        Ok(Appended { seq, hash })
    }
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
