//! `witness archive` and `witness prune` (DESIGN.md §5.8).
//!
//! Both act only on the *oldest contiguous run of sealed segments* and never on the newest
//! segment, so the chain always keeps a well-defined start and its current head. Each is
//! logged in the chain **before** anything is deleted, which is how `verify` can tell a
//! deliberate removal from tampering.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read};
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::chain::{self, Hash};
use crate::error::{Result, StoreError};
use crate::segment::{self, fidx_path, SegmentInfo};
use crate::store::{last_line_streaming, now_ns, scan_plain_tail, Store};
use crate::TYPE_SEAL;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegMeta {
    pub first_seq: u64,
    pub last_seq: u64,
    pub sealed: bool,
    pub seal_ts_ns: Option<u64>,
}

/// One segment as recorded in an `archive` or `prune` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    pub id: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub file: String,
    pub sha256_file: Hash,
    pub sha256_plain: Hash,
}

impl SegmentRecord {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "file": self.file,
            "sha256_file": chain::to_hex(&self.sha256_file),
            "sha256_plain": chain::to_hex(&self.sha256_plain),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveReport {
    pub segments: Vec<SegmentRecord>,
    /// Segments that were copied (others were already present and identical).
    pub copied: usize,
    pub moved: bool,
}

pub fn segment_meta(info: &SegmentInfo) -> Result<SegMeta> {
    let mut first = String::new();
    segment::open_reader(info)?.read_line(&mut first)?;
    let (body, _) = chain::decode_line(first.trim_end_matches('\n').as_bytes())?;
    let open: Value = serde_json::from_slice(&body)?;
    let first_seq = open["seq"]
        .as_u64()
        .ok_or_else(|| StoreError::Corrupt("segment_open without seq".into()))?;

    let last = if info.compressed {
        last_line_streaming(info)?
    } else {
        scan_plain_tail(&info.path)?.last_line
    }
    .ok_or_else(|| StoreError::Corrupt("segment has no complete record".into()))?;
    let (body, _) = chain::decode_line(&last)?;
    let v: Value = serde_json::from_slice(&body)?;
    let last_seq = v["seq"]
        .as_u64()
        .ok_or_else(|| StoreError::Corrupt("record without seq".into()))?;
    let sealed = v["type"] == TYPE_SEAL;
    Ok(SegMeta {
        first_seq,
        last_seq,
        sealed,
        seal_ts_ns: sealed.then(|| v["ts_wall_ns"].as_u64()).flatten(),
    })
}

/// The oldest run of sealed segments (never the newest segment), optionally only those
/// sealed before `before_ns`.
pub fn plan_prefix(seg_dir: &Path, before_ns: Option<u64>) -> Result<Vec<(SegmentInfo, SegMeta)>> {
    let segs = segment::list_segments(seg_dir)?;
    let mut plan = Vec::new();
    for s in segs.iter().take(segs.len().saturating_sub(1)) {
        let meta = segment_meta(s)?;
        if !meta.sealed {
            break;
        }
        if let Some(t) = before_ns {
            if meta.seal_ts_ns.is_none_or(|ts| ts >= t) {
                break;
            }
        }
        plan.push((s.clone(), meta));
    }
    Ok(plan)
}

fn raw_sha256(path: &Path) -> Result<Hash> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

fn describe(info: &SegmentInfo, meta: &SegMeta) -> Result<SegmentRecord> {
    Ok(SegmentRecord {
        id: info.id,
        first_seq: meta.first_seq,
        last_seq: meta.last_seq,
        file: info
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string(),
        sha256_file: raw_sha256(&info.path)?,
        sha256_plain: segment::file_sha256(info)?,
    })
}

/// Copies `src` into `dest_dir` and proves the copy: raw bytes and decompressed content
/// must hash identically. Returns whether a copy was made (false: identical file present).
fn copy_verified(src: &SegmentInfo, rec: &SegmentRecord, dest_dir: &Path) -> Result<bool> {
    let dest = dest_dir.join(&rec.file);
    if dest.exists() {
        return if raw_sha256(&dest)? == rec.sha256_file {
            Ok(false)
        } else {
            Err(StoreError::Corrupt(format!(
                "{} already exists and differs from the source",
                dest.display()
            )))
        };
    }
    let tmp = dest.with_extension("part");
    let result = (|| -> Result<()> {
        fs::copy(&src.path, &tmp)?;
        OpenOptions::new().write(true).open(&tmp)?.sync_all()?;
        if raw_sha256(&tmp)? != rec.sha256_file {
            return Err(StoreError::Corrupt("copy does not match the source".into()));
        }
        fs::rename(&tmp, &dest)?;
        segment::sync_dir(dest_dir)?;
        let copy = SegmentInfo {
            path: dest.clone(),
            ..src.clone()
        };
        if segment::file_sha256(&copy)? != rec.sha256_plain {
            let _ = fs::remove_file(&dest);
            return Err(StoreError::Corrupt(
                "archived copy decodes differently from the source".into(),
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    if src.compressed {
        let _ = fs::copy(fidx_path(&src.path), fidx_path(&dest)); // derived; best effort
    }
    Ok(true)
}

fn remove_segment(info: &SegmentInfo) -> Result<()> {
    fs::remove_file(&info.path)?;
    if info.compressed {
        let _ = fs::remove_file(fidx_path(&info.path));
    }
    Ok(())
}

fn actor_fields(f: &mut Map<String, Value>) {
    f.insert(
        "actor_uid".into(),
        rustix::process::getuid().as_raw().into(),
    );
    if let Ok(v) = std::env::var("SUDO_UID") {
        f.insert("sudo_uid".into(), v.into());
    }
}

impl Store {
    /// Copies the oldest sealed segments (optionally only those sealed before `before_ns`)
    /// to `dest/segments/`, verifies every copy, logs an `archive` record, and with
    /// `move_` removes the originals afterwards.
    pub fn archive(
        &mut self,
        dest: &Path,
        before_ns: Option<u64>,
        move_: bool,
    ) -> Result<ArchiveReport> {
        let plan = plan_prefix(self.segment_dir(), before_ns)?;
        if plan.is_empty() {
            return Ok(ArchiveReport {
                segments: Vec::new(),
                copied: 0,
                moved: false,
            });
        }
        let dest_dir = dest.join("segments");
        fs::create_dir_all(&dest_dir)?;
        let mut records = Vec::new();
        let mut copied = 0;
        for (info, meta) in &plan {
            let rec = describe(info, meta)?;
            if copy_verified(info, &rec, &dest_dir)? {
                copied += 1;
            }
            records.push(rec);
        }
        let through = records.last().map_or(0, |r| r.last_seq);
        let mut f = Map::new();
        f.insert("type".into(), "archive".into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("dest".into(), dest.display().to_string().into());
        f.insert("moved".into(), move_.into());
        f.insert("through_seq".into(), through.into());
        f.insert(
            "segments".into(),
            Value::Array(records.iter().map(SegmentRecord::to_json).collect()),
        );
        actor_fields(&mut f);
        self.append(f)?;
        self.sync()?;
        if move_ {
            for (info, _) in &plan {
                remove_segment(info)?;
            }
            segment::sync_dir(self.segment_dir())?;
        }
        Ok(ArchiveReport {
            segments: records,
            copied,
            moved: move_,
        })
    }

    /// Permanently deletes the oldest sealed segments sealed before `before_ns`.
    ///
    /// `expect` is the number of segments the caller reviewed in a dry run; a mismatch
    /// aborts. The `prune` record, listing every removed file's hashes, is made durable
    /// *before* the first file is deleted.
    pub fn prune(&mut self, before_ns: u64, expect: usize) -> Result<Vec<SegmentRecord>> {
        let plan = plan_prefix(self.segment_dir(), Some(before_ns))?;
        if plan.len() != expect {
            return Err(StoreError::Invalid(
                "the number of segments to delete differs from the number confirmed",
            ));
        }
        if plan.is_empty() {
            return Ok(Vec::new());
        }
        let records = plan
            .iter()
            .map(|(i, m)| describe(i, m))
            .collect::<Result<Vec<_>>>()?;
        let mut f = Map::new();
        f.insert("type".into(), "prune".into());
        f.insert("ts_wall_ns".into(), now_ns().into());
        f.insert("before_ns".into(), before_ns.into());
        f.insert(
            "through_seq".into(),
            records.last().map_or(0, |r| r.last_seq).into(),
        );
        f.insert(
            "segments".into(),
            Value::Array(records.iter().map(SegmentRecord::to_json).collect()),
        );
        actor_fields(&mut f);
        self.append(f)?;
        self.sync()?;
        for (info, _) in &plan {
            remove_segment(info)?;
        }
        segment::sync_dir(self.segment_dir())?;
        Ok(records)
    }
}
