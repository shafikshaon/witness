//! Incident bundle: a tar of a contiguous range of stored records plus everything needed to
//! check them independently (DESIGN.md §9.3).
//!
//! Contents: `events.ndjson` (the stored lines, byte for byte), `alerts.json`,
//! `chain-proof.json` (the hash of the record before the range and each record's hash, with a
//! self-check), `anchors.json`, `verify-report.json` (a verification of the whole store run at
//! export time), and `manifest.json` (SHA-256 of every other file). The range must be
//! contiguous: a hash chain cannot be checked across records that were left out.
//!
//! No signature is produced; sign `manifest.json` with a key you control if you need one.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::chain::{self, Hash, GENESIS};
use crate::verify::{verify_dirs, Options};

/// Largest number of records in one bundle (it is assembled in memory).
pub const MAX_RECORDS: usize = 500_000;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("{0}")]
    Invalid(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] crate::StoreError),
    #[error("record {seq} is malformed: {why}")]
    Record { seq: u64, why: String },
}

#[derive(Debug, Clone, Default)]
pub struct BundleOptions {
    /// First record to include (default: the first in the store).
    pub from_seq: Option<u64>,
    /// Last record to include (default: the last).
    pub to_seq: Option<u64>,
    /// Recorded in the manifest.
    pub tool_version: String,
    /// Export time (wall clock ns), recorded in the manifest.
    pub exported_wall_ns: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Appends one regular file to a ustar archive.
pub fn tar_entry(
    out: &mut Vec<u8>,
    name: &str,
    data: &[u8],
    mtime: u64,
) -> Result<(), BundleError> {
    if name.len() > 100 || !name.is_ascii() {
        return Err(BundleError::Invalid(format!("tar name too long: {name}")));
    }
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let put = |h: &mut [u8; 512], at: usize, width: usize, v: u64| {
        let s = format!("{v:0w$o}\0", w = width - 1);
        h[at..at + width].copy_from_slice(s.as_bytes());
    };
    put(&mut h, 100, 8, 0o644);
    put(&mut h, 108, 8, 0);
    put(&mut h, 116, 8, 0);
    put(&mut h, 124, 12, data.len() as u64);
    put(&mut h, 136, 12, mtime);
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let c = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(c.as_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    Ok(())
}

struct Line {
    seq: u64,
    raw: Vec<u8>,
    body: Vec<u8>,
    hash: Hash,
    value: Value,
}

/// Builds the bundle for records `from..=to` from the segments in `dirs`. `data_dir` is where
/// `anchors.log` lives.
pub fn build(dirs: &[PathBuf], data_dir: &Path, o: &BundleOptions) -> Result<Vec<u8>, BundleError> {
    let mut prev_hash: Hash = GENESIS;
    let mut prev_of_first: Option<Hash> = None;
    let mut selected: Vec<Line> = Vec::new();
    let mut triage: HashMap<u64, (u64, Value)> = HashMap::new();
    let (mut first_seen, mut head_seq, mut head_hash) = (None::<u64>, 0u64, GENESIS);

    for seg in crate::segment::list_segments_in(dirs)? {
        for line in crate::segment::open_reader(&seg)?.lines() {
            let line = line?;
            let (body, hash) =
                chain::decode_line(line.as_bytes()).map_err(|e| BundleError::Record {
                    seq: head_seq + 1,
                    why: e.to_string(),
                })?;
            let value: Value = serde_json::from_slice(&body).map_err(|e| BundleError::Record {
                seq: head_seq + 1,
                why: e.to_string(),
            })?;
            let seq = value["seq"].as_u64().unwrap_or(0);
            first_seen.get_or_insert(seq);
            head_seq = seq;
            head_hash = hash;
            if value["type"] == "triage_action" {
                if let Some(a) = value["data"]["alert_seq"].as_u64() {
                    if triage.get(&a).is_none_or(|(s, _)| seq > *s) {
                        triage.insert(a, (seq, json!({"status": value["data"]["status"], "note": value["data"]["note"], "by_uid": value["data"]["actor_uid"], "at_seq": seq})));
                    }
                }
            }
            let inside = o.from_seq.is_none_or(|f| seq >= f) && o.to_seq.is_none_or(|t| seq <= t);
            if inside {
                if selected.is_empty() {
                    prev_of_first = Some(prev_hash);
                }
                if selected.len() >= MAX_RECORDS {
                    return Err(BundleError::Invalid(format!(
                        "more than {MAX_RECORDS} records selected; narrow --from-seq/--to-seq"
                    )));
                }
                selected.push(Line {
                    seq,
                    raw: line.into_bytes(),
                    body,
                    hash,
                    value,
                });
            }
            prev_hash = hash;
        }
    }
    let first = selected
        .first()
        .ok_or_else(|| BundleError::Invalid("no records in that range".into()))?;
    let last = selected
        .last()
        .ok_or_else(|| BundleError::Invalid("no records in that range".into()))?;
    let (first_seq, last_seq) = (first.seq, last.seq);
    let start_hash = prev_of_first.unwrap_or(GENESIS);

    // Self-check: re-derive every hash from the record before the range.
    let mut p = start_hash;
    let mut proof_lines = Vec::with_capacity(selected.len());
    for l in &selected {
        p = chain::link(&p, &l.body);
        if p != l.hash {
            return Err(BundleError::Record {
                seq: l.seq,
                why: "its hash does not follow from the previous one".into(),
            });
        }
        proof_lines.push(json!({"seq": l.seq, "h": hex(&l.hash)}));
    }

    let mut events = Vec::new();
    for l in &selected {
        events.extend_from_slice(&l.raw);
        events.push(b'\n');
    }
    let alerts: Vec<Value> = selected
        .iter()
        .filter(|l| l.value["type"] == "alert")
        .map(|l| {
            let mut a = l.value.clone();
            a["triage"] = triage
                .get(&l.seq)
                .map(|(_, t)| t.clone())
                .unwrap_or_else(|| json!({"status": "new"}));
            a
        })
        .collect();
    let proof = json!({
        "algorithm": "h_n = SHA-256(h_(n-1) || body_n); body_n is the stored line with its last 72 bytes (`,\"h\":\"<64 hex>\"}`) replaced by `}`",
        "genesis": hex(&GENESIS),
        "first_seq": first_seq,
        "last_seq": last_seq,
        "records": selected.len(),
        "prev_hash": hex(&start_hash),
        "last_hash": hex(&selected.last().map(|l| l.hash).unwrap_or(GENESIS)),
        "slice_self_check": "passed",
        "lines": proof_lines,
    });
    let anchors: Vec<Value> = crate::anchor::read_anchors(&data_dir.join("anchors.log"))
        .unwrap_or_default()
        .iter()
        .filter(|a| a.seq >= first_seq && a.seq <= last_seq)
        .map(|a| json!({"seq": a.seq, "hash": hex(&a.hash)}))
        .collect();
    let report = match verify_dirs(
        dirs,
        &Options {
            allow_partial: true,
            ..Options::default()
        },
    ) {
        Ok(r) => json!({
            "state": if r.is_ok() { "ok" } else { "broken" },
            "segments": r.segments, "records": r.records, "head_seq": r.head_seq,
            "head_hash": hex(&r.head_hash), "seals": r.seals, "anchors_checked": r.anchors_checked,
            "partial_start": r.partial_start, "macs_checked": r.macs_checked,
            "broken": r.broken.map(|b| format!("{b:?}")),
        }),
        Err(e) => json!({"state": "error", "detail": e.to_string()}),
    };

    let files: Vec<(&str, Vec<u8>)> = vec![
        ("events.ndjson", events),
        (
            "alerts.json",
            serde_json::to_vec_pretty(&alerts).unwrap_or_default(),
        ),
        (
            "chain-proof.json",
            serde_json::to_vec_pretty(&proof).unwrap_or_default(),
        ),
        (
            "anchors.json",
            serde_json::to_vec_pretty(&anchors).unwrap_or_default(),
        ),
        (
            "verify-report.json",
            serde_json::to_vec_pretty(&report).unwrap_or_default(),
        ),
    ];
    let manifest = json!({
        "tool": "witness",
        "version": o.tool_version,
        "exported_wall_ns": o.exported_wall_ns,
        "range": {"first_seq": first_seq, "last_seq": last_seq, "records": selected.len()},
        "store_head": {"seq": head_seq, "hash": hex(&head_hash), "first_record_seq": first_seen},
        "files": files.iter().map(|(n, d)| json!({"name": n, "bytes": d.len(), "sha256": hex(&Sha256::digest(d))})).collect::<Vec<_>>(),
        "note": "events.ndjson holds the stored lines verbatim. To check them: start from chain-proof.json prev_hash and apply the algorithm line by line; each result must equal that line's h.",
        "signature": null,
    });
    let mtime = o.exported_wall_ns / 1_000_000_000;
    let mut tar = Vec::new();
    for (n, d) in &files {
        tar_entry(&mut tar, n, d, mtime)?;
    }
    tar_entry(
        &mut tar,
        "manifest.json",
        &serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
        mtime,
    )?;
    tar.resize(tar.len() + 1024, 0); // end-of-archive marker
    Ok(tar)
}
