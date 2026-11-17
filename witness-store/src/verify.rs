//! `witness verify`: walks every segment and reports the first point where the chain breaks.

use std::collections::HashMap;
use std::io::{BufRead, ErrorKind};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::anchor::Anchor;
use crate::chain::{self, Hash, GENESIS};
use crate::error::Result;
use crate::seal::{self, TYPE_SEAL_MAC};
use crate::segment::{self, SegmentInfo};
use crate::{TYPE_OPEN, TYPE_SEAL};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// The segment could not be read or decompressed.
    Unreadable(String),
    /// A line is not a well-formed chain record.
    Malformed(String),
    /// The record's hash does not match its content and predecessor (modification).
    BadHash,
    /// Sequence numbers are not gapless (deletion, insertion or reordering).
    SeqMismatch { expected: u64, found: u64 },
    /// A segment id is missing between two present segments.
    MissingSegment { expected_id: u64, found_id: u64 },
    /// The first record of a segment is not `segment_open`, or disagrees with its file name.
    BadSegmentOpen(String),
    /// `segment_open.prev_seg_sha256` does not match the previous segment's bytes.
    PrevSegmentHash,
    /// A non-final segment has no `segment_seal`.
    UnsealedMidStore,
    /// Data follows `segment_seal`.
    TrailingAfterSeal,
    /// `segment_seal.records` disagrees with the number of records present.
    SealCountMismatch { expected: u64, found: u64 },
    /// The file ends in the middle of a line (torn write or truncation).
    TornTail,
    /// A seal record is structurally wrong (missing fields, wrong `covers_seq`).
    BadSeal(String),
    /// Seal epochs must be consecutive starting at 1; a gap means seals were removed.
    SealEpochGap { expected: u64, found: u64 },
    /// The seal MAC does not verify under the key derived from the verification key.
    BadSealMac { epoch: u64 },
    /// A seal was required (`--require-seals`) but the store contains none.
    NoSeals,
    /// A published anchor disagrees with the chain's hash at that seq.
    AnchorMismatch { seq: u64 },
    /// A published anchor names a seq beyond the end of the chain: the tail was truncated.
    AnchorBeyondHead { anchor_seq: u64, head_seq: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Break {
    pub segment: PathBuf,
    pub segment_id: u64,
    /// Sequence number of the offending record, when one could be determined.
    pub seq: Option<u64>,
    /// 1-based line within the segment.
    pub line: u64,
    /// Byte offset of the line start within the *uncompressed* segment.
    pub offset: u64,
    pub kind: BreakKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub segments: u64,
    pub records: u64,
    pub head_seq: u64,
    pub head_hash: Hash,
    /// True when the oldest segment on disk is not segment 1 (pruned/archived history):
    /// verification starts from that segment's recorded `prev_head` and cannot check it.
    pub partial_start: bool,
    /// Number of seal records seen.
    pub seals: u64,
    pub last_seal_epoch: Option<u64>,
    /// Records up to here are covered by a seal; later ones are the unsealed tail.
    pub sealed_through_seq: Option<u64>,
    /// True if seal MACs were checked against a verification key (not just structure).
    pub macs_checked: bool,
    pub anchors_checked: u64,
    /// `None` means the whole chain verified.
    pub broken: Option<Break>,
}

/// Optional inputs that strengthen verification beyond the bare hash chain.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The admin-held verification key `K_0`; enables seal MAC checks.
    pub seal_key: Option<Hash>,
    /// Anchors published outside the evidence files.
    pub anchors: Vec<Anchor>,
    /// Fail if the store has no seal records at all.
    pub require_seals: bool,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.broken.is_none()
    }
}

struct Run {
    prev: Hash,
    expected_seq: u64,
    records: u64,
    prev_seg_sha: Option<Hash>,
    partial: bool,
    seals: u64,
    last_epoch: Option<u64>,
    sealed_through: Option<u64>,
    /// `(epoch, key)` of the evolving verification key.
    key: Option<(u64, Hash)>,
    anchors: HashMap<u64, Hash>,
    anchors_checked: u64,
}

pub fn verify_dir(seg_dir: &Path) -> Result<Report> {
    verify_with(seg_dir, &Options::default())
}

pub fn verify_with(seg_dir: &Path, opts: &Options) -> Result<Report> {
    let segs = segment::list_segments(seg_dir)?;
    let mut run = Run {
        prev: GENESIS,
        expected_seq: 1,
        records: 0,
        prev_seg_sha: Some(GENESIS),
        partial: false,
        seals: 0,
        last_epoch: None,
        sealed_through: None,
        key: opts.seal_key.map(|k| (0, k)),
        anchors: opts.anchors.iter().map(|a| (a.seq, a.hash)).collect(),
        anchors_checked: 0,
    };
    let mut report = Report {
        segments: 0,
        records: 0,
        head_seq: 0,
        head_hash: GENESIS,
        partial_start: false,
        seals: 0,
        last_seal_epoch: None,
        sealed_through_seq: None,
        macs_checked: false,
        anchors_checked: 0,
        broken: None,
    };
    let mut prev_id: Option<u64> = None;
    let last = segs.len().saturating_sub(1);
    for (i, seg) in segs.iter().enumerate() {
        if let Some(p) = prev_id {
            if seg.id != p + 1 {
                report.broken = Some(Break {
                    segment: seg.path.clone(),
                    segment_id: seg.id,
                    seq: None,
                    line: 0,
                    offset: 0,
                    kind: BreakKind::MissingSegment {
                        expected_id: p + 1,
                        found_id: seg.id,
                    },
                });
                break;
            }
        } else if seg.id != 1 {
            report.partial_start = true;
            run.partial = true;
            run.prev_seg_sha = None;
            run.expected_seq = seg.first_seq;
        }
        prev_id = Some(seg.id);
        let outcome = verify_segment(seg, &mut run, i == last);
        report.segments += 1;
        report.records = run.records;
        report.head_seq = run.expected_seq.saturating_sub(1);
        report.head_hash = run.prev;
        report.seals = run.seals;
        report.last_seal_epoch = run.last_epoch;
        report.sealed_through_seq = run.sealed_through;
        report.anchors_checked = run.anchors_checked;
        match outcome {
            Ok(sha) => run.prev_seg_sha = Some(sha),
            Err(b) => {
                report.broken = Some(*b);
                break;
            }
        }
    }
    report.macs_checked = opts.seal_key.is_some() && run.seals > 0;
    if report.broken.is_none() {
        report.broken = final_checks(segs.last(), &run, opts, report.head_seq);
    }
    Ok(report)
}

/// Checks that need the whole chain: truncation against anchors, and required seals.
fn final_checks(
    last: Option<&SegmentInfo>,
    run: &Run,
    opts: &Options,
    head_seq: u64,
) -> Option<Break> {
    let at = |seq: Option<u64>, kind: BreakKind| Break {
        segment: last.map(|s| s.path.clone()).unwrap_or_default(),
        segment_id: last.map_or(0, |s| s.id),
        seq,
        line: 0,
        offset: 0,
        kind,
    };
    let mut beyond: Vec<u64> = run
        .anchors
        .keys()
        .copied()
        .filter(|&s| s > head_seq)
        .collect();
    beyond.sort_unstable();
    if let Some(&anchor_seq) = beyond.first() {
        return Some(at(
            Some(anchor_seq),
            BreakKind::AnchorBeyondHead {
                anchor_seq,
                head_seq,
            },
        ));
    }
    if opts.require_seals && run.seals == 0 {
        return Some(at(None, BreakKind::NoSeals));
    }
    None
}

fn verify_segment(
    seg: &SegmentInfo,
    run: &mut Run,
    is_last: bool,
) -> std::result::Result<Hash, Box<Break>> {
    let brk = |seq: Option<u64>, line: u64, offset: u64, kind: BreakKind| {
        Box::new(Break {
            segment: seg.path.clone(),
            segment_id: seg.id,
            seq,
            line,
            offset,
            kind,
        })
    };
    let mut reader = segment::open_reader(seg)
        .map_err(|e| brk(None, 0, 0, BreakKind::Unreadable(e.to_string())))?;
    let mut sha = Sha256::new();
    let mut buf = Vec::new();
    let (mut line_no, mut offset) = (0u64, 0u64);
    let mut sealed = false;

    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(e) => {
                let k = if e.kind() == ErrorKind::UnexpectedEof {
                    BreakKind::TornTail
                } else {
                    BreakKind::Unreadable(e.to_string())
                };
                return Err(brk(None, line_no + 1, offset, k));
            }
        };
        if n == 0 {
            break;
        }
        line_no += 1;
        if buf.last() != Some(&b'\n') {
            return Err(brk(None, line_no, offset, BreakKind::TornTail));
        }
        if sealed {
            return Err(brk(None, line_no, offset, BreakKind::TrailingAfterSeal));
        }
        sha.update(&buf);
        let line = &buf[..buf.len() - 1];

        let (body, recorded) = chain::decode_line(line)
            .map_err(|e| brk(None, line_no, offset, BreakKind::Malformed(e.to_string())))?;
        let parsed: Option<Value> = serde_json::from_slice(&body).ok();
        if line_no == 1 && run.prev_seg_sha.is_none() {
            // Pruned/archived history: trust the recorded predecessor head (cannot be checked).
            if let Some(h) = parsed
                .as_ref()
                .and_then(|v| v["prev_head"].as_str())
                .and_then(|s| chain::from_hex(s.as_bytes()))
            {
                run.prev = h;
            }
        }
        let hash_ok = chain::link(&run.prev, &body) == recorded;
        let Some(v) = parsed else {
            let kind = if hash_ok {
                BreakKind::Malformed("not valid JSON".into())
            } else {
                BreakKind::BadHash
            };
            return Err(brk(None, line_no, offset, kind));
        };
        let Some(seq) = v["seq"].as_u64() else {
            let kind = if hash_ok {
                BreakKind::Malformed("missing seq".into())
            } else {
                BreakKind::BadHash
            };
            return Err(brk(None, line_no, offset, kind));
        };
        if seq != run.expected_seq {
            return Err(brk(
                Some(seq),
                line_no,
                offset,
                BreakKind::SeqMismatch {
                    expected: run.expected_seq,
                    found: seq,
                },
            ));
        }
        if !hash_ok {
            return Err(brk(Some(seq), line_no, offset, BreakKind::BadHash));
        }

        if let Some(want) = run.anchors.get(&seq) {
            if *want != recorded {
                return Err(brk(
                    Some(seq),
                    line_no,
                    offset,
                    BreakKind::AnchorMismatch { seq },
                ));
            }
            run.anchors_checked += 1;
        }
        if v["type"] == TYPE_SEAL_MAC {
            check_seal(&v, seq, run).map_err(|k| brk(Some(seq), line_no, offset, k))?;
        }

        if line_no == 1 {
            check_open(&v, seg, seq, run).map_err(|k| brk(Some(seq), line_no, offset, k))?;
        } else if v["type"] == TYPE_SEAL {
            sealed = true;
            let found = seq - seg.first_seq;
            let expected = v["records"].as_u64().unwrap_or(u64::MAX);
            if expected != found {
                return Err(brk(
                    Some(seq),
                    line_no,
                    offset,
                    BreakKind::SealCountMismatch { expected, found },
                ));
            }
        }
        run.prev = recorded;
        run.expected_seq = seq + 1;
        run.records += 1;
        offset += n as u64;
    }

    if line_no == 0 && !is_last {
        return Err(brk(
            None,
            0,
            0,
            BreakKind::Malformed("empty segment".into()),
        ));
    }
    if !sealed && !is_last {
        return Err(brk(None, line_no, offset, BreakKind::UnsealedMidStore));
    }
    Ok(sha.finalize().into())
}

fn check_open(
    v: &Value,
    seg: &SegmentInfo,
    seq: u64,
    run: &mut Run,
) -> std::result::Result<(), BreakKind> {
    let bad = |m: &str| BreakKind::BadSegmentOpen(m.to_string());
    if v["type"] != TYPE_OPEN {
        return Err(bad("first record is not segment_open"));
    }
    if v["seg"].as_u64() != Some(seg.id) || seq != seg.first_seq {
        return Err(bad("segment_open disagrees with the file name"));
    }
    let claimed = v["prev_seg_sha256"]
        .as_str()
        .and_then(|s| chain::from_hex(s.as_bytes()))
        .ok_or_else(|| bad("missing prev_seg_sha256"))?;
    match run.prev_seg_sha {
        Some(want) if want != claimed => Err(BreakKind::PrevSegmentHash),
        _ => Ok(()),
    }
}

fn check_seal(v: &Value, seq: u64, run: &mut Run) -> std::result::Result<(), BreakKind> {
    let bad = |m: &str| BreakKind::BadSeal(m.to_string());
    let epoch = v["epoch"].as_u64().ok_or_else(|| bad("missing epoch"))?;
    let covers = v["covers_seq"]
        .as_u64()
        .ok_or_else(|| bad("missing covers_seq"))?;
    let tag = v["mac"]
        .as_str()
        .and_then(|s| chain::from_hex(s.as_bytes()))
        .ok_or_else(|| bad("missing or malformed mac"))?;
    if covers + 1 != seq {
        return Err(bad("covers_seq is not the preceding record"));
    }
    let expected = match run.last_epoch {
        Some(e) => Some(e + 1),
        None if run.partial => None,
        None => Some(1),
    };
    if let Some(expected) = expected {
        if epoch != expected {
            return Err(BreakKind::SealEpochGap {
                expected,
                found: epoch,
            });
        }
    }
    if let Some((k_epoch, k)) = run.key {
        if epoch < k_epoch {
            return Err(BreakKind::SealEpochGap {
                expected: k_epoch,
                found: epoch,
            });
        }
        let key = seal::evolve_to(&k, k_epoch, epoch);
        // The head the MAC covers is the hash of the record just before this one.
        if !seal::mac_ok(&key, epoch, covers, &run.prev, &tag) {
            return Err(BreakKind::BadSealMac { epoch });
        }
        run.key = Some((epoch, key));
    }
    run.seals += 1;
    run.last_epoch = Some(epoch);
    run.sealed_through = Some(covers);
    Ok(())
}
