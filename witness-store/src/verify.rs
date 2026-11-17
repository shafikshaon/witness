//! `witness verify`: walks every segment and reports the first point where the chain breaks.

use std::io::{BufRead, ErrorKind};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::chain::{self, Hash, GENESIS};
use crate::error::Result;
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
    /// `None` means the whole chain verified.
    pub broken: Option<Break>,
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
}

pub fn verify_dir(seg_dir: &Path) -> Result<Report> {
    let segs = segment::list_segments(seg_dir)?;
    let mut run = Run {
        prev: GENESIS,
        expected_seq: 1,
        records: 0,
        prev_seg_sha: Some(GENESIS),
    };
    let mut report = Report {
        segments: 0,
        records: 0,
        head_seq: 0,
        head_hash: GENESIS,
        partial_start: false,
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
            run.prev_seg_sha = None;
            run.expected_seq = seg.first_seq;
        }
        prev_id = Some(seg.id);
        let outcome = verify_segment(seg, &mut run, i == last);
        report.segments += 1;
        report.records = run.records;
        report.head_seq = run.expected_seq.saturating_sub(1);
        report.head_hash = run.prev;
        match outcome {
            Ok(sha) => run.prev_seg_sha = Some(sha),
            Err(b) => {
                report.broken = Some(*b);
                break;
            }
        }
    }
    Ok(report)
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
