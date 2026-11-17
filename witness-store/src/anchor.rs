//! Anchors: small `(seq, head hash)` checkpoints published *outside* the evidence files
//! (DESIGN.md §5.4). They are what lets `verify` prove a truncated tail.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::chain::{self, Hash};
use crate::error::Result;

pub const TYPE_ANCHOR: &str = "anchor";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub hash: Hash,
}

/// A destination for anchors. Failures are reported but never block evidence writing.
pub trait AnchorSink: Send {
    fn name(&self) -> String;
    fn publish(&mut self, a: &Anchor) -> io::Result<()>;
}

/// Appends `seq=<n> head=<hex>` lines to a file (default `anchors.log`).
pub struct FileSink {
    path: PathBuf,
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileSink { path: path.into() }
    }
}

impl AnchorSink for FileSink {
    fn name(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn publish(&mut self, a: &Anchor) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "seq={} head={}", a.seq, chain::to_hex(&a.hash))?;
        f.sync_all()
    }
}

/// Runs an admin-configured program with the anchor in its environment
/// (`WITNESS_ANCHOR_SEQ`, `WITNESS_ANCHOR_HASH`). No shell is involved.
pub struct CommandSink {
    program: PathBuf,
    args: Vec<String>,
}

impl CommandSink {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        CommandSink {
            program: program.into(),
            args,
        }
    }
}

impl AnchorSink for CommandSink {
    fn name(&self) -> String {
        format!("command:{}", self.program.display())
    }

    fn publish(&mut self, a: &Anchor) -> io::Result<()> {
        let status = Command::new(&self.program)
            .args(&self.args)
            .env("WITNESS_ANCHOR_SEQ", a.seq.to_string())
            .env("WITNESS_ANCHOR_HASH", chain::to_hex(&a.hash))
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "anchor command exited with {status}"
            )))
        }
    }
}

/// Parses an anchors file. Malformed lines are an error: a silently skipped anchor would
/// weaken verification.
pub fn read_anchors(path: &Path) -> Result<Vec<Anchor>> {
    let f = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    for (i, line) in f.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let bad = || {
            crate::StoreError::Corrupt(format!("{}:{}: malformed anchor", path.display(), i + 1))
        };
        let mut seq = None;
        let mut head = None;
        for part in line.split_whitespace() {
            if let Some(v) = part.strip_prefix("seq=") {
                seq = v.parse().ok();
            } else if let Some(v) = part.strip_prefix("head=") {
                head = chain::from_hex(v.as_bytes());
            }
        }
        out.push(Anchor {
            seq: seq.ok_or_else(bad)?,
            hash: head.ok_or_else(bad)?,
        });
    }
    Ok(out)
}
