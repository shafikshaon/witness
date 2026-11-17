use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use witness_store::chain::to_hex;
use witness_store::verify::{verify_dir, Report};

#[derive(Parser)]
#[command(
    name = "witness",
    version,
    about = "Witness forensic activity monitor CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify the tamper-evident hash chain and report exactly where it breaks.
    Verify {
        /// Witness data directory (contains `segments/`).
        #[arg(long, default_value = "/var/lib/witness")]
        dir: PathBuf,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::Verify { dir, json } => {
            let seg_dir = dir.join("segments");
            let report =
                verify_dir(&seg_dir).with_context(|| format!("reading {}", seg_dir.display()))?;
            if json {
                println!("{}", report_json(&report));
            } else {
                print_report(&report);
            }
            Ok(if report.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

fn print_report(r: &Report) {
    println!(
        "segments: {}  records: {}  head: seq {} {}",
        r.segments,
        r.records,
        r.head_seq,
        to_hex(&r.head_hash)
    );
    if r.partial_start {
        println!("note: history before the oldest segment is absent; its start cannot be checked");
    }
    match &r.broken {
        None => println!("OK: chain verified"),
        Some(b) => {
            println!("BROKEN: {:?}", b.kind);
            println!("  segment: {} (id {})", b.segment.display(), b.segment_id);
            if let Some(s) = b.seq {
                println!("  seq: {s}");
            }
            println!("  line: {}  byte offset: {}", b.line, b.offset);
        }
    }
}

fn report_json(r: &Report) -> serde_json::Value {
    json!({
        "ok": r.is_ok(),
        "segments": r.segments,
        "records": r.records,
        "head_seq": r.head_seq,
        "head_hash": to_hex(&r.head_hash),
        "partial_start": r.partial_start,
        "broken": r.broken.as_ref().map(|b| json!({
            "kind": format!("{:?}", b.kind),
            "segment": b.segment.display().to_string(),
            "segment_id": b.segment_id,
            "seq": b.seq,
            "line": b.line,
            "offset": b.offset,
        })),
    })
}
