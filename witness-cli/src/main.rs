use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use witness_store::anchor::read_anchors;
use witness_store::chain::{self, to_hex, Hash};
use witness_store::index::Index;
use witness_store::seal::SealState;
use witness_store::store::read_head;
use witness_store::verify::{verify_dirs, Options, Report};

const DEFAULT_DIR: &str = "/var/lib/witness";

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
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Verification key K_0 (64 hex digits) printed by `witness init --seal`.
        #[arg(long, conflicts_with = "seal_key_file")]
        seal_key: Option<String>,
        /// File containing the verification key K_0.
        #[arg(long)]
        seal_key_file: Option<PathBuf>,
        /// Anchors file (`seq=<n> head=<hex>` lines). Defaults to `<dir>/anchors.log` if present.
        /// Pass it again from an off-host copy for the strongest check.
        #[arg(long)]
        anchors: Option<PathBuf>,
        /// Fail if the store contains no seal records.
        #[arg(long)]
        require_seals: bool,
        /// Also read segments from this archive directory (repeatable).
        #[arg(long = "include")]
        include: Vec<PathBuf>,
        /// Accept missing oldest history that no prune/archive record explains.
        #[arg(long)]
        allow_partial: bool,
    },
    /// Rebuild the SQLite query index from the segments.
    Reindex {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
    },
    /// Create the forward-secure sealing key. Prints the verification key ONCE.
    Init {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Enable forward-secure sealing (required; reserved for future init options).
        #[arg(long)]
        seal: bool,
    },
    /// Print the current chain head to record somewhere the host cannot rewrite.
    Anchor {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
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
        Cmd::Verify {
            dir,
            json,
            seal_key,
            seal_key_file,
            anchors,
            require_seals,
            include,
            allow_partial,
        } => cmd_verify(
            &dir,
            json,
            seal_key,
            seal_key_file,
            anchors,
            require_seals,
            &include,
            allow_partial,
        ),
        Cmd::Reindex { dir } => cmd_reindex(&dir),
        Cmd::Init { dir, seal } => cmd_init(&dir, seal),
        Cmd::Anchor { dir } => {
            let (seq, head) = read_head(&dir.join("segments"))
                .with_context(|| format!("reading {}", dir.display()))?;
            println!("seq={seq} head={}", to_hex(&head));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_key(s: &str) -> Result<Hash> {
    chain::from_hex(s.trim().to_ascii_lowercase().as_bytes())
        .context("verification key must be 64 hex digits")
}

#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    dir: &Path,
    json: bool,
    seal_key: Option<String>,
    seal_key_file: Option<PathBuf>,
    anchors: Option<PathBuf>,
    require_seals: bool,
    include: &[PathBuf],
    allow_partial: bool,
) -> Result<ExitCode> {
    let seal_key = match (seal_key, seal_key_file) {
        (Some(k), _) => Some(parse_key(&k)?),
        (None, Some(f)) => Some(parse_key(
            &fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?,
        )?),
        (None, None) => None,
    };
    let anchors_path = anchors.or_else(|| {
        let p = dir.join("anchors.log");
        p.exists().then_some(p)
    });
    let anchors = match &anchors_path {
        Some(p) => read_anchors(p).with_context(|| format!("reading {}", p.display()))?,
        None => Vec::new(),
    };
    let opts = Options {
        seal_key,
        anchors,
        require_seals,
        allow_partial,
    };
    let mut dirs = vec![dir.join("segments")];
    dirs.extend(include.iter().map(|d| d.join("segments")));
    let report = verify_dirs(&dirs, &opts)
        .with_context(|| format!("reading {}", dir.join("segments").display()))?;
    if json {
        println!("{}", report_json(&report));
    } else {
        print_report(&report, anchors_path.as_deref());
    }
    Ok(if report.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn cmd_reindex(dir: &Path) -> Result<ExitCode> {
    let db = dir.join("index.db");
    for ext in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{ext}", db.display()));
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
        }
    }
    let mut ix = Index::open(&db).context("creating index")?;
    let n = ix
        .catch_up(&dir.join("segments"))
        .context("indexing segments")?;
    let (seq, head) = ix.position()?;
    println!("indexed {n} records; head seq {seq} {}", to_hex(&head));
    Ok(ExitCode::SUCCESS)
}

fn cmd_init(dir: &Path, seal: bool) -> Result<ExitCode> {
    if !seal {
        bail!("nothing to do: pass --seal to create the sealing key");
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let k0 = SealState::init(&dir.join("seal.key")).context("creating seal.key")?;
    println!("Verification key (K_0): {}", to_hex(&k0));
    println!();
    println!("Store this key OFF this machine now (password manager, paper, another host).");
    println!("It is not saved here and cannot be recovered. Without it `witness verify`");
    println!("can still check structure and anchors, but not the seal MACs.");
    Ok(ExitCode::SUCCESS)
}

fn print_report(r: &Report, anchors: Option<&Path>) {
    println!(
        "segments: {}  records: {}  head: seq {} {}",
        r.segments,
        r.records,
        r.head_seq,
        to_hex(&r.head_hash)
    );
    if r.partial_start {
        if r.partial_explained {
            println!("note: older history was removed by a logged prune/archive; its start cannot be checked");
        } else {
            println!("note: history before the oldest segment is absent and no prune/archive record explains it");
        }
    }
    match (r.seals, r.macs_checked) {
        (0, _) => println!("seals: none"),
        (n, true) => println!(
            "seals: {n} (epoch {}), MACs verified; sealed through seq {}",
            r.last_seal_epoch.unwrap_or(0),
            r.sealed_through_seq.unwrap_or(0)
        ),
        (n, false) => println!(
            "seals: {n} present but MACs NOT checked (no verification key given); \
             a root attacker could have rewritten history consistently"
        ),
    }
    match anchors {
        Some(p) => println!(
            "anchors: {} checked from {}",
            r.anchors_checked,
            p.display()
        ),
        None => println!("anchors: none given; a clean truncation of the tail would go unnoticed"),
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
        "partial_explained": r.partial_explained,
        "seals": r.seals,
        "last_seal_epoch": r.last_seal_epoch,
        "sealed_through_seq": r.sealed_through_seq,
        "macs_checked": r.macs_checked,
        "anchors_checked": r.anchors_checked,
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
