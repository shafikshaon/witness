use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use witness_store::anchor::read_anchors;
use witness_store::archive::plan_prefix;
use witness_store::chain::{self, to_hex, Hash};
use witness_store::disk::DiskPolicy;
use witness_store::index::Index;
use witness_store::seal::SealState;
use witness_store::store::read_head;
use witness_store::verify::{verify_dirs, Options, Report};
use witness_store::{Config, Store, StoreError};

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
        /// Also index segments from this archive directory (repeatable).
        #[arg(long = "include")]
        include: Vec<PathBuf>,
    },
    /// Copy the oldest sealed segments to another path/device, verify them, and log it.
    Archive {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Destination directory (segments go to `<to>/segments`).
        #[arg(long)]
        to: PathBuf,
        /// Only segments sealed before this UTC date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ).
        #[arg(long)]
        before: Option<String>,
        /// Remove the originals after the copies are verified and logged.
        #[arg(long = "move")]
        move_: bool,
    },
    /// Permanently delete the oldest sealed segments. Dry run unless confirmed.
    Prune {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Delete segments sealed before this UTC date.
        #[arg(long)]
        before: String,
        /// Actually delete. Without this flag only the plan is printed.
        #[arg(long)]
        yes_delete_evidence: bool,
        /// Number of segments you reviewed in the dry run; must match.
        #[arg(long)]
        expect: Option<usize>,
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
        Cmd::Reindex { dir, include } => cmd_reindex(&dir, &include),
        Cmd::Archive {
            dir,
            to,
            before,
            move_,
        } => cmd_archive(&dir, &to, before.as_deref(), move_),
        Cmd::Prune {
            dir,
            before,
            yes_delete_evidence,
            expect,
        } => cmd_prune(&dir, &before, yes_delete_evidence, expect),
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

fn cmd_reindex(dir: &Path, include: &[PathBuf]) -> Result<ExitCode> {
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
    let mut dirs = vec![dir.join("segments")];
    dirs.extend(include.iter().map(|d| d.join("segments")));
    let n = ix.catch_up_dirs(&dirs).context("indexing segments")?;
    let (seq, head) = ix.position()?;
    println!("indexed {n} records; head seq {seq} {}", to_hex(&head));
    Ok(ExitCode::SUCCESS)
}

/// Opens the store for an offline maintenance action. No disk-policy reserve is created.
fn open_offline(dir: &Path) -> Result<Store> {
    let cfg = Config {
        disk: DiskPolicy::disabled(),
        ..Default::default()
    };
    match Store::open(dir, cfg) {
        Ok((store, recovered)) => {
            for r in recovered {
                eprintln!(
                    "warning: removed a torn tail ({} bytes) from {}; kept at {}",
                    r.bytes,
                    r.segment.display(),
                    r.quarantined_to.display()
                );
            }
            Ok(store)
        }
        Err(StoreError::Locked) => bail!(
            "the store is in use by another writer (is witnessd running?). \
             Stop it first; daemon-mediated archive/prune arrives with the API."
        ),
        Err(e) => Err(e).with_context(|| format!("opening {}", dir.display())),
    }
}

fn cmd_archive(dir: &Path, to: &Path, before: Option<&str>, move_: bool) -> Result<ExitCode> {
    let before_ns = before.map(parse_time_ns).transpose()?;
    let mut store = open_offline(dir)?;
    let rep = store
        .archive(to, before_ns, move_)
        .context("archiving segments")?;
    if rep.segments.is_empty() {
        println!("nothing to archive (only sealed segments older than the newest qualify)");
        return Ok(ExitCode::SUCCESS);
    }
    for s in &rep.segments {
        println!(
            "segment {:>8}  seq {}..{}  {}",
            s.id, s.first_seq, s.last_seq, s.file
        );
    }
    println!(
        "{} segment(s) verified at {} ({} copied, {} already present){}",
        rep.segments.len(),
        to.join("segments").display(),
        rep.copied,
        rep.segments.len() - rep.copied,
        if rep.moved {
            "; originals removed"
        } else {
            "; originals kept"
        }
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_prune(dir: &Path, before: &str, confirmed: bool, expect: Option<usize>) -> Result<ExitCode> {
    let before_ns = parse_time_ns(before)?;
    let plan = plan_prefix(&dir.join("segments"), Some(before_ns))
        .with_context(|| format!("reading {}", dir.display()))?;
    if plan.is_empty() {
        println!("nothing to prune before {before}");
        return Ok(ExitCode::SUCCESS);
    }
    println!("segments that would be PERMANENTLY DELETED:");
    for (info, m) in &plan {
        println!(
            "  segment {:>8}  seq {}..{}  {}",
            info.id,
            m.first_seq,
            m.last_seq,
            info.path.display()
        );
    }
    println!(
        "{} segment(s). Archive first (`witness archive --move`) if you may need them.",
        plan.len()
    );
    if !confirmed {
        println!(
            "dry run: re-run with --yes-delete-evidence --expect {} to delete",
            plan.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let Some(expect) = expect else {
        bail!("--yes-delete-evidence also needs --expect {}", plan.len());
    };
    let mut store = open_offline(dir)?;
    let gone = store
        .prune(before_ns, expect)
        .context("pruning (nothing was deleted)")?;
    println!(
        "deleted {} segment(s); the removal is recorded in the chain",
        gone.len()
    );
    Ok(ExitCode::SUCCESS)
}

/// Parses `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ` (UTC) to nanoseconds since the epoch.
fn parse_time_ns(s: &str) -> Result<u64> {
    let bad = || {
        anyhow::anyhow!(
            "expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ (UTC, years 1970-2500), got {s:?}"
        )
    };
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, Some(t.strip_suffix('Z').ok_or_else(bad)?)),
        None => (s, None),
    };
    let nums = |x: &str, sep: char, n: usize| -> Result<Vec<i64>> {
        let v: Vec<i64> = x
            .split(sep)
            .map(|p| p.parse::<i64>().map_err(|_| bad()))
            .collect::<Result<_>>()?;
        if v.len() == n {
            Ok(v)
        } else {
            Err(bad())
        }
    };
    let d = nums(date, '-', 3)?;
    let t = match time {
        Some(t) => nums(t, ':', 3)?,
        None => vec![0, 0, 0],
    };
    let (y, m, day) = (d[0], d[1], d[2]);
    if !(1970..=2500).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&t[0])
        || !(0..60).contains(&t[1])
        || !(0..61).contains(&t[2])
    {
        return Err(bad());
    }
    // Days from civil date (proleptic Gregorian), after Howard Hinnant's algorithm.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + t[0] * 3600 + t[1] * 60 + t[2];
    u64::try_from(secs)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .ok_or_else(bad)
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

#[cfg(test)]
mod tests {
    use super::parse_time_ns;

    #[test]
    fn dates_parse_to_known_epochs() {
        assert_eq!(parse_time_ns("1970-01-01").unwrap(), 0);
        assert_eq!(
            parse_time_ns("2000-03-01").unwrap(),
            951_868_800_000_000_000
        );
        assert_eq!(
            parse_time_ns("2024-02-29T12:30:45Z").unwrap(),
            1_709_209_845_000_000_000
        );
        assert_eq!(
            parse_time_ns("2026-11-17").unwrap(),
            1_794_873_600_000_000_000
        );
    }

    #[test]
    fn bad_dates_are_rejected() {
        for s in [
            "",
            "2024",
            "1969-12-31",
            "2999-01-01",
            "2024-01-32",
            "yesterday",
            "2024-01-01T10:00",
            "1969-12-31",
        ] {
            assert!(parse_time_ns(s).is_err(), "{s}");
        }
    }
}
