use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "witnessd", version, about = "Witness collector daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Capture process activity and print one JSON event per line (M1).
    Run {
        /// Stop after this many seconds (default: run until interrupted).
        #[arg(long)]
        seconds: Option<u64>,
    },
    /// Report what this kernel supports: BTF, resolved offsets, available hook functions.
    Doctor,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Doctor => witnessd::cli::doctor(),
        Cmd::Run { seconds } => witnessd::cli::run(seconds),
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<()> {
    let _ = Cli::parse();
    anyhow::bail!("witnessd runs on Linux only")
}
