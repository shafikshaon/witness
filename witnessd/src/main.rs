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
    /// Run the daemon: capture into the tamper-evident store until SIGTERM/SIGINT.
    Run {
        #[arg(long, default_value = witness_config::DEFAULT_PATH)]
        config: std::path::PathBuf,
        /// Override `daemon.data_dir` from the config.
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
        /// Stop after this many seconds (default: run until signalled).
        #[arg(long)]
        seconds: Option<u64>,
    },
    /// Capture and print one JSON event per line, storing nothing (debugging).
    Tail {
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
        Cmd::Run {
            config,
            data_dir,
            seconds,
        } => witnessd::cli::run(&config, data_dir, seconds),
        Cmd::Tail { seconds } => witnessd::cli::tail(seconds),
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<()> {
    let _ = Cli::parse();
    anyhow::bail!("witnessd runs on Linux only")
}
