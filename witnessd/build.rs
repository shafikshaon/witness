//! Builds the eBPF object with a pinned nightly (via `aya-build`) and exposes it at
//! `$OUT_DIR/witness-ebpf` for `include_bytes_aligned!`. Off Linux, or with
//! `AYA_BUILD_SKIP=1`, an empty placeholder is written so the rest of the daemon still
//! builds; loading it then fails with a clear error at runtime.

use std::{env, fs, path::PathBuf};

use anyhow::{anyhow, Result};
use aya_build::{Package, Toolchain};

/// Pinned so eBPF builds are reproducible (DESIGN.md §1.2). Matches the rustc recorded in
/// `docs/DESIGN.md`; bump deliberately.
const NIGHTLY: &str = "nightly-2026-11-17";

fn main() -> Result<()> {
    println!("cargo::rerun-if-env-changed=AYA_BUILD_SKIP");
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?);
    let on_linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    let skip = env::var("AYA_BUILD_SKIP").is_ok_and(|v| v == "1");

    if on_linux && !skip {
        aya_build::build_ebpf(
            [Package {
                name: "witness-ebpf",
                root_dir: "../witness-ebpf",
                ..Default::default()
            }],
            Toolchain::Custom(NIGHTLY),
        )?;
    }
    let obj = out.join("witness-ebpf");
    if !obj.exists() {
        fs::write(&obj, b"")?;
    }
    Ok(())
}
