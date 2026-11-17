//! Builds the eBPF object with a pinned nightly and exposes it at `$OUT_DIR/witness-ebpf`
//! for `include_bytes_aligned!`. Off Linux, or with `WITNESS_SKIP_EBPF=1`, an empty
//! placeholder is written so the rest of the daemon still builds; loading it then fails
//! with a clear error at runtime.
//!
//! `witness-ebpf` is deliberately a *separate* cargo workspace (different toolchain, `no_std`
//! BPF target), so it is built here with a direct `cargo` call rather than via `aya-build`,
//! which requires it to be a member of the main workspace.

use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{anyhow, bail, Result};

/// Pinned so eBPF builds are reproducible (DESIGN.md §1.2). Bump deliberately.
const NIGHTLY: &str = "nightly-2026-11-17";

fn main() -> Result<()> {
    println!("cargo::rerun-if-env-changed=WITNESS_SKIP_EBPF");
    for p in [
        "../witness-ebpf/src",
        "../witness-ebpf/Cargo.toml",
        "../witness-common/src",
    ] {
        println!("cargo::rerun-if-changed={p}");
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?);
    let obj = out.join("witness-ebpf");
    let on_linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    let skip = env::var("WITNESS_SKIP_EBPF").is_ok_and(|v| v == "1");

    if on_linux && !skip {
        let arch = env::var("CARGO_CFG_TARGET_ARCH")?;
        let target_dir = out.join("ebpf-target");
        let status = Command::new("rustup")
            .args(["run", NIGHTLY, "cargo", "build", "--release"])
            .args(["--manifest-path", "../witness-ebpf/Cargo.toml"])
            .args(["--target", "bpfel-unknown-none", "-Z", "build-std=core"])
            .arg("--target-dir")
            .arg(&target_dir)
            // The BPF target needs BTF debug info and the arch the bindings should use.
            .env(
                "CARGO_ENCODED_RUSTFLAGS",
                format!("--cfg=bpf_target_arch=\"{arch}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"),
            )
            .env_remove("RUSTC")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTFLAGS")
            .status()
            .map_err(|e| anyhow!("running rustup (is {NIGHTLY} installed with rust-src?): {e}"))?;
        if !status.success() {
            bail!("building witness-ebpf failed ({status}); needs `bpf-linker` on PATH and the {NIGHTLY} toolchain");
        }
        fs::copy(
            target_dir.join("bpfel-unknown-none/release/witness-ebpf"),
            &obj,
        )?;
    }
    if !obj.exists() {
        fs::write(&obj, b"")?;
    }
    Ok(())
}
