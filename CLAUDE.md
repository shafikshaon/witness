# Witness: working notes for Claude

Linux forensic activity monitor. Authoritative design: `docs/DESIGN.md` (approved). Read it before changing architecture; if you must deviate, explain why first.

## Layout
- `witness-ebpf/`: eBPF programs (`no_std`, aya). **Pinned nightly** + `bpf-linker`. License string `Dual MIT/GPL`.
- `witness-common/`: `#[repr(C)]` kernel<->user types and shared schema. `no_std` where shared with eBPF.
- `witnessd/`: collector daemon (loaders, enrichment, storage, rules, API).
- `witness-cli/`: `witness` CLI. `witness-gui/`: Dioxus Desktop app. `rules/`: YAML rule pack. `xtask/`: build and packaging.

## Commands
- Userspace build/test (stable): `cargo build --workspace --exclude witness-ebpf` / `cargo test --workspace --exclude witness-ebpf --all-features`
- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --exclude witness-ebpf --all-targets --all-features -- -D warnings`
- eBPF object: built automatically by `witnessd/build.rs` on Linux (needs `rustup` nightly `nightly-2026-11-17` with `rust-src`, and `bpf-linker` on PATH). Skip with `WITNESS_SKIP_EBPF=1` (e.g. on macOS or for clippy).
- Privileged integration tests (Linux VM, root only): build as the normal user, run the binary with sudo: `T=$(cargo test -p witnessd --test integration --no-run 2>&1 | sed -n 's/.*(\(target[^)]*\)).*/\1/p' | head -1); sudo $T --ignored --test-threads=1 --nocapture`
- Run the daemon on the VM: `sudo target/debug/witnessd run --config /nonexistent --data-dir /tmp/wd --seconds 10`, then `target/debug/witness verify --dir /tmp/wd` (use `sudo sh -c` for globs inside the root-only data dir).
- Kernel capability check: `target/debug/witnessd doctor` (BTF, resolved offsets, which `fentry` targets exist).
- Never run eBPF code on macOS; it only compiles there at best. Always state *compiled only* vs *verified on a real kernel*.

## Conventions
- No `unwrap()`/`expect()` outside tests (clippy deny). `thiserror` in libraries, `anyhow` in binaries, `tracing` for logs.
- Every `unsafe` block gets a `// SAFETY:` comment with its invariants. Minimize `unsafe`.
- Pin crate versions after checking crates.io/docs.rs. Do not invent APIs, hooks or features; mark unverified claims.
- Evidence is never deleted automatically. Never corrupt existing segments.
- Hash is computed over the exact stored bytes (no re-serialization).
- Tamper *detection*, not prevention.

## Git
- Small, focused commits. **No Co-Authored-By trailer** (user preference).

## Linux test VM (Lima)
- VM `witness-dev`: Ubuntu 22.04.5, kernel 5.15.0-198-generic, **aarch64**, 4 CPU / 8 GiB, BTF on, passwordless sudo. Start: `limactl start witness-dev`. Run: `limactl shell witness-dev -- bash -lc '<cmd>'`.
- The macOS home is mounted **read-only** in the VM. Work in the VM-local clone `~/witness`: `git -c safe.directory='*' pull /Users/shafikshaon/Workplace/Projects/Witness main`, commit on the Mac, pull in the VM. Build with `source ~/.cargo/env; export PATH=$HOME/.local/bin:$PATH`.
- Installed there: rustup stable + nightly (`rust-src`), `bpf-linker` 0.13.0 (prebuilt musl release; hash not independently verified), bpftool 5.15, clang/llvm 14, strace.
- Real-ENOSPC tests need a tiny mount: `sudo mount -t tmpfs -o size=1m tmpfs /mnt/witness-small && sudo chown $USER /mnt/witness-small`, then `WITNESS_SMALL_FS=/mnt/witness-small cargo test -p witness-store --test real_enospc -- --ignored --test-threads=1`.
- It is aarch64; x86_64 still needs a separate check (cloud VM or UTM). Always report the kernel (`uname -r`) and arch when claiming "verified on a real kernel".

## eBPF verifier debugging (learned the hard way; see DESIGN.md §2.10)
- Stats-only verifier logging is the default. `WITNESS_VERIFIER_LOG=debug|verbose` dumps the trace; `WITNESS_ONLY_HOOK=security_path_unlink` loads one hook. Under `sudo` pass them with `sudo env VAR=... cmd` (sudo strips the environment).
- In eBPF code: never branch on a helper's result or on `Option`; use `rd_or`. Do not compare two ranged values in a loop; mask. Initialise structs with field stores, not `zeroed()`. A loop's cost explodes when two branch outcomes both stay live.
- aarch64 < 6.0 has no fentry/fexit: file hooks are kprobes. aya's failed-load retry loop makes a rejection take minutes with full logging.
- `witnessd` blocks SIGTERM/SIGINT at start and reads them from a signalfd, so `timeout`/SIGTERM cannot interrupt a stuck kernel call; use SIGKILL.
