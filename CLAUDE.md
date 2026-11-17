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
- eBPF object (nightly, Linux): `cargo xtask build-ebpf` (output is embedded into `witnessd` via `include_bytes!`)
- Privileged integration tests (Linux VM, root only): `sudo -E cargo test -p witnessd --test integration -- --ignored`
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
