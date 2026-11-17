//! Witness collector daemon (library part). See `docs/DESIGN.md`.
pub mod btf;
#[cfg(target_os = "linux")]
pub mod cli;
pub mod decode;
#[cfg(target_os = "linux")]
pub mod loader;
pub mod pipeline;
