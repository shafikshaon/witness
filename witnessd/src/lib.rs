//! Witness collector daemon (library part). See `docs/DESIGN.md`.
pub mod baseline;
pub mod btf;
#[cfg(target_os = "linux")]
pub mod cli;
pub mod decode;
pub mod filepolicy;
#[cfg(target_os = "linux")]
pub mod loader;
pub mod pipeline;
