//! Witness collector daemon (library part). See `docs/DESIGN.md`.
pub mod accounts;
pub mod authlog;
pub mod baseline;
pub mod btf;
#[cfg(target_os = "linux")]
pub mod cli;
pub mod decode;
pub mod dns;
pub mod filepolicy;
pub mod hasher;
#[cfg(target_os = "linux")]
pub mod loader;
pub mod pipeline;
pub mod pkglog;
pub mod sensitive;
pub mod sources;
