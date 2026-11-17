//! Tamper-evident append-only storage for Witness (DESIGN.md §5).
pub mod anchor;
pub mod chain;
pub mod disk;
pub mod error;
pub mod index;
pub mod seal;
pub mod segment;
pub mod store;
pub mod verify;

pub use error::{Result, StoreError};
pub use store::{Config, Store};

pub const SCHEMA_VERSION: u16 = 1;
/// `type` of the first record of every segment.
pub const TYPE_OPEN: &str = "segment_open";
/// `type` of the last record of a sealed segment.
pub const TYPE_SEAL: &str = "segment_seal";
