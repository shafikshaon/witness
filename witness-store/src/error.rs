use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid record: {0}")]
    Line(#[from] crate::chain::LineError),
    #[error("store is corrupt: {0}")]
    Corrupt(String),
    #[error("disk is full: capture is stopped until space returns")]
    DiskFull,
    #[error("the store is locked by another writer (is witnessd running?)")]
    Locked,
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
}

pub type Result<T> = std::result::Result<T, StoreError>;
