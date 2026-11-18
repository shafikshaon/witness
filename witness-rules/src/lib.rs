//! The Witness rule language: parse YAML, compile to a typed tree, evaluate over events.
//!
//! This is *Sigma-inspired*, not Sigma-compatible (DESIGN.md §8.1). Evaluation works on the
//! event's JSON form, so a rule's field names are exactly the names in the stored records.

mod compile;
mod engine;
mod ops;

pub use compile::{load_dir, load_str, LoadResult, Rule, RuleError, RuleSet};
pub use engine::{Engine, Stats};
