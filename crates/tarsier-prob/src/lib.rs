#![doc = include_str!("../README.md")]

//! Probabilistic analysis for committee-based BFT protocols.
//!
//! This crate computes hypergeometric tail bounds to determine the maximum
//! number of Byzantine members in a randomly sampled committee, given a
//! population size, corruption ratio, committee size, and failure probability.

pub mod committee;
pub mod hypergeometric;

pub use committee::{analyze_committee, CommitteeAnalysis, CommitteeSpec};
pub use hypergeometric::HypergeometricParams;
