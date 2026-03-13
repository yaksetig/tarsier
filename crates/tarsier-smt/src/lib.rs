#![doc = include_str!("../README.md")]

//! SMT encoding and solver integration for threshold automata verification.
//!
//! This crate provides bounded model checking (BMC), k-induction, and
//! property-directed reachability (PDR/IC3) over QF_LIA encodings of
//! counter systems, with pluggable Z3 and cvc5 backends.

/// Concrete solver backends and backend-selection helpers.
pub mod backends;
/// Bounded model checking encodings and execution helpers.
pub mod bmc;
/// Core SMT encoders for verification queries.
pub mod encoder;
/// Shared helpers for assembling SMT terms and constraints.
pub mod encoding_helpers;
/// Encoders for equivalence and relational checking workflows.
pub mod equivalence_encoder;
/// Encoders used by refinement-oriented verification passes.
pub mod refinement_encoder;
/// Solver process management, queries, and result decoding.
pub mod solver;
/// Sort constructors and sort-level utilities.
pub mod sorts;
/// Term constructors, visitors, and expression helpers.
pub mod terms;
