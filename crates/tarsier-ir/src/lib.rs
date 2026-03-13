#![doc = include_str!("../README.md")]

//! Tarsier intermediate representation and lowering.
//!
//! This crate defines the threshold automaton IR, the lowering pass from the
//! DSL AST to the IR, counter-system abstraction, safety property extraction,
//! and compositional verification data structures.

/// Abstract interpretation and predicate abstractions over the IR.
pub mod abstraction;
/// Composition helpers for combining protocol fragments and analyses.
pub mod composition;
/// Counter-system representations derived from threshold automata.
pub mod counter_system;
/// Equivalence relations and cross-model comparison utilities.
pub mod equivalence;
/// Lowering passes from the DSL AST into the IR.
pub mod lowering;
/// Product constructions used for combined-state analyses.
pub mod product;
/// Property extraction and normalization for verification queries.
pub mod properties;
#[cfg(any(test, feature = "proptest"))]
pub mod proptest_generators;
/// Refinement data structures and helpers for iterative proof workflows.
pub mod refinement;
/// Runtime-trace representations shared by checking and replay code.
pub mod runtime_trace;
/// Core threshold-automaton types, guards, and transitions.
pub mod threshold_automaton;
