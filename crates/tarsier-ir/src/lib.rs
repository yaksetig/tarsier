#![doc = include_str!("../README.md")]

//! Tarsier intermediate representation and lowering.
//!
//! This crate defines the threshold automaton IR, the lowering pass from the
//! DSL AST to the IR, counter-system abstraction, safety property extraction,
//! and compositional verification data structures.

pub mod abstraction;
pub mod composition;
pub mod counter_system;
pub mod lowering;
pub mod properties;
#[cfg(any(test, feature = "proptest"))]
pub mod proptest_generators;
pub mod runtime_trace;
pub mod threshold_automaton;
