#![doc = include_str!("../README.md")]

//! SMT encoding and solver integration for threshold automata verification.
//!
//! This crate provides bounded model checking (BMC), k-induction, and
//! property-directed reachability (PDR/IC3) over QF_LIA encodings of
//! counter systems, with pluggable Z3 and cvc5 backends.

pub mod backends;
pub mod bmc;
pub mod encoder;
pub mod solver;
pub mod sorts;
pub mod terms;
