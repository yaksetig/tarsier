#![doc = include_str!("../README.md")]

//! Runtime conformance checking for Tarsier protocol implementations.
//!
//! This crate replays execution traces against a verified protocol model
//! to check that a concrete implementation conforms to the specification.

/// Active conformance-checking workflows that drive live implementations.
pub mod active;
/// Adapters that translate external traces and systems into replay inputs.
pub mod adapters;
/// Core conformance checker entrypoints and verdict computation.
pub mod checker;
/// Corpus and scenario manifests for conformance runs.
pub mod manifest;
/// Network-facing shims used by active replay and integration tests.
pub mod network_shim;
/// Obligation tracking for implementation-side conformance requirements.
pub mod obligations;
/// Replay engines for checking recorded executions against the model.
pub mod replay;
