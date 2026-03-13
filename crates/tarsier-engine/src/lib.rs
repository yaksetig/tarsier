#![doc = include_str!("../README.md")]

//! Tarsier verification engine.
//!
//! This crate orchestrates the full verification pipeline: parsing,
//! lowering, abstraction, SMT solving, counterexample extraction,
//! compositional checking, ByMC `.ta` export, and result reporting.

/// Compositional verification orchestration and decomposition helpers.
pub mod compositional;
/// Counterexample extraction, normalization, and rendering support.
pub mod counterexample;
/// Export paths for threshold-automaton interchange formats.
pub mod export_ta;
/// End-to-end verification and proof pipelines.
pub mod pipeline;
/// Structured result types emitted by engine workflows.
pub mod result;
/// Solver sandboxing and process-isolation helpers.
pub mod sandbox;
/// Visualization helpers for traces, automata, and reports.
pub mod visualization;

#[cfg(test)]
mod property_pipeline_unit_tests;
