#![doc = include_str!("../README.md")]

//! Tarsier verification engine.
//!
//! This crate orchestrates the full verification pipeline: parsing,
//! lowering, abstraction, SMT solving, counterexample extraction,
//! compositional checking, ByMC `.ta` export, and result reporting.

pub mod compositional;
pub mod counterexample;
pub mod export_ta;
pub mod pipeline;
pub mod result;
pub mod sandbox;
pub mod visualization;

#[cfg(test)]
mod property_pipeline_unit_tests;
