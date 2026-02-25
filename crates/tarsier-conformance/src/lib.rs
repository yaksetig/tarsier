#![doc = include_str!("../README.md")]

//! Runtime conformance checking for Tarsier protocol implementations.
//!
//! This crate replays execution traces against a verified protocol model
//! to check that a concrete implementation conforms to the specification.

pub mod adapters;
pub mod checker;
pub mod manifest;
pub mod obligations;
pub mod replay;
