#![doc = include_str!("../README.md")]

//! Tarsier DSL parser and abstract syntax tree.
//!
//! This crate implements the PEG parser for `.trs` protocol specification
//! files and defines the AST types that represent parsed protocol models
//! including roles, phases, threshold guards, adversary blocks, and properties.

pub mod ast;
pub mod errors;
pub mod parser;

pub use parser::parse;
pub use parser::parse_with_diagnostics;
pub use parser::resolve_imports;
