#![doc = include_str!("../README.md")]

//! Tarsier DSL parser and abstract syntax tree.
//!
//! This crate implements the PEG parser for `.trs` protocol specification
//! files and defines the AST types that represent parsed protocol models
//! including roles, phases, threshold guards, adversary blocks, and properties.

/// Abstract syntax tree nodes for parsed `.trs` programs.
pub mod ast;
/// Parser and lowering error types with source-span diagnostics.
pub mod errors;
mod parser;

/// Parse a `.trs` source string into a [`crate::ast::Program`].
///
/// # Examples
///
/// ```rust
/// use tarsier_dsl::parse;
///
/// let source = r#"
/// protocol Tiny {
///     params n, t, f;
///     resilience: n > 3*t;
///
///     adversary {
///         model: byzantine;
///         bound: f;
///     }
///
///     role R {
///         var decided: bool = true;
///         init done;
///         phase done {}
///     }
///
///     property inv: safety {
///         forall p: R. p.decided == true
///     }
/// }
/// "#;
///
/// let program = parse(source, "tiny.trs")?;
/// assert_eq!(program.protocol.node.name, "Tiny");
/// # Ok::<(), tarsier_dsl::errors::ParseError>(())
/// ```
pub use parser::parse;
/// Parse a `.trs` source string and return non-fatal parser diagnostics.
pub use parser::parse_with_diagnostics;
/// Resolve `import` declarations in a parsed program relative to `base_dir`.
pub use parser::resolve_imports;
