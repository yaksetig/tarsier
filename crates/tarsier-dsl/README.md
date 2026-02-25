# tarsier-dsl

PEG parser and AST for the Tarsier protocol specification language.

## Overview

`tarsier-dsl` is the front-end of the Tarsier verification pipeline. It parses
`.trs` protocol specification files into a typed abstract syntax tree (AST)
using a PEG grammar. The resulting AST is consumed by `tarsier-ir` for lowering
into threshold automata, and by `tarsier-codegen` for generating executable
protocol implementations.

## Key Types / API

- `parse(source, filename)` -- Parse a `.trs` source string into a `Program` AST.
  Returns rich `miette` diagnostics on failure.
- `parse_with_diagnostics(source, filename)` -- Like `parse`, but also collects
  non-fatal warnings and lint diagnostics.
- `resolve_imports(program, base_path)` -- Resolve `import` declarations by
  reading referenced files relative to the given base path.
- `ast::Program` -- Top-level AST node containing a single `ProtocolDecl`.
- `ast::ProtocolDecl` -- Protocol declaration with parameters, roles, messages,
  committees, adversary blocks, and properties.
- `ast::RoleDecl` -- A role (process template) with phases, transitions, and
  threshold guards.
- `ast::PropertyDecl` -- Safety or liveness property declaration.

## Usage

```rust,no_run
use tarsier_dsl::{parse, parse_with_diagnostics};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let source = std::fs::read_to_string("examples/reliable_broadcast.trs")?;
let program = parse(&source, "reliable_broadcast.trs")?;

println!("Protocol: {}", program.protocol.node.name);
for role in &program.protocol.node.roles {
    println!("  Role: {}", role.node.name);
}
# Ok(())
# }
```

## Features

| Feature     | Description                          |
|-------------|--------------------------------------|
| `serialize` | Enables `serde::Serialize` on all AST types via the `serde` dependency. |

## Architecture

The parser is built with the [`pest`](https://pest.rs) PEG parser generator.
The grammar is defined in `src/grammar.pest` and compiled at build time by
`pest_derive`. Post-parse AST construction walks the pest parse tree to produce
strongly-typed Rust structs with source spans for error reporting.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
- [Language reference](../../docs/LANGUAGE_REFERENCE.md)
