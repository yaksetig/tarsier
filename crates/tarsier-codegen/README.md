# tarsier-codegen

Code generation from verified protocol specifications.

## Overview

`tarsier-codegen` generates executable Rust and Go implementation skeletons
from parsed `.trs` protocol models. The generated code includes process state
machines, message type definitions, threshold guard checks, and network
interface traits. When a verified certificate bundle is available, provenance
headers are embedded in the output to link the generated code back to the
formally verified model.

## Key Types / API

- `generate(program, target)` -- Generate skeleton implementation code from a
  parsed `.trs` program for the given `CodegenTarget`. Returns the generated
  source as a `String`.
- `generate_with_provenance(program, target, provenance)` -- Like `generate`,
  but prepends provenance annotation comments (`@tarsier-provenance`) linking
  the generated code to the verified model and certificate.
- `CodegenTarget` -- Enum: `Rust` or `Go`.
- `CodegenError` -- Error type: `NoProtocol`, `NoRoles`, or `Unsupported`.
- `ProvenanceInfo` -- Provenance metadata: model SHA-256, options SHA-256,
  certificate reference, verification status, and optional audit tag.
- `rust_gen` module -- Rust-specific code generation backend.
- `go_gen` module -- Go-specific code generation backend.
- `trace_hooks` module -- Generates runtime trace hook instrumentation for
  conformance checking.

## Usage

```rust,no_run
use tarsier_codegen::{generate, CodegenTarget};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let source = std::fs::read_to_string("protocol.trs")?;
let program = tarsier_dsl::parse(&source, "protocol.trs")?;
let rust_code = generate(&program, CodegenTarget::Rust)?;
std::fs::write("protocol_generated.rs", &rust_code)?;
# Ok(())
# }
```

Or via the CLI:

```bash
tarsier codegen protocol.trs --target rust --out protocol_generated.rs
```

## Architecture

Each backend walks the protocol AST to emit target-language constructs: struct
definitions for configuration and process state, enums for phases and messages,
a `handle_message` dispatch function with threshold guard checks, and a
`Network` trait (Rust) or interface (Go) for message sending. Crypto object
fields, distinct-sender guards, and committee specifications are all translated
into idiomatic target-language patterns.

## Links

- [Workspace overview](../../README.md)
- [Codegen documentation](../../docs/CODEGEN.md)
- [Getting started](../../docs/GETTING_STARTED.md)
