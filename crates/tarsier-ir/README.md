# tarsier-ir

Intermediate representation and lowering for threshold automata.

## Overview

`tarsier-ir` defines the core intermediate representation used throughout the
Tarsier verification pipeline. It lowers the parsed DSL AST into threshold
automata (locations, rules, guards, shared variables), then abstracts those
automata into counter systems suitable for SMT-based model checking. This crate
also extracts safety and liveness properties from the AST and supports
compositional verification through module interfaces.

## Key Types / API

- `ThresholdAutomaton` -- The central IR type: locations, rules with threshold
  guards, shared variables, symbolic parameters, fault model, and timing model.
- `CounterSystem` -- Counter-abstracted view of a threshold automaton, tracking
  process counts per location (`kappa`) and shared variable values (`gamma`).
- `lowering::lower(protocol, source, filename)` -- Lower a `ProtocolDecl` AST
  into a `ThresholdAutomaton`. Reports `SpannedLoweringError` with source spans.
- `abstraction::abstract_to_counter_system(automaton)` -- Wrap a threshold
  automaton in a `CounterSystem` for BMC encoding.
- `properties::extract_agreement_property(automaton, property)` -- Extract a
  `SafetyProperty` from a named property declaration.
- `composition` module -- Data structures for compositional verification with
  assume/guarantee module interfaces.

## Usage

```rust,ignore
use tarsier_dsl::parse;
use tarsier_ir::lowering::lower;
use tarsier_ir::abstraction::abstract_to_counter_system;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let program = parse(&source, "protocol.trs")?;
let automaton = lower(&program.protocol.node, &source, "protocol.trs")?;
let counter_system = abstract_to_counter_system(automaton);

println!("Locations: {}", counter_system.num_locations());
println!("Shared vars: {}", counter_system.num_shared_vars());
println!("Rules: {}", counter_system.num_rules());
# Ok(())
# }
```

## Features

| Feature    | Description                                               |
|------------|-----------------------------------------------------------|
| `serialize`| Enables serde `Serialize`/`Deserialize` on IR types.      |
| `proptest` | Exposes `proptest_generators` module for property testing. |

## Architecture

Lowering translates each DSL role into a set of locations (one per phase) and
rules (one per guarded transition). Threshold guards become linear constraints
over symbolic parameters (`n`, `t`, `f`). The fault model (Byzantine, crash,
omission) and timing assumptions (asynchronous, partial synchrony) are encoded
as metadata on the automaton. Counter abstraction replaces per-process state
with aggregate counters, which is sound for the symmetric fault models used by
threshold automata.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
- [Language reference](../../docs/LANGUAGE_REFERENCE.md)
- [Semantics](../../docs/SEMANTICS.md)
