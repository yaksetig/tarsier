# tarsier-engine

Verification engine with BMC, k-induction, PDR, and CEGAR.

## Overview

`tarsier-engine` is the main orchestration layer of the Tarsier pipeline. It
wires together parsing (`tarsier-dsl`), lowering and abstraction (`tarsier-ir`),
SMT solving (`tarsier-smt`), and probabilistic analysis (`tarsier-prob`) into
a unified verification workflow. The engine supports bounded model checking,
unbounded safety proofs via k-induction and PDR/IC3, liveness checking under
fairness assumptions, CEGAR-based counterexample refinement, portfolio solving,
and proof certificate generation.

## Key Types / API

- `pipeline::verify(source, filename, options)` -- Run bounded model checking
  and return a `VerificationResult` with a counterexample trace or safe-up-to
  depth.
- `pipeline::prove_safety(source, filename, options)` -- Prove unbounded safety
  via k-induction or PDR, returning `UnboundedSafetyResult`.
- `pipeline::prove_fair_liveness(source, filename, options)` -- Prove liveness
  under weak or strong fairness, returning `UnboundedFairLivenessResult`.
- `pipeline::check_liveness(source, filename, options)` -- Check bounded
  liveness properties, returning `LivenessResult`.
- `result::VerificationResult` -- BMC outcome: `Safe`, `Unsafe(trace)`,
  `ProbabilisticallySafe`, or `Unknown`.
- `result::UnboundedSafetyResult` -- Unbounded proof outcome: `Proved(k)`,
  `Disproved(trace)`, `Inconclusive`, or `Unknown`.
- `counterexample::extract_trace(model, system)` -- Extract a concrete
  counterexample trace from a SAT model.
- `export_ta` module -- Export threshold automata to ByMC `.ta` format for
  cross-tool verification.
- `sandbox` module -- Resource limits (wall-clock timeout, RSS memory cap,
  input size cap) for untrusted input.

## Usage

```rust,no_run
use tarsier_engine::pipeline::{verify, SolverChoice, SoundnessMode, PipelineOptions};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let options = PipelineOptions::default();
let source = std::fs::read_to_string("protocol.trs")?;
let result = verify(&source, "protocol.trs", &options)?;
println!("{}", result);
# Ok(())
# }
```

## Architecture

The engine follows a layered pipeline: parse, lower, abstract, encode, solve.
Each layer produces artifacts consumed by the next. CEGAR adds a refinement loop
that re-encodes with additional predicates when spurious counterexamples are
detected. Portfolio mode runs Z3 and CVC5 in parallel and combines results
conservatively. Certificate generation emits SMT-LIB scripts with SHA-256
integrity hashes for offline replay.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
- [Trust boundary](../../docs/TRUST_BOUNDARY.md)
