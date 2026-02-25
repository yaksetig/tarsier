# tarsier-smt

SMT encoding and solver backends for threshold automata verification.

## Overview

`tarsier-smt` encodes counter systems as quantifier-free linear integer
arithmetic (QF_LIA) SMT formulas and provides solver backends for checking
satisfiability. It implements bounded model checking (BMC), k-induction, and
property-directed reachability (PDR/IC3) as verification algorithms over the
encoded transition relation. This crate sits between `tarsier-ir` (which
provides the counter system) and `tarsier-engine` (which orchestrates the
full pipeline).

## Key Types / API

- `encoder::BmcEncoding` -- Variable declarations, assertions, and model
  extraction metadata for a BMC encoding of a counter system.
- `encoder::encode_bmc(system, depth, property)` -- Encode a bounded model
  checking query up to a given depth.
- `encoder::encode_k_induction_step(system, k, property)` -- Encode the
  inductive step for k-induction at depth `k`.
- `bmc::run_bmc_with_deadline(system, property, depth, deadline)` -- Run BMC
  with a wall-clock deadline, returning `BmcResult`.
- `bmc::run_k_induction_with_deadline(...)` -- Run k-induction up to depth `k`.
- `bmc::run_pdr_with_deadline(...)` -- Run PDR/IC3 with invariant synthesis.
- `solver::SmtSolver` trait -- Abstract solver interface with `declare_var`,
  `assert`, `check_sat`, and `get_model` methods.
- `solver::SatResult` -- Enum: `Sat`, `Unsat`, or `Unknown(reason)`.
- `backends::z3_backend::Z3Solver` -- Z3 backend via the `z3` crate.
- `backends::cvc5_backend::Cvc5Solver` -- CVC5 backend via SMT-LIB pipes.
- `backends::smtlib_printer::to_smtlib(encoding)` -- Serialize an encoding to
  a standalone `.smt2` script for certificate bundles and debugging.

## Usage

```rust,ignore
use tarsier_smt::bmc::{run_bmc_with_deadline, BmcResult};
use std::time::{Duration, Instant};

let deadline = Instant::now() + Duration::from_secs(60);
let result = run_bmc_with_deadline(&counter_system, &property, 10, Some(deadline));

match result {
    BmcResult::Unsafe(trace) => println!("Counterexample found"),
    BmcResult::Safe(depth) => println!("Safe up to depth {}", depth),
    BmcResult::Unknown(reason) => println!("Unknown: {}", reason),
}
```

## Architecture

Encodings are constructed as abstract `SmtTerm` / `SmtSort` trees, decoupled
from any particular solver. The `SmtSolver` trait allows plugging in different
backends. The Z3 backend uses the `z3` crate (v0.19) with static linking; the
CVC5 backend communicates via SMT-LIB 2 over stdin/stdout pipes. Incremental
solving, assertion deduplication, and partial-order reduction are used to
improve performance on large protocol models.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
