# tarsier-prob

Hypergeometric probability analysis for committee-based protocols.

## Overview

`tarsier-prob` computes tail bounds for the hypergeometric distribution to
determine the maximum number of Byzantine members that can appear in a randomly
sampled committee. This is used by protocols like Algorand that rely on
committee selection for scalability. The crate plugs into the verification
pipeline to compute concrete fault bounds from committee specifications declared
in `.trs` files, which are then injected into the SMT encoding as additional
constraints.

## Key Types / API

- `CommitteeSpec` -- Specification of a committee selection process: population
  size `N`, Byzantine count `K`, committee size `S`, and target failure
  probability `epsilon`.
- `CommitteeAnalysis` -- Result of analyzing a committee: the maximum Byzantine
  count `b_max` in the committee with probability at least `1 - epsilon`, the
  expected Byzantine count, the actual tail probability, and the honest majority
  guarantee.
- `analyze_committee(spec)` -- Compute `CommitteeAnalysis` from a
  `CommitteeSpec`.
- `HypergeometricParams` -- Validated parameters for the hypergeometric
  distribution: population `n`, defectives `k`, draws `s`.
- `hypergeometric::inverse_survival(params, epsilon)` -- Find the smallest `b`
  such that `P(X > b) <= epsilon`, using exact arithmetic.

## Usage

```rust,no_run
use tarsier_prob::{CommitteeSpec, analyze_committee};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let spec = CommitteeSpec {
    name: "voters".into(),
    population: 1000,
    byzantine: 333,
    committee_size: 100,
    epsilon: 1e-9,
};
let analysis = analyze_committee(&spec)?;
println!("Max Byzantine in committee: {}", analysis.b_max);
println!("Honest majority: {}", analysis.honest_majority);
# Ok(())
# }
```

## Architecture

All intermediate arithmetic uses exact rational numbers (`BigInt` / `BigRational`
from the `num` crate) to avoid floating-point rounding errors in tail probability
computation. The final comparison against `epsilon` uses conservative `next_up`
rounding when converting from `BigRational` to `f64`, ensuring the computed bound
is never optimistic.

## Links

- [Workspace overview](../../README.md)
- [Getting started](../../docs/GETTING_STARTED.md)
- [Parameterized verification](../../docs/PARAMETERIZED_VERIFICATION.md)
