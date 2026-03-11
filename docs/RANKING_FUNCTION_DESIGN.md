# Ranking Function Framework Design (LRANK-01)

> Design document for ranking function synthesis as an alternative liveness
> proof strategy alongside PDR/IC3.

## 1. Motivation

The fair PDR engine proves liveness by showing no fair cycle exists in the
abstract state space. When PDR doesn't converge within budget (too many cubes,
too many frames), we need an alternative: **ranking functions**.

A ranking function `r(s)` maps states to a well-founded domain (typically ℕ)
such that:
1. `r(s) ≥ 0` for all reachable states
2. Under any fair execution step `s → s'`, `r(s) > r(s')` (strict decrease)
3. Therefore, no infinite fair execution exists (termination)

## 2. Ranking Template Types

### 2.1 Linear Ranking Functions

Template: `r(s) = c₀ + c₁·κ₁ + c₂·κ₂ + ... + cₙ·κₙ + d₁·γ₁ + ... + dₘ·γₘ`

Where:
- `κᵢ` are location counter variables
- `γⱼ` are shared variable values
- `cᵢ, dⱼ` are integer coefficients to synthesize

**SMT synthesis query** (∀-∃ form, reduced to ∃ via Farkas' lemma):

```
∃ c₀, c₁, ..., cₙ, d₁, ..., dₘ ∈ ℤ :
  ∀ s, s' satisfying transition(s, s') ∧ fair(s, s') :
    r(s) ≥ 0 ∧ r(s) - r(s') ≥ 1
```

For counter systems, the transition relation is already in QF_LIA, so we can
encode the Farkas dual directly.

### 2.2 Lexicographic Ranking Functions

When no single linear ranking function exists, use a tuple:
`R(s) = (r₁(s), r₂(s), ..., rₖ(s))` with lexicographic ordering.

Each component `rᵢ` is a linear template. The synthesis query becomes:
- For component `rᵢ`: either `rᵢ(s) > rᵢ(s')`, or `rᵢ(s) = rᵢ(s')` and
  the next component decreases.

### 2.3 Piecewise Linear Ranking Functions

Partition the state space into regions and synthesize a different linear
function per region. Useful when different protocol phases have different
progress measures.

Template: `r(s) = rⱼ(s)` where `s ∈ Regionⱼ`

Regions defined by guard conditions from the threshold automaton's rule
guards (natural partitioning).

## 3. Integration Architecture

### 3.1 New Module Location

```
crates/tarsier-engine/src/pipeline/verification/ranking.rs
```

### 3.2 Entry Point

```rust
pub(crate) fn try_ranking_function_proof<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    target: &FairLivenessTarget,
    fairness: FairnessMode,
    config: RankingConfig,
    deadline: Option<Instant>,
) -> Result<RankingResult, PipelineError>
```

### 3.3 Result Type

```rust
pub enum RankingResult {
    /// A ranking function was found, proving liveness.
    LiveProved {
        /// The synthesized ranking function coefficients.
        ranking: RankingFunction,
    },
    /// No ranking function found within the given template family.
    NotFound {
        /// Templates attempted.
        templates_tried: Vec<String>,
    },
    /// Search exceeded resource budget.
    Unknown { reason: String },
}

pub enum RankingFunction {
    Linear {
        /// Coefficients for location counters and shared vars.
        coefficients: Vec<(String, i64)>,
        constant: i64,
    },
    Lexicographic {
        components: Vec<RankingFunction>,
    },
}
```

### 3.4 Pipeline Integration

The ranking proof mode would be invoked:
1. As a fallback when PDR times out or exceeds cube budget
2. Directly via CLI: `tarsier prove --engine ranking --property liveness ...`
3. As part of a portfolio strategy: try PDR first, fall back to ranking

```rust
// In pipeline/verification/orchestration.rs
match run_unbounded_fair_pdr(solver, cs, max_k, target, ...) {
    Ok(UnboundedFairLivenessResult::Unknown { .. }) => {
        // PDR didn't converge — try ranking function synthesis
        try_ranking_function_proof(solver, cs, target, fairness, config, deadline)
    }
    other => other,
}
```

### 3.5 Certificate Output

A ranking function proof produces a certificate with:
- `kind: "fair_liveness_proof"`
- `proof_engine: "ranking"`
- Obligations:
  - `ranking_nonnegativity`: SMT script asserting `r(s) < 0` is UNSAT for reachable states
  - `ranking_decrease`: SMT script asserting `r(s) ≤ r(s')` under fair transitions is UNSAT

This requires extending the proof kernel's obligation profiles (currently only
`kinduction` and `pdr` are supported for liveness).

## 4. SMT Encoding Details

### 4.1 Linear Ranking Synthesis via Farkas' Lemma

The transition relation `T(s, s')` is a conjunction of linear constraints
(QF_LIA). By Farkas' lemma, `T(s, s') → r(s) - r(s') ≥ 1` holds iff there
exist non-negative multipliers `λᵢ ≥ 0` such that:

```
r(s) - r(s') - 1 = Σᵢ λᵢ · constraintᵢ(s, s')
```

This eliminates the universal quantifier, giving a purely existential query
over `(c₀, ..., cₙ, d₁, ..., dₘ, λ₁, ..., λₖ)`.

### 4.2 Fairness Integration

Under weak fairness, the decrease condition applies to transitions where:
- The rule is continuously enabled in the current state, AND
- The rule fires

Under strong fairness:
- The rule is enabled at some point in the current macro-step, AND
- The rule fires

The fairness condition is already encoded in the monitor variables, so we
conjoin the fairness constraint with the transition relation before applying
Farkas.

### 4.3 Counter Abstraction Compatibility

Ranking functions over counter-abstracted systems rank counter configurations,
not individual process states. This is sound: if the abstract system terminates
under fair scheduling, so does the concrete system (counter abstraction
preserves termination for threshold automata).

## 5. Implementation Plan

### Phase 1 (LRANK-02): Linear Ranking Synthesis
- Implement `RankingConfig` with template size bounds
- Encode Farkas dual for each transition rule
- Combine with fairness monitor constraints
- Extract coefficients from SAT model
- Add unit tests on trivial_live.trs and reliable_broadcast_safe_live.trs

### Phase 2 (LRANK-03): CLI Integration + Certificates
- Add `--engine ranking` flag to `prove` command
- Extend proof kernel obligation profiles for `ranking` engine
- Generate ranking proof certificates
- Add integration tests

### Phase 3 (Future): Lexicographic + Piecewise
- Iterative synthesis: try linear, then 2-component lex, then 3-component
- Piecewise: partition by rule guard regions
- Portfolio: PDR + ranking in parallel

## 6. Risks

1. **Farkas encoding size**: For protocols with many rules (>30), the dual
   encoding has many multiplier variables. Mitigate with rule grouping.
2. **Non-linear guards**: Threshold comparisons like `received >= 2*t+1` make
   Farkas' lemma inapplicable directly. Mitigate by treating parameters as
   fixed constants during synthesis.
3. **Soundness of counter abstraction for ranking**: Well-established for
   threshold automata (Konnov et al., 2017) but needs explicit documentation.
