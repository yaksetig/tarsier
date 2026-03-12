# Liveness Verification Guide

This guide covers practical liveness verification in Tarsier: how to model fairness and timing assumptions, when to use each proof engine, and how to debug inconclusive results.

## 1. Pick the Right Fairness Mode

Tarsier supports two fairness assumptions for liveness checking:

- `weak`: a transition that remains continuously enabled must eventually fire.
- `strong`: a transition enabled infinitely often must eventually fire.

Use `weak` by default for throughput/progress obligations under standard scheduler fairness. Use `strong` only when your protocol argument explicitly needs it.

CLI examples:

```bash
# Bounded fair-liveness search (lasso)
tarsier check-fair protocol.trs --fairness weak --max-depth 12

# Unbounded proof/counterexample search
tarsier prove-fair protocol.trs --engine pdr --fairness weak
```

## 2. Model Timing and GST Explicitly

For partial synchrony, encode GST assumptions in the first-class timing block:

```trs
timing {
  model: partial_synchrony;
  gst: GST;
}
```

Guidance:

- Use `partial_synchrony` when liveness depends on eventual delivery.
- Avoid mixing legacy adversary timing keys and first-class timing in the same file.
- Liveness checks under partial synchrony are interpreted on post-GST behavior.

## 3. Choose a Proof Engine

### `--engine pdr`

Best default for unbounded liveness when the model is moderate and fairness monitor state is tractable.

```bash
tarsier prove-fair protocol.trs --engine pdr --fairness weak --machine-readable
```

### `--engine ranking`

Use when PDR does not converge within budget but a ranking argument is expected to exist.

```bash
tarsier prove-fair protocol.trs --engine ranking --fairness weak --machine-readable
```

## 4. Read Machine-Readable Diagnostics

With `--machine-readable`, inspect:

- `details.reason_code`
- `details.convergence.frontier_frame`
- `details.convergence.bound_exhausted`

Common `reason_code` values:

- `timeout`: global timeout reached.
- `memory_budget_exceeded`: memory guardrail triggered.
- `cube_budget_exhausted`: PDR cube budget hit.
- `solver_unknown`: backend returned `unknown`.
- `lasso_recovery_failed`: fair state reachability found, but concrete lasso reconstruction failed.
- `cegar_refinement_inconclusive`: replay/refinement could not confirm or refute witness.

## 5. Troubleshooting Playbook

### Symptom: `Unknown` from PDR

Actions:

1. Increase `--max-depth` (bounded flow) or `--max-k` (unbounded PDR frontiers).
2. Raise timeout and memory budgets.
3. Switch fairness mode only if the model semantics justify it.
4. Try `--engine ranking` for termination-style progress obligations.

### Symptom: unexpected liveness counterexample

Actions:

1. Re-run with `--machine-readable` and capture witness details.
2. Check whether timing/fairness assumptions in the `.trs` match the intended deployment model.
3. Validate that non-goal locations or temporal acceptance sets encode the intended progress condition.

### Symptom: CI regressions in liveness runtime

Actions:

1. Compare benchmark deltas for `pdr_perf` suite.
2. Inspect changes in fairness monitor state size (rules, temporal automaton states, acceptance sets).
3. Re-run the affected protocol with fixed solver/time budgets to isolate modeling vs. engine regressions.

## 6. Recommended Verification Workflow

1. Start with bounded fair-liveness (`check-fair`) to get quick signal.
2. Move to unbounded PDR (`prove-fair --engine pdr`) once bounded checks pass.
3. If PDR is inconclusive, try ranking mode.
4. Keep machine-readable outputs in CI artifacts for regression triage.

## 7. Related References

- `docs/SEMANTICS.md`
- `docs/LANGUAGE_REFERENCE.md`
- `docs/PERFORMANCE.md`
- `docs/PDR_PERFORMANCE_PROFILE.md`
- `docs/CEGAR_LIVENESS_GAP_REPORT.md`
