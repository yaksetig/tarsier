# Tarsier Command Soundness Guide

This is the quick reference for "what does a passing result actually mean?"

Use this document when you want to compare CLI commands by assurance level
without reading the full semantics and trust-boundary documents first.

This guide is intentionally short. It does not replace:

- `docs/SEMANTICS.md` for model semantics and abstraction caveats
- `docs/TRUST_BOUNDARY.md` for the detailed trust model and checker layers

## How to Read Results

The most important distinction is:

- **Bounded search**: no bug was found up to a finite depth or bound.
- **Unbounded proof**: the selected proof engine discharged the property without a finite cutoff.
- **Replay / certificate checking**: previously generated obligations were rechecked independently.
- **Conformance**: observed implementation behavior matched the model for the recorded trace.

These are not interchangeable claims.

## Command-by-Command Summary

| Command | Strongest passing claim | What is still assumed / trusted | When to use it |
|---|---|---|---|
| `analyze` | The report layers that passed are all consistent with the selected `--goal` and `--profile`. `analyze` is an orchestrator, not a separate proof logic. | Strength depends on which layers actually ran: bounded search, unbounded proof, certificate generation, portfolio replay, and profile settings. You still trust the symbolic model, solver results, and any declared fairness/timing assumptions. | Default entry point. Use when you want the tool to choose a sensible workflow for bughunting, safety, or release gating. |
| `verify` | No safety violation was found up to the checked bound. If it returns `UNSAFE`, the counterexample is a bounded witness. | Only a finite depth was checked. Passing does **not** imply unbounded safety. You still trust parsing/lowering/encoding and solver correctness. | Fast bug-finding and CI triage. |
| `liveness` | No bounded liveness violation was found up to the checked bound. | Only a finite prefix/lasso search was explored. Passing does **not** prove eventual progress for all executions. | Fast bounded progress debugging. |
| `fair-liveness` | No bounded fair non-termination witness was found up to the checked bound under the selected fairness mode. | Same bounded caveat as `liveness`, plus the fairness mode is part of the claim. | Bounded liveness debugging when fairness matters. |
| `prove` | The selected unbounded safety engine (`k`-induction, PDR/IC3, or ranking when applicable) proved the safety property for the symbolic model. | You still trust solver soundness, the model/abstraction, and any approximation choices allowed by `--soundness`. This is stronger than `verify`, but it is still a model claim, not a claim about deployed binaries. | When you need an unbounded safety result, not just bounded bug hunting. |
| `prove-round` | Safety was proved on the round-erasure over-approximation. | The claim is about the abstracted model. You must justify that the abstraction preserves the property you care about. | When round variables make direct proving too expensive and the abstraction is acceptable. |
| `prove-fair` | The tool proved fair liveness for the symbolic model under the selected fairness semantics. | Fairness assumptions, timing/GST assumptions, solver soundness, and symbolic-model fidelity remain trusted. This is the strongest liveness-oriented claim Tarsier produces directly. | When you need an unbounded liveness argument, not just a bounded search. |
| `prove-fair-round` | Fair liveness was proved on the round-erasure abstraction under the selected fairness semantics. | Same caveats as `prove-fair`, plus abstraction-preservation assumptions. | When direct fair-liveness proving is too expensive and the round abstraction is justified. |
| `check-certificate` | The certificate bundle replayed successfully and, with `--rederive`, can also be checked against obligations regenerated from source. | Without `--rederive`, this validates the bundle and solver replay, not the source-to-obligation translation. With `--rederive`, you additionally trust the same Tarsier translation stack used to regenerate obligations. | Governance, release, and CI replay for generated proof artifacts. |
| `tarsier-certcheck` | The standalone minimal checker validated bundle integrity and obligation replay with a smaller trusted code base than the full CLI. | You still trust the external solver(s), optional proof checker, and the bundle producer's source-to-obligation mapping. | Highest-assurance bundle replay path when you want to minimize the Tarsier-side TCB. |
| `conformance-check` | The recorded runtime trace is consistent with the model's transition semantics for the events that were observed. | It does **not** prove the implementation is correct in general, only that the supplied trace conforms. Trace completeness and instrumentation fidelity remain trusted. | When you have implementation traces and want to compare them to the verified model. |
| `conformance-suite` | Each manifest entry satisfied its expected conformance outcome under deterministic replay. | Same caveats as `conformance-check`, applied repeatedly across a trace corpus. | Regression suites for implementation/model alignment. |
| `conformance-replay` | The tool generated a process-level replay from a model counterexample and then self-checked that replay against the model. | This is mainly a debugging and integration aid. It does not add assurance beyond the underlying verification result; it checks consistency of replay/concretization. | Debugging, demos, and adapter validation. |
| `codegen` | Generated code came from the selected verified model and, when used with certificate requirements, from a checked proof artifact chain. | Code generation does not itself prove the resulting implementation is correct. Manual implementation work, integration code, and runtime behavior still need review and conformance testing. | When moving from a verified model to implementation scaffolding. |

## Recommended Interpretation Ladder

If you want increasing confidence, use the commands in roughly this order:

1. `analyze` for the default workflow and readable triage.
2. `verify` / `liveness` / `fair-liveness` to find finite bugs quickly.
3. `prove` / `prove-fair` when you need unbounded claims.
4. `check-certificate` or `tarsier-certcheck` when the result must be replayed in CI or governance.
5. `conformance-check` / `conformance-suite` once an implementation exists.

## Common Misreadings

- `SAFE` from `verify` does not mean "proved forever". It means "no witness found up to the explored bound."
- `PROVED` from `prove` or `prove-fair` is a property of the symbolic model under the declared assumptions, not a guarantee about production binaries by itself.
- `PASS` from `conformance-check` means the observed trace matched the model. It does not rule out unobserved bad behaviors.
- Certificate replay validates proof artifacts more independently than rerunning the main pipeline, but it still relies on solver and environment correctness.

## Next Documents

- `docs/TRUST_BOUNDARY.md` for exact checker layers and the trusted computing base
- `docs/SEMANTICS.md` for abstraction and modeling caveats
- `docs/API_STABILITY.md` for which Rust APIs are supported vs provisional
