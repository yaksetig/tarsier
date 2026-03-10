# Invariant Inference Debugging Playbook

This playbook is for `infer-invariants` and `prove --auto-strengthen` when
unbounded safety proofs stall.

## Scope

Use this workflow when:
- `prove` returns `not_proved` for safety;
- `infer-invariants` returns no useful inductive predicates;
- `prove --auto-strengthen` does not improve over baseline.

## Fast Triage Workflow

### 1) Capture baseline proof result

```bash
tarsier prove <file>.trs --engine kinduction --k 12 --format json
```

Check:
- `result`: `safe | unsafe | not_proved | unknown`
- `details.max_k` (for `not_proved`)
- `details.cti` (if present): classification, rationale, violating condition

`details.cti` includes:
- `classification` (`concrete` or likely spurious)
- `classification_evidence`
- `hypothesis` and `violating` snapshots
- `final_step_rules`
- `violated_condition`

### 2) Run invariant inference and inspect distribution

```bash
tarsier infer-invariants <file>.trs --solver z3 --depth 12 --format json
```

Report fields:
- `candidates`: total mined predicates
- `inductive`: predicates satisfying init + consecution
- `init_only`: predicates true at init but not preserved
- `result`: `inductive_invariants_found | no_inductive_invariants | no_candidates`

Guideline:
- `inductive` non-empty: feed these via `prove --auto-strengthen`.
- only `init_only`: model likely needs stronger transition-preserved structure.
- `no_candidates`: candidate miner has little signal from current model/property shape.

### 3) Re-run with auto-strengthening

```bash
tarsier prove <file>.trs --engine kinduction --k 12 --auto-strengthen --format json
```

Compare to baseline:
- did `result` improve (`not_proved -> safe`)?
- did `details.max_k` increase?
- did CTI classification/rationale change?

### 4) Try proof/solver knobs before model edits

```bash
# switch engine
tarsier prove <file>.trs --engine pdr --k 12 --auto-strengthen

# higher budget
tarsier prove <file>.trs --engine kinduction --k 20 --timeout 600 --auto-strengthen

# alternate solver
tarsier infer-invariants <file>.trs --solver cvc5 --depth 12 --timeout 300

# portfolio proof path
tarsier analyze <file>.trs --goal safety --portfolio --format json
```

## Failure Signatures and Actions

| Signature | Interpretation | Next action |
|---|---|---|
| `result=no_candidates` from `infer-invariants` | Candidate miner extracted no usable templates | Verify model has explicit counters/guards linked to safety condition; run with larger `--depth`; inspect property specificity |
| Many `init_only`, few/no `inductive` | Candidates hold initially but fail consecution | Inspect transition rules near CTI violating step; add transition-preserved auxiliary facts |
| `prove --auto-strengthen` unchanged vs baseline | Inferred invariants are too weak or irrelevant | Switch to `pdr`, raise `k/timeout`, compare Z3 vs cvc5 outputs |
| `cti.classification=concrete` | Non-inductiveness is reachable evidence | Prioritize strengthening around CTI `violated_condition` and `final_step_rules` |
| `cti.classification` likely spurious | Over-approx/non-reachable CTI candidate | Increase depth and compare solvers before changing model logic |

## Minimal Repro Bundle for Debugging

When filing an issue or reviewing regressions, attach:
- protocol file (`.trs`)
- baseline proof JSON (`prove --format json`)
- inference JSON (`infer-invariants --format json`)
- auto-strengthen proof JSON (`prove --auto-strengthen --format json`)
- exact CLI commands and solver choice

## Notes

- `infer-invariants` is safety-focused strengthening support. Use
  `prove-fair`/liveness flows for liveness-only protocols.
- Keep comparisons deterministic: same model, same solver, same `k`, same timeout.
