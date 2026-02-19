# Tarsier Trust Boundary

This document states exactly what Tarsier verifies vs what remains trusted.

## 1. Claim Layers

Tarsier outputs are only as strong as the claim layer being used.

| Layer | Typical command | What is verified | What is still trusted |
|---|---|---|---|
| Certificate integrity | `tarsier-certcheck <bundle>` (or `check-certificate`) | `certificate.json` schema/profile checks, safe paths, per-obligation SHA256, bundle hash, SMT script sanity checks | The producer of the bundle selected the right obligations for the intended theorem |
| SMT replay | `--solvers z3,cvc5` | Each obligation result matches expected outcome under external solver replay | Solver correctness (`sat/unsat/unknown`) |
| Multi-solver replay | `--require-two-solvers` | At least two distinct solvers replay the same obligations | Common-mode solver bugs, environment integrity |
| Proof-object path (optional) | `--emit-proofs --require-proofs --proof-checker ...` | Proof objects are emitted, structurally checked, and optionally validated by external checker command | Completeness/soundness of the proof checker implementation and proof format semantics |
| Source->obligation consistency (same toolchain) | `tarsier-cli check-certificate --rederive` | Bundle obligations match freshly regenerated obligations from source | Parser/lowering/encoding implementation correctness (same Tarsier stack) |

## 2. Trusted Computing Base (TCB)

### 2.1 Bundle Replay Mode (`tarsier-certcheck`)

Trusted:

- `tarsier-proof-kernel` integrity logic
- `tarsier-certcheck` replay logic
- External solver binaries (`z3`, `cvc5`, or configured solver)
- Optional proof checker executable when `--proof-checker` is used
- Runtime/OS/filesystem integrity

Not required in this mode:

- Tarsier parser/lowering/SMT encoder/engine internals

### 2.2 Re-derivation Mode (`tarsier-cli check-certificate --rederive`)

Trusted:

- All of the above, plus parser/lowering/encoder/engine used to regenerate obligations

Benefit:

- Detects bundle tampering or mismatch from source at check time

Limitation:

- Re-derivation uses the same implementation family; it is not an independent translation validator.

## 3. What “Verified” Means

When a certificate check passes, the strongest direct statement is:

- “The checked SMT obligations replayed as expected under the selected solver configuration.”

Additional assumptions are needed to conclude:

- “The source model satisfies the intended protocol theorem,” and
- “The model faithfully represents the deployed protocol/network/crypto environment.”

Those assumptions include semantics mapping, abstraction choices, fairness/timing settings, and DSL modeling fidelity.

See:

- `docs/SEMANTICS.md` for semantics and abstraction-transfer caveats
- `docs/CERTIFICATE_SCHEMA.md` for certificate profile/integrity contract

## 4. Optional Proof-Object Path Scope

Current proof-object validation in CI uses:

- proof extraction from supported solvers (`z3`, `cvc5`)
- structural/non-empty checks (`--require-proofs`)
- external checker command (`.github/scripts/check_proof_object.py`)

This improves assurance against malformed proof output, but is not yet a full formally verified proof checker for SMT proof calculi.

## 5. Recommended Production Profile

For high-assurance CI replay:

```bash
cargo run -p tarsier-certcheck -- certs/<bundle> \
  --solvers z3,cvc5 \
  --require-two-solvers \
  --emit-proofs certs/<bundle>/proofs \
  --require-proofs \
  --proof-checker .github/scripts/check_proof_object.py \
  --json-report certs/<bundle>/certcheck-report.json
```

For source-bound replay (same toolchain regeneration check):

```bash
cargo run -p tarsier-cli -- check-certificate certs/<bundle> \
  --solvers z3,cvc5 \
  --rederive \
  --trusted-check \
  --min-solvers 2 \
  --proof-checker .github/scripts/check_proof_object.py
```
