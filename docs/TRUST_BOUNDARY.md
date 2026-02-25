# Tarsier Trust Boundary

This document states exactly what Tarsier verifies vs what remains trusted.

## 1. Claim Layers

Tarsier outputs are only as strong as the claim layer being used.

| Layer | Typical command | What is verified | What is still trusted |
|---|---|---|---|
| Certificate integrity | `tarsier-certcheck <bundle>` (or `check-certificate`) | `certificate.json` schema/profile checks, safe paths, per-obligation SHA256, bundle hash, SMT script sanity checks | The producer of the bundle selected the right obligations for the intended theorem |
| SMT replay | `--solvers z3,cvc5` | Each obligation result matches expected outcome under external solver replay | Solver correctness (`sat/unsat/unknown`) |
| Multi-solver replay | `--require-two-solvers` | At least two distinct solvers replay the same obligations | Common-mode solver bugs, environment integrity |
| Proof-object path (optional) | `--emit-proofs --require-proofs --proof-checker ...` | Proof objects are emitted, structurally checked, replay-validated by the solver, and (for cvc5) externally checked with Carcara when available | Completeness/soundness of solver/proof-checker implementations and proof format semantics |
| Source->obligation consistency (same toolchain) | `tarsier-cli check-certificate --rederive` | Bundle obligations match freshly regenerated obligations from source | Parser/lowering/encoding implementation correctness (same Tarsier stack) |
| Legacy-vs-tiny differential parity | `.github/scripts/check_checker_differential.py` | Outcome parity across a shared checker corpus between `check-certificate` and `tarsier-certcheck` | Shared bugs in both checker implementations, solver correctness |

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
- `docs/KERNEL_SPEC.md` for formal proof kernel specification and obligation-to-check mapping
- `docs/CHECKER_SOUNDNESS_ARGUMENT.md` for explicit checker assumptions/non-goals and machine-checked subset proof artifacts
- `docs/checker-differential-corpus-v1.json` and `docs/checker-differential-allowlist-v1.json` for differential-checker parity corpus and allowlisted divergence rationale

## 3.1 Differential Checker Parity Gate

To guard against silent drift between the legacy checker path and the tiny standalone checker, CI runs a differential parity gate:

- script: `.github/scripts/check_checker_differential.py`
- corpus: `docs/checker-differential-corpus-v1.json`
- divergence allowlist: `docs/checker-differential-allowlist-v1.json`

Contract:
- each corpus case is replayed through both `tarsier check-certificate` and `tarsier-certcheck`;
- outcomes are compared as `pass`/`fail`;
- any divergence fails CI unless explicitly allowlisted with a non-empty rationale;
- stale allowlist entries (no longer matching an observed divergence) also fail CI.

## 4. Optional Proof-Object Path Scope

Current proof-object validation in CI uses:

- proof extraction from supported solvers (`z3`, `cvc5`)
- structural/non-empty checks (`--require-proofs`)
- solver-backed replay checks (`z3` self-check + `cvc5 --check-proofs`)
- external checker command (`.github/scripts/check_proof_object.py`)
- external Alethe proof checking for cvc5 proofs via Carcara (`TARSIER_REQUIRE_CARCARA=1` in CI proof gates)

This materially improves assurance against malformed or inconsistent proof streams, but is still not a fully formally verified proof checker stack for all SMT proof calculi.

## 5. Named Governance Profiles

Governance profiles provide named presets for certificate checking rigor. Each profile sets a floor; explicit flags can only strengthen requirements.

| Profile | Min Solvers | Require Proofs | Require Proof Checker | Equivalent Flags |
|---------|-------------|----------------|----------------------|------------------|
| `standard` | 1 | No | No | (default) |
| `reinforced` | 2 | Yes | No | `--require-two-solvers --require-proofs` |
| `high-assurance` | 2 | Yes | Yes | `--require-two-solvers --require-proofs --proof-checker <path>` + `cvc5` in `--solvers` + `TARSIER_REQUIRE_CARCARA=1` |

Usage examples:

```bash
# Standard: single solver, no proof objects
tarsier-certcheck certs/bundle --profile standard --solvers z3

# Reinforced: two solvers, proof objects required
tarsier-certcheck certs/bundle --profile reinforced --solvers z3,cvc5

# High-assurance: two solvers, proof objects, external checker, mandatory Carcara gate
TARSIER_REQUIRE_CARCARA=1 tarsier-certcheck certs/bundle --profile high-assurance --solvers z3,cvc5 \
  --proof-checker .github/scripts/check_proof_object.py
```

## 6. Residual Trust Assumptions

Even with a fully passing certificate check, the following assumptions remain:

1. **Solver correctness** — Each solver's `sat`/`unsat`/`unknown` result is assumed correct. Mitigated by multi-solver replay (reinforced/high-assurance profiles), but not eliminated.
2. **Proof checker soundness** — The external proof checker (when used) is assumed sound. It is not itself formally verified.
3. **Modeling fidelity** — The `.trs` source file is assumed to faithfully represent the real protocol, network, and cryptographic environment. This is a manual audit concern.
4. **Toolchain correctness** — The Rust compiler, `serde` serialization, and SHA-256 implementation are assumed correct.
5. **Environment integrity** — The operating system, filesystem, and CPU are assumed to execute as specified.
6. **Domain tag uniqueness** — The `tarsier-certificate-v2\n` prefix used in bundle hash computation is assumed unique across all Tarsier-related hashing contexts.
7. **Obligation-theorem correspondence** — The structural obligation profiles (e.g., base case + inductive step for k-induction) are assumed to correspond to valid proof decompositions. The checker validates structure, not semantic correctness of the decomposition.

## 7. What Is NOT Verified

| Gap | Description | Mitigation |
|-----|-------------|------------|
| SMT content vs intended theorem | The checker verifies that obligations are `unsat` but not that they encode the intended property | Re-derivation mode (`--rederive`), manual audit |
| Protocol model faithfulness | Whether the `.trs` model matches the real deployed protocol | Manual audit, `docs/SEMANTICS.md` |
| Solver soundness bugs | A solver could have a correctness bug returning wrong `unsat` | Multi-solver replay, proof objects |
| TOCTOU between generation and checking | Bundle files could be modified between generation and checking | Per-obligation SHA256 hashes, bundle hash |
| Certificate provenance | No source-file hash is included in the bundle | Re-derivation mode compares against source |
| Solver network/filesystem isolation | Solver subprocesses are not OS-sandboxed (no seccomp/landlock/AppArmor) | Design invariant: solvers do not initiate connections or write to disk; pinned versions in CI |

## 7.1 Cryptography Scope Boundary

Cryptography-related claims in Tarsier are symbolic-model claims, not computational cryptography proofs.

| Category | In Scope (verified in model) | Out of Scope (explicit non-goal) |
|---|---|---|
| Signing authority | Identity/key ownership constraints and compromise-gated signing admissibility | Key-generation entropy quality, key-management process correctness |
| Non-forgeability | SMT constraints forbid forged signed traffic from uncompromised honest identities | EUF-CMA style reduction proofs and concrete security margins |
| Threshold certificates/QCs | Signer-set threshold and conflict admissibility constraints over symbolic witnesses | Real signature scheme algebra, aggregation implementation correctness |
| Security interpretation | "SAFE/PROVED" under declared symbolic assumptions and abstractions | End-to-end computational guarantee for deployed binaries/protocol stacks |

Use this interpretation consistently in reports and governance: Tarsier outputs certify properties of the declared symbolic model; they do not replace computational cryptographic analysis.

## 8. Threat Model Summary

| Threat Category | Attack Vector | Countermeasure |
|----------------|---------------|----------------|
| Tampering | Modify obligation `.smt2` files after generation | Per-obligation SHA256 hashes |
| Tampering | Modify `certificate.json` metadata fields | Deterministic `bundle_sha256` covering all metadata + obligation hashes |
| Tampering | Inject unknown fields into metadata | `deny_unknown_fields` in `serde` deserialization |
| Soundness | Single solver returns incorrect result | Multi-solver replay (`--require-two-solvers`) |
| Soundness | Solver produces trivial/empty proof object | Proof object structural validation (`--require-proofs`), external checker |
| Modeling | Source model does not match real protocol | Manual audit, `docs/SEMANTICS.md` |
| Supply chain | Compromised solver binary | Pinned solver versions in CI, solver version recording in reports |
| Supply chain | Checker binary depends on untrusted code | Minimal dependency boundary (`tarsier-certcheck` depends only on `tarsier-proof-kernel`) |
| Replay evasion | Skipping certificate checks in CI | CI gates, governance profiles as named enforcement levels |
| Resource exhaustion | Malicious input causes unbounded CPU/memory consumption | Runtime sandbox: wall-clock timeout, RSS memory budget, input size limit (fail-closed) |
| Solver escape | Compromised solver binary exfiltrates data via network or filesystem | Design invariant (not OS-enforced); mitigated by pinned solver versions with SHA256-verified downloads |
| Trust report provenance | Modify or forge trust-report.json after generation | Cosign keyless signature tied to CI workflow OIDC identity |

## 9. Recommended Production Profile

For high-assurance CI replay:

```bash
TARSIER_REQUIRE_CARCARA=1 cargo run -p tarsier-certcheck -- certs/<bundle> \
  --profile high-assurance \
  --solvers z3,cvc5 \
  --emit-proofs certs/<bundle>/proofs \
  --proof-checker .github/scripts/check_proof_object.py \
  --json-report certs/<bundle>/certcheck-report.json
```

For source-bound replay (same toolchain regeneration check):

```bash
cargo run -p tarsier-cli -- check-certificate certs/<bundle> \
  --profile reinforced \
  --solvers z3,cvc5 \
  --rederive \
  --trusted-check \
  --min-solvers 2 \
  --proof-checker .github/scripts/check_proof_object.py
```

## 10. Conformance Assurance Extension

The `tarsier-conformance` crate extends the trust boundary from verified models to implementation behavior. It validates runtime traces against model semantics without requiring the SMT verification stack.

### What Conformance Proves vs Does Not Prove

| Aspect | What conformance proves | What it does NOT prove |
|--------|------------------------|------------------------|
| Transition validity | Each observed transition matches a model rule with satisfied guard | Guard evaluation uses simplified arithmetic, not full SMT |
| Message ordering | Message sends/receives match model shared-var updates | Network timing/reordering fidelity |
| Property obligations | Runtime monitor definitions match verified model properties | Implementation correctly triggers monitors |
| Trace completeness | All recorded events are validated | Unrecorded events are invisible |

### Trust Boundary

The conformance layer has a strict dependency boundary:

- **Depends on:** `tarsier-ir` (types only), `tarsier-dsl`, `serde`/`serde_json`
- **Does NOT depend on:** `tarsier-smt`, `tarsier-engine`, `tarsier-prob`, `z3`

This means conformance checking can be performed independently of the verification infrastructure, with a minimal TCB.

### Conformance Checking Is Not a Formal Guarantee

Conformance checking validates that observed implementation behavior is *consistent with* the model. It does not prove:

1. **Completeness** — The implementation may have behaviors not captured in traces
2. **Faithful recording** — The trace recorder must be correctly instrumented
3. **Full guard semantics** — Guard evaluation uses concrete arithmetic, which is sound but may differ from SMT-level reasoning in edge cases involving adversary behavior
4. **Liveness** — Conformance checking validates safety-style properties only

See `docs/CONFORMANCE.md` for full usage documentation.

## 11. Verified Code Generation Trust Boundary

Code generation (`tarsier codegen`) extends the trust chain from verified models to implementation skeletons. By default, codegen requires a valid certificate bundle before generating code.

### Trust Chain

```
.trs source → verification → certificate → codegen → skeleton implementation
```

Each link in this chain is checked:

1. **Source → Verification:** BMC/k-induction proves safety/liveness properties
2. **Verification → Certificate:** Proof obligations and solver results are recorded in a signed bundle
3. **Certificate → Codegen:** Bundle integrity and obligation status are checked before generation
4. **Codegen → Skeleton:** Generated code faithfully represents the verified model's protocol logic

### What Codegen Guarantees vs Does Not Guarantee

| Aspect | Guaranteed | Not Guaranteed |
|--------|-----------|----------------|
| Protocol logic fidelity | Generated phases, guards, transitions, actions match the `.trs` model | Optimality or efficiency of generated code |
| Unsupported feature rejection | Fail-fast error for committee, channel, equivocation, identity constructs | Support for all DSL features |
| Certificate verification | Bundle integrity and all-UNSAT obligation check before generation | That the certificate corresponds to the *intended* theorem (see Section 7) |
| Provenance embedding | Model hash, options hash, certificate reference in generated artifact | Tamper-resistance of generated files after creation |
| Deterministic output | Same inputs always produce the same output | Stability across Tarsier versions |

### Unverified Override

The `--allow-unverified` flag bypasses the certificate requirement. When used:

- Generated artifacts are marked with `verified: false` and `audit_tag: UNVERIFIED_CODEGEN`
- A warning is emitted to stderr
- The provenance header clearly identifies the artifact as unverified

This override exists for development and prototyping workflows. Production deployments should always use verified codegen.

### Codegen TCB

The codegen path's Trusted Computing Base is:

- `tarsier-dsl` parser (source → AST)
- `tarsier-codegen` generator (AST → code)
- `tarsier-proof-kernel` integrity logic (certificate validation, when `--require-cert` is used)
- Rust compiler / Go compiler (compilation of generated code)

Notably, the SMT solver and `tarsier-engine` are NOT in the codegen TCB — they are needed to *produce* the certificate, but codegen only checks the *pre-existing* certificate bundle.

See `docs/CODEGEN.md` for the full codegen policy, faithful-semantics surface coverage, and usage examples.

## 12. Runtime Sandbox

The `tarsier-engine` sandbox (`SandboxGuard`) enforces resource constraints on all verification and proof pipelines. It activates by default with fail-closed semantics.

### Enforced Controls

| Control | Mechanism | Default |
|---------|-----------|---------|
| Wall-clock timeout | Deadline checks at pipeline stage boundaries (`enforce_active_limits()`) | 300 s |
| Memory budget (RSS) | `/proc/self/statm` (Linux) or `mach task_info` (macOS) polling | 4096 MiB |
| Input file size | Pre-parse size check before reading `.trs` source | 1 MiB |

### Not Enforced (Design Invariants)

| Control | Status | Rationale |
|---------|--------|-----------|
| Network isolation | Not enforced | Z3 is statically linked (no outbound connections). cvc5 subprocess inherits the parent network namespace but does not initiate connections. Enforcing this would require platform-specific OS controls (seccomp-bpf, landlock, AppArmor on Linux; deprecated `sandbox-exec` on macOS). |
| Filesystem write isolation | Not enforced | Solvers do not write to disk. CLI output is the only write path. Restricting this would require OS-level sandboxing. |

These are documented design invariants: the threat model assumes solver binaries behave as specified (no network exfiltration, no disk writes). A compromised or malicious solver binary could violate these assumptions. Mitigation: pinned solver versions with SHA256-verified downloads in CI (see Section 8, "Compromised solver binary").

### Fail-Closed Semantics

If a required control cannot be enforced on the current platform (e.g., memory monitoring on a platform without `/proc` or `mach` APIs), `SandboxGuard::activate()` returns an error unless `--allow-degraded-sandbox` is passed. This prevents silent degradation.

## 13. Signed Trust Report Provenance

Release trust reports are signed with Sigstore Cosign (keyless/OIDC) during the release certification gate. This provides:

- **Provenance**: The signing certificate encodes the GitHub Actions workflow identity, binding the report to a specific CI run.
- **Integrity**: The detached signature ensures the report has not been modified after generation.
- **Non-repudiation**: The Sigstore transparency log records the signing event.

Verification is documented in `docs/TRUST_REPORT_SCHEMA.md` (Signed Reports section).

Locally generated trust reports (via `tarsier generate-trust-report`) are **not signed**. They are still valid for local analysis but carry no CI provenance.
