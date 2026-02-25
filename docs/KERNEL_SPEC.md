# Proof Kernel Specification

This document formally specifies the minimal trusted checker kernel (`tarsier-proof-kernel`).
It defines exactly what the kernel checks, what it trusts, and maps each certificate obligation
to a specific kernel check with its error code.

Reference implementation: `crates/tarsier-proof-kernel/src/lib.rs`

## 1. Kernel Scope

The proof kernel is a **pure integrity checker**. It validates certificate bundle structure
and content hashes before any solver replay or proof analysis occurs.

### In Scope (kernel checks these)

| Category | What the kernel does |
|----------|---------------------|
| Schema validation | Exact `schema_version` match, strict JSON deserialization (`deny_unknown_fields`) |
| Obligation structure | Non-empty obligations, no duplicates (name or file), correct obligation profiles for `(kind, proof_engine)` |
| File integrity | SHA-256 hash verification for `.smt2` obligation files and `.proof` proof objects |
| Bundle integrity | Deterministic `bundle_sha256` covering all metadata + obligation hashes, domain-tagged with `tarsier-certificate-v2\n` |
| Path safety | Reject absolute paths, parent directory traversal (`..`), prefix components, symlink escapes outside bundle directory |
| SMT script sanity | Exactly one `(check-sat)`, exactly one `(exit)`, correct command order, at least one `(assert ...)`, no disallowed commands |
| Metadata consistency | `induction_k` presence, `fairness` field coupling with certificate `kind`, valid `kind` and `proof_engine` values |
| Governance profiles | Named presets (`standard`, `reinforced`, `high-assurance`) defining minimum verification rigor |

### Out of Scope (kernel does NOT check these)

| Category | Why it is excluded | Where it is handled |
|----------|-------------------|---------------------|
| Solver execution | Kernel is solver-independent; replay is a separate concern | `tarsier-certcheck` replay logic |
| SMT formula semantics | Kernel checks structure, not meaning | Manual audit, `docs/SEMANTICS.md` |
| Proof object validation | Proof checking requires solver-specific logic | External proof checker (`--proof-checker`) |
| Source-to-obligation correspondence | Requires full parser/lowering/encoder | `tarsier-cli check-certificate --rederive` |
| Protocol modeling fidelity | Domain-specific concern | Manual audit |
| Solver binary integrity | OS/supply-chain concern | Pinned versions, SHA-256 downloads in CI |

### Explicit Non-Goals

The kernel intentionally does NOT:

1. Parse or interpret SMT-LIB formulas beyond command extraction.
2. Execute any solver or external process.
3. Depend on `tarsier-engine`, `tarsier-ir`, `tarsier-dsl`, `tarsier-smt`, `tarsier-prob`, or `z3`.
4. Accept forward-compatible schema versions (exact match only).
5. Provide backward compatibility with schema version 1.

## 2. Trusted Computing Base

The kernel's TCB is minimal by design:

| Component | Role | Trust assumption |
|-----------|------|-----------------|
| `sha2` crate | SHA-256 computation | Correct digest output |
| `serde` + `serde_json` | JSON deserialization | Correct parsing, `deny_unknown_fields` enforcement |
| `thiserror` | Error type derivation | No runtime behavior |
| Rust standard library | File I/O, path manipulation | Correct `fs::read`, `fs::canonicalize` behavior |
| Rust compiler | Compilation of kernel source | Correct code generation |

**Total dependency count**: 4 direct crates (sha2, serde, serde_json, thiserror). No transitive solver or proof-engine dependencies.

## 3. Kernel Semantics

### 3.1 Entry Point

```
check_bundle_integrity(bundle_dir: &Path) -> Result<BundleIntegrityReport, ProofKernelError>
```

**Precondition**: `bundle_dir/certificate.json` exists and is valid JSON.

**Postcondition**: Returns a `BundleIntegrityReport` containing:
- The parsed `CertificateMetadata`
- A list of `BundleCheckIssue` items (empty if all checks pass)

**Invariant**: `report.is_ok() == true` if and only if the bundle passes ALL kernel checks.

### 3.2 Check Ordering

Checks execute in the following order. Each check may emit zero or more issues.
A failing check does NOT short-circuit subsequent checks (all issues are collected).

1. Schema version validation
2. Empty obligations check
3. Obligation profile validation (kind/engine compatibility, fairness, induction_k)
4. Per-obligation checks (loop):
   - Duplicate name/file detection
   - Expected result validation
   - Path safety
   - File existence and extension
   - Symlink escape detection
   - SHA-256 hash verification (obligation file)
   - Proof file validation (if proof metadata present)
   - SMT script sanity checks
5. Obligation completeness (required/unexpected names for profile)
6. Bundle hash verification

### 3.3 Fail-Open vs Fail-Closed

The kernel is **fail-closed**: any detected issue produces a `BundleCheckIssue` entry,
and `is_ok()` returns `false`. There is no mechanism to suppress or ignore individual checks.

## 4. Obligation-to-Check Mapping

Each kernel check has a unique error code. The following table provides a 1:1 mapping
from certificate obligations to kernel checks.

### 4.1 Schema & Structure Checks

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `schema_version` | Schema version | `metadata.schema_version` | `== CERTIFICATE_SCHEMA_VERSION` (currently 2) | Silent acceptance of incompatible future schemas |
| `empty_obligations` | Non-empty obligations | `metadata.obligations` | `len() > 0` | Empty certificate passing validation |
| `invalid_kind` | Valid certificate kind | `metadata.kind` | `"safety_proof"` or `"fair_liveness_proof"` | Unrecognized certificate types bypassing profile checks |
| `invalid_proof_engine` | Valid proof engine | `(metadata.kind, metadata.proof_engine)` | Valid combination (see Section 5) | Engine/kind mismatch evading obligation profile checks |
| `missing_induction_k` | Induction depth present | `metadata.induction_k` | `Some(_)` | Missing proof depth metadata |
| `unexpected_fairness` | No fairness on safety certs | `(metadata.kind, metadata.fairness)` | `kind == "safety_proof"` implies `fairness.is_none()` | Injecting fairness metadata into safety certificates |
| `missing_or_invalid_fairness` | Valid fairness on liveness certs | `(metadata.kind, metadata.fairness)` | `kind == "fair_liveness_proof"` implies `fairness in {"weak", "strong"}` | Missing or invalid fairness field |

### 4.2 Per-Obligation Checks

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `duplicate_obligation_name` | Unique names | `obligation.name` | No two obligations share a name | Obligation shadowing |
| `duplicate_obligation_file` | Unique files | `obligation.file` | No two obligations share a file path | File aliasing |
| `invalid_expected` | Valid expected result | `obligation.expected` | `"unsat"`, `"sat"`, or `"unknown"` | Unrecognized expected values |
| `invalid_expected_for_proof` | Proof expects unsat | `obligation.expected` | `"unsat"` (when obligation profile is known) | Non-unsat obligations in proof certificates |
| `unsafe_path` | Safe relative path | `obligation.file` | Not empty, not absolute, no `..` or prefix components | Path traversal attack |
| `missing_file` | File exists | `bundle_dir/obligation.file` | File exists on disk | Dangling obligation references |
| `invalid_obligation_extension` | SMT2 extension | `obligation.file` | Extension is `.smt2` | Non-SMT files accepted as obligations |
| `symlink_escape` | No symlink escape | `canonicalize(obligation_path)` | Canonical path starts with canonical bundle dir | Symlink-based directory escape |
| `obligation_hash_mismatch` | SHA-256 match | `sha256(file_contents)` vs `obligation.sha256` | Hashes match | Post-generation obligation tampering |
| `missing_obligation_hash` | Hash present | `obligation.sha256` | `Some(_)` | Missing integrity binding |

### 4.3 Proof Object Binding Checks

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `unsafe_proof_path` | Safe proof path | `obligation.proof_file` | Same rules as `unsafe_path` | Path traversal via proof file |
| `missing_proof_file` | Proof file exists | `bundle_dir/obligation.proof_file` | File exists on disk | Dangling proof reference |
| `proof_hash_mismatch` | Proof SHA-256 match | `sha256(proof_contents)` vs `obligation.proof_sha256` | Hashes match | Post-generation proof tampering |
| `missing_proof_hash` | Proof hash present when file set | `(obligation.proof_file, obligation.proof_sha256)` | `proof_file.is_some()` implies `proof_sha256.is_some()` | Unbound proof object |
| `orphan_proof_hash` | No orphan hash | `(obligation.proof_file, obligation.proof_sha256)` | `proof_sha256.is_some()` implies `proof_file.is_some()` | Hash without corresponding file |

### 4.4 SMT Script Sanity Checks

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `check_sat_count` | Single check-sat | Extracted SMT commands | Exactly 1 `(check-sat)` command | Multi-query or missing-query scripts |
| `exit_count` | Single exit | Extracted SMT commands | Exactly 1 `(exit)` command | Missing termination or multi-exit scripts |
| `invalid_command_order` | Correct ordering | Command positions | `(check-sat)` before `(exit)` | Reversed command order |
| `missing_assert` | Has assertions | Extracted SMT commands | At least 1 `(assert ...)` command | Trivially satisfiable empty scripts |
| `disallowed_commands` | No forbidden commands | Extracted SMT commands | None of: `get-model`, `get-value`, `get-assignment`, `get-unsat-core`, `get-proof`, `echo`, `push`, `pop`, `reset`, `reset-assertions` | Information leakage, state manipulation |

### 4.5 Obligation Profile Completeness Checks

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `missing_required_obligation` | Required obligations present | `(metadata.kind, metadata.proof_engine, obligation_names)` | All required obligation names present for the profile | Incomplete proof with missing obligations |
| `unexpected_obligation_name` | No extra obligations | `(metadata.kind, metadata.proof_engine, obligation_names)` | No obligation names outside the required profile | Injected obligations inflating the proof |

### 4.6 Bundle Hash Verification

| Error Code | Check | Input | Accept Condition | Threat Countered |
|------------|-------|-------|-----------------|-----------------|
| `missing_bundle_hash` | Bundle hash present | `metadata.bundle_sha256` | `Some(_)` | Missing top-level integrity seal |
| `bundle_hash_mismatch` | Bundle hash correct | `compute_bundle_sha256(metadata)` vs `metadata.bundle_sha256` | Hashes match | Metadata tampering after bundle creation |

## 5. Obligation Profiles

The kernel enforces obligation completeness by `(kind, proof_engine)` pair.

| Kind | Engine | Required Obligations | Count |
|------|--------|---------------------|-------|
| `safety_proof` | `kinduction` | `base_case`, `inductive_step` | 2 |
| `safety_proof` | `pdr` | `init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_safe` | 3 |
| `fair_liveness_proof` | `pdr` | `init_implies_inv`, `inv_and_transition_implies_inv_prime`, `inv_implies_no_fair_bad` | 3 |

Invalid combinations:
- `fair_liveness_proof` + `kinduction` → `invalid_proof_engine`
- Unknown `kind` → `invalid_kind`
- Unknown `proof_engine` for valid `kind` → `invalid_proof_engine`

## 6. Bundle Hash Specification

The deterministic bundle hash is computed as:

```
SHA-256(
  "tarsier-certificate-v2\n"          # domain tag (collision resistance)
  + kind + "\n"
  + protocol_file + "\n"
  + proof_engine + "\n"
  + (induction_k or "none") + "\n"
  + solver_used + "\n"
  + soundness + "\n"
  + (fairness or "") + "\n"
  + for each committee_bound:
      name + "=" + bound + "\n"
  + for each obligation:
      name + "|" + expected + "|" + file + "|"
      + (sha256 or "") + "|"
      + (proof_file or "") + "|"
      + (proof_sha256 or "") + "\n"
)
```

Properties:
- **Deterministic**: Same inputs always produce the same hash.
- **Domain-tagged**: The `tarsier-certificate-v2\n` prefix prevents cross-protocol collisions.
- **Complete coverage**: Every metadata field and every obligation field contributes to the hash.
- **Ordering-sensitive**: Obligation and committee-bound order affects the hash (canonicalized at emission time).

## 7. Governance Profiles

| Profile | `min_solvers` | `require_proofs` | `require_proof_checker` | `require_foundational_proof_path` |
|---------|--------------|-----------------|------------------------|----------------------------------|
| `standard` | 1 | false | false | false |
| `reinforced` | 2 | true | false | false |
| `high-assurance` | 2 | true | true | true |

Profile requirements set a floor; explicit CLI flags can only strengthen them.

## 8. Error Code Summary

Total: **31** distinct error codes.

| Category | Codes | Count |
|----------|-------|-------|
| Schema & structure | `schema_version`, `empty_obligations`, `invalid_kind`, `invalid_proof_engine`, `missing_induction_k`, `unexpected_fairness`, `missing_or_invalid_fairness` | 7 |
| Per-obligation | `duplicate_obligation_name`, `duplicate_obligation_file`, `invalid_expected`, `invalid_expected_for_proof`, `unsafe_path`, `missing_file`, `invalid_obligation_extension`, `symlink_escape`, `obligation_hash_mismatch`, `missing_obligation_hash` | 10 |
| Proof binding | `unsafe_proof_path`, `missing_proof_file`, `proof_hash_mismatch`, `missing_proof_hash`, `orphan_proof_hash` | 5 |
| SMT sanity | `check_sat_count`, `exit_count`, `invalid_command_order`, `missing_assert`, `disallowed_commands` | 5 |
| Profile completeness | `missing_required_obligation`, `unexpected_obligation_name` | 2 |
| Bundle hash | `missing_bundle_hash`, `bundle_hash_mismatch` | 2 |

## 9. Cross-References

| Document | Relationship |
|----------|-------------|
| `docs/CERTIFICATE_SCHEMA.md` | Certificate field definitions, versioning policy, schema changelog |
| `docs/certificate-schema-v2.json` | Machine-readable JSON Schema for `certificate.json` |
| `docs/TRUST_BOUNDARY.md` | Trust assumptions, governance profiles, threat model |
| `docs/CHECKER_SOUNDNESS_ARGUMENT.md` | Soundness argument artifact with explicit assumptions/non-goals and machine-checked subset proof links |
| `crates/tarsier-proof-kernel/src/lib.rs` | Reference implementation |
| `crates/tarsier-certcheck/src/main.rs` | Standalone replay binary using this kernel |
