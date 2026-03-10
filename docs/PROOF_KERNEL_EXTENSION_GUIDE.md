# Proof-Kernel Extension Guide

> How to extend the Tarsier proof kernel with new certificate types,
> checker contracts, and invariants.

## Overview

The proof kernel (`tarsier-proof-kernel`) is a minimal, auditable crate that validates
proof certificate bundles. It has only 4 dependencies (`serde`, `serde_json`, `sha2`,
`thiserror`) and is deliberately isolated from the solver, engine, DSL, and IR crates.

This guide covers:
1. Certificate schema structure
2. Adding new proof kinds
3. Adding new checker contracts (error codes)
4. Obligation profile completeness
5. Bundle hash algorithm
6. Governance profiles
7. Testing extensions

## 1. Certificate Schema

### Schema Version

The current schema version is **2** (`CERTIFICATE_SCHEMA_VERSION`). The checker
rejects any certificate with a different version. When making breaking changes to
the certificate format, increment this constant.

```rust
// lib.rs
pub const CERTIFICATE_SCHEMA_VERSION: u32 = 2;
```

### Certificate Metadata (`certificate.json`)

Every bundle directory contains a `certificate.json` with this structure:

```json
{
  "schema_version": 2,
  "kind": "safety_proof",
  "protocol_file": "my_protocol.trs",
  "proof_engine": "kinduction",
  "induction_k": 8,
  "solver_used": "z3",
  "soundness": "strict",
  "fairness": null,
  "committee_bounds": [],
  "bundle_sha256": "abcdef...",
  "obligations": [
    {
      "name": "base_case",
      "expected": "unsat",
      "file": "base_case.smt2",
      "sha256": "123456...",
      "proof_file": null,
      "proof_sha256": null
    }
  ]
}
```

Key types:
- `CertificateMetadata` — top-level structure (uses `#[serde(deny_unknown_fields)]`)
- `CertificateObligationMeta` — per-obligation entry

### Obligation Files

Each obligation is a self-contained `.smt2` file with exactly:
- One or more `(declare-fun ...)` / `(assert ...)` commands
- Exactly one `(check-sat)`
- Exactly one `(exit)`

Disallowed commands: `get-model`, `get-value`, `get-proof`, `push`, `pop`, `reset`, `echo`.

## 2. Adding a New Proof Kind

To add a new certificate kind (e.g., `"termination_proof"`):

### Step 1: Update kind validation

In `check_bundle_integrity()`, find the kind validation section:

```rust
let valid_kinds = ["safety_proof", "fair_liveness_proof"];
```

Add your new kind to the list.

### Step 2: Define valid engine pairings

Add valid `(kind, engine)` pairs:

```rust
let valid_pairs = [
    ("safety_proof", "kinduction"),
    ("safety_proof", "pdr"),
    ("fair_liveness_proof", "pdr"),
    ("termination_proof", "pdr"),       // NEW
];
```

### Step 3: Define the obligation profile

Add a new entry in the obligation profile completeness check:

```rust
fn required_obligations(kind: &str, engine: &str) -> &'static [&'static str] {
    match (kind, engine) {
        ("safety_proof", "kinduction") => &["base_case", "inductive_step"],
        ("safety_proof", "pdr") => &["init_implies_inv", "inv_and_transition_implies_inv_prime", "inv_implies_safe"],
        ("fair_liveness_proof", "pdr") => &["init_implies_inv", "inv_and_transition_implies_inv_prime", "inv_implies_no_fair_bad"],
        ("termination_proof", "pdr") => &["init_implies_inv", "inv_and_transition_implies_inv_prime", "inv_implies_progress"],  // NEW
        _ => &[],
    }
}
```

### Step 4: Add any kind-specific field validation

If the new kind requires specific metadata fields (like `fairness` for liveness):

```rust
if kind == "termination_proof" {
    // Validate termination-specific fields
    if meta.ranking_function.is_none() {
        issues.push(BundleCheckIssue { code: "missing_ranking_function", ... });
    }
}
```

### Step 5: Update the certificate generation pipeline

In `tarsier-engine/src/pipeline/certification.rs`, add a new generator function:

```rust
pub fn generate_termination_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<TerminationProofCertificate, PipelineError> {
    // Parse → lower → analyze → encode obligations → return certificate
}
```

### Step 6: Update documentation

- Update `docs/CERTIFICATE_SCHEMA.md` with the new kind
- Update `docs/KERNEL_SPEC.md` with new error codes and obligation profiles
- Update `docs/certificate-schema-v2.json` JSON Schema

## 3. Adding New Checker Contracts (Error Codes)

The checker uses string error codes organized into categories.

### Existing Error Code Categories

| Category | Codes | Purpose |
|----------|------:|---------|
| Schema & Structure | 7 | Version, kind, engine validation |
| Per-Obligation | 10 | File existence, hashes, paths |
| Proof Object Binding | 5 | Proof file integrity |
| SMT Sanity | 5 | Script structure validation |
| Profile Completeness | 2 | Obligation set correctness |
| Bundle Hash | 2 | Tamper detection |

### Adding a New Check

1. Choose a descriptive `snake_case` error code
2. Add the check in the appropriate phase of `check_bundle_integrity()`
3. Push to the `issues` vector:

```rust
issues.push(BundleCheckIssue {
    code: "my_new_check".into(),
    message: format!("Description of what went wrong: {}", detail),
    obligation: Some("obligation_name".into()),  // or None for global checks
});
```

4. Add a test:

```rust
#[test]
fn check_catches_my_new_issue() {
    let dir = setup_bundle_with_problem(...);
    let report = check_bundle_integrity(&dir).unwrap();
    assert!(!report.is_ok());
    assert!(report.issues.iter().any(|i| i.code == "my_new_check"));
}
```

5. Document the code in `docs/KERNEL_SPEC.md`

### Invariant: All Checks Are Fail-Closed

Every check defaults to **rejection**. If you cannot determine whether a condition
holds, emit an issue. Never silently accept an ambiguous state.

## 4. Obligation Profile Completeness

The checker enforces that certificates contain exactly the right set of obligations
for their `(kind, engine)` pair:

- **Missing obligation** → `missing_required_obligation`
- **Extra obligation** → `unexpected_obligation_name`

When extending obligation profiles:

1. Add the obligation name to `required_obligations()`
2. Ensure the engine generates the corresponding SMT-LIB script
3. The obligation's `expected` field must be `"unsat"` for proof certificates

### Example: Adding a `strengthening_lemma` obligation

```rust
// In the engine:
let strengthening = SafetyProofObligation {
    name: "strengthening_lemma".into(),
    expected: "unsat".into(),
    smt2: encode_strengthening_check(&invariant, &ta, k),
};
cert.obligations.push(strengthening);

// In the kernel:
("safety_proof", "kinduction") => &["base_case", "inductive_step", "strengthening_lemma"],
```

## 5. Bundle Hash Algorithm

The bundle hash provides tamper detection. It is computed deterministically:

```
SHA-256(
  "tarsier-certificate-v2\n"       // domain tag
  + kind + "\n"
  + protocol_file + "\n"
  + proof_engine + "\n"
  + (induction_k or "none") + "\n"
  + solver_used + "\n"
  + soundness + "\n"
  + (fairness or "") + "\n"
  + [sorted committee bounds: name + "=" + bound + "\n"]
  + [sorted obligations: name + "|" + expected + "|" + file + "|"
      + (sha256 or "") + "|" + (proof_file or "") + "|"
      + (proof_sha256 or "") + "\n"]
)
```

### Extending the Hash

If you add new metadata fields that affect certificate identity:

1. Add the field to the hash computation in `compute_bundle_sha256()`
2. Place it in a stable position (append after existing fields)
3. Increment `CERTIFICATE_SCHEMA_VERSION` (this is a breaking change)

**Critical**: The hash is the root of trust. Any change to its computation
invalidates all existing certificates.

## 6. Governance Profiles

Three assurance tiers with escalating requirements:

| Profile | Min Solvers | Require Proofs | Require Checker | Use Case |
|---------|:---:|:---:|:---:|---|
| **Standard** | 1 | No | No | Development, CI |
| **Reinforced** | 2 | Yes | No | Production release |
| **HighAssurance** | 2 | Yes | Yes | Audit, governance |

### Adding a New Profile

```rust
pub enum GovernanceProfile {
    Standard,
    Reinforced,
    HighAssurance,
    MyNewProfile,  // NEW
}

impl GovernanceProfile {
    pub fn requirements(&self) -> ProfileRequirements {
        match self {
            // ...
            Self::MyNewProfile => ProfileRequirements {
                min_solvers: 3,
                require_proofs: true,
                require_proof_checker: true,
                require_foundational_proof_path: true,
            },
        }
    }
}
```

Profiles set a **floor**: CLI flags can strengthen but never weaken the requirements.

## 7. Testing Extensions

### Unit Test Patterns

The kernel uses a test helper pattern with temporary directories:

```rust
#[test]
fn my_extension_test() {
    let dir = tempfile::tempdir().unwrap();

    // Write a certificate.json with the scenario to test
    let meta = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: "safety_proof".into(),
        // ... fill in fields
    };

    let cert_path = dir.path().join("certificate.json");
    std::fs::write(&cert_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    // Write obligation files
    let smt2 = "(declare-fun x () Int)\n(assert (> x 0))\n(check-sat)\n(exit)\n";
    std::fs::write(dir.path().join("base_case.smt2"), smt2).unwrap();

    // Run the checker
    let report = check_bundle_integrity(dir.path()).unwrap();
    assert!(report.is_ok());
}
```

### Integration Test Patterns

For end-to-end certificate generation and verification:

```rust
#[test]
fn roundtrip_generate_and_check() {
    let cert = generate_kinduction_safety_certificate(SRC, "test.trs", &opts).unwrap();
    let dir = write_certificate_bundle_to_temp(&cert);
    let report = check_bundle_integrity(&dir).unwrap();
    assert!(report.is_ok(), "generated certificate should pass kernel: {:?}", report.issues);
}
```

### What to Test When Extending

1. **Happy path**: valid certificate passes
2. **Missing field**: checker rejects with correct error code
3. **Wrong value**: checker rejects (e.g., wrong schema version)
4. **Tampered file**: hash mismatch detected
5. **Extra obligation**: rejected as unexpected
6. **Missing obligation**: rejected as incomplete
7. **Cross-kind confusion**: safety cert with liveness fields rejected

## 8. File Reference

| File | Purpose |
|------|---------|
| `crates/tarsier-proof-kernel/src/lib.rs` | Kernel implementation (2100+ lines) |
| `crates/tarsier-proof-kernel/README.md` | API overview |
| `crates/tarsier-engine/src/pipeline/certification.rs` | Certificate generation |
| `crates/tarsier-cli/src/commands/helpers.rs` | Bundle writing to disk |
| `docs/CERTIFICATE_SCHEMA.md` | Schema v2 specification |
| `docs/KERNEL_SPEC.md` | Formal kernel semantics, 31 error codes |
| `docs/TRUST_BOUNDARY.md` | TCB, threat model, governance |
| `docs/CHECKER_SOUNDNESS_ARGUMENT.md` | Soundness argument |
| `docs/certificate-schema-v2.json` | Machine-readable JSON Schema |
