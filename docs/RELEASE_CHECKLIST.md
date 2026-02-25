# Release Checklist

This document defines the mandatory steps for releasing a new version of Tarsier. The corpus certification suite **must pass on a pinned environment** before any release is tagged.

## Environment Pinning

Releases must be validated against a pinned environment to ensure reproducibility:

- **Rust toolchain**: Pinned in `rust-toolchain.toml` (single source of truth for the release Rust version).
- **Z3 version**: Record the Z3 version from `z3 --version` (static-linked build).
- **cvc5 version**: Record the cvc5 version from `cvc5 --version`.
- **Carcara version**: Record external Alethe checker version from `carcara --version` (pinned in CI via `.github/scripts/install_proof_checkers.sh`).
- **OS/arch**: Record `uname -a` in the release notes.
- **Solver timeout**: Use the default `TIMEOUT=120` for corpus certification.

## Pre-Release Steps

### 1. Update version numbers

- [ ] Bump `version` in all workspace `Cargo.toml` files.
- [ ] Bump `schema_version` in `cert_suite.json` only if the manifest schema changed.
- [ ] Bump quantitative `schema_version` only if `CommComplexityReport` JSON shape/semantics changed (`docs/QUANTITATIVE_SCHEMA.md`, `docs/quantitative-schema-v2.json`).
- [ ] Update `docs/CHANGELOG.md` with release notes.

### 2. Refresh model fingerprints

```bash
python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json
```

Verify no unexpected hash changes:
```bash
python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json --check
```

### 3. Run full corpus certification

```bash
./scripts/certify-corpus.sh
```

This runs:
- Hash consistency check (`CHECK_HASHES=1`)
- `tarsier cert-suite` with default engine (k-induction, k=8)
- Per-protocol verdict validation against expected outcomes

**All entries must match expected outcomes.** Any failure must be triaged:
- `model_change`: Protocol file was modified — update `model_sha256` and re-validate.
- `engine_regression`: Engine behavior changed — investigate root cause before release.
- `expected_update`: Expected outcome is stale — update after confirming the new result is correct.

### 4. Run full test suite

```bash
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --all-targets
```

All tests must pass with zero failures.

### 5. Run independent high-assurance proof replay gate

```bash
./.github/scripts/install_proof_checkers.sh
TARSIER_REQUIRE_CARCARA=1 cargo run -p tarsier-cli --features governance -- certify-safety \
  examples/reliable_broadcast.trs --engine kinduction --k 12 --timeout 120 \
  --out certs/release-proof/safety
TARSIER_REQUIRE_CARCARA=1 cargo run -p tarsier-cli --features governance -- certify-fair-liveness \
  examples/library/pbft_liveness_safe_ci.trs --fairness weak --k 8 --timeout 120 \
  --out certs/release-proof/live
TARSIER_REQUIRE_CARCARA=1 cargo run -p tarsier-certcheck -- certs/release-proof/safety \
  --profile high-assurance --solvers z3,cvc5 \
  --emit-proofs certs/release-proof/safety/proofs \
  --proof-checker ./.github/scripts/check_proof_object.py \
  --json-report certs/release-proof/safety/certcheck-report.json
TARSIER_REQUIRE_CARCARA=1 cargo run -p tarsier-certcheck -- certs/release-proof/live \
  --profile high-assurance --solvers z3,cvc5 \
  --emit-proofs certs/release-proof/live/proofs \
  --proof-checker ./.github/scripts/check_proof_object.py \
  --json-report certs/release-proof/live/certcheck-report.json
```

All obligations must pass independently with high-assurance profile.

### 6. Run pinned liveness reproducibility gate

```bash
python3 .github/scripts/check_liveness_reproducibility.py
```

This gate runs fair-liveness certification twice with identical inputs and
requires stable certificate metadata + obligation hashes.

### 7. Run quantitative analytic baseline cross-checks

```bash
./scripts/check-quantitative-baselines.sh
```

This gate validates communication/finality formulas against known baselines before release.

### 8. Run benchmarks (optional but recommended)

```bash
python3 benchmarks/run_library_bench.py --mode standard
```

Compare timing against previous release to catch performance regressions.

### 9. Verify artifact generation

```bash
FORMAT=json OUT=artifacts/release-cert-suite.json ARTIFACTS_DIR=artifacts/release-cert-suite ./scripts/certify-corpus.sh
```

Confirm that `artifacts/release-cert-suite.json` contains all entries with `pass: true` and timing data.

### 10. Run dependency vulnerability scan

```bash
cargo deny check
```

This checks advisories (known CVEs), license compliance, banned crates, and source registry restrictions. Any failure must be resolved before release — the CI `supply-chain-audit` job enforces this automatically.

### 11. Verify UX contracts + accessibility sanity checks

```bash
./scripts/beginner-ux-smoke.sh
./scripts/ux-regression-smoke.sh
python3 scripts/ux_snapshot_regression.py
```

These checks enforce the beginner/pro UX contract (help text, report schema fields, key command flows), playground export contract, and accessibility sanity markers (`aria-live` status updates + labeled controls) before release.

## Release Steps

### 12. Create release commit

- [ ] Stage all version bumps, changelog, and any cert-suite manifest updates.
- [ ] Commit with message: `release: vX.Y.Z`
- [ ] Tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`

### 13. Archive certification artifacts

- [ ] Include `artifacts/release-cert-suite.json` in the release assets.
- [ ] Include high-assurance certcheck reports (`certs/release-proof/*/certcheck-report.json`) in release assets.
- [ ] Include environment metadata (Rust version, Z3 version, OS) in release notes.

### 14. Push and publish

- [ ] Push the tag: `git push origin vX.Y.Z`
- [ ] Wait for `Release Binaries` workflow to complete. This automatically:
  - Builds binaries for all targets (x86_64/aarch64 Linux/macOS + x86_64 Windows).
  - Signs each artifact with Cosign (keyless OIDC).
  - Generates SPDX SBOM for each artifact.
  - Creates GitHub Artifact Attestation (SLSA provenance) for each artifact.
  - Verifies all signatures and checksums before creating the GitHub Release.
  - Publishes all artifacts (`.tar.gz`, `.sha256`, `.sig`, `.pem`, `.sbom.spdx.json`) to the GitHub Release.

## CI Gate

The `certify-corpus.sh` script is designed for CI integration:

```yaml
# Example GitHub Actions step
- name: Corpus Certification
  run: ./scripts/certify-corpus.sh
  env:
    CMAKE_POLICY_VERSION_MINIMUM: "3.5"
    CHECK_HASHES: "1"
    FORMAT: json
    OUT: artifacts/cert-suite.json
    ARTIFACTS_DIR: artifacts/cert-suite
```

The script exits with code 2 on any certification failure, which CI will treat as a failed step.

## Post-Release

- [ ] Verify the published release artifacts are accessible.
- [ ] Verify supply-chain integrity of published artifacts:
  ```bash
  ./scripts/verify-release-artifacts.sh vX.Y.Z
  ```
  This checks SHA256 checksums, Cosign signatures, trust report signature, SBOMs, and GitHub Artifact Attestations.
- [ ] Run corpus certification against the published binary to confirm reproducibility.
- [ ] Update `docs/CHANGELOG.md` with the next development cycle header.

## Downstream Verification

Users who download release artifacts can verify their integrity:

```bash
# Full automated verification (requires cosign, gh CLI)
./scripts/verify-release-artifacts.sh v0.1.0

# Manual: verify checksum
shasum -a 256 -c tarsier-x86_64-unknown-linux-gnu.tar.gz.sha256

# Manual: verify cosign signature
cosign verify-blob \
  --signature tarsier-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate tarsier-x86_64-unknown-linux-gnu.tar.gz.pem \
  --certificate-identity-regexp "github\\.com" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  tarsier-x86_64-unknown-linux-gnu.tar.gz

# Manual: verify GitHub attestation
gh attestation verify tarsier-x86_64-unknown-linux-gnu.tar.gz --repo myaksetig/tarsier

# Manual: inspect SBOM
python3 -c "import json; d=json.load(open('tarsier-x86_64-unknown-linux-gnu.sbom.spdx.json')); print(f'SPDX {d[\"spdxVersion\"]}: {len(d.get(\"packages\",[]))} packages')"
```

See `SECURITY.md` for the full security policy and vulnerability disclosure process.
