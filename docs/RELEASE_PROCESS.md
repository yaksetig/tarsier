# Release Process

This repository treats corpus certification plus independent high-assurance proof replay as hard release gates. Release artifacts are cryptographically signed, attested, and accompanied by SBOMs.

## Required Gates

Release tags (`v*`) trigger two GitHub workflows:

- `.github/workflows/release-certification.yml` (`Release Certification`) — correctness gates
- `.github/workflows/release-binaries.yml` (`Release Binaries`) — build, sign, attest, verify, publish

Both workflows must pass before a release is considered valid.

## Pinned Environment

The release certification gate runs on pinned versions:

- OS: `ubuntu-22.04`
- Rust toolchain: `1.92.0` (pinned in `rust-toolchain.toml`)
- Z3: `4.12.5` (pinned in `.github/scripts/install_solvers.sh`)
- cvc5: `1.1.2` (pinned in `.github/scripts/install_solvers.sh`)

Pins are enforced by:

- `rust-toolchain.toml` (Rust version, single source of truth)
- `.github/scripts/install_solvers.sh` (Z3 and cvc5 versions)
- `.github/scripts/verify_pinned_env.sh` (runtime version assertion)
- `.github/scripts/install_proof_checkers.sh` (Carcara version)
- `.github/scripts/check_certification_gate_contract.py` (workflow contract guard)
- `.github/scripts/check_release_doc_sync.py` (doc/workflow sync guard)

### Pin Update Process

When updating any pinned component (OS image, Rust toolchain, solver versions):

1. Update pin sources atomically:
   - `rust-toolchain.toml`
   - `.github/scripts/install_solvers.sh`
   - `.github/scripts/verify_pinned_env.sh`
   - `.github/workflows/ci.yml` / `.github/workflows/release-certification.yml` / `.github/workflows/release-binaries.yml` runner/toolchain entries
2. Regenerate/refresh benchmark budgets when runtime shifts materially:
   - `benchmarks/budgets/*.json`
3. Run contract checks and certification locally/CI:
   - `python3 .github/scripts/check_certification_gate_contract.py`
   - `python3 .github/scripts/check_release_doc_sync.py`
   - `./scripts/certify-corpus.sh`
4. Include rationale and expected impact in the release PR (performance deltas, solver behavior changes, compatibility notes).

## Supply-Chain Integrity

Every release artifact includes:

| Layer | Tool | Artifact |
|-------|------|----------|
| Checksum | `shasum -a 256` | `*.tar.gz.sha256` |
| Signature | Cosign (keyless/OIDC) | `*.tar.gz.sig` + `*.tar.gz.pem` |
| SBOM | Syft (SPDX) | `*.sbom.spdx.json` |
| Provenance | GitHub Artifact Attestations | SLSA build provenance |

Signatures are verified in CI before the GitHub Release is created (the `verify` job in `release-binaries.yml`). This ensures no unsigned artifact can be published.

## Release Checklist

1. Ensure mainline CI is green (including `supply-chain-audit` job).
2. Push tag `vX.Y.Z`.
3. Wait for `Release Certification` workflow to pass:
   - corpus certification gate
   - independent checker high-assurance proof gate (`tarsier-certcheck --profile high-assurance`, `TARSIER_REQUIRE_CARCARA=1`)
4. Wait for `Release Binaries` workflow to pass:
   - build all targets
   - sign all artifacts with Cosign
   - generate SBOMs for all artifacts
   - generate build provenance attestations
   - verify all signatures, checksums, SBOMs, and platform payload contents
     (including `.exe` binaries for Windows targets)
   - create GitHub Release with all artifacts attached
5. Publish/refer to release only after all gates are green.

## Downstream Verification

Users can verify downloaded release artifacts:

```bash
# Quick verification (requires cosign, gh CLI, shasum, python3)
./scripts/verify-release-artifacts.sh v0.1.0

# Manual cosign verification of a single artifact
cosign verify-blob \
  --signature tarsier-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate tarsier-x86_64-unknown-linux-gnu.tar.gz.pem \
  --certificate-identity-regexp "github\\.com" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  tarsier-x86_64-unknown-linux-gnu.tar.gz

# Verify GitHub attestation
gh attestation verify tarsier-x86_64-unknown-linux-gnu.tar.gz --repo myaksetig/tarsier
```

See `SECURITY.md` for the full security policy and vulnerability disclosure process.
