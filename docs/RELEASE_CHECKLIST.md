# Release Checklist

This document defines the mandatory steps for releasing a new version of Tarsier. The corpus certification suite **must pass on a pinned environment** before any release is tagged.

## Environment Pinning

Releases must be validated against a pinned environment to ensure reproducibility:

- **Rust toolchain**: Pin via `rust-toolchain.toml` or document the exact `rustc --version` output.
- **Z3 version**: Record the Z3 version from `z3 --version` (static-linked build).
- **OS/arch**: Record `uname -a` in the release notes.
- **Solver timeout**: Use the default `TIMEOUT=120` for corpus certification.

## Pre-Release Steps

### 1. Update version numbers

- [ ] Bump `version` in all workspace `Cargo.toml` files.
- [ ] Bump `schema_version` in `cert_suite.json` only if the manifest schema changed.
- [ ] Update `CHANGELOG.md` with release notes.

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

### 5. Run benchmarks (optional but recommended)

```bash
python3 benchmarks/run_library_bench.py --mode standard
```

Compare timing against previous release to catch performance regressions.

### 6. Verify artifact generation

```bash
./scripts/certify-corpus.sh FORMAT=json OUT=artifacts/release-cert-suite.json ARTIFACTS_DIR=artifacts/release-cert-suite
```

Confirm that `artifacts/release-cert-suite.json` contains all entries with `pass: true` and timing data.

## Release Steps

### 7. Create release commit

- [ ] Stage all version bumps, changelog, and any cert-suite manifest updates.
- [ ] Commit with message: `release: vX.Y.Z`
- [ ] Tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`

### 8. Archive certification artifacts

- [ ] Include `artifacts/release-cert-suite.json` in the release assets.
- [ ] Include environment metadata (Rust version, Z3 version, OS) in release notes.

### 9. Push and publish

- [ ] Push the tag: `git push origin vX.Y.Z`
- [ ] Create GitHub release with artifacts attached.

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
- [ ] Run corpus certification against the published binary to confirm reproducibility.
- [ ] Update `docs/CHANGELOG.md` with the next development cycle header.
