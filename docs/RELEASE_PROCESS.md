# Release Process

This repository treats corpus certification as a hard release gate.

## Required Gate

Release tags (`v*`) trigger GitHub workflow:

- `.github/workflows/release-certification.yml` (`Release Certification`)

That workflow must pass before a release is considered valid.

## Pinned Environment

The release gate runs on pinned versions:

- OS: `ubuntu-22.04`
- Rust toolchain: `1.92.0`
- Z3: `4.12.5`
- cvc5: `1.1.2`

Pins are enforced by:

- `.github/scripts/install_solvers.sh`
- `.github/scripts/verify_pinned_env.sh`

## Release Checklist

1. Ensure mainline CI is green.
2. Push tag `vX.Y.Z`.
3. Wait for `Release Certification` workflow to pass.
4. Publish/refer to release only after that gate is green.
