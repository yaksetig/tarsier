## Summary

- What changed and why.

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] Relevant test suites executed

## Reproducibility / Contracts

- [ ] `python3 .github/scripts/check_workspace_package_metadata.py`
- [ ] `python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json --check`
- [ ] `./scripts/check-clean-worktree.sh`

## Trust / Soundness Impact

- [ ] No trust-boundary or soundness changes
- [ ] Trust-boundary or soundness changes included and documented

If trust/soundness changed, summarize:

## Breaking Changes

- [ ] None
- [ ] Yes (describe migration impact and docs updated)

## Artifacts / Evidence

- Link to benchmark reports, conformance outputs, or certificate artifacts when relevant.
