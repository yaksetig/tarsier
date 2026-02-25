# Protocol Corpus Maintenance Policy

This policy defines ownership and operating cadence for the canonical protocol corpus
at `examples/library/` and its certification manifest
`examples/library/cert_suite.json`.

## Ownership

- Primary owner: `tarsier-core-maintainers` (repository maintainers responsible for merge/release decisions).
- Backup owner: `release-duty-maintainer` (on-call maintainer for release week).
- Scope of ownership:
  - protocol models under `examples/library/*.trs`
  - manifest expectations/hashes in `examples/library/cert_suite.json`
  - corpus gate tooling (`scripts/certify-corpus.sh`, hash update/check scripts)

Ownership responsibilities:
- approve/reject corpus changes;
- classify failures as `model_change`, `engine_regression`, or `expected_update`;
- keep manifest expectations aligned with current engine behavior and intentional model changes.

## Review Cadence

- Per-PR review (required): every PR that touches `examples/library/` or `cert_suite.json`.
- Weekly review: check CI history for corpus-gate failures and unresolved triage items.
- Monthly review: audit family coverage, minimal/faithful pair coverage, and known-bug sentinel health.
- Pre-release review: run full corpus certification on pinned environment and block release if it fails.

## Update Cadence and SLA

- New/changed protocol model SLA:
  - within 24 hours: add/update manifest entry and rationale (`notes`);
  - within 24 hours: refresh/verify `model_sha256`;
  - within 48 hours: add/adjust expected outcomes and variant metadata where relevant.
- Gate-failure SLA:
  - `model_change`: resolve or re-pin hash within 24 hours;
  - `expected_update`: update expectation tokens with rationale within 48 hours;
  - `engine_regression`: open issue immediately and triage within 1 business day.
- Release SLA:
  - no release tag is valid until corpus certification passes in pinned release workflow.

## Enforcement

The policy is enforced by repository gates:
- CI corpus gate: `.github/workflows/ci.yml` (`corpus-certification-gate`).
- Release corpus gate: `.github/workflows/release-certification.yml`.
- One-command certification entrypoint: `scripts/certify-corpus.sh`.
- Policy contract check: `.github/scripts/check_corpus_policy_contract.py`.

If any gate fails, corpus-related merges/releases are blocked until resolved.
