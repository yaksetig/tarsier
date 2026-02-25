# V1 UX Roadmap — Implementation Status

| Ticket | Title | Status | Evidence |
|--------|-------|--------|----------|
| V1-01 | Canonical entrypoint | Done | `Cli` struct `long_about`, `Analyze` at `display_order = 0` in `main.rs` |
| V1-02 | Goals API | Done | `--goal` arg on `Commands::Analyze`, goal→mode mapping in dispatch |
| V1-03 | Profiles API | Done | `--profile` arg with `beginner`/`pro`/`governance` presets in dispatch |
| V1-04 | Advanced gating | Done | `--advanced` flag; beginner rejects raw knobs with `advanced-only` error |
| V1-05 | Unified verdict taxonomy | Done | `CanonicalVerdict` enum, `canonical_verdict_from_*()` functions, `verdict` field on layers |
| V1-06 | Claim statement block | Done | `ClaimStatement` struct, `build_claim_statement()`, JSON `claim` field, text "What was proven:" block |
| V1-07 | Next-action recommender | Done | `NextAction` struct, `build_next_action()`, JSON `next_action` field, text "Recommended next step:" block |
| V1-08 | Beginner-safe defaults | Done | Profile-based defaults: beginner (depth=6, k=10, timeout=120s), pro/governance (depth=10, k=12, timeout=300s) |
| V1-09 | One-page quickstart | Done | README "Core Flow (Start Here)" section with scaffold→analyze→visualize→certify |
| V1-10 | Beginner UX CI gate | Done | `scripts/beginner-ux-smoke.sh` (5 tests), `beginner-ux-gate` job in `.github/workflows/ci.yml` |
| V1-11 | Migration hints | Done | Legacy commands tagged `(advanced — prefer ...)` with `display_order >= 10`, mapping table in README |
| V1-12 | Status artifact | Done | This file |

## Key Files Modified

- `crates/tarsier-cli/src/main.rs` — verdict taxonomy, claim/next-action, goals/profiles/advanced gating, help text
- `README.md` — Core Flow section, goals/profiles examples, legacy mapping table
- `scripts/beginner-ux-smoke.sh` — CI smoke tests for beginner happy path
- `.github/workflows/ci.yml` — `beginner-ux-gate` job

## Output Contract (JSON)

The `analyze --format json` output includes:
- `schema_version` — format version string
- `mode` — resolved analysis mode (quick/standard/proof/audit)
- `overall` — human-readable summary
- `overall_verdict` — one of SAFE, UNSAFE, LIVE_PROVED, LIVE_CEX, INCONCLUSIVE, UNKNOWN
- `layers` — array of layer reports, each with `verdict` field
- `claim` — object with `proven`, `assumptions`, `not_covered` arrays
- `next_action` — object with `command` and `reason`
