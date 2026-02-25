# Tarsier V2 Migration Guide

This guide helps you migrate from legacy Tarsier commands to the unified `analyze` workflow.

## Quick Reference

| Legacy Command | V2 Replacement | Notes |
|---|---|---|
| `verify --depth 10` | `analyze --goal bughunt` | Quick mode caps depth at 4; use `--advanced --depth 10` for exact match |
| `prove --k 12 --engine pdr` | `analyze --goal safety` | Runs both k-induction and PDR |
| `prove-fair --fairness weak` | `analyze --goal safety+liveness` | Includes bounded + unbounded fair-liveness |
| `round-sweep` | Remains standalone | No analyze equivalent |
| `certify-safety --out certs/` | `analyze --goal release --report-out dir/` | Auto-generates certs in audit mode |
| `certify-fair-liveness` | `analyze --goal release --report-out dir/` | Auto-generates certs in audit mode |
| `check-certificate` | Remains standalone | Used for manual re-verification |
| `cert-suite` | Remains standalone | CI corpus testing |
| `lint` | `analyze` (parse layer) | Lint checks subsumed by analysis parse layer |
| `comm` | Remains standalone | Communication complexity report |
| `liveness` | `analyze --goal safety+liveness` | Bounded liveness subsumed |
| `fair-liveness` | `analyze --goal safety+liveness` | Fair-liveness subsumed |
| `debug-cex` | `visualize --check verify` | Counterexample inspection |

## Detailed Migration Examples

### Safety Verification

**Before:**
```bash
tarsier verify my_protocol.trs --depth 10 --timeout 60
```

**After:**
```bash
tarsier analyze my_protocol.trs --goal bughunt
```

**Notes:** Quick mode uses a capped depth (max 4) for fast results. For exact depth control, use:
```bash
tarsier analyze my_protocol.trs --profile pro --advanced --depth 10 --timeout 60
```

### Unbounded Safety Proof

**Before:**
```bash
tarsier prove my_protocol.trs --k 12 --engine pdr --timeout 120
```

**After:**
```bash
tarsier analyze my_protocol.trs --goal safety
```

**Notes:** The `safety` goal runs both k-induction and PDR engines automatically. For specific engine control:
```bash
tarsier analyze my_protocol.trs --profile pro --mode proof --advanced --k 12 --timeout 120
```

### Fair-Liveness Proof

**Before:**
```bash
tarsier prove-fair my_protocol.trs --k 8 --fairness weak --timeout 120
```

**After:**
```bash
tarsier analyze my_protocol.trs --goal safety+liveness
```

**Notes:** Includes both bounded and unbounded fair-liveness checks. Fairness defaults to weak.

### Safety Certificate Generation

**Before:**
```bash
tarsier certify-safety my_protocol.trs --k 12 --engine pdr --out certs/safety
```

**After:**
```bash
tarsier analyze my_protocol.trs --goal release --report-out certs/
```

**Notes:** The release goal runs audit-grade analysis and auto-generates safety and fair-liveness certificates when proof layers pass.

### Fair-Liveness Certificate Generation

**Before:**
```bash
tarsier certify-fair-liveness my_protocol.trs --k 8 --fairness weak --out certs/fair
```

**After:**
```bash
tarsier analyze my_protocol.trs --goal release --report-out certs/
```

**Notes:** Release mode generates both safety and fair-liveness certificates in one command.

### Linting

**Before:**
```bash
tarsier lint my_protocol.trs --soundness strict
```

**After:**
```bash
tarsier analyze my_protocol.trs
```

**Notes:** The parse+lower layer in `analyze` performs all lint checks. Preflight warnings surface model completeness issues.

### Counterexample Debugging

**Before:**
```bash
tarsier debug-cex my_protocol.trs --check verify --depth 8
```

**After:**
```bash
tarsier visualize my_protocol.trs --check verify --depth 8 --format markdown --out cex.md
```

**Notes:** `visualize` produces richer output formats (timeline, Mermaid, markdown, JSON).

## Profile Migration

### CI Workflows

**Before:**
```bash
tarsier verify my_protocol.trs --depth 4 --timeout 60
tarsier prove my_protocol.trs --k 10 --timeout 300
```

**After:**
```bash
# Fast CI gate
tarsier analyze my_protocol.trs --profile ci-fast --format json

# CI proof gate
tarsier analyze my_protocol.trs --profile ci-proof --format json

# Release gating
tarsier analyze my_protocol.trs --profile release-gate --format json --report-out release/
```

### Governance Audits

**Before:**
```bash
tarsier verify my_protocol.trs --depth 10 --timeout 300 --soundness strict
tarsier prove my_protocol.trs --k 12 --engine pdr --timeout 300
tarsier certify-safety my_protocol.trs --k 12 --engine pdr --out certs/
```

**After:**
```bash
tarsier analyze my_protocol.trs --profile governance --goal release --format json --report-out audit/
```

**Notes:** Single command replaces the multi-step workflow. Generates analysis report, certificates, and governance bundle.

## Schema Changes

### Report Schema

- `schema_version` changed from integer `1` to string `"v1"`
- New field: `confidence_tier` (`"quick"`, `"bounded"`, `"proof"`, `"certified"`)
- New optional field: `preflight_warnings` (array of completeness warnings)

### Confidence Tiers

| Tier | Meaning |
|---|---|
| `quick` | Quick mode bug-finding only |
| `bounded` | Standard mode without passing proof layers |
| `proof` | At least one unbounded proof layer passed |
| `certified` | Audit mode with all certification checks passing |

## Commands That Remain Standalone

The following commands are not subsumed by `analyze` and remain available:

- `round-sweep` — Round/view cutoff bound sweeps
- `check-certificate` — Independent certificate verification
- `cert-suite` — Corpus regression testing
- `comm` — Communication complexity reporting
- `visualize` — Counterexample visualization
- `debug-cex` — Interactive counterexample replay
- `show-ta` — Threshold automaton inspection
- `codegen` — Skeleton code generation
