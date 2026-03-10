# Multi-Solver Operations Guide (DOCS-01)

This guide covers practical setup and operation for Tarsier with:
- Z3
- cvc5
- ByMC (cross-tool parity)

## 1) Solver Roles

| Tool | Primary Use in Tarsier | Typical Commands |
|---|---|---|
| Z3 | Default SMT backend for verify/prove/inference | `verify`, `prove`, `infer-invariants`, `analyze` |
| cvc5 | Alternate backend and portfolio/cross-check | `--solver cvc5`, `--portfolio`, certificate replay |
| ByMC | External parity benchmark path over exported automata | `benchmarks/cross_tool_runner.py`, `.ta` export workflows |

## 2) Environment Setup

### Z3 and cvc5

Local prerequisites:

- Build-from-source path: Z3 is built as part of Tarsier (`cargo build` with CMake).
- For cvc5-based runs, install cvc5 on your system `PATH`.

CI-pinned installer (Linux/x86_64):

```bash
bash .github/scripts/install_solvers.sh
z3 --version
cvc5 --version
```

Pinned versions in CI today:
- Z3: `4.12.5`
- cvc5: `1.1.2`

### ByMC

Use the wrapper under `benchmarks/bymc`:

```bash
bash benchmarks/bymc/build-docker.sh
bash benchmarks/bymc/run_bymc.sh --help
```

Reference and troubleshooting:
- `benchmarks/bymc/README.md`

## 3) Operational Commands

### Single-solver runs

```bash
# Z3 (default)
tarsier verify examples/reliable_broadcast.trs --depth 10 --solver z3

# cvc5
tarsier verify examples/reliable_broadcast.trs --depth 10 --solver cvc5
```

### Portfolio proof runs (Z3 + cvc5)

```bash
tarsier analyze examples/reliable_broadcast.trs --goal safety --portfolio --format json
```

### Certificate replay with multi-solver agreement

```bash
tarsier-certcheck certs/pbft --solvers z3,cvc5 --require-two-solvers
```

### ByMC parity run

```bash
python3 benchmarks/cross_tool_runner.py \
  --skip-build \
  --tools bymc \
  --bymc-binary benchmarks/bymc/run_bymc.sh \
  --bymc-mode real \
  --out /tmp/cross-tool-real-bymc.json

python3 .github/scripts/check_cross_tool_verdict_parity.py /tmp/cross-tool-real-bymc.json
```

## 4) Troubleshooting

| Symptom | Likely Cause | Action |
|---|---|---|
| `Unknown solver: cvc5` | cvc5 binary unavailable | Install cvc5 and ensure it is on `PATH` |
| `solver_unknown` outcomes spike | Timeout/resource pressure | Increase `--timeout`, reduce depth/k, or compare with portfolio mode |
| Portfolio returns `Unknown` disagreement | Solver result mismatch | Re-run single-solver commands with same inputs and inspect JSON artifacts |
| Certificate replay fails on one solver | Environment/version mismatch | Record `z3 --version`, `cvc5 --version`; align with pinned CI versions |
| ByMC run exits 127 | Wrapper cannot find local or Docker ByMC | Build image via `benchmarks/bymc/build-docker.sh` and retry |
| ByMC Docker run cannot find model path | Wrong working directory/path mapping | Run from repo root and pass repo-relative model paths |

## 5) Recommended CI Pattern

1. Default CI: Z3-based fast/proof profiles.
2. Portfolio/dual-solver checks: run where confidence matters (proof/audit paths).
3. ByMC parity: targeted or scheduled parity gate with artifact retention.
4. Record solver versions in release artifacts for reproducibility.

## 6) Diagnostics Checklist

When opening a solver-related issue, include:
- exact command line
- model file path/commit SHA
- solver versions (`z3 --version`, `cvc5 --version`)
- JSON artifact output (`--format json` / report files)
- whether issue reproduces in both single-solver and portfolio modes

## 7) Branch Protection Alignment

For merges into `main`, treat solver and parity checks as required status checks:
- `CI / build-test`
- `Mutation Testing (PR Targeted) / mutation-test-pr`
- `ByMC Parity (PR Targeted) / bymc-parity-pr`

Nightly workflows (`mutation-testing.yml`, `bymc-verification.yml`) should remain non-required and be used for broad drift detection plus artifact triage.
