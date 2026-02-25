# ByMC Integration

Run real [ByMC](https://github.com/konnov/bymc) (Byzantine Model Checker) verification against the cross-tool benchmark scenarios.

## Quick Start

```bash
# 1. Build the Docker image (one-time)
bash benchmarks/bymc/build-docker.sh

# 2. Run cross-tool benchmarks with real ByMC
python3 benchmarks/cross_tool_runner.py \
  --skip-build \
  --tools bymc \
  --bymc-binary benchmarks/bymc/run_bymc.sh \
  --bymc-mode real \
  --out /tmp/cross-tool-real.json

# 3. Check verdict parity
python3 .github/scripts/check_cross_tool_verdict_parity.py /tmp/cross-tool-real.json
```

## Pinned Dependencies

| Component | Version | Notes |
|-----------|---------|-------|
| Ubuntu | 18.04 | Last era with good OCaml 4.06 support |
| OCaml | 4.06.1 | Required by ByMC |
| Z3 | 4.8.7 | Compatible with ByMC's Z3 bindings |
| ByMC | v2.4.4 | Pinned tag for reproducibility |
| opam | 2.1.5 | OCaml package manager |

## How It Works

The `run_bymc.sh` wrapper detects the best available ByMC installation:

1. **Local**: If `verifypa-schema` is on `PATH`, use it directly
2. **Docker**: If `tarsier-bymc:latest` image exists, use `docker run`
3. **Neither**: Exit 127 with instructions

The wrapper adds `-O schema.tech=cav15` (fastest safety checking mode) by default.

## ByMC CLI

```
verifypa-schema <file.ta> <spec|all> [options]
```

Output patterns:
- `"Spec <name> holds"` → safe
- `"SLPS: ... verified"` → safe
- `"counterexample for <name> found"` → unsafe

## Troubleshooting

**Docker build fails on OCaml dependencies:**
The Dockerfile uses Ubuntu 18.04 for compatibility. If opam mirror issues occur, retry the build (transient network errors).

**Z3 version mismatch:**
ByMC v2.4.4 requires Z3 4.8.x. Newer Z3 versions may have incompatible API changes.

**Model file not found inside Docker:**
The wrapper mounts the repo root at `/work`. Model file paths must be relative to the repo root.
