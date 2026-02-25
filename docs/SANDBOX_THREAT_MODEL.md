# Sandbox Threat Model

This document describes the threat model for Tarsier's analysis execution sandbox and maps each threat to the enforced runtime controls.

## 1. Scope

The sandbox protects the **analysis execution path**: the sequence from reading a `.trs` source file through parsing, lowering, SMT encoding, and solver invocation. It covers both CLI (`tarsier verify`, `tarsier analyze`, `tarsier prove`, etc.) and programmatic API usage via `tarsier-engine`.

The playground web server (`tarsier-playground`) has its own additional layer of controls (rate limiting, authentication, subprocess isolation) documented in `playground/README.md`.

## 2. Threat Model

| ID | Threat | Vector | Impact |
|----|--------|--------|--------|
| T1 | CPU exhaustion | Crafted `.trs` file triggers unbounded solver exploration | Denial of service; CI timeout; resource starvation |
| T2 | Memory exhaustion | Large protocol model causes Z3/SMT to allocate unbounded memory | OOM kill; system instability; denial of service |
| T3 | Oversized input | Extremely large `.trs` file consumes excessive parse/lower time | CPU/memory exhaustion during parsing |
| T4 | Disk exhaustion | Analysis writes unbounded temporary or output files | Disk space exhaustion |
| T5 | Network exfiltration | Solver or analysis code makes outbound network connections | Data exfiltration; command-and-control |
| T6 | Filesystem escape | Analysis reads/writes files outside intended scope | Information disclosure; tampering |

## 3. Controls

### 3.1 Time/CPU (T1)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| Solver timeout | `tarsier-smt` solver backends | Z3: `timeout` + `solver2_timeout` parameters (ms). CVC5: `--tlimit` flag. |
| Overall deadline | `tarsier-smt` BMC/PDR loops | `deadline_exceeded(deadline: Option<Instant>)` checked at each iteration. |
| Global sandbox timeout | `tarsier-engine::sandbox::SandboxGuard` | Wall-clock deadline set at sandbox activation. Checked via `check_timeout()`. |
| CLI default | `tarsier-cli` | `--timeout` per command (default: 300s). Global sandbox timeout: 600s. |

### 3.2 Memory (T2)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| RSS monitoring | `tarsier-engine::sandbox` | Reads `/proc/self/statm` (Linux) or `mach task_info` (macOS). |
| Global memory budget | `SandboxConfig::memory_budget_mb` | Default: 4096 MiB. Checked via `check_memory()`. |
| Liveness-specific budget | `PipelineExecutionControls::liveness_memory_budget_mb` | Checked at each fair-liveness/PDR iteration. Returns `Unknown` on exceed. |
| Fail-closed | `SandboxGuard::activate()` | If memory monitoring is unavailable and `allow_degraded` is false, activation fails with actionable diagnostic. |

### 3.3 Input Size (T3)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| File size limit | `SandboxConfig::max_input_bytes` | Default: 1 MiB. Validated before reading source file via `sandbox_read_source()`. |
| CLI enforcement | `tarsier-cli` all commands | `sandbox_read_source(&file)` checks file metadata size before reading. |
| Playground enforcement | `tarsier-playground` | `TARSIER_MAX_SOURCE_BYTES` (default: 256 KB) and `TARSIER_MAX_REQUEST_BYTES` (default: 512 KB). |

### 3.4 Disk (T4)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| No intermediate files | Design invariant | Z3 is statically linked and operates in-memory. No temporary files are created during analysis. |
| Output-only writes | CLI output paths | Only `--out`, `--report-out`, `--cert-out` flags produce disk output. No implicit writes. |

### 3.5 Network (T5)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| No outbound connections | Design invariant | Z3 is statically linked (no network). CVC5 subprocess does not initiate connections. |
| Playground isolation | `tarsier-playground` | Worker subprocess inherits network namespace but analysis code path has no networking APIs. |

### 3.6 Filesystem Scope (T6)

| Control | Enforcement Point | Mechanism |
|---------|-------------------|-----------|
| Input validation | `sandbox_read_source()` | Only reads the specified `.trs` file. No path traversal or glob expansion. |
| Output scoping | CLI `--out` flags | Writes only to user-specified output directories. |

## 4. Platform Support

| Platform | Memory Monitoring | Status |
|----------|------------------|--------|
| Linux | `/proc/self/statm` | Full support |
| macOS | `mach task_info` (MACH_TASK_BASIC_INFO) | Full support |
| Other | Not available | Fail-closed unless `--allow-degraded-sandbox` |

## 5. Configuration

| CLI Flag | Default | Description |
|----------|---------|-------------|
| `--sandbox-memory-budget-mb` | 4096 | Global RSS memory budget (MiB) |
| `--sandbox-max-input-bytes` | 1048576 | Maximum `.trs` input file size (bytes) |
| `--allow-degraded-sandbox` | false | Allow execution when some controls are unavailable |
| `--timeout` | 300 (per command) | Solver/analysis timeout (seconds) |
| `--liveness-memory-budget-mb` | 0 (disabled) | Liveness-specific RSS budget (MiB) |

## 6. Residual Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| Z3 internal memory allocation | Z3 may allocate beyond the RSS budget between check intervals | RSS checks are periodic, not continuous. Budget provides best-effort containment. |
| Stack overflow | Deeply recursive protocol models could exhaust stack | Rust's default stack size (8 MiB) provides implicit containment. |
| OS-level resource limits | Sandbox does not use seccomp, AppArmor, or sandbox-exec | OS-level sandboxing is orthogonal; users can layer it on top. |
| CVC5 subprocess | CVC5 runs as a child process with inherited environment | CVC5 subprocess is killed on timeout via `kill_on_drop`. |
