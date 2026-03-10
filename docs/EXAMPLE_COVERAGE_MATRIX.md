# Example Feature-Coverage Matrix (EXAMPLE-01)

> Produced by auditing all 82 `.trs` files across `examples/`, `examples/library/`, and `examples/experimental/`.

## Feature Coverage Summary

| Feature | Safe Examples | Unsafe Examples | Coverage | Missing Pairs |
|---------|:---:|:---:|:---:|---|
| Message guards (threshold) | 45+ | 8 | Full | — |
| Distinct guards | 18+ | 4 | Full | — |
| Boolean variables | 40+ | 10+ | Full | — |
| Multiple phases | 50+ | 15+ | Full | — |
| Agreement property | 45+ | 8+ | Full | — |
| Crypto objects (form/lock/justify) | 12+ | 3 | Full | — |
| Multiple roles | 8+ | 2 | Good | — |
| Reconfigure actions | 2 | 2 | Good | — |
| Liveness property | 7 | 2 | Good | — |
| DAG rounds | 4 | 1 | Good | — |
| Enum variables | 1 | 1 | Full | — |
| Clocks/timeouts | 1 | 1 | Full | — |
| Collections (FIFO) | 1 | 1 | Good | — |
| Collections (bounded log) | 1 | 1 | Full | — |
| Committees | 3 | 1 | Full | — |
| Pacemaker | 1 | 1 | Full | — |
| Crash-recovery adversary | 1 | 1 | Full | — |
| Filtered guards (message_args) | 1 | 1 | Full | — |
| Leader election | 1 | 1 | Full | — |

## EXAMPLE-02 Additions (Gaps Closed)

The following examples were added in EXAMPLE-02 to close all previously reported
safe/unsafe pair gaps. Library entries were registered in
`examples/library/cert_suite.json` with expected verdict metadata. The
crash-recovery counterpart remains outside the strict cert-suite set and is
tracked in this matrix as metadata-only coverage.

| File | Feature | Expected Verdict |
|---|---|---|
| `clock_timeout_safe.trs` | Clocks/timeouts | Safe |
| `voting_enum_buggy.trs` | Enum variables | Unsafe |
| `bounded_log_overflow_buggy.trs` | Bounded collections (log) | Unsafe |
| `committee_weak_bound_buggy.trs` | Committees | Unsafe |
| `filtered_guard_safe.trs` | Filtered guards (`message_args`) | Safe |
| `filtered_guard_buggy.trs` | Filtered guards (`message_args`) | Unsafe |
| `leader_equivocation_buggy.trs` | Leader role | Unsafe |
| `crash_recovery_amnesia_buggy.trs` | Crash-recovery | Unsafe |
| `pacemaker_stuck_buggy.trs` | Pacemaker | Unsafe |

## Verdict Distribution

| Category | Count | Percentage |
|----------|------:|----------:|
| Safe (expected) | 57 | 63% |
| Unsafe (expected) | 28 | 31% |
| Invalid/parse error | 2 | 2% |
| Reproducer/test | 4 | 5% |
| **Total** | **91** | 100% |

The safe:unsafe ratio is now ~2.0:1 and every previously identified partial/missing
feature now has at least one safe and one unsafe exemplar.

## Protocol Family Coverage

| Protocol Family | Examples | Notes |
|----------------|------:|-------|
| PBFT variants | 12 | Core, faithful, crypto, liveness, view change |
| Reliable Broadcast | 10 | Safe, buggy, faithful, cohort/process selective |
| HotStuff variants | 5 | Simple, chained, crypto QC (safe+buggy) |
| Tendermint variants | 4 | Locking, crypto QC (safe+buggy) |
| Paxos/Multi-Paxos | 2 | Basic + multi-round |
| Raft | 1 | Election safety only |
| Algorand | 2 | Vote cert + committee |
| DAG protocols | 7 | Diamond, chain, multi-root, conflicting, invalid |
| View-stamped | 3 | Safe, buggy, faithful |
| ZAB | 3 | Safe, buggy, faithful |
| Misc (Streamlet, Jolteon, etc.) | 10+ | Single examples each |
