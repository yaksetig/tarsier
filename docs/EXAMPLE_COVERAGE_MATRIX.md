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
| Enum variables | 1 | 0 | **Partial** | Need unsafe enum pair |
| Clocks/timeouts | 0 | 1 | **Partial** | Need safe clock pair |
| Collections (FIFO) | 1 | 1 | Good | — |
| Collections (bounded log) | 1 | 0 | **Partial** | Need unsafe bounded-log pair |
| Committees | 3 | 0 | **Partial** | Need unsafe committee pair |
| Pacemaker | 1 | 0 | **Partial** | Need unsafe pacemaker pair |
| Crash-recovery adversary | 1 | 0 | **Partial** | Need unsafe crash-recovery pair |
| Filtered guards (message_args) | 0 | 0 | **Missing** | Need safe+unsafe pair |
| Leader election | 1 | 0 | **Partial** | Need unsafe leader pair |

## Identified Gaps (Missing Safe/Unsafe Pairs)

### GAP-A: Clocks/Timeouts — No Safe Example
- **Existing unsafe:** `clock_premature_buggy.trs` (premature timeout causes disagreement)
- **Missing:** A safe protocol that correctly uses clock guards and timeout resets
- **Priority:** High — clocks are a core feature used in real protocols

### GAP-B: Enum Variables — No Unsafe Example
- **Existing safe:** `voting_enum_phases.trs` (enum decision variable)
- **Missing:** An unsafe protocol where enum variable semantics allow disagreement
- **Priority:** Medium — enum is a newer feature that should have both polarity tests

### GAP-C: Bounded Collections (Log) — No Unsafe Example
- **Existing safe:** `bounded_log_demo.trs` (append to bounded log)
- **Missing:** An unsafe protocol where bounded collection overflow or weak guard causes bug
- **Priority:** Medium — bounded collections interact with threshold guards

### GAP-D: Committees — No Unsafe Example
- **Existing safe:** `algorand_committee.trs`, `minimmit_safe_faithful.trs`, `phoenixx_safe_faithful.trs`
- **Missing:** An unsafe protocol where committee sampling bound is insufficient
- **Priority:** Medium — probabilistic safety is a key differentiator

### GAP-E: Filtered Guards (message_args) — No Examples At All
- **Existing:** None
- **Missing:** Both safe and unsafe examples demonstrating filtered message guards
- **Priority:** Low-Medium — filtered guards exist in the DSL but have no example coverage

### GAP-F: Pacemaker — No Unsafe Example
- **Existing safe:** `pbft_faithful_liveness.trs` (pacemaker with view changes)
- **Missing:** An unsafe protocol where pacemaker semantics cause a bug
- **Priority:** Low — pacemaker is an advanced feature

### GAP-G: Crash-Recovery — No Unsafe Example
- **Existing safe:** `crash_recovery_demo.trs`
- **Missing:** An unsafe protocol under crash-recovery model
- **Priority:** Low — crash-recovery is a niche adversary model

### GAP-H: Leader Role — No Unsafe Example
- **Existing safe:** `leader_role_demo.trs`
- **Missing:** An unsafe protocol where leader misbehavior causes disagreement
- **Priority:** Low-Medium — leader roles are common in BFT protocols

## Recommended New Examples (EXAMPLE-02)

Priority order for creating missing pairs:

| # | File Name | Feature | Polarity | Effort |
|---|-----------|---------|----------|--------|
| 1 | `clock_timeout_safe.trs` | Clocks/timeouts | Safe | Medium |
| 2 | `voting_enum_buggy.trs` | Enum variables | Unsafe | Low |
| 3 | `bounded_log_overflow_buggy.trs` | Bounded collections | Unsafe | Low-Medium |
| 4 | `committee_weak_bound_buggy.trs` | Committees | Unsafe | Medium |
| 5 | `filtered_guard_safe.trs` | Filtered guards | Safe | Medium |
| 6 | `filtered_guard_buggy.trs` | Filtered guards | Unsafe | Medium |
| 7 | `leader_equivocation_buggy.trs` | Leader role | Unsafe | Low-Medium |
| 8 | `crash_recovery_amnesia_buggy.trs` | Crash-recovery | Unsafe | Low-Medium |
| 9 | `pacemaker_stuck_buggy.trs` | Pacemaker | Unsafe | Medium |

## Verdict Distribution

| Category | Count | Percentage |
|----------|------:|----------:|
| Safe (expected) | 55 | 67% |
| Unsafe (expected) | 21 | 26% |
| Invalid/parse error | 2 | 2% |
| Reproducer/test | 4 | 5% |
| **Total** | **82** | 100% |

The safe:unsafe ratio of ~2.6:1 is reasonable. The gaps above would bring
under-covered features to at least one safe + one unsafe example each.

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
