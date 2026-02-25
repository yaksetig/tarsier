# Partial-Order Reduction: Independence Relation Specification

## 1. Introduction

Partial-Order Reduction (POR) exploits the commutativity of independent transitions to
prune redundant interleavings from the state-space exploration. In Tarsier's counter
abstraction, a "transition" corresponds to a threshold automaton **rule** — a guarded
step that moves processes between locations and updates shared message counters.

POR can dramatically reduce the number of rules the SMT encoder must consider and the
number of cubes the PDR engine must explore, without affecting the set of reachable
states for safety properties.

## 2. Independence Relation

Two rules `r1` and `r2` are **independent** if and only if all three conditions hold:

| # | Condition | Intuition |
|---|-----------|-----------|
| 1 | **Disjoint locations:** `{r1.from, r1.to} ∩ {r2.from, r2.to} = ∅` | The rules operate on entirely separate locations in the automaton. |
| 2 | **Different roles:** `role(r1.from) ≠ role(r2.from)` | The rules belong to different protocol roles, so they cannot originate from the same population of processes. |
| 3 | **No read/write conflicts:** `writes(r1) ∩ writes(r2) = ∅` **and** `writes(r1) ∩ reads(r2) = ∅` **and** `writes(r2) ∩ reads(r1) = ∅` | Neither rule's guard depends on a counter that the other rule modifies, and the two rules do not update any common counter. |

Where:
- `writes(r)` = the set of shared variable IDs updated by rule `r`
- `reads(r)` = the set of shared variable IDs referenced in `r`'s guard

When two rules are independent, the order in which they fire does not affect the
resulting state, so the model checker can safely consider only one ordering.

## 3. Worked Examples

### Example 1: Independent Rules (Proposer broadcast / Replica receive)

```
rule r1: Proposer@Init -> Proposer@Proposed
  guard: true
  update: cnt_Propose@Replica += 1

rule r2: Replica@WaitPropose -> Replica@Voted
  guard: cnt_Propose@Replica >= 1
  update: cnt_Vote@Proposer += 1
```

**Analysis:**
1. Locations: `{Proposer@Init, Proposer@Proposed}` ∩ `{Replica@WaitPropose, Replica@Voted}` = ∅ ✓
2. Roles: `Proposer ≠ Replica` ✓
3. R/W sets:
   - `writes(r1)` = `{cnt_Propose@Replica}`, `writes(r2)` = `{cnt_Vote@Proposer}` → disjoint ✓
   - `writes(r1) ∩ reads(r2)` = `{cnt_Propose@Replica}` ∩ `{cnt_Propose@Replica}` = `{cnt_Propose@Replica}` ✗

**Verdict: NOT independent.** Even though locations and roles are disjoint, rule r1 writes
`cnt_Propose@Replica` which rule r2 reads in its guard. Firing r1 before r2 can enable r2's
guard, while the reverse order may not — so order matters.

### Example 2: Independent Rules (Disjoint counters)

```
rule r1: Proposer@Init -> Proposer@Proposed
  guard: true
  update: cnt_Propose@Replica += 1

rule r3: Acceptor@Init -> Acceptor@Accepted
  guard: cnt_Accept@Acceptor >= t + 1
  update: cnt_Done@Learner += 1
```

**Analysis:**
1. Locations: `{Proposer@Init, Proposer@Proposed}` ∩ `{Acceptor@Init, Acceptor@Accepted}` = ∅ ✓
2. Roles: `Proposer ≠ Acceptor` ✓
3. R/W sets:
   - `writes(r1)` = `{cnt_Propose@Replica}`, `writes(r3)` = `{cnt_Done@Learner}` → disjoint ✓
   - `writes(r1) ∩ reads(r3)` = `{cnt_Propose@Replica}` ∩ `{cnt_Accept@Acceptor}` = ∅ ✓
   - `writes(r3) ∩ reads(r1)` = `{cnt_Done@Learner}` ∩ ∅ = ∅ ✓

**Verdict: Independent.** These rules can be reordered freely without affecting reachability.

### Example 3: Not Independent — Same Role

```
rule r4: Replica@WaitPropose -> Replica@Voted
  guard: cnt_Propose@Replica >= 1
  update: cnt_Vote@Proposer += 1

rule r5: Replica@Voted -> Replica@Decided
  guard: cnt_Vote@Proposer >= 2*t + 1
  update: (none)
```

**Verdict: NOT independent.** Both rules originate from the Replica role (condition 2 fails).
In counter abstraction, processes within the same role share a single population counter, so
firing one rule changes the location counters available for the other.

### Example 4: Not Independent — Write/Write Conflict

```
rule r6: RoleA@L0 -> RoleA@L1
  guard: true
  update: cnt_Vote@Proposer += 1

rule r7: RoleB@L2 -> RoleB@L3
  guard: true
  update: cnt_Vote@Proposer += 1
```

**Verdict: NOT independent.** Both rules write to `cnt_Vote@Proposer` (condition 3 fails:
`writes(r6) ∩ writes(r7) ≠ ∅`). Although each individual increment is the same, the
combined effect on threshold guards can differ depending on interleaving.

## 4. Counterexample: Why Naive Commutativity Is Unsound

Consider two rules that both increment the same counter `cnt_Vote@R`:

```
Step A: cnt_Vote@R goes from 2 to 3  (rule r6)
Step B: cnt_Vote@R goes from 3 to 4  (rule r7)
```

If a guard checks `cnt_Vote@R >= 3`, it becomes enabled after step A. In the reverse
order (B then A), the counter goes 2 → 3 → 4, and the guard is also enabled after
step B — but any rule gated on `cnt_Vote@R >= 3` that fires *between* the two steps
would see different intermediate states. In counter abstraction, threshold crossings
are the critical observable events; skipping an interleaving that crosses a threshold
at a different point can miss or create reachable states.

This is why condition 3 (no R/W conflicts) is essential: it ensures that threshold
crossings are invariant under reordering.

## 5. POR Modes

Tarsier supports three POR modes, selectable via the DSL or CLI:

| Mode | Static Pruning | Dynamic Ample | Assumptions |
|------|---------------|---------------|-------------|
| `full` (default) | ✓ Stutter elimination, commutative-duplicate detection, guard domination | ✓ Per-cube ample set in PDR | Safety-only properties (reachability-preserving). |
| `static` | ✓ Same three static strategies | ✗ Disabled | No assumptions beyond the counter-abstraction model. Static pruning removes only provably redundant rules (identical effects or subsumed guards). |
| `off` | ✗ All rules active | ✗ All rules active | None. Full state-space exploration. Useful for debugging, cross-validation, or when POR assumptions may not hold. |

### Assumptions

- **`full` mode** assumes that the property being checked is a **safety property**
  (reachability). The dynamic ample-set optimization prunes rules that are independent
  of the current PDR cube's constrained variables. This is sound for safety
  (reachability-preserving) but may not preserve all liveness witnesses.

- **`static` mode** makes no assumptions beyond the counter-abstraction model itself.
  The three static pruning strategies (stutter, duplicate, guard domination) are
  semantically equivalent transformations: they remove rules that provably produce
  identical or subsumed successor states.

- **`off` mode** disables all POR optimizations. This is the most conservative setting
  and is useful for:
  - Debugging suspected POR-related issues
  - Cross-validating results between POR-enabled and POR-disabled runs
  - Protocols with unusual structure where POR assumptions warrant review

## 6. Configuration

### DSL Configuration

Set the POR mode in the `adversary` block:

```
adversary {
    bound: f;
    model: byzantine;
    por: full;      // or: static, off
}
```

Accepted values for the `por` key:
- `full` — all POR optimizations enabled (default)
- `static`, `static_only` — static pruning only
- `off`, `none`, `disabled` — all POR optimizations disabled

### CLI Configuration

Override the DSL setting with the `--por-mode` global flag:

```bash
tarsier analyze my_protocol.trs --por-mode off
tarsier analyze my_protocol.trs --por-mode static
tarsier analyze my_protocol.trs --por-mode full   # default
```

The CLI flag takes precedence over the DSL value when a non-default value is specified.

## 7. Equivalence and Soundness Regression Tests

POR correctness is verified by a CI regression suite that runs reference protocols with all three POR modes and asserts:

1. **Verdict equivalence:** Safe protocols produce Safe with `Full`, `Static`, and `Off`. Buggy protocols produce Unsafe with all modes.
2. **Counterexample preservation:** Known-buggy protocols (e.g., `reliable_broadcast_buggy.trs`) still produce actionable counterexample traces with POR enabled.
3. **Reduction effectiveness:** POR `Full` yields `por_effective_rule_count <= Off`, confirming that static pruning actually removes rules.

These tests live in `crates/tarsier-engine/tests/integration_tests.rs` (search for `por_equivalence` and `por_soundness`). The CI gate is "POR Equivalence and Soundness Regression Gate" in `.github/workflows/ci.yml`.

## 8. Reduction Diagnostics

POR reduction diagnostics are exposed in both JSON and text reports:

**JSON reports** (via `run_diagnostics_details()`):
- `lowerings[].por_stutter_rules_pruned` — rules pruned by stutter reduction
- `lowerings[].por_commutative_duplicate_rules_pruned` — duplicate rule signatures pruned
- `lowerings[].por_guard_dominated_rules_pruned` — guard-dominated rules pruned
- `lowerings[].por_effective_rule_count` — rules remaining after POR
- `lowerings[].independent_rule_pairs` — independent pairs enabling POR
- `applied_reductions[]` — network fallback entries with before/after footprints
- `reduction_notes[]` — dedup'd string entries (e.g., `por.independent_rule_pairs=N`)
- `por_dynamic_ample` — dynamic ample-set statistics from SMT profiles

**Counterexample traces** include per-step `por_status` annotations:
- `"active (full POR)"` — rule survived POR pruning with full optimizations
- `"active (static POR)"` — rule survived static-only pruning
- `null` — POR was off, no reduction applied

**Text output** (`render_optimization_summary()`):
```
POR: X rules pruned (Y stutter, Z commutative-dup, W guard-dominated), E effective rules, I independent pairs
```

## 9. Parallel-Run Isolation

POR mode overrides are now isolated per thread:

- `set_execution_controls(...)` sets a **thread-local** override.
- `set_global_execution_controls(...)` sets the process-wide default used when
  no thread-local override exists (CLI uses this path before spawning worker threads).

This prevents cross-test contamination where one test setting `por: full` could
accidentally affect another test expecting `por: off` under parallel execution.
The POR CI gates now run without forcing single-thread execution so this isolation
is continuously validated.

## 10. Cross-References

- **Formal semantics:** `docs/SEMANTICS.md` §6.6 — Partial-Order Reduction Soundness
- **Static pruning implementation:** `crates/tarsier-smt/src/encoder.rs` — `compute_por_rule_pruning()`
- **Dynamic ample-set implementation:** `crates/tarsier-smt/src/bmc.rs` — `dynamic_ample_disabled_rules_for_cube()`
- **Pipeline diagnostics:** `crates/tarsier-engine/src/pipeline.rs` — `por_rule_pruning_summary()`
- **IR enum:** `crates/tarsier-ir/src/threshold_automaton.rs` — `PorMode`
- **Regression tests:** `crates/tarsier-engine/tests/integration_tests.rs` — `por_equivalence_*`, `por_soundness_*`, `por_full_reduces_*`
