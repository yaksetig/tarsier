# Parameterized Verification in Tarsier

This document explains what Tarsier's verification results mean, when they generalize, and how to increase confidence in your verified protocol.

## What Is Parameterized Verification?

Tarsier verifies consensus protocols modeled as **threshold automata** — parameterized systems where `N` processes interact via threshold-guarded transitions. The parameters `n` (total processes), `t` (fault tolerance), and `f` (actual faults) remain symbolic throughout verification. A safety proof in Tarsier holds for **all** parameter instantiations satisfying the resilience condition (e.g., `n > 3*t`), not just a single concrete instance.

This is the key advantage of counter abstraction: instead of checking the protocol for `n=4, t=1`, Tarsier reasons about the protocol for **every** `n` and `t` simultaneously.

## What BMC Covers (and Doesn't)

### Bounded Model Checking (BMC)

The `verify` and `analyze --goal bughunt` commands use bounded model checking:

- **What it checks:** All possible executions up to a fixed depth `k` (number of transition steps).
- **What "Safe" means:** No counterexample exists within `k` steps. The protocol may still be unsafe at depth `k+1`.
- **What "Unsafe" means:** A concrete counterexample exists — this is a definitive bug.

BMC is **sound for bug-finding** (an Unsafe result is always a real bug) but **incomplete for proofs** (a Safe result at depth `k` does not imply safety at all depths).

### Unbounded Proofs

The `prove` command uses k-induction or PDR (IC3) to prove safety at **all** depths:

- **k-induction:** If the property holds for k base steps and the inductive step succeeds, the property holds forever.
- **PDR (IC3):** Iteratively strengthens invariants until either a proof or counterexample is found.

Use `tarsier prove` or `tarsier analyze --goal safety` to obtain unbounded safety guarantees.

## When Results Generalize: Cutoff Results

A natural question is: does verifying a threshold automaton with counter abstraction cover all possible system sizes? The answer comes from **cutoff results** in the literature:

For **symmetric threshold automata** (all processes in the same role follow the same protocol), small-model cutoffs exist. Specifically:

- Konnov, Lazic, Veith, and Widder (LMCS 2017) showed that for a class of threshold-guarded protocols, there exists a **cutoff** — a system size beyond which no new behaviors arise. Checking a bounded number of representative configurations suffices to verify the protocol for all sizes.
- Tarsier's counter abstraction inherently captures this: the symbolic encoding over `n, t, f` with counter variables (how many processes are in each location) already abstracts away individual process identities.

**In practice:** If Tarsier proves safety with `tarsier prove`, the result holds for all `n, t` satisfying the resilience condition. The counter abstraction is exact for the class of protocols expressible as threshold automata.

## How to Increase Confidence

### 1. Increase BMC Depth

```bash
tarsier verify my_protocol.trs --depth 20
```

Deeper bounds catch bugs with longer attack sequences.

### 2. Use Unbounded Proof

```bash
tarsier prove my_protocol.trs --engine kinduction --k 12
tarsier prove my_protocol.trs --engine pdr
```

A successful proof eliminates the depth limitation entirely.

### 3. Use Portfolio Mode

```bash
tarsier prove my_protocol.trs --portfolio
```

Runs Z3 and cvc5 in parallel, combining results conservatively. If either solver proves safety, the result is trusted.

### 4. Generate and Verify Certificates

```bash
tarsier certify-safety my_protocol.trs --cert-out /tmp/cert
tarsier-certcheck /tmp/cert
```

The `certify-safety` command generates an independently checkable proof bundle. The separate `tarsier-certcheck` binary (with a minimal trusted computing base) re-verifies the proof obligations using an external solver.

### 5. Use Round Sweeps

```bash
tarsier round-sweep my_protocol.trs --vars view --min-bound 2 --max-bound 16
```

Sweeps the view/round upper bound to check whether the verdict stabilizes, increasing confidence that the bound is sufficient.

## Counter Abstraction Limitations

Tarsier's counter abstraction is powerful but has inherent limitations under the default `network: classic` mode. Faithful network modes (`identity_selective`, `cohort_selective`, `process_selective`) address several of these — see `docs/INTERPRETATION_MATRIX.md` for the full comparison.

1. **No per-process state within a location (classic mode).** All processes in the same location are indistinguishable. The abstraction tracks *how many* processes are in each location, not *which* ones. If your protocol's correctness depends on distinguishing specific processes within the same state, the classic abstraction may be too coarse. **Mitigation:** `network: process_selective` assigns each process a distinct `pid` with per-process channels, achieving instance-exact semantics (see `SEMANTICS.md` Theorem 3). `network: identity_selective` provides sender-identity tracking without full per-process state.

2. **Global adversary injection (classic mode).** Byzantine message injections are modeled globally — the adversary injects messages that affect all counters uniformly. The model cannot represent scenarios where the adversary delivers different messages to different individual processes within the same location. **Mitigation:** `network: identity_selective` introduces sender-budget-coupled per-recipient delivery. `network: process_selective` provides per-process adversary activation with a static faulty-sender set.

3. **Disagreement requires different locations.** For a safety violation like agreement to be detected, processes must be in *different* decided locations. If your protocol has only one decision state, agreement is trivially safe — which is correct, not a limitation. This applies equally to all network modes.

4. **Finite-domain local variables.** Local variables must have finite domains (bool, bounded nat/int, enums). Unbounded local state requires manual abstraction. This applies equally to all network modes.

5. **No liveness without fairness.** Pure BMC cannot prove liveness properties. Use `tarsier fair-liveness` or `tarsier prove-fair` with appropriate fairness assumptions. This applies equally to all network modes.

## References

1. **Konnov, Lazic, Veith, Widder.** "A short counterexample property for safety and liveness verification of fault-tolerant distributed algorithms." *LMCS*, 2017. — Cutoff results for threshold-guarded protocols.

2. **Lazic, Konnov, Widder, Bloem.** "Synthesis of distributed algorithms with threshold guards." *LMCS*, 2017. — Synthesis and verification of threshold automata.

3. **John, Konnov, Schmid, Stoilkovska, Widder.** "Parameterized model checking of fault-tolerant distributed algorithms by abstraction." *FMCAD*, 2013. — Counter abstraction foundations for threshold automata.

4. **Konnov, Widder, Bloem.** "ByMC: Byzantine Model Checker." *ISoLA*, 2018. — Tool and methodology for verifying threshold-guarded protocols.
