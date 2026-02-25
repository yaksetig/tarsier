# Example Protocol Catalog

This document describes every protocol model shipped with Tarsier. Use it to find relevant examples for your protocol family, understand what each model verifies, and learn which DSL features each model demonstrates.

## Quick Reference

| Protocol | File | Fault Model | Verdict | Key Feature |
|----------|------|-------------|---------|-------------|
| Reliable Broadcast | `reliable_broadcast.trs` | Byzantine | Safe | Intro example |
| Buggy Consensus | `reliable_broadcast_buggy.trs` | Byzantine | **Unsafe** | Bug demo |
| PBFT Simple | `pbft_simple.trs` | Byzantine | Safe | Three-phase BFT |
| Crypto Objects | `crypto_objects.trs` | Byzantine | Safe | `certificate`, `threshold_signature` |
| Algorand Committee | `algorand_committee.trs` | Byzantine | Prob. Safe | `committee` block |
| PBFT Liveness | `pbft_faithful_liveness.trs` | Byzantine | Safe | View-change, GST |
| Temporal Liveness | `temporal_liveness.trs` | Byzantine | Safe | `~>`, `<>` operators |
| Trivial Live | `trivial_live.trs` | Byzantine | Safe | Minimal sanity |

---

## Introductory Examples (`examples/`)

These 8 files are the best starting point for learning Tarsier.

### reliable_broadcast.trs — Bracha Reliable Broadcast

**What it models:** The classic reliable broadcast protocol (Bracha, 1987). A designated sender broadcasts a value, and all honest processes agree on whether to deliver it.

**Phases:** waiting -> echoed -> readied -> done

**Key thresholds:** `>= 1 Init`, `>= 2t+1 Echo`, `>= 2t+1 Ready`

**Property:** Agreement — if any two processes decide, they decide the same value.

**Expected result:** Safe.

**Learn:** Basic protocol structure, threshold guards, the `agreement` property pattern.

```bash
tarsier analyze examples/reliable_broadcast.trs
```

### reliable_broadcast_buggy.trs — Buggy Two-Phase Commit

**What it models:** A flawed two-phase voting protocol where processes can end up in conflicting decision states. The threshold `t+1` is too low, and processes can be influenced by adversary-injected `Abort` messages.

**The bug:** Processes in the `propose` phase can decide NO on receiving an Abort, while processes that already gathered enough Votes proceed to decide YES. Byzantine processes trigger both paths simultaneously.

**Expected result:** **Unsafe** — Tarsier finds a counterexample showing disagreement.

**Learn:** How Tarsier reports counterexamples, why threshold choice matters.

```bash
tarsier analyze examples/reliable_broadcast_buggy.trs --goal bughunt
tarsier visualize examples/reliable_broadcast_buggy.trs --format timeline
```

### pbft_simple.trs — Simplified PBFT

**What it models:** The core safety mechanism of Practical Byzantine Fault Tolerance (Castro & Liskov, 1999). Abstracts away view-change to focus on the PrePrepare -> Prepare -> Commit three-phase pattern.

**Key thresholds:** `>= 1 PrePrepare`, `>= 2t+1 Prepare`, `>= 2t+1 Commit`

**Expected result:** Safe.

**Learn:** The classic BFT three-phase commit pattern.

```bash
tarsier analyze examples/pbft_simple.trs --goal safety
```

### crypto_objects.trs — Cryptographic Objects Demo

**What it models:** Demonstrates Tarsier's first-class cryptographic object support: `certificate` (quorum certificates) and `threshold_signature` constructs.

**Key features:** `certificate PrepareQC from Prepare threshold 2*t+1`, `form`, `has`, `lock`, `justify` actions.

**Expected result:** Safe.

**Learn:** How to model quorum certificates and threshold signatures.

### algorand_committee.trs — Committee-Based Voting

**What it models:** Algorand-style committee selection where a random subset of 100 processes is selected from a population of 1000 (with 333 Byzantine). Tarsier uses hypergeometric distribution analysis to compute the maximum number of Byzantine committee members.

**Key features:** `committee voters { population: 1000; byzantine: 333; size: 100; epsilon: 1.0e-9; bound_param: b; }`

**Expected result:** Probabilistically Safe (with computed failure probability).

**Learn:** Committee declarations, probabilistic verification.

```bash
tarsier analyze examples/algorand_committee.trs
```

### pbft_faithful_liveness.trs — PBFT with View-Change

**What it models:** PBFT with view-change and NewView mechanisms under partial synchrony. Includes a GST parameter that controls when the network stabilizes.

**Key features:** `timing: partial_synchrony`, `gst: gst`, pacemaker, view-change phases.

**Expected result:** Safe.

**Learn:** Partial synchrony modeling, pacemaker declarations, view-change logic.

### temporal_liveness.trs — Temporal Liveness Operators

**What it models:** A simple protocol demonstrating temporal liveness operators.

**Key features:** `~>` (leads-to), `<>` (eventually) in liveness properties.

**Expected result:** Safe.

**Learn:** Temporal property syntax.

### trivial_live.trs — Minimal Sanity Kernel

**What it models:** A trivial protocol where all processes start in the decided state. Used as a sanity check for the liveness verification machinery.

**Expected result:** Safe (trivially).

---

## Protocol Library (`examples/library/`)

The library contains 40 canonical protocol models organized by family. Each model is a compact safety/liveness kernel — not a byte-for-byte implementation, but a faithful threshold-automata abstraction of the protocol's core mechanism.

### How to Read This Catalog

- **Minimal** models use the simplest counter-based semantics
- **Faithful** models use identity-selective networks, signed authentication, per-recipient delivery, and no-equivocation policies for more precise modeling
- **Bug** models are intentionally broken regression sentinels — they should always report Unsafe
- **Variant groups** pair a minimal and faithful model of the same protocol for comparison

---

## PBFT Family

The Practical Byzantine Fault Tolerance family (Castro & Liskov, 1999). Three-phase commit: PrePrepare -> Prepare -> Commit.

### pbft_simple_safe.trs — PBFT Safety Kernel (Minimal)

| Field | Value |
|-------|-------|
| Fault model | Byzantine |
| Resilience | `n > 3*t` |
| Variant | Minimal (`pbft_simple_safe` group) |
| Expected | Safe |

Simplified PBFT checking agreement for a single decided value. No view-change, no value-carrying messages.

### pbft_simple_safe_faithful.trs — PBFT Safety Kernel (Faithful)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation |
| Resilience | `n > 3*t` |
| Variant | Faithful (`pbft_simple_safe` group) |
| Expected | Safe |

Same protocol with faithful network semantics: `distinct` sender counting, authenticated channels, and per-recipient delivery.

### pbft_core.trs — PBFT Core with Partial Synchrony

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Full core PBFT with value-carrying messages and round fields under partial synchrony.

### pbft_view_change.trs — PBFT View-Change

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

PBFT with ViewChange and NewView phases, modeling the view-change protocol that ensures progress after leader failure.

### pbft_crypto_qc_safe_faithful.trs — PBFT with Quorum Certificates (Safe)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation |
| Resilience | `n > 3*t` |
| Expected | Safe |

Demonstrates `certificate` objects with `conflicts exclusive` — forming a QC requires conflicting variants to be rejected.

### pbft_crypto_qc_bug_faithful.trs — PBFT with Quorum Certificates (Buggy)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, **full equivocation** |
| Resilience | `n > 3*t` |
| Expected | **Unsafe** |

Intentionally allows full equivocation with crypto objects, breaking the safety guarantee. A regression sentinel.

---

## HotStuff Family

Linear-communication BFT with leader-driven voting (Yin et al., 2019).

### hotstuff_chained.trs — Chained HotStuff

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Height-based chained voting with Vote, QC, and Commit messages.

### hotstuff_simple_safe_faithful.trs — HotStuff Safety (Faithful)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation, partial synchrony |
| Resilience | `n > 3*t` |
| Variant | Faithful (`hotstuff_safe_kernel` group) |
| Expected | Safe |

Simplified HotStuff with Proposal messages and faithful network model.

### jolteon_fast_hotstuff.trs — Jolteon / Fast-HotStuff

| Field | Value |
|-------|-------|
| Fault model | Byzantine, signed, no equivocation, partial synchrony |
| Resilience | `n > 3*t` |
| Variant | Minimal (`hotstuff_safe_kernel` group) |
| Expected | Safe |

Fast variant of HotStuff with NewView carrying `certificate HighQC`.

### hotstuff_crypto_qc_safe_faithful.trs — HotStuff QC (Safe)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

HotStuff with crypto quorum certificates and faithful modeling.

### hotstuff_crypto_qc_bug_faithful.trs — HotStuff QC (Buggy)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, **full equivocation**, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | **Unsafe** |

Regression sentinel — full equivocation breaks HotStuff safety.

---

## Tendermint Family

Round-based BFT with locking mechanism (Buchman et al., 2018).

### tendermint_locking.trs — Tendermint with Locking

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Models Proposal/Prevote/Precommit phases with the locking mechanism that prevents conflicting commits across rounds.

### tendermint_crypto_qc_safe_faithful.trs — Tendermint QC (Safe)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Tendermint with crypto QC under faithful semantics.

### tendermint_crypto_qc_bug_faithful.trs — Tendermint QC (Buggy)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, **full equivocation**, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | **Unsafe** |

Regression sentinel — full equivocation breaks Tendermint safety.

---

## Streamlet

Simplified blockchain protocol (Chan & Shi, 2020).

### streamlet.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Epoch-based Vote/Notarize protocol under partial synchrony.

---

## Casper FFG

Finality gadget for Ethereum 2.0 (Buterin & Griffith, 2017).

### casper_ffg_like.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Attestation/Justify phases with epoch-based voting.

---

## DLS

Dwork-Lynch-Stockmeyer partial synchrony protocol (1988).

### dls_partial_sync.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Echo/Ready phases, foundational partial-synchrony BFT protocol.

---

## Zyzzyva

Speculative BFT with fast path (Kotla et al., 2007).

### zyzzyva_fastpath.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

SpecResponse/CommitCert fast-path mechanism.

---

## SBFT

Scalable BFT with committee-based voting (Gueta et al., 2019).

### sbft_committee.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Committee-based Prepare/Commit phases.

---

## Algorand

Committee-based sortition voting (Gilad et al., 2017).

### algorand_vote_cert.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

SoftVote/CertVote phases for vote certification.

---

## Narwhal-Bullshark

DAG-based consensus (Danezis et al., 2022).

### narwhal_bullshark_vote.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

DAG voting with DagVote/Cert messages.

---

## Tusk

DAG-based consensus (Danezis et al., 2022).

### tusk_dag_cert.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, signed, no equivocation |
| Resilience | `n > 3*t` |
| Expected | Safe |

DAG certificate mechanism.

---

## GRANDPA

GHOST-based Recursive ANcestor Deriving Prefix Agreement (Stewart, 2020).

### grandpa_finality.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Prevote/Precommit/Finalize phases for Polkadot's finality gadget.

---

## DiemBFT

Diem's BFT engine (formerly LibraBFT).

### diembft_epoch.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, signed, no equivocation, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

Epoch-based consensus with `threshold_signature LedgerQC`.

---

## QBFT

Quorum-based BFT (from Istanbul BFT family).

### qbft_round_change.trs

| Field | Value |
|-------|-------|
| Fault model | Byzantine, signed, no equivocation |
| Resilience | `n = 3*f + 1` |
| Expected | Safe |

Round-change mechanism with Prepare/RoundChange phases.

---

## Paxos Family (Crash Fault Tolerant)

Classic consensus under crash faults (Lamport, 1998).

### paxos_basic.trs

| Field | Value |
|-------|-------|
| Fault model | Crash |
| Resilience | `n > 3*t` |
| Expected | Safe |

Prepare/Promise/Accept/Learn phases.

### multi_paxos_round.trs

| Field | Value |
|-------|-------|
| Fault model | Crash |
| Resilience | `n > 3*t` |
| Expected | Safe |

Per-slot acceptance for the Multi-Paxos optimization.

---

## Raft (Omission Fault Tolerant)

Leader-based consensus for practical systems (Ongaro & Ousterhout, 2014).

### raft_election_safety.trs

| Field | Value |
|-------|-------|
| Fault model | Omission, partial synchrony |
| Resilience | `n > 3*t` |
| Expected | Safe |

RequestVote/Vote/Heartbeat phases for election safety.

---

## Viewstamped Replication (Crash Fault Tolerant)

State machine replication under crash faults (Liskov & Cowling, 2012).

### viewstamped_replication.trs — Safe (Minimal)

| Field | Value |
|-------|-------|
| Fault model | Crash |
| Resilience | `n = 2*f + 1` |
| Variant | Minimal (`vr_safe` group) |
| Expected | Safe |

StartView/Prepare/Commit phases.

### viewstamped_replication_faithful.trs — Safe (Faithful)

| Field | Value |
|-------|-------|
| Fault model | Crash, identity-selective, signed, no equivocation |
| Resilience | `n = 2*f + 1` |
| Variant | Faithful (`vr_safe` group) |
| Expected | Safe |

### viewstamped_replication_buggy.trs — Buggy

| Field | Value |
|-------|-------|
| Fault model | Crash |
| Resilience | `n = 2*f + 1` |
| Expected | **Unsafe** |

Intentionally broken threshold (threshold=0 race condition). Regression sentinel.

---

## ZAB (Omission Fault Tolerant)

Zookeeper Atomic Broadcast (Hunt et al., 2010).

### zab_atomic_broadcast.trs — Safe (Minimal)

| Field | Value |
|-------|-------|
| Fault model | Omission, partial synchrony |
| Resilience | `n = 2*f + 1` |
| Variant | Minimal (`zab_safe` group) |
| Expected | Safe |

Proposal/Ack/Commit phases with epoch-based ordering.

### zab_atomic_broadcast_faithful.trs — Safe (Faithful)

| Field | Value |
|-------|-------|
| Fault model | Omission, identity-selective, signed, no equivocation, partial synchrony |
| Resilience | `n = 2*f + 1` |
| Variant | Faithful (`zab_safe` group) |
| Expected | Safe |

### zab_atomic_broadcast_buggy.trs — Buggy

| Field | Value |
|-------|-------|
| Fault model | Omission, partial synchrony |
| Resilience | `n = 2*f + 1` |
| Expected | **Unsafe** |

Intentionally broken ordering logic. Regression sentinel.

---

## Reliable Broadcast (Library Variants)

### reliable_broadcast_safe.trs — Safe (Minimal)

| Field | Value |
|-------|-------|
| Fault model | Byzantine |
| Resilience | `n > 3*t` |
| Variant | Minimal (`reliable_broadcast_safe` group) |
| Expected | Safe |

### reliable_broadcast_safe_faithful.trs — Safe (Faithful)

| Field | Value |
|-------|-------|
| Fault model | Byzantine, identity-selective, signed, no equivocation |
| Resilience | `n > 3*t` |
| Variant | Faithful (`reliable_broadcast_safe` group) |
| Expected | Safe |

### reliable_broadcast_buggy.trs — Buggy

| Field | Value |
|-------|-------|
| Fault model | Byzantine |
| Resilience | `n > 3*t` |
| Expected | **Unsafe** |

---

## HoneyBadgerBFT ACS

Asynchronous Common Subset (Miller et al., 2016).

### hbbft_acs_like.trs

| Field | Value |
|-------|-------|
| Fault model | Omission |
| Resilience | `n = 3*f + 1` |
| Expected | Safe |

RBCDone/BACommit phases for ACS-like pattern.

---

## Liveness and Testing Kernels

### trivial_live.trs

Minimal sanity kernel — all processes start decided. Used to validate liveness verification machinery.

### temporal_liveness_counterexample.trs

Demonstrates a bounded liveness counterexample using temporal operators.

---

## Variant Groups

Variant groups pair a **minimal** (classic/legacy) and **faithful** model of the same protocol for comparison. The minimal model uses simple counter-based semantics (`network: classic`); the faithful model adds identity-selective networks, authentication, and no-equivocation policies. For a detailed explanation of when these modes produce different verdicts and why, see `docs/INTERPRETATION_MATRIX.md`.

| Group | Minimal | Faithful |
|-------|---------|----------|
| `pbft_simple_safe` | `pbft_simple_safe.trs` | `pbft_simple_safe_faithful.trs` |
| `hotstuff_safe_kernel` | `jolteon_fast_hotstuff.trs` | `hotstuff_simple_safe_faithful.trs` |
| `reliable_broadcast_safe` | `reliable_broadcast_safe.trs` | `reliable_broadcast_safe_faithful.trs` |
| `vr_safe` | `viewstamped_replication.trs` | `viewstamped_replication_faithful.trs` |
| `zab_safe` | `zab_atomic_broadcast.trs` | `zab_atomic_broadcast_faithful.trs` |

---

## Fault Model Coverage

| Fault Model | Protocols |
|-------------|-----------|
| **Byzantine** | PBFT, HotStuff, Tendermint, Streamlet, Casper, DLS, Zyzzyva, SBFT, Algorand, Narwhal-Bullshark, GRANDPA, QBFT, DiemBFT, Tusk, Reliable Broadcast |
| **Crash** | Paxos, Multi-Paxos, Viewstamped Replication |
| **Omission** | Raft, Zab, HBBFT ACS |

---

## Running the Full Corpus

To verify all library protocols at once using the certification suite:

```bash
# Text output
tarsier cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format text

# JSON output with artifacts
tarsier cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format json --out artifacts/cert-suite.json --artifacts-dir artifacts/cert-suite

# Or use the convenience script
./scripts/certify-corpus.sh
```

See `docs/CERT_SUITE_SCHEMA.md` for the manifest format and `examples/library/README.md` for maintenance policies.
