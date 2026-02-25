# Protocol Library

This folder contains the canonical protocol corpus for BFT/CFT consensus-family checks.
Maintenance ownership/cadence/SLA policy is defined in `docs/CORPUS_MAINTENANCE_POLICY.md`.

Current scope:
- The models are compact safety/liveness kernels, not byte-for-byte implementations.
- They focus on threshold structure, quorum rules, fault model, timing model, and value flow.
- Most BFT entries use `adversary { model: byzantine; timing: partial_synchrony; gst: ...; values: sign; }`.
- CFT entries use `model: crash` or `model: omission`.
- `cert_suite.json` is schema v2 and classifies each protocol as:
- `class=expected_safe`: expected to satisfy configured safety/liveness checks.
- `class=known_bug`: expected to exhibit a configured safety/liveness violation.
- `class=known_bug` entries are intentional regression sentinels and must retain a bug-revealing expected outcome (`unsafe`/`not_live`/`fair_cycle_found`).
- The manifest includes both safety (`verify`/`prove`) and liveness (`liveness`/`fair_liveness`/`prove_fair`) expectations.
- For schema v2, every entry must define at least one expected outcome and a non-empty `notes` rationale.
- For schema v2, every entry must pin `model_sha256` (SHA-256 of the `.trs` file).
- Where relevant, entries also declare `variant=minimal|faithful` and `variant_group`; each group must include both variants.
- `enforce_library_coverage=true` ensures every `examples/library/*.trs` file has an expectation entry.
- Expected-outcome values are schema-checked by check type (for example `safe`/`unsafe`/`unknown`, `live`/`not_live`, etc.).
- Schema contract docs: `docs/CERT_SUITE_SCHEMA.md` and `docs/cert-suite-schema-v2.json`.

Protocols included (42):
- `pbft_core.trs`
- `pbft_liveness_safe_ci.trs`
- `pbft_liveness_buggy_ci.trs`
- `pbft_view_change.trs`
- `pbft_simple_safe.trs` (minimal, variant_group: pbft_simple_safe)
- `pbft_simple_safe_faithful.trs` (faithful, variant_group: pbft_simple_safe)
- `pbft_crypto_qc_safe_faithful.trs`
- `pbft_crypto_qc_bug_faithful.trs`
- `tendermint_locking.trs`
- `tendermint_crypto_qc_safe_faithful.trs`
- `tendermint_crypto_qc_bug_faithful.trs`
- `hotstuff_chained.trs`
- `hotstuff_simple_safe_faithful.trs` (faithful, variant_group: hotstuff_safe_kernel)
- `jolteon_fast_hotstuff.trs` (minimal, variant_group: hotstuff_safe_kernel)
- `hotstuff_crypto_qc_safe_faithful.trs`
- `hotstuff_crypto_qc_bug_faithful.trs`
- `streamlet.trs`
- `casper_ffg_like.trs`
- `dls_partial_sync.trs`
- `zyzzyva_fastpath.trs`
- `sbft_committee.trs`
- `algorand_vote_cert.trs`
- `narwhal_bullshark_vote.trs`
- `grandpa_finality.trs`
- `paxos_basic.trs`
- `multi_paxos_round.trs`
- `raft_election_safety.trs`
- `viewstamped_replication.trs` (minimal, variant_group: vr_safe)
- `viewstamped_replication_buggy.trs`
- `viewstamped_replication_faithful.trs` (faithful, variant_group: vr_safe)
- `qbft_round_change.trs`
- `diembft_epoch.trs`
- `hbbft_acs_like.trs`
- `tusk_dag_cert.trs`
- `zab_atomic_broadcast.trs` (minimal, variant_group: zab_safe)
- `zab_atomic_broadcast_buggy.trs`
- `zab_atomic_broadcast_faithful.trs` (faithful, variant_group: zab_safe)
- `reliable_broadcast_safe.trs` (minimal, variant_group: reliable_broadcast_safe)
- `reliable_broadcast_safe_faithful.trs` (faithful, variant_group: reliable_broadcast_safe)
- `reliable_broadcast_buggy.trs`
- `temporal_liveness_counterexample.trs`
- `trivial_live.trs`

Variant groups (5):
- `pbft_simple_safe`: minimal + faithful PBFT three-phase safety kernel
- `hotstuff_safe_kernel`: minimal Jolteon + faithful HotStuff two-phase safety kernel
- `reliable_broadcast_safe`: minimal + faithful Bracha reliable broadcast
- `vr_safe`: minimal + faithful Viewstamped Replication (crash faults)
- `zab_safe`: minimal + faithful Zab atomic broadcast (omission faults)

Fault model coverage:
- Byzantine (BFT): PBFT, HotStuff, Tendermint, Streamlet, Casper, DLS, Zyzzyva, SBFT, Algorand, Narwhal-Bullshark, GRANDPA, QBFT, DiemBFT, Tusk
- Crash (CFT): Paxos, Multi-Paxos, Viewstamped Replication
- Omission: Raft, Zab, HoneyBadgerBFT ACS

Recommended checks:

```bash
./scripts/certify-corpus.sh
cargo run -p tarsier-cli -- verify examples/library/pbft_core.trs --depth 8 --soundness strict
cargo run -p tarsier-cli -- analyze examples/library/hotstuff_chained.trs --mode proof --format json
cargo run -p tarsier-cli -- cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format text
cargo run -p tarsier-cli -- cert-suite --manifest examples/library/cert_suite.json --engine kinduction --k 8 --format json --out artifacts/cert-suite-library.json --artifacts-dir artifacts/cert-suite-library
python3 benchmarks/run_library_bench.py --mode standard
```

`cert-suite` JSON/text output includes per-protocol verdict, timing, assumptions, artifact links, and failure triage labels (`model_change`, `engine_regression`, `expected_update`).
Refresh entry fingerprints after protocol edits:
`python3 scripts/update-cert-suite-hashes.py --manifest examples/library/cert_suite.json`.
`./scripts/certify-corpus.sh` enforces hash consistency by default (`CHECK_HASHES=1`).
