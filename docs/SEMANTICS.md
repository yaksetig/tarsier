# Tarsier Formal Semantics (Operational)

This document specifies what Tarsier verifies, at the level of the lowered threshold automaton and SMT encodings.

## 1. Semantic Domains

A lowered model is a threshold automaton:

- Parameters `p = (p_0, ..., p_m)` with non-negative integer valuations.
- Locations `L` with counters `kappa[l]` (number of processes in location `l`).
- Shared variables `G` with counters `gamma[g]` (message counters and shared instrumentation).
- Rules `r: from -> to` with threshold guards and shared-variable updates.

Well-formed executions satisfy:

- `kappa[l] >= 0` and `gamma[g] >= 0`.
- Process conservation: sum of initial-role counters equals `n` (and role-local conservation where applicable).
- Resilience constraints from `resilience`.

## 2. Step Relation

At each step `k`, Tarsier introduces:

- `delta[k,r]`: how many processes fire rule `r`.
- `adv[k,g]`: adversary-injected increment for message/shared counter `g`.
- Optional `drop[k,g]` for lossy network modes (omission and Byzantine selective-network modes).
- Optional `advsend[k,v]` sender-budget variables for identity-coupled Byzantine network modes.

Transition constraints encode:

- Guard enablement: `delta[k,r] > 0` implies each guard atom of `r` holds at step `k`.
- Local flow:
  - `kappa[k+1,l] = kappa[k,l] - outflow + inflow`.
  - Outflow from `l` is bounded by `kappa[k,l]`.
- Shared flow:
  - In `network: classic`, message counters are recipient-scoped channels (`cnt_M@Role[...]`).
  - In faithful network modes (`identity_selective`, `cohort_selective`, `process_selective`), message counters are sender+recipient scoped delivery candidates (`cnt_M@Recipient<-Sender[...]`).
  - Under `network: cohort_selective`, channels are internally cohort-scoped (`cnt_M@Role#0[...]`, `cnt_M@Role#1[...]`).
  - Under `network: process_selective`, channels are process-scoped (`cnt_M@Role#id[...]`) from bounded local identity variables declared by `identity Role: process(<var>)`.
  - `send M(...) to R` lowers to per-recipient delivery candidates for `R`, each tagged with sender identity.
  - `send M(...)` lowers to per-recipient delivery candidates for every recipient role/channel (not a single role-collapsed aggregate update).
  - Receive guards consume identity-scoped deliveries by summing candidate counters relevant to the recipient location.
  - `received distinct` uses exact sender-set semantics (`sum_{sender} ite(counter(sender)>0,1,0)`), not aggregate approximations.
  - `form C(...)` increments the recipient-scoped counter for crypto object `C`.
    It also enforces a distinct-sender witness threshold on `C`'s source message:
    `received distinct >= threshold source_message(...)`.
    If `C` declares `signer <Role>`, witnesses are restricted to sender identities of that role.
  - `lock C(...)` / `justify C(...)` set internal per-process lock/justify flags and require `C` to be present (`has C(...)`).
  - If `C` declares `conflicts exclusive`, `form/lock/justify C(...)` additionally require all conflicting variants of `C` for the same recipient channel to be zero.
  - Increment-style counters accumulate rule sends plus adversary injections (minus drops where applicable).
  - Distinct-sender counters include sender-uniqueness instrumentation (`__sent_g*`) and population caps.

Crypto-object non-forgeability in the SMT encoding:

- Families declared as crypto objects are treated as derived artifacts.
- Adversarial injection variables for those families are forced to zero:
  `adv[k, crypto_var] = 0` and `net_forge[k, crypto_var] = 0`.
- Therefore, crypto objects can only be introduced through protocol `form` transitions, preserving source-message dependency checks end-to-end.

## 2.5 Crypto Object Operational Semantics

This subsection specifies the operational semantics of first-class cryptographic objects (`certificate` and `threshold_signature` declarations).

### `form C(...)`

Increments the recipient-scoped counter for crypto object `C` at the executing process's location. Forming `C` requires a distinct-sender source threshold on `C`'s declared source message: `received distinct >= threshold source_message(...)`. If `C` declares `signer <Role>`, the source witnesses are restricted to sender identities of that role, excluding counters from non-signer roles.

Signer-set threshold semantics are identity-based (set semantics), not multiplicity-based: each signer identity contributes at most one witness to the threshold check even if the corresponding counter magnitude is greater than `1`.

### `lock C(...)`

Sets the persistent `__lock_<name>` flag to `true` at the target location. An implicit `has C(...)` threshold check (`sum(C_vars) >= 1`) is injected into the guard. Lock flags are persistent: once set, they remain `true` across all reachable successor locations. If `C` declares `conflicts exclusive`, all conflicting variants must be zero (`sum_conflicting = 0`) for the lock to execute.

### `justify C(...)`

Identical to `lock` but sets a separate `__justify_<name>` flag. Lock and justify flags are independent: setting `__lock_<name>` does not affect `__justify_<name>`, and vice versa. Both flags are persistent.

### `has C(...)`

Threshold guard: `sum(C_vars) >= 1`, resolved to field-specific variants when field arguments are provided. For example, `has QC(value=true)` resolves to only the `cnt_QC@...[value=true]` counters, excluding `cnt_QC@...[value=false]`.

### Non-forgeability

For all crypto object counters `v` and all BMC steps `k`:
- `adv[k, v] = 0` — no adversarial injection of crypto objects.
- `net_forge[k, v] = 0` — no network-level forgery.

This ensures crypto objects can only be introduced through protocol `form` transitions, which enforce source-message dependency checks.

### Symbolic-Crypto Scope (Explicit Boundary)

Tarsier's cryptographic semantics are symbolic constraints over counters, identities, and key-compromise state.
The checker proves properties in this symbolic model only.

What is guaranteed in-model:
- identity/key-scoped signing authority with explicit compromise transitions;
- non-forgeability constraints for uncompromised-key signed channels and crypto-object counters;
- threshold signer-set and conflict-admissibility rules encoded as SMT constraints.

What is explicitly out of scope:
- computational assumptions (for example EUF-CMA reduction proofs or concrete security bounds);
- probabilistic cryptanalysis, nonce randomness quality, side channels, and implementation-level cryptographic bugs;
- protocol security statements that require computational composition theorems beyond this symbolic abstraction.

Interpretation rule: a "safe/proved" result means the protocol is safe in the declared symbolic model and assumptions, not a computational cryptography proof about concrete implementations.

### Conflict admissibility

- **`conflicts exclusive`**: For each recipient and each BMC step, if a crypto object variant `i` has `sum_i > 0`, then all other variants `j != i` must have `sum_j = 0`. This encodes mutual exclusion of conflicting crypto objects.
- **`conflicts allow`** (default): No additional admissibility constraints on conflicting variants.

### `certificate` vs `threshold_signature`

Both share the same counter-abstraction lowering. The distinction is syntactic:
- `certificate` declares a quorum certificate; `signer` is optional (defaults to all roles).
- `threshold_signature` requires an explicit `signer <Role>` declaration. Lowering rejects `threshold_signature` without a signer role.

### IR and SMT Mapping (Test-Linked)

This table makes the operational mapping explicit from DSL actions to IR lowering
artifacts and SMT constraints.

| DSL construct | IR lowering contract | SMT encoding contract | Regression tests |
| --- | --- | --- | --- |
| `certificate C from M threshold T [signer R]` | Adds `IrCryptoObject` with source `M`, threshold `T`, optional signer-role filter | Keeps `C` counters non-forgeable (`adv/net_forge = 0`), enforces threshold/dependency guards via lowered rules | `lower_crypto_object_form_lock_justify`, `lower_threshold_signature_form_filters_witnesses_to_signer_role`, `forging_crypto_object_family_is_unsat_even_with_byzantine_budget`, `valid_crypto_object_formation_path_is_sat` |
| `threshold_signature S ... signer R` | Same as certificate plus mandatory signer role at lowering time | Same non-forgeability constraints; signer-filtered witness channels drive satisfiable/unsatisfiable formation paths | `lower_rejects_threshold_signature_without_signer_role`, `lower_threshold_signature_form_filters_witnesses_to_signer_role`, `forging_crypto_object_family_is_unsat_even_with_byzantine_budget` |
| signer-set threshold witness counting | Distinct source-witness vars are selected per signer identity/channel | Distinct threshold guards evaluate signer-set cardinality (`sum(ite(gamma_var > 0, 1, 0))`), so repeated packets from one signer do not satisfy multi-signer thresholds | `signer_set_threshold_requires_distinct_signer_identities_not_counter_magnitude` |
| `form C(...)` | Adds send/update for `C` and injects distinct-source witness threshold over declared source message | Transition can introduce `C` only through legal `form` rule flow; direct adversarial forging blocked | `lower_crypto_object_form_lock_justify`, `valid_crypto_object_formation_path_is_sat`, `forging_crypto_object_family_is_unsat_even_with_byzantine_budget` |
| `lock C(...)` | Sets persistent `__lock_<name>` flag; injects implicit `has C(...)` guard | Guard/update lowering is preserved in encoded transition relation | `lower_lock_adds_implicit_has_threshold_guard`, `crypto_justify_independent_of_lock` |
| `justify C(...)` | Sets persistent `__justify_<name>` flag independently from lock | Independent flag-update behavior preserved in encoded transition relation | `lower_justify_sets_justify_flag_not_lock_flag`, `crypto_justify_independent_of_lock` |
| `conflicts exclusive` | Adds conflicting-variant zero guards to `form/lock/justify` rules | Adds mutual-exclusion admissibility constraints across conflicting variants | `lower_crypto_object_conflicts_exclusive_adds_admissibility_guard`, `exclusive_crypto_policy_blocks_conflicting_variants_in_same_state` |
| compromised signing keys | Lowering tracks key ownership and compromised keys in adversary model | Signed-channel forgery is UNSAT for uncompromised identities (unless sender is active Byzantine), and SAT when the key is compromised | `forging_signed_message_without_compromise_and_without_byzantine_sender_is_unsat`, `compromised_key_allows_signed_forge_sat` |

Implementation pointers:
- IR lowering: `crates/tarsier-ir/src/lowering.rs`
- SMT encoding: `crates/tarsier-smt/src/encoder.rs`
- End-to-end integration checks: `crates/tarsier-engine/tests/integration_tests.rs`

## 2.1 Protocol-Faithful Network Target (Semantic Contract)

This subsection defines the target semantics for a protocol-faithful network mode.
Current `classic` / `identity_selective` / `cohort_selective` / `process_selective` modes are abstractions of this target.

- Process identities: finite set `Proc`, role map `role: Proc -> Role`.
- Fault bound: persistent faulty identity set `F subseteq Proc` with `|F| <= f`.
- Packets are identity- and recipient-scoped objects:
  `pkt = (kind, slot, payload, sender, recipient, auth_tag)`.
  - `kind`: message family/type.
  - `slot`: protocol slot discriminator (for example view/round/height tuple).
  - `payload`: value-carrying content used by guards/properties.
  - `sender`, `recipient`: concrete process identities.
  - `auth_tag`: authentication witness (empty if `auth: none`).
- Network state at step `k`: multiset `InFlight_k` of packets pending delivery.
- Observable network actions per step:
  - `Send_k`: packet creation by protocol transitions (honest sends) or adversary (mode-dependent).
  - `Deliver_k`: packet delivery to recipients.
  - `Drop_k`: packet loss/removal without delivery.
- Step transition:
  `InFlight_{k+1} = (InFlight_k - Deliver_k - Drop_k) U Send_k`, with disjointness constraints:
  - every delivered/dropped packet must have been in-flight;
  - a packet cannot be both delivered and dropped in the same step.

Authentication interpretation:

- `auth: none`: `sender` field is unauthenticated metadata.
- `auth: signed`: delivered packet is valid iff either:
  - signature verifies under `sender` key and `sender` identity is authorized for that key, or
  - the sender key is explicitly compromised.
  In particular, uncompromised honest identities cannot be forged.

## 2.2 Authentication Semantics (Faithful Target)

Let `Key` be the key space and `owner: Key -> Proc` map keys to identities.
Let `Comp_k subseteq Key` be the compromised-key set at step `k`.

- Monotonic compromise: `Comp_k subseteq Comp_{k+1}`.
- Honest-send authenticity:
  - if honest process `p` sends `pkt`, then `pkt.sender = p` and `auth_tag` verifies under some key `sk` with `owner(sk) = p`.
- Signed-channel acceptance (`auth: signed`):
  - a packet claiming sender `s` is admissible only if:
    - its `auth_tag` verifies for `(kind, slot, payload, sender=s, recipient)`, and
    - either `s in F` (Byzantine sender identity) or `owner(sk) in Comp_k` for the signing key `sk`.
- Consequences:
  - impersonating uncompromised honest identities is forbidden;
  - Byzantine identities can sign as themselves;
  - compromised keys allow adversarial packets to pass authenticity checks for their owner identity.

For `auth: none`, authenticity checks are disabled and sender metadata is not trusted.

### 2.4 DSL-Level Identity / Channel / Equivocation Declarations

The DSL supports explicit per-role and per-message declarations:

- `identity Role: process(pid_var) key role_key;` or `identity Role: role key role_key;`
- `channel Msg: authenticated|unauthenticated;`
- `equivocation Msg: full|none;`
- `adversary { delivery: legacy_counter|per_recipient|global; faults: legacy_counter|per_recipient|global; }`
- `adversary { compromised_key: <key_name>; }` (repeatable; aliases: `compromise`, `compromised`)

Defaults when omitted:

- Identity: role-scoped, except `network: process_selective` defaults to `process(pid)`.
- Key namespace: `<role>_key`.
- Channel auth and equivocation inherit global `adversary { auth: ...; equivocation: ...; }`.
- Delivery/fault scopes default to `legacy_counter` for backwards compatibility.

## 2.3 Partial Synchrony at Network Layer (Faithful Target)

Let `GST` be Global Stabilization Time and `Delta > 0` the post-GST delivery bound.

- Pre-GST (`k < GST`):
  - delivery may be arbitrarily delayed, reordered, or dropped according to fault model.
- Post-GST (`k >= GST`):
  - for any packet sent at step `k` by a non-crashed honest sender to a non-crashed honest recipient, delivery occurs by some step `j` with `k < j <= k + Delta`;
  - network-induced drops on honest->honest channels are disallowed after GST;
  - packets involving faulty identities may still be adversarially controlled within the selected fault model.

Current implementation approximation:

- Partial synchrony is encoded by forcing modeled `drop` variables to `0` post-GST in lossy modes and constraining fair-liveness witnesses to post-GST cycles.
- The explicit bounded-delivery constant `Delta` is a semantic target; current encodings enforce eventual post-GST reliability through these constraints plus fairness assumptions.
- For signed channels, adversarial injections into sender-scoped counters are permitted only via a bounded Byzantine-sender activation budget or compromised keys; senderless signed counters are rejected (`adv = 0`).

## 3. Fault Models (Exact Adversary Powers in Protocol-Faithful Target)

### 3.1 Identity-Scoped Equivocation

For fixed step `k`, sender `s`, message kind `M`, and slot `sigma`, sender `s` equivocates iff there exist recipients `r1 != r2` and payloads `v1 != v2` such that both packets:

- `(M, sigma, v1, s, r1, ...)`
- `(M, sigma, v2, s, r2, ...)`

are sent or delivered in that step-region.

- Same sender + same payload to multiple recipients is not equivocation.
- Different senders emitting different payloads is not equivocation.
- `equivocation: none` enforces payload uniqueness per `(sender, kind, slot)` across all recipients.
- `equivocation: full` permits conflicting payloads from the same sender to different recipients.

### Byzantine

- Faulty identities in `F` are fully adversarial.
- Allowed adversary actions:
  - inject arbitrary packets from Byzantine senders to arbitrary recipients;
  - choose per-recipient selective delivery, delay, and drops;
  - equivocate identity-scoped as defined in 3.1 (unless `equivocation: none`);
  - if `auth: none`, spoof sender metadata freely.
- Authentication constraint under `auth: signed`:
  - adversary may sign only with keys it controls (faulty or compromised keys);
  - forging uncompromised honest sender signatures is forbidden.
- Honest identities (`Proc \ F`) follow protocol transition semantics only.

### Omission

- No forged packet creation.
- No payload mutation.
- No sender spoofing (with or without signatures).
- Allowed adversary action: suppress/delay deliveries (send or receive omissions) without introducing new packets.
- Omission faults do not include equivocation by adversarial fabrication.

### Crash

- Each faulty identity has a crash time `t_crash(p)` (at most once).
- Before crash: process behaves honestly.
- After crash: no further local transitions or sends from that identity.
- No forged packet creation, payload mutation, sender spoofing, or equivocation.

### 3.4 Current Implementation Mapping (Abstraction Modes)

Current network modes are over/under-approximating encodings of the target semantics above:

- `network: classic`:
  - role-scoped counter channels only.
- `network: identity_selective`:
  - recipient-coupled variant sender budgets and selective Byzantine delivery.
  - for families with equivocation enabled, contradictory adversarial variants are coupled to a single sender identity per step.
- `network: cohort_selective`:
  - internal role cohorts (`#0/#1`) for tighter selective-delivery approximation.
- `network: process_selective`:
  - bounded `pid` channels (`Role#pid`) with uniqueness constraints (`<= 1` process per `(role,pid)` bucket per step).
  - current implementation now enforces exact uniqueness (`= 1`) for each `(role,pid)` bucket per step.

Legacy encoding variables remain:

- `adv[k,g]`: adversarial injections per shared/message counter.
- `drop[k,g]`: lossy-network drops (mode-dependent).
- `advsend[k,v]`: variant sender budgets for identity-coupled modes.
- Explicit per-edge network flow variables for message counters:
  - `net_pending[k,g]`: in-flight backlog on edge `g` at step `k`.
  - `net_send[k,g]`: honest protocol sends on edge `g`.
  - `net_forge[k,g]`: adversarial forged/adversarial sends on edge `g` (`net_forge = adv`).
  - `net_deliver[k,g]`: deliveries accepted on edge `g`.
  - `net_drop[k,g]`: network/adversary drops on edge `g` (`net_drop = drop` in lossy modes, `0` otherwise).
  - Flow relation per step: `pending' = pending + send + forge - deliver - drop`, with
    `deliver + drop <= pending + send + forge`.
  - Equivocation is sender-scoped in faithful selective modes: payload-variant splitting is modeled per sender/channel edge.
    - `equivocation: full`: sender may split deliveries across variants.
    - `equivocation: none`: sender is constrained to at most one variant per message family per step.
  - Omission/drop constraints include per-message/per-recipient aggregates in faithful selective modes (in addition to legacy scopes).
  - Crash-stop reuses the same network object model with `net_forge = 0` and `net_drop = 0`.
  - Partial synchrony in faithful selective channels adds post-GST reliability constraints:
    - Byzantine + signed + uncompromised sender channel: if sender is not active Byzantine in the step, post-GST delivery equals all available traffic on that edge (`deliver = pending + send + forge`).
    - Omission/Crash modes: post-GST delivery equals all available traffic on each message edge.
  - Signed-sender consistency includes a static faulty-sender set:
    - `byzsender_static[sender] in {0,1}` with `sum byzsender_static <= f`;
    - per-step sender activation satisfies `byzsender[k,sender] <= byzsender_static[sender]`.
    This prevents impossible mixes that require a sender to alternate between honest/faulty identities across steps.
  - Strict faithful lint/verify blocks under-specified network models:
    - explicit `identity` + key declarations are required;
    - explicit auth semantics are required (`adversary { auth: ...; }` or per-message `channel ...`);
    - Byzantine faithful models must declare explicit `equivocation: full|none`.

Trace-level IR events expose first-class action kinds and auth provenance:

- Action kinds: `Send`, `Deliver`, `Drop`, `Forge`, `Equivocate`.
- Auth metadata: effective channel auth, signature key, key owner role, key-compromised flag, and provenance class.
- Default counterexample outputs (CLI text trace, JSON artifacts, debugger/visualization) include sender, recipient, payload, and auth fields per delivery event.

## 4. Timing / Fairness

- Logical time is an integer variable increasing by 1 per step.
- Faithful-target timing guarantees:
  - Asynchronous: no bound on delivery delay.
  - Partial synchrony: after GST, packets from honest live senders to honest live recipients are eventually delivered within a finite bound (unless the fault model explicitly permits omission/crash at endpoints).

### 4.1 Fairness Modes

- **Weak fairness (justice):** For every transition rule `r`, if `r` is continuously enabled from some point onward, then `r` must eventually fire. Formally: `FG(enabled(r)) → GF(fired(r))`.
- **Strong fairness (compassion):** For every transition rule `r`, if `r` is enabled infinitely often, then `r` must fire infinitely often. Formally: `GF(enabled(r)) → GF(fired(r))`. Strong fairness is strictly stronger than weak: every strongly-fair execution is weakly-fair, but not vice versa.

### 4.2 GST Integration in Proof Obligations

Under partial synchrony (`timing: partial_synchrony; gst: <param>;`), the Global Stabilization Time (GST) is integrated into **all** proof obligations — both bounded and unbounded:

1. **Lasso constraint:** Fair lasso cycles must be entirely post-GST (`gst ≤ loop_start`). Pre-GST-only cycles are excluded as they represent transient asynchronous behavior, not steady-state violations.
2. **Rule enablement gating:** A rule is considered "enabled" for fairness purposes only at post-GST steps (`gst ≤ step`). Pre-GST steps do not contribute to fairness obligations.
3. **PDR monitor initialization:** The fair-cycle monitor is armed only when the current step is post-GST. This ensures the proof obligation covers exactly the post-GST behavior that the protocol must guarantee.

This means: a `LiveProved` verdict under partial synchrony certifies that no fair non-terminating cycle exists in the post-GST steady state, which is the standard correctness criterion for partially-synchronous BFT protocols.

### 4.3 CI-Grade Real-Protocol Liveness Targets

For deterministic CI gating, the library includes a PBFT-shaped pair with partial synchrony and Byzantine faults:

- `examples/library/pbft_liveness_safe_ci.trs`: expected `LiveProved` under `prove-fair` (weak/strong fairness) with replayable fair-liveness proof obligations.
- `examples/library/pbft_liveness_buggy_ci.trs`: expected fair non-termination (`FairCycleFound` / `not_live`) under the same settings.

These two models are used as stable liveness class anchors:

- a positive unbounded fair-liveness proof path with independently replayable certificate obligations;
- a negative non-live sentinel to detect regressions that accidentally mask real fair-cycle witnesses.

## 5. Properties

## 5.1 Safety

Safety properties are lowered to bad-state reachability:

- `agreement`, `safety`, `invariant`, `validity` fragments supported by `extract_property(...)`.

## 5.2 Liveness

If `property ...: liveness` is absent, liveness falls back to `forall p: Role. p.decided == true` (derived from locations where local `decided == true`).

For explicit liveness properties (`forall p: Role. ...` or `exists p: Role. ...`):

- State-target fragment (`<state predicate over p.*>`):
  - Predicate is evaluated over each reachable location of `Role`.
  - This yields a target location set `Goal`.
  - Bounded `liveness` requires all processes in `Goal` at the bound.
  - `fair-liveness` / `prove-fair` search/prove absence of fair lassos that stay in reachable `not Goal`.

- Temporal fragment (`X`, `[]`, `<>`, `U`, `W`, `R`, `~>`):
  - Bounded `liveness` checks the temporal formula over finite prefixes up to depth.
  - `X phi` uses strong-next semantics in bounded checks (`X phi` is false at the final bound step).
  - `fair-liveness` / `prove-fair` compile the negated temporal property to a Büchi monitor and check fair accepting cycles in the product system.
  - Under partial synchrony, fair cycles are still constrained to post-GST behavior.

## 6. Soundness Notes

## 6.1 Safety of `equivocation: full` (when guards are monotone)

For threshold guards that are monotone in message counters (`>=` or `>`):

- Allowing more adversarial messages only enlarges the transition relation.
- Therefore `equivocation: full` is an over-approximation of non-equivocating Byzantine behaviors.
- Consequence:
  - `SAFE` results are sound w.r.t. stricter non-equivocating adversaries.
  - `UNSAFE` may include spurious counterexamples due to over-approximation.

Strict mode enforces this by rejecting non-monotone threshold operators in Byzantine full-equivocation settings.

## 6.2 `equivocation: none`

`equivocation: none` is a stricter adversary assumption. It can reduce spurious `UNSAFE` traces, but `SAFE` under `none` does not imply `SAFE` under `full`.

## 6.3 Bounded vs unbounded

- `verify`, `liveness`, `fair-liveness` are bounded checks.
- `prove` and `prove-fair` attempt unbounded proofs via induction/PDR; results can be `Unknown`/`NotProved` if convergence does not occur.
- `timeout_secs` is an enforced execution control: it is applied to solver backends (Z3/CVC5 timeout configuration) and to pipeline-level deadlines used by staged engines (CEGAR / PDR / fair-liveness).
- For safety `prove` with k-induction, `NotProved` may include a CTI (counterexample-to-induction) witness: a SAT step fragment showing non-inductiveness of the property. CTIs are not guaranteed reachable from initial states.
- CTI classification:
  - `concrete`: an independent bounded replay can reach the CTI hypothesis state under the same solver/model assumptions.
  - `likely_spurious`: replay proves the hypothesis unreachable, returns unknown, or structural impossibility checks fail (for example negative/over-populated counters).
  - Classification evidence is emitted in machine-readable JSON (`classification_evidence`) and in text output for auditability.
- With `prove --cegar-iters > 0`, CTI-guided synthesis is applied for `NotProved` k-induction outcomes: candidate location-unreachability predicates are mined from CTI states, validated as invariants, and then used as strengthening predicates in a rerun.
- For CEGAR predicate discovery, refinement planning combines trace/CTI signals with solver-backed UNSAT-core seeding to propose candidate predicates automatically.
- Candidate predicates are replay-checked before adoption: only refinement stages that eliminate the baseline witness contribute `discovered_predicates`; stages where the witness persists remain `UNSAFE` and do not publish adopted predicates.
- Multi-predicate CEGAR stages run solver-backed replay minimization (`Refinement-elimination core`): candidate subsets are replayed, and only the smallest subset that still eliminates the targeted baseline witness is adopted into discovered predicates.

### 6.3.1 Machine-Readable Unknown Diagnostics (Liveness)

For `prove-fair` outcomes that are not conclusive, machine-readable reports include:

- `details.reason_code`: stable category (`timeout`, `memory_budget_exceeded`, `cube_budget_exhausted`, `solver_unknown`, `lasso_recovery_failed`, `cegar_refinement_inconclusive`, `cegar_ladder_exhausted`).
- `details.convergence`: convergence diagnostics (`outcome`, `frontier_frame`, `bound_exhausted`, optional `reason`).

This contract is intended for CI/governance pipelines where `Unknown` is acceptable only for known reason classes with explicit convergence evidence.

### 6.3.2 CEGAR Stage-Delta Reporting Contract

`verify --cegar-iters > 0` emits stage-by-stage refinement deltas in the CEGAR report:

- `stages[i].model_changes`: refinement predicates applied at stage `i` (auditable model delta).
- `stages[i].eliminated_traces`: baseline witness traces eliminated by stage `i`.
- `stages[i].discovered_predicates`: predicates adopted from elimination-confirmed replay.

Classification rule (strict):

- If baseline stage is `UNSAFE` and at least one refinement eliminates that baseline witness,
  but no refined stage confirms a concrete `UNSAFE`, overall classification is
  `inconclusive` and final verdict is `Unknown`.
- Termination reason is explicitly `counterexample_eliminated_no_confirmation`.

## 6.4 Soundness Transfer: Abstraction Modes vs Faithful Target

Let `Reach_mode(k)` be the set of states reachable up to depth `k` under a given network mode.
Let `Reach_faithful(k)` be reachable states under the faithful target semantics (Section 2.1).

Transfer rules (general framework):

- Over-approximation case:
  - if `Reach_faithful(k) ⊆ Reach_mode(k)`, then `SAFE_mode` at depth/proof scope implies `SAFE_faithful`;
  - `UNSAFE_mode` may be spurious.
- Under-approximation case:
  - if `Reach_mode(k) ⊆ Reach_faithful(k)`, then `UNSAFE_mode` implies `UNSAFE_faithful`;
  - `SAFE_mode` may be optimistic.
- Mixed/unknown relation:
  - without a proved inclusion relation, neither `SAFE` nor `UNSAFE` transfers automatically.

For a practical guide to choosing between abstraction modes and understanding where they diverge, see `docs/INTERPRETATION_MATRIX.md`.

### 6.4.1 Transfer Theorem Table

| Mode | Result | Direction | Relationship | Condition |
|------|--------|-----------|-------------|-----------|
| `classic` | SAFE | → faithful | Sound if over-approx | Monotone guards, no sender-specific semantics, `equivocation: full` |
| `classic` | UNSAFE | → faithful | Not guaranteed | Classic admits traces impossible under sender-scoped faithful delivery |
| `identity_selective` | SAFE | → faithful | Sound (over-approx) | `auth: signed`, Byzantine model, sender budgets ≥ faithful |
| `identity_selective` | UNSAFE | → faithful | Conditional | Trace must be validated against faithful packet semantics |
| `cohort_selective` | SAFE | → faithful | Sound (over-approx) | Cohort partitioning is coarser than per-process |
| `cohort_selective` | UNSAFE | → faithful | Not guaranteed | Cohort-level traces may not map to per-process schedules |
| `process_selective` | SAFE | → faithful | Instance-exact | pid domain = [0, n-1], signed channels |
| `process_selective` | UNSAFE | → faithful | Instance-exact | Same conditions |

### 6.4.2 Formal Statements

**Theorem 1 (Classic over-approximation, conditional).**
Let `P` be a threshold protocol with monotone guards (`≥` or `>` threshold operators only), `equivocation: full`, and no sender-specific guard semantics (no `received distinct`).
If `SAFE_classic(k)` for all `k`, then `SAFE_faithful(k)` for all `k`.

*Proof obligations:*
(a) Every faithful-target trace is simulable by a classic trace: role-scoped counters aggregate all sender identities, so classic admits at least as many reachable configurations.
(b) Monotonicity ensures that additional adversarial messages (enabled by role-level aggregation) do not disable guards, only enable them — so the classic reachable set is a superset.

*Implementation status:* Condition (a) is checked structurally by the lowering. Condition (b) is enforced by strict mode (non-monotone guard rejection under full equivocation). Not fully automated — the user must ensure no sender-specific semantics are used.

**Theorem 2 (Identity-selective over-approximation).**
Let `P` use `auth: signed` and `model: byzantine`.
If `SAFE_identity_selective(k)` for all `k`, then `SAFE_faithful(k)` for all `k`, provided the identity-selective sender budgets are at least as permissive as the faithful-target budgets.

*Proof obligations:*
(a) Sender-scoped delivery candidates in identity_selective mode cover all faithful packet deliveries.
(b) Byzantine sender activation budgets bound adversarial capability at least as generously as the faithful target (identity_selective uses per-step sender activation with a static faulty-sender set constraint — see Section 2.4).

*Implementation status:* Structural soundness is enforced by the encoder. Budget comparison is not automated.

**Theorem 3 (Process-selective instance-exactness).**
Let `P` use `network: process_selective` with `pid ∈ [0, n-1]` and `auth: signed`.
Then `Reach_process_selective(k) = Reach_faithful(k)` for the `n`-process instance.

*Proof obligations:*
(a) Each pid maps to exactly one process identity — uniqueness constraints enforce `≤ 1` process per `(role, pid)` bucket per step.
(b) Signed channels prevent identity spoofing — sender metadata is authenticated.
(c) The pid domain `[0, n-1]` covers the full process population exactly.

*Implementation status:* Conditions (a) and (b) are enforced by the encoder. Condition (c) is checked by strict mode (see Section 6.5 for cutoff generalization).

### 6.4.3 Value Abstraction

The `values: sign` option introduces orthogonal data abstraction that maps concrete integer values to their sign class `{negative, zero, positive}`. Value abstraction transfer is independent of network mode transfer:

- `SAFE` under `values: sign` implies `SAFE` for all concrete value instances (over-approximation of value domain).
- `UNSAFE` under `values: sign` may be spurious if the counterexample relies on value distinctions finer than sign.
- CEGAR refinement (`values: exact` stage) can eliminate spurious value-abstraction traces.

When old results are still usable:

- Old `UNSAFE` results are actionable if the trace is replayed/validated under faithful semantics.
- Old `SAFE` results are useful for triage and regression screening; treat as final guarantees only when an explicit over-approximation argument to faithful semantics is established.

## 6.5 Bounded-Domain Cutoff Justification for `process_selective`

### Instance-Exactness Claim

For process-homogeneous threshold protocols with `pid ∈ [0, n-1]`, the process-selective encoding satisfies `Reach_ps(k) = Reach_faithful(k)` for the `n`-process instance (Theorem 3, Section 6.4.2).

This means that `SAFE_ps(k)` and `UNSAFE_ps(k)` are exact for the specific instance size `n`. No additional over/under-approximation is introduced by the encoding itself.

### Conditions for Instance-Exactness

1. **Single role or symmetric multi-role:** All processes within a role are interchangeable (process-homogeneous).
2. **Threshold guards only:** Guards are monotone threshold predicates over message counters, not dependent on specific process identities beyond counting.
3. **Full pid domain coverage:** The pid variable range `[0, n-1]` covers the entire process population, ensuring every process has a distinct identity in the encoding.
4. **No external data dependencies:** Protocol transitions depend only on internal state and message counts, not on external oracles or data sources.

### Cutoff Extension (Emerson–Namjoshi Style)

If additionally the protocol is process-homogeneous and the safety property is symmetric (invariant under process permutation), then `SAFE` for instance size `n` implies `SAFE` for all `n' > n`, subject to the threshold structure.

The intuition is that adding more honest processes to a threshold protocol with symmetric safety cannot introduce new violations: additional processes either strengthen quorum formation (helping safety) or are idle (not affecting reachable states).

The `round-sweep` command provides empirical cutoff evidence by running verification across a range of instance sizes and reporting whether the verdict is stable.

### Limitations

- **Non-symmetric protocols:** Protocols with role-asymmetric safety properties (e.g., leader-specific invariants) require per-instance analysis.
- **Data-dependent guards:** Guards that depend on concrete message payloads (beyond threshold counting) may introduce instance-specific behaviors.
- **Mixed-role initial states:** Protocols where initial configurations vary by process identity need careful justification that the pid-domain encoding captures all relevant initial distributions.

### Runtime Validation

Strict mode includes a pid-domain coverage check for `process_selective` networks: if the pid variable has a literal range with domain size ≤ 1, a diagnostic is emitted warning that the pid domain may not cover the full population. This catches common misconfigurations where the modeler uses a small fixed range instead of a population-scaled range.

## 6.6 Partial-Order Reduction (POR) Soundness

Tarsier applies three static pruning strategies and one dynamic ample-set optimization to reduce the rule set explored during model checking, without affecting the reachable state space for safety properties.

### Independence Relation

Two rules `r₁` and `r₂` are **independent** if all of the following hold:

1. **Disjoint locations:** `{r₁.from, r₁.to} ∩ {r₂.from, r₂.to} = ∅`
2. **Different roles:** `role(r₁.from) ≠ role(r₂.from)`
3. **No read/write conflicts:** The guard read-set and update write-set of each rule are pairwise disjoint:
   - `writes(r₁) ∩ writes(r₂) = ∅`
   - `writes(r₁) ∩ reads(r₂) = ∅`
   - `writes(r₂) ∩ reads(r₁) = ∅`

where `reads(r)` collects shared-variable indices from `guard_read_vars()` and `writes(r)` collects indices from `update_write_vars()`. See `rules_independent()` in `pipeline.rs`.

### Static Rule Pruning

Three pruning strategies are applied before encoding:

1. **Stutter elimination:** Rules where `from == to` and `updates` is empty are pure stuttering steps — they do not change the state and are discarded.
2. **Commutative duplicate detection:** Rules with identical canonical signatures (same `from`, `to`, guard atoms, and update list) are deduplicated, keeping only the first occurrence.
3. **Guard domination:** If rule `r₁` has the same effect signature (same `from`, `to`, updates) as rule `r₂`, and the guard of `r₁` syntactically entails the guard of `r₂` (checked via `guard_implies()`), then `r₁` is subsumed and discarded. Ties between equivalent guards are broken by rule index.

These are computed by `compute_por_rule_pruning()` in `encoder.rs` and reported by `por_rule_pruning_summary()` in `pipeline.rs`.

### Dynamic Ample Set (PDR)

During Property-Directed Reachability (PDR), the engine computes a per-cube ample set. Given a PDR cube (partial state description), rules whose source/target locations and updated shared variables are all disjoint from the cube's constrained variables are disabled for that frame query. This is sound because such rules cannot affect whether the cube is reachable. See `dynamic_ample_disabled_rules_for_cube()` in `bmc.rs`.

### Soundness Argument

The pruning preserves safety reachability:

- **Stutter rules** are vacuous (no state change); removing them does not alter the reachable state set.
- **Commutative duplicates** produce identical successor states; retaining one canonical representative suffices.
- **Guard-dominated rules** fire only when a less-restrictive rule with the same effect is also enabled; the dominated rule is redundant.
- **Dynamic ample-set disabling** removes rules that are independent of the cube's constrained variables; any counterexample involving such rules can be reordered to defer them without affecting reachability of the target state.

This is a conservative semantic argument, not a machine-checked proof. The independence relation is intentionally strict (requiring disjoint locations, different roles, and no R/W conflicts) to avoid unsound overapproximation.

For formal independence rules with worked examples, counterexamples, POR mode configuration, and explicit assumptions, see `docs/POR_INDEPENDENCE.md`.

## 6.7 Differential and Network-Fidelity Regression Coverage

The implementation is regression-tested for both transfer behavior and faithful network semantics:

- **Differential faithful-vs-legacy corpus checks:** `differential_regression_classic_vs_faithful_corpus()` (`crates/tarsier-engine/tests/integration_tests.rs`) runs a shared corpus in classic and faithful modes with expected outcomes and explicit divergence labels. The suite includes a required divergence sentinel (`temporal_liveness_counterexample.trs`) where strict legacy parsing errors but faithful permissive overlay is expected to verify `SAFE`.
- **Network-fidelity SAT/UNSAT checks:** `crates/tarsier-smt/src/encoder.rs` includes targeted tests that enforce key semantic constraints:
  - forged signed traffic without compromise and without active Byzantine sender is `UNSAT`;
  - Byzantine sender equivocation with `equivocation: full` can split payload variants across recipients (`SAT`);
  - sender-scoped coupling and per-recipient omission/drop bounds are enforced.
- **CI gate:** `.github/workflows/ci.yml` runs `cargo test --all-targets` in the `build-test` job, so these differential and network-fidelity tests are merge-gated.

## 7. Certificate Scope

Certificate bundles are independently checkable SMT obligation sets for:

- Safety k-induction and safety PDR invariants.
- Fair-liveness PDR invariants (`init => inv`, `inv & T => inv'`, `inv => no_fair_bad`).

Certificates attest satisfiability status of encoded obligations, not theorem-prover kernel proofs.

`check-certificate --rederive` strengthens checking by regenerating obligations from source and comparing obligation hashes before running external solvers.

Schema/version contract for certificate bundles is documented in `docs/CERTIFICATE_SCHEMA.md` (current `schema_version = 2`).
Trust boundary for certificate replay vs toolchain trust is documented in `docs/TRUST_BOUNDARY.md`.

## 8. DSL → TA → SMT Conformance Mapping

This section provides a precise mapping from DSL constructs through IR lowering to SMT encoding, enabling auditing of conformance between stages.

### 8.1 DSL → IR Lowering (`crates/tarsier-ir/src/lowering.rs:lower()`)

The `lower()` function transforms a parsed DSL `Program` into a `ThresholdAutomaton`:

**Parameters:**
Each `params` name in the DSL maps to `ta.parameters[i]` with `ParamDomain::NonNegativeInt`. The parameter index `i` is assigned in declaration order. Named references in guards and resilience expressions resolve to these indices via `find_param_by_name(name)`.

**Locations:**
The location set is the cross-product `(role, phase, bool-var-valuations)`. For a role with `k` boolean variables and `p` phases, this produces `p × 2^k` locations per role. Each location `l` records:
- `l.role`: originating role name.
- `l.phase`: phase name within the role.
- `l.local_vars`: map from variable name to `LocalValue::Bool(v)` for each boolean variable valuation.

**Shared variables:**
Each `message M` declaration produces one or more shared counter variables depending on network mode:
- `network: classic` → `cnt_M@Role[field-values]`, one per recipient role.
- Faithful modes (`identity_selective`, `cohort_selective`, `process_selective`) → sender-scoped variants `cnt_M@Recipient<-Sender[field-values]` per sender identity granularity.
- Crypto objects produce additional shared counters with non-forgeability constraints.

**Rules:**
Each `when guard => { actions }` within a `phase` block lowers to one or more IR rules:
- `from_location`: the location matching `(role, phase, current-bool-var-values)`.
- `to_location`: computed from `goto phase` and variable assignments in actions.
- `guards[]`: threshold guard atoms and boolean predicate guards.
- `updates[]`: shared variable increments from `send` actions.
When actions produce multiple destination locations (e.g., branching on boolean assignments), the transition fans out into multiple rules.

**Initial state:**
`init <phase>` combined with default variable values (all `false` for booleans, `0` for numerics) determines `ta.initial_locations`. Each role contributes one initial location.

**Resilience:**
`resilience: expr` lowers to `ta.resilience_condition`, a linear inequality over parameter indices. For example, `n > 3*t` becomes `n - 3*t > 0` encoded as a `LinearConstraint`.

**Adversary bound:**
`adversary { bound: f; }` resolves to `ta.adversary_bound_param`, the parameter index of `f`. This is used to bound cumulative adversary injections in the SMT encoding.

### 8.2 IR → SMT Encoding (`crates/tarsier-smt/src/encoder.rs:encode_bmc()`)

The BMC encoder creates Z3 variables and assertions for a bounded execution of `k_max` steps:

**Variables at step k:**
- `kappa[k,l]`: Z3 `Int` — number of processes in location `l` at step `k`.
- `gamma[k,g]`: Z3 `Int` — value of shared variable (message counter) `g` at step `k`.
- `delta[k,r]`: Z3 `Int` — number of processes firing rule `r` at step `k`.
- `adv[k,g]`: Z3 `Int` — adversary-injected increment for shared variable `g` at step `k`.

**Initial state (step 0):**
- `kappa[0,l] = initial_count(l)`: initial locations get symbolic process counts; non-initial locations get `0`.
- `gamma[0,g] = 0`: all message counters start at zero.
- Conservation: `sum_l kappa[0,l] = n` (total process population).

**Step transition k → k+1:**
- Guard enablement: `delta[k,r] > 0 ⇒ guard(r) holds at step k` for each rule `r`.
- Local flow (kappa): `kappa[k+1,l] = kappa[k,l] - sum(delta_outgoing[k,l]) + sum(delta_incoming[k,l])`.
- Outflow bound: `sum(delta_outgoing[k,l]) <= kappa[k,l]` for each location `l`.
- Shared flow (gamma): `gamma[k+1,g] = gamma[k,g] + honest_sends[k,g] + adv[k,g] - drops[k,g]`.
  - `honest_sends` are computed from `delta` counts of rules with send actions targeting `g`.
  - `drops` are mode-dependent (zero in lossless modes).
- Adversary total bound: `sum_{k=0}^{k_max} adv[k,g] <= f` for each message counter `g`.
- Non-negativity: `kappa[k,l] >= 0`, `gamma[k,g] >= 0`, `delta[k,r] >= 0`.

**Safety negation:**
The safety property extracted by `extract_property(...)` is negated and encoded as:
`OR_{k=0}^{k_max}(bad-state-predicate at step k)`
where the bad-state predicate is an existential formula over location occupancy (e.g., two conflicting decision locations simultaneously occupied).

### 8.3 Conformance Checklist

The following numbered invariants must hold in a conformant encoding. Each invariant identifies the encoding stage responsible:

1. **Location–variable bijection:** Every location `l` has exactly one `kappa[k,l]` variable per step `k`. *(Encoder: variable creation loop)*
2. **Process conservation:** `sum_l kappa[k,l] = n` for all steps `k`. *(Encoder: conservation constraint)*
3. **Guard enablement:** `delta[k,r] > 0 ⇒ guard(r)` for all steps `k` and rules `r`. *(Encoder: guard implication)*
4. **Outflow bound:** `sum(delta_outgoing[k,l]) <= kappa[k,l]` for all steps `k` and locations `l`. *(Encoder: outflow constraint)*
5. **Shared flow:** `gamma[k+1,g] = gamma[k,g] + honest_sends[k,g] + adv[k,g] - drops[k,g]` for each message counter `g`. *(Encoder: shared-variable update)*
6. **Adversary total bound:** `sum_{k=0}^{k_max} adv[k,g] <= f` for each message counter `g`. *(Encoder: adversary budget)*
7. **Non-negativity:** `kappa[k,l] >= 0`, `gamma[k,g] >= 0`, `delta[k,r] >= 0` for all variables at all steps. *(Encoder: non-negativity assertions)*
8. **Resilience:** Parameter constraint from the `resilience` declaration is asserted. *(Encoder: resilience assertion)*
9. **Crypto non-forgeability:** `adv[k, crypto_var] = 0` for all crypto-object shared variables. *(Encoder: crypto forgeability constraint)*
10. **Safety target:** The bad-state predicate matches the lowered property from `extract_property(...)`. *(Encoder: property negation)*

## 9. Portfolio Merge Semantics

When `--portfolio` mode is enabled, tarsier runs Z3 and CVC5 concurrently and merges their results deterministically.

### Result Precedence

Each command type defines a strict precedence over result kinds. The highest-precedence conclusive result wins:

| Command | Precedence (highest → lowest) |
|---------|-------------------------------|
| `verify` (BMC safety) | `unsafe` > `safe` = `probabilistically_safe` > `unknown` |
| `check-liveness` | `not_live` > `live` > `unknown` |
| `prove` (safety) | `unsafe` > `safe` = `probabilistically_safe` > `not_proved` > `unknown` |
| `prove-fair` (fair liveness) | `fair_cycle_found` > `live_proved` > `not_proved` > `unknown` |
| `check-fair-liveness` | `fair_cycle_found` > `no_fair_cycle_up_to` > `unknown` |

If both solvers return the same conclusive result kind, that result is taken directly. If they disagree (e.g., one says `safe` and the other says `not_proved`), the merged result is `Unknown` with a "Portfolio disagreement" message. If either solver errors, the result is `Unknown` with a "Portfolio incomplete" message.

### Trace Tiebreak

When both solvers produce counterexample traces (e.g., both report `unsafe`), the trace is selected by:
1. **Shorter trace preferred** — fewer steps is more informative.
2. **Lexicographic fingerprint** — deterministic tiebreak on the JSON-serialized trace.

For `live` results, the conservative (minimum) `depth_checked` is taken. For `not_proved` results, the optimistic (maximum) `max_k` is taken along with the best counter-to-induction (highest-k CTI).

### Determinism Guarantee

Given identical inputs and solver versions, the portfolio merge produces identical output. The merge policy metadata is included in JSON reports under `portfolio.merge_policy` with fields `deterministic: true`, `result_precedence`, and `trace_tiebreak`.
CI additionally runs a race-stress regression (`portfolio_stress_*`) that alternates solver completion order while asserting byte-stable portfolio artifacts for identical inputs.

### Merge Provenance Logging

Portfolio JSON reports include deterministic merge provenance fields:
- `portfolio.per_solver_outcomes`: per-solver status/result (`ok|error` + outcome kind).
- `portfolio.selected_solver`: which solver (or `both`/`none`) determined the merged outcome.
- `portfolio.merge_reason`: explicit deterministic reason for the selected result.

These fields are emitted for `verify`, `check-liveness`, `prove`, `check-fair-liveness`, and `prove-fair` portfolio merges.

See `merge_portfolio_verify_reports()`, `merge_portfolio_liveness_results()`, `merge_portfolio_prove_results()`, and `merge_portfolio_fair_liveness_results()` in `main.rs`.

## 10. Quantitative Semantics (Communication / Finality Reports)

The `comm` analysis path emits a machine-readable quantitative report with the following contract:

- **Schema/version:** outputs are versioned (`schema_version`) and must match `docs/quantitative-schema-v2.json` exactly.
- **Assumptions-first interpretation:** reports carry explicit assumptions (`fault_model`, `timing_model`, `authentication_mode`, `equivocation_mode`, `network_semantics`, optional `gst_param`) plus assumption notes.
- **Bound classification:** each metric is tagged as `upper_bound`, `lower_bound`, or `estimate` in `bound_annotations`, including evidence class (`theorem_backed` or `heuristic_estimate`) and per-metric assumptions.
- **Per-dimension accounting:** communication bounds are reported per message type, sender role, and phase at step/depth granularity.
- **Unsupported extrapolation rejection:** if probabilistic/finality assumptions are not satisfied (for example asynchronous timing without GST), affected metrics are set to `null` and an error-level assumption note is emitted; no silent extrapolation is allowed.
- **Reproducibility binding:** metadata includes model source hash, analysis options, environment fields, and a deterministic reproducibility fingerprint.

Implementation anchors:

- `crates/tarsier-engine/src/result.rs`
- `crates/tarsier-engine/src/pipeline.rs`
- `docs/QUANTITATIVE_SCHEMA.md`
- `scripts/check-quantitative-baselines.sh`
- `scripts/check-quantitative-cli-pipeline.sh`
- `.github/workflows/ci.yml` (`quantitative-gate`)
