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

Trace-level IR events expose first-class action kinds and auth provenance:

- Action kinds: `Send`, `Deliver`, `Drop`, `Forge`, `Equivocate`.
- Auth metadata: effective channel auth, signature key, key owner role, key-compromised flag, and provenance class.

## 4. Timing / Fairness

- Logical time is an integer variable increasing by 1 per step.
- Faithful-target timing guarantees:
  - Asynchronous: no bound on delivery delay.
  - Partial synchrony: after GST, packets from honest live senders to honest live recipients are eventually delivered within a finite bound (unless the fault model explicitly permits omission/crash at endpoints).
- Under partial synchrony, fair-liveness cycle witnesses are constrained to post-GST regions.
- Weak fairness: continuously-enabled transitions must eventually fire.
- Strong fairness: infinitely-often-enabled transitions must eventually fire.

## 5. Properties

## 5.1 Safety

Safety properties are lowered to bad-state reachability:

- `agreement`, `safety`, `invariant`, `validity` fragments supported by `extract_property(...)`.

## 5.2 Liveness

If `property ...: liveness` is absent, liveness falls back to `forall p: Role. p.decided == true` (derived from locations where local `decided == true`).

For explicit liveness properties (`forall p: Role. ...`):

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
- For safety `prove` with k-induction, `NotProved` may include a CTI (counterexample-to-induction) witness: a SAT step fragment showing non-inductiveness of the property. CTIs are not guaranteed reachable from initial states.
- With `prove --cegar-iters > 0`, CTI-guided synthesis is applied for `NotProved` k-induction outcomes: candidate location-unreachability predicates are mined from CTI states, validated as invariants, and then used as strengthening predicates in a rerun.

## 6.4 Soundness Transfer: Abstraction Modes vs Faithful Target

Let `Reach_mode(k)` be the set of states reachable up to depth `k` under a given network mode.
Let `Reach_faithful(k)` be reachable states under the faithful target semantics.

Transfer rules:

- Over-approximation case:
  - if `Reach_faithful(k) subseteq Reach_mode(k)`, then `SAFE_mode` at depth/proof scope implies `SAFE_faithful`;
  - `UNSAFE_mode` may be spurious.
- Under-approximation case:
  - if `Reach_mode(k) subseteq Reach_faithful(k)`, then `UNSAFE_mode` implies `UNSAFE_faithful`;
  - `SAFE_mode` may be optimistic.
- Mixed/unknown relation:
  - without a proved inclusion relation, neither `SAFE` nor `UNSAFE` transfers automatically.

Practical status for current modes:

- `classic`, `identity_selective`, and `cohort_selective` are generally mixed abstractions relative to the faithful target.
- `process_selective` is closest structurally but remains a bounded finite-instance approximation (`pid` domain bound), so transfer is instance-scoped unless a cutoff argument is supplied.
- `values: sign` introduces additional data abstraction; transfer requires separate value-abstraction justification.

When old results are still usable:

- Old `UNSAFE` results are actionable if the trace is replayed/validated under faithful semantics.
- Old `SAFE` results are useful for triage and regression screening; treat as final guarantees only when an explicit over-approximation argument to faithful semantics is established.

## 7. Certificate Scope

Certificate bundles are independently checkable SMT obligation sets for:

- Safety k-induction and safety PDR invariants.
- Fair-liveness PDR invariants (`init => inv`, `inv & T => inv'`, `inv => no_fair_bad`).

Certificates attest satisfiability status of encoded obligations, not theorem-prover kernel proofs.

`check-certificate --rederive` strengthens checking by regenerating obligations from source and comparing obligation hashes before running external solvers.

Schema/version contract for certificate bundles is documented in `docs/CERTIFICATE_SCHEMA.md` (current `schema_version = 2`).
Trust boundary for certificate replay vs toolchain trust is documented in `docs/TRUST_BOUNDARY.md`.
