# Tarsier DSL Language Reference

This document is the complete reference for the `.trs` protocol modeling language. Tarsier verifies distributed consensus protocols by modeling them as threshold automata and checking safety and liveness properties via SMT-based bounded model checking and k-induction.

## Table of Contents

1. [Program Structure](#1-program-structure)
2. [Parameters](#2-parameters)
3. [Resilience](#3-resilience)
4. [Adversary Model](#4-adversary-model)
5. [Messages](#5-messages)
6. [Enums](#6-enums)
7. [Roles](#7-roles)
8. [Variables](#8-variables)
9. [Phases and Transitions](#9-phases-and-transitions)
10. [Guards](#10-guards)
11. [Actions](#11-actions)
12. [Properties](#12-properties)
13. [Identity, Channel, and Equivocation Declarations](#13-identity-channel-and-equivocation-declarations)
14. [Cryptographic Objects](#14-cryptographic-objects)
15. [Committees](#15-committees)
16. [Pacemaker](#16-pacemaker)
17. [Expressions](#17-expressions)
18. [Comments and Whitespace](#18-comments-and-whitespace)
19. [Verification Workflow](#19-verification-workflow)
20. [Complete Examples](#20-complete-examples)

---

## 1. Program Structure

A Tarsier program consists of a single protocol declaration containing all model elements:

```
protocol ProtocolName {
    <declarations>
}
```

Declarations can appear in any order inside the protocol block. All declarations are optional, but a meaningful model requires at least parameters, a role with phases, and a property.

---

## 2. Parameters

Parameters are symbolic protocol constants (e.g., `n` for total processes, `t` for fault tolerance threshold, `f` for actual faults). They take non-negative integer values during verification.

**Compact syntax:**

```
params n, t, f;
```

All parameters default to type `nat` (non-negative integer).

**Typed compact syntax:**

```
params n, t, f: nat, gst: nat;
```

**Block syntax:**

```
parameters {
    n: nat;
    t: nat;
    f: nat;
}
```

Supported types: `nat` (non-negative integer), `int` (integer).

Parameters used in resilience constraints or adversary bounds are automatically collected even if not explicitly declared.

---

## 3. Resilience

The resilience declaration constrains protocol parameters to ensure fault tolerance. It defines the relationship between the total number of processes and the fault tolerance threshold.

**Inline syntax:**

```
resilience: n > 3*t;
```

**Block syntax:**

```
resilience {
    n > 3*t;
}
```

Common patterns:

| Fault model | Typical resilience |
|---|---|
| Byzantine (BFT) | `n > 3*t` |
| Crash (CFT) | `n = 2*f + 1` |
| Omission | `n = 3*f + 1` |

The left-hand and right-hand sides are linear expressions over parameters. Supported operators: `>`, `>=`, `<`, `<=`, `==`, `!=`.

---

## 4. Adversary Model

The adversary block configures the fault model, network timing assumptions, and authentication semantics.

```
adversary {
    <key>: <value>;
    ...
}
```

### Adversary fields

| Key | Values | Default | Description |
|---|---|---|---|
| `model` | `byzantine`, `crash`, `omission` | `byzantine` | Fault model |
| `bound` | parameter name (e.g., `f`) | none | Bounds total adversary injections |
| `timing` | `partial_synchrony`, `async` | `async` | Network timing model |
| `gst` | parameter name | none | Global Stabilization Time (required if `timing: partial_synchrony`) |
| `values` | `sign`, `exact` | `exact` | Value abstraction mode |
| `auth` | `signed`, `none` | `none` | Authentication mode |
| `network` | `classic`, `identity_selective`, `cohort_selective`, `process_selective` | `classic` | Network semantics mode |
| `delivery` | `legacy_counter`, `per_recipient`, `global` | `legacy_counter` | Delivery control scope |
| `faults` | `legacy_counter`, `per_recipient`, `global` | `legacy_counter` | Fault budget scope |
| `equivocation` | `full`, `none` | `full` | Equivocation policy |
| `compromised_key` | key name | none | Mark a key as compromised (repeatable) |

### Fault models

**Byzantine**: The adversary can inject arbitrary messages (up to the bound), delay or drop messages, and optionally equivocate (send different values to different recipients). Byzantine processes are fully controlled by the adversary.

**Crash**: Processes may crash at any point and stop sending messages. No message forgery or equivocation. Each faulty process has a single crash time; before it, the process behaves honestly.

**Omission**: Messages may be lost (send or receive omissions). No message forgery, mutation, or equivocation. Faults manifest only as suppressed deliveries.

### Value abstraction

- `exact`: Message fields with type `nat` or `int` must declare finite ranges (e.g., `in 0..4`). All field value combinations are explicitly enumerated.
- `sign`: Integer fields are abstracted to sign classes (`{neg, zero, pos}` for `int`; `{zero, pos}` for `nat`). This is required when message fields have unbounded domains but the protocol logic only depends on the sign/presence of a value.

### Network semantics

- `classic`: Legacy counter-based abstraction. Message counters are scoped per recipient role. Simplest and fastest, but least precise for reasoning about individual senders.
- `identity_selective`: Per-sender, per-recipient message tracking with sender-budget coupling. Enables `distinct` receive guards and precise equivocation modeling. Requires `identity` declarations.
- `cohort_selective`: Cohort-scoped delivery with internal lane splitting for tighter approximation.
- `process_selective`: Process-scoped delivery using bounded local identity variables. Closest to the protocol-faithful target semantics.

### Example adversary blocks

**Minimal Byzantine:**

```
adversary {
    model: byzantine;
    bound: f;
    values: sign;
}
```

**Byzantine with partial synchrony and authentication:**

```
adversary {
    model: byzantine;
    bound: f;
    timing: partial_synchrony;
    gst: gst;
    auth: signed;
    network: identity_selective;
    delivery: per_recipient;
    faults: per_recipient;
    equivocation: none;
    values: sign;
}
```

**Crash fault:**

```
adversary {
    model: crash;
    bound: f;
    values: sign;
}
```

**Omission fault with partial synchrony:**

```
adversary {
    model: omission;
    bound: f;
    timing: partial_synchrony;
    gst: gst;
    values: sign;
}
```

---

## 5. Messages

Messages are the unit of communication between processes. Each message type can carry typed fields.

**Simple message (no fields):**

```
message Echo;
message Ready;
```

**Message with fields:**

```
message Vote(round: nat, value: bool);
message Proposal(view: nat, slot: nat);
message Prepare(epoch: nat in 0..4, height: int in 0..10);
```

### Field types

| Type | Description |
|---|---|
| `bool` | Boolean (`true`/`false`) |
| `nat` | Non-negative integer |
| `int` | Integer |
| `<EnumName>` | User-defined enum variant |

### Field ranges

When using `values: exact` (the default), `nat` and `int` fields **must** declare finite ranges:

```
message Vote(round: nat in 0..4);
```

When using `values: sign`, ranges are optional. Without a range, values are abstracted to sign classes.

---

## 6. Enums

User-defined finite types for message fields and local variables.

```
enum Color {
    Red, Green, Blue
}
```

Enum variants can be used as field types, variable types, and in expressions.

---

## 7. Roles

A role defines the behavior of a class of processes. Each role is a state machine with local variables, an initial phase, and phases containing guarded transitions.

```
role Replica {
    var decided: bool = false;
    var decision: bool = false;

    init start;

    phase start {
        when received >= 1 Proposal => {
            send Vote;
            goto phase voted;
        }
    }

    phase voted {
        when received >= 2*t+1 Vote => {
            decision = true;
            decided = true;
            decide true;
            goto phase done;
        }
    }

    phase done {}
}
```

- `init <phase>` declares the initial phase (required if the role has phases).
- Empty phases (`phase done {}`) are terminal states.
- A protocol can have multiple roles (e.g., `Proposer`, `Voter`, `Relay`).

---

## 8. Variables

Local variables define per-process state within a role. They drive the state-space explosion: each variable value combination creates a distinct location in the threshold automaton.

```
var decided: bool = false;
var round: nat = 0;
var height: int in -5..10;
var color: Color;
```

| Type | Domain | Notes |
|---|---|---|
| `bool` | `{false, true}` | Default initializer: `false` |
| `nat` | `{0, 1, ..., max}` | Requires `in min..max` range |
| `int` | `{min, ..., max}` | Requires `in min..max` range |
| `<EnumName>` | Enum variants | First variant if no initializer |

The initializer (`= <expr>`) is optional. Variables without an initializer default to the first value in their domain.

**Keep variables minimal.** Each boolean variable doubles the location count. Use only the state needed for the property you are checking.

---

## 9. Phases and Transitions

Phases are the nodes of the role's control-flow automaton. Each phase contains zero or more guarded transitions.

```
phase prepare {
    when received >= n-f Prepare(view=0, slot=0) => {
        goto phase commit;
    }
}
```

A transition fires when its guard is satisfied. Multiple transitions in the same phase represent nondeterministic choice (any enabled transition can fire).

**Syntax:**

```
when <guard> => {
    <action>;
    <action>;
    ...
}
```

---

## 10. Guards

Guards are conditions that must hold for a transition to fire. They can be composed with `&&` (conjunction) and `||` (disjunction).

### Threshold guard (message counting)

Fires when the count of received messages of a given type meets a threshold:

```
when received >= 2*t+1 Vote => { ... }
when received >= n-f Prepare(view=0, slot=0) => { ... }
when received >= 1 Init => { ... }
```

The threshold is a linear expression over parameters. Comparison operators: `>=`, `>`, `<=`, `<`, `==`, `!=`.

**Message field filters** restrict counting to messages with specific field values:

```
when received >= 2*t+1 Vote(round=0) => { ... }
```

### Distinct sender counting

With `network: identity_selective` (or other faithful modes), use the `distinct` keyword to count messages from distinct senders rather than total message count:

```
when received distinct >= 2*t+1 Prepare => { ... }
```

This models the realistic requirement of collecting messages from `2t+1` *different* processes.

### Cryptographic object guard

Fires when a quorum certificate or threshold signature is available:

```
when has QC => { ... }
when has TS(round=current_round) => { ... }
```

### Comparison guard

Fires based on a local variable comparison:

```
when round > 0 => { ... }
when decided == false => { ... }
```

### Boolean variable guard

Shorthand for checking a boolean variable is true:

```
when certified => { ... }
```

### Compound guards

Guards can be combined:

```
when received >= 2*t+1 Vote && round == 0 => { ... }
when flag1 || flag2 => { ... }
```

---

## 11. Actions

Actions execute when a transition fires. They are processed in order within a transition body.

### Send

Broadcasts a message to all processes (or to a specific role):

```
send Vote;
send Proposal(view=0);
send Commit(epoch=0, zxid=0) to Leader;
```

Without `to <Role>`, the message is broadcast to all roles that have receive guards for it.

### Assignment

Updates a local variable:

```
decided = true;
round = round + 1;
decision = false;
```

### Phase transition

Moves the process to a different phase:

```
goto phase committed;
```

If no `goto phase` appears in a transition, the process stays in the current phase (self-loop).

### Decide

Records a consensus decision value:

```
decide true;
decide proposed_value;
```

This sets `decided = true` and `decision = <value>` if those variables exist in the role. Used by `agreement` properties to track what value each process decided on.

### Form cryptographic object

Creates a quorum certificate or threshold signature:

```
form QC;
form TS(round=2) to Proposer;
```

### Lock / Justify cryptographic object

Acquires a lock on or justifies a cryptographic object:

```
lock QC;
justify TS(round=current_round);
```

---

## 12. Properties

Properties define what the verifier checks. Each property has a name, a kind, and a quantified formula.

```
property <name>: <kind> {
    <formula>
}
```

### Property kinds

| Kind | Description | Verification commands |
|---|---|---|
| `agreement` | No two decided processes disagree | `verify`, `prove` |
| `invariant` | State predicate holds in all reachable states | `verify`, `prove` |
| `safety` | Alias for invariant | `verify`, `prove` |
| `validity` | Every decided value was proposed | `verify`, `prove` |
| `liveness` | All processes eventually reach a goal state | `liveness`, `fair-liveness`, `prove-fair` |

### Agreement properties

The most common property for consensus protocols. Uses `==>` (implication) to express that if two processes have both decided, their decisions must agree:

```
property agreement: agreement {
    forall p: Replica. forall q: Replica.
        (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
}
```

Simpler form (when there is only one decision value):

```
property agreement: agreement {
    forall p: Replica. forall q: Replica. p.decided == q.decided
}
```

### Invariant / safety properties

State predicates that must hold in every reachable state:

```
property no_double_commit: invariant {
    forall p: Replica. p.committed_a == false || p.committed_b == false
}
```

### Liveness properties

State targets that all processes must eventually reach:

```
property termination: liveness {
    forall p: Replica. p.decided == true
}
```

### Temporal liveness properties

Full temporal logic with LTL-style operators:

```
property progress: liveness {
    forall p: Replica. (p.progressed == false) ~> <> (p.progressed == true)
}
```

### Temporal operators

| Operator | Syntax | Meaning |
|---|---|---|
| Next | `X phi` or `next phi` | `phi` holds in the next state |
| Always | `[] phi` or `always phi` | `phi` holds in all future states |
| Eventually | `<> phi` or `eventually phi` | `phi` holds in some future state |
| Until | `phi U psi` | `phi` holds until `psi` becomes true |
| Weak until | `phi W psi` | `phi` holds until `psi` (or forever) |
| Release | `phi R psi` | `psi` holds until `phi` releases it |
| Leads-to | `phi ~> psi` | whenever `phi` holds, `psi` eventually follows |
| Not | `! phi` | negation |

### Logical connectives in formulas

| Connective | Syntax |
|---|---|
| And | `&&` |
| Or | `\|\|` |
| Implies | `==>` |
| Iff | `<=>` |

### Quantifiers

Formulas can be universally or existentially quantified over a role:

```
forall p: Replica. <formula>
exists p: Replica. <formula>
```

The quantified variable can access the role's local state via dot notation: `p.decided`, `p.round`, `p.decision`.

---

## 13. Identity, Channel, and Equivocation Declarations

These declarations enable the faithful network semantics, which provide more precise modeling of sender identity, message authentication, and equivocation.

### Identity declarations

Bind a cryptographic identity to a role:

```
identity Replica: role key replica_key;
```

This declares that processes in the `Replica` role have a role-scoped identity with key `replica_key`.

**Process-scoped identity** (for `process_selective` network mode):

```
identity Replica: process(pid) key replica_key;
```

Here `pid` must be a bounded local variable declared in the role.

### Channel declarations

Per-message authentication policy:

```
channel PrePrepare: authenticated;
channel Prepare: authenticated;
channel Commit: authenticated;
```

Authenticated channels ensure the sender identity on a message is cryptographically verified. Unauthenticated channels allow sender spoofing.

### Equivocation declarations

Per-message equivocation policy:

```
equivocation PrePrepare: none;
equivocation Prepare: none;
equivocation Commit: none;
```

- `none`: A process cannot send different payload values for the same message type to different recipients in the same step.
- `full`: A process can send conflicting values to different recipients (Byzantine equivocation).

### Faithful variant recipe

To create a protocol model with full faithful network semantics:

```
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: identity_selective;
    delivery: per_recipient;
    faults: per_recipient;
    equivocation: none;
    values: sign;
}

identity Replica: role key replica_key;

channel Vote: authenticated;
equivocation Vote: none;
```

Then use `distinct` in receive guards:

```
when received distinct >= 2*t+1 Vote => { ... }
```

---

## 14. Cryptographic Objects

Quorum certificates (QCs) and threshold signatures are first-class objects built from aggregating messages.

### Declaration

```
certificate QC from Vote threshold 2*t+1;
threshold_signature TS from Proposal threshold 2*t+1 signer Proposer;
certificate LockQC from Vote threshold 2*t+1 conflicts exclusive;
```

- `certificate`: A quorum certificate aggregating messages of a given type.
- `threshold_signature`: A threshold signature with a designated signer role.
- `from <Message>`: Source message type being aggregated.
- `threshold <expr>`: Number of messages required to form the object.
- `signer <Role>`: Signer role whose signatures are aggregated. Required for `threshold_signature`.
- `conflicts allow|exclusive`: Optional admissibility policy for conflicting variants (default `allow`).
  - `allow`: no extra conflict restriction.
  - `exclusive`: when forming/locking/justifying this object, conflicting variants for the same recipient are rejected.

### Usage in transitions

**Form** (create the object when threshold is met):

```
form QC;
```

**Has** (guard: check if object exists):

```
when has QC => { ... }
```

**Lock** (acquire a lock, ensuring the object is present):

```
lock QC;
```

**Justify** (use an existing object as justification):

```
justify QC;
```

---

## 15. Committees

Committee declarations enable probabilistic verification for protocols with random committee selection (e.g., Algorand-style sortition).

```
committee voters {
    population: 1000;
    byzantine: 333;
    size: 100;
    epsilon: 1.0e-9;
    bound_param: b;
}
```

| Field | Type | Description |
|---|---|---|
| `population` | integer | Total population size (N) |
| `byzantine` | integer | Maximum Byzantine nodes in population (K) |
| `size` | integer | Committee sample size (S) |
| `epsilon` | float | Target failure probability |
| `bound_param` | parameter name | Protocol parameter to receive the computed maximum Byzantine committee members |

Tarsier uses hypergeometric distribution analysis to compute the maximum number of Byzantine members `b_max` that can appear in a random committee of size `S` drawn from a population of `N` with `K` Byzantine nodes, with failure probability at most `epsilon`. The computed `b_max` is injected as an upper bound on the parameter named by `bound_param`.

The protocol's resilience and guards then use this parameter:

```
resilience: n > 2*b;

when received >= 2*b+1 CertVote => { ... }
```

If the protocol is safe under `b <= b_max`, the result is `ProbabilisticallySafe` with the union-bound failure probability.

---

## 16. Pacemaker

The pacemaker declaration adds automatic view-change transitions to a role.

```
pacemaker {
    view: current_view;
    start: propose;
    reset: decided, locked;
}
```

| Field | Description |
|---|---|
| `view` | Local variable to increment on view change |
| `start` | Phase to re-enter after the view change |
| `reset` | Variables to reset to their initial values |

When a pacemaker is active, the engine injects additional transitions that increment the view variable, reset the specified variables, and return to the start phase.

---

## 17. Expressions

### Arithmetic expressions

Used in assignments, send arguments, and guards.

| Operator | Syntax | Precedence |
|---|---|---|
| Multiplication | `*` | Highest |
| Division | `/` | Highest |
| Addition | `+` | Medium |
| Subtraction | `-` | Medium |
| Unary negation | `-x` | Prefix |
| Unary not | `!x` | Prefix |

Parentheses `(` `)` override precedence.

### Linear expressions

Used in thresholds and resilience constraints. Restricted to linear combinations of parameters:

```
2*t+1
n - f
3*f + 2*t + 1
```

Implicit multiplication is supported: `2t` is equivalent to `2*t`.

### Literals

| Type | Examples |
|---|---|
| Integer | `0`, `42`, `100` |
| Boolean | `true`, `false` |
| Float | `1.0e-9`, `3.14` (only in committee `epsilon`) |

### Variable references

Local variables and parameters can be referenced by name:

```
round + 1
decided == true
```

Qualified variable access (in formulas): `p.decided`, `q.round`.

---

## 18. Comments and Whitespace

**Line comments:**

```
// This is a comment
params n, t, f; // inline comment
```

**Block comments:**

```
/* This is a
   block comment */
```

Whitespace (spaces, tabs, newlines) is ignored between tokens.

---

## 19. Verification Workflow

### CLI commands

| Command | Description |
|---|---|
| `tarsier verify <file>` | Bounded model checking (safety) |
| `tarsier prove <file>` | Unbounded safety proof (k-induction/PDR) |
| `tarsier liveness <file>` | Bounded liveness check |
| `tarsier fair-liveness <file>` | Bounded fair liveness (cycle detection) |
| `tarsier prove-fair <file>` | Unbounded fair liveness proof |
| `tarsier lint <file>` | Semantic linting and warnings |
| `tarsier comm <file>` | Communication complexity analysis |
| `tarsier visualize <file>` | Trace visualization (timeline, MSC) |
| `tarsier debug-cex <file>` | Interactive counterexample debugger |

### Common flags

| Flag | Description |
|---|---|
| `--depth <N>` | Maximum exploration depth (default: 6) |
| `--k <N>` | Induction parameter for prove (default: 8) |
| `--solver z3\|cvc5` | SMT solver backend |
| `--soundness strict\|permissive` | Soundness profile |
| `--timeout <secs>` | Per-protocol timeout |
| `--format text\|json` | Output format |
| `--network-semantics dsl\|faithful` | Network semantics mode |

### Verification results

| Result | Meaning |
|---|---|
| `Safe` | No violation found up to depth (bounded) |
| `Unsafe` | Counterexample found (with trace) |
| `ProbabilisticallySafe` | Safe with committee probability bound |
| `Unknown` | Solver timeout or inconclusive |

### Proof results

| Result | Meaning |
|---|---|
| `Safe` | Inductive proof found (unbounded) |
| `Unsafe` | Counterexample found |
| `NotProved` | Induction failed (may include CTI witness) |

---

## 20. Complete Examples

### Bracha Reliable Broadcast (Byzantine, minimal)

```
protocol ReliableBroadcast {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
        values: sign;
    }

    message Init;
    message Echo;
    message Ready;

    role Process {
        var accepted: bool = false;
        var decided: bool = false;
        init waiting;

        phase waiting {
            when received >= 1 Init => {
                accepted = true;
                send Echo;
                goto phase echoed;
            }
        }

        phase echoed {
            when received >= 2*t+1 Echo => {
                send Ready;
                goto phase readied;
            }
        }

        phase readied {
            when received >= 2*t+1 Ready => {
                decided = true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process. p.decided == q.decided
    }
}
```

### PBFT Safety Kernel (Byzantine, faithful)

```
protocol PBFTSimpleSafeFaithful {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        network: identity_selective;
        delivery: per_recipient;
        faults: per_recipient;
        equivocation: none;
    }

    identity Replica: role key replica_key;
    channel PrePrepare: authenticated;
    channel Prepare: authenticated;
    channel Commit: authenticated;
    equivocation PrePrepare: none;
    equivocation Prepare: none;
    equivocation Commit: none;

    message PrePrepare;
    message Prepare;
    message Commit;

    role Replica {
        var decided: bool = false;
        var decision: bool = false;
        init start;

        phase start {
            when received >= 1 PrePrepare => {
                send Prepare;
                goto phase prepared;
            }
        }

        phase prepared {
            when received distinct >= 2*t+1 Prepare => {
                send Commit;
                goto phase committed;
            }
        }

        phase committed {
            when received distinct >= 2*t+1 Commit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
```

### Viewstamped Replication (Crash fault)

```
protocol ViewstampedReplication {
    params n, t, f;
    resilience: n = 2*f + 1;

    adversary {
        model: crash;
        bound: f;
        values: sign;
    }

    message StartView(view: nat);
    message Prepare(view: nat, slot: nat);
    message Commit(view: nat, slot: nat);

    role Replica {
        var decided: bool = false;
        init start;

        phase start {
            when received >= n-f StartView(view=0) => {
                goto phase prepare;
            }
        }

        phase prepare {
            when received >= n-f Prepare(view=0, slot=0) => {
                goto phase commit;
            }
        }

        phase commit {
            when received >= n-f Commit(view=0, slot=0) => {
                decided = true;
                goto phase decided;
            }
        }

        phase decided {}
    }

    property agreement: agreement {
        forall p: Replica. forall q: Replica. p.decided == q.decided
    }
}
```

### Algorand Committee Selection (Probabilistic)

```
protocol AlgorandCommittee {
    params n, t, f, b;
    resilience: n > 2*b;

    adversary {
        model: byzantine;
        bound: b;
        values: sign;
    }

    committee voters {
        population: 1000;
        byzantine: 333;
        size: 100;
        epsilon: 1.0e-9;
        bound_param: b;
    }

    message SoftVote;
    message CertVote;

    role Voter {
        var certified: bool = false;
        var decided: bool = false;
        var decision: bool = false;
        init soft_vote;

        phase soft_vote {
            when received >= 2*b+1 SoftVote => {
                send CertVote;
                goto phase cert_vote;
            }
        }

        phase cert_vote {
            when received >= 2*b+1 CertVote => {
                decision = true;
                decided = true;
                certified = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Voter. forall q: Voter.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
```

### Temporal Liveness

```
protocol LivenessExample {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
        values: sign;
    }

    message Vote;

    role Replica {
        var decided: bool = false;
        var progressed: bool = false;
        init start;

        phase start {
            when received >= 1 Vote => {
                progressed = true;
                decided = true;
                goto phase done;
            }
        }

        phase done {}
    }

    property live: liveness {
        forall p: Replica. p.decided == true
    }

    property progress: liveness {
        forall p: Replica. (p.progressed == false) ~> <> (p.progressed == true)
    }
}
```

---

## Grammar Summary

```
program         = protocol_decl
protocol_decl   = "protocol" IDENT "{" protocol_item* "}"
protocol_item   = params_decl | resilience_decl | adversary_decl
                | message_decl | enum_decl | role_decl | property_decl
                | identity_decl | channel_decl | equivocation_decl
                | committee_decl | crypto_object_decl | pacemaker_decl

params_decl     = "params" param_list ";"
                | "parameters" "{" param_def* "}"
resilience_decl = "resilience" ":" resilience_expr ";"
                | "resilience" "{" resilience_expr ";" "}"
adversary_decl  = "adversary" "{" adv_item* "}"
message_decl    = "message" IDENT [ "(" field_list ")" ] ";"
crypto_object_decl
                = ("certificate" | "threshold_signature") IDENT
                  "from" IDENT "threshold" linear_expr
                  ["signer" IDENT]
                  ["conflicts" ("allow" | "exclusive")]
                  ";"
enum_decl       = "enum" IDENT "{" variant_list "}"
role_decl       = "role" IDENT "{" role_item* "}"
property_decl   = "property" IDENT ":" kind "{" formula "}"

role_item       = var_decl | init_decl | phase_decl
var_decl        = "var" IDENT ":" type [ "in" range ] [ "=" expr ] ";"
init_decl       = "init" IDENT ";"
phase_decl      = "phase" IDENT "{" transition* "}"
transition      = "when" guard "=>" "{" action* "}"

guard           = threshold_guard | has_guard | cmp_guard | bool_guard
                | guard "&&" guard | guard "||" guard
threshold_guard = "received" ["distinct"] cmp_op linear_expr IDENT [msg_args]
has_guard       = "has" IDENT [msg_args]
msg_args        = "(" IDENT "=" expr ("," IDENT "=" expr)* ")"

action          = send | assign | goto | decide
                | form | lock | justify
send            = "send" IDENT [send_args] ["to" IDENT] ";"
assign          = IDENT "=" expr ";"
goto            = "goto" "phase" IDENT ";"
decide          = "decide" expr ";"

formula         = quantifier* formula_expr
quantifier      = ("forall" | "exists") IDENT ":" IDENT "."
formula_expr    = comparison | temporal | logical | "(" formula_expr ")"
temporal        = ("X"|"[]"|"<>") formula_expr
                | formula_expr ("U"|"W"|"R"|"~>") formula_expr
logical         = formula_expr ("&&"|"||"|"==>"|"<=>") formula_expr
                | "!" formula_expr
```

This grammar is approximate; see `crates/tarsier-dsl/src/grammar.pest` for the authoritative PEG grammar.
