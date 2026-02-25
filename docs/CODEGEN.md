# Code Generation

Tarsier can generate skeleton Rust and Go implementations from `.trs` protocol models. The generated code is a starting point for building a runnable node — it captures the verified protocol logic (phases, guards, transitions, actions) but leaves networking, serialization, and cryptographic verification to the implementer.

## Verified Codegen Policy

**Code generation requires a valid proof certificate by default.** This ensures that generated implementations correspond to verified protocol models. The verification gate is enforced at the CLI and API level — `tarsier codegen` will refuse to generate code unless a certificate bundle is provided and passes integrity/obligation checks.

### Policy Summary

| Mode | Flag | Behavior | Artifact Marker |
|------|------|----------|-----------------|
| **Verified** (default) | `--require-cert <path>` | Certificate bundle must pass integrity check and all obligations must be UNSAT. Generation proceeds only after verification. | `verified: true` in provenance header |
| **Unverified override** | `--allow-unverified` | Bypasses certificate requirement. Emits a warning and marks all generated artifacts as unverified. | `verified: false`, `audit_tag: UNVERIFIED_CODEGEN` in provenance header |

### Rationale

Generating code from an unverified model risks deploying protocol logic that has not been checked for safety or liveness properties. The default-verified policy enforces a trust chain from formal specification through verification to implementation:

1. **Model** (`.trs` file) defines protocol logic
2. **Verification** (BMC/k-induction) proves safety/liveness properties
3. **Certificate** records proof obligations and solver results
4. **Codegen** generates implementation from the *verified* model

Breaking this chain requires an explicit opt-in (`--allow-unverified`) that leaves an audit trail in the generated artifact.

## What Is Generated

For each protocol, codegen emits:

- **Config struct** — one field per protocol parameter (`n`, `t`, `f`, etc.)
- **Message structs** — one per `message` declaration, with typed fields
- **Envelope** — wraps a message with a `sender` ID
- **Protocol semantics surface** — generated metadata structs and helpers for:
  - `identity` declarations (role/process scope + optional key labels)
  - `channel` declarations (per-message auth mode)
  - `equivocation` declarations (per-message equivocation mode)
  - `committee` declarations (typed committee items/values)
- **Outbound message metadata** — send actions emit `OutboundMessage` objects carrying:
  - protocol message payload
  - optional DSL recipient role (`send ... to Role`)
  - resolved channel auth mode
  - resolved equivocation mode
- **Network trait/interface** — `Broadcast(outbound)` and `Send(outbound, to)` methods carrying message + policy metadata
- **Per-role state machine** including:
  - Phase enum (one variant per phase)
  - State struct with local variables, per-message receive buffers, and crypto object tracking fields
  - Constructor (`new()` / `NewXState()`) with correct initial values
  - `handle_message()` method that buffers the incoming message, evaluates guards for the current phase, and executes matching transition actions

## Crypto Object Support

Crypto objects (`certificate`, `threshold_signature`) are modeled with lightweight tracking fields:

| DSL construct | Generated Rust | Generated Go |
|---|---|---|
| `certificate QC ...` | `qc_count: u64`, `lock_qc: bool`, `justify_qc: bool` | `QCCount uint64`, `LockQC bool`, `JustifyQC bool` |
| `form QC(...)` | `self.qc_count += 1;` | `s.QCCount++` |
| `lock QC(...)` | `self.lock_qc = true;` | `s.LockQC = true` |
| `justify QC(...)` | `self.justify_qc = true;` | `s.JustifyQC = true` |
| `has QC(...)` | `self.qc_count >= 1` | `s.QCCount >= 1` |

These fields track *whether* a crypto object has been formed/locked/justified. Actual cryptographic verification (signature aggregation, threshold checks) is not generated — it is the implementer's responsibility.

## Threshold Guard Helpers

When the protocol uses field-filtered threshold guards (e.g., `received distinct >= 2*t+1 Vote(view=view)`), the generated Go code emits helper functions:

- `countFiltered(buf, match)` — counts envelopes satisfying a predicate
- `countDistinctFiltered(buf, match)` — counts distinct senders satisfying a predicate
- `countDistinctSenders(buf)` — counts unique senders (emitted when `distinct` guards are used)

In Rust, filtered guards are inlined as iterator chains.

## What Is NOT Generated

The following are **not** part of the generated skeleton:

- **Networking** — TCP/UDP/gRPC transport, peer discovery, message routing
- **Serialization** — protobuf/JSON/bincode encoding of messages
- **Cryptographic verification** — signature verification, threshold signature aggregation, certificate validation
- **Timers / Pacemaker** — timeout-driven transitions, view-change logic
- **Runtime committee sampling engines** — committee declarations are emitted as typed metadata/policy surface, but sampling logic/integration remains implementer-owned

## Faithful-Semantics Surface Coverage

Codegen now accepts models that include committee/channel/equivocation/identity declarations and emits them as a typed policy surface in generated Rust/Go artifacts.

| DSL feature | Generated surface |
|---|---|
| `identity` | `IdentityDeclSpec`, `IdentityScopeSpec`, `ProtocolSemanticsSpec.Identities` |
| `channel` | `ChannelPolicySpec`, per-message auth resolver (`channel_auth_for_message_family` / `channelAuthForMessageFamily`) |
| `equivocation` | `EquivocationPolicySpec`, per-message equivocation resolver (`equivocation_mode_for_message_family` / `equivocationModeForMessageFamily`) |
| `committee` | `CommitteeSpec`, `CommitteeItemSpec`, typed committee values (`Param`/`Int`/`Float`) |

This support is intentionally **scaffold-level**: metadata and send-path policy annotations are generated, while deployment/runtime enforcement remains external integration work.

## Guarantees

- **Deterministic** — same `.trs` input always produces the same output
- **Compiles** — generated Rust and Go code compiles without errors (tested in CI)
- **Faithful guards** — threshold guards, comparisons, and boolean guards match the `.trs` model
- **Faithful policy surface** — committee/channel/equivocation/identity declarations are emitted as typed metadata and per-send annotations
- **No TODO stubs** — crypto object operations generate real tracking code

## Testing and Contracts

Codegen quality is enforced by layered tests:

- **End-to-end codegen smoke tests** validate representative protocol examples compile after generation.
- **Unit tests for helper contracts** validate:
  - default auth/equivocation fallback behavior,
  - message constructor rendering for named/positional args,
  - literal/type fallback rendering rules,
  - distinct/filtered helper emission behavior.
- **Provenance golden tests** validate deterministic provenance headers and verified/unverified markers.

Recommended local loop when touching codegen internals:

```bash
cargo test -p tarsier-codegen
cargo test -p tarsier-cli --test codegen_verified
```

Quality bar for codegen changes:

- Preserve deterministic output for identical `(model, options)` input.
- Prefer semantic assertions (policy labels, constructor fields, fallback modes) over brittle full-file string matching.
- Add or update tests for any changed fallback/default behavior.

## Non-Goals

- **Not optimized** — generated code prioritizes correctness and readability over performance
- **Integration required** — generated code requires networking, crypto, and deployment infrastructure
- **Scaffold, not turnkey** — protocol logic is verified-by-construction; system integration is the developer's responsibility

## Usage

```bash
# Verified codegen (default — requires certificate)
tarsier codegen examples/reliable_broadcast.trs --target rust --require-cert certs/bundle --out src/

# Verified Go generation
tarsier codegen examples/reliable_broadcast.trs --target go --require-cert certs/bundle --out pkg/

# Unverified override (for development/prototyping only)
tarsier codegen examples/reliable_broadcast.trs --target rust --allow-unverified --out src/
# WARNING: generated artifact marked as UNVERIFIED_CODEGEN
```

## Provenance

Every generated artifact includes a provenance header comment with:

- **model_sha256** — SHA-256 hash of the source `.trs` file
- **options_sha256** — SHA-256 hash of the codegen options (target, flags)
- **certificate_ref** — path to the certificate bundle (if verified) or `"none"` (if unverified)
- **verified** — `true` if a valid certificate was provided, `false` otherwise
- **audit_tag** — `UNVERIFIED_CODEGEN` when `--allow-unverified` is used, absent otherwise
- **generated_at** — UTC timestamp of generation

This metadata enables downstream tooling to verify the provenance chain and flag unverified artifacts in CI/CD pipelines.
