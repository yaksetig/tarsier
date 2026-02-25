# Getting Started with Tarsier

This guide walks you through installing Tarsier, writing your first consensus protocol model, verifying it, and understanding the results. By the end, you will have verified a real Byzantine fault-tolerant broadcast protocol and diagnosed a buggy one.

## What is Tarsier?

Tarsier is a formal verification tool for distributed consensus protocols. You write a protocol model in a simple `.trs` DSL (domain-specific language), and Tarsier checks whether your protocol satisfies safety and liveness properties — even in the presence of Byzantine (malicious) faults.

Under the hood, Tarsier models your protocol as a **threshold automaton** — a finite-state machine where transitions are guarded by threshold conditions like "received at least 2t+1 votes." It then uses **SMT-based bounded model checking** to exhaustively search for bugs, and **k-induction/IC3** for unbounded safety proofs.

**What Tarsier can check:**
- **Agreement** — No two honest processes decide on different values
- **Safety invariants** — Bad states are never reached
- **Liveness** — All processes eventually make progress
- **Probabilistic safety** — Committee-based protocols with random selection

## Quick Install (Recommended)

### Option A: Shell installer

```bash
curl -fsSL https://raw.githubusercontent.com/tarsier-verify/tarsier/main/install.sh | sh
```

### Option B: Homebrew (macOS)

```bash
brew tap tarsier-verify/tarsier
brew install tarsier
```

### Option C: Download binary

Download the latest release for your platform from
[GitHub Releases](https://github.com/tarsier-verify/tarsier/releases).

Binaries are available for:
- Linux x86_64 and aarch64
- macOS x86_64 (Intel) and aarch64 (Apple Silicon)

### Option D: Build from source

See [Building from Source](#building-from-source) below.

---

## Building from Source

### Prerequisites

- **Rust toolchain** (1.75 or later): install via [rustup](https://rustup.rs/)
- **cmake**: required to build the Z3 solver backend
  - macOS: `brew install cmake`
  - Ubuntu/Debian: `sudo apt install cmake`
  - Fedora: `sudo dnf install cmake`

### Step 1: Install Tarsier

```bash
git clone https://github.com/tarsier-verify/tarsier.git
cd tarsier
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release
```

The build takes a few minutes because it compiles the Z3 SMT solver from source (statically linked). When complete, the binary is at `target/release/tarsier`.

> **Note:** Governance features (trust reports, cert suites, governance bundles, certificate commands) are optional.
> Build with `CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release --features governance` to enable them.
> Default builds intentionally omit governance-only commands from `tarsier --help`.

Add it to your PATH for convenience:

```bash
export PATH="$PWD/target/release:$PATH"
```

Verify the installation:

```bash
tarsier --help
```

### Command sets by build

Default build (`cargo build --release`) includes core verification commands such as:
`analyze`, `verify`, `prove`, `prove-fair`, `visualize`, `lint`, `assist`, `comm`.

Governance build (`cargo build --release --features governance`) adds:
`cert-suite`, `certify-safety`, `certify-fair-liveness`, `check-certificate`,
`generate-trust-report`, `governance-pipeline`, `verify-governance-bundle`.

## Canonical Paths

### Beginner (recommended)

```bash
tarsier assist --kind pbft --out my_protocol.trs
tarsier analyze my_protocol.trs --goal safety
tarsier visualize my_protocol.trs --check verify
```

### Pro (advanced controls)

```bash
tarsier analyze my_protocol.trs --profile pro --goal safety+liveness --depth 16 --k 20 --timeout 600
```

### Governance (feature build only)

```bash
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release --features governance
tarsier analyze my_protocol.trs --profile governance --goal release --format json
tarsier certify-safety my_protocol.trs --out certs/my_protocol
```

## Step 2: Your First Verification

Let's start by verifying an existing protocol. Tarsier ships with examples in the `examples/` directory.

### Verify a correct protocol

```bash
tarsier analyze examples/reliable_broadcast.trs
```

This runs Tarsier's unified analysis pipeline on the Bracha Reliable Broadcast protocol. You should see output indicating the protocol is **Safe** — no agreement violation was found.

### Find a bug in a broken protocol

```bash
tarsier analyze examples/reliable_broadcast_buggy.trs --goal bughunt
```

This time, Tarsier finds a bug and reports **Unsafe** with a counterexample trace showing exactly how Byzantine processes can cause disagreement.

## Step 3: Understand the Protocol Model

Let's read the correct protocol to understand the `.trs` language. Open `examples/reliable_broadcast.trs`:

```
protocol ReliableBroadcast {
    parameters {
        n: nat;     // total number of processes
        t: nat;     // max number of faulty processes
        f: nat;     // actual number of faulty processes
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Init;
    message Echo;
    message Ready;

    role Process {
        var accepted: bool = false;
        var decided: bool = false;
        var decision: bool = false;

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
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true)
                ==> (p.decision == q.decision)
    }
}
```

### Key concepts

Every `.trs` file has these building blocks:

| Block | Purpose |
|-------|---------|
| `parameters` | Symbolic constants — `n` (total processes), `t` (fault tolerance), `f` (actual faults) |
| `resilience` | Constraint relating parameters — here `n > 3t` (classic BFT bound) |
| `adversary` | Fault model — `byzantine` with `f` faulty processes |
| `message` | Message types exchanged between processes |
| `role` | Process behavior — phases (states) with guarded transitions |
| `property` | What to verify — here, agreement (no two decided processes disagree) |

### How the protocol works

1. **Waiting**: Each process waits for an `Init` message from the sender
2. **Echo**: On receiving `Init`, broadcast `Echo` to everyone
3. **Ready**: On receiving `2t+1` Echos, broadcast `Ready`
4. **Done**: On receiving `2t+1` Readys, deliver (decide `true`)

The threshold `2t+1` ensures that even if `t` Byzantine processes send conflicting messages, honest processes still agree — because any two sets of `2t+1` processes overlap in at least one honest process.

## Step 4: Write Your Own Protocol

Let's write a simple voting protocol from scratch. Create a file called `my_vote.trs`:

```
protocol SimpleVote {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Commit;

    role Voter {
        var decided: bool = false;
        var decision: bool = false;

        init voting;

        phase voting {
            // Collect 2t+1 votes, then send commit
            when received >= 2*t+1 Vote => {
                send Commit;
                goto phase committing;
            }
        }

        phase committing {
            // Collect 2t+1 commits, then decide
            when received >= 2*t+1 Commit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Voter. forall q: Voter.
            (p.decided == true && q.decided == true)
                ==> (p.decision == q.decision)
    }
}
```

Now verify it:

```bash
tarsier analyze my_vote.trs --goal safety
```

This protocol is safe because the `2t+1` thresholds are high enough that Byzantine processes cannot cause disagreement.

### Introduce a bug

Try changing the vote threshold from `2*t+1` to `t+1`:

```
when received >= t+1 Vote => {
```

Run verification again:

```bash
tarsier analyze my_vote.trs --goal bughunt
```

Tarsier will find a counterexample — with the weaker threshold, Byzantine processes can push different groups of honest processes to commit different values.

## Step 5: Visualize Counterexamples

When Tarsier finds a bug, you can visualize the counterexample trace in several formats:

```bash
# Human-readable step-by-step timeline
tarsier visualize examples/reliable_broadcast_buggy.trs --format timeline

# Mermaid sequence diagram (paste into any Mermaid renderer)
tarsier visualize examples/reliable_broadcast_buggy.trs --format mermaid

# Full markdown report
tarsier visualize examples/reliable_broadcast_buggy.trs --format markdown

# Export all formats at once
tarsier visualize examples/reliable_broadcast_buggy.trs --bundle /tmp/cex-bundle
```

### Interactive TUI explorer

For a richer experience, use the interactive terminal-based trace explorer:

```bash
tarsier explore examples/reliable_broadcast_buggy.trs
```

This opens a 3-panel TUI where you can step through the counterexample, see location occupancy (how many processes are in each phase), shared variable values, and message deliveries at each step.

**Key bindings:** `n`/Right = next step, `p`/Left = previous, `d` = toggle diff highlighting, `Tab` = cycle panels, `q` = quit.

### Interactive debugger

The debugger lets you filter and inspect counterexample traces:

```bash
tarsier debug-cex examples/reliable_broadcast_buggy.trs
```

Debugger commands: `n` (next), `p` (prev), `fs Role` (sender), `fr Role` (recipient),
`fm Family` (message), `fv text` (payload variant), `ff key=value` (payload field),
`fa auth` (auth metadata: `authenticated`/`unauthenticated`/`compromised`/`uncompromised`/provenance),
`fc` (clear filters), `q` (quit).

## Step 6: Lint Your Protocol

Before running expensive verification, lint your model for common mistakes:

```bash
tarsier lint my_vote.trs
```

The linter checks for:
- Missing parameter declarations
- Unbounded integer variables
- Missing adversary bounds
- Unreachable phases
- Unsound threshold expressions

Each issue includes a severity level, soundness impact, and a suggestion for how to fix it.

## Step 7: Visualize the Automaton Structure

Export your protocol's threshold automaton as a Graphviz DOT diagram:

```bash
tarsier export-dot examples/reliable_broadcast.trs --out automaton.dot
```

If you have Graphviz installed, render it directly to SVG:

```bash
tarsier export-dot examples/reliable_broadcast.trs --svg --out automaton.svg
```

This produces a graph where nodes are locations (phase + variable combinations) and edges are transitions labeled with their guards.

## Step 8: Scaffold a New Protocol

Tarsier can generate protocol skeletons for common BFT families:

```bash
tarsier assist --kind pbft --out my_pbft.trs
tarsier assist --kind hotstuff --out my_hotstuff.trs
tarsier assist --kind tendermint --out my_tendermint.trs
tarsier assist --kind raft --out my_raft.trs
```

Each scaffold comes with the correct resilience condition, fault model, message types, phases, and a starter property. Edit the generated file to match your protocol's specific logic.

## Step 9: Prove Unbounded Safety

Bounded model checking (BMC) searches for bugs up to a fixed depth. To prove your protocol is safe for *all* execution depths, use the proof engine:

```bash
# K-induction proof
tarsier prove examples/pbft_simple.trs --k 12 --engine kinduction

# IC3/PDR proof (often more powerful)
tarsier prove examples/pbft_simple.trs --k 12 --engine pdr
```

Or use the unified entry point:

```bash
tarsier analyze examples/pbft_simple.trs --goal safety
```

A successful proof means: **for all values of n, t, f satisfying the resilience constraint, the protocol is safe at all depths.**

## Step 10: Generate Proof Certificates

For maximum trust, generate independently verifiable proof certificates:

```bash
# Requires a governance feature build:
# CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release --features governance

# Generate certificate
tarsier certify-safety examples/pbft_simple.trs --k 12 --engine pdr --out certs/pbft

# Check with external SMT solvers
tarsier check-certificate certs/pbft --solvers z3,cvc5
```

The certificate is a bundle of SMT2 files that any standards-compliant SMT solver can verify, independent of Tarsier's implementation. See `docs/TRUST_BOUNDARY.md` for the full trust model.

## Common Workflows

### Quick bug-finding (during development)

```bash
tarsier analyze my_protocol.trs --goal bughunt
```

### Full safety proof (before merging)

```bash
tarsier analyze my_protocol.trs --goal safety
```

### CI gate (automated pipeline)

```bash
tarsier analyze my_protocol.trs --profile ci-proof --format json
```

### Governance/audit (release gating)

```bash
tarsier analyze my_protocol.trs --goal release --format json --report-out report/
```

## Fault Models

Tarsier supports three fault models:

| Model | Description | Resilience | Use for |
|-------|-------------|------------|---------|
| `byzantine` | Fully malicious processes that can forge, delay, equivocate | `n > 3t` | BFT protocols (PBFT, HotStuff, Tendermint) |
| `crash` | Processes stop permanently, no forgery | `n = 2f + 1` | CFT protocols (Paxos, Raft, VSR) |
| `omission` | Messages can be lost, no forgery | `n = 3f + 1` | Omission-tolerant protocols (Zab) |

## Project Structure

```
tarsier/
  examples/                    # 8 introductory example protocols
    library/                   # 40 canonical protocol corpus (PBFT, HotStuff, etc.)
  docs/
    GETTING_STARTED.md         # This guide
    TUTORIAL.md                # Detailed feature walkthrough
    LANGUAGE_REFERENCE.md      # Complete DSL reference
    EXAMPLE_CATALOG.md         # Annotated protocol catalog
    PARAMETERIZED_VERIFICATION.md  # When results generalize
    SEMANTICS.md               # Formal semantics
    TRUST_BOUNDARY.md          # Trust model and soundness
  editors/
    vscode/                    # VS Code extension with syntax highlighting and LSP
```

## VS Code Extension

Tarsier includes a VS Code extension for `.trs` files with syntax highlighting, bracket matching, and real-time diagnostics via LSP.

To set up:

1. Build the LSP server: `cargo build --release -p tarsier-lsp`
2. Open `editors/vscode/` in VS Code
3. Press `F5` to launch the Extension Development Host
4. Open any `.trs` file — you'll get syntax highlighting and error diagnostics as you type

## Next Steps

- **[Tutorial](TUTORIAL.md)** — Detailed walkthrough of all Tarsier features
- **[Example Catalog](EXAMPLE_CATALOG.md)** — What each example protocol models and why
- **[Language Reference](LANGUAGE_REFERENCE.md)** — Complete DSL syntax and semantics
- **[Parameterized Verification](PARAMETERIZED_VERIFICATION.md)** — When results generalize beyond fixed parameters
- **[Semantics](SEMANTICS.md)** — Formal semantics of threshold automata
- **[Trust Boundary](TRUST_BOUNDARY.md)** — What is trusted vs. independently verified
- Explore the protocol library in `examples/library/` for 40+ verified protocol models
- Use `tarsier assist` to scaffold new protocols from templates
- Try the web playground: `cargo run -p tarsier-playground` then open http://127.0.0.1:7878
