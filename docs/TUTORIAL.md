# Tarsier Tutorial: Getting Started

A step-by-step guide to writing, verifying, and debugging consensus protocol models with Tarsier.

## Prerequisites

- **Rust toolchain** (1.75+): install via [rustup](https://rustup.rs/)
- **cmake**: required by the Z3 solver backend (`brew install cmake` / `apt install cmake`)

## 1. Install Tarsier

```bash
git clone https://github.com/tarsier-verify/tarsier.git
cd tarsier
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release
```

The binary is at `target/release/tarsier`.

### Command paths by audience

**Beginner (canonical path):**

```bash
tarsier assist --kind pbft --out my_protocol.trs
tarsier analyze my_protocol.trs --goal safety
tarsier visualize my_protocol.trs --check verify
```

**Pro (advanced controls):**

```bash
tarsier analyze my_protocol.trs --profile pro --goal safety+liveness --depth 16 --k 20 --timeout 600
```

**Governance (feature build only):**

```bash
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release --features governance
tarsier analyze my_protocol.trs --profile governance --goal release --format json
tarsier certify-safety my_protocol.trs --out certs/my_protocol
```

## 2. Write Your First Protocol

Tarsier uses `.trs` files to describe consensus protocols as threshold automata. Start with the included example:

```bash
cat examples/reliable_broadcast.trs
```

A minimal protocol has:
- **params**: symbolic parameters like `n` (total nodes) and `f` (fault bound)
- **resilience**: the relationship between `n` and `f`
- **adversary**: the fault model and communication assumptions
- **messages**: typed message declarations
- **roles**: process roles with local variables, phases, and transitions
- **properties**: safety or liveness claims to verify

Here is a skeleton:

```
protocol MyProtocol {
    params n, f;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        timing: partial_synchrony;
        gst: f;
    }

    message Vote(value: bool);

    role Replica {
        var decided: bool = false;
        init idle;

        phase idle {
            on Vote(v) from >= 2*f+1 {
                decided := true;
                goto done;
            }
        }
        phase done {}
    }

    property agreement: safety {
        forall p, q: Replica.
            (p.decided == true && q.decided == true) ==> true
    }
}
```

## 3. Verify Safety

Use the unified beginner flow:

```bash
tarsier analyze examples/reliable_broadcast.trs --goal safety
```

This runs bounded checks plus unbounded safety proof layers with strict defaults (no solver/engine knobs required).

You can still run bounded model checking directly to search for safety violations:

```bash
tarsier verify examples/reliable_broadcast.trs
```

Expected output: `Safe` (no counterexample found up to the default depth).

To check a protocol with a known bug:

```bash
tarsier verify examples/reliable_broadcast_buggy.trs
```

Expected output: `Unsafe` with a counterexample trace.

## 4. Lint Your Model

The linter checks for common modeling mistakes before you run expensive verification:

```bash
tarsier lint examples/pbft_simple.trs
```

This reports missing parameters, unbounded variables, missing adversary bounds, and other issues. Each issue includes a suggestion for how to fix it.
Warn/error issues also include explicit source spans and a `soundness impact` note so you can prioritize fixes that directly affect proof trust.

Use `--format json` for machine-readable output:

```bash
tarsier lint examples/pbft_simple.trs --format json
```

## 5. Visualize Counterexamples

When verification finds a bug, visualize the counterexample trace:

```bash
tarsier visualize examples/reliable_broadcast_buggy.trs --format timeline
```

Available formats:
- `timeline` — human-readable step-by-step trace
- `mermaid` — Mermaid sequence diagram
- `markdown` — full report with all details
- `json` — structured trace data

Export all formats at once with `--bundle`:

```bash
tarsier visualize examples/reliable_broadcast_buggy.trs --bundle /tmp/tarsier-bundle
```

This creates `timeline.txt`, `msc.mermaid`, `report.md`, `trace.json`, and `metadata.json` in the specified directory.

## 6. Debug Counterexamples Interactively

The interactive debugger lets you step through counterexample traces:

```bash
tarsier debug-cex examples/reliable_broadcast_buggy.trs
```

Debugger commands:
- `n` / `next` — advance to next step
- `p` / `prev` — go back one step
- `j <k>` — jump to step k
- `fs <role>` — filter deliveries by sender role
- `fr <role>` — filter deliveries by recipient role
- `fm <family>` — filter deliveries by message family
- `fk <kind>` — filter by delivery kind (`send`/`deliver`/`drop`/`forge`/`equivocate`)
- `fv <text>` — filter by payload variant substring
- `ff <field=value>` — filter by payload field equality
- `fa <auth>` — filter by auth metadata (`authenticated`, `unauthenticated`, `compromised`, `uncompromised`, or provenance like `OwnedKey`)
- `fc` — clear all filters
- `fl` — list active filters
- `h` — show help
- `q` — quit

The debugger shows named locations (e.g., `Replica.idle: 4`) instead of raw array indices.

## 7. Check Liveness

Verify that your protocol eventually terminates:

```bash
tarsier liveness examples/trivial_live.trs
```

For fair-liveness (under fairness assumptions):

```bash
tarsier fair-liveness examples/pbft_faithful_liveness.trs --fairness weak
```

Or use the beginner unified proof path:

```bash
tarsier analyze examples/trivial_live.trs --goal safety+liveness
```

## 8. Generate Scaffolds

Quickly bootstrap a new protocol model from a template:

```bash
tarsier assist --kind pbft --out my_pbft.trs
```

Available scaffolds: `pbft`, `hotstuff`, `raft`, `tendermint`, `streamlet`, `casper`.

## 9. Use the Playground

The web-based playground provides an interactive environment for writing and verifying protocols:

```bash
cargo run -p tarsier-playground
```

Then open `http://127.0.0.1:7878` in your browser. The playground supports:
- Loading built-in examples
- Inserting scaffold templates
- Running verification, liveness, and proof checks
- Viewing lint results with suggestions, source spans, and structured fix snippets
- Exploring counterexample traces with interactive sliders and sender/recipient/message/kind/variant/field filters
- Mermaid sequence chart rendering for traces

## 10. Export Automaton Graphs

Visualize your protocol's threshold automaton structure as a Graphviz DOT graph:

```bash
tarsier export-dot examples/reliable_broadcast.trs --out automaton.dot
```

The output is a DOT file where nodes represent locations (phase + variable combinations) and edges represent transitions labeled with their guards. Locations are grouped by phase into subgraph clusters by default.

If you have Graphviz installed (`brew install graphviz` / `apt install graphviz`), render directly to SVG:

```bash
tarsier export-dot examples/reliable_broadcast.trs --svg --out automaton.svg
```

Options:
- `--cluster` / `--no-cluster` — group locations by phase (default: clustered)
- `--svg` — pipe output through `dot -Tsvg`
- `--out <path>` — write to file instead of stdout

## 11. Interactive Trace Explorer

The TUI (Terminal User Interface) explorer provides a rich interactive view of counterexample traces:

```bash
tarsier explore examples/reliable_broadcast_buggy.trs
```

The explorer shows three panels:
- **Left**: Location occupancy — how many processes are in each phase (kappa values)
- **Center**: Shared variables — message counters and global state (gamma values)
- **Right**: Message deliveries at the current step

Key bindings:
| Key | Action |
|-----|--------|
| `n` / Right arrow | Next step |
| `p` / Left arrow | Previous step |
| `j` / `k` | Scroll within panels |
| `d` | Toggle diff highlighting (yellow = changed since last step) |
| Tab | Cycle panel focus |
| `q` / Esc | Quit |

You can also load a previously saved trace from JSON:

```bash
tarsier explore examples/reliable_broadcast_buggy.trs --trace-json saved_trace.json
```

## 12. Compositional Verification

For large protocols, you can decompose verification into modules with assume-guarantee contracts:

```
protocol MyProtocol {
    params n, t, f;
    resilience: n > 3*t;

    module Broadcast {
        interface {
            guarantees: safety;
        }
        // ... protocol items for this module ...
    }

    module Finality {
        interface {
            assumes: received_count >= 2*t+1;
            guarantees: safety;
        }
        // ... protocol items for this module ...
    }
}
```

Check that module contracts are consistent:

```bash
tarsier compose-check my_protocol.trs
```

This verifies that:
1. Every module assumption is covered by some other module's guarantee
2. No circular dependencies exist between modules

## 13. VS Code Extension

Tarsier includes a VS Code extension that provides syntax highlighting, bracket matching, code snippets, and real-time diagnostics for `.trs` files.

### Setup

1. Build the LSP server:

```bash
cargo build --release -p tarsier-lsp
```

2. Open the extension directory in VS Code:

```bash
code editors/vscode/
```

3. Press `F5` to launch the Extension Development Host

4. Open any `.trs` file — you get:
   - **Syntax highlighting** for keywords, operators, numbers, comments
   - **Real-time diagnostics** — parse errors and lowering errors appear as you type
   - **Bracket matching** and auto-close for `{}`, `()`, `[]`
   - **Code snippets** — type `protocol`, `phase`, `transition`, `safety`, or `liveness` and press Tab

### Snippets

| Prefix | Description |
|--------|-------------|
| `protocol` | Full protocol skeleton with params, resilience, adversary, role, and property |
| `phase` | Phase block with a transition |
| `transition` | `when ... => { ... }` block |
| `safety` | Safety property declaration |
| `liveness` | Liveness property declaration |

## 14. Liveness Verification

Safety tells you "nothing bad happens." Liveness tells you "something good
eventually happens" — for example, all correct processes eventually decide.

### Adding a Liveness Property

Add a liveness property to your protocol:

```
property termination: liveness {
    forall p: Process. p.decided == true
}
```

See `examples/library/reliable_broadcast_safe_live.trs` for a complete example.

### Checking Liveness

```bash
# Bounded liveness check (depth 10)
tarsier liveness examples/library/reliable_broadcast_safe_live.trs --depth 10

# Bounded fair-liveness check (no fair non-terminating cycles)
tarsier fair-liveness examples/library/reliable_broadcast_safe_live.trs --depth 10

# Unbounded liveness proof attempt
tarsier prove-fair examples/library/reliable_broadcast_safe_live.trs

# With strong fairness
tarsier prove-fair examples/library/reliable_broadcast_safe_live.trs --fairness strong

# Stable nontrivial CI-grade unbounded fair-liveness targets
tarsier prove-fair examples/library/pbft_liveness_safe_ci.trs --fairness weak
tarsier prove-fair examples/library/pbft_liveness_buggy_ci.trs --fairness weak
```

### Understanding Fairness

- **Weak fairness (justice):** If a rule is continuously enabled, it eventually
  fires. This is the default.
- **Strong fairness (compassion):** If a rule is infinitely often enabled, it
  eventually fires. This is more permissive and may eliminate spurious cycles.

Under partial synchrony (`timing: partial_synchrony; gst: ...`), fair-liveness
obligations are interpreted post-GST: pre-GST-only cycles are excluded from the
steady-state liveness proof target.

### Liveness Bugs

Compare `reliable_broadcast_safe_live.trs` (correct) with
`reliable_broadcast_live_buggy.trs` (buggy). The buggy version has a self-loop
in the echoed phase that allows non-termination under weak fairness.

### Counter Abstraction Limitations

Counter abstraction over-approximates message delivery, which can produce
spurious liveness counterexamples. If bounded fair-liveness finds a cycle for a
protocol you believe is live, try:
1. Increasing the depth bound
2. Using strong fairness (`--fairness strong`)
3. Using the unbounded proof engine (`tarsier prove-fair`)

For machine-readable outputs (`analyze --goal safety+liveness --format json`),
inconclusive unbounded fair-liveness results include:
- `reason_code`: stable unknown category (for example `timeout`)
- `convergence`: frontier frame and convergence status diagnostics

## 15. Next Steps

- Read `docs/GETTING_STARTED.md` for a complete end-to-end walkthrough
- Read `docs/EXAMPLE_CATALOG.md` for descriptions of all 48 example protocols
- Read `docs/SEMANTICS.md` for the formal semantics of threshold automata
- Read `docs/PARAMETERIZED_VERIFICATION.md` to understand when verification results generalize and how to increase confidence
- Read `docs/LANGUAGE_REFERENCE.md` for the complete DSL syntax reference
- Read `docs/CODEGEN.md` for code generation from `.trs` models to Rust/Go skeletons
- Explore `examples/` for more protocol models (PBFT, Algorand committees, crypto objects)
- Use `tarsier prove` for unbounded safety proofs via k-induction or PDR
- Use `tarsier cert-suite` for governance-grade certification bundles
- Check `docs/TRUST_BOUNDARY.md` for the trust model and soundness guarantees
