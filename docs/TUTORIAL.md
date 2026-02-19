# Tarsier Tutorial: Getting Started

A step-by-step guide to writing, verifying, and debugging consensus protocol models with Tarsier.

## Prerequisites

- **Rust toolchain** (1.75+): install via [rustup](https://rustup.rs/)
- **cmake**: required by the Z3 solver backend (`brew install cmake` / `apt install cmake`)

## 1. Install Tarsier

```bash
git clone https://github.com/your-org/tarsier.git
cd tarsier
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release
```

The binary is at `target/release/tarsier`.

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

Run bounded model checking to search for safety violations:

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
- `fk <kind>` — filter by delivery kind (send/deliver/inject)
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
- Viewing lint results with suggestions
- Exploring counterexample traces with interactive sliders
- Mermaid sequence chart rendering for traces

## 10. Next Steps

- Read `docs/SEMANTICS.md` for the formal semantics of threshold automata
- Explore `examples/` for more protocol models (PBFT, Algorand committees, crypto objects)
- Use `tarsier prove` for unbounded safety proofs via k-induction or PDR
- Use `tarsier cert-suite` for governance-grade certification bundles
- Check `docs/TRUST_BOUNDARY.md` for the trust model and soundness guarantees
