# Formal Verification Prototypes

This directory contains Lean 4 and Coq formalization prototypes for the
Tarsier proof kernel checker soundness theorem (KERN-03 / KERN-04).

## Theorem Statement

Both prototypes prove the same minimal soundness theorem:

> **If the kernel checker accepts a bundle (returns `is_ok`), then all
> integrity predicates hold for that bundle.**

The integrity predicates cover:
- Schema version validity
- Profile admissibility (kind × engine × fairness)
- Obligation completeness (all required obligations present)
- No unexpected obligation names
- Path safety (no traversal/absolute paths)
- All obligations expect `unsat`
- Hash consistency (obligation file hashes match)
- Bundle hash validity
- Induction parameter presence
- Non-empty obligations
- No duplicate obligation names

## Structure

```
formal/
├── lean/
│   ├── lakefile.lean           # Lake project definition
│   ├── lean-toolchain          # Pinned Lean version
│   └── TarsierKernel/
│       └── Basic.lean          # Semantics + soundness theorem
├── coq/
│   ├── _CoqProject             # Coq project file
│   ├── Makefile                 # Build via coq_makefile
│   └── KernelSemantics.v       # Semantics + soundness theorem
├── scripts/
│   └── check-proofs.sh         # CI proof-check script
└── README.md
```

## Building

### Lean 4

```bash
cd formal/lean
lake build
```

### Coq

```bash
cd formal/coq
make
```

### Both (CI script)

```bash
./formal/scripts/check-proofs.sh
```

## Design Decisions

1. **Axiomatized checker**: The checker function is axiomatized rather than
   re-implemented in Lean/Coq. The checker contract axiom states the
   correspondence between `is_ok` and integrity predicates. Future work
   can replace this axiom with a verified implementation proof.

2. **Abstract hash/filesystem**: Hash functions and filesystem operations
   are abstract axioms. We do not prove SHA-256 correctness or filesystem
   behavior — these are explicit trust assumptions per `docs/TRUST_BOUNDARY.md`.

3. **Shared semantics**: Both Lean and Coq encode the same domain types,
   predicates, and theorem statement from `kernel_semantics_v1.json`,
   ensuring parity between the two formalizations.

## Relationship to Kernel Source

The formal types and obligation profiles are derived from:
- `artifacts/kernel-semantics/kernel_semantics_v1.json` (KERN-02 export)
- `crates/tarsier-proof-kernel/src/lib.rs` (implementation)
- `docs/KERNEL_FORMALIZATION_RFC.md` (design document)
