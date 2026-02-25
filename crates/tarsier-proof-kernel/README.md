# tarsier-proof-kernel

Minimal proof certificate validator with four dependencies.

## Overview

`tarsier-proof-kernel` is an intentionally small crate that validates proof
certificate bundles produced by the Tarsier verification engine. Its minimal
dependency footprint (serde, serde_json, sha2, thiserror) makes it feasible
to audit independently from the rest of the verification stack. The kernel
checks structural integrity, schema version compatibility, obligation
completeness, SHA-256 hash consistency, and SMT script well-formedness
without depending on any solver or engine internals.

## Key Types / API

- `CertificateMetadata` -- Parsed metadata from `certificate.json`: proof kind,
  engine, solver, obligation list, and integrity hashes.
- `CertificateObligationMeta` -- Metadata for one SMT obligation: name, expected
  solver result, file path, SHA-256 hash, and optional proof object binding.
- `BundleIntegrityReport` -- Full integrity-check report with a list of
  `BundleCheckIssue` instances. Call `.is_ok()` to check for clean results.
- `check_bundle_integrity(bundle_dir)` -- Validate structural and cryptographic
  integrity of a certificate bundle directory.
- `load_metadata(bundle_dir)` -- Load and deserialize `certificate.json`.
- `compute_bundle_sha256(metadata)` -- Compute the canonical tamper-detection
  hash over normalized metadata fields.
- `sha256_hex_file(path)` -- Compute a SHA-256 digest for a file on disk.
- `GovernanceProfile` -- Named assurance profiles (`Standard`, `Reinforced`,
  `HighAssurance`) with escalating replay requirements.
- `CERTIFICATE_SCHEMA_VERSION` -- Current schema version constant (v2).

## Usage

```rust,no_run
use std::path::Path;
use tarsier_proof_kernel::{check_bundle_integrity, load_metadata};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let bundle = Path::new("certs/my_protocol");
let report = check_bundle_integrity(bundle)?;

if report.is_ok() {
    println!("Certificate integrity: PASS");
} else {
    for issue in &report.issues {
        println!("[{}] {}", issue.code, issue.message);
    }
}
# Ok(())
# }
```

## Architecture

The kernel deliberately avoids importing any solver, SMT encoder, or engine
crate. It validates certificates purely through metadata parsing, file existence
checks, SHA-256 hash verification, and SMT-LIB command structure analysis. This
separation means the kernel can be used by `tarsier-certcheck` (the standalone
replay checker) without pulling in Z3 or any other heavyweight dependency.

## Links

- [Workspace overview](../../README.md)
- [Certificate schema](../../docs/CERTIFICATE_SCHEMA.md)
- [Kernel spec](../../docs/KERNEL_SPEC.md)
- [Trust boundary](../../docs/TRUST_BOUNDARY.md)
