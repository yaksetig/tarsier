# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest release (v0.x.y) | Yes |
| older releases | Best-effort only |

Only the most recent tagged release receives security patches. Users on older versions should upgrade.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use one of these channels:

1. **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](../../security/advisories) of this repository. This creates a private advisory visible only to maintainers.

2. **Email:** Send a detailed report to the maintainers listed in the repository's `Cargo.toml` files.

### What to Include

- Description of the vulnerability and its impact.
- Steps to reproduce (minimal example preferred).
- Affected versions and components (e.g., `tarsier-engine`, `tarsier-cli`, `playground`).
- Any suggested fix or mitigation.

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Within 30 days for critical/high severity |
| Public disclosure | After fix is released, or 90 days from report (whichever comes first) |

We follow coordinated disclosure: reporters are credited (unless they prefer anonymity) and fixes are released before full details are published.

## Scope

The following components are in scope for security reports:

- **tarsier-cli** and **tarsier-certcheck** release binaries.
- **tarsier-playground** web server (all endpoints, middleware, and configuration).
- **tarsier-engine** verification pipeline (soundness-critical logic).
- **Build and release infrastructure** (CI workflows, signing, provenance).
- **Dependencies** pulled into release artifacts.

Out of scope:

- The formal verification claims themselves (these are mathematical, not software vulnerabilities). Report modeling errors as regular issues.
- Third-party solver binaries (Z3, cvc5). Report upstream.

## Supply-Chain Integrity

Release artifacts are protected by multiple layers:

- **Cosign signatures:** Every `.tar.gz` release artifact is signed with keyless Sigstore/Cosign (OIDC-based, tied to the GitHub Actions workflow identity).
- **SBOM:** An SPDX Software Bill of Materials is generated for each release artifact.
- **Build provenance:** GitHub Artifact Attestations provide SLSA provenance for each build.
- **Trust report signatures:** Release trust reports are signed with Cosign keyless (Sigstore OIDC), binding each report to the CI workflow that produced it.
- **Dependency scanning:** `cargo-deny` runs in CI to detect known vulnerabilities, license violations, and untrusted registries.
- **Reproducible environment:** Release certification runs on a pinned environment (OS, Rust, solver versions) with SHA256-verified solver downloads.

### Verifying Release Artifacts

See `docs/RELEASE_CHECKLIST.md` for the full verification procedure, or use the quick verification script:

```bash
./scripts/verify-release-artifacts.sh v0.1.0
```

This verifies cosign signatures and downloads attestations for all release artifacts.
