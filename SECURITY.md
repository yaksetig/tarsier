# Security Policy

Tarsier is a verification framework for threshold automata protocols. Correctness
and soundness of the verification engine are essential to its purpose.

## Supported Versions

Only the latest release is supported with security updates.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Older releases | No        |

## Reporting a Vulnerability

If you discover a security issue, please report it through one of the following
channels:

- **Email:** security@tarsier-project.org
- **GitHub Security Advisories:** use the "Report a vulnerability" button on the
  repository's Security tab.

Please do **not** open a public GitHub issue for security vulnerabilities.

## Scope

**Critical** -- the verification engine, proof kernel, and certificate chain.
A bug in any of these components could cause Tarsier to produce incorrect
verification results.

**Lower priority** -- the LSP server (`tarsier-lsp`) and CLI (`tarsier-cli`).
Issues here are still welcome but are not treated as security-critical.

### Soundness Bugs

Soundness bugs -- where the tool reports a protocol as safe when it is not -- are
treated as **critical security issues** regardless of which component is affected.

## Response Timeline

- **Acknowledgement:** within 48 hours of the report.
- **Critical fixes:** within 30 days of acknowledgement.
- **Non-critical fixes:** addressed in the next regular release cycle.

## Disclosure

We follow coordinated disclosure. We ask reporters to allow us a reasonable window
to prepare a fix before publishing details.
