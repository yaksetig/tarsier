//! Governance trust-report synthesis from verification artifacts.
//
// Trust report generation.

use tarsier_proof_kernel::CERTIFICATE_SCHEMA_VERSION;

use super::{
    TrustReport, TrustReportBoundary, TrustReportClaimLayer, TrustReportResidualAssumption,
    TrustReportThreatEntry, TrustReportVerificationScope, TRUST_REPORT_SCHEMA_VERSION,
};

use super::chrono_utc_now;

pub(crate) fn generate_trust_report(
    governance_profile: &str,
    protocol_file: Option<&str>,
    solvers: &[&str],
    proof_engine: &str,
    soundness: &str,
) -> TrustReport {
    let multi_solver = solvers.len() >= 2;
    let is_high_assurance = governance_profile == "high-assurance";

    TrustReport {
        schema_version: TRUST_REPORT_SCHEMA_VERSION,
        generated_at: chrono_utc_now(),
        generator: format!("tarsier-cli v{}", env!("CARGO_PKG_VERSION")),
        governance_profile: governance_profile.to_string(),
        trust_boundary: TrustReportBoundary {
            claim_layers: vec![
                TrustReportClaimLayer {
                    name: "certificate_integrity".into(),
                    what_is_verified: "certificate.json schema/profile checks, safe paths, per-obligation SHA256, bundle hash, SMT script sanity checks".into(),
                    what_is_trusted: "The producer of the bundle selected the right obligations for the intended theorem".into(),
                    status: "enforced".into(),
                },
                TrustReportClaimLayer {
                    name: "smt_replay".into(),
                    what_is_verified: "Each obligation result matches expected outcome under external solver replay".into(),
                    what_is_trusted: "Solver correctness (sat/unsat/unknown)".into(),
                    status: "enforced".into(),
                },
                TrustReportClaimLayer {
                    name: "multi_solver_replay".into(),
                    what_is_verified: "At least two distinct solvers replay the same obligations".into(),
                    what_is_trusted: "Common-mode solver bugs, environment integrity".into(),
                    status: if multi_solver { "enforced" } else { "not_applicable" }.into(),
                },
                TrustReportClaimLayer {
                    name: "proof_object_path".into(),
                    what_is_verified: "Proof objects emitted, structurally checked, replay-validated".into(),
                    what_is_trusted: "Completeness/soundness of solver/proof-checker implementations".into(),
                    status: if is_high_assurance { "enforced" } else { "optional" }.into(),
                },
                TrustReportClaimLayer {
                    name: "source_obligation_consistency".into(),
                    what_is_verified: "Bundle obligations match freshly regenerated obligations from source".into(),
                    what_is_trusted: "Parser/lowering/encoding implementation correctness (same Tarsier stack)".into(),
                    status: "optional".into(),
                },
            ],
            threat_model: vec![
                TrustReportThreatEntry {
                    category: "tampering".into(),
                    vector: "Modify obligation .smt2 files after generation".into(),
                    countermeasure: "Per-obligation SHA256 hashes".into(),
                    status: "enforced".into(),
                },
                TrustReportThreatEntry {
                    category: "tampering".into(),
                    vector: "Modify certificate.json metadata fields".into(),
                    countermeasure: "Deterministic bundle_sha256 covering all metadata + obligation hashes".into(),
                    status: "enforced".into(),
                },
                TrustReportThreatEntry {
                    category: "tampering".into(),
                    vector: "Inject unknown fields into metadata".into(),
                    countermeasure: "deny_unknown_fields in serde deserialization".into(),
                    status: "enforced".into(),
                },
                TrustReportThreatEntry {
                    category: "soundness".into(),
                    vector: "Single solver returns incorrect result".into(),
                    countermeasure: "Multi-solver replay (--require-two-solvers)".into(),
                    status: if multi_solver { "enforced" } else { "available" }.into(),
                },
                TrustReportThreatEntry {
                    category: "soundness".into(),
                    vector: "Solver produces trivial/empty proof object".into(),
                    countermeasure: "Proof object structural validation (--require-proofs), external checker".into(),
                    status: if is_high_assurance { "enforced" } else { "available" }.into(),
                },
                TrustReportThreatEntry {
                    category: "modeling".into(),
                    vector: "Source model does not match real protocol".into(),
                    countermeasure: "Manual audit, docs/SEMANTICS.md".into(),
                    status: "not_applicable".into(),
                },
                TrustReportThreatEntry {
                    category: "supply_chain".into(),
                    vector: "Compromised solver binary".into(),
                    countermeasure: "Pinned solver versions in CI, solver version recording in reports".into(),
                    status: "enforced".into(),
                },
                TrustReportThreatEntry {
                    category: "supply_chain".into(),
                    vector: "Checker binary depends on untrusted code".into(),
                    countermeasure: "Minimal dependency boundary (tarsier-certcheck depends only on tarsier-proof-kernel)".into(),
                    status: "enforced".into(),
                },
                TrustReportThreatEntry {
                    category: "replay_evasion".into(),
                    vector: "Skipping certificate checks in CI".into(),
                    countermeasure: "CI gates, governance profiles as named enforcement levels".into(),
                    status: "enforced".into(),
                },
            ],
        },
        verification_scope: TrustReportVerificationScope {
            protocol_file: protocol_file.map(String::from),
            solvers: solvers.iter().map(|s| s.to_string()).collect(),
            proof_engine: proof_engine.to_string(),
            soundness: soundness.to_string(),
            certificate_schema_version: CERTIFICATE_SCHEMA_VERSION,
        },
        residual_assumptions: vec![
            TrustReportResidualAssumption {
                name: "solver_correctness".into(),
                description: "Each solver's sat/unsat/unknown result is assumed correct".into(),
                mitigation: Some("Multi-solver replay (reinforced/high-assurance profiles)".into()),
            },
            TrustReportResidualAssumption {
                name: "proof_checker_soundness".into(),
                description: "The external proof checker (when used) is assumed sound and not itself formally verified".into(),
                mitigation: None,
            },
            TrustReportResidualAssumption {
                name: "modeling_fidelity".into(),
                description: "The .trs source file is assumed to faithfully represent the real protocol, network, and cryptographic environment".into(),
                mitigation: Some("Manual audit concern".into()),
            },
            TrustReportResidualAssumption {
                name: "toolchain_correctness".into(),
                description: "The Rust compiler, serde serialization, and SHA-256 implementation are assumed correct".into(),
                mitigation: None,
            },
            TrustReportResidualAssumption {
                name: "environment_integrity".into(),
                description: "The operating system, filesystem, and CPU are assumed to execute as specified".into(),
                mitigation: None,
            },
            TrustReportResidualAssumption {
                name: "domain_tag_uniqueness".into(),
                description: "The tarsier-certificate-v2 prefix used in bundle hash computation is assumed unique across all hashing contexts".into(),
                mitigation: None,
            },
            TrustReportResidualAssumption {
                name: "obligation_theorem_correspondence".into(),
                description: "Structural obligation profiles are assumed to correspond to valid proof decompositions".into(),
                mitigation: None,
            },
        ],
    }
}
