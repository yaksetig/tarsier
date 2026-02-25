// Command handlers for: CertSuite, CertifySafety, CertifyFairLiveness, CheckCertificate,
//                        GenerateTrustReport, GovernancePipeline, VerifyGovernanceBundle
//
// These commands handle governance workflows including certification, trust reports, and pipelines.
// The entire module is gated behind #[cfg(feature = "governance")] in mod.rs.

use miette::IntoDiagnostic;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use tarsier_engine::pipeline::{
    FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_proof_kernel::{
    check_bundle_integrity, sha256_hex_bytes, sha256_hex_file, CertificateMetadata,
    GovernanceProfile, CERTIFICATE_SCHEMA_VERSION,
};

use super::helpers::*;
use crate::{
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety, parse_output_format,
    run_analysis, run_conformance_suite, run_external_solver_with_proof,
    validate_cli_network_semantics_mode, write_certificate_bundle, write_json_artifact,
    AnalysisMode, AnalysisReport, CertificateBundleInput, CertificateKind, CliNetworkSemanticsMode,
    LayerRunCfg, OutputFormat,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const CERT_SUITE_SCHEMA_VERSION: u32 = 2;
pub(crate) const CERT_SUITE_SCHEMA_DOC_PATH: &str = "docs/CERT_SUITE_SCHEMA.md";
pub(crate) const CERT_SUITE_CANONICAL_MIN_FAMILIES: usize = 12;
pub(crate) const TRIAGE_MODEL_CHANGE: &str = "model_change";
pub(crate) const TRIAGE_ENGINE_REGRESSION: &str = "engine_regression";
pub(crate) const TRIAGE_EXPECTED_UPDATE: &str = "expected_update";
pub(crate) const CERT_SUITE_TRIAGE_CATEGORIES: [&str; 3] = [
    TRIAGE_MODEL_CHANGE,
    TRIAGE_ENGINE_REGRESSION,
    TRIAGE_EXPECTED_UPDATE,
];

pub(crate) const TRUST_REPORT_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Governance Bundle Types
// ---------------------------------------------------------------------------

/// V2-08: Governance artifact bundle for release/audit workflows.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GovernanceBundle {
    pub(crate) schema_version: String,
    pub(crate) tarsier_version: String,
    pub(crate) environment: EnvironmentInfo,
    pub(crate) model_source_sha256: String,
    pub(crate) analysis_report: Value,
    pub(crate) certificates: Vec<CertificateReference>,
    pub(crate) artifacts: Vec<GovernanceArtifactReference>,
    pub(crate) signature: GovernanceBundleSignature,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct EnvironmentInfo {
    pub(crate) os: String,
    pub(crate) arch: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CertificateReference {
    pub(crate) kind: String,
    pub(crate) bundle_dir: String,
    pub(crate) bundle_sha256: Option<String>,
    pub(crate) integrity_ok: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GovernanceArtifactReference {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GovernanceBundleSignature {
    pub(crate) algorithm: String,
    pub(crate) public_key_hex: String,
    pub(crate) signature_hex: String,
    pub(crate) signed_payload_sha256: String,
}

#[derive(Serialize)]
pub(crate) struct GovernanceBundleVerificationCheck {
    pub(crate) check: String,
    pub(crate) status: String,
    pub(crate) details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct GovernanceBundleVerificationReport {
    pub(crate) schema_version: String,
    pub(crate) bundle: String,
    pub(crate) overall: String,
    pub(crate) checks: Vec<GovernanceBundleVerificationCheck>,
}

/// P2-09: Governance pipeline report -- gate-by-gate results.
#[derive(Serialize)]
pub(crate) struct GovernancePipelineReport {
    pub(crate) schema_version: String,
    pub(crate) tarsier_version: String,
    pub(crate) gates: Vec<GovernanceGateResult>,
    pub(crate) overall: String,
    pub(crate) elapsed_ms: u64,
}

#[derive(Serialize, Clone)]
pub(crate) struct GovernanceGateResult {
    pub(crate) gate: String,
    pub(crate) status: String,
    pub(crate) elapsed_ms: u64,
    pub(crate) details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

// ---------------------------------------------------------------------------
// Cert Suite Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertSuiteManifest {
    pub(crate) schema_version: u32,
    #[serde(default)]
    pub(crate) enforce_library_coverage: bool,
    #[serde(default)]
    pub(crate) enforce_corpus_breadth: bool,
    #[serde(default)]
    pub(crate) enforce_model_hash_consistency: bool,
    #[serde(default)]
    pub(crate) enforce_known_bug_sentinels: bool,
    #[serde(default)]
    pub(crate) required_known_bug_families: Vec<String>,
    #[serde(default)]
    pub(crate) required_variant_groups: Vec<String>,
    #[serde(default)]
    pub(crate) library_dir: Option<String>,
    pub(crate) entries: Vec<CertSuiteEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertSuiteEntry {
    pub(crate) file: String,
    #[serde(default)]
    pub(crate) verify: Option<String>,
    #[serde(default)]
    pub(crate) liveness: Option<String>,
    #[serde(default)]
    pub(crate) fair_liveness: Option<String>,
    #[serde(default)]
    pub(crate) prove: Option<String>,
    #[serde(default)]
    pub(crate) prove_fair: Option<String>,
    #[serde(default)]
    pub(crate) proof_engine: Option<String>,
    #[serde(default)]
    pub(crate) fairness: Option<String>,
    #[serde(default)]
    pub(crate) cegar_iters: Option<usize>,
    #[serde(default)]
    pub(crate) depth: Option<usize>,
    #[serde(default)]
    pub(crate) k: Option<usize>,
    #[serde(default)]
    pub(crate) timeout: Option<u64>,
    #[serde(default)]
    pub(crate) family: Option<String>,
    #[serde(default)]
    pub(crate) class: Option<String>,
    #[serde(default)]
    pub(crate) variant: Option<String>,
    #[serde(default)]
    pub(crate) variant_group: Option<String>,
    #[serde(default)]
    pub(crate) notes: Option<String>,
    #[serde(default)]
    pub(crate) model_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertSuiteCheckReport {
    pub(crate) check: String,
    pub(crate) expected: String,
    pub(crate) actual: String,
    pub(crate) status: String,
    pub(crate) duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) triage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_link: Option<String>,
    pub(crate) output: String,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct CertSuiteAssumptions {
    pub(crate) solver: String,
    pub(crate) proof_engine: String,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) network_semantics: String,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout_secs: u64,
    pub(crate) cegar_iters: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertSuiteEntryReport {
    pub(crate) file: String,
    pub(crate) family: Option<String>,
    pub(crate) class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) variant_group: Option<String>,
    pub(crate) verdict: String,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) triage: Option<String>,
    pub(crate) duration_ms: u64,
    pub(crate) assumptions: CertSuiteAssumptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model_sha256_expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model_sha256_actual: Option<String>,
    pub(crate) model_changed: bool,
    pub(crate) notes: Option<String>,
    pub(crate) artifact_links: Vec<String>,
    pub(crate) checks: Vec<CertSuiteCheckReport>,
    pub(crate) errors: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub(crate) struct CertSuiteBucketSummary {
    pub(crate) total: usize,
    pub(crate) passed: usize,
    pub(crate) failed: usize,
    pub(crate) errors: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertSuiteReport {
    pub(crate) schema_version: u32,
    pub(crate) manifest: String,
    pub(crate) solver: String,
    pub(crate) proof_engine: String,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) entries: Vec<CertSuiteEntryReport>,
    pub(crate) passed: usize,
    pub(crate) failed: usize,
    pub(crate) errors: usize,
    pub(crate) triage: BTreeMap<String, usize>,
    pub(crate) by_family: BTreeMap<String, CertSuiteBucketSummary>,
    pub(crate) by_class: BTreeMap<String, CertSuiteBucketSummary>,
    pub(crate) overall: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CertSuiteDefaults {
    pub(crate) solver: SolverChoice,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout_secs: u64,
    pub(crate) soundness: SoundnessMode,
    pub(crate) fairness: FairnessMode,
    pub(crate) proof_engine: ProofEngine,
}

// ---------------------------------------------------------------------------
// Trust Report Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReportClaimLayer {
    pub(crate) name: String,
    pub(crate) what_is_verified: String,
    pub(crate) what_is_trusted: String,
    pub(crate) status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReportThreatEntry {
    pub(crate) category: String,
    pub(crate) vector: String,
    pub(crate) countermeasure: String,
    pub(crate) status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReportBoundary {
    pub(crate) claim_layers: Vec<TrustReportClaimLayer>,
    pub(crate) threat_model: Vec<TrustReportThreatEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReportVerificationScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) protocol_file: Option<String>,
    pub(crate) solvers: Vec<String>,
    pub(crate) proof_engine: String,
    pub(crate) soundness: String,
    pub(crate) certificate_schema_version: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReportResidualAssumption {
    pub(crate) name: String,
    pub(crate) description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mitigation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustReport {
    pub(crate) schema_version: u32,
    pub(crate) generated_at: String,
    pub(crate) generator: String,
    pub(crate) governance_profile: String,
    pub(crate) trust_boundary: TrustReportBoundary,
    pub(crate) verification_scope: TrustReportVerificationScope,
    pub(crate) residual_assumptions: Vec<TrustReportResidualAssumption>,
}

// ---------------------------------------------------------------------------
// Function implementations
// ---------------------------------------------------------------------------

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

pub(crate) fn chrono_utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Simple ISO 8601 UTC without external dependency
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    // Approximate date from epoch days (good enough for reporting)
    let mut y = 1970i64;
    let mut remaining = days_since_epoch as i64;
    loop {
        let days_in_year = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for md in &mdays {
        if remaining < *md {
            break;
        }
        remaining -= *md;
        m += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

pub(crate) fn parse_solver_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn is_truthy_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(crate) fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => is_truthy_flag(&value),
        Err(_) => false,
    }
}

pub(crate) fn validate_foundational_profile_requirements(
    solver_cmds: &[String],
    require_carcara_env: bool,
) -> miette::Result<()> {
    if !solver_cmds.iter().any(|solver| solver == "cvc5") {
        miette::bail!(
            "--profile high-assurance requires cvc5 in --solvers so external Alethe proof-object validation can run."
        );
    }
    if require_carcara_env && !env_truthy("TARSIER_REQUIRE_CARCARA") {
        miette::bail!(
            "--profile high-assurance requires TARSIER_REQUIRE_CARCARA=1 to enforce external cvc5 proof-object validation."
        );
    }
    Ok(())
}

pub(crate) fn has_independent_solver(solvers: &[String], certificate_solver: &str) -> bool {
    solvers.iter().any(|solver| solver != certificate_solver)
}

pub(crate) fn validate_trusted_check_requirements(
    trusted_check: bool,
    min_solvers: usize,
    solver_cmds: &[String],
    metadata: &CertificateMetadata,
    rederive: bool,
    proof_checker: Option<&PathBuf>,
    allow_unchecked_proofs: bool,
) -> miette::Result<()> {
    if !trusted_check {
        return Ok(());
    }
    if min_solvers < 2 {
        miette::bail!("--trusted-check requires --min-solvers >= 2.");
    }
    if solver_cmds.len() < min_solvers {
        miette::bail!(
            "--trusted-check requires at least {} distinct solvers; got {}.",
            min_solvers,
            solver_cmds.len()
        );
    }
    if metadata.soundness != "strict" {
        miette::bail!(
            "--trusted-check requires certificate soundness=strict, got '{}'.",
            metadata.soundness
        );
    }
    if !rederive {
        miette::bail!(
            "--trusted-check requires --rederive to validate freshly regenerated obligations."
        );
    }
    if !crate::obligations_all_unsat(metadata) {
        miette::bail!(
            "--trusted-check currently supports UNSAT-only obligations; found non-UNSAT expected outcomes."
        );
    }
    if !has_independent_solver(solver_cmds, &metadata.solver_used) {
        miette::bail!(
            "--trusted-check requires at least one solver different from certificate solver_used='{}'.",
            metadata.solver_used
        );
    }
    if proof_checker.is_none() && !allow_unchecked_proofs {
        miette::bail!(
            "--trusted-check requires --proof-checker for independently validated UNSAT proofs. \
             Pass --allow-unchecked-proofs only if you explicitly accept weaker trust."
        );
    }
    Ok(())
}

pub(crate) fn run_external_solver_on_file(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<String> {
    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2").arg(smt_file);
        }
        "cvc5" => {
            cmd.arg("--lang").arg("smt2").arg(smt_file);
        }
        _ => {
            cmd.arg(smt_file);
        }
    }

    let output = cmd.output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver `{solver_cmd}` failed on {}: {}",
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let token = stdout
        .lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("unknown")
        .to_string();
    Ok(token)
}

pub(crate) fn proof_object_looks_nontrivial(proof_text: &str) -> bool {
    let non_empty_lines = proof_text.lines().filter(|l| !l.trim().is_empty()).count();
    if non_empty_lines <= 1 {
        return false;
    }
    let lowered = proof_text.to_ascii_lowercase();
    if lowered.contains("error") || lowered.contains("unsupported") {
        return false;
    }
    let mut balance = 0i64;
    for ch in proof_text.chars() {
        match ch {
            '(' => balance += 1,
            ')' => {
                balance -= 1;
                if balance < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    balance == 0 && proof_text.contains('(')
}

pub(crate) fn run_external_proof_checker(
    checker: &std::path::Path,
    solver_cmd: &str,
    smt_file: &std::path::Path,
    proof_file: &std::path::Path,
) -> miette::Result<()> {
    let output = Command::new(checker)
        .arg("--solver")
        .arg(solver_cmd)
        .arg("--smt2")
        .arg(smt_file)
        .arg("--proof")
        .arg(proof_file)
        .output()
        .into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "proof checker `{}` rejected {} with {}: {}",
            checker.display(),
            smt_file.display(),
            proof_file.display(),
            stderr.trim()
        );
    }
    Ok(())
}

pub(crate) fn parse_solver_choice_checked(raw: &str) -> miette::Result<SolverChoice> {
    match raw {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => miette::bail!("Unknown solver in certificate metadata: {other}"),
    }
}

pub(crate) fn parse_soundness_mode_checked(raw: &str) -> miette::Result<SoundnessMode> {
    match raw {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => miette::bail!("Unknown soundness mode in certificate metadata: {other}"),
    }
}

pub(crate) fn parse_proof_engine_checked(raw: &str) -> miette::Result<ProofEngine> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => miette::bail!("Unknown proof engine in certificate metadata: {other}"),
    }
}

pub(crate) fn parse_fairness_mode_checked(raw: &str) -> miette::Result<FairnessMode> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => miette::bail!("Unknown fairness mode in certificate metadata: {other}"),
    }
}

pub(crate) fn obligation_triplets_from_bundle(
    bundle: &CertificateBundleInput,
) -> Vec<(String, String, String)> {
    let mut out = Vec::with_capacity(bundle.obligations.len());
    for o in &bundle.obligations {
        out.push((
            o.name.clone(),
            o.expected.clone(),
            sha256_hex_bytes(o.smt2.as_bytes()),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub(crate) fn obligation_triplets_from_metadata(
    metadata: &CertificateMetadata,
) -> Vec<(String, String, String)> {
    let mut out = Vec::with_capacity(metadata.obligations.len());
    for o in &metadata.obligations {
        out.push((
            o.name.clone(),
            o.expected.clone(),
            o.sha256.clone().unwrap_or_default(),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub(crate) fn rederive_certificate_bundle_input(
    metadata: &CertificateMetadata,
    timeout_secs: u64,
) -> miette::Result<CertificateBundleInput> {
    let protocol_path = PathBuf::from(&metadata.protocol_file);
    let source = fs::read_to_string(&protocol_path).into_diagnostic()?;
    let solver = parse_solver_choice_checked(&metadata.solver_used)?;
    let soundness = parse_soundness_mode_checked(&metadata.soundness)?;
    let proof_engine = parse_proof_engine_checked(&metadata.proof_engine)?;
    let k = metadata.induction_k.unwrap_or(12);
    let options = PipelineOptions {
        solver,
        max_depth: k,
        timeout_secs,
        dump_smt: None,
        soundness,
        proof_engine,
    };

    match metadata.kind.as_str() {
        "safety_proof" => {
            let cert = tarsier_engine::pipeline::generate_safety_certificate(
                &source,
                &metadata.protocol_file,
                &options,
            )
            .into_diagnostic()?;
            Ok(crate::certificate_bundle_from_safety(&cert))
        }
        "fair_liveness_proof" => {
            let fairness_raw = metadata.fairness.as_ref().ok_or_else(|| {
                miette::miette!("fair_liveness_proof metadata is missing fairness")
            })?;
            let fairness = parse_fairness_mode_checked(fairness_raw)?;
            let cert = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                &source,
                &metadata.protocol_file,
                &options,
                fairness,
            )
            .into_diagnostic()?;
            Ok(crate::certificate_bundle_from_fair_liveness(&cert))
        }
        other => miette::bail!("Unsupported certificate kind for re-derivation: {other}"),
    }
}

pub(crate) fn expected_matches(expected: &str, actual: &str) -> bool {
    expected.trim().eq_ignore_ascii_case(actual.trim())
}

pub(crate) fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn classify_cert_suite_check_triage(
    check: &str,
    expected: &str,
    actual: &str,
    class: Option<&str>,
    model_changed: bool,
) -> String {
    if model_changed {
        return TRIAGE_MODEL_CHANGE.into();
    }

    fn is_bug_sentinel(check: &str, outcome: &str) -> bool {
        match check {
            "verify" | "prove" => outcome.eq_ignore_ascii_case("unsafe"),
            "liveness" => outcome.eq_ignore_ascii_case("not_live"),
            "fair_liveness" | "prove_fair" => outcome.eq_ignore_ascii_case("fair_cycle_found"),
            _ => false,
        }
    }

    let class = class.unwrap_or("");
    let class_known_bug = class.eq_ignore_ascii_case("known_bug");
    let class_expected_safe = class.eq_ignore_ascii_case("expected_safe");
    let expected_bug = is_bug_sentinel(check, expected);
    let actual_bug = is_bug_sentinel(check, actual);
    let actual_unknown = actual.eq_ignore_ascii_case("unknown");

    // Mismatch that preserves expected benchmark polarity usually indicates manifest drift.
    if class_known_bug && actual_bug {
        return TRIAGE_EXPECTED_UPDATE.into();
    }
    if class_expected_safe && !actual_bug && !actual_unknown {
        return TRIAGE_EXPECTED_UPDATE.into();
    }
    if expected_bug == actual_bug
        && !expected.eq_ignore_ascii_case("unknown")
        && !actual.eq_ignore_ascii_case("unknown")
    {
        return TRIAGE_EXPECTED_UPDATE.into();
    }

    TRIAGE_ENGINE_REGRESSION.into()
}

pub(crate) fn classify_cert_suite_entry_triage(entry: &CertSuiteEntryReport) -> Option<String> {
    if entry.status == "pass" {
        return None;
    }
    if !entry.errors.is_empty() {
        return Some(if entry.model_changed {
            TRIAGE_MODEL_CHANGE.into()
        } else {
            TRIAGE_ENGINE_REGRESSION.into()
        });
    }
    let mut categories: Vec<String> = entry
        .checks
        .iter()
        .filter(|c| c.status == "fail")
        .filter_map(|c| c.triage.clone())
        .collect();
    if categories.is_empty() {
        return Some(TRIAGE_ENGINE_REGRESSION.into());
    }
    categories.sort();
    categories.dedup();
    if categories.len() == 1 {
        return categories.into_iter().next();
    }
    if categories.iter().any(|c| c == TRIAGE_ENGINE_REGRESSION) {
        return Some(TRIAGE_ENGINE_REGRESSION.into());
    }
    if categories.iter().any(|c| c == TRIAGE_MODEL_CHANGE) {
        return Some(TRIAGE_MODEL_CHANGE.into());
    }
    Some(TRIAGE_EXPECTED_UPDATE.into())
}

pub(crate) fn is_valid_cert_suite_triage_kind(kind: &str) -> bool {
    CERT_SUITE_TRIAGE_CATEGORIES.contains(&kind)
}

pub(crate) fn validate_cert_suite_report_triage_contract(
    report: &CertSuiteReport,
) -> Result<(), String> {
    for kind in report.triage.keys() {
        if !is_valid_cert_suite_triage_kind(kind) {
            return Err(format!(
                "Invalid report triage key '{}'. Allowed: {}.",
                kind,
                CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
            ));
        }
    }
    for entry in &report.entries {
        if let Some(kind) = &entry.triage {
            if !is_valid_cert_suite_triage_kind(kind) {
                return Err(format!(
                    "Entry '{}' has invalid triage '{}'. Allowed: {}.",
                    entry.file,
                    kind,
                    CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
                ));
            }
        }
        for check in &entry.checks {
            if let Some(kind) = &check.triage {
                if !is_valid_cert_suite_triage_kind(kind) {
                    return Err(format!(
                        "Entry '{}' check '{}' has invalid triage '{}'. Allowed: {}.",
                        entry.file,
                        check.check,
                        kind,
                        CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest_expected_result(check: &str, expected: &str) -> Result<(), String> {
    let allowed: &[&str] = match check {
        "verify" => &["safe", "probabilistically_safe", "unsafe", "unknown"],
        "liveness" => &["live", "not_live", "unknown"],
        "fair_liveness" => &["no_fair_cycle_up_to", "fair_cycle_found", "unknown"],
        "prove" => &[
            "safe",
            "probabilistically_safe",
            "unsafe",
            "not_proved",
            "unknown",
        ],
        "prove_fair" => &["live_proved", "fair_cycle_found", "not_proved", "unknown"],
        other => {
            return Err(format!(
                "Unsupported manifest check '{other}' while validating expected outcome."
            ));
        }
    };
    let normalized = expected.trim().to_ascii_lowercase();
    if allowed.iter().any(|candidate| *candidate == normalized) {
        return Ok(());
    }

    Err(format!(
        "Invalid expected outcome '{}' for '{}'. Allowed: {}.",
        expected.trim(),
        check,
        allowed.join(", ")
    ))
}

pub(crate) fn validate_manifest_entry_contract(
    entry: &CertSuiteEntry,
    schema_version: u32,
) -> Vec<String> {
    let mut errors = Vec::new();
    let configured_checks = usize::from(entry.verify.is_some())
        + usize::from(entry.liveness.is_some())
        + usize::from(entry.fair_liveness.is_some())
        + usize::from(entry.prove.is_some())
        + usize::from(entry.prove_fair.is_some());
    if configured_checks == 0 {
        errors.push("Entry has no expected outcomes configured.".into());
    }

    if schema_version >= 2 {
        let has_rationale = entry
            .notes
            .as_deref()
            .map(|notes| !notes.trim().is_empty())
            .unwrap_or(false);
        if !has_rationale {
            errors.push(
                "Schema v2 requires a non-empty 'notes' rationale for each protocol entry.".into(),
            );
        }
        match entry.model_sha256.as_deref().map(str::trim) {
            Some("") | None => errors.push(
                "Schema v2 requires a non-empty 'model_sha256' (hex SHA-256 of the protocol file)."
                    .into(),
            ),
            Some(hash) if !is_valid_sha256_hex(hash) => errors.push(format!(
                "Entry '{}' has invalid model_sha256 '{}'; expected 64 hex chars.",
                entry.file, hash
            )),
            _ => {}
        }

        let variant = entry.variant.as_deref().map(str::trim);
        let variant_group = entry.variant_group.as_deref().map(str::trim);
        match (variant, variant_group) {
            (None, None) | (Some(""), None) | (None, Some("")) => {}
            (Some(""), Some(_)) | (None, Some(_)) => errors.push(format!(
                "Entry '{}' sets 'variant_group' but is missing non-empty 'variant'.",
                entry.file
            )),
            (Some(_), Some("")) | (Some(_), None) => errors.push(format!(
                "Entry '{}' sets 'variant' but is missing non-empty 'variant_group'.",
                entry.file
            )),
            (Some(v), Some(_)) => match v {
                "minimal" | "faithful" => {}
                other => errors.push(format!(
                    "Entry '{}' has invalid variant '{}'. Allowed: minimal, faithful.",
                    entry.file, other
                )),
            },
        }
    }

    for (check, expected) in [
        ("verify", entry.verify.as_deref()),
        ("liveness", entry.liveness.as_deref()),
        ("fair_liveness", entry.fair_liveness.as_deref()),
        ("prove", entry.prove.as_deref()),
        ("prove_fair", entry.prove_fair.as_deref()),
    ] {
        if let Some(expected) = expected {
            if let Err(msg) = validate_manifest_expected_result(check, expected) {
                errors.push(msg);
            }
        }
    }

    errors
}

pub(crate) fn validate_manifest_top_level_contract(manifest: &CertSuiteManifest) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.schema_version != CERT_SUITE_SCHEMA_VERSION {
        errors.push(format!(
            "Unsupported certification manifest schema {} (expected {}). See {}.",
            manifest.schema_version, CERT_SUITE_SCHEMA_VERSION, CERT_SUITE_SCHEMA_DOC_PATH
        ));
    }
    if manifest.entries.is_empty() {
        errors.push("Manifest must contain at least one protocol entry.".into());
    }

    fn has_bug_sentinel_outcome(entry: &CertSuiteEntry) -> bool {
        let is = |value: Option<&str>, expected: &str| {
            value
                .map(|v| v.trim().eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        };
        is(entry.verify.as_deref(), "unsafe")
            || is(entry.prove.as_deref(), "unsafe")
            || is(entry.liveness.as_deref(), "not_live")
            || is(entry.fair_liveness.as_deref(), "fair_cycle_found")
            || is(entry.prove_fair.as_deref(), "fair_cycle_found")
    }

    let mut seen_files: HashSet<String> = HashSet::new();
    let mut known_bug_entries = 0usize;
    let mut variant_groups: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut variant_group_files: BTreeMap<(String, String), String> = BTreeMap::new();
    for entry in &manifest.entries {
        let file = entry.file.trim();
        if file.is_empty() {
            errors.push("Manifest entry has an empty 'file' path.".into());
            continue;
        }
        if !file.ends_with(".trs") {
            errors.push(format!(
                "Manifest entry '{}' must reference a .trs protocol file.",
                entry.file
            ));
        }
        if !seen_files.insert(file.to_string()) {
            errors.push(format!("Duplicate manifest entry for file '{}'.", file));
        }

        if manifest.schema_version >= 2 {
            let family = entry.family.as_deref().map(str::trim).unwrap_or("");
            if family.is_empty() {
                errors.push(format!(
                    "Entry '{}' is missing required 'family' (schema v2).",
                    entry.file
                ));
            }
            match entry.class.as_deref().map(str::trim).unwrap_or("") {
                "expected_safe" | "known_bug" => {}
                "" => errors.push(format!(
                    "Entry '{}' is missing required 'class' (schema v2).",
                    entry.file
                )),
                other => errors.push(format!(
                    "Entry '{}' has invalid class '{}'. Allowed: expected_safe, known_bug.",
                    entry.file, other
                )),
            }
            if entry.class.as_deref() == Some("known_bug") {
                known_bug_entries += 1;
                if !has_bug_sentinel_outcome(entry) {
                    errors.push(format!(
                        "Entry '{}' is class=known_bug but has no bug sentinel expected outcome (unsafe/not_live/fair_cycle_found).",
                        entry.file
                    ));
                }
            }

            let variant = entry.variant.as_deref().map(str::trim).unwrap_or("");
            let variant_group = entry.variant_group.as_deref().map(str::trim).unwrap_or("");
            if !variant.is_empty() && !variant_group.is_empty() {
                variant_groups
                    .entry(variant_group.to_string())
                    .or_default()
                    .insert(variant.to_string());
                let key = (variant_group.to_string(), variant.to_string());
                if let Some(existing) = variant_group_files.insert(key.clone(), entry.file.clone())
                {
                    errors.push(format!(
                        "Variant pair duplicate for group '{}' variant '{}': '{}' and '{}'.",
                        key.0, key.1, existing, entry.file
                    ));
                }
            }
        }
    }
    if manifest.schema_version >= 2 && known_bug_entries == 0 {
        errors.push("Schema v2 manifest must include at least one class=known_bug regression sentinel entry.".into());
    }
    if manifest.schema_version >= 2 {
        for (group, variants) in variant_groups {
            if !variants.contains("minimal") || !variants.contains("faithful") {
                errors.push(format!(
                    "Variant group '{}' must define both minimal and faithful entries.",
                    group
                ));
            }
        }
    }

    errors
}

pub(crate) fn resolve_manifest_library_dir(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> PathBuf {
    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let library_dir_raw = manifest.library_dir.as_deref().unwrap_or(".");
    let candidate = PathBuf::from(library_dir_raw);
    if candidate.is_absolute() {
        candidate
    } else {
        base_dir.join(candidate)
    }
}

pub(crate) fn manifest_entry_fault_model(
    protocol_source: &str,
    protocol_name: &str,
) -> Result<Option<&'static str>, String> {
    let program = tarsier_dsl::parse(protocol_source, protocol_name).map_err(|e| {
        format!("Failed parsing '{protocol_name}' while classifying fault model: {e}")
    })?;
    let proto = &program.protocol.node;
    for item in &proto.adversary {
        if item.key == "model" {
            return Ok(match item.value.as_str() {
                "byzantine" => Some("byzantine"),
                "omission" => Some("omission"),
                "crash" => Some("crash"),
                _ => None,
            });
        }
    }
    Ok(None)
}

pub(crate) fn validate_manifest_corpus_breadth(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_corpus_breadth {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);

    if !library_dir.exists() {
        errors.push(format!(
            "Corpus breadth directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Corpus breadth path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    let family_count = manifest
        .entries
        .iter()
        .filter_map(|entry| entry.family.as_deref())
        .map(str::trim)
        .filter(|family| !family.is_empty())
        .collect::<HashSet<_>>()
        .len();
    if family_count < CERT_SUITE_CANONICAL_MIN_FAMILIES {
        errors.push(format!(
            "Canonical corpus breadth requires at least {} distinct families (found {}).",
            CERT_SUITE_CANONICAL_MIN_FAMILIES, family_count
        ));
    }

    let mut seen_fault_models: HashSet<&'static str> = HashSet::new();
    for entry in &manifest.entries {
        let raw = entry.file.trim();
        if raw.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(raw);
        let protocol_path = if candidate.is_absolute() {
            candidate
        } else {
            library_dir.join(candidate)
        };
        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                errors.push(format!(
                    "Corpus breadth classification could not read '{}': {e}",
                    protocol_path.display()
                ));
                continue;
            }
        };
        let protocol_name = protocol_path.display().to_string();
        match manifest_entry_fault_model(&source, &protocol_name) {
            Ok(Some(model)) => {
                seen_fault_models.insert(model);
            }
            Ok(None) => errors.push(format!(
                "Entry '{}' does not declare a supported adversary model (expected byzantine|omission|crash).",
                entry.file
            )),
            Err(msg) => errors.push(msg),
        }
    }

    for required in ["byzantine", "omission", "crash"] {
        if !seen_fault_models.contains(required) {
            errors.push(format!(
                "Canonical corpus breadth requires at least one '{}' model entry.",
                required
            ));
        }
    }

    errors
}

pub(crate) fn validate_manifest_known_bug_sentinel_coverage(
    manifest: &CertSuiteManifest,
) -> Vec<String> {
    if !manifest.enforce_known_bug_sentinels {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let known_bug_families: HashSet<String> = manifest
        .entries
        .iter()
        .filter(|entry| entry.class.as_deref() == Some("known_bug"))
        .filter_map(|entry| entry.family.as_deref())
        .map(str::trim)
        .filter(|family| !family.is_empty())
        .map(|family| family.to_string())
        .collect();

    let required_known_bug_families: Vec<String> = manifest
        .required_known_bug_families
        .iter()
        .map(|family| family.trim())
        .filter(|family| !family.is_empty())
        .map(|family| family.to_string())
        .collect();
    if required_known_bug_families.is_empty() {
        errors.push(
            "Known-bug sentinel enforcement is enabled but required_known_bug_families is empty."
                .into(),
        );
    }
    for family in &required_known_bug_families {
        if !known_bug_families.contains(family) {
            errors.push(format!(
                "Required known-bug sentinel family '{}' has no class=known_bug entry.",
                family
            ));
        }
    }

    let required_variant_groups: Vec<String> = manifest
        .required_variant_groups
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .map(|group| group.to_string())
        .collect();
    if required_variant_groups.is_empty() {
        errors.push(
            "Known-bug sentinel enforcement is enabled but required_variant_groups is empty."
                .into(),
        );
    }

    let mut group_variants: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut group_families: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for entry in &manifest.entries {
        let variant = entry.variant.as_deref().map(str::trim).unwrap_or("");
        let group = entry.variant_group.as_deref().map(str::trim).unwrap_or("");
        if variant.is_empty() || group.is_empty() {
            continue;
        }
        group_variants
            .entry(group.to_string())
            .or_default()
            .insert(variant.to_string());
        if let Some(family) = entry
            .family
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
        {
            group_families
                .entry(group.to_string())
                .or_default()
                .insert(family.to_string());
        }
    }

    for group in &required_variant_groups {
        let Some(variants) = group_variants.get(group) else {
            errors.push(format!(
                "Required variant group '{}' is missing from manifest.",
                group
            ));
            continue;
        };
        if !variants.contains("minimal") || !variants.contains("faithful") {
            errors.push(format!(
                "Required variant group '{}' must include both minimal and faithful entries.",
                group
            ));
        }

        let families = group_families.get(group).cloned().unwrap_or_default();
        if families.len() != 1 {
            errors.push(format!(
                "Required variant group '{}' must map to exactly one family (found {}).",
                group,
                families.len()
            ));
            continue;
        }
        let family = families.into_iter().next().unwrap_or_default();
        if !known_bug_families.contains(&family) {
            errors.push(format!(
                "Required variant group '{}' belongs to family '{}' but that family has no class=known_bug sentinel entry.",
                group, family
            ));
        }
    }

    errors
}

pub(crate) fn validate_manifest_model_hash_consistency(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_model_hash_consistency {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);
    if !library_dir.exists() {
        errors.push(format!(
            "Model-hash consistency directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Model-hash consistency path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    for entry in &manifest.entries {
        let raw = entry.file.trim();
        if raw.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(raw);
        let protocol_path = if candidate.is_absolute() {
            candidate
        } else {
            library_dir.join(candidate)
        };
        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                errors.push(format!(
                    "Model-hash consistency could not read '{}': {e}",
                    protocol_path.display()
                ));
                continue;
            }
        };
        let actual = sha256_hex_bytes(source.as_bytes());
        match entry.model_sha256.as_deref().map(str::trim) {
            Some(expected) if expected.eq_ignore_ascii_case(&actual) => {}
            Some(expected) => errors.push(format!(
                "Entry '{}' model_sha256 mismatch: expected {}, actual {}. Update hashes with `python3 scripts/update-cert-suite-hashes.py --manifest {}`.",
                entry.file,
                expected,
                actual,
                manifest_path.display()
            )),
            None => errors.push(format!(
                "Entry '{}' is missing model_sha256 required for hash consistency.",
                entry.file
            )),
        }
    }

    errors
}

pub(crate) fn validate_manifest_library_coverage(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_library_coverage {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);

    if !library_dir.exists() {
        errors.push(format!(
            "Library coverage directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Library coverage path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    let mut on_disk_files: HashSet<String> = HashSet::new();
    let read_dir = match fs::read_dir(&library_dir) {
        Ok(entries) => entries,
        Err(e) => {
            errors.push(format!(
                "Failed reading library directory '{}': {e}",
                library_dir.display()
            ));
            return errors;
        }
    };
    for item in read_dir {
        let item = match item {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!(
                    "Failed listing library directory '{}': {e}",
                    library_dir.display()
                ));
                continue;
            }
        };
        let path = item.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("trs"))
                .unwrap_or(false)
        {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                on_disk_files.insert(name.to_string());
            }
        }
    }

    let manifest_files: HashSet<String> = manifest
        .entries
        .iter()
        .filter_map(|entry| {
            let path = Path::new(entry.file.trim());
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string())
        })
        .collect();

    for missing in on_disk_files.difference(&manifest_files) {
        errors.push(format!(
            "Protocol '{}' exists in '{}' but has no cert-suite expectation entry.",
            missing,
            library_dir.display()
        ));
    }
    for stale in manifest_files.difference(&on_disk_files) {
        errors.push(format!(
            "Manifest contains '{}' but '{}' has no such protocol file.",
            stale,
            library_dir.display()
        ));
    }

    errors
}

pub(crate) fn write_artifact_text(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

pub(crate) fn finalize_cert_suite_entry(
    entry_report: &mut CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    let refresh_status = |report: &mut CertSuiteEntryReport| {
        if !report.errors.is_empty() {
            report.status = "error".into();
        } else if report.checks.iter().any(|c| c.status == "fail") {
            report.status = "fail".into();
        } else {
            report.status = "pass".into();
        }
        report.verdict = report.status.clone();
        report.triage = classify_cert_suite_entry_triage(report);
    };

    entry_report.duration_ms = entry_started.elapsed().as_millis() as u64;
    refresh_status(entry_report);

    if let Some(dir) = entry_artifact_dir {
        let entry_json = match serde_json::to_string_pretty(entry_report) {
            Ok(json) => json,
            Err(e) => {
                entry_report
                    .errors
                    .push(format!("entry artifact serialization failed: {e}"));
                return;
            }
        };
        let summary_path = dir.join("entry.json");
        match write_artifact_text(&summary_path, &entry_json) {
            Ok(()) => entry_report
                .artifact_links
                .push(summary_path.display().to_string()),
            Err(msg) => entry_report
                .errors
                .push(format!("entry artifact write failed: {msg}")),
        }
    }

    refresh_status(entry_report);
}

pub(crate) fn finalize_and_push_cert_suite_entry(
    reports: &mut Vec<CertSuiteEntryReport>,
    passed: &mut usize,
    failed: &mut usize,
    errors: &mut usize,
    mut entry_report: CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    finalize_cert_suite_entry(&mut entry_report, entry_started, entry_artifact_dir);
    match entry_report.status.as_str() {
        "pass" => *passed += 1,
        "fail" => *failed += 1,
        _ => *errors += 1,
    }
    reports.push(entry_report);
}

pub(crate) fn write_check_artifact(
    entry_artifact_dir: Option<&Path>,
    check_name: &str,
    output: &str,
) -> Result<Option<String>, String> {
    let Some(dir) = entry_artifact_dir else {
        return Ok(None);
    };
    let filename = format!(
        "check_{}.txt",
        crate::sanitize_artifact_component(check_name)
    );
    let artifact_path = dir.join(filename);
    write_artifact_text(&artifact_path, output)?;
    Ok(Some(artifact_path.display().to_string()))
}

pub(crate) fn render_suite_text(report: &CertSuiteReport) -> String {
    let mut out = String::new();
    out.push_str("CERTIFICATION SUITE\n");
    out.push_str(&format!("Manifest: {}\n", report.manifest));
    out.push_str(&format!(
        "Config: solver={}, proof_engine={}, soundness={}, fairness={}\n",
        report.solver, report.proof_engine, report.soundness, report.fairness
    ));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str(&format!(
        "Summary: {} pass, {} fail, {} error\n",
        report.passed, report.failed, report.errors
    ));
    if !report.triage.is_empty() {
        out.push_str("Failure triage:\n");
        for (kind, count) in &report.triage {
            out.push_str(&format!("  - {}: {}\n", kind, count));
        }
    }
    if !report.by_class.is_empty() {
        out.push_str("By class:\n");
        for (class, bucket) in &report.by_class {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                class, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    if !report.by_family.is_empty() {
        out.push_str("By family:\n");
        for (family, bucket) in &report.by_family {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                family, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    out.push_str("Entries:\n");
    for entry in &report.entries {
        let mut tags: Vec<String> = Vec::new();
        if let Some(family) = &entry.family {
            tags.push(format!("family={family}"));
        }
        if let Some(class) = &entry.class {
            tags.push(format!("class={class}"));
        }
        if let Some(variant) = &entry.variant {
            tags.push(format!("variant={variant}"));
        }
        if let Some(group) = &entry.variant_group {
            tags.push(format!("group={group}"));
        }
        let tag_suffix = if tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", tags.join(", "))
        };
        out.push_str(&format!(
            "- [{}] {}{} verdict={} time={}ms\n",
            entry.status.to_uppercase(),
            entry.file,
            tag_suffix,
            entry.verdict,
            entry.duration_ms
        ));
        if let Some(triage) = &entry.triage {
            out.push_str(&format!("    triage: {triage}\n"));
        }
        out.push_str(&format!(
            "    assumptions: solver={} proof_engine={} soundness={} fairness={} network={} depth={} k={} timeout={}s cegar={}\n",
            entry.assumptions.solver,
            entry.assumptions.proof_engine,
            entry.assumptions.soundness,
            entry.assumptions.fairness,
            entry.assumptions.network_semantics,
            entry.assumptions.depth,
            entry.assumptions.k,
            entry.assumptions.timeout_secs,
            entry.assumptions.cegar_iters
        ));
        if let Some(expected_hash) = &entry.model_sha256_expected {
            out.push_str(&format!(
                "    model_sha256: expected={} actual={} changed={}\n",
                expected_hash,
                entry.model_sha256_actual.as_deref().unwrap_or("n/a"),
                entry.model_changed
            ));
        }
        for link in &entry.artifact_links {
            out.push_str(&format!("    artifact: {link}\n"));
        }
        for check in &entry.checks {
            out.push_str(&format!(
                "    {}: expected {}, got {} [{}] ({}ms)\n",
                check.check,
                check.expected,
                check.actual,
                check.status.to_uppercase(),
                check.duration_ms
            ));
            if let Some(triage) = &check.triage {
                out.push_str(&format!("      triage: {triage}\n"));
            }
            if let Some(link) = &check.artifact_link {
                out.push_str(&format!("      artifact: {link}\n"));
            }
        }
        for error in &entry.errors {
            out.push_str(&format!("    error: {error}\n"));
        }
    }
    out
}

pub(crate) fn run_cert_suite(
    manifest_path: &PathBuf,
    defaults: &CertSuiteDefaults,
    network_mode: CliNetworkSemanticsMode,
    artifacts_dir: Option<&Path>,
) -> miette::Result<CertSuiteReport> {
    let manifest_raw = fs::read_to_string(manifest_path).into_diagnostic()?;
    let manifest: CertSuiteManifest = serde_json::from_str(&manifest_raw).into_diagnostic()?;
    let mut manifest_errors = validate_manifest_top_level_contract(&manifest);
    manifest_errors.extend(validate_manifest_library_coverage(&manifest, manifest_path));
    manifest_errors.extend(validate_manifest_corpus_breadth(&manifest, manifest_path));
    manifest_errors.extend(validate_manifest_known_bug_sentinel_coverage(&manifest));
    manifest_errors.extend(validate_manifest_model_hash_consistency(
        &manifest,
        manifest_path,
    ));
    if !manifest_errors.is_empty() {
        miette::bail!(
            "Certification manifest validation failed:\n{}",
            manifest_errors
                .into_iter()
                .map(|msg| format!("  - {msg}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let artifacts_root = artifacts_dir.map(Path::to_path_buf);
    if let Some(dir) = &artifacts_root {
        fs::create_dir_all(dir).into_diagnostic()?;
    }

    let mut reports: Vec<CertSuiteEntryReport> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;

    for (entry_idx, entry) in manifest.entries.into_iter().enumerate() {
        let entry_started = Instant::now();
        let entry_artifact_dir = artifacts_root.as_ref().map(|root| {
            root.join(format!(
                "{:03}_{}",
                entry_idx + 1,
                crate::sanitize_artifact_component(&entry.file)
            ))
        });

        let protocol_path = {
            let p = PathBuf::from(&entry.file);
            if p.is_absolute() {
                p
            } else {
                base_dir.join(p)
            }
        };
        let entry_depth = entry.depth.unwrap_or(defaults.depth);
        let entry_k = entry.k.unwrap_or(defaults.k);
        let entry_timeout = entry.timeout.unwrap_or(defaults.timeout_secs);
        let cegar_iters = entry.cegar_iters.unwrap_or(2);

        let mut entry_report = CertSuiteEntryReport {
            file: protocol_path.display().to_string(),
            family: entry.family.clone(),
            class: entry.class.clone(),
            variant: entry.variant.clone(),
            variant_group: entry.variant_group.clone(),
            verdict: "pending".into(),
            status: "pass".into(),
            triage: None,
            duration_ms: 0,
            assumptions: CertSuiteAssumptions {
                solver: crate::solver_name(defaults.solver).to_string(),
                proof_engine: crate::proof_engine_name(defaults.proof_engine).to_string(),
                soundness: crate::soundness_name(defaults.soundness).to_string(),
                fairness: crate::fairness_name(defaults.fairness).to_string(),
                network_semantics: crate::cli_network_mode_name(network_mode).to_string(),
                depth: entry_depth,
                k: entry_k,
                timeout_secs: entry_timeout,
                cegar_iters,
            },
            model_sha256_expected: entry.model_sha256.clone(),
            model_sha256_actual: None,
            model_changed: false,
            notes: entry.notes.clone(),
            artifact_links: Vec::new(),
            checks: Vec::new(),
            errors: Vec::new(),
        };
        if let Some(dir) = &entry_artifact_dir {
            if let Err(e) = fs::create_dir_all(dir) {
                entry_report.errors.push(format!(
                    "Failed creating artifact directory {}: {e}",
                    dir.display()
                ));
            }
        }

        let contract_errors = validate_manifest_entry_contract(&entry, manifest.schema_version);
        if !contract_errors.is_empty() {
            entry_report.errors.extend(contract_errors);
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                entry_report.errors.push(format!(
                    "Failed reading {}: {}",
                    protocol_path.display(),
                    e
                ));
                finalize_and_push_cert_suite_entry(
                    &mut reports,
                    &mut passed,
                    &mut failed,
                    &mut errors,
                    entry_report,
                    entry_started,
                    entry_artifact_dir.as_deref(),
                );
                continue;
            }
        };
        let model_sha_actual = sha256_hex_bytes(source.as_bytes());
        entry_report.model_sha256_actual = Some(model_sha_actual.clone());
        if let Some(expected_hash) = entry.model_sha256.as_deref() {
            entry_report.model_changed = !expected_hash.eq_ignore_ascii_case(&model_sha_actual);
        }
        let filename = protocol_path.display().to_string();
        if let Err(e) = crate::validate_cli_network_semantics_mode(
            &source,
            &filename,
            defaults.soundness,
            network_mode,
        ) {
            entry_report
                .errors
                .push(format!("network semantics validation failed: {e}"));
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        // Structural guarantee: entries tagged variant=faithful MUST declare
        // faithful network semantics in the model and pass strict-mode lint.
        if entry.variant.as_deref() == Some("faithful") {
            match tarsier_dsl::parse(&source, &filename) {
                Ok(program) => {
                    if crate::declared_network_mode_in_program(&program) != "faithful" {
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but the model does not declare \
                             faithful network semantics (need `adversary {{ network: identity_selective; }}` \
                             or equivalent).",
                            entry.file
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                    let lint = crate::lint_protocol_file(&source, &filename, SoundnessMode::Strict);
                    let blocking: Vec<String> = lint
                        .issues
                        .iter()
                        .filter(|issue| issue.severity == "error")
                        .map(|issue| format!("{}: {}", issue.code, issue.message))
                        .collect();
                    if !blocking.is_empty() {
                        let rendered = blocking
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ");
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but fails strict-mode lint: {}",
                            entry.file, rendered
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                }
                Err(e) => {
                    entry_report.errors.push(format!(
                        "Entry '{}' has variant=faithful but failed to parse for validation: {}",
                        entry.file, e
                    ));
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            }
        }

        let entry_proof_engine = match entry.proof_engine.as_deref() {
            Some(raw) => match crate::parse_manifest_proof_engine(raw) {
                Ok(engine) => engine,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.proof_engine,
        };
        let entry_fairness = match entry.fairness.as_deref() {
            Some(raw) => match crate::parse_manifest_fairness_mode(raw) {
                Ok(mode) => mode,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.fairness,
        };
        entry_report.assumptions = CertSuiteAssumptions {
            solver: crate::solver_name(defaults.solver).to_string(),
            proof_engine: crate::proof_engine_name(entry_proof_engine).to_string(),
            soundness: crate::soundness_name(defaults.soundness).to_string(),
            fairness: crate::fairness_name(entry_fairness).to_string(),
            network_semantics: crate::cli_network_mode_name(network_mode).to_string(),
            depth: entry_depth,
            k: entry_k,
            timeout_secs: entry_timeout,
            cegar_iters,
        };

        let bounded_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_depth,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };
        let proof_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_k,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };

        if let Some(expected) = entry.verify {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::verify_with_cegar_report(
                &source,
                &filename,
                &bounded_options,
                cegar_iters,
            ) {
                Ok(result) => {
                    let actual = crate::verification_result_kind(&result.final_result).to_string();
                    let output = format!("{}", result.final_result);
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "verify",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("verify artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "verify",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "verify".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("verify failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_liveness(&source, &filename, &bounded_options) {
                Ok(result) => {
                    let actual = crate::liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.fair_liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &source,
                &filename,
                &bounded_options,
                entry_fairness,
            ) {
                Ok(result) => {
                    let actual = crate::fair_liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "fair_liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("fair_liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "fair_liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "fair_liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report
                        .errors
                        .push(format!("fair_liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_safety_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_safety(&source, &filename, &proof_options)
            };
            match prove_result {
                Ok(result) => {
                    let actual = crate::unbounded_safety_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link =
                        match write_check_artifact(entry_artifact_dir.as_deref(), "prove", &output)
                        {
                            Ok(link) => link,
                            Err(msg) => {
                                entry_report
                                    .errors
                                    .push(format!("prove artifact write failed: {msg}"));
                                None
                            }
                        };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove_fair {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                )
            };
            match prove_result {
                Ok(result) => {
                    let actual = crate::unbounded_fair_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "prove_fair",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("prove_fair artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove_fair",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove_fair".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove_fair failed: {e}"));
                }
            }
        }
        finalize_and_push_cert_suite_entry(
            &mut reports,
            &mut passed,
            &mut failed,
            &mut errors,
            entry_report,
            entry_started,
            entry_artifact_dir.as_deref(),
        );
    }

    let overall = if errors > 0 || failed > 0 {
        "fail".to_string()
    } else {
        "pass".to_string()
    };

    let mut by_family: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut by_class: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut triage: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &reports {
        if let Some(family) = &entry.family {
            let bucket = by_family.entry(family.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(class) = &entry.class {
            let bucket = by_class.entry(class.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(kind) = &entry.triage {
            *triage.entry(kind.clone()).or_default() += 1;
        }
    }

    let report = CertSuiteReport {
        schema_version: CERT_SUITE_SCHEMA_VERSION,
        manifest: manifest_path.display().to_string(),
        solver: crate::solver_name(defaults.solver).to_string(),
        proof_engine: crate::proof_engine_name(defaults.proof_engine).to_string(),
        soundness: crate::soundness_name(defaults.soundness).to_string(),
        fairness: crate::fairness_name(defaults.fairness).to_string(),
        entries: reports,
        passed,
        failed,
        errors,
        triage,
        by_family,
        by_class,
        overall,
    };
    if let Err(msg) = validate_cert_suite_report_triage_contract(&report) {
        miette::bail!("Certification report triage validation failed: {msg}");
    }
    Ok(report)
}

pub(crate) fn governance_bundle_payload_json(
    bundle: &GovernanceBundle,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "schema_version": bundle.schema_version,
        "tarsier_version": bundle.tarsier_version,
        "environment": bundle.environment,
        "model_source_sha256": bundle.model_source_sha256,
        "analysis_report": bundle.analysis_report,
        "certificates": bundle.certificates,
        "artifacts": bundle.artifacts
    }))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let mut i = 0usize;
    while i < trimmed.len() {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at offset {i}"))?;
        bytes.push(byte);
        i += 2;
    }
    Ok(bytes)
}

pub(crate) fn sign_governance_bundle(
    bundle: &GovernanceBundle,
) -> miette::Result<GovernanceBundleSignature> {
    let payload = governance_bundle_payload_json(bundle).into_diagnostic()?;
    let payload_sha256 = sha256_hex_bytes(&payload);
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| miette::miette!("failed to generate governance signing key"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| miette::miette!("failed to parse governance signing key"))?;
    let sig = key_pair.sign(&payload);
    Ok(GovernanceBundleSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex_encode(key_pair.public_key().as_ref()),
        signature_hex: hex_encode(sig.as_ref()),
        signed_payload_sha256: payload_sha256,
    })
}

pub(crate) fn verify_governance_signature(bundle: &GovernanceBundle) -> Result<Value, String> {
    if bundle.signature.algorithm != "ed25519" {
        return Err(format!(
            "unsupported signature algorithm '{}'",
            bundle.signature.algorithm
        ));
    }
    let payload = governance_bundle_payload_json(bundle)
        .map_err(|e| format!("failed to serialize governance payload: {e}"))?;
    let payload_sha256 = sha256_hex_bytes(&payload);
    if payload_sha256 != bundle.signature.signed_payload_sha256 {
        return Err("signed_payload_sha256 mismatch".into());
    }
    let public_key = hex_decode(&bundle.signature.public_key_hex)?;
    let signature = hex_decode(&bundle.signature.signature_hex)?;
    let verifier = UnparsedPublicKey::new(&ED25519, &public_key);
    verifier
        .verify(&payload, &signature)
        .map_err(|_| "signature verification failed".to_string())?;
    Ok(json!({
        "algorithm": bundle.signature.algorithm,
        "signed_payload_sha256": bundle.signature.signed_payload_sha256,
        "public_key_len": public_key.len(),
        "signature_len": signature.len()
    }))
}

pub(crate) fn resolve_bundle_relative_path(bundle_file: &Path, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        bundle_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(p)
    }
}

pub(crate) fn verify_governance_schema(bundle: &GovernanceBundle) -> Result<Value, String> {
    if bundle.schema_version != "v1" {
        return Err(format!(
            "unsupported bundle schema_version '{}' (expected v1)",
            bundle.schema_version
        ));
    }
    if bundle.tarsier_version.trim().is_empty() {
        return Err("missing tarsier_version".into());
    }
    if bundle.model_source_sha256.trim().len() != 64 {
        return Err("model_source_sha256 must be 64 hex chars".into());
    }
    if !bundle.analysis_report.is_object() {
        return Err("analysis_report must be a JSON object".into());
    }
    for key in [
        "schema_version",
        "mode",
        "file",
        "layers",
        "overall",
        "overall_verdict",
    ] {
        if bundle.analysis_report.get(key).is_none() {
            return Err(format!("analysis_report missing required field '{key}'"));
        }
    }
    if bundle.signature.public_key_hex.trim().is_empty()
        || bundle.signature.signature_hex.trim().is_empty()
        || bundle.signature.signed_payload_sha256.trim().is_empty()
    {
        return Err("signature object missing required fields".into());
    }
    Ok(json!({
        "schema_version": bundle.schema_version,
        "analysis_report_fields_checked": ["schema_version", "mode", "file", "layers", "overall", "overall_verdict"]
    }))
}

pub(crate) fn verify_governance_completeness(
    bundle: &GovernanceBundle,
    bundle_file: &Path,
) -> Result<Value, String> {
    if bundle.artifacts.is_empty() {
        return Err("artifacts list must be non-empty".into());
    }

    let mut report_artifact_present = false;
    let mut checked_artifacts = 0usize;
    for artifact in &bundle.artifacts {
        if artifact.name == "analysis_report" && artifact.kind == "report" {
            report_artifact_present = true;
        }
        let artifact_path = resolve_bundle_relative_path(bundle_file, &artifact.path);
        if !artifact_path.exists() {
            return Err(format!(
                "artifact '{}' missing at {}",
                artifact.name,
                artifact_path.display()
            ));
        }
        let actual_sha = sha256_hex_file(&artifact_path)
            .map_err(|e| format!("failed hashing artifact '{}': {e}", artifact.name))?;
        if !actual_sha.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(format!(
                "artifact '{}' hash mismatch (expected {}, got {})",
                artifact.name, artifact.sha256, actual_sha
            ));
        }
        checked_artifacts += 1;
    }
    if !report_artifact_present {
        return Err("artifacts list missing required analysis_report artifact".into());
    }

    let mut checked_certificates = 0usize;
    for cert in &bundle.certificates {
        if cert.bundle_dir.trim().is_empty() {
            continue;
        }
        let bundle_dir = resolve_bundle_relative_path(bundle_file, &cert.bundle_dir);
        if !bundle_dir.exists() {
            return Err(format!(
                "certificate bundle directory missing: {}",
                bundle_dir.display()
            ));
        }
        let integrity = check_bundle_integrity(&bundle_dir).map_err(|e| {
            format!(
                "bundle integrity check failed for {}: {e}",
                bundle_dir.display()
            )
        })?;
        if !integrity.issues.is_empty() {
            let first = &integrity.issues[0].message;
            return Err(format!(
                "certificate integrity failed for {}: {}",
                bundle_dir.display(),
                first
            ));
        }
        checked_certificates += 1;
    }

    Ok(json!({
        "checked_artifacts": checked_artifacts,
        "checked_certificate_bundles": checked_certificates,
        "report_artifact_present": report_artifact_present
    }))
}

pub(crate) fn verify_governance_bundle(bundle_path: &Path) -> GovernanceBundleVerificationReport {
    let mut checks = Vec::new();
    let bundle_path_display = bundle_path.display().to_string();

    let raw = match fs::read_to_string(bundle_path) {
        Ok(raw) => raw,
        Err(e) => {
            checks.push(GovernanceBundleVerificationCheck {
                check: "load_bundle".into(),
                status: "fail".into(),
                details: json!({}),
                error: Some(format!("failed to read bundle: {e}")),
            });
            return GovernanceBundleVerificationReport {
                schema_version: "v1".into(),
                bundle: bundle_path_display,
                overall: "fail".into(),
                checks,
            };
        }
    };

    let bundle: GovernanceBundle = match serde_json::from_str(&raw) {
        Ok(bundle) => bundle,
        Err(e) => {
            checks.push(GovernanceBundleVerificationCheck {
                check: "parse_bundle".into(),
                status: "fail".into(),
                details: json!({}),
                error: Some(format!("invalid governance bundle JSON: {e}")),
            });
            return GovernanceBundleVerificationReport {
                schema_version: "v1".into(),
                bundle: bundle_path_display,
                overall: "fail".into(),
                checks,
            };
        }
    };

    match verify_governance_schema(&bundle) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "schema".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "schema".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }
    match verify_governance_signature(&bundle) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "signature".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "signature".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }
    match verify_governance_completeness(&bundle, bundle_path) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "completeness".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "completeness".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }

    let overall = if checks.iter().all(|c| c.status == "pass") {
        "pass"
    } else {
        "fail"
    };
    GovernanceBundleVerificationReport {
        schema_version: "v1".into(),
        bundle: bundle_path_display,
        overall: overall.to_string(),
        checks,
    }
}

/// V2-08: Build a governance artifact bundle.
pub(crate) fn build_governance_bundle(
    report: &AnalysisReport,
    source: &str,
    report_path: &Path,
    report_json: &str,
) -> miette::Result<GovernanceBundle> {
    let report_value = serde_json::to_value(report).unwrap_or_else(|_| json!({}));

    // Extract certificate references from cert layers
    let mut certificates = Vec::new();
    let mut artifacts = Vec::new();
    let report_sha256 = sha256_hex_bytes(report_json.as_bytes());
    artifacts.push(GovernanceArtifactReference {
        name: "analysis_report".to_string(),
        kind: "report".to_string(),
        path: report_path.display().to_string(),
        sha256: report_sha256,
    });

    for layer in &report.layers {
        if layer.layer.starts_with("certify[") {
            let kind = if layer.layer.contains("safety") {
                "safety"
            } else {
                "fair_liveness"
            };
            let bundle_dir = layer
                .details
                .get("bundle_dir")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let integrity_ok = layer
                .details
                .get("integrity_ok")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // Try to read bundle SHA from certificate.json
            let bundle_sha256 = if !bundle_dir.is_empty() {
                let cert_path = Path::new(&bundle_dir).join("certificate.json");
                if cert_path.exists() {
                    let cert_hash = sha256_hex_file(&cert_path).ok();
                    if let Some(hash) = cert_hash {
                        artifacts.push(GovernanceArtifactReference {
                            name: format!("certificate_{kind}"),
                            kind: "certificate".to_string(),
                            path: cert_path.display().to_string(),
                            sha256: hash,
                        });
                    }
                }
                std::fs::read_to_string(&cert_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| {
                        v.get("bundle_sha256")
                            .and_then(Value::as_str)
                            .map(String::from)
                    })
            } else {
                None
            };
            certificates.push(CertificateReference {
                kind: kind.to_string(),
                bundle_dir,
                bundle_sha256,
                integrity_ok,
            });
        }
    }

    let mut bundle = GovernanceBundle {
        schema_version: "v1".to_string(),
        tarsier_version: env!("CARGO_PKG_VERSION").to_string(),
        environment: EnvironmentInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        },
        model_source_sha256: sha256_hex_bytes(source.as_bytes()),
        analysis_report: report_value,
        certificates,
        artifacts,
        signature: GovernanceBundleSignature {
            algorithm: "ed25519".to_string(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            signed_payload_sha256: String::new(),
        },
    };
    bundle.signature = sign_governance_bundle(&bundle)?;
    Ok(bundle)
}

// ---------------------------------------------------------------------------
// Command handler functions (wired from main.rs match arms)
// ---------------------------------------------------------------------------

/// Handler for `Commands::CertSuite`.
pub(crate) fn run_cert_suite_command(
    manifest: PathBuf,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    engine: String,
    soundness: String,
    fairness: String,
    format: String,
    out: Option<PathBuf>,
    artifacts_dir: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let solver = parse_solver_choice(&solver);
    let engine = parse_proof_engine(&engine);
    let soundness = parse_soundness_mode(&soundness);
    if cli_network_mode == CliNetworkSemanticsMode::Faithful && soundness != SoundnessMode::Strict {
        miette::bail!("`--network-semantics faithful` requires `--soundness strict`.");
    }
    let fairness = parse_fairness_mode(&fairness);
    let output_format = parse_output_format(&format);
    let defaults = CertSuiteDefaults {
        solver,
        depth,
        k,
        timeout_secs: timeout,
        soundness,
        fairness,
        proof_engine: engine,
    };

    let report = run_cert_suite(
        &manifest,
        &defaults,
        cli_network_mode,
        artifacts_dir.as_deref(),
    )?;
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        write_json_artifact(&path, &report_json_value)?;
        println!("Certification suite report written to {}", path.display());
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_suite_text(&report)),
        OutputFormat::Json => println!("{report_json}"),
    }

    if report.overall != "pass" {
        std::process::exit(2);
    }
    Ok(())
}

/// Handler for `Commands::CertifySafety`.
pub(crate) fn run_certify_safety_command(
    file: PathBuf,
    solver: String,
    k: usize,
    engine: String,
    timeout: u64,
    soundness: String,
    out: PathBuf,
    capture_proofs: bool,
    allow_missing_proofs: bool,
    trust_report: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = fs::read_to_string(&file).into_diagnostic()?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver),
        max_depth: k,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: parse_proof_engine(&engine),
    };

    let cert =
        match tarsier_engine::pipeline::generate_safety_certificate(&source, &filename, &options) {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };

    let bundle = certificate_bundle_from_safety(&cert);
    write_certificate_bundle(&out, &bundle, capture_proofs, allow_missing_proofs)?;

    if let Some(report_path) = trust_report {
        let report =
            generate_trust_report("standard", Some(&filename), &[&solver], &engine, &soundness);
        let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
        fs::write(&report_path, json).into_diagnostic()?;
        println!("Trust report written to {}", report_path.display());
    }
    Ok(())
}

/// Handler for `Commands::CertifyFairLiveness`.
pub(crate) fn run_certify_fair_liveness_command(
    file: PathBuf,
    solver: String,
    k: usize,
    timeout: u64,
    soundness: String,
    fairness: String,
    out: PathBuf,
    capture_proofs: bool,
    allow_missing_proofs: bool,
    trust_report: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = fs::read_to_string(&file).into_diagnostic()?;
    let filename = file.display().to_string();
    let fairness = parse_fairness_mode(&fairness);
    let soundness_mode = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver),
        max_depth: k,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::Pdr,
    };

    let cert = match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        &source, &filename, &options, fairness,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let bundle = certificate_bundle_from_fair_liveness(&cert);
    write_certificate_bundle(&out, &bundle, capture_proofs, allow_missing_proofs)?;

    if let Some(report_path) = trust_report {
        let report =
            generate_trust_report("standard", Some(&filename), &[&solver], "pdr", &soundness);
        let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
        fs::write(&report_path, json).into_diagnostic()?;
        println!("Trust report written to {}", report_path.display());
    }
    Ok(())
}

/// Handler for `Commands::CheckCertificate`.
pub(crate) fn run_check_certificate_command(
    bundle: PathBuf,
    profile: Option<String>,
    solvers: String,
    emit_proofs: Option<PathBuf>,
    require_proofs: bool,
    proof_checker: Option<PathBuf>,
    allow_unchecked_proofs: bool,
    rederive: bool,
    rederive_timeout: u64,
    trusted_check: bool,
    min_solvers: usize,
) -> miette::Result<()> {
    // Apply governance profile floor requirements.
    let mut min_solvers = min_solvers;
    let mut require_proofs = require_proofs;
    let mut require_foundational_proof_path = false;
    if let Some(profile_name) = &profile {
        let gov_profile: GovernanceProfile = profile_name
            .parse()
            .map_err(|e: String| miette::miette!("{}", e))?;
        let reqs = gov_profile.requirements();
        if reqs.min_solvers > min_solvers {
            min_solvers = reqs.min_solvers;
        }
        if reqs.require_proofs {
            require_proofs = true;
        }
        if reqs.require_proof_checker && proof_checker.is_none() {
            miette::bail!(
                "--profile {} requires --proof-checker to be set.",
                profile_name
            );
        }
        if reqs.require_foundational_proof_path {
            require_foundational_proof_path = true;
        }
    }

    let integrity = check_bundle_integrity(&bundle).into_diagnostic()?;
    let metadata = integrity.metadata;

    if metadata.kind != CertificateKind::SafetyProof.as_str()
        && metadata.kind != CertificateKind::FairLivenessProof.as_str()
    {
        miette::bail!("Unsupported certificate kind: {}", metadata.kind);
    }

    let mut solver_cmds = parse_solver_list(&solvers);
    solver_cmds.sort();
    solver_cmds.dedup();
    if solver_cmds.is_empty() {
        miette::bail!("No solver commands provided (use --solvers z3,cvc5).");
    }
    if require_foundational_proof_path {
        validate_foundational_profile_requirements(&solver_cmds, true)?;
    }
    validate_trusted_check_requirements(
        trusted_check,
        min_solvers,
        &solver_cmds,
        &metadata,
        rederive,
        proof_checker.as_ref(),
        allow_unchecked_proofs,
    )?;

    let mut had_error = false;
    for issue in integrity.issues {
        had_error = true;
        println!("[FAIL] integrity [{}]: {}", issue.code, issue.message);
    }

    if had_error {
        std::process::exit(2);
    }

    if trusted_check && proof_checker.is_none() && allow_unchecked_proofs {
        println!(
            "[WARN] trusted-check: --allow-unchecked-proofs enabled; relying on solver UNSAT + proof-shape checks only"
        );
    }

    if rederive {
        match rederive_certificate_bundle_input(&metadata, rederive_timeout) {
            Ok(rederived_bundle) => {
                let expected = obligation_triplets_from_metadata(&metadata);
                let actual = obligation_triplets_from_bundle(&rederived_bundle);
                if expected != actual {
                    had_error = true;
                    println!(
                        "[FAIL] rederive: certificate obligations differ from freshly generated obligations"
                    );
                    println!(
                        "        (metadata obligations: {}, regenerated obligations: {})",
                        expected.len(),
                        actual.len()
                    );
                } else {
                    println!(
                        "[PASS] rederive: regenerated obligations match certificate metadata hashes"
                    );
                }
            }
            Err(e) => {
                had_error = true;
                println!("[ERROR] rederive: {e}");
            }
        }
    }

    if had_error {
        std::process::exit(2);
    }

    let emit_proofs_dir = emit_proofs.clone();
    if let Some(dir) = &emit_proofs_dir {
        fs::create_dir_all(dir).into_diagnostic()?;
    }

    let require_proofs = require_proofs || trusted_check;
    let mut obligation_pass_counts = vec![0usize; metadata.obligations.len()];
    let mut obligation_solver_errors = vec![0usize; metadata.obligations.len()];

    for solver_cmd in solver_cmds {
        let mut solver_pass = true;
        let solver_proof_dir = emit_proofs_dir.as_ref().map(|d| d.join(&solver_cmd));
        if let Some(dir) = &solver_proof_dir {
            fs::create_dir_all(dir).into_diagnostic()?;
        }
        for (obligation_idx, obligation) in metadata.obligations.iter().enumerate() {
            let obligation_path = bundle.join(&obligation.file);
            let need_proofs = emit_proofs_dir.is_some() || require_proofs;
            if need_proofs {
                match run_external_solver_with_proof(&solver_cmd, &obligation_path) {
                    Ok((result, proof_text)) => {
                        let mut passed = result == obligation.expected;
                        if !passed {
                            solver_pass = false;
                            if !trusted_check {
                                had_error = true;
                            }
                            println!(
                                "[FAIL] {}: {} expected {}, got {}",
                                solver_cmd, obligation.name, obligation.expected, result
                            );
                        } else if require_proofs
                            && obligation.expected == "unsat"
                            && !proof_object_looks_nontrivial(&proof_text)
                        {
                            solver_pass = false;
                            passed = false;
                            if !trusted_check {
                                had_error = true;
                            }
                            println!(
                                "[FAIL] {}: {} UNSAT but emitted proof object is empty/malformed",
                                solver_cmd, obligation.name
                            );
                        }
                        let mut proof_file_for_check: Option<PathBuf> = None;
                        let mut temp_proof_file: Option<PathBuf> = None;
                        if let Some(dir) = &solver_proof_dir {
                            let proof_file = dir.join(format!("{}.proof", obligation.name));
                            if let Err(e) = fs::write(&proof_file, &proof_text) {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!(
                                    "[ERROR] {}: failed writing proof file {}: {}",
                                    solver_cmd,
                                    proof_file.display(),
                                    e
                                );
                                passed = false;
                            } else {
                                proof_file_for_check = Some(proof_file);
                            }
                        } else if proof_checker.is_some() && obligation.expected == "unsat" {
                            let temp_path = std::env::temp_dir().join(format!(
                                "tarsier-proof-{}-{}-{}-{}.proof",
                                std::process::id(),
                                solver_cmd,
                                obligation_idx,
                                obligation.name
                            ));
                            if let Err(e) = fs::write(&temp_path, &proof_text) {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!(
                                    "[ERROR] {}: failed writing temporary proof file {}: {}",
                                    solver_cmd,
                                    temp_path.display(),
                                    e
                                );
                                passed = false;
                            } else {
                                proof_file_for_check = Some(temp_path.clone());
                                temp_proof_file = Some(temp_path);
                            }
                        }

                        if passed && obligation.expected == "unsat" && result == "unsat" {
                            if let Some(checker) = proof_checker.as_ref() {
                                if let Some(proof_file) = &proof_file_for_check {
                                    if let Err(e) = run_external_proof_checker(
                                        checker,
                                        &solver_cmd,
                                        &obligation_path,
                                        proof_file,
                                    ) {
                                        solver_pass = false;
                                        obligation_solver_errors[obligation_idx] += 1;
                                        if !trusted_check {
                                            had_error = true;
                                        }
                                        passed = false;
                                        println!(
                                            "[FAIL] {}: {} ({e})",
                                            solver_cmd, obligation.name
                                        );
                                    }
                                } else {
                                    solver_pass = false;
                                    obligation_solver_errors[obligation_idx] += 1;
                                    if !trusted_check {
                                        had_error = true;
                                    }
                                    passed = false;
                                    println!(
                                        "[FAIL] {}: {} no proof file available for --proof-checker",
                                        solver_cmd, obligation.name
                                    );
                                }
                            }
                        }

                        if passed {
                            obligation_pass_counts[obligation_idx] += 1;
                        }

                        if let Some(temp_path) = temp_proof_file {
                            let _ = fs::remove_file(temp_path);
                        }
                    }
                    Err(e) => {
                        solver_pass = false;
                        obligation_solver_errors[obligation_idx] += 1;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!("[ERROR] {}: {}", solver_cmd, e);
                    }
                }
            } else {
                match run_external_solver_on_file(&solver_cmd, &obligation_path) {
                    Ok(result) if result == obligation.expected => {
                        obligation_pass_counts[obligation_idx] += 1;
                    }
                    Ok(result) => {
                        solver_pass = false;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!(
                            "[FAIL] {}: {} expected {}, got {}",
                            solver_cmd, obligation.name, obligation.expected, result
                        );
                    }
                    Err(e) => {
                        solver_pass = false;
                        obligation_solver_errors[obligation_idx] += 1;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!("[ERROR] {}: {}", solver_cmd, e);
                    }
                }
            }
        }
        if solver_pass {
            println!(
                "[PASS] {}: all {} obligations satisfied",
                solver_cmd,
                metadata.obligations.len()
            );
            if let Some(dir) = &solver_proof_dir {
                println!(
                    "[PASS] {}: proof objects written to {}",
                    solver_cmd,
                    dir.display()
                );
            }
        } else {
            println!("[FAIL] {}: one or more obligations failed", solver_cmd);
        }
    }

    if trusted_check {
        let mut consensus_failures = 0usize;
        for (idx, obligation) in metadata.obligations.iter().enumerate() {
            let confirmations = obligation_pass_counts[idx];
            if confirmations < min_solvers {
                consensus_failures += 1;
                println!(
                    "[FAIL] trusted-check: obligation '{}' has {} confirmation(s), requires {}.",
                    obligation.name, confirmations, min_solvers
                );
            } else {
                println!(
                    "[PASS] trusted-check: obligation '{}' confirmed by {} solver(s).",
                    obligation.name, confirmations
                );
            }
            if obligation_solver_errors[idx] > 0 {
                println!(
                    "[WARN] trusted-check: obligation '{}' had {} solver execution/proof I/O error(s).",
                    obligation.name, obligation_solver_errors[idx]
                );
            }
        }
        if consensus_failures > 0 {
            had_error = true;
        }
    }

    if had_error {
        std::process::exit(2);
    } else {
        println!(
            "Certificate verified for kind '{}' with engine '{}' (k/frame: {}).",
            metadata.kind,
            metadata.proof_engine,
            metadata
                .induction_k
                .map(|k| k.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
    Ok(())
}

/// Handler for `Commands::GenerateTrustReport`.
pub(crate) fn run_generate_trust_report_command(
    profile: String,
    protocol_file: Option<String>,
    solvers: String,
    engine: String,
    soundness: String,
    out: PathBuf,
) -> miette::Result<()> {
    // Validate governance profile
    let valid_profiles = ["standard", "reinforced", "high-assurance"];
    if !valid_profiles.contains(&profile.as_str()) {
        eprintln!(
            "Error: invalid governance profile '{}'. Must be one of: {}",
            profile,
            valid_profiles.join(", ")
        );
        std::process::exit(1);
    }
    // Validate soundness
    let valid_soundness = ["strict", "permissive"];
    if !valid_soundness.contains(&soundness.as_str()) {
        eprintln!(
            "Error: invalid soundness '{}'. Must be one of: {}",
            soundness,
            valid_soundness.join(", ")
        );
        std::process::exit(1);
    }
    // Validate engine
    let valid_engines = ["kinduction", "pdr"];
    if !valid_engines.contains(&engine.as_str()) {
        eprintln!(
            "Error: invalid engine '{}'. Must be one of: {}",
            engine,
            valid_engines.join(", ")
        );
        std::process::exit(1);
    }

    let solver_list: Vec<&str> = solvers.split(',').map(|s| s.trim()).collect();
    let report = generate_trust_report(
        &profile,
        protocol_file.as_deref(),
        &solver_list,
        &engine,
        &soundness,
    );
    let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
    fs::write(&out, json).into_diagnostic()?;
    println!("Trust report written to {}", out.display());
    Ok(())
}

/// Handler for `Commands::GovernancePipeline`.
pub(crate) fn run_governance_pipeline_command(
    file: PathBuf,
    cert_manifest: PathBuf,
    conformance_manifest: PathBuf,
    benchmark_report: Option<PathBuf>,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: String,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
    por_mode: &str,
) -> miette::Result<()> {
    let pipeline_start = std::time::Instant::now();
    let output_format = parse_output_format(&format);
    let mut gates: Vec<GovernanceGateResult> = Vec::new();

    // --- Gate 1: Proof (analyze in audit mode) ---
    let proof_start = std::time::Instant::now();
    let proof_gate = (|| -> Result<GovernanceGateResult, String> {
        let source = fs::read_to_string(&file).map_err(|e| e.to_string())?;
        let filename = file.display().to_string();
        let eff_solver = parse_solver_choice(&solver);
        let eff_soundness = parse_soundness_mode(&soundness);
        let cfg = LayerRunCfg {
            solver: eff_solver,
            depth,
            k,
            timeout,
            soundness: eff_soundness,
            fairness: FairnessMode::Weak,
            cegar_iters: 0,
            portfolio: true,
        };
        let report = run_analysis(
            &source,
            &filename,
            AnalysisMode::Audit,
            cfg,
            cli_network_mode,
            None,
            por_mode,
        );
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "proof".to_string(),
            status: status.to_string(),
            elapsed_ms: proof_start.elapsed().as_millis() as u64,
            details: json!({
                "mode": report.mode,
                "overall": report.overall,
                "overall_verdict": report.overall_verdict,
                "confidence_tier": report.confidence_tier,
                "layer_count": report.layers.len(),
            }),
            error: None,
        })
    })();
    match proof_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "proof".to_string(),
            status: "error".to_string(),
            elapsed_ms: proof_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 2: Cert-suite ---
    let cert_start = std::time::Instant::now();
    let cert_gate = (|| -> Result<GovernanceGateResult, String> {
        let eff_solver = parse_solver_choice(&solver);
        let eff_soundness = parse_soundness_mode(&soundness);
        let defaults = CertSuiteDefaults {
            solver: eff_solver,
            depth,
            k,
            timeout_secs: timeout,
            soundness: eff_soundness,
            fairness: FairnessMode::Weak,
            proof_engine: ProofEngine::KInduction,
        };
        let report = run_cert_suite(&cert_manifest, &defaults, cli_network_mode, None)
            .map_err(|e| format!("{e}"))?;
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "cert".to_string(),
            status: status.to_string(),
            elapsed_ms: cert_start.elapsed().as_millis() as u64,
            details: json!({
                "manifest": report.manifest,
                "passed": report.passed,
                "failed": report.failed,
                "errors": report.errors,
                "overall": report.overall,
            }),
            error: None,
        })
    })();
    match cert_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "cert".to_string(),
            status: "error".to_string(),
            elapsed_ms: cert_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 3: Corpus (conformance-suite) ---
    let corpus_start = std::time::Instant::now();
    let corpus_gate = (|| -> Result<GovernanceGateResult, String> {
        let report =
            run_conformance_suite(&conformance_manifest, None).map_err(|e| format!("{e}"))?;
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "corpus".to_string(),
            status: status.to_string(),
            elapsed_ms: corpus_start.elapsed().as_millis() as u64,
            details: json!({
                "manifest": report.manifest_path,
                "passed": report.passed,
                "failed": report.failed,
                "errors": report.errors,
                "overall": report.overall,
            }),
            error: None,
        })
    })();
    match corpus_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "corpus".to_string(),
            status: "error".to_string(),
            elapsed_ms: corpus_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 4: Perf (benchmark report validation) ---
    let perf_start = std::time::Instant::now();
    if let Some(ref bench_path) = benchmark_report {
        let perf_gate = (|| -> Result<GovernanceGateResult, String> {
            let raw = fs::read_to_string(bench_path).map_err(|e| e.to_string())?;
            let report: Value =
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}"))?;
            let perf_gate_obj = report.get("performance_gate");
            let perf_pass = perf_gate_obj
                .and_then(|g| g.get("pass"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let scale_gate_obj = report.get("scale_band_gate");
            let scale_pass = scale_gate_obj
                .and_then(|g| g.get("pass"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let summary = report.get("summary").cloned().unwrap_or(json!({}));
            let status = if perf_pass && scale_pass {
                "pass"
            } else {
                "fail"
            };
            Ok(GovernanceGateResult {
                gate: "perf".to_string(),
                status: status.to_string(),
                elapsed_ms: perf_start.elapsed().as_millis() as u64,
                details: json!({
                    "benchmark_file": bench_path.display().to_string(),
                    "performance_gate_pass": perf_pass,
                    "scale_band_gate_pass": scale_pass,
                    "summary": summary,
                }),
                error: None,
            })
        })();
        match perf_gate {
            Ok(g) => gates.push(g),
            Err(e) => gates.push(GovernanceGateResult {
                gate: "perf".to_string(),
                status: "error".to_string(),
                elapsed_ms: perf_start.elapsed().as_millis() as u64,
                details: json!({}),
                error: Some(e),
            }),
        }
    } else {
        gates.push(GovernanceGateResult {
            gate: "perf".to_string(),
            status: "skip".to_string(),
            elapsed_ms: 0,
            details: json!({"reason": "no --benchmark-report provided"}),
            error: None,
        });
    }

    let overall = if gates
        .iter()
        .all(|g| g.status == "pass" || g.status == "skip")
    {
        "pass"
    } else {
        "fail"
    };

    let pipeline_report = GovernancePipelineReport {
        schema_version: "v1".to_string(),
        tarsier_version: env!("CARGO_PKG_VERSION").to_string(),
        gates: gates.clone(),
        overall: overall.to_string(),
        elapsed_ms: pipeline_start.elapsed().as_millis() as u64,
    };

    let report_json = serde_json::to_string_pretty(&pipeline_report).into_diagnostic()?;
    if let Some(ref path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).into_diagnostic()?;
        }
        fs::write(path, &report_json).into_diagnostic()?;
    }

    match output_format {
        OutputFormat::Text => {
            println!("Governance Pipeline Report");
            println!("==========================");
            for gate in &pipeline_report.gates {
                let icon = match gate.status.as_str() {
                    "pass" => "PASS",
                    "fail" => "FAIL",
                    "skip" => "SKIP",
                    _ => "ERR ",
                };
                println!(
                    "  [{icon}] {gate:<8} ({ms}ms)",
                    gate = gate.gate,
                    ms = gate.elapsed_ms,
                );
                if let Some(ref e) = gate.error {
                    println!("         error: {e}");
                }
            }
            println!("---");
            println!("Overall: {overall}");
        }
        OutputFormat::Json => println!("{report_json}"),
    }

    if overall != "pass" {
        std::process::exit(2);
    }
    Ok(())
}

/// Handler for `Commands::VerifyGovernanceBundle`.
pub(crate) fn run_verify_governance_bundle_command(
    bundle: PathBuf,
    format: String,
) -> miette::Result<()> {
    let output_format = parse_output_format(&format);
    let report = verify_governance_bundle(&bundle);
    let report_json = serde_json::to_string_pretty(&report).into_diagnostic()?;
    match output_format {
        OutputFormat::Text => {
            println!("Governance Bundle Verification");
            println!("==============================");
            println!("Bundle: {}", report.bundle);
            for check in &report.checks {
                let icon = if check.status == "pass" {
                    "PASS"
                } else {
                    "FAIL"
                };
                println!("  [{icon}] {}", check.check);
                if let Some(err) = &check.error {
                    println!("         error: {err}");
                }
            }
            println!("---");
            println!("Overall: {}", report.overall);
        }
        OutputFormat::Json => {
            println!("{report_json}");
        }
    }
    if report.overall != "pass" {
        std::process::exit(2);
    }
    Ok(())
}
