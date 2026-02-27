// Governance module types: structs and enums for governance bundles, cert suites, and trust reports.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use tarsier_engine::pipeline::{FairnessMode, ProofEngine, SolverChoice, SoundnessMode};

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
