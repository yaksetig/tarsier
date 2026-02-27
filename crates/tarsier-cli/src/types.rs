//! Shared types used across CLI commands and tests.

use serde::Serialize;
use serde_json::Value;

use tarsier_engine::pipeline::{FairnessMode, SolverChoice, SoundnessMode};

#[derive(Clone, Copy, Debug)]
pub(crate) enum AnalysisMode {
    Quick,
    Standard,
    Proof,
    Audit,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CliNetworkSemanticsMode {
    Dsl,
    Faithful,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum VisualizeCheck {
    Verify,
    Liveness,
    FairLiveness,
    Prove,
    ProveFair,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum VisualizeFormat {
    Timeline,
    Mermaid,
    Markdown,
    Json,
}

#[derive(Clone, Copy)]
pub(crate) struct LayerRunCfg {
    pub(crate) solver: SolverChoice,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: SoundnessMode,
    pub(crate) fairness: FairnessMode,
    pub(crate) cegar_iters: usize,
    pub(crate) portfolio: bool,
}

#[derive(Serialize)]
pub(crate) struct AnalysisConfig {
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout_secs: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) portfolio: bool,
    pub(crate) por_mode: String,
}

#[derive(Clone, Copy)]
pub(crate) enum CertificateKind {
    SafetyProof,
    FairLivenessProof,
}

impl CertificateKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CertificateKind::SafetyProof => "safety_proof",
            CertificateKind::FairLivenessProof => "fair_liveness_proof",
        }
    }
}

#[derive(Clone)]
pub(crate) struct CertificateBundleObligation {
    pub(crate) name: String,
    pub(crate) expected: String,
    pub(crate) smt2: String,
}

#[derive(Clone)]
pub(crate) struct CertificateBundleInput {
    pub(crate) kind: CertificateKind,
    pub(crate) protocol_file: String,
    pub(crate) proof_engine: String,
    pub(crate) induction_k: Option<usize>,
    pub(crate) solver_used: String,
    pub(crate) soundness: String,
    pub(crate) fairness: Option<String>,
    pub(crate) committee_bounds: Vec<(String, u64)>,
    pub(crate) obligations: Vec<CertificateBundleObligation>,
}

#[derive(Serialize)]
pub(crate) struct AnalysisLayerReport {
    pub(crate) layer: String,
    pub(crate) status: String,
    pub(crate) verdict: String,
    pub(crate) summary: String,
    pub(crate) details: Value,
    pub(crate) output: String,
}

#[derive(Serialize)]
pub(crate) struct AnalysisReport {
    pub(crate) schema_version: String,
    pub(crate) mode: String,
    pub(crate) file: String,
    pub(crate) config: AnalysisConfig,
    pub(crate) network_faithfulness: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) liveness_governance: Option<Value>,
    pub(crate) layers: Vec<AnalysisLayerReport>,
    pub(crate) overall: String,
    pub(crate) overall_verdict: String,
    pub(crate) interpretation: AnalysisInterpretation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) claim: Option<ClaimStatement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_action: Option<NextAction>,
    pub(crate) confidence_tier: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) preflight_warnings: Vec<Value>,
}

/// Beginner-facing property interpretation.
#[derive(Serialize)]
pub(crate) struct AnalysisInterpretation {
    pub(crate) safety: String,
    pub(crate) liveness: String,
    pub(crate) summary: String,
    pub(crate) overall_status_meaning: String,
}

/// V1-06: What was proven / assumptions / not covered.
#[derive(Serialize)]
pub(crate) struct ClaimStatement {
    pub(crate) proven: Vec<String>,
    pub(crate) assumptions: Vec<String>,
    pub(crate) not_covered: Vec<String>,
}

/// V1-07: Deterministic next-best-command recommendation.
#[derive(Serialize)]
pub(crate) struct NextAction {
    pub(crate) command: String,
    pub(crate) reason: String,
}

// ---------------------------------------------------------------------------
// V1-05: Unified verdict taxonomy
// ---------------------------------------------------------------------------
// Every command maps its native result to one of these canonical labels so
// that text output, JSON reports, and the analyze pipeline all share a single
// vocabulary.

/// Canonical verdict labels shared across all commands and output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CanonicalVerdict {
    Safe,
    Unsafe,
    LiveProved,
    LiveCex,
    Inconclusive,
    Unknown,
}

impl CanonicalVerdict {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CanonicalVerdict::Safe => "SAFE",
            CanonicalVerdict::Unsafe => "UNSAFE",
            CanonicalVerdict::LiveProved => "LIVE_PROVED",
            CanonicalVerdict::LiveCex => "LIVE_CEX",
            CanonicalVerdict::Inconclusive => "INCONCLUSIVE",
            CanonicalVerdict::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for CanonicalVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
