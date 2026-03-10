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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CertificateKind --

    #[test]
    fn certificate_kind_safety_proof() {
        assert_eq!(CertificateKind::SafetyProof.as_str(), "safety_proof");
    }

    #[test]
    fn certificate_kind_fair_liveness_proof() {
        assert_eq!(
            CertificateKind::FairLivenessProof.as_str(),
            "fair_liveness_proof"
        );
    }

    #[test]
    fn certificate_kind_is_copy() {
        let k = CertificateKind::SafetyProof;
        let k2 = k;
        assert_eq!(k.as_str(), k2.as_str());
    }

    // -- CanonicalVerdict --

    #[test]
    fn canonical_verdict_as_str() {
        assert_eq!(CanonicalVerdict::Safe.as_str(), "SAFE");
        assert_eq!(CanonicalVerdict::Unsafe.as_str(), "UNSAFE");
        assert_eq!(CanonicalVerdict::LiveProved.as_str(), "LIVE_PROVED");
        assert_eq!(CanonicalVerdict::LiveCex.as_str(), "LIVE_CEX");
        assert_eq!(CanonicalVerdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(CanonicalVerdict::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn canonical_verdict_display() {
        assert_eq!(format!("{}", CanonicalVerdict::Safe), "SAFE");
        assert_eq!(format!("{}", CanonicalVerdict::Unsafe), "UNSAFE");
    }

    #[test]
    fn canonical_verdict_eq() {
        assert_eq!(CanonicalVerdict::Safe, CanonicalVerdict::Safe);
        assert_ne!(CanonicalVerdict::Safe, CanonicalVerdict::Unsafe);
    }

    #[test]
    fn canonical_verdict_debug() {
        let debug = format!("{:?}", CanonicalVerdict::Safe);
        assert_eq!(debug, "Safe");
    }

    #[test]
    fn canonical_verdict_serializes_screaming_snake_case() {
        let json = serde_json::to_string(&CanonicalVerdict::LiveProved).unwrap();
        assert_eq!(json, "\"LIVE_PROVED\"");
    }

    #[test]
    fn canonical_verdict_copy() {
        let v = CanonicalVerdict::Inconclusive;
        let v2 = v;
        assert_eq!(v, v2);
    }

    // -- CertificateBundleObligation --

    #[test]
    fn certificate_bundle_obligation_clone() {
        let obl = CertificateBundleObligation {
            name: "init".into(),
            expected: "unsat".into(),
            smt2: "(assert true)".into(),
        };
        let cloned = obl.clone();
        assert_eq!(cloned.name, "init");
        assert_eq!(cloned.expected, "unsat");
        assert_eq!(cloned.smt2, "(assert true)");
    }

    // -- CertificateBundleInput --

    #[test]
    fn certificate_bundle_input_clone() {
        let input = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "proto.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(12),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("f".into(), 1)],
            obligations: vec![],
        };
        let cloned = input.clone();
        assert_eq!(cloned.protocol_file, "proto.trs");
        assert_eq!(cloned.induction_k, Some(12));
        assert!(cloned.fairness.is_none());
        assert_eq!(cloned.committee_bounds.len(), 1);
    }

    // -- AnalysisReport serialization --

    #[test]
    fn analysis_report_serializes() {
        let report = AnalysisReport {
            schema_version: "v1".into(),
            mode: "quick".into(),
            file: "test.trs".into(),
            config: AnalysisConfig {
                solver: "z3".into(),
                depth: 10,
                k: 12,
                timeout_secs: 60,
                soundness: "strict".into(),
                fairness: "weak".into(),
                portfolio: false,
                por_mode: "full".into(),
            },
            network_faithfulness: serde_json::json!({}),
            liveness_governance: None,
            layers: vec![],
            overall: "pass".into(),
            overall_verdict: "SAFE".into(),
            interpretation: AnalysisInterpretation {
                safety: "safe".into(),
                liveness: "unknown".into(),
                summary: "Protocol is safe.".into(),
                overall_status_meaning: "passed".into(),
            },
            claim: None,
            next_action: None,
            confidence_tier: "standard".into(),
            preflight_warnings: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], "v1");
        assert_eq!(json["mode"], "quick");
        assert_eq!(json["overall"], "pass");
        // liveness_governance should be skipped when None
        assert!(!json.as_object().unwrap().contains_key("liveness_governance"));
    }

    // -- LayerRunCfg --

    #[test]
    fn layer_run_cfg_copy() {
        let cfg = LayerRunCfg {
            solver: SolverChoice::Z3,
            depth: 10,
            k: 12,
            timeout: 60,
            soundness: SoundnessMode::Strict,
            fairness: FairnessMode::Weak,
            cegar_iters: 2,
            portfolio: true,
        };
        let copy = cfg;
        assert_eq!(copy.depth, 10);
        assert!(copy.portfolio);
    }

    // -- enum debug --

    #[test]
    fn analysis_mode_debug() {
        assert_eq!(format!("{:?}", AnalysisMode::Quick), "Quick");
        assert_eq!(format!("{:?}", AnalysisMode::Standard), "Standard");
        assert_eq!(format!("{:?}", AnalysisMode::Proof), "Proof");
        assert_eq!(format!("{:?}", AnalysisMode::Audit), "Audit");
    }

    #[test]
    fn output_format_debug() {
        assert_eq!(format!("{:?}", OutputFormat::Text), "Text");
        assert_eq!(format!("{:?}", OutputFormat::Json), "Json");
    }

    #[test]
    fn cli_network_semantics_mode_eq() {
        assert_eq!(CliNetworkSemanticsMode::Dsl, CliNetworkSemanticsMode::Dsl);
        assert_ne!(
            CliNetworkSemanticsMode::Dsl,
            CliNetworkSemanticsMode::Faithful
        );
    }

    #[test]
    fn visualize_check_debug() {
        assert_eq!(format!("{:?}", VisualizeCheck::Verify), "Verify");
        assert_eq!(
            format!("{:?}", VisualizeCheck::FairLiveness),
            "FairLiveness"
        );
    }

    #[test]
    fn visualize_format_debug() {
        assert_eq!(format!("{:?}", VisualizeFormat::Timeline), "Timeline");
        assert_eq!(format!("{:?}", VisualizeFormat::Mermaid), "Mermaid");
    }
}
