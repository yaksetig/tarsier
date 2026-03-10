//! Export-friendly IR for proof certificates.
//!
//! This module provides a stable, serializable representation of proof
//! certificates so downstream backends (Lean/Coq or other consumers) can work
//! from a normalized payload independent of CLI bundle layout.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PROOF_EXPORT_IR_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofExportKind {
    Safety,
    FairLiveness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofExportCertificateObligationEvidence {
    /// Relative path to the SMT-LIB obligation file in the certificate bundle.
    pub obligation_file: String,
    /// Optional SHA-256 hash recorded for the SMT-LIB obligation file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation_sha256: Option<String>,
    /// Optional relative path to solver proof object file in the certificate bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_file: Option<String>,
    /// Optional SHA-256 hash recorded for the solver proof object file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofExportObligation {
    pub name: String,
    pub expected: String,
    pub smt2: String,
    /// Optional mapping to the original certificate bundle artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_evidence: Option<ProofExportCertificateObligationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofExportIr {
    pub schema_version: u32,
    pub kind: ProofExportKind,
    pub protocol_file: String,
    pub proof_engine: String,
    pub fairness: Option<String>,
    pub induction_k: Option<usize>,
    pub frame: Option<usize>,
    pub solver_used: String,
    pub soundness: String,
    pub committee_bounds: Vec<(String, u64)>,
    pub obligations: Vec<ProofExportObligation>,
}

pub fn export_ir_from_safety_certificate(cert: &SafetyProofCertificate) -> ProofExportIr {
    ProofExportIr {
        schema_version: PROOF_EXPORT_IR_SCHEMA_VERSION,
        kind: ProofExportKind::Safety,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_label(cert.proof_engine).to_string(),
        fairness: None,
        induction_k: cert.induction_k,
        frame: None,
        solver_used: solver_label(cert.solver_used).to_string(),
        soundness: soundness_label(cert.soundness).to_string(),
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(export_obligation)
            .collect::<Vec<_>>(),
    }
}

pub fn export_ir_from_fair_liveness_certificate(
    cert: &FairLivenessProofCertificate,
) -> ProofExportIr {
    ProofExportIr {
        schema_version: PROOF_EXPORT_IR_SCHEMA_VERSION,
        kind: ProofExportKind::FairLiveness,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_label(cert.proof_engine).to_string(),
        fairness: Some(fairness_label(cert.fairness).to_string()),
        induction_k: None,
        frame: Some(cert.frame),
        solver_used: solver_label(cert.solver_used).to_string(),
        soundness: soundness_label(cert.soundness).to_string(),
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(export_obligation)
            .collect::<Vec<_>>(),
    }
}

fn export_obligation(ob: &SafetyProofObligation) -> ProofExportObligation {
    ProofExportObligation {
        name: ob.name.clone(),
        expected: ob.expected.clone(),
        smt2: ob.smt2.clone(),
        certificate_evidence: None,
    }
}

/// Attach certificate artifact evidence to IR obligations by obligation name.
///
/// Returns the number of obligations for which evidence was attached.
pub fn attach_certificate_evidence_by_name(
    ir: &mut ProofExportIr,
    evidence_by_name: &BTreeMap<String, ProofExportCertificateObligationEvidence>,
) -> usize {
    let mut attached = 0usize;
    for ob in &mut ir.obligations {
        if let Some(evidence) = evidence_by_name.get(&ob.name) {
            ob.certificate_evidence = Some(evidence.clone());
            attached += 1;
        }
    }
    attached
}

fn proof_engine_label(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

fn fairness_label(fairness: FairnessMode) -> &'static str {
    match fairness {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

fn solver_label(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn soundness_label(soundness: SoundnessMode) -> &'static str {
    match soundness {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_ir_from_safety_certificate_maps_core_fields() {
        let cert = SafetyProofCertificate {
            protocol_file: "safe.trs".into(),
            proof_engine: ProofEngine::Pdr,
            induction_k: Some(7),
            solver_used: SolverChoice::Z3,
            soundness: SoundnessMode::Strict,
            committee_bounds: vec![("n".into(), 4), ("f".into(), 1)],
            obligations: vec![SafetyProofObligation {
                name: "init_implies_inv".into(),
                expected: "unsat".into(),
                smt2: "(check-sat)".into(),
            }],
        };

        let ir = export_ir_from_safety_certificate(&cert);
        assert_eq!(ir.schema_version, 1);
        assert_eq!(ir.kind, ProofExportKind::Safety);
        assert_eq!(ir.proof_engine, "pdr");
        assert_eq!(ir.solver_used, "z3");
        assert_eq!(ir.soundness, "strict");
        assert_eq!(ir.induction_k, Some(7));
        assert_eq!(ir.frame, None);
        assert_eq!(ir.fairness, None);
        assert_eq!(ir.obligations.len(), 1);
        assert_eq!(ir.obligations[0].name, "init_implies_inv");
        assert!(ir.obligations[0].certificate_evidence.is_none());
    }

    #[test]
    fn export_ir_from_fair_liveness_certificate_maps_core_fields() {
        let cert = FairLivenessProofCertificate {
            protocol_file: "fair.trs".into(),
            fairness: FairnessMode::Strong,
            proof_engine: ProofEngine::Pdr,
            frame: 9,
            solver_used: SolverChoice::Cvc5,
            soundness: SoundnessMode::Permissive,
            committee_bounds: vec![("n".into(), 4)],
            obligations: vec![SafetyProofObligation {
                name: "inv_implies_no_fair_bad".into(),
                expected: "unsat".into(),
                smt2: "(check-sat)".into(),
            }],
        };

        let ir = export_ir_from_fair_liveness_certificate(&cert);
        assert_eq!(ir.schema_version, 1);
        assert_eq!(ir.kind, ProofExportKind::FairLiveness);
        assert_eq!(ir.proof_engine, "pdr");
        assert_eq!(ir.solver_used, "cvc5");
        assert_eq!(ir.soundness, "permissive");
        assert_eq!(ir.induction_k, None);
        assert_eq!(ir.frame, Some(9));
        assert_eq!(ir.fairness.as_deref(), Some("strong"));
        assert_eq!(ir.obligations.len(), 1);
        assert_eq!(ir.obligations[0].name, "inv_implies_no_fair_bad");
        assert!(ir.obligations[0].certificate_evidence.is_none());
    }

    #[test]
    fn attach_certificate_evidence_by_name_maps_matching_obligations_only() {
        let cert = SafetyProofCertificate {
            protocol_file: "safe.trs".into(),
            proof_engine: ProofEngine::Pdr,
            induction_k: Some(3),
            solver_used: SolverChoice::Z3,
            soundness: SoundnessMode::Strict,
            committee_bounds: vec![("n".into(), 4)],
            obligations: vec![
                SafetyProofObligation {
                    name: "init_implies_inv".into(),
                    expected: "unsat".into(),
                    smt2: "(check-sat)".into(),
                },
                SafetyProofObligation {
                    name: "inv_implies_safe".into(),
                    expected: "unsat".into(),
                    smt2: "(check-sat)".into(),
                },
            ],
        };
        let mut ir = export_ir_from_safety_certificate(&cert);
        let mut evidence_by_name = BTreeMap::new();
        evidence_by_name.insert(
            "init_implies_inv".into(),
            ProofExportCertificateObligationEvidence {
                obligation_file: "init_implies_inv.smt2".into(),
                obligation_sha256: Some("abc".into()),
                proof_file: Some("init_implies_inv.proof".into()),
                proof_sha256: Some("def".into()),
            },
        );
        evidence_by_name.insert(
            "extra_unused".into(),
            ProofExportCertificateObligationEvidence {
                obligation_file: "extra_unused.smt2".into(),
                obligation_sha256: None,
                proof_file: None,
                proof_sha256: None,
            },
        );

        let attached = attach_certificate_evidence_by_name(&mut ir, &evidence_by_name);
        assert_eq!(attached, 1);
        assert!(ir.obligations[0].certificate_evidence.is_some());
        assert!(ir.obligations[1].certificate_evidence.is_none());
    }
}
