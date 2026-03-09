use miette::IntoDiagnostic;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use tarsier_engine::pipeline::{
    export_ir_from_fair_liveness_certificate, export_ir_from_safety_certificate,
    FairLivenessProofCertificate, FairnessMode, ProofEngine, SafetyProofCertificate,
    SafetyProofObligation, SolverChoice, SoundnessMode,
};
use tarsier_proof_kernel::load_metadata;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProofExportReport {
    pub(crate) target: String,
    pub(crate) bundle: String,
    pub(crate) output: Option<String>,
    pub(crate) kind: String,
}

pub(crate) fn run_proof_export_command(
    bundle: PathBuf,
    to: String,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    let target = parse_export_target(&to)?;
    let metadata = load_metadata(&bundle).into_diagnostic()?;
    let obligations = metadata
        .obligations
        .iter()
        .map(|ob| -> miette::Result<SafetyProofObligation> {
            let smt2_path = bundle.join(&ob.file);
            let smt2 = fs::read_to_string(&smt2_path).into_diagnostic()?;
            Ok(SafetyProofObligation {
                name: ob.name.clone(),
                expected: ob.expected.clone(),
                smt2,
            })
        })
        .collect::<miette::Result<Vec<_>>>()?;

    let export_ir = match metadata.kind.as_str() {
        "safety_proof" => {
            let cert = SafetyProofCertificate {
                protocol_file: metadata.protocol_file.clone(),
                proof_engine: parse_proof_engine(&metadata.proof_engine)?,
                induction_k: metadata.induction_k,
                solver_used: parse_solver_choice(&metadata.solver_used)?,
                soundness: parse_soundness_mode(&metadata.soundness)?,
                committee_bounds: metadata.committee_bounds.clone(),
                obligations,
            };
            export_ir_from_safety_certificate(&cert)
        }
        "fair_liveness_proof" => {
            let cert = FairLivenessProofCertificate {
                protocol_file: metadata.protocol_file.clone(),
                fairness: parse_fairness_mode(metadata.fairness.as_deref().unwrap_or("weak"))?,
                proof_engine: parse_proof_engine(&metadata.proof_engine)?,
                frame: metadata.induction_k.unwrap_or(0),
                solver_used: parse_solver_choice(&metadata.solver_used)?,
                soundness: parse_soundness_mode(&metadata.soundness)?,
                committee_bounds: metadata.committee_bounds.clone(),
                obligations,
            };
            export_ir_from_fair_liveness_certificate(&cert)
        }
        other => {
            miette::bail!(
                "Unsupported certificate kind '{other}'. Expected 'safety_proof' or 'fair_liveness_proof'."
            );
        }
    };

    let payload = serde_json::json!({
        "schema_version": 1,
        "target": target,
        "proof": export_ir,
    });
    let rendered = serde_json::to_string_pretty(&payload).into_diagnostic()?;
    if let Some(path) = out.clone() {
        fs::write(&path, rendered).into_diagnostic()?;
        println!("Proof export written to {}", path.display());
    } else {
        println!("{rendered}");
    }

    let report = ProofExportReport {
        target: target.to_string(),
        bundle: bundle.display().to_string(),
        output: out.as_ref().map(|p| p.display().to_string()),
        kind: metadata.kind,
    };
    let report_json = serde_json::to_string(&report).into_diagnostic()?;
    eprintln!("{report_json}");
    Ok(())
}

fn parse_export_target(target: &str) -> miette::Result<&'static str> {
    match target.to_ascii_lowercase().as_str() {
        "lean" => Ok("lean"),
        "coq" => Ok("coq"),
        other => miette::bail!("Unsupported export target '{other}'. Use --to lean or --to coq."),
    }
}

fn parse_solver_choice(s: &str) -> miette::Result<SolverChoice> {
    match s.to_ascii_lowercase().as_str() {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => miette::bail!("Unsupported solver '{other}' in certificate metadata."),
    }
}

fn parse_soundness_mode(s: &str) -> miette::Result<SoundnessMode> {
    match s.to_ascii_lowercase().as_str() {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => miette::bail!("Unsupported soundness mode '{other}' in certificate metadata."),
    }
}

fn parse_proof_engine(s: &str) -> miette::Result<ProofEngine> {
    match s.to_ascii_lowercase().as_str() {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => miette::bail!("Unsupported proof engine '{other}' in certificate metadata."),
    }
}

fn parse_fairness_mode(s: &str) -> miette::Result<FairnessMode> {
    match s.to_ascii_lowercase().as_str() {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => miette::bail!("Unsupported fairness mode '{other}' in certificate metadata."),
    }
}
