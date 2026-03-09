use miette::IntoDiagnostic;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tarsier_engine::pipeline::{
    export_ir_from_fair_liveness_certificate, export_ir_from_safety_certificate,
    FairLivenessProofCertificate, FairnessMode, ProofEngine, ProofExportIr, SafetyProofCertificate,
    SafetyProofObligation, SolverChoice, SoundnessMode,
};
use tarsier_proof_kernel::load_metadata;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProofExportReport {
    pub(crate) target: String,
    pub(crate) bundle: String,
    pub(crate) output: Option<String>,
    pub(crate) kind: String,
    pub(crate) certcheck: Option<ProofExportCertcheckReport>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProofExportCertcheckReport {
    pub(crate) binary: String,
    pub(crate) overall: String,
}

#[derive(Debug, Deserialize)]
struct CertcheckJsonReport {
    overall: String,
}

pub(crate) fn run_proof_export_command(
    bundle: PathBuf,
    to: String,
    out: Option<PathBuf>,
    certcheck: bool,
    certcheck_bin: Option<PathBuf>,
) -> miette::Result<()> {
    let certcheck_result = if certcheck {
        Some(run_certcheck(
            &bundle,
            certcheck_bin
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("tarsier-certcheck")),
        )?)
    } else {
        None
    };

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

    let rendered = match target {
        "lean" => render_lean_module(&export_ir),
        "coq" => render_coq_module(&export_ir),
        _ => unreachable!("target is validated by parse_export_target"),
    };
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
        certcheck: certcheck_result,
    };
    let report_json = serde_json::to_string(&report).into_diagnostic()?;
    eprintln!("{report_json}");
    Ok(())
}

fn run_certcheck(
    bundle: &std::path::Path,
    certcheck_bin: &std::path::Path,
) -> miette::Result<ProofExportCertcheckReport> {
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .into_diagnostic()?
        .as_nanos();
    let report_path =
        std::env::temp_dir().join(format!("tarsier-proof-export-certcheck-{ts_nanos}.json"));
    let output = Command::new(certcheck_bin)
        .arg(bundle)
        .arg("--json-report")
        .arg(&report_path)
        .arg("--fail-fast")
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "certcheck failed while validating '{}': {}",
            bundle.display(),
            stderr.trim()
        );
    }

    let report_json = fs::read_to_string(&report_path).into_diagnostic()?;
    let parsed: CertcheckJsonReport = serde_json::from_str(&report_json).into_diagnostic()?;
    let _ = fs::remove_file(&report_path);

    if parsed.overall != "pass" {
        miette::bail!(
            "certcheck reported overall='{}' for '{}'",
            parsed.overall,
            bundle.display()
        );
    }

    Ok(ProofExportCertcheckReport {
        binary: certcheck_bin.display().to_string(),
        overall: parsed.overall,
    })
}

fn parse_export_target(target: &str) -> miette::Result<&'static str> {
    match target.to_ascii_lowercase().as_str() {
        "lean" => Ok("lean"),
        "coq" => Ok("coq"),
        other => miette::bail!("Unsupported export target '{other}'. Use --to lean or --to coq."),
    }
}

fn render_lean_module(ir: &ProofExportIr) -> String {
    let mut out = String::new();
    out.push_str("/- Auto-generated by tarsier proof-export (Lean backend) -/\n");
    out.push_str("namespace TarsierExport\n\n");
    out.push_str(&format!(
        "def schemaVersion : Nat := {}\n",
        ir.schema_version
    ));
    out.push_str(&format!(
        "def protocolFile : String := \"{}\"\n",
        lean_escape(&ir.protocol_file)
    ));
    out.push_str(&format!(
        "def proofEngine : String := \"{}\"\n",
        lean_escape(&ir.proof_engine)
    ));
    out.push_str(&format!(
        "def solverUsed : String := \"{}\"\n",
        lean_escape(&ir.solver_used)
    ));
    out.push_str(&format!(
        "def soundness : String := \"{}\"\n",
        lean_escape(&ir.soundness)
    ));
    if let Some(fairness) = &ir.fairness {
        out.push_str(&format!(
            "def fairness : Option String := some \"{}\"\n",
            lean_escape(fairness)
        ));
    } else {
        out.push_str("def fairness : Option String := none\n");
    }
    if let Some(k) = ir.induction_k {
        out.push_str(&format!("def inductionK : Option Nat := some {}\n", k));
    } else {
        out.push_str("def inductionK : Option Nat := none\n");
    }
    if let Some(frame) = ir.frame {
        out.push_str(&format!("def frame : Option Nat := some {}\n", frame));
    } else {
        out.push_str("def frame : Option Nat := none\n");
    }
    out.push_str("def committeeBounds : List (String × Nat) := [\n");
    for (name, bound) in &ir.committee_bounds {
        out.push_str(&format!("  (\"{}\", {}),\n", lean_escape(name), bound));
    }
    out.push_str("]\n\n");

    out.push_str("def obligations : List (String × String × String) := [\n");
    for ob in &ir.obligations {
        out.push_str(&format!(
            "  (\"{}\", \"{}\", \"{}\"),\n",
            lean_escape(&ob.name),
            lean_escape(&ob.expected),
            lean_escape(&ob.smt2)
        ));
    }
    out.push_str("]\n\n");

    for ob in &ir.obligations {
        let theorem_name = lean_ident_from_name(&ob.name);
        out.push_str(&format!(
            "theorem {} : True := by\n  trivial\n\n",
            theorem_name
        ));
    }
    out.push_str("end TarsierExport\n");
    out
}

fn lean_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\n', "\\n")
}

fn lean_ident_from_name(name: &str) -> String {
    let mut out = String::from("obligation_");
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.ends_with('_') {
        out.push('x');
    }
    out
}

fn render_coq_module(ir: &ProofExportIr) -> String {
    let mut out = String::new();
    out.push_str("(* Auto-generated by tarsier proof-export (Coq backend) *)\n");
    out.push_str("From Coq Require Import String List.\n");
    out.push_str("Import ListNotations.\n");
    out.push_str("Open Scope string_scope.\n\n");
    out.push_str("Module TarsierExport.\n\n");
    out.push_str(&format!(
        "Definition schema_version : nat := {}.\n",
        ir.schema_version
    ));
    out.push_str(&format!(
        "Definition protocol_file : string := \"{}\".\n",
        coq_escape(&ir.protocol_file)
    ));
    out.push_str(&format!(
        "Definition proof_engine : string := \"{}\".\n",
        coq_escape(&ir.proof_engine)
    ));
    out.push_str(&format!(
        "Definition solver_used : string := \"{}\".\n",
        coq_escape(&ir.solver_used)
    ));
    out.push_str(&format!(
        "Definition soundness : string := \"{}\".\n",
        coq_escape(&ir.soundness)
    ));
    if let Some(fairness) = &ir.fairness {
        out.push_str(&format!(
            "Definition fairness : option string := Some \"{}\".\n",
            coq_escape(fairness)
        ));
    } else {
        out.push_str("Definition fairness : option string := None.\n");
    }
    if let Some(k) = ir.induction_k {
        out.push_str(&format!(
            "Definition induction_k : option nat := Some {}.\n",
            k
        ));
    } else {
        out.push_str("Definition induction_k : option nat := None.\n");
    }
    if let Some(frame) = ir.frame {
        out.push_str(&format!(
            "Definition frame : option nat := Some {}.\n",
            frame
        ));
    } else {
        out.push_str("Definition frame : option nat := None.\n");
    }
    out.push_str("Definition committee_bounds : list (string * nat) := [\n");
    for (name, bound) in &ir.committee_bounds {
        out.push_str(&format!("  (\"{}\", {});\n", coq_escape(name), bound));
    }
    out.push_str("].\n\n");

    out.push_str("Definition obligations : list (string * string * string) := [\n");
    for ob in &ir.obligations {
        out.push_str(&format!(
            "  (\"{}\", \"{}\", \"{}\");\n",
            coq_escape(&ob.name),
            coq_escape(&ob.expected),
            coq_escape(&ob.smt2)
        ));
    }
    out.push_str("].\n\n");

    for ob in &ir.obligations {
        let lemma_name = coq_ident_from_name(&ob.name);
        out.push_str(&format!(
            "Lemma {} : True.\nProof. exact I. Qed.\n\n",
            lemma_name
        ));
    }
    out.push_str("End TarsierExport.\n");
    out
}

fn coq_escape(input: &str) -> String {
    input.replace('\"', "\"\"").replace('\n', "\\n")
}

fn coq_ident_from_name(name: &str) -> String {
    let mut out = String::from("obligation_");
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.ends_with('_') {
        out.push('x');
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tarsier_engine::pipeline::{ProofExportKind, ProofExportObligation};

    #[test]
    fn render_lean_module_contains_expected_sections() {
        let ir = ProofExportIr {
            schema_version: 1,
            kind: ProofExportKind::Safety,
            protocol_file: "pbft.trs".into(),
            proof_engine: "pdr".into(),
            fairness: None,
            induction_k: Some(12),
            frame: None,
            solver_used: "z3".into(),
            soundness: "strict".into(),
            committee_bounds: vec![("n".into(), 4), ("f".into(), 1)],
            obligations: vec![ProofExportObligation {
                name: "init_implies_inv".into(),
                expected: "unsat".into(),
                smt2: "(check-sat)".into(),
            }],
        };
        let lean = render_lean_module(&ir);
        assert!(lean.contains("namespace TarsierExport"));
        assert!(lean.contains("def protocolFile : String := \"pbft.trs\""));
        assert!(lean.contains("def obligations : List (String × String × String)"));
        assert!(lean.contains("theorem obligation_init_implies_inv : True := by"));
    }

    #[test]
    fn lean_escape_escapes_quotes_backslashes_and_newlines() {
        let escaped = lean_escape("a\"b\\c\nd");
        assert_eq!(escaped, "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn render_coq_module_contains_expected_sections() {
        let ir = ProofExportIr {
            schema_version: 1,
            kind: ProofExportKind::Safety,
            protocol_file: "pbft.trs".into(),
            proof_engine: "pdr".into(),
            fairness: None,
            induction_k: Some(12),
            frame: None,
            solver_used: "z3".into(),
            soundness: "strict".into(),
            committee_bounds: vec![("n".into(), 4), ("f".into(), 1)],
            obligations: vec![ProofExportObligation {
                name: "init_implies_inv".into(),
                expected: "unsat".into(),
                smt2: "(check-sat)".into(),
            }],
        };
        let coq = render_coq_module(&ir);
        assert!(coq.contains("Module TarsierExport."));
        assert!(coq.contains("Definition protocol_file : string := \"pbft.trs\"."));
        assert!(coq.contains("Definition obligations : list (string * string * string)"));
        assert!(coq.contains("Lemma obligation_init_implies_inv : True."));
    }

    #[test]
    fn coq_escape_escapes_quotes_and_newlines() {
        let escaped = coq_escape("a\"b\nc");
        assert_eq!(escaped, "a\"\"b\\nc");
    }

    #[cfg(unix)]
    #[test]
    fn run_certcheck_reports_pass_for_valid_json_report() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("tarsier-proof-export-certcheck-pass-{unique}"));
        fs::create_dir_all(&base).expect("temp dir should be created");

        let script_path = base.join("fake-certcheck.sh");
        let script = r#"#!/bin/sh
set -eu
REPORT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--json-report" ]; then
    REPORT="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"overall":"pass"}' > "$REPORT"
"#;
        fs::write(&script_path, script).expect("script should be written");
        let mut perms = fs::metadata(&script_path)
            .expect("script metadata should be readable")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("script should be executable");

        let result = run_certcheck(&base, &script_path).expect("certcheck wrapper should pass");
        assert_eq!(result.overall, "pass");
        assert_eq!(result.binary, script_path.display().to_string());

        fs::remove_dir_all(&base).expect("temp dir cleanup should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn run_certcheck_fails_when_report_overall_is_fail() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("tarsier-proof-export-certcheck-fail-{unique}"));
        fs::create_dir_all(&base).expect("temp dir should be created");

        let script_path = base.join("fake-certcheck.sh");
        let script = r#"#!/bin/sh
set -eu
REPORT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--json-report" ]; then
    REPORT="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"overall":"fail"}' > "$REPORT"
"#;
        fs::write(&script_path, script).expect("script should be written");
        let mut perms = fs::metadata(&script_path)
            .expect("script metadata should be readable")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("script should be executable");

        let err = run_certcheck(&base, &script_path).expect_err("certcheck wrapper should fail");
        let msg = format!("{err:?}");
        assert!(msg.contains("overall='fail'"));

        fs::remove_dir_all(&base).expect("temp dir cleanup should succeed");
    }
}
