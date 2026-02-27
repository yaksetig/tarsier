// Utility functions for governance workflows.

use miette::IntoDiagnostic;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tarsier_engine::pipeline::{
    FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_proof_kernel::{sha256_hex_bytes, CertificateMetadata};

use crate::CertificateBundleInput;

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
