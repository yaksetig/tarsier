//! Shared helpers used by governance command implementations.
//
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- chrono_utc_now --

    #[test]
    fn chrono_utc_now_iso_format() {
        let ts = chrono_utc_now();
        // Should look like "YYYY-MM-DDTHH:MM:SSZ"
        assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
        assert_eq!(ts.len(), 20, "timestamp should be 20 chars: {ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn chrono_utc_now_year_reasonable() {
        let ts = chrono_utc_now();
        let year: u32 = ts[0..4].parse().unwrap();
        assert!(year >= 2024 && year <= 2100);
    }

    // -- parse_solver_list --

    #[test]
    fn parse_solver_list_single() {
        assert_eq!(parse_solver_list("z3"), vec!["z3"]);
    }

    #[test]
    fn parse_solver_list_multiple() {
        assert_eq!(parse_solver_list("z3,cvc5"), vec!["z3", "cvc5"]);
    }

    #[test]
    fn parse_solver_list_with_spaces() {
        assert_eq!(parse_solver_list("z3 , cvc5"), vec!["z3", "cvc5"]);
    }

    #[test]
    fn parse_solver_list_empty_entries() {
        assert_eq!(parse_solver_list("z3,,cvc5,"), vec!["z3", "cvc5"]);
    }

    #[test]
    fn parse_solver_list_empty_string() {
        let result: Vec<String> = parse_solver_list("");
        assert!(result.is_empty());
    }

    // -- is_truthy_flag --

    #[test]
    fn is_truthy_flag_true_values() {
        for val in &["1", "true", "yes", "on", "TRUE", "Yes", "ON", " true "] {
            assert!(is_truthy_flag(val), "should be truthy: {val}");
        }
    }

    #[test]
    fn is_truthy_flag_false_values() {
        for val in &["0", "false", "no", "off", "", "maybe"] {
            assert!(!is_truthy_flag(val), "should be falsy: {val}");
        }
    }

    // -- has_independent_solver --

    #[test]
    fn has_independent_solver_true() {
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        assert!(has_independent_solver(&solvers, "z3"));
    }

    #[test]
    fn has_independent_solver_false() {
        let solvers = vec!["z3".to_string()];
        assert!(!has_independent_solver(&solvers, "z3"));
    }

    #[test]
    fn has_independent_solver_empty() {
        let solvers: Vec<String> = vec![];
        assert!(!has_independent_solver(&solvers, "z3"));
    }

    // -- proof_object_looks_nontrivial --

    #[test]
    fn proof_object_nontrivial_valid() {
        let proof = "(proof\n  (step1)\n  (step2)\n)";
        assert!(proof_object_looks_nontrivial(proof));
    }

    #[test]
    fn proof_object_trivial_single_line() {
        assert!(!proof_object_looks_nontrivial("unsat"));
    }

    #[test]
    fn proof_object_trivial_empty() {
        assert!(!proof_object_looks_nontrivial(""));
    }

    #[test]
    fn proof_object_error_text() {
        assert!(!proof_object_looks_nontrivial(
            "(error\n  unsupported\n)"
        ));
    }

    #[test]
    fn proof_object_unbalanced_parens() {
        assert!(!proof_object_looks_nontrivial("(\n)\n)"));
    }

    #[test]
    fn proof_object_no_parens() {
        assert!(!proof_object_looks_nontrivial("line1\nline2\nline3"));
    }

    // -- parse_solver_choice_checked --

    #[test]
    fn parse_solver_choice_checked_valid() {
        assert!(parse_solver_choice_checked("z3").is_ok());
        assert!(parse_solver_choice_checked("cvc5").is_ok());
    }

    #[test]
    fn parse_solver_choice_checked_invalid() {
        assert!(parse_solver_choice_checked("minisat").is_err());
    }

    // -- parse_soundness_mode_checked --

    #[test]
    fn parse_soundness_mode_checked_valid() {
        assert!(parse_soundness_mode_checked("strict").is_ok());
        assert!(parse_soundness_mode_checked("permissive").is_ok());
    }

    #[test]
    fn parse_soundness_mode_checked_invalid() {
        assert!(parse_soundness_mode_checked("relaxed").is_err());
    }

    // -- parse_proof_engine_checked --

    #[test]
    fn parse_proof_engine_checked_valid() {
        assert!(parse_proof_engine_checked("kinduction").is_ok());
        assert!(parse_proof_engine_checked("pdr").is_ok());
    }

    #[test]
    fn parse_proof_engine_checked_invalid() {
        assert!(parse_proof_engine_checked("bmc").is_err());
    }

    // -- parse_fairness_mode_checked --

    #[test]
    fn parse_fairness_mode_checked_valid() {
        assert!(parse_fairness_mode_checked("weak").is_ok());
        assert!(parse_fairness_mode_checked("strong").is_ok());
    }

    #[test]
    fn parse_fairness_mode_checked_invalid() {
        assert!(parse_fairness_mode_checked("fair").is_err());
    }

    // -- expected_matches --

    #[test]
    fn expected_matches_exact() {
        assert!(expected_matches("safe", "safe"));
    }

    #[test]
    fn expected_matches_case_insensitive() {
        assert!(expected_matches("SAFE", "safe"));
        assert!(expected_matches("Safe", "SAFE"));
    }

    #[test]
    fn expected_matches_with_whitespace() {
        assert!(expected_matches(" safe ", " SAFE "));
    }

    #[test]
    fn expected_matches_different() {
        assert!(!expected_matches("safe", "unsafe"));
    }

    // -- is_valid_sha256_hex --

    #[test]
    fn is_valid_sha256_hex_valid() {
        let hash = "a".repeat(64);
        assert!(is_valid_sha256_hex(&hash));
    }

    #[test]
    fn is_valid_sha256_hex_valid_mixed_case() {
        let hash = "aAbBcCdDeEfF0123456789".to_string() + &"0".repeat(42);
        assert!(is_valid_sha256_hex(&hash));
    }

    #[test]
    fn is_valid_sha256_hex_too_short() {
        assert!(!is_valid_sha256_hex("abcd"));
    }

    #[test]
    fn is_valid_sha256_hex_too_long() {
        let hash = "a".repeat(65);
        assert!(!is_valid_sha256_hex(&hash));
    }

    #[test]
    fn is_valid_sha256_hex_invalid_chars() {
        let hash = "g".repeat(64);
        assert!(!is_valid_sha256_hex(&hash));
    }

    // -- validate_foundational_profile_requirements --

    #[test]
    fn validate_foundational_requires_cvc5() {
        let solvers = vec!["z3".to_string()];
        assert!(validate_foundational_profile_requirements(&solvers, false).is_err());
    }

    #[test]
    fn validate_foundational_passes_with_cvc5() {
        let solvers = vec!["cvc5".to_string()];
        assert!(validate_foundational_profile_requirements(&solvers, false).is_ok());
    }
}
