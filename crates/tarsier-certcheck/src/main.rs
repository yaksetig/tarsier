use clap::Parser;
use miette::{Context, IntoDiagnostic};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tarsier_proof_kernel::{check_bundle_integrity, CERTIFICATE_SCHEMA_VERSION};

#[derive(Debug, Parser)]
#[command(
    name = "tarsier-certcheck",
    about = "Minimal standalone checker for Tarsier proof certificates"
)]
struct Cli {
    /// Path to the certificate bundle directory.
    bundle: PathBuf,

    /// Comma-separated solver commands (e.g. z3,cvc5).
    #[arg(long, default_value = "z3,cvc5")]
    solvers: String,

    /// Require at least two distinct solvers for replay.
    #[arg(long, default_value_t = false)]
    require_two_solvers: bool,

    /// Optional directory for emitted raw solver proof objects.
    #[arg(long)]
    emit_proofs: Option<PathBuf>,

    /// Require non-empty/balanced proof objects for UNSAT obligations.
    #[arg(long, default_value_t = false)]
    require_proofs: bool,

    /// Optional external proof checker executable.
    ///
    /// The checker is invoked with:
    /// `--solver <name> --smt2 <file> --proof <file>`
    #[arg(long)]
    proof_checker: Option<PathBuf>,

    /// Optional JSON report output path.
    #[arg(long)]
    json_report: Option<PathBuf>,

    /// Stop replay at the first failed obligation.
    #[arg(long)]
    fail_fast: bool,
}

#[derive(Debug, Serialize)]
struct ObligationReplayReport {
    name: String,
    expected: String,
    file: String,
    solver_results: BTreeMap<String, SolverOutcome>,
    status: String,
}

#[derive(Debug, Serialize)]
struct CheckerReport {
    schema_version: u32,
    checker: String,
    bundle: String,
    cert_kind: String,
    proof_engine: String,
    induction_k: Option<usize>,
    solver_used: String,
    soundness: String,
    fairness: Option<String>,
    solvers: Vec<String>,
    integrity_ok: bool,
    integrity_issues: Vec<String>,
    obligations: Vec<ObligationReplayReport>,
    per_solver: BTreeMap<String, SolverSummary>,
    passed: usize,
    failed: usize,
    overall: String,
}

#[derive(Debug, Serialize, Clone)]
struct SolverOutcome {
    status: String,
    actual: Option<String>,
    message: Option<String>,
    proof_status: Option<String>,
    proof_message: Option<String>,
    proof_file: Option<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
struct SolverSummary {
    passed: usize,
    failed: usize,
    errors: usize,
    proof_passed: usize,
    proof_failed: usize,
    proof_errors: usize,
    proof_skipped: usize,
}

fn parse_solver_list(raw: &str) -> Vec<String> {
    let mut solvers: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    solvers.sort();
    solvers.dedup();
    solvers
}

fn solver_output_excerpt(stdout: &str, max_chars: usize) -> String {
    let mut excerpt = String::new();
    for ch in stdout.chars().take(max_chars) {
        excerpt.push(ch);
    }
    if stdout.chars().count() > max_chars {
        excerpt.push_str("...");
    }
    excerpt.replace('\n', "\\n")
}

fn parse_solver_result_token(stdout: &str) -> miette::Result<String> {
    let mut tokens = Vec::new();
    for raw in stdout.lines().flat_map(|line| line.split_whitespace()) {
        let normalized = raw
            .trim_matches(|c: char| !c.is_ascii_alphabetic())
            .to_ascii_lowercase();
        if normalized == "sat" || normalized == "unsat" || normalized == "unknown" {
            tokens.push(normalized);
        }
    }

    let distinct: BTreeSet<String> = tokens.into_iter().collect();
    if distinct.is_empty() {
        miette::bail!(
            "malformed solver output: expected one of sat/unsat/unknown, got `{}`",
            solver_output_excerpt(stdout, 160)
        );
    }
    if distinct.len() > 1 {
        miette::bail!(
            "malformed solver output: conflicting result tokens {:?}",
            distinct
        );
    }

    Ok(distinct
        .into_iter()
        .next()
        .expect("set should contain one token"))
}

fn parse_solver_result_prefix(stdout: &str) -> miette::Result<String> {
    let token = stdout
        .lines()
        .flat_map(|line| line.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("");
    let normalized = token
        .trim_matches(|c: char| !c.is_ascii_alphabetic())
        .to_ascii_lowercase();
    if normalized == "sat" || normalized == "unsat" || normalized == "unknown" {
        return Ok(normalized);
    }
    miette::bail!(
        "malformed solver output: expected sat/unsat/unknown prefix, got `{}`",
        solver_output_excerpt(stdout, 160)
    );
}

fn run_external_solver_on_file(solver_cmd: &str, smt_file: &Path) -> miette::Result<String> {
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

    let output = cmd.output().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to execute solver '{}' on {}",
            solver_cmd,
            smt_file.display()
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver '{}' failed on {}: {}",
            solver_cmd,
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_solver_result_token(&stdout)
}

fn augment_query_for_proof(script: &str, solver_cmd: &str) -> String {
    let mut out = String::new();
    match solver_cmd {
        "z3" | "cvc5" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        _ => {}
    }

    // Existing obligations already have check-sat/exit.
    let body = script.replace("(exit)\n", "").replace("(exit)", "");
    out.push_str(&body);
    if !body.contains("(check-sat)") {
        out.push_str("\n(check-sat)\n");
    }
    out.push_str("(get-proof)\n");
    out.push_str("(exit)\n");
    out
}

fn run_external_solver_with_proof(
    solver_cmd: &str,
    smt_file: &Path,
) -> miette::Result<(String, String)> {
    let base_script = fs::read_to_string(smt_file).into_diagnostic()?;
    let proof_script = augment_query_for_proof(&base_script, solver_cmd);

    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2").arg("-in");
        }
        "cvc5" => {
            cmd.arg("--lang").arg("smt2").arg("-");
        }
        _ => {
            miette::bail!(
                "Proof extraction for solver '{}' is unsupported; use z3 or cvc5.",
                solver_cmd
            );
        }
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().into_diagnostic()?;
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(proof_script.as_bytes()).into_diagnostic()?;
    }
    let output = child.wait_with_output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver '{}' failed on {} while extracting proofs: {}",
            solver_cmd,
            smt_file.display(),
            stderr.trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let token = parse_solver_result_prefix(&stdout)?;
    Ok((token, stdout))
}

fn proof_object_looks_nontrivial(proof_text: &str) -> bool {
    let non_empty_lines = proof_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
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

fn run_external_proof_checker(
    checker: &Path,
    solver_cmd: &str,
    smt_file: &Path,
    proof_file: &Path,
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
            "proof checker '{}' rejected {} with {}: {}",
            checker.display(),
            smt_file.display(),
            proof_file.display(),
            stderr.trim()
        );
    }
    Ok(())
}

fn write_report(path: &Path, report: &CheckerReport) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).into_diagnostic()?;
        }
    }
    let json = serde_json::to_string_pretty(report).into_diagnostic()?;
    fs::write(path, json).into_diagnostic()?;
    Ok(())
}

fn ensure_solver_summary<'a>(
    per_solver: &'a mut BTreeMap<String, SolverSummary>,
    solver: &str,
) -> &'a mut SolverSummary {
    per_solver.entry(solver.to_string()).or_default()
}

fn record_solver_outcome(
    solver: &str,
    expected: &str,
    result: miette::Result<String>,
    per_solver: &mut BTreeMap<String, SolverSummary>,
) -> SolverOutcome {
    match result {
        Ok(actual) => {
            if actual == expected {
                ensure_solver_summary(per_solver, solver).passed += 1;
                SolverOutcome {
                    status: "pass".into(),
                    actual: Some(actual),
                    message: None,
                    proof_status: None,
                    proof_message: None,
                    proof_file: None,
                }
            } else {
                ensure_solver_summary(per_solver, solver).failed += 1;
                SolverOutcome {
                    status: "fail".into(),
                    actual: Some(actual),
                    message: Some(format!("expected {expected}")),
                    proof_status: None,
                    proof_message: None,
                    proof_file: None,
                }
            }
        }
        Err(err) => {
            ensure_solver_summary(per_solver, solver).errors += 1;
            SolverOutcome {
                status: "error".into(),
                actual: None,
                message: Some(err.to_string()),
                proof_status: None,
                proof_message: None,
                proof_file: None,
            }
        }
    }
}

fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    let solver_cmds = parse_solver_list(&cli.solvers);
    if solver_cmds.is_empty() {
        miette::bail!("No solver commands provided. Use --solvers z3,cvc5");
    }
    if cli.require_two_solvers && solver_cmds.len() < 2 {
        miette::bail!(
            "--require-two-solvers needs at least 2 distinct solver commands; got {}.",
            solver_cmds.len()
        );
    }
    if let Some(checker) = &cli.proof_checker {
        if !checker.exists() {
            miette::bail!("--proof-checker path does not exist: {}", checker.display());
        }
    }
    let need_proof_objects =
        cli.emit_proofs.is_some() || cli.require_proofs || cli.proof_checker.is_some();
    if let Some(root) = &cli.emit_proofs {
        fs::create_dir_all(root).into_diagnostic()?;
    }

    let integrity = check_bundle_integrity(&cli.bundle).into_diagnostic()?;
    let metadata = integrity.metadata;

    let mut integrity_issues = Vec::new();
    for issue in integrity.issues {
        let line = format!("[{}] {}", issue.code, issue.message);
        integrity_issues.push(line.clone());
        println!("[FAIL] integrity: {line}");
    }

    let mut replay_reports = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut per_solver: BTreeMap<String, SolverSummary> = BTreeMap::new();
    for solver in &solver_cmds {
        per_solver.insert(solver.clone(), SolverSummary::default());
    }

    if integrity_issues.is_empty() {
        println!(
            "[PASS] integrity: schema={}, kind={}, engine={}, obligations={}",
            metadata.schema_version,
            metadata.kind,
            metadata.proof_engine,
            metadata.obligations.len()
        );

        for obligation in &metadata.obligations {
            let smt_path = cli.bundle.join(&obligation.file);
            let mut solver_results = BTreeMap::new();
            let mut ok = true;

            for solver_cmd in &solver_cmds {
                let outcome = if need_proof_objects {
                    match run_external_solver_with_proof(solver_cmd, &smt_path) {
                        Ok((actual, proof_text)) => {
                            let mut outcome = record_solver_outcome(
                                solver_cmd,
                                &obligation.expected,
                                Ok(actual),
                                &mut per_solver,
                            );

                            if obligation.expected != "unsat" {
                                ensure_solver_summary(&mut per_solver, solver_cmd).proof_skipped +=
                                    1;
                                outcome.proof_status = Some("skipped".into());
                            } else if cli.require_proofs
                                && !proof_object_looks_nontrivial(&proof_text)
                            {
                                ensure_solver_summary(&mut per_solver, solver_cmd).proof_failed +=
                                    1;
                                outcome.proof_status = Some("fail".into());
                                outcome.proof_message =
                                    Some("UNSAT proof object is empty or malformed".into());
                                outcome.status = "fail".into();
                                if outcome.message.is_none() {
                                    outcome.message = Some("expected unsat".into());
                                }
                            } else {
                                let mut proof_file_for_check: Option<PathBuf> = None;
                                let mut temp_proof_file: Option<PathBuf> = None;

                                if let Some(root) = &cli.emit_proofs {
                                    let solver_dir = root.join(solver_cmd);
                                    if let Err(err) = fs::create_dir_all(&solver_dir) {
                                        ensure_solver_summary(&mut per_solver, solver_cmd)
                                            .proof_errors += 1;
                                        outcome.proof_status = Some("error".into());
                                        outcome.proof_message =
                                            Some(format!("failed creating proof dir: {err}"));
                                        outcome.status = "error".into();
                                    } else {
                                        let proof_path =
                                            solver_dir.join(format!("{}.proof", obligation.name));
                                        match fs::write(&proof_path, &proof_text) {
                                            Ok(()) => {
                                                outcome.proof_file =
                                                    Some(proof_path.display().to_string());
                                                proof_file_for_check = Some(proof_path);
                                            }
                                            Err(err) => {
                                                ensure_solver_summary(
                                                    &mut per_solver,
                                                    solver_cmd,
                                                )
                                                .proof_errors += 1;
                                                outcome.proof_status = Some("error".into());
                                                outcome.proof_message = Some(format!(
                                                    "failed writing proof file: {err}"
                                                ));
                                                outcome.status = "error".into();
                                            }
                                        }
                                    }
                                } else if cli.proof_checker.is_some() {
                                    let millis = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis();
                                    let temp_path = std::env::temp_dir().join(format!(
                                        "tarsier-proof-{}-{}-{}-{}.proof",
                                        std::process::id(),
                                        solver_cmd,
                                        obligation.name,
                                        millis
                                    ));
                                    match fs::write(&temp_path, &proof_text) {
                                        Ok(()) => {
                                            outcome.proof_file =
                                                Some(temp_path.display().to_string());
                                            proof_file_for_check = Some(temp_path.clone());
                                            temp_proof_file = Some(temp_path);
                                        }
                                        Err(err) => {
                                            ensure_solver_summary(&mut per_solver, solver_cmd)
                                                .proof_errors += 1;
                                            outcome.proof_status = Some("error".into());
                                            outcome.proof_message = Some(format!(
                                                "failed writing temporary proof file: {err}"
                                            ));
                                            outcome.status = "error".into();
                                        }
                                    }
                                }

                                if outcome.proof_status.is_none() {
                                    if let Some(checker) = cli.proof_checker.as_ref() {
                                        if let Some(proof_path) = &proof_file_for_check {
                                            match run_external_proof_checker(
                                                checker, solver_cmd, &smt_path, proof_path,
                                            ) {
                                                Ok(()) => {
                                                    ensure_solver_summary(
                                                        &mut per_solver,
                                                        solver_cmd,
                                                    )
                                                    .proof_passed += 1;
                                                    outcome.proof_status = Some("pass".into());
                                                    outcome.proof_message = Some(format!(
                                                        "validated by {}",
                                                        checker.display()
                                                    ));
                                                }
                                                Err(err) => {
                                                    ensure_solver_summary(
                                                        &mut per_solver,
                                                        solver_cmd,
                                                    )
                                                    .proof_failed += 1;
                                                    outcome.proof_status = Some("fail".into());
                                                    outcome.proof_message = Some(err.to_string());
                                                    outcome.status = "fail".into();
                                                }
                                            }
                                        } else {
                                            ensure_solver_summary(&mut per_solver, solver_cmd)
                                                .proof_failed += 1;
                                            outcome.proof_status = Some("fail".into());
                                            outcome.proof_message = Some(
                                                "no proof file available for --proof-checker"
                                                    .into(),
                                            );
                                            outcome.status = "fail".into();
                                        }
                                    } else {
                                        ensure_solver_summary(&mut per_solver, solver_cmd)
                                            .proof_passed += 1;
                                        outcome.proof_status = Some("captured".into());
                                    }
                                }

                                if let Some(temp_path) = temp_proof_file {
                                    let _ = fs::remove_file(temp_path);
                                }
                            }

                            outcome
                        }
                        Err(err) => {
                            let mut outcome = record_solver_outcome(
                                solver_cmd,
                                &obligation.expected,
                                Err(err),
                                &mut per_solver,
                            );
                            ensure_solver_summary(&mut per_solver, solver_cmd).proof_errors += 1;
                            outcome.proof_status = Some("error".into());
                            outcome.proof_message = Some("proof extraction failed".into());
                            outcome
                        }
                    }
                } else {
                    record_solver_outcome(
                        solver_cmd,
                        &obligation.expected,
                        run_external_solver_on_file(solver_cmd, &smt_path),
                        &mut per_solver,
                    )
                };
                match (&outcome.status[..], &outcome.actual, &outcome.message) {
                    ("pass", Some(actual), _) => {
                        println!(
                            "[PASS] {} :: {} expected {} got {}",
                            solver_cmd, obligation.name, obligation.expected, actual
                        );
                    }
                    ("fail", Some(actual), Some(msg)) => {
                        ok = false;
                        println!(
                            "[FAIL] {} :: {} {} got {}",
                            solver_cmd, obligation.name, msg, actual
                        );
                    }
                    ("error", _, Some(msg)) => {
                        ok = false;
                        println!(
                            "[ERROR] {} :: {} could not be checked ({})",
                            solver_cmd, obligation.name, msg
                        );
                    }
                    _ => {
                        ok = false;
                        println!(
                            "[ERROR] {} :: {} had an internal outcome serialization error",
                            solver_cmd, obligation.name
                        );
                    }
                }
                if let Some(proof_status) = outcome.proof_status.as_deref() {
                    let details = outcome
                        .proof_message
                        .as_deref()
                        .map(|msg| format!(" ({msg})"))
                        .unwrap_or_default();
                    println!(
                        "[{}] {} :: {} proof {}{}",
                        proof_status.to_ascii_uppercase(),
                        solver_cmd,
                        obligation.name,
                        proof_status,
                        details
                    );
                }
                if outcome.status != "pass" {
                    ok = false;
                }
                solver_results.insert(solver_cmd.clone(), outcome);
            }

            if ok {
                passed += 1;
            } else {
                failed += 1;
            }

            replay_reports.push(ObligationReplayReport {
                name: obligation.name.clone(),
                expected: obligation.expected.clone(),
                file: obligation.file.clone(),
                solver_results,
                status: if ok { "pass".into() } else { "fail".into() },
            });

            if cli.fail_fast && failed > 0 {
                break;
            }
        }
    }

    let overall = if integrity_issues.is_empty() && failed == 0 {
        "pass"
    } else {
        "fail"
    }
    .to_string();

    let report = CheckerReport {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        checker: "tarsier-certcheck".into(),
        bundle: cli.bundle.display().to_string(),
        cert_kind: metadata.kind,
        proof_engine: metadata.proof_engine,
        induction_k: metadata.induction_k,
        solver_used: metadata.solver_used,
        soundness: metadata.soundness,
        fairness: metadata.fairness,
        solvers: solver_cmds,
        integrity_ok: integrity_issues.is_empty(),
        integrity_issues,
        obligations: replay_reports,
        per_solver,
        passed,
        failed,
        overall,
    };

    if let Some(path) = &cli.json_report {
        write_report(path, &report)?;
        println!("JSON report written to {}", path.display());
    }

    if report.integrity_ok {
        println!(
            "Replay summary: {} passed, {} failed",
            report.passed, report.failed
        );
        for (solver, summary) in &report.per_solver {
            println!(
                "  solver={} sat:pass={} fail={} err={} proof:pass={} fail={} err={} skipped={}",
                solver,
                summary.passed,
                summary.failed,
                summary.errors,
                summary.proof_passed,
                summary.proof_failed,
                summary.proof_errors,
                summary.proof_skipped
            );
        }
    }

    if report.overall == "pass" {
        println!("Certificate check PASSED.");
        Ok(())
    } else {
        miette::bail!("Certificate check FAILED.");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        augment_query_for_proof, parse_solver_list, parse_solver_result_prefix,
        parse_solver_result_token, proof_object_looks_nontrivial, record_solver_outcome,
        run_external_solver_on_file, SolverSummary,
    };
    use miette::miette;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parse_solver_list_dedups_and_sorts() {
        let solvers = parse_solver_list("cvc5, z3,cvc5 ,,z3");
        assert_eq!(solvers, vec!["cvc5".to_string(), "z3".to_string()]);
    }

    #[test]
    fn first_solver_token_uses_first_non_empty_token() {
        assert_eq!(
            parse_solver_result_token("\n  unsat\n(model ...)\n")
                .expect("unsat output should parse"),
            "unsat"
        );
    }

    #[test]
    fn parse_solver_result_rejects_missing_result_token() {
        let err = parse_solver_result_token("warning: something happened\n")
            .expect_err("missing result token should fail");
        let msg = err.to_string();
        assert!(msg.contains("malformed solver output"));
    }

    #[test]
    fn parse_solver_result_rejects_conflicting_tokens() {
        let err = parse_solver_result_token("sat\nunsat\n")
            .expect_err("conflicting result token should fail");
        let msg = err.to_string();
        assert!(msg.contains("conflicting result tokens"));
    }

    #[test]
    fn parse_solver_result_prefix_reads_first_token_for_proof_stream() {
        let parsed = parse_solver_result_prefix("unsat\n(proof\n  (step)\n)\n")
            .expect("proof stream prefix should parse");
        assert_eq!(parsed, "unsat");
    }

    #[test]
    fn augment_query_for_proof_adds_get_proof_and_keeps_single_check_sat() {
        let query = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let augmented = augment_query_for_proof(query, "z3");
        assert!(augmented.contains("(set-option :produce-proofs true)"));
        assert!(augmented.contains("(get-proof)"));
        assert_eq!(augmented.matches("(check-sat)").count(), 1);
        assert!(augmented.trim_end().ends_with("(exit)"));
    }

    #[test]
    fn proof_object_nontrivial_heuristic_rejects_empty_or_malformed() {
        assert!(!proof_object_looks_nontrivial("unsat\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(error \"oops\")\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(abc\n"));
    }

    #[test]
    fn proof_object_nontrivial_heuristic_accepts_balanced_structure() {
        let proof = "unsat\n(proof\n  (step1)\n)\n";
        assert!(proof_object_looks_nontrivial(proof));
    }

    #[test]
    fn record_solver_outcome_tracks_per_solver_totals() {
        let mut per_solver = BTreeMap::<String, SolverSummary>::new();
        let pass = record_solver_outcome("z3", "unsat", Ok("unsat".into()), &mut per_solver);
        let fail = record_solver_outcome("z3", "unsat", Ok("sat".into()), &mut per_solver);
        let err = record_solver_outcome("cvc5", "unsat", Err(miette!("boom")), &mut per_solver);

        assert_eq!(pass.status, "pass");
        assert_eq!(fail.status, "fail");
        assert_eq!(err.status, "error");

        let z3 = per_solver.get("z3").expect("z3 summary should exist");
        assert_eq!(z3.passed, 1);
        assert_eq!(z3.failed, 1);
        assert_eq!(z3.errors, 0);

        let cvc5 = per_solver.get("cvc5").expect("cvc5 summary should exist");
        assert_eq!(cvc5.passed, 0);
        assert_eq!(cvc5.failed, 0);
        assert_eq!(cvc5.errors, 1);
    }

    fn tmp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        path.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
        path
    }

    #[cfg(unix)]
    #[test]
    fn external_solver_runner_reads_sat_token() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("tarsier_certcheck_solver");
        fs::create_dir_all(&dir).expect("temp dir should be created");

        let solver = dir.join("solver.sh");
        let smt = dir.join("query.smt2");
        fs::write(
            &solver,
            "#!/usr/bin/env bash\necho unsat\necho \"(proof...)\"\n",
        )
        .expect("solver script should be written");
        fs::set_permissions(&solver, fs::Permissions::from_mode(0o755))
            .expect("solver script should be executable");
        fs::write(
            &smt,
            "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n",
        )
        .expect("query should be written");

        let token = run_external_solver_on_file(
            solver
                .to_str()
                .expect("temporary script path should be valid UTF-8"),
            &smt,
        )
        .expect("solver run should succeed");
        assert_eq!(token, "unsat");

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn external_solver_runner_rejects_malformed_output() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("tarsier_certcheck_solver_bad");
        fs::create_dir_all(&dir).expect("temp dir should be created");

        let solver = dir.join("solver.sh");
        let smt = dir.join("query.smt2");
        fs::write(&solver, "#!/usr/bin/env bash\necho \"no result here\"\n")
            .expect("solver script should be written");
        fs::set_permissions(&solver, fs::Permissions::from_mode(0o755))
            .expect("solver script should be executable");
        fs::write(
            &smt,
            "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n",
        )
        .expect("query should be written");

        let err = run_external_solver_on_file(
            solver
                .to_str()
                .expect("temporary script path should be valid UTF-8"),
            &smt,
        )
        .expect_err("malformed solver output should be rejected");
        assert!(err.to_string().contains("malformed solver output"));

        fs::remove_dir_all(&dir).ok();
    }
}
