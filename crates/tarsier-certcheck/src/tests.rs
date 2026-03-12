use super::{
    augment_query_for_proof, enforce_foundational_profile_requirements, is_truthy_flag,
    parse_solver_list, parse_solver_result_prefix, parse_solver_result_token,
    proof_object_looks_nontrivial, record_solver_outcome, run_external_solver_on_file,
    SolverSummary,
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
fn env_truthy_parses_expected_values() {
    assert!(is_truthy_flag("1"));
    assert!(is_truthy_flag("YES"));
    assert!(is_truthy_flag("true"));
    assert!(!is_truthy_flag("false"));
    assert!(!is_truthy_flag(""));
}

#[test]
fn foundational_profile_requires_cvc5_solver_and_carcara_gate() {
    let ok = vec!["z3".to_string(), "cvc5".to_string()];
    enforce_foundational_profile_requirements(&ok, false)
        .expect("z3+cvc5 with TARSIER_REQUIRE_CARCARA=1 should pass");

    let missing_cvc5 = vec!["z3".to_string()];
    let err = enforce_foundational_profile_requirements(&missing_cvc5, false)
        .expect_err("missing cvc5 should fail foundational profile checks");
    assert!(err.to_string().contains("requires cvc5"));
}

#[test]
fn first_solver_token_uses_first_non_empty_token() {
    assert_eq!(
        parse_solver_result_token("\n  unsat\n(model ...)\n").expect("unsat output should parse"),
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

#[test]
fn certcheck_dependency_boundary_guard() {
    let cargo_toml = include_str!("../Cargo.toml");
    let forbidden = [
        "tarsier-engine",
        "tarsier-ir",
        "tarsier-dsl",
        "tarsier-smt",
        "tarsier-prob",
        "z3",
    ];
    for dep in &forbidden {
        assert!(
            !cargo_toml.contains(dep),
            "tarsier-certcheck must not depend on '{}' — \
                 the standalone checker must remain independent of engine internals",
            dep
        );
    }
}
