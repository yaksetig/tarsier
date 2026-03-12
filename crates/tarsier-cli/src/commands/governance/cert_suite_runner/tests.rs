use super::*;
use std::time::Instant;

fn make_test_assumptions() -> CertSuiteAssumptions {
    CertSuiteAssumptions {
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        network_semantics: "dsl".into(),
        depth: 10,
        k: 12,
        timeout_secs: 60,
        cegar_iters: 0,
    }
}

fn make_test_entry_report() -> CertSuiteEntryReport {
    CertSuiteEntryReport {
        file: "test.trs".into(),
        family: Some("pbft".into()),
        class: Some("expected_safe".into()),
        variant: None,
        variant_group: None,
        verdict: "pending".into(),
        status: "pass".into(),
        triage: None,
        duration_ms: 0,
        assumptions: make_test_assumptions(),
        model_sha256_expected: None,
        model_sha256_actual: None,
        model_changed: false,
        notes: None,
        artifact_links: vec![],
        checks: vec![],
        errors: vec![],
    }
}

// -- write_artifact_text --

#[test]
fn write_artifact_text_creates_and_writes() {
    let dir = std::env::temp_dir().join(format!(
        "tarsier_test_write_artifact_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("test.txt");
    write_artifact_text(&path, "hello").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    let _ = std::fs::remove_dir_all(&dir);
}

// -- finalize_cert_suite_entry --

#[test]
fn finalize_entry_pass() {
    let mut entry = make_test_entry_report();
    let started = Instant::now();
    finalize_cert_suite_entry(&mut entry, started, None);
    assert_eq!(entry.status, "pass");
    assert_eq!(entry.verdict, "pass");
    assert!(entry.triage.is_none());
}

#[test]
fn finalize_entry_with_errors() {
    let mut entry = make_test_entry_report();
    entry.errors.push("something went wrong".into());
    let started = Instant::now();
    finalize_cert_suite_entry(&mut entry, started, None);
    assert_eq!(entry.status, "error");
}

#[test]
fn finalize_entry_with_failed_check() {
    let mut entry = make_test_entry_report();
    entry.checks.push(CertSuiteCheckReport {
        check: "verify".into(),
        expected: "safe".into(),
        actual: "unsafe".into(),
        status: "fail".into(),
        duration_ms: 0,
        triage: Some("engine_regression".into()),
        artifact_link: None,
        output: String::new(),
    });
    let started = Instant::now();
    finalize_cert_suite_entry(&mut entry, started, None);
    assert_eq!(entry.status, "fail");
}

// -- finalize_and_push_cert_suite_entry --

#[test]
fn finalize_and_push_increments_passed() {
    let mut reports = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut errors = 0;
    let entry = make_test_entry_report();
    finalize_and_push_cert_suite_entry(
        &mut reports,
        &mut passed,
        &mut failed,
        &mut errors,
        entry,
        Instant::now(),
        None,
    );
    assert_eq!(passed, 1);
    assert_eq!(failed, 0);
    assert_eq!(errors, 0);
    assert_eq!(reports.len(), 1);
}

#[test]
fn finalize_and_push_increments_failed() {
    let mut reports = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut errors = 0;
    let mut entry = make_test_entry_report();
    entry.checks.push(CertSuiteCheckReport {
        check: "verify".into(),
        expected: "safe".into(),
        actual: "unsafe".into(),
        status: "fail".into(),
        duration_ms: 0,
        triage: None,
        artifact_link: None,
        output: String::new(),
    });
    finalize_and_push_cert_suite_entry(
        &mut reports,
        &mut passed,
        &mut failed,
        &mut errors,
        entry,
        Instant::now(),
        None,
    );
    assert_eq!(passed, 0);
    assert_eq!(failed, 1);
}

#[test]
fn finalize_and_push_increments_errors() {
    let mut reports = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut errors = 0;
    let mut entry = make_test_entry_report();
    entry.errors.push("error".into());
    finalize_and_push_cert_suite_entry(
        &mut reports,
        &mut passed,
        &mut failed,
        &mut errors,
        entry,
        Instant::now(),
        None,
    );
    assert_eq!(passed, 0);
    assert_eq!(errors, 1);
}

// -- write_check_artifact --

#[test]
fn write_check_artifact_no_dir() {
    let result = write_check_artifact(None, "verify", "output text");
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn write_check_artifact_with_dir() {
    let dir = std::env::temp_dir().join(format!(
        "tarsier_test_check_artifact_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let result = write_check_artifact(Some(&dir), "verify", "output text");
    assert!(result.is_ok());
    let link = result.unwrap().unwrap();
    assert!(link.contains("check_verify.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

// -- render_suite_text --

#[test]
fn render_suite_text_empty() {
    let report = CertSuiteReport {
        schema_version: 2,
        manifest: "test.json".into(),
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        entries: vec![],
        passed: 0,
        failed: 0,
        errors: 0,
        triage: BTreeMap::new(),
        by_family: BTreeMap::new(),
        by_class: BTreeMap::new(),
        overall: "pass".into(),
    };
    let text = render_suite_text(&report);
    assert!(text.contains("CERTIFICATION SUITE"));
    assert!(text.contains("Manifest: test.json"));
    assert!(text.contains("Overall: pass"));
    assert!(text.contains("0 pass, 0 fail, 0 error"));
}

#[test]
fn render_suite_text_with_entry() {
    let mut report = CertSuiteReport {
        schema_version: 2,
        manifest: "test.json".into(),
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        entries: vec![make_test_entry_report()],
        passed: 1,
        failed: 0,
        errors: 0,
        triage: BTreeMap::new(),
        by_family: BTreeMap::new(),
        by_class: BTreeMap::new(),
        overall: "pass".into(),
    };
    report.entries[0].status = "pass".into();
    report.entries[0].verdict = "pass".into();
    let text = render_suite_text(&report);
    assert!(text.contains("[PASS]"));
    assert!(text.contains("test.trs"));
    assert!(text.contains("family=pbft"));
}

#[test]
fn render_suite_text_with_triage() {
    let mut triage = BTreeMap::new();
    triage.insert("model_change".to_string(), 2);
    let report = CertSuiteReport {
        schema_version: 2,
        manifest: "test.json".into(),
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        entries: vec![],
        passed: 0,
        failed: 2,
        errors: 0,
        triage,
        by_family: BTreeMap::new(),
        by_class: BTreeMap::new(),
        overall: "fail".into(),
    };
    let text = render_suite_text(&report);
    assert!(text.contains("Failure triage:"));
    assert!(text.contains("model_change: 2"));
}
