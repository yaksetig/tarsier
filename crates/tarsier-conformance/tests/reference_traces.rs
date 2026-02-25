//! Integration tests that replay external JSON trace fixtures against
//! the `simple_vote.trs` model.

use std::path::PathBuf;

use tarsier_conformance::checker::{CheckResult, ConformanceChecker, ViolationKind};
use tarsier_ir::runtime_trace::RuntimeTrace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;

/// Parse and lower the fixture model.
fn load_model() -> (tarsier_dsl::ast::Program, ThresholdAutomaton) {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let model_path = manifest.join("tests/fixtures/simple_vote.trs");
    let source = std::fs::read_to_string(&model_path).expect("read simple_vote.trs");
    let filename = model_path.display().to_string();
    let program = tarsier_dsl::parse(&source, &filename).expect("parse simple_vote.trs");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower simple_vote.trs");
    (program, ta)
}

/// Load a trace fixture by name from tests/fixtures/.
fn load_trace(name: &str) -> RuntimeTrace {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let trace_path = manifest.join(format!("tests/fixtures/{name}"));
    let source =
        std::fs::read_to_string(&trace_path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&source).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Check a trace against the model and return the result.
fn check_trace(ta: &ThresholdAutomaton, trace: &RuntimeTrace) -> CheckResult {
    let checker = ConformanceChecker::new(ta, &trace.params);
    checker.check(trace)
}

// -----------------------------------------------------------------------
// Model smoke test
// -----------------------------------------------------------------------

#[test]
fn fixture_model_lowering_smoke() {
    let (_program, ta) = load_model();

    // Verify expected locations exist
    let loc_names: Vec<&str> = ta.locations.iter().map(|l| l.name.as_str()).collect();
    assert!(
        loc_names.contains(&"Process_waiting[decided=false,decision=false]"),
        "missing initial location; got: {loc_names:?}"
    );
    assert!(
        loc_names.contains(&"Process_done[decided=true,decision=true]"),
        "missing done location; got: {loc_names:?}"
    );
    assert!(
        loc_names.contains(&"Process_aborted[decided=false,decision=false]"),
        "missing aborted location; got: {loc_names:?}"
    );

    // Verify shared var
    let sv_names: Vec<&str> = ta.shared_vars.iter().map(|sv| sv.name.as_str()).collect();
    assert!(
        sv_names.contains(&"cnt_Vote@Process"),
        "missing cnt_Vote@Process; got: {sv_names:?}"
    );

    // Verify we have rules (at least the guarded and trivial ones)
    assert!(
        ta.rules.len() >= 2,
        "expected at least 2 rules, got {}",
        ta.rules.len()
    );
}

// -----------------------------------------------------------------------
// Trace fixture tests
// -----------------------------------------------------------------------

#[test]
fn valid_trace_passes() {
    let (_program, ta) = load_model();
    let trace = load_trace("valid_trace.json");
    let result = check_trace(&ta, &trace);
    assert!(
        result.passed,
        "expected PASS but got {} violation(s): {:?}",
        result.violations.len(),
        result.violations
    );
}

#[test]
fn guard_not_satisfied_fails() {
    let (_program, ta) = load_model();
    let trace = load_trace("guard_not_satisfied.json");
    let result = check_trace(&ta, &trace);
    assert!(!result.passed, "expected FAIL but got PASS");
    assert_eq!(result.violations.len(), 1, "expected exactly 1 violation");
    assert_eq!(
        result.violations[0].kind,
        ViolationKind::GuardNotSatisfied,
        "expected GuardNotSatisfied, got {:?}",
        result.violations[0].kind
    );
}

#[test]
fn no_matching_rule_fails() {
    let (_program, ta) = load_model();
    let trace = load_trace("no_matching_rule.json");
    let result = check_trace(&ta, &trace);
    assert!(!result.passed, "expected FAIL but got PASS");
    assert_eq!(result.violations.len(), 1, "expected exactly 1 violation");
    assert_eq!(
        result.violations[0].kind,
        ViolationKind::NoMatchingRule,
        "expected NoMatchingRule, got {:?}",
        result.violations[0].kind
    );
}

#[test]
fn multi_process_valid_passes() {
    let (_program, ta) = load_model();
    let trace = load_trace("multi_process_valid.json");
    let result = check_trace(&ta, &trace);
    assert!(
        result.passed,
        "expected PASS but got {} violation(s): {:?}",
        result.violations.len(),
        result.violations
    );
}

// -----------------------------------------------------------------------
// Reliable Broadcast conformance tests (end-to-end demo)
// -----------------------------------------------------------------------

fn load_rb_model() -> ThresholdAutomaton {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let model_path = workspace_root.join("examples/library/reliable_broadcast_safe.trs");
    let source = std::fs::read_to_string(&model_path).expect("read reliable_broadcast_safe.trs");
    let filename = model_path.display().to_string();
    let program =
        tarsier_dsl::parse(&source, &filename).expect("parse reliable_broadcast_safe.trs");
    tarsier_ir::lowering::lower(&program).expect("lower reliable_broadcast_safe.trs")
}

fn load_rb_trace(name: &str) -> RuntimeTrace {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let trace_path = workspace_root.join(format!("examples/conformance/traces/{name}"));
    let source =
        std::fs::read_to_string(&trace_path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&source).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

#[test]
fn rb_safe_trace_passes_conformance() {
    let ta = load_rb_model();
    let trace = load_rb_trace("rb_safe_n4_t1.json");
    let checker = ConformanceChecker::new(&ta, &trace.params);
    let result = checker.check(&trace);
    assert!(
        result.passed,
        "expected PASS but got {} violation(s): {:?}",
        result.violations.len(),
        result.violations
    );
}

#[test]
fn rb_byzantine_trace_passes_conformance() {
    let ta = load_rb_model();
    let trace = load_rb_trace("rb_byzantine_n4_t1.json");
    let checker = ConformanceChecker::new(&ta, &trace.params);
    let result = checker.check(&trace);
    assert!(
        result.passed,
        "expected PASS but got {} violation(s): {:?}",
        result.violations.len(),
        result.violations
    );
}

#[test]
fn rb_violation_trace_detects_violation() {
    let ta = load_rb_model();
    let trace = load_rb_trace("rb_violation_n4_t1.json");
    let checker = ConformanceChecker::new(&ta, &trace.params);
    let result = checker.check(&trace);
    assert!(!result.passed, "expected FAIL but got PASS");
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::NoMatchingRule),
        "expected NoMatchingRule violation, got: {:?}",
        result.violations
    );
}
