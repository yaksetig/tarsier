use std::path::PathBuf;

use tarsier_conformance::adapters::{adapt_trace, AdapterKind};
use tarsier_conformance::checker::{ConformanceChecker, ConformanceMode, ViolationKind};
use tarsier_ir::threshold_automaton::ThresholdAutomaton;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_model() -> ThresholdAutomaton {
    let root = workspace_root();
    let model = root.join("crates/tarsier-conformance/tests/fixtures/simple_vote.trs");
    let source = std::fs::read_to_string(&model).expect("read simple_vote model");
    let filename = model.display().to_string();
    let program = tarsier_dsl::parse(&source, &filename).expect("parse model");
    tarsier_ir::lowering::lower(&program).expect("lower model")
}

fn load_fixture(path: &str) -> String {
    let root = workspace_root();
    std::fs::read_to_string(root.join(path)).expect("read fixture")
}

fn check_fixture(
    model: &ThresholdAutomaton,
    adapter: AdapterKind,
    fixture: &str,
    mode: ConformanceMode,
) -> tarsier_conformance::checker::CheckResult {
    let raw = load_fixture(fixture);
    let runtime = adapt_trace(adapter, &raw).expect("adapt fixture");
    let checker = ConformanceChecker::new_with_mode(model, &runtime.params, mode);
    checker.check(&runtime)
}

#[test]
fn cometbft_fixture_passes_simple_vote() {
    let model = load_model();
    let result = check_fixture(
        &model,
        AdapterKind::CometBft,
        "examples/conformance/adapters/cometbft_simple_vote_pass.json",
        ConformanceMode::Strict,
    );
    assert!(result.passed, "violations: {:?}", result.violations);
}

#[test]
fn cometbft_guard_violation_is_detected() {
    let model = load_model();
    let result = check_fixture(
        &model,
        AdapterKind::CometBft,
        "examples/conformance/adapters/cometbft_simple_vote_fail_guard.json",
        ConformanceMode::Strict,
    );
    assert!(!result.passed, "expected guard violation");
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::GuardNotSatisfied),
        "expected GuardNotSatisfied, got {:?}",
        result.violations
    );
}

#[test]
fn strict_unknown_mapping_rejected_but_permissive_allows() {
    let model = load_model();
    let fixture = "examples/conformance/adapters/cometbft_unknown_mapping.json";

    let strict = check_fixture(
        &model,
        AdapterKind::CometBft,
        fixture,
        ConformanceMode::Strict,
    );
    assert!(!strict.passed, "strict mode should reject unknown mappings");
    assert!(
        strict
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::UnknownMessageType),
        "expected UnknownMessageType, got {:?}",
        strict.violations
    );

    let permissive = check_fixture(
        &model,
        AdapterKind::CometBft,
        fixture,
        ConformanceMode::Permissive,
    );
    assert!(
        permissive.passed,
        "permissive mode should allow unknown mapping fixture"
    );
}

#[test]
fn etcd_raft_fixture_passes_simple_vote() {
    let model = load_model();
    let result = check_fixture(
        &model,
        AdapterKind::EtcdRaft,
        "examples/conformance/adapters/etcd_raft_simple_vote_pass.json",
        ConformanceMode::Strict,
    );
    assert!(result.passed, "violations: {:?}", result.violations);
}

#[test]
fn etcd_raft_invalid_decide_context_fails_in_strict_mode() {
    let model = load_model();
    let result = check_fixture(
        &model,
        AdapterKind::EtcdRaft,
        "examples/conformance/adapters/etcd_raft_invalid_decide_context.json",
        ConformanceMode::Strict,
    );
    assert!(!result.passed, "expected strict decide-context violation");
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::InvalidDecideContext),
        "expected InvalidDecideContext, got {:?}",
        result.violations
    );
}

#[test]
fn tampered_adapter_payloads_fail_deterministically() {
    let comet_err = adapt_trace(
        AdapterKind::CometBft,
        &load_fixture("examples/conformance/adapters/cometbft_corrupted.json"),
    )
    .expect_err("corrupted cometbft trace should fail");
    let comet_msg = format!("{comet_err}");
    assert!(comet_msg.contains("cometbft"));
    assert!(comet_msg.contains("decode"));

    let raft_err = adapt_trace(
        AdapterKind::EtcdRaft,
        &load_fixture("examples/conformance/adapters/etcd_raft_corrupted.json"),
    )
    .expect_err("corrupted etcd-raft trace should fail");
    let raft_msg = format!("{raft_err}");
    assert!(raft_msg.contains("etcd-raft"));
    assert!(raft_msg.contains("decode"));
}
