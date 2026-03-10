//! End-to-end tests for invariant inference (INV-06).
//!
//! Covers: auto-strengthened proving, solver parity (Z3 vs cvc5),
//! safe/buggy protocol corpus, and PDR engine compatibility.

mod common;

use tarsier_engine::pipeline::verification::prove_safety_with_auto_strengthen;
use tarsier_engine::pipeline::{self, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
use tarsier_engine::result::UnboundedSafetyResult;

fn default_options() -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 10,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

// ---------------------------------------------------------------------------
// Auto-strengthen e2e: safe protocols
// ---------------------------------------------------------------------------

#[test]
fn auto_strengthen_reliable_broadcast_safe() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast.trs")
        .expect("read reliable_broadcast.trs");
    let result =
        prove_safety_with_auto_strengthen(&source, "reliable_broadcast.trs", &default_options())
            .expect("prove should succeed");
    match &result {
        UnboundedSafetyResult::Safe { induction_k } => {
            assert!(*induction_k >= 1, "expected k >= 1, got {induction_k}");
        }
        other => panic!("Expected SAFE, got: {other}"),
    }
}

#[test]
fn auto_strengthen_pbft_simple_safe() {
    let source =
        std::fs::read_to_string("../../examples/pbft_simple.trs").expect("read pbft_simple.trs");
    let result = prove_safety_with_auto_strengthen(&source, "pbft_simple.trs", &default_options())
        .expect("prove should succeed");
    match &result {
        UnboundedSafetyResult::Safe { induction_k } => {
            assert!(*induction_k >= 1);
        }
        other => panic!("Expected SAFE, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Auto-strengthen e2e: buggy protocol should still detect violation
// ---------------------------------------------------------------------------

#[test]
fn auto_strengthen_reliable_broadcast_buggy_detects_violation() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast_buggy.trs")
        .expect("read reliable_broadcast_buggy.trs");
    let result = prove_safety_with_auto_strengthen(
        &source,
        "reliable_broadcast_buggy.trs",
        &default_options(),
    )
    .expect("prove should complete");
    match &result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(
                !trace.param_values.is_empty(),
                "trace should have param values"
            );
        }
        other => panic!("Expected UNSAFE for buggy protocol, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Solver parity: Z3 vs cvc5 should agree on auto-strengthen results
// ---------------------------------------------------------------------------

#[test]
fn solver_parity_auto_strengthen_reliable_broadcast() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast.trs")
        .expect("read reliable_broadcast.trs");

    let z3_options = PipelineOptions {
        solver: SolverChoice::Z3,
        ..default_options()
    };
    let z3_result =
        prove_safety_with_auto_strengthen(&source, "reliable_broadcast.trs", &z3_options)
            .expect("Z3 prove");

    let cvc5_options = PipelineOptions {
        solver: SolverChoice::Cvc5,
        ..default_options()
    };
    let cvc5_result =
        prove_safety_with_auto_strengthen(&source, "reliable_broadcast.trs", &cvc5_options);

    // cvc5 may not be available; if it is, results should agree.
    if let Ok(cvc5_result) = cvc5_result {
        let z3_safe = matches!(z3_result, UnboundedSafetyResult::Safe { .. });
        let cvc5_safe = matches!(cvc5_result, UnboundedSafetyResult::Safe { .. });
        assert_eq!(
            z3_safe, cvc5_safe,
            "Z3 and cvc5 should agree: Z3={z3_result}, cvc5={cvc5_result}"
        );
    }
}

// ---------------------------------------------------------------------------
// Auto-strengthen with PDR engine
// ---------------------------------------------------------------------------

#[test]
fn auto_strengthen_pdr_reliable_broadcast_safe() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast.trs")
        .expect("read reliable_broadcast.trs");
    let options = PipelineOptions {
        proof_engine: ProofEngine::Pdr,
        ..default_options()
    };
    let result = prove_safety_with_auto_strengthen(&source, "reliable_broadcast.trs", &options)
        .expect("prove should succeed");
    match &result {
        UnboundedSafetyResult::Safe { induction_k } => {
            assert!(*induction_k >= 1);
        }
        other => panic!("Expected SAFE with PDR, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Consistency: auto-strengthen and baseline should agree on verdicts
// ---------------------------------------------------------------------------

#[test]
fn auto_strengthen_agrees_with_baseline_safe() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast.trs")
        .expect("read reliable_broadcast.trs");
    let options = default_options();

    let baseline = pipeline::prove_safety(&source, "reliable_broadcast.trs", &options)
        .expect("baseline prove");
    let strengthened =
        prove_safety_with_auto_strengthen(&source, "reliable_broadcast.trs", &options)
            .expect("strengthened prove");

    let baseline_safe = matches!(baseline, UnboundedSafetyResult::Safe { .. });
    let strengthened_safe = matches!(strengthened, UnboundedSafetyResult::Safe { .. });
    assert_eq!(
        baseline_safe, strengthened_safe,
        "auto-strengthen and baseline should agree on safe/unsafe"
    );
}

#[test]
fn auto_strengthen_agrees_with_baseline_unsafe() {
    let source = std::fs::read_to_string("../../examples/reliable_broadcast_buggy.trs")
        .expect("read reliable_broadcast_buggy.trs");
    let options = default_options();

    let baseline = pipeline::prove_safety(&source, "reliable_broadcast_buggy.trs", &options)
        .expect("baseline prove");
    let strengthened =
        prove_safety_with_auto_strengthen(&source, "reliable_broadcast_buggy.trs", &options)
            .expect("strengthened prove");

    let baseline_unsafe = matches!(baseline, UnboundedSafetyResult::Unsafe { .. });
    let strengthened_unsafe = matches!(strengthened, UnboundedSafetyResult::Unsafe { .. });
    assert_eq!(
        baseline_unsafe, strengthened_unsafe,
        "auto-strengthen and baseline should agree on unsafe"
    );
}

// ---------------------------------------------------------------------------
// Library protocol corpus: auto-strengthen should not panic
// ---------------------------------------------------------------------------

#[test]
fn auto_strengthen_library_safe_protocols_complete_without_panic() {
    let safe_protocols = &[
        "../../examples/library/reliable_broadcast_safe.trs",
        "../../examples/library/pbft_simple_safe.trs",
    ];
    let options = PipelineOptions {
        timeout_secs: 15,
        max_depth: 6,
        ..default_options()
    };
    for path in safe_protocols {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // skip if file missing
        };
        let filename = path.rsplit('/').next().unwrap_or(path);
        let result = prove_safety_with_auto_strengthen(&source, filename, &options);
        assert!(
            result.is_ok(),
            "auto-strengthen should not error on {filename}: {:?}",
            result.err()
        );
    }
}
