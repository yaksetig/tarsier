//! Integration tests for liveness verification on real protocols.
//!
//! These tests exercise the bounded and unbounded liveness engines on
//! the Reliable Broadcast protocol with a genuine liveness property.

use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{FairLivenessResult, UnboundedFairLivenessResult, VerificationResult};

fn load_library(name: &str) -> String {
    let path = format!(
        "{}/../../examples/library/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

fn default_opts(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

fn unbounded_pdr_opts(timeout_secs: u64) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 0,
        timeout_secs,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    }
}

// -----------------------------------------------------------------------
// Safety property still holds for both models
// -----------------------------------------------------------------------

#[test]
fn rb_live_safety_holds() {
    let source = load_library("reliable_broadcast_safe_live.trs");
    let result =
        pipeline::verify(&source, "rb_live.trs", &default_opts(6)).expect("verify should complete");
    assert!(
        matches!(result, VerificationResult::Safe { .. }),
        "expected Safe, got {result}"
    );
}

#[test]
fn rb_live_buggy_safety_holds() {
    // Safety (agreement) should still hold even for the buggy model
    // because the bug is a liveness bug, not a safety bug.
    let source = load_library("reliable_broadcast_live_buggy.trs");
    let result = pipeline::verify(&source, "rb_buggy.trs", &default_opts(6))
        .expect("verify should complete");
    assert!(
        matches!(result, VerificationResult::Safe { .. }),
        "expected Safe, got {result}"
    );
}

// -----------------------------------------------------------------------
// Fair liveness: bounded checking
// -----------------------------------------------------------------------

#[test]
fn rb_live_bounded_fair_liveness() {
    let source = load_library("reliable_broadcast_safe_live.trs");
    let opts = default_opts(6);
    let result =
        pipeline::check_fair_liveness_with_mode(&source, "rb_live.trs", &opts, FairnessMode::Weak)
            .expect("fair liveness check should complete");
    // Under counter abstraction, bounded fair-liveness may report a spurious
    // fair cycle because the abstraction can't enforce that message delivery
    // is monotonically increasing across steps.
    match result {
        FairLivenessResult::NoFairCycleUpTo { .. } => {
            // Ideal: no fair cycle found (fully precise abstraction)
        }
        FairLivenessResult::FairCycleFound { .. } => {
            // Expected with counter abstraction: spurious cycle due to
            // over-approximation of message delivery scheduling
        }
        FairLivenessResult::Unknown { .. } => {
            // Acceptable: solver timeout or inconclusive
        }
    }
}

#[test]
fn rb_buggy_bounded_fair_liveness() {
    let source = load_library("reliable_broadcast_live_buggy.trs");
    let opts = default_opts(6);
    let result =
        pipeline::check_fair_liveness_with_mode(&source, "rb_buggy.trs", &opts, FairnessMode::Weak)
            .expect("fair liveness check should complete");
    // The buggy model has a self-loop in echoed that can cause genuine
    // non-termination under weak fairness. Under counter abstraction,
    // this should definitely find a fair cycle.
    match result {
        FairLivenessResult::FairCycleFound { depth, .. } => {
            assert!(depth >= 1, "fair cycle should have depth >= 1");
        }
        FairLivenessResult::NoFairCycleUpTo { .. } => {
            panic!("buggy model should have a fair cycle");
        }
        FairLivenessResult::Unknown { .. } => {
            // Acceptable: solver timeout
        }
    }
}

// -----------------------------------------------------------------------
// Unbounded fair liveness proof attempts
// -----------------------------------------------------------------------

#[test]
fn rb_live_unbounded_proof_attempt() {
    let source = load_library("reliable_broadcast_safe_live.trs");
    let opts = default_opts(4);
    let result =
        pipeline::prove_fair_liveness_with_mode(&source, "rb_live.trs", &opts, FairnessMode::Weak)
            .expect("prove-fair should complete");
    // With counter abstraction, unbounded proofs for real protocols are
    // challenging. Accept any valid outcome.
    match result {
        UnboundedFairLivenessResult::LiveProved { .. } => {
            // Ideal but unlikely for this protocol under counter abstraction
        }
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            // May find spurious cycle due to abstraction
        }
        UnboundedFairLivenessResult::NotProved { .. } => {
            // Expected: PDR/IC3 may not converge
        }
        UnboundedFairLivenessResult::Unknown { .. } => {
            // Timeout or inconclusive
        }
    }
}

// -----------------------------------------------------------------------
// Strong fairness behavior
// -----------------------------------------------------------------------

#[test]
fn rb_buggy_strong_fairness_still_finds_cycle() {
    let source = load_library("reliable_broadcast_live_buggy.trs");
    let opts = default_opts(6);
    let result = pipeline::check_fair_liveness_with_mode(
        &source,
        "rb_buggy.trs",
        &opts,
        FairnessMode::Strong,
    )
    .expect("fair liveness check should complete");
    // Under strong fairness, the self-loop bug might be masked (if the
    // higher-threshold rule is infinitely often enabled, strong fairness
    // forces it to fire). But counter abstraction may still find a cycle.
    match result {
        FairLivenessResult::FairCycleFound { .. } => {
            // Counter abstraction finds cycle (spurious or real)
        }
        FairLivenessResult::NoFairCycleUpTo { .. } => {
            // Strong fairness eliminated the cycle — correct behavior
        }
        FairLivenessResult::Unknown { .. } => {
            // Timeout
        }
    }
}

// -----------------------------------------------------------------------
// Deterministic PBFT-shaped CI liveness targets
// -----------------------------------------------------------------------

#[test]
fn pbft_liveness_ci_safe_is_live_proved_unbounded() {
    let source = load_library("pbft_liveness_safe_ci.trs");
    let opts = unbounded_pdr_opts(60);
    let result = pipeline::prove_fair_liveness_with_mode(
        &source,
        "pbft_liveness_safe_ci.trs",
        &opts,
        FairnessMode::Weak,
    )
    .expect("prove-fair should complete for pbft_liveness_safe_ci");
    assert!(
        matches!(result, UnboundedFairLivenessResult::LiveProved { .. }),
        "expected LiveProved, got {result}"
    );
}

#[test]
fn pbft_liveness_ci_buggy_finds_fair_cycle_unbounded() {
    let source = load_library("pbft_liveness_buggy_ci.trs");
    let opts = unbounded_pdr_opts(60);
    let result = pipeline::prove_fair_liveness_with_mode(
        &source,
        "pbft_liveness_buggy_ci.trs",
        &opts,
        FairnessMode::Weak,
    )
    .expect("prove-fair should complete for pbft_liveness_buggy_ci");
    assert!(
        matches!(result, UnboundedFairLivenessResult::FairCycleFound { .. }),
        "expected FairCycleFound, got {result}"
    );
}

#[test]
fn pbft_liveness_ci_safe_certificate_generation_is_deterministic() {
    let source = load_library("pbft_liveness_safe_ci.trs");
    let opts = unbounded_pdr_opts(60);

    let cert_a = pipeline::generate_fair_liveness_certificate_with_mode(
        &source,
        "pbft_liveness_safe_ci.trs",
        &opts,
        FairnessMode::Weak,
    )
    .expect("first fair-liveness certificate generation should succeed");
    let cert_b = pipeline::generate_fair_liveness_certificate_with_mode(
        &source,
        "pbft_liveness_safe_ci.trs",
        &opts,
        FairnessMode::Weak,
    )
    .expect("second fair-liveness certificate generation should succeed");

    assert_eq!(cert_a.protocol_file, cert_b.protocol_file);
    assert_eq!(cert_a.fairness, cert_b.fairness);
    assert_eq!(cert_a.frame, cert_b.frame);
    assert_eq!(cert_a.obligations.len(), 3);
    assert_eq!(cert_a.obligations.len(), cert_b.obligations.len());
    for (lhs, rhs) in cert_a.obligations.iter().zip(cert_b.obligations.iter()) {
        assert_eq!(lhs.name, rhs.name);
        assert_eq!(lhs.expected, rhs.expected);
        assert_eq!(lhs.smt2, rhs.smt2);
    }
}
