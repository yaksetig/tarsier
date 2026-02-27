//! Property-based tests for the SMT encoding stage.
//!
//! These tests verify that encoding well-formed ThresholdAutomata into
//! Z3 assertions preserves structural soundness and doesn't panic.

use std::path::PathBuf;

use tarsier_engine::pipeline::{self, PipelineOptions};
use tarsier_engine::result::VerificationResult;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn opts_depth(depth: usize) -> PipelineOptions {
    PipelineOptions {
        max_depth: depth,
        timeout_secs: 30,
        ..PipelineOptions::default()
    }
}

/// For known-safe library protocols, BMC at depth 1 returns Safe (not Unsafe).
/// This is a sanity check: a single step from the initial state should not
/// violate safety for any of our safe library models.
#[test]
#[ignore = "slow: ~25s total for file, run with --ignored"]
fn safe_library_protocols_safe_at_depth_1() {
    let safe_models = ["reliable_broadcast_safe.trs", "pbft_simple_safe.trs"];
    for model in &safe_models {
        let path = workspace_root().join(format!("examples/library/{model}"));
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {model}: {e}"));
        let result = pipeline::verify(&source, model, &opts_depth(1));
        match result {
            Ok(VerificationResult::Safe { .. }) => { /* expected */ }
            Ok(VerificationResult::ProbabilisticallySafe { .. }) => { /* also fine */ }
            Ok(other) => panic!("{model}: expected Safe at depth 1, got {other}"),
            Err(e) => panic!("{model}: verify failed: {e}"),
        }
    }
}

/// For known-unsafe library protocols, BMC finds a counterexample within depth 10.
#[test]
#[ignore = "slow: ~25s total for file, run with --ignored"]
fn unsafe_library_protocols_detected() {
    let unsafe_models = ["reliable_broadcast_buggy.trs"];
    for model in &unsafe_models {
        let path = workspace_root().join(format!("examples/library/{model}"));
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {model}: {e}"));
        let result = pipeline::verify(&source, model, &opts_depth(10));
        match result {
            Ok(VerificationResult::Unsafe { .. }) => { /* expected */ }
            Ok(other) => panic!("{model}: expected Unsafe, got {other}"),
            Err(e) => panic!("{model}: verify failed: {e}"),
        }
    }
}

/// Encoding at depth 0 for all library models doesn't panic.
#[test]
#[ignore = "slow: ~25s total for file, run with --ignored"]
fn encoding_depth_0_no_panic_on_library() {
    let lib_dir = workspace_root().join("examples/library");
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.file_name().unwrap().to_str().unwrap();
            // Verify at depth 0 should always succeed (safe) since no transitions happen
            let result = pipeline::verify(&source, filename, &opts_depth(0));
            match result {
                Ok(VerificationResult::Safe { .. }) => { /* expected at depth 0 */ }
                Ok(VerificationResult::ProbabilisticallySafe { .. }) => { /* fine */ }
                Ok(VerificationResult::Unsafe { .. }) => {
                    // At depth 0, unsafe means the initial state violates safety,
                    // which is possible for some models
                }
                Ok(VerificationResult::Unknown { .. }) => { /* fine */ }
                Err(_) => { /* parse/lower error for some models is OK */ }
            }
        }
    }
}
