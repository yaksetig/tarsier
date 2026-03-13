#![cfg(not(feature = "governance"))]

use serde_json::Value;
use std::process::Command;

#[test]
#[ignore = "slow: ~20s, run with --ignored"]
fn analyze_proof_mode_reports_machine_readable_fair_liveness_counterexample_diagnostics() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .args([
            "analyze",
            "examples/library/reliable_broadcast_safe_live.trs",
            "--goal",
            "safety+liveness",
            "--mode",
            "proof",
            "--solver",
            "z3",
            "--depth",
            "6",
            "--k",
            "8",
            "--timeout",
            "20",
            "--fairness",
            "weak",
            "--format",
            "json",
            "--profile",
            "pro",
        ])
        .current_dir(format!("{}/../..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .expect("failed to execute analyze command");

    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "analyze --format json output should be valid JSON (status={}, stderr={}). parse error: {e}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    });

    let layers = report["layers"]
        .as_array()
        .expect("report.layers should be an array");
    let fair_layer = layers
        .iter()
        .find(|layer| layer["layer"].as_str() == Some("prove[fair_pdr]"))
        .expect("proof report should include prove[fair_pdr] layer");

    assert_eq!(
        fair_layer["verdict"].as_str(),
        Some("UNKNOWN"),
        "expected unknown unbounded fair-liveness verdict class for this hard model"
    );

    let details = &fair_layer["details"];
    assert_eq!(
        details["result"].as_str(),
        Some("fair_cycle_found"),
        "fair-liveness counterexample should expose a machine-readable result kind"
    );
    assert_eq!(
        details["depth"].as_u64(),
        Some(1),
        "fair-liveness counterexample should expose the loop depth"
    );
    assert_eq!(
        details["loop_start"].as_u64(),
        Some(0),
        "fair-liveness counterexample should expose the loop start"
    );

    let convergence = &details["convergence"];
    assert_eq!(
        convergence["outcome"].as_str(),
        Some("counterexample"),
        "convergence diagnostics should expose a machine-readable counterexample outcome"
    );
    assert_eq!(
        convergence["counterexample_depth"].as_u64(),
        Some(1),
        "convergence diagnostics should expose the counterexample depth"
    );
    assert_eq!(
        convergence["loop_start"].as_u64(),
        Some(0),
        "convergence diagnostics should expose the loop start"
    );
}
