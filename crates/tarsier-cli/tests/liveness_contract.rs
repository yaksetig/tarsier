#![cfg(not(feature = "governance"))]

use serde_json::Value;
use std::process::Command;

#[test]
#[ignore = "slow: ~20s, run with --ignored"]
fn analyze_proof_mode_reports_machine_readable_fair_liveness_unknown_diagnostics() {
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
        details["reason_code"].as_str(),
        Some("timeout"),
        "unknown fair-liveness outcome should expose a machine-readable reason_code"
    );

    let convergence = &details["convergence"];
    assert!(
        convergence["outcome"].is_string(),
        "convergence diagnostics must include outcome"
    );
    assert_eq!(
        convergence["reason_code"].as_str(),
        Some("timeout"),
        "convergence diagnostics should carry stable unknown reason categories"
    );
}
