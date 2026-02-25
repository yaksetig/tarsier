#![cfg(not(feature = "governance"))]

use serde_json::Value;
use std::process::Command;

fn workspace_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn beginner_default_analyze_reports_clear_safety_liveness_interpretation() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .args([
            "analyze",
            "examples/library/reliable_broadcast_safe.trs",
            "--format",
            "json",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("failed to execute analyze command");

    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(2),
        "analyze should return 0 (pass) or 2 (non-pass report), got {:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "analyze output should be JSON (status={:?}, stderr={}). parse error: {e}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });

    let interpretation = report["interpretation"]
        .as_object()
        .expect("report.interpretation should be an object");
    assert_eq!(
        interpretation.get("safety").and_then(Value::as_str),
        Some("SAFE"),
        "default beginner report should expose safety=SAFE for reliable_broadcast_safe"
    );
    assert_eq!(
        interpretation.get("liveness").and_then(Value::as_str),
        Some("UNKNOWN"),
        "default beginner report should expose liveness=UNKNOWN for reliable_broadcast_safe"
    );
    assert!(
        interpretation
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("Safety holds"),
        "summary should explicitly disambiguate safety/liveness"
    );
    assert!(
        interpretation
            .get("overall_status_meaning")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("overall"),
        "interpretation should explain meaning of overall status"
    );
}

#[test]
fn beginner_help_is_discoverable_and_non_governance() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--help")
        .output()
        .expect("failed to execute tarsier --help");
    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for snippet in [
        "tarsier assist --kind pbft --out my_protocol.trs",
        "tarsier analyze my_protocol.trs --goal safety",
        "tarsier visualize my_protocol.trs --check verify",
    ] {
        assert!(
            stdout.contains(snippet),
            "help should include canonical beginner step: {snippet}"
        );
    }
    for governance_only in [
        "cert-suite",
        "certify-safety",
        "certify-fair-liveness",
        "check-certificate",
        "governance-pipeline",
    ] {
        assert!(
            !stdout.contains(governance_only),
            "default help must not advertise governance-only command: {governance_only}"
        );
    }
}
