#![cfg(not(feature = "governance"))]

use std::process::Command;

#[test]
fn default_binary_help_excludes_governance_only_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--help")
        .output()
        .expect("failed to execute tarsier --help");
    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("cert-suite"),
        "default help must hide governance-only commands"
    );
    assert!(
        !stdout.contains("certify-safety"),
        "default help must hide governance-only commands"
    );
    assert!(
        !stdout.contains("governance-pipeline"),
        "default help must hide governance-only commands"
    );
}

#[test]
fn default_help_advertises_canonical_beginner_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--help")
        .output()
        .expect("failed to execute tarsier --help");
    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let assist = stdout
        .find("tarsier assist --kind pbft --out my_protocol.trs")
        .expect("help should include assist beginner step");
    let analyze = stdout
        .find("tarsier analyze my_protocol.trs --goal safety")
        .expect("help should include analyze beginner step");
    let visualize = stdout
        .find("tarsier visualize my_protocol.trs --check verify")
        .expect("help should include visualize beginner step");
    assert!(
        assist < analyze && analyze < visualize,
        "canonical beginner flow order must be assist -> analyze -> visualize"
    );
}

#[test]
fn default_binary_rejects_governance_only_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("certify-safety")
        .arg("examples/reliable_broadcast.trs")
        .arg("--out")
        .arg("certs/pbft")
        .output()
        .expect("failed to execute default build governance command check");
    assert!(
        !output.status.success(),
        "default build should reject governance-only subcommands"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("certify-safety"),
        "error output should identify missing governance command: {stderr}"
    );
}
