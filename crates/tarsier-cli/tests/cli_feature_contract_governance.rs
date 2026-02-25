#![cfg(feature = "governance")]

use std::process::Command;

#[test]
fn governance_binary_help_includes_governance_only_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--help")
        .output()
        .expect("failed to execute tarsier --help");
    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cert-suite"),
        "governance help must list cert-suite"
    );
    assert!(
        stdout.contains("certify-safety"),
        "governance help must list certify-safety"
    );
    assert!(
        stdout.contains("governance-pipeline"),
        "governance help must list governance-pipeline"
    );
}

#[test]
fn governance_help_keeps_canonical_beginner_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--help")
        .output()
        .expect("failed to execute tarsier --help");
    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let assist = stdout
        .find("tarsier assist --kind pbft --out my_protocol.trs")
        .expect("help should include canonical assist step");
    let analyze = stdout
        .find("tarsier analyze my_protocol.trs --goal safety")
        .expect("help should include canonical analyze step");
    let visualize = stdout
        .find("tarsier visualize my_protocol.trs --check verify")
        .expect("help should include canonical visualize step");
    assert!(
        assist < analyze && analyze < visualize,
        "canonical beginner flow order must be assist -> analyze -> visualize"
    );
}

#[test]
fn governance_binary_accepts_governance_only_subcommand_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("certify-safety")
        .arg("--help")
        .output()
        .expect("failed to execute certify-safety --help");
    assert!(
        output.status.success(),
        "governance build should expose certify-safety: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--out"),
        "certify-safety help should include required out flag"
    );
}
