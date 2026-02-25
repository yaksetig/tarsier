//! End-to-end tests verifying that codegen enforces certificate requirements by default.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for tarsier-cli is crates/tarsier-cli;
    // workspace root is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo_run_codegen(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tarsier"));
    cmd.arg("codegen");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.current_dir(workspace_root())
        .output()
        .expect("failed to execute tarsier codegen")
}

#[test]
fn codegen_fails_without_cert_and_without_override() {
    let output = cargo_run_codegen(&["examples/reliable_broadcast.trs", "--target", "rust"]);
    assert!(
        !output.status.success(),
        "codegen should fail without --require-cert or --allow-unverified"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires a certificate bundle by default")
            || stderr.contains("--require-cert")
            || stderr.contains("--allow-unverified"),
        "error message should mention cert requirement; got: {stderr}"
    );
}

#[test]
fn codegen_succeeds_with_allow_unverified() {
    let out_dir = std::env::temp_dir().join(format!(
        "tarsier_codegen_e2e_unverified_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&out_dir).unwrap();

    let output = cargo_run_codegen(&[
        "examples/reliable_broadcast.trs",
        "--target",
        "rust",
        "--allow-unverified",
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "codegen with --allow-unverified should succeed; stderr: {stderr}, stdout: {stdout}"
    );

    // Verify the generated file exists and contains provenance header
    // Protocol name "ReliableBroadcast" → "reliablebroadcast.rs"
    let generated = out_dir.join("reliablebroadcast.rs");
    assert!(generated.exists(), "generated file should exist");
    let content = std::fs::read_to_string(&generated).unwrap();
    assert!(
        content.contains("@tarsier-provenance verified=false"),
        "unverified codegen should have verified=false in provenance"
    );
    assert!(
        content.contains("audit_tag=UNVERIFIED_CODEGEN"),
        "unverified codegen should have UNVERIFIED_CODEGEN audit tag"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn codegen_fails_with_invalid_cert_path() {
    let output = cargo_run_codegen(&[
        "examples/reliable_broadcast.trs",
        "--target",
        "rust",
        "--require-cert",
        "/nonexistent/cert/bundle",
    ]);
    assert!(
        !output.status.success(),
        "codegen should fail with invalid cert path"
    );
}

#[test]
fn codegen_committee_identity_channel_equivocation_surface_succeeds() {
    let out_dir = std::env::temp_dir().join(format!(
        "tarsier_codegen_e2e_semantics_surface_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&out_dir).unwrap();

    let output = cargo_run_codegen(&[
        "examples/algorand_committee.trs",
        "--target",
        "rust",
        "--allow-unverified",
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "codegen for protocol with committee/channel/equivocation/identity surface should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Generated rust code written to"),
        "codegen should report generated output path: {stdout}"
    );

    let generated = out_dir.join("algorandcommittee.rs");
    assert!(generated.exists(), "generated file should exist");
    let content = std::fs::read_to_string(&generated).unwrap();
    assert!(
        content.contains("CommitteeSpec") && content.contains("protocol_semantics_spec"),
        "generated code should include committee semantics surface"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}
