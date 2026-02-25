use std::process::Command;

fn parse_and_generate_rust(source: &str) -> String {
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    tarsier_codegen::generate(&program, tarsier_codegen::CodegenTarget::Rust)
        .expect("codegen failed")
}

fn parse_and_generate_go(source: &str) -> String {
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    tarsier_codegen::generate(&program, tarsier_codegen::CodegenTarget::Go).expect("codegen failed")
}

fn assert_rust_compiles(name: &str, code: &str) {
    let dir = std::env::temp_dir().join(format!("tarsier_smoke_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src_path = dir.join(format!("{name}.rs"));
    let out_path = dir.join(format!("{name}.rlib"));
    std::fs::write(&src_path, code).unwrap();

    let output = Command::new("rustc")
        .args(["--edition", "2021", "--crate-type", "lib"])
        .arg(&src_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("failed to run rustc — is it installed?");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Cleanup before asserting so we don't leave temp files on failure
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "rustc failed for {name}:\n{stderr}"
    );
    // Also verify zero warnings (our #![allow(unused, unused_comparisons)] should suppress all)
    assert!(
        !stderr.contains("warning:"),
        "rustc produced warnings for {name}:\n{stderr}"
    );
}

fn assert_go_compiles(name: &str, code: &str) {
    let go_check = Command::new("go").arg("version").output();
    if go_check.is_err() || !go_check.as_ref().unwrap().status.success() {
        eprintln!("Go not installed, skipping Go compilation test for {name}");
        return;
    }

    let dir = std::env::temp_dir().join(format!("tarsier_go_smoke_{name}_{}", std::process::id()));
    let pkg_dir = dir.join("pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    // Write go.mod
    std::fs::write(
        dir.join("go.mod"),
        format!("module tarsier_smoke_{name}\n\ngo 1.21\n"),
    )
    .unwrap();

    // Write source file
    std::fs::write(pkg_dir.join(format!("{name}.go")), code).unwrap();

    let output = Command::new("go")
        .arg("build")
        .arg("./pkg")
        .current_dir(&dir)
        .output()
        .expect("failed to run go build");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "go build failed for {name}:\n{stderr}"
    );
}

// ==================== Rust smoke tests ====================

#[test]
fn smoke_reliable_broadcast_compiles() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("reliable_broadcast", &code);
}

#[test]
fn smoke_pbft_simple_compiles() {
    let source = include_str!("../../../examples/pbft_simple.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("pbft_simple", &code);
}

#[test]
fn smoke_buggy_consensus_compiles() {
    let source = include_str!("../../../examples/reliable_broadcast_buggy.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("buggy_consensus", &code);
}

#[test]
fn smoke_algorand_committee_compiles() {
    let source = include_str!("../../../examples/algorand_committee.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("algorand_committee", &code);
    assert!(code.contains("CommitteeSpec"));
}

#[test]
fn smoke_temporal_liveness_compiles() {
    let source = include_str!("../../../examples/temporal_liveness.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("temporal_liveness", &code);
}

#[test]
fn smoke_crypto_objects_compiles() {
    let source = include_str!("../../../examples/crypto_objects.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("crypto_objects", &code);
}

#[test]
fn smoke_pbft_faithful_compiles() {
    let source = include_str!("../../../examples/pbft_faithful_liveness.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("pbft_faithful", &code);
}

#[test]
fn smoke_trivial_live_compiles() {
    let source = include_str!("../../../examples/trivial_live.trs");
    let code = parse_and_generate_rust(source);
    assert_rust_compiles("trivial_live", &code);
}

// ==================== Go smoke tests ====================

#[test]
fn smoke_go_reliable_broadcast_compiles() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("reliable_broadcast", &code);
}

#[test]
fn smoke_go_pbft_simple_compiles() {
    let source = include_str!("../../../examples/pbft_simple.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("pbft_simple", &code);
}

#[test]
fn smoke_go_buggy_consensus_compiles() {
    let source = include_str!("../../../examples/reliable_broadcast_buggy.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("buggy_consensus", &code);
}

#[test]
fn smoke_go_crypto_objects_compiles() {
    let source = include_str!("../../../examples/crypto_objects.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("crypto_objects", &code);
}

#[test]
fn smoke_go_pbft_faithful_compiles() {
    let source = include_str!("../../../examples/pbft_faithful_liveness.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("pbft_faithful", &code);
}

#[test]
fn smoke_go_trivial_live_compiles() {
    let source = include_str!("../../../examples/trivial_live.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("trivial_live", &code);
}

#[test]
fn smoke_go_temporal_liveness_compiles() {
    let source = include_str!("../../../examples/temporal_liveness.trs");
    let code = parse_and_generate_go(source);
    assert_go_compiles("temporal_liveness", &code);
}

#[test]
fn smoke_faithful_identity_channel_equivocation_compiles() {
    let source = include_str!("../../../examples/library/pbft_simple_safe_faithful.trs");
    let rust = parse_and_generate_rust(source);
    assert_rust_compiles("pbft_simple_safe_faithful", &rust);
    assert!(rust.contains("IdentityDeclSpec"));
    assert!(rust.contains("ChannelPolicySpec"));
    assert!(rust.contains("EquivocationPolicySpec"));
    assert!(rust.contains("OutboundMessage"));

    let go = parse_and_generate_go(source);
    assert_go_compiles("pbft_simple_safe_faithful", &go);
    assert!(go.contains("type IdentityDeclSpec struct"));
    assert!(go.contains("type ChannelPolicySpec struct"));
    assert!(go.contains("type EquivocationPolicySpec struct"));
    assert!(go.contains("type OutboundMessage struct"));
}

// ==================== Regression tests ====================

#[test]
fn regression_go_negation_balanced_parens() {
    let source = include_str!("../../../examples/crypto_objects.trs");
    let code = parse_and_generate_go(source);
    // The total file should have balanced parentheses
    let opens: usize = code.matches('(').count();
    let closes: usize = code.matches(')').count();
    assert_eq!(
        opens, closes,
        "unbalanced parentheses in generated Go code: {opens} opens vs {closes} closes"
    );
    // Specifically check that negation expressions don't have missing parens
    for (i, line) in code.lines().enumerate() {
        if line.contains("-int64(") {
            let lo = line.matches('(').count();
            let lc = line.matches(')').count();
            assert_eq!(
                lo,
                lc,
                "unbalanced parentheses in negation on line {}: {line}",
                i + 1
            );
        }
    }
}

#[test]
fn regression_rust_no_todo_crypto_objects() {
    let source = include_str!("../../../examples/crypto_objects.trs");
    let code = parse_and_generate_rust(source);
    assert!(
        !code.contains("TODO"),
        "generated Rust code should not contain TODO comments"
    );
}

#[test]
fn regression_go_no_todo_crypto_objects() {
    let source = include_str!("../../../examples/crypto_objects.trs");
    let code = parse_and_generate_go(source);
    assert!(
        !code.contains("TODO"),
        "generated Go code should not contain TODO comments"
    );
}

// ==================== Provenance golden tests ====================

#[test]
fn golden_provenance_rust_verified() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    let provenance = tarsier_codegen::ProvenanceInfo {
        model_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        options_sha256: "a1b2c3d4".into(),
        certificate_ref: "certs/rb_bundle".into(),
        verified: true,
        audit_tag: None,
    };
    let code = tarsier_codegen::generate_with_provenance(
        &program,
        tarsier_codegen::CodegenTarget::Rust,
        &provenance,
    )
    .unwrap();

    // All provenance fields present
    assert!(code.contains("@tarsier-provenance model_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert!(code.contains("@tarsier-provenance options_sha256=a1b2c3d4"));
    assert!(code.contains("@tarsier-provenance certificate_ref=certs/rb_bundle"));
    assert!(code.contains("@tarsier-provenance verified=true"));
    assert!(!code.contains("audit_tag"));

    // Deterministic: same inputs produce same output
    let code2 = tarsier_codegen::generate_with_provenance(
        &program,
        tarsier_codegen::CodegenTarget::Rust,
        &provenance,
    )
    .unwrap();
    assert_eq!(
        code, code2,
        "provenance golden test: output must be deterministic"
    );

    // Generated code still compiles
    assert_rust_compiles("provenance_golden", &code);
}

#[test]
fn golden_provenance_go_unverified() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    let provenance = tarsier_codegen::ProvenanceInfo {
        model_sha256: "deadbeef".into(),
        options_sha256: "cafebabe".into(),
        certificate_ref: "none".into(),
        verified: false,
        audit_tag: Some("UNVERIFIED_CODEGEN".into()),
    };
    let code = tarsier_codegen::generate_with_provenance(
        &program,
        tarsier_codegen::CodegenTarget::Go,
        &provenance,
    )
    .unwrap();

    assert!(code.contains("@tarsier-provenance model_sha256=deadbeef"));
    assert!(code.contains("@tarsier-provenance options_sha256=cafebabe"));
    assert!(code.contains("@tarsier-provenance certificate_ref=none"));
    assert!(code.contains("@tarsier-provenance verified=false"));
    assert!(code.contains("@tarsier-provenance audit_tag=UNVERIFIED_CODEGEN"));

    assert_go_compiles("provenance_golden_unverified", &code);
}
