use std::process::Command;

fn parse_and_generate_rust(source: &str) -> String {
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    tarsier_codegen::generate(&program, tarsier_codegen::CodegenTarget::Rust)
        .expect("codegen failed")
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
