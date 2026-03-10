use tarsier_codegen::trace_oracle::{build_model_trace_oracle, validate_generated_trace_oracle};
use tarsier_codegen::{generate, CodegenTarget};

fn parse_example(source: &str) -> tarsier_dsl::ast::Program {
    tarsier_dsl::parse(source, "trace_oracle_integration.trs").expect("parse failed")
}

#[test]
fn trace_oracle_matches_rust_and_go_from_same_model() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let program = parse_example(source);
    let oracle = build_model_trace_oracle(&program).expect("oracle build should succeed");

    let rust_generated = generate(&program, CodegenTarget::Rust).expect("rust codegen should work");
    let go_generated = generate(&program, CodegenTarget::Go).expect("go codegen should work");

    let rust_report =
        validate_generated_trace_oracle(&oracle, CodegenTarget::Rust, &rust_generated);
    assert!(
        rust_report.is_match(),
        "rust oracle mismatches: {:?}",
        rust_report.missing
    );

    let go_report = validate_generated_trace_oracle(&oracle, CodegenTarget::Go, &go_generated);
    assert!(
        go_report.is_match(),
        "go oracle mismatches: {:?}",
        go_report.missing
    );
}

#[test]
fn trace_oracle_detects_missing_transition_surface() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let program = parse_example(source);
    let oracle = build_model_trace_oracle(&program).expect("oracle build should succeed");

    let rust_generated = generate(&program, CodegenTarget::Rust).expect("rust codegen should work");
    let broken = rust_generated.replacen(
        "self.phase = ProcessPhase::Echoed;",
        "// removed transition for oracle negative test",
        1,
    );

    let report = validate_generated_trace_oracle(&oracle, CodegenTarget::Rust, &broken);
    assert!(!report.is_match(), "broken code should fail oracle checks");
    assert!(
        report
            .missing
            .iter()
            .any(|item| item.check == "transition.goto_phase"),
        "expected transition.goto_phase mismatch, got: {:?}",
        report.missing
    );
}
