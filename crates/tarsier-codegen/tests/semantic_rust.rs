use tarsier_codegen::trace_oracle::{build_model_trace_oracle, validate_generated_trace_oracle};
use tarsier_codegen::{generate, CodegenTarget};

fn parse_model(source: &str, name: &str) -> tarsier_dsl::ast::Program {
    tarsier_dsl::parse(source, name).expect("model should parse")
}

#[test]
fn rust_semantic_validation_matches_model_oracle_for_core_examples() {
    let fixtures = [
        ("reliable_broadcast.trs", include_str!("../../../examples/reliable_broadcast.trs")),
        ("pbft_simple.trs", include_str!("../../../examples/pbft_simple.trs")),
        (
            "pbft_faithful_liveness.trs",
            include_str!("../../../examples/pbft_faithful_liveness.trs"),
        ),
        ("crypto_objects.trs", include_str!("../../../examples/crypto_objects.trs")),
    ];

    for (name, source) in fixtures {
        let program = parse_model(source, name);
        let oracle = build_model_trace_oracle(&program).expect("oracle build should succeed");
        let generated = generate(&program, CodegenTarget::Rust).expect("rust codegen should work");
        let report = validate_generated_trace_oracle(&oracle, CodegenTarget::Rust, &generated);
        assert!(
            report.is_match(),
            "oracle mismatch for {name}: {:?}",
            report.missing
        );
    }
}

#[test]
fn rust_semantic_validation_flags_missing_send_semantics() {
    let source = include_str!("../../../examples/reliable_broadcast.trs");
    let program = parse_model(source, "reliable_broadcast.trs");
    let oracle = build_model_trace_oracle(&program).expect("oracle build should succeed");
    let generated = generate(&program, CodegenTarget::Rust).expect("rust codegen should work");

    let broken = generated.replacen(
        "channel_auth_for_message_family(\"Echo\")",
        "ChannelAuthModeSpec::Unauthenticated",
        1,
    );

    let report = validate_generated_trace_oracle(&oracle, CodegenTarget::Rust, &broken);
    assert!(!report.is_match(), "broken output should fail oracle checks");
    assert!(
        report
            .missing
            .iter()
            .any(|m| m.check == "send.channel_auth"),
        "expected send.channel_auth mismatch, got {:?}",
        report.missing
    );
}
