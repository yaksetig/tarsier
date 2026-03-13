use super::*;
use crate::pipeline::*;

fn default_options() -> PipelineOptions {
    PipelineOptions::default()
}

// -- verify: parse error on empty input --

#[test]
fn verify_empty_source_returns_parse_error() {
    let result = verify("", "test.trs", &default_options());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PipelineError::Parse(_)));
}

#[test]
fn verify_invalid_syntax_returns_parse_error() {
    let result = verify("not valid tarsier", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn verify_with_cegar_empty_source_returns_parse_error() {
    let result = verify_with_cegar("", "test.trs", &default_options(), 0);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PipelineError::Parse(_)));
}

#[test]
fn prove_safety_empty_source_returns_parse_error() {
    let result = prove_safety("", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn check_liveness_empty_source_returns_parse_error() {
    let result = check_liveness("", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn prove_fair_liveness_empty_source_returns_parse_error() {
    let result = prove_fair_liveness("", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn check_fair_liveness_empty_source_returns_parse_error() {
    let result = check_fair_liveness("", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn verify_all_properties_empty_source_returns_parse_error() {
    let result = verify_all_properties("", "test.trs", &default_options());
    assert!(result.is_err());
}

#[test]
fn verify_program_ast_rejects_empty_program() {
    let program = ast::Program {
        protocol: ast::Spanned {
            node: ast::ProtocolDecl {
                name: "test".into(),
                imports: vec![],
                refines: None,
                modules: vec![],
                enums: vec![],
                parameters: vec![],
                resilience: None,
                pacemaker: None,
                adversary: vec![],
                timing: None,
                identities: vec![],
                channels: vec![],
                equivocation_policies: vec![],
                committees: vec![],
                dag_rounds: vec![],
                collections: vec![],
                clocks: vec![],
                messages: vec![],
                crypto_objects: vec![],
                roles: vec![],
                properties: vec![],
            },
            span: ast::Span { start: 0, end: 0 },
        },
    };
    let options = default_options();
    let result = verify_program_ast(&program, &options);
    // Empty program -> validation error (no roles, no properties, etc.)
    assert!(result.is_err());
}

#[test]
fn prove_safety_program_ast_rejects_empty_program() {
    let program = ast::Program {
        protocol: ast::Spanned {
            node: ast::ProtocolDecl {
                name: "test".into(),
                imports: vec![],
                refines: None,
                modules: vec![],
                enums: vec![],
                parameters: vec![],
                resilience: None,
                pacemaker: None,
                adversary: vec![],
                timing: None,
                identities: vec![],
                channels: vec![],
                equivocation_policies: vec![],
                committees: vec![],
                dag_rounds: vec![],
                collections: vec![],
                clocks: vec![],
                messages: vec![],
                crypto_objects: vec![],
                roles: vec![],
                properties: vec![],
            },
            span: ast::Span { start: 0, end: 0 },
        },
    };
    let options = default_options();
    let result = prove_safety_program_ast(&program, &options);
    assert!(result.is_err());
}
