pub mod common;
pub mod go_gen;
pub mod rust_gen;

use tarsier_dsl::ast;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodegenTarget {
    Rust,
    Go,
}

#[derive(Debug, thiserror::Error)]
pub enum CodegenError {
    #[error("no protocol found in program")]
    NoProtocol,
    #[error("no roles defined in protocol '{0}'")]
    NoRoles(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

/// Generate skeleton implementation code from a parsed `.trs` program.
pub fn generate(program: &ast::Program, target: CodegenTarget) -> Result<String, CodegenError> {
    let protocol = &program.protocol.node;
    if protocol.roles.is_empty() {
        return Err(CodegenError::NoRoles(protocol.name.clone()));
    }
    match target {
        CodegenTarget::Rust => rust_gen::generate_rust(protocol),
        CodegenTarget::Go => go_gen::generate_go(protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_example(source: &str) -> ast::Program {
        tarsier_dsl::parse(source, "test.trs").expect("parse failed")
    }

    // --- Reliable Broadcast ---

    #[test]
    fn test_rust_generation_reliable_broadcast() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(!code.is_empty());
        assert!(code.contains("struct Config"));
        assert!(code.contains("enum ProcessPhase"));
        assert!(code.contains("struct ProcessState"));
        assert!(code.contains("trait Network"));
        assert!(code.contains("fn handle_message"));
        assert!(code.contains("enum Message"));
        assert!(code.contains("#![allow(unused"));
    }

    #[test]
    fn test_go_generation_reliable_broadcast() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(!code.is_empty());
        assert!(code.contains("type Config struct"));
        assert!(code.contains("func"));
        assert!(code.contains("HandleMessage"));
    }

    // --- PBFT Simple ---

    #[test]
    fn test_rust_generation_pbft() {
        let source = include_str!("../../tarsier-dsl/../../examples/pbft_simple.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(!code.is_empty());
        assert!(code.contains("struct Config"));
        assert!(code.contains("enum ReplicaPhase"));
    }

    #[test]
    fn test_go_generation_pbft() {
        let source = include_str!("../../tarsier-dsl/../../examples/pbft_simple.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(!code.is_empty());
        assert!(code.contains("type Config struct"));
    }

    // --- Reliable Broadcast Buggy ---

    #[test]
    fn test_rust_generation_buggy_consensus() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast_buggy.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum ProcessPhase"));
        assert!(code.contains("VoteMsg"));
        assert!(code.contains("CommitMsg"));
        assert!(code.contains("AbortMsg"));
    }

    #[test]
    fn test_go_generation_buggy_consensus() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast_buggy.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("VoteMsg"));
        assert!(code.contains("CommitMsg"));
    }

    // --- Algorand Committee ---

    #[test]
    fn test_rust_generation_algorand_committee() {
        let source = include_str!("../../tarsier-dsl/../../examples/algorand_committee.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum VoterPhase"));
        assert!(code.contains("SoftVoteMsg"));
        assert!(code.contains("CertVoteMsg"));
    }

    #[test]
    fn test_go_generation_algorand_committee() {
        let source = include_str!("../../tarsier-dsl/../../examples/algorand_committee.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("SoftVoteMsg"));
        assert!(code.contains("CertVoteMsg"));
    }

    // --- Trivial Live (no messages — edge case) ---

    #[test]
    fn test_rust_generation_trivial_live() {
        let source = include_str!("../../tarsier-dsl/../../examples/trivial_live.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum RPhase"));
        assert!(code.contains("enum Message"));
        // No message buffering match when protocol has no messages
        assert!(!code.contains("Buffer incoming message"));
    }

    #[test]
    fn test_go_generation_trivial_live() {
        let source = include_str!("../../tarsier-dsl/../../examples/trivial_live.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("type RPhase int"));
    }

    // --- Temporal Liveness ---

    #[test]
    fn test_rust_generation_temporal_liveness() {
        let source = include_str!("../../tarsier-dsl/../../examples/temporal_liveness.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum ReplicaPhase"));
        assert!(code.contains("TickMsg"));
    }

    #[test]
    fn test_go_generation_temporal_liveness() {
        let source = include_str!("../../tarsier-dsl/../../examples/temporal_liveness.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("TickMsg"));
    }

    // --- Crypto Objects (message fields + distinct guards + crypto placeholders) ---

    #[test]
    fn test_rust_generation_crypto_objects() {
        let source = include_str!("../../tarsier-dsl/../../examples/crypto_objects.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum ReplicaPhase"));
        // Message with fields
        assert!(code.contains("pub view:"));
        // Distinct guard generates HashSet import
        assert!(code.contains("use std::collections::HashSet"));
        // Crypto object placeholders
        assert!(code.contains("TODO: form crypto object"));
    }

    #[test]
    fn test_go_generation_crypto_objects() {
        let source = include_str!("../../tarsier-dsl/../../examples/crypto_objects.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        // Message with fields
        assert!(code.contains("View"));
        // Distinct helper emitted
        assert!(code.contains("countDistinctSenders"));
        assert!(code.contains("func countDistinctSenders"));
    }

    // --- PBFT Faithful Liveness (multi-field messages + distinct + pacemaker) ---

    #[test]
    fn test_rust_generation_pbft_faithful() {
        let source = include_str!("../../tarsier-dsl/../../examples/pbft_faithful_liveness.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("enum ReplicaPhase"));
        // Multi-field message
        assert!(code.contains("NewViewMsg"));
        assert!(code.contains("pub view:"));
        assert!(code.contains("pub value:"));
        // Distinct guard
        assert!(code.contains("HashSet"));
    }

    #[test]
    fn test_go_generation_pbft_faithful() {
        let source = include_str!("../../tarsier-dsl/../../examples/pbft_faithful_liveness.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("NewViewMsg"));
        assert!(code.contains("countDistinctSenders"));
    }

    // --- Go Decide bool fix ---

    #[test]
    fn test_go_decide_bool_renders_numeric() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        // Should render as uint64(1), not uint64(true)
        assert!(code.contains("uint64(1)"));
        assert!(!code.contains("uint64(true)"));
    }
}
