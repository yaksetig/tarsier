#![doc = include_str!("../README.md")]

//! Code generation from Tarsier protocol specifications.
//!
//! This crate generates executable Rust and Go implementations from parsed
//! `.trs` protocol models, including runtime trace hooks for conformance checking.

pub mod common;
pub mod go_gen;
pub mod rust_gen;
pub mod trace_hooks;

use tarsier_dsl::ast;

/// Target language for generated protocol implementation skeletons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodegenTarget {
    /// Generate Rust source code.
    Rust,
    /// Generate Go source code.
    Go,
}

/// Errors returned by code generation entry points.
#[derive(Debug, thiserror::Error)]
pub enum CodegenError {
    /// The parsed AST does not contain a protocol declaration.
    #[error("no protocol found in program")]
    NoProtocol,
    /// The protocol has no role declarations to generate process code from.
    #[error("no roles defined in protocol '{0}'")]
    NoRoles(String),
    /// The input uses a feature not yet implemented by the selected backend.
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

/// Provenance metadata embedded as a header comment in generated artifacts.
#[derive(Debug, Clone)]
pub struct ProvenanceInfo {
    /// SHA-256 hash of the source `.trs` model file.
    pub model_sha256: String,
    /// SHA-256 hash of the codegen options (target, flags).
    pub options_sha256: String,
    /// Path to the certificate bundle, or `"none"` if unverified.
    pub certificate_ref: String,
    /// Whether a valid certificate was provided and verified.
    pub verified: bool,
    /// Audit tag set when `--allow-unverified` is used.
    pub audit_tag: Option<String>,
}

/// Generate skeleton implementation code with a provenance header.
///
/// # Parameters
/// - `program`: Parsed protocol model.
/// - `target`: Output language backend.
/// - `provenance`: Provenance metadata emitted as header annotations.
///
/// # Returns
/// Generated source code including provenance header lines, or a codegen error.
pub fn generate_with_provenance(
    program: &ast::Program,
    target: CodegenTarget,
    provenance: &ProvenanceInfo,
) -> Result<String, CodegenError> {
    let code = generate(program, target)?;
    let comment_prefix = match target {
        CodegenTarget::Rust => "//",
        CodegenTarget::Go => "//",
    };
    let mut header = String::new();
    header.push_str(&format!(
        "{comment_prefix} @tarsier-provenance model_sha256={}\n",
        provenance.model_sha256
    ));
    header.push_str(&format!(
        "{comment_prefix} @tarsier-provenance options_sha256={}\n",
        provenance.options_sha256
    ));
    header.push_str(&format!(
        "{comment_prefix} @tarsier-provenance certificate_ref={}\n",
        provenance.certificate_ref
    ));
    header.push_str(&format!(
        "{comment_prefix} @tarsier-provenance verified={}\n",
        provenance.verified
    ));
    if let Some(tag) = &provenance.audit_tag {
        header.push_str(&format!(
            "{comment_prefix} @tarsier-provenance audit_tag={tag}\n",
        ));
    }
    header.push('\n');
    Ok(format!("{header}{code}"))
}

/// Generate skeleton implementation code from a parsed `.trs` program.
///
/// # Parameters
/// - `program`: Parsed protocol model.
/// - `target`: Output language backend.
///
/// # Returns
/// Generated source code for the selected target, or a codegen error.
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

    // --- Algorand Committee (committee semantics surface support) ---

    #[test]
    fn test_rust_generation_algorand_committee() {
        let source = include_str!("../../tarsier-dsl/../../examples/algorand_committee.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Rust).expect("codegen failed");
        assert!(code.contains("CommitteeSpec"));
        assert!(code.contains("protocol_semantics_spec"));
        assert!(code.contains("CommitteeValueSpec::Float"));
    }

    #[test]
    fn test_go_generation_algorand_committee() {
        let source = include_str!("../../tarsier-dsl/../../examples/algorand_committee.trs");
        let program = parse_example(source);
        let code = generate(&program, CodegenTarget::Go).expect("codegen failed");
        assert!(code.contains("type CommitteeSpec struct"));
        assert!(code.contains("func ProtocolSemanticsSpecData()"));
        assert!(code.contains("CommitteeValueFloat"));
    }

    #[test]
    fn test_faithful_surface_generation_includes_identity_channel_equivocation() {
        let source =
            include_str!("../../tarsier-dsl/../../examples/library/pbft_simple_safe_faithful.trs");
        let program = parse_example(source);
        let rust_code = generate(&program, CodegenTarget::Rust).expect("rust codegen failed");
        assert!(rust_code.contains("IdentityDeclSpec"));
        assert!(rust_code.contains("ChannelPolicySpec"));
        assert!(rust_code.contains("EquivocationPolicySpec"));
        assert!(rust_code.contains("channel_auth_for_message_family"));
        assert!(rust_code.contains("equivocation_mode_for_message_family"));
        assert!(rust_code.contains("OutboundMessage"));

        let go_code = generate(&program, CodegenTarget::Go).expect("go codegen failed");
        assert!(go_code.contains("type IdentityDeclSpec struct"));
        assert!(go_code.contains("type ChannelPolicySpec struct"));
        assert!(go_code.contains("type EquivocationPolicySpec struct"));
        assert!(go_code.contains("channelAuthForMessageFamily"));
        assert!(go_code.contains("equivocationModeForMessageFamily"));
        assert!(go_code.contains("type OutboundMessage struct"));
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
        // Crypto object fields and actions (QC -> q_c via to_snake_case)
        assert!(code.contains("q_c_count"));
        assert!(code.contains("lock_q_c"));
        assert!(code.contains("justify_q_c"));
        assert!(code.contains("q_c_count += 1"));
        assert!(code.contains("lock_q_c = true"));
        assert!(code.contains("justify_q_c = true"));
        // No remaining TODOs
        assert!(!code.contains("TODO"));
        assert!(!code.contains("/* TODO"));
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
        // Crypto object fields and actions (QC -> QC via to_pascal_case)
        assert!(code.contains("QCCount"));
        assert!(code.contains("LockQC"));
        assert!(code.contains("JustifyQC"));
        assert!(code.contains("QCCount++"));
        assert!(code.contains("LockQC = true"));
        assert!(code.contains("JustifyQC = true"));
        // No remaining TODOs
        assert!(!code.contains("TODO"));
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

    // --- Provenance header ---

    #[test]
    fn test_rust_provenance_header_verified() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let provenance = ProvenanceInfo {
            model_sha256: "abc123".into(),
            options_sha256: "def456".into(),
            certificate_ref: "certs/bundle".into(),
            verified: true,
            audit_tag: None,
        };
        let code = generate_with_provenance(&program, CodegenTarget::Rust, &provenance).unwrap();
        assert!(code.contains("// @tarsier-provenance model_sha256=abc123"));
        assert!(code.contains("// @tarsier-provenance options_sha256=def456"));
        assert!(code.contains("// @tarsier-provenance certificate_ref=certs/bundle"));
        assert!(code.contains("// @tarsier-provenance verified=true"));
        assert!(!code.contains("audit_tag"));
    }

    #[test]
    fn test_rust_provenance_header_unverified() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let provenance = ProvenanceInfo {
            model_sha256: "abc123".into(),
            options_sha256: "def456".into(),
            certificate_ref: "none".into(),
            verified: false,
            audit_tag: Some("UNVERIFIED_CODEGEN".into()),
        };
        let code = generate_with_provenance(&program, CodegenTarget::Rust, &provenance).unwrap();
        assert!(code.contains("// @tarsier-provenance verified=false"));
        assert!(code.contains("// @tarsier-provenance audit_tag=UNVERIFIED_CODEGEN"));
        assert!(code.contains("// @tarsier-provenance certificate_ref=none"));
    }

    #[test]
    fn test_go_provenance_header() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let provenance = ProvenanceInfo {
            model_sha256: "abc123".into(),
            options_sha256: "def456".into(),
            certificate_ref: "certs/bundle".into(),
            verified: true,
            audit_tag: None,
        };
        let code = generate_with_provenance(&program, CodegenTarget::Go, &provenance).unwrap();
        assert!(code.contains("// @tarsier-provenance model_sha256=abc123"));
        assert!(code.contains("// @tarsier-provenance verified=true"));
    }

    #[test]
    fn test_provenance_deterministic() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse_example(source);
        let provenance = ProvenanceInfo {
            model_sha256: "abc123".into(),
            options_sha256: "def456".into(),
            certificate_ref: "certs/bundle".into(),
            verified: true,
            audit_tag: None,
        };
        let code1 = generate_with_provenance(&program, CodegenTarget::Rust, &provenance).unwrap();
        let code2 = generate_with_provenance(&program, CodegenTarget::Rust, &provenance).unwrap();
        assert_eq!(code1, code2, "provenance output should be deterministic");
    }
}
