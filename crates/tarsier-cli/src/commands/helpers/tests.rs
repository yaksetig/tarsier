use super::*;
use tarsier_engine::pipeline::AutomatonFootprint;
use tarsier_engine::pipeline::{FairnessMode, SolverChoice, SoundnessMode};

// -- CliParseError --

#[test]
fn cli_parse_error_display() {
    let err = CliParseError::new("boom");
    assert_eq!(err.to_string(), "boom");
}

#[test]
fn cli_parse_error_implements_std_error() {
    let err = CliParseError::new("test");
    let _: &dyn std::error::Error = &err;
}

#[test]
fn cli_parse_error_eq() {
    let a = CliParseError::new("x");
    let b = CliParseError::new("x");
    let c = CliParseError::new("y");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// -- CliExitError --

#[test]
fn cli_exit_error_display() {
    let err = CliExitError::new(2, "failed");
    assert_eq!(err.to_string(), "failed");
    assert_eq!(err.code, 2);
}

#[test]
fn exit_code_round_trip() {
    let report = report_with_exit_code(42, "test");
    assert_eq!(exit_code_from_report(&report), Some(42));
}

#[test]
fn exit_code_returns_none_for_other_errors() {
    let report = miette::Report::msg("generic error");
    assert_eq!(exit_code_from_report(&report), None);
}

// -- parse_soundness_mode --

#[test]
fn parse_soundness_mode_strict() {
    assert!(matches!(
        parse_soundness_mode("strict"),
        Ok(SoundnessMode::Strict)
    ));
}

#[test]
fn parse_soundness_mode_permissive() {
    assert!(matches!(
        parse_soundness_mode("permissive"),
        Ok(SoundnessMode::Permissive)
    ));
}

#[test]
fn parse_soundness_mode_unknown() {
    let err = parse_soundness_mode("foo").unwrap_err();
    assert!(err.to_string().contains("Unknown soundness mode"));
}

// -- parse_proof_engine --

#[test]
fn parse_proof_engine_valid() {
    assert!(matches!(
        parse_proof_engine("kinduction"),
        Ok(ProofEngine::KInduction)
    ));
    assert!(matches!(parse_proof_engine("pdr"), Ok(ProofEngine::Pdr)));
    assert!(matches!(
        parse_proof_engine("ranking"),
        Ok(ProofEngine::Ranking)
    ));
}

#[test]
fn parse_proof_engine_invalid() {
    assert!(parse_proof_engine("abc").is_err());
}

// -- parse_solver_choice --

#[test]
fn parse_solver_choice_valid() {
    assert!(matches!(parse_solver_choice("z3"), Ok(SolverChoice::Z3)));
    assert!(matches!(
        parse_solver_choice("cvc5"),
        Ok(SolverChoice::Cvc5)
    ));
}

#[test]
fn parse_solver_choice_invalid() {
    let err = parse_solver_choice("minisat").unwrap_err();
    assert!(err.to_string().contains("Unknown solver"));
}

// -- parse_analysis_mode --

#[test]
fn parse_analysis_mode_all_variants() {
    assert!(matches!(
        parse_analysis_mode("quick"),
        Ok(AnalysisMode::Quick)
    ));
    assert!(matches!(
        parse_analysis_mode("standard"),
        Ok(AnalysisMode::Standard)
    ));
    assert!(matches!(
        parse_analysis_mode("proof"),
        Ok(AnalysisMode::Proof)
    ));
    assert!(matches!(
        parse_analysis_mode("audit"),
        Ok(AnalysisMode::Audit)
    ));
}

#[test]
fn parse_analysis_mode_invalid() {
    assert!(parse_analysis_mode("turbo").is_err());
}

// -- parse_output_format --

#[test]
fn parse_output_format_valid() {
    assert!(matches!(
        parse_output_format("text"),
        Ok(OutputFormat::Text)
    ));
    assert!(matches!(
        parse_output_format("json"),
        Ok(OutputFormat::Json)
    ));
}

#[test]
fn parse_output_format_invalid() {
    assert!(parse_output_format("xml").is_err());
}

// -- parse_cli_network_semantics_mode --

#[test]
fn parse_cli_network_semantics_mode_valid() {
    assert!(matches!(
        parse_cli_network_semantics_mode("dsl"),
        Ok(CliNetworkSemanticsMode::Dsl)
    ));
    assert!(matches!(
        parse_cli_network_semantics_mode("faithful"),
        Ok(CliNetworkSemanticsMode::Faithful)
    ));
}

#[test]
fn parse_cli_network_semantics_mode_invalid() {
    assert!(parse_cli_network_semantics_mode("legacy").is_err());
}

// -- parse_cli_por_mode --

#[test]
fn parse_cli_por_mode_full() {
    assert_eq!(parse_cli_por_mode("full").unwrap(), None);
}

#[test]
fn parse_cli_por_mode_static() {
    assert!(matches!(
        parse_cli_por_mode("static"),
        Ok(Some(PorMode::Static))
    ));
    assert!(matches!(
        parse_cli_por_mode("static_only"),
        Ok(Some(PorMode::Static))
    ));
}

#[test]
fn parse_cli_por_mode_off_variants() {
    for name in &["off", "none", "disabled"] {
        assert!(matches!(parse_cli_por_mode(name), Ok(Some(PorMode::Off))));
    }
}

#[test]
fn parse_cli_por_mode_invalid() {
    assert!(parse_cli_por_mode("dynamic").is_err());
}

// -- parse_visualize_check --

#[test]
fn parse_visualize_check_valid_names() {
    assert!(matches!(
        parse_visualize_check("verify"),
        Ok(VisualizeCheck::Verify)
    ));
    assert!(matches!(
        parse_visualize_check("liveness"),
        Ok(VisualizeCheck::Liveness)
    ));
    assert!(matches!(
        parse_visualize_check("fair-liveness"),
        Ok(VisualizeCheck::FairLiveness)
    ));
    assert!(matches!(
        parse_visualize_check("fair_liveness"),
        Ok(VisualizeCheck::FairLiveness)
    ));
    assert!(matches!(
        parse_visualize_check("prove"),
        Ok(VisualizeCheck::Prove)
    ));
    assert!(matches!(
        parse_visualize_check("prove-fair"),
        Ok(VisualizeCheck::ProveFair)
    ));
    assert!(matches!(
        parse_visualize_check("prove_fair"),
        Ok(VisualizeCheck::ProveFair)
    ));
}

#[test]
fn parse_visualize_check_invalid() {
    assert!(parse_visualize_check("debug").is_err());
}

// -- visualize_check_name round-trip --

#[test]
fn visualize_check_name_round_trip() {
    assert_eq!(visualize_check_name(VisualizeCheck::Verify), "verify");
    assert_eq!(visualize_check_name(VisualizeCheck::Liveness), "liveness");
    assert_eq!(
        visualize_check_name(VisualizeCheck::FairLiveness),
        "fair-liveness"
    );
    assert_eq!(visualize_check_name(VisualizeCheck::Prove), "prove");
    assert_eq!(
        visualize_check_name(VisualizeCheck::ProveFair),
        "prove-fair"
    );
}

// -- parse_visualize_format --

#[test]
fn parse_visualize_format_valid() {
    assert!(matches!(
        parse_visualize_format("timeline"),
        Ok(VisualizeFormat::Timeline)
    ));
    assert!(matches!(
        parse_visualize_format("mermaid"),
        Ok(VisualizeFormat::Mermaid)
    ));
    assert!(matches!(
        parse_visualize_format("markdown"),
        Ok(VisualizeFormat::Markdown)
    ));
    assert!(matches!(
        parse_visualize_format("json"),
        Ok(VisualizeFormat::Json)
    ));
}

#[test]
fn parse_visualize_format_invalid() {
    assert!(parse_visualize_format("svg").is_err());
}

// -- visualize_format_name round-trip --

#[test]
fn visualize_format_name_round_trip() {
    assert_eq!(visualize_format_name(VisualizeFormat::Timeline), "timeline");
    assert_eq!(visualize_format_name(VisualizeFormat::Mermaid), "mermaid");
    assert_eq!(visualize_format_name(VisualizeFormat::Markdown), "markdown");
    assert_eq!(visualize_format_name(VisualizeFormat::Json), "json");
}

// -- parse_fairness_mode --

#[test]
fn parse_fairness_mode_valid() {
    assert!(matches!(
        parse_fairness_mode("weak"),
        Ok(FairnessMode::Weak)
    ));
    assert!(matches!(
        parse_fairness_mode("strong"),
        Ok(FairnessMode::Strong)
    ));
}

#[test]
fn parse_fairness_mode_invalid() {
    assert!(parse_fairness_mode("fair").is_err());
}

// -- parse_faithful_fallback_floor --

#[test]
fn parse_faithful_fallback_floor_off_variants() {
    for name in &["off", "none", "disabled"] {
        assert!(parse_faithful_fallback_floor(name).unwrap().is_none());
    }
}

#[test]
fn parse_faithful_fallback_floor_identity() {
    assert!(matches!(
        parse_faithful_fallback_floor("identity"),
        Ok(Some(FaithfulFallbackFloor::IdentitySelective))
    ));
    assert!(matches!(
        parse_faithful_fallback_floor("faithful"),
        Ok(Some(FaithfulFallbackFloor::IdentitySelective))
    ));
}

#[test]
fn parse_faithful_fallback_floor_classic() {
    assert!(matches!(
        parse_faithful_fallback_floor("classic"),
        Ok(Some(FaithfulFallbackFloor::Classic))
    ));
}

#[test]
fn parse_faithful_fallback_floor_invalid() {
    assert!(parse_faithful_fallback_floor("xyz").is_err());
}

// -- cli_network_mode_name --

#[test]
fn cli_network_mode_name_values() {
    assert_eq!(cli_network_mode_name(CliNetworkSemanticsMode::Dsl), "dsl");
    assert_eq!(
        cli_network_mode_name(CliNetworkSemanticsMode::Faithful),
        "faithful"
    );
}

// -- solver_name / solver_cmd_name --

#[test]
fn solver_name_values() {
    assert_eq!(solver_name(SolverChoice::Z3), "z3");
    assert_eq!(solver_name(SolverChoice::Cvc5), "cvc5");
}

#[test]
fn solver_cmd_name_values() {
    assert_eq!(solver_cmd_name(SolverChoice::Z3), "z3");
    assert_eq!(solver_cmd_name(SolverChoice::Cvc5), "cvc5");
}

// -- proof_engine_name / soundness_name --

#[test]
fn proof_engine_name_values() {
    assert_eq!(proof_engine_name(ProofEngine::KInduction), "kinduction");
    assert_eq!(proof_engine_name(ProofEngine::Pdr), "pdr");
    assert_eq!(proof_engine_name(ProofEngine::Ranking), "ranking");
}

#[test]
fn soundness_name_values() {
    assert_eq!(soundness_name(SoundnessMode::Strict), "strict");
    assert_eq!(soundness_name(SoundnessMode::Permissive), "permissive");
}

// -- ratio --

#[test]
fn ratio_normal() {
    assert!((ratio(1, 4) - 0.25).abs() < f64::EPSILON);
}

#[test]
fn ratio_zero_denominator() {
    assert!((ratio(5, 0) - 0.0).abs() < f64::EPSILON);
}

// -- canonical_verdict_from_layer_result --

#[test]
fn canonical_verdict_safe_variants() {
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "safe"),
        CanonicalVerdict::Safe
    );
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "probabilistically_safe"),
        CanonicalVerdict::Safe
    );
}

#[test]
fn canonical_verdict_unsafe() {
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "unsafe"),
        CanonicalVerdict::Unsafe
    );
}

#[test]
fn canonical_verdict_live_variants() {
    assert_eq!(
        canonical_verdict_from_layer_result("liveness", "live"),
        CanonicalVerdict::LiveProved
    );
    assert_eq!(
        canonical_verdict_from_layer_result("fair", "no_fair_cycle_up_to"),
        CanonicalVerdict::LiveProved
    );
    assert_eq!(
        canonical_verdict_from_layer_result("prove", "live_proved"),
        CanonicalVerdict::LiveProved
    );
}

#[test]
fn canonical_verdict_live_cex() {
    assert_eq!(
        canonical_verdict_from_layer_result("liveness", "not_live"),
        CanonicalVerdict::LiveCex
    );
    assert_eq!(
        canonical_verdict_from_layer_result("fair", "fair_cycle_found"),
        CanonicalVerdict::LiveCex
    );
}

#[test]
fn canonical_verdict_inconclusive() {
    assert_eq!(
        canonical_verdict_from_layer_result("prove", "not_proved"),
        CanonicalVerdict::Inconclusive
    );
}

#[test]
fn canonical_verdict_unknown() {
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "unknown"),
        CanonicalVerdict::Unknown
    );
}

#[test]
fn canonical_verdict_pass_liveness_layer() {
    assert_eq!(
        canonical_verdict_from_layer_result("fair_liveness", "pass"),
        CanonicalVerdict::LiveProved
    );
}

#[test]
fn canonical_verdict_pass_safety_layer() {
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "pass"),
        CanonicalVerdict::Safe
    );
}

#[test]
fn canonical_verdict_fail_maps_to_unknown() {
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "fail"),
        CanonicalVerdict::Unknown
    );
    assert_eq!(
        canonical_verdict_from_layer_result("verify", "error"),
        CanonicalVerdict::Unknown
    );
}

// -- make_options --

#[test]
fn make_options_builds_correct_struct() {
    let opts = make_options(SolverChoice::Z3, 10, 30, SoundnessMode::Strict);
    assert!(matches!(opts.solver, SolverChoice::Z3));
    assert_eq!(opts.max_depth, 10);
    assert_eq!(opts.timeout_secs, 30);
    assert!(matches!(opts.soundness, SoundnessMode::Strict));
    assert!(matches!(opts.proof_engine, ProofEngine::KInduction));
    assert!(opts.dump_smt.is_none());
}

// -- automaton_footprint_json --

#[test]
fn automaton_footprint_json_has_expected_keys() {
    let fp = AutomatonFootprint {
        locations: 5,
        rules: 3,
        shared_vars: 2,
        message_counters: 1,
    };
    let json = automaton_footprint_json(fp);
    assert_eq!(json["locations"], 5);
    assert_eq!(json["rules"], 3);
    assert_eq!(json["shared_vars"], 2);
    assert_eq!(json["message_counters"], 1);
}

// -- property_template --

#[test]
fn property_template_known_kinds() {
    for kind in &[
        "agreement",
        "validity",
        "termination",
        "liveness",
        "integrity",
    ] {
        assert!(
            property_template(kind).is_some(),
            "expected template for '{kind}'"
        );
    }
}

#[test]
fn property_template_unknown() {
    assert!(property_template("finality").is_none());
}

// -- assistant_template --

#[test]
fn assistant_template_known_protocols() {
    for kind in &[
        "pbft",
        "hotstuff",
        "raft",
        "tendermint",
        "streamlet",
        "casper",
    ] {
        assert!(
            assistant_template(kind).is_some(),
            "expected scaffold for '{kind}'"
        );
    }
}

#[test]
fn assistant_template_unknown() {
    assert!(assistant_template("paxos").is_none());
}

// -- augment_query_for_proof --

#[test]
fn augment_query_for_proof_adds_produce_proofs() {
    let script = "(declare-const x Int)\n(assert (> x 0))\n(check-sat)\n(exit)\n";
    let result = augment_query_for_proof(script, "z3");
    assert!(result.starts_with("(set-option :produce-proofs true)\n"));
    assert!(result.contains("(get-proof)\n"));
    assert!(result.ends_with("(exit)\n"));
    // (exit) from original should be stripped and re-added at end
    assert!(!result.contains("(exit)\n(exit)"));
}

#[test]
fn augment_query_adds_check_sat_if_missing() {
    let script = "(assert (> x 0))\n";
    let result = augment_query_for_proof(script, "cvc5");
    assert!(result.contains("(check-sat)"));
    assert!(result.contains("(get-proof)"));
}

// -- canonicalize_obligation_smt2 --

#[test]
fn canonicalize_sorts_declarations_and_assertions() {
    let script = "(declare-const b Int)\n(declare-const a Int)\n(assert (> b 0))\n(assert (> a 0))\n(check-sat)\n(exit)\n";
    let canonical = canonicalize_obligation_smt2(script);
    let lines: Vec<&str> = canonical.lines().collect();
    // Declarations should be sorted
    let a_pos = lines.iter().position(|l| l.contains("declare-const a"));
    let b_pos = lines.iter().position(|l| l.contains("declare-const b"));
    assert!(a_pos.unwrap() < b_pos.unwrap());
    // Assertions should be sorted
    let assert_a_pos = lines.iter().position(|l| l.contains("(assert (> a"));
    let assert_b_pos = lines.iter().position(|l| l.contains("(assert (> b"));
    assert!(assert_a_pos.unwrap() < assert_b_pos.unwrap());
    // Should end with check-sat and exit
    assert!(canonical.contains("(check-sat)\n"));
    assert!(canonical.contains("(exit)\n"));
}

#[test]
fn canonicalize_deduplicates() {
    let script = "(declare-const a Int)\n(declare-const a Int)\n(assert (> a 0))\n(assert (> a 0))\n(check-sat)\n";
    let canonical = canonicalize_obligation_smt2(script);
    assert_eq!(canonical.matches("(declare-const a Int)").count(), 1);
    assert_eq!(canonical.matches("(assert (> a 0))").count(), 1);
}

#[test]
fn canonicalize_default_logic() {
    let script = "(assert true)\n(check-sat)\n";
    let canonical = canonicalize_obligation_smt2(script);
    assert!(canonical.starts_with("(set-logic QF_LIA)\n"));
}

// -- obligations_all_unsat --

#[test]
fn obligations_all_unsat_empty() {
    let metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: "safety_proof".into(),
        protocol_file: "x.trs".into(),
        proof_engine: "pdr".into(),
        induction_k: None,
        solver_used: "z3".into(),
        soundness: "strict".into(),
        fairness: None,
        committee_bounds: vec![],
        bundle_sha256: None,
        obligations: vec![],
    };
    assert!(obligations_all_unsat(&metadata));
}

#[test]
fn obligations_all_unsat_true() {
    let metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: "safety_proof".into(),
        protocol_file: "x.trs".into(),
        proof_engine: "pdr".into(),
        induction_k: None,
        solver_used: "z3".into(),
        soundness: "strict".into(),
        fairness: None,
        committee_bounds: vec![],
        bundle_sha256: None,
        obligations: vec![CertificateObligationMeta {
            name: "o1".into(),
            expected: "unsat".into(),
            file: "o1.smt2".into(),
            sha256: None,
            proof_file: None,
            proof_sha256: None,
        }],
    };
    assert!(obligations_all_unsat(&metadata));
}

#[test]
fn obligations_all_unsat_false_when_sat_present() {
    let metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: "safety_proof".into(),
        protocol_file: "x.trs".into(),
        proof_engine: "pdr".into(),
        induction_k: None,
        solver_used: "z3".into(),
        soundness: "strict".into(),
        fairness: None,
        committee_bounds: vec![],
        bundle_sha256: None,
        obligations: vec![CertificateObligationMeta {
            name: "o1".into(),
            expected: "sat".into(),
            file: "o1.smt2".into(),
            sha256: None,
            proof_file: None,
            proof_sha256: None,
        }],
    };
    assert!(!obligations_all_unsat(&metadata));
}

// -- sanitize_artifact_component --

#[cfg(feature = "governance")]
#[test]
fn sanitize_artifact_component_basic() {
    assert_eq!(sanitize_artifact_component("foo.trs"), "foo_trs");
    assert_eq!(
        sanitize_artifact_component("path/to/file.trs"),
        "path_to_file_trs"
    );
}

#[cfg(feature = "governance")]
#[test]
fn sanitize_artifact_component_empty() {
    assert_eq!(sanitize_artifact_component("..."), "entry");
}

#[cfg(feature = "governance")]
#[test]
fn sanitize_artifact_component_special_chars() {
    assert_eq!(sanitize_artifact_component("a b"), "a_b");
    assert_eq!(sanitize_artifact_component("AB-cd_12"), "ab-cd_12");
}

// -- CertificateKind --

#[test]
fn certificate_kind_as_str() {
    assert_eq!(CertificateKind::SafetyProof.as_str(), "safety_proof");
    assert_eq!(
        CertificateKind::FairLivenessProof.as_str(),
        "fair_liveness_proof"
    );
}

// -- CanonicalVerdict --

#[test]
fn canonical_verdict_as_str_and_display() {
    assert_eq!(CanonicalVerdict::Safe.as_str(), "SAFE");
    assert_eq!(CanonicalVerdict::Unsafe.as_str(), "UNSAFE");
    assert_eq!(CanonicalVerdict::LiveProved.as_str(), "LIVE_PROVED");
    assert_eq!(CanonicalVerdict::LiveCex.as_str(), "LIVE_CEX");
    assert_eq!(CanonicalVerdict::Inconclusive.as_str(), "INCONCLUSIVE");
    assert_eq!(CanonicalVerdict::Unknown.as_str(), "UNKNOWN");
    // Display should match as_str
    assert_eq!(format!("{}", CanonicalVerdict::Safe), "SAFE");
}

#[cfg(feature = "governance")]
#[test]
fn parse_manifest_proof_engine_valid() {
    assert!(matches!(
        parse_manifest_proof_engine("kinduction"),
        Ok(ProofEngine::KInduction)
    ));
    assert!(matches!(
        parse_manifest_proof_engine("pdr"),
        Ok(ProofEngine::Pdr)
    ));
    assert!(matches!(
        parse_manifest_proof_engine("ranking"),
        Ok(ProofEngine::Ranking)
    ));
}

#[cfg(feature = "governance")]
#[test]
fn parse_manifest_proof_engine_invalid() {
    assert!(parse_manifest_proof_engine("bmc").is_err());
}
