mod common;
use common::*;

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
use tarsier_engine::result::VerificationResult;

#[test]
fn parse_reliable_broadcast() {
    let source = load_example("reliable_broadcast.trs");
    let program = tarsier_dsl::parse(&source, "reliable_broadcast.trs");
    assert!(program.is_ok(), "Failed to parse: {:?}", program.err());
    let prog = program.unwrap();
    assert_eq!(prog.protocol.node.name, "ReliableBroadcast");
    assert_eq!(prog.protocol.node.parameters.len(), 3);
    assert_eq!(prog.protocol.node.messages.len(), 3);
    assert_eq!(prog.protocol.node.roles.len(), 1);
}

#[test]
fn parse_buggy_protocol() {
    let source = load_example("reliable_broadcast_buggy.trs");
    let program = tarsier_dsl::parse(&source, "reliable_broadcast_buggy.trs");
    assert!(program.is_ok(), "Failed to parse: {:?}", program.err());
    let prog = program.unwrap();
    assert_eq!(prog.protocol.node.name, "BuggyConsensus");
}

#[test]
fn parse_and_lower_library_protocols() {
    let examples = load_library_examples();
    assert!(examples.len() >= 15);
    for (file, source) in examples {
        let program = tarsier_dsl::parse(&source, &file)
            .unwrap_or_else(|e| panic!("Failed to parse {file}: {e}"));
        tarsier_ir::lowering::lower(&program)
            .unwrap_or_else(|e| panic!("Failed to lower {file}: {e}"));
    }
}

#[test]
fn library_corpus_spans_bft_and_cft_fault_models() {
    let examples = load_library_examples();
    let mut byzantine = 0usize;
    let mut crash = 0usize;
    let mut omission = 0usize;

    for (_file, source) in examples {
        if source.contains("model: byzantine;") {
            byzantine += 1;
        }
        if source.contains("model: crash;") {
            crash += 1;
        }
        if source.contains("model: omission;") {
            omission += 1;
        }
    }

    assert!(
        byzantine >= 10,
        "expected at least 10 byzantine corpus models, found {byzantine}"
    );
    assert!(
        crash >= 4,
        "expected at least 4 crash-fault corpus models, found {crash}"
    );
    assert!(
        omission >= 4,
        "expected at least 4 omission-fault corpus models, found {omission}"
    );
}

#[test]
fn cert_suite_manifest_includes_crash_and_omission_protocol_families() {
    let manifest = load_library_manifest();
    assert!(
        manifest.contains("\"file\": \"viewstamped_replication.trs\""),
        "cert suite should include canonical viewstamped replication model"
    );
    assert!(
        manifest.contains("\"file\": \"zab_atomic_broadcast.trs\""),
        "cert suite should include canonical zab model"
    );
    assert!(
        manifest.contains("\"family\": \"viewstamped-replication\""),
        "cert suite should include a viewstamped-replication family bucket"
    );
    assert!(
        manifest.contains("\"family\": \"zab\""),
        "cert suite should include a zab family bucket"
    );
}

#[test]
fn verify_library_pbft_hotstuff_tendermint_known_bug_outcomes() {
    let options = verify_options(4, SoundnessMode::Strict);
    for file in [
        "pbft_core.trs",
        "pbft_crypto_qc_bug_faithful.trs",
        "hotstuff_chained.trs",
        "hotstuff_crypto_qc_bug_faithful.trs",
        "tendermint_locking.trs",
        "tendermint_crypto_qc_bug_faithful.trs",
    ] {
        let source = load_library_example(file);
        let result = tarsier_engine::pipeline::verify(&source, file, &options)
            .unwrap_or_else(|e| panic!("verify failed for {file}: {e}"));
        match result {
            VerificationResult::Unsafe { .. } => {}
            other => panic!("Expected UNSAFE for {file}, got: {other}"),
        }
    }
}

#[test]
fn verify_library_pbft_and_hotstuff_expected_safe_outcomes() {
    let options = verify_options(4, SoundnessMode::Strict);
    for file in [
        "pbft_simple_safe.trs",
        "jolteon_fast_hotstuff.trs",
        "pbft_crypto_qc_safe_faithful.trs",
        "hotstuff_crypto_qc_safe_faithful.trs",
        "tendermint_crypto_qc_safe_faithful.trs",
    ] {
        let source = load_library_example(file);
        let result = tarsier_engine::pipeline::verify(&source, file, &options)
            .unwrap_or_else(|e| panic!("verify failed for {file}: {e}"));
        match result {
            VerificationResult::Safe { depth_checked } => {
                assert_eq!(depth_checked, 4, "unexpected depth for {file}");
            }
            other => panic!("Expected SAFE for {file}, got: {other}"),
        }
    }
}

#[test]
fn lower_reliable_broadcast() {
    let source = load_example("reliable_broadcast.trs");
    let program = tarsier_dsl::parse(&source, "reliable_broadcast.trs").unwrap();
    let ta = tarsier_ir::lowering::lower(&program).unwrap();

    // 4 phases × 8 bool var combos (accepted, decided, decision) = 32 locations
    assert_eq!(ta.locations.len(), 32);
    // 3 message types → 3 shared vars
    assert_eq!(ta.shared_vars.len(), 3);
    // 3 params
    assert_eq!(ta.parameters.len(), 3);
    // 1 initial location (waiting, accepted=false, decided=false)
    assert_eq!(ta.initial_locations.len(), 1);
    assert!(ta.resilience_condition.is_some());
}

#[test]
fn show_ta_reliable_broadcast() {
    let source = load_example("reliable_broadcast.trs");
    let output = tarsier_engine::pipeline::show_ta(&source, "reliable_broadcast.trs").unwrap();
    assert!(output.contains("Threshold Automaton:"));
    assert!(output.contains("Locations:"));
    assert!(output.contains("Rules:"));
}

#[test]
fn verify_reliable_broadcast_safe() {
    let source = load_example("reliable_broadcast.trs");
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();

    match result {
        VerificationResult::Safe { depth_checked } => {
            assert!(depth_checked >= 5, "Should verify to depth 5");
        }
        other => panic!("Expected Safe, got: {other}"),
    }
}

#[test]
fn verify_buggy_broadcast_unsafe() {
    let source = load_example("reliable_broadcast_buggy.trs");
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    match result {
        VerificationResult::Unsafe { trace } => {
            // Counterexample should have parameter values
            assert!(!trace.param_values.is_empty());
        }
        other => panic!("Expected Unsafe, got: {other}"),
    }
}

#[test]
fn dump_smt_encoding() {
    let source = load_example("reliable_broadcast.trs");
    let tmp = std::env::temp_dir().join("tarsier_test_dump.smt2");
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 60,
        dump_smt: Some(tmp.display().to_string()),
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let _ = tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options);

    let smt_content = std::fs::read_to_string(&tmp).unwrap();
    assert!(smt_content.contains("(set-logic QF_LIA)"));
    assert!(smt_content.contains("declare-const"));
    assert!(smt_content.contains("(check-sat)"));
    std::fs::remove_file(tmp).ok();
}

#[test]
fn parse_algorand_committee() {
    let source = load_example("algorand_committee.trs");
    let program = tarsier_dsl::parse(&source, "algorand_committee.trs");
    assert!(program.is_ok(), "Failed to parse: {:?}", program.err());
    let prog = program.unwrap();
    assert_eq!(prog.protocol.node.name, "AlgorandCommittee");
    assert_eq!(prog.protocol.node.parameters.len(), 4);
    assert_eq!(prog.protocol.node.committees.len(), 1);
    assert_eq!(prog.protocol.node.messages.len(), 2);
    assert_eq!(prog.protocol.node.roles.len(), 1);

    // Check committee items
    let committee = &prog.protocol.node.committees[0];
    assert_eq!(committee.name, "voters");
    assert_eq!(committee.items.len(), 5);
}

#[test]
fn lower_algorand_committee() {
    let source = load_example("algorand_committee.trs");
    let program = tarsier_dsl::parse(&source, "algorand_committee.trs").unwrap();
    let ta = tarsier_ir::lowering::lower(&program).unwrap();

    // 4 params: n, t, f, b
    assert_eq!(ta.parameters.len(), 4);
    // 2 message types -> 2 shared vars
    assert_eq!(ta.shared_vars.len(), 2);
    // 1 committee
    assert_eq!(ta.committees.len(), 1);
    // adversary bound set
    assert!(ta.adversary_bound_param.is_some());
}

#[test]
fn verify_algorand_committee_probabilistic_safe() {
    let source = load_example("algorand_committee.trs");
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 120,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let result =
        tarsier_engine::pipeline::verify(&source, "algorand_committee.trs", &options).unwrap();

    match result {
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => {
            assert!(depth_checked >= 5, "Should verify to depth 5");
            assert!(
                failure_probability <= 1e-8,
                "Failure prob should be <= 1e-8"
            );
            assert_eq!(
                committee_analyses.len(),
                1,
                "Should have 1 committee analysis"
            );
            let ca = &committee_analyses[0];
            assert_eq!(ca.name, "voters");
            assert_eq!(ca.population, 1000);
            assert_eq!(ca.byzantine, 333);
            assert_eq!(ca.committee_size, 100);
            assert!(ca.b_max > 33, "b_max should be above expected value");
            assert!(ca.b_max < 100, "b_max should be less than committee size");
        }
        other => panic!("Expected ProbabilisticallySafe, got: {other}"),
    }
}

#[test]
fn verify_algorand_committee_display() {
    let source = load_example("algorand_committee.trs");
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let result =
        tarsier_engine::pipeline::verify(&source, "algorand_committee.trs", &options).unwrap();

    let display = format!("{result}");
    assert!(
        display.contains("SAFE (probabilistic)"),
        "Should show probabilistic safety: {display}"
    );
    assert!(
        display.contains("voters"),
        "Should mention committee name: {display}"
    );
    assert!(
        display.contains("1000"),
        "Should mention population: {display}"
    );
}

#[test]
fn strict_mode_requires_explicit_property() {
    let source = r#"
protocol NoProp {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let err = tarsier_engine::pipeline::verify(source, "no_prop.trs", &options)
        .expect_err("strict mode should reject missing property");
    let msg = format!("{err}");
    assert!(
        msg.contains("exactly one safety property"),
        "unexpected error: {msg}"
    );
}

#[test]
fn permissive_mode_allows_missing_property() {
    let source = r#"
protocol NoPropPermissive {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Permissive,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::verify(source, "no_prop_permissive.trs", &options).unwrap();
    match result {
        VerificationResult::Safe { .. } => {}
        other => panic!("Expected Safe in permissive mode, got: {other}"),
    }
}

#[test]
fn strict_mode_rejects_unbounded_int_locals() {
    let source = r#"
protocol UnboundedLocal {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var view: nat = 0;
        var decided: bool = false;
        init s;
        phase s {}
    }
    property agreement: agreement {
        forall p: R. forall q: R. p.decided == q.decided
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let err = tarsier_engine::pipeline::verify(source, "unbounded_local.trs", &options)
        .expect_err("strict mode should reject unbounded int/nat locals");
    let msg = format!("{err}");
    assert!(
        msg.contains("Unbounded local variable"),
        "unexpected error: {msg}"
    );
}

#[test]
fn strict_mode_accepts_omission_model_with_gst() {
    let source = r#"
protocol StrictOmission {
    params n, t, f, gst;
    resilience: n > 3*t;
    adversary { model: omission; bound: f; timing: partial_synchrony; gst: gst; }
    message M;
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "strict_omission.trs", &options)
        .expect("strict mode should accept omission model with gst");
    match result {
        VerificationResult::Safe { depth_checked } => assert_eq!(depth_checked, 2),
        other => panic!("Expected SAFE, got: {other}"),
    }
}

#[test]
fn strict_mode_requires_adversary_bound_when_fault_model_is_explicit() {
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    for (model, file) in [
        ("crash", "strict_missing_bound_crash.trs"),
        ("omission", "strict_missing_bound_omission.trs"),
    ] {
        let source = format!(
            r#"
protocol MissingBound {{
    params n, t;
    resilience: n > 3*t;
    adversary {{ model: {model}; }}
    role R {{
        var decided: bool = true;
        init s;
        phase s {{}}
    }}
    property inv: safety {{
        forall p: R. p.decided == true
    }}
}}
"#
        );
        let err = tarsier_engine::pipeline::verify(&source, file, &options).expect_err(
            "strict mode should reject explicit crash/omission model without adversary bound",
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("adversary { bound: <param>; }"),
            "unexpected error: {msg}"
        );
    }
}

#[test]
fn strict_mode_accepts_distinct_guard_with_exact_sender_semantics() {
    let source = r#"
protocol DistinctApprox {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received distinct >= n+1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "distinct_approx.trs", &options)
        .expect("strict mode should accept exact distinct-sender semantics");
    match result {
        VerificationResult::Safe { .. } => {}
        other => panic!("Expected Safe, got: {other}"),
    }
}

#[test]
fn verify_accepts_process_selective_network_semantics() {
    let source = r#"
protocol ProcessSelectiveVerify {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        network: process_selective;
        equivocation: full;
        delivery: per_recipient;
        faults: per_recipient;
    }
    identity R: process(pid) key r_key;
    message Vote;
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "process_selective_verify.trs", &options)
        .expect("verify should support process_selective network semantics");
    match result {
        VerificationResult::Unsafe { .. } => {}
        other => panic!("Expected UNSAFE, got: {other}"),
    }
}

#[test]
fn strict_mode_rejects_faithful_mode_without_explicit_identity_and_auth() {
    let source = r#"
protocol FaithfulStrictMissingIdentityAuth {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        network: identity_selective;
    }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let err =
        tarsier_engine::pipeline::verify(source, "faithful_missing_identity_auth.trs", &options)
            .expect_err(
                "strict mode should reject faithful network without explicit identity/auth",
            );
    let msg = err.to_string();
    assert!(
        msg.contains("explicit `identity` declarations")
            || msg.contains("explicit authentication semantics"),
        "unexpected error: {msg}"
    );
}

#[test]
fn strict_mode_rejects_non_monotone_thresholds_under_full_byzantine_equivocation() {
    let source = r#"
protocol NonMonotoneGuard {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received <= t Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let err = tarsier_engine::pipeline::verify(source, "non_monotone_guard.trs", &options)
        .expect_err("strict mode should reject non-monotone byzantine thresholds");
    let msg = format!("{err}");
    assert!(
        msg.contains("full-equivocation") && msg.contains("monotone threshold"),
        "unexpected error: {msg}"
    );
}

#[test]
fn strict_mode_allows_non_monotone_thresholds_with_equivocation_none() {
    let source = r#"
protocol NonMonotoneGuardNoEq {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; equivocation: none; }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received <= t Vote => {
                goto phase s;
            }
        }
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "non_monotone_guard_no_eq.trs", &options)
        .expect("strict mode should allow non-monotone thresholds with equivocation none");
    match result {
        VerificationResult::Safe { .. } => {}
        other => panic!("Expected SAFE, got: {other}"),
    }
}

#[test]
fn distinct_adversary_budget_is_cumulative_per_counter() {
    let source = r#"
protocol DistinctAdvBudget {
    params n, t, f;
    resilience: n = 3*f+1;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received distinct >= 2*f+1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "distinct_adv_budget.trs", &options)
        .expect("verification should complete");
    match result {
        VerificationResult::Safe { .. } => {}
        other => panic!("Expected Safe with cumulative adversary distinct budget, got: {other}"),
    }
}

#[test]
fn prove_safety_reports_actionable_error_for_liveness_only_protocols() {
    let source = r#"
protocol LivenessOnlyForProve {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 5,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let err = tarsier_engine::pipeline::prove_safety(source, "liveness_only_prove.trs", &options)
        .expect_err("prove_safety should guide users to fair-liveness");
    let msg = format!("{err}");
    assert!(
        msg.contains("prove-fair") || msg.contains("prove_fair_liveness"),
        "unexpected error: {msg}"
    );
}

#[test]
fn verify_accepts_safety_plus_liveness_property() {
    let source = r#"
protocol MixedProps {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
    property term: liveness {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::verify(source, "mixed_props.trs", &options)
        .expect("verify should accept mixed safety/liveness declarations");
    match result {
        VerificationResult::Safe { depth_checked } => assert_eq!(depth_checked, 2),
        other => panic!("Expected SAFE verification, got: {other}"),
    }
}

