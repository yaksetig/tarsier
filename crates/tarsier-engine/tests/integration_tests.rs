use tarsier_engine::pipeline::{
    FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{
    BoundKind, CegarStageOutcome, FairLivenessResult, LivenessResult, UnboundedFairLivenessResult,
    UnboundedSafetyResult, VerificationResult,
};

fn load_example(name: &str) -> String {
    let path = format!("{}/../../examples/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

fn load_library_examples() -> Vec<(String, String)> {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&library_dir)
        .unwrap_or_else(|e| panic!("Failed to read {library_dir}: {e}"))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("trs"))
        .collect();
    files.sort();

    files
        .into_iter()
        .map(|path| {
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.trs")
                .to_string();
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
            (file, src)
        })
        .collect()
}

fn load_library_example(name: &str) -> String {
    let path = format!(
        "{}/../../examples/library/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

fn load_library_manifest() -> String {
    let path = format!(
        "{}/../../examples/library/cert_suite.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

fn verify_options(depth: usize, soundness: SoundnessMode) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 60,
        dump_smt: None,
        soundness,
        proof_engine: ProofEngine::KInduction,
    }
}

fn add_identity_selective_overlay_for_replica(source: &str) -> String {
    let mut out = source.to_string();
    if !out.contains("network: identity_selective;") {
        if out.contains("values: sign;") {
            out = out.replacen(
                "values: sign;",
                "values: sign;\n        auth: signed;\n        network: identity_selective;",
                1,
            );
        } else {
            out = out.replacen(
                "bound: f;",
                "bound: f;\n        auth: signed;\n        network: identity_selective;",
                1,
            );
        }
    }
    if !out.contains("identity Replica:") {
        out = out.replacen(
            "    message ",
            "    identity Replica: role key replica_key;\n\n    message ",
            1,
        );
    }
    out
}

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
fn verify_library_crypto_object_paths_are_reachable_in_real_snippets() {
    let options = verify_options(4, SoundnessMode::Strict);
    for (file, object_family) in [
        ("pbft_crypto_qc_bug_faithful.trs", "PrepareQC"),
        ("hotstuff_crypto_qc_bug_faithful.trs", "HighQC"),
        ("tendermint_crypto_qc_bug_faithful.trs", "Polka"),
    ] {
        let source = load_library_example(file);
        let result = tarsier_engine::pipeline::verify(&source, file, &options)
            .unwrap_or_else(|e| panic!("verify failed for {file}: {e}"));
        match result {
            VerificationResult::Unsafe { trace } => {
                let seen = trace
                    .steps
                    .iter()
                    .flat_map(|step| step.deliveries.iter())
                    .any(|d| {
                        d.payload.family == object_family
                            && matches!(
                                d.kind,
                                tarsier_ir::counter_system::MessageEventKind::Send
                                    | tarsier_ir::counter_system::MessageEventKind::Deliver
                            )
                    });
                assert!(
                    seen,
                    "expected reachable crypto-object family '{object_family}' in counterexample for {file}"
                );
            }
            other => panic!("Expected UNSAFE with trace for {file}, got: {other}"),
        }
    }
}

#[test]
fn regression_legacy_vs_faithful_overlay_on_bft_library_cases() {
    let legacy_options = verify_options(4, SoundnessMode::Strict);
    let faithful_options = verify_options(4, SoundnessMode::Strict);
    for file in [
        "pbft_core.trs",
        "hotstuff_chained.trs",
        "tendermint_locking.trs",
    ] {
        let legacy_source = load_library_example(file);
        let faithful_source = add_identity_selective_overlay_for_replica(&legacy_source);

        let legacy_result = tarsier_engine::pipeline::verify(&legacy_source, file, &legacy_options)
            .unwrap_or_else(|e| panic!("legacy verify failed for {file}: {e}"));
        let faithful_result = tarsier_engine::pipeline::verify(
            &faithful_source,
            &format!("faithful_overlay_{file}"),
            &faithful_options,
        )
        .unwrap_or_else(|e| panic!("faithful verify failed for {file}: {e}"));

        assert!(
            matches!(legacy_result, VerificationResult::Unsafe { .. }),
            "legacy result for {file} should be UNSAFE"
        );
        assert!(
            matches!(faithful_result, VerificationResult::Unsafe { .. }),
            "faithful overlay result for {file} should be UNSAFE"
        );
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
fn comm_complexity_reliable_broadcast() {
    let source = load_example("reliable_broadcast.trs");
    let report =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();
    assert!(report.per_step_bound.contains("n"));
    assert!(report.depth == 3);
}

#[test]
fn comm_complexity_byzantine_adv_bound_is_family_recipient_aware_with_signed_auth() {
    let source = r#"
protocol CommSigned {
    params n, f;
    resilience: n = 3*f + 1;
    adversary { model: byzantine; bound: f; auth: signed; }

    message Vote(v: bool);

    role A {
        var active: bool = true;
        init s;
        phase s {
            when active == true => { send Vote(v=true); }
        }
    }

    role B {
        var active: bool = true;
        init s;
        phase s {}
    }
}
"#;

    let report = tarsier_engine::pipeline::comm_complexity(source, "comm_signed.trs", 2).unwrap();
    assert_eq!(report.adversary_per_step_bound.as_deref(), Some("f * 2"));
    assert_eq!(
        report
            .adversary_per_step_type_bounds
            .iter()
            .find(|(msg, _)| msg == "Vote")
            .map(|(_, b)| b.as_str()),
        Some("f * 2")
    );
    assert_eq!(
        report.per_step_bound_with_adv.as_deref(),
        Some("n * 2 + f * 2")
    );
}

#[test]
fn comm_complexity_byzantine_adv_bound_scales_with_variants_without_auth() {
    let source = r#"
protocol CommUnsigned {
    params n, f;
    resilience: n = 3*f + 1;
    adversary { model: byzantine; bound: f; }

    message Vote(v: bool);

    role A {
        var active: bool = true;
        init s;
        phase s {
            when active == true => { send Vote(v=true); }
        }
    }

    role B {
        var active: bool = true;
        init s;
        phase s {}
    }
}
"#;

    let report = tarsier_engine::pipeline::comm_complexity(source, "comm_unsigned.trs", 2).unwrap();
    assert_eq!(report.adversary_per_step_bound.as_deref(), Some("f * 4"));
    assert_eq!(
        report
            .adversary_per_step_type_bounds
            .iter()
            .find(|(msg, _)| msg == "Vote")
            .map(|(_, b)| b.as_str()),
        Some("f * 4")
    );
    assert_eq!(
        report.per_step_bound_with_adv.as_deref(),
        Some("n * 2 + f * 4")
    );
}

#[test]
fn comm_complexity_uses_role_population_parameters_when_available() {
    let source = r#"
protocol CommRoleAware {
    params n, n_a, n_b, f;
    resilience: n = n_a + n_b;
    adversary { model: byzantine; bound: f; auth: signed; }

    message Ping;

    role A {
        var active: bool = true;
        init s;
        phase s {
            when active == true => { send Ping; }
        }
    }

    role B {
        var active: bool = true;
        init s;
        phase s {
            when active == true => { send Ping to B; }
        }
    }
}
"#;

    let report =
        tarsier_engine::pipeline::comm_complexity(source, "comm_role_aware.trs", 2).unwrap();
    assert_eq!(report.per_step_bound, "n_a * 2 + n_b");
    assert_eq!(report.per_depth_bound, "2 * (n_a * 2 + n_b)");
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
fn verify_with_cegar_eliminates_equivocation_spurious_counterexample() {
    let source = r#"
protocol CegarEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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

    let no_cegar = tarsier_engine::pipeline::verify(source, "cegar_equivocation.trs", &options)
        .expect("plain verify should complete");
    match no_cegar {
        VerificationResult::Unsafe { .. } => {}
        other => panic!("Expected UNSAFE without CEGAR, got: {other}"),
    }

    let with_cegar =
        tarsier_engine::pipeline::verify_with_cegar(source, "cegar_equivocation.trs", &options, 1)
            .expect("CEGAR verify should complete");
    match with_cegar {
        VerificationResult::Unknown { reason } => {
            assert!(reason.contains("CEGAR refinements eliminated"));
        }
        other => panic!("Expected CEGAR UNKNOWN due to eliminated cex, got: {other}"),
    }
}

#[test]
fn verify_with_cegar_report_records_refinement_stages() {
    let source = r#"
protocol CegarReport {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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

    let report =
        tarsier_engine::pipeline::verify_with_cegar_report(source, "cegar_report.trs", &options, 1)
            .expect("CEGAR report should complete");

    assert_eq!(report.max_refinements, 1);
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(
        report.stages[1].label.contains("equivocation"),
        "first refinement stage should include an equivocation-tightening predicate"
    );
    assert_eq!(report.classification, "inconclusive");
    assert_eq!(report.termination.iteration_budget, 1);
    assert_eq!(report.termination.iterations_used, 1);
    assert!(
        report.termination.reason == "counterexample_eliminated_no_confirmation"
            || report.termination.reason == "max_refinements_reached",
        "termination reason should explain loop stop condition"
    );
    assert!(
        report
            .discovered_predicates
            .iter()
            .any(|pred| pred.contains("equivocation")),
        "discovered predicates should include at least one equivocation predicate"
    );
    let baseline_analysis = report.stages[0]
        .counterexample_analysis
        .as_ref()
        .expect("baseline stage should include counterexample analysis");
    assert_eq!(baseline_analysis.classification, "potentially_spurious");
    assert!(baseline_analysis
        .rationale
        .contains("Baseline stage reported UNSAFE"));
    let refined_analysis = report.stages[1]
        .counterexample_analysis
        .as_ref()
        .expect("refined stage should include counterexample analysis");
    assert_eq!(refined_analysis.classification, "potentially_spurious");
    assert!(refined_analysis.rationale.contains("eliminated"));
    assert!(
        report.stages[1]
            .model_changes
            .iter()
            .any(|change| !change.predicate.is_empty()),
        "stage report should include explicit model change details"
    );
    assert_eq!(
        report.stages[1].eliminated_traces.len(),
        1,
        "stage report should include eliminated baseline trace"
    );
    assert!(
        !report.stages[1].discovered_predicates.is_empty(),
        "stage report should expose discovered predicates for elimination stages"
    );
    let overall_analysis = report
        .counterexample_analysis
        .as_ref()
        .expect("overall report should include counterexample analysis");
    assert_eq!(overall_analysis.classification, "potentially_spurious");
    assert!(overall_analysis.rationale.contains("eliminated"));
    assert!(matches!(
        report.stages[0].outcome,
        CegarStageOutcome::Unsafe { .. }
    ));
    assert!(matches!(
        report.final_result,
        VerificationResult::Unknown { .. }
    ));
}

#[test]
fn verify_with_cegar_report_includes_values_exact_refinement() {
    let source = r#"
protocol CegarValues {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: none; auth: signed; values: sign; }
    message Vote(v: nat in 0..3);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote(v=0) => {
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

    let report =
        tarsier_engine::pipeline::verify_with_cegar_report(source, "cegar_values.trs", &options, 1)
            .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "values:exact");
}

#[test]
fn verify_with_cegar_report_classifies_persistent_witness_as_concrete() {
    let source = r#"
protocol CegarConcrete {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: full; auth: none; network: classic; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote(v=true) => {
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

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_concrete.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.classification, "unsafe_confirmed");
    assert_eq!(report.stages.len(), 2);
    assert!(matches!(
        report.stages[1].outcome,
        CegarStageOutcome::Unsafe { .. }
    ));
    let stage_analysis = report.stages[1]
        .counterexample_analysis
        .as_ref()
        .expect("unsafe refined stage should include analysis");
    assert_eq!(stage_analysis.classification, "concrete");
    assert!(stage_analysis.rationale.contains("persists"));
    assert!(
        report.stages[1].eliminated_traces.is_empty(),
        "persistent unsafe stage should not report eliminated traces"
    );
    let overall_analysis = report
        .counterexample_analysis
        .as_ref()
        .expect("overall report should include analysis");
    assert_eq!(overall_analysis.classification, "concrete");
}

#[test]
fn verify_with_cegar_report_synthesizes_message_scoped_refinements() {
    let source = r#"
protocol CegarMessageScoped {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_message_scoped.trs",
        &options,
        2,
    )
    .expect("CEGAR report should complete");

    assert!(
        report
            .stages
            .iter()
            .any(|stage| stage.label.contains("equivocation:Vote=none")),
        "trace-based refinement discovery should synthesize message-scoped equivocation predicates"
    );
    assert!(
        report
            .discovered_predicates
            .contains(&"equivocation(Vote)=none".to_string()),
        "discovered predicates should include synthesized message-scoped refinements"
    );
}

#[test]
fn soundness_negative_spurious_value_abstraction_trace_is_eliminated_by_cegar() {
    let source = r#"
protocol SpuriousValuesSign {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
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
    let options = verify_options(2, SoundnessMode::Strict);

    let baseline =
        tarsier_engine::pipeline::verify(source, "spurious_values_sign.trs", &options).unwrap();
    assert!(
        matches!(baseline, VerificationResult::Unsafe { .. }),
        "baseline sign abstraction should expose a spurious unsafe trace"
    );

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "spurious_values_sign.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.classification, "inconclusive");
    assert_eq!(
        report.discovered_predicates,
        vec!["adversary.values=exact".to_string()]
    );
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "values:exact");
    assert!(matches!(
        report.stages[1].outcome,
        CegarStageOutcome::Safe { .. }
    ));
    assert!(matches!(
        report.final_result,
        VerificationResult::Unknown { .. }
    ));
}

#[test]
fn regression_known_spurious_cases_are_eliminated_by_refinement() {
    struct Case<'a> {
        name: &'a str,
        source: &'a str,
        depth: usize,
        max_refinements: usize,
        expected_predicate_fragment: &'a str,
    }

    let cases = vec![
        Case {
            name: "equivocation_global",
            source: r#"
protocol SpuriousEqGlobal {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "equivocation",
        },
        Case {
            name: "value_abstraction_sign",
            source: r#"
protocol SpuriousValuesSignRegression {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
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
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "values=exact",
        },
        Case {
            name: "equivocation_message_scoped",
            source: r#"
protocol SpuriousEqMessageScoped {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "equivocation(Vote)=none",
        },
    ];

    for case in cases {
        let options = verify_options(case.depth, SoundnessMode::Strict);
        let baseline = tarsier_engine::pipeline::verify(case.source, case.name, &options)
            .unwrap_or_else(|e| panic!("baseline verify should succeed for {}: {e}", case.name));
        assert!(
            matches!(baseline, VerificationResult::Unsafe { .. }),
            "baseline run should expose spurious unsafe witness for {}",
            case.name
        );

        let report = tarsier_engine::pipeline::verify_with_cegar_report(
            case.source,
            case.name,
            &options,
            case.max_refinements,
        )
        .unwrap_or_else(|e| panic!("cegar report should succeed for {}: {e}", case.name));

        assert_eq!(
            report.classification, "inconclusive",
            "eliminated baseline witness without refined concrete unsafe must be inconclusive ({})",
            case.name
        );
        assert!(
            matches!(report.final_result, VerificationResult::Unknown { .. }),
            "eliminated baseline witness must produce unknown/inconclusive verdict ({})",
            case.name
        );
        assert!(
            report
                .stages
                .iter()
                .any(|s| !s.eliminated_traces.is_empty()),
            "cegar stages should record eliminated baseline trace for {}",
            case.name
        );
        assert!(
            report
                .discovered_predicates
                .iter()
                .any(|p| p.contains(case.expected_predicate_fragment)),
            "discovered predicates should include fragment '{}' for {}",
            case.expected_predicate_fragment,
            case.name
        );
    }
}

#[test]
fn scalability_refinement_materially_reduces_false_alarms_on_harder_models() {
    struct HardCase<'a> {
        name: &'a str,
        source: &'a str,
        depth: usize,
        refinements: usize,
    }

    // These models intentionally stress approximation-sensitive paths with
    // wider local domains and multi-phase guards, so baseline runs expose
    // spurious UNSAFE witnesses that refinement should eliminate.
    let cases = vec![
        HardCase {
            name: "hard_equivocation_multiphase.trs",
            source: r#"
protocol HardEquivocationMultiphase {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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
"#,
            depth: 2,
            refinements: 3,
        },
        HardCase {
            name: "hard_values_sign_multiphase.trs",
            source: r#"
protocol HardValuesSignMultiphase {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
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
"#,
            depth: 2,
            refinements: 3,
        },
        HardCase {
            name: "hard_message_scoped_equivocation.trs",
            source: r#"
protocol HardMessageScopedEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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
"#,
            depth: 2,
            refinements: 3,
        },
    ];

    let mut baseline_false_alarms = 0usize;
    let mut remaining_false_alarms_after_refinement = 0usize;
    let mut eliminated_cases = 0usize;

    for case in cases {
        let options = verify_options(case.depth, SoundnessMode::Strict);
        let baseline = tarsier_engine::pipeline::verify(case.source, case.name, &options)
            .unwrap_or_else(|e| panic!("baseline verify should succeed for {}: {e}", case.name));
        if !matches!(baseline, VerificationResult::Unsafe { .. }) {
            // Some models may become proved-safe as the core engine tightens.
            // Keep the suite robust by only measuring cases that still trigger
            // approximation false alarms at baseline.
            continue;
        }
        baseline_false_alarms += 1;

        let report = tarsier_engine::pipeline::verify_with_cegar_report(
            case.source,
            case.name,
            &options,
            case.refinements,
        )
        .unwrap_or_else(|e| panic!("cegar report should succeed for {}: {e}", case.name));

        if report
            .stages
            .iter()
            .any(|stage| !stage.eliminated_traces.is_empty())
        {
            eliminated_cases += 1;
        }
        if matches!(report.final_result, VerificationResult::Unsafe { .. }) {
            remaining_false_alarms_after_refinement += 1;
        }
    }

    assert_eq!(
        baseline_false_alarms, 3,
        "all selected harder cases should expose baseline false alarms"
    );
    let reduced = baseline_false_alarms.saturating_sub(remaining_false_alarms_after_refinement);
    assert!(
        reduced * 100 >= baseline_false_alarms * 66,
        "refinement should materially reduce false alarms on harder models \
         (baseline={}, remaining={}, reduced={})",
        baseline_false_alarms,
        remaining_false_alarms_after_refinement,
        reduced
    );
    assert!(
        eliminated_cases >= 2,
        "at least two harder models should show explicit eliminated traces (got {})",
        eliminated_cases
    );
}

#[test]
fn verify_with_cegar_report_includes_network_identity_selective_refinement() {
    let source = r#"
protocol CegarNetwork {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        auth: signed;
        values: exact;
        network: classic;
    }
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

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_network.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "network:identity_selective");
    assert_eq!(
        report.stages[1].refinements,
        vec!["adversary.network=identity_selective".to_string()]
    );
}

#[test]
fn verify_with_cegar_report_includes_network_process_selective_refinement() {
    let source = r#"
protocol CegarNetworkProcess {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        auth: signed;
        values: exact;
        network: identity_selective;
    }
    identity R: role key r_key;
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

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_network_process.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "network:process_selective");
    assert_eq!(
        report.stages[1].refinements,
        vec!["adversary.network=process_selective".to_string()]
    );
}

#[test]
fn prove_with_cegar_eliminates_equivocation_spurious_counterexample() {
    let source = r#"
protocol CegarProveEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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

    let no_cegar = tarsier_engine::pipeline::prove_safety(source, "cegar_prove.trs", &options)
        .expect("plain prove should complete");
    match no_cegar {
        UnboundedSafetyResult::Unsafe { .. } => {}
        other => panic!("Expected UNSAFE without CEGAR, got: {other}"),
    }

    let with_cegar =
        tarsier_engine::pipeline::prove_safety_with_cegar(source, "cegar_prove.trs", &options, 1)
            .expect("CEGAR prove should complete");
    match with_cegar {
        UnboundedSafetyResult::Unknown { reason } => {
            assert!(
                reason.contains("CEGAR refinements eliminated")
                    || reason.contains("CEGAR refinements were inconclusive")
            );
        }
        other => panic!("Expected CEGAR UNKNOWN due to eliminated unsafe witness, got: {other}"),
    }
}

#[test]
fn prove_with_cegar_report_exposes_controls_and_machine_readable_status() {
    let source = r#"
protocol CegarProveEquivocationReport {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
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

    let report = tarsier_engine::pipeline::prove_safety_with_cegar_report(
        source,
        "cegar_prove_report.trs",
        &options,
        1,
    )
    .expect("CEGAR proof report should complete");

    assert_eq!(report.controls.max_refinements, 1);
    assert_eq!(report.controls.timeout_secs, 30);
    assert_eq!(report.controls.solver, "z3");
    assert_eq!(report.controls.proof_engine.as_deref(), Some("kinduction"));
    assert!(report.controls.fairness.is_none());
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].stage, 0);
    assert_eq!(report.stages[1].stage, 1);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(report.stages[1]
        .note
        .as_deref()
        .unwrap_or_default()
        .contains("Selection rationale"));
    assert!(matches!(
        report.baseline_result,
        UnboundedSafetyResult::Unsafe { .. }
    ));
    assert!(matches!(
        report.final_result,
        UnboundedSafetyResult::Unknown { .. }
    ));
    assert_eq!(report.classification, "inconclusive");
    let analysis = report
        .counterexample_analysis
        .expect("counterexample analysis should exist");
    assert!(
        analysis.classification == "potentially_spurious"
            || analysis.classification == "inconclusive"
    );
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
fn prove_unbounded_safety_trivial_invariant() {
    let source = r#"
protocol TrivialSafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
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
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_safe.trs", &options)
        .expect("prove should succeed");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => assert!(induction_k >= 1),
        other => panic!("Expected unbounded safe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_reports_real_counterexample() {
    let source = r#"
protocol TrivialUnsafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 M => {
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
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_unsafe.trs", &options)
        .expect("prove should complete");
    match result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(!trace.param_values.is_empty());
        }
        other => panic!("Expected unsafe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_with_pdr_engine_safe() {
    let source = r#"
protocol TrivialSafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
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
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_safe_pdr.trs", &options)
        .expect("prove should succeed");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => assert!(induction_k >= 1),
        other => panic!("Expected unbounded safe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_with_pdr_engine_unsafe() {
    let source = r#"
protocol TrivialUnsafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 M => {
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
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_safety(source, "trivial_unsafe_pdr.trs", &options)
        .expect("prove should complete");
    match result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(!trace.param_values.is_empty());
        }
        other => panic!("Expected unsafe, got: {other}"),
    }
}

#[test]
fn prove_unbounded_safety_not_proved_reports_induction_cti() {
    let source = r#"
protocol NeedsStrengthening {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    message Prepare;
    role R {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Prepare => {
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
        max_depth: 3,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::prove_safety(source, "needs_strengthening.trs", &options)
            .expect("prove should complete");
    match result {
        UnboundedSafetyResult::NotProved {
            max_k,
            cti: Some(cti),
        } => {
            assert_eq!(max_k, 3);
            assert!((1..=3).contains(&cti.k));
            assert!(!cti.violating_locations.is_empty());
            assert!(cti.violated_condition.contains("invariant violated"));
        }
        other => panic!("Expected not proved with CTI, got: {other}"),
    }
}

#[test]
fn prove_with_cegar_auto_synthesizes_predicates_from_cti() {
    let source = r#"
protocol NeedsStrengtheningCegar {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    message Prepare;
    role R {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Prepare => {
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
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::prove_safety_with_cegar(
        source,
        "needs_strengthening_cegar.trs",
        &options,
        2,
    )
    .expect("prove with CEGAR should complete");
    match result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {}
        UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => {
            assert!(
                cti.violated_condition
                    .contains("auto-synthesized predicates"),
                "expected synthesized predicate note, got: {}",
                cti.violated_condition
            );
        }
        UnboundedSafetyResult::Unknown { reason } => {
            assert!(
                reason.contains("Auto-synthesized predicates")
                    || reason.contains("CEGAR refinements"),
                "expected synthesis/refinement note, got: {reason}"
            );
        }
        other => panic!("Unexpected CEGAR prove result: {other}"),
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
fn bounded_liveness_uses_explicit_liveness_property() {
    let source = r#"
protocol CustomLiveness {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var done: bool = false;
        init s;
        phase s {
            when received >= 0 Tick => {
                done = true;
                goto phase done_phase;
            }
        }
        phase done_phase {}
    }
    message Tick;
    property term: liveness {
        forall p: R. p.done == true
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
    let result = tarsier_engine::pipeline::check_liveness(source, "custom_liveness.trs", &options)
        .expect("liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } | LivenessResult::Live { .. } => {}
        other => panic!("Expected concrete bounded liveness result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_always_operator() {
    let source = r#"
protocol TemporalAlways {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var safe: bool = true;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (p.safe == true)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_liveness(source, "temporal_always.trs", &options)
        .expect("temporal liveness check should complete");
    match result {
        LivenessResult::Live { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected LIVE temporal result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_next_operator() {
    let source = r#"
protocol TemporalNext {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var ready: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. X (p.ready == true)
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
    let result = tarsier_engine::pipeline::check_liveness(source, "temporal_next.trs", &options)
        .expect("temporal next liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } => {}
        other => panic!("Expected NOT LIVE temporal-next result, got: {other}"),
    }
}

#[test]
fn bounded_liveness_supports_temporal_leads_to_operator() {
    let source = r#"
protocol TemporalLeadsTo {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Tick;
    role R {
        var flag: bool = false;
        init s0;
        phase s0 {
            when received >= 0 Tick => {
                flag = true;
                goto phase s1;
            }
        }
        phase s1 {}
    }
    property live: liveness {
        forall p: R. (p.flag == true) ~> <> (p.flag == false)
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
    let result =
        tarsier_engine::pipeline::check_liveness(source, "temporal_leads_to.trs", &options)
            .expect("temporal liveness check should complete");
    match result {
        LivenessResult::NotLive { .. } => {}
        other => panic!("Expected NOT LIVE temporal result, got: {other}"),
    }
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

#[test]
fn fair_liveness_finds_nonterminating_lasso() {
    let source = r#"
protocol FairNonTerminating {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_nonterminating.trs", &options)
            .expect("fair liveness search should complete");
    match result {
        FairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected fair cycle, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_unbounded_temporal_formula() {
    let source = r#"
protocol FairTemporalUnsupported {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (p.decided == false)
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_temporal.trs", &options)
            .expect("fair-liveness should support temporal operators");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for satisfied temporal property, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_unbounded_temporal_next_operator() {
    let source = r#"
protocol FairTemporalNext {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. [] (X (p.decided == false))
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_temporal_next.trs", &options)
            .expect("fair-liveness should support temporal next operator");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for temporal-next property, got: {other}"),
    }
}

#[test]
fn fair_liveness_supports_all_unbounded_temporal_infix_operators() {
    let source = r#"
protocol FairTemporalInfixOps {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R.
            ((p.decided == false) U (p.decided == false)) &&
            ((p.decided == false) W (p.decided == true)) &&
            ((p.decided == false) R (p.decided == false)) &&
            ((p.decided == true) ~> <> (p.decided == false))
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_fair_liveness(
        source,
        "fair_temporal_infix_ops.trs",
        &options,
    )
    .expect("fair-liveness should support all infix temporal operators");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 3),
        other => panic!("Expected no fair cycle for satisfied temporal formula, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_accepts_temporal_formula() {
    let source = r#"
protocol FairTemporalCounterexample {
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
        max_depth: 5,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result =
        tarsier_engine::pipeline::prove_fair_liveness(source, "fair_temporal_cex.trs", &options)
            .expect("prove-fair should support temporal operators");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. }
        | UnboundedFairLivenessResult::LiveProved { .. }
        | UnboundedFairLivenessResult::NotProved { .. }
        | UnboundedFairLivenessResult::Unknown { .. } => {}
    }
}

#[test]
fn prove_fair_liveness_accepts_all_temporal_infix_operators() {
    let source = r#"
protocol FairTemporalInfixProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R.
            ((p.decided == false) U (p.decided == false)) &&
            ((p.decided == false) W (p.decided == true)) &&
            ((p.decided == false) R (p.decided == false)) &&
            ((p.decided == true) ~> <> (p.decided == false))
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 5,
        timeout_secs: 2,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_temporal_infix_proof.trs",
        &options,
    )
    .expect("prove-fair should support all infix temporal operators");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. }
        | UnboundedFairLivenessResult::LiveProved { .. }
        | UnboundedFairLivenessResult::NotProved { .. }
        | UnboundedFairLivenessResult::Unknown { .. } => {}
    }
}

#[test]
fn fair_liveness_no_counterexample_when_already_decided() {
    let source = r#"
protocol FairAlreadyDecided {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result =
        tarsier_engine::pipeline::check_fair_liveness(source, "fair_already_decided.trs", &options)
            .expect("fair liveness search should complete");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
            assert_eq!(depth_checked, 3);
        }
        other => panic!("Expected no fair cycle up to bound, got: {other}"),
    }
}

#[test]
fn fair_liveness_strong_mode_finds_counterexample() {
    let source = r#"
protocol FairNonTerminatingStrong {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
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

    let strong = tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        "fair_nonterminating_strong.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("strong fair liveness should complete");
    match strong {
        FairLivenessResult::FairCycleFound { .. } => {}
        other => panic!("Expected strong fairness cycle, got: {other}"),
    }
}

#[test]
fn fair_liveness_partial_synchrony_ignores_pre_gst_only_cycles() {
    let source = r#"
protocol FairAfterGst {
    params n, t, f, gst;
    resilience: n > 3*t;
    adversary { model: omission; bound: f; timing: partial_synchrony; gst: gst; }
    message Tick;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Tick => {
                send Tick;
                goto phase s;
            }
            when received >= 1 Tick => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let result = tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        "fair_after_gst.trs",
        &options,
        FairnessMode::Weak,
    )
    .expect("fair-liveness search should complete");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => assert_eq!(depth_checked, 6),
        other => panic!("Expected no fair cycle after GST, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_reports_counterexample() {
    let source = r#"
protocol FairNonTerminatingProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_nonterminating_proof.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected fair cycle counterexample, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_with_strong_mode_reports_counterexample() {
    let source = r#"
protocol FairNonTerminatingProofStrong {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
        source,
        "fair_nonterminating_proof_strong.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound {
            depth, loop_start, ..
        } => {
            assert!(depth >= 1);
            assert!(loop_start < depth);
        }
        other => panic!("Expected strong-fair cycle counterexample, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_with_cegar_report_exposes_controls_and_machine_readable_status() {
    let source = r#"
protocol FairNonTerminatingProofReport {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };

    let report = tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
        source,
        "fair_nonterminating_proof_report.trs",
        &options,
        FairnessMode::Strong,
        1,
    )
    .expect("fair-liveness CEGAR proof report should complete");

    assert_eq!(report.controls.max_refinements, 1);
    assert_eq!(report.controls.timeout_secs, 30);
    assert_eq!(report.controls.solver, "z3");
    assert_eq!(report.controls.proof_engine.as_deref(), Some("pdr"));
    assert_eq!(report.controls.fairness.as_deref(), Some("strong"));
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].stage, 0);
    assert_eq!(report.stages[1].stage, 1);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(report.stages[1]
        .note
        .as_deref()
        .unwrap_or_default()
        .contains("Selection rationale"));
    assert!(matches!(
        report.baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    ));
    assert!(matches!(
        report.final_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    ));
    assert_eq!(report.classification, "fair_cycle_confirmed");
    let analysis = report
        .counterexample_analysis
        .expect("counterexample analysis should exist");
    assert_eq!(analysis.classification, "concrete");
}

#[test]
fn prove_fair_liveness_proves_already_decided_protocol() {
    let source = r#"
protocol FairAlreadyDecidedProof {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 3,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_already_decided_proof.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => assert!(frame <= 3),
        other => panic!("Expected proved fair liveness, got: {other}"),
    }
}

#[test]
fn prove_fair_liveness_k_zero_runs_unbounded_until_result() {
    let source = r#"
protocol FairNonTerminatingUnbounded {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 0,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let result = tarsier_engine::pipeline::prove_fair_liveness(
        source,
        "fair_nonterminating_unbounded.trs",
        &options,
    )
    .expect("unbounded fair liveness proof should complete");
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. } => {}
        other => panic!("Expected fair cycle for unbounded k=0 run, got: {other}"),
    }
}

#[test]
fn generate_kinduction_certificate_for_safe_protocol() {
    let source = r#"
protocol CertSafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
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
    let cert = tarsier_engine::pipeline::generate_kinduction_safety_certificate(
        source,
        "cert_safe.trs",
        &options,
    )
    .expect("certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::KInduction);
    assert!(cert.induction_k.expect("k present") <= 4);
    assert_eq!(cert.obligations.len(), 2);
    assert!(cert.obligations[0].smt2.contains("(check-sat)"));
    assert!(cert.obligations[1].smt2.contains("(check-sat)"));
}

#[test]
fn generate_kinduction_certificate_rejects_unsafe_protocol() {
    let source = r#"
protocol CertUnsafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
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
    let err = tarsier_engine::pipeline::generate_kinduction_safety_certificate(
        source,
        "cert_unsafe.trs",
        &options,
    )
    .expect_err("unsafe protocol should not produce certificate");
    assert!(format!("{err}").contains("Cannot certify safety"));
}

#[test]
fn generate_pdr_certificate_for_safe_protocol() {
    let source = r#"
protocol CertSafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let cert = tarsier_engine::pipeline::generate_pdr_safety_certificate(
        source,
        "cert_safe_pdr.trs",
        &options,
    )
    .expect("pdr certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::Pdr);
    assert!(cert.induction_k.expect("frame present") <= 4);
    assert_eq!(cert.obligations.len(), 3);
    for obligation in cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(obligation.smt2.contains("(check-sat)"));
    }

    let cert2 = tarsier_engine::pipeline::generate_safety_certificate(
        source,
        "cert_safe_pdr.trs",
        &options,
    )
    .expect("generic certificate generation should succeed");
    assert_eq!(cert2.proof_engine, ProofEngine::Pdr);
    assert_eq!(cert2.obligations.len(), 3);
}

#[test]
fn generate_fair_liveness_certificate_for_live_protocol() {
    let source = r#"
protocol CertFairLive {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let cert = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        source,
        "cert_fair_live.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("fair-liveness certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::Pdr);
    assert_eq!(cert.fairness, FairnessMode::Strong);
    assert!(cert.frame <= 4);
    assert_eq!(cert.obligations.len(), 3);
    for obligation in cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(obligation.smt2.contains("(check-sat)"));
    }
}

#[test]
fn generate_fair_liveness_certificate_rejects_non_live_protocol() {
    let source = r#"
protocol CertFairNotLive {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let err = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        source,
        "cert_fair_not_live.trs",
        &options,
        FairnessMode::Weak,
    )
    .expect_err("non-live protocol should not produce fair-liveness certificate");
    assert!(format!("{err}").contains("Cannot certify fair-liveness"));
}

#[test]
fn prove_round_abstraction_safe_on_simple_protocol() {
    let source = r#"
protocol RoundSafe {
    params n, t, f;
    resilience: n = 1;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Tick(view: int in 0..3);
    role R {
        var view: int in 0..3 = 0;
        var ok: bool = true;
        init s;
        phase s {
            when received >= 0 Tick(view=view) => {
                send Tick(view=view);
            }
        }
    }
    property safe: safety {
        forall p: R. p.ok == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let round_vars = vec!["view".to_string()];
    let result = tarsier_engine::pipeline::prove_safety_with_round_abstraction(
        source,
        "round_safe.trs",
        &options,
        &round_vars,
    )
    .expect("round abstraction proof should run");

    assert!(
        result.summary.abstract_locations <= result.summary.original_locations,
        "abstraction should not increase location count"
    );
    assert!(
        result.summary.abstract_message_counters <= result.summary.original_message_counters,
        "abstraction should not increase message counter count"
    );
    match result.result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {}
        other => panic!("Expected SAFE result under round abstraction, got: {other:?}"),
    }
}

#[test]
fn prove_fair_round_abstraction_live_on_simple_protocol() {
    let source = r#"
protocol RoundLive {
    params n, t, f;
    resilience: n = 1;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Tick(view: int in 0..3);
    role R {
        var view: int in 0..3 = 0;
        var decided: bool = true;
        init s;
        phase s {
            when received >= 0 Tick(view=view) => {
                send Tick(view=view);
            }
        }
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let round_vars = vec!["view".to_string()];
    let result = tarsier_engine::pipeline::prove_fair_liveness_with_round_abstraction(
        source,
        "round_live.trs",
        &options,
        FairnessMode::Strong,
        &round_vars,
    )
    .expect("round abstraction fair-liveness proof should run");

    assert!(
        result.summary.abstract_locations <= result.summary.original_locations,
        "abstraction should not increase location count"
    );
    match result.result {
        UnboundedFairLivenessResult::LiveProved { .. } => {}
        other => panic!("Expected LIVE_PROVED under round abstraction, got: {other:?}"),
    }
}

// ============================================================================
// Cross-check tests: validate formulas against known analytic baselines (item 6)
// ============================================================================

#[test]
fn cross_check_pbft_message_complexity_is_quadratic() {
    // PBFT has 3 message phases (PrePrepare, Prepare, Commit),
    // each phase involves a broadcast to n replicas => O(n) per step.
    // With depth 3 (one per phase), total is O(3n) => per-depth is O(k*n).
    let source = load_example("pbft_simple.trs");
    let report = tarsier_engine::pipeline::comm_complexity(&source, "pbft_simple.trs", 3).unwrap();
    assert_eq!(
        report.per_step_bound_big_o, "O(n)",
        "PBFT per-step complexity should be O(n)"
    );
    assert_eq!(
        report.per_depth_bound_big_o, "O(k * n)",
        "PBFT per-depth complexity should be O(k * n)"
    );
    // Per-step type bounds: each message type should be O(n) individually
    for (msg, big_o) in &report.per_step_type_big_o {
        assert_eq!(
            big_o, "O(n)",
            "PBFT per-step bound for {msg} should be O(n)"
        );
    }
}

#[test]
fn cross_check_reliable_broadcast_message_complexity() {
    // Reliable broadcast: single role, O(n) per step.
    let source = load_example("reliable_broadcast.trs");
    let report =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();
    assert_eq!(report.per_step_bound_big_o, "O(n)");
    assert!(
        report.per_step_bound.contains("n"),
        "Reliable broadcast bound should reference n"
    );
}

#[test]
fn cross_check_geometric_finality_formula() {
    // For a protocol with committee epsilon = 1e-6, the geometric distribution
    // rounds for 99% confidence should be ceil(ln(0.01) / ln(1e-6)) = 1.
    // Since p_fail is so small, even 1 round gives > 99% confidence.
    let source = r#"
protocol GeometricCheck {
    params n, t, f;
    resilience: n > 2*t;
    adversary { model: byzantine; bound: f; auth: signed; }

    committee voters {
        population: 1000;
        byzantine: 333;
        size: 100;
        epsilon: 1.0e-6;
        bound_param: f;
    }

    message Vote;

    role Replica {
        var decided: bool = false;
        init idle;
        phase idle {
            when received >= 2*t+1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: Replica. p.decided == false
    }
}
"#;
    let report =
        tarsier_engine::pipeline::comm_complexity(source, "geometric_check.trs", 5).unwrap();
    // With epsilon ~1e-6, P(success) ≈ 1, so expected rounds ≈ 1.0
    assert!(
        report.expected_rounds_to_finality.is_some(),
        "Should have finality estimate"
    );
    let expected = report.expected_rounds_to_finality.unwrap();
    assert!(
        expected < 1.01,
        "Expected rounds to finality should be very close to 1.0 with tiny epsilon, got {expected}"
    );
    // 90% confidence rounds should be 1
    assert_eq!(
        report.rounds_for_90pct_finality,
        Some(1),
        "90% finality should be achieved in 1 round"
    );
    assert_eq!(
        report.rounds_for_99pct_finality,
        Some(1),
        "99% finality should be achieved in 1 round"
    );
}

#[test]
fn cross_check_hypergeometric_committee_b_max() {
    // Cross-validate against known result: N=1000, K=333, S=100, epsilon=1e-9 => b_max=61
    let spec = tarsier_prob::CommitteeSpec {
        name: "test".into(),
        population: 1000,
        byzantine: 333,
        committee_size: 100,
        epsilon: 1e-9,
    };
    let analysis = tarsier_prob::analyze_committee(&spec).unwrap();
    assert_eq!(
        analysis.b_max, 61,
        "Known baseline: N=1000,K=333,S=100,eps=1e-9 => b_max=61"
    );
    assert!(
        analysis.tail_probability <= 1e-9,
        "Tail probability should be <= epsilon"
    );
}

#[test]
fn cross_check_crash_fault_model_has_zero_adversary_injection() {
    let source = r#"
protocol CrashCheck {
    params n, t, f;
    resilience: n > 2*t;
    adversary { model: crash; bound: f; }

    message Echo;

    role Node {
        var decided: bool = false;
        init idle;
        phase idle {
            when received >= t+1 Echo => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: Node. p.decided == false
    }
}
"#;
    let report = tarsier_engine::pipeline::comm_complexity(source, "crash_check.trs", 3).unwrap();
    // Crash faults cannot inject messages: bound should be absent or "0"
    match report.adversary_per_step_bound.as_deref() {
        None | Some("0") => {} // both valid representations of zero injection
        other => panic!(
            "Crash fault model should have no adversary injection, got {:?}",
            other
        ),
    }
    // Should have a note about crash faults
    assert!(
        report
            .assumption_notes
            .iter()
            .any(|n| n.message.contains("Crash fault")),
        "Should note crash fault implications"
    );
}

// ============================================================================
// Golden expected ranges: benchmark corpus with quantitative assertions (item 9)
// ============================================================================

#[test]
fn golden_pbft_simple_quantitative_ranges() {
    let source = load_example("pbft_simple.trs");
    let report = tarsier_engine::pipeline::comm_complexity(&source, "pbft_simple.trs", 10).unwrap();

    // Schema version
    assert_eq!(report.schema_version, 1);

    // PBFT has 3 message types: PrePrepare, Prepare, Commit
    assert!(
        report.max_sends_per_rule_by_type.len() >= 1,
        "PBFT should have at least 1 message type"
    );

    // Latency lower bound: PBFT requires at least 3 steps (start->prepared->committed->done)
    assert!(
        report.min_decision_steps.is_some(),
        "PBFT should have a reachable decided location"
    );
    assert!(
        report.min_decision_steps.unwrap() >= 3,
        "PBFT needs at least 3 steps to decide, got {:?}",
        report.min_decision_steps
    );

    // Per-step bound should reference n
    assert!(report.per_step_bound.contains("n"));

    // Depth should match what we requested
    assert_eq!(report.depth, 10);

    // Model assumptions should reflect PBFT's Byzantine fault model
    assert_eq!(report.model_assumptions.fault_model, "Byzantine");

    // Metadata should be present and valid
    assert!(!report.model_metadata.source_hash.is_empty());
    assert_eq!(report.model_metadata.filename, "pbft_simple.trs");
    assert_eq!(report.model_metadata.analysis_depth, 10);
}

#[test]
fn golden_reliable_broadcast_quantitative_ranges() {
    let source = load_example("reliable_broadcast.trs");
    let report =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 5).unwrap();

    // Reliable broadcast has fewer steps than PBFT
    assert!(report.min_decision_steps.is_some());
    let min_steps = report.min_decision_steps.unwrap();
    assert!(
        min_steps >= 1 && min_steps <= 5,
        "Reliable broadcast decision steps should be in [1,5], got {min_steps}"
    );

    // Max sends per rule should be positive
    assert!(
        report.max_sends_per_rule >= 1,
        "Should have at least 1 send per rule"
    );

    // Per-step bound should reference n
    assert!(report.per_step_bound.contains("n"));
    assert_eq!(report.per_step_bound_big_o, "O(n)");
}

#[test]
fn golden_report_has_bound_annotations() {
    let source = load_example("reliable_broadcast.trs");
    let report =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();

    // Should have bound annotations
    assert!(
        !report.bound_annotations.is_empty(),
        "Report should have bound annotations"
    );

    // Key fields should have annotations
    let annotated_fields: Vec<&str> = report
        .bound_annotations
        .iter()
        .map(|a| a.field.as_str())
        .collect();
    assert!(
        annotated_fields.contains(&"min_decision_steps"),
        "min_decision_steps should be annotated"
    );
    assert!(
        annotated_fields.contains(&"per_step_bound"),
        "per_step_bound should be annotated"
    );
    assert!(
        annotated_fields.contains(&"per_depth_bound"),
        "per_depth_bound should be annotated"
    );

    // Check that bound kinds are correct
    let min_steps_annotation = report
        .bound_annotations
        .iter()
        .find(|a| a.field == "min_decision_steps")
        .unwrap();
    assert!(
        matches!(min_steps_annotation.kind, BoundKind::LowerBound),
        "min_decision_steps should be annotated as lower_bound"
    );

    let per_step_annotation = report
        .bound_annotations
        .iter()
        .find(|a| a.field == "per_step_bound")
        .unwrap();
    assert!(
        matches!(per_step_annotation.kind, BoundKind::UpperBound),
        "per_step_bound should be annotated as upper_bound"
    );
}

#[test]
fn golden_report_json_serialization_roundtrip() {
    let source = load_example("reliable_broadcast.trs");
    let report =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&report).expect("Should serialize to JSON");

    // Parse as generic JSON value to verify structure
    let value: serde_json::Value = serde_json::from_str(&json).expect("Should parse JSON back");

    // Verify top-level fields exist
    assert!(value.get("schema_version").is_some());
    assert!(value.get("model_metadata").is_some());
    assert!(value.get("model_assumptions").is_some());
    assert!(value.get("bound_annotations").is_some());
    assert!(value.get("depth").is_some());
    assert!(value.get("per_step_bound").is_some());
    assert!(value.get("per_role_step_bounds").is_some());
    assert!(value.get("per_phase_step_bounds").is_some());
    assert!(value.get("sensitivity").is_some());

    // Verify schema_version is 1
    assert_eq!(value["schema_version"], 1);

    // Verify model_metadata has expected fields
    let meta = &value["model_metadata"];
    assert!(meta["source_hash"].is_string());
    assert!(meta["filename"].is_string());
    assert!(meta["analysis_depth"].is_number());
    assert!(meta["engine_version"].is_string());

    // Verify model_assumptions has expected fields
    let assumptions = &value["model_assumptions"];
    assert!(assumptions["fault_model"].is_string());
    assert!(assumptions["timing_model"].is_string());
    assert!(assumptions["authentication_mode"].is_string());
    assert!(assumptions["equivocation_mode"].is_string());
    assert!(assumptions["network_semantics"].is_string());
}

#[test]
fn golden_deterministic_hash_for_same_source() {
    let source = load_example("reliable_broadcast.trs");
    let report1 =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();
    let report2 =
        tarsier_engine::pipeline::comm_complexity(&source, "reliable_broadcast.trs", 3).unwrap();

    // Same source should produce same hash
    assert_eq!(
        report1.model_metadata.source_hash, report2.model_metadata.source_hash,
        "Deterministic hash: same source should produce same hash"
    );

    // Same bounds
    assert_eq!(report1.per_step_bound, report2.per_step_bound);
    assert_eq!(report1.per_depth_bound, report2.per_depth_bound);
    assert_eq!(report1.per_step_bound_big_o, report2.per_step_bound_big_o);
}

#[test]
fn golden_per_role_and_per_phase_bounds_present() {
    // Multi-role protocol to test per-role and per-phase bounds
    let source = r#"
protocol MultiRole {
    params n, n_a, n_b, f;
    resilience: n = n_a + n_b;
    adversary { model: byzantine; bound: f; auth: signed; }

    message Ping;
    message Pong;

    role A {
        var active: bool = true;
        init idle;
        phase idle {
            when active == true => {
                send Ping;
                goto phase working;
            }
        }
        phase working {
            when active == true => {
                send Pong;
                goto phase done;
            }
        }
        phase done {}
    }

    role B {
        var active: bool = true;
        init idle;
        phase idle {
            when active == true => {
                send Pong to B;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: A. p.active == true
    }
}
"#;
    let report = tarsier_engine::pipeline::comm_complexity(source, "multi_role.trs", 3).unwrap();

    // Should have per-role bounds for both A and B
    let role_names: Vec<&str> = report
        .per_role_step_bounds
        .iter()
        .map(|(r, _)| r.as_str())
        .collect();
    assert!(role_names.contains(&"A"), "Should have bounds for role A");
    assert!(role_names.contains(&"B"), "Should have bounds for role B");

    // Should have per-phase bounds
    let phase_names: Vec<&str> = report
        .per_phase_step_bounds
        .iter()
        .map(|(p, _)| p.as_str())
        .collect();
    assert!(
        phase_names.contains(&"idle"),
        "Should have bounds for phase idle"
    );
    assert!(
        phase_names.contains(&"working"),
        "Should have bounds for phase working"
    );

    // Role A sends in 2 phases, role B sends in 1 phase
    let a_bound = report
        .per_role_step_bounds
        .iter()
        .find(|(r, _)| r == "A")
        .map(|(_, b)| b.clone())
        .unwrap();
    assert!(
        !a_bound.is_empty() && a_bound != "0",
        "Role A should have non-zero bound"
    );
}

#[test]
fn golden_sensitivity_analysis_for_committee_protocol() {
    let source = r#"
protocol SensCheck {
    params n, t, f;
    resilience: n > 2*t;
    adversary { model: byzantine; bound: f; auth: signed; }

    committee voters {
        population: 1000;
        byzantine: 333;
        size: 100;
        epsilon: 1.0e-6;
        bound_param: f;
    }

    message Vote;

    role Replica {
        var decided: bool = false;
        init idle;
        phase idle {
            when received >= 2*t+1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: Replica. p.decided == false
    }
}
"#;
    let report = tarsier_engine::pipeline::comm_complexity(source, "sens_check.trs", 5).unwrap();

    // Should have sensitivity points for epsilon variation
    assert!(
        !report.sensitivity.is_empty(),
        "Committee protocol should have sensitivity analysis"
    );

    // All sensitivity points should be for epsilon parameter
    for pt in &report.sensitivity {
        assert_eq!(pt.parameter, "epsilon");
        assert!(pt.base_value > 0.0);
        assert!(pt.varied_value > 0.0);
        assert!(pt.base_result > 0.0);
        assert!(pt.varied_result > 0.0);
    }

    // Larger epsilon should give smaller or equal b_max
    let relaxed = report
        .sensitivity
        .iter()
        .find(|pt| pt.varied_value > pt.base_value)
        .expect("Should have a relaxed epsilon point");
    assert!(
        relaxed.varied_result <= relaxed.base_result,
        "Larger epsilon should yield smaller or equal b_max: {} vs {}",
        relaxed.varied_result,
        relaxed.base_result
    );

    // Smaller epsilon should give larger or equal b_max
    let tighter = report
        .sensitivity
        .iter()
        .find(|pt| pt.varied_value < pt.base_value)
        .expect("Should have a tighter epsilon point");
    assert!(
        tighter.varied_result >= tighter.base_result,
        "Smaller epsilon should yield larger or equal b_max: {} vs {}",
        tighter.varied_result,
        tighter.base_result
    );
}

#[test]
fn golden_assumption_notes_for_async_no_gst() {
    let source = r#"
protocol AsyncCheck {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    message Echo;

    role Node {
        var decided: bool = false;
        init idle;
        phase idle {
            when received >= 2*t+1 Echo => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: invariant {
        forall p: Node. p.decided == false
    }
}
"#;
    let report = tarsier_engine::pipeline::comm_complexity(source, "async_check.trs", 3).unwrap();

    // Default timing model is Asynchronous with no GST
    assert_eq!(report.model_assumptions.timing_model, "Asynchronous");

    // Should have a warning about finality under pure asynchrony
    assert!(
        report
            .assumption_notes
            .iter()
            .any(|n| n.level == "warning" && n.message.contains("asynchrony")),
        "Should warn about finality under pure asynchrony"
    );
}

// ── Manifest quality and corpus coverage tests ──────────────────────────

#[test]
fn manifest_all_entries_have_substantive_notes() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let notes = entry["notes"].as_str().unwrap();
        assert!(
            notes.len() >= 40,
            "Entry '{}' has a notes field that is too short ({} chars < 40): {:?}",
            file,
            notes.len(),
            notes
        );
        // Notes should not be the old generic placeholder
        assert!(
            notes != "Expected clean safety benchmark.",
            "Entry '{}' still has the generic placeholder notes",
            file
        );
    }
}

#[test]
fn manifest_variant_groups_are_complete() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    // Collect all variant groups and their variants
    let mut groups: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for entry in entries {
        if let Some(group) = entry.get("variant_group").and_then(|v| v.as_str()) {
            let variant = entry["variant"].as_str().unwrap().to_string();
            groups.entry(group.to_string()).or_default().push(variant);
        }
    }

    assert!(
        groups.len() >= 5,
        "Expected at least 5 variant groups, got {}",
        groups.len()
    );

    for (group, variants) in &groups {
        assert!(
            variants.contains(&"minimal".to_string()),
            "Variant group '{}' is missing a minimal variant",
            group
        );
        assert!(
            variants.contains(&"faithful".to_string()),
            "Variant group '{}' is missing a faithful variant",
            group
        );
    }
}

#[test]
fn manifest_known_bug_coverage_is_adequate() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let known_bugs: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["class"].as_str() == Some("known_bug"))
        .collect();

    let expected_safe: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["class"].as_str() == Some("expected_safe"))
        .collect();

    // Must have at least 16 known bugs
    assert!(
        known_bugs.len() >= 16,
        "Expected at least 16 known_bug entries, got {}",
        known_bugs.len()
    );

    // Must have at least 16 expected_safe entries
    assert!(
        expected_safe.len() >= 16,
        "Expected at least 16 expected_safe entries, got {}",
        expected_safe.len()
    );

    // All known_bug entries must have at least one bug-revealing outcome
    for entry in &known_bugs {
        let file = entry["file"].as_str().unwrap();
        let has_bug_outcome = entry.get("verify").and_then(|v| v.as_str()) == Some("unsafe")
            || entry.get("prove").and_then(|v| v.as_str()) == Some("unsafe")
            || entry.get("liveness").and_then(|v| v.as_str()) == Some("not_live")
            || entry.get("fair_liveness").and_then(|v| v.as_str()) == Some("fair_cycle_found")
            || entry.get("prove_fair").and_then(|v| v.as_str()) == Some("fair_cycle_found");
        assert!(
            has_bug_outcome,
            "known_bug entry '{}' has no bug-revealing expected outcome",
            file
        );
    }
}

#[test]
fn manifest_model_sha256_format_is_valid() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let hash = entry["model_sha256"].as_str().unwrap();
        assert_eq!(
            hash.len(),
            64,
            "Entry '{}' model_sha256 should be 64 hex chars, got {} chars",
            file,
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Entry '{}' model_sha256 contains non-hex characters: '{}'",
            file,
            hash
        );
    }
}

#[test]
fn manifest_files_are_unique() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in entries {
        let file = entry["file"].as_str().unwrap().to_string();
        assert!(
            seen.insert(file.clone()),
            "Duplicate file entry in manifest: '{}'",
            file
        );
    }
}

#[test]
fn manifest_entries_reference_existing_files() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let path = format!("{}/{}", library_dir, file);
        assert!(
            std::path::Path::new(&path).exists(),
            "Manifest references '{}' but file does not exist at '{}'",
            file,
            path
        );
    }
}

#[test]
fn manifest_library_coverage_all_trs_files_have_entries() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let manifest_files: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["file"].as_str().unwrap().to_string())
        .collect();

    let trs_files: Vec<String> = std::fs::read_dir(&library_dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("trs"))
        .map(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap()
                .to_string()
        })
        .collect();

    for trs_file in &trs_files {
        assert!(
            manifest_files.contains(trs_file),
            "Library file '{}' has no entry in cert_suite.json",
            trs_file
        );
    }
}

#[test]
fn manifest_fault_model_breadth() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let families: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["family"].as_str().unwrap().to_string())
        .collect();

    // Must cover BFT families
    assert!(families.contains("pbft"), "Missing BFT family: pbft");
    assert!(
        families.contains("hotstuff"),
        "Missing BFT family: hotstuff"
    );
    assert!(
        families.contains("tendermint"),
        "Missing BFT family: tendermint"
    );

    // Must cover crash-fault families
    assert!(families.contains("paxos"), "Missing CFT family: paxos");
    assert!(
        families.contains("viewstamped-replication"),
        "Missing CFT family: viewstamped-replication"
    );

    // Must cover omission-fault families
    assert!(families.contains("zab"), "Missing omission family: zab");
    assert!(families.contains("raft"), "Missing omission family: raft");

    // Overall breadth
    assert!(
        families.len() >= 16,
        "Expected at least 16 protocol families, got {}",
        families.len()
    );
}

#[test]
fn manifest_schema_version_is_v2() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(
        parsed["schema_version"].as_u64(),
        Some(2),
        "Manifest schema_version should be 2"
    );
    assert_eq!(
        parsed["enforce_library_coverage"].as_bool(),
        Some(true),
        "enforce_library_coverage should be true"
    );
}

#[test]
fn manifest_expected_outcomes_are_valid_tokens() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let verify_valid = ["safe", "probabilistically_safe", "unsafe", "unknown"];
    let liveness_valid = ["live", "not_live", "unknown"];
    let fair_valid = ["no_fair_cycle_up_to", "fair_cycle_found", "unknown"];
    let prove_valid = [
        "safe",
        "probabilistically_safe",
        "unsafe",
        "not_proved",
        "unknown",
    ];
    let prove_fair_valid = ["live_proved", "fair_cycle_found", "not_proved", "unknown"];

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        if let Some(v) = entry.get("verify").and_then(|v| v.as_str()) {
            assert!(
                verify_valid.contains(&v),
                "Entry '{}' has invalid verify value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("liveness").and_then(|v| v.as_str()) {
            assert!(
                liveness_valid.contains(&v),
                "Entry '{}' has invalid liveness value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("fair_liveness").and_then(|v| v.as_str()) {
            assert!(
                fair_valid.contains(&v),
                "Entry '{}' has invalid fair_liveness value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("prove").and_then(|v| v.as_str()) {
            assert!(
                prove_valid.contains(&v),
                "Entry '{}' has invalid prove value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("prove_fair").and_then(|v| v.as_str()) {
            assert!(
                prove_fair_valid.contains(&v),
                "Entry '{}' has invalid prove_fair value: '{}'",
                file,
                v
            );
        }

        // Each entry must have at least one expected outcome
        let has_outcome = entry.get("verify").is_some()
            || entry.get("liveness").is_some()
            || entry.get("fair_liveness").is_some()
            || entry.get("prove").is_some()
            || entry.get("prove_fair").is_some();
        assert!(
            has_outcome,
            "Entry '{}' has no expected outcome field",
            file
        );
    }
}

#[test]
fn manifest_new_faithful_variants_verify_safe() {
    // Verify the two new faithful variant models parse and verify safe
    let vr_faithful = load_library_example("viewstamped_replication_faithful.trs");
    let zab_faithful = load_library_example("zab_atomic_broadcast_faithful.trs");

    let opts = verify_options(4, SoundnessMode::Strict);

    let vr_result = tarsier_engine::pipeline::verify(
        &vr_faithful,
        "viewstamped_replication_faithful.trs",
        &opts,
    )
    .unwrap();
    assert!(
        matches!(vr_result, VerificationResult::Safe { .. }),
        "viewstamped_replication_faithful.trs should verify safe, got {:?}",
        vr_result
    );

    let zab_result =
        tarsier_engine::pipeline::verify(&zab_faithful, "zab_atomic_broadcast_faithful.trs", &opts)
            .unwrap();
    assert!(
        matches!(zab_result, VerificationResult::Safe { .. }),
        "zab_atomic_broadcast_faithful.trs should verify safe, got {:?}",
        zab_result
    );
}

#[test]
fn manifest_faithful_variants_declare_faithful_network_semantics() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let faithful_indicators = [
        "network: identity_selective",
        "network: cohort_selective",
        "network: process_selective",
        "network: faithful",
        "network: selective",
    ];

    for entry in entries {
        if entry.get("variant").and_then(|v| v.as_str()) != Some("faithful") {
            continue;
        }
        let file = entry["file"].as_str().unwrap();
        let path = format!("{}/{}", library_dir, file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path));

        let has_faithful = faithful_indicators
            .iter()
            .any(|indicator| source.contains(indicator));
        assert!(
            has_faithful,
            "Faithful variant '{}' does not declare faithful network semantics in its adversary block. \
             Expected one of: {:?}",
            file, faithful_indicators
        );

        // Must also have identity declaration
        assert!(
            source.contains("identity "),
            "Faithful variant '{}' should declare an identity mapping (e.g., `identity Replica: role key replica_key;`)",
            file
        );

        // Must use distinct receive guards
        assert!(
            source.contains("distinct"),
            "Faithful variant '{}' should use `distinct` keyword in receive guards for sender-counting",
            file
        );

        // Must declare signed auth
        assert!(
            source.contains("auth: signed"),
            "Faithful variant '{}' should declare `auth: signed` in adversary block",
            file
        );

        // Must declare equivocation policy
        assert!(
            source.contains("equivocation: none") || source.contains("equivocation: full"),
            "Faithful variant '{}' should declare an explicit equivocation policy",
            file
        );
    }
}

#[test]
fn manifest_faithful_vs_minimal_variant_pair_consistency() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    // Group entries by variant_group
    let mut groups: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for entry in entries {
        if let Some(group) = entry.get("variant_group").and_then(|v| v.as_str()) {
            groups.entry(group.to_string()).or_default().push(entry);
        }
    }

    for (group, members) in &groups {
        let minimal = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("minimal"));
        let faithful = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("faithful"));

        let minimal =
            minimal.unwrap_or_else(|| panic!("Group '{}' missing minimal variant", group));
        let faithful =
            faithful.unwrap_or_else(|| panic!("Group '{}' missing faithful variant", group));

        // Both must be in the same family
        assert_eq!(
            minimal["family"].as_str(),
            faithful["family"].as_str(),
            "Variant group '{}': minimal and faithful must be in the same family",
            group
        );

        // Both must have the same class
        assert_eq!(
            minimal["class"].as_str(),
            faithful["class"].as_str(),
            "Variant group '{}': minimal and faithful must have the same class",
            group
        );

        // Both must have the same verify expectation
        assert_eq!(
            minimal.get("verify").and_then(|v| v.as_str()),
            faithful.get("verify").and_then(|v| v.as_str()),
            "Variant group '{}': minimal and faithful must have the same verify expectation",
            group
        );

        // Both protocol files must exist
        let min_path = format!("{}/{}", library_dir, minimal["file"].as_str().unwrap());
        let faith_path = format!("{}/{}", library_dir, faithful["file"].as_str().unwrap());
        assert!(
            std::path::Path::new(&min_path).exists(),
            "Minimal variant file missing: {}",
            min_path
        );
        assert!(
            std::path::Path::new(&faith_path).exists(),
            "Faithful variant file missing: {}",
            faith_path
        );
    }
}
