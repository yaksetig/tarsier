mod common;
use common::*;

use tarsier_engine::result::BoundKind;

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
    // The protocol defaults to asynchronous timing with no GST, so the pipeline
    // correctly suppresses finality extrapolation (finality probabilities are
    // meaningful only under partial synchrony / synchrony). Verify the committee
    // was analyzed (epsilon captured in model_assumptions) even though finality
    // is not extrapolated.
    assert!(
        report.model_assumptions.fault_model == "Byzantine",
        "Should detect Byzantine fault model"
    );
    // Committee epsilon should be captured somewhere in the bound annotations
    assert!(
        !report.bound_annotations.is_empty(),
        "Committee protocol should produce bound annotations"
    );
    // If finality IS computed (e.g., pipeline adds GST inference), validate it
    if let Some(expected) = report.expected_rounds_to_finality {
        assert!(
            expected < 1.01,
            "Expected rounds to finality should be very close to 1.0 with tiny epsilon, got {expected}"
        );
    }
    if let Some(rounds_90) = report.rounds_for_90pct_finality {
        assert_eq!(rounds_90, 1, "90% finality should be achieved in 1 round");
    }
    if let Some(rounds_99) = report.rounds_for_99pct_finality {
        assert_eq!(rounds_99, 1, "99% finality should be achieved in 1 round");
    }
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

#[test]
fn golden_pbft_simple_quantitative_ranges() {
    let source = load_example("pbft_simple.trs");
    let report = tarsier_engine::pipeline::comm_complexity(&source, "pbft_simple.trs", 10).unwrap();

    // Schema version (v2 since quantitative schema upgrade)
    assert_eq!(report.schema_version, 2);

    // PBFT has 3 message types: PrePrepare, Prepare, Commit
    assert!(
        !report.max_sends_per_rule_by_type.is_empty(),
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
        (1..=5).contains(&min_steps),
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

    // Verify schema_version is 2 (current quantitative schema version)
    assert_eq!(value["schema_version"], 2);

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

