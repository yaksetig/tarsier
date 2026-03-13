use super::{
    add_bounds, analyze_and_constrain_committees, apply_round_erasure_abstraction,
    base_message_name, build_location_merge_key, ensure_n_parameter,
    erase_round_fields_from_message_counter_name, format_bound, format_scaled_term,
    format_sum_bounds, geometric_rounds_for_confidence, is_erased_var_name,
    message_family_and_recipient_from_counter_name, normalize_erased_var_names, push_prob_sample,
    push_prob_sensitivity_point, quantile, quantitative_reproducibility_fingerprint,
    scale_bound_by_depth, sha256_hex,
};
use crate::pipeline::*;
use std::collections::BTreeMap;
use tarsier_ir::threshold_automaton::{
    CmpOp, Guard, IrCommitteeSpec, LinearCombination, Location, Parameter, Rule, SharedVar, Update,
    UpdateKind,
};

fn mk_location(name: &str, round: i64, flag: bool) -> Location {
    let mut loc = Location {
        name: name.to_string(),
        role: "R".to_string(),
        phase: "p".to_string(),
        local_vars: Default::default(),
    };
    loc.local_vars
        .insert("round".to_string(), LocalValue::Int(round));
    loc.local_vars
        .insert("flag".to_string(), LocalValue::Bool(flag));
    loc
}

fn mk_erasure_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter {
        name: "n".to_string(),
        time_varying: false,
    });
    ta.locations.push(mk_location("l0", 1, false));
    ta.locations.push(mk_location("l1", 2, false));
    ta.locations.push(mk_location("l2", 2, true));
    ta.initial_locations = vec![0.into(), 1.into()];
    ta.shared_vars.push(SharedVar {
        name: "cnt_Vote@R[round=1,value=true]".to_string(),
        kind: SharedVarKind::MessageCounter,
        distinct: true,
        distinct_role: Some("R".to_string()),
    });
    ta.shared_vars.push(SharedVar {
        name: "cnt_Vote@R[round=2,value=true]".to_string(),
        kind: SharedVarKind::MessageCounter,
        distinct: true,
        distinct_role: Some("S".to_string()),
    });
    ta.shared_vars.push(SharedVar {
        name: "decided".to_string(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta.rules.push(Rule {
        from: 0.into(),
        to: 2.into(),
        guard: Guard {
            atoms: vec![GuardAtom::Threshold {
                vars: vec![0.into(), 1.into()],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }],
        },
        updates: vec![
            Update {
                var: 0.into(),
                kind: UpdateKind::Increment,
            },
            Update {
                var: 1.into(),
                kind: UpdateKind::Increment,
            },
            Update {
                var: 2.into(),
                kind: UpdateKind::Increment,
            },
        ],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    ta
}

#[test]
fn base_message_name_parses_counter_family_and_rejects_non_counters() {
    assert_eq!(
        base_message_name("cnt_Vote@Replica#1<-Replica#0[view=2,value=true]"),
        Some("Vote".to_string())
    );
    assert_eq!(
        base_message_name("cnt_Prepare[round=3]"),
        Some("Prepare".to_string())
    );
    assert_eq!(base_message_name("decided"), None);
}

#[test]
fn message_family_and_recipient_parser_handles_sender_suffix_and_missing_recipient() {
    assert_eq!(
        message_family_and_recipient_from_counter_name(
            "cnt_Vote@Replica#1<-Replica#0[view=2,value=true]"
        ),
        Some(("Vote".to_string(), Some("Replica#1".to_string())))
    );
    assert_eq!(
        message_family_and_recipient_from_counter_name("cnt_Vote@Replica#1[view=2]"),
        Some(("Vote".to_string(), Some("Replica#1".to_string())))
    );
    assert_eq!(
        message_family_and_recipient_from_counter_name("cnt_Vote[view=2]"),
        Some(("Vote".to_string(), None))
    );
}

#[test]
fn erased_name_normalization_and_lookup_are_case_insensitive() {
    let normalized =
        normalize_erased_var_names(&[" round ".to_string(), "View".to_string(), "".into()]);
    assert!(normalized.contains("round"));
    assert!(normalized.contains("view"));
    assert!(is_erased_var_name("ROUND", &normalized));
    assert!(is_erased_var_name("view", &normalized));
    assert!(!is_erased_var_name("height", &normalized));
}

#[test]
fn erasing_counter_fields_drops_selected_assignments_and_collapses_empty_payload() {
    let erased = normalize_erased_var_names(&["round".to_string(), "view".to_string()]);
    assert_eq!(
        erase_round_fields_from_message_counter_name(
            "cnt_Vote@R[round=1,value=true,view=2]",
            &erased
        ),
        "cnt_Vote@R[value=true]"
    );
    assert_eq!(
        erase_round_fields_from_message_counter_name("cnt_Vote@R[round=1,view=2]", &erased),
        "cnt_Vote@R"
    );
    assert_eq!(
        erase_round_fields_from_message_counter_name("decided", &erased),
        "decided"
    );
}

#[test]
fn location_merge_key_sorts_locals_and_drops_erased_fields() {
    let mut loc = Location {
        name: "L".to_string(),
        role: "Replica".to_string(),
        phase: "prepare".to_string(),
        local_vars: Default::default(),
    };
    loc.local_vars
        .insert("z".to_string(), LocalValue::Bool(true));
    loc.local_vars.insert("a".to_string(), LocalValue::Int(1));
    loc.local_vars
        .insert("view".to_string(), LocalValue::Int(9));
    let erased = normalize_erased_var_names(&["view".to_string()]);
    let key = build_location_merge_key(&loc, &erased);
    assert_eq!(key.role, "Replica");
    assert_eq!(key.phase, "prepare");
    assert_eq!(
        key.locals,
        vec![
            ("a".to_string(), LocalValue::Int(1)),
            ("z".to_string(), LocalValue::Bool(true))
        ]
    );
}

#[test]
fn round_erasure_abstraction_merges_locations_and_message_counters() {
    let ta = mk_erasure_ta();
    let (abs, summary) = apply_round_erasure_abstraction(&ta, &["round".to_string()]);

    assert_eq!(summary.original_locations, 3);
    assert_eq!(summary.abstract_locations, 2);
    assert_eq!(summary.original_shared_vars, 3);
    assert_eq!(summary.abstract_shared_vars, 2);
    assert_eq!(summary.original_message_counters, 2);
    assert_eq!(summary.abstract_message_counters, 1);
    assert_eq!(abs.initial_locations, vec![0]);

    let merged_counter = abs
        .shared_vars
        .iter()
        .find(|v| v.kind == SharedVarKind::MessageCounter)
        .expect("message counter must remain after abstraction");
    assert_eq!(merged_counter.name, "cnt_Vote@R[value=true]");
    assert!(!merged_counter.distinct);
    assert_eq!(merged_counter.distinct_role, None);

    let mapped_guard_vars = match &abs.rules[0].guard.atoms[0] {
        GuardAtom::Threshold { vars, .. } => vars.clone(),
    };
    assert_eq!(mapped_guard_vars.len(), 2);
    assert_eq!(mapped_guard_vars[0], mapped_guard_vars[1]);
    assert_eq!(abs.rules[0].updates[0].var, abs.rules[0].updates[1].var);
}

#[test]
fn symbolic_bound_helpers_render_expected_forms() {
    assert_eq!(format_bound(&[]), "0");
    assert_eq!(format_bound(&["n".to_string(), "2".to_string()]), "n * 2");

    assert_eq!(format_scaled_term("n", 0), "0");
    assert_eq!(format_scaled_term("n", 1), "n");
    assert_eq!(format_scaled_term("n", 3), "n * 3");

    assert_eq!(
        format_sum_bounds(&["0".to_string(), "n".to_string(), "f".to_string()]),
        "n + f"
    );
    assert_eq!(format_sum_bounds(&["0".to_string(), "0".to_string()]), "0");

    assert_eq!(scale_bound_by_depth(3, "0"), "0");
    assert_eq!(scale_bound_by_depth(1, "n + f"), "n + f");
    assert_eq!(scale_bound_by_depth(2, "n + f"), "2 * (n + f)");
    assert_eq!(scale_bound_by_depth(2, "n"), "2 * n");

    assert_eq!(add_bounds("0", "n"), "n");
    assert_eq!(add_bounds("f", "0"), "f");
    assert_eq!(add_bounds("n", "f"), "n + f");
}

#[test]
fn geometric_round_estimator_handles_edges_and_finite_cases() {
    assert_eq!(geometric_rounds_for_confidence(-0.1, 0.9), None);
    assert_eq!(geometric_rounds_for_confidence(0.1, 1.0), None);
    assert_eq!(geometric_rounds_for_confidence(0.0, 0.95), Some(1));
    assert_eq!(geometric_rounds_for_confidence(1.0, 0.95), None);
    assert_eq!(geometric_rounds_for_confidence(0.5, 0.75), Some(2));
}

#[test]
fn hashing_fingerprint_and_quantile_helpers_are_deterministic() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let opts_a = QuantitativeAnalysisOptions {
        command: "comm".to_string(),
        depth: 4,
    };
    let opts_b = QuantitativeAnalysisOptions {
        command: "comm".to_string(),
        depth: 5,
    };
    let env = QuantitativeAnalysisEnvironment {
        target_os: "macos".to_string(),
        target_arch: "aarch64".to_string(),
        target_family: "unix".to_string(),
        build_profile: "debug".to_string(),
    };

    let fp_a1 = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_a, &env)
        .expect("fingerprint should serialize");
    let fp_a2 = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_a, &env)
        .expect("fingerprint should serialize");
    let fp_b = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_b, &env)
        .expect("fingerprint should serialize");
    assert_eq!(fp_a1, fp_a2);
    assert_ne!(fp_a1, fp_b);

    assert_eq!(quantile(&[3.0, 1.0, 2.0], 0.0), Some(1.0));
    assert_eq!(quantile(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
    assert_eq!(quantile(&[3.0, 1.0, 2.0], 1.0), Some(3.0));
    assert_eq!(quantile(&[0.0, 10.0], 0.25), Some(2.5));
    assert_eq!(quantile(&[], 0.5), None);
    assert_eq!(quantile(&[1.0], 1.1), None);
}

#[test]
fn probabilistic_sample_and_sensitivity_helpers_filter_invalid_inputs() {
    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut sensitivity = Vec::new();

    push_prob_sample(&mut samples, "p", None);
    push_prob_sample(&mut samples, "p", Some(f64::NAN));
    push_prob_sample(&mut samples, "p", Some(f64::INFINITY));
    assert!(samples.is_empty());

    push_prob_sensitivity_point(
        &mut sensitivity,
        &mut samples,
        "metric",
        Some(0.2),
        Some(0.1),
        1e-6,
        1e-4,
    );
    assert_eq!(sensitivity.len(), 1);
    assert_eq!(samples.get("metric"), Some(&vec![0.1]));

    push_prob_sensitivity_point(
        &mut sensitivity,
        &mut samples,
        "metric",
        None,
        Some(0.05),
        1e-6,
        1e-3,
    );
    assert_eq!(sensitivity.len(), 1);
    assert_eq!(samples.get("metric"), Some(&vec![0.1]));
}

#[test]
fn committee_analysis_sets_single_bound_param_or_rejects_ambiguous_bounds() {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter {
        name: "n".to_string(),
        time_varying: false,
    });
    ta.parameters.push(Parameter {
        name: "f".to_string(),
        time_varying: false,
    });
    ta.constraints.committees.push(IrCommitteeSpec {
        name: "c1".to_string(),
        population: ParamOrConst::Const(100),
        byzantine: ParamOrConst::Const(33),
        committee_size: ParamOrConst::Const(25),
        epsilon: Some(1e-6),
        bound_param: Some(1.into()),
    });

    let summaries =
        analyze_and_constrain_committees(&mut ta).expect("single bound param should succeed");
    assert_eq!(summaries.len(), 1);
    assert_eq!(ta.constraints.adversary_bound_param, Some(1.into()));

    let mut ambiguous = ThresholdAutomaton::new();
    ambiguous.parameters.push(Parameter {
        name: "f1".to_string(),
        time_varying: false,
    });
    ambiguous.parameters.push(Parameter {
        name: "f2".to_string(),
        time_varying: false,
    });
    ambiguous.constraints.committees.push(IrCommitteeSpec {
        name: "c1".to_string(),
        population: ParamOrConst::Const(100),
        byzantine: ParamOrConst::Const(33),
        committee_size: ParamOrConst::Const(25),
        epsilon: Some(1e-6),
        bound_param: Some(0.into()),
    });
    ambiguous.constraints.committees.push(IrCommitteeSpec {
        name: "c2".to_string(),
        population: ParamOrConst::Const(100),
        byzantine: ParamOrConst::Const(33),
        committee_size: ParamOrConst::Const(25),
        epsilon: Some(1e-6),
        bound_param: Some(1.into()),
    });

    let err = analyze_and_constrain_committees(&mut ambiguous)
        .expect_err("ambiguous bound params should require explicit adversary bound");
    match err {
        PipelineError::Property(msg) => {
            assert!(msg.contains("Multiple committee bound parameters"))
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn ensure_n_parameter_requires_population_parameter() {
    let mut ta = ThresholdAutomaton::new();
    let err = ensure_n_parameter(&ta).expect_err("missing n must fail");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("parameter `n`")),
        other => panic!("unexpected error kind: {other}"),
    }

    ta.parameters.push(Parameter {
        name: "n".to_string(),
        time_varying: false,
    });
    ensure_n_parameter(&ta).expect("n parameter should pass");
}
