use crate::pipeline::verification::*;
use crate::pipeline::*;

#[test]
fn solver_choice_name_z3() {
    assert_eq!(solver_choice_name(SolverChoice::Z3), "z3");
}

#[test]
fn solver_choice_name_cvc5() {
    assert_eq!(solver_choice_name(SolverChoice::Cvc5), "cvc5");
}

#[test]
fn soundness_mode_name_strict() {
    assert_eq!(soundness_mode_name(SoundnessMode::Strict), "strict");
}

#[test]
fn soundness_mode_name_permissive() {
    assert_eq!(soundness_mode_name(SoundnessMode::Permissive), "permissive");
}

#[test]
fn solver_choice_label_matches_name() {
    assert_eq!(solver_choice_label(SolverChoice::Z3), "z3");
    assert_eq!(solver_choice_label(SolverChoice::Cvc5), "cvc5");
}

#[test]
fn proof_engine_label_values() {
    assert_eq!(proof_engine_label(ProofEngine::KInduction), "kinduction");
    assert_eq!(proof_engine_label(ProofEngine::Pdr), "pdr");
    assert_eq!(proof_engine_label(ProofEngine::Ranking), "ranking");
}

#[test]
fn fairness_mode_label_values() {
    assert_eq!(fairness_mode_label(FairnessMode::Weak), "weak");
    assert_eq!(fairness_mode_label(FairnessMode::Strong), "strong");
}

#[test]
fn committee_bound_assertions_empty() {
    let result = committee_bound_assertions(&[]);
    assert!(result.is_empty());
}

#[test]
fn committee_bound_assertions_single_bound() {
    let result = committee_bound_assertions(&[(0, 42)]);
    assert_eq!(result.len(), 2);
    // First: p_0 <= 42
    let expected_le = SmtTerm::var("p_0".to_string()).le(SmtTerm::int(42));
    assert_eq!(result[0], expected_le);
    // Second: p_0 >= 0
    let expected_ge = SmtTerm::var("p_0".to_string()).ge(SmtTerm::int(0));
    assert_eq!(result[1], expected_ge);
}

#[test]
fn committee_bound_assertions_multiple_bounds() {
    let result = committee_bound_assertions(&[(0, 10), (2, 20)]);
    assert_eq!(result.len(), 4);
}

#[test]
fn location_zero_assertions_for_depth_correct_count() {
    let locs = vec![2, 5];
    let depth = 3;
    let result = location_zero_assertions_for_depth(&locs, depth);
    // 2 locations * (depth+1=4) steps = 8 assertions
    assert_eq!(result.len(), 8);
}

#[test]
fn location_zero_assertions_for_depth_content() {
    let locs = vec![3];
    let depth = 1;
    let result = location_zero_assertions_for_depth(&locs, depth);
    assert_eq!(result.len(), 2);
    // step 0: kappa_0_3 = 0
    assert_eq!(
        result[0],
        SmtTerm::var("kappa_0_3".to_string()).eq(SmtTerm::int(0))
    );
    // step 1: kappa_1_3 = 0
    assert_eq!(
        result[1],
        SmtTerm::var("kappa_1_3".to_string()).eq(SmtTerm::int(0))
    );
}

#[test]
fn location_zero_assertions_for_step_relation_count() {
    let locs = vec![1, 2, 3];
    let result = location_zero_assertions_for_step_relation(&locs);
    // 3 locations * 2 steps (0 and 1) = 6 assertions
    assert_eq!(result.len(), 6);
}

#[test]
fn location_zero_assertions_for_step_relation_content() {
    let locs = vec![5];
    let result = location_zero_assertions_for_step_relation(&locs);
    assert_eq!(result.len(), 2);
    assert_eq!(
        result[0],
        SmtTerm::var("kappa_0_5".to_string()).eq(SmtTerm::int(0))
    );
    assert_eq!(
        result[1],
        SmtTerm::var("kappa_1_5".to_string()).eq(SmtTerm::int(0))
    );
}

#[test]
fn safety_property_canonical_agreement_sorted() {
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![(2.into(), 3.into()), (0.into(), 1.into())],
    };
    let canon = safety_property_canonical(&prop);
    // Pairs should be sorted
    assert_eq!(
        canon,
        "agreement:[(LocationId(0), LocationId(1)), (LocationId(2), LocationId(3))]"
    );
}

#[test]
fn safety_property_canonical_agreement_empty() {
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let canon = safety_property_canonical(&prop);
    assert_eq!(canon, "agreement:[]");
}

#[test]
fn safety_property_canonical_invariant() {
    let prop = SafetyProperty::Invariant {
        bad_sets: vec![vec![2.into(), 1.into()], vec![0.into()]],
    };
    let canon = safety_property_canonical(&prop);
    // Inner sets sorted, outer sorted
    assert_eq!(
        canon,
        "invariant:[[LocationId(0)], [LocationId(1), LocationId(2)]]"
    );
}

#[test]
fn safety_property_canonical_termination() {
    let prop = SafetyProperty::Termination {
        goal_locs: vec![3.into(), 1.into(), 2.into()],
    };
    let canon = safety_property_canonical(&prop);
    assert_eq!(
        canon,
        "termination:[LocationId(1), LocationId(2), LocationId(3)]"
    );
}

/// Helper: build a minimal ThresholdAutomaton with the given parameters.
fn make_ta_with_params(params: &[&str]) -> ThresholdAutomaton {
    ThresholdAutomaton {
        parameters: params
            .iter()
            .map(|name| tarsier_ir::threshold_automaton::Parameter {
                name: name.to_string(),
                time_varying: false,
            })
            .collect(),
        ..ThresholdAutomaton::default()
    }
}

#[test]
fn named_committee_bounds_with_params() {
    let ta = make_ta_with_params(&["n", "t", "b"]);
    let bounds = vec![(2, 61), (0, 100)];
    let named = named_committee_bounds(&ta, &bounds);
    // Should be sorted by name: b, n
    assert_eq!(named, vec![("b".into(), 61), ("n".into(), 100)]);
}

#[test]
fn named_committee_bounds_missing_param() {
    let ta = make_ta_with_params(&["n"]);
    // param_id=5 is out of bounds
    let bounds = vec![(5, 42)];
    let named = named_committee_bounds(&ta, &bounds);
    assert_eq!(named, vec![("param#5".into(), 42)]);
}

#[test]
fn liveness_result_to_property_verification_live() {
    let result =
        liveness_result_to_property_verification(LivenessResult::Live { depth_checked: 10 });
    match result {
        VerificationResult::Safe { depth_checked } => assert_eq!(depth_checked, 10),
        _ => panic!("Expected Safe variant"),
    }
}

#[test]
fn liveness_result_to_property_verification_unknown() {
    let result = liveness_result_to_property_verification(LivenessResult::Unknown {
        reason: "timeout".into(),
    });
    match result {
        VerificationResult::Unknown { reason } => assert_eq!(reason, "timeout"),
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn build_cti_rationale_likely_spurious() {
    let rationale = build_cti_rationale(
        &CtiClassification::LikelySpurious,
        3,
        10,
        "agreement violated",
    );
    assert!(rationale.contains("k = 3"));
    assert!(rationale.contains("depth 10"));
    assert!(rationale.contains("agreement violated"));
    assert!(rationale.contains("likely unreachable"));
}

#[test]
fn build_cti_rationale_concrete() {
    let rationale = build_cti_rationale(&CtiClassification::Concrete, 2, 5, "invariant violated");
    assert!(rationale.contains("k = 2"));
    assert!(rationale.contains("invariant violated"));
    assert!(rationale.contains("genuine safety issue"));
}
