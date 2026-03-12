use super::*;
use tarsier_ir::counter_system::Configuration;
use tarsier_ir::threshold_automaton::{Location, SharedVar, SharedVarKind};

fn make_test_ta() -> ThresholdAutomaton {
    ThresholdAutomaton {
        locations: vec![
            Location {
                name: "Init".into(),
                role: "R".into(),
                phase: "p0".into(),
                local_vars: Default::default(),
            },
            Location {
                name: "Sent".into(),
                role: "R".into(),
                phase: "p1".into(),
                local_vars: Default::default(),
            },
            Location {
                name: "Decided".into(),
                role: "R".into(),
                phase: "p2".into(),
                local_vars: Default::default(),
            },
        ],
        initial_locations: vec![0.into()],
        shared_vars: vec![SharedVar {
            name: "msgs".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        }],
        parameters: vec![
            tarsier_ir::threshold_automaton::Parameter {
                name: "n".into(),
                time_varying: false,
            },
            tarsier_ir::threshold_automaton::Parameter {
                name: "t".into(),
                time_varying: false,
            },
            tarsier_ir::threshold_automaton::Parameter {
                name: "f".into(),
                time_varying: false,
            },
        ],
        ..ThresholdAutomaton::default()
    }
}

#[test]
fn generate_candidates_produces_zero_location_for_non_initial() {
    let ta = make_test_ta();
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![(1.into(), 2.into())],
    };
    let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
    // Should have zero-location candidates for Sent and Decided (not Init).
    let zero_labels: Vec<&str> = candidates
        .iter()
        .filter(|c| {
            c.op == PredicateOp::Eq && matches!(c.rhs.as_slice(), [(1, LinearTerm::Const(0))])
        })
        .map(|c| c.label.as_str())
        .collect();
    assert!(zero_labels.contains(&"kappa_Sent = 0"));
    assert!(zero_labels.contains(&"kappa_Decided = 0"));
    assert!(!zero_labels.iter().any(|l| l.contains("Init")));
}

#[test]
fn generate_candidates_includes_upper_bounds() {
    let ta = make_test_ta();
    let prop = SafetyProperty::Invariant {
        bad_sets: vec![vec![2.into()]],
    };
    let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
    let has_kappa_le_n = candidates.iter().any(|c| c.label == "kappa_Init <= n");
    assert!(has_kappa_le_n);
}

#[test]
fn generate_candidates_includes_shared_var_bounds() {
    let ta = make_test_ta();
    let prop = SafetyProperty::Invariant {
        bad_sets: vec![vec![2.into()]],
    };
    let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
    assert!(candidates.iter().any(|c| c.label == "gamma_msgs >= 0"));
    assert!(candidates.iter().any(|c| c.label == "gamma_msgs <= n"));
}

#[test]
fn generate_candidates_includes_pairwise_sums() {
    let ta = make_test_ta();
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![(1.into(), 2.into())],
    };
    let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
    assert!(candidates
        .iter()
        .any(|c| c.label == "kappa_Sent + kappa_Decided <= n"));
}

#[test]
fn generate_candidates_cti_filters_occupied_locations() {
    let ta = make_test_ta();
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![(1.into(), 2.into())],
    };
    let cti = InductionCtiSummary {
        k: 1,
        params: vec![("n".into(), 4), ("t".into(), 1), ("f".into(), 1)],
        hypothesis_locations: vec![("Sent".into(), 2)],
        hypothesis_shared: vec![],
        violating_locations: vec![("Decided".into(), 1)],
        violating_shared: vec![],
        final_step_rules: vec![],
        violated_condition: String::new(),
        classification: CtiClassification::LikelySpurious,
        classification_evidence: vec![],
        rationale: String::new(),
    };
    let candidates = generate_linear_predicate_candidates(&ta, &prop, Some(&cti));
    // Zero-location candidates for Sent and Decided should be excluded (CTI-occupied).
    let zero_labels: Vec<&str> = candidates
        .iter()
        .filter(|c| {
            c.op == PredicateOp::Eq && matches!(c.rhs.as_slice(), [(1, LinearTerm::Const(0))])
        })
        .map(|c| c.label.as_str())
        .collect();
    assert!(!zero_labels.contains(&"kappa_Sent = 0"));
    assert!(!zero_labels.contains(&"kappa_Decided = 0"));
}

#[test]
fn candidate_predicate_evaluate_zero_location() {
    let pred = CandidatePredicate::zero_location(1, "Sent");
    let config_zero = Configuration {
        kappa: vec![3, 0, 1],
        gamma: vec![],
        params: vec![4],
    };
    assert!(pred.evaluate(&config_zero));
    let config_nonzero = Configuration {
        kappa: vec![3, 2, 1],
        gamma: vec![],
        params: vec![4],
    };
    assert!(!pred.evaluate(&config_nonzero));
}

#[test]
fn candidate_predicate_evaluate_le_param() {
    let pred = CandidatePredicate::kappa_le_param(0, "Init", 0, "n");
    let config_ok = Configuration {
        kappa: vec![3],
        gamma: vec![],
        params: vec![4],
    };
    assert!(pred.evaluate(&config_ok));
    let config_bad = Configuration {
        kappa: vec![5],
        gamma: vec![],
        params: vec![4],
    };
    assert!(!pred.evaluate(&config_bad));
}

#[test]
fn to_smt_term_zero_location() {
    let pred = CandidatePredicate::zero_location(2, "Decided");
    let term = pred.to_smt_term(0);
    // Should be: kappa_0_2 = 0
    let expected = SmtTerm::var("kappa_0_2").eq(SmtTerm::int(0));
    assert_eq!(term, expected);
}

#[test]
fn to_smt_term_le_param() {
    let pred = CandidatePredicate::kappa_le_param(1, "Sent", 0, "n");
    let term = pred.to_smt_term(3);
    // Should be: kappa_3_1 <= p_0
    let expected = SmtTerm::var("kappa_3_1").le(SmtTerm::var("p_0"));
    assert_eq!(term, expected);
}

#[test]
fn to_smt_term_pairwise_sum() {
    let pred = CandidatePredicate::kappa_sum_le_param(&[(1, "Sent"), (2, "Decided")], 0, "n");
    let term = pred.to_smt_term(0);
    // Should be: (kappa_0_1 + kappa_0_2) <= p_0
    let expected = SmtTerm::var("kappa_0_1")
        .add(SmtTerm::var("kappa_0_2"))
        .le(SmtTerm::var("p_0"));
    assert_eq!(term, expected);
}

#[test]
fn to_smt_term_gamma_ge_zero() {
    let pred = CandidatePredicate::gamma_ge_zero(0, "msgs");
    let term = pred.to_smt_term(1);
    // Should be: g_1_0 >= 0
    let expected = SmtTerm::var("g_1_0").ge(SmtTerm::int(0));
    assert_eq!(term, expected);
}

/// Build a minimal ThresholdAutomaton suitable for solver-based tests.
/// Two locations (Init, Done), one shared var, one rule Init→Done.
fn make_solver_test_ta() -> ThresholdAutomaton {
    use tarsier_ir::threshold_automaton::*;
    ThresholdAutomaton {
        locations: vec![
            Location {
                name: "Init".into(),
                role: "R".into(),
                phase: "p0".into(),
                local_vars: Default::default(),
            },
            Location {
                name: "Done".into(),
                role: "R".into(),
                phase: "p1".into(),
                local_vars: Default::default(),
            },
        ],
        initial_locations: vec![0.into()],
        shared_vars: vec![],
        rules: vec![Rule {
            from: 0.into(),
            to: 1.into(),
            guard: Guard { atoms: vec![] },
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        }],
        parameters: vec![Parameter {
            name: "n".into(),
            time_varying: false,
        }],
        constraints: ThresholdAutomatonConstraints {
            resilience_condition: None,
            adversary_bound_param: None,
            committees: vec![],
        },
        ..ThresholdAutomaton::default()
    }
}

#[test]
fn check_init_zero_non_initial_location_holds() {
    // kappa_Done = 0 should hold at init (all processes start at Init).
    let ta = make_solver_test_ta();
    let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
    let pred = CandidatePredicate::zero_location(1, "Done");
    let mut solver = Z3Solver::with_timeout_secs(10);
    let result = check_predicate_init(&mut solver, &cs, &pred, &[]).unwrap();
    assert!(result, "kappa_Done = 0 should hold at init");
}

#[test]
fn check_init_zero_initial_location_fails_with_resilience() {
    // kappa_Init = 0 should NOT hold at init when n >= 1
    // (processes start at Init, so kappa_Init = n >= 1).
    use tarsier_ir::threshold_automaton::{
        CmpOp as IrCmpOp, LinearCombination, LinearConstraint, ParamId,
    };
    let mut ta = make_solver_test_ta();
    // Add resilience condition: n >= 1 (so there's at least one process).
    ta.constraints.resilience_condition = Some(LinearConstraint {
        lhs: LinearCombination {
            terms: vec![(1, ParamId::new(0))],
            constant: 0,
        },
        op: IrCmpOp::Ge,
        rhs: LinearCombination {
            terms: vec![],
            constant: 1,
        },
    });
    let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
    let pred = CandidatePredicate::zero_location(0, "Init");
    let mut solver = Z3Solver::with_timeout_secs(10);
    let result = check_predicate_init(&mut solver, &cs, &pred, &[]).unwrap();
    assert!(
        !result,
        "kappa_Init = 0 should NOT hold at init when n >= 1"
    );
}

#[test]
fn score_candidates_ranks_by_inductiveness() {
    let ta = make_solver_test_ta();
    let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
    let candidates = vec![
        CandidatePredicate::zero_location(0, "Init"), // fails init
        CandidatePredicate::kappa_le_param(0, "Init", 0, "n"), // kappa_Init <= n: should be inductive
    ];
    let mut solver = Z3Solver::with_timeout_secs(10);
    let results = score_candidates(&mut solver, &cs, &candidates, &[]).unwrap();
    // The inductive candidate (kappa_Init <= n) should score higher.
    assert!(results[0].score >= results[1].score);
    assert!(results[0].holds_at_init);
}

#[test]
fn property_relevant_location_set_agreement() {
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![(0.into(), 1.into()), (2.into(), 3.into())],
    };
    let locs = property_relevant_location_set(&prop);
    assert_eq!(locs.len(), 4);
    assert!(locs.contains(&0));
    assert!(locs.contains(&1));
    assert!(locs.contains(&2));
    assert!(locs.contains(&3));
}

#[test]
fn property_relevant_location_set_invariant() {
    let prop = SafetyProperty::Invariant {
        bad_sets: vec![vec![5.into(), 6.into()], vec![7.into()]],
    };
    let locs = property_relevant_location_set(&prop);
    assert_eq!(locs.len(), 3);
    assert!(locs.contains(&5));
    assert!(locs.contains(&6));
    assert!(locs.contains(&7));
}

#[test]
fn property_relevant_location_set_termination() {
    let prop = SafetyProperty::Termination {
        goal_locs: vec![10.into(), 20.into()],
    };
    let locs = property_relevant_location_set(&prop);
    assert_eq!(locs.len(), 2);
    assert!(locs.contains(&10));
    assert!(locs.contains(&20));
}

// --- INV-05 tests: pre-pass integration ---

#[test]
fn predicate_assertions_for_depth_generates_correct_count() {
    let preds = vec![
        CandidatePredicate::zero_location(1, "Sent"),
        CandidatePredicate::gamma_ge_zero(0, "msgs"),
    ];
    let assertions = predicate_assertions_for_depth(&preds, 3);
    // 2 predicates × 4 steps (0..=3) = 8
    assert_eq!(assertions.len(), 8);
}

#[test]
fn predicate_assertions_for_step_relation_generates_pairs() {
    let preds = vec![CandidatePredicate::zero_location(1, "Sent")];
    let assertions = predicate_assertions_for_step_relation(&preds);
    // 1 predicate × 2 steps (0, 1)
    assert_eq!(assertions.len(), 2);
}

#[test]
fn infer_inductive_predicates_returns_only_fully_inductive() {
    let ta = make_solver_test_ta();
    let cs = abstract_to_cs(ta.clone());
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let options = PipelineOptions::default();
    let result = infer_inductive_predicates(&ta, &cs, &prop, &[], &options).unwrap();
    // All returned predicates should be fully inductive (score == 2).
    // The exact count depends on the TA, but we should get at least some.
    // kappa_Init <= n should hold at init (all processes start there)
    // and be inductive (no rule can create more processes than n).
    for pred in &result {
        // Verify each returned predicate is actually inductive by re-checking.
        let mut solver = Z3Solver::with_timeout_secs(10);
        assert!(
            check_predicate_init(&mut solver, &cs, pred, &[]).unwrap(),
            "predicate {} should hold at init",
            pred.label
        );
        assert!(
            check_predicate_consecution(&mut solver, &cs, pred, &[]).unwrap(),
            "predicate {} should be inductive",
            pred.label
        );
    }
}

#[test]
fn k_induction_with_predicate_invariants_proves_with_strengthening() {
    // Build a simple system (Init=0, Done=1) and verify that injecting
    // a known-inductive predicate allows k-induction to succeed.
    let ta = make_solver_test_ta();
    let cs = abstract_to_cs(ta.clone());
    let prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    // kappa_Done <= n is inductive for this system.
    let invariants = vec![CandidatePredicate::kappa_le_param(1, "Done", 0, "n")];
    let mut solver = Z3Solver::with_timeout_secs(10);
    let result = run_k_induction_with_predicate_invariants(
        &mut solver,
        &cs,
        &prop,
        5,
        &[],
        &invariants,
        None,
    )
    .unwrap();
    // With empty conflicting_pairs and a valid invariant,
    // the property should be trivially provable.
    assert!(
        matches!(result, KInductionResult::Proved { .. }),
        "expected Proved, got {:?}",
        result
    );
}
