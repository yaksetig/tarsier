use super::*;
use std::collections::HashMap;
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::{
    LocalValue, Location, Parameter, SharedVar, SharedVarKind, ThresholdAutomaton,
};
use tarsier_smt::bmc::{BmcResult, KInductionCti};
use tarsier_smt::solver::{Model, ModelValue};
use tarsier_smt::terms::SmtTerm;

fn report_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter { name: "n".into() });
    ta.locations.push(Location {
        name: "Init".into(),
        role: "R".into(),
        phase: "init".into(),
        local_vars: Default::default(),
    });
    ta.locations.push(Location {
        name: "Commit".into(),
        role: "R".into(),
        phase: "commit".into(),
        local_vars: Default::default(),
    });
    ta.locations.push(Location {
        name: "Done".into(),
        role: "R".into(),
        phase: "done".into(),
        local_vars: Default::default(),
    });
    ta.initial_locations = vec![0];
    ta.shared_vars.push(SharedVar {
        name: "vote_count".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.shared_vars.push(SharedVar {
        name: "decided".into(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta
}

fn int_model(values: &[(&str, i64)]) -> Model {
    let mut out = HashMap::new();
    for (name, value) in values {
        out.insert((*name).to_string(), ModelValue::Int(*value));
    }
    Model { values: out }
}

#[test]
fn bmc_result_to_liveness_result_preserves_safe_and_unknown_shapes() {
    let cs = CounterSystem::new(report_ta());

    let safe = bmc_result_to_liveness_result(BmcResult::Safe { depth_checked: 4 }, &cs);
    match safe {
        LivenessResult::Live { depth_checked } => assert_eq!(depth_checked, 4),
        other => panic!("expected Live, got {other:?}"),
    }

    let unknown = bmc_result_to_liveness_result(
        BmcResult::Unknown {
            depth: 9,
            reason: "solver timeout".into(),
        },
        &cs,
    );
    match unknown {
        LivenessResult::Unknown { reason } => assert_eq!(reason, "solver timeout"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn bmc_result_to_liveness_result_unsafe_maps_to_not_live_trace() {
    let cs = CounterSystem::new(report_ta());
    let result = bmc_result_to_liveness_result(
        BmcResult::Unsafe {
            depth: 1,
            model: int_model(&[]),
        },
        &cs,
    );
    match result {
        LivenessResult::NotLive { trace } => {
            assert_eq!(trace.steps.len(), 0);
            assert_eq!(trace.initial_config.kappa.len(), 3);
        }
        other => panic!("expected NotLive, got {other:?}"),
    }
}

#[test]
fn collect_named_location_values_filters_zero_and_negative_entries() {
    let ta = report_ta();
    let model = int_model(&[
        ("kappa_2_0", 3),
        ("kappa_2_1", 0),
        ("kappa_2_2", -2),
        ("kappa_0_0", 99),
    ]);

    let named = collect_named_location_values(&ta, &model, 2);
    assert_eq!(named, vec![("Init".to_string(), 3)]);
}

#[test]
fn collect_named_shared_values_filters_zero_and_missing_entries() {
    let ta = report_ta();
    let model = int_model(&[("g_5_0", 7), ("g_5_1", 0)]);

    let named = collect_named_shared_values(&ta, &model, 5);
    assert_eq!(named, vec![("vote_count".to_string(), 7)]);
}

#[test]
fn summarize_property_violation_covers_agreement_witness_and_fallback() {
    let ta = report_ta();
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![(0, 1), (1, 2)],
    };

    let witness_model = int_model(&[("kappa_4_0", 1), ("kappa_4_1", 2), ("kappa_4_2", 0)]);
    let witness = summarize_property_violation(&ta, &property, &witness_model, 4);
    assert_eq!(witness, "agreement violated: Init and Commit both occupied");

    let fallback_model = int_model(&[("kappa_4_0", 1), ("kappa_4_1", 0), ("kappa_4_2", 0)]);
    let fallback = summarize_property_violation(&ta, &property, &fallback_model, 4);
    assert!(
        fallback.contains("violates agreement"),
        "unexpected fallback text: {fallback}"
    );
}

#[test]
fn summarize_property_violation_covers_invariant_witness_and_fallback() {
    let ta = report_ta();
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![0, 2], vec![1]],
    };

    let witness_model = int_model(&[("kappa_3_0", 1), ("kappa_3_1", 0), ("kappa_3_2", 4)]);
    let witness = summarize_property_violation(&ta, &property, &witness_model, 3);
    assert_eq!(witness, "invariant violated: all of {Init, Done} occupied");

    let fallback_model = int_model(&[("kappa_3_0", 1), ("kappa_3_1", 0), ("kappa_3_2", 0)]);
    let fallback = summarize_property_violation(&ta, &property, &fallback_model, 3);
    assert!(
        fallback.contains("violates invariant"),
        "unexpected fallback text: {fallback}"
    );
}

#[test]
fn summarize_property_violation_termination_highlights_non_goal_population() {
    let ta = report_ta();
    let property = SafetyProperty::Termination { goal_locs: vec![2] };

    let witness_model = int_model(&[("kappa_1_0", 1), ("kappa_1_1", 2), ("kappa_1_2", 0)]);
    let witness = summarize_property_violation(&ta, &property, &witness_model, 1);
    assert_eq!(
        witness,
        "termination violated: non-goal locations still populated (Init=1, Commit=2)"
    );

    let fallback_model = int_model(&[("kappa_1_0", 0), ("kappa_1_1", 0), ("kappa_1_2", 3)]);
    let fallback = summarize_property_violation(&ta, &property, &fallback_model, 1);
    assert_eq!(fallback, "termination violated at step k");
}

#[test]
fn build_cti_rationale_mentions_context_for_both_classifications() {
    let likely = build_cti_rationale(
        &CtiClassification::LikelySpurious,
        3,
        7,
        "agreement violated",
    );
    assert!(likely.contains("k = 3"));
    assert!(likely.contains("depth 7"));
    assert!(likely.contains("likely unreachable"));

    let concrete = build_cti_rationale(&CtiClassification::Concrete, 2, 5, "invariant violated");
    assert!(concrete.contains("k = 2"));
    assert!(concrete.contains("genuine safety issue"));
}

#[test]
fn cti_hypothesis_state_assertions_include_bounds_and_model_defaults() {
    let ta = report_ta();
    let cs = CounterSystem::new(ta);
    let witness = KInductionCti {
        k: 1,
        model: int_model(&[("kappa_0_0", 5), ("g_0_0", 3), ("p_0", 11)]),
    };

    let assertions = cti_hypothesis_state_assertions(&cs, &witness, &[(0, 9)]);
    assert_eq!(assertions.len(), 8);

    assert!(assertions.contains(&SmtTerm::var("p_0").le(SmtTerm::int(9))));
    assert!(assertions.contains(&SmtTerm::var("p_0").ge(SmtTerm::int(0))));
    assert!(assertions.contains(&SmtTerm::var("kappa_0_0").eq(SmtTerm::int(5))));
    assert!(assertions.contains(&SmtTerm::var("kappa_0_1").eq(SmtTerm::int(0))));
    assert!(assertions.contains(&SmtTerm::var("kappa_0_2").eq(SmtTerm::int(0))));
    assert!(assertions.contains(&SmtTerm::var("g_0_0").eq(SmtTerm::int(3))));
    assert!(assertions.contains(&SmtTerm::var("g_0_1").eq(SmtTerm::int(0))));
    assert!(assertions.contains(&SmtTerm::var("p_0").eq(SmtTerm::int(11))));
}

// ========================================================================
// Group 1: POR Entailment & Guard Implication
// ========================================================================

#[test]
fn por_entails_exhaustive_table() {
    use CmpOp::*;
    // All 15 positive match arms
    assert!(por_threshold_op_entails(Eq, 5, Eq, 5));
    assert!(!por_threshold_op_entails(Eq, 5, Eq, 6));

    assert!(por_threshold_op_entails(Eq, 5, Ge, 5));
    assert!(por_threshold_op_entails(Eq, 5, Ge, 3));
    assert!(!por_threshold_op_entails(Eq, 5, Ge, 6));

    assert!(por_threshold_op_entails(Eq, 5, Gt, 4));
    assert!(!por_threshold_op_entails(Eq, 5, Gt, 5));

    assert!(por_threshold_op_entails(Eq, 5, Le, 5));
    assert!(por_threshold_op_entails(Eq, 5, Le, 7));
    assert!(!por_threshold_op_entails(Eq, 5, Le, 4));

    assert!(por_threshold_op_entails(Eq, 5, Lt, 6));
    assert!(!por_threshold_op_entails(Eq, 5, Lt, 5));

    assert!(por_threshold_op_entails(Eq, 5, Ne, 6));
    assert!(!por_threshold_op_entails(Eq, 5, Ne, 5));

    // Ge -> Ge
    assert!(por_threshold_op_entails(Ge, 5, Ge, 3));
    assert!(por_threshold_op_entails(Ge, 5, Ge, 5));
    assert!(!por_threshold_op_entails(Ge, 3, Ge, 5));

    // Ge -> Gt
    assert!(por_threshold_op_entails(Ge, 5, Gt, 4));
    assert!(!por_threshold_op_entails(Ge, 5, Gt, 5));

    // Gt -> Gt
    assert!(por_threshold_op_entails(Gt, 5, Gt, 5));
    assert!(por_threshold_op_entails(Gt, 5, Gt, 3));
    assert!(!por_threshold_op_entails(Gt, 3, Gt, 5));

    // Gt -> Ge
    assert!(por_threshold_op_entails(Gt, 5, Ge, 5));
    assert!(!por_threshold_op_entails(Gt, 3, Ge, 5));

    // Le -> Le
    assert!(por_threshold_op_entails(Le, 3, Le, 5));
    assert!(!por_threshold_op_entails(Le, 5, Le, 3));

    // Le -> Lt
    assert!(por_threshold_op_entails(Le, 3, Lt, 4));
    assert!(!por_threshold_op_entails(Le, 5, Lt, 5));

    // Lt -> Lt
    assert!(por_threshold_op_entails(Lt, 3, Lt, 5));
    assert!(!por_threshold_op_entails(Lt, 5, Lt, 3));

    // Lt -> Le
    assert!(por_threshold_op_entails(Lt, 3, Le, 5));
    assert!(!por_threshold_op_entails(Lt, 5, Le, 3));

    // Ne -> Ne
    assert!(por_threshold_op_entails(Ne, 5, Ne, 5));
    assert!(!por_threshold_op_entails(Ne, 5, Ne, 6));

    // Negative: incompatible direction pairs return false
    assert!(!por_threshold_op_entails(Ge, 5, Lt, 10));
    assert!(!por_threshold_op_entails(Lt, 5, Ge, 0));
    assert!(!por_threshold_op_entails(Ne, 5, Eq, 5));
}

#[test]
fn por_normalized_vars_dedup_and_sort() {
    assert_eq!(por_normalized_vars(&[3, 1, 2, 1, 3]), vec![1, 2, 3]);
    assert_eq!(por_normalized_vars(&[]), Vec::<usize>::new());
    assert_eq!(por_normalized_vars(&[7]), vec![7]);
}

#[test]
fn por_normalized_lc_terms_merges_duplicates() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(2, 0), (3, 1), (-2, 0)],
    };
    // (2, 0) + (-2, 0) = 0, filtered out; only (3, 1) remains
    assert_eq!(por_normalized_lc_terms(&lc), vec![(3, 1)]);

    let lc2 = LinearCombination {
        constant: 5,
        terms: vec![(1, 2), (1, 0)],
    };
    // sorted by param id: (1,0), (1,2)
    assert_eq!(por_normalized_lc_terms(&lc2), vec![(1, 0), (1, 2)]);
}

#[test]
fn por_comparable_lc_constants_same_vs_different_terms() {
    let lhs = LinearCombination {
        constant: 10,
        terms: vec![(1, 0)],
    };
    let rhs = LinearCombination {
        constant: 20,
        terms: vec![(1, 0)],
    };
    assert_eq!(por_comparable_lc_constants(&lhs, &rhs), Some((10, 20)));

    let rhs_diff = LinearCombination {
        constant: 20,
        terms: vec![(2, 0)],
    };
    assert_eq!(por_comparable_lc_constants(&lhs, &rhs_diff), None);
}

fn make_guard_atom(
    vars: Vec<usize>,
    op: CmpOp,
    constant: i64,
    terms: Vec<(i64, usize)>,
    distinct: bool,
) -> GuardAtom {
    GuardAtom::Threshold {
        vars,
        op,
        bound: LinearCombination { constant, terms },
        distinct,
    }
}

fn make_guard(atoms: Vec<GuardAtom>) -> tarsier_ir::threshold_automaton::Guard {
    tarsier_ir::threshold_automaton::Guard { atoms }
}

#[test]
fn por_guard_atom_implies_stronger_bound_and_different_vars() {
    // x >= 5 implies x >= 3
    let lhs = make_guard_atom(vec![0], CmpOp::Ge, 5, vec![], false);
    let rhs = make_guard_atom(vec![0], CmpOp::Ge, 3, vec![], false);
    assert!(por_guard_atom_implies(&lhs, &rhs));

    // x >= 3 does NOT imply x >= 5
    assert!(!por_guard_atom_implies(&rhs, &lhs));

    // Different vars: no implication
    let diff = make_guard_atom(vec![1], CmpOp::Ge, 3, vec![], false);
    assert!(!por_guard_atom_implies(&lhs, &diff));

    // Different distinct flags: no implication
    let dist = make_guard_atom(vec![0], CmpOp::Ge, 3, vec![], true);
    assert!(!por_guard_atom_implies(&lhs, &dist));
}

#[test]
fn por_guard_implies_subset_and_empty_rhs() {
    let a1 = make_guard_atom(vec![0], CmpOp::Ge, 5, vec![], false);
    let a2 = make_guard_atom(vec![1], CmpOp::Le, 3, vec![], false);

    // empty rhs: always implied
    let lhs = make_guard(vec![a1.clone(), a2.clone()]);
    let empty_rhs = make_guard(vec![]);
    assert!(por_guard_implies(&lhs, &empty_rhs));

    // rhs is a subset of lhs atoms
    let rhs_one = make_guard(vec![make_guard_atom(vec![0], CmpOp::Ge, 3, vec![], false)]);
    assert!(por_guard_implies(&lhs, &rhs_one));

    // rhs has an atom that lhs cannot imply
    let rhs_extra = make_guard(vec![make_guard_atom(vec![2], CmpOp::Ge, 1, vec![], false)]);
    assert!(!por_guard_implies(&lhs, &rhs_extra));
}

// ========================================================================
// Group 2: Combinatorics & CEGAR Helpers
// ========================================================================

#[test]
fn combinations_of_size_basic_and_edge_cases() {
    // C(4, 2) = 6
    let result = combinations_of_size(4, 2);
    assert_eq!(result.len(), 6);
    assert_eq!(result[0], vec![0, 1]);
    assert_eq!(result[5], vec![2, 3]);

    // pick=0 -> one empty combination
    assert_eq!(combinations_of_size(5, 0), vec![Vec::<usize>::new()]);

    // pick > n -> empty
    assert_eq!(combinations_of_size(2, 5), Vec::<Vec<usize>>::new());

    // C(3, 3) = 1
    assert_eq!(combinations_of_size(3, 3), vec![vec![0, 1, 2]]);

    // C(1, 1) = 1
    assert_eq!(combinations_of_size(1, 1), vec![vec![0]]);
}

#[test]
fn cegar_selection_timeout_clamps_to_bounds() {
    assert_eq!(cegar_selection_timeout_secs(0), 1);
    assert_eq!(cegar_selection_timeout_secs(1), 1);
    assert_eq!(cegar_selection_timeout_secs(10), 10);
    assert_eq!(cegar_selection_timeout_secs(15), 15);
    assert_eq!(cegar_selection_timeout_secs(100), 15);
}

#[test]
fn cegar_core_compound_predicate_join_behavior() {
    // Single predicate -> None
    assert_eq!(cegar_core_compound_predicate(&["a".into()]), None);

    // Empty -> None
    assert_eq!(cegar_core_compound_predicate(&[]), None);

    // Multiple predicates -> joined
    let result = cegar_core_compound_predicate(&["a".into(), "b".into(), "c".into()]);
    assert_eq!(result, Some("cegar.core.min(a && b && c)".to_string()));
}

#[test]
fn parse_counter_signature_full_minimal_and_invalid() {
    // Full signature with variant brackets and recipient
    let result = parse_counter_signature("cnt_vote[v=1]@Alice<-Bob");
    // variant includes everything after first '[' in stripped name
    assert_eq!(
        result,
        Some((
            "vote".into(),
            "vote[v=1]@Alice<-Bob".into(),
            Some("Alice".into())
        ))
    );

    // Minimal: no brackets, no sender
    let result = parse_counter_signature("cnt_echo@Replica");
    assert_eq!(
        result,
        Some(("echo".into(), "echo".into(), Some("Replica".into())))
    );

    // Invalid: no cnt_ prefix
    assert_eq!(parse_counter_signature("vote@Alice"), None);

    // Invalid: no @ separator
    assert_eq!(parse_counter_signature("cnt_vote"), None);
}

#[test]
fn sorted_unique_strings_dedup_and_sort() {
    let input = vec!["c".into(), "a".into(), "b".into(), "a".into()];
    assert_eq!(
        sorted_unique_strings(input),
        vec!["a".to_string(), "b".into(), "c".into()]
    );
    assert_eq!(sorted_unique_strings(vec![]), Vec::<String>::new());
}

fn make_default_program() -> ast::Program {
    use tarsier_dsl::ast::*;
    ast::Program {
        protocol: Spanned {
            node: ProtocolDecl {
                name: "test".into(),
                imports: vec![],
                modules: vec![],
                enums: vec![],
                parameters: vec![],
                resilience: None,
                pacemaker: None,
                adversary: vec![],
                identities: vec![],
                channels: vec![],
                equivocation_policies: vec![],
                committees: vec![],
                messages: vec![],
                crypto_objects: vec![],
                roles: vec![],
                properties: vec![],
            },
            span: Span { start: 0, end: 0 },
        },
    }
}

#[test]
fn cegar_atomic_refinements_from_default_adversary() {
    // Default adversary: model=byzantine, equivocation=full, auth=none,
    // values=exact, network=classic
    let program = make_default_program();
    let refinements = cegar_atomic_refinements(&program);
    let kinds: Vec<_> = refinements.iter().map(|r| &r.kind).collect();
    assert!(kinds.contains(&&CegarRefinementKind::GlobalEquivocationNone));
    assert!(kinds.contains(&&CegarRefinementKind::GlobalAuthSigned));
    // values=exact by default, so no GlobalValuesExact refinement
    assert!(!kinds.contains(&&CegarRefinementKind::GlobalValuesExact));
    assert!(kinds.contains(&&CegarRefinementKind::GlobalNetworkIdentitySelective));
    assert!(kinds.contains(&&CegarRefinementKind::GlobalNetworkProcessSelective));
}

#[test]
fn cegar_atomic_refinements_with_all_refinements_applied() {
    use tarsier_dsl::ast::*;
    let mut program = make_default_program();
    let span = Span { start: 0, end: 0 };
    let proto = &mut program.protocol.node;
    proto.adversary = vec![
        AdversaryItem {
            key: "model".into(),
            value: "byzantine".into(),
            span,
        },
        AdversaryItem {
            key: "equivocation".into(),
            value: "none".into(),
            span,
        },
        AdversaryItem {
            key: "auth".into(),
            value: "signed".into(),
            span,
        },
        AdversaryItem {
            key: "values".into(),
            value: "exact".into(),
            span,
        },
        AdversaryItem {
            key: "network".into(),
            value: "process_selective".into(),
            span,
        },
    ];
    let refinements = cegar_atomic_refinements(&program);
    // All refinements already applied -> no atomic refinements available
    assert!(refinements.is_empty());
}

// ========================================================================
// Group 3: FairPDR Cube/Frame Data Structures
// ========================================================================

fn make_cube(lits: &[(usize, i64)]) -> FairPdrCube {
    FairPdrCube {
        lits: lits
            .iter()
            .map(|&(idx, val)| FairPdrCubeLit {
                state_var_idx: idx,
                value: val,
            })
            .collect(),
    }
}

fn test_state_vars() -> Vec<(String, SmtSort)> {
    vec![
        ("kappa_0_0".into(), SmtSort::Int),
        ("kappa_0_1".into(), SmtSort::Int),
        ("g_0_0".into(), SmtSort::Int),
    ]
}

#[test]
fn cube_to_conjunction_equality_terms() {
    let cube = make_cube(&[(0, 5), (2, 3)]);
    let state_vars = test_state_vars();
    let conj = cube.to_conjunction(&state_vars);

    let expected = SmtTerm::and(vec![
        SmtTerm::var("kappa_0_0").eq(SmtTerm::int(5)),
        SmtTerm::var("g_0_0").eq(SmtTerm::int(3)),
    ]);
    assert_eq!(conj, expected);
}

#[test]
fn cube_to_conjunction_empty_is_true() {
    let cube = make_cube(&[]);
    let state_vars = test_state_vars();
    assert_eq!(cube.to_conjunction(&state_vars), SmtTerm::bool(true));
}

#[test]
fn cube_subsumes_reflexive_and_subset() {
    let big = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    let small = make_cube(&[(0, 1), (2, 3)]);

    // Reflexive
    assert!(big.subsumes(&big));

    // small subsumes big (small has fewer lits, all present in big)
    assert!(small.subsumes(&big));

    // big does NOT subsume small
    assert!(!big.subsumes(&small));
}

#[test]
fn cube_not_subsumes_when_lit_missing() {
    let a = make_cube(&[(0, 1), (1, 5)]);
    let b = make_cube(&[(0, 1), (1, 2)]);
    // Different values for same var_idx -> not subsumed
    assert!(!a.subsumes(&b));
    assert!(!b.subsumes(&a));
}

#[test]
fn frame_insert_removes_subsumed() {
    let mut frame = FairPdrFrame::default();
    let big = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    frame.insert(big.clone());
    assert!(frame.contains(&big));

    // Insert a more general cube: should remove big
    let small = make_cube(&[(0, 1), (2, 3)]);
    frame.insert(small.clone());
    assert!(frame.contains(&small));
    assert!(!frame.contains(&big));
    assert_eq!(frame.cubes.len(), 1);
}

#[test]
fn frame_insert_skips_when_existing_subsumes() {
    let mut frame = FairPdrFrame::default();
    let small = make_cube(&[(0, 1)]);
    frame.insert(small.clone());

    // Insert a more specific cube: should be skipped
    let big = make_cube(&[(0, 1), (1, 2)]);
    frame.insert(big.clone());
    assert!(!frame.contains(&big));
    assert_eq!(frame.cubes.len(), 1);
}

#[test]
fn fair_pdr_budgets_scale_correctly() {
    // bad_cube_budget: 5000 + state*120 + frontier*800
    assert_eq!(fair_pdr_bad_cube_budget(0, 0), 5_000);
    assert_eq!(fair_pdr_bad_cube_budget(10, 0), 5_000 + 10 * 120);
    assert_eq!(fair_pdr_bad_cube_budget(10, 5), 5_000 + 10 * 120 + 5 * 800);

    // obligation_budget: 10000 + state*220 + level*1500
    assert_eq!(fair_pdr_obligation_budget(0, 0), 10_000);
    assert_eq!(fair_pdr_obligation_budget(10, 0), 10_000 + 10 * 220);
    assert_eq!(
        fair_pdr_obligation_budget(10, 5),
        10_000 + 10 * 220 + 5 * 1500
    );
}

#[test]
fn literal_drop_order_prioritizes_by_prefix() {
    let state_vars: Vec<(String, SmtSort)> = vec![
        ("kappa_0_0".into(), SmtSort::Int), // idx 0, class 4 (kappa, val!=0)
        ("m_armed_0".into(), SmtSort::Int), // idx 1, class 0 (monitor)
        ("g_0_0".into(), SmtSort::Int),     // idx 2, class 2 (gamma, val!=0)
        ("time_0".into(), SmtSort::Int),    // idx 3, class 0 (time)
    ];
    let cube = FairPdrCube {
        lits: vec![
            FairPdrCubeLit {
                state_var_idx: 0,
                value: 5,
            },
            FairPdrCubeLit {
                state_var_idx: 1,
                value: 1,
            },
            FairPdrCubeLit {
                state_var_idx: 2,
                value: 3,
            },
            FairPdrCubeLit {
                state_var_idx: 3,
                value: 7,
            },
        ],
    };
    let order = fair_pdr_literal_drop_order(&cube, &state_vars);
    // Class 0: indices 1 (m_armed), 3 (time) -> cube positions 1, 3
    // Class 2: index 2 (g_0_0, val!=0) -> cube position 2
    // Class 4: index 0 (kappa, val!=0) -> cube position 0
    assert_eq!(order, vec![1, 3, 2, 0]);
}

// ========================================================================
// Group 4: POR Rule Analysis
// ========================================================================

use tarsier_ir::threshold_automaton::{Rule, Update, UpdateKind};

#[test]
fn guard_read_vars_from_threshold_atoms() {
    let guard = make_guard(vec![
        make_guard_atom(vec![0, 1], CmpOp::Ge, 5, vec![], false),
        make_guard_atom(vec![2], CmpOp::Le, 3, vec![], false),
    ]);
    let vars = guard_read_vars(&guard);
    assert_eq!(vars.len(), 3);
    assert!(vars.contains(&0));
    assert!(vars.contains(&1));
    assert!(vars.contains(&2));
}

#[test]
fn update_write_vars_unique() {
    let updates = vec![
        Update {
            var: 0,
            kind: UpdateKind::Increment,
        },
        Update {
            var: 2,
            kind: UpdateKind::Increment,
        },
        Update {
            var: 0,
            kind: UpdateKind::Increment,
        },
    ];
    let vars = update_write_vars(&updates);
    assert_eq!(vars.len(), 2);
    assert!(vars.contains(&0));
    assert!(vars.contains(&2));
}

#[test]
fn is_pure_stutter_rule_detection() {
    let stutter = Rule {
        from: 0,
        to: 0,
        guard: make_guard(vec![]),
        updates: vec![],
    };
    assert!(is_pure_stutter_rule(&stutter));

    let non_stutter_move = Rule {
        from: 0,
        to: 1,
        guard: make_guard(vec![]),
        updates: vec![],
    };
    assert!(!is_pure_stutter_rule(&non_stutter_move));

    let non_stutter_update = Rule {
        from: 0,
        to: 0,
        guard: make_guard(vec![]),
        updates: vec![Update {
            var: 0,
            kind: UpdateKind::Increment,
        }],
    };
    assert!(!is_pure_stutter_rule(&non_stutter_update));
}

fn make_por_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters
        .push(tarsier_ir::threshold_automaton::Parameter { name: "n".into() });
    // Location 0: Init (role A)
    ta.locations.push(Location {
        name: "Init".into(),
        role: "A".into(),
        phase: "init".into(),
        local_vars: Default::default(),
    });
    // Location 1: Done (role A)
    ta.locations.push(Location {
        name: "Done".into(),
        role: "A".into(),
        phase: "done".into(),
        local_vars: Default::default(),
    });
    // Location 2: Wait (role B)
    ta.locations.push(Location {
        name: "Wait".into(),
        role: "B".into(),
        phase: "wait".into(),
        local_vars: Default::default(),
    });
    // Location 3: Finished (role B)
    ta.locations.push(Location {
        name: "Finished".into(),
        role: "B".into(),
        phase: "finished".into(),
        local_vars: Default::default(),
    });
    ta.shared_vars.push(SharedVar {
        name: "x".into(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta.shared_vars.push(SharedVar {
        name: "y".into(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta.initial_locations = vec![0, 2];
    ta
}

#[test]
fn rules_independent_disjoint_locations_and_vars() {
    let ta = make_por_ta();
    // Rule A: 0 -> 1 (role A), writes var 0
    let rule_a = Rule {
        from: 0,
        to: 1,
        guard: make_guard(vec![]),
        updates: vec![Update {
            var: 0,
            kind: UpdateKind::Increment,
        }],
    };
    // Rule B: 2 -> 3 (role B), writes var 1
    let rule_b = Rule {
        from: 2,
        to: 3,
        guard: make_guard(vec![]),
        updates: vec![Update {
            var: 1,
            kind: UpdateKind::Increment,
        }],
    };
    assert!(rules_independent(&ta, &rule_a, &rule_b));
}

#[test]
fn rules_not_independent_shared_location() {
    let ta = make_por_ta();
    // Both rules share source location 0
    let rule_a = Rule {
        from: 0,
        to: 1,
        guard: make_guard(vec![]),
        updates: vec![],
    };
    let rule_b = Rule {
        from: 0,
        to: 1,
        guard: make_guard(vec![]),
        updates: vec![],
    };
    assert!(!rules_independent(&ta, &rule_a, &rule_b));
}

#[test]
fn rules_not_independent_write_read_conflict() {
    let ta = make_por_ta();
    // Rule A: 0 -> 1, writes var 0
    let rule_a = Rule {
        from: 0,
        to: 1,
        guard: make_guard(vec![]),
        updates: vec![Update {
            var: 0,
            kind: UpdateKind::Increment,
        }],
    };
    // Rule B: 2 -> 3, reads var 0 (in guard)
    let rule_b = Rule {
        from: 2,
        to: 3,
        guard: make_guard(vec![make_guard_atom(vec![0], CmpOp::Ge, 1, vec![], false)]),
        updates: vec![],
    };
    assert!(!rules_independent(&ta, &rule_a, &rule_b));
}

#[test]
fn automaton_footprint_counts() {
    let ta = make_por_ta();
    let fp = automaton_footprint(&ta);
    assert_eq!(fp.locations, 4);
    assert_eq!(fp.rules, 0);
    assert_eq!(fp.shared_vars, 2);
    assert_eq!(fp.message_counters, 0);
}

// ========================================================================
// Group 5: SMT Term Construction Helpers
// ========================================================================

#[test]
fn committee_bound_assertions_produces_pairs() {
    let bounds = vec![(0, 10u64), (2, 5u64)];
    let assertions = committee_bound_assertions(&bounds);
    assert_eq!(assertions.len(), 4);
    assert!(assertions.contains(&SmtTerm::var("p_0").le(SmtTerm::int(10))));
    assert!(assertions.contains(&SmtTerm::var("p_0").ge(SmtTerm::int(0))));
    assert!(assertions.contains(&SmtTerm::var("p_2").le(SmtTerm::int(5))));
    assert!(assertions.contains(&SmtTerm::var("p_2").ge(SmtTerm::int(0))));

    // Empty bounds -> no assertions
    assert!(committee_bound_assertions(&[]).is_empty());
}

#[test]
fn one_hot_sum_equals_one() {
    let vars: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
    let term = one_hot_assertion(&vars);
    let expected = SmtTerm::int(0)
        .add(SmtTerm::var("a"))
        .add(SmtTerm::var("b"))
        .add(SmtTerm::var("c"))
        .eq(SmtTerm::int(1));
    assert_eq!(term, expected);

    // Empty vars -> false
    assert_eq!(one_hot_assertion(&[]), SmtTerm::bool(false));
}

#[test]
fn bit_helpers_correct_terms() {
    assert_eq!(
        bit_is_true(String::from("x")),
        SmtTerm::var("x").eq(SmtTerm::int(1))
    );
    assert_eq!(
        bit_is_false(String::from("x")),
        SmtTerm::var("x").eq(SmtTerm::int(0))
    );

    let domain = bit_domain(String::from("x"));
    assert_eq!(domain.len(), 2);
    assert_eq!(domain[0], SmtTerm::var("x").ge(SmtTerm::int(0)));
    assert_eq!(domain[1], SmtTerm::var("x").le(SmtTerm::int(1)));
}

#[test]
fn encode_lc_constant_and_with_params() {
    // Constant only
    let lc = LinearCombination {
        constant: 42,
        terms: vec![],
    };
    assert_eq!(encode_lc_term(&lc), SmtTerm::int(42));

    // With params: 42 + 1*p_0 + 3*p_1
    let lc2 = LinearCombination {
        constant: 42,
        terms: vec![(1, 0), (3, 1)],
    };
    let result = encode_lc_term(&lc2);
    let expected = SmtTerm::int(42)
        .add(SmtTerm::var("p_0"))
        .add(SmtTerm::int(3).mul(SmtTerm::var("p_1")));
    assert_eq!(result, expected);
}

#[test]
fn location_zero_assertions_count() {
    let locs = vec![3usize, 5];
    let assertions = location_zero_assertions_for_depth(&locs, 2);
    // 2 locations * (2+1) steps = 6 assertions
    assert_eq!(assertions.len(), 6);
    // Spot check first and last
    assert_eq!(assertions[0], SmtTerm::var("kappa_0_3").eq(SmtTerm::int(0)));
    assert_eq!(assertions[5], SmtTerm::var("kappa_2_5").eq(SmtTerm::int(0)));
}

#[test]
fn bool_to_bit_produces_ite() {
    let cond = SmtTerm::var("flag");
    let result = bool_to_bit(cond.clone());
    let expected = SmtTerm::Ite(
        Box::new(cond),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::int(0)),
    );
    assert_eq!(result, expected);
}
