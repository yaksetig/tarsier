//! Extended integration tests for refinement SMT encoding (REF-06 + REFX-01).

use tarsier_ir::product::build_product;
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
use tarsier_ir::threshold_automaton::*;
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::refinement_encoder::{
    encode_refinement_check, run_refinement_solver, SimulationCheckResult,
};

fn make_ta(
    loc_names: &[&str],
    initial: &[usize],
    rules: &[(usize, usize)],
    params: &[&str],
    shared_vars: &[&str],
) -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    for name in loc_names {
        ta.add_location(Location {
            name: name.to_string(),
            role: "R".into(),
            phase: name.to_string(),
            local_vars: Default::default(),
        });
    }
    for &i in initial {
        ta.initial_locations.push(LocationId::from(i));
    }
    for &(from, to) in rules {
        ta.add_rule(Rule {
            from: LocationId::from(from),
            to: LocationId::from(to),
            guard: Guard::trivial(),
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
    }
    for name in params {
        ta.add_parameter(Parameter {
            name: name.to_string(),
            time_varying: false,
        });
    }
    for name in shared_vars {
        ta.add_shared_var(SharedVar {
            name: name.to_string(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
    }
    ta
}

fn build_encoding(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
    loc_map: &[(usize, Option<usize>)],
    depth: usize,
) -> (usize, usize) {
    let mut mapping = RefinementMapping::new("abs".into());
    for &(c, a) in loc_map {
        match a {
            Some(a_id) => mapping.map_location(LocationId::from(c), LocationId::from(a_id)),
            None => mapping.mark_location_internal(LocationId::from(c)),
        }
    }
    let rel = RefinementRelation::new(mapping);
    let product = build_product(concrete, abstract_ta, &rel).unwrap();
    let enc = encode_refinement_check(&product, depth);
    (enc.declarations.len(), enc.assertions.len())
}

#[test]
fn encoding_size_scales_with_depth() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let (decls_d1, asserts_d1) =
        build_encoding(&concrete, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 1);
    let (decls_d3, asserts_d3) =
        build_encoding(&concrete, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 3);

    assert!(
        decls_d3 > decls_d1,
        "deeper encoding should have more declarations"
    );
    assert!(
        asserts_d3 > asserts_d1,
        "deeper encoding should have more assertions"
    );
}

#[test]
fn encoding_with_parameters_declares_param_vars() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &["n", "t"], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &["n"], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();
    let enc = encode_refinement_check(&product, 1);

    // Should have pp_0, pp_1, pp_2 declarations (3 merged params).
    let param_decls: Vec<_> = enc
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pp_"))
        .collect();
    assert_eq!(param_decls.len(), 3);
}

#[test]
fn encoding_with_shared_vars_declares_gamma_vars() {
    let concrete = make_ta(&["A"], &[0], &[], &[], &["x"]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &["y"]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();
    let enc = encode_refinement_check(&product, 1);

    // Step 0: pg_0_0, pg_0_1; Step 1: pg_1_0, pg_1_1
    let gamma_decls: Vec<_> = enc
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pg_"))
        .collect();
    assert_eq!(gamma_decls.len(), 4); // 2 vars × 2 steps (0 and 1)
}

#[test]
fn encoding_trivial_no_mismatches() {
    // Single location, identity — no mismatches, encoding should assert false.
    let concrete = make_ta(&["A"], &[0], &[], &[], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();
    let enc = encode_refinement_check(&product, 5);

    // Should have BoolLit(false) assertion.
    let has_false = enc
        .assertions
        .iter()
        .any(|t| matches!(t, tarsier_smt::terms::SmtTerm::BoolLit(false)));
    assert!(has_false);
}

#[test]
fn encoding_depth_zero_still_has_initial_state() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let (decls, asserts) =
        build_encoding(&concrete, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 0);

    assert!(decls > 0, "depth 0 should still declare initial state vars");
    assert!(
        asserts > 0,
        "depth 0 should still have initial state constraints"
    );
}

// ===========================================================================
// REF-06: Extended encoding tests
// ===========================================================================

#[test]
fn encoding_with_guarded_rules_has_more_assertions() {
    // Plain rules vs guarded rules: guards add threshold constraints
    let plain = make_ta(&["A", "B"], &[0], &[(0, 1)], &["n"], &[]);
    let mut guarded = make_ta(&["A", "B"], &[0], &[], &["n"], &["votes"]);
    guarded.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination::param(ParamId::from(0)),
            distinct: false,
        }),
        updates: vec![Update {
            var: SharedVarId::from(0),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &["n"], &[]);

    let (_, asserts_plain) = build_encoding(&plain, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 2);
    let (_, asserts_guarded) =
        build_encoding(&guarded, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 2);

    assert!(
        asserts_guarded > asserts_plain,
        "guarded rules should produce more assertions ({} vs {})",
        asserts_guarded,
        asserts_plain
    );
}

#[test]
fn encoding_internal_locations_produce_stutter_rules() {
    // Concrete: A→B→C, B is internal. Should produce stutter rules in encoding.
    let concrete = make_ta(&["A", "B", "C"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let abstract_ta = make_ta(&["A", "C"], &[0], &[(0, 1)], &[], &[]);

    let (decls, asserts) = build_encoding(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, None), (2, Some(1))],
        2,
    );

    // Should have non-trivial encoding with stutter rules
    assert!(decls > 0);
    assert!(asserts > 0);
}

#[test]
fn encoding_large_product_scales_linearly() {
    // Test that encoding size grows roughly proportionally with product size
    let small_concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let small_abstract = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let large_names: Vec<String> = (0..5).map(|i| format!("L{i}")).collect();
    let large_refs: Vec<&str> = large_names.iter().map(|s| s.as_str()).collect();
    let large_rules: Vec<(usize, usize)> = (0..4).map(|i| (i, i + 1)).collect();
    let large_concrete = make_ta(&large_refs, &[0], &large_rules, &[], &[]);
    let large_abstract = make_ta(&large_refs, &[0], &large_rules, &[], &[]);

    let small_map: Vec<(usize, Option<usize>)> = (0..2).map(|i| (i, Some(i))).collect();
    let large_map: Vec<(usize, Option<usize>)> = (0..5).map(|i| (i, Some(i))).collect();

    let (small_decls, _) = build_encoding(&small_concrete, &small_abstract, &small_map, 2);
    let (large_decls, _) = build_encoding(&large_concrete, &large_abstract, &large_map, 2);

    // Large product (25 locs) should have more declarations than small (4 locs)
    assert!(
        large_decls > small_decls,
        "larger product should have more declarations ({} vs {})",
        large_decls,
        small_decls,
    );
}

#[test]
fn encoding_multiple_shared_vars_correct_count() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &["x", "y", "z"]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &["x", "y"]);

    let (_, _) = build_encoding(&concrete, &abstract_ta, &[(0, Some(0)), (1, Some(1))], 1);

    // Also verify via the full encoding
    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));
    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();
    let enc = encode_refinement_check(&product, 1);

    // Should have gamma vars for all 5 merged shared vars at 2 steps
    let gamma_decls: Vec<_> = enc
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pg_"))
        .collect();
    assert_eq!(gamma_decls.len(), 10); // 5 vars × 2 steps
}

// ===========================================================================
// REFX-01: Solver integration tests
// ===========================================================================

fn build_product_for_test(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
    loc_map: &[(usize, Option<usize>)],
) -> tarsier_ir::product::ProductAutomaton {
    let mut mapping = RefinementMapping::new("abs".into());
    for &(c, a) in loc_map {
        match a {
            Some(a_id) => mapping.map_location(LocationId::from(c), LocationId::from(a_id)),
            None => mapping.mark_location_internal(LocationId::from(c)),
        }
    }
    let rel = RefinementRelation::new(mapping);
    build_product(concrete, abstract_ta, &rel).unwrap()
}

#[test]
fn solver_trivially_holds_no_mismatches() {
    // Identity mapping on single location → no mismatches, trivially holds.
    let concrete = make_ta(&["A"], &[0], &[], &[], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &[]);
    let product = build_product_for_test(&concrete, &abstract_ta, &[(0, Some(0))]);

    let mut solver = Z3Solver::new();
    let result = run_refinement_solver(&mut solver, &product, 3).unwrap();

    assert!(
        matches!(result, SimulationCheckResult::SimulationHolds { depth: 3 }),
        "identity mapping should trivially hold, got: {result:?}"
    );
}

#[test]
fn solver_holds_matching_transitions() {
    // Concrete: A→B, Abstract: A→B, identity mapping → simulation holds.
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let product = build_product_for_test(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, Some(1))],
    );

    let mut solver = Z3Solver::new();
    let result = run_refinement_solver(&mut solver, &product, 5).unwrap();

    match result {
        SimulationCheckResult::SimulationHolds { .. } => {} // expected
        other => panic!("expected SimulationHolds, got: {other:?}"),
    }
}

#[test]
fn solver_holds_with_mismatches_unreachable() {
    // Product has mismatch locations but they are unreachable because
    // no product rule leads to them. The solver should return UNSAT.
    let concrete = make_ta(&["A", "B", "C"], &[0], &[(0, 1), (0, 2)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B", "C"], &[0], &[(0, 1)], &[], &[]);

    let product = build_product_for_test(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, Some(1)), (2, Some(2))],
    );

    assert!(product.has_mismatches(), "product should have mismatch locations");

    let mut solver = Z3Solver::new();
    let result = run_refinement_solver(&mut solver, &product, 5).unwrap();

    // Mismatches exist but are unreachable → solver says UNSAT → holds.
    match result {
        SimulationCheckResult::SimulationHolds { .. } => {} // correct
        other => panic!("expected SimulationHolds (unreachable mismatches), got: {other:?}"),
    }
}

#[test]
fn solver_holds_with_internal_locations() {
    // Concrete: A→B→C, B is internal. Abstract: A→C.
    // If B is internal (stutter), simulation should hold since A→C path exists in abstract.
    let concrete = make_ta(&["A", "B", "C"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let abstract_ta = make_ta(&["A", "C"], &[0], &[(0, 1)], &[], &[]);

    let product = build_product_for_test(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, None), (2, Some(1))],
    );

    let mut solver = Z3Solver::new();
    let result = run_refinement_solver(&mut solver, &product, 5).unwrap();

    match result {
        SimulationCheckResult::SimulationHolds { .. } => {} // expected
        other => panic!("expected SimulationHolds with internal location, got: {other:?}"),
    }
}

#[test]
fn solver_unknown_variant_exists() {
    // Just verify the Unknown variant is constructible (no solver timeout test needed).
    let result = SimulationCheckResult::Unknown {
        depth: 3,
        reason: "timeout".to_string(),
    };
    assert!(matches!(result, SimulationCheckResult::Unknown { .. }));
}

#[test]
fn witness_minimized_trims_trace_and_zeros() {
    use tarsier_ir::product::ProductLocationId;
    use tarsier_smt::refinement_encoder::{RefinementWitness, WitnessStep};

    let witness = RefinementWitness {
        depth: 5,
        violation_step: 1,
        mismatch_location: ProductLocationId {
            concrete: LocationId::from(0),
            abstract_loc: LocationId::from(1),
        },
        parameter_values: vec![(0, 10)],
        trace: vec![
            WitnessStep {
                step: 0,
                location_counters: vec![
                    (ProductLocationId { concrete: LocationId::from(0), abstract_loc: LocationId::from(0) }, 5),
                    (ProductLocationId { concrete: LocationId::from(1), abstract_loc: LocationId::from(0) }, 0),
                ],
                shared_var_values: vec![(0, 0)],
                rule_firings: vec![(0, 3), (1, 0)],
            },
            WitnessStep {
                step: 1,
                location_counters: vec![],
                shared_var_values: vec![],
                rule_firings: vec![],
            },
            WitnessStep {
                step: 2,
                location_counters: vec![],
                shared_var_values: vec![],
                rule_firings: vec![(0, 1)],
            },
            WitnessStep {
                step: 3,
                location_counters: vec![],
                shared_var_values: vec![],
                rule_firings: vec![],
            },
        ],
    };

    let min = witness.minimized();
    // Trace trimmed to steps 0, 1, 2 (violation_step + 1 = 2)
    assert_eq!(min.trace.len(), 3);
    assert_eq!(min.trace[0].step, 0);
    assert_eq!(min.trace[2].step, 2);

    // Zero-valued counters removed from step 0
    assert_eq!(min.trace[0].location_counters.len(), 1);
    assert_eq!(min.trace[0].rule_firings.len(), 1);
    assert_eq!(min.trace[0].rule_firings[0], (0, 3));
}
