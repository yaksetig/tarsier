//! Extended integration tests for the refinement checking pipeline (REF-06).
//!
//! Tests cover:
//! - RefinementMapping edge cases
//! - Product automaton construction with various topologies
//! - Mismatch detection and synchronization correctness
//! - Auto-mapping behavior
//! - Error propagation

use tarsier_ir::product::{build_product, ProductError};
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation, SimulationKind};
use tarsier_ir::threshold_automaton::*;

/// Build a minimal TA with named locations and optional shared vars.
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

// ======================== RefinementMapping tests ========================

#[test]
fn mapping_overwrite_location() {
    let mut m = RefinementMapping::new("test".into());
    let c = LocationId::from(0);
    m.map_location(c, LocationId::from(1));
    m.map_location(c, LocationId::from(2));
    assert_eq!(m.abstract_location(c), Some(Some(LocationId::from(2))));
}

#[test]
fn mapping_overwrite_variable() {
    let mut m = RefinementMapping::new("test".into());
    let c = SharedVarId::from(0);
    m.map_variable(c, SharedVarId::from(1));
    m.map_variable(c, SharedVarId::from(3));
    assert_eq!(m.abstract_variable(c), Some(Some(SharedVarId::from(3))));
}

#[test]
fn mapping_internal_then_mapped() {
    let mut m = RefinementMapping::new("test".into());
    let c = LocationId::from(0);
    m.mark_location_internal(c);
    assert_eq!(m.abstract_location(c), Some(None));
    m.map_location(c, LocationId::from(5));
    assert_eq!(m.abstract_location(c), Some(Some(LocationId::from(5))));
}

#[test]
fn mapping_empty_maps_return_none() {
    let m = RefinementMapping::new("test".into());
    assert_eq!(m.abstract_location(LocationId::from(0)), None);
    assert_eq!(m.abstract_variable(SharedVarId::from(0)), None);
}

// ======================== SimulationKind tests ========================

#[test]
fn simulation_kind_default_is_forward() {
    assert_eq!(SimulationKind::default(), SimulationKind::Forward);
}

#[test]
fn refinement_relation_with_backward() {
    let m = RefinementMapping::new("test".into());
    let r = RefinementRelation::with_simulation_kind(m, SimulationKind::Backward);
    assert_eq!(r.simulation_kind, SimulationKind::Backward);
}

// ======================== Product automaton tests ========================

#[test]
fn product_single_location_identity() {
    let concrete = make_ta(&["Init"], &[0], &[], &[], &[]);
    let abstract_ta = make_ta(&["Init"], &[0], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 1); // 1×1
    assert_eq!(product.initial_locations.len(), 1);
    assert!(!product.has_mismatches());
    assert_eq!(product.num_rules(), 0);
}

#[test]
fn product_two_by_two_identity_mapping() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 4); // 2×2
    // Off-diagonal are mismatches: (0,1) and (1,0)
    assert_eq!(product.mismatch_locations.len(), 2);
    assert!(product.has_mismatches());
}

#[test]
fn product_three_concrete_two_abstract_with_merge() {
    // Concrete has 3 locations, abstract has 2.
    // Two concrete locations map to the same abstract location.
    let concrete = make_ta(&["Init", "Mid", "Done"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let abstract_ta = make_ta(&["Init", "Done"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0)); // Init→Init
    mapping.map_location(LocationId::from(1), LocationId::from(0)); // Mid→Init (merge)
    mapping.map_location(LocationId::from(2), LocationId::from(1)); // Done→Done

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 6); // 3×2
    // Initial: (Init, Init) only
    assert_eq!(product.initial_locations.len(), 1);
}

#[test]
fn product_all_internal_concrete_locations() {
    // All concrete locations are internal (no abstract counterpart).
    let concrete = make_ta(&["X", "Y"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.mark_location_internal(LocationId::from(0));
    mapping.mark_location_internal(LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 2); // 2×1
    // Internal locations have no expected abstract, so no mismatches.
    assert!(!product.has_mismatches());
}

#[test]
fn product_unmapped_concrete_location_error() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    // LocationId(1) is unmapped.

    let rel = RefinementRelation::new(mapping);
    let result = build_product(&concrete, &abstract_ta, &rel);

    assert!(result.is_err());
    match result.unwrap_err() {
        ProductError::UnmappedConcreteLocation(id) => assert_eq!(id, LocationId::from(1)),
        other => panic!("expected UnmappedConcreteLocation, got: {other:?}"),
    }
}

#[test]
fn product_shared_var_merging_preserves_order() {
    let concrete = make_ta(&["A"], &[0], &[], &[], &["x", "y"]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &[], &["p", "q", "r"]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    // 2 concrete + 3 abstract = 5 shared vars
    assert_eq!(product.shared_vars.len(), 5);
    assert_eq!(product.shared_vars[0].name, "conc_x");
    assert_eq!(product.shared_vars[1].name, "conc_y");
    assert_eq!(product.shared_vars[2].name, "abs_p");
    assert_eq!(product.shared_vars[3].name, "abs_q");
    assert_eq!(product.shared_vars[4].name, "abs_r");
}

#[test]
fn product_parameter_merging_preserves_order() {
    let concrete = make_ta(&["A"], &[0], &[], &["n", "t", "f"], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[], &["n", "t"], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.parameters.len(), 5); // 3 + 2
    assert_eq!(product.parameters[0].name, "conc_n");
    assert_eq!(product.parameters[1].name, "conc_t");
    assert_eq!(product.parameters[2].name, "conc_f");
    assert_eq!(product.parameters[3].name, "abs_n");
    assert_eq!(product.parameters[4].name, "abs_t");
}

#[test]
fn product_synchronized_rule_requires_matching_abstract_rule() {
    // Concrete: A→B, Abstract: A→B — should produce synchronized rule.
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    let synced: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_some())
        .collect();
    assert!(!synced.is_empty(), "should have at least one synchronized rule");
}

#[test]
fn product_no_abstract_rule_means_no_synchronized_rule() {
    // Concrete: A→B, Abstract has no rules — no synchronized rules, only stutter.
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[], &[], &[]); // no abstract rules

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    let synced: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_some())
        .collect();
    assert!(synced.is_empty(), "no abstract rules means no synchronized rules");
}

#[test]
fn product_self_loop_generates_stutter() {
    // Concrete: A→A (self-loop), Abstract: A→A
    // Mapping: 0→0. Should generate both synchronized and stutter rules.
    let concrete = make_ta(&["A"], &[0], &[(0, 0)], &[], &[]);
    let abstract_ta = make_ta(&["A"], &[0], &[(0, 0)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    let stutter: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_none())
        .collect();
    assert!(!stutter.is_empty(), "self-loop should generate stutter rule");
}

#[test]
fn product_multiple_initial_locations() {
    // Both concrete and abstract have 2 initial locations.
    let concrete = make_ta(&["A", "B"], &[0, 1], &[], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0, 1], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    // Initial: (0,0) and (1,1)
    assert_eq!(product.initial_locations.len(), 2);
}

#[test]
fn product_location_index_lookup() {
    let concrete = make_ta(&["A", "B"], &[0], &[], &[], &[]);
    let abstract_ta = make_ta(&["X", "Y"], &[0], &[], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    // All 4 product locations should be findable.
    for loc in &product.locations {
        assert!(product.location_idx(loc).is_some());
    }
}

#[test]
fn product_with_guarded_rules() {
    // Concrete rule with a threshold guard.
    let mut concrete = make_ta(&["A", "B"], &[0], &[], &["n"], &["votes"]);
    concrete.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 0,
                terms: vec![(1, ParamId::from(0))],
            },
            distinct: false,
        }),
        updates: vec![],
        collection_updates: vec![],
        param_updates: vec![],
    });

    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &["n"], &["votes"]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    // Synchronized rule should exist and have guard atoms.
    let synced: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_some())
        .collect();
    assert!(!synced.is_empty());
    // Combined guard should have at least the concrete guard atom.
    assert!(!synced[0].guard.atoms.is_empty());
}

#[test]
fn product_with_updates() {
    // Concrete rule with an Increment update.
    let mut concrete = make_ta(&["A", "B"], &[0], &[], &[], &["counter"]);
    concrete.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::trivial(),
        updates: vec![Update {
            var: SharedVarId::from(0),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        param_updates: vec![],
    });

    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &["counter"]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    let synced: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_some())
        .collect();
    assert!(!synced.is_empty());
    // Concrete updates should be remapped.
    assert_eq!(synced[0].concrete_updates.len(), 1);
}

// ======================== Benchmark-style topology tests ========================

#[test]
fn product_linear_chain_concrete_refines_shorter_abstract() {
    // Concrete: A→B→C→D, Abstract: A→D
    // Mapping: A→A, B→internal, C→internal, D→D
    let concrete = make_ta(
        &["A", "B", "C", "D"],
        &[0],
        &[(0, 1), (1, 2), (2, 3)],
        &[],
        &[],
    );
    let abstract_ta = make_ta(&["A", "D"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.mark_location_internal(LocationId::from(1));
    mapping.mark_location_internal(LocationId::from(2));
    mapping.map_location(LocationId::from(3), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 8); // 4×2
    // Internal locations have no expected abstract, so mismatches only from mapped.
    // Mapped: (A,D)=mismatch, (D,A)=mismatch → 2 mismatches from mapped locs.
    assert!(product.has_mismatches());
}

#[test]
fn product_diamond_topology() {
    // Concrete diamond: Start→Left, Start→Right, Left→End, Right→End
    // Abstract: Start→End
    let concrete = make_ta(
        &["Start", "Left", "Right", "End"],
        &[0],
        &[(0, 1), (0, 2), (1, 3), (2, 3)],
        &[],
        &[],
    );
    let abstract_ta = make_ta(&["Start", "End"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.mark_location_internal(LocationId::from(1)); // Left internal
    mapping.mark_location_internal(LocationId::from(2)); // Right internal
    mapping.map_location(LocationId::from(3), LocationId::from(1));

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 8); // 4×2
    // Should have stutter rules for internal transitions.
    let stutter: Vec<_> = product
        .rules
        .iter()
        .filter(|r| r.abstract_rule.is_none())
        .collect();
    assert!(stutter.len() >= 2, "diamond should have stutter rules for internal paths");
}

#[test]
fn product_error_display() {
    let err = ProductError::UnmappedConcreteLocation(LocationId::from(42));
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("no refinement mapping"));
}

// ===========================================================================
// REF-06: Extended tests and benchmark suite
// ===========================================================================

// ── Self-refinement: identity mapping should have no mismatches ──

#[test]
fn self_refinement_identity_no_mismatches() {
    let ta = make_ta(
        &["Init", "Voted", "Done"],
        &[0],
        &[(0, 1), (1, 2)],
        &["n", "t"],
        &["votes"],
    );
    let mut mapping = RefinementMapping::new("self".into());
    for i in 0..3 {
        mapping.map_location(LocationId::from(i), LocationId::from(i));
    }
    mapping.map_variable(SharedVarId::from(0), SharedVarId::from(0));
    let rel = RefinementRelation::new(mapping);
    let product = build_product(&ta, &ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 9); // 3×3
    // Off-diagonal product locations are mismatches (e.g., (Init,Done)).
    // For N=3, diagonal has 3 locations, off-diagonal has 6 mismatches.
    // This is expected: the simulation check verifies these are unreachable.
    assert_eq!(
        product.mismatch_locations.len(),
        6,
        "3×3 identity mapping should have 6 off-diagonal mismatches"
    );
}

// ── Star topology: one hub with many branches ──

#[test]
fn product_star_topology_with_shared_vars() {
    // Concrete star: Hub→A, Hub→B, Hub→C
    let concrete = make_ta(
        &["Hub", "A", "B", "C"],
        &[0],
        &[(0, 1), (0, 2), (0, 3)],
        &["n"],
        &["msg_a", "msg_b"],
    );
    // Abstract: Hub→Done (collapses A/B/C into Done)
    let abstract_ta = make_ta(&["Hub", "Done"], &[0], &[(0, 1)], &["n"], &["msg_a"]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0)); // Hub→Hub
    mapping.map_location(LocationId::from(1), LocationId::from(1)); // A→Done
    mapping.map_location(LocationId::from(2), LocationId::from(1)); // B→Done
    mapping.map_location(LocationId::from(3), LocationId::from(1)); // C→Done
    mapping.map_variable(SharedVarId::from(0), SharedVarId::from(0)); // msg_a→msg_a
    mapping.mark_variable_internal(SharedVarId::from(1)); // msg_b is internal

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 8); // 4×2
    // Check that parameters were merged correctly
    assert_eq!(product.parameters.len(), 2); // conc_n + abs_n
}

// ── Scaling: large concrete, small abstract ──

#[test]
fn product_scaling_10_concrete_2_abstract() {
    let loc_names: Vec<String> = (0..10).map(|i| format!("L{i}")).collect();
    let loc_refs: Vec<&str> = loc_names.iter().map(|s| s.as_str()).collect();
    let rules: Vec<(usize, usize)> = (0..9).map(|i| (i, i + 1)).collect();
    let concrete = make_ta(&loc_refs, &[0], &rules, &["n"], &[]);
    let abstract_ta = make_ta(&["Start", "End"], &[0], &[(0, 1)], &["n"], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0)); // L0→Start
    for i in 1..9 {
        mapping.mark_location_internal(LocationId::from(i));
    }
    mapping.map_location(LocationId::from(9), LocationId::from(1)); // L9→End

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 20); // 10×2
    assert!(product.has_mismatches());
    // Stutter rules for the 8 internal locations
    let stutter_count = product.rules.iter().filter(|r| r.abstract_rule.is_none()).count();
    assert!(stutter_count >= 8, "should have stutter rules for internal transitions");
}

// ── Multiple initial locations in both automata ──

#[test]
fn product_multiple_initials_both_automata() {
    let concrete = make_ta(&["A", "B", "C"], &[0, 1], &[(0, 2), (1, 2)], &[], &[]);
    let abstract_ta = make_ta(&["X", "Y"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0)); // A→X
    mapping.map_location(LocationId::from(1), LocationId::from(0)); // B→X
    mapping.map_location(LocationId::from(2), LocationId::from(1)); // C→Y

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();

    assert_eq!(product.num_locations(), 6); // 3×2
    // Initial locations should be product states where concrete is initial
    // and abstract matches the mapping
    assert!(!product.initial_locations.is_empty());
}

// ── Backward simulation ──

#[test]
fn backward_simulation_kind_preserved() {
    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);

    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));

    let mut rel = RefinementRelation::new(mapping);
    rel.simulation_kind = SimulationKind::Backward;

    let product = build_product(&concrete, &abstract_ta, &rel).unwrap();
    assert_eq!(product.num_locations(), 4); // 2×2
}

// ── DSL-based E2E refinement tests ──

#[test]
fn dsl_refinement_self_check_product_construction() {
    // A protocol should refine itself
    let src = r#"
protocol Simple {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role R {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= n - t Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let prog = tarsier_dsl::parse(src, "simple.trs").unwrap();
    let ta = tarsier_ir::lowering::lower(&prog).unwrap();

    // Self-mapping: map every location to itself
    let mut mapping = RefinementMapping::new("self.trs".into());
    for (i, _) in ta.locations.iter().enumerate() {
        mapping.map_location(LocationId::from(i), LocationId::from(i));
    }
    for (i, _) in ta.shared_vars.iter().enumerate() {
        mapping.map_variable(SharedVarId::from(i), SharedVarId::from(i));
    }

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&ta, &ta, &rel).unwrap();

    let n = ta.locations.len();
    assert_eq!(product.num_locations(), n * n);
    // Every diagonal location is a match, so no mismatches on diagonal
}

#[test]
fn dsl_refinement_concrete_extends_abstract() {
    // Concrete has an extra phase that the abstract doesn't
    let concrete_src = r#"
protocol Concrete {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role R {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Vote => {
                goto phase validating;
            }
        }
        phase validating {
            when received >= n - t Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let abstract_src = r#"
protocol Abstract {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role R {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= n - t Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let concrete_prog = tarsier_dsl::parse(concrete_src, "concrete.trs").unwrap();
    let abstract_prog = tarsier_dsl::parse(abstract_src, "abstract.trs").unwrap();
    let concrete_ta = tarsier_ir::lowering::lower(&concrete_prog).unwrap();
    let abstract_ta = tarsier_ir::lowering::lower(&abstract_prog).unwrap();

    // Auto-mapping by name: "waiting" and "done" match, "validating" is internal
    let mut mapping = RefinementMapping::new("abstract.trs".into());
    for (c_idx, c_loc) in concrete_ta.locations.iter().enumerate() {
        let c_id = LocationId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_location_by_name(&c_loc.name) {
            mapping.map_location(c_id, a_id);
        } else {
            mapping.mark_location_internal(c_id);
        }
    }
    for (c_idx, c_var) in concrete_ta.shared_vars.iter().enumerate() {
        let c_id = SharedVarId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_shared_var_by_name(&c_var.name) {
            mapping.map_variable(c_id, a_id);
        }
    }

    let rel = RefinementRelation::new(mapping);
    let product = build_product(&concrete_ta, &abstract_ta, &rel).unwrap();

    // Product should be non-trivial
    assert!(product.num_locations() > 0);
    assert!(product.num_rules() > 0);

    // Should have some internal (stutter) rules for validating transitions
    let stutter_count = product.rules.iter().filter(|r| r.abstract_rule.is_none()).count();
    assert!(stutter_count > 0, "extra validating phase should produce stutter rules");
}
