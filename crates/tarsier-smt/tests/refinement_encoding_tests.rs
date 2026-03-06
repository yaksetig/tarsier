//! Extended integration tests for refinement SMT encoding (REF-06).

use tarsier_ir::product::build_product;
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
use tarsier_ir::threshold_automaton::*;
use tarsier_smt::refinement_encoder::encode_refinement_check;

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
        });
    }
    for name in params {
        ta.add_parameter(Parameter {
            name: name.to_string(),
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

    let (decls_d1, asserts_d1) = build_encoding(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, Some(1))],
        1,
    );
    let (decls_d3, asserts_d3) = build_encoding(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, Some(1))],
        3,
    );

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

    let (decls, asserts) = build_encoding(
        &concrete,
        &abstract_ta,
        &[(0, Some(0)), (1, Some(1))],
        0,
    );

    assert!(decls > 0, "depth 0 should still declare initial state vars");
    assert!(asserts > 0, "depth 0 should still have initial state constraints");
}
