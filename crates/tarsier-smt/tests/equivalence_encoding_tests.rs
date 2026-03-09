//! Integration tests for equivalence SMT encoding (EQ-04).

use tarsier_ir::equivalence::build_equivalence_products;
use tarsier_ir::threshold_automaton::*;
use tarsier_smt::equivalence_encoder::encode_equivalence_check;

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

#[test]
fn trivial_equivalence_both_assert_false() {
    let a = make_ta(&["S"], &[0], &[], &[], &[]);
    let b = make_ta(&["S"], &[0], &[], &[], &[]);
    let products = build_equivalence_products(&a, &b).unwrap();
    let enc = encode_equivalence_check(&products, 3);

    let fwd_false = enc
        .forward
        .assertions
        .iter()
        .any(|t| matches!(t, tarsier_smt::terms::SmtTerm::BoolLit(false)));
    let bwd_false = enc
        .backward
        .assertions
        .iter()
        .any(|t| matches!(t, tarsier_smt::terms::SmtTerm::BoolLit(false)));
    assert!(fwd_false && bwd_false);
}

#[test]
fn encoding_size_scales_with_depth() {
    let a = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let b = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let products = build_equivalence_products(&a, &b).unwrap();

    let enc1 = encode_equivalence_check(&products, 1);
    let enc3 = encode_equivalence_check(&products, 3);

    assert!(enc3.forward.declarations.len() > enc1.forward.declarations.len());
    assert!(enc3.backward.declarations.len() > enc1.backward.declarations.len());
    assert!(enc3.forward.assertions.len() > enc1.forward.assertions.len());
}

#[test]
fn parameters_declared_in_both_directions() {
    let a = make_ta(&["S"], &[0], &[], &["n", "t"], &[]);
    let b = make_ta(&["S"], &[0], &[], &["n"], &[]);
    let products = build_equivalence_products(&a, &b).unwrap();
    let enc = encode_equivalence_check(&products, 1);

    // Forward: 4 params (conc_n, conc_t, abs_n) but products merge them.
    let fwd_params: Vec<_> = enc
        .forward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pp_"))
        .collect();
    assert_eq!(fwd_params.len(), 3); // conc_n, conc_t, abs_n

    let bwd_params: Vec<_> = enc
        .backward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pp_"))
        .collect();
    assert_eq!(bwd_params.len(), 3); // conc_n, abs_n, abs_t
}

#[test]
fn shared_vars_declared_in_both_directions() {
    let a = make_ta(&["S"], &[0], &[], &[], &["x"]);
    let b = make_ta(&["S"], &[0], &[], &[], &["y"]);
    let products = build_equivalence_products(&a, &b).unwrap();
    let enc = encode_equivalence_check(&products, 1);

    // Forward: pg_0_0 (conc_x), pg_0_1 (abs_y), pg_1_0, pg_1_1
    let fwd_gamma: Vec<_> = enc
        .forward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pg_"))
        .collect();
    assert_eq!(fwd_gamma.len(), 4); // 2 vars × 2 steps

    let bwd_gamma: Vec<_> = enc
        .backward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pg_"))
        .collect();
    assert_eq!(bwd_gamma.len(), 4);
}

#[test]
fn asymmetric_automata_different_mismatch_counts() {
    // A has extra location, so forward has different product shape than backward.
    let a = make_ta(&["Init", "Extra", "Done"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)], &[], &[]);
    let products = build_equivalence_products(&a, &b).unwrap();
    let enc = encode_equivalence_check(&products, 2);

    // Forward product: 3×2 = 6 locs.
    let fwd_locs_step0: Vec<_> = enc
        .forward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pk_0_"))
        .collect();
    assert_eq!(fwd_locs_step0.len(), 6);

    // Backward product: 2×3 = 6 locs.
    let bwd_locs_step0: Vec<_> = enc
        .backward
        .declarations
        .iter()
        .filter(|(name, _)| name.starts_with("pk_0_"))
        .collect();
    assert_eq!(bwd_locs_step0.len(), 6);
}
