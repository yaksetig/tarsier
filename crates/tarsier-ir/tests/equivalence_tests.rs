//! Integration tests for behavioral equivalence (EQ-04).

use tarsier_ir::equivalence::build_equivalence_products;
use tarsier_ir::threshold_automaton::*;

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

#[test]
fn identical_single_location_trivially_equivalent() {
    let a = make_ta(&["S"], &[0], &[], &[], &[]);
    let b = make_ta(&["S"], &[0], &[], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    assert!(p.is_trivially_equivalent());
}

#[test]
fn identical_two_locations_has_off_diagonal_mismatches() {
    let a = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let b = make_ta(&["A", "B"], &[0], &[(0, 1)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // 2×2 = 4 product locs, 2 off-diagonal per direction.
    assert_eq!(p.forward.mismatch_locations.len(), 2);
    assert_eq!(p.backward.mismatch_locations.len(), 2);
}

#[test]
fn extra_location_in_a_becomes_internal() {
    let a = make_ta(&["Init", "Extra", "Done"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // Forward: 3×2=6 product locs. "Extra" is internal in A.
    assert_eq!(p.forward.num_locations(), 6);
    // Backward: 2×3=6 product locs. "Extra" not in B so B has no mapping to it.
    assert_eq!(p.backward.num_locations(), 6);
}

#[test]
fn no_name_overlap_all_internal() {
    let a = make_ta(&["X", "Y"], &[0], &[(0, 1)], &[], &[]);
    let b = make_ta(&["P", "Q"], &[0], &[(0, 1)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // All locations are internal → no mismatches.
    assert!(p.is_trivially_equivalent());
}

#[test]
fn parameters_merged_in_both_directions() {
    let a = make_ta(&["S"], &[0], &[], &["n", "t"], &[]);
    let b = make_ta(&["S"], &[0], &[], &["n", "f"], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // Forward: conc_n, conc_t, abs_n, abs_f = 4
    assert_eq!(p.forward.parameters.len(), 4);
    // Backward: conc_n, conc_f, abs_n, abs_t = 4
    assert_eq!(p.backward.parameters.len(), 4);
}

#[test]
fn shared_vars_merged_in_both_directions() {
    let a = make_ta(&["S"], &[0], &[], &[], &["votes", "commits"]);
    let b = make_ta(&["S"], &[0], &[], &[], &["votes"]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // Forward: conc_votes, conc_commits, abs_votes = 3
    assert_eq!(p.forward.shared_vars.len(), 3);
    // Backward: conc_votes, abs_votes, abs_commits = 3
    assert_eq!(p.backward.shared_vars.len(), 3);
}

#[test]
fn symmetric_products_have_same_location_counts() {
    let a = make_ta(&["Init", "Mid", "Done"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let b = make_ta(&["Init", "Mid", "Done"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    assert_eq!(p.forward.num_locations(), p.backward.num_locations());
    assert_eq!(p.forward.mismatch_locations.len(), p.backward.mismatch_locations.len());
}

#[test]
fn diamond_topology_equivalence() {
    // Diamond: Init → {Left, Right} → Done
    let a = make_ta(
        &["Init", "Left", "Right", "Done"],
        &[0],
        &[(0, 1), (0, 2), (1, 3), (2, 3)],
        &[],
        &[],
    );
    let b = make_ta(
        &["Init", "Left", "Right", "Done"],
        &[0],
        &[(0, 1), (0, 2), (1, 3), (2, 3)],
        &[],
        &[],
    );
    let p = build_equivalence_products(&a, &b).unwrap();
    // 4×4 = 16 product locs per direction.
    assert_eq!(p.forward.num_locations(), 16);
    // 12 off-diagonal mismatches per direction (4*4 - 4 diagonal).
    assert_eq!(p.forward.mismatch_locations.len(), 12);
    assert_eq!(p.backward.mismatch_locations.len(), 12);
}

#[test]
fn linear_chain_different_lengths() {
    // A: 4 locations, B: 3 locations. "C" is only in A.
    let a = make_ta(&["A", "B", "C", "D"], &[0], &[(0, 1), (1, 2), (2, 3)], &[], &[]);
    let b = make_ta(&["A", "B", "D"], &[0], &[(0, 1), (1, 2)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // Forward: 4×3 = 12 product locs.
    assert_eq!(p.forward.num_locations(), 12);
    // Backward: 3×4 = 12 product locs.
    assert_eq!(p.backward.num_locations(), 12);
}

#[test]
fn initial_locations_paired_correctly() {
    let a = make_ta(&["Init", "Done"], &[0], &[(0, 1)], &[], &[]);
    let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    // Forward initial: (Init_a=0, Init_b=0)
    assert_eq!(p.forward.initial_locations.len(), 1);
    assert_eq!(p.forward.initial_locations[0].concrete, LocationId::from(0));
    assert_eq!(p.forward.initial_locations[0].abstract_loc, LocationId::from(0));
}

#[test]
fn total_mismatches_sums_both_directions() {
    let a = make_ta(&["X", "Y"], &[0], &[(0, 1)], &[], &[]);
    let b = make_ta(&["X", "Y"], &[0], &[(0, 1)], &[], &[]);
    let p = build_equivalence_products(&a, &b).unwrap();
    assert_eq!(
        p.total_mismatches(),
        p.forward.mismatch_locations.len() + p.backward.mismatch_locations.len()
    );
}
