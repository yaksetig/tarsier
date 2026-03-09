//! Cross-feature solver parity + performance smoke tests (X-04).
//!
//! Covers:
//! - Refinement encoding SAT/UNSAT behavior.
//! - Equivalence encoding divergence/trivial behavior.
//! - Parity between Z3 and cvc5 (ignored by default).
//! - Lightweight encoding+solve wall-clock regression budgets.

use std::time::Instant;

use tarsier_ir::equivalence::build_equivalence_products;
use tarsier_ir::product::build_product;
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
use tarsier_ir::threshold_automaton::*;
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::equivalence_encoder::encode_equivalence_check;
use tarsier_smt::refinement_encoder::encode_refinement_check;
use tarsier_smt::solver::{SatResult, SmtSolver};

fn make_ta(loc_names: &[&str], initial: &[usize], rules: &[(usize, usize)]) -> ThresholdAutomaton {
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
    ta
}

fn solve_assertions_with_z3(
    declarations: &[(String, tarsier_smt::sorts::SmtSort)],
    assertions: &[tarsier_smt::terms::SmtTerm],
) -> SatResult {
    let mut solver = Z3Solver::with_default_config();
    for (name, sort) in declarations {
        solver.declare_var(name, sort).expect("declare in z3");
    }
    for assertion in assertions {
        solver.assert(assertion).expect("assert in z3");
    }
    solver.check_sat().expect("z3 check_sat")
}

#[test]
fn refinement_encoding_stable_outcomes_with_z3() {
    // UNSAT case: no mismatch locations.
    let c_unsat = make_ta(&["S"], &[0], &[]);
    let a_unsat = make_ta(&["S"], &[0], &[]);
    let mut m_unsat = RefinementMapping::new("abs".into());
    m_unsat.map_location(LocationId::from(0), LocationId::from(0));
    let p_unsat = build_product(&c_unsat, &a_unsat, &RefinementRelation::new(m_unsat))
        .expect("build product unsat");
    let e_unsat = encode_refinement_check(&p_unsat, 2);
    let r_unsat = solve_assertions_with_z3(&e_unsat.declarations, &e_unsat.assertions);
    assert_eq!(r_unsat, SatResult::Unsat);

    // Mismatch-bearing case: solver should return a stable SAT/UNSAT verdict.
    let c_mismatch = make_ta(&["A", "B"], &[0], &[(0, 1)]);
    let a_mismatch = make_ta(&["A", "B"], &[0], &[]);
    let mut m_mismatch = RefinementMapping::new("abs".into());
    m_mismatch.map_location(LocationId::from(0), LocationId::from(0));
    m_mismatch.map_location(LocationId::from(1), LocationId::from(1));
    let p_mismatch = build_product(
        &c_mismatch,
        &a_mismatch,
        &RefinementRelation::new(m_mismatch),
    )
    .expect("build product mismatch");
    assert!(
        p_mismatch.has_mismatches(),
        "fixture should exercise mismatch-bearing refinement encoding"
    );
    let e_mismatch = encode_refinement_check(&p_mismatch, 2);
    let r_mismatch = solve_assertions_with_z3(&e_mismatch.declarations, &e_mismatch.assertions);
    assert!(
        !matches!(r_mismatch, SatResult::Unknown(_)),
        "mismatch fixture should produce a concrete SAT/UNSAT verdict"
    );
}

#[test]
fn equivalence_encoding_distinguishes_trivial_and_divergent_with_z3() {
    // Trivial equivalence: both directions UNSAT.
    let eq_a = make_ta(&["S"], &[0], &[]);
    let eq_b = make_ta(&["S"], &[0], &[]);
    let eq_products = build_equivalence_products(&eq_a, &eq_b).expect("build products equal");
    let eq_enc = encode_equivalence_check(&eq_products, 2);
    let eq_fwd = solve_assertions_with_z3(&eq_enc.forward.declarations, &eq_enc.forward.assertions);
    let eq_bwd =
        solve_assertions_with_z3(&eq_enc.backward.declarations, &eq_enc.backward.assertions);
    assert_eq!(eq_fwd, SatResult::Unsat);
    assert_eq!(eq_bwd, SatResult::Unsat);

    // Divergence-shaped fixture: at least one direction should have mismatches.
    let div_a = make_ta(&["A", "B"], &[0], &[(0, 1)]);
    let div_b = make_ta(&["A", "B"], &[0], &[]);
    let div_products =
        build_equivalence_products(&div_a, &div_b).expect("build products divergent");
    assert!(
        !div_products.is_trivially_equivalent(),
        "fixture should have mismatch-bearing products"
    );
    let div_enc = encode_equivalence_check(&div_products, 2);
    let div_fwd =
        solve_assertions_with_z3(&div_enc.forward.declarations, &div_enc.forward.assertions);
    let div_bwd =
        solve_assertions_with_z3(&div_enc.backward.declarations, &div_enc.backward.assertions);
    assert!(
        !matches!(div_fwd, SatResult::Unknown(_)) && !matches!(div_bwd, SatResult::Unknown(_)),
        "divergence fixture should produce concrete SAT/UNSAT verdicts (forward={div_fwd:?}, backward={div_bwd:?})"
    );
}

#[test]
fn refinement_equivalence_encoding_perf_smoke_under_10s() {
    let start = Instant::now();

    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[]);
    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));
    let product = build_product(&concrete, &abstract_ta, &RefinementRelation::new(mapping))
        .expect("build product for perf");
    let refinement_enc = encode_refinement_check(&product, 8);
    let refinement_result =
        solve_assertions_with_z3(&refinement_enc.declarations, &refinement_enc.assertions);
    assert!(
        !matches!(refinement_result, SatResult::Unknown(_)),
        "refinement perf fixture should produce concrete SAT/UNSAT verdict"
    );

    let products = build_equivalence_products(&concrete, &abstract_ta).expect("build eq products");
    let eq_enc = encode_equivalence_check(&products, 8);
    let eq_fwd = solve_assertions_with_z3(&eq_enc.forward.declarations, &eq_enc.forward.assertions);
    let eq_bwd =
        solve_assertions_with_z3(&eq_enc.backward.declarations, &eq_enc.backward.assertions);
    assert!(
        !matches!(eq_fwd, SatResult::Unknown(_)) && !matches!(eq_bwd, SatResult::Unknown(_)),
        "equivalence perf fixture should produce concrete SAT/UNSAT verdicts"
    );

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "refinement/equivalence perf smoke took {:.2}s (limit 10s)",
        elapsed.as_secs_f64()
    );
}

#[test]
#[ignore = "requires cvc5 binary"]
fn cvc5_parity_refinement_and_equivalence_matches_z3() {
    use tarsier_smt::backends::cvc5_backend::Cvc5Solver;

    if Cvc5Solver::new().is_err() {
        return;
    }

    let concrete = make_ta(&["A", "B"], &[0], &[(0, 1)]);
    let abstract_ta = make_ta(&["A", "B"], &[0], &[]);
    let mut mapping = RefinementMapping::new("abs".into());
    mapping.map_location(LocationId::from(0), LocationId::from(0));
    mapping.map_location(LocationId::from(1), LocationId::from(1));
    let product = build_product(&concrete, &abstract_ta, &RefinementRelation::new(mapping))
        .expect("build product parity");
    let refinement_enc = encode_refinement_check(&product, 2);

    let z3_ref = solve_assertions_with_z3(&refinement_enc.declarations, &refinement_enc.assertions);
    let cvc5_ref = {
        let mut solver = Cvc5Solver::new().expect("cvc5 should initialize");
        for (name, sort) in &refinement_enc.declarations {
            solver.declare_var(name, sort).expect("declare in cvc5");
        }
        for assertion in &refinement_enc.assertions {
            solver.assert(assertion).expect("assert in cvc5");
        }
        solver.check_sat().expect("cvc5 check_sat")
    };
    assert_eq!(z3_ref, cvc5_ref, "refinement encoding parity mismatch");

    let products = build_equivalence_products(&concrete, &abstract_ta).expect("build eq products");
    let eq_enc = encode_equivalence_check(&products, 2);
    let z3_fwd = solve_assertions_with_z3(&eq_enc.forward.declarations, &eq_enc.forward.assertions);
    let z3_bwd =
        solve_assertions_with_z3(&eq_enc.backward.declarations, &eq_enc.backward.assertions);
    let cvc5_fwd = {
        let mut solver = Cvc5Solver::new().expect("cvc5 should initialize");
        for (name, sort) in &eq_enc.forward.declarations {
            solver.declare_var(name, sort).expect("declare in cvc5");
        }
        for assertion in &eq_enc.forward.assertions {
            solver.assert(assertion).expect("assert in cvc5");
        }
        solver.check_sat().expect("cvc5 check_sat")
    };
    let cvc5_bwd = {
        let mut solver = Cvc5Solver::new().expect("cvc5 should initialize");
        for (name, sort) in &eq_enc.backward.declarations {
            solver.declare_var(name, sort).expect("declare in cvc5");
        }
        for assertion in &eq_enc.backward.assertions {
            solver.assert(assertion).expect("assert in cvc5");
        }
        solver.check_sat().expect("cvc5 check_sat")
    };
    assert_eq!(z3_fwd, cvc5_fwd, "equivalence forward parity mismatch");
    assert_eq!(z3_bwd, cvc5_bwd, "equivalence backward parity mismatch");
}
