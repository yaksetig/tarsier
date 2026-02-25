//! Backend parity tests: verify that Z3 and cvc5 produce the same SAT/UNSAT
//! verdicts on a set of small formulas.
//!
//! cvc5 tests are gated behind `#[ignore]` so they can be skipped in CI when
//! cvc5 is not installed. Run with `cargo test -- --ignored` to include them.

use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::solver::{SatResult, SmtSolver};
use tarsier_smt::sorts::SmtSort;
use tarsier_smt::terms::SmtTerm;

/// Helper: check a formula with Z3 and return the result.
fn z3_check(setup: impl FnOnce(&mut Z3Solver)) -> SatResult {
    let mut solver = Z3Solver::with_default_config();
    setup(&mut solver);
    solver.check_sat().unwrap()
}

#[test]
fn z3_simple_sat() {
    let result = z3_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("x").lt(SmtTerm::int(10)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Sat);
}

#[test]
fn z3_simple_unsat() {
    let result = z3_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("x").lt(SmtTerm::int(0)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Unsat);
}

#[test]
fn z3_threshold_guard_encoding_sat() {
    // sum >= n - t where n=4, t=1 and sum can be at most 3
    // so sum >= 3, which is satisfiable
    let result = z3_check(|s| {
        s.declare_var("sum", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("sum").ge(SmtTerm::int(0)),
            SmtTerm::var("sum").le(SmtTerm::int(4)),
            // sum >= n - t = 4 - 1 = 3
            SmtTerm::var("sum").ge(SmtTerm::int(3)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Sat);
}

#[test]
fn z3_threshold_guard_encoding_unsat() {
    // sum >= n - t where n=4, t=0 and sum can be at most 3
    // so sum >= 4 but max 3 => unsat
    let result = z3_check(|s| {
        s.declare_var("sum", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("sum").ge(SmtTerm::int(0)),
            SmtTerm::var("sum").le(SmtTerm::int(3)),
            SmtTerm::var("sum").ge(SmtTerm::int(4)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Unsat);
}

// ---- cvc5 parity tests (ignored by default) ----

use tarsier_smt::backends::cvc5_backend::Cvc5Solver;

fn cvc5_available() -> bool {
    Cvc5Solver::new().is_ok()
}

fn cvc5_check(setup: impl FnOnce(&mut Cvc5Solver)) -> SatResult {
    let mut solver = Cvc5Solver::new().expect("cvc5 should be available");
    setup(&mut solver);
    solver.check_sat().unwrap()
}

#[test]
#[ignore = "requires cvc5 binary"]
fn cvc5_simple_sat() {
    if !cvc5_available() {
        return;
    }
    let result = cvc5_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("x").lt(SmtTerm::int(10)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Sat);
}

#[test]
#[ignore = "requires cvc5 binary"]
fn cvc5_simple_unsat() {
    if !cvc5_available() {
        return;
    }
    let result = cvc5_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("x").lt(SmtTerm::int(0)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Unsat);
}

#[test]
#[ignore = "requires cvc5 binary"]
fn cvc5_threshold_guard_encoding_sat() {
    if !cvc5_available() {
        return;
    }
    let result = cvc5_check(|s| {
        s.declare_var("sum", &SmtSort::Int).unwrap();
        s.assert(&SmtTerm::and(vec![
            SmtTerm::var("sum").ge(SmtTerm::int(0)),
            SmtTerm::var("sum").le(SmtTerm::int(4)),
            SmtTerm::var("sum").ge(SmtTerm::int(3)),
        ]))
        .unwrap();
    });
    assert_eq!(result, SatResult::Sat);
}

#[test]
#[ignore = "requires cvc5 binary"]
fn cvc5_z3_parity_unsat() {
    if !cvc5_available() {
        return;
    }
    // Same formula checked with both solvers should agree
    let formula = SmtTerm::and(vec![
        SmtTerm::var("x").gt(SmtTerm::int(5)),
        SmtTerm::var("x").lt(SmtTerm::int(3)),
    ]);

    let z3_result = z3_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&formula).unwrap();
    });

    let cvc5_result = cvc5_check(|s| {
        s.declare_var("x", &SmtSort::Int).unwrap();
        s.assert(&formula).unwrap();
    });

    assert_eq!(z3_result, cvc5_result, "Z3 and cvc5 should agree on UNSAT");
}
