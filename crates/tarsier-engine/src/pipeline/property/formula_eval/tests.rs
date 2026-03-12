use super::*;

fn int_lit(v: i64) -> ast::FormulaAtom {
    ast::FormulaAtom::IntLit(v)
}

fn bool_lit(v: bool) -> ast::FormulaAtom {
    ast::FormulaAtom::BoolLit(v)
}

fn qvar(object: &str, field: &str) -> ast::FormulaAtom {
    ast::FormulaAtom::QualifiedVar {
        object: object.to_string(),
        field: field.to_string(),
    }
}

fn var_atom(name: &str) -> ast::FormulaAtom {
    ast::FormulaAtom::Var(name.to_string())
}

fn cmp(lhs: ast::FormulaAtom, op: ast::CmpOp, rhs: ast::FormulaAtom) -> ast::FormulaExpr {
    ast::FormulaExpr::Comparison { lhs, op, rhs }
}

fn test_loc(vars: Vec<(&str, LocalValue)>) -> tarsier_ir::threshold_automaton::Location {
    let mut loc = tarsier_ir::threshold_automaton::Location {
        name: "TestLoc".into(),
        role: "R".into(),
        phase: "test".into(),
        local_vars: Default::default(),
    };
    for (k, v) in vars {
        loc.local_vars.insert(k.to_string(), v);
    }
    loc
}

// -- FormulaValue construction --

#[test]
fn formula_value_from_local_bool() {
    assert_eq!(
        formula_value_from_local(&LocalValue::Bool(true)),
        FormulaValue::Bool(true)
    );
}

#[test]
fn formula_value_from_local_int() {
    assert_eq!(
        formula_value_from_local(&LocalValue::Int(42)),
        FormulaValue::Int(42)
    );
}

#[test]
fn formula_value_from_local_enum() {
    assert_eq!(
        formula_value_from_local(&LocalValue::Enum("Phase1".into())),
        FormulaValue::Enum("Phase1".into())
    );
}

// -- eval_formula_comparison --

#[test]
fn comparison_int_eq() {
    assert!(
        eval_formula_comparison(ast::CmpOp::Eq, FormulaValue::Int(5), FormulaValue::Int(5))
            .unwrap()
    );
    assert!(
        !eval_formula_comparison(ast::CmpOp::Eq, FormulaValue::Int(5), FormulaValue::Int(6))
            .unwrap()
    );
}

#[test]
fn comparison_int_ordering() {
    assert!(
        eval_formula_comparison(ast::CmpOp::Ge, FormulaValue::Int(5), FormulaValue::Int(3))
            .unwrap()
    );
    assert!(
        !eval_formula_comparison(ast::CmpOp::Lt, FormulaValue::Int(5), FormulaValue::Int(3))
            .unwrap()
    );
}

#[test]
fn comparison_bool_eq_ne() {
    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Bool(true),
        FormulaValue::Bool(true)
    )
    .unwrap());
    assert!(eval_formula_comparison(
        ast::CmpOp::Ne,
        FormulaValue::Bool(true),
        FormulaValue::Bool(false)
    )
    .unwrap());
}

#[test]
fn comparison_bool_ordering_error() {
    assert!(eval_formula_comparison(
        ast::CmpOp::Ge,
        FormulaValue::Bool(true),
        FormulaValue::Bool(false)
    )
    .is_err());
}

#[test]
fn comparison_enum_eq_ne() {
    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Enum("A".into()),
        FormulaValue::Enum("A".into())
    )
    .unwrap());
    assert!(eval_formula_comparison(
        ast::CmpOp::Ne,
        FormulaValue::Enum("A".into()),
        FormulaValue::Enum("B".into())
    )
    .unwrap());
}

#[test]
fn comparison_type_mismatch_error() {
    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Bool(true),
        FormulaValue::Int(1)
    )
    .is_err());
}

// -- eval_formula_atom_on_location --

#[test]
fn atom_int_lit_returns_int() {
    let loc = test_loc(vec![]);
    let result = eval_formula_atom_on_location(&int_lit(7), "p", &loc);
    assert_eq!(result.unwrap(), FormulaValue::Int(7));
}

#[test]
fn atom_bool_lit_returns_bool() {
    let loc = test_loc(vec![]);
    let result = eval_formula_atom_on_location(&bool_lit(false), "p", &loc);
    assert_eq!(result.unwrap(), FormulaValue::Bool(false));
}

#[test]
fn atom_qualified_var_found() {
    let loc = test_loc(vec![("decided", LocalValue::Bool(true))]);
    let result = eval_formula_atom_on_location(&qvar("p", "decided"), "p", &loc);
    assert_eq!(result.unwrap(), FormulaValue::Bool(true));
}

#[test]
fn atom_qualified_var_wrong_object_errors() {
    let loc = test_loc(vec![("decided", LocalValue::Bool(true))]);
    let result = eval_formula_atom_on_location(&qvar("q", "decided"), "p", &loc);
    assert!(result.is_err());
}

#[test]
fn atom_var_resolves_local_or_enum() {
    let loc = test_loc(vec![("x", LocalValue::Int(5))]);
    let result = eval_formula_atom_on_location(&var_atom("x"), "p", &loc);
    assert_eq!(result.unwrap(), FormulaValue::Int(5));

    let result = eval_formula_atom_on_location(&var_atom("unknown"), "p", &loc);
    assert_eq!(result.unwrap(), FormulaValue::Enum("unknown".into()));
}

// -- eval_formula_expr_on_location --

#[test]
fn expr_not_inverts() {
    let loc = test_loc(vec![("x", LocalValue::Bool(true))]);
    let expr = ast::FormulaExpr::Not(Box::new(cmp(
        qvar("p", "x"),
        ast::CmpOp::Eq,
        bool_lit(true),
    )));
    assert!(!eval_formula_expr_on_location(&expr, "p", &loc).unwrap());
}

#[test]
fn expr_and_both_true() {
    let loc = test_loc(vec![
        ("x", LocalValue::Bool(true)),
        ("y", LocalValue::Bool(true)),
    ]);
    let expr = ast::FormulaExpr::And(
        Box::new(cmp(qvar("p", "x"), ast::CmpOp::Eq, bool_lit(true))),
        Box::new(cmp(qvar("p", "y"), ast::CmpOp::Eq, bool_lit(true))),
    );
    assert!(eval_formula_expr_on_location(&expr, "p", &loc).unwrap());
}

#[test]
fn expr_implies_false_antecedent() {
    let loc = test_loc(vec![("x", LocalValue::Bool(false))]);
    let expr = ast::FormulaExpr::Implies(
        Box::new(cmp(qvar("p", "x"), ast::CmpOp::Eq, bool_lit(true))),
        Box::new(cmp(int_lit(1), ast::CmpOp::Eq, int_lit(2))),
    );
    assert!(eval_formula_expr_on_location(&expr, "p", &loc).unwrap());
}

#[test]
fn expr_temporal_operator_errors() {
    let loc = test_loc(vec![]);
    let inner = cmp(int_lit(1), ast::CmpOp::Eq, int_lit(1));
    let expr = ast::FormulaExpr::Always(Box::new(inner));
    assert!(eval_formula_expr_on_location(&expr, "p", &loc).is_err());
}

// -- formula_contains_temporal --

#[test]
fn temporal_detection_comparison() {
    let expr = cmp(int_lit(1), ast::CmpOp::Eq, int_lit(1));
    assert!(!formula_contains_temporal(&expr));
}

#[test]
fn temporal_detection_always() {
    let expr = ast::FormulaExpr::Always(Box::new(cmp(int_lit(1), ast::CmpOp::Eq, int_lit(1))));
    assert!(formula_contains_temporal(&expr));
}

#[test]
fn temporal_detection_nested_in_and() {
    let temporal =
        ast::FormulaExpr::Eventually(Box::new(cmp(int_lit(1), ast::CmpOp::Eq, int_lit(1))));
    let non_temporal = cmp(int_lit(2), ast::CmpOp::Eq, int_lit(2));
    let expr = ast::FormulaExpr::And(Box::new(non_temporal), Box::new(temporal));
    assert!(formula_contains_temporal(&expr));
}

#[test]
fn temporal_detection_not_wrapped() {
    let inner = cmp(int_lit(1), ast::CmpOp::Eq, int_lit(1));
    let expr = ast::FormulaExpr::Not(Box::new(inner));
    assert!(!formula_contains_temporal(&expr));
}
