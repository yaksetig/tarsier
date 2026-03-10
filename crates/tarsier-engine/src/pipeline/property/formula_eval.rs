//! `FormulaValue`, `eval_formula_*` functions.

use crate::pipeline::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormulaValue {
    Bool(bool),
    Int(i64),
    Enum(String),
}

pub(crate) fn formula_value_from_local(value: &LocalValue) -> FormulaValue {
    match value {
        LocalValue::Bool(b) => FormulaValue::Bool(*b),
        LocalValue::Int(i) => FormulaValue::Int(*i),
        LocalValue::Enum(v) => FormulaValue::Enum(v.clone()),
    }
}

pub(crate) fn eval_formula_atom_on_location(
    atom: &ast::FormulaAtom,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<FormulaValue, PipelineError> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(v) = loc.local_vars.get(name) {
                Ok(formula_value_from_local(v))
            } else {
                // Unresolved identifiers are treated as enum literals.
                Ok(FormulaValue::Enum(name.clone()))
            }
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            if object != quantified_var {
                return Err(PipelineError::Property(format!(
                    "Liveness formula references unsupported quantified variable '{object}'."
                )));
            }
            let value = loc.local_vars.get(field).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Unknown local variable '{field}' in liveness formula."
                ))
            })?;
            Ok(formula_value_from_local(value))
        }
    }
}

pub(crate) fn eval_formula_comparison(
    op: ast::CmpOp,
    lhs: FormulaValue,
    rhs: FormulaValue,
) -> Result<bool, PipelineError> {
    use tarsier_dsl::ast::CmpOp;
    match (lhs, rhs) {
        (FormulaValue::Bool(l), FormulaValue::Bool(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err(PipelineError::Property(
                "Boolean liveness comparisons only support == and !=.".into(),
            )),
        },
        (FormulaValue::Int(l), FormulaValue::Int(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            CmpOp::Ge => Ok(l >= r),
            CmpOp::Gt => Ok(l > r),
            CmpOp::Le => Ok(l <= r),
            CmpOp::Lt => Ok(l < r),
        },
        (FormulaValue::Enum(l), FormulaValue::Enum(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err(PipelineError::Property(
                "Enum liveness comparisons only support == and !=.".into(),
            )),
        },
        _ => Err(PipelineError::Property(
            "Type mismatch in liveness formula comparison.".into(),
        )),
    }
}

pub(crate) fn eval_formula_expr_on_location(
    expr: &ast::FormulaExpr,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<bool, PipelineError> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let l = eval_formula_atom_on_location(lhs, quantified_var, loc)?;
            let r = eval_formula_atom_on_location(rhs, quantified_var, loc)?;
            eval_formula_comparison(*op, l, r)
        }
        ast::FormulaExpr::Not(inner) => {
            Ok(!eval_formula_expr_on_location(inner, quantified_var, loc)?)
        }
        ast::FormulaExpr::And(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                && eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            Ok(!eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let lv = eval_formula_expr_on_location(lhs, quantified_var, loc)?;
            let rv = eval_formula_expr_on_location(rhs, quantified_var, loc)?;
            Ok(lv == rv)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => Err(PipelineError::Property(
            "Temporal operators are not valid inside a single-state predicate context.".into(),
        )),
    }
}

fn eval_formula_atom_for_assignment(
    ta: &ThresholdAutomaton,
    atom: &ast::FormulaAtom,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<FormulaValue, PipelineError> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(loc_id) = assignment.get(default_quantified_var) {
                let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                    PipelineError::Property(format!(
                        "Invalid location id {loc_id} while evaluating liveness formula."
                    ))
                })?;
                if let Some(v) = loc.local_vars.get(name) {
                    return Ok(formula_value_from_local(v));
                }
            }
            // Unresolved identifiers are treated as enum literals.
            Ok(FormulaValue::Enum(name.clone()))
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            let loc_id = assignment.get(object).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Liveness formula references unsupported quantified variable '{object}'."
                ))
            })?;
            let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Invalid location id {loc_id} while evaluating liveness formula."
                ))
            })?;
            let value = loc.local_vars.get(field).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Unknown local variable '{field}' in liveness formula."
                ))
            })?;
            Ok(formula_value_from_local(value))
        }
    }
}

pub(crate) fn eval_formula_expr_for_assignment(
    ta: &ThresholdAutomaton,
    expr: &ast::FormulaExpr,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<bool, PipelineError> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let l = eval_formula_atom_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let r = eval_formula_atom_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            eval_formula_comparison(*op, l, r)
        }
        ast::FormulaExpr::Not(inner) => Ok(!eval_formula_expr_for_assignment(
            ta,
            inner,
            assignment,
            default_quantified_var,
        )?),
        ast::FormulaExpr::And(lhs, rhs) => {
            Ok(
                eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    && eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            Ok(
                eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    || eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            Ok(
                !eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    || eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let lv = eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let rv = eval_formula_expr_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            Ok(lv == rv)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => Err(PipelineError::Property(
            "Temporal operators are not valid inside a single-state predicate context.".into(),
        )),
    }
}

pub(crate) fn formula_contains_temporal(expr: &ast::FormulaExpr) -> bool {
    match expr {
        ast::FormulaExpr::Comparison { .. } => false,
        ast::FormulaExpr::Not(inner) => formula_contains_temporal(inner),
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_) => true,
        ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => true,
        ast::FormulaExpr::And(lhs, rhs)
        | ast::FormulaExpr::Or(lhs, rhs)
        | ast::FormulaExpr::Implies(lhs, rhs)
        | ast::FormulaExpr::Iff(lhs, rhs) => {
            formula_contains_temporal(lhs) || formula_contains_temporal(rhs)
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert!(eval_formula_comparison(
            ast::CmpOp::Eq,
            FormulaValue::Int(5),
            FormulaValue::Int(5)
        )
        .unwrap());
        assert!(!eval_formula_comparison(
            ast::CmpOp::Eq,
            FormulaValue::Int(5),
            FormulaValue::Int(6)
        )
        .unwrap());
    }

    #[test]
    fn comparison_int_ordering() {
        assert!(eval_formula_comparison(
            ast::CmpOp::Ge,
            FormulaValue::Int(5),
            FormulaValue::Int(3)
        )
        .unwrap());
        assert!(!eval_formula_comparison(
            ast::CmpOp::Lt,
            FormulaValue::Int(5),
            FormulaValue::Int(3)
        )
        .unwrap());
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
}
