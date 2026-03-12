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
mod tests;
