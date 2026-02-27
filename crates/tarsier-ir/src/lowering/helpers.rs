//! Shared utility functions used across lowering submodules.

use indexmap::IndexMap;
use std::collections::HashSet;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::{FieldDomain, LocalVarType, LoweringError};

pub(super) fn collect_params_from_linear_expr(
    expr: &ast::LinearExpr,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    match expr {
        ast::LinearExpr::Const(_) => {}
        ast::LinearExpr::Var(name) => {
            if seen.insert(name.clone()) {
                out.push(name.clone());
            }
        }
        ast::LinearExpr::Add(lhs, rhs) | ast::LinearExpr::Sub(lhs, rhs) => {
            collect_params_from_linear_expr(lhs, out, seen);
            collect_params_from_linear_expr(rhs, out, seen);
        }
        ast::LinearExpr::Mul(_, inner) => {
            collect_params_from_linear_expr(inner, out, seen);
        }
    }
}

pub(super) fn lower_linear_expr_to_lc(
    expr: &ast::LinearExpr,
    params: &IndexMap<String, ParamId>,
) -> Result<LinearCombination, LoweringError> {
    match expr {
        ast::LinearExpr::Const(c) => Ok(LinearCombination::constant(*c)),
        ast::LinearExpr::Var(name) => {
            if let Some(&pid) = params.get(name) {
                Ok(LinearCombination::param(pid))
            } else {
                Err(LoweringError::UnknownParameter(name.clone()))
            }
        }
        ast::LinearExpr::Add(lhs, rhs) => {
            let l = lower_linear_expr_to_lc(lhs, params)?;
            let r = lower_linear_expr_to_lc(rhs, params)?;
            Ok(l.add(&r))
        }
        ast::LinearExpr::Sub(lhs, rhs) => {
            let l = lower_linear_expr_to_lc(lhs, params)?;
            let r = lower_linear_expr_to_lc(rhs, params)?;
            Ok(l.sub(&r))
        }
        ast::LinearExpr::Mul(coeff, inner) => {
            let r = lower_linear_expr_to_lc(inner, params)?;
            Ok(r.scale(*coeff))
        }
    }
}

pub(super) fn lower_committee_value(
    value: &ast::CommitteeValue,
    params: &IndexMap<String, ParamId>,
) -> Result<ParamOrConst, LoweringError> {
    match value {
        ast::CommitteeValue::Int(n) => Ok(ParamOrConst::Const(*n)),
        ast::CommitteeValue::Float(_) => Err(LoweringError::Unsupported(
            "Float values are only allowed for committee epsilon".into(),
        )),
        ast::CommitteeValue::Param(name) => {
            if let Some(&pid) = params.get(name) {
                Ok(ParamOrConst::Param(pid))
            } else {
                Err(LoweringError::UnknownParameter(name.clone()))
            }
        }
    }
}

pub(super) fn lower_cmp_op(op: ast::CmpOp) -> CmpOp {
    match op {
        ast::CmpOp::Ge => CmpOp::Ge,
        ast::CmpOp::Le => CmpOp::Le,
        ast::CmpOp::Gt => CmpOp::Gt,
        ast::CmpOp::Lt => CmpOp::Lt,
        ast::CmpOp::Eq => CmpOp::Eq,
        ast::CmpOp::Ne => CmpOp::Ne,
    }
}

pub(super) fn enumerate_local_assignments(
    domains: &[(String, Vec<LocalValue>)],
) -> Vec<IndexMap<String, LocalValue>> {
    let mut assignments: Vec<IndexMap<String, LocalValue>> = vec![IndexMap::new()];
    for (name, values) in domains {
        let mut next = Vec::new();
        for assign in &assignments {
            for val in values {
                let mut new_assign = assign.clone();
                new_assign.insert(name.clone(), val.clone());
                next.push(new_assign);
            }
        }
        assignments = next;
    }
    assignments
}

pub(super) fn eval_enum_literal(
    expr: &ast::Expr,
    enum_name: &str,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<LocalValue, LoweringError> {
    let variants = enum_defs
        .get(enum_name)
        .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
    match expr {
        ast::Expr::Var(name) => {
            if variants.contains(name) {
                Ok(LocalValue::Enum(name.clone()))
            } else {
                Err(LoweringError::UnknownEnumVariant(
                    name.clone(),
                    enum_name.to_string(),
                ))
            }
        }
        _ => Err(LoweringError::Unsupported(format!(
            "Enum literal expected for type '{enum_name}'"
        ))),
    }
}

pub(super) fn eval_bool_expr(
    expr: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
) -> Result<bool, LoweringError> {
    match expr {
        ast::Expr::BoolLit(b) => Ok(*b),
        ast::Expr::Var(name) => match locals.get(name) {
            Some(LocalValue::Bool(b)) => Ok(*b),
            _ => Err(LoweringError::Unsupported(format!(
                "Unknown boolean local variable '{name}'"
            ))),
        },
        ast::Expr::Not(inner) => Ok(!eval_bool_expr(inner, locals)?),
        _ => Err(LoweringError::Unsupported(
            "Unsupported boolean expression in assignment".into(),
        )),
    }
}

pub(super) fn eval_int_expr(
    expr: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
) -> Result<i64, LoweringError> {
    match expr {
        ast::Expr::IntLit(n) => Ok(*n),
        ast::Expr::Var(name) => match locals.get(name) {
            Some(LocalValue::Int(v)) => Ok(*v),
            Some(LocalValue::Bool(_)) | Some(LocalValue::Enum(_)) => Err(
                LoweringError::Unsupported(format!("Variable '{name}' is not an integer")),
            ),
            None => Err(LoweringError::Unsupported(format!(
                "Unknown integer local variable '{name}'"
            ))),
        },
        ast::Expr::Add(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? + eval_int_expr(rhs, locals)?),
        ast::Expr::Sub(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? - eval_int_expr(rhs, locals)?),
        ast::Expr::Mul(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? * eval_int_expr(rhs, locals)?),
        ast::Expr::Div(lhs, rhs) => {
            let denom = eval_int_expr(rhs, locals)?;
            if denom == 0 {
                return Err(LoweringError::Unsupported(
                    "Division by zero in integer expression".into(),
                ));
            }
            Ok(eval_int_expr(lhs, locals)? / denom)
        }
        ast::Expr::Neg(inner) => Ok(-eval_int_expr(inner, locals)?),
        _ => Err(LoweringError::Unsupported(
            "Unsupported integer expression".into(),
        )),
    }
}

pub(super) fn eval_local_expr(
    var_name: &str,
    expr: &ast::Expr,
    ty: &LocalVarType,
    locals: &IndexMap<String, LocalValue>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<LocalValue, LoweringError> {
    match ty {
        LocalVarType::Bool => Ok(LocalValue::Bool(eval_bool_expr(expr, locals)?)),
        LocalVarType::Enum(enum_name) => match expr {
            ast::Expr::Var(name) => {
                if let Some(LocalValue::Enum(v)) = locals.get(name) {
                    Ok(LocalValue::Enum(v.clone()))
                } else {
                    eval_enum_literal(expr, enum_name, enum_defs)
                }
            }
            _ => eval_enum_literal(expr, enum_name, enum_defs),
        },
        LocalVarType::Int { min, max } => {
            let val = eval_int_expr(expr, locals)?;
            if val < *min || val > *max {
                return Err(LoweringError::OutOfRange {
                    var: var_name.to_string(),
                    value: val,
                    min: *min,
                    max: *max,
                });
            }
            Ok(LocalValue::Int(val))
        }
    }
}

pub(super) fn eval_field_expr(
    expr: &ast::Expr,
    domain: &FieldDomain,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<String, LoweringError> {
    match domain {
        FieldDomain::Bool => {
            let b = eval_bool_expr(expr, locals)?;
            Ok(if b { "true" } else { "false" }.into())
        }
        FieldDomain::Enum(variants) => match expr {
            ast::Expr::Var(name) => {
                if let Some(LocalValue::Enum(v)) = locals.get(name) {
                    if let Some(LocalVarType::Enum(enum_name)) = local_var_types.get(name) {
                        let enum_variants = enum_defs
                            .get(enum_name)
                            .ok_or_else(|| LoweringError::UnknownEnum(enum_name.clone()))?;
                        if enum_variants != variants {
                            return Err(LoweringError::Unsupported(format!(
                                "Enum variable '{name}' does not match message field type"
                            )));
                        }
                    }
                    return Ok(v.clone());
                }
                if let Some(LocalVarType::Enum(enum_name)) = local_var_types.get(name) {
                    return Err(LoweringError::Unsupported(format!(
                        "Cannot use enum variable '{name}' as a literal (type '{enum_name}')"
                    )));
                }
                if variants.contains(name) {
                    Ok(name.clone())
                } else {
                    Err(LoweringError::UnknownEnumVariant(
                        name.clone(),
                        "message-field".into(),
                    ))
                }
            }
            _ => Err(LoweringError::Unsupported(
                "Unsupported message field expression".into(),
            )),
        },
        FieldDomain::Int { min, max } => {
            let v = eval_int_expr(expr, locals)?;
            if v < *min || v > *max {
                return Err(LoweringError::OutOfRange {
                    var: "message-field".into(),
                    value: v,
                    min: *min,
                    max: *max,
                });
            }
            Ok(v.to_string())
        }
        FieldDomain::AbstractNatSign(_values) => {
            let v = eval_int_expr(expr, locals)?;
            if v == 0 {
                Ok("zero".into())
            } else if v > 0 {
                Ok("pos".into())
            } else if v < 0 {
                Err(LoweringError::Unsupported(
                    "Negative value used where nat sign abstraction expects non-negative values"
                        .into(),
                ))
            } else {
                unreachable!("i64 value is not ==0, >0, or <0")
            }
        }
        FieldDomain::AbstractIntSign(_values) => {
            let v = eval_int_expr(expr, locals)?;
            if v < 0 {
                Ok("neg".into())
            } else if v == 0 {
                Ok("zero".into())
            } else {
                Ok("pos".into())
            }
        }
    }
}

pub(super) fn is_bool_expr(
    expr: &ast::Expr,
    local_var_types: &IndexMap<String, LocalVarType>,
) -> bool {
    match expr {
        ast::Expr::BoolLit(_) => true,
        ast::Expr::Var(name) => matches!(local_var_types.get(name), Some(LocalVarType::Bool)),
        ast::Expr::Not(inner) => is_bool_expr(inner, local_var_types),
        _ => false,
    }
}

pub(super) fn expr_enum_type<'a>(
    expr: &ast::Expr,
    local_var_types: &'a IndexMap<String, LocalVarType>,
) -> Option<&'a String> {
    match expr {
        ast::Expr::Var(name) => match local_var_types.get(name) {
            Some(LocalVarType::Enum(enum_name)) => Some(enum_name),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn eval_enum_expr(
    expr: &ast::Expr,
    enum_name: &str,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<String, LoweringError> {
    match expr {
        ast::Expr::Var(name) => match local_var_types.get(name) {
            Some(LocalVarType::Enum(var_enum)) => {
                if var_enum != enum_name {
                    return Err(LoweringError::Unsupported(format!(
                        "Enum comparison mixes '{var_enum}' with '{enum_name}'"
                    )));
                }
                match locals.get(name) {
                    Some(LocalValue::Enum(v)) => Ok(v.clone()),
                    _ => Err(LoweringError::Unsupported(format!(
                        "Enum variable '{name}' has no value in this location"
                    ))),
                }
            }
            Some(LocalVarType::Bool) => Err(LoweringError::Unsupported(
                "Enum comparison uses a boolean variable".into(),
            )),
            Some(LocalVarType::Int { .. }) => Err(LoweringError::Unsupported(
                "Enum comparison uses an integer variable".into(),
            )),
            None => {
                let variants = enum_defs
                    .get(enum_name)
                    .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
                if variants.contains(name) {
                    Ok(name.clone())
                } else {
                    Err(LoweringError::UnknownEnumVariant(
                        name.clone(),
                        enum_name.to_string(),
                    ))
                }
            }
        },
        _ => Err(LoweringError::Unsupported(
            "Enum comparison expects enum variables or literals".into(),
        )),
    }
}

pub(super) fn enum_variant_index(
    enum_name: &str,
    variant: &str,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<usize, LoweringError> {
    let variants = enum_defs
        .get(enum_name)
        .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
    variants.iter().position(|v| v == variant).ok_or_else(|| {
        LoweringError::UnknownEnumVariant(variant.to_string(), enum_name.to_string())
    })
}
