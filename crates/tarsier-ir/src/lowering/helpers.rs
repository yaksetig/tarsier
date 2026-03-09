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

/// Convert a general `ast::Expr` to a `LinearCombination`, supporting the
/// subset that is linear over parameters (IntLit, Var→param, Add, Sub, Neg).
pub(super) fn lower_expr_to_lc(
    expr: &ast::Expr,
    params: &IndexMap<String, ParamId>,
) -> Result<LinearCombination, LoweringError> {
    match expr {
        ast::Expr::IntLit(c) => Ok(LinearCombination::constant(*c)),
        ast::Expr::Var(name) => {
            if let Some(&pid) = params.get(name) {
                Ok(LinearCombination::param(pid))
            } else {
                Err(LoweringError::UnknownParameter(name.clone()))
            }
        }
        ast::Expr::Add(lhs, rhs) => {
            let l = lower_expr_to_lc(lhs, params)?;
            let r = lower_expr_to_lc(rhs, params)?;
            Ok(l.add(&r))
        }
        ast::Expr::Sub(lhs, rhs) => {
            let l = lower_expr_to_lc(lhs, params)?;
            let r = lower_expr_to_lc(rhs, params)?;
            Ok(l.sub(&r))
        }
        ast::Expr::Neg(inner) => {
            let lc = lower_expr_to_lc(inner, params)?;
            Ok(lc.scale(-1))
        }
        _ => Err(LoweringError::Unsupported(
            "Collection append value must be a linear expression over parameters and constants"
                .into(),
        )),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_params_constant_yields_none() {
        let expr = ast::LinearExpr::Const(42);
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        collect_params_from_linear_expr(&expr, &mut out, &mut seen);
        assert!(out.is_empty());
    }

    #[test]
    fn collect_params_var_yields_name() {
        let expr = ast::LinearExpr::Var("n".into());
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        collect_params_from_linear_expr(&expr, &mut out, &mut seen);
        assert_eq!(out, vec!["n"]);
    }

    #[test]
    fn collect_params_deduplicates() {
        let expr = ast::LinearExpr::Add(
            Box::new(ast::LinearExpr::Var("n".into())),
            Box::new(ast::LinearExpr::Var("n".into())),
        );
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        collect_params_from_linear_expr(&expr, &mut out, &mut seen);
        assert_eq!(out, vec!["n"]);
    }

    #[test]
    fn collect_params_complex_expr() {
        let expr = ast::LinearExpr::Sub(
            Box::new(ast::LinearExpr::Add(
                Box::new(ast::LinearExpr::Mul(
                    3,
                    Box::new(ast::LinearExpr::Var("t".into())),
                )),
                Box::new(ast::LinearExpr::Var("n".into())),
            )),
            Box::new(ast::LinearExpr::Const(1)),
        );
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        collect_params_from_linear_expr(&expr, &mut out, &mut seen);
        assert_eq!(out, vec!["t", "n"]);
    }

    #[test]
    fn lower_linear_constant() {
        let params: IndexMap<String, ParamId> = IndexMap::new();
        let lc = lower_linear_expr_to_lc(&ast::LinearExpr::Const(5), &params).unwrap();
        assert_eq!(lc.constant, 5);
        assert!(lc.terms.is_empty());
    }

    #[test]
    fn lower_linear_var() {
        let mut params: IndexMap<String, ParamId> = IndexMap::new();
        params.insert("n".into(), ParamId::from(0));
        let lc =
            lower_linear_expr_to_lc(&ast::LinearExpr::Var("n".into()), &params).unwrap();
        assert_eq!(lc.constant, 0);
        assert_eq!(lc.terms.len(), 1);
        assert_eq!(lc.terms[0], (1, ParamId::from(0)));
    }

    #[test]
    fn lower_linear_unknown_param_error() {
        let params: IndexMap<String, ParamId> = IndexMap::new();
        assert!(
            lower_linear_expr_to_lc(&ast::LinearExpr::Var("x".into()), &params).is_err()
        );
    }

    #[test]
    fn lower_linear_add_sub() {
        let mut params: IndexMap<String, ParamId> = IndexMap::new();
        params.insert("n".into(), ParamId::from(0));
        let expr = ast::LinearExpr::Add(
            Box::new(ast::LinearExpr::Var("n".into())),
            Box::new(ast::LinearExpr::Const(3)),
        );
        let lc = lower_linear_expr_to_lc(&expr, &params).unwrap();
        assert_eq!(lc.constant, 3);
        assert_eq!(lc.terms.len(), 1);
    }

    #[test]
    fn lower_linear_mul() {
        let mut params: IndexMap<String, ParamId> = IndexMap::new();
        params.insert("t".into(), ParamId::from(0));
        let expr =
            ast::LinearExpr::Mul(3, Box::new(ast::LinearExpr::Var("t".into())));
        let lc = lower_linear_expr_to_lc(&expr, &params).unwrap();
        assert_eq!(lc.constant, 0);
        assert_eq!(lc.terms[0], (3, ParamId::from(0)));
    }

    #[test]
    fn lower_cmp_op_all_variants() {
        assert_eq!(lower_cmp_op(ast::CmpOp::Ge), CmpOp::Ge);
        assert_eq!(lower_cmp_op(ast::CmpOp::Le), CmpOp::Le);
        assert_eq!(lower_cmp_op(ast::CmpOp::Gt), CmpOp::Gt);
        assert_eq!(lower_cmp_op(ast::CmpOp::Lt), CmpOp::Lt);
        assert_eq!(lower_cmp_op(ast::CmpOp::Eq), CmpOp::Eq);
        assert_eq!(lower_cmp_op(ast::CmpOp::Ne), CmpOp::Ne);
    }

    #[test]
    fn enumerate_empty_domains() {
        let domains: Vec<(String, Vec<LocalValue>)> = vec![];
        let assigns = enumerate_local_assignments(&domains);
        assert_eq!(assigns.len(), 1);
        assert!(assigns[0].is_empty());
    }

    #[test]
    fn enumerate_single_bool_domain() {
        let domains = vec![(
            "decided".into(),
            vec![LocalValue::Bool(false), LocalValue::Bool(true)],
        )];
        let assigns = enumerate_local_assignments(&domains);
        assert_eq!(assigns.len(), 2);
    }

    #[test]
    fn enumerate_cross_product() {
        let domains = vec![
            (
                "a".into(),
                vec![LocalValue::Bool(false), LocalValue::Bool(true)],
            ),
            (
                "b".into(),
                vec![LocalValue::Int(0), LocalValue::Int(1), LocalValue::Int(2)],
            ),
        ];
        let assigns = enumerate_local_assignments(&domains);
        assert_eq!(assigns.len(), 6);
    }

    #[test]
    fn eval_bool_literal() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        assert!(eval_bool_expr(&ast::Expr::BoolLit(true), &locals).unwrap());
        assert!(!eval_bool_expr(&ast::Expr::BoolLit(false), &locals).unwrap());
    }

    #[test]
    fn eval_bool_var() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("flag".into(), LocalValue::Bool(true));
        assert!(eval_bool_expr(&ast::Expr::Var("flag".into()), &locals).unwrap());
    }

    #[test]
    fn eval_bool_not() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let expr = ast::Expr::Not(Box::new(ast::Expr::BoolLit(true)));
        assert!(!eval_bool_expr(&expr, &locals).unwrap());
    }

    #[test]
    fn eval_bool_unknown_var_error() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        assert!(eval_bool_expr(&ast::Expr::Var("missing".into()), &locals).is_err());
    }

    #[test]
    fn eval_int_literal() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        assert_eq!(eval_int_expr(&ast::Expr::IntLit(42), &locals).unwrap(), 42);
    }

    #[test]
    fn eval_int_arithmetic() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let expr = ast::Expr::Mul(
            Box::new(ast::Expr::Add(
                Box::new(ast::Expr::IntLit(3)),
                Box::new(ast::Expr::IntLit(2)),
            )),
            Box::new(ast::Expr::IntLit(4)),
        );
        assert_eq!(eval_int_expr(&expr, &locals).unwrap(), 20);
    }

    #[test]
    fn eval_int_div_by_zero_error() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let expr = ast::Expr::Div(
            Box::new(ast::Expr::IntLit(10)),
            Box::new(ast::Expr::IntLit(0)),
        );
        assert!(eval_int_expr(&expr, &locals).is_err());
    }

    #[test]
    fn eval_int_neg() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let expr = ast::Expr::Neg(Box::new(ast::Expr::IntLit(5)));
        assert_eq!(eval_int_expr(&expr, &locals).unwrap(), -5);
    }

    #[test]
    fn eval_int_var() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("x".into(), LocalValue::Int(7));
        assert_eq!(
            eval_int_expr(&ast::Expr::Var("x".into()), &locals).unwrap(),
            7
        );
    }

    #[test]
    fn is_bool_expr_checks() {
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("flag".into(), LocalVarType::Bool);
        types.insert("count".into(), LocalVarType::Int { min: 0, max: 10 });
        assert!(is_bool_expr(&ast::Expr::BoolLit(true), &types));
        assert!(is_bool_expr(&ast::Expr::Var("flag".into()), &types));
        assert!(!is_bool_expr(&ast::Expr::Var("count".into()), &types));
        assert!(!is_bool_expr(&ast::Expr::IntLit(0), &types));
    }

    #[test]
    fn eval_enum_literal_valid() {
        let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        enum_defs.insert("Color".into(), vec!["red".into(), "blue".into()]);
        let result =
            eval_enum_literal(&ast::Expr::Var("red".into()), "Color", &enum_defs).unwrap();
        assert_eq!(result, LocalValue::Enum("red".into()));
    }

    #[test]
    fn eval_enum_literal_unknown_variant_error() {
        let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        enum_defs.insert("Color".into(), vec!["red".into(), "blue".into()]);
        assert!(
            eval_enum_literal(&ast::Expr::Var("green".into()), "Color", &enum_defs).is_err()
        );
    }

    #[test]
    fn eval_enum_literal_unknown_enum_error() {
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(
            eval_enum_literal(&ast::Expr::Var("x".into()), "Missing", &enum_defs).is_err()
        );
    }

    #[test]
    fn enum_variant_index_valid() {
        let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        enum_defs.insert(
            "View".into(),
            vec!["v0".into(), "v1".into(), "v2".into()],
        );
        assert_eq!(enum_variant_index("View", "v0", &enum_defs).unwrap(), 0);
        assert_eq!(enum_variant_index("View", "v2", &enum_defs).unwrap(), 2);
    }

    #[test]
    fn enum_variant_index_unknown_variant_error() {
        let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        enum_defs.insert("View".into(), vec!["v0".into()]);
        assert!(enum_variant_index("View", "v99", &enum_defs).is_err());
    }

    #[test]
    fn eval_local_expr_bool() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        let result = eval_local_expr(
            "flag",
            &ast::Expr::BoolLit(true),
            &LocalVarType::Bool,
            &locals,
            &enum_defs,
        )
        .unwrap();
        assert_eq!(result, LocalValue::Bool(true));
    }

    #[test]
    fn eval_local_expr_int_out_of_range_error() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(eval_local_expr(
            "x",
            &ast::Expr::IntLit(100),
            &LocalVarType::Int { min: 0, max: 10 },
            &locals,
            &enum_defs,
        )
        .is_err());
    }

    #[test]
    fn eval_local_expr_int_in_range() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        let result = eval_local_expr(
            "x",
            &ast::Expr::IntLit(5),
            &LocalVarType::Int { min: 0, max: 10 },
            &locals,
            &enum_defs,
        )
        .unwrap();
        assert_eq!(result, LocalValue::Int(5));
    }

    #[test]
    fn eval_field_expr_bool_domain() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let result = eval_field_expr(
            &ast::Expr::BoolLit(true),
            &FieldDomain::Bool,
            &locals,
            &types,
            &enums,
        )
        .unwrap();
        assert_eq!(result, "true");
    }

    #[test]
    fn eval_field_expr_int_domain_in_range() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let result = eval_field_expr(
            &ast::Expr::IntLit(3),
            &FieldDomain::Int { min: 0, max: 5 },
            &locals,
            &types,
            &enums,
        )
        .unwrap();
        assert_eq!(result, "3");
    }

    #[test]
    fn eval_field_expr_int_domain_out_of_range_error() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(eval_field_expr(
            &ast::Expr::IntLit(10),
            &FieldDomain::Int { min: 0, max: 5 },
            &locals,
            &types,
            &enums,
        )
        .is_err());
    }

    #[test]
    fn eval_field_expr_nat_sign_abstraction() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let domain =
            FieldDomain::AbstractNatSign(vec!["zero".into(), "pos".into()]);
        assert_eq!(
            eval_field_expr(&ast::Expr::IntLit(0), &domain, &locals, &types, &enums)
                .unwrap(),
            "zero"
        );
        assert_eq!(
            eval_field_expr(&ast::Expr::IntLit(5), &domain, &locals, &types, &enums)
                .unwrap(),
            "pos"
        );
    }

    #[test]
    fn eval_field_expr_int_sign_abstraction() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let domain = FieldDomain::AbstractIntSign(vec![
            "neg".into(),
            "zero".into(),
            "pos".into(),
        ]);
        assert_eq!(
            eval_field_expr(
                &ast::Expr::IntLit(-3),
                &domain,
                &locals,
                &types,
                &enums
            )
            .unwrap(),
            "neg"
        );
        assert_eq!(
            eval_field_expr(&ast::Expr::IntLit(0), &domain, &locals, &types, &enums)
                .unwrap(),
            "zero"
        );
        assert_eq!(
            eval_field_expr(&ast::Expr::IntLit(3), &domain, &locals, &types, &enums)
                .unwrap(),
            "pos"
        );
    }

    #[test]
    fn lower_expr_to_lc_int_lit() {
        let params: IndexMap<String, ParamId> = IndexMap::new();
        let lc = lower_expr_to_lc(&ast::Expr::IntLit(7), &params).unwrap();
        assert_eq!(lc.constant, 7);
        assert!(lc.terms.is_empty());
    }

    #[test]
    fn lower_expr_to_lc_neg() {
        let mut params: IndexMap<String, ParamId> = IndexMap::new();
        params.insert("n".into(), ParamId::from(0));
        let expr = ast::Expr::Neg(Box::new(ast::Expr::Var("n".into())));
        let lc = lower_expr_to_lc(&expr, &params).unwrap();
        assert_eq!(lc.terms[0], (-1, ParamId::from(0)));
    }

    #[test]
    fn lower_expr_to_lc_unsupported_bool_error() {
        let params: IndexMap<String, ParamId> = IndexMap::new();
        assert!(lower_expr_to_lc(&ast::Expr::BoolLit(true), &params).is_err());
    }

    #[test]
    fn expr_enum_type_returns_enum_name() {
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("view".into(), LocalVarType::Enum("View".into()));
        assert_eq!(
            expr_enum_type(&ast::Expr::Var("view".into()), &types),
            Some(&"View".to_string())
        );
    }

    #[test]
    fn expr_enum_type_returns_none_for_non_enum() {
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("count".into(), LocalVarType::Int { min: 0, max: 10 });
        assert_eq!(
            expr_enum_type(&ast::Expr::Var("count".into()), &types),
            None
        );
        assert_eq!(expr_enum_type(&ast::Expr::IntLit(5), &types), None);
    }
}
