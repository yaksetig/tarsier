//! Guard expression lowering and DNF normalization.

use indexmap::IndexMap;
use std::collections::HashSet;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::counters::{
    resolve_message_counter_from_guard, GuardCounterLookup, MessageCounterContext,
};
use super::helpers::{
    enum_variant_index, eval_bool_expr, eval_enum_expr, eval_int_expr, expr_enum_type,
    is_bool_expr, lower_cmp_op, lower_linear_expr_to_lc,
};
use super::{LocalVarType, LoweringError, MessageInfo};

/// Context for lowering guards, grouping the many parameters needed during
/// guard translation into a single struct for readability.
pub(super) struct GuardLoweringContext<'a> {
    pub(super) msg_vars: &'a IndexMap<String, SharedVarId>,
    pub(super) message_infos: &'a IndexMap<String, MessageInfo>,
    pub(super) params: &'a IndexMap<String, ParamId>,
    pub(super) locals: &'a IndexMap<String, LocalValue>,
    pub(super) local_var_types: &'a IndexMap<String, LocalVarType>,
    pub(super) enum_defs: &'a IndexMap<String, Vec<String>>,
    pub(super) role_channels: &'a IndexMap<String, Vec<String>>,
    pub(super) recipient_channel: &'a str,
    pub(super) role_name: &'a str,
}

pub(super) fn lower_guard(
    guard: &ast::GuardExpr,
    ctx: &GuardLoweringContext<'_>,
) -> Result<Guard, LoweringError> {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            let sender_role = if tg.distinct {
                Some(tg.distinct_role.as_deref().unwrap_or(ctx.role_name))
            } else {
                None
            };
            let counter_ctx = MessageCounterContext {
                role_names: &[],
                role_channels: ctx.role_channels,
                message_infos: ctx.message_infos,
                msg_var_ids: ctx.msg_vars,
                locals: ctx.locals,
                local_var_types: ctx.local_var_types,
                enum_defs: ctx.enum_defs,
            };
            let query = GuardCounterLookup {
                msg_name: &tg.message_type,
                recipient_role: ctx.recipient_channel,
                args: &tg.message_args,
                sender_role,
            };
            let var_ids = resolve_message_counter_from_guard(&query, &counter_ctx)?;
            let bound = lower_linear_expr_to_lc(&tg.threshold, ctx.params)?;
            let op = lower_cmp_op(tg.op);
            Ok(Guard::single(GuardAtom::Threshold {
                vars: var_ids,
                op,
                bound,
                distinct: tg.distinct,
            }))
        }
        ast::GuardExpr::HasCryptoObject {
            object_name,
            object_args,
        } => {
            let counter_ctx = MessageCounterContext {
                role_names: &[],
                role_channels: ctx.role_channels,
                message_infos: ctx.message_infos,
                msg_var_ids: ctx.msg_vars,
                locals: ctx.locals,
                local_var_types: ctx.local_var_types,
                enum_defs: ctx.enum_defs,
            };
            let query = GuardCounterLookup {
                msg_name: object_name,
                recipient_role: ctx.recipient_channel,
                args: object_args,
                sender_role: None,
            };
            let var_ids = resolve_message_counter_from_guard(&query, &counter_ctx)?;
            Ok(Guard::single(GuardAtom::Threshold {
                vars: var_ids,
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }))
        }
        ast::GuardExpr::And(lhs, rhs) => {
            let mut lg = lower_guard(lhs, ctx)?;
            let rg = lower_guard(rhs, ctx)?;
            lg.atoms.extend(rg.atoms);
            Ok(lg)
        }
        ast::GuardExpr::Comparison { .. } => {
            // Comparison guards on local vars are enforced by filtering
            // source locations in extract_local_guard_requirements().
            // Return trivial guard for the threshold-level encoding.
            Ok(Guard::trivial())
        }
        ast::GuardExpr::Timeout { .. } => {
            // Timeout guards are lowered separately into `Rule.clock_guards`
            // in the timed lowering path.
            Ok(Guard::trivial())
        }
        ast::GuardExpr::BoolVar(_) => {
            // Boolean var guards are enforced by filtering source locations
            // in extract_local_guard_requirements().
            Ok(Guard::trivial())
        }
        ast::GuardExpr::Or(_, _) => Err(LoweringError::Unsupported(
            "Internal lowering invariant violated: OR guards should be split into DNF clauses \
             before threshold-guard lowering"
                .into(),
        )),
    }
}

pub(super) fn collect_timeout_guards(
    guard: &ast::GuardExpr,
    clock_ids: &IndexMap<String, ClockId>,
    params: &IndexMap<String, ParamId>,
) -> Result<Vec<ClockGuard>, LoweringError> {
    match guard {
        ast::GuardExpr::And(lhs, rhs) => {
            let mut out = collect_timeout_guards(lhs, clock_ids, params)?;
            out.extend(collect_timeout_guards(rhs, clock_ids, params)?);
            Ok(out)
        }
        ast::GuardExpr::Timeout {
            clock,
            op,
            threshold,
        } => {
            let clock_id = clock_ids.get(clock).copied().ok_or_else(|| {
                LoweringError::Unsupported(format!("Unknown clock '{clock}' in timeout guard"))
            })?;
            let bound = lower_linear_expr_to_lc(threshold, params)?;
            Ok(vec![ClockGuard {
                clock: clock_id,
                op: lower_cmp_op(*op),
                bound,
            }])
        }
        _ => Ok(vec![]),
    }
}

pub(super) fn guard_expr_sort_key(guard: &ast::GuardExpr) -> String {
    match guard {
        ast::GuardExpr::And(lhs, rhs) => {
            let mut keys = [guard_expr_sort_key(lhs), guard_expr_sort_key(rhs)];
            keys.sort();
            format!("and({}, {})", keys[0], keys[1])
        }
        ast::GuardExpr::Or(lhs, rhs) => {
            let mut keys = [guard_expr_sort_key(lhs), guard_expr_sort_key(rhs)];
            keys.sort();
            format!("or({}, {})", keys[0], keys[1])
        }
        _ => format!("{guard:?}"),
    }
}

pub(super) fn collect_guard_conjuncts(guard: &ast::GuardExpr, out: &mut Vec<ast::GuardExpr>) {
    match guard {
        ast::GuardExpr::And(lhs, rhs) => {
            collect_guard_conjuncts(lhs, out);
            collect_guard_conjuncts(rhs, out);
        }
        _ => out.push(guard.clone()),
    }
}

pub(super) fn normalize_guard_clause(guard: &ast::GuardExpr) -> Vec<(String, ast::GuardExpr)> {
    let mut conjuncts = Vec::new();
    collect_guard_conjuncts(guard, &mut conjuncts);
    let mut keyed: Vec<(String, ast::GuardExpr)> = conjuncts
        .into_iter()
        .map(|expr| (guard_expr_sort_key(&expr), expr))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    keyed
}

pub(super) fn rebuild_guard_clause(conjuncts: Vec<(String, ast::GuardExpr)>) -> ast::GuardExpr {
    let mut iter = conjuncts.into_iter().map(|(_, expr)| expr);
    // Safety: callers only pass conjunct lists produced by normalize_guard_clause(),
    // which always yields at least one element since guard_to_dnf_raw_clauses()
    // never produces empty clauses.
    let mut clause = iter
        .next()
        .expect("normalized DNF guard clause should contain at least one conjunct");
    for expr in iter {
        clause = ast::GuardExpr::And(Box::new(clause), Box::new(expr));
    }
    clause
}

pub(super) fn sorted_guard_keys_subset(subset: &[String], superset: &[String]) -> bool {
    if subset.len() > superset.len() {
        return false;
    }
    let mut i = 0usize;
    let mut j = 0usize;
    while i < subset.len() && j < superset.len() {
        match subset[i].cmp(&superset[j]) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
            }
        }
    }
    i == subset.len()
}

pub(super) fn guard_to_dnf_raw_clauses(guard: &ast::GuardExpr) -> Vec<ast::GuardExpr> {
    match guard {
        ast::GuardExpr::Or(lhs, rhs) => {
            let mut clauses = guard_to_dnf_raw_clauses(lhs);
            clauses.extend(guard_to_dnf_raw_clauses(rhs));
            clauses
        }
        ast::GuardExpr::And(lhs, rhs) => {
            let left = guard_to_dnf_raw_clauses(lhs);
            let right = guard_to_dnf_raw_clauses(rhs);
            let mut out = Vec::new();
            for l in &left {
                for r in &right {
                    out.push(ast::GuardExpr::And(
                        Box::new(l.clone()),
                        Box::new(r.clone()),
                    ));
                }
            }
            out
        }
        _ => vec![guard.clone()],
    }
}

pub(super) fn guard_to_dnf_clauses(guard: &ast::GuardExpr) -> Vec<ast::GuardExpr> {
    // Normalize DNF clauses to keep lowering robust:
    // - canonicalize conjunction ordering
    // - remove duplicate conjuncts inside a clause
    // - remove duplicate clauses
    // - prune subsumed clauses (`A || (A && B)` => `A`)
    let raw_clauses = guard_to_dnf_raw_clauses(guard);
    #[allow(clippy::type_complexity)]
    let mut normalized_clauses: Vec<(Vec<String>, Vec<(String, ast::GuardExpr)>)> = Vec::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    for clause in raw_clauses {
        let normalized = normalize_guard_clause(&clause);
        let key_vec: Vec<String> = normalized.iter().map(|(k, _)| k.clone()).collect();
        let key = key_vec.join(" && ");
        if seen_keys.insert(key) {
            normalized_clauses.push((key_vec, normalized));
        }
    }

    let mut subsumed = vec![false; normalized_clauses.len()];
    for i in 0..normalized_clauses.len() {
        if subsumed[i] {
            continue;
        }
        for j in 0..normalized_clauses.len() {
            if i == j || subsumed[j] {
                continue;
            }
            let keys_i = &normalized_clauses[i].0;
            let keys_j = &normalized_clauses[j].0;
            if sorted_guard_keys_subset(keys_j, keys_i) {
                subsumed[i] = true;
                break;
            }
        }
    }

    normalized_clauses
        .into_iter()
        .enumerate()
        .filter_map(|(idx, (_keys, conjuncts))| {
            (!subsumed[idx]).then(|| rebuild_guard_clause(conjuncts))
        })
        .collect()
}

pub(super) fn local_guard_satisfied(
    guard: &ast::GuardExpr,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<bool, LoweringError> {
    match guard {
        ast::GuardExpr::BoolVar(name) => match locals.get(name) {
            Some(LocalValue::Bool(b)) => Ok(*b),
            _ => Err(LoweringError::Unsupported(format!(
                "Guard refers to non-boolean variable '{name}'"
            ))),
        },
        ast::GuardExpr::Comparison { lhs, op, rhs } => {
            eval_local_comparison(lhs, *op, rhs, locals, local_var_types, enum_defs)
        }
        ast::GuardExpr::And(lhs, rhs) => {
            Ok(
                local_guard_satisfied(lhs, locals, local_var_types, enum_defs)?
                    && local_guard_satisfied(rhs, locals, local_var_types, enum_defs)?,
            )
        }
        ast::GuardExpr::Or(lhs, rhs) => {
            Ok(
                local_guard_satisfied(lhs, locals, local_var_types, enum_defs)?
                    || local_guard_satisfied(rhs, locals, local_var_types, enum_defs)?,
            )
        }
        ast::GuardExpr::Threshold(_) => Ok(true),
        ast::GuardExpr::HasCryptoObject { .. } => Ok(true),
        ast::GuardExpr::Timeout { .. } => Ok(true),
    }
}

pub(super) fn eval_local_comparison(
    lhs: &ast::Expr,
    op: ast::CmpOp,
    rhs: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<bool, LoweringError> {
    let lhs_bool = is_bool_expr(lhs, local_var_types);
    let rhs_bool = is_bool_expr(rhs, local_var_types);

    if lhs_bool || rhs_bool {
        if !lhs_bool || !rhs_bool {
            return Err(LoweringError::Unsupported(
                "Guard comparison mixes boolean and non-boolean values".into(),
            ));
        }
        let l = eval_bool_expr(lhs, locals)?;
        let r = eval_bool_expr(rhs, locals)?;
        return match op {
            ast::CmpOp::Eq => Ok(l == r),
            ast::CmpOp::Ne => Ok(l != r),
            _ => Err(LoweringError::Unsupported(
                "Only == and != comparisons are supported for booleans".into(),
            )),
        };
    }

    if let Some(enum_name) =
        expr_enum_type(lhs, local_var_types).or_else(|| expr_enum_type(rhs, local_var_types))
    {
        let l_var = eval_enum_expr(lhs, enum_name, locals, local_var_types, enum_defs)?;
        let r_var = eval_enum_expr(rhs, enum_name, locals, local_var_types, enum_defs)?;
        let l_idx = enum_variant_index(enum_name, &l_var, enum_defs)?;
        let r_idx = enum_variant_index(enum_name, &r_var, enum_defs)?;

        return Ok(match op {
            ast::CmpOp::Eq => l_idx == r_idx,
            ast::CmpOp::Ne => l_idx != r_idx,
            ast::CmpOp::Lt => l_idx < r_idx,
            ast::CmpOp::Le => l_idx <= r_idx,
            ast::CmpOp::Gt => l_idx > r_idx,
            ast::CmpOp::Ge => l_idx >= r_idx,
        });
    }

    // Fallback to integer comparison
    let l = eval_int_expr(lhs, locals)?;
    let r = eval_int_expr(rhs, locals)?;
    Ok(match op {
        ast::CmpOp::Eq => l == r,
        ast::CmpOp::Ne => l != r,
        ast::CmpOp::Lt => l < r,
        ast::CmpOp::Le => l <= r,
        ast::CmpOp::Gt => l > r,
        ast::CmpOp::Ge => l >= r,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold_guard(msg: &str) -> ast::GuardExpr {
        ast::GuardExpr::Threshold(ast::ThresholdGuard {
            op: ast::CmpOp::Ge,
            threshold: ast::LinearExpr::Const(1),
            message_type: msg.into(),
            message_args: vec![],
            distinct: false,
            distinct_role: None,
        })
    }

    #[test]
    fn dnf_raw_single_atom() {
        let g = threshold_guard("Vote");
        let clauses = guard_to_dnf_raw_clauses(&g);
        assert_eq!(clauses.len(), 1);
    }

    #[test]
    fn dnf_raw_or_splits() {
        let g = ast::GuardExpr::Or(
            Box::new(threshold_guard("A")),
            Box::new(threshold_guard("B")),
        );
        let clauses = guard_to_dnf_raw_clauses(&g);
        assert_eq!(clauses.len(), 2);
    }

    #[test]
    fn dnf_raw_and_distributes_over_or() {
        let g = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::Or(
                Box::new(threshold_guard("A")),
                Box::new(threshold_guard("B")),
            )),
            Box::new(threshold_guard("C")),
        );
        let clauses = guard_to_dnf_raw_clauses(&g);
        assert_eq!(clauses.len(), 2);
    }

    #[test]
    fn dnf_raw_nested_or() {
        let g = ast::GuardExpr::Or(
            Box::new(ast::GuardExpr::Or(
                Box::new(threshold_guard("A")),
                Box::new(threshold_guard("B")),
            )),
            Box::new(threshold_guard("C")),
        );
        let clauses = guard_to_dnf_raw_clauses(&g);
        assert_eq!(clauses.len(), 3);
    }

    #[test]
    fn dnf_deduplicates_clauses() {
        let g = ast::GuardExpr::Or(
            Box::new(threshold_guard("A")),
            Box::new(threshold_guard("A")),
        );
        let clauses = guard_to_dnf_clauses(&g);
        assert_eq!(clauses.len(), 1);
    }

    #[test]
    fn dnf_prunes_subsumed() {
        let g = ast::GuardExpr::Or(
            Box::new(threshold_guard("A")),
            Box::new(ast::GuardExpr::And(
                Box::new(threshold_guard("A")),
                Box::new(threshold_guard("B")),
            )),
        );
        let clauses = guard_to_dnf_clauses(&g);
        assert_eq!(clauses.len(), 1);
    }

    #[test]
    fn collect_conjuncts_single() {
        let g = threshold_guard("X");
        let mut out = Vec::new();
        collect_guard_conjuncts(&g, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn collect_conjuncts_nested_and() {
        let g = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::And(
                Box::new(threshold_guard("A")),
                Box::new(threshold_guard("B")),
            )),
            Box::new(threshold_guard("C")),
        );
        let mut out = Vec::new();
        collect_guard_conjuncts(&g, &mut out);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn normalize_sorts_and_deduplicates() {
        let g = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::And(
                Box::new(threshold_guard("B")),
                Box::new(threshold_guard("A")),
            )),
            Box::new(threshold_guard("A")),
        );
        let normalized = normalize_guard_clause(&g);
        assert_eq!(normalized.len(), 2);
        assert!(normalized[0].0 <= normalized[1].0);
    }

    #[test]
    fn subset_check_true() {
        let subset = vec!["a".to_string(), "c".to_string()];
        let superset = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(sorted_guard_keys_subset(&subset, &superset));
    }

    #[test]
    fn subset_check_false() {
        let subset = vec!["a".to_string(), "d".to_string()];
        let superset = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(!sorted_guard_keys_subset(&subset, &superset));
    }

    #[test]
    fn subset_larger_than_superset() {
        let subset = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let superset = vec!["a".to_string(), "b".to_string()];
        assert!(!sorted_guard_keys_subset(&subset, &superset));
    }

    #[test]
    fn subset_empty_is_always_subset() {
        let subset: Vec<String> = vec![];
        let superset = vec!["a".to_string()];
        assert!(sorted_guard_keys_subset(&subset, &superset));
    }

    #[test]
    fn local_guard_bool_var_satisfied() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("ready".into(), LocalValue::Bool(true));
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = ast::GuardExpr::BoolVar("ready".into());
        assert!(local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn local_guard_bool_var_not_satisfied() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("ready".into(), LocalValue::Bool(false));
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = ast::GuardExpr::BoolVar("ready".into());
        assert!(!local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn local_guard_threshold_always_true() {
        let locals: IndexMap<String, LocalValue> = IndexMap::new();
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = threshold_guard("Vote");
        assert!(local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn local_guard_and_both_true() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("a".into(), LocalValue::Bool(true));
        locals.insert("b".into(), LocalValue::Bool(true));
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::BoolVar("a".into())),
            Box::new(ast::GuardExpr::BoolVar("b".into())),
        );
        assert!(local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn local_guard_and_one_false() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("a".into(), LocalValue::Bool(true));
        locals.insert("b".into(), LocalValue::Bool(false));
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::BoolVar("a".into())),
            Box::new(ast::GuardExpr::BoolVar("b".into())),
        );
        assert!(!local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn local_guard_or_one_true() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("a".into(), LocalValue::Bool(false));
        locals.insert("b".into(), LocalValue::Bool(true));
        let types: IndexMap<String, LocalVarType> = IndexMap::new();
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        let g = ast::GuardExpr::Or(
            Box::new(ast::GuardExpr::BoolVar("a".into())),
            Box::new(ast::GuardExpr::BoolVar("b".into())),
        );
        assert!(local_guard_satisfied(&g, &locals, &types, &enums).unwrap());
    }

    #[test]
    fn eval_local_comparison_int_ge() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("x".into(), LocalValue::Int(5));
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("x".into(), LocalVarType::Int { min: 0, max: 10 });
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(eval_local_comparison(
            &ast::Expr::Var("x".into()),
            ast::CmpOp::Ge,
            &ast::Expr::IntLit(3),
            &locals,
            &types,
            &enums,
        )
        .unwrap());
    }

    #[test]
    fn eval_local_comparison_bool_eq() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("flag".into(), LocalValue::Bool(true));
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("flag".into(), LocalVarType::Bool);
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(eval_local_comparison(
            &ast::Expr::Var("flag".into()),
            ast::CmpOp::Eq,
            &ast::Expr::BoolLit(true),
            &locals,
            &types,
            &enums,
        )
        .unwrap());
    }

    #[test]
    fn eval_local_comparison_bool_gt_error() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("flag".into(), LocalValue::Bool(true));
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("flag".into(), LocalVarType::Bool);
        let enums: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(eval_local_comparison(
            &ast::Expr::Var("flag".into()),
            ast::CmpOp::Gt,
            &ast::Expr::BoolLit(false),
            &locals,
            &types,
            &enums,
        )
        .is_err());
    }

    #[test]
    fn eval_local_comparison_enum() {
        let mut locals: IndexMap<String, LocalValue> = IndexMap::new();
        locals.insert("view".into(), LocalValue::Enum("v1".into()));
        let mut types: IndexMap<String, LocalVarType> = IndexMap::new();
        types.insert("view".into(), LocalVarType::Enum("View".into()));
        let mut enums: IndexMap<String, Vec<String>> = IndexMap::new();
        enums.insert("View".into(), vec!["v0".into(), "v1".into(), "v2".into()]);
        assert!(eval_local_comparison(
            &ast::Expr::Var("view".into()),
            ast::CmpOp::Ge,
            &ast::Expr::Var("v0".into()),
            &locals,
            &types,
            &enums,
        )
        .unwrap());
    }

    #[test]
    fn sort_key_deterministic_for_and() {
        let g = ast::GuardExpr::And(
            Box::new(threshold_guard("B")),
            Box::new(threshold_guard("A")),
        );
        let key = guard_expr_sort_key(&g);
        assert!(key.starts_with("and("));
    }

    #[test]
    fn rebuild_single_conjunct() {
        let conjuncts = vec![("key".into(), threshold_guard("X"))];
        let rebuilt = rebuild_guard_clause(conjuncts);
        assert!(matches!(rebuilt, ast::GuardExpr::Threshold(_)));
    }

    #[test]
    fn rebuild_multiple_conjuncts() {
        let conjuncts = vec![
            ("a".into(), threshold_guard("A")),
            ("b".into(), threshold_guard("B")),
        ];
        let rebuilt = rebuild_guard_clause(conjuncts);
        assert!(matches!(rebuilt, ast::GuardExpr::And(_, _)));
    }
}
