//! Guard expression lowering and DNF normalization.

use indexmap::IndexMap;
use std::collections::HashSet;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::counters::resolve_message_counter_from_guard;
use super::helpers::{
    enum_variant_index, eval_bool_expr, eval_enum_expr, eval_int_expr, expr_enum_type,
    is_bool_expr, lower_cmp_op, lower_linear_expr_to_lc,
};
use super::{LocalVarType, LoweringError, MessageInfo};

#[allow(clippy::too_many_arguments)]
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
            let var_ids = resolve_message_counter_from_guard(
                &tg.message_type,
                ctx.recipient_channel,
                &tg.message_args,
                sender_role,
                ctx.role_channels,
                ctx.message_infos,
                ctx.msg_vars,
                ctx.locals,
                ctx.local_var_types,
                ctx.enum_defs,
            )?;
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
            let var_ids = resolve_message_counter_from_guard(
                object_name,
                ctx.recipient_channel,
                object_args,
                None,
                ctx.role_channels,
                ctx.message_infos,
                ctx.msg_vars,
                ctx.locals,
                ctx.local_var_types,
                ctx.enum_defs,
            )?;
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
