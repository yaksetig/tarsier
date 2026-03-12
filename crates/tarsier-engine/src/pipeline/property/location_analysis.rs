//! Location grouping, guard parsing, reachability.

use crate::pipeline::*;

pub(crate) fn graph_reachable_locations(ta: &ThresholdAutomaton) -> HashSet<usize> {
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = ta
        .initial_locations
        .iter()
        .map(|id| id.as_usize())
        .collect();
    while let Some(lid) = stack.pop() {
        if !reachable.insert(lid) {
            continue;
        }
        for rule in &ta.rules {
            if rule.from.as_usize() == lid && !reachable.contains(&rule.to.as_usize()) {
                stack.push(rule.to.as_usize());
            }
        }
    }
    reachable
}

/// Parse `p.x == q.x` (optionally wrapped by outer `[]`) into `(p, q, x)`.
pub(crate) fn parse_qualified_eq(body: &ast::FormulaExpr) -> Option<(String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (
                ast::FormulaAtom::QualifiedVar {
                    object: lobj,
                    field,
                },
                ast::FormulaAtom::QualifiedVar {
                    object: robj,
                    field: rfield,
                },
            ) if field == rfield => Some((lobj.clone(), robj.clone(), field.clone())),
            _ => None,
        }
    } else {
        None
    }
}

/// Parse `p.x == true/false` (either orientation, optionally wrapped by outer `[]`).
pub(crate) fn parse_qualified_eq_bool(body: &ast::FormulaExpr) -> Option<(String, String, bool)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (ast::FormulaAtom::QualifiedVar { object, field }, ast::FormulaAtom::BoolLit(b)) => {
                Some((object.clone(), field.clone(), *b))
            }
            (ast::FormulaAtom::BoolLit(b), ast::FormulaAtom::QualifiedVar { object, field }) => {
                Some((object.clone(), field.clone(), *b))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Parse guarded agreement shape:
/// `(p.g == true && q.g == true) ==> (p.x == q.x)`.
pub(crate) fn parse_guarded_agreement(
    body: &ast::FormulaExpr,
) -> Option<(String, String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Implies(lhs, rhs) = body {
        let (var_l, var_r, decision_field) = parse_qualified_eq(rhs)?;
        let mut guards = Vec::new();
        if !collect_guard_comparisons(lhs, &mut guards) {
            return None;
        }
        if guards.len() != 2 {
            return None;
        }
        let (g1_var, g1_field, g1_val) = &guards[0];
        let (g2_var, g2_field, g2_val) = &guards[1];
        if g1_field != g2_field || !*g1_val || !*g2_val {
            return None;
        }
        if (g1_var == &var_l && g2_var == &var_r) || (g1_var == &var_r && g2_var == &var_l) {
            Some((g1_field.clone(), decision_field, var_l, var_r))
        } else {
            None
        }
    } else {
        None
    }
}

/// Strip any leading stack of outer `[]` wrappers.
pub(crate) fn strip_outer_always(body: &ast::FormulaExpr) -> &ast::FormulaExpr {
    if let ast::FormulaExpr::Always(inner) = body {
        strip_outer_always(inner)
    } else {
        body
    }
}

/// Collect boolean guard comparisons from a conjunction tree.
pub(crate) fn collect_guard_comparisons(
    expr: &ast::FormulaExpr,
    out: &mut Vec<(String, String, bool)>,
) -> bool {
    match expr {
        ast::FormulaExpr::And(lhs, rhs) => {
            collect_guard_comparisons(lhs, out) && collect_guard_comparisons(rhs, out)
        }
        ast::FormulaExpr::Comparison { .. } => {
            if let Some((var, field, val)) = parse_qualified_eq_bool(expr) {
                out.push((var, field, val));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub(crate) fn locs_by_bool_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<(Vec<usize>, Vec<usize>), PipelineError> {
    let mut true_locs = Vec::new();
    let mut false_locs = Vec::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            match val {
                LocalValue::Bool(b) => {
                    if *b {
                        true_locs.push(id);
                    } else {
                        false_locs.push(id);
                    }
                }
                _ => {
                    return Err(PipelineError::Property(format!(
                        "Local variable '{field}' in role '{role}' is not boolean."
                    )));
                }
            }
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown boolean local variable '{field}' in role '{role}'."
        )));
    }
    Ok((true_locs, false_locs))
}

pub(crate) fn locs_by_local_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

pub(crate) fn locs_by_local_var_with_guard(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    guard_field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found_field = false;
    let mut found_guard = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        let guard_val = match loc.local_vars.get(guard_field) {
            Some(LocalValue::Bool(b)) => {
                found_guard = true;
                *b
            }
            Some(_) => {
                return Err(PipelineError::Property(format!(
                    "Guard variable '{guard_field}' in role '{role}' is not boolean."
                )))
            }
            None => false,
        };
        if !guard_val {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found_field = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found_field || !found_guard {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' or guard '{guard_field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

pub(crate) fn build_conflicts_from_groups(
    groups: &std::collections::HashMap<LocalValue, Vec<usize>>,
    out: &mut Vec<(usize, usize)>,
) {
    let group_vec: Vec<&Vec<usize>> = groups.values().collect();
    for i in 0..group_vec.len() {
        for j in (i + 1)..group_vec.len() {
            for &li in group_vec[i] {
                for &lj in group_vec[j] {
                    out.push((li, lj));
                }
            }
        }
    }
}

pub(crate) fn is_safety_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(
        kind,
        ast::PropertyKind::Agreement
            | ast::PropertyKind::Validity
            | ast::PropertyKind::Safety
            | ast::PropertyKind::Invariant
    )
}

pub(crate) fn is_liveness_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(kind, ast::PropertyKind::Liveness)
}

pub(crate) fn has_safety_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind))
}

pub(crate) fn has_liveness_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_liveness_property_kind(p.node.kind))
}

pub(crate) fn collect_decided_goal_locs(ta: &ThresholdAutomaton) -> Vec<usize> {
    ta.locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.local_vars.get("decided") == Some(&LocalValue::Bool(true)))
        .map(|(id, _)| id)
        .collect()
}

pub(crate) fn collect_non_goal_reachable_locs(
    ta: &ThresholdAutomaton,
    goal_locs: &[usize],
) -> Vec<usize> {
    let reachable = graph_reachable_locations(ta);
    let goals: HashSet<usize> = goal_locs.iter().copied().collect();
    ta.locations
        .iter()
        .enumerate()
        .filter(|(id, _)| reachable.contains(id) && !goals.contains(id))
        .map(|(id, _)| id)
        .collect()
}

#[cfg(test)]
mod tests;
