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
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::*;

    fn mk_loc(name: &str, role: &str, vars: Vec<(&str, LocalValue)>) -> Location {
        let mut loc = Location {
            name: name.into(),
            role: role.into(),
            phase: name.to_lowercase(),
            local_vars: Default::default(),
        };
        for (k, v) in vars {
            loc.local_vars.insert(k.to_string(), v);
        }
        loc
    }

    fn mk_rule(from: usize, to: usize) -> Rule {
        Rule {
            from: from.into(),
            to: to.into(),
            guard: Guard { atoms: vec![] },
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        }
    }

    fn simple_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.locations.push(mk_loc("Init", "R", vec![]));
        ta.locations.push(mk_loc("Mid", "R", vec![]));
        ta.locations.push(mk_loc("Done", "R", vec![]));
        ta.initial_locations = vec![0.into()];
        ta.rules.push(mk_rule(0, 1));
        ta.rules.push(mk_rule(1, 2));
        ta
    }

    #[test]
    fn reachable_locations_all_connected() {
        let ta = simple_ta();
        let reachable = graph_reachable_locations(&ta);
        assert_eq!(reachable.len(), 3);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
    }

    #[test]
    fn reachable_locations_disconnected() {
        let mut ta = ThresholdAutomaton::new();
        ta.locations.push(mk_loc("A", "R", vec![]));
        ta.locations.push(mk_loc("B", "R", vec![]));
        ta.initial_locations = vec![0.into()];
        let reachable = graph_reachable_locations(&ta);
        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&0));
        assert!(!reachable.contains(&1));
    }

    #[test]
    fn strip_always_unwraps() {
        let inner = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::IntLit(1),
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::IntLit(1),
        };
        let wrapped = ast::FormulaExpr::Always(Box::new(inner));
        let result = strip_outer_always(&wrapped);
        assert!(matches!(result, ast::FormulaExpr::Comparison { .. }));
    }

    #[test]
    fn strip_always_nested() {
        let inner = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::IntLit(1),
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::IntLit(1),
        };
        let double = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Always(Box::new(inner))));
        let result = strip_outer_always(&double);
        assert!(matches!(result, ast::FormulaExpr::Comparison { .. }));
    }

    #[test]
    fn strip_always_non_always_passthrough() {
        let expr = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::IntLit(1),
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::IntLit(1),
        };
        let result = strip_outer_always(&expr);
        assert!(std::ptr::eq(result, &expr));
    }

    #[test]
    fn parse_qualified_eq_basic() {
        let expr = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::QualifiedVar {
                object: "p".into(),
                field: "x".into(),
            },
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::QualifiedVar {
                object: "q".into(),
                field: "x".into(),
            },
        };
        assert_eq!(
            parse_qualified_eq(&expr),
            Some(("p".into(), "q".into(), "x".into()))
        );
    }

    #[test]
    fn parse_qualified_eq_different_fields_none() {
        let expr = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::QualifiedVar {
                object: "p".into(),
                field: "x".into(),
            },
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::QualifiedVar {
                object: "q".into(),
                field: "y".into(),
            },
        };
        assert_eq!(parse_qualified_eq(&expr), None);
    }

    #[test]
    fn parse_qualified_eq_bool_true() {
        let expr = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::QualifiedVar {
                object: "p".into(),
                field: "decided".into(),
            },
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::BoolLit(true),
        };
        assert_eq!(
            parse_qualified_eq_bool(&expr),
            Some(("p".into(), "decided".into(), true))
        );
    }

    #[test]
    fn parse_qualified_eq_bool_reversed() {
        let expr = ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::BoolLit(false),
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::QualifiedVar {
                object: "p".into(),
                field: "done".into(),
            },
        };
        assert_eq!(
            parse_qualified_eq_bool(&expr),
            Some(("p".into(), "done".into(), false))
        );
    }

    #[test]
    fn safety_property_kinds() {
        assert!(is_safety_property_kind(ast::PropertyKind::Agreement));
        assert!(is_safety_property_kind(ast::PropertyKind::Invariant));
        assert!(is_safety_property_kind(ast::PropertyKind::Safety));
        assert!(is_safety_property_kind(ast::PropertyKind::Validity));
        assert!(!is_safety_property_kind(ast::PropertyKind::Liveness));
    }

    #[test]
    fn liveness_property_kind() {
        assert!(is_liveness_property_kind(ast::PropertyKind::Liveness));
        assert!(!is_liveness_property_kind(ast::PropertyKind::Safety));
    }

    #[test]
    fn locs_by_bool_var_partitions() {
        let mut ta = ThresholdAutomaton::new();
        ta.locations
            .push(mk_loc("A", "R", vec![("d", LocalValue::Bool(true))]));
        ta.locations
            .push(mk_loc("B", "R", vec![("d", LocalValue::Bool(false))]));
        ta.locations
            .push(mk_loc("C", "R", vec![("d", LocalValue::Bool(true))]));
        let reachable: HashSet<usize> = [0, 1, 2].into();
        let (true_locs, false_locs) = locs_by_bool_var(&ta, "R", "d", &reachable).unwrap();
        assert_eq!(true_locs, vec![0, 2]);
        assert_eq!(false_locs, vec![1]);
    }

    #[test]
    fn locs_by_bool_var_unknown_field_error() {
        let mut ta = ThresholdAutomaton::new();
        ta.locations.push(mk_loc("A", "R", vec![]));
        let reachable: HashSet<usize> = [0].into();
        assert!(locs_by_bool_var(&ta, "R", "d", &reachable).is_err());
    }

    #[test]
    fn conflicts_from_two_groups() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(LocalValue::Int(1), vec![0, 1]);
        groups.insert(LocalValue::Int(2), vec![2]);
        let mut conflicts = Vec::new();
        build_conflicts_from_groups(&groups, &mut conflicts);
        assert_eq!(conflicts.len(), 2);
    }

    #[test]
    fn conflicts_from_single_group_empty() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(LocalValue::Int(1), vec![0, 1, 2]);
        let mut conflicts = Vec::new();
        build_conflicts_from_groups(&groups, &mut conflicts);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn decided_goal_locs_collected() {
        let mut ta = ThresholdAutomaton::new();
        ta.locations.push(mk_loc(
            "Init",
            "R",
            vec![("decided", LocalValue::Bool(false))],
        ));
        ta.locations.push(mk_loc(
            "Done",
            "R",
            vec![("decided", LocalValue::Bool(true))],
        ));
        ta.locations.push(mk_loc(
            "Also",
            "R",
            vec![("decided", LocalValue::Bool(true))],
        ));
        let goals = collect_decided_goal_locs(&ta);
        assert_eq!(goals, vec![1, 2]);
    }

    #[test]
    fn non_goal_reachable_locs() {
        let ta = simple_ta();
        let non_goal = collect_non_goal_reachable_locs(&ta, &[2]);
        assert_eq!(non_goal, vec![0, 1]);
    }
}
