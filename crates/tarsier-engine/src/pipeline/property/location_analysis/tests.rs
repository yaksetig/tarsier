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
