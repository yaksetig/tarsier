//! Unit tests for property lowering, evaluation, and temporal encodings.

use super::super::verification::pdr_kappa_var;
use crate::pipeline::property::*;
use crate::pipeline::*;
use tarsier_ir::threshold_automaton::{Guard, Location, Parameter, Rule};
use tarsier_smt::terms::SmtTerm;

fn qvar(object: &str, field: &str) -> ast::FormulaAtom {
    ast::FormulaAtom::QualifiedVar {
        object: object.to_string(),
        field: field.to_string(),
    }
}

fn cmp(lhs: ast::FormulaAtom, op: ast::CmpOp, rhs: ast::FormulaAtom) -> ast::FormulaExpr {
    ast::FormulaExpr::Comparison { lhs, op, rhs }
}

fn forall(var: &str, domain: &str) -> ast::QuantifierBinding {
    ast::QuantifierBinding {
        quantifier: ast::Quantifier::ForAll,
        var: var.to_string(),
        domain: domain.to_string(),
    }
}

fn exists(var: &str, domain: &str) -> ast::QuantifierBinding {
    ast::QuantifierBinding {
        quantifier: ast::Quantifier::Exists,
        var: var.to_string(),
        domain: domain.to_string(),
    }
}

fn liveness_prop(
    name: &str,
    quantifiers: Vec<ast::QuantifierBinding>,
    body: ast::FormulaExpr,
) -> ast::PropertyDecl {
    ast::PropertyDecl {
        name: name.to_string(),
        kind: ast::PropertyKind::Liveness,
        formula: ast::QuantifiedFormula { quantifiers, body },
    }
}

fn test_ta() -> ThresholdAutomaton {
    fn mk_loc(
        name: &str,
        role: &str,
        phase: &str,
        decided: bool,
        flag: bool,
        mode: &str,
        round: i64,
    ) -> Location {
        let mut loc = Location {
            name: name.to_string(),
            role: role.to_string(),
            phase: phase.to_string(),
            local_vars: Default::default(),
        };
        loc.local_vars
            .insert("decided".to_string(), LocalValue::Bool(decided));
        loc.local_vars
            .insert("flag".to_string(), LocalValue::Bool(flag));
        loc.local_vars
            .insert("mode".to_string(), LocalValue::Enum(mode.to_string()));
        loc.local_vars
            .insert("round".to_string(), LocalValue::Int(round));
        loc
    }

    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter {
        name: "n".to_string(),
        time_varying: false,
    });
    ta.locations
        .push(mk_loc("r0", "R", "p0", false, true, "Init", 0)); // 0
    ta.locations
        .push(mk_loc("r1", "R", "p1", true, true, "Commit", 1)); // 1
    ta.locations
        .push(mk_loc("r2", "R", "p2", false, false, "Alt", 2)); // 2
    ta.locations
        .push(mk_loc("s0", "S", "s0", false, true, "Other", 0)); // 3
    ta.locations
        .push(mk_loc("ghost", "R", "u", true, true, "Ghost", 99)); // 4 unreachable
    ta.initial_locations = vec![0.into(), 3.into()];

    ta.rules.push(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::trivial(),
        updates: vec![],
                    collection_updates: vec![],
                    param_updates: vec![],
    });
    ta.rules.push(Rule {
        from: 1.into(),
        to: 2.into(),
        guard: Guard::trivial(),
        updates: vec![],
                    collection_updates: vec![],
                    param_updates: vec![],
    });
    ta.rules.push(Rule {
        from: 3.into(),
        to: 3.into(),
        guard: Guard::trivial(),
        updates: vec![],
                    collection_updates: vec![],
                    param_updates: vec![],
    });
    ta
}

#[test]
fn parse_helpers_handle_outer_always_and_guarded_agreement_shape() {
    let eq = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Always(Box::new(cmp(
        qvar("p", "x"),
        ast::CmpOp::Eq,
        qvar("q", "x"),
    )))));
    assert_eq!(
        parse_qualified_eq(&eq),
        Some(("p".to_string(), "q".to_string(), "x".to_string()))
    );
    assert_eq!(
        parse_qualified_eq_bool(&cmp(
            ast::FormulaAtom::BoolLit(true),
            ast::CmpOp::Eq,
            qvar("p", "decided")
        )),
        Some(("p".to_string(), "decided".to_string(), true))
    );
    assert_eq!(
        parse_qualified_eq(&cmp(qvar("p", "x"), ast::CmpOp::Ne, qvar("q", "x"))),
        None
    );

    let guarded = ast::FormulaExpr::Implies(
        Box::new(ast::FormulaExpr::And(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
            Box::new(cmp(
                qvar("q", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
        )),
        Box::new(cmp(qvar("p", "vote"), ast::CmpOp::Eq, qvar("q", "vote"))),
    );
    assert_eq!(
        parse_guarded_agreement(&guarded),
        Some((
            "decided".to_string(),
            "vote".to_string(),
            "p".to_string(),
            "q".to_string()
        ))
    );
}

#[test]
fn collect_guard_comparisons_rejects_non_boolean_clauses() {
    let mut out = Vec::new();
    let expr = ast::FormulaExpr::And(
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )),
        Box::new(cmp(
            qvar("q", "round"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::IntLit(1),
        )),
    );
    assert!(!collect_guard_comparisons(&expr, &mut out));
    assert_eq!(out.len(), 1);
}

#[test]
fn reachability_and_goal_helpers_respect_unreachable_locations() {
    let ta = test_ta();
    let reachable = graph_reachable_locations(&ta);
    assert!(reachable.contains(&0));
    assert!(reachable.contains(&1));
    assert!(reachable.contains(&2));
    assert!(reachable.contains(&3));
    assert!(!reachable.contains(&4));

    assert_eq!(collect_decided_goal_locs(&ta), vec![1, 4]);
    assert_eq!(collect_non_goal_reachable_locs(&ta, &[1]), vec![0, 2, 3]);
}

#[test]
fn location_group_helpers_cover_success_and_error_branches() {
    let ta = test_ta();
    let reachable = graph_reachable_locations(&ta);

    let (true_locs, false_locs) =
        locs_by_bool_var(&ta, "R", "decided", &reachable).expect("bool grouping");
    assert_eq!(true_locs, vec![1]);
    assert_eq!(false_locs, vec![0, 2]);

    let err = locs_by_bool_var(&ta, "R", "mode", &reachable).expect_err("non-bool must fail");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("not boolean")),
        other => panic!("unexpected error: {other}"),
    }
    assert!(locs_by_bool_var(&ta, "R", "missing", &reachable).is_err());

    let by_mode = locs_by_local_var(&ta, "R", "mode", &reachable).expect("mode groups");
    assert_eq!(by_mode.len(), 3);
    assert_eq!(
        by_mode.get(&LocalValue::Enum("Init".to_string())).cloned(),
        Some(vec![0])
    );
    assert!(locs_by_local_var(&ta, "R", "missing", &reachable).is_err());

    let guarded =
        locs_by_local_var_with_guard(&ta, "R", "mode", "flag", &reachable).expect("guarded groups");
    assert_eq!(guarded.len(), 2);
    assert_eq!(
        guarded.get(&LocalValue::Enum("Init".to_string())).cloned(),
        Some(vec![0])
    );
    assert_eq!(
        guarded
            .get(&LocalValue::Enum("Commit".to_string()))
            .cloned(),
        Some(vec![1])
    );
    assert!(locs_by_local_var_with_guard(&ta, "R", "decided", "mode", &reachable).is_err());
    assert!(locs_by_local_var_with_guard(&ta, "R", "mode", "missing", &reachable).is_err());
}

#[test]
fn conflict_builder_emits_cartesian_pairs_across_distinct_value_groups() {
    let mut groups = std::collections::HashMap::new();
    groups.insert(LocalValue::Bool(true), vec![1, 2]);
    groups.insert(LocalValue::Bool(false), vec![5]);
    let mut out = Vec::new();
    build_conflicts_from_groups(&groups, &mut out);
    for (a, b) in &mut out {
        if *a > *b {
            std::mem::swap(a, b);
        }
    }
    out.sort_unstable();
    assert_eq!(out, vec![(1, 5), (2, 5)]);
}

#[test]
fn formula_atom_and_comparison_evaluation_enforces_type_rules() {
    let ta = test_ta();
    let loc = &ta.locations[0];

    assert_eq!(
        eval_formula_atom_on_location(&ast::FormulaAtom::IntLit(7), "p", loc).unwrap(),
        FormulaValue::Int(7)
    );
    assert_eq!(
        eval_formula_atom_on_location(&ast::FormulaAtom::Var("mode".to_string()), "p", loc)
            .unwrap(),
        FormulaValue::Enum("Init".to_string())
    );
    assert_eq!(
        eval_formula_atom_on_location(&ast::FormulaAtom::Var("UNRESOLVED".to_string()), "p", loc)
            .unwrap(),
        FormulaValue::Enum("UNRESOLVED".to_string())
    );
    assert!(eval_formula_atom_on_location(&qvar("q", "decided"), "p", loc).is_err());
    assert!(eval_formula_atom_on_location(&qvar("p", "missing"), "p", loc).is_err());

    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Bool(true),
        FormulaValue::Bool(true)
    )
    .unwrap());
    assert!(
        eval_formula_comparison(ast::CmpOp::Lt, FormulaValue::Int(1), FormulaValue::Int(2))
            .unwrap()
    );
    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Enum("A".to_string()),
        FormulaValue::Enum("A".to_string())
    )
    .unwrap());
    assert!(eval_formula_comparison(
        ast::CmpOp::Ge,
        FormulaValue::Bool(true),
        FormulaValue::Bool(false)
    )
    .is_err());
    assert!(eval_formula_comparison(
        ast::CmpOp::Gt,
        FormulaValue::Enum("A".to_string()),
        FormulaValue::Enum("B".to_string())
    )
    .is_err());
    assert!(eval_formula_comparison(
        ast::CmpOp::Eq,
        FormulaValue::Bool(true),
        FormulaValue::Int(1)
    )
    .is_err());
}

#[test]
fn formula_expr_eval_and_temporal_detection_cover_key_branches() {
    let ta = test_ta();
    let loc = &ta.locations[0];
    let decided_false = cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(false),
    );
    let round_is_zero = cmp(
        qvar("p", "round"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::IntLit(0),
    );
    let round_is_one = cmp(
        qvar("p", "round"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::IntLit(1),
    );

    assert!(eval_formula_expr_on_location(
        &ast::FormulaExpr::And(
            Box::new(decided_false.clone()),
            Box::new(round_is_zero.clone())
        ),
        "p",
        loc
    )
    .unwrap());
    assert!(!eval_formula_expr_on_location(
        &ast::FormulaExpr::Or(
            Box::new(round_is_one.clone()),
            Box::new(ast::FormulaExpr::Not(Box::new(round_is_zero.clone())))
        ),
        "p",
        loc
    )
    .unwrap());
    assert!(eval_formula_expr_on_location(
        &ast::FormulaExpr::Implies(
            Box::new(round_is_one.clone()),
            Box::new(round_is_zero.clone())
        ),
        "p",
        loc
    )
    .unwrap());
    assert!(eval_formula_expr_on_location(
        &ast::FormulaExpr::Iff(
            Box::new(decided_false.clone()),
            Box::new(decided_false.clone())
        ),
        "p",
        loc
    )
    .unwrap());
    assert!(eval_formula_expr_on_location(
        &ast::FormulaExpr::Always(Box::new(decided_false.clone())),
        "p",
        loc
    )
    .is_err());

    assert!(!formula_contains_temporal(&decided_false));
    assert!(formula_contains_temporal(&ast::FormulaExpr::Eventually(
        Box::new(round_is_zero)
    )));
}

#[test]
fn temporal_simplifiers_and_nnf_translation_behave_canonically() {
    assert_eq!(
        temporal_and(TemporalFormula::False, TemporalFormula::Atom(1)),
        TemporalFormula::False
    );
    assert_eq!(
        temporal_and(TemporalFormula::Atom(2), TemporalFormula::Atom(1)),
        TemporalFormula::And(
            Box::new(TemporalFormula::Atom(1)),
            Box::new(TemporalFormula::Atom(2))
        )
    );
    assert_eq!(
        temporal_or(TemporalFormula::False, TemporalFormula::Atom(1)),
        TemporalFormula::Atom(1)
    );
    assert_eq!(
        temporal_until(TemporalFormula::False, TemporalFormula::Atom(3)),
        TemporalFormula::Atom(3)
    );
    assert_eq!(
        temporal_release(TemporalFormula::True, TemporalFormula::Atom(4)),
        TemporalFormula::Atom(4)
    );

    let mut atoms = TemporalAtomTable::default();
    let weak = ast::FormulaExpr::WeakUntil(
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(false),
        )),
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )),
    );
    let nnf = formula_to_temporal_nnf(&weak, &mut atoms, false).expect("weak-until nnf");
    let mut untils = BTreeSet::new();
    collect_until_formulas(&nnf, &mut untils);
    assert!(!untils.is_empty());
    assert!(!temporal_formula_canonical(&nnf).is_empty());
}

#[test]
fn temporal_seed_expansion_handles_conflicts_dedup_and_branching() {
    let mut todo = vec![TemporalFormula::Atom(1)];
    let mut old = BTreeSet::new();
    old.insert(TemporalFormula::Atom(0));
    temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(0));
    temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(1));
    temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(2));
    assert_eq!(todo.len(), 2);

    let conflict_seed = BTreeSet::from([TemporalFormula::Atom(0), TemporalFormula::NotAtom(0)]);
    let conflict_outcomes = expand_temporal_seed(&conflict_seed);
    assert!(conflict_outcomes.is_empty());

    let or_seed = BTreeSet::from([TemporalFormula::Or(
        Box::new(TemporalFormula::Atom(0)),
        Box::new(TemporalFormula::Atom(1)),
    )]);
    let outcomes = expand_temporal_seed(&or_seed);
    assert_eq!(outcomes.len(), 2);
}

#[test]
fn temporal_compilation_and_encoding_helpers_cover_boundary_branches() {
    let ta = test_ta();
    let always_true = ast::FormulaExpr::Always(Box::new(cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    )));
    let monitor = compile_temporal_buchi_automaton(ast::Quantifier::ForAll, "p", "R", &always_true)
        .expect("temporal compile");
    assert!(!monitor.states.is_empty());
    assert!(!monitor.initial_states.is_empty());
    let canonical = temporal_buchi_monitor_canonical(&monitor);
    assert!(canonical.contains("quantifier=forall;quantified_var=p;role=R"));

    let decided_true = cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let state_term = build_quantified_state_predicate_term(
        &ta,
        ast::Quantifier::ForAll,
        "p",
        "R",
        &decided_true,
        2,
    )
    .unwrap();
    assert_eq!(
        state_term,
        SmtTerm::and(vec![
            SmtTerm::var(pdr_kappa_var(2, 0)).eq(SmtTerm::int(0)),
            SmtTerm::var(pdr_kappa_var(2, 2)).eq(SmtTerm::int(0)),
        ])
    );

    let always_nonnegative = cmp(
        qvar("p", "round"),
        ast::CmpOp::Ge,
        ast::FormulaAtom::IntLit(0),
    );
    assert_eq!(
        build_quantified_state_predicate_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &always_nonnegative,
            0,
        )
        .unwrap(),
        SmtTerm::bool(true)
    );
    assert_eq!(
        build_quantified_state_predicate_term(
            &ta,
            ast::Quantifier::Exists,
            "p",
            "R",
            &decided_true,
            0,
        )
        .unwrap(),
        SmtTerm::or(vec![
            SmtTerm::var(pdr_kappa_var(0, 1)).gt(SmtTerm::int(0)),
            SmtTerm::var(pdr_kappa_var(0, 4)).gt(SmtTerm::int(0)),
        ])
    );
    assert_eq!(
        build_quantified_state_predicate_term(
            &ta,
            ast::Quantifier::Exists,
            "p",
            "R",
            &cmp(
                qvar("p", "round"),
                ast::CmpOp::Gt,
                ast::FormulaAtom::IntLit(1000)
            ),
            0,
        )
        .unwrap(),
        SmtTerm::bool(false)
    );

    assert_eq!(
        encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &decided_true,
            3,
            2,
        )
        .unwrap(),
        SmtTerm::bool(false)
    );
    assert_eq!(
        encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &ast::FormulaExpr::Next(Box::new(decided_true.clone())),
            2,
            2
        )
        .unwrap(),
        SmtTerm::bool(false)
    );
    assert_eq!(
        encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &decided_true,
            1,
            2,
        )
        .unwrap(),
        build_quantified_state_predicate_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &decided_true,
            1,
        )
        .unwrap()
    );

    let weak_until = ast::FormulaExpr::WeakUntil(
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(false),
        )),
        Box::new(decided_true.clone()),
    );
    match encode_quantified_temporal_formula_term(
        &ta,
        ast::Quantifier::ForAll,
        "p",
        "R",
        &weak_until,
        0,
        2,
    )
    .unwrap()
    {
        SmtTerm::Or(parts) => assert_eq!(parts.len(), 2),
        other => panic!("expected weak-until desugaring to OR, got {other:?}"),
    }

    let release_lhs = cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(false),
    );
    let release_rhs = decided_true.clone();
    let release =
        ast::FormulaExpr::Release(Box::new(release_lhs.clone()), Box::new(release_rhs.clone()));
    let release_dual = ast::FormulaExpr::Not(Box::new(ast::FormulaExpr::Until(
        Box::new(ast::FormulaExpr::Not(Box::new(release_lhs))),
        Box::new(ast::FormulaExpr::Not(Box::new(release_rhs))),
    )));
    let release_term = encode_quantified_temporal_formula_term(
        &ta,
        ast::Quantifier::ForAll,
        "p",
        "R",
        &release,
        0,
        2,
    )
    .unwrap();
    let release_dual_term = encode_quantified_temporal_formula_term(
        &ta,
        ast::Quantifier::ForAll,
        "p",
        "R",
        &release_dual,
        0,
        2,
    )
    .unwrap();
    match release_term {
        SmtTerm::And(parts) => assert_eq!(parts.len(), 3),
        other => panic!("expected release expansion to AND, got {other:?}"),
    }
    match release_dual_term {
        SmtTerm::Not(_) => {}
        other => panic!("expected release dual form to be wrapped by NOT, got {other:?}"),
    }
}

#[test]
fn liveness_extraction_and_target_resolution_cover_error_and_success_paths() {
    let ta = test_ta();
    let propositional = cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let temporal = ast::FormulaExpr::Eventually(Box::new(propositional.clone()));

    let err =
        extract_liveness_spec_from_decl(&ta, &liveness_prop("bad", vec![], propositional.clone()))
            .expect_err("missing quantifier must fail");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("at least 1 quantifier")),
        other => panic!("unexpected error: {other}"),
    }
    let err = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "bad_role",
            vec![forall("p", "UnknownRole")],
            propositional.clone(),
        ),
    )
    .expect_err("unknown role must fail");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("unknown role")),
        other => panic!("unexpected error: {other}"),
    }

    let spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "live_extra_forall",
            vec![forall("p", "R"), forall("q", "R")],
            propositional.clone(),
        ),
    )
    .expect("unused universal quantifier should be accepted");
    match spec {
        LivenessSpec::TerminationGoalLocs(goal_locs) => assert_eq!(goal_locs, vec![1, 3]),
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let err = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "bad_extra_exists",
            vec![forall("p", "R"), exists("q", "R")],
            propositional.clone(),
        ),
    )
    .expect_err("unused existential quantifier should be rejected");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("unused universal")),
        other => panic!("unexpected error: {other}"),
    }

    let spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop("live", vec![forall("p", "R")], propositional.clone()),
    )
    .expect("propositional liveness should compile");
    match spec.clone() {
        LivenessSpec::TerminationGoalLocs(goal_locs) => assert_eq!(goal_locs, vec![1, 3]),
        other => panic!("expected termination spec, got {other:?}"),
    }

    let temporal_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop("live_t", vec![forall("p", "R")], temporal),
    )
    .expect("temporal liveness should compile");
    match temporal_spec.clone() {
        LivenessSpec::Temporal { quantifiers, .. } => {
            assert_eq!(quantifiers, vec![forall("p", "R")]);
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let exists_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop("exists_live", vec![exists("p", "R")], propositional.clone()),
    )
    .expect("existential liveness should compile");
    match exists_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![exists("p", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(propositional.clone()))
            );
        }
        other => panic!("expected temporal exists spec, got {other:?}"),
    }

    match fair_liveness_target_from_spec(&ta, spec).expect("termination target") {
        FairLivenessTarget::NonGoalLocs(locs) => assert_eq!(locs, vec![0, 2]),
        other => panic!("expected non-goal target, got {other:?}"),
    }
    match fair_liveness_target_from_spec(&ta, temporal_spec).expect("temporal target") {
        FairLivenessTarget::Temporal(automaton) => assert!(!automaton.states.is_empty()),
        other => panic!("expected temporal target, got {other:?}"),
    }
}

#[test]
fn liveness_multi_quantifier_normalization_enforces_soundness_guards() {
    let ta = test_ta();

    let forall_multi_ref_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "forall_multi_ref",
            vec![forall("p", "R"), forall("q", "R")],
            ast::FormulaExpr::And(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            ),
        ),
    )
    .expect("propositional forall multi-ref should route to temporal monitoring");
    match forall_multi_ref_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                )))
            );
        }
        other => panic!("expected termination spec, got {other:?}"),
    }

    let exists_multi_ref_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "exists_multi_ref_or",
            vec![exists("p", "R"), exists("q", "R")],
            ast::FormulaExpr::Or(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            ),
        ),
    )
    .expect("disjunctive exists multi-ref should preserve both quantified refs");
    match exists_multi_ref_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![exists("p", "R"), exists("q", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::Or(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                )))
            );
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let err = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_extra_exists",
            vec![forall("p", "R"), forall("q", "R"), exists("z", "R")],
            ast::FormulaExpr::And(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            ),
        ),
    )
    .expect_err("unreferenced existential extras should be rejected in multi-ref path");
    match err {
        PipelineError::Property(msg) => assert!(msg.contains("unsupported existential extras")),
        other => panic!("unexpected error: {other}"),
    }

    let mixed_quantifiers_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_mixed_quantifiers",
            vec![forall("p", "R"), exists("q", "R")],
            ast::FormulaExpr::And(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            ),
        ),
    )
    .expect("mixed quantifier kinds in multi-ref liveness should be supported");
    match mixed_quantifiers_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), exists("q", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                )))
            );
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let mixed_roles_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_mixed_roles",
            vec![forall("p", "R"), forall("q", "S")],
            ast::FormulaExpr::And(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            ),
        ),
    )
    .expect("mixed roles in multi-ref liveness should be supported");
    match mixed_roles_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "S")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                )))
            );
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let temporal_formula = ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )),
        Box::new(cmp(
            qvar("q", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )),
    )));
    let temporal_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_temporal",
            vec![forall("p", "R"), forall("q", "R")],
            temporal_formula.clone(),
        ),
    )
    .expect("temporal multi-ref liveness should now be supported");
    match temporal_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
            assert_eq!(formula, temporal_formula);
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let mixed_temporal = ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
        Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )),
        Box::new(cmp(
            qvar("q", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(false),
        )),
    )));
    let mixed_temporal_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_temporal_mixed",
            vec![forall("p", "R"), exists("q", "S")],
            mixed_temporal.clone(),
        ),
    )
    .expect("temporal multi-ref with mixed quantifier/role should be supported");
    match mixed_temporal_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), exists("q", "S")]);
            assert_eq!(formula, mixed_temporal);
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let cross_compare_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_cross_compare",
            vec![forall("p", "R"), forall("q", "R")],
            cmp(qvar("p", "decided"), ast::CmpOp::Eq, qvar("q", "decided")),
        ),
    )
    .expect("cross-variable comparisons should be supported via temporal monitoring");
    match cross_compare_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    qvar("q", "decided")
                )))
            );
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }

    let complex_multi_ref = ast::FormulaExpr::Iff(
        Box::new(ast::FormulaExpr::Not(Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )))),
        Box::new(ast::FormulaExpr::Implies(
            Box::new(cmp(
                qvar("q", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                qvar("q", "decided"),
            )),
        )),
    );
    let complex_multi_ref_spec = extract_liveness_spec_from_decl(
        &ta,
        &liveness_prop(
            "multi_ref_not_implies_iff",
            vec![forall("p", "R"), forall("q", "R")],
            complex_multi_ref.clone(),
        ),
    )
    .expect("complex multi-ref propositional forms should be supported");
    match complex_multi_ref_spec {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
            assert_eq!(
                formula,
                ast::FormulaExpr::Eventually(Box::new(complex_multi_ref))
            );
        }
        other => panic!("expected temporal spec, got {other:?}"),
    }
}

#[test]
fn safety_kind_exists_predicate_is_wrapped_as_always_temporal_spec() {
    let ta = test_ta();
    let body = cmp(
        qvar("p", "decided"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let prop = ast::PropertyDecl {
        name: "safe_exists".to_string(),
        kind: ast::PropertyKind::Safety,
        formula: ast::QuantifiedFormula {
            quantifiers: vec![exists("p", "R")],
            body: body.clone(),
        },
    };
    match extract_liveness_spec_from_decl(&ta, &prop).expect("safety exists wraps to temporal") {
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => {
            assert_eq!(quantifiers, vec![exists("p", "R")]);
            assert_eq!(formula, ast::FormulaExpr::Always(Box::new(body)));
        }
        other => panic!("expected wrapped temporal spec, got {other:?}"),
    }
}

#[test]
fn extract_liveness_spec_program_level_and_param_resolution_helpers_work() {
    let ta = test_ta();

    let src_no_liveness = r#"
protocol NoLive {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let program = tarsier_dsl::parse(src_no_liveness, "no_live.trs").expect("parse");
    match extract_liveness_spec(&ta, &program).expect("default liveness spec") {
        LivenessSpec::TerminationGoalLocs(goal_locs) => {
            assert_eq!(goal_locs, collect_decided_goal_locs(&ta))
        }
        other => panic!("expected default decided-goal spec, got {other:?}"),
    }

    let src_multi = r#"
protocol MultiLive {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property l1: liveness {
        forall p: R. p.decided == true
    }
    property l2: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
    let program_multi = tarsier_dsl::parse(src_multi, "multi_live.trs").expect("parse");
    assert!(extract_liveness_spec(&ta, &program_multi).is_err());

    assert_eq!(
        resolve_param_or_const(&ParamOrConst::Const(7), &ta).unwrap(),
        7
    );
    assert!(resolve_param_or_const(&ParamOrConst::Param(0.into()), &ta).is_err());
}

#[test]
fn property_kind_helpers_and_program_scans_are_consistent() {
    assert!(is_safety_property_kind(ast::PropertyKind::Agreement));
    assert!(is_safety_property_kind(ast::PropertyKind::Safety));
    assert!(!is_safety_property_kind(ast::PropertyKind::Liveness));
    assert!(is_liveness_property_kind(ast::PropertyKind::Liveness));
    assert!(!is_liveness_property_kind(ast::PropertyKind::Invariant));

    let src = r#"
protocol KindScan {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
    let program = tarsier_dsl::parse(src, "kind_scan.trs").expect("parse");
    assert!(has_safety_properties(&program));
    assert!(has_liveness_properties(&program));
}

#[test]
fn select_property_for_ta_export_prefers_liveness_termination_when_no_safety() {
    let src = r#"
protocol ExportTerminationOnly {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property termination: liveness {
        forall p: Replica. p.decided == true
    }
}
"#;
    let program = tarsier_dsl::parse(src, "export_term_only.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    match select_property_for_ta_export(&ta, &program) {
        SafetyProperty::Termination { goal_locs } => {
            assert!(
                !goal_locs.is_empty(),
                "termination goals should be non-empty"
            );
        }
        other => panic!("expected termination export property, got {other:?}"),
    }
}

#[test]
fn select_property_for_ta_export_falls_back_from_temporal_liveness() {
    let src = r#"
protocol ExportTemporalLiveness {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_decide: liveness {
        forall p: Replica. <> (p.decided == true)
    }
}
"#;
    let program = tarsier_dsl::parse(src, "export_temporal.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    match select_property_for_ta_export(&ta, &program) {
        SafetyProperty::Agreement { .. } => {}
        other => panic!("expected agreement fallback for temporal liveness, got {other:?}"),
    }
}

#[test]
fn select_ta_export_property_preserves_temporal_liveness() {
    let src = r#"
protocol ExportTemporalLiveness {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_decide: liveness {
        forall p: Replica. <> (p.decided == true)
    }
}
"#;
    let program = tarsier_dsl::parse(src, "export_temporal_selector.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");

    match select_ta_export_property(&ta, &program) {
        TaExportProperty::Temporal {
            quantifiers,
            formula,
        } => {
            assert_eq!(quantifiers.len(), 1, "expected one temporal quantifier");
            assert!(
                formula_contains_temporal(&formula),
                "expected preserved temporal formula"
            );
        }
        other => panic!("expected temporal export property, got {other:?}"),
    }
}
