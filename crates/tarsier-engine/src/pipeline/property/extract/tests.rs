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

fn forall(var: &str, domain: &str) -> ast::QuantifierBinding {
    ast::QuantifierBinding {
        quantifier: ast::Quantifier::ForAll,
        var: var.to_string(),
        domain: domain.to_string(),
    }
}

fn qvar(object: &str, field: &str) -> ast::FormulaAtom {
    ast::FormulaAtom::QualifiedVar {
        object: object.to_string(),
        field: field.to_string(),
    }
}

fn cmp(lhs: ast::FormulaAtom, op: ast::CmpOp, rhs: ast::FormulaAtom) -> ast::FormulaExpr {
    ast::FormulaExpr::Comparison { lhs, op, rhs }
}

fn make_prop(
    name: &str,
    kind: ast::PropertyKind,
    quantifiers: Vec<ast::QuantifierBinding>,
    body: ast::FormulaExpr,
) -> ast::PropertyDecl {
    ast::PropertyDecl {
        name: name.to_string(),
        kind,
        formula: ast::QuantifiedFormula { quantifiers, body },
    }
}

fn agreement_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    // Two locations with different phase values
    ta.locations.push(mk_loc(
        "Decide0",
        "R",
        vec![("phase", LocalValue::Enum("zero".into()))],
    ));
    ta.locations.push(mk_loc(
        "Decide1",
        "R",
        vec![("phase", LocalValue::Enum("one".into()))],
    ));
    ta.locations.push(mk_loc(
        "Init",
        "R",
        vec![("phase", LocalValue::Enum("init".into()))],
    ));
    ta.initial_locations = vec![2.into()];
    ta.rules.push(mk_rule(2, 0));
    ta.rules.push(mk_rule(2, 1));
    ta
}

// -- extract_property_from_decl: Agreement --

#[test]
fn extract_agreement_property_basic() {
    let ta = agreement_ta();
    let body = cmp(qvar("p", "phase"), ast::CmpOp::Eq, qvar("q", "phase"));
    let prop = make_prop(
        "agr",
        ast::PropertyKind::Agreement,
        vec![forall("p", "R"), forall("q", "R")],
        body,
    );
    let result = extract_property_from_decl(&ta, &prop).unwrap();
    match result {
        SafetyProperty::Agreement { conflicting_pairs } => {
            // "zero", "one", and "init" are 3 groups -> 3 conflict pairs
            assert!(!conflicting_pairs.is_empty());
        }
        _ => panic!("expected Agreement property"),
    }
}

#[test]
fn extract_agreement_wrong_quantifier_count_errors() {
    let ta = agreement_ta();
    let body = cmp(
        qvar("p", "phase"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let prop = make_prop(
        "agr",
        ast::PropertyKind::Agreement,
        vec![forall("p", "R")],
        body,
    );
    assert!(extract_property_from_decl(&ta, &prop).is_err());
}

#[test]
fn extract_agreement_different_roles_errors() {
    let ta = agreement_ta();
    let body = cmp(qvar("p", "phase"), ast::CmpOp::Eq, qvar("q", "phase"));
    let prop = make_prop(
        "agr",
        ast::PropertyKind::Agreement,
        vec![forall("p", "R"), forall("q", "S")],
        body,
    );
    assert!(extract_property_from_decl(&ta, &prop).is_err());
}

// -- extract_property_from_decl: Invariant --

#[test]
fn extract_invariant_property() {
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    ta.locations
        .push(mk_loc("Good", "R", vec![("valid", LocalValue::Bool(true))]));
    ta.locations
        .push(mk_loc("Bad", "R", vec![("valid", LocalValue::Bool(false))]));
    ta.initial_locations = vec![0.into()];
    ta.rules.push(mk_rule(0, 1));

    let body = cmp(
        qvar("p", "valid"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let prop = make_prop(
        "inv",
        ast::PropertyKind::Invariant,
        vec![forall("p", "R")],
        body,
    );
    let result = extract_property_from_decl(&ta, &prop).unwrap();
    match result {
        SafetyProperty::Invariant { bad_sets } => {
            // bad_sets should include location 1 (where valid=false)
            assert_eq!(bad_sets.len(), 1);
            assert_eq!(bad_sets[0].len(), 1);
            assert_eq!(bad_sets[0][0].as_usize(), 1);
        }
        _ => panic!("expected Invariant property"),
    }
}

// -- extract_property_from_decl: Liveness rejected --

#[test]
fn extract_liveness_property_errors() {
    let ta = agreement_ta();
    let body = cmp(
        qvar("p", "phase"),
        ast::CmpOp::Eq,
        ast::FormulaAtom::BoolLit(true),
    );
    let prop = make_prop(
        "live",
        ast::PropertyKind::Liveness,
        vec![forall("p", "R")],
        body,
    );
    let result = extract_property_from_decl(&ta, &prop);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Liveness properties are not safety properties"));
}

// -- TaExportProperty enum --

#[test]
fn ta_export_property_debug_format() {
    let prop = TaExportProperty::Safety(SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    });
    let debug = format!("{:?}", prop);
    assert!(debug.contains("Safety"));
}

// -- select_single_safety_property_decl --

#[test]
fn select_single_safety_strict_no_props_errors() {
    let program = ast::Program {
        protocol: ast::Spanned {
            node: ast::ProtocolDecl {
                name: "test".into(),
                imports: vec![],
                refines: None,
                modules: vec![],
                enums: vec![],
                parameters: vec![],
                resilience: None,
                pacemaker: None,
                adversary: vec![],
                timing: None,
                identities: vec![],
                channels: vec![],
                equivocation_policies: vec![],
                committees: vec![],
                dag_rounds: vec![],
                collections: vec![],
                clocks: vec![],
                messages: vec![],
                crypto_objects: vec![],
                roles: vec![],
                properties: vec![],
            },
            span: ast::Span { start: 0, end: 0 },
        },
    };
    let result = select_single_safety_property_decl(&program, SoundnessMode::Strict);
    assert!(result.is_err());
}

#[test]
fn select_single_safety_permissive_no_props_ok() {
    let program = ast::Program {
        protocol: ast::Spanned {
            node: ast::ProtocolDecl {
                name: "test".into(),
                imports: vec![],
                refines: None,
                modules: vec![],
                enums: vec![],
                parameters: vec![],
                resilience: None,
                pacemaker: None,
                adversary: vec![],
                timing: None,
                identities: vec![],
                channels: vec![],
                equivocation_policies: vec![],
                committees: vec![],
                dag_rounds: vec![],
                collections: vec![],
                clocks: vec![],
                messages: vec![],
                crypto_objects: vec![],
                roles: vec![],
                properties: vec![],
            },
            span: ast::Span { start: 0, end: 0 },
        },
    };
    let result = select_single_safety_property_decl(&program, SoundnessMode::Permissive);
    assert!(result.unwrap().is_none());
}
