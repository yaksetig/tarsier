use super::*;
use tarsier_ir::threshold_automaton::*;
use tarsier_smt::backends::z3_backend::Z3Solver;

/// Build a minimal counter system with two locations and one transition.
fn simple_two_location_system() -> CounterSystem {
    let mut ta = ThresholdAutomaton::new();
    let loc_a = ta.add_location(Location {
        name: "A".into(),
        role: "R".into(),
        phase: "0".into(),
        local_vars: Default::default(),
    });
    let loc_b = ta.add_location(Location {
        name: "B".into(),
        role: "R".into(),
        phase: "1".into(),
        local_vars: Default::default(),
    });
    ta.initial_locations.push(loc_a);
    ta.rules.push(Rule {
        from: loc_a,
        to: loc_b,
        guard: Guard::trivial(),
        updates: Vec::new(),
        collection_updates: Vec::new(),
        clock_guards: Vec::new(),
        clock_updates: Vec::new(),
        param_updates: Vec::new(),
    });
    ta
}

#[test]
fn extract_state_variables_includes_locations_and_shared_vars() {
    let mut cs = simple_two_location_system();
    cs.shared_vars.push(SharedVar {
        name: "msg_count".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let vars = extract_state_variables(&cs);
    assert_eq!(vars.len(), 3); // 2 locations + 1 shared var
    assert_eq!(vars[0].0, "kappa[A]");
    assert_eq!(vars[1].0, "kappa[B]");
    assert_eq!(vars[2].0, "gamma[msg_count]");
}

#[test]
fn build_ranking_template_produces_correct_number_of_coefficients() {
    let state_vars = vec![
        ("x".to_string(), SmtSort::Int),
        ("y".to_string(), SmtSort::Int),
    ];
    let (_term, coeff_names) = build_ranking_template(&state_vars, "s", "c");
    assert_eq!(coeff_names.len(), 3); // c_0, c_1, c_2
    assert_eq!(coeff_names[0], "c_0");
    assert_eq!(coeff_names[1], "c_1");
    assert_eq!(coeff_names[2], "c_2");
}

#[test]
fn try_ranking_function_proof_returns_not_found_when_no_state_vars() {
    let cs = CounterSystem::from(ThresholdAutomaton::new());
    let mut solver = Z3Solver::with_timeout_secs(2);
    let target = FairLivenessTarget::NonGoalLocs(vec![]);
    let result = try_ranking_function_proof(&mut solver, &cs, &target, &RankingConfig::default())
        .expect("ranking proof should return a result");
    match result {
        RankingResult::NotFound { reason } => {
            assert!(reason.contains("No state variables"));
        }
        other => panic!("expected NotFound for empty state vars, got {other:?}"),
    }
}

#[test]
fn try_ranking_function_proof_returns_not_found_when_no_rules() {
    let mut cs = simple_two_location_system();
    cs.rules.clear();
    let mut solver = Z3Solver::with_timeout_secs(2);
    let target = FairLivenessTarget::NonGoalLocs(vec![0]);
    let result = try_ranking_function_proof(&mut solver, &cs, &target, &RankingConfig::default())
        .expect("ranking proof should return a result");
    match result {
        RankingResult::NotFound { reason } => {
            assert!(reason.contains("No transition rules"));
        }
        other => panic!("expected NotFound for no rules, got {other:?}"),
    }
}

#[test]
fn try_ranking_function_proof_returns_not_found_when_max_coefficients_zero() {
    let cs = simple_two_location_system();
    let mut solver = Z3Solver::with_timeout_secs(2);
    let target = FairLivenessTarget::NonGoalLocs(vec![0]);
    let config = RankingConfig {
        max_coefficients: Some(0),
        ..RankingConfig::default()
    };
    let result = try_ranking_function_proof(&mut solver, &cs, &target, &config)
        .expect("ranking proof should return a result");
    match result {
        RankingResult::NotFound { reason } => {
            assert!(reason.contains("max_coefficients is zero"));
        }
        other => panic!("expected NotFound for zero max_coefficients, got {other:?}"),
    }
}

#[test]
fn try_ranking_function_proof_uses_lexicographic_variant_when_requested() {
    let cs = simple_two_location_system();
    let mut solver = Z3Solver::with_timeout_secs(2);
    let target = FairLivenessTarget::NonGoalLocs(vec![0]);
    let config = RankingConfig {
        max_lexicographic_components: 2,
        ..RankingConfig::default()
    };
    let result = try_ranking_function_proof(&mut solver, &cs, &target, &config)
        .expect("ranking proof should return a result");
    match result {
        RankingResult::LiveProved {
            function:
                RankingFunction::Lexicographic {
                    components,
                    variable_names,
                },
        } => {
            assert_eq!(components.len(), 1);
            assert_eq!(variable_names.len(), 2);
        }
        other => panic!("expected LiveProved::Lexicographic, got {other:?}"),
    }
}
