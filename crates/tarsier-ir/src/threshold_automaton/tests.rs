use super::*;

#[test]
fn por_mode_default_is_full() {
    assert_eq!(PorMode::default(), PorMode::Full);
}

#[test]
fn threshold_automaton_new_has_full_por_mode() {
    let ta = ThresholdAutomaton::new();
    assert_eq!(ta.semantics.por_mode, PorMode::Full);
}

/// Helper to build a minimal valid TA for validation tests.
fn minimal_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "t".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    let loc0 = ta.add_location(Location {
        name: "Init".into(),
        role: "R".into(),
        phase: "init".into(),
        local_vars: IndexMap::new(),
    });
    let loc1 = ta.add_location(Location {
        name: "Done".into(),
        role: "R".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations.push(loc0);
    ta.add_shared_var(SharedVar {
        name: "msg_count".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_rule(Rule {
        from: loc0,
        to: loc1,
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination::param(ParamId::from(0)),
            distinct: false,
        }),
        updates: vec![Update {
            var: SharedVarId::from(0),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    ta.constraints.adversary_bound_param = Some(ParamId::from(2)); // f
    ta.constraints.resilience_condition = Some(LinearConstraint {
        lhs: LinearCombination::param(ParamId::from(1)), // t
        op: CmpOp::Lt,
        rhs: LinearCombination::param(ParamId::from(0)), // n
    });
    ta
}

#[test]
fn validate_minimal_ta_ok() {
    let ta = minimal_ta();
    assert!(ta.validate().is_ok());
}

#[test]
fn validate_invalid_initial_location() {
    let mut ta = minimal_ta();
    ta.initial_locations.push(LocationId::from(999));
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidInitialLocation {
            location_id,
            ..
        } if location_id == LocationId::from(999)
    ));
}

#[test]
fn validate_invalid_rule_source() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(999),
        to: LocationId::from(0),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidRuleSource {
            location_id,
            ..
        } if location_id == LocationId::from(999)
    ));
}

#[test]
fn validate_invalid_rule_target() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(999),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidRuleTarget {
            location_id,
            ..
        } if location_id == LocationId::from(999)
    ));
}

#[test]
fn validate_invalid_guard_var() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(999)],
            op: CmpOp::Ge,
            bound: LinearCombination::constant(1),
            distinct: false,
        }),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidGuardVar {
            var_id,
            ..
        } if var_id == SharedVarId::from(999)
    ));
}

#[test]
fn validate_invalid_guard_param() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination::param(ParamId::from(999)),
            distinct: false,
        }),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidGuardParam {
            param_id,
            ..
        } if param_id == ParamId::from(999)
    ));
}

#[test]
fn validate_invalid_update_var() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::trivial(),
        updates: vec![Update {
            var: SharedVarId::from(999),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidUpdateVar {
            var_id,
            ..
        } if var_id == SharedVarId::from(999)
    ));
}

#[test]
fn validate_invalid_adversary_param() {
    let mut ta = minimal_ta();
    ta.constraints.adversary_bound_param = Some(ParamId::from(999));
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidAdversaryParam {
            param_id,
            ..
        } if param_id == ParamId::from(999)
    ));
}

#[test]
fn validate_invalid_gst_param() {
    let mut ta = minimal_ta();
    ta.semantics.gst_param = Some(ParamId::from(999));
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidGstParam {
            param_id,
            ..
        } if param_id == ParamId::from(999)
    ));
}

#[test]
fn validate_invalid_committee_bound_param() {
    let mut ta = minimal_ta();
    ta.constraints.committees.push(IrCommitteeSpec {
        name: "test_committee".into(),
        population: ParamOrConst::Const(100),
        byzantine: ParamOrConst::Const(33),
        committee_size: ParamOrConst::Const(10),
        epsilon: Some(1e-9),
        bound_param: Some(ParamId::from(999)),
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidCommitteeBoundParam {
            param_id,
            ..
        } if param_id == ParamId::from(999)
    ));
}

#[test]
fn validate_invalid_resilience_param() {
    let mut ta = minimal_ta();
    ta.constraints.resilience_condition = Some(LinearConstraint {
        lhs: LinearCombination::param(ParamId::from(999)),
        op: CmpOp::Lt,
        rhs: LinearCombination::param(ParamId::from(0)),
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidResilienceParam {
            param_id,
            ..
        } if param_id == ParamId::from(999)
    ));
}

#[test]
fn lookup_helpers_find_existing_and_missing_symbols() {
    let ta = minimal_ta();
    assert_eq!(ta.find_param_by_name("n"), Some(ParamId::from(0)));
    assert_eq!(ta.find_param_by_name("missing"), None);
    assert_eq!(
        ta.find_shared_var_by_name("msg_count"),
        Some(SharedVarId::from(0))
    );
    assert_eq!(ta.find_shared_var_by_name("unknown_counter"), None);
    assert_eq!(ta.find_location_by_name("Init"), Some(LocationId::from(0)));
    assert_eq!(ta.find_location_by_name("unknown_location"), None);
    assert_eq!(
        ta.role_locations("R"),
        vec![LocationId::from(0), LocationId::from(1)]
    );
    assert!(ta.role_locations("Other").is_empty());
}

#[test]
fn clock_helpers_find_existing_and_missing_symbols() {
    let mut ta = minimal_ta();
    let clock_id = ta.add_clock(IrClockSpec {
        name: "round_clock".into(),
    });
    assert_eq!(clock_id, ClockId::from(0));
    assert_eq!(ta.find_clock_by_name("round_clock"), Some(clock_id));
    assert_eq!(ta.find_clock_by_name("missing_clock"), None);
}

#[test]
fn validate_invalid_clock_update_clock() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![ClockUpdate {
            clock: ClockId::from(42),
            kind: ClockUpdateKind::Reset,
        }],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidClockUpdateClock { clock_id, .. } if clock_id == ClockId::from(42)
    ));
}

#[test]
fn validate_invalid_clock_guard_clock() {
    let mut ta = minimal_ta();
    ta.rules.push(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![ClockGuard {
            clock: ClockId::from(7),
            op: CmpOp::Ge,
            bound: LinearCombination::constant(1),
        }],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidClockGuardClock { clock_id, .. } if clock_id == ClockId::from(7)
    ));
}

#[test]
fn message_effective_policies_respect_overrides_and_global_defaults() {
    let mut ta = minimal_ta();
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.equivocation_mode = EquivocationMode::Full;

    ta.security.message_policies.insert(
        "Vote".into(),
        MessagePolicy {
            auth: MessageAuthPolicy::Unauthenticated,
            equivocation: MessageEquivocationPolicy::None,
        },
    );
    ta.security.message_policies.insert(
        "Ack".into(),
        MessagePolicy {
            auth: MessageAuthPolicy::Authenticated,
            equivocation: MessageEquivocationPolicy::Inherit,
        },
    );

    assert!(!ta.message_effective_authenticated("Vote"));
    assert!(ta.message_effective_non_equivocating("Vote"));
    assert!(ta.message_effective_authenticated("Ack"));
    assert!(!ta.message_effective_non_equivocating("Ack"));

    // Unknown message families inherit global settings.
    assert!(ta.message_effective_authenticated("Unknown"));
    assert!(!ta.message_effective_non_equivocating("Unknown"));
}

#[test]
fn key_owner_helpers_report_owner_and_compromise_status() {
    let mut ta = minimal_ta();
    ta.security.key_ownership.insert("r_key".into(), "R".into());
    ta.security.compromised_keys.insert("r_key".into());

    assert_eq!(ta.key_owner("r_key"), Some("R"));
    assert_eq!(ta.key_owner("missing_key"), None);
    assert!(ta.key_is_compromised("r_key"));
    assert!(!ta.key_is_compromised("other_key"));
}

#[test]
fn display_renders_dag_rounds_when_present() {
    let mut ta = minimal_ta();
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r0".into(),
        parent_rounds: vec![],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r1".into(),
        parent_rounds: vec!["r0".into()],
    });

    let rendered = format!("{ta}");
    assert!(rendered.contains("DAG rounds:"));
    assert!(rendered.contains("r0: (root)"));
    assert!(rendered.contains("r1: r0"));
}

#[test]
fn linear_combination_arithmetic_and_display_are_consistent() {
    let lc = LinearCombination::constant(5)
        .add(&LinearCombination {
            constant: 0,
            terms: vec![(2, ParamId::from(0)), (-1, ParamId::from(1))],
        })
        .sub(&LinearCombination::param(ParamId::from(0)));

    assert_eq!(lc.constant, 5);
    assert_eq!(
        lc.terms,
        vec![(1, ParamId::from(0)), (-1, ParamId::from(1))]
    );
    assert_eq!(format!("{lc}"), "5 + p0 - p1");

    let zero = LinearCombination {
        constant: 0,
        terms: vec![(0, ParamId::from(3))],
    };
    assert_eq!(format!("{zero}"), "0");
}

// -----------------------------------------------------------------------
// RECONF-02: time-varying parameters and reconfiguration
// -----------------------------------------------------------------------

#[test]
fn parameter_fixed_and_varying_constructors() {
    let fixed = Parameter::fixed("n".to_string());
    assert!(!fixed.time_varying);
    assert_eq!(fixed.name, "n");

    let varying = Parameter::varying("committee_size".to_string());
    assert!(varying.time_varying);
    assert_eq!(varying.name, "committee_size");
}

#[test]
fn has_reconfiguration_reflects_param_updates() {
    let mut ta = minimal_ta();
    assert!(!ta.has_reconfiguration());

    // Add a varying param and a rule with a param_update
    let v_id = ta.add_parameter(Parameter::varying("epoch_n".to_string()));
    ta.rules[0].param_updates.push(ParamUpdate {
        param: v_id,
        value: LinearCombination::constant(42),
    });
    assert!(ta.has_reconfiguration());
}

#[test]
fn time_varying_params_lists_only_varying() {
    let mut ta = minimal_ta();
    // All default params are fixed
    assert!(ta.time_varying_params().is_empty());

    // Add a varying param
    let v_id = ta.add_parameter(Parameter::varying("epoch_n".to_string()));
    let varying = ta.time_varying_params();
    assert_eq!(varying.len(), 1);
    assert_eq!(varying[0], (v_id, "epoch_n"));
}

#[test]
fn validate_param_update_on_fixed_param_rejected() {
    let mut ta = minimal_ta();
    // param 0 ("n") is fixed — updating it should fail
    ta.rules[0].param_updates.push(ParamUpdate {
        param: ParamId::from(0),
        value: LinearCombination::constant(10),
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::ParamUpdateOnFixedParam { .. }
    ));
}

#[test]
fn validate_param_update_on_invalid_param_rejected() {
    let mut ta = minimal_ta();
    ta.rules[0].param_updates.push(ParamUpdate {
        param: ParamId::from(999),
        value: LinearCombination::constant(10),
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidParamUpdateTarget { .. }
    ));
}

#[test]
fn validate_param_update_value_with_invalid_param_rejected() {
    let mut ta = minimal_ta();
    let v_id = ta.add_parameter(Parameter::varying("epoch_n".to_string()));
    ta.rules[0].param_updates.push(ParamUpdate {
        param: v_id,
        value: LinearCombination::param(ParamId::from(999)),
    });
    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidParamUpdateValue { .. }
    ));
}

#[test]
fn validate_param_update_on_varying_param_accepted() {
    let mut ta = minimal_ta();
    let v_id = ta.add_parameter(Parameter::varying("epoch_n".to_string()));
    ta.rules[0].param_updates.push(ParamUpdate {
        param: v_id,
        value: LinearCombination::param(ParamId::from(0)).add(&LinearCombination::constant(1)),
    });
    assert!(ta.validate().is_ok());
}

#[test]
fn reconfiguration_semantics_variants() {
    let next = ReconfigurationSemantics::NextStep;
    let imm = ReconfigurationSemantics::Immediate;
    // Just ensure both variants exist and are distinct
    assert!(!matches!(next, ReconfigurationSemantics::Immediate));
    assert!(!matches!(imm, ReconfigurationSemantics::NextStep));
}

#[test]
fn validate_reconfiguration_immediate_semantics_rejected() {
    let mut ta = minimal_ta();
    let t_id = ta.add_parameter(Parameter::varying("epoch_t".to_string()));
    ta.rules[0].param_updates.push(ParamUpdate {
        param: t_id,
        value: LinearCombination::constant(1),
    });
    ta.reconfiguration = Some(ReconfigurationSpec {
        semantics: ReconfigurationSemantics::Immediate,
        max_reconfigurations: 0,
    });

    let err = ta.validate().unwrap_err();
    assert!(matches!(
        err,
        ValidationError::UnsupportedReconfigurationSemantics { .. }
    ));
}

// --- Builder method tests ---

#[test]
fn add_location_returns_sequential_ids() {
    let mut ta = ThresholdAutomaton::new();
    let id0 = ta.add_location(Location {
        name: "L0".into(),
        role: "R".into(),
        phase: "p".into(),
        local_vars: IndexMap::new(),
    });
    let id1 = ta.add_location(Location {
        name: "L1".into(),
        role: "R".into(),
        phase: "q".into(),
        local_vars: IndexMap::new(),
    });
    assert_eq!(id0, LocationId::from(0));
    assert_eq!(id1, LocationId::from(1));
    assert_eq!(ta.num_locations(), 2);
    assert_eq!(ta.locations[id0.as_usize()].name, "L0");
    assert_eq!(ta.locations[id1.as_usize()].name, "L1");
}

#[test]
fn add_shared_var_returns_sequential_ids() {
    let mut ta = ThresholdAutomaton::new();
    let v0 = ta.add_shared_var(SharedVar {
        name: "cnt_A".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let v1 = ta.add_shared_var(SharedVar {
        name: "cnt_B".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: true,
        distinct_role: Some("R".into()),
    });
    assert_eq!(v0, SharedVarId::from(0));
    assert_eq!(v1, SharedVarId::from(1));
    assert_eq!(ta.num_shared_vars(), 2);
    assert!(ta.shared_vars[v1.as_usize()].distinct);
}

#[test]
fn add_parameter_returns_sequential_ids() {
    let mut ta = ThresholdAutomaton::new();
    let p0 = ta.add_parameter(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    let p1 = ta.add_parameter(Parameter::varying("epoch".to_string()));
    assert_eq!(p0, ParamId::from(0));
    assert_eq!(p1, ParamId::from(1));
    assert_eq!(ta.num_parameters(), 2);
    assert!(!ta.parameters[p0.as_usize()].time_varying);
    assert!(ta.parameters[p1.as_usize()].time_varying);
}

#[test]
fn add_rule_returns_sequential_ids() {
    let mut ta = ThresholdAutomaton::new();
    let l0 = ta.add_location(Location {
        name: "A".into(),
        role: "R".into(),
        phase: "p".into(),
        local_vars: IndexMap::new(),
    });
    let l1 = ta.add_location(Location {
        name: "B".into(),
        role: "R".into(),
        phase: "q".into(),
        local_vars: IndexMap::new(),
    });
    let r0 = ta.add_rule(Rule {
        from: l0,
        to: l1,
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    assert_eq!(r0, RuleId::from(0));
    assert_eq!(ta.num_rules(), 1);
    assert_eq!(ta.rules[r0.as_usize()].from, l0);
    assert_eq!(ta.rules[r0.as_usize()].to, l1);
}

#[test]
fn add_collection_and_find_by_name() {
    let mut ta = ThresholdAutomaton::new();
    let cid = ta.add_collection(IrCollectionSpec {
        name: "log".into(),
        kind: IrCollectionKind::Log,
        element_type: "int".into(),
        capacity: LinearCombination::constant(100),
        queue_model: QueueModel::default(),
    });
    assert_eq!(cid, CollectionId::from(0));
    assert_eq!(ta.find_collection_by_name("log"), Some(cid));
    assert_eq!(ta.find_collection_by_name("other"), None);
}

#[test]
fn num_accessors_return_correct_counts() {
    let ta = minimal_ta();
    assert_eq!(ta.num_parameters(), 3); // n, t, f
    assert_eq!(ta.num_locations(), 2); // Init, Done
    assert_eq!(ta.num_shared_vars(), 1); // msg_count
    assert_eq!(ta.num_rules(), 1);
}

// --- LinearCombination tests ---

#[test]
fn linear_combination_scale() {
    let p = ParamId::from(0);
    let lc = LinearCombination {
        constant: 3,
        terms: vec![(2, p)],
    };
    let scaled = lc.scale(4);
    assert_eq!(scaled.constant, 12);
    assert_eq!(scaled.terms, vec![(8, p)]);
}

#[test]
fn linear_combination_scale_by_zero() {
    let p = ParamId::from(0);
    let lc = LinearCombination {
        constant: 5,
        terms: vec![(3, p)],
    };
    let scaled = lc.scale(0);
    assert_eq!(scaled.constant, 0);
    assert_eq!(scaled.terms, vec![(0, p)]);
}

#[test]
fn linear_combination_scale_negative() {
    let p = ParamId::from(0);
    let lc = LinearCombination {
        constant: 2,
        terms: vec![(3, p)],
    };
    let scaled = lc.scale(-1);
    assert_eq!(scaled.constant, -2);
    assert_eq!(scaled.terms, vec![(-3, p)]);
}

#[test]
fn linear_combination_sub() {
    let p0 = ParamId::from(0);
    let p1 = ParamId::from(1);
    let a = LinearCombination {
        constant: 10,
        terms: vec![(3, p0)],
    };
    let b = LinearCombination {
        constant: 4,
        terms: vec![(1, p1)],
    };
    let result = a.sub(&b);
    assert_eq!(result.constant, 6);
    assert_eq!(result.terms.len(), 2);
}

#[test]
fn linear_combination_display() {
    let p0 = ParamId::from(0);
    let lc = LinearCombination::constant(5);
    assert_eq!(format!("{lc}"), "5");

    let lc2 = LinearCombination::param(p0);
    let display = format!("{lc2}");
    assert!(!display.is_empty());
}

// --- Guard construction tests ---

#[test]
fn guard_trivial_has_empty_atoms() {
    let g = Guard::trivial();
    assert!(g.atoms.is_empty());
}

#[test]
fn guard_single_has_one_atom() {
    let atom = GuardAtom::Threshold {
        vars: vec![SharedVarId::from(0)],
        op: CmpOp::Ge,
        bound: LinearCombination::constant(1),
        distinct: false,
    };
    let g = Guard::single(atom.clone());
    assert_eq!(g.atoms.len(), 1);
}

// --- find_location_by_name ---

#[test]
fn find_location_by_name_works() {
    let ta = minimal_ta();
    assert_eq!(ta.find_location_by_name("Init"), Some(LocationId::from(0)));
    assert_eq!(ta.find_location_by_name("Done"), Some(LocationId::from(1)));
    assert_eq!(ta.find_location_by_name("Missing"), None);
}

// --- find_param_by_name ---

#[test]
fn find_param_by_name_works() {
    let ta = minimal_ta();
    assert!(ta.find_param_by_name("n").is_some());
    assert!(ta.find_param_by_name("t").is_some());
    assert!(ta.find_param_by_name("missing").is_none());
}
