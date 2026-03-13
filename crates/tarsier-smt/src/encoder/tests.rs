use super::*;
use crate::backends::smtlib_printer::to_smtlib;
use crate::backends::z3_backend::Z3Solver;
use crate::solver::{SatResult, SmtSolver};
use indexmap::IndexMap;

fn make_simple_ta() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();

    // Parameters: n, t
    ta.add_parameter(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "t".into(),
        time_varying: false,
    });

    // Resilience: n > 3*t
    ta.constraints.resilience_condition = Some(LinearConstraint {
        lhs: LinearCombination::param(0.into()), // n
        op: CmpOp::Gt,
        rhs: LinearCombination::param(1.into()).scale(3), // 3*t
    });

    // 1 message counter
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    // 2 locations: waiting, done
    ta.add_location(Location {
        name: "waiting".into(),
        role: "P".into(),
        phase: "waiting".into(),
        local_vars: IndexMap::new(),
    });
    ta.add_location(Location {
        name: "done".into(),
        role: "P".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });

    ta.initial_locations = vec![0.into()];

    // Rule: waiting -> done when cnt_Echo >= 2*t+1, sends Echo
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![0.into()],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 1,
                terms: vec![(2, 1.into())], // 2*t + 1
            },
            distinct: false,
        }),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    ta
}

fn make_signer_set_threshold_ta() -> ThresholdAutomaton {
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
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );

    ta.add_location(Location {
        name: "waiting".into(),
        role: "P".into(),
        phase: "waiting".into(),
        local_vars: IndexMap::new(),
    });
    ta.add_location(Location {
        name: "done".into(),
        role: "P".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations = vec![0.into()];

    let vote_sender_0 = ta.add_shared_var(SharedVar {
        name: "cnt_Vote@P#0<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let vote_sender_1 = ta.add_shared_var(SharedVar {
        name: "cnt_Vote@P#0<-P#1[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let sig = ta.add_shared_var(SharedVar {
        name: "cnt_Sig@P#0<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![vote_sender_0, vote_sender_1],
            op: CmpOp::Ge,
            bound: LinearCombination::constant(2),
            distinct: true,
        }),
        updates: vec![Update {
            var: sig,
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    ta
}

fn solve_with_extra_assertions(enc: &BmcEncoding, extra: &[SmtTerm]) -> SatResult {
    let mut solver = Z3Solver::with_default_config();
    for (name, sort) in &enc.declarations {
        solver
            .declare_var(name, sort)
            .expect("encoding variable declaration should be valid");
    }
    for assertion in &enc.assertions {
        solver
            .assert(assertion)
            .expect("encoding assertion should be valid");
    }
    for assertion in extra {
        solver
            .assert(assertion)
            .expect("extra assertion should be valid");
    }
    solver
        .check_sat()
        .expect("solver should return SAT/UNSAT for finite encoding")
}

#[test]
fn bmc_builder_phases_are_unit_testable() {
    let ta = make_simple_ta();
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let mut builder = BmcEncoderBuilder::new(&cs, &property, 1);
    builder.phase_declare_parameters_and_resilience();
    assert!(
        builder
            .enc
            .declarations
            .iter()
            .any(|(name, _)| name == "p_0"),
        "parameter declarations should be emitted in phase 1"
    );

    builder.phase_declare_initial_state();
    assert!(
        builder
            .enc
            .declarations
            .iter()
            .any(|(name, _)| name == "kappa_0_0"),
        "initial-state declarations should be emitted in phase 2"
    );

    builder.phase_encode_transitions_and_fault_bounds();
    builder.phase_encode_property_violation();
    assert!(
        !builder.enc.assertions.is_empty(),
        "phase composition should produce non-empty constraints"
    );
}

#[test]
fn k_induction_builder_phases_are_unit_testable() {
    let ta = make_simple_ta();
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let mut builder = super::k_induction::KInductionEncoderBuilder::new(&cs, &property, 1);
    builder.phase_declare_parameters_and_resilience();
    assert!(
        builder
            .encoding()
            .declarations
            .iter()
            .any(|(name, _)| name == "p_0"),
        "parameter declarations should be emitted in phase 1"
    );

    builder.phase_declare_state_and_transition_variables();
    assert!(
        builder
            .encoding()
            .declarations
            .iter()
            .any(|(name, _)| name == "kappa_0_0"),
        "state declarations should be emitted in phase 2"
    );

    builder.phase_encode_transition_relation_and_fault_bounds();
    builder.phase_encode_induction_goal();
    assert!(
        !builder.encoding().assertions.is_empty(),
        "phase composition should produce non-empty constraints"
    );
}

#[test]
fn encoding_produces_declarations() {
    let ta = make_simple_ta();
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 2);
    // Should have parameter vars + location vars + shared vars + delta vars
    assert!(!enc.declarations.is_empty());
    assert!(!enc.assertions.is_empty());
}

fn add_depth(term: &SmtTerm) -> usize {
    match term {
        SmtTerm::Add(lhs, rhs) => 1 + add_depth(lhs).max(add_depth(rhs)),
        _ => 0,
    }
}

#[test]
fn balanced_sum_builder_stays_shallow() {
    let terms = (0..1024)
        .map(|i| SmtTerm::var(format!("x_{i}")))
        .collect::<Vec<_>>();
    let sum = sum_terms_balanced(terms);
    // 1024 leaves should fit in a depth-10 balanced tree.
    assert!(add_depth(&sum) <= 10);
}

#[test]
fn structural_hashing_deduplicates_commutative_identity_constraints() {
    let mut enc = BmcEncoding::new();
    enc.assert_term(SmtTerm::var("a").eq(SmtTerm::var("b")));
    enc.assert_term(SmtTerm::var("b").eq(SmtTerm::var("a")));
    enc.assert_term(SmtTerm::and(vec![SmtTerm::var("x"), SmtTerm::var("y")]));
    enc.assert_term(SmtTerm::and(vec![SmtTerm::var("y"), SmtTerm::var("x")]));
    assert_eq!(enc.assertions.len(), 2);
}

#[test]
fn por_prunes_stutter_rules_by_forcing_zero_delta() {
    let mut ta = make_simple_ta();
    ta.add_rule(Rule {
        from: 0.into(),
        to: 0.into(),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let bmc = encode_bmc(&cs, &property, 1);
    let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
    assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

    let step = encode_k_induction_step(&cs, &property, 1);
    let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(step_assertions.iter().any(|a| a == "(= delta_0_1 0)"));
}

#[test]
fn por_prunes_commutative_duplicate_rules_by_forcing_zero_delta() {
    let mut ta = make_simple_ta();
    ta.add_rule(ta.rules[0].clone());
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let bmc = encode_bmc(&cs, &property, 1);
    let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
    assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

    let step = encode_k_induction_step(&cs, &property, 1);
    let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(step_assertions.iter().any(|a| a == "(= delta_0_1 0)"));
}

#[test]
fn por_prunes_guard_dominated_rules_by_forcing_zero_delta() {
    let mut ta = make_simple_ta();
    ta.rules.clear();
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![0.into()],
            op: CmpOp::Ge,
            bound: LinearCombination::constant(2),
            distinct: false,
        }),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![0.into()],
            op: CmpOp::Ge,
            bound: LinearCombination::constant(1),
            distinct: false,
        }),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let bmc = encode_bmc(&cs, &property, 1);
    let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
    assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_0 0)"));

    let step = encode_k_induction_step(&cs, &property, 1);
    let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(step_assertions.iter().any(|a| a == "(= delta_0_0 0)"));
}

#[test]
fn omission_partial_sync_encodes_drop_and_post_gst_delivery() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "gst".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Omission;
    ta.semantics.timing_model = TimingModel::PartialSynchrony;
    ta.semantics.gst_param = Some(3.into());
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("drop_0_0"));
    assert!(decls.contains("gst_step"));
    assert!(decls.contains("time_0"));
    assert!(decls.contains("time_1"));

    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    assert!(assertions.iter().any(|a| a == "(<= drop_0_0 p_2)"));
    assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 drop_0_0)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (<= gst_step time_0) (= net_drop_0_0 0))"));
    assert!(assertions.iter().any(|a| a == "(= gst_step p_3)"));
    assert!(assertions.iter().any(|a| a == "(= time_0 0)"));
    assert!(assertions.iter().any(|a| a == "(= time_1 (+ time_0 1))"));
}

#[test]
fn message_network_flow_is_explicitly_modeled_per_edge() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);

    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("net_pending_0_0"));
    assert!(decls.contains("net_pending_1_0"));
    assert!(decls.contains("net_send_0_0"));
    assert!(decls.contains("net_forge_0_0"));
    assert!(decls.contains("net_deliver_0_0"));
    assert!(decls.contains("net_drop_0_0"));

    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= net_pending_0_0 0)"));
    assert!(assertions.iter().any(|a| a == "(= net_send_0_0 delta_0_0)"));
    assert!(assertions.iter().any(|a| a == "(= net_forge_0_0 adv_0_0)"));
    assert!(assertions.iter().any(
            |a| a == "(<= (+ net_deliver_0_0 net_drop_0_0) (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0))"
        ));
    assert!(assertions.iter().any(
            |a| a == "(= net_pending_1_0 (- (- (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0) net_deliver_0_0) net_drop_0_0))"
        ));
    assert!(assertions
        .iter()
        .any(|a| a == "(= g_1_0 (+ g_0_0 net_deliver_0_0))"));
}

#[test]
fn byzantine_model_does_not_declare_drop_variables() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(!decls.iter().any(|n| n.starts_with("drop_")));
}

#[test]
fn byzantine_identity_selective_declares_drop_and_advsend_variables() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("drop_0_0"));
    assert!(decls.contains("drop_0_1"));
    assert!(decls.contains("drop_0_2"));
    assert!(decls.contains("advsend_0_0"));
    assert!(decls.contains("advsend_0_1"));
}

#[test]
fn byzantine_cohort_selective_couples_lane_variants_with_sender_budget() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::CohortSelective;
    ta.shared_vars[0].name = "cnt_Echo@Replica#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica#1[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("drop_0_0"));
    assert!(decls.contains("drop_0_1"));
    assert!(decls.contains("advsend_0_0"));

    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(<= adv_0_0 advsend_0_0)"));
    assert!(assertions.iter().any(|a| a == "(<= adv_0_1 advsend_0_0)"));
}

#[test]
fn fault_scope_per_recipient_adds_recipient_aggregate_bounds() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.fault_budget_scope = FaultBudgetScope::PerRecipient;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
    assert!(assertions.iter().any(|a| a == "(<= adv_0_2 p_2)"));
}

#[test]
fn omission_selective_adds_per_message_per_recipient_drop_bounds() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Omission;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica<-P#1[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ drop_0_0 drop_0_1) p_2)"));
    assert!(assertions.iter().any(|a| a == "(<= drop_0_2 p_2)"));
}

#[test]
fn fault_scope_global_adds_global_aggregate_bound() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.fault_budget_scope = FaultBudgetScope::Global;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ (+ adv_0_0 adv_0_1) adv_0_2) p_2)"));
}

#[test]
fn delivery_control_global_couples_variant_injections_across_recipients() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.delivery_control = DeliveryControlMode::Global;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_1 adv_0_0)"));
}

#[test]
fn process_selective_adds_pid_bucket_uniqueness_constraints() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
    ta.shared_vars[0].name = "cnt_Echo@P#0".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@P#1".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    ta.locations[0]
        .local_vars
        .insert("pid".into(), LocalValue::Int(0));
    ta.locations[1]
        .local_vars
        .insert("pid".into(), LocalValue::Int(0));
    ta.add_location(Location {
        name: "waiting_pid1".into(),
        role: "P".into(),
        phase: "waiting".into(),
        local_vars: indexmap::indexmap! {"pid".into() => LocalValue::Int(1)},
    });
    ta.add_location(Location {
        name: "done_pid1".into(),
        role: "P".into(),
        phase: "done".into(),
        local_vars: indexmap::indexmap! {"pid".into() => LocalValue::Int(1)},
    });
    ta.rules[0].from = 2.into();
    ta.rules[0].to = 3.into();
    ta.initial_locations = vec![0.into(), 2.into()];

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(= (+ kappa_0_0 kappa_0_1) 1)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(= (+ kappa_1_0 kappa_1_1) 1)"));
}

#[test]
fn process_selective_uses_declared_identity_variable_for_uniqueness() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("node_id".into()),
            key_name: "p_key".into(),
        },
    );
    ta.shared_vars[0].name = "cnt_Echo@P#0".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@P#1".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    ta.locations[0]
        .local_vars
        .insert("node_id".into(), LocalValue::Int(0));
    ta.locations[1]
        .local_vars
        .insert("node_id".into(), LocalValue::Int(0));
    ta.add_location(Location {
        name: "waiting_id1".into(),
        role: "P".into(),
        phase: "waiting".into(),
        local_vars: indexmap::indexmap! {"node_id".into() => LocalValue::Int(1)},
    });
    ta.add_location(Location {
        name: "done_id1".into(),
        role: "P".into(),
        phase: "done".into(),
        local_vars: indexmap::indexmap! {"node_id".into() => LocalValue::Int(1)},
    });
    ta.rules[0].from = 2.into();
    ta.rules[0].to = 3.into();
    ta.initial_locations = vec![0.into(), 2.into()];

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(= (+ kappa_0_0 kappa_0_1) 1)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(= (+ kappa_1_0 kappa_1_1) 1)"));
}

#[test]
fn byzantine_identity_selective_couples_variant_delivery_across_recipients() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.equivocation_mode = EquivocationMode::None;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    // Replica and client counters for the same variant are tied to one sender budget.
    assert!(assertions.iter().any(|a| a == "(<= adv_0_0 advsend_0_0)"));
    assert!(assertions.iter().any(|a| a == "(<= adv_0_2 advsend_0_0)"));
    assert!(assertions.iter().any(|a| a == "(<= adv_0_1 advsend_0_1)"));
    assert!(assertions.iter().any(|a| a == "(<= adv_0_3 advsend_0_1)"));
    // Non-equivocation globally caps Byzantine variant choices per family.
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ advsend_0_0 advsend_0_1) p_2)"));
}

#[test]
fn byzantine_equivocation_none_bounds_family_sum() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.equivocation_mode = EquivocationMode::None;
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
}

#[test]
fn byzantine_equivocation_none_bounds_family_sum_per_recipient() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.equivocation_mode = EquivocationMode::None;

    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_2 adv_0_3) p_2)"));
}

#[test]
fn byzantine_signed_auth_bounds_family_sum_even_with_full_equivocation() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.equivocation_mode = EquivocationMode::Full;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;

    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_2 adv_0_3) p_2)"));
}

#[test]
fn message_auth_policy_authenticated_enforces_identity_cap() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.equivocation_mode = EquivocationMode::Full;
    ta.semantics.authentication_mode = AuthenticationMode::None;
    ta.security.message_policies.insert(
        "Echo".into(),
        MessagePolicy {
            auth: MessageAuthPolicy::Authenticated,
            equivocation: MessageEquivocationPolicy::Inherit,
        },
    );

    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
}

#[test]
fn signed_senderless_messages_forbid_adversary_injection() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
}

#[test]
fn signed_sender_scoped_messages_require_byzantine_sender_activation() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("byzsender_0_0"));
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (= byzsender_0_0 0) (= adv_0_0 0))"));
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (= byzsender_0_0 0) (= adv_0_1 0))"));
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (= byzsender_0_0 0) (= net_forge_0_0 0))"));
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (= byzsender_0_0 0) (= net_forge_0_1 0))"));
    assert!(assertions.iter().any(|a| a == "(<= byzsender_0_0 p_2)"));
}

#[test]
fn byzantine_sender_set_is_static_and_step_activation_is_subset() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica<-P#1[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("byzsender_static_0"));
    assert!(decls.contains("byzsender_static_1"));

    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a == "(<= byzsender_0_0 byzsender_static_0)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(<= byzsender_0_1 byzsender_static_1)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(<= (+ byzsender_static_0 byzsender_static_1) p_2)"));
}

#[test]
fn partial_synchrony_faithful_channels_force_honest_post_gst_delivery() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "gst".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.timing_model = TimingModel::PartialSynchrony;
    ta.semantics.gst_param = Some(3.into());
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| {
        a.contains("(=> (and (<= gst_step time_0) (= byzsender_0_0 0))")
            && a.contains("(= net_deliver_0_0 (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0))")
    }));
}

#[test]
fn compromised_signing_key_allows_sender_channel_forge_without_byzsender_gate() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    ta.security.compromised_keys.insert("p_key".into());
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(
        !decls.contains("byzsender_0_0"),
        "compromised key channels should not require byzsender activation"
    );
}

#[test]
fn compromised_key_allows_signed_forge_sat() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    ta.security.compromised_keys.insert("p_key".into());
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);

    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(sat, SatResult::Sat);
}

#[test]
fn signer_set_threshold_requires_distinct_signer_identities_not_counter_magnitude() {
    let ta = make_signer_set_threshold_ta();
    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 2);

    let repeated_single_signer = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(1)),
            SmtTerm::var("p_1").eq(SmtTerm::int(2)),
            SmtTerm::var("p_2").eq(SmtTerm::int(2)),
            SmtTerm::var("delta_0_0").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_1_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_1").eq(SmtTerm::int(0)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_1").eq(SmtTerm::int(0)),
            SmtTerm::var("g_1_0").eq(SmtTerm::int(2)),
            SmtTerm::var("g_1_1").eq(SmtTerm::int(0)),
            SmtTerm::var("g_1_2").eq(SmtTerm::int(0)),
        ],
    );
    assert_eq!(repeated_single_signer, SatResult::Unsat);

    let two_distinct_signers = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(1)),
            SmtTerm::var("p_1").eq(SmtTerm::int(2)),
            SmtTerm::var("p_2").eq(SmtTerm::int(2)),
            SmtTerm::var("delta_0_0").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_1_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_1").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_1").eq(SmtTerm::int(1)),
            SmtTerm::var("g_1_0").eq(SmtTerm::int(1)),
            SmtTerm::var("g_1_1").eq(SmtTerm::int(1)),
            SmtTerm::var("g_1_2").eq(SmtTerm::int(0)),
        ],
    );
    assert_eq!(two_distinct_signers, SatResult::Sat);
}

#[test]
fn forging_signed_message_without_compromise_and_without_byzantine_sender_is_unsat() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("byzsender_0_0"));
    assert!(decls.contains("net_forge_0_0"));

    let baseline_sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
            SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(baseline_sat, SatResult::Sat);

    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(0)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(0)),
            SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(sat, SatResult::Unsat);
}

#[test]
fn forging_crypto_object_family_is_unsat_even_with_byzantine_budget() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    ta.shared_vars[0].name = "cnt_QC@P#0<-P#0[value=false]".into();
    ta.security.crypto_objects.insert(
        "QC".into(),
        IrCryptoObjectSpec {
            name: "QC".into(),
            kind: IrCryptoObjectKind::QuorumCertificate,
            source_message: "Vote".into(),
            threshold: LinearCombination::constant(1),
            signer_role: Some("P".into()),
            conflict_policy: CryptoConflictPolicy::Allow,
        },
    );

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);

    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
            SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(sat, SatResult::Unsat);
}

#[test]
fn valid_crypto_object_formation_path_is_sat() {
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "t".into(),
        time_varying: false,
    });
    ta.add_location(Location {
        name: "waiting".into(),
        role: "P".into(),
        phase: "waiting".into(),
        local_vars: IndexMap::new(),
    });
    ta.add_location(Location {
        name: "done".into(),
        role: "P".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations = vec![0.into()];
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );

    let vote = ta.add_shared_var(SharedVar {
        name: "cnt_Vote@P#0<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    let qc = ta.add_shared_var(SharedVar {
        name: "cnt_QC@P#0<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.security.crypto_objects.insert(
        "QC".into(),
        IrCryptoObjectSpec {
            name: "QC".into(),
            kind: IrCryptoObjectKind::QuorumCertificate,
            source_message: "Vote".into(),
            threshold: LinearCombination::constant(1),
            signer_role: Some("P".into()),
            conflict_policy: CryptoConflictPolicy::Allow,
        },
    );
    ta.add_rule(Rule {
        from: 0.into(),
        to: 0.into(),
        guard: Guard::trivial(),
        updates: vec![Update {
            var: vote,
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![vote],
            op: CmpOp::Ge,
            bound: LinearCombination::constant(1),
            distinct: true,
        }),
        updates: vec![Update {
            var: qc,
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 2);
    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(1)),
            SmtTerm::var("p_1").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("delta_0_1").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_1_0").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_1_1").eq(SmtTerm::int(1)),
            SmtTerm::var("g_2_1").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(sat, SatResult::Sat);
}

#[test]
fn exclusive_crypto_policy_blocks_conflicting_variants_in_same_state() {
    let build_ta = |policy: CryptoConflictPolicy| {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "t".into(),
            time_varying: false,
        });
        ta.add_location(Location {
            name: "s".into(),
            role: "P".into(),
            phase: "s".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations = vec![0.into()];
        let qc_false = ta.add_shared_var(SharedVar {
            name: "cnt_QC@P#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let qc_true = ta.add_shared_var(SharedVar {
            name: "cnt_QC@P#0<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_rule(Rule {
            from: 0.into(),
            to: 0.into(),
            guard: Guard::trivial(),
            updates: vec![Update {
                var: qc_false,
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.add_rule(Rule {
            from: 0.into(),
            to: 0.into(),
            guard: Guard::trivial(),
            updates: vec![Update {
                var: qc_true,
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.security.crypto_objects.insert(
            "QC".into(),
            IrCryptoObjectSpec {
                name: "QC".into(),
                kind: IrCryptoObjectKind::QuorumCertificate,
                source_message: "Vote".into(),
                threshold: LinearCombination::constant(1),
                signer_role: Some("P".into()),
                conflict_policy: policy,
            },
        );
        ta
    };

    let make_goal = |ta| {
        let cs = ta;
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        encode_bmc(&cs, &property, 1)
    };

    let allow_enc = make_goal(build_ta(CryptoConflictPolicy::Allow));
    let allow_sat = solve_with_extra_assertions(
        &allow_enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(2)),
            SmtTerm::var("p_1").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("delta_0_1").eq(SmtTerm::int(1)),
            SmtTerm::var("g_1_0").gt(SmtTerm::int(0)),
            SmtTerm::var("g_1_1").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(allow_sat, SatResult::Sat);

    let exclusive_enc = make_goal(build_ta(CryptoConflictPolicy::Exclusive));
    let exclusive_sat = solve_with_extra_assertions(
        &exclusive_enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(2)),
            SmtTerm::var("p_1").eq(SmtTerm::int(0)),
            SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
            SmtTerm::var("delta_0_1").eq(SmtTerm::int(1)),
            SmtTerm::var("g_1_0").gt(SmtTerm::int(0)),
            SmtTerm::var("g_1_1").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(exclusive_sat, SatResult::Unsat);
}

#[test]
fn full_equivocation_can_split_byzantine_payloads_across_recipients_sat() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.equivocation_mode = EquivocationMode::Full;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    ta.shared_vars[0].name = "cnt_Vote@A#0<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Vote@B#0<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Vote@A#0<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Vote@B#0<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Termination { goal_locs: vec![] };
    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("byzsender_0_0"));

    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
            SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
            // Same Byzantine sender forges different payloads to different recipients.
            SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
            SmtTerm::var("net_forge_0_3").gt(SmtTerm::int(0)),
        ],
    );
    assert_eq!(sat, SatResult::Sat);
}

#[test]
fn equivocation_none_enforces_sender_scoped_variant_exclusivity() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.equivocation_mode = EquivocationMode::None;
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions
        .iter()
        .any(|a| a
            == "(=> (> (+ net_forge_0_0 net_forge_0_1) 0) (= (+ net_forge_0_2 net_forge_0_3) 0))"));
    assert!(assertions
        .iter()
        .any(|a| a
            == "(=> (> (+ net_forge_0_2 net_forge_0_3) 0) (= (+ net_forge_0_0 net_forge_0_1) 0))"));
}

#[test]
fn equivocation_full_allows_sender_scoped_split_variants() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    ta.semantics.authentication_mode = AuthenticationMode::Signed;
    ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
    ta.semantics.equivocation_mode = EquivocationMode::Full;
    ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=false]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Replica<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_shared_var(SharedVar {
        name: "cnt_Echo@Client<-P#0[value=true]".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(!assertions
        .iter()
        .any(|a| a
            == "(=> (> (+ net_forge_0_0 net_forge_0_1) 0) (= (+ net_forge_0_2 net_forge_0_3) 0))"));
}

#[test]
fn crash_model_uses_crash_counter_not_drop_variables() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    let crash_counter = ta.add_shared_var(SharedVar {
        name: "__crashed_count".into(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Crash;
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(!decls.iter().any(|n| n.starts_with("drop_")));
    assert!(decls.contains("net_pending_0_0"));
    assert!(decls.contains("net_pending_1_0"));
    assert!(decls.contains("net_send_0_0"));
    assert!(decls.contains("net_forge_0_0"));
    assert!(decls.contains("net_deliver_0_0"));
    assert!(decls.contains("net_drop_0_0"));
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    assert!(assertions.iter().any(|a| a == "(= net_forge_0_0 adv_0_0)"));
    assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 0)"));
    assert!(assertions
        .iter()
        .any(|a| a == &format!("(<= g_1_{} p_2)", crash_counter)));
}

#[test]
fn adversary_bound_is_capped_by_t_in_bmc_and_kinduction() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Byzantine;
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let bmc = encode_bmc(&cs, &property, 1);
    let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
    assert!(bmc_assertions.iter().any(|a| a == "(<= p_2 p_1)"));

    let step = encode_k_induction_step(&cs, &property, 1);
    let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(step_assertions.iter().any(|a| a == "(<= p_2 p_1)"));
}

#[test]
fn omission_without_bound_forces_zero_injection_and_drops() {
    let mut ta = make_simple_ta();
    ta.semantics.fault_model = FaultModel::Omission;
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("drop_0_0"));
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    assert!(assertions.iter().any(|a| a == "(= drop_0_0 0)"));
}

#[test]
fn crash_without_bound_forces_zero_crashes() {
    let mut ta = make_simple_ta();
    let crash_counter = ta.add_shared_var(SharedVar {
        name: "__crashed_count".into(),
        kind: SharedVarKind::Shared,
        distinct: false,
        distinct_role: None,
    });
    ta.semantics.fault_model = FaultModel::Crash;
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    assert!(assertions
        .iter()
        .any(|a| a == &format!("(= g_1_{} 0)", crash_counter)));
}

#[test]
fn kinduction_omission_partial_sync_encodes_drop_bound_and_post_gst_delivery() {
    let mut ta = make_simple_ta();
    ta.add_parameter(Parameter {
        name: "f".into(),
        time_varying: false,
    });
    ta.add_parameter(Parameter {
        name: "gst".into(),
        time_varying: false,
    });
    ta.constraints.adversary_bound_param = Some(2.into());
    ta.semantics.fault_model = FaultModel::Omission;
    ta.semantics.timing_model = TimingModel::PartialSynchrony;
    ta.semantics.gst_param = Some(3.into());
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let step = encode_k_induction_step(&cs, &property, 1);
    let decls: std::collections::HashSet<_> =
        step.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(decls.contains("gst_step"));
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    assert!(assertions.iter().any(|a| a == "(<= drop_0_0 p_2)"));
    assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 drop_0_0)"));
    assert!(assertions
        .iter()
        .any(|a| a == "(=> (<= gst_step time_0) (= net_drop_0_0 0))"));
    assert!(assertions.iter().any(|a| a == "(= gst_step p_3)"));
}

#[test]
fn kinduction_depth_zero_declares_no_transition_step_variables() {
    let ta = make_simple_ta();
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![(0.into(), 1.into())],
    };

    let step = encode_k_induction_step(&cs, &property, 0);
    let decls: std::collections::HashSet<_> =
        step.declarations.iter().map(|(n, _)| n.clone()).collect();
    assert!(!decls.iter().any(|n| n.starts_with("delta_")));
    assert!(!decls.iter().any(|n| n.starts_with("adv_")));
    assert!(decls.contains("kappa_0_0"));
    assert!(decls.contains("g_0_0"));
}

#[test]
fn kinduction_process_selective_missing_pid_is_unsat() {
    let mut ta = make_simple_ta();
    ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
    ta.security.role_identities.insert(
        "P".into(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".into()),
            key_name: "p_key".into(),
        },
    );
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![(0.into(), 1.into())],
    };

    let step = encode_k_induction_step(&cs, &property, 1);
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(
        assertions.iter().any(|a| a == "false"),
        "missing process identities should force UNSAT in process-selective mode"
    );
}

#[test]
fn kinduction_distinct_counter_without_population_bound_is_unsat() {
    let mut ta = ThresholdAutomaton::new();
    ta.add_shared_var(SharedVar {
        name: "cnt_M".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: true,
        distinct_role: None,
    });
    ta.add_location(Location {
        name: "s0".into(),
        role: "P".into(),
        phase: "s0".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations = vec![0.into()];
    let cs = ta;
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![0.into()]],
    };

    let step = encode_k_induction_step(&cs, &property, 1);
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(
        assertions.iter().any(|a| a == "false"),
        "distinct counters require n or n_<role> population bounds"
    );
}

#[test]
fn kinduction_por_off_does_not_force_duplicate_delta_to_zero() {
    let mut ta_full = make_simple_ta();
    ta_full.add_rule(ta_full.rules[0].clone());
    ta_full.semantics.por_mode = PorMode::Full;
    let cs_full = ta_full;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let full = encode_k_induction_step(&cs_full, &property, 1);
    let full_assertions: Vec<String> = full.assertions.iter().map(to_smtlib).collect();
    assert!(full_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

    let mut ta_off = make_simple_ta();
    ta_off.add_rule(ta_off.rules[0].clone());
    ta_off.semantics.por_mode = PorMode::Off;
    let cs_off = ta_off;
    let off = encode_k_induction_step(&cs_off, &property, 1);
    let off_assertions: Vec<String> = off.assertions.iter().map(to_smtlib).collect();
    assert!(
        !off_assertions.iter().any(|a| a == "(= delta_0_1 0)"),
        "POR off should keep duplicate-rule deltas unconstrained by pruning"
    );
}

#[test]
fn kinduction_crash_model_without_crash_counter_is_unsat() {
    let mut ta = make_simple_ta();
    ta.semantics.fault_model = FaultModel::Crash;
    ta.constraints.adversary_bound_param = Some(1.into());
    let cs = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };

    let step = encode_k_induction_step(&cs, &property, 1);
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
    assert!(
        assertions.iter().any(|a| a == "false"),
        "crash model requires __crashed_count instrumentation"
    );
}

#[test]
fn por_mode_off_disables_all_pruning() {
    let mut ta = make_simple_ta();
    // Add a duplicate rule (same signature as rule 0) to test pruning
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![0.into()],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 1,
                terms: vec![(2, 1.into())],
            },
            distinct: false,
        }),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    // With Full POR, duplicate should be pruned
    ta.semantics.por_mode = PorMode::Full;
    let pruning_full = compute_por_rule_pruning(&ta);
    let active_full = pruning_full.active_rule_ids().len();

    // With POR Off, no rules should be pruned
    ta.semantics.por_mode = PorMode::Off;
    let pruning_off = compute_por_rule_pruning(&ta);
    assert_eq!(pruning_off.stutter_pruned, 0);
    assert_eq!(pruning_off.commutative_duplicate_pruned, 0);
    assert_eq!(pruning_off.guard_dominated_pruned, 0);
    let active_off = pruning_off.active_rule_ids().len();
    assert_eq!(active_off, ta.rules.len());
    assert!(active_off > active_full);
}

// ── canonical_term_key tests ─────────────────────────────────────

#[test]
fn canonical_term_key_commutative_add() {
    let ab = SmtTerm::var("a").add(SmtTerm::var("b"));
    let ba = SmtTerm::var("b").add(SmtTerm::var("a"));
    assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
}

#[test]
fn canonical_term_key_commutative_mul() {
    let ab = SmtTerm::var("a").mul(SmtTerm::var("b"));
    let ba = SmtTerm::var("b").mul(SmtTerm::var("a"));
    assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
}

#[test]
fn canonical_term_key_commutative_eq() {
    let ab = SmtTerm::var("a").eq(SmtTerm::var("b"));
    let ba = SmtTerm::var("b").eq(SmtTerm::var("a"));
    assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
}

#[test]
fn canonical_term_key_noncommutative_sub() {
    let ab = SmtTerm::var("a").sub(SmtTerm::var("b"));
    let ba = SmtTerm::var("b").sub(SmtTerm::var("a"));
    assert_ne!(canonical_term_key(&ab), canonical_term_key(&ba));
}

#[test]
fn canonical_term_key_noncommutative_lt_le_gt_ge() {
    let a = SmtTerm::var("a");
    let b = SmtTerm::var("b");
    assert_ne!(
        canonical_term_key(&a.clone().lt(b.clone())),
        canonical_term_key(&b.clone().lt(a.clone()))
    );
    assert_ne!(
        canonical_term_key(&a.clone().le(b.clone())),
        canonical_term_key(&b.clone().le(a.clone()))
    );
    assert_ne!(
        canonical_term_key(&a.clone().gt(b.clone())),
        canonical_term_key(&b.clone().gt(a.clone()))
    );
    assert_ne!(
        canonical_term_key(&a.clone().ge(b.clone())),
        canonical_term_key(&b.ge(a))
    );
}

#[test]
fn canonical_term_key_and_or_sorts_children() {
    let xy = SmtTerm::and(vec![SmtTerm::var("x"), SmtTerm::var("y")]);
    let yx = SmtTerm::and(vec![SmtTerm::var("y"), SmtTerm::var("x")]);
    assert_eq!(canonical_term_key(&xy), canonical_term_key(&yx));

    let or_xy = SmtTerm::or(vec![SmtTerm::var("x"), SmtTerm::var("y")]);
    let or_yx = SmtTerm::or(vec![SmtTerm::var("y"), SmtTerm::var("x")]);
    assert_eq!(canonical_term_key(&or_xy), canonical_term_key(&or_yx));
}

// ── sum_terms_balanced tests ─────────────────────────────────────

#[test]
fn sum_terms_balanced_empty_is_zero() {
    assert_eq!(sum_terms_balanced(vec![]), SmtTerm::int(0));
}

#[test]
fn sum_terms_balanced_single_term() {
    let t = SmtTerm::var("x");
    assert_eq!(sum_terms_balanced(vec![t.clone()]), t);
}

#[test]
fn sum_terms_balanced_two_terms() {
    let a = SmtTerm::var("a");
    let b = SmtTerm::var("b");
    assert_eq!(
        sum_terms_balanced(vec![a.clone(), b.clone()]),
        SmtTerm::Add(Box::new(a), Box::new(b))
    );
}

// ── encode_lc tests ──────────────────────────────────────────────

#[test]
fn encode_lc_constant_only() {
    let lc = LinearCombination {
        constant: 42,
        terms: vec![],
    };
    assert_eq!(encode_lc(&lc), SmtTerm::int(42));
}

#[test]
fn encode_lc_zero_constant_with_params() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(1, 0.into())],
    };
    // constant=0 is skipped, only p_0
    assert_eq!(encode_lc(&lc), SmtTerm::var("p_0"));
}

#[test]
fn encode_lc_scaled_param() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(3, 1.into())],
    };
    assert_eq!(
        encode_lc(&lc),
        SmtTerm::Mul(Box::new(SmtTerm::int(3)), Box::new(SmtTerm::var("p_1")))
    );
}

// ── encode_threshold_guard tests ─────────────────────────────────

#[test]
fn encode_threshold_guard_distinct_uses_ite() {
    let term = encode_threshold_guard_at_step(
        0,
        &[0, 1],
        CmpOp::Ge,
        &LinearCombination::constant(2),
        true,
    );
    let s = to_smtlib(&term);
    assert!(s.contains("ite"), "distinct guard should use ite: {s}");
}

#[test]
fn encode_threshold_guard_ne_uses_not_eq() {
    let term =
        encode_threshold_guard_at_step(0, &[0], CmpOp::Ne, &LinearCombination::constant(1), false);
    let s = to_smtlib(&term);
    assert!(s.contains("not"), "Ne guard should use Not: {s}");
    assert!(s.contains("="), "Ne guard should use Eq inside Not: {s}");
}

// ── encode_property_violation tests ──────────────────────────────

#[test]
fn encode_property_violation_empty_pairs_is_false() {
    let ta = make_simple_ta();
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let term = encode_property_violation(&ta, &property, 2);
    assert_eq!(term, SmtTerm::bool(false));
}

#[test]
fn encode_property_violation_agreement_single_pair() {
    let ta = make_simple_ta();
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![(0.into(), 1.into())],
    };
    let term = encode_property_violation_at_step(&ta, &property, 0);
    let s = to_smtlib(&term);
    assert!(s.contains("kappa_0_0"), "should reference loc 0: {s}");
    assert!(s.contains("kappa_0_1"), "should reference loc 1: {s}");
}

// ── proptest ─────────────────────────────────────────────────────

use proptest::prelude::*;
use tarsier_ir::proptest_generators::arb_threshold_automaton;

fn arb_ta_and_property() -> impl Strategy<Value = (CounterSystem, SafetyProperty, usize)> {
    arb_threshold_automaton()
        .prop_flat_map(|ta| {
            let nlocs = ta.locations.len();
            let cs = ta;
            // depth 0-3
            (Just(cs), Just(nlocs), 0..=3usize)
        })
        .prop_map(|(cs, nlocs, depth)| {
            // Generate a trivially-empty agreement property (safe for any TA)
            let property = if nlocs >= 2 {
                SafetyProperty::Agreement {
                    conflicting_pairs: vec![(0.into(), 1.into())],
                }
            } else {
                SafetyProperty::Agreement {
                    conflicting_pairs: vec![],
                }
            };
            (cs, property, depth)
        })
}

fn smt_proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 32,
        source_file: Some(file!()),
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
        ..ProptestConfig::default()
    }
}

fn collect_all_var_refs(term: &SmtTerm, out: &mut std::collections::HashSet<String>) {
    match term {
        SmtTerm::Var(name) => {
            out.insert(name.clone());
        }
        SmtTerm::IntLit(_) | SmtTerm::BoolLit(_) => {}
        SmtTerm::Add(l, r)
        | SmtTerm::Sub(l, r)
        | SmtTerm::Mul(l, r)
        | SmtTerm::Eq(l, r)
        | SmtTerm::Lt(l, r)
        | SmtTerm::Le(l, r)
        | SmtTerm::Gt(l, r)
        | SmtTerm::Ge(l, r)
        | SmtTerm::Implies(l, r) => {
            collect_all_var_refs(l, out);
            collect_all_var_refs(r, out);
        }
        SmtTerm::And(ts) | SmtTerm::Or(ts) => {
            for t in ts {
                collect_all_var_refs(t, out);
            }
        }
        SmtTerm::Not(inner) => collect_all_var_refs(inner, out),
        SmtTerm::ForAll(_, body) | SmtTerm::Exists(_, body) => {
            collect_all_var_refs(body, out);
        }
        SmtTerm::Ite(c, t, e) => {
            collect_all_var_refs(c, out);
            collect_all_var_refs(t, out);
            collect_all_var_refs(e, out);
        }
    }
}

proptest! {
    #![proptest_config(smt_proptest_config())]

    #[test]
    fn encode_bmc_never_panics((cs, property, depth) in arb_ta_and_property()) {
        let _enc = encode_bmc(&cs, &property, depth);
    }

    #[test]
    fn encode_bmc_produces_nonempty_encoding((cs, property, depth) in arb_ta_and_property()) {
        let enc = encode_bmc(&cs, &property, depth);
        prop_assert!(!enc.declarations.is_empty(), "declarations must be non-empty");
        prop_assert!(!enc.assertions.is_empty(), "assertions must be non-empty");
    }

    #[test]
    fn encode_bmc_all_declared_vars_appear_in_model_vars((cs, property, depth) in arb_ta_and_property()) {
        let enc = encode_bmc(&cs, &property, depth);
        let model_var_names: std::collections::HashSet<_> =
            enc.model_vars.iter().map(|(n, _)| n.clone()).collect();
        for (name, _) in &enc.declarations {
            prop_assert!(
                model_var_names.contains(name),
                "declared var {} not in model_vars", name
            );
        }
    }

    #[test]
    fn encode_bmc_assertions_are_structurally_valid((cs, property, depth) in arb_ta_and_property()) {
        let enc = encode_bmc(&cs, &property, depth);
        let declared: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        // Collect all var references from assertions
        let mut referenced = std::collections::HashSet::new();
        for assertion in &enc.assertions {
            collect_all_var_refs(assertion, &mut referenced);
        }
        // Every referenced variable must be declared
        for var_name in &referenced {
            prop_assert!(
                declared.contains(var_name),
                "undeclared variable {} referenced in assertions", var_name
            );
        }
    }
}

// ── Parse-and-lower integration tests ─────────────────────────────

fn parse_and_lower(source: &str) -> CounterSystem {
    let program = tarsier_dsl::parse(source, "test.trs").unwrap();
    tarsier_ir::lowering::lower(&program).unwrap()
}

const RELIABLE_BROADCAST_SAFE: &str = r#"
protocol RB {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
    }

    message Init;
    message Echo;
    message Ready;

    role Process {
        var accepted: bool = false;
        var decided: bool = false;
        var decision: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Init => {
                accepted = true;
                send Echo;
                goto phase echoed;
            }
        }

        phase echoed {
            when received >= 2*t+1 Echo => {
                send Ready;
                goto phase readied;
            }
        }

        phase readied {
            when received >= 2*t+1 Ready => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

const BUGGY_BROADCAST: &str = r#"
protocol BuggyBroadcast {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Commit;
    message Abort;

    role Process {
        var decided: bool = false;
        var decision: bool = false;

        init propose;

        phase propose {
            when received >= 1 Vote => {
                send Vote;
                goto phase voted;
            }
            when received >= 1 Abort => {
                decision = false;
                decided = true;
                goto phase done_no;
            }
        }

        phase voted {
            when received >= t+1 Vote => {
                send Commit;
                goto phase ready_yes;
            }
        }

        phase ready_yes {
            when received >= t+1 Commit => {
                decision = true;
                decided = true;
                goto phase done_yes;
            }
        }

        phase done_yes {}
        phase done_no {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

#[test]
fn parsed_protocol_encoding_has_expected_param_declarations() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let decl_names: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    // Should have parameter variables for n, t, f
    assert!(decl_names.contains("p_0"), "missing param p_0 (n)");
    assert!(decl_names.contains("p_1"), "missing param p_1 (t)");
    assert!(decl_names.contains("p_2"), "missing param p_2 (f)");
}

#[test]
fn parsed_protocol_encoding_has_kappa_gamma_delta_time_vars() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let decl_names: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();
    let num_locs = cs.num_locations();
    let num_svars = cs.num_shared_vars();
    let num_rules = cs.num_rules();

    // Step 0 kappa variables
    for l in 0..num_locs {
        assert!(decl_names.contains(&kappa_var(0, l)), "missing kappa_0_{l}");
    }
    // Step 1 kappa variables
    for l in 0..num_locs {
        assert!(decl_names.contains(&kappa_var(1, l)), "missing kappa_1_{l}");
    }
    // Gamma variables at step 0 and 1
    for v in 0..num_svars {
        assert!(decl_names.contains(&gamma_var(0, v)), "missing g_0_{v}");
        assert!(decl_names.contains(&gamma_var(1, v)), "missing g_1_{v}");
    }
    // Delta variables for step 0
    for r in 0..num_rules {
        assert!(decl_names.contains(&delta_var(0, r)), "missing delta_0_{r}");
    }
    // Time variables
    assert!(decl_names.contains(&time_var(0)), "missing time_0");
    assert!(decl_names.contains(&time_var(1)), "missing time_1");
}

#[test]
fn parsed_protocol_initial_state_constraints() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
    let ta = &cs;

    // All shared vars start at 0
    for v in 0..cs.num_shared_vars() {
        let expected = format!("(= g_0_{v} 0)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "missing initial zero constraint for g_0_{v}: {expected}"
        );
    }

    // time_0 = 0
    assert!(
        assertions.iter().any(|a| a == "(= time_0 0)"),
        "missing time_0 = 0"
    );

    // Non-initial locations start empty
    for l in 0..cs.num_locations() {
        if !ta.initial_locations.contains(&l.into()) {
            let expected = format!("(= kappa_0_{l} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "non-initial loc {l} should start at 0: {expected}"
            );
        }
    }

    // Parameters are non-negative
    for i in 0..cs.num_parameters() {
        let expected = format!("(>= p_{i} 0)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "missing non-negative param constraint: {expected}"
        );
    }
}

#[test]
fn parsed_protocol_transition_location_updates() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

    // For each location, kappa_{k+1}_l depends on kappa_k_l plus incoming minus outgoing.
    // At minimum, each kappa_1_l should appear in an equality assertion.
    for l in 0..cs.num_locations() {
        let kappa_next = format!("kappa_1_{l}");
        let has_update = assertions
            .iter()
            .any(|a| a.starts_with(&format!("(= {kappa_next}")));
        assert!(
            has_update,
            "missing location counter update for kappa_1_{l}"
        );
    }

    // Delta variables are non-negative
    for r in 0..cs.num_rules() {
        let expected = format!("(>= delta_0_{r} 0)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "missing non-negativity for delta_0_{r}"
        );
    }

    // kappa_{k+1}_l >= 0
    for l in 0..cs.num_locations() {
        let expected = format!("(>= kappa_1_{l} 0)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "missing non-negativity for kappa_1_{l}"
        );
    }
}

#[test]
fn parsed_protocol_time_progression() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

    assert!(
        assertions.iter().any(|a| a == "(= time_1 (+ time_0 1))"),
        "missing time_1 = time_0 + 1"
    );
    assert!(
        assertions.iter().any(|a| a == "(= time_2 (+ time_1 1))"),
        "missing time_2 = time_1 + 1"
    );
}

#[test]
fn encoding_depth_scales_declarations() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);

    let enc1 = encode_bmc(&cs, &property, 1);
    let enc2 = encode_bmc(&cs, &property, 2);
    let enc4 = encode_bmc(&cs, &property, 4);

    // More depth = more declarations and assertions
    assert!(
        enc2.declarations.len() > enc1.declarations.len(),
        "depth 2 should have more declarations than depth 1: {} vs {}",
        enc2.declarations.len(),
        enc1.declarations.len()
    );
    assert!(
        enc4.declarations.len() > enc2.declarations.len(),
        "depth 4 should have more declarations than depth 2: {} vs {}",
        enc4.declarations.len(),
        enc2.declarations.len()
    );
    assert!(
        enc2.assertions.len() > enc1.assertions.len(),
        "depth 2 should have more assertions than depth 1"
    );
    assert!(
        enc4.assertions.len() > enc2.assertions.len(),
        "depth 4 should have more assertions than depth 2"
    );

    // Verify depth-specific variables exist
    let decl4: std::collections::HashSet<_> =
        enc4.declarations.iter().map(|(n, _)| n.clone()).collect();
    // Step 4 kappa variables should exist
    assert!(decl4.contains(&kappa_var(4, 0)));
    // Step 3 delta variables should exist (transitions 0..3)
    assert!(decl4.contains(&delta_var(3, 0)));
    // Time variable at step 4
    assert!(decl4.contains(&time_var(4)));
}

#[test]
fn k_induction_step_parsed_protocol() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);

    let step = encode_k_induction_step(&cs, &property, 2);

    // k-induction step should have declarations for steps 0..=k
    let decl_names: std::collections::HashSet<_> =
        step.declarations.iter().map(|(n, _)| n.clone()).collect();
    // Should have kappa at all three steps (0, 1, 2)
    for s in 0..=2 {
        for l in 0..cs.num_locations() {
            assert!(
                decl_names.contains(&kappa_var(s, l)),
                "k-induction step missing kappa_{s}_{l}"
            );
        }
    }
    // Delta variables for steps 0..k-1 (i.e., step 0 and step 1)
    for s in 0..2 {
        for r in 0..cs.num_rules() {
            assert!(
                decl_names.contains(&delta_var(s, r)),
                "k-induction step missing delta_{s}_{r}"
            );
        }
    }

    // k-induction does NOT constrain step 0 to be initial
    // so there should be no "kappa_0_l = 0" for non-initial locations
    // as there is in BMC. Instead, kappa_0 values are free.
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();

    // But it should still have non-negativity for all kappa
    for l in 0..cs.num_locations() {
        let expected = format!("(>= kappa_0_{l} 0)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "k-induction step missing non-negativity for kappa_0_{l}"
        );
    }
}

#[test]
fn parsed_protocol_property_violation_agreement() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);

    // The agreement property should have conflicting pairs
    // (at least for protocols with multiple decision phases)
    match &property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            // Reliable broadcast has a single decision value, so
            // conflicting_pairs might be empty (single phase).
            // Regardless, the encoding should work.
            let enc = encode_bmc(&cs, &property, 1);
            if conflicting_pairs.is_empty() {
                // Violation should be trivially false => UNSAT
                let sat = solve_with_extra_assertions(
                    &enc,
                    &[
                        SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                        SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                        SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                    ],
                );
                assert_eq!(sat, SatResult::Unsat);
            }
        }
        _ => panic!("expected Agreement property"),
    }
}

#[test]
fn parsed_buggy_protocol_violation_is_reachable() {
    let cs = parse_and_lower(BUGGY_BROADCAST);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);

    // The buggy protocol should have conflicting pairs (done_yes vs done_no)
    match &property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            assert!(
                !conflicting_pairs.is_empty(),
                "buggy protocol should have conflicting decision pairs"
            );
        }
        _ => panic!("expected Agreement property"),
    }

    // At sufficient depth, the violation should be SAT (reachable)
    let enc = encode_bmc(&cs, &property, 4);
    let sat = solve_with_extra_assertions(
        &enc,
        &[
            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
        ],
    );
    assert_eq!(
        sat,
        SatResult::Sat,
        "buggy protocol agreement violation should be reachable"
    );
}

#[test]
fn parsed_protocol_adversary_injection_bounded() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

    // The adversary bound parameter (f = p_2) should cap each adv variable
    for v in 0..cs.num_shared_vars() {
        let expected = format!("(<= adv_0_{v} p_2)");
        assert!(
            assertions.iter().any(|a| a == &expected),
            "missing adversary bound for adv_0_{v}: {expected}"
        );
    }

    // f <= t constraint
    assert!(
        assertions.iter().any(|a| a == "(<= p_2 p_1)"),
        "missing f <= t constraint"
    );
}

#[test]
fn depth_zero_encoding_checks_only_initial_state() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 0);
    let decl_names: std::collections::HashSet<_> =
        enc.declarations.iter().map(|(n, _)| n.clone()).collect();

    // At depth 0, there are no transition steps, so no delta variables
    assert!(
        !decl_names.iter().any(|n| n.starts_with("delta_")),
        "depth 0 should have no delta variables"
    );

    // Should still have step 0 kappa and gamma
    assert!(decl_names.contains(&kappa_var(0, 0)));
    assert!(decl_names.contains(&gamma_var(0, 0)));
    assert!(decl_names.contains(&time_var(0)));
}

#[test]
fn property_violation_invariant_encoding() {
    let ta = make_simple_ta();
    // Invariant: bad set = both locations occupied
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![0.into(), 1.into()]],
    };
    let term = encode_property_violation_at_step(&ta, &property, 0);
    let s = to_smtlib(&term);
    assert!(
        s.contains("kappa_0_0") && s.contains("kappa_0_1"),
        "invariant violation should reference both locations: {s}"
    );
}

#[test]
fn property_violation_termination_encoding() {
    let ta = make_simple_ta();
    // Termination: goal is location 1 (done)
    let property = SafetyProperty::Termination {
        goal_locs: vec![1.into()],
    };
    let term = encode_property_violation_at_step(&ta, &property, 0);
    let s = to_smtlib(&term);
    // Termination violation means some process is NOT in a goal location
    // So kappa_0_0 > 0 should appear (location 0 is not a goal)
    assert!(
        s.contains("kappa_0_0"),
        "termination violation should reference non-goal location: {s}"
    );
}

#[test]
fn property_violation_empty_invariant_is_false() {
    let ta = make_simple_ta();
    let property = SafetyProperty::Invariant { bad_sets: vec![] };
    let term = encode_property_violation(&ta, &property, 2);
    assert_eq!(term, SmtTerm::bool(false));
}

#[test]
fn dedup_stats_are_consistent() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 2);

    assert_eq!(
        enc.assertion_candidates(),
        enc.assertion_unique() + enc.assertion_dedup_hits(),
        "candidates should equal unique + dedup hits"
    );
    assert!(
        enc.assertion_unique() > 0,
        "should have at least one unique assertion"
    );
}

#[test]
fn resilience_condition_encoded_from_parsed_protocol() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let enc = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

    // Resilience condition: n > 3*t should appear as (> p_0 (* 3 p_1))
    let has_resilience = assertions
        .iter()
        .any(|a| a.contains("p_0") && a.contains("p_1") && (a.contains(">") || a.contains("<")));
    assert!(
        has_resilience,
        "missing resilience condition encoding involving p_0 and p_1"
    );
}

#[test]
fn k_induction_step_has_conservation_strengthening() {
    let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
    let property = tarsier_ir::properties::extract_agreement_property(&cs);
    let step = encode_k_induction_step(&cs, &property, 1);
    let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();

    // k-induction step should have process conservation: sum of kappa = n
    // This appears as an equality involving p_0 (the n parameter)
    let has_conservation = assertions
        .iter()
        .any(|a| a.contains("kappa_0_") && a.contains("p_0") && a.contains("="));
    assert!(
        has_conservation,
        "k-induction step should have process conservation strengthening"
    );
}

#[test]
fn collection_length_variables_are_declared_and_bounded() {
    let mut ta = make_simple_ta();

    // Add a bounded collection with capacity = n
    ta.add_collection(IrCollectionSpec {
        name: "Votes".into(),
        kind: IrCollectionKind::Log,
        element_type: "int".into(),
        capacity: LinearCombination::param(ParamId::from(0)), // n
        queue_model: QueueModel::None,
    });

    // Add an append rule (waiting->done appends to Votes)
    ta.rules[0].collection_updates.push(CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Append(LinearCombination::constant(1)),
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Check collection length var at step 0 is declared and initialized to 0
    let has_len_init = assertions
        .iter()
        .any(|a| a.contains("clen_0_0") && a.contains("0"));
    assert!(has_len_init, "Collection length should be initialized to 0");

    // Check collection length var at step 1 is declared
    let has_len_step1 = assertions.iter().any(|a| a.contains("clen_1_0"));
    assert!(has_len_step1, "Collection length at step 1 should exist");

    // Check capacity bound exists (clen <= p_0 which is n)
    let has_cap_bound = assertions
        .iter()
        .any(|a| a.contains("clen_") && a.contains("p_0"));
    assert!(
        has_cap_bound,
        "Collection length should be bounded by capacity"
    );
}

#[test]
fn collection_length_update_encodes_append_deltas() {
    let mut ta = make_simple_ta();

    // Add a log collection with constant capacity 5
    ta.add_collection(IrCollectionSpec {
        name: "Log".into(),
        kind: IrCollectionKind::Log,
        element_type: "int".into(),
        capacity: LinearCombination::constant(5),
        queue_model: QueueModel::None,
    });

    // The existing rule (waiting->done) appends to the log
    ta.rules[0].collection_updates.push(CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Append(LinearCombination::constant(42)),
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Length at step 1 should reference delta from rule 0 and clen_0_0
    let has_len_update = assertions
        .iter()
        .any(|a| a.contains("clen_1_0") && (a.contains("clen_0_0") || a.contains("delta_0_")));
    assert!(
        has_len_update,
        "Step 1 length should be updated based on step 0 length + deltas"
    );

    // Capacity bound of 5 should appear
    let has_const_cap = assertions
        .iter()
        .any(|a| a.contains("clen_") && a.contains("5"));
    assert!(has_const_cap, "Constant capacity 5 should appear in bounds");
}

#[test]
fn collection_no_appends_preserves_length() {
    let mut ta = make_simple_ta();

    // Add a collection but no rules reference it
    ta.add_collection(IrCollectionSpec {
        name: "Unused".into(),
        kind: IrCollectionKind::Sequence,
        element_type: "int".into(),
        capacity: LinearCombination::constant(10),
        queue_model: QueueModel::None,
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Length should be preserved across all steps (= equality constraints)
    let step0_eq = assertions
        .iter()
        .any(|a| a.contains("clen_1_0") && a.contains("clen_0_0"));
    let step1_eq = assertions
        .iter()
        .any(|a| a.contains("clen_2_0") && a.contains("clen_1_0"));
    assert!(
        step0_eq,
        "Unused collection length should be preserved step 0→1"
    );
    assert!(
        step1_eq,
        "Unused collection length should be preserved step 1→2"
    );
}

#[test]
fn queue_variable_naming_conventions() {
    // Verify the queue head/tail variable naming follows conventions
    assert_eq!(queue_head_var(0, 0), "qhead_0_0");
    assert_eq!(queue_head_var(3, 1), "qhead_3_1");
    assert_eq!(queue_tail_var(0, 0), "qtail_0_0");
    assert_eq!(queue_tail_var(2, 5), "qtail_2_5");
    assert_eq!(dag_round_active_var(1, 2), "dag_active_1_2");
    assert_eq!(clock_var(1, 2), "clk_1_2");
}

#[test]
fn clock_encoding_applies_timeout_guards_and_updates() {
    let mut ta = make_simple_ta();
    let clock_id = ta.add_clock(IrClockSpec {
        name: "deadline".into(),
    });
    ta.rules[0].clock_guards.push(ClockGuard {
        clock: clock_id,
        op: CmpOp::Ge,
        bound: LinearCombination::constant(2),
    });
    ta.rules[0].clock_updates.push(ClockUpdate {
        clock: clock_id,
        kind: ClockUpdateKind::TickBy(LinearCombination::constant(3)),
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    assert!(
        assertions.iter().any(|a| a.contains("(= clk_0_0 0)")),
        "clock must be initialized at step 0"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(=> (> delta_0_0 0) (>= clk_0_0 2))")),
        "timeout guard should gate rule firing"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(=> (> delta_0_0 0) (= clk_1_0 (+ clk_0_0 3)))")),
        "tick update should advance clock on rule firing"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(=> (= delta_0_0 0) (= clk_1_0 clk_0_0))")),
        "clock should frame when no clock-updating rule fires"
    );
}

#[test]
fn dag_round_encoding_declares_activation_and_parent_constraints() {
    let mut ta = make_simple_ta();
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r0".into(),
        parent_rounds: vec![],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r1".into(),
        parent_rounds: vec!["r0".into()],
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);

    let declarations: std::collections::HashSet<_> = encoding
        .declarations
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert!(declarations.contains("dag_active_0_0"));
    assert!(declarations.contains("dag_active_0_1"));
    assert!(declarations.contains("dag_active_1_0"));
    assert!(declarations.contains("dag_active_1_1"));
    assert!(declarations.contains("dag_active_2_0"));
    assert!(declarations.contains("dag_active_2_1"));

    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(= dag_active_0_0 0)")),
        "step-0 DAG root should initialize to 0"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(>= dag_active_2_1 dag_active_1_1)")),
        "DAG round activation should be monotonic"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("(<= dag_active_2_1 dag_active_1_0)")),
        "child DAG round activation must depend on prior parent activation"
    );

    // Verify delta variables exist.
    assert!(
        declarations.contains("dag_delta_0_0"),
        "should declare dag activation delta"
    );
    assert!(
        declarations.contains("dag_delta_0_1"),
        "should declare dag activation delta for child"
    );
}

#[test]
fn dag_round_delta_equals_next_minus_curr() {
    let mut ta = make_simple_ta();
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r0".into(),
        parent_rounds: vec![],
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 1);

    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
    // dag_delta_0_0 = dag_active_1_0 - dag_active_0_0
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("dag_delta_0_0") && a.contains("dag_active_1_0")),
        "delta should be defined as next - curr; assertions: {:?}",
        assertions
            .iter()
            .filter(|a| a.contains("dag_delta"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn dag_round_multi_parent_all_parents_constrain_child() {
    let mut ta = make_simple_ta();
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r0".into(),
        parent_rounds: vec![],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r1".into(),
        parent_rounds: vec![],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r2".into(),
        parent_rounds: vec!["r0".into(), "r1".into()],
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);

    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
    // r2 (index 2) needs both r0 (index 0) and r1 (index 1) active.
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("dag_active_1_2") && a.contains("dag_active_0_0")),
        "child r2 should depend on parent r0"
    );
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("dag_active_1_2") && a.contains("dag_active_0_1")),
        "child r2 should depend on parent r1"
    );
}

#[test]
fn dag_round_deep_chain_produces_correct_constraint_count() {
    let mut ta = make_simple_ta();
    // Chain: r0 → r1 → r2 → r3
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r0".into(),
        parent_rounds: vec![],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r1".into(),
        parent_rounds: vec!["r0".into()],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r2".into(),
        parent_rounds: vec!["r1".into()],
    });
    ta.dag_rounds.push(IrDagRoundSpec {
        name: "r3".into(),
        parent_rounds: vec!["r2".into()],
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 5);

    let declarations: std::collections::HashSet<_> = encoding
        .declarations
        .iter()
        .map(|(n, _)| n.clone())
        .collect();

    // 4 rounds × 6 steps (0..=5) for active vars
    let dag_active_count = declarations
        .iter()
        .filter(|d| d.starts_with("dag_active_"))
        .count();
    assert_eq!(dag_active_count, 24, "4 rounds × 6 steps = 24 active vars");

    // 4 rounds × 5 deltas (0..4)
    let dag_delta_count = declarations
        .iter()
        .filter(|d| d.starts_with("dag_delta_"))
        .count();
    assert_eq!(dag_delta_count, 20, "4 rounds × 5 steps = 20 delta vars");
}

#[test]
fn fifo_queue_encoding_declares_head_tail_variables() {
    let mut ta = make_simple_ta();

    // Add a FIFO channel collection with capacity = n
    ta.add_collection(IrCollectionSpec {
        name: "MsgQueue".into(),
        kind: IrCollectionKind::FifoChannel,
        element_type: "int".into(),
        capacity: LinearCombination::param(ParamId::from(0)), // n
        queue_model: QueueModel::LinearFifo,
    });

    // Rule: waiting->done enqueues to MsgQueue
    ta.rules[0].collection_updates.push(CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Enqueue(LinearCombination::constant(1)),
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Check head and tail variables are declared at step 0
    let has_head_init = assertions
        .iter()
        .any(|a| a.contains("qhead_0_0") && a.contains("0"));
    let has_tail_init = assertions
        .iter()
        .any(|a| a.contains("qtail_0_0") && a.contains("0"));
    assert!(has_head_init, "Queue head should be initialized to 0");
    assert!(has_tail_init, "Queue tail should be initialized to 0");

    // Check head/tail variables exist at step 1
    let has_head_1 = assertions.iter().any(|a| a.contains("qhead_1_0"));
    let has_tail_1 = assertions.iter().any(|a| a.contains("qtail_1_0"));
    assert!(has_head_1, "Queue head at step 1 should exist");
    assert!(has_tail_1, "Queue tail at step 1 should exist");

    // Check head <= tail constraint
    let has_ordering = assertions
        .iter()
        .any(|a| a.contains("qhead_1_0") && a.contains("qtail_1_0") && a.contains("<="));
    assert!(
        has_ordering,
        "head <= tail ordering constraint should exist"
    );

    // Check occupancy = tail - head = length
    let has_occupancy = assertions
        .iter()
        .any(|a| a.contains("clen_1_0") && a.contains("qtail_1_0") && a.contains("qhead_1_0"));
    assert!(
        has_occupancy,
        "Occupancy (tail - head) should equal collection length"
    );
}

#[test]
fn fifo_queue_dequeue_updates_head() {
    let mut ta = make_simple_ta();

    ta.add_collection(IrCollectionSpec {
        name: "Q".into(),
        kind: IrCollectionKind::FifoChannel,
        element_type: "int".into(),
        capacity: LinearCombination::constant(10),
        queue_model: QueueModel::LinearFifo,
    });

    // Rule: waiting->done dequeues from Q
    ta.rules[0].collection_updates.push(CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Dequeue,
    });

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // head_1 should reference head_0 and delta (dequeue delta)
    let has_head_update = assertions
        .iter()
        .any(|a| a.contains("qhead_1_0") && (a.contains("qhead_0_0") || a.contains("delta_0_")));
    assert!(has_head_update, "Dequeue should update queue head");
}

#[test]
fn fifo_queue_with_enqueue_and_dequeue_combined() {
    let mut ta = make_simple_ta();

    ta.add_collection(IrCollectionSpec {
        name: "Chan".into(),
        kind: IrCollectionKind::FifoChannel,
        element_type: "int".into(),
        capacity: LinearCombination::constant(5),
        queue_model: QueueModel::LinearFifo,
    });

    // Rule 0: waiting->done enqueues
    ta.rules[0].collection_updates.push(CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Enqueue(LinearCombination::constant(1)),
    });

    // Add a second rule for dequeue (done->waiting)
    let dequeue_rule = Rule {
        from: ta.rules[0].to, // done
        to: ta.rules[0].from, // waiting
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Dequeue,
        }],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    };
    ta.rules.push(dequeue_rule);

    let cs: CounterSystem = ta;
    let property = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let declarations: Vec<String> = encoding
        .declarations
        .iter()
        .map(|(name, _)| name.clone())
        .collect();

    // Verify head/tail variables exist at steps 0, 1, 2
    for step in 0..=2 {
        assert!(
            declarations.contains(&queue_head_var(step, 0)),
            "qhead_{step}_0 should be declared"
        );
        assert!(
            declarations.contains(&queue_tail_var(step, 0)),
            "qtail_{step}_0 should be declared"
        );
    }

    // Verify capacity bound (5) appears in assertions
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
    let has_cap = assertions
        .iter()
        .any(|a| a.contains("clen_") && a.contains("5"));
    assert!(has_cap, "Capacity bound of 5 should appear");
}

// ── RECONF-04: epoch-aware parameter encoding tests ─────────────

#[test]
fn encode_lc_at_step_fixed_params_use_global_vars() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(1, ParamId::from(0))],
    };
    // No time-varying params → should use global p_0
    let term = encode_lc_at_step(&lc, 3, &[]);
    assert_eq!(term, SmtTerm::var("p_0"));
}

#[test]
fn encode_lc_at_step_varying_params_use_step_vars() {
    let lc = LinearCombination {
        constant: 5,
        terms: vec![(2, ParamId::from(1))],
    };
    // Param 1 is time-varying → should use p_1_2 at step 2
    let term = encode_lc_at_step(&lc, 2, &[1]);
    // Expected: 5 + 2*p_1_2
    let expected = SmtTerm::int(5).add(SmtTerm::int(2).mul(SmtTerm::var("p_1_2")));
    assert_eq!(term, expected);
}

#[test]
fn encode_lc_at_step_mixed_fixed_and_varying() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(1, ParamId::from(0)), (1, ParamId::from(1))],
    };
    // Param 0 fixed, param 1 varying, at step 5
    let term = encode_lc_at_step(&lc, 5, &[1]);
    // Expected: p_0 + p_1_5
    let expected = SmtTerm::var("p_0").add(SmtTerm::var("p_1_5"));
    assert_eq!(term, expected);
}

#[test]
fn epoch_encoding_declares_step_param_vars() {
    // Build a minimal TA with a time-varying parameter and a reconfigure rule
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter::fixed("n".to_string()));
    let t_id = ta.add_parameter(Parameter::varying("t".to_string()));
    let l0 = ta.add_location(Location {
        name: "Init".into(),
        role: "R".into(),
        phase: "init".into(),
        local_vars: IndexMap::new(),
    });
    let l1 = ta.add_location(Location {
        name: "Done".into(),
        role: "R".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations.push(l0);
    ta.add_shared_var(SharedVar {
        name: "votes".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_rule(Rule {
        from: l0,
        to: l1,
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![ParamUpdate {
            param: t_id,
            value: LinearCombination::constant(5),
        }],
    });
    ta.constraints.adversary_bound_param = Some(t_id);

    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 2);

    let decl_names: Vec<&str> = encoding
        .declarations
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();

    // Should have step-dependent param vars for the varying param (index 1)
    assert!(
        decl_names.contains(&"p_1_0"),
        "should declare p_1_0 (step-0 varying param)"
    );
    assert!(
        decl_names.contains(&"p_1_1"),
        "should declare p_1_1 (step-1 varying param)"
    );
    assert!(
        decl_names.contains(&"p_1_2"),
        "should declare p_1_2 (step-2 varying param)"
    );

    // Global p_0 (fixed) and p_1 (initial value) should also exist
    assert!(decl_names.contains(&"p_0"), "should declare global p_0");
    assert!(
        decl_names.contains(&"p_1"),
        "should declare global p_1 (initial)"
    );
}

// ── RECONF-03: multi-epoch regression tests ─────────────────────

/// Helper: build a minimal TA with n (fixed), t (varying), and a
/// reconfigure rule from l0→l1 that sets t = new_value.
fn build_reconfig_ta(
    new_value: LinearCombination,
) -> (ThresholdAutomaton, LocationId, LocationId, ParamId) {
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter::fixed("n".to_string()));
    let t_id = ta.add_parameter(Parameter::varying("t".to_string()));
    let l0 = ta.add_location(Location {
        name: "Init".into(),
        role: "R".into(),
        phase: "init".into(),
        local_vars: IndexMap::new(),
    });
    let l1 = ta.add_location(Location {
        name: "Done".into(),
        role: "R".into(),
        phase: "done".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations.push(l0);
    ta.add_shared_var(SharedVar {
        name: "votes".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_rule(Rule {
        from: l0,
        to: l1,
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![ParamUpdate {
            param: t_id,
            value: new_value,
        }],
    });
    ta.constraints.adversary_bound_param = Some(t_id);
    (ta, l0, l1, t_id)
}

#[test]
fn epoch_resilience_reasserted_at_each_step() {
    // TA with resilience n > 3*t and reconfigure { t = 5; }
    let (mut ta, _l0, l1, _t_id) = build_reconfig_ta(LinearCombination::constant(5));
    ta.constraints.resilience_condition = Some(LinearConstraint {
        lhs: LinearCombination {
            constant: 0,
            terms: vec![(1, ParamId::from(0))], // n
        },
        op: CmpOp::Gt,
        rhs: LinearCombination {
            constant: 0,
            terms: vec![(3, ParamId::from(1))], // 3*t
        },
    });

    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 2);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Should contain resilience re-assertion at step 1 using p_1_1 (step-1 t)
    let has_epoch_resilience = assertions
        .iter()
        .any(|a| a.contains("p_1_1") && a.contains("p_0"));
    assert!(
        has_epoch_resilience,
        "resilience should be re-asserted using epoch-aware params at step 1"
    );
}

#[test]
fn epoch_mutual_exclusion_for_multi_rule_updates() {
    // TA with two rules both updating t to different values
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter::fixed("n".to_string()));
    let t_id = ta.add_parameter(Parameter::varying("t".to_string()));
    let l0 = ta.add_location(Location {
        name: "Init".into(),
        role: "R".into(),
        phase: "init".into(),
        local_vars: IndexMap::new(),
    });
    let l1 = ta.add_location(Location {
        name: "DoneA".into(),
        role: "R".into(),
        phase: "done_a".into(),
        local_vars: IndexMap::new(),
    });
    let l2 = ta.add_location(Location {
        name: "DoneB".into(),
        role: "R".into(),
        phase: "done_b".into(),
        local_vars: IndexMap::new(),
    });
    ta.initial_locations.push(l0);
    ta.add_shared_var(SharedVar {
        name: "votes".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    // Rule 0: reconfigure t = 1
    ta.add_rule(Rule {
        from: l0,
        to: l1,
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![ParamUpdate {
            param: t_id,
            value: LinearCombination::constant(1),
        }],
    });
    // Rule 1: reconfigure t = 2
    ta.add_rule(Rule {
        from: l0,
        to: l2,
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![ParamUpdate {
            param: t_id,
            value: LinearCombination::constant(2),
        }],
    });
    ta.constraints.adversary_bound_param = Some(t_id);

    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 1);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Should contain mutual exclusion constraint (ite-based indicator sum <= 1)
    let has_mutex = assertions
        .iter()
        .any(|a| a.contains("ite") && a.contains("delta_0_0") && a.contains("delta_0_1"));
    assert!(
        has_mutex,
        "should have mutual-exclusion constraint for multi-rule param updates"
    );
}

#[test]
fn epoch_frame_constraint_preserves_unchanged_params() {
    // TA with varying param but no rule updates it at some steps
    let (ta, _l0, l1, _t_id) = build_reconfig_ta(LinearCombination::constant(5));
    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 3);
    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

    // Check frame constraints exist at each step boundary
    for step in 0..3 {
        let curr = format!("p_1_{}", step);
        let next = format!("p_1_{}", step + 1);
        let has_frame = assertions
            .iter()
            .any(|a| a.contains(&curr) && a.contains(&next));
        assert!(
            has_frame,
            "should have frame/update constraint between step {} and {}",
            step,
            step + 1
        );
    }
}

#[test]
fn reconfiguration_max_count_constraints_emitted() {
    let (mut ta, _l0, l1, _t_id) = build_reconfig_ta(LinearCombination::constant(5));
    ta.reconfiguration = Some(ReconfigurationSpec {
        semantics: ReconfigurationSemantics::NextStep,
        max_reconfigurations: 2,
    });

    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 2);

    let decl_names: Vec<&str> = encoding
        .declarations
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(decl_names.contains(&"reconf_count_0"));
    assert!(decl_names.contains(&"reconf_count_1"));
    assert!(decl_names.contains(&"reconf_count_2"));

    let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
    assert!(
        assertions
            .iter()
            .any(|a| a.contains("reconf_count_1") && a.contains("<=") && a.contains("2")),
        "expected max_reconfigurations upper bound constraint"
    );
}

#[test]
fn immediate_reconfiguration_semantics_fail_closed() {
    let (mut ta, _l0, l1, _t_id) = build_reconfig_ta(LinearCombination::constant(5));
    ta.reconfiguration = Some(ReconfigurationSpec {
        semantics: ReconfigurationSemantics::Immediate,
        max_reconfigurations: 0,
    });

    let cs = CounterSystem::from(ta);
    let property = SafetyProperty::Invariant {
        bad_sets: vec![vec![l1]],
    };
    let encoding = encode_bmc(&cs, &property, 1);
    assert!(
        encoding.assertions.contains(&SmtTerm::bool(false)),
        "encoder should fail closed when immediate semantics is requested"
    );
}
