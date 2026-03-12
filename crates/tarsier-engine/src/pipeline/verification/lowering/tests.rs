use crate::pipeline::verification::*;
use crate::pipeline::*;
use tarsier_ir::threshold_automaton::{Guard, LinearCombination, Rule, Update, UpdateKind};

// Helper: create a minimal ProtocolDecl for testing
fn empty_proto() -> ast::ProtocolDecl {
    ast::ProtocolDecl {
        name: "Test".into(),
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
    }
}

#[test]
fn adversary_value_returns_matching_key() {
    let mut proto = empty_proto();
    proto.adversary.push(ast::AdversaryItem {
        key: "model".into(),
        value: "byzantine".into(),
        span: ast::Span::new(0, 0),
    });
    assert_eq!(adversary_value(&proto, "model"), Some("byzantine"));
}

#[test]
fn adversary_value_returns_none_for_missing_key() {
    let proto = empty_proto();
    assert_eq!(adversary_value(&proto, "model"), None);
}

#[test]
fn upsert_adversary_item_inserts_new() {
    let mut proto = empty_proto();
    upsert_adversary_item(&mut proto, "auth", "signed");
    assert_eq!(adversary_value(&proto, "auth"), Some("signed"));
    assert_eq!(proto.adversary.len(), 1);
}

#[test]
fn upsert_adversary_item_updates_existing() {
    let mut proto = empty_proto();
    proto.adversary.push(ast::AdversaryItem {
        key: "auth".into(),
        value: "none".into(),
        span: ast::Span::new(0, 0),
    });
    upsert_adversary_item(&mut proto, "auth", "signed");
    assert_eq!(adversary_value(&proto, "auth"), Some("signed"));
    assert_eq!(proto.adversary.len(), 1);
}

#[test]
fn network_semantics_name_all_variants() {
    assert_eq!(network_semantics_name(NetworkSemantics::Classic), "classic");
    assert_eq!(
        network_semantics_name(NetworkSemantics::IdentitySelective),
        "identity_selective"
    );
    assert_eq!(
        network_semantics_name(NetworkSemantics::CohortSelective),
        "cohort_selective"
    );
    assert_eq!(
        network_semantics_name(NetworkSemantics::ProcessSelective),
        "process_selective"
    );
}

#[test]
fn fault_model_name_all_variants() {
    assert_eq!(fault_model_name(FaultModel::Byzantine), "byzantine");
    assert_eq!(fault_model_name(FaultModel::Crash), "crash");
    assert_eq!(fault_model_name(FaultModel::Omission), "omission");
}

#[test]
fn authentication_mode_name_all_variants() {
    assert_eq!(authentication_mode_name(AuthenticationMode::None), "none");
    assert_eq!(
        authentication_mode_name(AuthenticationMode::Signed),
        "signed"
    );
}

#[test]
fn equivocation_mode_name_all_variants() {
    assert_eq!(equivocation_mode_name(EquivocationMode::Full), "full");
    assert_eq!(equivocation_mode_name(EquivocationMode::None), "none");
}

#[test]
fn parse_declared_network_semantics_classic_default() {
    assert_eq!(
        parse_declared_network_semantics("classic"),
        NetworkSemantics::Classic
    );
    assert_eq!(
        parse_declared_network_semantics("unknown_value"),
        NetworkSemantics::Classic
    );
}

#[test]
fn parse_declared_network_semantics_identity_selective_aliases() {
    assert_eq!(
        parse_declared_network_semantics("identity_selective"),
        NetworkSemantics::IdentitySelective
    );
    assert_eq!(
        parse_declared_network_semantics("faithful"),
        NetworkSemantics::IdentitySelective
    );
    assert_eq!(
        parse_declared_network_semantics("selective"),
        NetworkSemantics::IdentitySelective
    );
    assert_eq!(
        parse_declared_network_semantics("selective_delivery"),
        NetworkSemantics::IdentitySelective
    );
}

#[test]
fn parse_declared_network_semantics_cohort_selective_aliases() {
    assert_eq!(
        parse_declared_network_semantics("cohort_selective"),
        NetworkSemantics::CohortSelective
    );
    assert_eq!(
        parse_declared_network_semantics("lane_selective"),
        NetworkSemantics::CohortSelective
    );
}

#[test]
fn parse_declared_network_semantics_process_selective_aliases() {
    assert_eq!(
        parse_declared_network_semantics("process_selective"),
        NetworkSemantics::ProcessSelective
    );
    assert_eq!(
        parse_declared_network_semantics("per_process"),
        NetworkSemantics::ProcessSelective
    );
    assert_eq!(
        parse_declared_network_semantics("process_scoped"),
        NetworkSemantics::ProcessSelective
    );
}

#[test]
fn is_faithful_network_correct() {
    assert!(!is_faithful_network(NetworkSemantics::Classic));
    assert!(is_faithful_network(NetworkSemantics::IdentitySelective));
    assert!(is_faithful_network(NetworkSemantics::CohortSelective));
    assert!(is_faithful_network(NetworkSemantics::ProcessSelective));
}

#[test]
fn next_coarser_network_mode_process_to_cohort() {
    assert_eq!(
        next_coarser_network_mode(
            NetworkSemantics::ProcessSelective,
            FaithfulFallbackFloor::IdentitySelective
        ),
        Some(NetworkSemantics::CohortSelective)
    );
}

#[test]
fn next_coarser_network_mode_cohort_to_identity() {
    assert_eq!(
        next_coarser_network_mode(
            NetworkSemantics::CohortSelective,
            FaithfulFallbackFloor::IdentitySelective
        ),
        Some(NetworkSemantics::IdentitySelective)
    );
}

#[test]
fn next_coarser_network_mode_identity_floors() {
    // With IdentitySelective floor, identity cannot go lower
    assert_eq!(
        next_coarser_network_mode(
            NetworkSemantics::IdentitySelective,
            FaithfulFallbackFloor::IdentitySelective
        ),
        None
    );
    // With Classic floor, identity can fall back to classic
    assert_eq!(
        next_coarser_network_mode(
            NetworkSemantics::IdentitySelective,
            FaithfulFallbackFloor::Classic
        ),
        Some(NetworkSemantics::Classic)
    );
}

#[test]
fn next_coarser_network_mode_classic_is_bottom() {
    assert_eq!(
        next_coarser_network_mode(NetworkSemantics::Classic, FaithfulFallbackFloor::Classic),
        None
    );
}

#[test]
fn footprint_exceeds_budget_all_within() {
    let footprint = AutomatonFootprint {
        locations: 10,
        rules: 5,
        shared_vars: 8,
        message_counters: 3,
    };
    let cfg = FaithfulFallbackConfig {
        max_locations: 20,
        max_shared_vars: 20,
        max_message_counters: 10,
        floor: FaithfulFallbackFloor::IdentitySelective,
    };
    assert!(!footprint_exceeds_budget(&footprint, &cfg));
}

#[test]
fn footprint_exceeds_budget_locations_over() {
    let footprint = AutomatonFootprint {
        locations: 25,
        rules: 5,
        shared_vars: 8,
        message_counters: 3,
    };
    let cfg = FaithfulFallbackConfig {
        max_locations: 20,
        max_shared_vars: 20,
        max_message_counters: 10,
        floor: FaithfulFallbackFloor::IdentitySelective,
    };
    assert!(footprint_exceeds_budget(&footprint, &cfg));
}

#[test]
fn por_normalized_vars_sorts_and_deduplicates() {
    let vars = vec![3, 1, 2, 1, 3];
    assert_eq!(por_normalized_vars(&vars), vec![1, 2, 3]);
}

#[test]
fn por_normalized_vars_empty() {
    let vars: Vec<usize> = vec![];
    assert_eq!(por_normalized_vars(&vars), Vec::<usize>::new());
}

#[test]
fn por_normalized_lc_terms_merges_and_filters() {
    let lc = LinearCombination {
        constant: 0,
        terms: vec![(2, 0.into()), (3, 0.into()), (1, 1.into()), (0, 2.into())],
    };
    let result = por_normalized_lc_terms(&lc);
    // pid=0: 2+3=5, pid=1: 1, pid=2: coeff 0 is filtered
    assert_eq!(result, vec![(5, 0), (1, 1)]);
}

#[test]
fn por_comparable_lc_constants_same_terms() {
    let lhs = LinearCombination {
        constant: 10,
        terms: vec![(1, 0.into())],
    };
    let rhs = LinearCombination {
        constant: 20,
        terms: vec![(1, 0.into())],
    };
    assert_eq!(por_comparable_lc_constants(&lhs, &rhs), Some((10, 20)));
}

#[test]
fn por_comparable_lc_constants_different_terms() {
    let lhs = LinearCombination {
        constant: 10,
        terms: vec![(1, 0.into())],
    };
    let rhs = LinearCombination {
        constant: 20,
        terms: vec![(1, 1.into())],
    };
    assert_eq!(por_comparable_lc_constants(&lhs, &rhs), None);
}

#[test]
fn por_threshold_op_entails_basic_cases() {
    // Eq entails Eq only if same constant
    assert!(por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 5));
    assert!(!por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 6));
    // Eq entails Ge if lhs_const >= rhs_const
    assert!(por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Ge, 3));
    assert!(!por_threshold_op_entails(CmpOp::Eq, 3, CmpOp::Ge, 5));
    // Ge entails Ge if lhs_const >= rhs_const
    assert!(por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Ge, 3));
    assert!(por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Ge, 5));
    assert!(!por_threshold_op_entails(CmpOp::Ge, 3, CmpOp::Ge, 5));
    // Gt entails Ge
    assert!(por_threshold_op_entails(CmpOp::Gt, 5, CmpOp::Ge, 5));
    // Le entails Le
    assert!(por_threshold_op_entails(CmpOp::Le, 3, CmpOp::Le, 5));
    // Ne entails Ne only if same constant
    assert!(por_threshold_op_entails(CmpOp::Ne, 5, CmpOp::Ne, 5));
    assert!(!por_threshold_op_entails(CmpOp::Ne, 5, CmpOp::Ne, 6));
    // Cross that should not entail
    assert!(!por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Le, 5));
}

#[test]
fn is_pure_stutter_rule_true_case() {
    let rule = Rule {
        from: 0.into(),
        to: 0.into(),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    };
    assert!(is_pure_stutter_rule(&rule));
}

#[test]
fn is_pure_stutter_rule_false_different_locations() {
    let rule = Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    };
    assert!(!is_pure_stutter_rule(&rule));
}

#[test]
fn is_pure_stutter_rule_false_has_updates() {
    let rule = Rule {
        from: 0.into(),
        to: 0.into(),
        guard: Guard::trivial(),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    };
    assert!(!is_pure_stutter_rule(&rule));
}

#[test]
fn guard_read_vars_extracts_vars() {
    let guard = Guard {
        atoms: vec![
            GuardAtom::Threshold {
                vars: vec![0.into(), 1.into()],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            },
            GuardAtom::Threshold {
                vars: vec![2.into()],
                op: CmpOp::Gt,
                bound: LinearCombination::constant(0),
                distinct: false,
            },
        ],
    };
    let reads = guard_read_vars(&guard);
    assert!(reads.contains(&0));
    assert!(reads.contains(&1));
    assert!(reads.contains(&2));
    assert_eq!(reads.len(), 3);
}

#[test]
fn update_write_vars_extracts_vars() {
    let updates = vec![
        Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        },
        Update {
            var: 3.into(),
            kind: UpdateKind::Increment,
        },
    ];
    let writes = update_write_vars(&updates);
    assert!(writes.contains(&0));
    assert!(writes.contains(&3));
    assert_eq!(writes.len(), 2);
}

#[test]
fn por_linear_combination_signature_format() {
    let lc = LinearCombination {
        constant: 5,
        terms: vec![(2, 0.into()), (1, 1.into())],
    };
    let sig = por_linear_combination_signature(&lc);
    assert_eq!(sig, "c=5|2*p0|1*p1");
}

#[test]
fn por_update_signature_increment() {
    let update = Update {
        var: 3.into(),
        kind: UpdateKind::Increment,
    };
    assert_eq!(por_update_signature(&update), "inc@3");
}

#[test]
fn por_update_signature_set() {
    let update = Update {
        var: 1.into(),
        kind: UpdateKind::Set(LinearCombination {
            constant: 0,
            terms: vec![(1, 0.into())],
        }),
    };
    assert_eq!(por_update_signature(&update), "set@1=c=0|1*p0");
}

#[test]
fn upsert_message_channel_policy_inserts_new() {
    let mut proto = empty_proto();
    upsert_message_channel_policy(&mut proto, "Vote", ast::ChannelAuthMode::Authenticated);
    assert_eq!(proto.channels.len(), 1);
    assert_eq!(proto.channels[0].message, "Vote");
    assert_eq!(proto.channels[0].auth, ast::ChannelAuthMode::Authenticated);
}

#[test]
fn upsert_message_channel_policy_updates_existing() {
    let mut proto = empty_proto();
    proto.channels.push(ast::ChannelDecl {
        message: "Vote".into(),
        auth: ast::ChannelAuthMode::Unauthenticated,
        span: ast::Span::new(0, 0),
    });
    upsert_message_channel_policy(&mut proto, "Vote", ast::ChannelAuthMode::Authenticated);
    assert_eq!(proto.channels.len(), 1);
    assert_eq!(proto.channels[0].auth, ast::ChannelAuthMode::Authenticated);
}

#[test]
fn upsert_message_equivocation_policy_inserts_new() {
    let mut proto = empty_proto();
    upsert_message_equivocation_policy(&mut proto, "Vote", ast::EquivocationPolicyMode::None);
    assert_eq!(proto.equivocation_policies.len(), 1);
    assert_eq!(proto.equivocation_policies[0].message, "Vote");
    assert_eq!(
        proto.equivocation_policies[0].mode,
        ast::EquivocationPolicyMode::None
    );
}

#[test]
fn upsert_message_equivocation_policy_updates_existing() {
    let mut proto = empty_proto();
    proto.equivocation_policies.push(ast::EquivocationDecl {
        message: "Vote".into(),
        mode: ast::EquivocationPolicyMode::Full,
        span: ast::Span::new(0, 0),
    });
    upsert_message_equivocation_policy(&mut proto, "Vote", ast::EquivocationPolicyMode::None);
    assert_eq!(proto.equivocation_policies.len(), 1);
    assert_eq!(
        proto.equivocation_policies[0].mode,
        ast::EquivocationPolicyMode::None
    );
}
