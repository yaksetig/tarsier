use super::*;
use std::collections::HashMap;
use tarsier_ir::threshold_automaton::{
    AuthenticationMode, CryptoConflictPolicy, Guard, IrCryptoObjectKind, IrCryptoObjectSpec,
    LinearCombination, Location, MessageAuthPolicy, MessagePolicy, Parameter, RoleIdentityConfig,
    RoleIdentityScope, Rule, SharedVar, SharedVarKind, Update,
};
use tarsier_smt::solver::ModelValue;

fn test_model(entries: &[(&str, ModelValue)]) -> Model {
    let mut values = HashMap::new();
    for (k, v) in entries {
        values.insert((*k).to_string(), v.clone());
    }
    Model { values }
}

fn make_location(name: &str, role: &str, pid: i64) -> Location {
    let mut loc = Location {
        name: name.to_string(),
        role: role.to_string(),
        phase: "p".to_string(),
        local_vars: Default::default(),
    };
    loc.local_vars
        .insert("pid".to_string(), LocalValue::Int(pid));
    loc
}

fn make_ta(counter_name: &str, authenticated: bool) -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    ta.add_parameter(Parameter {
        name: "n".to_string(),
        time_varying: false,
    });
    let from = ta.add_location(make_location("L0", "Replica", 0));
    let to = ta.add_location(make_location("L1", "Replica", 1));
    ta.initial_locations.push(from);
    ta.add_shared_var(SharedVar {
        name: counter_name.to_string(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.add_rule(Rule {
        from,
        to,
        guard: Guard::trivial(),
        updates: vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });
    ta.security.role_identities.insert(
        "Replica".to_string(),
        RoleIdentityConfig {
            scope: RoleIdentityScope::Process,
            process_var: Some("pid".to_string()),
            key_name: "replica_key".to_string(),
        },
    );
    ta.security
        .key_ownership
        .insert("replica_key".to_string(), "Replica".to_string());
    ta.semantics.authentication_mode = if authenticated {
        AuthenticationMode::Signed
    } else {
        AuthenticationMode::None
    };
    ta
}

fn forge_event(sender_pid: &str, family: &str, variant: &str) -> MessageDeliveryEvent {
    MessageDeliveryEvent {
        shared_var: 0,
        shared_var_name: "cnt_dummy".to_string(),
        sender: MessageIdentity {
            role: "Replica".to_string(),
            process: Some(sender_pid.to_string()),
            key: Some("replica_key".to_string()),
        },
        recipient: MessageIdentity {
            role: "Replica".to_string(),
            process: Some("1".to_string()),
            key: Some("replica_key".to_string()),
        },
        payload: MessagePayloadVariant {
            family: family.to_string(),
            fields: vec![],
            variant: variant.to_string(),
        },
        count: 1,
        kind: MessageEventKind::Forge,
        auth: MessageAuthMetadata {
            authenticated_channel: true,
            signature_key: Some("replica_key".to_string()),
            key_owner_role: Some("Replica".to_string()),
            key_compromised: false,
            provenance: SignatureProvenance::OwnedKey,
        },
    }
}

#[test]
fn parse_counter_metadata_extracts_family_recipient_sender_and_fields() {
    let parsed = parse_counter_message_metadata("cnt_Vote@Replica#1<-Replica#0[view=2,value=true]")
        .expect("counter metadata should parse");
    assert_eq!(parsed.0, "Vote");
    assert_eq!(parsed.1, "Replica#1");
    assert_eq!(parsed.2.as_deref(), Some("Replica#0"));
    assert_eq!(parsed.3.family, "Vote");
    assert_eq!(
        parsed.3.fields,
        vec![
            ("view".to_string(), "2".to_string()),
            ("value".to_string(), "true".to_string())
        ]
    );
    assert_eq!(parsed.3.variant, "Vote[view=2,value=true]");
}

#[test]
fn parse_counter_metadata_rejects_non_counter_names() {
    assert!(parse_counter_message_metadata("g_0").is_none());
}

#[test]
fn parse_counter_metadata_supports_minimal_counter_shape() {
    let parsed = parse_counter_message_metadata("cnt_Vote").expect("counter should parse");
    assert_eq!(parsed.0, "Vote");
    assert_eq!(parsed.1, "*");
    assert_eq!(parsed.2, None);
    assert_eq!(parsed.3.fields.len(), 0);
    assert_eq!(parsed.3.variant, "Vote");
}

#[test]
fn sender_role_parser_handles_none_role_and_role_with_pid() {
    assert_eq!(sender_role_from_channel(None), None);
    assert_eq!(sender_role_from_channel(Some("Replica")), Some("Replica"));
    assert_eq!(sender_role_from_channel(Some("Replica#7")), Some("Replica"));
}

#[test]
fn identity_helpers_extract_process_and_key_information() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let recipient = identity_from_recipient_channel(&ta, "Replica#7");
    let sender = identity_from_sender_channel(&ta, "Replica#3");
    let from_loc = identity_from_location(&ta, 0);

    assert_eq!(recipient.role, "Replica");
    assert_eq!(recipient.process.as_deref(), Some("7"));
    assert_eq!(recipient.key.as_deref(), Some("replica_key"));
    assert_eq!(sender.process.as_deref(), Some("3"));
    assert_eq!(from_loc.process.as_deref(), Some("0"));
}

#[test]
fn auth_metadata_owned_sender_tracks_auth_policy_and_compromise() {
    let mut ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let sender = MessageIdentity {
        role: "Replica".to_string(),
        process: Some("0".to_string()),
        key: Some("replica_key".to_string()),
    };

    let owned = auth_metadata_for_owned_sender(&ta, &sender, "Vote");
    assert_eq!(owned.provenance, SignatureProvenance::OwnedKey);
    assert!(owned.authenticated_channel);
    assert!(!owned.key_compromised);

    ta.security
        .compromised_keys
        .insert("replica_key".to_string());
    let compromised = auth_metadata_for_owned_sender(&ta, &sender, "Vote");
    assert_eq!(compromised.provenance, SignatureProvenance::CompromisedKey);
    assert!(compromised.key_compromised);

    ta.security.message_policies.insert(
        "Vote".to_string(),
        MessagePolicy {
            auth: MessageAuthPolicy::Unauthenticated,
            equivocation: Default::default(),
        },
    );
    let unauth = auth_metadata_for_owned_sender(&ta, &sender, "Vote");
    assert_eq!(
        unauth.provenance,
        SignatureProvenance::UnauthenticatedChannel
    );
    assert!(!unauth.authenticated_channel);
    assert!(unauth.signature_key.is_none());
}

#[test]
fn auth_metadata_for_forge_chooses_compromised_or_byzantine_provenance() {
    let mut ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let byz = auth_metadata_for_forge(&ta, "Vote");
    assert_eq!(byz.provenance, SignatureProvenance::ByzantineSigner);
    assert!(byz.authenticated_channel);

    ta.security
        .compromised_keys
        .insert("replica_key".to_string());
    let compromised = auth_metadata_for_forge(&ta, "Vote");
    assert_eq!(compromised.provenance, SignatureProvenance::CompromisedKey);
    assert_eq!(compromised.signature_key.as_deref(), Some("replica_key"));

    ta.semantics.authentication_mode = AuthenticationMode::None;
    let unauth = auth_metadata_for_forge(&ta, "Vote");
    assert_eq!(
        unauth.provenance,
        SignatureProvenance::UnauthenticatedChannel
    );
    assert!(!unauth.authenticated_channel);
}

#[test]
fn rule_delivery_extraction_emits_send_and_deliver_events() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0[view=1]", true);
    let events = extract_rule_delivery_events(&ta, 0, 2);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, MessageEventKind::Send);
    assert_eq!(events[1].kind, MessageEventKind::Deliver);
    assert_eq!(events[0].count, 2);
    assert_eq!(events[0].sender.process.as_deref(), Some("0"));
    assert_eq!(events[0].recipient.process.as_deref(), Some("1"));
    assert_eq!(events[0].payload.variant, "Vote[view=1]");
}

#[test]
fn rule_delivery_extraction_falls_back_to_rule_source_identity() {
    let ta = make_ta("cnt_Vote@Replica#1[view=1]", true);
    let events = extract_rule_delivery_events(&ta, 0, 1);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sender.role, "Replica");
    assert_eq!(events[0].sender.process.as_deref(), Some("0"));
}

#[test]
fn adversary_and_drop_extraction_emit_expected_event_kinds() {
    let ta = make_ta("cnt_Vote@Replica#1[view=1]", true);
    let model = test_model(&[
        ("adv_0_0", ModelValue::Int(3)),
        ("drop_0_0", ModelValue::Int(2)),
    ]);

    let adv_events = extract_adversary_delivery_events(&ta, &model, 0);
    assert_eq!(adv_events.len(), 2);
    assert_eq!(adv_events[0].kind, MessageEventKind::Forge);
    assert_eq!(adv_events[1].kind, MessageEventKind::Deliver);
    assert_eq!(adv_events[0].sender.role, "Byzantine");

    let drop_events = extract_drop_events(&ta, &model, 0);
    assert_eq!(drop_events.len(), 1);
    assert_eq!(drop_events[0].kind, MessageEventKind::Drop);
    assert_eq!(drop_events[0].sender.role, "Network");
}

#[test]
fn crypto_summary_returns_none_when_delivery_family_is_not_a_crypto_object() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let pre_config = Configuration {
        kappa: vec![1, 0],
        gamma: vec![0],
        params: vec![4],
    };
    let delivery = MessageDeliveryEvent {
        shared_var: 0,
        shared_var_name: "cnt_Vote@Replica#1<-Replica#0".to_string(),
        sender: MessageIdentity {
            role: "Replica".to_string(),
            process: Some("0".to_string()),
            key: Some("replica_key".to_string()),
        },
        recipient: MessageIdentity {
            role: "Replica".to_string(),
            process: Some("1".to_string()),
            key: Some("replica_key".to_string()),
        },
        payload: MessagePayloadVariant {
            family: "Vote".to_string(),
            fields: vec![],
            variant: "Vote".to_string(),
        },
        count: 1,
        kind: MessageEventKind::Deliver,
        auth: MessageAuthMetadata {
            authenticated_channel: true,
            signature_key: Some("replica_key".to_string()),
            key_owner_role: Some("Replica".to_string()),
            key_compromised: false,
            provenance: SignatureProvenance::OwnedKey,
        },
    };

    assert!(crypto_summary_for_delivery(&ta, &pre_config, &delivery).is_none());
}

#[test]
fn equivocation_events_require_conflicting_variants_for_same_sender_family() {
    let adversary_events = vec![
        forge_event("0", "Vote", "Vote[value=true]"),
        forge_event("0", "Vote", "Vote[value=false]"),
        forge_event("1", "Vote", "Vote[value=true]"),
    ];
    let equivocations = extract_equivocation_events(&adversary_events);
    assert_eq!(equivocations.len(), 2);
    assert!(equivocations
        .iter()
        .all(|ev| ev.kind == MessageEventKind::Equivocate));
    assert!(equivocations
        .iter()
        .all(|ev| ev.sender.process.as_deref() == Some("0")));
}

#[test]
fn extract_trace_builds_steps_and_por_annotation() {
    let mut ta = make_ta("cnt_Vote@Replica#1<-Replica#0[view=1]", true);
    ta.semantics.por_mode = PorMode::Static;
    let cs = ta;
    let model = test_model(&[
        ("p_0", ModelValue::Int(4)),
        ("kappa_0_0", ModelValue::Int(1)),
        ("kappa_0_1", ModelValue::Int(0)),
        ("g_0_0", ModelValue::Int(0)),
        ("delta_0_0", ModelValue::Int(1)),
        ("kappa_1_0", ModelValue::Int(0)),
        ("kappa_1_1", ModelValue::Int(1)),
        ("g_1_0", ModelValue::Int(1)),
    ]);

    let trace = extract_trace(&cs, &model, 1);
    assert_eq!(trace.param_values, vec![("n".to_string(), 4)]);
    assert_eq!(trace.steps.len(), 1);
    assert_eq!(trace.steps[0].rule_id, 0);
    assert_eq!(
        trace.steps[0].por_status.as_deref(),
        Some("active (static POR)")
    );
    assert_eq!(trace.steps[0].deliveries.len(), 2);
    assert_eq!(trace.steps[0].config.kappa, vec![0, 1]);
}

#[test]
fn extract_trace_attaches_global_adversary_effects_only_once_per_step() {
    let mut ta = make_ta("cnt_Vote@Replica#1<-Replica#0[view=1]", true);
    ta.add_rule(Rule {
        from: 0.into(),
        to: 1.into(),
        guard: Guard::trivial(),
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
    let model = test_model(&[
        ("p_0", ModelValue::Int(4)),
        ("kappa_0_0", ModelValue::Int(1)),
        ("kappa_0_1", ModelValue::Int(0)),
        ("g_0_0", ModelValue::Int(0)),
        ("delta_0_0", ModelValue::Int(1)),
        ("delta_0_1", ModelValue::Int(1)),
        ("adv_0_0", ModelValue::Int(2)),
        ("kappa_1_0", ModelValue::Int(0)),
        ("kappa_1_1", ModelValue::Int(1)),
        ("g_1_0", ModelValue::Int(2)),
    ]);

    let trace = extract_trace(&cs, &model, 1);
    assert_eq!(trace.steps.len(), 2);
    assert_eq!(trace.steps[0].deliveries.len(), 4);
    assert_eq!(trace.steps[1].deliveries.len(), 2);
    assert!(!trace.steps[1]
        .deliveries
        .iter()
        .any(|ev| ev.kind == MessageEventKind::Forge));
}

#[test]
fn format_trace_includes_crypto_summary_when_spec_is_available() {
    let mut ta = make_ta("cnt_QC@Replica#1<-Replica#0[view=1]", true);
    ta.shared_vars.push(SharedVar {
        name: "cnt_Vote@Replica#1<-Replica#0[view=1]".to_string(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });
    ta.security.crypto_objects.insert(
        "QC".to_string(),
        IrCryptoObjectSpec {
            name: "QC".to_string(),
            kind: IrCryptoObjectKind::QuorumCertificate,
            source_message: "Vote".to_string(),
            threshold: LinearCombination::constant(1),
            signer_role: Some("Replica".to_string()),
            conflict_policy: CryptoConflictPolicy::Exclusive,
        },
    );

    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![1, 0],
            gamma: vec![0, 1],
            params: vec![4],
        },
        steps: vec![TraceStep {
            smt_step: 0,
            rule_id: 0.into(),
            delta: 1,
            deliveries: vec![MessageDeliveryEvent {
                shared_var: 0,
                shared_var_name: "cnt_QC@Replica#1<-Replica#0[view=1]".to_string(),
                sender: MessageIdentity {
                    role: "Replica".to_string(),
                    process: Some("0".to_string()),
                    key: Some("replica_key".to_string()),
                },
                recipient: MessageIdentity {
                    role: "Replica".to_string(),
                    process: Some("1".to_string()),
                    key: Some("replica_key".to_string()),
                },
                payload: MessagePayloadVariant {
                    family: "QC".to_string(),
                    fields: vec![("view".to_string(), "1".to_string())],
                    variant: "QC[view=1]".to_string(),
                },
                count: 1,
                kind: MessageEventKind::Deliver,
                auth: MessageAuthMetadata {
                    authenticated_channel: true,
                    signature_key: Some("replica_key".to_string()),
                    key_owner_role: Some("Replica".to_string()),
                    key_compromised: false,
                    provenance: SignatureProvenance::OwnedKey,
                },
            }],
            config: Configuration {
                kappa: vec![0, 1],
                gamma: vec![1, 1],
                params: vec![4],
            },
            por_status: None,
        }],
        param_values: vec![("n".to_string(), 4)],
    };

    let rendered = format_trace(&trace, &ta);
    assert!(rendered.contains("Counterexample trace"));
    assert!(rendered.contains("crypto=certificate"));
    assert!(rendered.contains("source=Vote"));
    assert!(rendered.contains("required=1"));
    assert!(rendered.contains("conflicts=exclusive"));
}

#[test]
fn format_trace_renders_por_status_suffix_when_available() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0[view=1]", true);
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![1, 0],
            gamma: vec![0],
            params: vec![4],
        },
        steps: vec![TraceStep {
            smt_step: 0,
            rule_id: 0.into(),
            delta: 1,
            deliveries: vec![],
            config: Configuration {
                kappa: vec![0, 1],
                gamma: vec![1],
                params: vec![4],
            },
            por_status: Some("active (full POR)".to_string()),
        }],
        param_values: vec![("n".to_string(), 4)],
    };

    let rendered = format_trace(&trace, &ta);
    assert!(rendered.contains("[active (full POR)]"));
}

// --- Trace construction and Display tests ---

#[test]
fn trace_with_no_steps_displays_initial_config_only() {
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![4, 0],
            gamma: vec![0],
            params: vec![4],
        },
        steps: vec![],
        param_values: vec![("n".to_string(), 4)],
    };
    let s = format!("{trace}");
    assert!(s.contains("Counterexample trace:"));
    assert!(s.contains("n = 4"));
    assert!(s.contains("Initial configuration:"));
}

#[test]
fn trace_display_shows_param_values() {
    let trace = Trace {
        initial_config: Configuration::new(2, 1, 2),
        steps: vec![],
        param_values: vec![("n".to_string(), 10), ("f".to_string(), 3)],
    };
    let s = format!("{trace}");
    assert!(s.contains("n = 10"));
    assert!(s.contains("f = 3"));
}

// --- format_trace tests ---

#[test]
fn format_trace_empty_steps_shows_initial_config() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![3, 0],
            gamma: vec![0],
            params: vec![3],
        },
        steps: vec![],
        param_values: vec![("n".to_string(), 3)],
    };
    let rendered = format_trace(&trace, &ta);
    assert!(rendered.contains("Counterexample trace:"));
    assert!(rendered.contains("n = 3"));
    assert!(rendered.contains("L0: 3 process(es)"));
    // No step should appear
    assert!(!rendered.contains("Step 1"));
}

#[test]
fn format_trace_shows_none_when_no_deliveries() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![1, 0],
            gamma: vec![0],
            params: vec![4],
        },
        steps: vec![TraceStep {
            smt_step: 0,
            rule_id: 0.into(),
            delta: 1,
            deliveries: vec![],
            config: Configuration {
                kappa: vec![0, 1],
                gamma: vec![0],
                params: vec![4],
            },
            por_status: None,
        }],
        param_values: vec![("n".to_string(), 4)],
    };
    let rendered = format_trace(&trace, &ta);
    assert!(rendered.contains("deliveries: (none)"));
}

#[test]
fn format_trace_no_por_status_omits_bracket_annotation() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![1, 0],
            gamma: vec![0],
            params: vec![4],
        },
        steps: vec![TraceStep {
            smt_step: 0,
            rule_id: 0.into(),
            delta: 1,
            deliveries: vec![],
            config: Configuration {
                kappa: vec![0, 1],
                gamma: vec![0],
                params: vec![4],
            },
            por_status: None,
        }],
        param_values: vec![("n".to_string(), 4)],
    };
    let rendered = format_trace(&trace, &ta);
    assert!(rendered.contains("Step 1: rule r0 fires 1 time(s): L0 -> L1\n"));
    assert!(!rendered.contains("[active"));
}

// --- format_identity tests ---

#[test]
fn format_identity_with_process_id() {
    let id = MessageIdentity {
        role: "Replica".to_string(),
        process: Some("3".to_string()),
        key: None,
    };
    assert_eq!(format_identity(&id), "Replica#3");
}

#[test]
fn format_identity_without_process_id() {
    let id = MessageIdentity {
        role: "Byzantine".to_string(),
        process: None,
        key: None,
    };
    assert_eq!(format_identity(&id), "Byzantine");
}

// --- format_config tests ---

#[test]
fn format_config_hides_zero_counters() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let config = Configuration {
        kappa: vec![0, 0],
        gamma: vec![0],
        params: vec![4],
    };
    let mut out = String::new();
    format_config(&mut out, &config, &ta);
    // All zeros should produce empty output
    assert!(out.is_empty(), "zero counters should be hidden: {out:?}");
}

#[test]
fn format_config_shows_nonzero_counters_and_shared_vars() {
    let ta = make_ta("cnt_Vote@Replica#1<-Replica#0", true);
    let config = Configuration {
        kappa: vec![3, 1],
        gamma: vec![5],
        params: vec![4],
    };
    let mut out = String::new();
    format_config(&mut out, &config, &ta);
    assert!(out.contains("L0: 3 process(es)"));
    assert!(out.contains("L1: 1 process(es)"));
    assert!(out.contains("cnt_Vote@Replica#1<-Replica#0 = 5"));
}

// --- eval_linear_combination tests ---

#[test]
fn eval_linear_combination_constant_only() {
    let lc = LinearCombination {
        constant: 42,
        terms: vec![],
    };
    assert_eq!(eval_linear_combination(&lc, &[10, 20]), 42);
}

#[test]
fn eval_linear_combination_with_terms() {
    // 3 + 2*p0 - 1*p1
    let lc = LinearCombination {
        constant: 3,
        terms: vec![(2, 0.into()), (-1, 1.into())],
    };
    assert_eq!(eval_linear_combination(&lc, &[5, 7]), 3 + 2 * 5 - 7);
}

#[test]
fn eval_linear_combination_missing_param_defaults_to_zero() {
    let lc = LinearCombination {
        constant: 10,
        terms: vec![(5, 99.into())], // param index 99 does not exist
    };
    assert_eq!(eval_linear_combination(&lc, &[1, 2, 3]), 10);
}

// --- parse_counter_message_metadata edge cases ---

#[test]
fn parse_counter_metadata_with_sender_no_fields() {
    let parsed =
        parse_counter_message_metadata("cnt_Prepare@Replica#1<-Replica#0").expect("should parse");
    assert_eq!(parsed.0, "Prepare");
    assert_eq!(parsed.1, "Replica#1");
    assert_eq!(parsed.2.as_deref(), Some("Replica#0"));
    assert!(parsed.3.fields.is_empty());
    assert_eq!(parsed.3.variant, "Prepare");
}

#[test]
fn parse_counter_metadata_recipient_only_no_sender() {
    let parsed = parse_counter_message_metadata("cnt_Commit@Leader#0").expect("should parse");
    assert_eq!(parsed.0, "Commit");
    assert_eq!(parsed.1, "Leader#0");
    assert_eq!(parsed.2, None);
}

// --- adversary_identity and network_identity tests ---

#[test]
fn adversary_identity_role_is_byzantine() {
    let id = adversary_identity();
    assert_eq!(id.role, "Byzantine");
    assert!(id.process.is_none());
    assert!(id.key.is_none());
}

#[test]
fn network_identity_role_is_network() {
    let id = network_identity();
    assert_eq!(id.role, "Network");
    assert!(id.process.is_none());
    assert!(id.key.is_none());
}

// --- extract_config tests ---

#[test]
fn extract_config_populates_kappa_gamma_and_params() {
    let model = test_model(&[
        ("kappa_0_0", ModelValue::Int(3)),
        ("kappa_0_1", ModelValue::Int(1)),
        ("g_0_0", ModelValue::Int(7)),
    ]);
    let config = extract_config(&model, 0, 2, 1, &[4]);
    assert_eq!(config.kappa, vec![3, 1]);
    assert_eq!(config.gamma, vec![7]);
    assert_eq!(config.params, vec![4]);
}

#[test]
fn extract_config_defaults_missing_values_to_zero() {
    let model = test_model(&[]);
    let config = extract_config(&model, 0, 2, 1, &[]);
    assert_eq!(config.kappa, vec![0, 0]);
    assert_eq!(config.gamma, vec![0]);
    assert!(config.params.is_empty());
}
