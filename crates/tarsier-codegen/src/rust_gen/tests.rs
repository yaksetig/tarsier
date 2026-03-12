    use super::*;

    fn span() -> Span {
        Span::new(0, 0)
    }

    fn empty_protocol() -> ProtocolDecl {
        ProtocolDecl {
            name: "TestProtocol".to_string(),
            imports: vec![],
            refines: None,
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            timing: None,
            adversary: vec![],
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

    fn protocol_with_vote_message() -> ProtocolDecl {
        let mut protocol = empty_protocol();
        protocol.messages.push(MessageDecl {
            name: "Vote".to_string(),
            fields: vec![
                FieldDef {
                    name: "view".to_string(),
                    ty: "nat".to_string(),
                    range: None,
                },
                FieldDef {
                    name: "value".to_string(),
                    ty: "bool".to_string(),
                    range: None,
                },
            ],
            span: span(),
        });
        protocol
    }

    #[test]
    fn default_channel_auth_variant_follows_adversary_auth_entry() {
        let mut protocol = empty_protocol();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Unauthenticated"
        );

        protocol.adversary.push(AdversaryItem {
            key: "auth".to_string(),
            value: "signed".to_string(),
            span: span(),
        });
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Authenticated"
        );

        protocol.adversary[0].value = "none".to_string();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Unauthenticated"
        );
    }

    #[test]
    fn default_equivocation_variant_follows_explicit_or_model_defaults() {
        let mut protocol = empty_protocol();
        protocol.adversary.push(AdversaryItem {
            key: "model".to_string(),
            value: "byzantine".to_string(),
            span: span(),
        });
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::Full"
        );

        protocol.adversary.push(AdversaryItem {
            key: "equivocation".to_string(),
            value: "none".to_string(),
            span: span(),
        });
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::None"
        );

        protocol.adversary[1].value = "full".to_string();
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::Full"
        );

        protocol.adversary = vec![AdversaryItem {
            key: "model".to_string(),
            value: "crash".to_string(),
            span: span(),
        }];
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::None"
        );
    }

    #[test]
    fn render_message_ctor_supports_named_and_positional_arguments() {
        let protocol = protocol_with_vote_message();
        let params = collect_param_names(&[ParamDef {
            name: "n".to_string(),
            ty: ParamType::Nat,
            span: span(),
        }]);

        let named = render_message_ctor(
            "Vote",
            &[
                SendArg::Named {
                    name: "view".to_string(),
                    value: Expr::IntLit(3),
                },
                SendArg::Named {
                    name: "value".to_string(),
                    value: Expr::BoolLit(true),
                },
            ],
            &protocol,
            &params,
        );
        assert_eq!(named, "Message::Vote(VoteMsg { view: 3, value: true })");

        let positional = render_message_ctor(
            "Vote",
            &[
                SendArg::Positional(Expr::Var("n".to_string())),
                SendArg::Positional(Expr::BoolLit(false)),
            ],
            &protocol,
            &params,
        );
        assert_eq!(
            positional,
            "Message::Vote(VoteMsg { view: config.n, value: false })"
        );
    }

    #[test]
    fn render_message_ctor_uses_unit_struct_for_unknown_or_fieldless_message() {
        let protocol = protocol_with_vote_message();
        let params = HashSet::new();
        assert_eq!(
            render_message_ctor("Unknown", &[], &protocol, &params),
            "Message::Unknown(UnknownMsg)"
        );

        let mut fieldless = empty_protocol();
        fieldless.messages.push(MessageDecl {
            name: "Ping".to_string(),
            fields: vec![],
            span: span(),
        });
        assert_eq!(
            render_message_ctor("Ping", &[], &fieldless, &params),
            "Message::Ping(PingMsg)"
        );
    }

    #[test]
    fn literal_and_type_helpers_have_stable_fallbacks() {
        assert_eq!(render_expr_literal(&Expr::IntLit(9)), "9");
        assert_eq!(render_expr_literal(&Expr::BoolLit(false)), "false");
        assert_eq!(render_expr_literal(&Expr::Var("x".to_string())), "x");
        assert_eq!(
            render_expr_literal(&Expr::Add(
                Box::new(Expr::IntLit(1)),
                Box::new(Expr::IntLit(2))
            )),
            "Default::default()"
        );
        assert_eq!(field_type_to_rust("bool"), "bool");
        assert_eq!(field_type_to_rust("nat"), "u64");
        assert_eq!(field_type_to_rust("int"), "i64");
        assert_eq!(field_type_to_rust("enum"), "u64");
    }

    // --- Guard rendering tests ---

    #[test]
    fn render_guard_simple_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(3),
            distinct: false,
            distinct_role: None,
            message_args: vec![],
        });
        let result = render_guard(&guard, &params);
        assert_eq!(result, "self.vote_buffer.len() as u64 >= 3");
    }

    #[test]
    fn render_guard_distinct_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(2),
            distinct: true,
            distinct_role: None,
            message_args: vec![],
        });
        let result = render_guard(&guard, &params);
        assert!(
            result.contains("collect::<HashSet<_>>().len()"),
            "distinct guard should use HashSet: {result}"
        );
        assert!(result.contains(">= 2"));
    }

    #[test]
    fn render_guard_filtered_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(1),
            distinct: false,
            distinct_role: None,
            message_args: vec![("view".into(), Expr::IntLit(5))],
        });
        let result = render_guard(&guard, &params);
        assert!(
            result.contains("filter"),
            "filtered guard should use .filter: {result}"
        );
        assert!(
            result.contains("m.view == 5"),
            "should check field: {result}"
        );
        assert!(
            result.contains(".count()"),
            "non-distinct filter should use .count(): {result}"
        );
    }

    #[test]
    fn render_guard_filtered_distinct_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(1),
            distinct: true,
            distinct_role: None,
            message_args: vec![("view".into(), Expr::IntLit(3))],
        });
        let result = render_guard(&guard, &params);
        assert!(result.contains("filter"), "should use filter: {result}");
        assert!(
            result.contains("HashSet<_>"),
            "distinct filter should collect to HashSet: {result}"
        );
    }

    #[test]
    fn render_guard_timeout() {
        let params = HashSet::new();
        let guard = GuardExpr::Timeout {
            clock: "deadline".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(10),
        };
        assert_eq!(render_guard(&guard, &params), "self.deadline >= 10");
    }

    #[test]
    fn render_guard_bool_var() {
        let params = HashSet::new();
        assert_eq!(
            render_guard(&GuardExpr::BoolVar("locked".into()), &params),
            "self.locked"
        );
    }

    #[test]
    fn render_guard_and_or_nesting() {
        let params = HashSet::new();
        let guard = GuardExpr::And(
            Box::new(GuardExpr::BoolVar("ready".into())),
            Box::new(GuardExpr::Or(
                Box::new(GuardExpr::BoolVar("a".into())),
                Box::new(GuardExpr::BoolVar("b".into())),
            )),
        );
        let result = render_guard(&guard, &params);
        assert_eq!(result, "(self.ready) && ((self.a) || (self.b))");
    }

    #[test]
    fn render_guard_has_crypto_object() {
        let params = HashSet::new();
        let guard = GuardExpr::HasCryptoObject {
            object_name: "QC".into(),
            object_args: vec![],
        };
        assert_eq!(render_guard(&guard, &params), "self.q_c_count >= 1");
    }

    // --- Action rendering tests ---

    #[test]
    fn write_actions_assign_renders_correctly() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[Action::Assign {
                var: "view".into(),
                value: Expr::IntLit(42),
            }],
            &protocol,
            &params,
            "Validator",
            "        ",
        )
        .unwrap();
        assert!(out.contains("self.view = 42;"), "got: {out}");
    }

    #[test]
    fn write_actions_goto_phase_renders_pascal_case() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[Action::GotoPhase {
                phase: "pre_commit".into(),
            }],
            &protocol,
            &params,
            "Validator",
            "        ",
        )
        .unwrap();
        assert!(
            out.contains("ValidatorPhase::PreCommit"),
            "phase should be PascalCase: {out}"
        );
    }

    #[test]
    fn write_actions_decide_casts_to_u64() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[Action::Decide {
                value: Expr::IntLit(1),
            }],
            &protocol,
            &params,
            "Voter",
            "        ",
        )
        .unwrap();
        assert!(out.contains("decision = Some(VoterDecision"), "got: {out}");
        assert!(out.contains("1 as u64"), "should cast to u64: {out}");
    }

    #[test]
    fn write_actions_crypto_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[
                Action::FormCryptoObject {
                    object_name: "QC".into(),
                    args: vec![],
                    recipient_role: None,
                },
                Action::LockCryptoObject {
                    object_name: "QC".into(),
                    args: vec![],
                },
                Action::JustifyCryptoObject {
                    object_name: "QC".into(),
                    args: vec![],
                },
            ],
            &protocol,
            &params,
            "Leader",
            "        ",
        )
        .unwrap();
        assert!(out.contains("self.q_c_count += 1;"), "form: {out}");
        assert!(out.contains("self.lock_q_c = true;"), "lock: {out}");
        assert!(out.contains("self.justify_q_c = true;"), "justify: {out}");
    }

    #[test]
    fn write_actions_collection_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[
                Action::Append {
                    collection: "log".into(),
                    value: Expr::IntLit(1),
                },
                Action::Enqueue {
                    collection: "pending_msgs".into(),
                    value: Expr::IntLit(2),
                },
                Action::Dequeue {
                    collection: "pending_msgs".into(),
                },
            ],
            &protocol,
            &params,
            "Node",
            "        ",
        )
        .unwrap();
        assert!(out.contains("self.log.push(1);"), "append: {out}");
        assert!(
            out.contains("self.pending_msgs.push_back(2);"),
            "enqueue: {out}"
        );
        assert!(
            out.contains("self.pending_msgs.pop_front();"),
            "dequeue: {out}"
        );
    }

    #[test]
    fn write_actions_reconfigure() {
        let protocol = empty_protocol();
        let params: HashSet<String> = ["n".into()].into_iter().collect();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[Action::Reconfigure {
                updates: vec![ReconfigureUpdate {
                    param: "n".into(),
                    value: Expr::IntLit(10),
                }],
            }],
            &protocol,
            &params,
            "Node",
            "        ",
        )
        .unwrap();
        assert!(out.contains("self.n = 10;"), "reconfigure: {out}");
    }

    #[test]
    fn write_actions_clock_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions(
            &mut out,
            &[
                Action::ResetClock {
                    clock: "timer".into(),
                },
                Action::TickClock {
                    clock: "timer".into(),
                    amount: Some(LinearExpr::Const(5)),
                },
                Action::TickClock {
                    clock: "timer".into(),
                    amount: None,
                },
            ],
            &protocol,
            &params,
            "Node",
            "        ",
        )
        .unwrap();
        assert!(out.contains("self.timer = 0;"), "reset: {out}");
        assert!(
            out.contains("self.timer = self.timer + 5;"),
            "tick by 5: {out}"
        );
        assert!(
            out.contains("self.timer = self.timer + 1;"),
            "tick by default 1: {out}"
        );
    }

    #[test]
    fn rust_codegen_imports_hashset_only_when_distinct_guards_are_used() {
        let with_distinct_src =
            include_str!("../../../tarsier-dsl/../../examples/crypto_objects.trs");
        let with_distinct_program =
            tarsier_dsl::parse(with_distinct_src, "crypto_objects.trs").unwrap();
        let with_distinct = generate_rust(&with_distinct_program.protocol.node).unwrap();
        assert!(with_distinct.contains("use std::collections::HashSet;"));

        let no_distinct_src =
            include_str!("../../../tarsier-dsl/../../examples/trivial_live.trs");
        let no_distinct_program = tarsier_dsl::parse(no_distinct_src, "trivial_live.trs").unwrap();
        let no_distinct = generate_rust(&no_distinct_program.protocol.node).unwrap();
        assert!(!no_distinct.contains("use std::collections::HashSet;"));
    }
