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
            "ChannelAuthUnauthenticated"
        );

        protocol.adversary.push(AdversaryItem {
            key: "auth".to_string(),
            value: "signed".to_string(),
            span: span(),
        });
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthAuthenticated"
        );

        protocol.adversary[0].value = "none".to_string();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthUnauthenticated"
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
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationFull");

        protocol.adversary.push(AdversaryItem {
            key: "equivocation".to_string(),
            value: "none".to_string(),
            span: span(),
        });
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationNone");

        protocol.adversary[1].value = "full".to_string();
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationFull");

        protocol.adversary = vec![AdversaryItem {
            key: "model".to_string(),
            value: "crash".to_string(),
            span: span(),
        }];
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationNone");
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
        assert_eq!(named, "&VoteMsg{ View: 3, Value: true }");

        let positional = render_message_ctor(
            "Vote",
            &[
                SendArg::Positional(Expr::Var("n".to_string())),
                SendArg::Positional(Expr::BoolLit(false)),
            ],
            &protocol,
            &params,
        );
        assert_eq!(positional, "&VoteMsg{ View: config.N, Value: false }");
    }

    #[test]
    fn render_message_ctor_uses_empty_struct_for_unknown_or_fieldless_message() {
        let protocol = protocol_with_vote_message();
        let params = HashSet::new();
        assert_eq!(
            render_message_ctor("Unknown", &[], &protocol, &params),
            "&UnknownMsg{}"
        );

        let mut fieldless = empty_protocol();
        fieldless.messages.push(MessageDecl {
            name: "Ping".to_string(),
            fields: vec![],
            span: span(),
        });
        assert_eq!(
            render_message_ctor("Ping", &[], &fieldless, &params),
            "&PingMsg{}"
        );
    }

    #[test]
    fn literal_and_type_helpers_have_stable_fallbacks() {
        assert_eq!(render_expr_literal_go(&Expr::IntLit(9)), "9");
        assert_eq!(render_expr_literal_go(&Expr::BoolLit(false)), "false");
        assert_eq!(
            render_expr_literal_go(&Expr::Add(
                Box::new(Expr::IntLit(1)),
                Box::new(Expr::IntLit(2))
            )),
            "0"
        );
        assert_eq!(field_type_to_go("bool"), "bool");
        assert_eq!(field_type_to_go("nat"), "uint64");
        assert_eq!(field_type_to_go("int"), "int64");
        assert_eq!(field_type_to_go("enum"), "uint64");
    }

    // --- Guard rendering tests ---

    #[test]
    fn render_guard_go_simple_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(3),
            distinct: false,
            distinct_role: None,
            message_args: vec![],
        });
        assert_eq!(
            render_guard_go(&guard, &params),
            "uint64(len(s.VoteBuffer)) >= 3"
        );
    }

    #[test]
    fn render_guard_go_distinct_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(2),
            distinct: true,
            distinct_role: None,
            message_args: vec![],
        });
        let result = render_guard_go(&guard, &params);
        assert!(
            result.contains("countDistinctSenders"),
            "distinct guard should use helper: {result}"
        );
    }

    #[test]
    fn render_guard_go_filtered_threshold() {
        let params = HashSet::new();
        let guard = GuardExpr::Threshold(ThresholdGuard {
            message_type: "Vote".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(1),
            distinct: false,
            distinct_role: None,
            message_args: vec![("view".into(), Expr::IntLit(5))],
        });
        let result = render_guard_go(&guard, &params);
        assert!(
            result.contains("countFiltered"),
            "filtered guard should use helper: {result}"
        );
        assert!(
            result.contains("m.View == 5"),
            "should check PascalCase field: {result}"
        );
    }

    #[test]
    fn render_guard_go_timeout() {
        let params = HashSet::new();
        let guard = GuardExpr::Timeout {
            clock: "deadline".into(),
            op: CmpOp::Ge,
            threshold: LinearExpr::Const(10),
        };
        assert_eq!(render_guard_go(&guard, &params), "s.Deadline >= 10");
    }

    #[test]
    fn render_guard_go_bool_var() {
        let params = HashSet::new();
        assert_eq!(
            render_guard_go(&GuardExpr::BoolVar("locked".into()), &params),
            "s.Locked"
        );
    }

    #[test]
    fn render_guard_go_and_or_nesting() {
        let params = HashSet::new();
        let guard = GuardExpr::And(
            Box::new(GuardExpr::BoolVar("ready".into())),
            Box::new(GuardExpr::Or(
                Box::new(GuardExpr::BoolVar("a".into())),
                Box::new(GuardExpr::BoolVar("b".into())),
            )),
        );
        assert_eq!(
            render_guard_go(&guard, &params),
            "(s.Ready) && ((s.A) || (s.B))"
        );
    }

    #[test]
    fn render_guard_go_has_crypto_object() {
        let params = HashSet::new();
        let guard = GuardExpr::HasCryptoObject {
            object_name: "QC".into(),
            object_args: vec![],
        };
        assert_eq!(render_guard_go(&guard, &params), "s.QCCount >= 1");
    }

    // --- Action rendering tests ---

    #[test]
    fn write_actions_go_assign() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
            &mut out,
            &[Action::Assign {
                var: "view".into(),
                value: Expr::IntLit(42),
            }],
            &protocol,
            &params,
            "Validator",
            "ValidatorPhase",
            "\t",
        )
        .unwrap();
        assert!(out.contains("s.View = 42"), "got: {out}");
    }

    #[test]
    fn write_actions_go_goto_phase() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
            &mut out,
            &[Action::GotoPhase {
                phase: "pre_commit".into(),
            }],
            &protocol,
            &params,
            "Validator",
            "ValidatorPhase",
            "\t",
        )
        .unwrap();
        assert!(
            out.contains("ValidatorPhasePreCommit"),
            "should be PascalCase: {out}"
        );
    }

    #[test]
    fn write_actions_go_decide_bool_maps_to_numeric() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
            &mut out,
            &[Action::Decide {
                value: Expr::BoolLit(true),
            }],
            &protocol,
            &params,
            "Voter",
            "VoterPhase",
            "\t",
        )
        .unwrap();
        assert!(
            out.contains("uint64(1)"),
            "bool true should map to 1: {out}"
        );
    }

    #[test]
    fn write_actions_go_crypto_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
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
            "LeaderPhase",
            "\t",
        )
        .unwrap();
        assert!(out.contains("s.QCCount++"), "form: {out}");
        assert!(out.contains("s.LockQC = true"), "lock: {out}");
        assert!(out.contains("s.JustifyQC = true"), "justify: {out}");
    }

    #[test]
    fn write_actions_go_collection_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
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
            "NodePhase",
            "\t",
        )
        .unwrap();
        assert!(out.contains("append(s.Log, 1)"), "append: {out}");
        assert!(out.contains("append(s.PendingMsgs, 2)"), "enqueue: {out}");
        assert!(
            out.contains("s.PendingMsgs = s.PendingMsgs[1:]"),
            "dequeue: {out}"
        );
    }

    #[test]
    fn write_actions_go_clock_operations() {
        let protocol = empty_protocol();
        let params = HashSet::new();
        let mut out = String::new();
        write_actions_go(
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
            "NodePhase",
            "\t",
        )
        .unwrap();
        assert!(out.contains("s.Timer = 0"), "reset: {out}");
        assert!(out.contains("s.Timer = s.Timer + 5"), "tick by 5: {out}");
        assert!(
            out.contains("s.Timer = s.Timer + 1"),
            "tick by default 1: {out}"
        );
    }

    #[test]
    fn write_actions_go_reconfigure() {
        let protocol = empty_protocol();
        let params: HashSet<String> = ["n".into()].into_iter().collect();
        let mut out = String::new();
        write_actions_go(
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
            "NodePhase",
            "\t",
        )
        .unwrap();
        assert!(out.contains("s.N = 10"), "reconfigure: {out}");
    }

    #[test]
    fn go_codegen_emits_distinct_and_filtered_helpers_only_when_needed() {
        let filtered_src = include_str!("../../../tarsier-dsl/../../examples/crypto_objects.trs");
        let filtered_program = tarsier_dsl::parse(filtered_src, "crypto_objects.trs").unwrap();
        let filtered = generate_go(&filtered_program.protocol.node).unwrap();
        assert!(filtered.contains("func countDistinctSenders"));
        assert!(filtered.contains("func countFiltered"));
        assert!(filtered.contains("func countDistinctFiltered"));

        let plain_src = include_str!("../../../tarsier-dsl/../../examples/trivial_live.trs");
        let plain_program = tarsier_dsl::parse(plain_src, "trivial_live.trs").unwrap();
        let plain = generate_go(&plain_program.protocol.node).unwrap();
        assert!(!plain.contains("func countDistinctSenders"));
        assert!(!plain.contains("func countFiltered"));
        assert!(!plain.contains("func countDistinctFiltered"));
    }
