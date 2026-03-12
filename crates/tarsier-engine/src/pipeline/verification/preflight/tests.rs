use crate::pipeline::verification::*;
use crate::pipeline::*;

// Helper: build a simple ThresholdGuard for testing
fn make_threshold_guard(
    msg: &str,
    op: ast::CmpOp,
    distinct: bool,
    distinct_role: Option<&str>,
) -> ast::ThresholdGuard {
    ast::ThresholdGuard {
        op,
        threshold: ast::LinearExpr::Const(1),
        message_type: msg.to_string(),
        message_args: vec![],
        distinct,
        distinct_role: distinct_role.map(|s| s.to_string()),
    }
}

#[test]
fn guard_uses_threshold_on_threshold_guard() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Ge, false, None));
    assert!(guard_uses_threshold(&guard));
}

#[test]
fn guard_uses_threshold_on_bool_guard() {
    let guard = ast::GuardExpr::BoolVar("ready".into());
    assert!(!guard_uses_threshold(&guard));
}

#[test]
fn guard_uses_threshold_nested_and() {
    let inner =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Ge, false, None));
    let guard = ast::GuardExpr::And(
        Box::new(ast::GuardExpr::BoolVar("x".into())),
        Box::new(inner),
    );
    assert!(guard_uses_threshold(&guard));
}

#[test]
fn guard_uses_distinct_threshold_true() {
    let guard = ast::GuardExpr::Threshold(make_threshold_guard(
        "Vote",
        ast::CmpOp::Ge,
        true,
        Some("Validator"),
    ));
    assert!(guard_uses_distinct_threshold(&guard));
}

#[test]
fn guard_uses_distinct_threshold_false_when_not_distinct() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Ge, false, None));
    assert!(!guard_uses_distinct_threshold(&guard));
}

#[test]
fn collect_distinct_roles_from_guard_collects_role() {
    let guard = ast::GuardExpr::Threshold(make_threshold_guard(
        "Vote",
        ast::CmpOp::Ge,
        true,
        Some("Validator"),
    ));
    let mut roles = HashSet::new();
    collect_distinct_roles_from_guard(&guard, &mut roles);
    assert!(roles.contains("Validator"));
    assert_eq!(roles.len(), 1);
}

#[test]
fn collect_distinct_roles_empty_when_not_distinct() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Ge, false, None));
    let mut roles = HashSet::new();
    collect_distinct_roles_from_guard(&guard, &mut roles);
    assert!(roles.is_empty());
}

#[test]
fn collect_distinct_messages_from_guard_collects_msg() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Prepare", ast::CmpOp::Ge, true, None));
    let mut messages = HashSet::new();
    collect_distinct_messages_from_guard(&guard, &mut messages);
    assert!(messages.contains("Prepare"));
}

#[test]
fn collect_distinct_messages_empty_when_not_distinct() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Prepare", ast::CmpOp::Ge, false, None));
    let mut messages = HashSet::new();
    collect_distinct_messages_from_guard(&guard, &mut messages);
    assert!(messages.is_empty());
}

#[test]
fn guard_has_non_monotone_threshold_le_is_non_monotone() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Le, false, None));
    assert!(guard_has_non_monotone_threshold(&guard));
}

#[test]
fn guard_has_non_monotone_threshold_ge_is_monotone() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Ge, false, None));
    assert!(!guard_has_non_monotone_threshold(&guard));
}

#[test]
fn guard_has_non_monotone_threshold_gt_is_monotone() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Gt, false, None));
    assert!(!guard_has_non_monotone_threshold(&guard));
}

#[test]
fn guard_has_non_monotone_eq_is_non_monotone() {
    let guard =
        ast::GuardExpr::Threshold(make_threshold_guard("Vote", ast::CmpOp::Eq, false, None));
    assert!(guard_has_non_monotone_threshold(&guard));
}

#[test]
fn collect_crypto_objects_from_guard_basic() {
    let guard = ast::GuardExpr::HasCryptoObject {
        object_name: "cert".to_string(),
        object_args: vec![],
    };
    let mut out = HashSet::new();
    collect_crypto_objects_from_guard(&guard, &mut out);
    assert!(out.contains("cert"));
    assert_eq!(out.len(), 1);
}

#[test]
fn collect_crypto_objects_nested_or() {
    let left = ast::GuardExpr::HasCryptoObject {
        object_name: "cert_a".to_string(),
        object_args: vec![],
    };
    let right = ast::GuardExpr::HasCryptoObject {
        object_name: "cert_b".to_string(),
        object_args: vec![],
    };
    let guard = ast::GuardExpr::Or(Box::new(left), Box::new(right));
    let mut out = HashSet::new();
    collect_crypto_objects_from_guard(&guard, &mut out);
    assert!(out.contains("cert_a"));
    assert!(out.contains("cert_b"));
    assert_eq!(out.len(), 2);
}

#[test]
fn guard_has_crypto_check_matches() {
    let guard = ast::GuardExpr::HasCryptoObject {
        object_name: "cert".to_string(),
        object_args: vec![],
    };
    assert!(guard_has_crypto_check(&guard, "cert"));
    assert!(!guard_has_crypto_check(&guard, "other"));
}

#[test]
fn effective_message_authenticated_via_channel() {
    let proto = ast::ProtocolDecl {
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
        channels: vec![ast::ChannelDecl {
            message: "Vote".into(),
            auth: ast::ChannelAuthMode::Authenticated,
            span: ast::Span::new(0, 0),
        }],
        equivocation_policies: vec![],
        committees: vec![],
        dag_rounds: vec![],
        collections: vec![],
        clocks: vec![],
        messages: vec![],
        crypto_objects: vec![],
        roles: vec![],
        properties: vec![],
    };
    assert!(effective_message_authenticated(&proto, "Vote", "none"));
    assert!(!effective_message_authenticated(&proto, "Other", "none"));
}

#[test]
fn effective_message_authenticated_via_global_auth() {
    let proto = ast::ProtocolDecl {
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
    };
    assert!(effective_message_authenticated(&proto, "Vote", "signed"));
    assert!(!effective_message_authenticated(&proto, "Vote", "none"));
}

#[test]
fn effective_message_non_equivocating_via_policy() {
    let proto = ast::ProtocolDecl {
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
        equivocation_policies: vec![ast::EquivocationDecl {
            message: "Vote".into(),
            mode: ast::EquivocationPolicyMode::None,
            span: ast::Span::new(0, 0),
        }],
        committees: vec![],
        dag_rounds: vec![],
        collections: vec![],
        clocks: vec![],
        messages: vec![],
        crypto_objects: vec![],
        roles: vec![],
        properties: vec![],
    };
    assert!(effective_message_non_equivocating(&proto, "Vote", "full"));
    // Message not covered by policy falls back to global
    assert!(!effective_message_non_equivocating(&proto, "Other", "full"));
}

fn strict_reconfigure_protocol(update_stmt: &str) -> String {
    format!(
        r#"
protocol StrictReconfigure {{
    params n, t, f;
    resilience: n > 3*t;
    adversary {{ model: byzantine; bound: f; }}
    message Vote;
    role Replica {{
        var decided: bool = false;
        init waiting;
        phase waiting {{
            when received >= 1 Vote => {{
                reconfigure {{
                    {update_stmt};
                }}
                goto phase waiting;
            }}
        }}
    }}
    property inv: invariant {{
        forall p: Replica. p.decided == false
    }}
}}
"#
    )
}

#[test]
fn strict_preflight_rejects_resilience_weakening_reconfigure_update() {
    let src = strict_reconfigure_protocol("t = t + 1");
    let program = tarsier_dsl::parse(&src, "strict_weakening.trs").expect("parse");
    let err = strict_preflight_validate(&program, PipelineCommand::Verify)
        .expect_err("strict preflight should reject resilience-weakening reconfigure");
    let msg = err.to_string();
    assert!(msg.contains("may weaken resilience"));
    assert!(msg.contains("t = (t + 1)") || msg.contains("t = t + 1"));
}

#[test]
fn strict_preflight_allows_resilience_strengthening_reconfigure_update() {
    let src = strict_reconfigure_protocol("t = t - 1");
    let program = tarsier_dsl::parse(&src, "strict_strengthening.trs").expect("parse");
    strict_preflight_validate(&program, PipelineCommand::Verify)
        .expect("strict preflight should allow resilience-strengthening updates");
}

#[test]
fn strict_preflight_ignores_reconfigure_updates_outside_resilience_expression() {
    let src = strict_reconfigure_protocol("f = f + 1");
    let program = tarsier_dsl::parse(&src, "strict_unrelated.trs").expect("parse");
    strict_preflight_validate(&program, PipelineCommand::Verify)
        .expect("strict preflight should ignore updates to unrelated parameters");
}

#[test]
fn effective_message_non_equivocating_via_global() {
    let proto = ast::ProtocolDecl {
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
    };
    assert!(effective_message_non_equivocating(&proto, "Vote", "none"));
    assert!(!effective_message_non_equivocating(&proto, "Vote", "full"));
}

#[test]
fn pipeline_command_eq() {
    assert!(PipelineCommand::Verify == PipelineCommand::Verify);
    assert!(PipelineCommand::Verify != PipelineCommand::Liveness);
    assert!(PipelineCommand::Liveness == PipelineCommand::Liveness);
    assert!(PipelineCommand::VerifyAllProperties != PipelineCommand::Verify);
}
