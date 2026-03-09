//! Lowering regression tests from DSL to threshold automaton IR.

use super::*;
use tarsier_dsl::parse;

#[test]
fn lower_simple_protocol() {
    let src = r#"
protocol Simple {
parameters { n: nat; t: nat; }
resilience { n > 3*t; }
message Echo;
role Process {
    var decided: bool = false;
    init waiting;
    phase waiting {
        when received >= 2*t+1 Echo => {
            decided = true;
            send Echo;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // 2 params
    assert_eq!(ta.parameters.len(), 2);
    // 1 message type → 1 shared var
    assert_eq!(ta.shared_vars.len(), 1);
    // 2 phases × 2 bool combos = 4 locations
    assert_eq!(ta.locations.len(), 4);
    // 1 initial location (waiting with decided=false)
    assert_eq!(ta.initial_locations.len(), 1);
    // 2 rules (one for decided=false→done/decided=true, one for decided=true→done/decided=true)
    assert_eq!(ta.rules.len(), 2);
    // Resilience condition present
    assert!(ta.constraints.resilience_condition.is_some());
}

#[test]
fn lower_send_to_role_updates_only_target_recipient_counter() {
    let src = r#"
protocol TargetedSend {
params n, t;
resilience: n > 3*t;
message Vote;
role Leader {
    init start;
    phase start {
        when received >= 0 Vote => {
            send Vote to Replica;
            goto phase done;
        }
    }
    phase done {}
}
role Replica {
    init start;
    phase start {}
}
}
"#;
    let prog = parse(src, "targeted_send.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(ta.shared_vars.len(), 2);
    let leader_counter = ta
        .find_shared_var_by_name("cnt_Vote@Leader")
        .expect("leader recipient counter should exist");
    let replica_counter = ta
        .find_shared_var_by_name("cnt_Vote@Replica")
        .expect("replica recipient counter should exist");

    let send_rules: Vec<_> = ta
        .rules
        .iter()
        .filter(|rule| {
            ta.locations[rule.from.as_usize()].role == "Leader" && !rule.updates.is_empty()
        })
        .collect();
    assert!(
        !send_rules.is_empty(),
        "expected targeted send rules from Leader"
    );
    assert!(send_rules.iter().all(|rule| {
        rule.updates.len() == 1
            && rule.updates[0].var == replica_counter
            && rule.updates[0].var != leader_counter
    }));
}

#[test]
fn lower_send_without_recipient_broadcasts_to_all_roles() {
    let src = r#"
protocol BroadcastSend {
params n, t;
resilience: n > 3*t;
message Vote;
role Leader {
    init start;
    phase start {
        when received >= 0 Vote => {
            send Vote;
            goto phase done;
        }
    }
    phase done {}
}
role Replica {
    init start;
    phase start {}
}
}
"#;
    let prog = parse(src, "broadcast_send.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let leader_counter = ta
        .find_shared_var_by_name("cnt_Vote@Leader")
        .expect("leader recipient counter should exist");
    let replica_counter = ta
        .find_shared_var_by_name("cnt_Vote@Replica")
        .expect("replica recipient counter should exist");

    let send_rules: Vec<_> = ta
        .rules
        .iter()
        .filter(|rule| {
            ta.locations[rule.from.as_usize()].role == "Leader" && !rule.updates.is_empty()
        })
        .collect();
    assert!(
        !send_rules.is_empty(),
        "expected broadcast send rules from Leader"
    );
    assert!(send_rules.iter().all(|rule| {
        let mut vars: Vec<_> = rule.updates.iter().map(|u| u.var).collect();
        vars.sort_unstable();
        let mut expected = vec![leader_counter, replica_counter];
        expected.sort_unstable();
        vars == expected
    }));
}

#[test]
fn lower_enum_ordering_guard() {
    let src = r#"
protocol EnumGuard {
params n, t;
resilience: n > 3*t;

enum View { v0, v1 };

role Replica {
    var view: View = v0;
    var locked: View = v0;
    init start;
    phase start {
        when view >= locked => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "enum_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // 2 enum vars with 2 values each -> 4 locations per phase, 2 phases
    assert_eq!(ta.locations.len(), 8);
    // Guard view >= locked should allow 3 of the 4 combinations
    // => 3 rules for start->done transitions.
    assert_eq!(ta.rules.len(), 3);
}

#[test]
fn lower_bounded_int_guard() {
    let src = r#"
protocol IntGuard {
params n, t;
resilience: n > 3*t;

role Replica {
    var view: int in 0..2 = 0;
    init start;
    phase start {
        when view >= 1 => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "int_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // view in 0..2 => 3 locations per phase, 2 phases
    assert_eq!(ta.locations.len(), 6);
    // Guard view >= 1 should allow 2 of the 3 combinations
    assert_eq!(ta.rules.len(), 2);
}

#[test]
fn lower_pacemaker_auto_view_change() {
    let src = r#"
protocol AutoView {
params n, t;
resilience: n > 3*t;

pacemaker {
    view: view;
    start: start;
}

role Replica {
    var view: int in 0..1 = 0;
    init start;
    phase start {}
}
}
"#;
    let prog = parse(src, "auto_view.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // view in 0..1 => 2 locations, 1 phase
    assert_eq!(ta.locations.len(), 2);
    // pacemaker should add a single view-advance rule (from view=0 to view=1)
    assert_eq!(ta.rules.len(), 1);
}

#[test]
fn lower_distinct_guard_marks_counter() {
    let src = r#"
protocol DistinctGuard {
parameters { n: nat; t: nat; }
resilience { n > 3*t; }
message Echo;
role Process {
    init waiting;
    phase waiting {
        when received distinct >= 1 Echo => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "distinct_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.shared_vars.len(), 1);
    let guard = ta
        .rules
        .first()
        .expect("distinct guard should produce at least one rule")
        .guard
        .atoms
        .first()
        .expect("rule should contain threshold guard");
    assert!(matches!(
        guard,
        GuardAtom::Threshold {
            distinct: true,
            vars,
            ..
        } if vars.len() == 1
    ));
}

#[test]
fn distinct_guard_instruments_sender_uniqueness_flags() {
    let src = r#"
protocol DistinctExact {
parameters { n: nat; t: nat; f: nat; }
resilience { n > 3*t; }
adversary { model: byzantine; bound: f; }
message Vote;
role Process {
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            goto phase s;
        }
        when received distinct >= 1 Vote => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "distinct_exact.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let flag = "__sent_g0";
    assert!(
        ta.locations
            .iter()
            .all(|loc| loc.local_vars.contains_key(flag)),
        "all locations should carry the internal sender-uniqueness flag"
    );

    let send_rules: Vec<_> = ta.rules.iter().filter(|r| !r.updates.is_empty()).collect();
    assert!(
        !send_rules.is_empty(),
        "expected at least one send rule in the model"
    );
    assert!(send_rules.iter().all(|r| {
        ta.locations[r.from.as_usize()].local_vars.get(flag) == Some(&LocalValue::Bool(false))
            && ta.locations[r.to.as_usize()].local_vars.get(flag) == Some(&LocalValue::Bool(true))
    }));
}

#[test]
fn lower_value_abstraction_sign_allows_unbounded_message_fields() {
    let src = r#"
protocol ValueAbsSign {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; values: sign; }
message Vote(view: int, round: nat);
role R {
    var view: int in 0..2 = 0;
    init s;
    phase s {
        when received >= 0 Vote(view=view, round=1) => { goto phase s; }
    }
}
}
"#;
    let prog = parse(src, "value_abs_sign.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // int(sign) x nat(sign) = 3 x 2 = 6 abstract counters.
    assert_eq!(ta.shared_vars.len(), 6);
    assert_eq!(ta.semantics.value_abstraction, ValueAbstractionMode::Sign);
}

#[test]
fn lower_partial_synchrony_and_gst_settings() {
    let src = r#"
protocol PartialSyncCfg {
params n, t, f, gst;
resilience: n > 3*t;
adversary {
    model: omission;
    bound: f;
    timing: partial_synchrony;
    gst: gst;
}
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "partial_sync_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.fault_model, FaultModel::Omission);
    assert_eq!(ta.semantics.timing_model, TimingModel::PartialSynchrony);
    let gst = ta.semantics.gst_param.expect("gst param should be set");
    assert_eq!(ta.parameters[gst.as_usize()].name, "gst");
}

#[test]
fn lower_parses_byzantine_equivocation_mode() {
    let src = r#"
protocol EqCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; equivocation: none; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "eq_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.equivocation_mode, EquivocationMode::None);
}

#[test]
fn lower_parses_authentication_mode_and_tracks_sender_flags() {
    let src = r#"
protocol AuthCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; }
message Vote;
role R {
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "auth_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.authentication_mode, AuthenticationMode::Signed);
    assert!(
        ta.locations
            .iter()
            .all(|loc| loc.local_vars.keys().any(|k| k.starts_with("__sent_g"))),
        "signed auth should track sender uniqueness flags for sent message counters"
    );
}

#[test]
fn lower_message_channel_and_equivocation_policies() {
    let src = r#"
protocol MsgPolicies {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: none; equivocation: full; }
channel Vote: authenticated;
channel Ping: unauthenticated;
equivocation Vote: none;
equivocation Ping: full;
message Vote;
message Ping;
role R {
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            send Ping;
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "msg_policies.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let vote_policy = ta
        .security
        .message_policies
        .get("Vote")
        .expect("Vote policy");
    assert_eq!(vote_policy.auth, MessageAuthPolicy::Authenticated);
    assert_eq!(vote_policy.equivocation, MessageEquivocationPolicy::None);

    let ping_policy = ta
        .security
        .message_policies
        .get("Ping")
        .expect("Ping policy");
    assert_eq!(ping_policy.auth, MessageAuthPolicy::Unauthenticated);
    assert_eq!(ping_policy.equivocation, MessageEquivocationPolicy::Full);

    let sent_flags: std::collections::HashSet<String> = ta
        .locations
        .iter()
        .flat_map(|loc| loc.local_vars.keys().cloned())
        .filter(|k| k.starts_with("__sent_g"))
        .collect();
    assert_eq!(
        sent_flags.len(),
        1,
        "only authenticated Vote counters should get sender-uniqueness flags"
    );
}

#[test]
fn lower_parses_identity_selective_network_semantics() {
    let src = r#"
protocol NetCfg {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: identity_selective;
}
message Vote;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "net_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.semantics.network_semantics,
        NetworkSemantics::IdentitySelective
    );
}

#[test]
fn lower_parses_delivery_and_fault_scope_controls() {
    let src = r#"
protocol DeliveryFaultScopeCfg {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    network: identity_selective;
    delivery: per_recipient;
    faults: global;
}
message Vote;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "delivery_fault_scope_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.semantics.delivery_control,
        DeliveryControlMode::PerRecipient
    );
    assert_eq!(ta.semantics.fault_budget_scope, FaultBudgetScope::Global);
}

#[test]
fn lower_rejects_delivery_control_with_classic_network() {
    let src = r#"
protocol DeliveryClassicInvalid {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    network: classic;
    delivery: global;
}
message Vote;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "delivery_classic_invalid.trs").unwrap();
    let err = lower(&prog).expect_err("delivery controls on classic network should fail");
    let msg = err.to_string();
    assert!(msg.contains("delivery controls require non-classic"));
}

#[test]
fn lower_process_selective_network_uses_pid_scoped_channels() {
    let src = r#"
protocol ProcessSelectiveNetCfg {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: process_selective;
}
message Vote;
role R {
    var pid: nat in 0..1;
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "process_selective_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.semantics.network_semantics,
        NetworkSemantics::ProcessSelective
    );

    let recipient0_vars: std::collections::HashSet<usize> = ta
        .shared_vars
        .iter()
        .enumerate()
        .filter(|(_, v)| v.name.starts_with("cnt_Vote@R#0<-"))
        .map(|(i, _)| i)
        .collect();
    let recipient1_vars: std::collections::HashSet<usize> = ta
        .shared_vars
        .iter()
        .enumerate()
        .filter(|(_, v)| v.name.starts_with("cnt_Vote@R#1<-"))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !recipient0_vars.is_empty(),
        "recipient R#0 counters missing"
    );
    assert!(
        !recipient1_vars.is_empty(),
        "recipient R#1 counters missing"
    );

    assert!(
        ta.locations.iter().all(|loc| matches!(
            loc.local_vars.get(DEFAULT_PROCESS_ID_VAR),
            Some(LocalValue::Int(_))
        )),
        "all locations should include concrete process identifier values"
    );
    assert!(
        ta.locations
            .iter()
            .all(|loc| !loc.local_vars.contains_key(INTERNAL_DELIVERY_LANE_VAR)),
        "process-selective mode should not inject cohort lane locals"
    );
    let mut initial_pids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for lid in &ta.initial_locations {
        if let Some(LocalValue::Int(pid)) = ta.locations[lid.as_usize()]
            .local_vars
            .get(DEFAULT_PROCESS_ID_VAR)
        {
            initial_pids.insert(*pid);
        }
    }
    assert_eq!(
        initial_pids,
        std::collections::HashSet::from([0_i64, 1_i64])
    );

    let mut guarded_vars = std::collections::HashSet::new();
    for rule in &ta.rules {
        if ta.locations[rule.from.as_usize()].phase != "s" {
            continue;
        }
        let from_pid = match ta.locations[rule.from.as_usize()]
            .local_vars
            .get(DEFAULT_PROCESS_ID_VAR)
        {
            Some(LocalValue::Int(pid)) => pid,
            _ => continue,
        };
        if let Some(atom) = rule.guard.atoms.first() {
            let GuardAtom::Threshold { vars, .. } = atom;
            for var in vars {
                guarded_vars.insert(var.as_usize());
                let counter_name = &ta.shared_vars[var.as_usize()].name;
                assert!(
                    counter_name.contains(&format!("@R#{from_pid}<-")),
                    "guard should read recipient-scoped identity deliveries for pid {from_pid}: {counter_name}"
                );
            }
        }
    }
    assert!(!guarded_vars.is_empty());
    assert!(guarded_vars.iter().any(|v| recipient0_vars.contains(v)));
    assert!(guarded_vars.iter().any(|v| recipient1_vars.contains(v)));
}

#[test]
fn lower_process_selective_uses_declared_identity_variable() {
    let src = r#"
protocol ProcessSelectiveIdentityCfg {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: process_selective;
}
identity R: process(node_id) key replica_key;
message Vote;
role R {
    var node_id: nat in 0..1;
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "process_selective_identity_var.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(
        ta.semantics.network_semantics,
        NetworkSemantics::ProcessSelective
    );
    assert!(
        ta.locations
            .iter()
            .all(|loc| matches!(loc.local_vars.get("node_id"), Some(LocalValue::Int(_)))),
        "all locations should include declared process identity variable"
    );
    assert!(
        ta.locations
            .iter()
            .all(|loc| !loc.local_vars.contains_key(DEFAULT_PROCESS_ID_VAR)),
        "custom identity variable should replace implicit pid variable"
    );
    assert!(
        ta.shared_vars
            .iter()
            .any(|v| v.name.starts_with("cnt_Vote@R#0<-")),
        "expected sender-scoped counters for recipient R#0"
    );
    assert!(
        ta.shared_vars
            .iter()
            .any(|v| v.name.starts_with("cnt_Vote@R#1<-")),
        "expected sender-scoped counters for recipient R#1"
    );
}

#[test]
fn lower_process_selective_targeted_send_updates_only_target_recipients() {
    let src = r#"
protocol ProcessSelectiveTargetedSend {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: none;
    network: process_selective;
}
identity Leader: process(leader_id) key leader_key;
identity Replica: process(replica_id) key replica_key;
message Vote;
role Leader {
    var leader_id: nat in 0..1;
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote to Replica;
            goto phase done;
        }
    }
    phase done {}
}
role Replica {
    var replica_id: nat in 0..1;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "process_selective_targeted_send.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let send_rules: Vec<_> = ta
        .rules
        .iter()
        .filter(|rule| {
            let from = &ta.locations[rule.from.as_usize()];
            from.role == "Leader" && from.phase == "s" && !rule.updates.is_empty()
        })
        .collect();
    assert!(!send_rules.is_empty(), "expected sender rules from Leader");

    for rule in send_rules {
        let from = &ta.locations[rule.from.as_usize()];
        let sender_pid = match from.local_vars.get("leader_id") {
            Some(LocalValue::Int(pid)) => pid,
            other => panic!("missing leader identity on sender location: {other:?}"),
        };
        let updated_names: std::collections::HashSet<String> = rule
            .updates
            .iter()
            .map(|u| ta.shared_vars[u.var.as_usize()].name.clone())
            .collect();
        let expected: std::collections::HashSet<String> = [
            format!("cnt_Vote@Replica#0<-Leader#{sender_pid}"),
            format!("cnt_Vote@Replica#1<-Leader#{sender_pid}"),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            updated_names, expected,
            "targeted send should update recipient-scoped Replica channels only"
        );
        assert!(updated_names.iter().all(|name| !name.contains("@Leader#")));
    }
}

#[test]
fn lower_process_selective_keeps_per_sender_variant_channels_for_equivocation() {
    let src = r#"
protocol ProcessSelectiveEquivocationChannels {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: none;
    equivocation: full;
    network: process_selective;
}
message Vote(value: bool);
role Replica {
    var pid: nat in 0..1;
    init s;
    phase s {
        when received >= 0 Vote(value=false) => {
            send Vote(value=true);
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "process_selective_equiv_channels.trs").unwrap();
    let ta = lower(&prog).unwrap();

    for sender in [0_i64, 1_i64] {
        for value in ["false", "true"] {
            let counter = format!("cnt_Vote@Replica#0<-Replica#{sender}[value={value}]");
            assert!(
                ta.find_shared_var_by_name(&counter).is_some(),
                "missing sender-scoped variant counter: {counter}"
            );
        }
    }

    let guard_rule = ta
        .rules
        .iter()
        .find(|rule| {
            ta.locations[rule.from.as_usize()].role == "Replica"
                && ta.locations[rule.from.as_usize()].phase == "s"
                && ta.locations[rule.from.as_usize()].local_vars.get("pid")
                    == Some(&LocalValue::Int(0))
        })
        .expect("expected a pid=0 guard rule");
    let guard_vars = match guard_rule.guard.atoms.first().expect("threshold guard") {
        GuardAtom::Threshold { vars, .. } => vars,
    };
    let guard_names: std::collections::HashSet<String> = guard_vars
        .iter()
        .map(|v| ta.shared_vars[v.as_usize()].name.clone())
        .collect();
    let expected_guard: std::collections::HashSet<String> = [
        "cnt_Vote@Replica#0<-Replica#0[value=false]".to_string(),
        "cnt_Vote@Replica#0<-Replica#1[value=false]".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        guard_names, expected_guard,
        "distinct guard should consume sender-scoped channels for one payload variant"
    );
}

#[test]
fn lower_process_selective_requires_pid_domain() {
    let src = r#"
protocol ProcessSelectiveMissingPid {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: process_selective;
}
message Vote;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "process_selective_missing_pid.trs").unwrap();
    let err = lower(&prog).expect_err("missing pid should be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("pid") && msg.contains("process_selective"),
        "unexpected error: {msg}"
    );
}

#[test]
fn lower_cohort_selective_keeps_internal_lane_instrumentation() {
    let src = r#"
protocol CohortSelectiveNetCfg {
params n, t, f;
resilience: n > 3*t;
adversary {
    model: byzantine;
    bound: f;
    auth: signed;
    network: cohort_selective;
}
message Vote;
role R {
    init s;
    phase s {
        when received >= 0 Vote => {
            send Vote;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "cohort_selective_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.semantics.network_semantics,
        NetworkSemantics::CohortSelective
    );
    assert!(
        ta.locations
            .iter()
            .all(|loc| loc.local_vars.contains_key(INTERNAL_DELIVERY_LANE_VAR)),
        "cohort-selective mode should keep internal lane variable"
    );
}

#[test]
fn lower_accepts_crash_model() {
    let src = r#"
protocol CrashCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: crash; bound: f; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "crash_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.fault_model, FaultModel::Crash);
    let crash_counter = ta
        .find_shared_var_by_name(INTERNAL_CRASH_COUNTER)
        .expect("crash model should include internal crash counter");
    assert!(
        ta.locations
            .iter()
            .all(|loc| loc.local_vars.contains_key(INTERNAL_ALIVE_VAR)),
        "all locations should include internal alive/dead flag"
    );
    assert!(ta.initial_locations.iter().all(|&lid| {
        ta.locations[lid.as_usize()]
            .local_vars
            .get(INTERNAL_ALIVE_VAR)
            == Some(&LocalValue::Bool(true))
    }));
    let has_crash_rule = ta.rules.iter().any(|rule| {
        ta.locations[rule.from.as_usize()]
            .local_vars
            .get(INTERNAL_ALIVE_VAR)
            == Some(&LocalValue::Bool(true))
            && ta.locations[rule.to.as_usize()]
                .local_vars
                .get(INTERNAL_ALIVE_VAR)
                == Some(&LocalValue::Bool(false))
            && rule
                .updates
                .iter()
                .any(|u| u.var == crash_counter && matches!(u.kind, UpdateKind::Increment))
    });
    assert!(has_crash_rule, "expected at least one injected crash rule");
}

#[test]
fn lower_crash_recovery_model_has_recovery_transitions() {
    let src = r#"
protocol CrashRecoveryCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: crash_recovery; bound: f; }
message M;
role R {
    init s;
    phase s {
        when received >= 1 M => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crash_recovery_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.fault_model, FaultModel::CrashRecovery);
    // All locations should have __alive flag.
    assert!(
        ta.locations
            .iter()
            .all(|loc| loc.local_vars.contains_key(INTERNAL_ALIVE_VAR)),
        "all locations should include internal alive/dead flag"
    );
    // Should NOT have a crash counter (crash-recovery uses dead-location sum instead).
    assert!(
        ta.find_shared_var_by_name(INTERNAL_CRASH_COUNTER).is_none(),
        "crash-recovery model should not have a crash counter"
    );
    // Should have crash transitions (alive -> dead).
    let has_crash_rule = ta.rules.iter().any(|rule| {
        ta.locations[rule.from.as_usize()]
            .local_vars
            .get(INTERNAL_ALIVE_VAR)
            == Some(&LocalValue::Bool(true))
            && ta.locations[rule.to.as_usize()]
                .local_vars
                .get(INTERNAL_ALIVE_VAR)
                == Some(&LocalValue::Bool(false))
    });
    assert!(has_crash_rule, "expected crash transitions");
    // Should have recovery transitions (dead -> initial alive).
    let initial_alive_lids: Vec<_> = ta
        .initial_locations
        .iter()
        .filter(|&&lid| {
            ta.locations[lid.as_usize()]
                .local_vars
                .get(INTERNAL_ALIVE_VAR)
                == Some(&LocalValue::Bool(true))
        })
        .collect();
    let has_recovery_rule = ta.rules.iter().any(|rule| {
        ta.locations[rule.from.as_usize()]
            .local_vars
            .get(INTERNAL_ALIVE_VAR)
            == Some(&LocalValue::Bool(false))
            && initial_alive_lids.contains(&&rule.to)
    });
    assert!(has_recovery_rule, "expected recovery transitions");
}

#[test]
fn lower_leader_role_records_leader() {
    let src = r#"
protocol LeaderTest {
params n, t;
resilience: n > 3*t;
message Propose;
leader role Proposer {
    init s;
    phase s {}
}
role Validator {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "leader_test.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.leader_roles, vec!["Proposer".to_string()]);
}

#[test]
fn lower_or_threshold_guard_splits_rules() {
    let src = r#"
protocol OrGuard {
params n, t;
resilience: n > 3*t;
message A;
message B;
role P {
    init s;
    phase s {
        when received >= 1 A || received >= 1 B => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // Single source location, OR split into two TA rules.
    assert_eq!(ta.rules.len(), 2);
}

#[test]
fn lower_or_guard_mixed_local_and_threshold_is_supported() {
    let src = r#"
protocol OrGuardMixed {
params n, t;
resilience: n > 3*t;
message A;
role P {
    var ready: bool = false;
    init s;
    phase s {
        when ready || received >= 1 A => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_guard_mixed.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert!(
        ta.rules.iter().any(|r| r.guard.atoms.is_empty()),
        "expected at least one rule for local disjunct (trivial TA guard)"
    );
    assert!(
        ta.rules.iter().any(|r| !r.guard.atoms.is_empty()),
        "expected at least one threshold-guarded rule for message disjunct"
    );
}

#[test]
fn lower_or_and_guard_expands_to_dnf_rules() {
    let src = r#"
protocol OrAndGuard {
params n, t;
resilience: n > 3*t;
message A;
message B;
message C;
role P {
    init s;
    phase s {
        when (received >= 1 A || received >= 1 B) && received >= 1 C => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_and_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(
        ta.rules.len(),
        2,
        "expected two DNF-expanded rules: (A && C) and (B && C)"
    );
    assert!(
        ta.rules.iter().all(|r| r.guard.atoms.len() == 2),
        "each expanded rule should have two threshold atoms"
    );
}

#[test]
fn lower_or_guard_duplicate_disjuncts_are_deduplicated() {
    let src = r#"
protocol OrGuardDuplicate {
params n, t;
resilience: n > 3*t;
message A;
role P {
    init s;
    phase s {
        when received >= 1 A || received >= 1 A => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_guard_duplicate.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.rules.len(),
        1,
        "duplicate disjunct should produce one rule"
    );
}

#[test]
fn lower_or_guard_subsumed_conjunctive_clause_is_pruned() {
    let src = r#"
protocol OrGuardSubsumed {
params n, t;
resilience: n > 3*t;
message A;
message B;
role P {
    init s;
    phase s {
        when received >= 1 A || (received >= 1 A && received >= 1 B) => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_guard_subsumed.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.rules.len(),
        1,
        "subsumed disjunct `(A && B)` should be pruned when `A` exists"
    );
    assert_eq!(
        ta.rules[0].guard.atoms.len(),
        1,
        "remaining rule should keep only the minimal `A` guard atom"
    );
}

#[test]
fn lower_or_and_commuted_disjuncts_are_canonicalized() {
    let src = r#"
protocol OrAndCommuted {
params n, t;
resilience: n > 3*t;
message A;
message B;
role P {
    init s;
    phase s {
        when (received >= 1 A || received >= 1 B) && (received >= 1 B || received >= 1 A) => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "or_and_commuted.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(
        ta.rules.len(),
        2,
        "commuted disjunctive terms should reduce to two minimal rules (A or B)"
    );
    assert!(
        ta.rules.iter().all(|r| r.guard.atoms.len() == 1),
        "canonicalization should remove redundant two-atom conjunction clauses"
    );
}

#[test]
fn lower_decide_maps_to_decision_and_decided() {
    let src = r#"
protocol DecideSemantics {
params n, t;
resilience: n > 3*t;
message Vote;
role P {
    var decided: bool = false;
    var decision: bool = false;
    init s;
    phase s {
        when received >= 1 Vote => {
            decide true;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "decide_semantics.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let has_decided_true_rule = ta.rules.iter().any(|r| {
        let to = &ta.locations[r.to.as_usize()];
        to.local_vars.get("decided") == Some(&LocalValue::Bool(true))
            && to.local_vars.get("decision") == Some(&LocalValue::Bool(true))
    });
    assert!(has_decided_true_rule);
}

#[test]
fn lower_bounded_int_message_fields() {
    let src = r#"
protocol IntMsg {
params n, t;
resilience: n > 3*t;
message Vote(view: int in 0..1);
role P {
    var view: int in 0..1 = 0;
    init s;
    phase s {
        when received >= 1 Vote(view=view) => {
            send Vote(view=view);
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "int_msg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // view in {0,1} => two message counters.
    assert_eq!(ta.shared_vars.len(), 2);
}

#[test]
fn lower_crypto_object_form_lock_justify() {
    let src = r#"
protocol CryptoLower {
params n, t, f;
resilience: n > 3*t;
message Vote(view: nat in 0..2);
certificate QC from Vote threshold 2*t+1 signer Replica;
role Replica {
    var view: nat in 0..2 = 0;
    init s;
    phase s {
        when received distinct >= 2*t+1 Vote(view=view) => {
            form QC(view=view);
            lock QC(view=view);
            justify QC(view=view);
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crypto_lower.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let vote_counter = ta
        .find_shared_var_by_name("cnt_Vote@Replica[view=0]")
        .expect("vote counter should exist");
    let qc_counter = ta
        .find_shared_var_by_name("cnt_QC@Replica[view=0]")
        .expect("qc counter should exist");
    assert!(
        ta.locations.iter().all(|loc| {
            loc.local_vars.contains_key("__lock_qc") && loc.local_vars.contains_key("__justify_qc")
        }),
        "lock/justify instrumentation should be present"
    );
    assert!(
        ta.rules.iter().any(|rule| {
            rule.updates
                .iter()
                .any(|u| u.var == qc_counter && matches!(u.kind, UpdateKind::Increment))
                && rule.guard.atoms.iter().any(|atom| {
                    matches!(
                        atom,
                        GuardAtom::Threshold {
                            vars,
                            op: CmpOp::Ge,
                            distinct: true,
                            ..
                        } if vars.contains(&vote_counter)
                    )
                })
        }),
        "forming QC should require a distinct-source threshold guard and increment QC counter"
    );
}

#[test]
fn lower_threshold_signature_form_filters_witnesses_to_signer_role() {
    let src = r#"
protocol CryptoSignerFilter {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; network: identity_selective; }
message Vote(view: nat in 0..0);
threshold_signature Sig from Vote threshold 1 signer Replica;
role Replica {
    var view: nat in 0..0 = 0;
    init s;
    phase s {
        when received >= 0 Vote(view=view) => {
            form Sig(view=view);
            goto phase done;
        }
    }
    phase done {}
}
role Client {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "crypto_signer_filter.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let sig_update_rule = ta
        .rules
        .iter()
        .find(|rule| {
            rule.updates.iter().any(|upd| {
                ta.shared_vars
                    .get(upd.var.as_usize())
                    .map(|sv| sv.name.starts_with("cnt_Sig@Replica<-Replica"))
                    .unwrap_or(false)
            })
        })
        .expect("form Sig rule should exist");
    let source_guard = sig_update_rule
        .guard
        .atoms
        .iter()
        .find_map(|atom| match atom {
            GuardAtom::Threshold {
                vars,
                op: CmpOp::Ge,
                distinct: true,
                ..
            } => Some(vars),
            _ => None,
        })
        .expect("form Sig should include distinct source-threshold guard");
    let source_names: Vec<String> = source_guard
        .iter()
        .map(|var_id| ta.shared_vars[var_id.as_usize()].name.clone())
        .collect();
    assert!(
        source_names
            .iter()
            .all(|name| name.contains("cnt_Vote@Replica<-Replica")),
        "source witnesses should be restricted to signer role Replica: {source_names:?}"
    );
    assert!(
        source_names
            .iter()
            .all(|name| !name.contains("cnt_Vote@Replica<-Client")),
        "source witnesses must not include non-signer role channels: {source_names:?}"
    );
}

#[test]
fn lower_crypto_object_conflicts_exclusive_adds_admissibility_guard() {
    let src = r#"
protocol CryptoExclusive {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; network: identity_selective; }
message Vote(value: bool);
certificate QC from Vote threshold 1 conflicts exclusive;
role Replica {
    init s;
    phase s {
        when received >= 0 Vote(value=true) => {
            form QC(value=true);
            lock QC(value=true);
            justify QC(value=true);
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crypto_exclusive.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let qc_false = ta
        .find_shared_var_by_name("cnt_QC@Replica<-Replica[value=false]")
        .expect("conflicting QC variant should exist");
    let guarded_rule = ta
        .rules
        .iter()
        .find(|rule| {
            rule.updates.iter().any(|upd| {
                ta.shared_vars
                    .get(upd.var.as_usize())
                    .map(|sv| sv.name == "cnt_QC@Replica<-Replica[value=true]")
                    .unwrap_or(false)
            })
        })
        .expect("form QC(value=true) rule should exist");
    assert!(
        guarded_rule.guard.atoms.iter().any(|atom| {
            matches!(
                atom,
                GuardAtom::Threshold {
                    vars,
                    op: CmpOp::Eq,
                    bound,
                    distinct: false
                } if vars.contains(&qc_false) && bound.constant == 0 && bound.terms.is_empty()
            )
        }),
        "exclusive conflict policy should add equality-to-zero guard over conflicting QC variants"
    );
}

#[test]
fn lower_crypto_object_defaults_to_authenticated_channel_policy() {
    let src = r#"
protocol CryptoAuthDefault {
params n, t;
resilience: n > 3*t;
message Vote(value: bool);
certificate QC from Vote threshold 1;
role Replica {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "crypto_auth_default.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let qc_policy = ta
        .security
        .message_policies
        .get("QC")
        .expect("crypto object should have default message policy");
    assert_eq!(qc_policy.auth, MessageAuthPolicy::Authenticated);
}

#[test]
fn lower_rejects_threshold_signature_without_signer_role() {
    let src = r#"
protocol CryptoMissingSigner {
params n, t;
resilience: n > 3*t;
message Vote(value: bool);
threshold_signature QC from Vote threshold 1;
role Replica {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "crypto_missing_signer.trs").unwrap();
    let err = lower(&prog).expect_err("threshold signatures require an explicit signer role");
    let msg = format!("{err}");
    assert!(msg.contains("requires an explicit signer role"));
}

#[test]
fn lower_rejects_partial_synchrony_without_gst() {
    let src = r#"
protocol MissingGst {
params n, t, f;
resilience: n > 3*t;
adversary { model: omission; bound: f; timing: partial_synchrony; }
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "missing_gst.trs").unwrap();
    let err = lower(&prog).expect_err("partial_synchrony without gst should be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("requires `adversary { gst: <param>; }`"));
}

#[test]
fn lower_rejects_unknown_adversary_bound_parameter() {
    let src = r#"
protocol UnknownBoundParam {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: ghost; }
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "unknown_bound_param.trs").unwrap();
    let err = lower(&prog).expect_err("lowering should reject unknown adversary bound parameter");
    let msg = format!("{err}");
    assert!(msg.contains("Unknown parameter 'ghost'"));
}

#[test]
fn lower_rejects_unknown_adversary_key() {
    // Unknown adversary keys are now caught at parse time, not lowering.
    let src = r#"
protocol UnknownAdversaryKey {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; foo: bar; }
role R {
    init s;
    phase s {}
}
}
"#;
    let err = parse(src, "unknown_adversary_key.trs")
        .expect_err("parse should reject unknown adversary key");
    let msg = format!("{err}");
    assert!(
        msg.contains("foo"),
        "error should mention the unknown key, got: {msg}"
    );
}

#[test]
fn lower_tracks_key_ownership_and_compromised_keys() {
    let src = r#"
protocol KeyCompromiseCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; compromised_key: r_key; }
identity R: role key r_key;
message Vote;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "key_compromise_cfg.trs").unwrap();
    let ta = lower(&prog).expect("lowering should accept declared compromised key");
    assert_eq!(ta.key_owner("r_key"), Some("R"));
    assert!(ta.key_is_compromised("r_key"));
}

#[test]
fn lower_supports_compromised_keys_alias_and_default_identity_key() {
    let src = r#"
protocol KeyCompromiseAliasCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; compromised_keys: client_key; }
identity Client: role;
message Request;
role Client {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "key_compromise_alias_cfg.trs").unwrap();
    let ta = lower(&prog).expect("lowering should infer default key names");
    assert_eq!(ta.key_owner("client_key"), Some("Client"));
    assert!(ta.key_is_compromised("client_key"));
}

#[test]
fn lower_rejects_compromised_key_without_owner() {
    let src = r#"
protocol UnknownCompromisedKey {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; compromised_key: ghost_key; }
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "unknown_compromised_key.trs").unwrap();
    let err = lower(&prog).expect_err("unknown compromised key should be rejected");
    let msg = err.to_string();
    assert!(msg.contains("compromised key"));
    assert!(msg.contains("ghost_key"));
}

#[test]
fn lower_rejects_duplicate_identity_key_across_roles() {
    let src = r#"
protocol DuplicateIdentityKey {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; auth: signed; }
identity A: role key shared_key;
identity B: role key shared_key;
role A {
    init s;
    phase s {}
}
role B {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "duplicate_identity_key.trs").unwrap();
    let err = lower(&prog).expect_err("duplicate identity key should fail");
    let msg = err.to_string();
    assert!(msg.contains("assigned to multiple roles"));
}

#[test]
fn lower_enforces_identity_immutability_for_process_scope() {
    let src = r#"
protocol IdentityImmutable {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; network: identity_selective; }
identity R: process(pid) key r_key;
message M;
role R {
    var pid: nat in 0..1 = 0;
    init s;
    phase s {
        when received >= 0 M => {
            pid = 1;
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "identity_immutable.trs").unwrap();
    let err = lower(&prog).expect_err("assigning process identity variable should be rejected");
    let msg = err.to_string();
    assert!(msg.contains("identity variable"));
    assert!(msg.contains("immutable"));
}

#[test]
fn lower_has_guard_with_field_args_resolves_correct_variant() {
    let src = r#"
protocol CryptoHasGuard {
params n, t, f;
resilience: n > 3*t;
message Vote(value: bool);
certificate QC from Vote threshold 1;
role Replica {
    init s;
    phase s {
        when has QC(value=true) => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crypto_has_guard.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let qc_true = ta
        .find_shared_var_by_name("cnt_QC@Replica[value=true]")
        .expect("QC true variant counter should exist");
    let qc_false = ta
        .find_shared_var_by_name("cnt_QC@Replica[value=false]")
        .expect("QC false variant counter should exist");
    // Find the rule that transitions from phase s to done
    let has_rule = ta
        .rules
        .iter()
        .find(|rule| {
            rule.guard.atoms.iter().any(|atom| {
                matches!(
                    atom,
                    GuardAtom::Threshold {
                        vars,
                        op: CmpOp::Ge,
                        distinct: false,
                        ..
                    } if vars.contains(&qc_true)
                )
            })
        })
        .expect("has QC(value=true) guard rule should exist");
    // The guard should reference QC[value=true] but NOT QC[value=false]
    let guard_vars: Vec<SharedVarId> = has_rule
        .guard
        .atoms
        .iter()
        .flat_map(|atom| {
            let GuardAtom::Threshold { vars, .. } = atom;
            vars.clone()
        })
        .collect();
    assert!(
        guard_vars.contains(&qc_true),
        "has QC(value=true) guard should include QC[value=true] counter"
    );
    assert!(
        !guard_vars.contains(&qc_false),
        "has QC(value=true) guard should NOT include QC[value=false] counter"
    );
}

#[test]
fn lower_justify_sets_justify_flag_not_lock_flag() {
    let src = r#"
protocol CryptoJustifyOnly {
params n, t, f;
resilience: n > 3*t;
message Vote(value: bool);
certificate QC from Vote threshold 1;
role Replica {
    init s;
    phase s {
        when received >= 0 Vote(value=true) => {
            justify QC(value=true);
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crypto_justify_only.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // Find the "done" phase locations
    let done_locs: Vec<_> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.name.contains("done"))
        .collect();
    assert!(!done_locs.is_empty(), "should have 'done' phase locations");
    // In the done locations reached by the justify action,
    // __justify_qc should be true, __lock_qc should be false
    let has_justify_true_done = done_locs.iter().any(|(_, loc)| {
        loc.local_vars.get("__justify_qc") == Some(&LocalValue::Bool(true))
            && loc.local_vars.get("__lock_qc") == Some(&LocalValue::Bool(false))
    });
    assert!(
        has_justify_true_done,
        "at least one 'done' location should have __justify_qc=true, __lock_qc=false: {:?}",
        done_locs
            .iter()
            .map(|(_, loc)| (&loc.name, &loc.local_vars))
            .collect::<Vec<_>>()
    );
}

#[test]
fn lower_lock_adds_implicit_has_threshold_guard() {
    let src = r#"
protocol CryptoLockImplicit {
params n, t, f;
resilience: n > 3*t;
message Vote(value: bool);
certificate QC from Vote threshold 1;
role Replica {
    init s;
    phase s {
        when received >= 0 Vote(value=true) => {
            lock QC(value=true);
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "crypto_lock_implicit.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let qc_true = ta
        .find_shared_var_by_name("cnt_QC@Replica[value=true]")
        .expect("QC true counter should exist");
    // Find the rule that sets __lock_qc=true
    let lock_rule = ta
        .rules
        .iter()
        .find(|rule| {
            let target_loc = &ta.locations[rule.to.as_usize()];
            target_loc.local_vars.get("__lock_qc") == Some(&LocalValue::Bool(true))
                && ta.locations[rule.from.as_usize()]
                    .local_vars
                    .get("__lock_qc")
                    == Some(&LocalValue::Bool(false))
        })
        .expect("lock transition rule should exist");
    // The lock rule should have an implicit threshold guard over QC counter (has check)
    let has_qc_guard = lock_rule.guard.atoms.iter().any(|atom| {
        matches!(
            atom,
            GuardAtom::Threshold {
                vars,
                bound,
                op: CmpOp::Ge,
                distinct: false,
            } if vars.contains(&qc_true) && bound.constant == 1
        )
    });
    assert!(
        has_qc_guard,
        "lock action should inject implicit has-threshold guard (>= 1) over QC counter"
    );
}

fn make_por_mode_protocol(por_value: &str) -> String {
    format!(
        r#"
protocol PorTest {{
parameters {{ n: nat; t: nat; }}
resilience {{ n > 3*t; }}
adversary {{
    bound: t;
    model: byzantine;
    por: {por_value};
}}
message Echo;
role Process {{
    init waiting;
    phase waiting {{
        when received >= 2*t+1 Echo => {{
            send Echo;
            goto phase done;
        }}
    }}
    phase done {{}}
}}
}}
"#
    )
}

#[test]
fn lower_por_mode_full() {
    let src = make_por_mode_protocol("full");
    let prog = parse(&src, "por_full.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.por_mode, PorMode::Full);
}

#[test]
fn lower_por_mode_static() {
    let src = make_por_mode_protocol("static");
    let prog = parse(&src, "por_static.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.por_mode, PorMode::Static);
}

#[test]
fn lower_por_mode_off() {
    let src = make_por_mode_protocol("off");
    let prog = parse(&src, "por_off.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.por_mode, PorMode::Off);
}

#[test]
fn lower_por_mode_none_alias() {
    let src = make_por_mode_protocol("none");
    let prog = parse(&src, "por_none.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.por_mode, PorMode::Off);
}

#[test]
fn lower_por_mode_invalid() {
    let src = make_por_mode_protocol("bogus");
    let prog = parse(&src, "por_bogus.trs").unwrap();
    let result = lower(&prog);
    assert!(result.is_err());
}

#[test]
fn lower_interface_assumption_converts_parameter_constraint() {
    use tarsier_dsl::ast;

    // Build a minimal TA with parameters n, t, f
    let mut ta = ThresholdAutomaton::new();
    ta.parameters.push(Parameter { name: "n".into(), time_varying: false });
    ta.parameters.push(Parameter { name: "t".into(), time_varying: false });
    ta.parameters.push(Parameter { name: "f".into(), time_varying: false });

    // AST assumption: n > 3*t
    let assumption = ast::InterfaceAssumption {
        lhs: ast::LinearExpr::Var("n".into()),
        op: ast::CmpOp::Gt,
        rhs: ast::LinearExpr::Mul(3, Box::new(ast::LinearExpr::Var("t".into()))),
        span: ast::Span::new(0, 0),
    };

    let result = lower_interface_assumption(&assumption, &ta).unwrap();
    match result {
        crate::composition::Assumption::ParameterConstraint { lhs, op, rhs } => {
            // lhs should reference param 0 (n); terms are (coefficient, param_id)
            assert_eq!(lhs.terms.len(), 1);
            assert_eq!(lhs.terms[0].0, 1); // coefficient 1
            assert_eq!(lhs.terms[0].1, 0); // param_id 0 (n)
            assert_eq!(op, CmpOp::Gt);
            // rhs should reference param 1 (t) with coefficient 3
            assert_eq!(rhs.terms.len(), 1);
            assert_eq!(rhs.terms[0].0, 3); // coefficient 3
            assert_eq!(rhs.terms[0].1, 1); // param_id 1 (t)
        }
        _ => panic!("expected ParameterConstraint"),
    }
}

#[test]
fn lower_interface_assumption_rejects_unknown_param() {
    use tarsier_dsl::ast;

    let ta = ThresholdAutomaton::new(); // no parameters

    let assumption = ast::InterfaceAssumption {
        lhs: ast::LinearExpr::Var("x".into()),
        op: ast::CmpOp::Ge,
        rhs: ast::LinearExpr::Const(0),
        span: ast::Span::new(0, 0),
    };

    let result = lower_interface_assumption(&assumption, &ta);
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// Additional coverage tests
// ---------------------------------------------------------------

#[test]
fn lower_rejects_missing_init_phase() {
    let src = r#"
protocol MissingInit {
params n, t;
resilience: n > 3*t;
message Echo;
role Process {
    phase waiting {
        when received >= 1 Echo => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "missing_init.trs").unwrap();
    let err = lower(&prog).expect_err("missing init phase should be rejected");
    assert!(
        matches!(err, LoweringError::NoInitPhase(ref name) if name == "Process"),
        "expected NoInitPhase(Process), got: {err}"
    );
}

#[test]
fn lower_rejects_unknown_phase_in_goto() {
    let src = r#"
protocol UnknownGoto {
params n, t;
resilience: n > 3*t;
message Echo;
role Process {
    init waiting;
    phase waiting {
        when received >= 1 Echo => {
            goto phase nonexistent;
        }
    }
}
}
"#;
    let prog = parse(src, "unknown_goto.trs").unwrap();
    let err = lower(&prog).expect_err("goto unknown phase should be rejected");
    assert!(
        matches!(err, LoweringError::UnknownPhase(ref name) if name == "nonexistent"),
        "expected UnknownPhase(nonexistent), got: {err}"
    );
}

#[test]
fn lower_parameters_extracted_in_order() {
    let src = r#"
protocol ParamOrder {
parameters { n: nat; t: nat; f: nat; }
resilience { n > 3*t; }
adversary { model: byzantine; bound: f; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "param_order.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.parameters.len(), 3);
    assert_eq!(ta.parameters[0].name, "n");
    assert_eq!(ta.parameters[1].name, "t");
    assert_eq!(ta.parameters[2].name, "f");
    assert_eq!(ta.find_param_by_name("n"), Some(ParamId::from(0)));
    assert_eq!(ta.find_param_by_name("t"), Some(ParamId::from(1)));
    assert_eq!(ta.find_param_by_name("f"), Some(ParamId::from(2)));
}

#[test]
fn lower_implicit_parameters_from_resilience_expression() {
    // Parameters referenced in resilience but not in explicit params list
    // should be auto-discovered.
    let src = r#"
protocol ImplicitParams {
resilience { n > 3*t + f; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "implicit_params.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // n, t, f should all be discovered from the resilience expression
    assert!(ta.find_param_by_name("n").is_some());
    assert!(ta.find_param_by_name("t").is_some());
    assert!(ta.find_param_by_name("f").is_some());
}

#[test]
fn lower_locations_from_phases_and_bool_vars() {
    let src = r#"
protocol LocationCheck {
params n, t;
resilience: n > 3*t;
message M;
role R {
    var flag: bool = false;
    init phase_a;
    phase phase_a {
        when received >= 1 M => {
            flag = true;
            goto phase phase_b;
        }
    }
    phase phase_b {}
}
}
"#;
    let prog = parse(src, "location_check.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // 2 phases x 2 bool values = 4 locations
    assert_eq!(ta.locations.len(), 4);
    // All locations should be in role "R"
    assert!(ta.locations.iter().all(|loc| loc.role == "R"));
    // Check phase names
    let phase_names: std::collections::HashSet<String> =
        ta.locations.iter().map(|loc| loc.phase.clone()).collect();
    assert!(phase_names.contains("phase_a"));
    assert!(phase_names.contains("phase_b"));
    // Initial location should be phase_a with flag=false
    assert_eq!(ta.initial_locations.len(), 1);
    let init_loc = &ta.locations[ta.initial_locations[0].as_usize()];
    assert_eq!(init_loc.phase, "phase_a");
    assert_eq!(
        init_loc.local_vars.get("flag"),
        Some(&LocalValue::Bool(false))
    );
}

#[test]
fn lower_message_types_create_shared_counter_variables() {
    let src = r#"
protocol MsgCounters {
params n, t;
resilience: n > 3*t;
message Echo;
message Ready;
role Sender {
    init s;
    phase s {}
}
role Receiver {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "msg_counters.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // Classic network: 2 message types x 2 roles = 4 counters
    assert_eq!(ta.shared_vars.len(), 4);
    assert!(ta.find_shared_var_by_name("cnt_Echo@Sender").is_some());
    assert!(ta.find_shared_var_by_name("cnt_Echo@Receiver").is_some());
    assert!(ta.find_shared_var_by_name("cnt_Ready@Sender").is_some());
    assert!(ta.find_shared_var_by_name("cnt_Ready@Receiver").is_some());
    // All should be MessageCounter kind
    assert!(ta
        .shared_vars
        .iter()
        .all(|v| v.kind == SharedVarKind::MessageCounter));
}

#[test]
fn lower_committee_declaration_with_concrete_values() {
    let src = r#"
protocol CommitteeTest {
params n, t, f, b;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; }
committee validators {
    population: 1000;
    byzantine: 333;
    size: 100;
    epsilon: 1.0e-9;
    bound_param: b;
}
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "committee_test.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.constraints.committees.len(), 1);
    let c = &ta.constraints.committees[0];
    assert_eq!(c.name, "validators");
    assert!(matches!(c.population, ParamOrConst::Const(1000)));
    assert!(matches!(c.byzantine, ParamOrConst::Const(333)));
    assert!(matches!(c.committee_size, ParamOrConst::Const(100)));
    assert_eq!(c.epsilon, Some(1.0e-9));
    let bound_pid = c.bound_param.expect("bound_param should be set");
    assert_eq!(ta.parameters[bound_pid.as_usize()].name, "b");
}

#[test]
fn lower_committee_declaration_with_param_references() {
    let src = r#"
protocol CommitteeParamRef {
params N, K, S, b;
resilience: N > 3*K;
committee sample {
    population: N;
    byzantine: K;
    size: S;
    bound_param: b;
}
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "committee_param_ref.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.constraints.committees.len(), 1);
    let c = &ta.constraints.committees[0];
    assert!(
        matches!(c.population, ParamOrConst::Param(pid) if ta.parameters[pid.as_usize()].name == "N")
    );
    assert!(
        matches!(c.byzantine, ParamOrConst::Param(pid) if ta.parameters[pid.as_usize()].name == "K")
    );
    assert!(
        matches!(c.committee_size, ParamOrConst::Param(pid) if ta.parameters[pid.as_usize()].name == "S")
    );
    assert!(c.epsilon.is_none());
}

#[test]
fn lower_byzantine_adversary_model() {
    let src = r#"
protocol ByzantineCfg {
params n, t, f;
resilience: n > 3*t;
adversary { model: byzantine; bound: f; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "byzantine_cfg.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert_eq!(ta.semantics.fault_model, FaultModel::Byzantine);
    let bound = ta
        .constraints
        .adversary_bound_param
        .expect("adversary bound should be set");
    assert_eq!(ta.parameters[bound.as_usize()].name, "f");
    // No crash counter in Byzantine mode
    assert!(ta.find_shared_var_by_name(INTERNAL_CRASH_COUNTER).is_none());
    // No alive flag in Byzantine mode
    assert!(ta
        .locations
        .iter()
        .all(|loc| !loc.local_vars.contains_key(INTERNAL_ALIVE_VAR)));
}

#[test]
fn lower_resilience_condition_structure() {
    let src = r#"
protocol ResilienceCheck {
parameters { n: nat; t: nat; }
resilience { n > 3*t + 1; }
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "resilience_check.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let rc = ta
        .constraints
        .resilience_condition
        .as_ref()
        .expect("resilience condition should be present");
    // lhs should be n (param 0)
    assert_eq!(rc.lhs.terms.len(), 1);
    assert_eq!(rc.lhs.terms[0].1, 0); // param_id for n
    assert_eq!(rc.lhs.terms[0].0, 1); // coefficient 1
    assert_eq!(rc.op, CmpOp::Gt);
    // rhs should be 3*t + 1
    assert_eq!(rc.rhs.constant, 1);
    assert_eq!(rc.rhs.terms.len(), 1);
    assert_eq!(rc.rhs.terms[0].1, 1); // param_id for t
    assert_eq!(rc.rhs.terms[0].0, 3); // coefficient 3
}

#[test]
fn lower_enum_variable_creates_variant_locations() {
    let src = r#"
protocol EnumLower {
params n, t;
resilience: n > 3*t;
enum Status { idle, active, done };
role Worker {
    var status: Status = idle;
    init s;
    phase s {
        when status == idle => {
            status = active;
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "enum_lower.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // 3 enum variants x 1 phase = 3 locations
    assert_eq!(ta.locations.len(), 3);
    // Initial location should have status=idle
    assert_eq!(ta.initial_locations.len(), 1);
    let init = &ta.locations[ta.initial_locations[0].as_usize()];
    assert_eq!(
        init.local_vars.get("status"),
        Some(&LocalValue::Enum("idle".into()))
    );
    // Only the idle->active transition should pass the guard
    assert_eq!(ta.rules.len(), 1);
    let rule = &ta.rules[0];
    assert_eq!(
        ta.locations[rule.from.as_usize()].local_vars.get("status"),
        Some(&LocalValue::Enum("idle".into()))
    );
    assert_eq!(
        ta.locations[rule.to.as_usize()].local_vars.get("status"),
        Some(&LocalValue::Enum("active".into()))
    );
}

#[test]
fn lower_rejects_enum_variable_without_init() {
    let src = r#"
protocol EnumNoInit {
params n, t;
resilience: n > 3*t;
enum Status { idle, active };
role Worker {
    var status: Status;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "enum_no_init.trs").unwrap();
    let err = lower(&prog).expect_err("enum without init should be rejected");
    assert!(
        matches!(err, LoweringError::MissingEnumInit(ref name) if name == "status"),
        "expected MissingEnumInit(status), got: {err}"
    );
}

#[test]
fn lower_rejects_unknown_enum_type() {
    let src = r#"
protocol UnknownEnum {
params n, t;
resilience: n > 3*t;
role Worker {
    var status: Bogus = idle;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "unknown_enum.trs").unwrap();
    let err = lower(&prog).expect_err("unknown enum type should be rejected");
    assert!(
        matches!(err, LoweringError::UnknownEnum(ref name) if name == "Bogus"),
        "expected UnknownEnum(Bogus), got: {err}"
    );
}

#[test]
fn lower_ranged_int_variable_out_of_range_init() {
    let src = r#"
protocol OutOfRange {
params n, t;
resilience: n > 3*t;
role Worker {
    var x: int in 0..3 = 5;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "out_of_range.trs").unwrap();
    let err = lower(&prog).expect_err("out-of-range init should be rejected");
    assert!(
        matches!(err, LoweringError::OutOfRange { ref var, value: 5, min: 0, max: 3 } if var == "x"),
        "expected OutOfRange for x with value 5, got: {err}"
    );
}

#[test]
fn lower_ranged_int_variable_invalid_range() {
    let src = r#"
protocol InvalidRange {
params n, t;
resilience: n > 3*t;
role Worker {
    var x: int in 5..2;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "invalid_range.trs").unwrap();
    let err = lower(&prog).expect_err("inverted range should be rejected");
    assert!(
        matches!(err, LoweringError::InvalidRange(ref var, 5, 2) if var == "x"),
        "expected InvalidRange(x, 5, 2), got: {err}"
    );
}

#[test]
fn lower_with_source_returns_spanned_error() {
    let src = r#"
protocol SpannedErr {
params n, t;
resilience: n > 3*t;
message Echo;
role Process {
    init waiting;
    phase waiting {
        when received >= 1 Echo => {
            goto phase nonexistent;
        }
    }
}
}
"#;
    let prog = parse(src, "spanned.trs").unwrap();
    let err =
        lower_with_source(&prog, src, "spanned.trs").expect_err("should produce spanned error");
    assert!(matches!(err.inner, LoweringError::UnknownPhase(ref name) if name == "nonexistent"));
    assert_eq!(
        err.src.name(),
        "spanned.trs",
        "source name should be preserved"
    );
}

#[test]
fn lower_safety_property_extraction_via_agreement() {
    // Integration test: lower a protocol and check that the agreement
    // property extractor works over the lowered TA.
    let src = r#"
protocol AgreementProp {
params n, t;
resilience: n > 3*t;
enum Decision { val_a, val_b };
message Vote;
role Voter {
    var decided: bool = false;
    var decision: Decision = val_a;
    init waiting;
    phase waiting {
        when received >= 2*t+1 Vote => {
            decided = true;
            decision = val_a;
            goto phase done_a;
        }
        when received >= 1 Vote => {
            decided = true;
            decision = val_b;
            goto phase done_b;
        }
    }
    phase done_a {}
    phase done_b {}
}
}
"#;
    let prog = parse(src, "agreement_prop.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let prop = crate::properties::extract_agreement_property(&ta);
    match prop {
        crate::properties::SafetyProperty::Agreement { conflicting_pairs } => {
            // decided=true locations in done_a vs done_b are conflicting
            assert!(
                !conflicting_pairs.is_empty(),
                "agreement property should find cross-phase conflicting pairs"
            );
            for (l, r) in &conflicting_pairs {
                let lp = &ta.locations[l.as_usize()].phase;
                let rp = &ta.locations[r.as_usize()].phase;
                assert_ne!(lp, rp, "conflicting pairs must be in different phases");
            }
        }
        other => panic!("expected Agreement property, got: {other:?}"),
    }
}

#[test]
fn lower_termination_property_extraction() {
    // Integration test: lower a protocol and construct a Termination property.
    let src = r#"
protocol TerminationProp {
params n, t;
resilience: n > 3*t;
message Echo;
role Process {
    var decided: bool = false;
    init waiting;
    phase waiting {
        when received >= 2*t+1 Echo => {
            decided = true;
            send Echo;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "termination_prop.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // Identify "done" locations as liveness goals
    let goal_locs: Vec<LocationId> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.phase == "done")
        .map(|(id, _)| LocationId::from(id))
        .collect();
    assert!(
        !goal_locs.is_empty(),
        "should have goal locations in done phase"
    );
    let prop = crate::properties::SafetyProperty::Termination {
        goal_locs: goal_locs.clone(),
    };
    match prop {
        crate::properties::SafetyProperty::Termination {
            goal_locs: extracted,
        } => {
            assert_eq!(extracted, goal_locs);
        }
        other => panic!("expected Termination property, got: {other:?}"),
    }
}

#[test]
fn lower_crypto_object_appears_in_ta_crypto_objects() {
    let src = r#"
protocol CryptoObjIR {
params n, t;
resilience: n > 3*t;
message Vote(view: nat in 0..1);
certificate QC from Vote threshold 2*t+1 signer Replica;
role Replica {
    var view: nat in 0..1 = 0;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "crypto_obj_ir.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert!(ta.security.crypto_objects.contains_key("QC"));
    let qc = &ta.security.crypto_objects["QC"];
    assert_eq!(qc.source_message, "Vote");
    assert_eq!(qc.signer_role.as_deref(), Some("Replica"));
    assert!(matches!(qc.kind, IrCryptoObjectKind::QuorumCertificate));
    assert_eq!(qc.conflict_policy, CryptoConflictPolicy::Allow);
}

#[test]
fn lower_multiple_roles_create_distinct_locations() {
    let src = r#"
protocol MultiRole {
params n, t;
resilience: n > 3*t;
message M;
role Leader {
    init start;
    phase start {}
}
role Replica {
    init waiting;
    phase waiting {}
    phase done {}
}
}
"#;
    let prog = parse(src, "multi_role.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // Leader has 1 phase, Replica has 2 => 3 total
    assert_eq!(ta.locations.len(), 3);
    let leader_locs: Vec<_> = ta.role_locations("Leader");
    let replica_locs: Vec<_> = ta.role_locations("Replica");
    assert_eq!(leader_locs.len(), 1);
    assert_eq!(replica_locs.len(), 2);
    // Initial locations: one from Leader, one from Replica
    assert_eq!(ta.initial_locations.len(), 2);
}

#[test]
fn lower_ranged_int_assignment_creates_transitions() {
    let src = r#"
protocol IntAssign {
params n, t;
resilience: n > 3*t;
message M;
role R {
    var counter: int in 0..2 = 0;
    init s;
    phase s {
        when received >= 1 M => {
            counter = counter + 1;
            goto phase s;
        }
    }
}
}
"#;
    let prog = parse(src, "int_assign.trs").unwrap();
    let ta = lower(&prog).unwrap();
    // counter in 0..2 => 3 locations
    assert_eq!(ta.locations.len(), 3);
    // counter=0 -> counter=1 and counter=1 -> counter=2 should exist
    // counter=2 -> counter=3 is out of range, so no rule from counter=2
    assert_eq!(ta.rules.len(), 2);
    for rule in &ta.rules {
        let from_val = match ta.locations[rule.from.as_usize()].local_vars.get("counter") {
            Some(LocalValue::Int(v)) => *v,
            _ => panic!("expected int counter"),
        };
        let to_val = match ta.locations[rule.to.as_usize()].local_vars.get("counter") {
            Some(LocalValue::Int(v)) => *v,
            _ => panic!("expected int counter"),
        };
        assert_eq!(to_val, from_val + 1, "transition should increment counter");
    }
}

#[test]
fn lower_ta_validation_succeeds() {
    // Ensure the lowered TA passes its own internal validation
    let src = r#"
protocol ValidationTest {
parameters { n: nat; t: nat; f: nat; }
resilience { n > 3*t; }
adversary { model: byzantine; bound: f; }
message Echo;
role Process {
    var decided: bool = false;
    init waiting;
    phase waiting {
        when received >= 2*t+1 Echo => {
            decided = true;
            send Echo;
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "validation_test.trs").unwrap();
    let ta = lower(&prog).unwrap();
    ta.validate()
        .expect("lowered TA should pass internal validation");
}

#[test]
fn lower_guard_threshold_bound_references_correct_params() {
    let src = r#"
protocol GuardParamRef {
parameters { n: nat; t: nat; }
resilience { n > 3*t; }
message Echo;
role Process {
    init waiting;
    phase waiting {
        when received >= 2*t+1 Echo => {
            goto phase done;
        }
    }
    phase done {}
}
}
"#;
    let prog = parse(src, "guard_param_ref.trs").unwrap();
    let ta = lower(&prog).unwrap();
    let rule = &ta.rules[0];
    let atom = &rule.guard.atoms[0];
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            assert_eq!(vars.len(), 1, "should reference one counter variable");
            assert_eq!(*op, CmpOp::Ge);
            assert!(!distinct);
            // bound should be 2*t + 1
            let t_id = ta.find_param_by_name("t").unwrap();
            assert_eq!(bound.constant, 1, "bound constant should be 1");
            assert_eq!(bound.terms.len(), 1, "bound should have one param term");
            assert_eq!(bound.terms[0].0, 2, "coefficient of t should be 2");
            assert_eq!(bound.terms[0].1, t_id, "should reference param t");
        }
    }
}

#[test]
fn lower_rejects_reserved_variable_prefix() {
    let src = r#"
protocol ReservedVar {
params n, t;
resilience: n > 3*t;
role R {
    var __internal: bool = false;
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "reserved_var.trs").unwrap();
    let err = lower(&prog).expect_err("__ prefix variable should be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("reserved") && msg.contains("__internal"),
        "unexpected error: {msg}"
    );
}

#[test]
fn lower_no_adversary_bound_param_by_default() {
    let src = r#"
protocol NoAdvBound {
params n, t;
resilience: n > 3*t;
message M;
role R {
    init s;
    phase s {}
}
}
"#;
    let prog = parse(src, "no_adv_bound.trs").unwrap();
    let ta = lower(&prog).unwrap();
    assert!(
        ta.constraints.adversary_bound_param.is_none(),
        "adversary bound param should be None when not declared"
    );
    assert_eq!(ta.semantics.fault_model, FaultModel::Byzantine); // default
    assert_eq!(ta.semantics.timing_model, TimingModel::Asynchronous); // default
}

#[test]
fn lower_bounded_collection_declarations() {
    let src = r#"
protocol CollTest {
    params n, t;
    resilience: n > 3*t;
    log VoteHistory: int[n];
    sequence Decisions: bool[10];
    message Vote;
    role Voter {
        init Idle;
        phase Idle {}
    }
    property safe: safety {
        forall p: Voter. p.Idle == 0
    }
}
"#;
    let prog = parse(src, "coll_test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(ta.collections.len(), 2);

    let log_coll = &ta.collections[0];
    assert_eq!(log_coll.name, "VoteHistory");
    assert_eq!(log_coll.kind, IrCollectionKind::Log);
    assert_eq!(log_coll.element_type, "int");

    let seq_coll = &ta.collections[1];
    assert_eq!(seq_coll.name, "Decisions");
    assert_eq!(seq_coll.kind, IrCollectionKind::Sequence);
    assert_eq!(seq_coll.element_type, "bool");
}

#[test]
fn lower_append_action_produces_collection_update() {
    let src = r#"
protocol AppendTest {
    params n, t;
    resilience: n > 3*t;
    log Votes: int[n];
    message Vote;
    role Voter {
        init Idle;
        phase Idle {
            when received >= t+1 Vote => {
                append Votes 1;
                goto phase Done;
            }
        }
        phase Done {}
    }
    property safe: safety {
        forall p: Voter. p.Done == 0
    }
}
"#;
    let prog = parse(src, "append_test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let rules_with_updates: Vec<_> = ta
        .rules
        .iter()
        .filter(|r| !r.collection_updates.is_empty())
        .collect();
    assert!(
        !rules_with_updates.is_empty(),
        "Expected at least one rule with collection updates from append action"
    );

    let cu = &rules_with_updates[0].collection_updates[0];
    assert_eq!(cu.collection, CollectionId::new(0));
    match &cu.kind {
        CollectionUpdateKind::Append(lc) => {
            assert_eq!(lc.constant, 1);
            assert!(lc.terms.is_empty(), "Expected constant-only linear combination");
        }
        other => panic!("Expected Append, got {:?}", other),
    }
}

#[test]
fn lower_collection_pipeline_end_to_end() {
    let src = r#"
protocol CollPipeline {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    log VoteLog: int[n];
    sequence DecBuf: bool[10];
    message Vote;
    role Voter {
        init Listening;
        phase Listening {
            when received >= 2*t+1 Vote => {
                append VoteLog 1;
                goto phase Done;
            }
        }
        phase Done {}
    }
    property safe: safety {
        forall p: Voter. forall q: Voter.
            p.Done == 0 || q.Done == 0
    }
}
"#;
    let prog = parse(src, "coll_pipeline.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // Verify collections lowered correctly
    assert_eq!(ta.collections.len(), 2, "Expected 2 collections (log + sequence)");
    assert_eq!(ta.collections[0].name, "VoteLog");
    assert_eq!(ta.collections[0].kind, IrCollectionKind::Log);
    assert_eq!(ta.collections[1].name, "DecBuf");
    assert_eq!(ta.collections[1].kind, IrCollectionKind::Sequence);

    // Verify at least one rule has an append collection update
    let append_rules: Vec<_> = ta
        .rules
        .iter()
        .filter(|r| {
            r.collection_updates
                .iter()
                .any(|cu| matches!(cu.kind, CollectionUpdateKind::Append(_)))
        })
        .collect();
    assert!(
        !append_rules.is_empty(),
        "Expected at least one rule with Append collection update"
    );

    // Verify the ThresholdAutomaton validates
    ta.validate().unwrap();
}

#[test]
fn lower_append_with_param_value() {
    let src = r#"
protocol ParamAppend {
    params n, t;
    resilience: n > 3*t;
    log Buf: int[n];
    message M;
    role R {
        init S;
        phase S {
            when received >= t+1 M => {
                append Buf t;
                goto phase Done;
            }
        }
        phase Done {}
    }
    property safe: safety {
        forall p: R. p.Done == 0
    }
}
"#;
    let prog = parse(src, "param_append.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let rules_with_updates: Vec<_> = ta
        .rules
        .iter()
        .filter(|r| !r.collection_updates.is_empty())
        .collect();
    assert!(!rules_with_updates.is_empty());

    let cu = &rules_with_updates[0].collection_updates[0];
    match &cu.kind {
        CollectionUpdateKind::Append(lc) => {
            assert_eq!(lc.constant, 0);
            assert_eq!(lc.terms.len(), 1, "Expected one parameter term for 't'");
        }
        other => panic!("Expected Append, got {:?}", other),
    }
}

#[test]
fn lower_unknown_collection_in_append_returns_error() {
    let src = r#"
protocol BadAppend {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        init S;
        phase S {
            when received >= t+1 M => {
                append NonExistent 1;
                goto phase Done;
            }
        }
        phase Done {}
    }
    property safe: safety {
        forall p: R. p.Done == 0
    }
}
"#;
    let prog = parse(src, "bad_append.trs").unwrap();
    let result = lower(&prog);
    assert!(result.is_err(), "Appending to nonexistent collection should fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("NonExistent"),
        "Error should mention the unknown collection name"
    );
}

#[test]
fn lower_fifo_channel_declaration() {
    let src = r#"
protocol FifoTest {
    params n, t;
    resilience: n > 3*t;
    fifo_channel MsgQueue: int[n];
    message Vote;
    role Voter {
        init Idle;
        phase Idle {}
    }
    property safe: safety {
        forall p: Voter. p.Idle == 0
    }
}
"#;
    let prog = parse(src, "fifo_test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(ta.collections.len(), 1);
    let coll = &ta.collections[0];
    assert_eq!(coll.name, "MsgQueue");
    assert_eq!(coll.kind, IrCollectionKind::FifoChannel);
    assert_eq!(coll.element_type, "int");
    assert_eq!(coll.queue_model, QueueModel::LinearFifo);
}

#[test]
fn lower_log_and_sequence_have_no_queue_model() {
    let src = r#"
protocol CollTest {
    params n, t;
    resilience: n > 3*t;
    log VoteHistory: int[n];
    sequence Decisions: bool[10];
    message Vote;
    role Voter {
        init Idle;
        phase Idle {}
    }
    property safe: safety {
        forall p: Voter. p.Idle == 0
    }
}
"#;
    let prog = parse(src, "coll_test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(ta.collections.len(), 2);
    assert_eq!(ta.collections[0].queue_model, QueueModel::None);
    assert_eq!(ta.collections[1].queue_model, QueueModel::None);
}

#[test]
fn collection_update_enqueue_dequeue_display() {
    let enq = CollectionUpdate {
        collection: CollectionId::new(0),
        kind: CollectionUpdateKind::Enqueue(LinearCombination::constant(42)),
    };
    assert_eq!(format!("{enq}"), "c0.enqueue(42)");

    let deq = CollectionUpdate {
        collection: CollectionId::new(1),
        kind: CollectionUpdateKind::Dequeue,
    };
    assert_eq!(format!("{deq}"), "c1.dequeue()");
}

#[test]
fn lower_enqueue_dequeue_actions() {
    let src = r#"
protocol QueueTest {
    params n, t;
    resilience: n > 3*t;
    fifo_channel MsgQueue: int[n];
    message Request;
    role Worker {
        init Waiting;
        phase Waiting {
            when received >= 1 Request => {
                enqueue MsgQueue 1;
                dequeue MsgQueue;
                goto phase Waiting;
            }
        }
    }
    property safe: safety {
        forall p: Worker. p.Waiting == 0
    }
}
"#;
    let prog = parse(src, "queue_test.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // Find a rule with collection updates
    let rules_with_updates: Vec<_> = ta
        .rules
        .iter()
        .filter(|r| !r.collection_updates.is_empty())
        .collect();
    assert!(
        !rules_with_updates.is_empty(),
        "Should have rules with collection updates"
    );

    let updates = &rules_with_updates[0].collection_updates;
    assert_eq!(updates.len(), 2);
    assert!(matches!(updates[0].kind, CollectionUpdateKind::Enqueue(_)));
    assert!(matches!(updates[1].kind, CollectionUpdateKind::Dequeue));
}

#[test]
fn fifo_channel_end_to_end_pipeline() {
    // Full pipeline: parse → lower → verify IR structure
    let src = r#"
protocol FifoE2E {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    fifo_channel MsgQueue: int[n];
    message Request;
    role Producer {
        init Idle;
        phase Idle {
            when received >= 1 Request => {
                enqueue MsgQueue 1;
                goto phase Idle;
            }
        }
    }
    role Consumer {
        init Waiting;
        phase Waiting {
            when received >= 1 Request => {
                dequeue MsgQueue;
                goto phase Waiting;
            }
        }
    }
    property safe: safety {
        forall p: Producer. forall q: Consumer.
            p.Idle == 0 || q.Waiting == 0
    }
}
"#;
    let prog = parse(src, "fifo_e2e.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // Verify collection
    assert_eq!(ta.collections.len(), 1);
    let coll = &ta.collections[0];
    assert_eq!(coll.name, "MsgQueue");
    assert_eq!(coll.kind, IrCollectionKind::FifoChannel);
    assert_eq!(coll.queue_model, QueueModel::LinearFifo);

    // Verify enqueue rules exist
    let enqueue_rules: Vec<_> = ta.rules.iter()
        .filter(|r| r.collection_updates.iter()
            .any(|cu| matches!(cu.kind, CollectionUpdateKind::Enqueue(_))))
        .collect();
    assert!(!enqueue_rules.is_empty(), "Should have enqueue rules");

    // Verify dequeue rules exist
    let dequeue_rules: Vec<_> = ta.rules.iter()
        .filter(|r| r.collection_updates.iter()
            .any(|cu| matches!(cu.kind, CollectionUpdateKind::Dequeue)))
        .collect();
    assert!(!dequeue_rules.is_empty(), "Should have dequeue rules");
}

#[test]
fn fifo_channel_mixed_with_log_and_sequence() {
    let src = r#"
protocol MixedCollections {
    params n, t;
    resilience: n > 3*t;
    log History: int[n];
    sequence Buffer: int[10];
    fifo_channel Queue: int[n];
    message Vote;
    role Voter {
        init Idle;
        phase Idle {
            when received >= 1 Vote => {
                append History 1;
                enqueue Queue 1;
                goto phase Idle;
            }
        }
    }
    property safe: safety {
        forall p: Voter. p.Idle == 0
    }
}
"#;
    let prog = parse(src, "mixed_coll.trs").unwrap();
    let ta = lower(&prog).unwrap();

    assert_eq!(ta.collections.len(), 3);
    assert_eq!(ta.collections[0].kind, IrCollectionKind::Log);
    assert_eq!(ta.collections[0].queue_model, QueueModel::None);
    assert_eq!(ta.collections[1].kind, IrCollectionKind::Sequence);
    assert_eq!(ta.collections[1].queue_model, QueueModel::None);
    assert_eq!(ta.collections[2].kind, IrCollectionKind::FifoChannel);
    assert_eq!(ta.collections[2].queue_model, QueueModel::LinearFifo);
}

// ---------------------------------------------------------------------------
// RECONF-03: reconfigure action lowering
// ---------------------------------------------------------------------------

#[test]
fn lower_reconfigure_constant_updates() {
    let src = r#"
protocol Reconfig {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role Replica {
        init waiting;
        phase waiting {
            when received >= 1 Vote => {
                reconfigure {
                    n = 10;
                    t = 3;
                }
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let prog = parse(src, "reconfig.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // At least one rule should have param_updates
    let reconf_rules: Vec<_> = ta.rules.iter().filter(|r| !r.param_updates.is_empty()).collect();
    assert!(!reconf_rules.is_empty(), "should have rules with param_updates");

    let rule = &reconf_rules[0];
    assert_eq!(rule.param_updates.len(), 2);

    // n = 10
    let n_id = ta.find_param_by_name("n").unwrap();
    let t_id = ta.find_param_by_name("t").unwrap();
    assert_eq!(rule.param_updates[0].param, n_id);
    assert_eq!(rule.param_updates[0].value.constant, 10);
    assert!(rule.param_updates[0].value.terms.is_empty());

    // t = 3
    assert_eq!(rule.param_updates[1].param, t_id);
    assert_eq!(rule.param_updates[1].value.constant, 3);
    assert!(rule.param_updates[1].value.terms.is_empty());

    // Targeted params should be marked time-varying
    assert!(ta.parameters[n_id.as_usize()].time_varying);
    assert!(ta.parameters[t_id.as_usize()].time_varying);
}

#[test]
fn lower_reconfigure_param_expression() {
    let src = r#"
protocol Reconfig {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role Replica {
        init waiting;
        phase waiting {
            when received >= 1 Vote => {
                reconfigure {
                    t = n - 1;
                }
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let prog = parse(src, "reconfig_expr.trs").unwrap();
    let ta = lower(&prog).unwrap();

    let reconf_rules: Vec<_> = ta.rules.iter().filter(|r| !r.param_updates.is_empty()).collect();
    assert!(!reconf_rules.is_empty());

    let rule = &reconf_rules[0];
    assert_eq!(rule.param_updates.len(), 1);

    let t_id = ta.find_param_by_name("t").unwrap();
    let n_id = ta.find_param_by_name("n").unwrap();
    assert_eq!(rule.param_updates[0].param, t_id);
    // value should be n - 1
    assert_eq!(rule.param_updates[0].value.constant, -1);
    assert_eq!(rule.param_updates[0].value.terms, vec![(1, n_id)]);

    // Only t should be time-varying (target), n should remain fixed
    assert!(ta.parameters[t_id.as_usize()].time_varying);
    assert!(!ta.parameters[n_id.as_usize()].time_varying);
}

#[test]
fn lower_reconfigure_empty_is_noop() {
    let src = r#"
protocol Reconfig {
    parameters { n: nat; }
    resilience { n > 1; }
    message Vote;
    role Replica {
        init waiting;
        phase waiting {
            when received >= 1 Vote => {
                reconfigure {}
                goto phase waiting;
            }
        }
    }
    property safe: safety { true == true }
}
"#;
    let prog = parse(src, "reconfig_empty.trs").unwrap();
    let ta = lower(&prog).unwrap();

    // No rule should have param_updates
    assert!(ta.rules.iter().all(|r| r.param_updates.is_empty()));
    // No params should be time-varying
    assert!(ta.parameters.iter().all(|p| !p.time_varying));
}

#[test]
fn lower_reconfigure_unknown_param_errors() {
    let src = r#"
protocol Reconfig {
    parameters { n: nat; }
    resilience { n > 1; }
    message Vote;
    role Replica {
        init waiting;
        phase waiting {
            when received >= 1 Vote => {
                reconfigure {
                    unknown_param = 5;
                }
                goto phase done;
            }
        }
        phase done {}
    }
    property safe: safety { true == true }
}
"#;
    let prog = parse(src, "reconfig_bad.trs").unwrap();
    let err = lower(&prog).unwrap_err();
    assert!(
        format!("{err:?}").contains("unknown_param"),
        "error should mention unknown param, got: {err:?}"
    );
}
