use tarsier_ir::counter_system::{Configuration, MessageDeliveryEvent, Trace};
use tarsier_ir::threshold_automaton::{
    LinearCombination, SharedVarKind, ThresholdAutomaton, UpdateKind,
};

fn mermaid_escape(input: &str) -> String {
    input.replace('\n', " ").replace('"', "'")
}

fn participant_id(role: &str, index: usize) -> String {
    let mut out = String::with_capacity(role.len() + 8);
    out.push('R');
    out.push_str(&(index + 1).to_string());
    out.push('_');
    for ch in role.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

pub fn config_snapshot(config: &Configuration, ta: &ThresholdAutomaton) -> String {
    let mut out = String::new();

    let occupied: Vec<String> = config
        .kappa
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(idx, count)| {
            format!(
                "{} ({}:{})={}",
                ta.locations[idx].name, ta.locations[idx].role, ta.locations[idx].phase, count
            )
        })
        .collect();
    if occupied.is_empty() {
        out.push_str("  Occupied locations: (none)\n");
    } else {
        out.push_str("  Occupied locations:\n");
        for line in occupied {
            out.push_str(&format!("    - {line}\n"));
        }
    }

    let shared: Vec<String> = config
        .gamma
        .iter()
        .enumerate()
        .filter(|(_, val)| **val > 0)
        .map(|(idx, val)| format!("{}={}", ta.shared_vars[idx].name, val))
        .collect();
    if shared.is_empty() {
        out.push_str("  Shared/message counters: (all zero)\n");
    } else {
        out.push_str("  Shared/message counters:\n");
        for line in shared {
            out.push_str(&format!("    - {line}\n"));
        }
    }

    out
}

fn identity_label(role: &str, process: Option<&str>) -> String {
    if let Some(pid) = process {
        format!("{role}#{pid}")
    } else {
        role.to_string()
    }
}

fn payload_fields_label(fields: &[(String, String)]) -> String {
    if fields.is_empty() {
        "(none)".into()
    } else {
        fields
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn eval_linear_combination(lc: &LinearCombination, params: &[i64]) -> i64 {
    let mut value = lc.constant;
    for (coeff, pid) in &lc.terms {
        value += coeff * params.get(*pid).copied().unwrap_or(0);
    }
    value
}

fn parse_counter_metadata(
    counter_name: &str,
) -> Option<(String, String, Option<String>, Vec<(String, String)>)> {
    let stripped = counter_name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped
        .split_once('@')
        .map(|(f, r)| (f, r))
        .unwrap_or((stripped, "*"));
    let channel = recipient_part
        .split_once('[')
        .map(|(recipient, _)| recipient)
        .unwrap_or(recipient_part);
    let (recipient_channel, sender_channel) = channel
        .split_once("<-")
        .map(|(recipient, sender)| (recipient.to_string(), Some(sender.to_string())))
        .unwrap_or_else(|| (channel.to_string(), None));
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    let fields: Vec<(String, String)> = stripped
        .split_once('[')
        .and_then(|(_, rest)| rest.strip_suffix(']'))
        .map(|field_blob| {
            field_blob
                .split(',')
                .filter_map(|entry| {
                    let (k, v) = entry.split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Some((family, recipient_channel, sender_channel, fields))
}

fn sender_role_from_channel(sender_channel: Option<&str>) -> Option<&str> {
    sender_channel.map(|sender| {
        sender
            .split_once('#')
            .map(|(role, _)| role)
            .unwrap_or(sender)
    })
}

fn render_crypto_provenance(
    out: &mut String,
    ta: &ThresholdAutomaton,
    pre_config: &Configuration,
    delivery: &MessageDeliveryEvent,
) {
    let Some(spec) = ta.crypto_objects.get(&delivery.payload.family) else {
        return;
    };
    let recipient_channel = delivery
        .recipient
        .process
        .as_ref()
        .map(|pid| format!("{}#{pid}", delivery.recipient.role))
        .unwrap_or_else(|| delivery.recipient.role.clone());
    let mut witness_vars = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient, sender_channel, fields)) =
            parse_counter_metadata(&shared.name)
        else {
            continue;
        };
        if family != spec.source_message || recipient != recipient_channel {
            continue;
        }
        if fields != delivery.payload.fields {
            continue;
        }
        if let Some(expected_role) = spec.signer_role.as_deref() {
            if sender_role_from_channel(sender_channel.as_deref()) != Some(expected_role) {
                continue;
            }
        }
        witness_vars.push(var_id);
    }
    let observed_distinct = witness_vars
        .iter()
        .filter(|var_id| pre_config.gamma.get(**var_id).copied().unwrap_or(0) > 0)
        .count() as i64;
    let required = eval_linear_combination(&spec.threshold, &pre_config.params);

    out.push_str(&format!("      crypto.kind: {}\n", spec.kind));
    out.push_str(&format!("      crypto.source: {}\n", spec.source_message));
    out.push_str(&format!(
        "      crypto.signer_role: {}\n",
        optional_str(spec.signer_role.as_deref())
    ));
    out.push_str(&format!(
        "      crypto.conflicts: {}\n",
        spec.conflict_policy
    ));
    out.push_str(&format!(
        "      crypto.threshold: {} (observed_distinct_support={observed_distinct}, required={required})\n",
        spec.threshold
    ));
}

fn render_delivery_details(
    out: &mut String,
    ta: &ThresholdAutomaton,
    pre_config: &Configuration,
    delivery: &MessageDeliveryEvent,
) {
    let sender = identity_label(&delivery.sender.role, delivery.sender.process.as_deref());
    let recipient = identity_label(
        &delivery.recipient.role,
        delivery.recipient.process.as_deref(),
    );
    out.push_str(&format!("    - kind: {:?}\n", delivery.kind));
    out.push_str(&format!("      sender: {sender}\n"));
    out.push_str(&format!(
        "      sender.key: {}\n",
        optional_str(delivery.sender.key.as_deref())
    ));
    out.push_str(&format!("      recipient: {recipient}\n"));
    out.push_str(&format!(
        "      recipient.key: {}\n",
        optional_str(delivery.recipient.key.as_deref())
    ));
    out.push_str(&format!(
        "      value.family: {}\n",
        delivery.payload.family
    ));
    out.push_str(&format!(
        "      value.fields: {}\n",
        payload_fields_label(&delivery.payload.fields)
    ));
    out.push_str(&format!(
        "      value.variant: {}\n",
        delivery.payload.variant
    ));
    out.push_str(&format!("      count: {}\n", delivery.count));
    out.push_str(&format!(
        "      auth.channel: {}\n",
        if delivery.auth.authenticated_channel {
            "authenticated"
        } else {
            "unauthenticated"
        }
    ));
    out.push_str(&format!(
        "      auth.signature_key: {}\n",
        optional_str(delivery.auth.signature_key.as_deref())
    ));
    out.push_str(&format!(
        "      auth.key_owner: {}\n",
        optional_str(delivery.auth.key_owner_role.as_deref())
    ));
    out.push_str(&format!(
        "      auth.key_compromised: {}\n",
        delivery.auth.key_compromised
    ));
    out.push_str(&format!(
        "      auth.provenance: {:?}\n",
        delivery.auth.provenance
    ));
    render_crypto_provenance(out, ta, pre_config, delivery);
}

/// Render a human-readable counterexample timeline.
pub fn render_trace_timeline(
    trace: &Trace,
    ta: &ThresholdAutomaton,
    loop_start: Option<usize>,
) -> String {
    let mut out = String::new();
    out.push_str("COUNTEREXAMPLE TIMELINE\n");
    if let Some(ls) = loop_start {
        out.push_str(&format!("Lasso loop start (solver depth index): {ls}\n"));
    }
    if trace.param_values.is_empty() {
        out.push_str("Parameters: (none)\n");
    } else {
        out.push_str("Parameters:\n");
        for (name, value) in &trace.param_values {
            out.push_str(&format!("  - {name} = {value}\n"));
        }
    }

    out.push_str("\nStep 0 (initial)\n");
    out.push_str(&config_snapshot(&trace.initial_config, ta));

    for (i, step) in trace.steps.iter().enumerate() {
        let rule = &ta.rules[step.rule_id];
        let from = &ta.locations[rule.from];
        let to = &ta.locations[rule.to];
        let pre_config = if i == 0 {
            &trace.initial_config
        } else {
            &trace.steps[i - 1].config
        };

        out.push_str(&format!("\nStep {} (event)\n", i + 1));
        out.push_str(&format!("  Rule: r{} x{}\n", step.rule_id, step.delta));
        out.push_str(&format!(
            "  Move: {} ({}:{}) -> {} ({}:{})\n",
            from.name, from.role, from.phase, to.name, to.role, to.phase
        ));
        out.push_str(&format!("  Guard: {}\n", rule.guard));
        if rule.updates.is_empty() {
            out.push_str("  Updates: (none)\n");
        } else {
            out.push_str("  Updates:\n");
            for update in &rule.updates {
                let var = &ta.shared_vars[update.var].name;
                match &update.kind {
                    UpdateKind::Increment => {
                        out.push_str(&format!("    - {var} += {}\n", step.delta));
                    }
                    UpdateKind::Set(lc) => {
                        out.push_str(&format!("    - {var} := {lc}\n"));
                    }
                }
            }
        }
        if step.deliveries.is_empty() {
            out.push_str("  Deliveries: (none)\n");
        } else {
            out.push_str("  Deliveries:\n");
            for delivery in &step.deliveries {
                render_delivery_details(&mut out, ta, pre_config, delivery);
            }
        }
        out.push_str(&config_snapshot(&step.config, ta));
    }

    out
}

/// Render a Mermaid sequence diagram approximation of the counterexample trace.
pub fn render_trace_mermaid(
    trace: &Trace,
    ta: &ThresholdAutomaton,
    loop_start: Option<usize>,
) -> String {
    let mut roles: Vec<String> = Vec::new();
    for loc in &ta.locations {
        if !roles.iter().any(|role| role == &loc.role) {
            roles.push(loc.role.clone());
        }
    }
    for step in &trace.steps {
        for delivery in &step.deliveries {
            if !roles.iter().any(|role| role == &delivery.sender.role) {
                roles.push(delivery.sender.role.clone());
            }
            if !roles.iter().any(|role| role == &delivery.recipient.role) {
                roles.push(delivery.recipient.role.clone());
            }
        }
    }
    if roles.is_empty() {
        roles.push("Process".to_string());
    }

    let participants: Vec<(String, String)> = roles
        .iter()
        .enumerate()
        .map(|(idx, role)| (role.clone(), participant_id(role, idx)))
        .collect();

    let first_participant = participants
        .first()
        .map(|(_, id)| id.as_str())
        .unwrap_or("R1_Process");

    let mut out = String::new();
    out.push_str("sequenceDiagram\n");
    out.push_str("    autonumber\n");
    for (role, id) in &participants {
        out.push_str(&format!(
            "    participant {} as {}\n",
            id,
            mermaid_escape(role)
        ));
    }
    if let Some(ls) = loop_start {
        out.push_str(&format!(
            "    Note over {}: lasso loop start (solver depth index) = {}\n",
            first_participant, ls
        ));
    }
    if trace.steps.is_empty() {
        out.push_str(&format!(
            "    Note over {}: no transition events were extracted\n",
            first_participant
        ));
        return out;
    }

    for (idx, step) in trace.steps.iter().enumerate() {
        let rule = &ta.rules[step.rule_id];
        let from = &ta.locations[rule.from];
        let to = &ta.locations[rule.to];
        let from_id = participants
            .iter()
            .find(|(role, _)| role == &from.role)
            .map(|(_, id)| id.as_str())
            .unwrap_or(first_participant);
        let to_id = participants
            .iter()
            .find(|(role, _)| role == &to.role)
            .map(|(_, id)| id.as_str())
            .unwrap_or(first_participant);

        if loop_start == Some(idx + 1) {
            out.push_str(&format!(
                "    Note over {}: lasso loop entry begins here\n",
                from_id
            ));
        }

        let label = format!(
            "r{} x{}: {} -> {}",
            step.rule_id,
            step.delta,
            mermaid_escape(&from.phase),
            mermaid_escape(&to.phase)
        );
        out.push_str(&format!("    {}->>{}: {}\n", from_id, to_id, label));

        for update in &rule.updates {
            let var_name = &ta.shared_vars[update.var].name;
            match &update.kind {
                UpdateKind::Increment => out.push_str(&format!(
                    "    Note over {}: {} += {}\n",
                    to_id,
                    mermaid_escape(var_name),
                    step.delta
                )),
                UpdateKind::Set(lc) => out.push_str(&format!(
                    "    Note over {}: {} := {}\n",
                    to_id,
                    mermaid_escape(var_name),
                    mermaid_escape(&lc.to_string())
                )),
            }
        }
        for delivery in &step.deliveries {
            let sender_id = participants
                .iter()
                .find(|(role, _)| role == &delivery.sender.role)
                .map(|(_, id)| id.as_str())
                .unwrap_or(first_participant);
            let recipient_id = participants
                .iter()
                .find(|(role, _)| role == &delivery.recipient.role)
                .map(|(_, id)| id.as_str())
                .unwrap_or(first_participant);
            let sender_label =
                identity_label(&delivery.sender.role, delivery.sender.process.as_deref());
            let recipient_label = identity_label(
                &delivery.recipient.role,
                delivery.recipient.process.as_deref(),
            );
            let label = format!(
                "{:?} {} -> {} {} [{}] x{} auth={} prov={:?}",
                delivery.kind,
                mermaid_escape(&sender_label),
                mermaid_escape(&recipient_label),
                mermaid_escape(&delivery.payload.family),
                mermaid_escape(&payload_fields_label(&delivery.payload.fields)),
                delivery.count,
                if delivery.auth.authenticated_channel {
                    "signed"
                } else {
                    "none"
                },
                delivery.auth.provenance
            );
            out.push_str(&format!(
                "    {}-->>{}: {}\n",
                sender_id, recipient_id, label
            ));
            let auth_note = format!(
                "sender_key={} recipient_key={} sig_key={} owner={} compromised={}",
                mermaid_escape(optional_str(delivery.sender.key.as_deref())),
                mermaid_escape(optional_str(delivery.recipient.key.as_deref())),
                mermaid_escape(optional_str(delivery.auth.signature_key.as_deref())),
                mermaid_escape(optional_str(delivery.auth.key_owner_role.as_deref())),
                delivery.auth.key_compromised
            );
            out.push_str(&format!("    Note over {}: {}\n", recipient_id, auth_note));
        }
    }

    out
}

/// Render a Markdown report with timeline + Mermaid MSC.
pub fn render_trace_markdown(
    title: &str,
    trace: &Trace,
    ta: &ThresholdAutomaton,
    loop_start: Option<usize>,
) -> String {
    let timeline = render_trace_timeline(trace, ta, loop_start);
    let mermaid = render_trace_mermaid(trace, ta, loop_start);
    format!(
        "# {}\n\n## Timeline\n```text\n{}\n```\n\n## Message Sequence Chart\n```mermaid\n{}\n```\n",
        title,
        timeline.trim_end(),
        mermaid.trim_end(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::{
        Configuration, MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind,
        MessageIdentity, MessagePayloadVariant, SignatureProvenance, TraceStep,
    };
    use tarsier_ir::threshold_automaton::{
        CmpOp, Guard, GuardAtom, LinearCombination, Location, Parameter, Rule, SharedVar,
        SharedVarKind, ThresholdAutomaton, Update,
    };

    fn sample_ta_and_trace() -> (ThresholdAutomaton, Trace) {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_shared_var(SharedVar {
            name: "cnt_Prepare".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_location(Location {
            name: "replica.pre".into(),
            role: "Replica".into(),
            phase: "pre".into(),
            local_vars: Default::default(),
        });
        ta.add_location(Location {
            name: "replica.commit".into(),
            role: "Replica".into(),
            phase: "commit".into(),
            local_vars: Default::default(),
        });
        ta.initial_locations = vec![0];
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });

        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![4, 0],
                gamma: vec![0],
                params: vec![4],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 2,
                deliveries: vec![MessageDeliveryEvent {
                    shared_var: 0,
                    shared_var_name: "cnt_Prepare".into(),
                    sender: MessageIdentity {
                        role: "Replica".into(),
                        process: Some("0".into()),
                        key: Some("replica_key".into()),
                    },
                    recipient: MessageIdentity {
                        role: "Replica".into(),
                        process: Some("1".into()),
                        key: Some("replica_key".into()),
                    },
                    payload: MessagePayloadVariant {
                        family: "Prepare".into(),
                        fields: vec![("view".into(), "1".into()), ("value".into(), "true".into())],
                        variant: "Prepare[view=1,value=true]".into(),
                    },
                    count: 2,
                    kind: MessageEventKind::Send,
                    auth: MessageAuthMetadata {
                        authenticated_channel: true,
                        signature_key: Some("replica_key".into()),
                        key_owner_role: Some("R".into()),
                        key_compromised: false,
                        provenance: SignatureProvenance::OwnedKey,
                    },
                }],
                config: Configuration {
                    kappa: vec![2, 2],
                    gamma: vec![2],
                    params: vec![4],
                },
            }],
            param_values: vec![("n".into(), 4)],
        };
        (ta, trace)
    }

    #[test]
    fn timeline_contains_rule_and_parameters() {
        let (ta, trace) = sample_ta_and_trace();
        let text = render_trace_timeline(&trace, &ta, None);
        assert!(text.contains("n = 4"));
        assert!(text.contains("Rule: r0 x2"));
        assert!(text.contains("cnt_Prepare += 2"));
        assert!(text.contains("sender.key: replica_key"));
        assert!(text.contains("value.fields: view=1, value=true"));
        assert!(text.contains("auth.provenance: OwnedKey"));
    }

    #[test]
    fn mermaid_contains_sequence_events() {
        let (ta, trace) = sample_ta_and_trace();
        let mermaid = render_trace_mermaid(&trace, &ta, Some(1));
        assert!(mermaid.contains("sequenceDiagram"));
        assert!(mermaid.contains("participant"));
        assert!(mermaid.contains("r0 x2"));
        assert!(mermaid.contains("loop"));
        assert!(mermaid.contains("auth=signed"));
        assert!(mermaid.contains("view=1, value=true"));
        assert!(mermaid.contains("sender_key=replica_key"));
    }

    #[test]
    fn markdown_contains_timeline_and_mermaid_blocks() {
        let (ta, trace) = sample_ta_and_trace();
        let md = render_trace_markdown("Trace", &trace, &ta, None);
        assert!(md.contains("## Timeline"));
        assert!(md.contains("```text"));
        assert!(md.contains("## Message Sequence Chart"));
        assert!(md.contains("```mermaid"));
    }
}
