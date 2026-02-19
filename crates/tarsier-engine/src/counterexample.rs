use tarsier_ir::counter_system::{
    Configuration, CounterSystem, MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind,
    MessageIdentity, MessagePayloadVariant, SignatureProvenance, Trace, TraceStep,
};
use tarsier_ir::threshold_automaton::{
    LocalValue, RoleIdentityScope, SharedVarKind, ThresholdAutomaton, UpdateKind,
};
use tarsier_smt::solver::Model;

/// Extract a counterexample trace from a SAT model.
pub fn extract_trace(cs: &CounterSystem, model: &Model, depth: usize) -> Trace {
    let ta = &cs.automaton;
    let num_locs = cs.num_locations();
    let num_svars = cs.num_shared_vars();
    let num_params = cs.num_parameters();
    let num_rules = cs.num_rules();

    // Extract parameter values
    let mut param_values = Vec::new();
    let mut param_vals = Vec::new();
    for i in 0..num_params {
        let val = model.get_int(&format!("p_{i}")).unwrap_or(0);
        param_values.push((ta.parameters[i].name.clone(), val));
        param_vals.push(val);
    }

    // Extract initial configuration
    let initial_config = extract_config(model, 0, num_locs, num_svars, &param_vals);

    // Extract steps
    let mut steps = Vec::new();
    for k in 0..depth {
        let adversary_deliveries = extract_adversary_delivery_events(ta, model, k);
        let drop_events = extract_drop_events(ta, model, k);
        let equivocation_events = extract_equivocation_events(&adversary_deliveries);
        let mut attached_adversary = false;
        // Find which rules fired
        for r in 0..num_rules {
            let delta = model.get_int(&format!("delta_{k}_{r}")).unwrap_or(0);
            if delta > 0 {
                let config = extract_config(model, k + 1, num_locs, num_svars, &param_vals);
                let mut deliveries = extract_rule_delivery_events(ta, r, delta);
                if !attached_adversary {
                    deliveries.extend(adversary_deliveries.clone());
                    deliveries.extend(equivocation_events.clone());
                    deliveries.extend(drop_events.clone());
                    attached_adversary = true;
                }
                steps.push(TraceStep {
                    smt_step: k,
                    rule_id: r,
                    delta,
                    deliveries,
                    config,
                });
            }
        }
    }

    Trace {
        initial_config,
        steps,
        param_values,
    }
}

fn extract_config(
    model: &Model,
    step: usize,
    num_locs: usize,
    num_svars: usize,
    params: &[i64],
) -> Configuration {
    let kappa: Vec<i64> = (0..num_locs)
        .map(|l| model.get_int(&format!("kappa_{step}_{l}")).unwrap_or(0))
        .collect();

    let gamma: Vec<i64> = (0..num_svars)
        .map(|v| model.get_int(&format!("g_{step}_{v}")).unwrap_or(0))
        .collect();

    Configuration {
        kappa,
        gamma,
        params: params.to_vec(),
    }
}

/// Pretty-print a counterexample trace with location names.
pub fn format_trace(trace: &Trace, ta: &ThresholdAutomaton) -> String {
    let mut out = String::new();
    out.push_str("Counterexample trace:\n");
    out.push_str("  Parameters:\n");
    for (name, val) in &trace.param_values {
        out.push_str(&format!("    {name} = {val}\n"));
    }
    out.push_str("  Initial configuration:\n");
    format_config(&mut out, &trace.initial_config, ta);
    for (i, step) in trace.steps.iter().enumerate() {
        let pre_config = if i == 0 {
            &trace.initial_config
        } else {
            &trace.steps[i - 1].config
        };
        let rule = &ta.rules[step.rule_id];
        let from_name = &ta.locations[rule.from].name;
        let to_name = &ta.locations[rule.to].name;
        out.push_str(&format!(
            "  Step {}: rule r{} fires {} time(s): {} -> {}\n",
            i + 1,
            step.rule_id,
            step.delta,
            from_name,
            to_name,
        ));
        if step.deliveries.is_empty() {
            out.push_str("    deliveries: (none)\n");
        } else {
            out.push_str("    deliveries:\n");
            for d in &step.deliveries {
                let sender = format_identity(&d.sender);
                let recipient = format_identity(&d.recipient);
                out.push_str(&format!(
                    "      - {:?}: {} -> {} {} x{} ({:?})\n",
                    d.kind, sender, recipient, d.payload.variant, d.count, d.auth.provenance
                ));
                if let Some(summary) = crypto_summary_for_delivery(ta, pre_config, d) {
                    out.push_str(&format!("        {summary}\n"));
                }
            }
        }
        format_config(&mut out, &step.config, ta);
    }
    out
}

fn format_config(out: &mut String, config: &Configuration, ta: &ThresholdAutomaton) {
    for (l, &count) in config.kappa.iter().enumerate() {
        if count > 0 {
            let name = &ta.locations[l].name;
            out.push_str(&format!("    {name}: {count} process(es)\n"));
        }
    }
    for (v, &val) in config.gamma.iter().enumerate() {
        if val > 0 {
            let name = &ta.shared_vars[v].name;
            out.push_str(&format!("    {name} = {val}\n"));
        }
    }
}

fn format_identity(id: &MessageIdentity) -> String {
    if let Some(pid) = &id.process {
        format!("{}#{pid}", id.role)
    } else {
        id.role.clone()
    }
}

fn eval_linear_combination(
    lc: &tarsier_ir::threshold_automaton::LinearCombination,
    params: &[i64],
) -> i64 {
    let mut value = lc.constant;
    for (coeff, pid) in &lc.terms {
        value += coeff * params.get(*pid).copied().unwrap_or(0);
    }
    value
}

fn sender_role_from_channel(sender_channel: Option<&str>) -> Option<&str> {
    sender_channel.map(|sender| {
        sender
            .split_once('#')
            .map(|(role, _)| role)
            .unwrap_or(sender)
    })
}

fn crypto_summary_for_delivery(
    ta: &ThresholdAutomaton,
    pre_config: &Configuration,
    delivery: &MessageDeliveryEvent,
) -> Option<String> {
    let spec = ta.crypto_objects.get(&delivery.payload.family)?;
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
        let Some((family, recipient, sender_channel, payload)) =
            parse_counter_message_metadata(&shared.name)
        else {
            continue;
        };
        if family != spec.source_message || recipient != recipient_channel {
            continue;
        }
        if payload.fields != delivery.payload.fields {
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
    Some(format!(
        "crypto={} source={} signer={} threshold={} observed_distinct={} required={} conflicts={}",
        spec.kind,
        spec.source_message,
        spec.signer_role.as_deref().unwrap_or("-"),
        spec.threshold,
        observed_distinct,
        required,
        spec.conflict_policy
    ))
}

fn parse_counter_message_metadata(
    counter_name: &str,
) -> Option<(String, String, Option<String>, MessagePayloadVariant)> {
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

    let variant = if fields.is_empty() {
        family.clone()
    } else {
        let rendered = fields
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{family}[{rendered}]")
    };
    let payload = MessagePayloadVariant {
        family: family.clone(),
        fields,
        variant,
    };
    Some((family, recipient_channel, sender_channel, payload))
}

fn identity_from_recipient_channel(
    ta: &ThresholdAutomaton,
    recipient_channel: &str,
) -> MessageIdentity {
    let (role, process) = recipient_channel
        .split_once('#')
        .map(|(r, p)| (r.to_string(), Some(p.to_string())))
        .unwrap_or_else(|| (recipient_channel.to_string(), None));
    let key = ta
        .role_identities
        .get(&role)
        .map(|cfg| cfg.key_name.clone());
    MessageIdentity { role, process, key }
}

fn identity_from_sender_channel(ta: &ThresholdAutomaton, sender_channel: &str) -> MessageIdentity {
    let (role, process) = sender_channel
        .split_once('#')
        .map(|(r, p)| (r.to_string(), Some(p.to_string())))
        .unwrap_or_else(|| (sender_channel.to_string(), None));
    let key = ta
        .role_identities
        .get(&role)
        .map(|cfg| cfg.key_name.clone());
    MessageIdentity { role, process, key }
}

fn identity_from_location(ta: &ThresholdAutomaton, loc_id: usize) -> MessageIdentity {
    let loc = &ta.locations[loc_id];
    let cfg = ta.role_identities.get(&loc.role);
    let process = cfg.and_then(|cfg| {
        if cfg.scope != RoleIdentityScope::Process {
            return None;
        }
        let var = cfg.process_var.as_deref().unwrap_or("pid");
        loc.local_vars.get(var).map(|value| match value {
            LocalValue::Int(n) => n.to_string(),
            LocalValue::Bool(b) => b.to_string(),
            LocalValue::Enum(v) => v.clone(),
        })
    });
    let key = cfg.map(|cfg| cfg.key_name.clone());
    MessageIdentity {
        role: loc.role.clone(),
        process,
        key,
    }
}

fn adversary_identity() -> MessageIdentity {
    MessageIdentity {
        role: "Byzantine".into(),
        process: None,
        key: None,
    }
}

fn network_identity() -> MessageIdentity {
    MessageIdentity {
        role: "Network".into(),
        process: None,
        key: None,
    }
}

fn auth_metadata_for_owned_sender(
    ta: &ThresholdAutomaton,
    sender: &MessageIdentity,
    message_family: &str,
) -> MessageAuthMetadata {
    let authenticated = ta.message_effective_authenticated(message_family);
    if !authenticated {
        return MessageAuthMetadata {
            authenticated_channel: false,
            signature_key: None,
            key_owner_role: None,
            key_compromised: false,
            provenance: SignatureProvenance::UnauthenticatedChannel,
        };
    }

    let signature_key = sender.key.clone();
    let key_owner_role = signature_key
        .as_deref()
        .and_then(|key| ta.key_owner(key))
        .map(str::to_string);
    let key_compromised = signature_key
        .as_deref()
        .map(|key| ta.key_is_compromised(key))
        .unwrap_or(false);
    let provenance = if key_compromised {
        SignatureProvenance::CompromisedKey
    } else {
        SignatureProvenance::OwnedKey
    };

    MessageAuthMetadata {
        authenticated_channel: true,
        signature_key,
        key_owner_role,
        key_compromised,
        provenance,
    }
}

fn auth_metadata_for_forge(ta: &ThresholdAutomaton, message_family: &str) -> MessageAuthMetadata {
    let authenticated = ta.message_effective_authenticated(message_family);
    if !authenticated {
        return MessageAuthMetadata {
            authenticated_channel: false,
            signature_key: None,
            key_owner_role: None,
            key_compromised: false,
            provenance: SignatureProvenance::UnauthenticatedChannel,
        };
    }

    if let Some(key) = ta.compromised_keys.iter().next() {
        return MessageAuthMetadata {
            authenticated_channel: true,
            signature_key: Some(key.clone()),
            key_owner_role: ta.key_owner(key).map(str::to_string),
            key_compromised: true,
            provenance: SignatureProvenance::CompromisedKey,
        };
    }

    MessageAuthMetadata {
        authenticated_channel: true,
        signature_key: None,
        key_owner_role: None,
        key_compromised: false,
        provenance: SignatureProvenance::ByzantineSigner,
    }
}

fn extract_rule_delivery_events(
    ta: &ThresholdAutomaton,
    rule_id: usize,
    delta: i64,
) -> Vec<MessageDeliveryEvent> {
    let mut events = Vec::new();
    let rule = &ta.rules[rule_id];
    for update in &rule.updates {
        if !matches!(update.kind, UpdateKind::Increment) {
            continue;
        }
        let Some(shared) = ta.shared_vars.get(update.var) else {
            continue;
        };
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((_family, recipient_channel, sender_channel, payload)) =
            parse_counter_message_metadata(&shared.name)
        else {
            continue;
        };
        let sender = sender_channel
            .as_deref()
            .map(|channel| identity_from_sender_channel(ta, channel))
            .unwrap_or_else(|| identity_from_location(ta, rule.from));
        let recipient = identity_from_recipient_channel(ta, &recipient_channel);
        let auth = auth_metadata_for_owned_sender(ta, &sender, &payload.family);
        events.push(MessageDeliveryEvent {
            shared_var: update.var,
            shared_var_name: shared.name.clone(),
            sender: sender.clone(),
            recipient: recipient.clone(),
            payload: payload.clone(),
            count: delta,
            kind: MessageEventKind::Send,
            auth: auth.clone(),
        });
        events.push(MessageDeliveryEvent {
            shared_var: update.var,
            shared_var_name: shared.name.clone(),
            sender,
            recipient,
            payload,
            count: delta,
            kind: MessageEventKind::Deliver,
            auth,
        });
    }
    events
}

fn extract_adversary_delivery_events(
    ta: &ThresholdAutomaton,
    model: &Model,
    smt_step: usize,
) -> Vec<MessageDeliveryEvent> {
    let mut events = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let adv = model
            .get_int(&format!("adv_{smt_step}_{var_id}"))
            .unwrap_or(0);
        if adv <= 0 {
            continue;
        }
        let Some((_family, recipient_channel, sender_channel, payload)) =
            parse_counter_message_metadata(&shared.name)
        else {
            continue;
        };
        let sender = sender_channel
            .as_deref()
            .map(|channel| identity_from_sender_channel(ta, channel))
            .unwrap_or_else(adversary_identity);
        let recipient = identity_from_recipient_channel(ta, &recipient_channel);
        let auth = auth_metadata_for_forge(ta, &payload.family);
        events.push(MessageDeliveryEvent {
            shared_var: var_id,
            shared_var_name: shared.name.clone(),
            sender: sender.clone(),
            recipient: recipient.clone(),
            payload: payload.clone(),
            count: adv,
            kind: MessageEventKind::Forge,
            auth: auth.clone(),
        });
        events.push(MessageDeliveryEvent {
            shared_var: var_id,
            shared_var_name: shared.name.clone(),
            sender,
            recipient,
            payload,
            count: adv,
            kind: MessageEventKind::Deliver,
            auth,
        });
    }
    events
}

fn extract_drop_events(
    ta: &ThresholdAutomaton,
    model: &Model,
    smt_step: usize,
) -> Vec<MessageDeliveryEvent> {
    let mut events = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let dropped = model
            .get_int(&format!("drop_{smt_step}_{var_id}"))
            .unwrap_or(0);
        if dropped <= 0 {
            continue;
        }
        let Some((_family, recipient_channel, sender_channel, payload)) =
            parse_counter_message_metadata(&shared.name)
        else {
            continue;
        };
        let auth = MessageAuthMetadata {
            authenticated_channel: ta.message_effective_authenticated(&payload.family),
            signature_key: None,
            key_owner_role: None,
            key_compromised: false,
            provenance: SignatureProvenance::Unknown,
        };
        events.push(MessageDeliveryEvent {
            shared_var: var_id,
            shared_var_name: shared.name.clone(),
            sender: sender_channel
                .as_deref()
                .map(|channel| identity_from_sender_channel(ta, channel))
                .unwrap_or_else(network_identity),
            recipient: identity_from_recipient_channel(ta, &recipient_channel),
            payload,
            count: dropped,
            kind: MessageEventKind::Drop,
            auth,
        });
    }
    events
}

fn extract_equivocation_events(
    adversary_events: &[MessageDeliveryEvent],
) -> Vec<MessageDeliveryEvent> {
    let mut family_variants: std::collections::HashMap<
        (String, Option<String>, String),
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for ev in adversary_events
        .iter()
        .filter(|ev| ev.kind == MessageEventKind::Forge && ev.count > 0)
    {
        let key = (
            ev.sender.role.clone(),
            ev.sender.process.clone(),
            ev.payload.family.clone(),
        );
        family_variants
            .entry(key)
            .or_default()
            .insert(ev.payload.variant.clone());
    }

    adversary_events
        .iter()
        .filter(|ev| ev.kind == MessageEventKind::Forge && ev.count > 0)
        .filter(|ev| {
            let key = (
                ev.sender.role.clone(),
                ev.sender.process.clone(),
                ev.payload.family.clone(),
            );
            family_variants
                .get(&key)
                .map(|variants| variants.len() > 1)
                .unwrap_or(false)
        })
        .map(|ev| {
            let mut cloned = ev.clone();
            cloned.kind = MessageEventKind::Equivocate;
            cloned
        })
        .collect()
}
