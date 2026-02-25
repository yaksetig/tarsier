use tarsier_ir::counter_system::{
    Configuration, CounterSystem, MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind,
    MessageIdentity, MessagePayloadVariant, SignatureProvenance, Trace, TraceStep,
};
use tarsier_ir::threshold_automaton::{
    LocalValue, PorMode, RoleIdentityScope, SharedVarKind, ThresholdAutomaton, UpdateKind,
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

    // Determine POR annotation for trace steps
    let por_status = match ta.por_mode {
        PorMode::Off => None,
        PorMode::Static => Some("active (static POR)".to_string()),
        PorMode::Full => Some("active (full POR)".to_string()),
    };

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
                // Adversary/drop/equivocation counters are step-global effects in the SMT
                // encoding. Attach them once to the first fired rule at this step so the
                // rendered trace does not duplicate global effects per rule.
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
                    por_status: por_status.clone(),
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
        let por_tag = match &step.por_status {
            Some(status) => format!(" [{status}]"),
            None => String::new(),
        };
        out.push_str(&format!(
            "  Step {}: rule r{} fires {} time(s): {} -> {}{}\n",
            i + 1,
            step.rule_id,
            step.delta,
            from_name,
            to_name,
            por_tag,
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

/// Return the sender role label from a channel identifier (`Role#pid` or `Role`).
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

/// Parse counter-style message metadata from shared-var names.
///
/// Expected shape:
/// `cnt_<Family>@<Recipient>[<-<Sender>][<field=value,...>]`
///
/// Examples:
/// - `cnt_Vote@Replica#1<-Replica#0[view=2,value=true]`
/// - `cnt_Prepare@Replica#3`
fn parse_counter_message_metadata(
    counter_name: &str,
) -> Option<(String, String, Option<String>, MessagePayloadVariant)> {
    let stripped = counter_name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped.split_once('@').unwrap_or((stripped, "*"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tarsier_ir::threshold_automaton::{
        AuthenticationMode, CryptoConflictPolicy, Guard, IrCryptoObjectKind, IrCryptoObjectSpec,
        LinearCombination, Location, MessageAuthPolicy, MessagePolicy, Parameter,
        RoleIdentityConfig, RoleIdentityScope, Rule, SharedVar, SharedVarKind, Update,
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
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });
        ta.role_identities.insert(
            "Replica".to_string(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".to_string()),
                key_name: "replica_key".to_string(),
            },
        );
        ta.key_ownership
            .insert("replica_key".to_string(), "Replica".to_string());
        ta.authentication_mode = if authenticated {
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
        let parsed =
            parse_counter_message_metadata("cnt_Vote@Replica#1<-Replica#0[view=2,value=true]")
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

        ta.compromised_keys.insert("replica_key".to_string());
        let compromised = auth_metadata_for_owned_sender(&ta, &sender, "Vote");
        assert_eq!(compromised.provenance, SignatureProvenance::CompromisedKey);
        assert!(compromised.key_compromised);

        ta.message_policies.insert(
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

        ta.compromised_keys.insert("replica_key".to_string());
        let compromised = auth_metadata_for_forge(&ta, "Vote");
        assert_eq!(compromised.provenance, SignatureProvenance::CompromisedKey);
        assert_eq!(compromised.signature_key.as_deref(), Some("replica_key"));

        ta.authentication_mode = AuthenticationMode::None;
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
        ta.por_mode = PorMode::Static;
        let cs = CounterSystem::new(ta);
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
            from: 0,
            to: 1,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });
        let cs = CounterSystem::new(ta);
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
        ta.crypto_objects.insert(
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
                rule_id: 0,
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
                rule_id: 0,
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
            param_values: vec![
                ("n".to_string(), 10),
                ("f".to_string(), 3),
            ],
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
                rule_id: 0,
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
                rule_id: 0,
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
            terms: vec![(2, 0), (-1, 1)],
        };
        assert_eq!(eval_linear_combination(&lc, &[5, 7]), 3 + 2 * 5 - 7);
    }

    #[test]
    fn eval_linear_combination_missing_param_defaults_to_zero() {
        let lc = LinearCombination {
            constant: 10,
            terms: vec![(5, 99)], // param index 99 does not exist
        };
        assert_eq!(eval_linear_combination(&lc, &[1, 2, 3]), 10);
    }

    // --- parse_counter_message_metadata edge cases ---

    #[test]
    fn parse_counter_metadata_with_sender_no_fields() {
        let parsed =
            parse_counter_message_metadata("cnt_Prepare@Replica#1<-Replica#0")
                .expect("should parse");
        assert_eq!(parsed.0, "Prepare");
        assert_eq!(parsed.1, "Replica#1");
        assert_eq!(parsed.2.as_deref(), Some("Replica#0"));
        assert!(parsed.3.fields.is_empty());
        assert_eq!(parsed.3.variant, "Prepare");
    }

    #[test]
    fn parse_counter_metadata_recipient_only_no_sender() {
        let parsed =
            parse_counter_message_metadata("cnt_Commit@Leader#0")
                .expect("should parse");
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
}
