//! Message counter resolution and related helpers.

use indexmap::IndexMap;
use std::collections::HashSet;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::helpers::eval_field_expr;
use super::messages::msg_key;
use super::{LocalVarType, LoweringError, MessageInfo, INTERNAL_DELIVERY_LANE_VAR};

pub(super) fn message_effective_authenticated(ta: &ThresholdAutomaton, message_type: &str) -> bool {
    match ta
        .security
        .message_policies
        .get(message_type)
        .map(|p| p.auth)
        .unwrap_or(MessageAuthPolicy::Inherit)
    {
        MessageAuthPolicy::Authenticated => true,
        MessageAuthPolicy::Unauthenticated => false,
        MessageAuthPolicy::Inherit => {
            ta.semantics.authentication_mode == AuthenticationMode::Signed
        }
    }
}

pub(super) fn collect_distinct_messages_in_guard(
    guard: &ast::GuardExpr,
    out: &mut HashSet<String>,
) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            if tg.distinct {
                out.insert(tg.message_type.clone());
            }
        }
        ast::GuardExpr::HasCryptoObject { .. } => {}
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_distinct_messages_in_guard(lhs, out);
            collect_distinct_messages_in_guard(rhs, out);
        }
        _ => {}
    }
}

pub(super) fn collect_distinct_messages_by_role(
    proto: &ast::ProtocolDecl,
) -> IndexMap<String, HashSet<String>> {
    let mut by_role: IndexMap<String, HashSet<String>> = IndexMap::new();
    for role in &proto.roles {
        let role_name = role.node.name.clone();
        let mut distinct_msgs: HashSet<String> = HashSet::new();
        for phase in &role.node.phases {
            for transition in &phase.node.transitions {
                collect_distinct_messages_in_guard(&transition.node.guard, &mut distinct_msgs);
            }
        }
        by_role.insert(role_name, distinct_msgs);
    }
    by_role
}

pub(super) fn collect_sent_messages_in_role(role: &ast::RoleDecl) -> HashSet<String> {
    let mut sent: HashSet<String> = HashSet::new();
    for phase in &role.phases {
        for transition in &phase.node.transitions {
            for action in &transition.node.actions {
                match action {
                    ast::Action::Send { message_type, .. } => {
                        sent.insert(message_type.clone());
                    }
                    ast::Action::FormCryptoObject { object_name, .. } => {
                        sent.insert(object_name.clone());
                    }
                    _ => {}
                }
            }
        }
    }
    sent
}

pub(super) fn object_counter_vars_for_recipient(
    ta: &ThresholdAutomaton,
    object_name: &str,
    recipient_channel: &str,
) -> Vec<SharedVarId> {
    let prefix = format!("cnt_{object_name}@{recipient_channel}");
    ta.shared_vars
        .iter()
        .enumerate()
        .filter(|(_, var)| {
            var.kind == SharedVarKind::MessageCounter && var.name.starts_with(prefix.as_str())
        })
        .map(|(var_id, _)| SharedVarId::from(var_id))
        .collect()
}

pub(super) fn append_exclusive_conflict_guard(
    ta: &ThresholdAutomaton,
    guard: &mut Guard,
    object_name: &str,
    recipient_channel: &str,
    selected_vars: &[SharedVarId],
) {
    let all_vars = object_counter_vars_for_recipient(ta, object_name, recipient_channel);
    if all_vars.is_empty() {
        return;
    }
    let selected: HashSet<SharedVarId> = selected_vars.iter().copied().collect();
    let conflicts: Vec<SharedVarId> = all_vars
        .into_iter()
        .filter(|var_id| !selected.contains(var_id))
        .collect();
    if conflicts.is_empty() {
        return;
    }
    guard.atoms.push(GuardAtom::Threshold {
        vars: conflicts,
        op: CmpOp::Eq,
        bound: LinearCombination::constant(0),
        distinct: false,
    });
}

pub(super) fn recipient_channel_for_location(
    role_name: &str,
    locals: &IndexMap<String, LocalValue>,
    network_semantics: NetworkSemantics,
    process_id_var: &str,
) -> Result<String, LoweringError> {
    match network_semantics {
        NetworkSemantics::ProcessSelective => match locals.get(process_id_var) {
            Some(LocalValue::Int(pid)) if *pid >= 0 => Ok(format!("{role_name}#{pid}")),
            Some(LocalValue::Int(_)) => Err(LoweringError::Unsupported(format!(
                "Process identifier `{process_id_var}` must be non-negative"
            ))),
            Some(_) => Err(LoweringError::Unsupported(format!(
                "Process identifier `{process_id_var}` must be an integer"
            ))),
            None => Err(LoweringError::Unsupported(format!(
                "Missing process identifier variable `{process_id_var}` in location"
            ))),
        },
        NetworkSemantics::CohortSelective => match locals.get(INTERNAL_DELIVERY_LANE_VAR) {
            Some(LocalValue::Int(lane)) => Ok(format!("{role_name}#{lane}")),
            Some(_) => Err(LoweringError::Unsupported(format!(
                "Internal delivery-lane variable '{INTERNAL_DELIVERY_LANE_VAR}' must be an integer"
            ))),
            None => Err(LoweringError::Unsupported(format!(
                "Missing internal delivery-lane variable '{INTERNAL_DELIVERY_LANE_VAR}' in location"
            ))),
        },
        _ => Ok(role_name.to_string()),
    }
}

pub(super) struct MessageCounterContext<'a> {
    pub(super) role_names: &'a [String],
    pub(super) role_channels: &'a IndexMap<String, Vec<String>>,
    pub(super) message_infos: &'a IndexMap<String, MessageInfo>,
    pub(super) msg_var_ids: &'a IndexMap<String, SharedVarId>,
    pub(super) locals: &'a IndexMap<String, LocalValue>,
    pub(super) local_var_types: &'a IndexMap<String, LocalVarType>,
    pub(super) enum_defs: &'a IndexMap<String, Vec<String>>,
}

pub(super) struct SendCounterLookup<'a> {
    pub(super) msg_name: &'a str,
    pub(super) recipient_role: Option<&'a str>,
    pub(super) exact_recipient_channel: Option<&'a str>,
    pub(super) sender_channel: Option<&'a str>,
    pub(super) sender_role_filter: Option<&'a str>,
    pub(super) args: &'a [ast::SendArg],
}

pub(super) fn resolve_message_counter_from_send(
    query: &SendCounterLookup<'_>,
    ctx: &MessageCounterContext<'_>,
) -> Result<Vec<SharedVarId>, LoweringError> {
    let msg_name = query.msg_name;
    let args = query.args;
    let role_names = ctx.role_names;
    let role_channels = ctx.role_channels;
    let message_infos = ctx.message_infos;
    let msg_var_ids = ctx.msg_var_ids;
    let locals = ctx.locals;
    let local_var_types = ctx.local_var_types;
    let enum_defs = ctx.enum_defs;
    let msg_info = message_infos
        .get(msg_name)
        .ok_or_else(|| LoweringError::UnknownMessageType(msg_name.to_string()))?;
    if msg_info.fields.is_empty() && !args.is_empty() {
        return Err(LoweringError::Unsupported(format!(
            "Message '{msg_name}' does not take arguments"
        )));
    }

    let mut field_exprs: IndexMap<String, ast::Expr> = IndexMap::new();
    let has_named = args.iter().any(|a| matches!(a, ast::SendArg::Named { .. }));
    if has_named {
        let field_names: HashSet<&str> = msg_info.fields.iter().map(|f| f.name.as_str()).collect();
        for arg in args {
            match arg {
                ast::SendArg::Named { name, value } => {
                    if !field_names.contains(name.as_str()) {
                        return Err(LoweringError::Unsupported(format!(
                            "Unknown argument '{name}' for message '{msg_name}'"
                        )));
                    }
                    if field_exprs.insert(name.clone(), value.clone()).is_some() {
                        return Err(LoweringError::Unsupported(format!(
                            "Duplicate argument '{name}' for message '{msg_name}'"
                        )));
                    }
                }
                ast::SendArg::Positional(_) => {
                    return Err(LoweringError::Unsupported(
                        "Cannot mix positional and named message arguments".into(),
                    ))
                }
            }
        }
    } else if !args.is_empty() {
        if args.len() != msg_info.fields.len() {
            return Err(LoweringError::Unsupported(format!(
                "Message '{msg_name}' expects {} arguments, got {}",
                msg_info.fields.len(),
                args.len()
            )));
        }
        for (field, arg) in msg_info.fields.iter().zip(args.iter()) {
            match arg {
                ast::SendArg::Positional(expr) => {
                    field_exprs.insert(field.name.clone(), expr.clone());
                }
                ast::SendArg::Named { .. } => {
                    return Err(LoweringError::Unsupported(
                        "Cannot mix positional and named message arguments".into(),
                    ))
                }
            }
        }
    }

    let mut values = Vec::new();
    for field in &msg_info.fields {
        if !field_exprs.contains_key(&field.name) && local_var_types.contains_key(&field.name) {
            field_exprs.insert(field.name.clone(), ast::Expr::Var(field.name.clone()));
        }
        let expr = field_exprs.get(&field.name).ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Missing argument '{}' for message '{msg_name}'",
                field.name
            ))
        })?;
        let v = eval_field_expr(expr, &field.domain, locals, local_var_types, enum_defs)?;
        values.push(v);
    }

    let recipients: Vec<String> = if let Some(channel) = query.exact_recipient_channel {
        vec![channel.to_string()]
    } else {
        let recipient_roles: Vec<&str> = if let Some(role) = query.recipient_role {
            if !role_names.iter().any(|r| r == role) {
                return Err(LoweringError::Unsupported(format!(
                    "Unknown recipient role '{role}' in send action"
                )));
            }
            vec![role]
        } else {
            role_names.iter().map(|s| s.as_str()).collect()
        };
        let mut channels = Vec::new();
        for role in recipient_roles {
            if let Some(role_chs) = role_channels.get(role) {
                channels.extend(role_chs.iter().cloned());
            } else {
                channels.push(role.to_string());
            }
        }
        channels
    };

    let sender_candidates: Vec<Option<&str>> = if let Some(sender_channel) = query.sender_channel {
        vec![Some(sender_channel)]
    } else if let Some(sender_role) = query.sender_role_filter {
        let mut candidates: Vec<Option<&str>> = role_channels
            .get(sender_role)
            .map(|channels| channels.iter().map(|s| Some(s.as_str())).collect())
            .unwrap_or_default();
        // Classic mode counters do not have sender-scoped suffixes.
        candidates.push(None);
        candidates
    } else {
        let mut candidates: Vec<Option<&str>> = role_channels
            .values()
            .flat_map(|channels| channels.iter().map(|s| Some(s.as_str())))
            .collect();
        // Classic mode counters do not have sender-scoped suffixes.
        candidates.push(None);
        candidates
    };

    let mut resolved = Vec::new();
    for recipient in recipients {
        for sender in &sender_candidates {
            let key = msg_key(msg_name, &recipient, *sender, &values);
            if let Some(var) = msg_var_ids.get(&key).copied() {
                resolved.push(var);
            }
        }
    }
    if resolved.is_empty() {
        return Err(LoweringError::UnknownMessageType(msg_name.to_string()));
    }
    Ok(resolved)
}

pub(super) struct GuardCounterLookup<'a> {
    pub(super) msg_name: &'a str,
    pub(super) recipient_role: &'a str,
    pub(super) args: &'a [(String, ast::Expr)],
    pub(super) sender_role: Option<&'a str>,
}

pub(super) fn resolve_message_counter_from_guard(
    query: &GuardCounterLookup<'_>,
    ctx: &MessageCounterContext<'_>,
) -> Result<Vec<SharedVarId>, LoweringError> {
    let msg_name = query.msg_name;
    let recipient_role = query.recipient_role;
    let args = query.args;
    let sender_role = query.sender_role;
    let role_channels = ctx.role_channels;
    let message_infos = ctx.message_infos;
    let msg_var_ids = ctx.msg_var_ids;
    let locals = ctx.locals;
    let local_var_types = ctx.local_var_types;
    let enum_defs = ctx.enum_defs;
    let msg_info = message_infos
        .get(msg_name)
        .ok_or_else(|| LoweringError::UnknownMessageType(msg_name.to_string()))?;
    if msg_info.fields.is_empty() {
        if !args.is_empty() {
            return Err(LoweringError::Unsupported(format!(
                "Message '{msg_name}' does not take arguments"
            )));
        }
        let sender_channels: Vec<Option<&str>> = if let Some(sender_role) = sender_role {
            let mut channels: Vec<Option<&str>> = role_channels
                .get(sender_role)
                .map(|channels| channels.iter().map(|s| Some(s.as_str())).collect())
                .unwrap_or_default();
            channels.push(None);
            channels
        } else {
            let mut channels: Vec<Option<&str>> = role_channels
                .values()
                .flat_map(|v| v.iter().map(|s| Some(s.as_str())))
                .collect();
            channels.push(None);
            channels
        };
        let mut resolved = Vec::new();
        for sender in sender_channels {
            if let Some(var) = msg_var_ids
                .get(&msg_key(msg_name, recipient_role, sender, &[]))
                .copied()
            {
                resolved.push(var);
            }
        }
        if resolved.is_empty() {
            return Err(LoweringError::UnknownMessageType(msg_name.to_string()));
        }
        return Ok(resolved);
    }

    let mut field_exprs: IndexMap<String, ast::Expr> = IndexMap::new();
    let field_names: HashSet<&str> = msg_info.fields.iter().map(|f| f.name.as_str()).collect();
    for (name, expr) in args {
        if !field_names.contains(name.as_str()) {
            return Err(LoweringError::Unsupported(format!(
                "Unknown argument '{name}' for message '{msg_name}'"
            )));
        }
        if field_exprs.insert(name.clone(), expr.clone()).is_some() {
            return Err(LoweringError::Unsupported(format!(
                "Duplicate argument '{name}' for message '{msg_name}'"
            )));
        }
    }

    let mut values = Vec::new();
    for field in &msg_info.fields {
        if !field_exprs.contains_key(&field.name) && local_var_types.contains_key(&field.name) {
            field_exprs.insert(field.name.clone(), ast::Expr::Var(field.name.clone()));
        }
        let expr = field_exprs.get(&field.name).ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Missing argument '{}' for message '{msg_name}'",
                field.name
            ))
        })?;
        let v = eval_field_expr(expr, &field.domain, locals, local_var_types, enum_defs)?;
        values.push(v);
    }

    let sender_channels: Vec<Option<&str>> = if let Some(sender_role) = sender_role {
        let mut channels: Vec<Option<&str>> = role_channels
            .get(sender_role)
            .map(|channels| channels.iter().map(|s| Some(s.as_str())).collect())
            .unwrap_or_default();
        channels.push(None);
        channels
    } else {
        let mut channels: Vec<Option<&str>> = role_channels
            .values()
            .flat_map(|v| v.iter().map(|s| Some(s.as_str())))
            .collect();
        channels.push(None);
        channels
    };
    let mut resolved = Vec::new();
    for sender in sender_channels {
        if let Some(var) = msg_var_ids
            .get(&msg_key(msg_name, recipient_role, sender, &values))
            .copied()
        {
            resolved.push(var);
        }
    }
    if resolved.is_empty() {
        return Err(LoweringError::UnknownMessageType(msg_name.to_string()));
    }
    Ok(resolved)
}
