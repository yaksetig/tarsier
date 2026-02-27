//! Adversary, identity, channel, network, and equivocation configuration.

use indexmap::{IndexMap, IndexSet};
use std::collections::HashSet;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::{LoweringError, DEFAULT_PROCESS_ID_VAR};

pub(super) fn parse_fault_model(raw: &str) -> Result<FaultModel, LoweringError> {
    match raw {
        "byzantine" => Ok(FaultModel::Byzantine),
        "crash" | "crash_stop" => Ok(FaultModel::Crash),
        "omission" => Ok(FaultModel::Omission),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported adversary model '{other}'; expected 'byzantine', 'crash', or 'omission'"
        ))),
    }
}

pub(super) fn parse_timing_model(raw: &str) -> Result<TimingModel, LoweringError> {
    match raw {
        "async" | "asynchronous" => Ok(TimingModel::Asynchronous),
        "partial_synchrony" | "partial_sync" => Ok(TimingModel::PartialSynchrony),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported timing model '{other}'; expected 'asynchronous' or 'partial_synchrony'"
        ))),
    }
}

pub(super) fn parse_value_abstraction_mode(
    raw: &str,
) -> Result<ValueAbstractionMode, LoweringError> {
    match raw {
        "exact" => Ok(ValueAbstractionMode::Exact),
        "sign" => Ok(ValueAbstractionMode::Sign),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported value abstraction '{other}'; expected 'exact' or 'sign'"
        ))),
    }
}

pub(super) fn parse_equivocation_mode(raw: &str) -> Result<EquivocationMode, LoweringError> {
    match raw {
        "full" | "enabled" | "on" => Ok(EquivocationMode::Full),
        "none" | "disabled" | "off" => Ok(EquivocationMode::None),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported equivocation mode '{other}'; expected 'full' or 'none'"
        ))),
    }
}

pub(super) fn parse_authentication_mode(raw: &str) -> Result<AuthenticationMode, LoweringError> {
    match raw {
        "none" | "off" => Ok(AuthenticationMode::None),
        "signed" | "signature" | "signatures" | "authenticated" => Ok(AuthenticationMode::Signed),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported authentication mode '{other}'; expected 'none' or 'signed'"
        ))),
    }
}

pub(super) fn parse_network_semantics(raw: &str) -> Result<NetworkSemantics, LoweringError> {
    match raw {
        "classic" | "counter" | "legacy" => Ok(NetworkSemantics::Classic),
        "identity_selective" | "faithful" | "selective" | "selective_delivery" => {
            Ok(NetworkSemantics::IdentitySelective)
        }
        "cohort_selective" | "lane_selective" => Ok(NetworkSemantics::CohortSelective),
        "process_selective" | "per_process" | "process_scoped" => {
            Ok(NetworkSemantics::ProcessSelective)
        }
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported network semantics '{other}'; expected 'classic', \
             'identity_selective', 'cohort_selective', or 'process_selective'"
        ))),
    }
}

pub(super) fn parse_delivery_control_mode(raw: &str) -> Result<DeliveryControlMode, LoweringError> {
    match raw {
        "legacy" | "legacy_counter" | "counter" => Ok(DeliveryControlMode::LegacyCounter),
        "per_recipient" | "recipient" | "recipient_scoped" => {
            Ok(DeliveryControlMode::PerRecipient)
        }
        "global" => Ok(DeliveryControlMode::Global),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported delivery control '{other}'; expected 'legacy_counter', 'per_recipient', or 'global'"
        ))),
    }
}

pub(super) fn parse_fault_budget_scope(raw: &str) -> Result<FaultBudgetScope, LoweringError> {
    match raw {
        "legacy" | "legacy_counter" | "counter" => Ok(FaultBudgetScope::LegacyCounter),
        "per_recipient" | "recipient" | "recipient_scoped" => Ok(FaultBudgetScope::PerRecipient),
        "global" => Ok(FaultBudgetScope::Global),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported fault scope '{other}'; expected 'legacy_counter', 'per_recipient', or 'global'"
        ))),
    }
}

pub(super) fn parse_por_mode(raw: &str) -> Result<PorMode, LoweringError> {
    match raw {
        "full" => Ok(PorMode::Full),
        "static" | "static_only" => Ok(PorMode::Static),
        "off" | "none" | "disabled" => Ok(PorMode::Off),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported POR mode '{other}'; expected 'full', 'static', or 'off'"
        ))),
    }
}

pub(super) fn process_selective_channels_for_role(
    role_decl: &ast::RoleDecl,
    process_id_var: &str,
) -> Result<Vec<String>, LoweringError> {
    let pid_var = role_decl
        .vars
        .iter()
        .find(|v| v.name == process_id_var)
        .ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Role '{}' must declare `{process_id_var}: nat/int in <min>..<max>` for \
                 `network: process_selective`",
                role_decl.name
            ))
        })?;

    match pid_var.ty {
        ast::VarType::Nat | ast::VarType::Int => {}
        _ => {
            return Err(LoweringError::Unsupported(format!(
                "Role '{}' variable `{process_id_var}` must be nat/int for \
                 `network: process_selective`",
                role_decl.name
            )));
        }
    }

    let range = pid_var.range.as_ref().ok_or_else(|| {
        LoweringError::Unsupported(format!(
            "Role '{}' variable `{process_id_var}` must be bounded (e.g. `in 0..3`) for \
             `network: process_selective`",
            role_decl.name
        ))
    })?;
    if range.min < 0 {
        return Err(LoweringError::Unsupported(format!(
            "Role '{}' variable `{process_id_var}` must have non-negative bounds for \
             `network: process_selective`",
            role_decl.name
        )));
    }
    if range.max < range.min {
        return Err(LoweringError::InvalidRange(
            process_id_var.into(),
            range.min,
            range.max,
        ));
    }

    Ok((range.min..=range.max)
        .map(|pid| format!("{}#{pid}", role_decl.name))
        .collect())
}

pub(super) fn default_key_name_for_role(role: &str) -> String {
    format!("{}_key", role.to_lowercase())
}

pub(super) fn build_role_identity_configs(
    proto: &ast::ProtocolDecl,
    network_semantics: NetworkSemantics,
) -> Result<IndexMap<String, RoleIdentityConfig>, LoweringError> {
    let role_names: HashSet<String> = proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let mut explicit: IndexMap<String, RoleIdentityConfig> = IndexMap::new();

    for decl in &proto.identities {
        if !role_names.contains(&decl.role) {
            return Err(LoweringError::Unsupported(format!(
                "identity declaration references unknown role '{}'",
                decl.role
            )));
        }
        if explicit.contains_key(&decl.role) {
            return Err(LoweringError::Unsupported(format!(
                "duplicate identity declaration for role '{}'",
                decl.role
            )));
        }
        let scope = match decl.scope {
            ast::IdentityScope::Role => RoleIdentityScope::Role,
            ast::IdentityScope::Process => RoleIdentityScope::Process,
        };
        let process_var = match decl.scope {
            ast::IdentityScope::Process => decl
                .process_var
                .clone()
                .or_else(|| Some(DEFAULT_PROCESS_ID_VAR.into())),
            ast::IdentityScope::Role => None,
        };
        let key_name = decl
            .key
            .clone()
            .unwrap_or_else(|| default_key_name_for_role(&decl.role));
        explicit.insert(
            decl.role.clone(),
            RoleIdentityConfig {
                scope,
                process_var,
                key_name,
            },
        );
    }

    let mut result = IndexMap::new();
    for role in &proto.roles {
        let role_name = role.node.name.clone();
        if let Some(cfg) = explicit.get(&role_name) {
            result.insert(role_name.clone(), cfg.clone());
            continue;
        }

        let scope = if network_semantics == NetworkSemantics::ProcessSelective {
            RoleIdentityScope::Process
        } else {
            RoleIdentityScope::Role
        };
        let process_var = if scope == RoleIdentityScope::Process {
            Some(DEFAULT_PROCESS_ID_VAR.into())
        } else {
            None
        };
        result.insert(
            role_name.clone(),
            RoleIdentityConfig {
                scope,
                process_var,
                key_name: default_key_name_for_role(&role_name),
            },
        );
    }

    if network_semantics == NetworkSemantics::ProcessSelective {
        for (role, cfg) in &result {
            if cfg.scope != RoleIdentityScope::Process {
                return Err(LoweringError::Unsupported(format!(
                    "network: process_selective requires process-scoped identity for role '{role}'"
                )));
            }
            if cfg.process_var.is_none() {
                return Err(LoweringError::Unsupported(format!(
                    "process-scoped identity for role '{role}' must declare process variable"
                )));
            }
        }
    }

    Ok(result)
}

pub(super) fn build_key_ownership(
    role_identities: &IndexMap<String, RoleIdentityConfig>,
) -> Result<IndexMap<String, String>, LoweringError> {
    let mut owners: IndexMap<String, String> = IndexMap::new();
    for (role, cfg) in role_identities {
        if let Some(existing_role) = owners.get(&cfg.key_name) {
            if existing_role != role {
                return Err(LoweringError::Unsupported(format!(
                    "identity key '{}' is assigned to multiple roles ('{}' and '{}'); \
                     keys must be role-consistent",
                    cfg.key_name, existing_role, role
                )));
            }
        } else {
            owners.insert(cfg.key_name.clone(), role.clone());
        }
    }
    Ok(owners)
}

pub(super) fn validate_compromised_keys(
    compromised: &IndexSet<String>,
    key_owners: &IndexMap<String, String>,
) -> Result<(), LoweringError> {
    for key in compromised {
        if !key_owners.contains_key(key) {
            return Err(LoweringError::Unsupported(format!(
                "adversary compromised key '{}' is not declared by any role identity",
                key
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_identity_and_key_invariants(
    ta: &ThresholdAutomaton,
) -> Result<(), LoweringError> {
    for (role, cfg) in &ta.role_identities {
        match ta.key_ownership.get(&cfg.key_name) {
            Some(owner) if owner == role => {}
            Some(owner) => {
                return Err(LoweringError::Unsupported(format!(
                    "key-role consistency violated: role '{}' expects key '{}' but ownership maps to '{}'",
                    role, cfg.key_name, owner
                )));
            }
            None => {
                return Err(LoweringError::Unsupported(format!(
                    "key-role consistency violated: role '{}' key '{}' has no ownership mapping",
                    role, cfg.key_name
                )));
            }
        }
    }
    validate_compromised_keys(&ta.compromised_keys, &ta.key_ownership)?;

    for (rule_id, rule) in ta.rules.iter().enumerate() {
        let from_loc = &ta.locations[rule.from];
        let to_loc = &ta.locations[rule.to];
        let Some(identity_cfg) = ta.role_identities.get(&from_loc.role) else {
            continue;
        };
        if identity_cfg.scope != RoleIdentityScope::Process {
            continue;
        }
        let pid_var = identity_cfg
            .process_var
            .as_deref()
            .unwrap_or(DEFAULT_PROCESS_ID_VAR);
        let from_pid = from_loc.local_vars.get(pid_var);
        let to_pid = to_loc.local_vars.get(pid_var);
        if from_pid != to_pid {
            return Err(LoweringError::Unsupported(format!(
                "identity immutability violated by rule r{rule_id} ({} -> {}): \
                 process identity variable '{}' changes from {:?} to {:?}",
                from_loc.name, to_loc.name, pid_var, from_pid, to_pid
            )));
        }
    }

    Ok(())
}

pub(super) fn build_message_policy_overrides(
    proto: &ast::ProtocolDecl,
) -> Result<IndexMap<String, MessagePolicy>, LoweringError> {
    let mut declared_messages: HashSet<String> =
        proto.messages.iter().map(|m| m.name.clone()).collect();
    declared_messages.extend(proto.crypto_objects.iter().map(|o| o.name.clone()));
    let mut policies: IndexMap<String, MessagePolicy> = IndexMap::new();

    for ch in &proto.channels {
        if !declared_messages.contains(&ch.message) {
            return Err(LoweringError::Unsupported(format!(
                "channel declaration references unknown message '{}'",
                ch.message
            )));
        }
        let policy = policies.entry(ch.message.clone()).or_default();
        if policy.auth != MessageAuthPolicy::Inherit {
            return Err(LoweringError::Unsupported(format!(
                "duplicate channel declaration for message '{}'",
                ch.message
            )));
        }
        policy.auth = match ch.auth {
            ast::ChannelAuthMode::Authenticated => MessageAuthPolicy::Authenticated,
            ast::ChannelAuthMode::Unauthenticated => MessageAuthPolicy::Unauthenticated,
        };
    }

    for eq in &proto.equivocation_policies {
        if !declared_messages.contains(&eq.message) {
            return Err(LoweringError::Unsupported(format!(
                "equivocation declaration references unknown message '{}'",
                eq.message
            )));
        }
        let policy = policies.entry(eq.message.clone()).or_default();
        if policy.equivocation != MessageEquivocationPolicy::Inherit {
            return Err(LoweringError::Unsupported(format!(
                "duplicate equivocation declaration for message '{}'",
                eq.message
            )));
        }
        policy.equivocation = match eq.mode {
            ast::EquivocationPolicyMode::Full => MessageEquivocationPolicy::Full,
            ast::EquivocationPolicyMode::None => MessageEquivocationPolicy::None,
        };
    }

    Ok(policies)
}
