use indexmap::{IndexMap, IndexSet};
use miette::{Diagnostic, NamedSource, SourceSpan};
use std::collections::HashSet;
use thiserror::Error;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

const INTERNAL_ALIVE_VAR: &str = "__alive";
const INTERNAL_CRASH_COUNTER: &str = "__crashed_count";
const INTERNAL_DELIVERY_LANE_VAR: &str = "__delivery_lane";
const DEFAULT_PROCESS_ID_VAR: &str = "pid";
const PROCESS_SELECTIVE_LANE_COUNT: i64 = 2;

fn internal_lock_flag_name(object_name: &str) -> String {
    format!("__lock_{}", object_name.to_lowercase())
}

fn internal_justify_flag_name(object_name: &str) -> String {
    format!("__justify_{}", object_name.to_lowercase())
}

#[derive(Debug, Error)]
pub enum LoweringError {
    #[error("Unknown parameter '{0}' in expression")]
    UnknownParameter(String),
    #[error("Unknown message type '{0}'")]
    UnknownMessageType(String),
    #[error("Unknown phase '{0}' in goto")]
    UnknownPhase(String),
    #[error("Role '{0}' has no init phase")]
    NoInitPhase(String),
    #[error("Unknown enum type '{0}'")]
    UnknownEnum(String),
    #[error("Unknown enum variant '{0}' for enum '{1}'")]
    UnknownEnumVariant(String, String),
    #[error("Missing init value for enum variable '{0}'")]
    MissingEnumInit(String),
    #[error("Out of range for variable '{var}': {value} not in [{min}, {max}]")]
    OutOfRange {
        var: String,
        value: i64,
        min: i64,
        max: i64,
    },
    #[error("Invalid range for variable '{0}': {1}..{2}")]
    InvalidRange(String, i64, i64),
    #[error("Unsupported: {0}")]
    Unsupported(String),
}

/// A lowering error enriched with source span information for pretty-printed diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("{inner}")]
pub struct SpannedLoweringError {
    #[source_code]
    pub src: NamedSource<String>,
    pub inner: LoweringError,
    #[label("here")]
    pub span: Option<SourceSpan>,
}

impl SpannedLoweringError {
    fn new(err: LoweringError, source: String, filename: String, span: Option<ast::Span>) -> Self {
        Self {
            src: NamedSource::new(filename, source),
            inner: err,
            span: span.map(|s| SourceSpan::new(s.start.into(), (s.end - s.start).into())),
        }
    }
}

/// Lower an AST Program into a ThresholdAutomaton, with rich source-span diagnostics.
///
/// This wraps `lower()` and attaches source spans for pretty error reporting via miette.
pub fn lower_with_source(
    program: &ast::Program,
    source: &str,
    filename: &str,
) -> Result<ThresholdAutomaton, SpannedLoweringError> {
    lower(program).map_err(|err| {
        let span = find_span_for_error(&err, program);
        SpannedLoweringError::new(err, source.to_string(), filename.to_string(), span)
    })
}

/// Best-effort span lookup for a lowering error by examining the AST.
fn find_span_for_error(err: &LoweringError, program: &ast::Program) -> Option<ast::Span> {
    let proto = &program.protocol.node;
    match err {
        LoweringError::UnknownPhase(name) => {
            // Search transition actions for GotoPhase with the unknown phase name
            for role in &proto.roles {
                for phase in &role.node.phases {
                    for tr in &phase.node.transitions {
                        for action in &tr.node.actions {
                            if let ast::Action::GotoPhase { phase } = action {
                                if phase == name {
                                    return Some(tr.span);
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        LoweringError::NoInitPhase(role_name) => {
            for role in &proto.roles {
                if role.node.name == *role_name {
                    return Some(role.span);
                }
            }
            None
        }
        LoweringError::UnknownMessageType(msg_name) => {
            // Search transition actions for Send with the unknown message
            for role in &proto.roles {
                for phase in &role.node.phases {
                    for tr in &phase.node.transitions {
                        for action in &tr.node.actions {
                            if let ast::Action::Send { message_type, .. } = action {
                                if message_type == msg_name {
                                    return Some(tr.span);
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        LoweringError::UnknownParameter(param_name) => {
            for p in &proto.parameters {
                if p.name == *param_name {
                    return Some(p.span);
                }
            }
            None
        }
        LoweringError::OutOfRange { var, .. } | LoweringError::InvalidRange(var, ..) => {
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.name == *var {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::UnknownEnum(enum_name) | LoweringError::MissingEnumInit(enum_name) => {
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.name == *enum_name {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::UnknownEnumVariant(_, enum_name) => {
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.name == *enum_name {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::Unsupported(_) => Some(program.protocol.span),
    }
}

#[derive(Debug, Clone)]
enum LocalVarType {
    Bool,
    Enum(String),
    Int { min: i64, max: i64 },
}

#[derive(Debug, Clone)]
struct MessageFieldInfo {
    name: String,
    domain: FieldDomain,
}

#[derive(Debug, Clone)]
struct MessageInfo {
    name: String,
    fields: Vec<MessageFieldInfo>,
}

#[derive(Debug, Clone)]
struct CryptoObjectInfo {
    source_message: String,
    threshold: LinearCombination,
    signer_role: Option<String>,
    conflict_policy: CryptoConflictPolicy,
}

#[derive(Debug, Clone)]
enum FieldDomain {
    Bool,
    Enum(Vec<String>),
    Int { min: i64, max: i64 },
    AbstractNatSign(Vec<String>),
    AbstractIntSign(Vec<String>),
}

#[derive(Debug, Clone)]
enum PendingTransitionAction {
    Send {
        message_type: String,
        args: Vec<ast::SendArg>,
        recipient_role: Option<String>,
    },
    FormCryptoObject {
        object_name: String,
        args: Vec<ast::SendArg>,
        recipient_role: Option<String>,
    },
    LockCryptoObject {
        object_name: String,
        args: Vec<ast::SendArg>,
    },
    JustifyCryptoObject {
        object_name: String,
        args: Vec<ast::SendArg>,
    },
}

fn parse_fault_model(raw: &str) -> Result<FaultModel, LoweringError> {
    match raw {
        "byzantine" => Ok(FaultModel::Byzantine),
        "crash" | "crash_stop" => Ok(FaultModel::Crash),
        "omission" => Ok(FaultModel::Omission),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported adversary model '{other}'; expected 'byzantine', 'crash', or 'omission'"
        ))),
    }
}

fn parse_timing_model(raw: &str) -> Result<TimingModel, LoweringError> {
    match raw {
        "async" | "asynchronous" => Ok(TimingModel::Asynchronous),
        "partial_synchrony" | "partial_sync" => Ok(TimingModel::PartialSynchrony),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported timing model '{other}'; expected 'asynchronous' or 'partial_synchrony'"
        ))),
    }
}

fn parse_value_abstraction_mode(raw: &str) -> Result<ValueAbstractionMode, LoweringError> {
    match raw {
        "exact" => Ok(ValueAbstractionMode::Exact),
        "sign" => Ok(ValueAbstractionMode::Sign),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported value abstraction '{other}'; expected 'exact' or 'sign'"
        ))),
    }
}

fn parse_equivocation_mode(raw: &str) -> Result<EquivocationMode, LoweringError> {
    match raw {
        "full" | "enabled" | "on" => Ok(EquivocationMode::Full),
        "none" | "disabled" | "off" => Ok(EquivocationMode::None),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported equivocation mode '{other}'; expected 'full' or 'none'"
        ))),
    }
}

fn parse_authentication_mode(raw: &str) -> Result<AuthenticationMode, LoweringError> {
    match raw {
        "none" | "off" => Ok(AuthenticationMode::None),
        "signed" | "signature" | "signatures" | "authenticated" => Ok(AuthenticationMode::Signed),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported authentication mode '{other}'; expected 'none' or 'signed'"
        ))),
    }
}

fn parse_network_semantics(raw: &str) -> Result<NetworkSemantics, LoweringError> {
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

fn parse_delivery_control_mode(raw: &str) -> Result<DeliveryControlMode, LoweringError> {
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

fn parse_fault_budget_scope(raw: &str) -> Result<FaultBudgetScope, LoweringError> {
    match raw {
        "legacy" | "legacy_counter" | "counter" => Ok(FaultBudgetScope::LegacyCounter),
        "per_recipient" | "recipient" | "recipient_scoped" => Ok(FaultBudgetScope::PerRecipient),
        "global" => Ok(FaultBudgetScope::Global),
        other => Err(LoweringError::Unsupported(format!(
            "Unsupported fault scope '{other}'; expected 'legacy_counter', 'per_recipient', or 'global'"
        ))),
    }
}

fn process_selective_channels_for_role(
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

fn message_effective_authenticated(ta: &ThresholdAutomaton, message_type: &str) -> bool {
    match ta
        .message_policies
        .get(message_type)
        .map(|p| p.auth)
        .unwrap_or(MessageAuthPolicy::Inherit)
    {
        MessageAuthPolicy::Authenticated => true,
        MessageAuthPolicy::Unauthenticated => false,
        MessageAuthPolicy::Inherit => ta.authentication_mode == AuthenticationMode::Signed,
    }
}

fn collect_distinct_messages_in_guard(guard: &ast::GuardExpr, out: &mut HashSet<String>) {
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

fn collect_distinct_messages_by_role(
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

fn collect_sent_messages_in_role(role: &ast::RoleDecl) -> HashSet<String> {
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

fn default_key_name_for_role(role: &str) -> String {
    format!("{}_key", role.to_lowercase())
}

fn build_role_identity_configs(
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

fn build_key_ownership(
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

fn validate_compromised_keys(
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

fn validate_identity_and_key_invariants(ta: &ThresholdAutomaton) -> Result<(), LoweringError> {
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

fn build_message_policy_overrides(
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

/// Lower an AST Program into a ThresholdAutomaton.
pub fn lower(program: &ast::Program) -> Result<ThresholdAutomaton, LoweringError> {
    let proto = &program.protocol.node;
    let pacemaker = proto.pacemaker.as_ref();
    let mut ta = ThresholdAutomaton::new();
    let mut compromised_keys_from_adversary: IndexSet<String> = IndexSet::new();

    // 1. Add parameters (explicit + implicit from resilience expression)
    let mut param_order: Vec<String> = proto.parameters.iter().map(|p| p.name.clone()).collect();
    let mut seen: HashSet<String> = param_order.iter().cloned().collect();

    if let Some(ref res) = proto.resilience {
        collect_params_from_linear_expr(&res.condition.lhs, &mut param_order, &mut seen);
        collect_params_from_linear_expr(&res.condition.rhs, &mut param_order, &mut seen);
    }

    let param_ids: IndexMap<String, ParamId> = param_order
        .into_iter()
        .map(|name| {
            let id = ta.add_parameter(Parameter { name: name.clone() });
            (name, id)
        })
        .collect();

    // 1b. Collect enum declarations
    let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
    for en in &proto.enums {
        enum_defs.insert(en.name.clone(), en.variants.clone());
    }

    // 2. Add resilience condition
    if let Some(ref res) = proto.resilience {
        let lhs = lower_linear_expr_to_lc(&res.condition.lhs, &param_ids)?;
        let rhs = lower_linear_expr_to_lc(&res.condition.rhs, &param_ids)?;
        let op = lower_cmp_op(res.condition.op);
        ta.resilience_condition = Some(LinearConstraint { lhs, op, rhs });
    }

    // 2b. Set adversary/fault/timing/value-abstraction configuration
    for item in &proto.adversary {
        match item.key.as_str() {
            "bound" => {
                if let Some(&pid) = param_ids.get(&item.value) {
                    ta.adversary_bound_param = Some(pid);
                } else {
                    return Err(LoweringError::UnknownParameter(item.value.clone()));
                }
            }
            "model" => {
                ta.fault_model = parse_fault_model(&item.value)?;
            }
            "timing" => {
                ta.timing_model = parse_timing_model(&item.value)?;
            }
            "gst" => {
                if let Some(&pid) = param_ids.get(&item.value) {
                    ta.gst_param = Some(pid);
                } else {
                    return Err(LoweringError::UnknownParameter(item.value.clone()));
                }
            }
            "values" | "value_abstraction" => {
                ta.value_abstraction = parse_value_abstraction_mode(&item.value)?;
            }
            "equivocation" => {
                ta.equivocation_mode = parse_equivocation_mode(&item.value)?;
            }
            "auth" | "authentication" => {
                ta.authentication_mode = parse_authentication_mode(&item.value)?;
            }
            "network" => {
                ta.network_semantics = parse_network_semantics(&item.value)?;
            }
            "delivery" | "delivery_scope" => {
                ta.delivery_control = parse_delivery_control_mode(&item.value)?;
            }
            "faults" | "fault_scope" | "fault_budget" => {
                ta.fault_budget_scope = parse_fault_budget_scope(&item.value)?;
            }
            "compromise" | "compromised" | "compromised_key" | "compromised_keys" => {
                compromised_keys_from_adversary.insert(item.value.clone());
            }
            other => {
                return Err(LoweringError::Unsupported(format!(
                    "Unknown adversary key '{other}'"
                )));
            }
        }
    }
    if ta.timing_model == TimingModel::PartialSynchrony && ta.gst_param.is_none() {
        return Err(LoweringError::Unsupported(
            "timing: partial_synchrony requires `adversary { gst: <param>; }`".into(),
        ));
    }
    if ta.delivery_control != DeliveryControlMode::LegacyCounter
        && ta.network_semantics == NetworkSemantics::Classic
    {
        return Err(LoweringError::Unsupported(
            "delivery controls require non-classic network semantics. \
             Use `network: identity_selective|cohort_selective|process_selective`."
                .into(),
        ));
    }
    ta.role_identities = build_role_identity_configs(proto, ta.network_semantics)?;
    ta.key_ownership = build_key_ownership(&ta.role_identities)?;
    validate_compromised_keys(&compromised_keys_from_adversary, &ta.key_ownership)?;
    ta.compromised_keys = compromised_keys_from_adversary;
    ta.message_policies = build_message_policy_overrides(proto)?;

    // 2c. Process committee declarations
    for committee in &proto.committees {
        let mut population = None;
        let mut byzantine = None;
        let mut committee_size = None;
        let mut epsilon = None;
        let mut bound_param = None;

        for item in &committee.items {
            match item.key.as_str() {
                "population" => {
                    population = Some(lower_committee_value(&item.value, &param_ids)?);
                }
                "byzantine" => {
                    byzantine = Some(lower_committee_value(&item.value, &param_ids)?);
                }
                "size" => {
                    committee_size = Some(lower_committee_value(&item.value, &param_ids)?);
                }
                "epsilon" => match &item.value {
                    ast::CommitteeValue::Float(f) => {
                        epsilon = Some(*f);
                    }
                    _ => {
                        return Err(LoweringError::Unsupported(format!(
                            "Committee '{}' field 'epsilon' must be a float literal",
                            committee.name
                        )));
                    }
                },
                "bound_param" => match &item.value {
                    ast::CommitteeValue::Param(name) => {
                        if let Some(&pid) = param_ids.get(name) {
                            bound_param = Some(pid);
                        } else {
                            return Err(LoweringError::UnknownParameter(name.clone()));
                        }
                    }
                    _ => {
                        return Err(LoweringError::Unsupported(format!(
                            "Committee '{}' field 'bound_param' must reference a parameter",
                            committee.name
                        )));
                    }
                },
                other => {
                    return Err(LoweringError::Unsupported(format!(
                        "Unknown field '{other}' in committee '{}'",
                        committee.name
                    )));
                }
            }
        }

        let population = population.ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Committee '{}' missing required field 'population'",
                committee.name
            ))
        })?;
        let byzantine = byzantine.ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Committee '{}' missing required field 'byzantine'",
                committee.name
            ))
        })?;
        let committee_size = committee_size.ok_or_else(|| {
            LoweringError::Unsupported(format!(
                "Committee '{}' missing required field 'size'",
                committee.name
            ))
        })?;

        ta.committees.push(IrCommitteeSpec {
            name: committee.name.clone(),
            population,
            byzantine,
            committee_size,
            epsilon,
            bound_param,
        });
    }

    // 3. Add shared variables for each message type (expanded by field values)
    let mut message_infos = build_message_infos(&proto.messages, &enum_defs, ta.value_abstraction)?;
    let mut crypto_objects: IndexMap<String, CryptoObjectInfo> = IndexMap::new();
    for object in &proto.crypto_objects {
        let source_info = message_infos
            .get(&object.source_message)
            .ok_or_else(|| LoweringError::UnknownMessageType(object.source_message.clone()))?;
        if message_infos.contains_key(&object.name) {
            return Err(LoweringError::Unsupported(format!(
                "Crypto object '{}' collides with an existing message/object name",
                object.name
            )));
        }
        if let Some(role) = &object.signer_role {
            if !proto.roles.iter().any(|r| r.node.name == *role) {
                return Err(LoweringError::Unsupported(format!(
                    "Crypto object '{}' references unknown signer role '{}'",
                    object.name, role
                )));
            }
        }
        let kind = match object.kind {
            ast::CryptoObjectKind::QuorumCertificate => IrCryptoObjectKind::QuorumCertificate,
            ast::CryptoObjectKind::ThresholdSignature => IrCryptoObjectKind::ThresholdSignature,
        };
        if matches!(kind, IrCryptoObjectKind::ThresholdSignature) && object.signer_role.is_none() {
            return Err(LoweringError::Unsupported(format!(
                "threshold_signature '{}' requires an explicit signer role",
                object.name
            )));
        }
        let conflict_policy = match object.conflict_policy {
            ast::CryptoConflictPolicy::Allow => CryptoConflictPolicy::Allow,
            ast::CryptoConflictPolicy::Exclusive => CryptoConflictPolicy::Exclusive,
        };
        let threshold = lower_linear_expr_to_lc(&object.threshold, &param_ids)?;
        let signer_role = object.signer_role.clone();
        crypto_objects.insert(
            object.name.clone(),
            CryptoObjectInfo {
                source_message: object.source_message.clone(),
                threshold: threshold.clone(),
                signer_role: signer_role.clone(),
                conflict_policy,
            },
        );
        ta.crypto_objects.insert(
            object.name.clone(),
            IrCryptoObjectSpec {
                name: object.name.clone(),
                kind,
                source_message: object.source_message.clone(),
                threshold,
                signer_role: signer_role.clone(),
                conflict_policy,
            },
        );
        // Crypto objects are authenticated by default unless explicitly overridden.
        ta.message_policies
            .entry(object.name.clone())
            .or_insert(MessagePolicy {
                auth: MessageAuthPolicy::Authenticated,
                equivocation: MessageEquivocationPolicy::Inherit,
            });
        message_infos.insert(
            object.name.clone(),
            MessageInfo {
                name: object.name.clone(),
                fields: source_info.fields.clone(),
            },
        );
    }
    let role_names: Vec<String> = proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let use_cohort_selective_channels = ta.network_semantics == NetworkSemantics::CohortSelective;
    let use_process_selective_channels = ta.network_semantics == NetworkSemantics::ProcessSelective;
    let role_process_identity_var: IndexMap<String, String> = ta
        .role_identities
        .iter()
        .filter_map(|(role, cfg)| {
            if cfg.scope == RoleIdentityScope::Process {
                cfg.process_var.as_ref().map(|v| (role.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect();
    let role_channels: IndexMap<String, Vec<String>> = role_names
        .iter()
        .map(|role| -> Result<(String, Vec<String>), LoweringError> {
            let channels = if use_cohort_selective_channels {
                (0..PROCESS_SELECTIVE_LANE_COUNT)
                    .map(|lane| format!("{role}#{lane}"))
                    .collect()
            } else if use_process_selective_channels {
                let role_decl = proto
                    .roles
                    .iter()
                    .find(|r| r.node.name == *role)
                    .map(|r| &r.node)
                    .ok_or_else(|| {
                        LoweringError::Unsupported(format!(
                            "Unknown role '{role}' while lowering process-selective channels"
                        ))
                    })?;
                let process_var = role_process_identity_var.get(role).ok_or_else(|| {
                    LoweringError::Unsupported(format!(
                        "Role '{role}' is missing process-scoped identity declaration for \
                         `network: process_selective`"
                    ))
                })?;
                process_selective_channels_for_role(role_decl, process_var)?
            } else {
                vec![role.clone()]
            };
            Ok((role.clone(), channels))
        })
        .collect::<Result<IndexMap<String, Vec<String>>, LoweringError>>()?;
    let mut msg_var_ids: IndexMap<String, SharedVarId> = IndexMap::new();
    let mut msg_var_message_type: IndexMap<SharedVarId, String> = IndexMap::new();
    let all_sender_channels: Vec<String> = role_channels
        .values()
        .flat_map(|channels| channels.iter().cloned())
        .collect();
    for msg_info in message_infos.values() {
        let mut combos = enumerate_field_values(&msg_info.fields);
        if combos.is_empty() {
            combos.push(Vec::new());
        }
        for channels in role_channels.values() {
            for recipient in channels {
                for values in &combos {
                    let sender_candidates: Vec<Option<&str>> =
                        if ta.network_semantics == NetworkSemantics::Classic {
                            vec![None]
                        } else {
                            all_sender_channels
                                .iter()
                                .map(|sender| Some(sender.as_str()))
                                .collect()
                        };
                    for sender in sender_candidates {
                        let id = ta.add_shared_var(SharedVar {
                            name: format_msg_counter_name(
                                &msg_info.name,
                                recipient,
                                sender,
                                &msg_info.fields,
                                values,
                            ),
                            kind: SharedVarKind::MessageCounter,
                            distinct: false,
                            distinct_role: None,
                        });
                        msg_var_ids.insert(msg_key(&msg_info.name, recipient, sender, values), id);
                        msg_var_message_type.insert(id, msg_info.name.clone());
                    }
                }
            }
        }
    }

    let crash_counter_var = if ta.fault_model == FaultModel::Crash {
        if ta.find_shared_var_by_name(INTERNAL_CRASH_COUNTER).is_some() {
            return Err(LoweringError::Unsupported(format!(
                "Internal crash counter name collision for '{INTERNAL_CRASH_COUNTER}'"
            )));
        }
        Some(ta.add_shared_var(SharedVar {
            name: INTERNAL_CRASH_COUNTER.into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        }))
    } else {
        None
    };

    let distinct_messages_by_role = collect_distinct_messages_by_role(proto);

    // 4. Process each role
    for role in &proto.roles {
        let role_decl = &role.node;
        let process_identity_var = ta
            .role_identities
            .get(&role_decl.name)
            .and_then(|cfg| {
                if cfg.scope == RoleIdentityScope::Process {
                    cfg.process_var.as_deref()
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_PROCESS_ID_VAR)
            .to_string();

        // Collect finite local variables (bool + enum)
        let mut local_var_types: IndexMap<String, LocalVarType> = IndexMap::new();
        let mut local_domains: Vec<(String, Vec<LocalValue>)> = Vec::new();

        for v in &role_decl.vars {
            if v.name.starts_with("__") {
                return Err(LoweringError::Unsupported(format!(
                    "Local variable names starting with '__' are reserved for internal instrumentation: '{}'",
                    v.name
                )));
            }
            match &v.ty {
                ast::VarType::Bool => {
                    if v.range.is_some() {
                        return Err(LoweringError::Unsupported(format!(
                            "Boolean variable '{}' cannot have a range",
                            v.name
                        )));
                    }
                    local_var_types.insert(v.name.clone(), LocalVarType::Bool);
                    local_domains.push((
                        v.name.clone(),
                        vec![LocalValue::Bool(false), LocalValue::Bool(true)],
                    ));
                }
                ast::VarType::Enum(enum_name) => {
                    if v.range.is_some() {
                        return Err(LoweringError::Unsupported(format!(
                            "Enum variable '{}' cannot have a range",
                            v.name
                        )));
                    }
                    let variants = enum_defs
                        .get(enum_name)
                        .ok_or_else(|| LoweringError::UnknownEnum(enum_name.clone()))?;
                    let domain: Vec<LocalValue> =
                        variants.iter().cloned().map(LocalValue::Enum).collect();
                    local_var_types.insert(v.name.clone(), LocalVarType::Enum(enum_name.clone()));
                    local_domains.push((v.name.clone(), domain));
                }
                ast::VarType::Nat | ast::VarType::Int => {
                    if let Some(range) = &v.range {
                        if range.max < range.min {
                            return Err(LoweringError::InvalidRange(
                                v.name.clone(),
                                range.min,
                                range.max,
                            ));
                        }
                        let mut values = Vec::new();
                        for val in range.min..=range.max {
                            values.push(LocalValue::Int(val));
                        }
                        local_var_types.insert(
                            v.name.clone(),
                            LocalVarType::Int {
                                min: range.min,
                                max: range.max,
                            },
                        );
                        local_domains.push((v.name.clone(), values));
                    } else {
                        tracing::warn!(
                            "Non-boolean local variable '{}' in role '{}' is not modeled in \
                             the counter abstraction. Only boolean, enum, and bounded int/nat \
                             variables create distinct locations; unbounded integer/nat variables \
                             are ignored.",
                            v.name,
                            role_decl.name
                        );
                    }
                }
            }
        }

        if ta.fault_model == FaultModel::Crash {
            if local_var_types.contains_key(INTERNAL_ALIVE_VAR) {
                return Err(LoweringError::Unsupported(format!(
                    "Local variable name collision with internal crash-state variable '{INTERNAL_ALIVE_VAR}'"
                )));
            }
            local_var_types.insert(INTERNAL_ALIVE_VAR.into(), LocalVarType::Bool);
            local_domains.push((
                INTERNAL_ALIVE_VAR.into(),
                vec![LocalValue::Bool(false), LocalValue::Bool(true)],
            ));
        }
        if use_cohort_selective_channels {
            if local_var_types.contains_key(INTERNAL_DELIVERY_LANE_VAR) {
                return Err(LoweringError::Unsupported(format!(
                    "Local variable name collision with internal delivery-lane variable '{INTERNAL_DELIVERY_LANE_VAR}'"
                )));
            }
            local_var_types.insert(
                INTERNAL_DELIVERY_LANE_VAR.into(),
                LocalVarType::Int {
                    min: 0,
                    max: PROCESS_SELECTIVE_LANE_COUNT - 1,
                },
            );
            let mut lane_values = Vec::new();
            for lane in 0..PROCESS_SELECTIVE_LANE_COUNT {
                lane_values.push(LocalValue::Int(lane));
            }
            local_domains.push((INTERNAL_DELIVERY_LANE_VAR.into(), lane_values));
        }
        if use_process_selective_channels {
            let pid_ty = local_var_types.get(&process_identity_var).ok_or_else(|| {
                LoweringError::Unsupported(format!(
                    "Role '{}' must declare `{process_identity_var}: nat/int in <min>..<max>` for \
                     `network: process_selective`",
                    role_decl.name
                ))
            })?;
            match pid_ty {
                LocalVarType::Int { min, .. } if *min >= 0 => {}
                LocalVarType::Int { .. } => {
                    return Err(LoweringError::Unsupported(format!(
                        "Role '{}' variable `{process_identity_var}` must have non-negative range for \
                         `network: process_selective`",
                        role_decl.name
                    )));
                }
                _ => {
                    return Err(LoweringError::Unsupported(format!(
                        "Role '{}' variable `{process_identity_var}` must be bounded nat/int for \
                         `network: process_selective`",
                        role_decl.name
                    )));
                }
            }
        }

        let mut lock_flag_by_object: IndexMap<String, String> = IndexMap::new();
        let mut justify_flag_by_object: IndexMap<String, String> = IndexMap::new();
        for object_name in crypto_objects.keys() {
            let lock_flag = internal_lock_flag_name(object_name);
            if local_var_types.contains_key(&lock_flag) {
                return Err(LoweringError::Unsupported(format!(
                    "Local variable name collision with internal lock flag '{lock_flag}'"
                )));
            }
            local_var_types.insert(lock_flag.clone(), LocalVarType::Bool);
            local_domains.push((
                lock_flag.clone(),
                vec![LocalValue::Bool(false), LocalValue::Bool(true)],
            ));
            lock_flag_by_object.insert(object_name.clone(), lock_flag);

            let justify_flag = internal_justify_flag_name(object_name);
            if local_var_types.contains_key(&justify_flag) {
                return Err(LoweringError::Unsupported(format!(
                    "Local variable name collision with internal justify flag '{justify_flag}'"
                )));
            }
            local_var_types.insert(justify_flag.clone(), LocalVarType::Bool);
            local_domains.push((
                justify_flag.clone(),
                vec![LocalValue::Bool(false), LocalValue::Bool(true)],
            ));
            justify_flag_by_object.insert(object_name.clone(), justify_flag);
        }

        // Automatic sender-uniqueness tracking for distinct guards:
        // if this role checks `received distinct` for message type M, every
        // sender process in this role gets per-counter `__sent_*` flags for
        // M-counters that this role can emit. This yields exact distinct-sender
        // semantics for those counters (including view-scoped counters).
        let distinct_msgs = distinct_messages_by_role
            .get(&role_decl.name)
            .cloned()
            .unwrap_or_default();
        let sent_msgs = collect_sent_messages_in_role(role_decl);
        let tracked_msgs: HashSet<String> = sent_msgs
            .iter()
            .filter(|msg| message_effective_authenticated(&ta, msg) || distinct_msgs.contains(*msg))
            .cloned()
            .collect();

        let mut sent_flag_by_var: IndexMap<SharedVarId, String> = IndexMap::new();
        if !tracked_msgs.is_empty() {
            for (var_id, msg_name) in &msg_var_message_type {
                if !tracked_msgs.contains(msg_name) {
                    continue;
                }
                let flag = format!("__sent_g{var_id}");
                if local_var_types.contains_key(&flag) {
                    return Err(LoweringError::Unsupported(format!(
                        "Local variable name collision with internal sender-uniqueness flag '{flag}'"
                    )));
                }
                local_var_types.insert(flag.clone(), LocalVarType::Bool);
                local_domains.push((
                    flag.clone(),
                    vec![LocalValue::Bool(false), LocalValue::Bool(true)],
                ));
                sent_flag_by_var.insert(*var_id, flag);
            }
        }

        let assignments = enumerate_local_assignments(&local_domains);
        let mut location_map: IndexMap<String, Vec<LocationId>> = IndexMap::new();

        for phase in &role_decl.phases {
            let phase_name = &phase.node.name;
            let mut locs_for_phase = Vec::new();

            for local_vars in &assignments {
                let loc_name = if local_domains.is_empty() {
                    format!("{}_{}", role_decl.name, phase_name)
                } else {
                    let var_str: Vec<String> =
                        local_vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    format!("{}_{}[{}]", role_decl.name, phase_name, var_str.join(","))
                };

                let lid = ta.add_location(Location {
                    name: loc_name,
                    role: role_decl.name.clone(),
                    phase: phase_name.clone(),
                    local_vars: local_vars.clone(),
                });
                locs_for_phase.push(lid);
            }
            location_map.insert(phase_name.clone(), locs_for_phase);
        }

        // Compute expected initial values for finite locals
        let mut initial_values: IndexMap<String, LocalValue> = IndexMap::new();
        for v in &role_decl.vars {
            match &v.ty {
                ast::VarType::Bool => {
                    let expected = match &v.init {
                        Some(ast::Expr::BoolLit(b)) => LocalValue::Bool(*b),
                        _ => LocalValue::Bool(false),
                    };
                    initial_values.insert(v.name.clone(), expected);
                }
                ast::VarType::Enum(enum_name) => {
                    let expected = match &v.init {
                        Some(expr) => eval_enum_literal(expr, enum_name, &enum_defs)?,
                        None => return Err(LoweringError::MissingEnumInit(v.name.clone())),
                    };
                    initial_values.insert(v.name.clone(), expected);
                }
                ast::VarType::Nat | ast::VarType::Int => {
                    if let Some(range) = &v.range {
                        if use_process_selective_channels
                            && v.name == process_identity_var
                            && v.init.is_some()
                        {
                            return Err(LoweringError::Unsupported(format!(
                                "`{process_identity_var}` must not have an explicit init under \
                                 `network: process_selective`; leave it unset to quantify over \
                                 all process identities"
                            )));
                        }
                        let init_val = if let Some(expr) = &v.init {
                            eval_int_expr(expr, &IndexMap::new())?
                        } else if use_process_selective_channels && v.name == process_identity_var {
                            // Process identity is not initialized to one concrete value:
                            // all pid-domain locations are valid initial states.
                            continue;
                        } else {
                            range.min
                        };
                        if init_val < range.min || init_val > range.max {
                            return Err(LoweringError::OutOfRange {
                                var: v.name.clone(),
                                value: init_val,
                                min: range.min,
                                max: range.max,
                            });
                        }
                        initial_values.insert(v.name.clone(), LocalValue::Int(init_val));
                    }
                }
            }
        }

        for flag in sent_flag_by_var.values() {
            initial_values.insert(flag.clone(), LocalValue::Bool(false));
        }
        for flag in lock_flag_by_object.values() {
            initial_values.insert(flag.clone(), LocalValue::Bool(false));
        }
        for flag in justify_flag_by_object.values() {
            initial_values.insert(flag.clone(), LocalValue::Bool(false));
        }
        if ta.fault_model == FaultModel::Crash {
            initial_values.insert(INTERNAL_ALIVE_VAR.into(), LocalValue::Bool(true));
        }

        // Set initial locations
        if let Some(ref init) = role_decl.init_phase {
            if let Some(locs) = location_map.get(init) {
                // Find the location(s) matching initial variable values
                for &lid in locs {
                    let loc = &ta.locations[lid];
                    let is_initial = initial_values
                        .iter()
                        .all(|(name, expected)| loc.local_vars.get(name) == Some(expected));
                    if is_initial {
                        ta.initial_locations.push(lid);
                    }
                }
            } else {
                return Err(LoweringError::UnknownPhase(init.clone()));
            }
        } else if !role_decl.phases.is_empty() {
            return Err(LoweringError::NoInitPhase(role_decl.name.clone()));
        }

        // 5. Process transitions for each phase
        for phase in &role_decl.phases {
            let phase_name = &phase.node.name;
            let from_locs = location_map.get(phase_name).cloned().unwrap_or_default();

            for transition in &phase.node.transitions {
                let trans = &transition.node;

                // Determine target phase and variable updates
                let mut target_phase = phase_name.clone();
                let mut assigns: Vec<(String, ast::Expr)> = Vec::new();
                let mut pending_actions: Vec<PendingTransitionAction> = Vec::new();
                let mut decide_value: Option<ast::Expr> = None;

                for action in &trans.actions {
                    match action {
                        ast::Action::GotoPhase { phase } => {
                            target_phase = phase.clone();
                        }
                        ast::Action::Assign { var, value } => {
                            assigns.push((var.clone(), value.clone()));
                        }
                        ast::Action::Send {
                            message_type,
                            args,
                            recipient_role,
                        } => {
                            pending_actions.push(PendingTransitionAction::Send {
                                message_type: message_type.clone(),
                                args: args.clone(),
                                recipient_role: recipient_role.clone(),
                            });
                        }
                        ast::Action::FormCryptoObject {
                            object_name,
                            args,
                            recipient_role,
                        } => {
                            pending_actions.push(PendingTransitionAction::FormCryptoObject {
                                object_name: object_name.clone(),
                                args: args.clone(),
                                recipient_role: recipient_role.clone(),
                            });
                        }
                        ast::Action::LockCryptoObject { object_name, args } => {
                            pending_actions.push(PendingTransitionAction::LockCryptoObject {
                                object_name: object_name.clone(),
                                args: args.clone(),
                            });
                        }
                        ast::Action::JustifyCryptoObject { object_name, args } => {
                            pending_actions.push(PendingTransitionAction::JustifyCryptoObject {
                                object_name: object_name.clone(),
                                args: args.clone(),
                            });
                        }
                        ast::Action::Decide { value } => {
                            if decide_value.is_some() {
                                return Err(LoweringError::Unsupported(
                                    "Multiple decide actions in a single transition are not supported"
                                        .into(),
                                ));
                            }
                            decide_value = Some(value.clone());
                        }
                    }
                }

                if let Some(decide_expr) = decide_value {
                    let mut mapped = false;
                    let has_decided_assign = assigns.iter().any(|(name, _)| name == "decided");
                    let has_decision_assign = assigns.iter().any(|(name, _)| name == "decision");

                    if has_decided_assign
                        || matches!(local_var_types.get("decided"), Some(LocalVarType::Bool))
                    {
                        if !has_decided_assign
                            && matches!(local_var_types.get("decided"), Some(LocalVarType::Bool))
                        {
                            assigns.push(("decided".into(), ast::Expr::BoolLit(true)));
                        }
                        mapped = true;
                    }
                    if has_decision_assign || local_var_types.contains_key("decision") {
                        if !has_decision_assign && local_var_types.contains_key("decision") {
                            assigns.push(("decision".into(), decide_expr));
                        }
                        mapped = true;
                    }

                    if !mapped && matches!(local_var_types.get("decided"), Some(LocalVarType::Bool))
                    {
                        // `decide` still implies `decided=true` if that variable exists,
                        // even if there is no `decision` variable.
                        assigns.push(("decided".into(), ast::Expr::BoolLit(true)));
                        mapped = true;
                    }
                    if !mapped {
                        return Err(LoweringError::Unsupported(
                            "`decide ...;` requires local variable `decided: bool` and/or \
                             `decision`."
                                .into(),
                        ));
                    }
                }

                let to_locs = location_map
                    .get(&target_phase)
                    .ok_or_else(|| LoweringError::UnknownPhase(target_phase.clone()))?;

                // Expand OR-guards to disjunctive normal form and lower each
                // disjunct into a separate threshold-automaton rule.
                let guard_clauses = guard_to_dnf_clauses(&trans.guard);

                for guard_clause in &guard_clauses {
                    // Create rules for each matching (from, to) location pair,
                    // filtering source locations by local guard requirements.
                    for &from_lid in &from_locs {
                        let from_loc = &ta.locations[from_lid];
                        if ta.fault_model == FaultModel::Crash
                            && from_loc.local_vars.get(INTERNAL_ALIVE_VAR)
                                != Some(&LocalValue::Bool(true))
                        {
                            continue;
                        }

                        // Check local guard conditions against source location.
                        if !local_guard_satisfied(
                            guard_clause,
                            &from_loc.local_vars,
                            &local_var_types,
                            &enum_defs,
                        )? {
                            continue;
                        }
                        let current_recipient_channel = recipient_channel_for_location(
                            &role_decl.name,
                            &from_loc.local_vars,
                            ta.network_semantics,
                            &process_identity_var,
                        )?;
                        let sender_channel_opt =
                            if ta.network_semantics == NetworkSemantics::Classic {
                                None
                            } else {
                                Some(current_recipient_channel.as_str())
                            };

                        // Build guard (only threshold guards survive; local
                        // bool/comparison guards are enforced by location filtering).
                        let mut guard = lower_guard(
                            guard_clause,
                            &msg_var_ids,
                            &message_infos,
                            &param_ids,
                            &from_loc.local_vars,
                            &local_var_types,
                            &enum_defs,
                            &role_channels,
                            current_recipient_channel.as_str(),
                            &role_decl.name,
                        )?;

                        // Build updates (message sends), resolved for this location.
                        let mut updates = Vec::new();
                        let mut send_blocked_by_uniqueness = false;
                        let mut set_sent_flags: HashSet<String> = HashSet::new();
                        let mut set_lock_flags: HashSet<String> = HashSet::new();
                        let mut set_justify_flags: HashSet<String> = HashSet::new();

                        for action in &pending_actions {
                            match action {
                                PendingTransitionAction::Send {
                                    message_type,
                                    args,
                                    recipient_role,
                                } => {
                                    let var_ids = resolve_message_counter_from_send(
                                        message_type,
                                        recipient_role.as_deref(),
                                        None,
                                        sender_channel_opt,
                                        None,
                                        &role_names,
                                        &role_channels,
                                        args,
                                        &message_infos,
                                        &msg_var_ids,
                                        &from_loc.local_vars,
                                        &local_var_types,
                                        &enum_defs,
                                    )?;
                                    for var_id in var_ids {
                                        if let Some(flag) = sent_flag_by_var.get(&var_id) {
                                            if from_loc.local_vars.get(flag)
                                                != Some(&LocalValue::Bool(false))
                                            {
                                                send_blocked_by_uniqueness = true;
                                                break;
                                            }
                                            set_sent_flags.insert(flag.clone());
                                        }
                                        updates.push(Update {
                                            var: var_id,
                                            kind: UpdateKind::Increment,
                                        });
                                    }
                                }
                                PendingTransitionAction::FormCryptoObject {
                                    object_name,
                                    args,
                                    recipient_role,
                                } => {
                                    let object =
                                        crypto_objects.get(object_name).ok_or_else(|| {
                                            LoweringError::Unsupported(format!(
                                            "Unknown crypto object '{object_name}' in form action"
                                        ))
                                        })?;
                                    let source_vars = resolve_message_counter_from_send(
                                        &object.source_message,
                                        None,
                                        Some(current_recipient_channel.as_str()),
                                        None,
                                        object.signer_role.as_deref(),
                                        &role_names,
                                        &role_channels,
                                        args,
                                        &message_infos,
                                        &msg_var_ids,
                                        &from_loc.local_vars,
                                        &local_var_types,
                                        &enum_defs,
                                    )?;
                                    if source_vars.is_empty() {
                                        return Err(LoweringError::Unsupported(format!(
                                            "Unable to resolve source message '{}' for crypto object '{}'",
                                            object.source_message, object_name
                                        )));
                                    }
                                    guard.atoms.push(GuardAtom::Threshold {
                                        vars: source_vars,
                                        op: CmpOp::Ge,
                                        bound: object.threshold.clone(),
                                        distinct: true,
                                    });

                                    let var_ids = resolve_message_counter_from_send(
                                        object_name,
                                        recipient_role.as_deref(),
                                        None,
                                        sender_channel_opt,
                                        None,
                                        &role_names,
                                        &role_channels,
                                        args,
                                        &message_infos,
                                        &msg_var_ids,
                                        &from_loc.local_vars,
                                        &local_var_types,
                                        &enum_defs,
                                    )?;
                                    for var_id in &var_ids {
                                        if let Some(flag) = sent_flag_by_var.get(var_id) {
                                            if from_loc.local_vars.get(flag)
                                                != Some(&LocalValue::Bool(false))
                                            {
                                                send_blocked_by_uniqueness = true;
                                                break;
                                            }
                                            set_sent_flags.insert(flag.clone());
                                        }
                                        updates.push(Update {
                                            var: *var_id,
                                            kind: UpdateKind::Increment,
                                        });
                                    }
                                    if object.conflict_policy == CryptoConflictPolicy::Exclusive {
                                        append_exclusive_conflict_guard(
                                            &ta,
                                            &mut guard,
                                            object_name,
                                            current_recipient_channel.as_str(),
                                            &var_ids,
                                        );
                                    }
                                }
                                PendingTransitionAction::LockCryptoObject { object_name, args } => {
                                    let object =
                                        crypto_objects.get(object_name).ok_or_else(|| {
                                            LoweringError::Unsupported(format!(
                                            "Unknown crypto object '{object_name}' in lock action"
                                        ))
                                        })?;
                                    let lock_flag = lock_flag_by_object
                                        .get(object_name)
                                        .ok_or_else(|| {
                                            LoweringError::Unsupported(format!(
                                                "Unknown crypto object '{object_name}' in lock action"
                                            ))
                                        })?;
                                    let object_vars = resolve_message_counter_from_send(
                                        object_name,
                                        None,
                                        Some(current_recipient_channel.as_str()),
                                        None,
                                        None,
                                        &role_names,
                                        &role_channels,
                                        args,
                                        &message_infos,
                                        &msg_var_ids,
                                        &from_loc.local_vars,
                                        &local_var_types,
                                        &enum_defs,
                                    )?;
                                    if object_vars.is_empty() {
                                        return Err(LoweringError::Unsupported(format!(
                                            "Unable to resolve crypto object '{object_name}' in lock action"
                                        )));
                                    }
                                    guard.atoms.push(GuardAtom::Threshold {
                                        vars: object_vars.clone(),
                                        op: CmpOp::Ge,
                                        bound: LinearCombination::constant(1),
                                        distinct: false,
                                    });
                                    if object.conflict_policy == CryptoConflictPolicy::Exclusive {
                                        append_exclusive_conflict_guard(
                                            &ta,
                                            &mut guard,
                                            object_name,
                                            current_recipient_channel.as_str(),
                                            &object_vars,
                                        );
                                    }
                                    set_lock_flags.insert(lock_flag.clone());
                                }
                                PendingTransitionAction::JustifyCryptoObject {
                                    object_name,
                                    args,
                                } => {
                                    let object = crypto_objects.get(object_name).ok_or_else(|| {
                                        LoweringError::Unsupported(format!(
                                            "Unknown crypto object '{object_name}' in justify action"
                                        ))
                                    })?;
                                    let justify_flag = justify_flag_by_object
                                        .get(object_name)
                                        .ok_or_else(|| {
                                            LoweringError::Unsupported(format!(
                                                "Unknown crypto object '{object_name}' in justify action"
                                            ))
                                        })?;
                                    let object_vars = resolve_message_counter_from_send(
                                        object_name,
                                        None,
                                        Some(current_recipient_channel.as_str()),
                                        None,
                                        None,
                                        &role_names,
                                        &role_channels,
                                        args,
                                        &message_infos,
                                        &msg_var_ids,
                                        &from_loc.local_vars,
                                        &local_var_types,
                                        &enum_defs,
                                    )?;
                                    if object_vars.is_empty() {
                                        return Err(LoweringError::Unsupported(format!(
                                            "Unable to resolve crypto object '{object_name}' in justify action"
                                        )));
                                    }
                                    guard.atoms.push(GuardAtom::Threshold {
                                        vars: object_vars.clone(),
                                        op: CmpOp::Ge,
                                        bound: LinearCombination::constant(1),
                                        distinct: false,
                                    });
                                    if object.conflict_policy == CryptoConflictPolicy::Exclusive {
                                        append_exclusive_conflict_guard(
                                            &ta,
                                            &mut guard,
                                            object_name,
                                            current_recipient_channel.as_str(),
                                            &object_vars,
                                        );
                                    }
                                    set_justify_flags.insert(justify_flag.clone());
                                }
                            }
                            if send_blocked_by_uniqueness {
                                break;
                            }
                        }
                        if send_blocked_by_uniqueness {
                            continue;
                        }

                        // Determine which target location this maps to.
                        let mut target_vars = from_loc.local_vars.clone();
                        let mut assignment_valid = true;
                        for (k, expr) in &assigns {
                            if k.starts_with("__") {
                                return Err(LoweringError::Unsupported(format!(
                                    "Assignment to internal variable '{k}' is not allowed"
                                )));
                            }
                            if ta
                                .role_identities
                                .get(&role_decl.name)
                                .map(|cfg| cfg.scope == RoleIdentityScope::Process)
                                .unwrap_or(false)
                                && k == &process_identity_var
                            {
                                return Err(LoweringError::Unsupported(format!(
                                    "`{process_identity_var}` is an identity variable and is immutable"
                                )));
                            }
                            let ty = local_var_types.get(k).ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Assignment to unsupported local variable '{k}'"
                                ))
                            })?;
                            match eval_local_expr(k, expr, ty, &from_loc.local_vars, &enum_defs) {
                                Ok(new_val) => {
                                    target_vars.insert(k.clone(), new_val);
                                }
                                Err(LoweringError::OutOfRange { .. }) => {
                                    assignment_valid = false;
                                    break;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        for flag in &set_sent_flags {
                            target_vars.insert(flag.clone(), LocalValue::Bool(true));
                        }
                        for flag in &set_lock_flags {
                            target_vars.insert(flag.clone(), LocalValue::Bool(true));
                        }
                        for flag in &set_justify_flags {
                            target_vars.insert(flag.clone(), LocalValue::Bool(true));
                        }
                        if !assignment_valid {
                            continue;
                        }

                        // Find matching target location.
                        for &to_lid in to_locs {
                            let to_loc = &ta.locations[to_lid];
                            if to_loc.local_vars == target_vars {
                                ta.add_rule(Rule {
                                    from: from_lid,
                                    to: to_lid,
                                    guard: guard.clone(),
                                    updates: updates.clone(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 6. Inject pacemaker (automatic view changes), if configured
        if let Some(pm) = pacemaker {
            if let Some(view_ty) = local_var_types.get(&pm.view_var) {
                let (view_min, view_max) = match view_ty {
                    LocalVarType::Int { min, max } => (*min, *max),
                    _ => {
                        return Err(LoweringError::Unsupported(format!(
                            "Pacemaker view variable '{}' must be a bounded int/nat",
                            pm.view_var
                        )));
                    }
                };

                let start_locs = location_map
                    .get(&pm.start_phase)
                    .ok_or_else(|| LoweringError::UnknownPhase(pm.start_phase.clone()))?;

                for reset in &pm.reset_vars {
                    if !initial_values.contains_key(reset) {
                        return Err(LoweringError::Unsupported(format!(
                            "Pacemaker reset variable '{reset}' not found in role '{}'",
                            role_decl.name
                        )));
                    }
                }

                for phase in &role_decl.phases {
                    let from_locs = location_map
                        .get(&phase.node.name)
                        .cloned()
                        .unwrap_or_default();
                    for &from_lid in &from_locs {
                        let from_loc = &ta.locations[from_lid];
                        if ta.fault_model == FaultModel::Crash
                            && from_loc.local_vars.get(INTERNAL_ALIVE_VAR)
                                != Some(&LocalValue::Bool(true))
                        {
                            continue;
                        }
                        let current_view = match from_loc.local_vars.get(&pm.view_var) {
                            Some(LocalValue::Int(v)) => *v,
                            _ => {
                                return Err(LoweringError::Unsupported(format!(
                                    "Pacemaker view variable '{}' is not integer-valued",
                                    pm.view_var
                                )));
                            }
                        };
                        let next_view = current_view + 1;
                        if next_view > view_max || next_view < view_min {
                            continue;
                        }

                        let mut target_vars = from_loc.local_vars.clone();
                        target_vars.insert(pm.view_var.clone(), LocalValue::Int(next_view));
                        for reset in &pm.reset_vars {
                            if let Some(init_val) = initial_values.get(reset) {
                                target_vars.insert(reset.clone(), init_val.clone());
                            }
                        }

                        for &to_lid in start_locs {
                            let to_loc = &ta.locations[to_lid];
                            if to_loc.local_vars == target_vars {
                                ta.add_rule(Rule {
                                    from: from_lid,
                                    to: to_lid,
                                    guard: Guard::trivial(),
                                    updates: Vec::new(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 7. Inject crash-stop transitions, if configured.
        //
        // Semantics:
        // - user transitions are only enabled from `__alive=true` locations
        // - a crash transition can move any alive process to the matching
        //   dead location in the same phase
        // - each crash increments `__crashed_count`; encoder bounds it by `f`
        if ta.fault_model == FaultModel::Crash {
            let crash_counter_var = crash_counter_var.expect("crash counter should exist");
            for phase in &role_decl.phases {
                let phase_locs = location_map
                    .get(&phase.node.name)
                    .cloned()
                    .unwrap_or_default();
                for &from_lid in &phase_locs {
                    let from_loc = &ta.locations[from_lid];
                    if from_loc.local_vars.get(INTERNAL_ALIVE_VAR) != Some(&LocalValue::Bool(true))
                    {
                        continue;
                    }

                    let mut target_vars = from_loc.local_vars.clone();
                    target_vars.insert(INTERNAL_ALIVE_VAR.into(), LocalValue::Bool(false));

                    for &to_lid in &phase_locs {
                        let to_loc = &ta.locations[to_lid];
                        if to_loc.local_vars == target_vars {
                            ta.add_rule(Rule {
                                from: from_lid,
                                to: to_lid,
                                guard: Guard::trivial(),
                                updates: vec![Update {
                                    var: crash_counter_var,
                                    kind: UpdateKind::Increment,
                                }],
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    validate_identity_and_key_invariants(&ta)?;

    Ok(ta)
}

fn collect_params_from_linear_expr(
    expr: &ast::LinearExpr,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    match expr {
        ast::LinearExpr::Const(_) => {}
        ast::LinearExpr::Var(name) => {
            if seen.insert(name.clone()) {
                out.push(name.clone());
            }
        }
        ast::LinearExpr::Add(lhs, rhs) | ast::LinearExpr::Sub(lhs, rhs) => {
            collect_params_from_linear_expr(lhs, out, seen);
            collect_params_from_linear_expr(rhs, out, seen);
        }
        ast::LinearExpr::Mul(_, inner) => {
            collect_params_from_linear_expr(inner, out, seen);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn lower_guard(
    guard: &ast::GuardExpr,
    msg_vars: &IndexMap<String, SharedVarId>,
    message_infos: &IndexMap<String, MessageInfo>,
    params: &IndexMap<String, ParamId>,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
    role_channels: &IndexMap<String, Vec<String>>,
    recipient_channel: &str,
    role_name: &str,
) -> Result<Guard, LoweringError> {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            let sender_role = if tg.distinct {
                Some(tg.distinct_role.as_deref().unwrap_or(role_name))
            } else {
                None
            };
            let var_ids = resolve_message_counter_from_guard(
                &tg.message_type,
                recipient_channel,
                &tg.message_args,
                sender_role,
                role_channels,
                message_infos,
                msg_vars,
                locals,
                local_var_types,
                enum_defs,
            )?;
            let bound = lower_linear_expr_to_lc(&tg.threshold, params)?;
            let op = lower_cmp_op(tg.op);
            Ok(Guard::single(GuardAtom::Threshold {
                vars: var_ids,
                op,
                bound,
                distinct: tg.distinct,
            }))
        }
        ast::GuardExpr::HasCryptoObject {
            object_name,
            object_args,
        } => {
            let var_ids = resolve_message_counter_from_guard(
                object_name,
                recipient_channel,
                object_args,
                None,
                role_channels,
                message_infos,
                msg_vars,
                locals,
                local_var_types,
                enum_defs,
            )?;
            Ok(Guard::single(GuardAtom::Threshold {
                vars: var_ids,
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }))
        }
        ast::GuardExpr::And(lhs, rhs) => {
            let mut lg = lower_guard(
                lhs,
                msg_vars,
                message_infos,
                params,
                locals,
                local_var_types,
                enum_defs,
                role_channels,
                recipient_channel,
                role_name,
            )?;
            let rg = lower_guard(
                rhs,
                msg_vars,
                message_infos,
                params,
                locals,
                local_var_types,
                enum_defs,
                role_channels,
                recipient_channel,
                role_name,
            )?;
            lg.atoms.extend(rg.atoms);
            Ok(lg)
        }
        ast::GuardExpr::Comparison { .. } => {
            // Comparison guards on local vars are enforced by filtering
            // source locations in extract_local_guard_requirements().
            // Return trivial guard for the threshold-level encoding.
            Ok(Guard::trivial())
        }
        ast::GuardExpr::BoolVar(_) => {
            // Boolean var guards are enforced by filtering source locations
            // in extract_local_guard_requirements().
            Ok(Guard::trivial())
        }
        ast::GuardExpr::Or(_, _) => Err(LoweringError::Unsupported(
            "OR guards not yet supported in threshold automata".into(),
        )),
    }
}

fn lower_linear_expr_to_lc(
    expr: &ast::LinearExpr,
    params: &IndexMap<String, ParamId>,
) -> Result<LinearCombination, LoweringError> {
    match expr {
        ast::LinearExpr::Const(c) => Ok(LinearCombination::constant(*c)),
        ast::LinearExpr::Var(name) => {
            if let Some(&pid) = params.get(name) {
                Ok(LinearCombination::param(pid))
            } else {
                Err(LoweringError::UnknownParameter(name.clone()))
            }
        }
        ast::LinearExpr::Add(lhs, rhs) => {
            let l = lower_linear_expr_to_lc(lhs, params)?;
            let r = lower_linear_expr_to_lc(rhs, params)?;
            Ok(l.add(&r))
        }
        ast::LinearExpr::Sub(lhs, rhs) => {
            let l = lower_linear_expr_to_lc(lhs, params)?;
            let r = lower_linear_expr_to_lc(rhs, params)?;
            Ok(l.sub(&r))
        }
        ast::LinearExpr::Mul(coeff, inner) => {
            let r = lower_linear_expr_to_lc(inner, params)?;
            Ok(r.scale(*coeff))
        }
    }
}

fn guard_to_dnf_clauses(guard: &ast::GuardExpr) -> Vec<ast::GuardExpr> {
    match guard {
        ast::GuardExpr::Or(lhs, rhs) => {
            let mut clauses = guard_to_dnf_clauses(lhs);
            clauses.extend(guard_to_dnf_clauses(rhs));
            clauses
        }
        ast::GuardExpr::And(lhs, rhs) => {
            let left = guard_to_dnf_clauses(lhs);
            let right = guard_to_dnf_clauses(rhs);
            let mut out = Vec::new();
            for l in &left {
                for r in &right {
                    out.push(ast::GuardExpr::And(
                        Box::new(l.clone()),
                        Box::new(r.clone()),
                    ));
                }
            }
            out
        }
        _ => vec![guard.clone()],
    }
}

fn lower_committee_value(
    value: &ast::CommitteeValue,
    params: &IndexMap<String, ParamId>,
) -> Result<ParamOrConst, LoweringError> {
    match value {
        ast::CommitteeValue::Int(n) => Ok(ParamOrConst::Const(*n)),
        ast::CommitteeValue::Float(_) => Err(LoweringError::Unsupported(
            "Float values are only allowed for committee epsilon".into(),
        )),
        ast::CommitteeValue::Param(name) => {
            if let Some(&pid) = params.get(name) {
                Ok(ParamOrConst::Param(pid))
            } else {
                Err(LoweringError::UnknownParameter(name.clone()))
            }
        }
    }
}

fn lower_cmp_op(op: ast::CmpOp) -> CmpOp {
    match op {
        ast::CmpOp::Ge => CmpOp::Ge,
        ast::CmpOp::Le => CmpOp::Le,
        ast::CmpOp::Gt => CmpOp::Gt,
        ast::CmpOp::Lt => CmpOp::Lt,
        ast::CmpOp::Eq => CmpOp::Eq,
        ast::CmpOp::Ne => CmpOp::Ne,
    }
}

fn enumerate_local_assignments(
    domains: &[(String, Vec<LocalValue>)],
) -> Vec<IndexMap<String, LocalValue>> {
    let mut assignments: Vec<IndexMap<String, LocalValue>> = vec![IndexMap::new()];
    for (name, values) in domains {
        let mut next = Vec::new();
        for assign in &assignments {
            for val in values {
                let mut new_assign = assign.clone();
                new_assign.insert(name.clone(), val.clone());
                next.push(new_assign);
            }
        }
        assignments = next;
    }
    assignments
}

fn abstract_nat_values_sign(min: i64, max: i64) -> Vec<String> {
    let mut out = Vec::new();
    if min <= 0 && 0 <= max {
        out.push("zero".to_string());
    }
    if max >= 1 {
        out.push("pos".to_string());
    }
    out
}

fn abstract_int_values_sign(min: i64, max: i64) -> Vec<String> {
    let mut out = Vec::new();
    if min <= -1 {
        out.push("neg".to_string());
    }
    if min <= 0 && 0 <= max {
        out.push("zero".to_string());
    }
    if max >= 1 {
        out.push("pos".to_string());
    }
    out
}

fn build_message_infos(
    messages: &[ast::MessageDecl],
    enum_defs: &IndexMap<String, Vec<String>>,
    value_abstraction: ValueAbstractionMode,
) -> Result<IndexMap<String, MessageInfo>, LoweringError> {
    let mut infos: IndexMap<String, MessageInfo> = IndexMap::new();
    for msg in messages {
        let mut fields = Vec::new();
        for f in &msg.fields {
            let domain = match f.ty.as_str() {
                "bool" => FieldDomain::Bool,
                "nat" => match value_abstraction {
                    ValueAbstractionMode::Exact => {
                        let range = f.range.as_ref().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Message field '{}' in '{}' with type nat must use a finite range \
                                     (e.g., `in 0..4`) unless `adversary {{ values: sign; }}` is enabled",
                                    f.name, msg.name
                                ))
                            })?;
                        if range.min < 0 || range.max < range.min {
                            return Err(LoweringError::Unsupported(format!(
                                "Invalid nat range for message field '{}' in '{}': {}..{}",
                                f.name, msg.name, range.min, range.max
                            )));
                        }
                        FieldDomain::Int {
                            min: range.min,
                            max: range.max,
                        }
                    }
                    ValueAbstractionMode::Sign => {
                        let values = if let Some(range) = &f.range {
                            if range.min < 0 || range.max < range.min {
                                return Err(LoweringError::Unsupported(format!(
                                    "Invalid nat range for message field '{}' in '{}': {}..{}",
                                    f.name, msg.name, range.min, range.max
                                )));
                            }
                            abstract_nat_values_sign(range.min, range.max)
                        } else {
                            vec!["zero".into(), "pos".into()]
                        };
                        FieldDomain::AbstractNatSign(values)
                    }
                },
                "int" => match value_abstraction {
                    ValueAbstractionMode::Exact => {
                        let range = f.range.as_ref().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Message field '{}' in '{}' with type int must use a finite range \
                                     (e.g., `in 0..4`) unless `adversary {{ values: sign; }}` is enabled",
                                    f.name, msg.name
                                ))
                            })?;
                        if range.max < range.min {
                            return Err(LoweringError::Unsupported(format!(
                                "Invalid int range for message field '{}' in '{}': {}..{}",
                                f.name, msg.name, range.min, range.max
                            )));
                        }
                        FieldDomain::Int {
                            min: range.min,
                            max: range.max,
                        }
                    }
                    ValueAbstractionMode::Sign => {
                        let values = if let Some(range) = &f.range {
                            if range.max < range.min {
                                return Err(LoweringError::Unsupported(format!(
                                    "Invalid int range for message field '{}' in '{}': {}..{}",
                                    f.name, msg.name, range.min, range.max
                                )));
                            }
                            abstract_int_values_sign(range.min, range.max)
                        } else {
                            vec!["neg".into(), "zero".into(), "pos".into()]
                        };
                        FieldDomain::AbstractIntSign(values)
                    }
                },
                other => {
                    if f.range.is_some() {
                        return Err(LoweringError::Unsupported(format!(
                            "Message field '{}' in '{}' uses range syntax but type '{}' is not int/nat",
                            f.name, msg.name, other
                        )));
                    }
                    let variants = enum_defs
                        .get(other)
                        .ok_or_else(|| LoweringError::UnknownEnum(other.to_string()))?;
                    FieldDomain::Enum(variants.clone())
                }
            };
            fields.push(MessageFieldInfo {
                name: f.name.clone(),
                domain,
            });
        }
        infos.insert(
            msg.name.clone(),
            MessageInfo {
                name: msg.name.clone(),
                fields,
            },
        );
    }
    Ok(infos)
}

fn enumerate_field_values(fields: &[MessageFieldInfo]) -> Vec<Vec<String>> {
    let mut results: Vec<Vec<String>> = vec![Vec::new()];
    for field in fields {
        let values: Vec<String> = match &field.domain {
            FieldDomain::Bool => vec!["false".into(), "true".into()],
            FieldDomain::Enum(variants) => variants.clone(),
            FieldDomain::Int { min, max } => {
                let mut vals = Vec::new();
                for v in *min..=*max {
                    vals.push(v.to_string());
                }
                vals
            }
            FieldDomain::AbstractNatSign(values) | FieldDomain::AbstractIntSign(values) => {
                values.clone()
            }
        };
        let mut next = Vec::new();
        for prefix in &results {
            for v in &values {
                let mut new = prefix.clone();
                new.push(v.clone());
                next.push(new);
            }
        }
        results = next;
    }
    results
}

fn msg_key(
    name: &str,
    recipient_role: &str,
    sender_channel: Option<&str>,
    values: &[String],
) -> String {
    let sender_part = sender_channel.map(|s| format!("<-{s}")).unwrap_or_default();
    if values.is_empty() {
        format!("{name}@{recipient_role}{sender_part}")
    } else {
        format!("{name}@{recipient_role}{sender_part}|{}", values.join("|"))
    }
}

fn object_counter_vars_for_recipient(
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
        .map(|(var_id, _)| var_id)
        .collect()
}

fn append_exclusive_conflict_guard(
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

fn recipient_channel_for_location(
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

fn format_msg_counter_name(
    name: &str,
    recipient_role: &str,
    sender_channel: Option<&str>,
    fields: &[MessageFieldInfo],
    values: &[String],
) -> String {
    let sender_suffix = sender_channel
        .map(|sender| format!("<-{sender}"))
        .unwrap_or_default();
    if fields.is_empty() {
        format!("cnt_{name}@{recipient_role}{sender_suffix}")
    } else {
        let parts: Vec<String> = fields
            .iter()
            .zip(values.iter())
            .map(|(f, v)| format!("{}={}", f.name, v))
            .collect();
        format!(
            "cnt_{name}@{recipient_role}{sender_suffix}[{}]",
            parts.join(",")
        )
    }
}

fn eval_enum_literal(
    expr: &ast::Expr,
    enum_name: &str,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<LocalValue, LoweringError> {
    let variants = enum_defs
        .get(enum_name)
        .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
    match expr {
        ast::Expr::Var(name) => {
            if variants.contains(name) {
                Ok(LocalValue::Enum(name.clone()))
            } else {
                Err(LoweringError::UnknownEnumVariant(
                    name.clone(),
                    enum_name.to_string(),
                ))
            }
        }
        _ => Err(LoweringError::Unsupported(format!(
            "Enum literal expected for type '{enum_name}'"
        ))),
    }
}

fn eval_bool_expr(
    expr: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
) -> Result<bool, LoweringError> {
    match expr {
        ast::Expr::BoolLit(b) => Ok(*b),
        ast::Expr::Var(name) => match locals.get(name) {
            Some(LocalValue::Bool(b)) => Ok(*b),
            _ => Err(LoweringError::Unsupported(format!(
                "Unknown boolean local variable '{name}'"
            ))),
        },
        ast::Expr::Not(inner) => Ok(!eval_bool_expr(inner, locals)?),
        _ => Err(LoweringError::Unsupported(
            "Unsupported boolean expression in assignment".into(),
        )),
    }
}

fn eval_int_expr(
    expr: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
) -> Result<i64, LoweringError> {
    match expr {
        ast::Expr::IntLit(n) => Ok(*n),
        ast::Expr::Var(name) => match locals.get(name) {
            Some(LocalValue::Int(v)) => Ok(*v),
            Some(LocalValue::Bool(_)) | Some(LocalValue::Enum(_)) => Err(
                LoweringError::Unsupported(format!("Variable '{name}' is not an integer")),
            ),
            None => Err(LoweringError::Unsupported(format!(
                "Unknown integer local variable '{name}'"
            ))),
        },
        ast::Expr::Add(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? + eval_int_expr(rhs, locals)?),
        ast::Expr::Sub(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? - eval_int_expr(rhs, locals)?),
        ast::Expr::Mul(lhs, rhs) => Ok(eval_int_expr(lhs, locals)? * eval_int_expr(rhs, locals)?),
        ast::Expr::Div(lhs, rhs) => {
            let denom = eval_int_expr(rhs, locals)?;
            if denom == 0 {
                return Err(LoweringError::Unsupported(
                    "Division by zero in integer expression".into(),
                ));
            }
            Ok(eval_int_expr(lhs, locals)? / denom)
        }
        ast::Expr::Neg(inner) => Ok(-eval_int_expr(inner, locals)?),
        _ => Err(LoweringError::Unsupported(
            "Unsupported integer expression".into(),
        )),
    }
}

fn eval_local_expr(
    var_name: &str,
    expr: &ast::Expr,
    ty: &LocalVarType,
    locals: &IndexMap<String, LocalValue>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<LocalValue, LoweringError> {
    match ty {
        LocalVarType::Bool => Ok(LocalValue::Bool(eval_bool_expr(expr, locals)?)),
        LocalVarType::Enum(enum_name) => match expr {
            ast::Expr::Var(name) => {
                if let Some(LocalValue::Enum(v)) = locals.get(name) {
                    Ok(LocalValue::Enum(v.clone()))
                } else {
                    eval_enum_literal(expr, enum_name, enum_defs)
                }
            }
            _ => eval_enum_literal(expr, enum_name, enum_defs),
        },
        LocalVarType::Int { min, max } => {
            let val = eval_int_expr(expr, locals)?;
            if val < *min || val > *max {
                return Err(LoweringError::OutOfRange {
                    var: var_name.to_string(),
                    value: val,
                    min: *min,
                    max: *max,
                });
            }
            Ok(LocalValue::Int(val))
        }
    }
}

fn eval_field_expr(
    expr: &ast::Expr,
    domain: &FieldDomain,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<String, LoweringError> {
    match domain {
        FieldDomain::Bool => {
            let b = eval_bool_expr(expr, locals)?;
            Ok(if b { "true" } else { "false" }.into())
        }
        FieldDomain::Enum(variants) => match expr {
            ast::Expr::Var(name) => {
                if let Some(LocalValue::Enum(v)) = locals.get(name) {
                    if let Some(LocalVarType::Enum(enum_name)) = local_var_types.get(name) {
                        let enum_variants = enum_defs
                            .get(enum_name)
                            .ok_or_else(|| LoweringError::UnknownEnum(enum_name.clone()))?;
                        if enum_variants != variants {
                            return Err(LoweringError::Unsupported(format!(
                                "Enum variable '{name}' does not match message field type"
                            )));
                        }
                    }
                    return Ok(v.clone());
                }
                if let Some(LocalVarType::Enum(enum_name)) = local_var_types.get(name) {
                    return Err(LoweringError::Unsupported(format!(
                        "Cannot use enum variable '{name}' as a literal (type '{enum_name}')"
                    )));
                }
                if variants.contains(name) {
                    Ok(name.clone())
                } else {
                    Err(LoweringError::UnknownEnumVariant(
                        name.clone(),
                        "message-field".into(),
                    ))
                }
            }
            _ => Err(LoweringError::Unsupported(
                "Unsupported message field expression".into(),
            )),
        },
        FieldDomain::Int { min, max } => {
            let v = eval_int_expr(expr, locals)?;
            if v < *min || v > *max {
                return Err(LoweringError::OutOfRange {
                    var: "message-field".into(),
                    value: v,
                    min: *min,
                    max: *max,
                });
            }
            Ok(v.to_string())
        }
        FieldDomain::AbstractNatSign(_values) => {
            let v = eval_int_expr(expr, locals)?;
            if v == 0 {
                Ok("zero".into())
            } else if v > 0 {
                Ok("pos".into())
            } else if v < 0 {
                Err(LoweringError::Unsupported(
                    "Negative value used where nat sign abstraction expects non-negative values"
                        .into(),
                ))
            } else {
                unreachable!()
            }
        }
        FieldDomain::AbstractIntSign(_values) => {
            let v = eval_int_expr(expr, locals)?;
            if v < 0 {
                Ok("neg".into())
            } else if v == 0 {
                Ok("zero".into())
            } else {
                Ok("pos".into())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_message_counter_from_send(
    msg_name: &str,
    recipient_role: Option<&str>,
    exact_recipient_channel: Option<&str>,
    sender_channel: Option<&str>,
    sender_role_filter: Option<&str>,
    role_names: &[String],
    role_channels: &IndexMap<String, Vec<String>>,
    args: &[ast::SendArg],
    message_infos: &IndexMap<String, MessageInfo>,
    msg_var_ids: &IndexMap<String, SharedVarId>,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<Vec<SharedVarId>, LoweringError> {
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

    let recipients: Vec<String> = if let Some(channel) = exact_recipient_channel {
        vec![channel.to_string()]
    } else {
        let recipient_roles: Vec<&str> = if let Some(role) = recipient_role {
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

    let sender_candidates: Vec<Option<&str>> = if let Some(sender_channel) = sender_channel {
        vec![Some(sender_channel)]
    } else if let Some(sender_role) = sender_role_filter {
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

#[allow(clippy::too_many_arguments)]
fn resolve_message_counter_from_guard(
    msg_name: &str,
    recipient_role: &str,
    args: &[(String, ast::Expr)],
    sender_role: Option<&str>,
    role_channels: &IndexMap<String, Vec<String>>,
    message_infos: &IndexMap<String, MessageInfo>,
    msg_var_ids: &IndexMap<String, SharedVarId>,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<Vec<SharedVarId>, LoweringError> {
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

fn local_guard_satisfied(
    guard: &ast::GuardExpr,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<bool, LoweringError> {
    match guard {
        ast::GuardExpr::BoolVar(name) => match locals.get(name) {
            Some(LocalValue::Bool(b)) => Ok(*b),
            _ => Err(LoweringError::Unsupported(format!(
                "Guard refers to non-boolean variable '{name}'"
            ))),
        },
        ast::GuardExpr::Comparison { lhs, op, rhs } => {
            eval_local_comparison(lhs, *op, rhs, locals, local_var_types, enum_defs)
        }
        ast::GuardExpr::And(lhs, rhs) => {
            Ok(
                local_guard_satisfied(lhs, locals, local_var_types, enum_defs)?
                    && local_guard_satisfied(rhs, locals, local_var_types, enum_defs)?,
            )
        }
        ast::GuardExpr::Or(lhs, rhs) => {
            Ok(
                local_guard_satisfied(lhs, locals, local_var_types, enum_defs)?
                    || local_guard_satisfied(rhs, locals, local_var_types, enum_defs)?,
            )
        }
        ast::GuardExpr::Threshold(_) => Ok(true),
        ast::GuardExpr::HasCryptoObject { .. } => Ok(true),
    }
}

fn eval_local_comparison(
    lhs: &ast::Expr,
    op: ast::CmpOp,
    rhs: &ast::Expr,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<bool, LoweringError> {
    let lhs_bool = is_bool_expr(lhs, local_var_types);
    let rhs_bool = is_bool_expr(rhs, local_var_types);

    if lhs_bool || rhs_bool {
        if !lhs_bool || !rhs_bool {
            return Err(LoweringError::Unsupported(
                "Guard comparison mixes boolean and non-boolean values".into(),
            ));
        }
        let l = eval_bool_expr(lhs, locals)?;
        let r = eval_bool_expr(rhs, locals)?;
        return match op {
            ast::CmpOp::Eq => Ok(l == r),
            ast::CmpOp::Ne => Ok(l != r),
            _ => Err(LoweringError::Unsupported(
                "Only == and != comparisons are supported for booleans".into(),
            )),
        };
    }

    if let Some(enum_name) =
        expr_enum_type(lhs, local_var_types).or_else(|| expr_enum_type(rhs, local_var_types))
    {
        let l_var = eval_enum_expr(lhs, enum_name, locals, local_var_types, enum_defs)?;
        let r_var = eval_enum_expr(rhs, enum_name, locals, local_var_types, enum_defs)?;
        let l_idx = enum_variant_index(enum_name, &l_var, enum_defs)?;
        let r_idx = enum_variant_index(enum_name, &r_var, enum_defs)?;

        return Ok(match op {
            ast::CmpOp::Eq => l_idx == r_idx,
            ast::CmpOp::Ne => l_idx != r_idx,
            ast::CmpOp::Lt => l_idx < r_idx,
            ast::CmpOp::Le => l_idx <= r_idx,
            ast::CmpOp::Gt => l_idx > r_idx,
            ast::CmpOp::Ge => l_idx >= r_idx,
        });
    }

    // Fallback to integer comparison
    let l = eval_int_expr(lhs, locals)?;
    let r = eval_int_expr(rhs, locals)?;
    Ok(match op {
        ast::CmpOp::Eq => l == r,
        ast::CmpOp::Ne => l != r,
        ast::CmpOp::Lt => l < r,
        ast::CmpOp::Le => l <= r,
        ast::CmpOp::Gt => l > r,
        ast::CmpOp::Ge => l >= r,
    })
}

fn is_bool_expr(expr: &ast::Expr, local_var_types: &IndexMap<String, LocalVarType>) -> bool {
    match expr {
        ast::Expr::BoolLit(_) => true,
        ast::Expr::Var(name) => matches!(local_var_types.get(name), Some(LocalVarType::Bool)),
        ast::Expr::Not(inner) => is_bool_expr(inner, local_var_types),
        _ => false,
    }
}

fn expr_enum_type<'a>(
    expr: &ast::Expr,
    local_var_types: &'a IndexMap<String, LocalVarType>,
) -> Option<&'a String> {
    match expr {
        ast::Expr::Var(name) => match local_var_types.get(name) {
            Some(LocalVarType::Enum(enum_name)) => Some(enum_name),
            _ => None,
        },
        _ => None,
    }
}

fn eval_enum_expr(
    expr: &ast::Expr,
    enum_name: &str,
    locals: &IndexMap<String, LocalValue>,
    local_var_types: &IndexMap<String, LocalVarType>,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<String, LoweringError> {
    match expr {
        ast::Expr::Var(name) => match local_var_types.get(name) {
            Some(LocalVarType::Enum(var_enum)) => {
                if var_enum != enum_name {
                    return Err(LoweringError::Unsupported(format!(
                        "Enum comparison mixes '{var_enum}' with '{enum_name}'"
                    )));
                }
                match locals.get(name) {
                    Some(LocalValue::Enum(v)) => Ok(v.clone()),
                    _ => Err(LoweringError::Unsupported(format!(
                        "Enum variable '{name}' has no value in this location"
                    ))),
                }
            }
            Some(LocalVarType::Bool) => Err(LoweringError::Unsupported(
                "Enum comparison uses a boolean variable".into(),
            )),
            Some(LocalVarType::Int { .. }) => Err(LoweringError::Unsupported(
                "Enum comparison uses an integer variable".into(),
            )),
            None => {
                let variants = enum_defs
                    .get(enum_name)
                    .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
                if variants.contains(name) {
                    Ok(name.clone())
                } else {
                    Err(LoweringError::UnknownEnumVariant(
                        name.clone(),
                        enum_name.to_string(),
                    ))
                }
            }
        },
        _ => Err(LoweringError::Unsupported(
            "Enum comparison expects enum variables or literals".into(),
        )),
    }
}

fn enum_variant_index(
    enum_name: &str,
    variant: &str,
    enum_defs: &IndexMap<String, Vec<String>>,
) -> Result<usize, LoweringError> {
    let variants = enum_defs
        .get(enum_name)
        .ok_or_else(|| LoweringError::UnknownEnum(enum_name.to_string()))?;
    variants.iter().position(|v| v == variant).ok_or_else(|| {
        LoweringError::UnknownEnumVariant(variant.to_string(), enum_name.to_string())
    })
}

#[cfg(test)]
mod tests {
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
        assert!(ta.resilience_condition.is_some());
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
            .filter(|rule| ta.locations[rule.from].role == "Leader" && !rule.updates.is_empty())
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
            .filter(|rule| ta.locations[rule.from].role == "Leader" && !rule.updates.is_empty())
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
            ta.locations[r.from].local_vars.get(flag) == Some(&LocalValue::Bool(false))
                && ta.locations[r.to].local_vars.get(flag) == Some(&LocalValue::Bool(true))
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
        assert_eq!(ta.value_abstraction, ValueAbstractionMode::Sign);
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
        assert_eq!(ta.fault_model, FaultModel::Omission);
        assert_eq!(ta.timing_model, TimingModel::PartialSynchrony);
        let gst = ta.gst_param.expect("gst param should be set");
        assert_eq!(ta.parameters[gst].name, "gst");
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
        assert_eq!(ta.equivocation_mode, EquivocationMode::None);
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
        assert_eq!(ta.authentication_mode, AuthenticationMode::Signed);
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

        let vote_policy = ta.message_policies.get("Vote").expect("Vote policy");
        assert_eq!(vote_policy.auth, MessageAuthPolicy::Authenticated);
        assert_eq!(vote_policy.equivocation, MessageEquivocationPolicy::None);

        let ping_policy = ta.message_policies.get("Ping").expect("Ping policy");
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
        assert_eq!(ta.network_semantics, NetworkSemantics::IdentitySelective);
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
        assert_eq!(ta.delivery_control, DeliveryControlMode::PerRecipient);
        assert_eq!(ta.fault_budget_scope, FaultBudgetScope::Global);
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
        assert_eq!(ta.network_semantics, NetworkSemantics::ProcessSelective);

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
        let mut initial_pids = std::collections::HashSet::new();
        for lid in &ta.initial_locations {
            if let Some(LocalValue::Int(pid)) =
                ta.locations[*lid].local_vars.get(DEFAULT_PROCESS_ID_VAR)
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
            if ta.locations[rule.from].phase != "s" {
                continue;
            }
            let from_pid = match ta.locations[rule.from]
                .local_vars
                .get(DEFAULT_PROCESS_ID_VAR)
            {
                Some(LocalValue::Int(pid)) => *pid,
                _ => continue,
            };
            if let Some(atom) = rule.guard.atoms.first() {
                let GuardAtom::Threshold { vars, .. } = atom;
                for var in vars {
                    guarded_vars.insert(*var);
                    let counter_name = &ta.shared_vars[*var].name;
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

        assert_eq!(ta.network_semantics, NetworkSemantics::ProcessSelective);
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
                let from = &ta.locations[rule.from];
                from.role == "Leader" && from.phase == "s" && !rule.updates.is_empty()
            })
            .collect();
        assert!(!send_rules.is_empty(), "expected sender rules from Leader");

        for rule in send_rules {
            let from = &ta.locations[rule.from];
            let sender_pid = match from.local_vars.get("leader_id") {
                Some(LocalValue::Int(pid)) => *pid,
                other => panic!("missing leader identity on sender location: {other:?}"),
            };
            let updated_names: std::collections::HashSet<String> = rule
                .updates
                .iter()
                .map(|u| ta.shared_vars[u.var].name.clone())
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
                ta.locations[rule.from].role == "Replica"
                    && ta.locations[rule.from].phase == "s"
                    && ta.locations[rule.from].local_vars.get("pid") == Some(&LocalValue::Int(0))
            })
            .expect("expected a pid=0 guard rule");
        let guard_vars = match guard_rule.guard.atoms.first().expect("threshold guard") {
            GuardAtom::Threshold { vars, .. } => vars,
        };
        let guard_names: std::collections::HashSet<String> = guard_vars
            .iter()
            .map(|v| ta.shared_vars[*v].name.clone())
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
        assert_eq!(ta.network_semantics, NetworkSemantics::CohortSelective);
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
        assert_eq!(ta.fault_model, FaultModel::Crash);
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
            ta.locations[lid].local_vars.get(INTERNAL_ALIVE_VAR) == Some(&LocalValue::Bool(true))
        }));
        let has_crash_rule = ta.rules.iter().any(|rule| {
            ta.locations[rule.from].local_vars.get(INTERNAL_ALIVE_VAR)
                == Some(&LocalValue::Bool(true))
                && ta.locations[rule.to].local_vars.get(INTERNAL_ALIVE_VAR)
                    == Some(&LocalValue::Bool(false))
                && rule
                    .updates
                    .iter()
                    .any(|u| u.var == crash_counter && matches!(u.kind, UpdateKind::Increment))
        });
        assert!(has_crash_rule, "expected at least one injected crash rule");
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
            let to = &ta.locations[r.to];
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
                loc.local_vars.contains_key("__lock_qc")
                    && loc.local_vars.contains_key("__justify_qc")
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
                        .get(upd.var)
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
            .map(|var_id| ta.shared_vars[*var_id].name.clone())
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
                        .get(upd.var)
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
        let err =
            lower(&prog).expect_err("lowering should reject unknown adversary bound parameter");
        let msg = format!("{err}");
        assert!(msg.contains("Unknown parameter 'ghost'"));
    }

    #[test]
    fn lower_rejects_unknown_adversary_key() {
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
        let prog = parse(src, "unknown_adversary_key.trs").unwrap();
        let err = lower(&prog).expect_err("lowering should reject unknown adversary keys");
        let msg = format!("{err}");
        assert!(msg.contains("Unknown adversary key 'foo'"));
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
}
