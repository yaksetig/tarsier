#![allow(unused_assignments)]

mod config;
mod counters;
mod guards;
mod helpers;
mod messages;
mod validation;

use indexmap::{IndexMap, IndexSet};
use miette::{Diagnostic, NamedSource, SourceSpan};
use std::collections::HashSet;
use thiserror::Error;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use config::*;
use counters::*;
use guards::*;
use helpers::*;
use messages::*;
use validation::*;

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
    #[error("Validation error: {0}")]
    Validation(String),
}

/// A lowering error enriched with source span information for pretty-printed diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("{inner}")]
#[allow(unused_assignments)]
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
            span: span.map(|s| SourceSpan::new(s.start.into(), s.end - s.start)),
        }
    }
}

/// Lower an AST Program into a ThresholdAutomaton, with rich source-span diagnostics.
///
/// This wraps `lower()` and attaches source spans for pretty error reporting via miette.
#[allow(clippy::result_large_err)]
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

/// Lower an AST Program, collecting as many errors as possible.
///
/// Returns the successfully-lowered automaton (if any) together with all
/// errors encountered during lowering wrapped with source-span information.
pub fn lower_with_source_multi(
    program: &ast::Program,
    source: &str,
    filename: &str,
) -> (Option<ThresholdAutomaton>, Vec<SpannedLoweringError>) {
    match lower(program) {
        Ok(ta) => (Some(ta), Vec::new()),
        Err(err) => {
            let span = find_span_for_error(&err, program);
            let spanned =
                SpannedLoweringError::new(err, source.to_string(), filename.to_string(), span);
            (None, vec![spanned])
        }
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

/// Convert an AST [`InterfaceAssumption`](ast::InterfaceAssumption) into an
/// IR [`Assumption::ParameterConstraint`](crate::composition::Assumption::ParameterConstraint)
/// using the parameter names from a lowered [`ThresholdAutomaton`].
pub fn lower_interface_assumption(
    assumption: &ast::InterfaceAssumption,
    ta: &ThresholdAutomaton,
) -> Result<crate::composition::Assumption, LoweringError> {
    let param_map: IndexMap<String, ParamId> = ta
        .parameters
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name.clone(), i))
        .collect();
    let lhs = lower_linear_expr_to_lc(&assumption.lhs, &param_map)?;
    let rhs = lower_linear_expr_to_lc(&assumption.rhs, &param_map)?;
    let op = lower_cmp_op(assumption.op);
    Ok(crate::composition::Assumption::ParameterConstraint { lhs, op, rhs })
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
            "por" | "por_mode" => {
                ta.por_mode = parse_por_mode(&item.value)?;
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
                        let guard_ctx = GuardLoweringContext {
                            msg_vars: &msg_var_ids,
                            message_infos: &message_infos,
                            params: &param_ids,
                            locals: &from_loc.local_vars,
                            local_var_types: &local_var_types,
                            enum_defs: &enum_defs,
                            role_channels: &role_channels,
                            recipient_channel: current_recipient_channel.as_str(),
                            role_name: &role_decl.name,
                        };
                        let mut guard = lower_guard(guard_clause, &guard_ctx)?;

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
            let crash_counter_var = crash_counter_var.ok_or_else(|| {
                LoweringError::Unsupported("crash model requires internal crash counter".into())
            })?;
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
                let target_loc = &ta.locations[rule.to];
                target_loc.local_vars.get("__lock_qc") == Some(&LocalValue::Bool(true))
                    && ta.locations[rule.from].local_vars.get("__lock_qc")
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
        assert_eq!(ta.por_mode, PorMode::Full);
    }

    #[test]
    fn lower_por_mode_static() {
        let src = make_por_mode_protocol("static");
        let prog = parse(&src, "por_static.trs").unwrap();
        let ta = lower(&prog).unwrap();
        assert_eq!(ta.por_mode, PorMode::Static);
    }

    #[test]
    fn lower_por_mode_off() {
        let src = make_por_mode_protocol("off");
        let prog = parse(&src, "por_off.trs").unwrap();
        let ta = lower(&prog).unwrap();
        assert_eq!(ta.por_mode, PorMode::Off);
    }

    #[test]
    fn lower_por_mode_none_alias() {
        let src = make_por_mode_protocol("none");
        let prog = parse(&src, "por_none.trs").unwrap();
        let ta = lower(&prog).unwrap();
        assert_eq!(ta.por_mode, PorMode::Off);
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
        ta.parameters.push(Parameter { name: "n".into() });
        ta.parameters.push(Parameter { name: "t".into() });
        ta.parameters.push(Parameter { name: "f".into() });

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
        assert_eq!(ta.find_param_by_name("n"), Some(0));
        assert_eq!(ta.find_param_by_name("t"), Some(1));
        assert_eq!(ta.find_param_by_name("f"), Some(2));
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
        let init_loc = &ta.locations[ta.initial_locations[0]];
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
        assert_eq!(ta.committees.len(), 1);
        let c = &ta.committees[0];
        assert_eq!(c.name, "validators");
        assert!(matches!(c.population, ParamOrConst::Const(1000)));
        assert!(matches!(c.byzantine, ParamOrConst::Const(333)));
        assert!(matches!(c.committee_size, ParamOrConst::Const(100)));
        assert_eq!(c.epsilon, Some(1.0e-9));
        let bound_pid = c.bound_param.expect("bound_param should be set");
        assert_eq!(ta.parameters[bound_pid].name, "b");
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
        assert_eq!(ta.committees.len(), 1);
        let c = &ta.committees[0];
        assert!(matches!(c.population, ParamOrConst::Param(pid) if ta.parameters[pid].name == "N"));
        assert!(matches!(c.byzantine, ParamOrConst::Param(pid) if ta.parameters[pid].name == "K"));
        assert!(
            matches!(c.committee_size, ParamOrConst::Param(pid) if ta.parameters[pid].name == "S")
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
        assert_eq!(ta.fault_model, FaultModel::Byzantine);
        let bound = ta
            .adversary_bound_param
            .expect("adversary bound should be set");
        assert_eq!(ta.parameters[bound].name, "f");
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
        let init = &ta.locations[ta.initial_locations[0]];
        assert_eq!(
            init.local_vars.get("status"),
            Some(&LocalValue::Enum("idle".into()))
        );
        // Only the idle->active transition should pass the guard
        assert_eq!(ta.rules.len(), 1);
        let rule = &ta.rules[0];
        assert_eq!(
            ta.locations[rule.from].local_vars.get("status"),
            Some(&LocalValue::Enum("idle".into()))
        );
        assert_eq!(
            ta.locations[rule.to].local_vars.get("status"),
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
        assert!(
            matches!(err.inner, LoweringError::UnknownPhase(ref name) if name == "nonexistent")
        );
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
                    let lp = &ta.locations[*l].phase;
                    let rp = &ta.locations[*r].phase;
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
            .map(|(id, _)| id)
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
        assert!(ta.crypto_objects.contains_key("QC"));
        let qc = &ta.crypto_objects["QC"];
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
            let from_val = match ta.locations[rule.from].local_vars.get("counter") {
                Some(LocalValue::Int(v)) => *v,
                _ => panic!("expected int counter"),
            };
            let to_val = match ta.locations[rule.to].local_vars.get("counter") {
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
            ta.adversary_bound_param.is_none(),
            "adversary bound param should be None when not declared"
        );
        assert_eq!(ta.fault_model, FaultModel::Byzantine); // default
        assert_eq!(ta.timing_model, TimingModel::Asynchronous); // default
    }
}
