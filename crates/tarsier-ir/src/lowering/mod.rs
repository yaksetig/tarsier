// The lowering pass uses incremental assignment patterns where variables are
// conditionally overwritten; the initial assignment triggers unused_assignments.
#![allow(unused_assignments)]

mod config;
mod counters;
mod guards;
mod helpers;
mod messages;
mod validation;

use indexmap::{IndexMap, IndexSet};
use miette::{Diagnostic, NamedSource, SourceSpan};
use std::collections::{HashMap, HashSet};
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

/// Returns true for fault models that use the `__alive` local variable (crash-stop and crash-recovery).
fn uses_alive_var(fm: FaultModel) -> bool {
    matches!(fm, FaultModel::Crash | FaultModel::CrashRecovery)
}
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
        .map(|(i, p)| (p.name.clone(), ParamId::from(i)))
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
            let id = ta.add_parameter(Parameter::fixed(name.clone()));
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
        ta.constraints.resilience_condition = Some(LinearConstraint { lhs, op, rhs });
    }

    // 2b. Set adversary/fault/timing/value-abstraction configuration
    for item in &proto.adversary {
        match item.key.as_str() {
            "bound" => {
                if let Some(&pid) = param_ids.get(&item.value) {
                    ta.constraints.adversary_bound_param = Some(pid);
                } else {
                    return Err(LoweringError::UnknownParameter(item.value.clone()));
                }
            }
            "model" => {
                ta.semantics.fault_model = parse_fault_model(&item.value)?;
            }
            "timing" => {
                ta.semantics.timing_model = parse_timing_model(&item.value)?;
            }
            "gst" => {
                if let Some(&pid) = param_ids.get(&item.value) {
                    ta.semantics.gst_param = Some(pid);
                } else {
                    return Err(LoweringError::UnknownParameter(item.value.clone()));
                }
            }
            "values" | "value_abstraction" => {
                ta.semantics.value_abstraction = parse_value_abstraction_mode(&item.value)?;
            }
            "equivocation" => {
                ta.semantics.equivocation_mode = parse_equivocation_mode(&item.value)?;
            }
            "auth" | "authentication" => {
                ta.semantics.authentication_mode = parse_authentication_mode(&item.value)?;
            }
            "network" => {
                ta.semantics.network_semantics = parse_network_semantics(&item.value)?;
            }
            "delivery" | "delivery_scope" => {
                ta.semantics.delivery_control = parse_delivery_control_mode(&item.value)?;
            }
            "faults" | "fault_scope" | "fault_budget" => {
                ta.semantics.fault_budget_scope = parse_fault_budget_scope(&item.value)?;
            }
            "por" | "por_mode" => {
                ta.semantics.por_mode = parse_por_mode(&item.value)?;
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
    if ta.semantics.timing_model == TimingModel::PartialSynchrony
        && ta.semantics.gst_param.is_none()
    {
        return Err(LoweringError::Unsupported(
            "timing: partial_synchrony requires `adversary { gst: <param>; }`".into(),
        ));
    }
    if ta.semantics.delivery_control != DeliveryControlMode::LegacyCounter
        && ta.semantics.network_semantics == NetworkSemantics::Classic
    {
        return Err(LoweringError::Unsupported(
            "delivery controls require non-classic network semantics. \
             Use `network: identity_selective|cohort_selective|process_selective`."
                .into(),
        ));
    }
    ta.security.role_identities =
        build_role_identity_configs(proto, ta.semantics.network_semantics)?;
    ta.security.key_ownership = build_key_ownership(&ta.security.role_identities)?;
    validate_compromised_keys(&compromised_keys_from_adversary, &ta.security.key_ownership)?;
    ta.security.compromised_keys = compromised_keys_from_adversary;
    ta.security.message_policies = build_message_policy_overrides(proto)?;

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
                        if let Some(&pid) = param_ids.get(name.as_str()) {
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

        ta.constraints.committees.push(IrCommitteeSpec {
            name: committee.name.clone(),
            population,
            byzantine,
            committee_size,
            epsilon,
            bound_param,
        });
    }

    // 2d. Process bounded collection declarations
    for round in &proto.dag_rounds {
        ta.dag_rounds.push(IrDagRoundSpec {
            name: round.name.clone(),
            parent_rounds: round.parents.clone(),
        });
    }
    validate_dag_rounds(&ta.dag_rounds)?;

    // 2e. Process bounded collection declarations
    for coll in &proto.collections {
        let kind = match coll.kind {
            ast::CollectionKind::Log => IrCollectionKind::Log,
            ast::CollectionKind::Sequence => IrCollectionKind::Sequence,
            ast::CollectionKind::FifoChannel => IrCollectionKind::FifoChannel,
        };
        let capacity = lower_linear_expr_to_lc(&coll.capacity, &param_ids)?;
        let queue_model = match kind {
            IrCollectionKind::FifoChannel => QueueModel::LinearFifo,
            _ => QueueModel::None,
        };
        ta.add_collection(IrCollectionSpec {
            name: coll.name.clone(),
            kind,
            element_type: coll.element_type.clone(),
            capacity,
            queue_model,
        });
    }

    // 2e. Process logical clock declarations
    let mut clock_ids: IndexMap<String, ClockId> = IndexMap::new();
    for clock in &proto.clocks {
        if clock_ids.contains_key(&clock.name) {
            return Err(LoweringError::Unsupported(format!(
                "Duplicate clock declaration '{}'",
                clock.name
            )));
        }
        let id = ta.add_clock(IrClockSpec {
            name: clock.name.clone(),
        });
        clock_ids.insert(clock.name.clone(), id);
    }

    // 3. Add shared variables for each message type (expanded by field values)
    let mut message_infos =
        build_message_infos(&proto.messages, &enum_defs, ta.semantics.value_abstraction)?;
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
        ta.security.crypto_objects.insert(
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
        ta.security
            .message_policies
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
    let use_cohort_selective_channels =
        ta.semantics.network_semantics == NetworkSemantics::CohortSelective;
    let use_process_selective_channels =
        ta.semantics.network_semantics == NetworkSemantics::ProcessSelective;
    let role_process_identity_var: IndexMap<String, String> = ta
        .security
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
                        if ta.semantics.network_semantics == NetworkSemantics::Classic {
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

    let crash_counter_var = if ta.semantics.fault_model == FaultModel::Crash {
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
        if role_decl.is_leader {
            ta.leader_roles.push(role_decl.name.clone());
        }
        let process_identity_var = ta
            .security
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

        if uses_alive_var(ta.semantics.fault_model) {
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
        if uses_alive_var(ta.semantics.fault_model) {
            initial_values.insert(INTERNAL_ALIVE_VAR.into(), LocalValue::Bool(true));
        }

        // Set initial locations
        if let Some(ref init) = role_decl.init_phase {
            if let Some(locs) = location_map.get(init) {
                // Find the location(s) matching initial variable values
                for &lid in locs {
                    let loc = &ta.locations[lid.as_usize()];
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
                let mut pending_collection_updates: Vec<CollectionUpdate> = Vec::new();
                let mut pending_param_updates: Vec<ParamUpdate> = Vec::new();
                let mut clock_updates: Vec<ClockUpdate> = Vec::new();
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
                        ast::Action::Append { collection, value } => {
                            let coll_id =
                                ta.find_collection_by_name(collection).ok_or_else(|| {
                                    LoweringError::Unsupported(format!(
                                        "Unknown collection '{collection}' in append action"
                                    ))
                                })?;
                            let lc = helpers::lower_expr_to_lc(value, &param_ids)?;
                            pending_collection_updates.push(CollectionUpdate {
                                collection: coll_id,
                                kind: CollectionUpdateKind::Append(lc),
                            });
                        }
                        ast::Action::Enqueue { collection, value } => {
                            let coll_id =
                                ta.find_collection_by_name(collection).ok_or_else(|| {
                                    LoweringError::Unsupported(format!(
                                        "Unknown collection '{collection}' in enqueue action"
                                    ))
                                })?;
                            let lc = helpers::lower_expr_to_lc(value, &param_ids)?;
                            pending_collection_updates.push(CollectionUpdate {
                                collection: coll_id,
                                kind: CollectionUpdateKind::Enqueue(lc),
                            });
                        }
                        ast::Action::Dequeue { collection } => {
                            let coll_id =
                                ta.find_collection_by_name(collection).ok_or_else(|| {
                                    LoweringError::Unsupported(format!(
                                        "Unknown collection '{collection}' in dequeue action"
                                    ))
                                })?;
                            pending_collection_updates.push(CollectionUpdate {
                                collection: coll_id,
                                kind: CollectionUpdateKind::Dequeue,
                            });
                        }
                        ast::Action::Reconfigure { updates } => {
                            for upd in updates {
                                let pid = *param_ids.get(&upd.param).ok_or_else(|| {
                                    LoweringError::UnknownParameter(upd.param.clone())
                                })?;
                                let value = helpers::lower_expr_to_lc(&upd.value, &param_ids)?;
                                pending_param_updates.push(ParamUpdate { param: pid, value });
                            }
                        }
                        ast::Action::ResetClock { clock } => {
                            let clock_id = clock_ids.get(clock).copied().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Unknown clock '{clock}' in reset action"
                                ))
                            })?;
                            clock_updates.push(ClockUpdate {
                                clock: clock_id,
                                kind: ClockUpdateKind::Reset,
                            });
                        }
                        ast::Action::TickClock { clock, amount } => {
                            let clock_id = clock_ids.get(clock).copied().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Unknown clock '{clock}' in tick action"
                                ))
                            })?;
                            let delta = amount
                                .as_ref()
                                .map(|amt| lower_linear_expr_to_lc(amt, &param_ids))
                                .transpose()?
                                .unwrap_or_else(|| LinearCombination::constant(1));
                            clock_updates.push(ClockUpdate {
                                clock: clock_id,
                                kind: ClockUpdateKind::TickBy(delta),
                            });
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
                        let from_loc = &ta.locations[from_lid.as_usize()];
                        if uses_alive_var(ta.semantics.fault_model)
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
                            ta.semantics.network_semantics,
                            &process_identity_var,
                        )?;
                        let sender_channel_opt =
                            if ta.semantics.network_semantics == NetworkSemantics::Classic {
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
                        let timeout_guards =
                            collect_timeout_guards(guard_clause, &clock_ids, &param_ids)?;

                        // Build updates (message sends), resolved for this location.
                        let mut updates = Vec::new();
                        let mut send_blocked_by_uniqueness = false;
                        let mut set_sent_flags: HashSet<String> = HashSet::new();
                        let mut set_lock_flags: HashSet<String> = HashSet::new();
                        let mut set_justify_flags: HashSet<String> = HashSet::new();
                        let counter_ctx = MessageCounterContext {
                            role_names: &role_names,
                            role_channels: &role_channels,
                            message_infos: &message_infos,
                            msg_var_ids: &msg_var_ids,
                            locals: &from_loc.local_vars,
                            local_var_types: &local_var_types,
                            enum_defs: &enum_defs,
                        };

                        for action in &pending_actions {
                            match action {
                                PendingTransitionAction::Send {
                                    message_type,
                                    args,
                                    recipient_role,
                                } => {
                                    let query = SendCounterLookup {
                                        msg_name: message_type,
                                        recipient_role: recipient_role.as_deref(),
                                        exact_recipient_channel: None,
                                        sender_channel: sender_channel_opt,
                                        sender_role_filter: None,
                                        args,
                                    };
                                    let var_ids =
                                        resolve_message_counter_from_send(&query, &counter_ctx)?;
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
                                    let source_query = SendCounterLookup {
                                        msg_name: &object.source_message,
                                        recipient_role: None,
                                        exact_recipient_channel: Some(
                                            current_recipient_channel.as_str(),
                                        ),
                                        sender_channel: None,
                                        sender_role_filter: object.signer_role.as_deref(),
                                        args,
                                    };
                                    let source_vars = resolve_message_counter_from_send(
                                        &source_query,
                                        &counter_ctx,
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

                                    let object_query = SendCounterLookup {
                                        msg_name: object_name,
                                        recipient_role: recipient_role.as_deref(),
                                        exact_recipient_channel: None,
                                        sender_channel: sender_channel_opt,
                                        sender_role_filter: None,
                                        args,
                                    };
                                    let var_ids = resolve_message_counter_from_send(
                                        &object_query,
                                        &counter_ctx,
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
                                    let lock_query = SendCounterLookup {
                                        msg_name: object_name,
                                        recipient_role: None,
                                        exact_recipient_channel: Some(
                                            current_recipient_channel.as_str(),
                                        ),
                                        sender_channel: None,
                                        sender_role_filter: None,
                                        args,
                                    };
                                    let object_vars = resolve_message_counter_from_send(
                                        &lock_query,
                                        &counter_ctx,
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
                                    let justify_query = SendCounterLookup {
                                        msg_name: object_name,
                                        recipient_role: None,
                                        exact_recipient_channel: Some(
                                            current_recipient_channel.as_str(),
                                        ),
                                        sender_channel: None,
                                        sender_role_filter: None,
                                        args,
                                    };
                                    let object_vars = resolve_message_counter_from_send(
                                        &justify_query,
                                        &counter_ctx,
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
                                .security
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
                            let to_loc = &ta.locations[to_lid.as_usize()];
                            if to_loc.local_vars == target_vars {
                                ta.add_rule(Rule {
                                    from: from_lid,
                                    to: to_lid,
                                    guard: guard.clone(),
                                    updates: updates.clone(),
                                    collection_updates: pending_collection_updates.clone(),
                                    clock_guards: timeout_guards.clone(),
                                    clock_updates: clock_updates.clone(),
                                    param_updates: pending_param_updates.clone(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 5b. Mark parameters targeted by reconfigure actions as time-varying.
        {
            let varying_ids: Vec<usize> = ta
                .rules
                .iter()
                .flat_map(|r| r.param_updates.iter().map(|pu| pu.param.as_usize()))
                .collect();
            for id in varying_ids {
                ta.parameters[id].time_varying = true;
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
                        let from_loc = &ta.locations[from_lid.as_usize()];
                        if uses_alive_var(ta.semantics.fault_model)
                            && from_loc.local_vars.get(INTERNAL_ALIVE_VAR)
                                != Some(&LocalValue::Bool(true))
                        {
                            continue;
                        }
                        let current_view = match from_loc.local_vars.get(&pm.view_var) {
                            Some(LocalValue::Int(v)) => v,
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
                            let to_loc = &ta.locations[to_lid.as_usize()];
                            if to_loc.local_vars == target_vars {
                                ta.add_rule(Rule {
                                    from: from_lid,
                                    to: to_lid,
                                    guard: Guard::trivial(),
                                    updates: Vec::new(),
                                    collection_updates: vec![],
                                    clock_guards: vec![],
                                    clock_updates: vec![],
                                    param_updates: vec![],
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
        if ta.semantics.fault_model == FaultModel::Crash {
            let crash_counter_var = crash_counter_var.ok_or_else(|| {
                LoweringError::Unsupported("crash model requires internal crash counter".into())
            })?;
            for phase in &role_decl.phases {
                let phase_locs = location_map
                    .get(&phase.node.name)
                    .cloned()
                    .unwrap_or_default();
                for &from_lid in &phase_locs {
                    let from_loc = &ta.locations[from_lid.as_usize()];
                    if from_loc.local_vars.get(INTERNAL_ALIVE_VAR) != Some(&LocalValue::Bool(true))
                    {
                        continue;
                    }

                    let mut target_vars = from_loc.local_vars.clone();
                    target_vars.insert(INTERNAL_ALIVE_VAR.into(), LocalValue::Bool(false));

                    for &to_lid in &phase_locs {
                        let to_loc = &ta.locations[to_lid.as_usize()];
                        if to_loc.local_vars == target_vars {
                            ta.add_rule(Rule {
                                from: from_lid,
                                to: to_lid,
                                guard: Guard::trivial(),
                                updates: vec![Update {
                                    var: crash_counter_var,
                                    kind: UpdateKind::Increment,
                                }],
                                collection_updates: vec![],
                                clock_guards: vec![],
                                clock_updates: vec![],
                                param_updates: vec![],
                            });
                            break;
                        }
                    }
                }
            }
        }

        // 7b. Inject crash-recovery transitions, if configured.
        //
        // Semantics:
        // - same `__alive` variable as crash-stop
        // - crash transitions: alive → dead (no counter, bounded by dead-loc sum in encoder)
        // - recovery transitions: any dead location → initial alive location (amnesia model)
        if ta.semantics.fault_model == FaultModel::CrashRecovery {
            // Find the initial alive location for this role.
            let initial_alive_lid = ta
                .initial_locations
                .iter()
                .find(|&&lid| {
                    let loc = &ta.locations[lid.as_usize()];
                    loc.role == role_decl.name
                        && loc.local_vars.get(INTERNAL_ALIVE_VAR) == Some(&LocalValue::Bool(true))
                })
                .copied();

            for phase in &role_decl.phases {
                let phase_locs = location_map
                    .get(&phase.node.name)
                    .cloned()
                    .unwrap_or_default();
                for &from_lid in &phase_locs {
                    let from_loc = &ta.locations[from_lid.as_usize()];
                    if from_loc.local_vars.get(INTERNAL_ALIVE_VAR) == Some(&LocalValue::Bool(true))
                    {
                        // Crash transition: alive → dead in same phase (no counter update).
                        let mut target_vars = from_loc.local_vars.clone();
                        target_vars.insert(INTERNAL_ALIVE_VAR.into(), LocalValue::Bool(false));
                        for &to_lid in &phase_locs {
                            let to_loc = &ta.locations[to_lid.as_usize()];
                            if to_loc.local_vars == target_vars {
                                ta.add_rule(Rule {
                                    from: from_lid,
                                    to: to_lid,
                                    guard: Guard::trivial(),
                                    updates: vec![],
                                    collection_updates: vec![],
                                    clock_guards: vec![],
                                    clock_updates: vec![],
                                    param_updates: vec![],
                                });
                                break;
                            }
                        }
                    } else if let Some(init_lid) = initial_alive_lid {
                        // Recovery transition: dead → initial alive location (amnesia).
                        ta.add_rule(Rule {
                            from: from_lid,
                            to: init_lid,
                            guard: Guard::trivial(),
                            updates: vec![],
                            collection_updates: vec![],
                            clock_guards: vec![],
                            clock_updates: vec![],
                            param_updates: vec![],
                        });
                    }
                }
            }
        }
    }

    validate_identity_and_key_invariants(&ta)?;

    Ok(ta)
}

fn validate_dag_rounds(rounds: &[IrDagRoundSpec]) -> Result<(), LoweringError> {
    if rounds.is_empty() {
        return Ok(());
    }

    // 1. Check for duplicate names.
    let mut round_index: HashMap<&str, usize> = HashMap::new();
    for (idx, round) in rounds.iter().enumerate() {
        if round_index.insert(round.name.as_str(), idx).is_some() {
            return Err(LoweringError::Unsupported(format!(
                "Duplicate dag_round declaration '{}'",
                round.name
            )));
        }
    }

    // 2. Check for self-loops.
    for round in rounds {
        if round.parent_rounds.contains(&round.name) {
            return Err(LoweringError::Unsupported(format!(
                "dag_round '{}' lists itself as a parent (self-loop)",
                round.name
            )));
        }
    }

    // 3. Check for unknown parents.
    for round in rounds {
        for parent in &round.parent_rounds {
            if !round_index.contains_key(parent.as_str()) {
                return Err(LoweringError::Unsupported(format!(
                    "dag_round '{}' references unknown parent '{}'; \
                     declared rounds: [{}]",
                    round.name,
                    parent,
                    rounds
                        .iter()
                        .map(|r| r.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    }

    // 4. Check for duplicate parents in a single round.
    for round in rounds {
        let mut seen = HashSet::new();
        for parent in &round.parent_rounds {
            if !seen.insert(parent.as_str()) {
                return Err(LoweringError::Unsupported(format!(
                    "dag_round '{}' lists parent '{}' more than once",
                    round.name, parent
                )));
            }
        }
    }

    // 5. Cycle detection via DFS.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VisitState {
        Visiting,
        Done,
    }

    fn dfs<'a>(
        node: &'a str,
        path: &mut Vec<&'a str>,
        rounds: &'a [IrDagRoundSpec],
        idx: &HashMap<&'a str, usize>,
        state: &mut HashMap<&'a str, VisitState>,
    ) -> Result<(), LoweringError> {
        if let Some(existing) = state.get(node) {
            return match existing {
                VisitState::Done => Ok(()),
                VisitState::Visiting => {
                    // Build cycle path for actionable error.
                    let cycle_start = path.iter().position(|&n| n == node).unwrap_or(0);
                    let cycle: Vec<&str> = path[cycle_start..].to_vec();
                    Err(LoweringError::Unsupported(format!(
                        "dag_round dependency cycle: {} → {}",
                        cycle.join(" → "),
                        node
                    )))
                }
            };
        }

        state.insert(node, VisitState::Visiting);
        path.push(node);
        let round = &rounds[idx[node]];
        for parent in &round.parent_rounds {
            dfs(parent.as_str(), path, rounds, idx, state)?;
        }
        path.pop();
        state.insert(node, VisitState::Done);
        Ok(())
    }

    let mut state: HashMap<&str, VisitState> = HashMap::new();
    for round in rounds {
        let mut path = Vec::new();
        dfs(round.name.as_str(), &mut path, rounds, &round_index, &mut state)?;
    }

    // 6. Require at least one root (no parents).
    let roots: Vec<&str> = rounds
        .iter()
        .filter(|r| r.parent_rounds.is_empty())
        .map(|r| r.name.as_str())
        .collect();
    if roots.is_empty() {
        return Err(LoweringError::Unsupported(
            "dag_round graph has no root rounds (every round has parents); \
             at least one root round with no parents is required"
                .into(),
        ));
    }

    // 7. Check connectivity: every non-root round must be reachable from some root.
    let mut reachable: HashSet<&str> = HashSet::new();
    // Build child→parent adjacency for reverse traversal (parent→children).
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for round in rounds {
        children.entry(round.name.as_str()).or_default();
        for parent in &round.parent_rounds {
            children
                .entry(parent.as_str())
                .or_default()
                .push(round.name.as_str());
        }
    }
    // BFS from roots.
    let mut queue: Vec<&str> = roots.clone();
    while let Some(node) = queue.pop() {
        if reachable.insert(node) {
            if let Some(kids) = children.get(node) {
                queue.extend(kids.iter());
            }
        }
    }
    let unreachable: Vec<&str> = rounds
        .iter()
        .filter(|r| !reachable.contains(r.name.as_str()))
        .map(|r| r.name.as_str())
        .collect();
    if !unreachable.is_empty() {
        return Err(LoweringError::Unsupported(format!(
            "dag_round(s) [{}] are not reachable from any root round [{}]",
            unreachable.join(", "),
            roots.join(", ")
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
