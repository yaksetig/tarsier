use indexmap::{IndexMap, IndexSet};
use std::fmt;
use thiserror::Error;

macro_rules! define_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        #[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serialize", serde(transparent))]
        pub struct $name(usize);

        impl $name {
            pub const fn new(value: usize) -> Self {
                Self(value)
            }

            pub const fn as_usize(self) -> usize {
                self.0
            }
        }

        impl From<usize> for $name {
            fn from(value: usize) -> Self {
                Self(value)
            }
        }

        impl From<$name> for usize {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl PartialEq<usize> for $name {
            fn eq(&self, other: &usize) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for usize {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl PartialOrd<usize> for $name {
            fn partial_cmp(&self, other: &usize) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }

        impl PartialOrd<$name> for usize {
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                self.partial_cmp(&other.0)
            }
        }
    };
}

define_id!(
    LocationId,
    "A unique identifier for a location in the threshold automaton."
);
define_id!(SharedVarId, "A unique identifier for a shared variable.");
define_id!(
    CollectionId,
    "A unique identifier for a bounded log/sequence collection."
);
define_id!(ClockId, "A unique identifier for a logical clock.");
define_id!(RuleId, "A unique identifier for a rule.");
define_id!(ParamId, "A unique identifier for a parameter.");

/// Fault model used for environment behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultModel {
    /// Byzantine environment can inject arbitrary messages up to a bound.
    #[default]
    Byzantine,
    /// Crash-stop failures (processes transition to a dead state and stop sending).
    Crash,
    /// Crash-recovery failures (processes crash and may later recover from initial state).
    /// At most f processes are simultaneously crashed at any step.
    CrashRecovery,
    /// Omission failures (message loss/drop without forged injections).
    Omission,
}

/// Timing assumptions for liveness reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimingModel {
    /// Fully asynchronous scheduling/network.
    #[default]
    Asynchronous,
    /// Partial synchrony with an unknown Global Stabilization Time.
    PartialSynchrony,
}

/// Value abstraction mode for data-carrying message fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueAbstractionMode {
    /// Exact finite domains only.
    #[default]
    Exact,
    /// Sign-style abstraction:
    /// - int: {neg, zero, pos}
    /// - nat: {zero, pos}
    Sign,
}

/// Equivocation behavior of Byzantine senders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EquivocationMode {
    /// Byzantine senders may inject conflicting message variants in the same step.
    #[default]
    Full,
    /// Byzantine senders are restricted to one variant per message type per step.
    None,
}

/// Network authentication assumptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationMode {
    /// No explicit authentication assumptions.
    #[default]
    None,
    /// Authenticated sender identities (e.g., signatures).
    Signed,
}

/// Network-delivery semantics for message counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkSemantics {
    /// Legacy counter-network abstraction (role-scoped counters, no byzantine drop channel).
    #[default]
    Classic,
    /// Identity-coupled selective delivery for Byzantine channels.
    ///
    /// Adds per-variant sender-budget coupling across recipients and allows
    /// per-recipient selective delivery via lossy byzantine channels.
    IdentitySelective,
    /// Process-cohort selective delivery (higher-fidelity approximation).
    ///
    /// This refines recipient channels into internal per-role delivery cohorts,
    /// enabling different subsets of same-role processes to observe different
    /// byzantine deliveries while staying in counter abstraction.
    CohortSelective,
    /// Process-scoped selective delivery.
    ///
    /// Recipient channels are indexed by concrete process identifiers (`pid`)
    /// from bounded local domains, with per-step identity uniqueness constraints.
    ProcessSelective,
}

/// Scope for applying delivery-control constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliveryControlMode {
    /// Legacy counter semantics (no explicit recipient coupling).
    #[default]
    LegacyCounter,
    /// Controls are recipient-scoped.
    PerRecipient,
    /// Controls are globally coupled across recipients.
    Global,
}

/// Scope for adversary/drop fault budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultBudgetScope {
    /// Legacy counter semantics (`adv[k,v] <= f`, `drop[k,v] <= f`).
    #[default]
    LegacyCounter,
    /// Per-recipient aggregate budget.
    PerRecipient,
    /// Single aggregate budget for all recipients.
    Global,
}

/// Partial-Order Reduction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PorMode {
    /// All static and dynamic POR optimizations enabled (default).
    #[default]
    Full,
    /// Static pruning only (stutter, commutative duplicate, guard domination).
    /// Dynamic ample-set optimization is disabled.
    Static,
    /// All POR optimizations disabled. Full state space explored.
    Off,
}

/// Identity scope for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleIdentityScope {
    Role,
    Process,
}

/// Identity/key configuration for a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleIdentityConfig {
    pub scope: RoleIdentityScope,
    pub process_var: Option<String>,
    pub key_name: String,
}

/// Per-message authentication override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageAuthPolicy {
    /// Inherit global `authentication_mode`.
    #[default]
    Inherit,
    /// Authenticated sender/channel semantics for this message family.
    Authenticated,
    /// Unauthenticated sender/channel semantics for this message family.
    Unauthenticated,
}

/// Per-message equivocation override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageEquivocationPolicy {
    /// Inherit global `equivocation_mode`.
    #[default]
    Inherit,
    /// Full Byzantine equivocation for this message family.
    Full,
    /// No equivocation per sender identity for this message family.
    None,
}

/// Per-message transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePolicy {
    pub auth: MessageAuthPolicy,
    pub equivocation: MessageEquivocationPolicy,
}

impl Default for MessagePolicy {
    fn default() -> Self {
        Self {
            auth: MessageAuthPolicy::Inherit,
            equivocation: MessageEquivocationPolicy::Inherit,
        }
    }
}

/// Kind of first-class crypto object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrCryptoObjectKind {
    QuorumCertificate,
    ThresholdSignature,
}

impl fmt::Display for IrCryptoObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrCryptoObjectKind::QuorumCertificate => write!(f, "certificate"),
            IrCryptoObjectKind::ThresholdSignature => write!(f, "threshold_signature"),
        }
    }
}

/// Admissibility policy for conflicting crypto-object variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CryptoConflictPolicy {
    /// No extra admissibility restrictions.
    #[default]
    Allow,
    /// Reject conflicting object variants at a recipient.
    Exclusive,
}

impl fmt::Display for CryptoConflictPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoConflictPolicy::Allow => write!(f, "allow"),
            CryptoConflictPolicy::Exclusive => write!(f, "exclusive"),
        }
    }
}

/// First-class crypto object declaration lowered into IR.
#[derive(Debug, Clone)]
pub struct IrCryptoObjectSpec {
    pub name: String,
    pub kind: IrCryptoObjectKind,
    pub source_message: String,
    pub threshold: LinearCombination,
    pub signer_role: Option<String>,
    pub conflict_policy: CryptoConflictPolicy,
}

/// The core threshold automaton data structure.
///
/// Represents a parameterized system where N processes move between locations
/// according to threshold-guarded rules. Counter abstraction tracks how many
/// processes are in each location rather than individual process states.
/// Resilience, adversary-bound, and committee constraints for a threshold automaton.
#[derive(Debug, Clone, Default)]
pub struct ThresholdAutomatonConstraints {
    /// Resilience condition as a linear constraint.
    pub resilience_condition: Option<LinearConstraint>,
    /// Index of the parameter that bounds adversary (Byzantine) injections.
    pub adversary_bound_param: Option<ParamId>,
    /// Committee selection specifications.
    pub committees: Vec<IrCommitteeSpec>,
}

/// Fault model, timing, network, and delivery semantics for a threshold automaton.
#[derive(Debug, Clone, Default)]
pub struct ThresholdAutomatonSemantics {
    /// Fault model selected by the protocol.
    pub fault_model: FaultModel,
    /// Timing model selected by the protocol.
    pub timing_model: TimingModel,
    /// Parameter representing GST for partial synchrony (if used).
    pub gst_param: Option<ParamId>,
    /// Message value abstraction mode.
    pub value_abstraction: ValueAbstractionMode,
    /// Byzantine equivocation mode.
    pub equivocation_mode: EquivocationMode,
    /// Network authentication assumptions.
    pub authentication_mode: AuthenticationMode,
    /// Network message-delivery semantics.
    pub network_semantics: NetworkSemantics,
    /// Delivery-control coupling scope for network/adversary behavior.
    pub delivery_control: DeliveryControlMode,
    /// Scope for fault/drop budget constraints.
    pub fault_budget_scope: FaultBudgetScope,
    /// Partial-order reduction mode.
    pub por_mode: PorMode,
}

/// Identity, key ownership, and per-message authentication policies.
#[derive(Debug, Clone, Default)]
pub struct ThresholdAutomatonSecurity {
    /// Role identity/key semantics (explicit or inferred defaults).
    pub role_identities: IndexMap<String, RoleIdentityConfig>,
    /// Key ownership map (`key_name -> role`), derived from role identities.
    pub key_ownership: IndexMap<String, String>,
    /// Keys explicitly compromised by the adversary model.
    pub compromised_keys: IndexSet<String>,
    /// Per-message policy overrides (auth/equivocation).
    pub message_policies: IndexMap<String, MessagePolicy>,
    /// First-class crypto object declarations.
    pub crypto_objects: IndexMap<String, IrCryptoObjectSpec>,
}

/// A threshold automaton: the core IR for fault-tolerant distributed protocols.
#[derive(Debug, Clone)]
pub struct ThresholdAutomaton {
    /// Named locations (role, phase, local-var valuation).
    pub locations: Vec<Location>,
    /// Which locations are initial (all processes start here).
    pub initial_locations: Vec<LocationId>,
    /// Shared variables (message counters, etc.).
    pub shared_vars: Vec<SharedVar>,
    /// Transition rules.
    pub rules: Vec<Rule>,
    /// Protocol parameters (n, t, f, etc.).
    pub parameters: Vec<Parameter>,
    /// Verification/model constraints (resilience, adversary bound, committees).
    pub constraints: ThresholdAutomatonConstraints,
    /// Fault/network/por semantics.
    pub semantics: ThresholdAutomatonSemantics,
    /// Identity, key, and per-message security policies.
    pub security: ThresholdAutomatonSecurity,
    /// Roles marked as `leader` (exactly one process occupies leader locations at all times).
    pub leader_roles: Vec<String>,
    /// DAG-round declarations (name + parent edges).
    pub dag_rounds: Vec<IrDagRoundSpec>,
    /// Bounded log/sequence collection declarations.
    pub collections: Vec<IrCollectionSpec>,
    /// Reconfiguration specification (None if protocol has no dynamic membership).
    pub reconfiguration: Option<ReconfigurationSpec>,
    /// Logical clock declarations.
    pub clocks: Vec<IrClockSpec>,
}

/// A value that is either a reference to a protocol parameter or a concrete constant.
#[derive(Debug, Clone)]
pub enum ParamOrConst {
    Param(ParamId),
    Const(i64),
}

/// Committee selection specification in the IR.
#[derive(Debug, Clone)]
pub struct IrCommitteeSpec {
    /// Name of this committee.
    pub name: String,
    /// Total population size (N).
    pub population: ParamOrConst,
    /// Number of Byzantine nodes in the population (K).
    pub byzantine: ParamOrConst,
    /// Committee size (S).
    pub committee_size: ParamOrConst,
    /// Target failure probability epsilon.
    pub epsilon: Option<f64>,
    /// Which protocol parameter receives the derived adversary bound.
    pub bound_param: Option<ParamId>,
}

/// DAG round specification in the IR.
#[derive(Debug, Clone)]
pub struct IrDagRoundSpec {
    /// Round name.
    pub name: String,
    /// Names of parent rounds referenced by this round.
    pub parent_rounds: Vec<String>,
}

/// Kind of bounded collection in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrCollectionKind {
    /// Append-only log with FIFO read semantics.
    Log,
    /// Random-access bounded sequence.
    Sequence,
    /// FIFO channel with queue semantics (enqueue/dequeue).
    FifoChannel,
}

impl fmt::Display for IrCollectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrCollectionKind::Log => write!(f, "log"),
            IrCollectionKind::Sequence => write!(f, "sequence"),
            IrCollectionKind::FifoChannel => write!(f, "fifo_channel"),
        }
    }
}

/// Queue state model for FIFO channels.
///
/// Tracks head (dequeue position) and tail (enqueue position) indices
/// to enforce FIFO ordering and capacity constraints. The queue occupancy
/// is `tail - head`, bounded by the collection's `capacity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueueModel {
    /// Not a queue — used for log and sequence collections.
    #[default]
    None,
    /// Unbounded-index FIFO queue: head and tail are monotonically increasing
    /// integers. Occupancy = tail - head, bounded by capacity.
    LinearFifo,
}

/// Bounded log or sequence specification in the IR.
#[derive(Debug, Clone)]
pub struct IrCollectionSpec {
    /// Name of this collection type.
    pub name: String,
    /// Log, sequence, or FIFO channel.
    pub kind: IrCollectionKind,
    /// Element type name (e.g., "int", "bool", "Vote").
    pub element_type: String,
    /// Maximum capacity as a linear combination of parameters/constants.
    pub capacity: LinearCombination,
    /// Queue state model (only meaningful for FifoChannel).
    pub queue_model: QueueModel,
}

/// Logical clock specification in the IR.
#[derive(Debug, Clone)]
pub struct IrClockSpec {
    /// Name of this clock.
    pub name: String,
}

impl ThresholdAutomaton {
    pub fn new() -> Self {
        Self {
            locations: Vec::new(),
            initial_locations: Vec::new(),
            shared_vars: Vec::new(),
            rules: Vec::new(),
            parameters: Vec::new(),
            constraints: ThresholdAutomatonConstraints::default(),
            semantics: ThresholdAutomatonSemantics::default(),
            security: ThresholdAutomatonSecurity::default(),
            leader_roles: Vec::new(),
            dag_rounds: Vec::new(),
            collections: Vec::new(),
            reconfiguration: None,
            clocks: Vec::new(),
        }
    }

    pub fn add_location(&mut self, loc: Location) -> LocationId {
        let id = LocationId::from(self.locations.len());
        self.locations.push(loc);
        id
    }

    pub fn add_shared_var(&mut self, var: SharedVar) -> SharedVarId {
        let id = SharedVarId::from(self.shared_vars.len());
        self.shared_vars.push(var);
        id
    }

    pub fn add_rule(&mut self, rule: Rule) -> RuleId {
        let id = RuleId::from(self.rules.len());
        self.rules.push(rule);
        id
    }

    pub fn add_parameter(&mut self, param: Parameter) -> ParamId {
        let id = ParamId::from(self.parameters.len());
        self.parameters.push(param);
        id
    }

    pub fn find_param_by_name(&self, name: &str) -> Option<ParamId> {
        self.parameters
            .iter()
            .position(|p| p.name == name)
            .map(ParamId::from)
    }

    pub fn find_shared_var_by_name(&self, name: &str) -> Option<SharedVarId> {
        self.shared_vars
            .iter()
            .position(|v| v.name == name)
            .map(SharedVarId::from)
    }

    pub fn find_location_by_name(&self, name: &str) -> Option<LocationId> {
        self.locations
            .iter()
            .position(|l| l.name == name)
            .map(LocationId::from)
    }

    /// Return the number of control locations.
    pub fn num_locations(&self) -> usize {
        self.locations.len()
    }

    /// Return the number of shared variables.
    pub fn num_shared_vars(&self) -> usize {
        self.shared_vars.len()
    }

    /// Return the number of transition rules.
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    /// Return the number of symbolic parameters.
    pub fn num_parameters(&self) -> usize {
        self.parameters.len()
    }

    pub fn add_collection(&mut self, spec: IrCollectionSpec) -> CollectionId {
        let id = CollectionId::from(self.collections.len());
        self.collections.push(spec);
        id
    }

    pub fn find_collection_by_name(&self, name: &str) -> Option<CollectionId> {
        self.collections
            .iter()
            .position(|c| c.name == name)
            .map(CollectionId::from)
    }

    pub fn add_clock(&mut self, spec: IrClockSpec) -> ClockId {
        let id = ClockId::from(self.clocks.len());
        self.clocks.push(spec);
        id
    }

    pub fn find_clock_by_name(&self, name: &str) -> Option<ClockId> {
        self.clocks
            .iter()
            .position(|c| c.name == name)
            .map(ClockId::from)
    }

    pub fn role_locations(&self, role: &str) -> Vec<LocationId> {
        self.locations
            .iter()
            .enumerate()
            .filter(|(_, loc)| loc.role == role)
            .map(|(id, _)| LocationId::from(id))
            .collect()
    }

    pub fn message_effective_authenticated(&self, message_family: &str) -> bool {
        match self
            .security
            .message_policies
            .get(message_family)
            .map(|p| p.auth)
            .unwrap_or(MessageAuthPolicy::Inherit)
        {
            MessageAuthPolicy::Authenticated => true,
            MessageAuthPolicy::Unauthenticated => false,
            MessageAuthPolicy::Inherit => {
                self.semantics.authentication_mode == AuthenticationMode::Signed
            }
        }
    }

    pub fn message_effective_non_equivocating(&self, message_family: &str) -> bool {
        match self
            .security
            .message_policies
            .get(message_family)
            .map(|p| p.equivocation)
            .unwrap_or(MessageEquivocationPolicy::Inherit)
        {
            MessageEquivocationPolicy::None => true,
            MessageEquivocationPolicy::Full => false,
            MessageEquivocationPolicy::Inherit => {
                self.semantics.equivocation_mode == EquivocationMode::None
            }
        }
    }

    pub fn key_owner(&self, key: &str) -> Option<&str> {
        self.security.key_ownership.get(key).map(String::as_str)
    }

    pub fn key_is_compromised(&self, key: &str) -> bool {
        self.security.compromised_keys.contains(key)
    }

    /// True if any rule has parameter updates (reconfiguration actions).
    pub fn has_reconfiguration(&self) -> bool {
        self.rules.iter().any(|r| !r.param_updates.is_empty())
    }

    /// Return the IDs and names of parameters marked as time-varying.
    pub fn time_varying_params(&self) -> Vec<(ParamId, &str)> {
        self.parameters
            .iter()
            .enumerate()
            .filter(|(_, p)| p.time_varying)
            .map(|(i, p)| (ParamId::from(i), p.name.as_str()))
            .collect()
    }

    /// Validate internal consistency of the threshold automaton.
    ///
    /// Checks that all location, shared-variable, and parameter references
    /// are within bounds. Should be called immediately after lowering.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let num_locs = self.locations.len();
        let num_vars = self.shared_vars.len();
        let num_params = self.parameters.len();

        // Check initial locations
        for &loc_id in &self.initial_locations {
            if loc_id.as_usize() >= num_locs {
                return Err(ValidationError::InvalidInitialLocation {
                    location_id: loc_id,
                    max: num_locs.saturating_sub(1),
                });
            }
        }

        // Check rules
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            let rule_id = RuleId::from(rule_idx);
            if rule.from.as_usize() >= num_locs {
                return Err(ValidationError::InvalidRuleSource {
                    rule_id,
                    location_id: rule.from,
                    max: num_locs.saturating_sub(1),
                });
            }
            if rule.to.as_usize() >= num_locs {
                return Err(ValidationError::InvalidRuleTarget {
                    rule_id,
                    location_id: rule.to,
                    max: num_locs.saturating_sub(1),
                });
            }

            // Check guard atoms
            for atom in &rule.guard.atoms {
                match atom {
                    GuardAtom::Threshold { vars, bound, .. } => {
                        for &var_id in vars {
                            if var_id.as_usize() >= num_vars {
                                return Err(ValidationError::InvalidGuardVar {
                                    rule_id,
                                    var_id,
                                    max: num_vars.saturating_sub(1),
                                });
                            }
                        }
                        for &(_, param_id) in &bound.terms {
                            if param_id.as_usize() >= num_params {
                                return Err(ValidationError::InvalidGuardParam {
                                    rule_id,
                                    param_id,
                                    max: num_params.saturating_sub(1),
                                });
                            }
                        }
                    }
                }
            }

            // Check updates
            for upd in &rule.updates {
                if upd.var.as_usize() >= num_vars {
                    return Err(ValidationError::InvalidUpdateVar {
                        rule_id,
                        var_id: upd.var,
                        max: num_vars.saturating_sub(1),
                    });
                }
                if let UpdateKind::Set(ref lc) = upd.kind {
                    for &(_, param_id) in &lc.terms {
                        if param_id.as_usize() >= num_params {
                            return Err(ValidationError::InvalidGuardParam {
                                rule_id,
                                param_id,
                                max: num_params.saturating_sub(1),
                            });
                        }
                    }
                }
            }

            // Check timeout guards
            for guard in &rule.clock_guards {
                if guard.clock.as_usize() >= self.clocks.len() {
                    return Err(ValidationError::InvalidClockGuardClock {
                        rule_id,
                        clock_id: guard.clock,
                        max: self.clocks.len().saturating_sub(1),
                    });
                }
                for &(_, param_id) in &guard.bound.terms {
                    if param_id.as_usize() >= num_params {
                        return Err(ValidationError::InvalidGuardParam {
                            rule_id,
                            param_id,
                            max: num_params.saturating_sub(1),
                        });
                    }
                }
            }

            // Check param updates (reconfiguration)
            for pu in &rule.param_updates {
                if pu.param.as_usize() >= num_params {
                    return Err(ValidationError::InvalidParamUpdateTarget {
                        rule_id,
                        param_id: pu.param,
                        max: num_params.saturating_sub(1),
                    });
                }
                if !self.parameters[pu.param.as_usize()].time_varying {
                    return Err(ValidationError::ParamUpdateOnFixedParam {
                        rule_id,
                        param_name: self.parameters[pu.param.as_usize()].name.clone(),
                    });
                }
                for &(_, ref_param_id) in &pu.value.terms {
                    if ref_param_id.as_usize() >= num_params {
                        return Err(ValidationError::InvalidParamUpdateValue {
                            rule_id,
                            param_id: ref_param_id,
                            max: num_params.saturating_sub(1),
                        });
                    }
                }
            }

            // Check clock updates
            for upd in &rule.clock_updates {
                if upd.clock.as_usize() >= self.clocks.len() {
                    return Err(ValidationError::InvalidClockUpdateClock {
                        rule_id,
                        clock_id: upd.clock,
                        max: self.clocks.len().saturating_sub(1),
                    });
                }
                if let ClockUpdateKind::TickBy(ref lc) = upd.kind {
                    for &(_, param_id) in &lc.terms {
                        if param_id.as_usize() >= num_params {
                            return Err(ValidationError::InvalidGuardParam {
                                rule_id,
                                param_id,
                                max: num_params.saturating_sub(1),
                            });
                        }
                    }
                }
            }
        }

        // Check adversary bound param
        if let Some(param_id) = self.constraints.adversary_bound_param {
            if param_id.as_usize() >= num_params {
                return Err(ValidationError::InvalidAdversaryParam {
                    param_id,
                    max: num_params.saturating_sub(1),
                });
            }
        }

        // Check GST param
        if let Some(param_id) = self.semantics.gst_param {
            if param_id.as_usize() >= num_params {
                return Err(ValidationError::InvalidGstParam {
                    param_id,
                    max: num_params.saturating_sub(1),
                });
            }
        }

        // Check committee bound params
        for committee in &self.constraints.committees {
            if let Some(param_id) = committee.bound_param {
                if param_id.as_usize() >= num_params {
                    return Err(ValidationError::InvalidCommitteeBoundParam {
                        name: committee.name.clone(),
                        param_id,
                        max: num_params.saturating_sub(1),
                    });
                }
            }
        }

        // Check resilience condition param IDs
        if let Some(ref rc) = self.constraints.resilience_condition {
            for &(_, param_id) in &rc.lhs.terms {
                if param_id.as_usize() >= num_params {
                    return Err(ValidationError::InvalidResilienceParam {
                        param_id,
                        max: num_params.saturating_sub(1),
                    });
                }
            }
            for &(_, param_id) in &rc.rhs.terms {
                if param_id.as_usize() >= num_params {
                    return Err(ValidationError::InvalidResilienceParam {
                        param_id,
                        max: num_params.saturating_sub(1),
                    });
                }
            }
        }

        if let Some(spec) = &self.reconfiguration {
            if spec.semantics != ReconfigurationSemantics::NextStep {
                return Err(ValidationError::UnsupportedReconfigurationSemantics {
                    semantics: spec.semantics,
                });
            }
        }

        Ok(())
    }
}

/// Errors from validating a `ThresholdAutomaton`'s internal consistency.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Rule {rule_id} references invalid source location {location_id} (max: {max})")]
    InvalidRuleSource {
        rule_id: RuleId,
        location_id: LocationId,
        max: usize,
    },
    #[error("Rule {rule_id} references invalid target location {location_id} (max: {max})")]
    InvalidRuleTarget {
        rule_id: RuleId,
        location_id: LocationId,
        max: usize,
    },
    #[error("Rule {rule_id} guard references invalid shared var {var_id} (max: {max})")]
    InvalidGuardVar {
        rule_id: RuleId,
        var_id: SharedVarId,
        max: usize,
    },
    #[error("Rule {rule_id} guard references invalid parameter {param_id} (max: {max})")]
    InvalidGuardParam {
        rule_id: RuleId,
        param_id: ParamId,
        max: usize,
    },
    #[error("Rule {rule_id} timeout guard references invalid clock {clock_id} (max: {max})")]
    InvalidClockGuardClock {
        rule_id: RuleId,
        clock_id: ClockId,
        max: usize,
    },
    #[error("Rule {rule_id} update references invalid shared var {var_id} (max: {max})")]
    InvalidUpdateVar {
        rule_id: RuleId,
        var_id: SharedVarId,
        max: usize,
    },
    #[error("Rule {rule_id} clock update references invalid clock {clock_id} (max: {max})")]
    InvalidClockUpdateClock {
        rule_id: RuleId,
        clock_id: ClockId,
        max: usize,
    },
    #[error("Initial location {location_id} is out of bounds (max: {max})")]
    InvalidInitialLocation { location_id: LocationId, max: usize },
    #[error("Adversary bound param {param_id} is out of bounds (max: {max})")]
    InvalidAdversaryParam { param_id: ParamId, max: usize },
    #[error("GST param {param_id} is out of bounds (max: {max})")]
    InvalidGstParam { param_id: ParamId, max: usize },
    #[error("Committee '{name}' bound param {param_id} is out of bounds (max: {max})")]
    InvalidCommitteeBoundParam {
        name: String,
        param_id: ParamId,
        max: usize,
    },
    #[error("Resilience condition references invalid parameter {param_id} (max: {max})")]
    InvalidResilienceParam { param_id: ParamId, max: usize },
    #[error(
        "Unsupported reconfiguration semantics '{semantics}'; only 'next_step' is implemented"
    )]
    UnsupportedReconfigurationSemantics { semantics: ReconfigurationSemantics },
    #[error("Rule {rule_id} param_update targets invalid parameter {param_id} (max: {max})")]
    InvalidParamUpdateTarget {
        rule_id: RuleId,
        param_id: ParamId,
        max: usize,
    },
    #[error(
        "Rule {rule_id} param_update targets fixed (non-time-varying) parameter '{param_name}'"
    )]
    ParamUpdateOnFixedParam { rule_id: RuleId, param_name: String },
    #[error(
        "Rule {rule_id} param_update value references invalid parameter {param_id} (max: {max})"
    )]
    InvalidParamUpdateValue {
        rule_id: RuleId,
        param_id: ParamId,
        max: usize,
    },
}

impl Default for ThresholdAutomaton {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ThresholdAutomaton {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Threshold Automaton:")?;
        writeln!(f, "  Parameters:")?;
        for (i, p) in self.parameters.iter().enumerate() {
            writeln!(f, "    p{i}: {}", p.name)?;
        }
        if let Some(ref rc) = self.constraints.resilience_condition {
            writeln!(f, "  Resilience: {rc}")?;
        }
        writeln!(
            f,
            "  Fault model: {}",
            match self.semantics.fault_model {
                FaultModel::Byzantine => "byzantine",
                FaultModel::Crash => "crash",
                FaultModel::CrashRecovery => "crash_recovery",
                FaultModel::Omission => "omission",
            }
        )?;
        writeln!(
            f,
            "  Timing model: {}",
            match self.semantics.timing_model {
                TimingModel::Asynchronous => "asynchronous",
                TimingModel::PartialSynchrony => "partial_synchrony",
            }
        )?;
        if let Some(pid) = self.semantics.gst_param {
            writeln!(
                f,
                "  GST parameter: p{pid} ({})",
                self.parameters[pid.as_usize()].name
            )?;
        }
        writeln!(
            f,
            "  Value abstraction: {}",
            match self.semantics.value_abstraction {
                ValueAbstractionMode::Exact => "exact",
                ValueAbstractionMode::Sign => "sign",
            }
        )?;
        writeln!(
            f,
            "  Byzantine equivocation: {}",
            match self.semantics.equivocation_mode {
                EquivocationMode::Full => "full",
                EquivocationMode::None => "none",
            }
        )?;
        writeln!(
            f,
            "  Authentication: {}",
            match self.semantics.authentication_mode {
                AuthenticationMode::None => "none",
                AuthenticationMode::Signed => "signed",
            }
        )?;
        writeln!(
            f,
            "  Network semantics: {}",
            match self.semantics.network_semantics {
                NetworkSemantics::Classic => "classic",
                NetworkSemantics::IdentitySelective => "identity_selective",
                NetworkSemantics::CohortSelective => "cohort_selective",
                NetworkSemantics::ProcessSelective => "process_selective",
            }
        )?;
        writeln!(
            f,
            "  Delivery control: {}",
            match self.semantics.delivery_control {
                DeliveryControlMode::LegacyCounter => "legacy_counter",
                DeliveryControlMode::PerRecipient => "per_recipient",
                DeliveryControlMode::Global => "global",
            }
        )?;
        writeln!(
            f,
            "  Fault budget scope: {}",
            match self.semantics.fault_budget_scope {
                FaultBudgetScope::LegacyCounter => "legacy_counter",
                FaultBudgetScope::PerRecipient => "per_recipient",
                FaultBudgetScope::Global => "global",
            }
        )?;
        if !self.security.role_identities.is_empty() {
            writeln!(f, "  Identities:")?;
            for (role, cfg) in &self.security.role_identities {
                match cfg.scope {
                    RoleIdentityScope::Role => {
                        writeln!(f, "    {role}: role (key={})", cfg.key_name)?;
                    }
                    RoleIdentityScope::Process => {
                        let pid = cfg.process_var.as_deref().unwrap_or("pid");
                        writeln!(f, "    {role}: process({pid}) (key={})", cfg.key_name)?;
                    }
                }
            }
        }
        if !self.security.key_ownership.is_empty() {
            writeln!(f, "  Key ownership:")?;
            for (key, role) in &self.security.key_ownership {
                let compromised = if self.security.compromised_keys.contains(key) {
                    " (compromised)"
                } else {
                    ""
                };
                writeln!(f, "    {key}: {role}{compromised}")?;
            }
        } else if !self.security.compromised_keys.is_empty() {
            writeln!(f, "  Compromised keys:")?;
            for key in &self.security.compromised_keys {
                writeln!(f, "    {key}")?;
            }
        }
        if !self.security.message_policies.is_empty() {
            writeln!(f, "  Message policies:")?;
            for (msg, pol) in &self.security.message_policies {
                let auth = match pol.auth {
                    MessageAuthPolicy::Inherit => "inherit",
                    MessageAuthPolicy::Authenticated => "authenticated",
                    MessageAuthPolicy::Unauthenticated => "unauthenticated",
                };
                let equiv = match pol.equivocation {
                    MessageEquivocationPolicy::Inherit => "inherit",
                    MessageEquivocationPolicy::Full => "full",
                    MessageEquivocationPolicy::None => "none",
                };
                writeln!(f, "    {msg}: auth={auth}, equivocation={equiv}")?;
            }
        }
        if !self.security.crypto_objects.is_empty() {
            writeln!(f, "  Crypto objects:")?;
            for spec in self.security.crypto_objects.values() {
                let signer = spec
                    .signer_role
                    .as_deref()
                    .map(|s| format!(", signer={s}"))
                    .unwrap_or_default();
                writeln!(
                    f,
                    "    {}: {} from {} threshold {}{} conflicts={}",
                    spec.name,
                    spec.kind,
                    spec.source_message,
                    spec.threshold,
                    signer,
                    spec.conflict_policy
                )?;
            }
        }
        if !self.leader_roles.is_empty() {
            writeln!(f, "  Leader roles:")?;
            for role in &self.leader_roles {
                writeln!(f, "    {role}")?;
            }
        }
        if !self.dag_rounds.is_empty() {
            writeln!(f, "  DAG rounds:")?;
            for round in &self.dag_rounds {
                if round.parent_rounds.is_empty() {
                    writeln!(f, "    {}: (root)", round.name)?;
                } else {
                    writeln!(f, "    {}: {}", round.name, round.parent_rounds.join(", "))?;
                }
            }
        }
        if !self.collections.is_empty() {
            writeln!(f, "  Collections:")?;
            for (i, coll) in self.collections.iter().enumerate() {
                writeln!(
                    f,
                    "    c{i}: {} {} (element={}, capacity={})",
                    coll.kind, coll.name, coll.element_type, coll.capacity
                )?;
            }
        }
        if !self.clocks.is_empty() {
            writeln!(f, "  Clocks:")?;
            for (i, clock) in self.clocks.iter().enumerate() {
                writeln!(f, "    t{i}: {}", clock.name)?;
            }
        }
        writeln!(f, "  Locations:")?;
        for (i, loc) in self.locations.iter().enumerate() {
            let initial = if self.initial_locations.contains(&LocationId::from(i)) {
                " (initial)"
            } else {
                ""
            };
            writeln!(f, "    L{i}: {}{initial}", loc.name)?;
        }
        writeln!(f, "  Shared variables:")?;
        for (i, v) in self.shared_vars.iter().enumerate() {
            if v.distinct {
                if let Some(role) = &v.distinct_role {
                    writeln!(f, "    g{i}: {} ({} distinct from {role})", v.name, v.kind)?;
                } else {
                    writeln!(f, "    g{i}: {} ({} distinct)", v.name, v.kind)?;
                }
            } else {
                writeln!(f, "    g{i}: {} ({})", v.name, v.kind)?;
            }
        }
        writeln!(f, "  Rules:")?;
        for (i, r) in self.rules.iter().enumerate() {
            writeln!(f, "    r{i}: L{} -> L{} when {}", r.from, r.to, r.guard)?;
            for upd in &r.updates {
                writeln!(f, "      update: {upd}")?;
            }
            for upd in &r.collection_updates {
                writeln!(f, "      collection: {upd}")?;
            }
            for guard in &r.clock_guards {
                writeln!(f, "      timeout: {guard}")?;
            }
            for upd in &r.clock_updates {
                writeln!(f, "      clock: {upd}")?;
            }
        }
        Ok(())
    }
}

/// A parameter of the protocol (e.g., n, t, f).
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    /// True if this parameter can change via `reconfigure` actions.
    /// Time-varying parameters get per-epoch SMT variables.
    pub time_varying: bool,
}

impl Parameter {
    /// Create a static (non-time-varying) parameter.
    pub fn fixed(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            time_varying: false,
        }
    }

    /// Create a time-varying parameter (can be updated by reconfigure).
    pub fn varying(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            time_varying: true,
        }
    }
}

/// A location in the threshold automaton.
#[derive(Debug, Clone)]
pub struct Location {
    pub name: String,
    pub role: String,
    pub phase: String,
    /// Local variable valuation (for Boolean vars, the combination).
    pub local_vars: IndexMap<String, LocalValue>,
}

/// Local variable value (boolean or enum variant).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LocalValue {
    Bool(bool),
    Enum(String),
    Int(i64),
}

impl std::fmt::Display for LocalValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalValue::Bool(b) => write!(f, "{b}"),
            LocalValue::Enum(v) => write!(f, "{v}"),
            LocalValue::Int(n) => write!(f, "{n}"),
        }
    }
}

/// A shared variable (typically a message counter).
#[derive(Debug, Clone)]
pub struct SharedVar {
    pub name: String,
    pub kind: SharedVarKind,
    pub distinct: bool,
    pub distinct_role: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedVarKind {
    /// Counter for received messages of a type.
    MessageCounter,
    /// Protocol-level shared variable.
    Shared,
}

impl fmt::Display for SharedVarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SharedVarKind::MessageCounter => write!(f, "msg_counter"),
            SharedVarKind::Shared => write!(f, "shared"),
        }
    }
}

/// A transition rule in the threshold automaton.
#[derive(Debug, Clone)]
pub struct Rule {
    pub from: LocationId,
    pub to: LocationId,
    pub guard: Guard,
    pub updates: Vec<Update>,
    pub collection_updates: Vec<CollectionUpdate>,
    pub clock_guards: Vec<ClockGuard>,
    pub clock_updates: Vec<ClockUpdate>,
    /// Parameter updates from `reconfigure` actions.
    /// These change time-varying parameters at epoch boundaries.
    pub param_updates: Vec<ParamUpdate>,
}

/// An update to a bounded collection (log append or sequence set).
#[derive(Debug, Clone)]
pub struct CollectionUpdate {
    pub collection: CollectionId,
    pub kind: CollectionUpdateKind,
}

#[derive(Debug, Clone)]
pub enum CollectionUpdateKind {
    Append(LinearCombination),
    SetAt {
        index: LinearCombination,
        value: LinearCombination,
    },
    /// Enqueue a value at the tail of a FIFO channel.
    Enqueue(LinearCombination),
    /// Dequeue (consume) the head element of a FIFO channel.
    Dequeue,
}

impl fmt::Display for CollectionUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CollectionUpdateKind::Append(val) => write!(f, "c{}.append({})", self.collection, val),
            CollectionUpdateKind::SetAt { index, value } => {
                write!(f, "c{}[{}] = {}", self.collection, index, value)
            }
            CollectionUpdateKind::Enqueue(val) => {
                write!(f, "c{}.enqueue({})", self.collection, val)
            }
            CollectionUpdateKind::Dequeue => write!(f, "c{}.dequeue()", self.collection),
        }
    }
}

/// An update to a logical clock.
#[derive(Debug, Clone)]
pub struct ClockUpdate {
    pub clock: ClockId,
    pub kind: ClockUpdateKind,
}

#[derive(Debug, Clone)]
pub enum ClockUpdateKind {
    Reset,
    TickBy(LinearCombination),
}

impl fmt::Display for ClockUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ClockUpdateKind::Reset => write!(f, "t{} := 0", self.clock),
            ClockUpdateKind::TickBy(delta) => {
                write!(f, "t{} := t{} + {}", self.clock, self.clock, delta)
            }
        }
    }
}

/// A timeout/clock comparison guard on a rule.
#[derive(Debug, Clone)]
pub struct ClockGuard {
    pub clock: ClockId,
    pub op: CmpOp,
    pub bound: LinearCombination,
}

impl fmt::Display for ClockGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t{} {} {}", self.clock, self.op, self.bound)
    }
}

/// Guard on a rule — conjunction of guard atoms.
#[derive(Debug, Clone)]
pub struct Guard {
    pub atoms: Vec<GuardAtom>,
}

impl Guard {
    pub fn trivial() -> Self {
        Guard { atoms: Vec::new() }
    }

    pub fn single(atom: GuardAtom) -> Self {
        Guard { atoms: vec![atom] }
    }
}

impl fmt::Display for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.atoms.is_empty() {
            write!(f, "true")
        } else {
            for (i, a) in self.atoms.iter().enumerate() {
                if i > 0 {
                    write!(f, " && ")?;
                }
                write!(f, "{a}")?;
            }
            Ok(())
        }
    }
}

/// A single guard atom: a comparison involving shared vars and parameters.
#[derive(Debug, Clone)]
pub enum GuardAtom {
    /// sum(shared_vars) cmp_op linear_combination(params)
    Threshold {
        vars: Vec<SharedVarId>,
        op: CmpOp,
        bound: LinearCombination,
        /// When set, guards use exact sender-set semantics:
        /// `sum(ite(g_v > 0, 1, 0) for v in vars)`.
        distinct: bool,
    },
}

impl fmt::Display for GuardAtom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardAtom::Threshold {
                vars,
                op,
                bound,
                distinct,
            } => {
                let lhs = if vars.len() == 1 {
                    format!("g{}", vars[0])
                } else if vars.is_empty() {
                    "0".to_string()
                } else {
                    vars.iter()
                        .map(|v| format!("g{v}"))
                        .collect::<Vec<_>>()
                        .join(" + ")
                };
                if *distinct {
                    write!(f, "distinct({lhs}) {op} {bound}")
                } else {
                    write!(f, "{lhs} {op} {bound}")
                }
            }
        }
    }
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Ge,
    Le,
    Gt,
    Lt,
    Eq,
    Ne,
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CmpOp::Ge => write!(f, ">="),
            CmpOp::Le => write!(f, "<="),
            CmpOp::Gt => write!(f, ">"),
            CmpOp::Lt => write!(f, "<"),
            CmpOp::Eq => write!(f, "=="),
            CmpOp::Ne => write!(f, "!="),
        }
    }
}

/// Linear combination over parameters: c0 + c1*p1 + c2*p2 + ...
#[derive(Debug, Clone)]
pub struct LinearCombination {
    pub constant: i64,
    /// (coefficient, parameter_id)
    pub terms: Vec<(i64, ParamId)>,
}

impl LinearCombination {
    pub fn constant(c: i64) -> Self {
        LinearCombination {
            constant: c,
            terms: Vec::new(),
        }
    }

    pub fn param(id: ParamId) -> Self {
        LinearCombination {
            constant: 0,
            terms: vec![(1, id)],
        }
    }

    pub fn add(&self, other: &LinearCombination) -> Self {
        let mut result = self.clone();
        result.constant += other.constant;
        for &(coeff, pid) in &other.terms {
            if let Some(existing) = result.terms.iter_mut().find(|(_, p)| *p == pid) {
                existing.0 += coeff;
            } else {
                result.terms.push((coeff, pid));
            }
        }
        result
    }

    pub fn sub(&self, other: &LinearCombination) -> Self {
        let mut negated = other.clone();
        negated.constant = -negated.constant;
        for t in &mut negated.terms {
            t.0 = -t.0;
        }
        self.add(&negated)
    }

    pub fn scale(&self, factor: i64) -> Self {
        LinearCombination {
            constant: self.constant * factor,
            terms: self.terms.iter().map(|&(c, p)| (c * factor, p)).collect(),
        }
    }
}

impl fmt::Display for LinearCombination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terms.is_empty() {
            return write!(f, "{}", self.constant);
        }
        let mut first = true;
        if self.constant != 0 {
            write!(f, "{}", self.constant)?;
            first = false;
        }
        for &(coeff, pid) in &self.terms {
            if coeff == 0 {
                continue;
            }
            if first {
                if coeff == 1 {
                    write!(f, "p{pid}")?;
                } else if coeff == -1 {
                    write!(f, "-p{pid}")?;
                } else {
                    write!(f, "{coeff}*p{pid}")?;
                }
                first = false;
            } else if coeff > 0 {
                if coeff == 1 {
                    write!(f, " + p{pid}")?;
                } else {
                    write!(f, " + {coeff}*p{pid}")?;
                }
            } else if coeff == -1 {
                write!(f, " - p{pid}")?;
            } else {
                write!(f, " - {}*p{pid}", -coeff)?;
            }
        }
        if first {
            write!(f, "0")?;
        }
        Ok(())
    }
}

/// An update to a shared variable when a rule fires.
#[derive(Debug, Clone)]
pub struct Update {
    pub var: SharedVarId,
    pub kind: UpdateKind,
}

#[derive(Debug, Clone)]
pub enum UpdateKind {
    /// Increment by 1 (for message sends).
    Increment,
    /// Set to a specific linear combination.
    Set(LinearCombination),
}

impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            UpdateKind::Increment => write!(f, "g{} += 1", self.var),
            UpdateKind::Set(lc) => write!(f, "g{} := {lc}", self.var),
        }
    }
}

/// A linear constraint for resilience conditions.
#[derive(Debug, Clone)]
pub struct LinearConstraint {
    pub lhs: LinearCombination,
    pub op: CmpOp,
    pub rhs: LinearCombination,
}

impl fmt::Display for LinearConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.lhs, self.op, self.rhs)
    }
}

// ---------------------------------------------------------------------------
// Dynamic membership / reconfiguration (RECONF-02)
// ---------------------------------------------------------------------------

/// When a reconfiguration takes effect relative to the transition that fires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReconfigurationSemantics {
    /// New parameter values take effect at the *next* step boundary.
    /// The transition that fires the reconfigure uses the old values.
    #[default]
    NextStep,
    /// New parameter values take effect immediately within the same step.
    /// Guards have already been checked with old values, but subsequent
    /// transitions in the same step see the new values.
    Immediate,
}

impl fmt::Display for ReconfigurationSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReconfigurationSemantics::NextStep => write!(f, "next_step"),
            ReconfigurationSemantics::Immediate => write!(f, "immediate"),
        }
    }
}

/// Protocol-level reconfiguration specification.
#[derive(Debug, Clone, Default)]
pub struct ReconfigurationSpec {
    /// When parameter changes take effect.
    pub semantics: ReconfigurationSemantics,
    /// Maximum number of reconfigurations allowed per run (0 = unbounded).
    pub max_reconfigurations: usize,
}

/// A parameter update produced by a `reconfigure` action on a rule.
#[derive(Debug, Clone)]
pub struct ParamUpdate {
    /// Which parameter is being updated.
    pub param: ParamId,
    /// New value as a linear combination over (old) parameters.
    pub value: LinearCombination,
}

impl fmt::Display for ParamUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p{} := {}", self.param, self.value)
    }
}

#[cfg(test)]
mod tests;
