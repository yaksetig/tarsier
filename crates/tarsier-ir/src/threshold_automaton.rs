use indexmap::{IndexMap, IndexSet};
use std::fmt;

/// A unique identifier for a location in the threshold automaton.
pub type LocationId = usize;
/// A unique identifier for a shared variable.
pub type SharedVarId = usize;
/// A unique identifier for a rule.
pub type RuleId = usize;
/// A unique identifier for a parameter.
pub type ParamId = usize;

/// Fault model used for environment behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultModel {
    /// Byzantine environment can inject arbitrary messages up to a bound.
    #[default]
    Byzantine,
    /// Crash-stop failures (processes transition to a dead state and stop sending).
    Crash,
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
    /// Resilience condition as a linear constraint.
    pub resilience_condition: Option<LinearConstraint>,
    /// Index of the parameter that bounds adversary (Byzantine) injections.
    /// E.g., if `adversary { bound: f; }` and `f` is parameter index 2, this is Some(2).
    pub adversary_bound_param: Option<ParamId>,
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
    /// Committee selection specifications.
    pub committees: Vec<IrCommitteeSpec>,
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

impl ThresholdAutomaton {
    pub fn new() -> Self {
        Self {
            locations: Vec::new(),
            initial_locations: Vec::new(),
            shared_vars: Vec::new(),
            rules: Vec::new(),
            parameters: Vec::new(),
            resilience_condition: None,
            adversary_bound_param: None,
            fault_model: FaultModel::Byzantine,
            timing_model: TimingModel::Asynchronous,
            gst_param: None,
            value_abstraction: ValueAbstractionMode::Exact,
            equivocation_mode: EquivocationMode::Full,
            authentication_mode: AuthenticationMode::None,
            network_semantics: NetworkSemantics::Classic,
            delivery_control: DeliveryControlMode::LegacyCounter,
            fault_budget_scope: FaultBudgetScope::LegacyCounter,
            role_identities: IndexMap::new(),
            key_ownership: IndexMap::new(),
            compromised_keys: IndexSet::new(),
            message_policies: IndexMap::new(),
            crypto_objects: IndexMap::new(),
            committees: Vec::new(),
        }
    }

    pub fn add_location(&mut self, loc: Location) -> LocationId {
        let id = self.locations.len();
        self.locations.push(loc);
        id
    }

    pub fn add_shared_var(&mut self, var: SharedVar) -> SharedVarId {
        let id = self.shared_vars.len();
        self.shared_vars.push(var);
        id
    }

    pub fn add_rule(&mut self, rule: Rule) -> RuleId {
        let id = self.rules.len();
        self.rules.push(rule);
        id
    }

    pub fn add_parameter(&mut self, param: Parameter) -> ParamId {
        let id = self.parameters.len();
        self.parameters.push(param);
        id
    }

    pub fn find_param_by_name(&self, name: &str) -> Option<ParamId> {
        self.parameters.iter().position(|p| p.name == name)
    }

    pub fn find_shared_var_by_name(&self, name: &str) -> Option<SharedVarId> {
        self.shared_vars.iter().position(|v| v.name == name)
    }

    pub fn find_location_by_name(&self, name: &str) -> Option<LocationId> {
        self.locations.iter().position(|l| l.name == name)
    }

    pub fn role_locations(&self, role: &str) -> Vec<LocationId> {
        self.locations
            .iter()
            .enumerate()
            .filter(|(_, loc)| loc.role == role)
            .map(|(id, _)| id)
            .collect()
    }

    pub fn message_effective_authenticated(&self, message_family: &str) -> bool {
        match self
            .message_policies
            .get(message_family)
            .map(|p| p.auth)
            .unwrap_or(MessageAuthPolicy::Inherit)
        {
            MessageAuthPolicy::Authenticated => true,
            MessageAuthPolicy::Unauthenticated => false,
            MessageAuthPolicy::Inherit => self.authentication_mode == AuthenticationMode::Signed,
        }
    }

    pub fn message_effective_non_equivocating(&self, message_family: &str) -> bool {
        match self
            .message_policies
            .get(message_family)
            .map(|p| p.equivocation)
            .unwrap_or(MessageEquivocationPolicy::Inherit)
        {
            MessageEquivocationPolicy::None => true,
            MessageEquivocationPolicy::Full => false,
            MessageEquivocationPolicy::Inherit => self.equivocation_mode == EquivocationMode::None,
        }
    }

    pub fn key_owner(&self, key: &str) -> Option<&str> {
        self.key_ownership.get(key).map(String::as_str)
    }

    pub fn key_is_compromised(&self, key: &str) -> bool {
        self.compromised_keys.contains(key)
    }
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
        if let Some(ref rc) = self.resilience_condition {
            writeln!(f, "  Resilience: {rc}")?;
        }
        writeln!(
            f,
            "  Fault model: {}",
            match self.fault_model {
                FaultModel::Byzantine => "byzantine",
                FaultModel::Crash => "crash",
                FaultModel::Omission => "omission",
            }
        )?;
        writeln!(
            f,
            "  Timing model: {}",
            match self.timing_model {
                TimingModel::Asynchronous => "asynchronous",
                TimingModel::PartialSynchrony => "partial_synchrony",
            }
        )?;
        if let Some(pid) = self.gst_param {
            writeln!(f, "  GST parameter: p{pid} ({})", self.parameters[pid].name)?;
        }
        writeln!(
            f,
            "  Value abstraction: {}",
            match self.value_abstraction {
                ValueAbstractionMode::Exact => "exact",
                ValueAbstractionMode::Sign => "sign",
            }
        )?;
        writeln!(
            f,
            "  Byzantine equivocation: {}",
            match self.equivocation_mode {
                EquivocationMode::Full => "full",
                EquivocationMode::None => "none",
            }
        )?;
        writeln!(
            f,
            "  Authentication: {}",
            match self.authentication_mode {
                AuthenticationMode::None => "none",
                AuthenticationMode::Signed => "signed",
            }
        )?;
        writeln!(
            f,
            "  Network semantics: {}",
            match self.network_semantics {
                NetworkSemantics::Classic => "classic",
                NetworkSemantics::IdentitySelective => "identity_selective",
                NetworkSemantics::CohortSelective => "cohort_selective",
                NetworkSemantics::ProcessSelective => "process_selective",
            }
        )?;
        writeln!(
            f,
            "  Delivery control: {}",
            match self.delivery_control {
                DeliveryControlMode::LegacyCounter => "legacy_counter",
                DeliveryControlMode::PerRecipient => "per_recipient",
                DeliveryControlMode::Global => "global",
            }
        )?;
        writeln!(
            f,
            "  Fault budget scope: {}",
            match self.fault_budget_scope {
                FaultBudgetScope::LegacyCounter => "legacy_counter",
                FaultBudgetScope::PerRecipient => "per_recipient",
                FaultBudgetScope::Global => "global",
            }
        )?;
        if !self.role_identities.is_empty() {
            writeln!(f, "  Identities:")?;
            for (role, cfg) in &self.role_identities {
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
        if !self.key_ownership.is_empty() {
            writeln!(f, "  Key ownership:")?;
            for (key, role) in &self.key_ownership {
                let compromised = if self.compromised_keys.contains(key) {
                    " (compromised)"
                } else {
                    ""
                };
                writeln!(f, "    {key}: {role}{compromised}")?;
            }
        } else if !self.compromised_keys.is_empty() {
            writeln!(f, "  Compromised keys:")?;
            for key in &self.compromised_keys {
                writeln!(f, "    {key}")?;
            }
        }
        if !self.message_policies.is_empty() {
            writeln!(f, "  Message policies:")?;
            for (msg, pol) in &self.message_policies {
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
        if !self.crypto_objects.is_empty() {
            writeln!(f, "  Crypto objects:")?;
            for spec in self.crypto_objects.values() {
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
        writeln!(f, "  Locations:")?;
        for (i, loc) in self.locations.iter().enumerate() {
            let initial = if self.initial_locations.contains(&i) {
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
        }
        Ok(())
    }
}

/// A parameter of the protocol (e.g., n, t, f).
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
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
