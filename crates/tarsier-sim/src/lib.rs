//! Finite simulation engine for lowered Tarsier threshold automata.
//!
//! This crate is intentionally independent from the SMT verification pipeline.
//! It executes concrete, bounded schedules over the lowered counter-system IR and
//! emits both counter traces and runtime traces for inspection. Message counters
//! remain aggregate counters, but `received distinct` guards use concrete sender
//! provenance collected during the simulated run. The crate also exposes a
//! reusable message-queue network runner for protocol adapters that need
//! per-node local state machines.

pub mod avalanche;
pub mod hotstuff;
pub mod network;
pub mod phoenixx;

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use tarsier_ir::counter_system::{Configuration, Trace, TraceStep};
use tarsier_ir::runtime_trace::{ProcessEvent, ProcessEventKind, ProcessTrace, RuntimeTrace};
use tarsier_ir::threshold_automaton::{
    ClockUpdateKind, CmpOp, GuardAtom, LinearCombination, LinearConstraint, LocalValue, LocationId,
    Rule, RuleId, SharedVarId, SharedVarKind, ThresholdAutomaton, UpdateKind,
};

/// Rule selection policy for simulation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheduler {
    /// Pick the first enabled rule and first eligible process.
    First,
    /// Pick enabled rules and eligible processes using the configured seed.
    #[default]
    Random,
}

/// Simulation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationOptions {
    /// Maximum number of rule firings before stopping.
    pub max_steps: usize,
    /// Seed used by [`Scheduler::Random`].
    pub seed: u64,
    /// Rule/process scheduling policy.
    pub scheduler: Scheduler,
    /// Initial message/shared-counter values.
    ///
    /// Names may be exact lowered shared variable names (for example
    /// `cnt_Init@Replica`) or message-family names (for example `Init`).
    pub initial_shared: Vec<(String, i64)>,
}

impl Default for SimulationOptions {
    fn default() -> Self {
        Self {
            max_steps: 50,
            seed: 0,
            scheduler: Scheduler::Random,
            initial_shared: Vec::new(),
        }
    }
}

/// Per-step execution metadata for user-facing reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationStep {
    pub step: usize,
    pub rule_id: usize,
    pub process_id: u64,
    pub from_location: String,
    pub to_location: String,
    pub enabled_rules_before: usize,
}

/// Summary of one finite simulation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationSummary {
    pub steps_executed: usize,
    pub stopped_reason: StopReason,
    pub final_location_counts: Vec<(String, i64)>,
    pub final_shared_vars: Vec<(String, i64)>,
    pub final_params: Vec<(String, i64)>,
    pub final_clocks: Vec<(String, i64)>,
}

/// Why a simulation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    MaxSteps,
    Deadlock,
}

/// Complete simulation output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub summary: SimulationSummary,
    pub steps: Vec<SimulationStep>,
    pub counter_trace: Trace,
    pub runtime_trace: RuntimeTrace,
    pub warnings: Vec<String>,
}

/// Errors returned by the simulator.
#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("missing concrete value for parameter '{0}'")]
    MissingParameter(String),
    #[error("parameter '{name}' must be non-negative for simulation, got {value}")]
    NegativeParameter { name: String, value: i64 },
    #[error("simulation requires at least one initial location")]
    NoInitialLocation,
    #[error("simulation requires a positive process count, got {0}")]
    NonPositiveProcessCount(i64),
    #[error("parameter binding '{0}' does not match any protocol parameter")]
    UnknownParameter(String),
    #[error("initial shared/message seed '{0}' does not match any shared variable")]
    UnknownInitialShared(String),
    #[error("initial shared/message seed '{name}' must be non-negative, got {value}")]
    NegativeInitialShared { name: String, value: i64 },
    #[error("resilience condition is not satisfied by supplied parameters")]
    ResilienceViolation,
    #[error("internal simulation invariant failed: no process at enabled source location L{0}")]
    MissingProcessAtLocation(usize),
}

/// Execute a finite simulation over a lowered threshold automaton.
///
/// `param_bindings` must provide concrete values for every protocol parameter.
/// The simulator fires one process transition at a time (`delta = 1`) and uses
/// lowered message counters for threshold guards.
pub fn simulate(
    automaton: &ThresholdAutomaton,
    param_bindings: &[(String, i64)],
    options: SimulationOptions,
) -> Result<SimulationResult, SimulationError> {
    let mut params = concrete_params(automaton, param_bindings)?;
    validate_resilience(automaton, &params)?;
    let mut rng = DeterministicRng::new(options.seed);
    let mut warnings = simulation_warnings(automaton);

    let mut config = initial_configuration(automaton, &params)?;
    let mut message_provenance = MessageProvenance::new(automaton);
    apply_initial_shared(
        automaton,
        &mut config,
        &mut message_provenance,
        &options.initial_shared,
    )?;
    let initial_config = config.clone();
    let mut clocks = vec![0i64; automaton.clocks.len()];
    let mut processes = instantiate_processes(automaton, &config);

    let mut trace_steps = Vec::new();
    let mut report_steps = Vec::new();
    let mut stopped_reason = StopReason::MaxSteps;

    for step in 0..options.max_steps {
        let enabled = enabled_rules(automaton, &config, &params, &clocks, &message_provenance);
        if enabled.is_empty() {
            stopped_reason = StopReason::Deadlock;
            break;
        }

        let rule_index = choose_index(&enabled, options.scheduler, &mut rng);
        let rule_id = enabled[rule_index];
        let rule = &automaton.rules[rule_id];
        let proc_index = choose_process_at_location(
            &processes,
            rule.from.as_usize(),
            options.scheduler,
            &mut rng,
        )
        .ok_or_else(|| SimulationError::MissingProcessAtLocation(rule.from.as_usize()))?;

        let process_id = processes[proc_index].id;
        let from_name = location_name(automaton, rule.from);
        let to_name = location_name(automaton, rule.to);

        emit_pre_transition_receives(
            automaton,
            rule,
            &params,
            &config,
            &message_provenance,
            &mut processes[proc_index],
        );
        push_event(
            &mut processes[proc_index],
            ProcessEventKind::Transition {
                from_location: from_name.clone(),
                to_location: to_name.clone(),
                rule_id: Some(rule_id),
            },
        );
        emit_local_state_events(automaton, rule, &mut processes[proc_index]);

        config.kappa[rule.from.as_usize()] -= 1;
        config.kappa[rule.to.as_usize()] += 1;
        processes[proc_index].current_location = rule.to.as_usize();

        for update in &rule.updates {
            match &update.kind {
                UpdateKind::Increment => {
                    config.gamma[update.var.as_usize()] += 1;
                    if is_message_counter(automaton, update.var.as_usize()) {
                        message_provenance.record_send(update.var, process_id);
                    }
                    let message_type = automaton
                        .shared_vars
                        .get(update.var.as_usize())
                        .map(|v| v.name.clone())
                        .unwrap_or_else(|| format!("g{}", update.var));
                    push_event(
                        &mut processes[proc_index],
                        ProcessEventKind::Send {
                            message_type,
                            fields: vec![],
                        },
                    );
                }
                UpdateKind::Set(lc) => {
                    let value = eval_lc(lc, &params);
                    config.gamma[update.var.as_usize()] = value;
                    let var_name = automaton
                        .shared_vars
                        .get(update.var.as_usize())
                        .map(|v| v.name.clone())
                        .unwrap_or_else(|| format!("g{}", update.var));
                    push_event(
                        &mut processes[proc_index],
                        ProcessEventKind::VarUpdate {
                            var_name,
                            new_value: value.to_string(),
                        },
                    );
                }
            }
        }

        for update in &rule.param_updates {
            let value = eval_lc(&update.value, &params);
            params[update.param.as_usize()] = value;
        }
        config.params = params.clone();

        for update in &rule.clock_updates {
            let slot = &mut clocks[update.clock.as_usize()];
            match &update.kind {
                ClockUpdateKind::Reset => *slot = 0,
                ClockUpdateKind::TickBy(lc) => *slot += eval_lc(lc, &params),
            }
        }

        if !rule.collection_updates.is_empty() {
            warnings.push(format!(
                "step {} fired rule r{} with collection updates; collection contents are not tracked by this simulator yet",
                step + 1,
                rule_id
            ));
        }

        trace_steps.push(TraceStep {
            smt_step: step,
            rule_id: RuleId::from(rule_id),
            delta: 1,
            deliveries: vec![],
            config: config.clone(),
            por_status: None,
        });
        report_steps.push(SimulationStep {
            step: step + 1,
            rule_id,
            process_id,
            from_location: from_name,
            to_location: to_name,
            enabled_rules_before: enabled.len(),
        });
    }

    let counter_trace = Trace {
        initial_config,
        steps: trace_steps,
        param_values: param_values(automaton, &params),
    };
    let runtime_trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: protocol_name(automaton),
        params: param_values(automaton, &params),
        processes: processes
            .into_iter()
            .map(|p| ProcessTrace {
                process_id: p.id,
                role: p.role,
                events: p.events,
            })
            .collect(),
    };

    Ok(SimulationResult {
        summary: SimulationSummary {
            steps_executed: report_steps.len(),
            stopped_reason,
            final_location_counts: location_counts(automaton, &config),
            final_shared_vars: shared_var_values(automaton, &config),
            final_params: param_values(automaton, &params),
            final_clocks: clock_values(automaton, &clocks),
        },
        steps: report_steps,
        counter_trace,
        runtime_trace,
        warnings,
    })
}

fn concrete_params(
    automaton: &ThresholdAutomaton,
    bindings: &[(String, i64)],
) -> Result<Vec<i64>, SimulationError> {
    let mut by_name: HashMap<&str, i64> = HashMap::new();
    for (name, value) in bindings {
        if automaton.find_param_by_name(name).is_none() {
            return Err(SimulationError::UnknownParameter(name.clone()));
        }
        if *value < 0 {
            return Err(SimulationError::NegativeParameter {
                name: name.clone(),
                value: *value,
            });
        }
        by_name.insert(name, *value);
    }

    automaton
        .parameters
        .iter()
        .map(|p| {
            by_name
                .get(p.name.as_str())
                .copied()
                .ok_or_else(|| SimulationError::MissingParameter(p.name.clone()))
        })
        .collect()
}

fn validate_resilience(
    automaton: &ThresholdAutomaton,
    params: &[i64],
) -> Result<(), SimulationError> {
    if let Some(condition) = &automaton.constraints.resilience_condition {
        if !eval_constraint(condition, params) {
            return Err(SimulationError::ResilienceViolation);
        }
    }
    Ok(())
}

fn initial_configuration(
    automaton: &ThresholdAutomaton,
    params: &[i64],
) -> Result<Configuration, SimulationError> {
    if automaton.initial_locations.is_empty() {
        return Err(SimulationError::NoInitialLocation);
    }

    let process_count = process_count(automaton, params);
    if process_count <= 0 {
        return Err(SimulationError::NonPositiveProcessCount(process_count));
    }

    let mut config = Configuration::new(
        automaton.locations.len(),
        automaton.shared_vars.len(),
        automaton.parameters.len(),
    );
    config.params = params.to_vec();

    let init_count = automaton.initial_locations.len() as i64;
    let base = process_count / init_count;
    let mut remainder = process_count % init_count;
    for &loc in &automaton.initial_locations {
        let extra = i64::from(remainder > 0);
        config.kappa[loc.as_usize()] = base + extra;
        remainder = remainder.saturating_sub(1);
    }

    Ok(config)
}

fn apply_initial_shared(
    automaton: &ThresholdAutomaton,
    config: &mut Configuration,
    message_provenance: &mut MessageProvenance,
    seeds: &[(String, i64)],
) -> Result<(), SimulationError> {
    for (name, value) in seeds {
        if *value < 0 {
            return Err(SimulationError::NegativeInitialShared {
                name: name.clone(),
                value: *value,
            });
        }
        let matches: Vec<usize> = automaton
            .shared_vars
            .iter()
            .enumerate()
            .filter(|(_, var)| {
                var.name == *name
                    || message_family_name(&var.name)
                        .map(|family| family == name)
                        .unwrap_or(false)
            })
            .map(|(idx, _)| idx)
            .collect();
        if matches.is_empty() {
            return Err(SimulationError::UnknownInitialShared(name.clone()));
        }
        for idx in matches {
            config.gamma[idx] = *value;
            if is_message_counter(automaton, idx) {
                message_provenance.set_seed_senders(SharedVarId::from(idx), *value);
            }
        }
    }
    Ok(())
}

fn process_count(automaton: &ThresholdAutomaton, params: &[i64]) -> i64 {
    automaton
        .find_param_by_name("n")
        .or_else(|| (!automaton.parameters.is_empty()).then(|| 0.into()))
        .and_then(|pid| params.get(pid.as_usize()).copied())
        .unwrap_or(1)
}

fn instantiate_processes(
    automaton: &ThresholdAutomaton,
    config: &Configuration,
) -> Vec<ConcreteProcess> {
    let mut processes = Vec::new();
    let mut next_pid = 0u64;
    for (lid, count) in config.kappa.iter().copied().enumerate() {
        for _ in 0..count {
            let loc = &automaton.locations[lid];
            let mut proc = ConcreteProcess {
                id: next_pid,
                role: loc.role.clone(),
                current_location: lid,
                events: Vec::new(),
            };
            push_event(
                &mut proc,
                ProcessEventKind::Init {
                    location: loc.name.clone(),
                },
            );
            processes.push(proc);
            next_pid += 1;
        }
    }
    processes
}

fn enabled_rules(
    automaton: &ThresholdAutomaton,
    config: &Configuration,
    params: &[i64],
    clocks: &[i64],
    message_provenance: &MessageProvenance,
) -> Vec<usize> {
    automaton
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| config.kappa[rule.from.as_usize()] > 0)
        .filter(|(_, rule)| guard_enabled(rule, config, params, message_provenance))
        .filter(|(_, rule)| clock_guards_enabled(rule, params, clocks))
        .map(|(idx, _)| idx)
        .collect()
}

fn guard_enabled(
    rule: &Rule,
    config: &Configuration,
    params: &[i64],
    message_provenance: &MessageProvenance,
) -> bool {
    rule.guard
        .atoms
        .iter()
        .all(|atom| guard_atom_enabled(atom, config, params, message_provenance))
}

fn guard_atom_enabled(
    atom: &GuardAtom,
    config: &Configuration,
    params: &[i64],
    message_provenance: &MessageProvenance,
) -> bool {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            let lhs = if *distinct {
                message_provenance.distinct_sender_count(vars)
            } else {
                vars.iter().map(|v| config.gamma[v.as_usize()]).sum()
            };
            eval_cmp(lhs, *op, eval_lc(bound, params))
        }
    }
}

fn clock_guards_enabled(rule: &Rule, params: &[i64], clocks: &[i64]) -> bool {
    rule.clock_guards.iter().all(|guard| {
        eval_cmp(
            clocks[guard.clock.as_usize()],
            guard.op,
            eval_lc(&guard.bound, params),
        )
    })
}

fn emit_pre_transition_receives(
    automaton: &ThresholdAutomaton,
    rule: &Rule,
    params: &[i64],
    config: &Configuration,
    message_provenance: &MessageProvenance,
    proc: &mut ConcreteProcess,
) {
    for atom in &rule.guard.atoms {
        let GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } = atom;
        let Some(&first_var) = vars.first() else {
            continue;
        };
        let Some(shared_var) = automaton.shared_vars.get(first_var.as_usize()) else {
            continue;
        };
        if shared_var.kind != SharedVarKind::MessageCounter {
            continue;
        }

        let required = lower_bound_for_receive_events(*op, eval_lc(bound, params));
        if required <= 0 {
            continue;
        }
        let available = if *distinct {
            message_provenance.distinct_sender_count(vars)
        } else {
            vars.iter().map(|v| config.gamma[v.as_usize()]).sum()
        };
        let count = required.min(available).max(0);
        if *distinct {
            for sender in message_provenance
                .distinct_senders(vars)
                .into_iter()
                .take(count as usize)
            {
                push_event(
                    proc,
                    ProcessEventKind::Receive {
                        message_type: shared_var.name.clone(),
                        from_process: sender,
                        fields: vec![],
                    },
                );
            }
        } else {
            for _ in 0..count {
                push_event(
                    proc,
                    ProcessEventKind::Receive {
                        message_type: shared_var.name.clone(),
                        from_process: 0,
                        fields: vec![],
                    },
                );
            }
        }
    }
}

fn lower_bound_for_receive_events(op: CmpOp, rhs: i64) -> i64 {
    match op {
        CmpOp::Ge | CmpOp::Eq => rhs,
        CmpOp::Gt => rhs + 1,
        CmpOp::Le | CmpOp::Lt | CmpOp::Ne => 0,
    }
}

fn emit_local_state_events(
    automaton: &ThresholdAutomaton,
    rule: &Rule,
    proc: &mut ConcreteProcess,
) {
    let from = &automaton.locations[rule.from.as_usize()];
    let to = &automaton.locations[rule.to.as_usize()];
    for (name, new_value) in &to.local_vars {
        if from.local_vars.get(name) != Some(new_value) {
            push_event(
                proc,
                ProcessEventKind::VarUpdate {
                    var_name: name.clone(),
                    new_value: new_value.to_string(),
                },
            );
        }
    }

    let was_decided = matches!(from.local_vars.get("decided"), Some(LocalValue::Bool(true)));
    let now_decided = matches!(to.local_vars.get("decided"), Some(LocalValue::Bool(true)));
    if !was_decided && now_decided {
        let value = to
            .local_vars
            .get("decision")
            .map(ToString::to_string)
            .unwrap_or_else(|| "true".into());
        push_event(proc, ProcessEventKind::Decide { value });
    }
}

fn choose_index(candidates: &[usize], scheduler: Scheduler, rng: &mut DeterministicRng) -> usize {
    match scheduler {
        Scheduler::First => 0,
        Scheduler::Random => rng.index(candidates.len()),
    }
}

fn choose_process_at_location(
    processes: &[ConcreteProcess],
    location: usize,
    scheduler: Scheduler,
    rng: &mut DeterministicRng,
) -> Option<usize> {
    let candidates: Vec<usize> = processes
        .iter()
        .enumerate()
        .filter(|(_, proc)| proc.current_location == location)
        .map(|(idx, _)| idx)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let selected = choose_index(&candidates, scheduler, rng);
    candidates.get(selected).copied()
}

fn eval_lc(lc: &LinearCombination, params: &[i64]) -> i64 {
    let mut value = lc.constant;
    for &(coeff, pid) in &lc.terms {
        value += coeff * params.get(pid.as_usize()).copied().unwrap_or(0);
    }
    value
}

fn eval_constraint(condition: &LinearConstraint, params: &[i64]) -> bool {
    eval_cmp(
        eval_lc(&condition.lhs, params),
        condition.op,
        eval_lc(&condition.rhs, params),
    )
}

fn eval_cmp(lhs: i64, op: CmpOp, rhs: i64) -> bool {
    match op {
        CmpOp::Ge => lhs >= rhs,
        CmpOp::Le => lhs <= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Lt => lhs < rhs,
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
    }
}

fn location_counts(automaton: &ThresholdAutomaton, config: &Configuration) -> Vec<(String, i64)> {
    automaton
        .locations
        .iter()
        .enumerate()
        .filter_map(|(idx, loc)| {
            let count = config.kappa.get(idx).copied().unwrap_or(0);
            (count != 0).then(|| (loc.name.clone(), count))
        })
        .collect()
}

fn shared_var_values(automaton: &ThresholdAutomaton, config: &Configuration) -> Vec<(String, i64)> {
    automaton
        .shared_vars
        .iter()
        .enumerate()
        .filter_map(|(idx, var)| {
            let value = config.gamma.get(idx).copied().unwrap_or(0);
            (value != 0).then(|| (var.name.clone(), value))
        })
        .collect()
}

fn param_values(automaton: &ThresholdAutomaton, params: &[i64]) -> Vec<(String, i64)> {
    automaton
        .parameters
        .iter()
        .enumerate()
        .map(|(idx, p)| (p.name.clone(), params.get(idx).copied().unwrap_or(0)))
        .collect()
}

fn clock_values(automaton: &ThresholdAutomaton, clocks: &[i64]) -> Vec<(String, i64)> {
    automaton
        .clocks
        .iter()
        .enumerate()
        .map(|(idx, c)| (c.name.clone(), clocks.get(idx).copied().unwrap_or(0)))
        .collect()
}

fn location_name(automaton: &ThresholdAutomaton, id: LocationId) -> String {
    automaton
        .locations
        .get(id.as_usize())
        .map(|l| l.name.clone())
        .unwrap_or_else(|| format!("L{}", id))
}

fn protocol_name(automaton: &ThresholdAutomaton) -> String {
    automaton
        .locations
        .first()
        .map(|loc| loc.role.clone())
        .unwrap_or_else(|| "Protocol".into())
}

fn simulation_warnings(automaton: &ThresholdAutomaton) -> Vec<String> {
    let mut warnings = Vec::new();
    if automaton.semantics.network_semantics
        != tarsier_ir::threshold_automaton::NetworkSemantics::Classic
    {
        warnings.push(format!(
            "simulation executes lowered counter semantics; distinct-sender guards use concrete sender provenance, but {:?} delivery/adversary semantics are still approximated",
            automaton.semantics.network_semantics
        ));
    }
    if !automaton.security.crypto_objects.is_empty() {
        warnings.push(
            "crypto objects are represented through their lowered counters/flags; cryptographic provenance is not simulated yet"
                .into(),
        );
    }
    if !automaton.collections.is_empty() {
        warnings.push(
            "bounded collection contents are not tracked yet; collection update actions are reported when fired"
                .into(),
        );
    }
    if !automaton.clocks.is_empty() {
        warnings.push(
            "logical clocks are simulated for guards/updates but are not included in counter traces"
                .into(),
        );
    }
    if automaton.has_reconfiguration() {
        warnings.push(
            "parameter reconfiguration updates are applied, but reconfiguration budget metadata is not enforced by the simulator yet"
                .into(),
        );
    }
    warnings
}

fn message_family_name(shared_var_name: &str) -> Option<&str> {
    let rest = shared_var_name.strip_prefix("cnt_")?;
    let end = rest.find(['@', '#', '[', '<', '-']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn is_message_counter(automaton: &ThresholdAutomaton, shared_var: usize) -> bool {
    automaton
        .shared_vars
        .get(shared_var)
        .map(|var| var.kind == SharedVarKind::MessageCounter)
        .unwrap_or(false)
}

fn push_event(proc: &mut ConcreteProcess, kind: ProcessEventKind) {
    proc.events.push(ProcessEvent {
        sequence: proc.events.len() as u64,
        kind,
    });
}

struct MessageProvenance {
    senders_by_var: Vec<BTreeSet<u64>>,
    next_synthetic_sender: u64,
}

impl MessageProvenance {
    fn new(automaton: &ThresholdAutomaton) -> Self {
        Self {
            senders_by_var: vec![BTreeSet::new(); automaton.shared_vars.len()],
            next_synthetic_sender: 1 << 63,
        }
    }

    fn set_seed_senders(&mut self, var: SharedVarId, count: i64) {
        let idx = var.as_usize();
        let Some(senders) = self.senders_by_var.get_mut(idx) else {
            return;
        };
        senders.clear();
        if count <= 0 {
            return;
        }
        for _ in 0..count {
            senders.insert(self.next_synthetic_sender);
            self.next_synthetic_sender = self.next_synthetic_sender.saturating_add(1);
        }
    }

    fn record_send(&mut self, var: SharedVarId, sender: u64) {
        if let Some(senders) = self.senders_by_var.get_mut(var.as_usize()) {
            senders.insert(sender);
        }
    }

    fn distinct_sender_count(&self, vars: &[SharedVarId]) -> i64 {
        self.distinct_senders(vars).len() as i64
    }

    fn distinct_senders(&self, vars: &[SharedVarId]) -> Vec<u64> {
        let mut senders = BTreeSet::new();
        for var in vars {
            if let Some(var_senders) = self.senders_by_var.get(var.as_usize()) {
                senders.extend(var_senders.iter().copied());
            }
        }
        senders.into_iter().collect()
    }
}

struct ConcreteProcess {
    id: u64,
    role: String,
    current_location: usize,
    events: Vec<ProcessEvent>,
}

pub(crate) struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn index(&mut self, len: usize) -> usize {
        debug_assert!(len > 0);
        (self.next() as usize) % len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use tarsier_ir::threshold_automaton::{
        Guard, Location, Parameter, SharedVar, SharedVarId, Update,
    };

    fn tiny_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter::fixed("n"));
        let start = ta.add_location(Location {
            name: "Replica_start[decided=false]".into(),
            role: "Replica".into(),
            phase: "start".into(),
            local_vars: IndexMap::from([("decided".into(), LocalValue::Bool(false))]),
        });
        let voted = ta.add_location(Location {
            name: "Replica_voted[decided=false]".into(),
            role: "Replica".into(),
            phase: "voted".into(),
            local_vars: IndexMap::from([("decided".into(), LocalValue::Bool(false))]),
        });
        let done = ta.add_location(Location {
            name: "Replica_done[decided=true,decision=true]".into(),
            role: "Replica".into(),
            phase: "done".into(),
            local_vars: IndexMap::from([
                ("decided".into(), LocalValue::Bool(true)),
                ("decision".into(), LocalValue::Bool(true)),
            ]),
        });
        ta.initial_locations.push(start);
        let vote = ta.add_shared_var(SharedVar {
            name: "cnt_Vote@Replica".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_rule(Rule {
            from: start,
            to: voted,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: vote,
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.add_rule(Rule {
            from: voted,
            to: done,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![SharedVarId::from(vote.as_usize())],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }),
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta
    }

    fn distinct_vote_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter::fixed("n"));
        let start = ta.add_location(Location {
            name: "Replica_start".into(),
            role: "Replica".into(),
            phase: "start".into(),
            local_vars: IndexMap::new(),
        });
        let voted = ta.add_location(Location {
            name: "Replica_voted".into(),
            role: "Replica".into(),
            phase: "voted".into(),
            local_vars: IndexMap::new(),
        });
        let done = ta.add_location(Location {
            name: "Replica_done".into(),
            role: "Replica".into(),
            phase: "done".into(),
            local_vars: IndexMap::from([("decided".into(), LocalValue::Bool(true))]),
        });
        ta.initial_locations.push(start);
        let vote = ta.add_shared_var(SharedVar {
            name: "cnt_Vote@Replica".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: true,
            distinct_role: Some("Replica".into()),
        });
        ta.add_rule(Rule {
            from: start,
            to: voted,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: vote,
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.add_rule(Rule {
            from: voted,
            to: done,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![vote],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(2),
                distinct: true,
            }),
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta
    }

    #[test]
    fn simulation_executes_enabled_rules_and_emits_traces() {
        let ta = tiny_automaton();
        let result = simulate(
            &ta,
            &[("n".into(), 2)],
            SimulationOptions {
                max_steps: 3,
                seed: 7,
                scheduler: Scheduler::First,
                initial_shared: Vec::new(),
            },
        )
        .expect("simulation should succeed");

        assert_eq!(result.summary.steps_executed, 3);
        assert_eq!(result.counter_trace.steps.len(), 3);
        assert_eq!(result.runtime_trace.processes.len(), 2);
        assert!(result
            .runtime_trace
            .processes
            .iter()
            .flat_map(|p| &p.events)
            .any(|event| matches!(event.kind, ProcessEventKind::Decide { .. })));
    }

    #[test]
    fn simulation_stops_on_deadlock() {
        let ta = tiny_automaton();
        let result = simulate(
            &ta,
            &[("n".into(), 1)],
            SimulationOptions {
                max_steps: 10,
                seed: 0,
                scheduler: Scheduler::First,
                initial_shared: Vec::new(),
            },
        )
        .expect("simulation should succeed");

        assert_eq!(result.summary.stopped_reason, StopReason::Deadlock);
        assert_eq!(result.summary.steps_executed, 2);
    }

    #[test]
    fn simulation_applies_initial_message_family_seed() {
        let ta = tiny_automaton();
        let result = simulate(
            &ta,
            &[("n".into(), 1)],
            SimulationOptions {
                max_steps: 1,
                seed: 0,
                scheduler: Scheduler::First,
                initial_shared: vec![("Vote".into(), 3)],
            },
        )
        .expect("simulation should succeed");

        assert!(result
            .summary
            .final_shared_vars
            .iter()
            .any(|(name, value)| name == "cnt_Vote@Replica" && *value >= 3));
    }

    #[test]
    fn distinct_guard_counts_concrete_senders_not_counter_families() {
        let ta = distinct_vote_automaton();
        let result = simulate(
            &ta,
            &[("n".into(), 2)],
            SimulationOptions {
                max_steps: 3,
                seed: 0,
                scheduler: Scheduler::First,
                initial_shared: Vec::new(),
            },
        )
        .expect("simulation should succeed");

        assert_eq!(result.summary.steps_executed, 3);
        assert!(result
            .summary
            .final_location_counts
            .iter()
            .any(|(name, count)| name == "Replica_done" && *count == 1));
        let receive_senders: BTreeSet<u64> = result
            .runtime_trace
            .processes
            .iter()
            .flat_map(|process| &process.events)
            .filter_map(|event| match &event.kind {
                ProcessEventKind::Receive { from_process, .. } => Some(*from_process),
                _ => None,
            })
            .collect();
        assert_eq!(receive_senders, BTreeSet::from([0, 1]));
    }
}
