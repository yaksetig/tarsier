use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tarsier_ir::runtime_trace::{ProcessEventKind, RuntimeTrace};
use tarsier_ir::threshold_automaton::{
    CmpOp, GuardAtom, LinearCombination, LocationId, RuleId, ThresholdAutomaton,
};

/// Result of checking a runtime trace against a model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Schema version for JSON output stability.
    pub schema_version: u32,
    /// Whether the trace passes all checks.
    pub passed: bool,
    /// List of violations found (empty if passed).
    pub violations: Vec<Violation>,
}

/// A single conformance violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Process that produced the violation.
    pub process_id: u64,
    /// Sequence number of the violating event.
    pub event_sequence: u64,
    /// Kind of violation.
    pub kind: ViolationKind,
    /// Human-readable description.
    pub message: String,
}

/// The kind of conformance violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViolationKind {
    InvalidInitialLocation,
    NoMatchingRule,
    GuardNotSatisfied,
    InvalidTransitionTarget,
    UnknownLocation,
    UnknownMessageType,
    InvalidDecideContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConformanceMode {
    /// Accept unknown message kinds and incomplete decide-context details.
    Permissive,
    /// Fail on unknown message kinds and malformed decide-context details.
    Strict,
}

/// Strictness knobs for runtime-trace checking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckerOptions {
    pub mode: ConformanceMode,
    pub reject_unknown_message_type: bool,
    pub reject_invalid_decide_context: bool,
}

impl CheckerOptions {
    /// Build permissive checker options for exploratory replay.
    pub fn permissive() -> Self {
        Self {
            mode: ConformanceMode::Permissive,
            reject_unknown_message_type: false,
            reject_invalid_decide_context: false,
        }
    }

    /// Build strict checker options for CI and release validation.
    pub fn strict() -> Self {
        Self {
            mode: ConformanceMode::Strict,
            reject_unknown_message_type: true,
            reject_invalid_decide_context: true,
        }
    }
}

impl Default for CheckerOptions {
    fn default() -> Self {
        Self::permissive()
    }
}

/// Validates runtime traces against a threshold automaton model.
pub struct ConformanceChecker<'a> {
    automaton: &'a ThresholdAutomaton,
    params: Vec<i64>,
    options: CheckerOptions,
}

impl<'a> ConformanceChecker<'a> {
    /// Create a new checker for the given automaton and parameter bindings.
    ///
    /// `param_bindings` maps parameter names to concrete values.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use tarsier_conformance::checker::ConformanceChecker;
    /// use tarsier_dsl::parse;
    /// use tarsier_ir::lowering::lower;
    /// use tarsier_ir::runtime_trace::{ProcessEvent, ProcessEventKind, ProcessTrace, RuntimeTrace};
    ///
    /// let source = r#"
    /// protocol TrivialLive {
    ///     params n, t, f;
    ///     resilience: n > 3*t;
    ///
    ///     adversary {
    ///         model: byzantine;
    ///         bound: f;
    ///     }
    ///
    ///     role R {
    ///         var decided: bool = true;
    ///         init done;
    ///         phase done {}
    ///     }
    ///
    ///     property inv: safety {
    ///         forall p: R. p.decided == true
    ///     }
    /// }
    /// "#;
    ///
    /// let program = parse(source, "trivial_live.trs")?;
    /// let automaton = lower(&program)?;
    /// let checker = ConformanceChecker::new(&automaton, &[("n".into(), 4), ("t".into(), 1)]);
    ///
    /// let trace = RuntimeTrace {
    ///     schema_version: 1,
    ///     protocol_name: "TrivialLive".into(),
    ///     params: vec![("n".into(), 4), ("t".into(), 1)],
    ///     processes: vec![ProcessTrace {
    ///         process_id: 0,
    ///         role: "R".into(),
    ///         events: vec![ProcessEvent {
    ///             sequence: 0,
    ///             kind: ProcessEventKind::Init {
    ///                 location: "R_done".into(),
    ///             },
    ///         }],
    ///     }],
    /// };
    ///
    /// let _result = checker.check(&trace);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(automaton: &'a ThresholdAutomaton, param_bindings: &[(String, i64)]) -> Self {
        Self::new_with_options(automaton, param_bindings, CheckerOptions::default())
    }

    /// Create a checker with one of the built-in strictness presets.
    pub fn new_with_mode(
        automaton: &'a ThresholdAutomaton,
        param_bindings: &[(String, i64)],
        mode: ConformanceMode,
    ) -> Self {
        let options = match mode {
            ConformanceMode::Permissive => CheckerOptions::permissive(),
            ConformanceMode::Strict => CheckerOptions::strict(),
        };
        Self::new_with_options(automaton, param_bindings, options)
    }

    /// Create a checker with explicit options.
    pub fn new_with_options(
        automaton: &'a ThresholdAutomaton,
        param_bindings: &[(String, i64)],
        options: CheckerOptions,
    ) -> Self {
        let mut params = vec![0i64; automaton.parameters.len()];
        for (name, val) in param_bindings {
            if let Some(pid) = automaton.find_param_by_name(name) {
                params[pid.as_usize()] = *val;
            }
        }
        ConformanceChecker {
            automaton,
            params,
            options,
        }
    }

    /// Return the effective checker options.
    pub fn options(&self) -> CheckerOptions {
        self.options
    }

    fn message_type_is_known(&self, message_type: &str) -> bool {
        self.automaton
            .shared_vars
            .iter()
            .any(|sv| sv.name.contains(message_type))
    }

    /// Check a runtime trace against the model.
    ///
    /// A passing result means the supplied trace is consistent with the model's
    /// transition semantics. It does not prove the implementation is correct
    /// for executions that were not recorded.
    pub fn check(&self, trace: &RuntimeTrace) -> CheckResult {
        let mut violations = Vec::new();

        for process_trace in &trace.processes {
            // Per-process state: current location, message counters, sender sets
            let mut current_location: Option<LocationId> = None;
            let mut msg_counters: HashMap<String, i64> = HashMap::new();
            let mut sender_sets: HashMap<String, HashSet<u64>> = HashMap::new();

            for event in &process_trace.events {
                match &event.kind {
                    ProcessEventKind::Init { location } => {
                        match self.automaton.find_location_by_name(location) {
                            Some(lid) => {
                                if !self.automaton.initial_locations.contains(&lid) {
                                    violations.push(Violation {
                                        process_id: process_trace.process_id,
                                        event_sequence: event.sequence,
                                        kind: ViolationKind::InvalidInitialLocation,
                                        message: format!(
                                            "location '{}' is not an initial location",
                                            location
                                        ),
                                    });
                                }
                                current_location = Some(lid);
                            }
                            None => {
                                violations.push(Violation {
                                    process_id: process_trace.process_id,
                                    event_sequence: event.sequence,
                                    kind: ViolationKind::UnknownLocation,
                                    message: format!("unknown location '{}'", location),
                                });
                            }
                        }
                    }

                    ProcessEventKind::Transition {
                        from_location,
                        to_location,
                        rule_id,
                    } => {
                        let from_lid = self.automaton.find_location_by_name(from_location);
                        let to_lid = self.automaton.find_location_by_name(to_location);

                        if from_lid.is_none() {
                            violations.push(Violation {
                                process_id: process_trace.process_id,
                                event_sequence: event.sequence,
                                kind: ViolationKind::UnknownLocation,
                                message: format!("unknown from_location '{}'", from_location),
                            });
                            continue;
                        }
                        if to_lid.is_none() {
                            violations.push(Violation {
                                process_id: process_trace.process_id,
                                event_sequence: event.sequence,
                                kind: ViolationKind::UnknownLocation,
                                message: format!("unknown to_location '{}'", to_location),
                            });
                            continue;
                        }

                        let (Some(from_lid), Some(to_lid)) = (from_lid, to_lid) else {
                            // Defensive fallback: unknown locations already emitted above.
                            continue;
                        };

                        // Verify transition validity
                        if let Some(rid) = rule_id {
                            // If a specific rule is claimed, validate it
                            if *rid < self.automaton.rules.len() {
                                let rule = &self.automaton.rules[*rid];
                                if rule.from != from_lid || rule.to != to_lid {
                                    violations.push(Violation {
                                        process_id: process_trace.process_id,
                                        event_sequence: event.sequence,
                                        kind: ViolationKind::InvalidTransitionTarget,
                                        message: format!(
                                            "rule {} goes from L{} to L{}, but trace claims {} -> {}",
                                            rid, rule.from, rule.to, from_location, to_location
                                        ),
                                    });
                                } else if !self.evaluate_guard(
                                    RuleId::from(*rid),
                                    &msg_counters,
                                    &sender_sets,
                                ) {
                                    violations.push(Violation {
                                        process_id: process_trace.process_id,
                                        event_sequence: event.sequence,
                                        kind: ViolationKind::GuardNotSatisfied,
                                        message: format!("guard of rule {} not satisfied", rid),
                                    });
                                }
                            } else {
                                violations.push(Violation {
                                    process_id: process_trace.process_id,
                                    event_sequence: event.sequence,
                                    kind: ViolationKind::NoMatchingRule,
                                    message: format!(
                                        "rule_id {} is out of range (automaton has {} rules)",
                                        rid,
                                        self.automaton.rules.len()
                                    ),
                                });
                            }
                        } else {
                            // No specific rule claimed — find any matching rule
                            let matching = self.find_matching_rules(
                                from_lid,
                                to_lid,
                                &msg_counters,
                                &sender_sets,
                            );
                            if matching.is_empty() {
                                // Check if any rule exists for this transition at all
                                let any_rule_exists = self
                                    .automaton
                                    .rules
                                    .iter()
                                    .any(|r| r.from == from_lid && r.to == to_lid);
                                if any_rule_exists {
                                    violations.push(Violation {
                                        process_id: process_trace.process_id,
                                        event_sequence: event.sequence,
                                        kind: ViolationKind::GuardNotSatisfied,
                                        message: format!(
                                            "rules exist from '{}' to '{}' but no guard is satisfied",
                                            from_location, to_location
                                        ),
                                    });
                                } else {
                                    violations.push(Violation {
                                        process_id: process_trace.process_id,
                                        event_sequence: event.sequence,
                                        kind: ViolationKind::NoMatchingRule,
                                        message: format!(
                                            "no rule from '{}' to '{}'",
                                            from_location, to_location
                                        ),
                                    });
                                }
                            }
                        }

                        current_location = Some(to_lid);
                    }

                    ProcessEventKind::Send { message_type, .. } => {
                        if self.options.reject_unknown_message_type
                            && !self.message_type_is_known(message_type)
                        {
                            violations.push(Violation {
                                process_id: process_trace.process_id,
                                event_sequence: event.sequence,
                                kind: ViolationKind::UnknownMessageType,
                                message: format!(
                                    "message type '{}' cannot be mapped to any model counter",
                                    message_type
                                ),
                            });
                        }
                    }

                    ProcessEventKind::Receive {
                        message_type,
                        from_process,
                        ..
                    } => {
                        if self.options.reject_unknown_message_type
                            && !self.message_type_is_known(message_type)
                        {
                            violations.push(Violation {
                                process_id: process_trace.process_id,
                                event_sequence: event.sequence,
                                kind: ViolationKind::UnknownMessageType,
                                message: format!(
                                    "message type '{}' cannot be mapped to any model counter",
                                    message_type
                                ),
                            });
                        }
                        // Update message counters
                        *msg_counters.entry(message_type.clone()).or_insert(0) += 1;
                        sender_sets
                            .entry(message_type.clone())
                            .or_default()
                            .insert(*from_process);
                    }

                    ProcessEventKind::Decide { .. } => {
                        if self.options.reject_invalid_decide_context {
                            let in_decided_location = current_location
                                .and_then(|lid| self.automaton.locations.get(lid.as_usize()))
                                .and_then(|loc| loc.local_vars.get("decided"))
                                .map(|value| {
                                    matches!(
                                        value,
                                        tarsier_ir::threshold_automaton::LocalValue::Bool(true)
                                    )
                                })
                                .unwrap_or(false);
                            if !in_decided_location {
                                violations.push(Violation {
                                    process_id: process_trace.process_id,
                                    event_sequence: event.sequence,
                                    kind: ViolationKind::InvalidDecideContext,
                                    message:
                                        "decide event occurred outside a decided=true location"
                                            .into(),
                                });
                            }
                        }
                    }

                    ProcessEventKind::VarUpdate { .. } => {
                        // Variable updates are informational; no model validation needed.
                    }
                }
            }
        }

        CheckResult {
            schema_version: 1,
            passed: violations.is_empty(),
            violations,
        }
    }

    /// Evaluate a linear combination with concrete parameter values.
    fn eval_linear_combination(&self, lc: &LinearCombination) -> i64 {
        let mut val = lc.constant;
        for &(coeff, pid) in &lc.terms {
            val += coeff * self.params.get(pid.as_usize()).copied().unwrap_or(0);
        }
        val
    }

    /// Evaluate a comparison operation.
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

    /// Evaluate a guard atom with current message counters and sender sets.
    fn evaluate_guard_atom(
        &self,
        atom: &GuardAtom,
        msg_counters: &HashMap<String, i64>,
        sender_sets: &HashMap<String, HashSet<u64>>,
    ) -> bool {
        match atom {
            GuardAtom::Threshold {
                vars,
                op,
                bound,
                distinct,
            } => {
                let lhs = if *distinct {
                    // Count distinct senders across the referenced shared vars
                    let mut combined_senders: HashSet<u64> = HashSet::new();
                    for &vid in vars {
                        if let Some(sv) = self.automaton.shared_vars.get(vid.as_usize()) {
                            if let Some(senders) = sender_sets.get(&sv.name) {
                                combined_senders.extend(senders);
                            }
                        }
                    }
                    combined_senders.len() as i64
                } else {
                    // Sum of message counters for the referenced shared vars
                    let mut sum = 0i64;
                    for &vid in vars {
                        if let Some(sv) = self.automaton.shared_vars.get(vid.as_usize()) {
                            sum += msg_counters.get(&sv.name).copied().unwrap_or(0);
                        }
                    }
                    sum
                };
                let rhs = self.eval_linear_combination(bound);
                Self::eval_cmp(lhs, *op, rhs)
            }
        }
    }

    /// Evaluate the full guard of a rule.
    fn evaluate_guard(
        &self,
        rule_id: RuleId,
        msg_counters: &HashMap<String, i64>,
        sender_sets: &HashMap<String, HashSet<u64>>,
    ) -> bool {
        let rule = &self.automaton.rules[rule_id.as_usize()];
        // A guard is a conjunction of atoms; empty guard is trivially true.
        rule.guard
            .atoms
            .iter()
            .all(|atom| self.evaluate_guard_atom(atom, msg_counters, sender_sets))
    }

    /// Find all rules from `from` to `to` whose guards are satisfied.
    fn find_matching_rules(
        &self,
        from: LocationId,
        to: LocationId,
        msg_counters: &HashMap<String, i64>,
        sender_sets: &HashMap<String, HashSet<u64>>,
    ) -> Vec<RuleId> {
        self.automaton
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.from == from && r.to == to)
            .filter(|(rid, _)| self.evaluate_guard(RuleId::from(*rid), msg_counters, sender_sets))
            .map(|(rid, _)| RuleId::from(rid))
            .collect()
    }
}

#[cfg(test)]
mod tests;
