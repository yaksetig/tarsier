use tarsier_ir::counter_system::Trace;
use tarsier_ir::runtime_trace::{ProcessEvent, ProcessEventKind, ProcessTrace, RuntimeTrace};
use tarsier_ir::threshold_automaton::{ThresholdAutomaton, UpdateKind};

/// Error during trace concretization.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("not enough processes at location L{location} (need {needed}, have {available})")]
    NotEnoughProcesses {
        location: usize,
        needed: i64,
        available: i64,
    },
    #[error("rule {rule_id} is out of range (automaton has {num_rules} rules)")]
    UnknownRule { rule_id: usize, num_rules: usize },
    #[error("negative delta {delta} for rule {rule_id}")]
    NegativeDelta { rule_id: usize, delta: i64 },
}

/// Concretize a counter-level trace into a process-level runtime trace.
///
/// Creates concrete processes from initial kappa values and replays each
/// trace step by moving `delta` processes from the rule's source to
/// destination location.
pub fn concretize_trace(
    counter_trace: &Trace,
    automaton: &ThresholdAutomaton,
) -> Result<RuntimeTrace, ReplayError> {
    let protocol_name = automaton
        .locations
        .first()
        .map(|l| l.role.clone())
        .unwrap_or_default();

    // Instantiate concrete processes from initial kappa
    let mut processes: Vec<ConcreteProcess> = Vec::new();
    let mut next_pid: u64 = 0;

    for (lid, &count) in counter_trace.initial_config.kappa.iter().enumerate() {
        for _ in 0..count {
            processes.push(ConcreteProcess {
                id: next_pid,
                role: automaton
                    .locations
                    .get(lid)
                    .map(|l| l.role.clone())
                    .unwrap_or_default(),
                current_location: lid,
                events: vec![ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: automaton
                            .locations
                            .get(lid)
                            .map(|l| l.name.clone())
                            .unwrap_or_else(|| format!("L{}", lid)),
                    },
                }],
            });
            next_pid += 1;
        }
    }

    // Replay each step
    for step in &counter_trace.steps {
        let rule_id = step.rule_id;
        if rule_id >= automaton.rules.len() {
            return Err(ReplayError::UnknownRule {
                rule_id,
                num_rules: automaton.rules.len(),
            });
        }
        if step.delta < 0 {
            return Err(ReplayError::NegativeDelta {
                rule_id,
                delta: step.delta,
            });
        }

        let rule = &automaton.rules[rule_id];
        let from = rule.from;
        let to = rule.to;
        let delta = step.delta;

        // Count available processes at the source location
        let available = processes
            .iter()
            .filter(|p| p.current_location == from)
            .count() as i64;
        if available < delta {
            return Err(ReplayError::NotEnoughProcesses {
                location: from,
                needed: delta,
                available,
            });
        }

        // Select `delta` processes at the source (deterministic: first-available by ID)
        let mut moved = 0i64;
        for proc in processes.iter_mut() {
            if moved >= delta {
                break;
            }
            if proc.current_location == from {
                let from_name = automaton
                    .locations
                    .get(from)
                    .map(|l| l.name.clone())
                    .unwrap_or_else(|| format!("L{}", from));
                let to_name = automaton
                    .locations
                    .get(to)
                    .map(|l| l.name.clone())
                    .unwrap_or_else(|| format!("L{}", to));

                let seq = proc.events.len() as u64;
                proc.events.push(ProcessEvent {
                    sequence: seq,
                    kind: ProcessEventKind::Transition {
                        from_location: from_name,
                        to_location: to_name,
                        rule_id: Some(rule_id),
                    },
                });

                // Emit update events
                for update in &rule.updates {
                    let seq = proc.events.len() as u64;
                    let var_name = automaton
                        .shared_vars
                        .get(update.var)
                        .map(|v| v.name.clone())
                        .unwrap_or_else(|| format!("g{}", update.var));

                    match &update.kind {
                        UpdateKind::Increment => {
                            proc.events.push(ProcessEvent {
                                sequence: seq,
                                kind: ProcessEventKind::Send {
                                    message_type: var_name,
                                    fields: vec![],
                                },
                            });
                        }
                        UpdateKind::Set(lc) => {
                            let val = eval_lc(lc, &counter_trace.param_values);
                            proc.events.push(ProcessEvent {
                                sequence: seq,
                                kind: ProcessEventKind::VarUpdate {
                                    var_name,
                                    new_value: val.to_string(),
                                },
                            });
                        }
                    }
                }

                proc.current_location = to;
                moved += 1;
            }
        }
    }

    // Build the final runtime trace
    let process_traces = processes
        .into_iter()
        .map(|p| ProcessTrace {
            process_id: p.id,
            role: p.role,
            events: p.events,
        })
        .collect();

    Ok(RuntimeTrace {
        schema_version: 1,
        protocol_name,
        params: counter_trace.param_values.clone(),
        processes: process_traces,
    })
}

/// A concrete process during replay.
struct ConcreteProcess {
    id: u64,
    role: String,
    current_location: usize,
    events: Vec<ProcessEvent>,
}

/// Evaluate a linear combination with named parameter bindings.
fn eval_lc(
    lc: &tarsier_ir::threshold_automaton::LinearCombination,
    param_values: &[(String, i64)],
) -> i64 {
    let mut val = lc.constant;
    for &(coeff, pid) in &lc.terms {
        let pval = param_values.get(pid).map(|(_, v)| *v).unwrap_or(0);
        val += coeff * pval;
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::{Configuration, TraceStep};
    use tarsier_ir::threshold_automaton::*;

    fn make_test_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_parameter(Parameter { name: "t".into() });

        // L0: Init
        ta.add_location(Location {
            name: "Process_Init".into(),
            role: "Process".into(),
            phase: "Init".into(),
            local_vars: Default::default(),
        });
        // L1: Decided
        ta.add_location(Location {
            name: "Process_Decided".into(),
            role: "Process".into(),
            phase: "Decided".into(),
            local_vars: Default::default(),
        });

        ta.initial_locations = vec![0];
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        // Rule 0: L0 -> L1
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });

        ta
    }

    #[test]
    fn test_concretize_simple_trace() {
        let ta = make_test_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![3, 0],
                gamma: vec![0],
                params: vec![4, 1],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 2,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![1, 2],
                    gamma: vec![2],
                    params: vec![4, 1],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let result = concretize_trace(&trace, &ta).unwrap();
        assert_eq!(result.schema_version, 1);
        assert_eq!(result.processes.len(), 3);

        // First 2 processes should have Init + Transition + Send events
        assert!(result.processes[0].events.len() >= 2);
        assert!(result.processes[1].events.len() >= 2);
        // Third process should only have Init
        assert_eq!(result.processes[2].events.len(), 1);
    }

    #[test]
    fn test_concretize_roundtrip() {
        let ta = make_test_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![2, 0],
                gamma: vec![0],
                params: vec![4, 1],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![1, 1],
                    gamma: vec![1],
                    params: vec![4, 1],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let runtime_trace = concretize_trace(&trace, &ta).unwrap();

        // The concretized trace should be checkable
        let checker = crate::checker::ConformanceChecker::new(&ta, &runtime_trace.params);
        let result = checker.check(&runtime_trace);
        // The checker validates transitions — trivial guards should pass
        assert!(
            result.passed,
            "roundtrip validation failed: {:?}",
            result.violations
        );
    }

    #[test]
    fn test_impossible_concretization() {
        let ta = make_test_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![4, 1],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 3, // but only 1 process at L0
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![0, 3],
                    gamma: vec![3],
                    params: vec![4, 1],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let result = concretize_trace(&trace, &ta);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReplayError::NotEnoughProcesses {
                location,
                needed,
                available,
            } => {
                assert_eq!(location, 0);
                assert_eq!(needed, 3);
                assert_eq!(available, 1);
            }
            other => panic!("expected NotEnoughProcesses, got: {other}"),
        }
    }
}
