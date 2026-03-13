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
///
/// # Examples
///
/// ```rust,no_run
/// use tarsier_conformance::replay::concretize_trace;
/// use tarsier_dsl::parse;
/// use tarsier_ir::counter_system::{Configuration, Trace};
/// use tarsier_ir::lowering::lower;
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
/// let counter_trace = Trace {
///     initial_config: Configuration {
///         kappa: vec![1],
///         gamma: vec![0],
///         params: vec![4, 1, 1],
///     },
///     steps: vec![],
///     param_values: vec![("n".into(), 4), ("t".into(), 1), ("f".into(), 1)],
/// };
///
/// let _runtime_trace = concretize_trace(&counter_trace, &automaton)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
                rule_id: rule_id.as_usize(),
                num_rules: automaton.rules.len(),
            });
        }
        if step.delta < 0 {
            return Err(ReplayError::NegativeDelta {
                rule_id: rule_id.as_usize(),
                delta: step.delta,
            });
        }

        let rule = &automaton.rules[rule_id.as_usize()];
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
                location: from.as_usize(),
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
                    .get(from.as_usize())
                    .map(|l| l.name.clone())
                    .unwrap_or_else(|| format!("L{}", from));
                let to_name = automaton
                    .locations
                    .get(to.as_usize())
                    .map(|l| l.name.clone())
                    .unwrap_or_else(|| format!("L{}", to));

                let seq = proc.events.len() as u64;
                proc.events.push(ProcessEvent {
                    sequence: seq,
                    kind: ProcessEventKind::Transition {
                        from_location: from_name,
                        to_location: to_name,
                        rule_id: Some(rule_id.as_usize()),
                    },
                });

                // Emit update events
                for update in &rule.updates {
                    let seq = proc.events.len() as u64;
                    let var_name = automaton
                        .shared_vars
                        .get(update.var.as_usize())
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

                proc.current_location = to.as_usize();
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
        let pval = param_values
            .get(pid.as_usize())
            .map(|(_, v)| *v)
            .unwrap_or(0);
        val += coeff * pval;
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::{Configuration, TraceStep};
    use tarsier_ir::runtime_trace::ProcessEventKind;
    use tarsier_ir::threshold_automaton::*;

    fn make_test_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "t".into(),
            time_varying: false,
        });

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

        ta.initial_locations = vec![LocationId::from(0)];
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        // Rule 0: L0 -> L1
        ta.add_rule(Rule {
            from: LocationId::from(0),
            to: LocationId::from(1),
            guard: Guard::trivial(),
            updates: vec![Update {
                var: SharedVarId::from(0),
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });

        ta
    }

    fn make_set_update_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });

        ta.add_location(Location {
            name: "Worker_Init".into(),
            role: "Worker".into(),
            phase: "Init".into(),
            local_vars: Default::default(),
        });
        ta.add_location(Location {
            name: "Worker_Done".into(),
            role: "Worker".into(),
            phase: "Done".into(),
            local_vars: Default::default(),
        });

        ta.initial_locations = vec![LocationId::from(0)];
        ta.add_shared_var(SharedVar {
            name: "var_decision".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });

        ta.add_rule(Rule {
            from: LocationId::from(0),
            to: LocationId::from(1),
            guard: Guard::trivial(),
            updates: vec![Update {
                var: SharedVarId::from(0),
                kind: UpdateKind::Set(LinearCombination {
                    constant: 2,
                    terms: vec![(4, ParamId::from(0)), (7, ParamId::from(1))],
                }),
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
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
                rule_id: RuleId::from(0),
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
                rule_id: RuleId::from(0),
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
                rule_id: RuleId::from(0),
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

    #[test]
    fn test_concretize_rejects_unknown_rule_id() {
        let ta = make_test_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![4, 1],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: RuleId::from(42),
                delta: 1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![1],
                    params: vec![4, 1],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let err = concretize_trace(&trace, &ta).expect_err("unknown rule id should fail");
        assert!(matches!(
            err,
            ReplayError::UnknownRule {
                rule_id: 42,
                num_rules: 1
            }
        ));
    }

    #[test]
    fn test_concretize_rejects_negative_delta() {
        let ta = make_test_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![4, 1],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: RuleId::from(0),
                delta: -1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![2, -1],
                    gamma: vec![0],
                    params: vec![4, 1],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let err = concretize_trace(&trace, &ta).expect_err("negative delta should fail");
        assert!(matches!(
            err,
            ReplayError::NegativeDelta {
                rule_id: 0,
                delta: -1
            }
        ));
    }

    #[test]
    fn test_concretize_set_update_emits_var_update_event() {
        let ta = make_set_update_automaton();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![3],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: RuleId::from(0),
                delta: 1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![14],
                    params: vec![3],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 3)],
        };

        let runtime = concretize_trace(&trace, &ta).expect("set update trace should concretize");
        let events = &runtime.processes[0].events;
        let var_update = events
            .iter()
            .find_map(|event| match &event.kind {
                ProcessEventKind::VarUpdate {
                    var_name,
                    new_value,
                } => Some((var_name.as_str(), new_value.as_str())),
                _ => None,
            })
            .expect("expected VarUpdate event from UpdateKind::Set");

        assert_eq!(var_update.0, "var_decision");
        assert_eq!(
            var_update.1, "14",
            "missing param index in LC should be treated as zero"
        );
    }

    #[test]
    fn test_concretize_empty_trace_without_locations() {
        let ta = ThresholdAutomaton::new();
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![],
                gamma: vec![],
                params: vec![],
            },
            steps: vec![],
            param_values: vec![],
        };

        let runtime = concretize_trace(&trace, &ta).expect("empty trace should concretize");
        assert_eq!(runtime.protocol_name, "");
        assert!(runtime.processes.is_empty());
        assert_eq!(runtime.schema_version, 1);
    }
}
