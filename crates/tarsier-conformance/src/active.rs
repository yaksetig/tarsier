use serde::{Deserialize, Serialize};
use tarsier_ir::counter_system::{MessageEventKind, Trace};

/// One adversarial/network-control action scheduled at a logical tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub tick: u64,
    pub action: FaultAction,
}

/// Active test scenario used by implementation-level conformance harnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveScenario {
    pub scenario_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub faults: Vec<ScheduledFault>,
}

/// Fault/perturbation types supported by the active harness API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaultAction {
    DelayMessage {
        channel: String,
        #[serde(default)]
        from_process: Option<u64>,
        #[serde(default)]
        to_process: Option<u64>,
        delay_ticks: u64,
    },
    DropMessage {
        channel: String,
        #[serde(default)]
        from_process: Option<u64>,
        #[serde(default)]
        to_process: Option<u64>,
    },
    ReorderChannel {
        channel: String,
    },
    PartitionLink {
        process_a: u64,
        process_b: u64,
    },
    HealPartition,
    SpawnTwin {
        process_id: u64,
        twin_id: u64,
    },
    RetireTwin {
        twin_id: u64,
    },
}

/// One applied fault entry in a harness run report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFault {
    pub tick: u64,
    pub schedule_index: usize,
    pub action: FaultAction,
}

/// Result summary for one active schedule execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveRunReport {
    pub scenario_id: String,
    pub max_tick_reached: u64,
    pub applied_faults: Vec<AppliedFault>,
}

/// Error returned by active harness components.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ActiveHarnessError {
    #[error("invalid active scenario: {0}")]
    InvalidScenario(String),
    #[error("implementation adapter error: {0}")]
    Adapter(String),
    #[error("schedule injector error: {0}")]
    Injector(String),
}

/// Interface for implementation-specific lifecycle/tick control.
pub trait ActiveImplementationAdapter {
    fn start(&mut self) -> Result<(), ActiveHarnessError>;
    fn advance_to_tick(&mut self, tick: u64) -> Result<(), ActiveHarnessError>;
    fn stop(&mut self) -> Result<(), ActiveHarnessError>;
}

/// Interface that injects a scheduled perturbation into the system under test.
pub trait ScheduleInjector {
    fn inject(&mut self, tick: u64, action: &FaultAction) -> Result<(), ActiveHarnessError>;
}

/// Deterministic active harness runner.
///
/// Execution model:
/// 1. Start implementation adapter.
/// 2. Replay all faults ordered by `(tick, original_index)` (stable ordering).
/// 3. Advance adapter when moving to a new tick.
/// 4. Inject each action through the schedule injector.
/// 5. Stop adapter and emit a machine-readable report.
pub struct ActiveHarness;

impl ActiveHarness {
    pub fn run<A: ActiveImplementationAdapter, I: ScheduleInjector>(
        scenario: &ActiveScenario,
        adapter: &mut A,
        injector: &mut I,
    ) -> Result<ActiveRunReport, ActiveHarnessError> {
        if scenario.scenario_id.trim().is_empty() {
            return Err(ActiveHarnessError::InvalidScenario(
                "scenario_id must be non-empty".into(),
            ));
        }

        let mut ordered: Vec<(usize, &ScheduledFault)> = scenario.faults.iter().enumerate().collect();
        ordered.sort_by_key(|(idx, fault)| (fault.tick, *idx));

        adapter.start()?;

        let mut current_tick: Option<u64> = None;
        let mut applied = Vec::with_capacity(ordered.len());
        for (idx, fault) in ordered {
            if current_tick != Some(fault.tick) {
                adapter.advance_to_tick(fault.tick)?;
                current_tick = Some(fault.tick);
            }
            injector.inject(fault.tick, &fault.action)?;
            applied.push(AppliedFault {
                tick: fault.tick,
                schedule_index: idx,
                action: fault.action.clone(),
            });
        }

        adapter.stop()?;

        Ok(ActiveRunReport {
            scenario_id: scenario.scenario_id.clone(),
            max_tick_reached: current_tick.unwrap_or(0),
            applied_faults: applied,
        })
    }
}

/// Controls for deriving an active scenario from a model counterexample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioDerivationOptions {
    /// If true, also derive delay perturbations from benign delivery events.
    pub include_delivery_delay_faults: bool,
    /// Optional hard cap on generated faults.
    pub max_faults: Option<usize>,
    /// Tick multiplier per trace step (step i => tick (i+1)*tick_stride).
    pub tick_stride: u64,
}

impl Default for ScenarioDerivationOptions {
    fn default() -> Self {
        Self {
            include_delivery_delay_faults: false,
            max_faults: None,
            tick_stride: 1,
        }
    }
}

/// Build an executable active scenario from a counterexample trace.
///
/// The derived schedule is deterministic and stable:
/// - step order is preserved
/// - delivery order in each step is preserved
/// - each mapped fault receives a monotonically increasing schedule index
pub fn scenario_from_counterexample(
    trace: &Trace,
    scenario_id: impl Into<String>,
    options: ScenarioDerivationOptions,
) -> ActiveScenario {
    let scenario_id = scenario_id.into();
    let tick_stride = options.tick_stride.max(1);
    let mut faults = Vec::new();

    for (step_idx, step) in trace.steps.iter().enumerate() {
        let tick = (step_idx as u64 + 1) * tick_stride;
        for (delivery_idx, delivery) in step.deliveries.iter().enumerate() {
            if let Some(max_faults) = options.max_faults {
                if faults.len() >= max_faults {
                    break;
                }
            }
            let channel = delivery.payload.family.clone();
            let from_process = parse_process_id(delivery.sender.process.as_deref());
            let to_process = parse_process_id(delivery.recipient.process.as_deref());

            let action = match delivery.kind {
                MessageEventKind::Drop => Some(FaultAction::DropMessage {
                    channel,
                    from_process,
                    to_process,
                }),
                MessageEventKind::Forge | MessageEventKind::Equivocate => {
                    let process_id = from_process.unwrap_or(0);
                    Some(FaultAction::SpawnTwin {
                        process_id,
                        twin_id: synthesize_twin_id(process_id, step_idx as u64, delivery_idx as u64),
                    })
                }
                MessageEventKind::Deliver if options.include_delivery_delay_faults => {
                    Some(FaultAction::DelayMessage {
                        channel,
                        from_process,
                        to_process,
                        delay_ticks: 1,
                    })
                }
                MessageEventKind::Send | MessageEventKind::Deliver => None,
            };

            if let Some(action) = action {
                faults.push(ScheduledFault { tick, action });
            }
        }

        if let Some(max_faults) = options.max_faults {
            if faults.len() >= max_faults {
                break;
            }
        }
    }

    ActiveScenario {
        scenario_id: scenario_id.clone(),
        description: format!(
            "Derived from model counterexample: steps={}, generated_faults={}",
            trace.steps.len(),
            faults.len()
        ),
        faults,
    }
}

fn parse_process_id(raw: Option<&str>) -> Option<u64> {
    let text = raw?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(pid) = text.parse::<u64>() {
        return Some(pid);
    }
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

fn synthesize_twin_id(process_id: u64, step: u64, offset: u64) -> u64 {
    process_id
        .saturating_mul(1_000_000)
        .saturating_add(step.saturating_mul(1_000))
        .saturating_add(offset)
        .saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::{
        Configuration, MessageAuthMetadata, MessageDeliveryEvent, MessageIdentity,
        MessagePayloadVariant, SignatureProvenance, TraceStep,
    };
    use tarsier_ir::threshold_automaton::RuleId;

    #[derive(Default)]
    struct RecordingAdapter {
        started: bool,
        stopped: bool,
        ticks: Vec<u64>,
    }

    impl ActiveImplementationAdapter for RecordingAdapter {
        fn start(&mut self) -> Result<(), ActiveHarnessError> {
            self.started = true;
            Ok(())
        }

        fn advance_to_tick(&mut self, tick: u64) -> Result<(), ActiveHarnessError> {
            self.ticks.push(tick);
            Ok(())
        }

        fn stop(&mut self) -> Result<(), ActiveHarnessError> {
            self.stopped = true;
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingInjector {
        calls: Vec<(u64, FaultAction)>,
    }

    impl ScheduleInjector for RecordingInjector {
        fn inject(&mut self, tick: u64, action: &FaultAction) -> Result<(), ActiveHarnessError> {
            self.calls.push((tick, action.clone()));
            Ok(())
        }
    }

    #[test]
    fn run_executes_faults_in_tick_order_with_stable_ties() {
        let scenario = ActiveScenario {
            scenario_id: "case-1".into(),
            description: String::new(),
            faults: vec![
                ScheduledFault {
                    tick: 5,
                    action: FaultAction::HealPartition,
                },
                ScheduledFault {
                    tick: 2,
                    action: FaultAction::ReorderChannel {
                        channel: "vote".into(),
                    },
                },
                ScheduledFault {
                    tick: 5,
                    action: FaultAction::DropMessage {
                        channel: "vote".into(),
                        from_process: Some(1),
                        to_process: Some(2),
                    },
                },
            ],
        };

        let mut adapter = RecordingAdapter::default();
        let mut injector = RecordingInjector::default();
        let report = ActiveHarness::run(&scenario, &mut adapter, &mut injector).unwrap();

        assert!(adapter.started);
        assert!(adapter.stopped);
        assert_eq!(adapter.ticks, vec![2, 5]);
        assert_eq!(report.max_tick_reached, 5);
        assert_eq!(injector.calls.len(), 3);
        assert_eq!(report.applied_faults.len(), 3);
        // Stable ordering for equal ticks keeps original index order.
        assert_eq!(
            report
                .applied_faults
                .iter()
                .map(|a| a.schedule_index)
                .collect::<Vec<_>>(),
            vec![1, 0, 2]
        );
    }

    #[test]
    fn run_rejects_empty_scenario_id() {
        let scenario = ActiveScenario {
            scenario_id: " ".into(),
            description: String::new(),
            faults: vec![],
        };
        let mut adapter = RecordingAdapter::default();
        let mut injector = RecordingInjector::default();
        let err = ActiveHarness::run(&scenario, &mut adapter, &mut injector).unwrap_err();
        assert!(matches!(err, ActiveHarnessError::InvalidScenario(_)));
    }

    struct FailingInjector;

    impl ScheduleInjector for FailingInjector {
        fn inject(&mut self, _tick: u64, _action: &FaultAction) -> Result<(), ActiveHarnessError> {
            Err(ActiveHarnessError::Injector("network shim unavailable".into()))
        }
    }

    #[test]
    fn run_propagates_injector_errors() {
        let scenario = ActiveScenario {
            scenario_id: "case-2".into(),
            description: String::new(),
            faults: vec![ScheduledFault {
                tick: 1,
                action: FaultAction::HealPartition,
            }],
        };
        let mut adapter = RecordingAdapter::default();
        let mut injector = FailingInjector;
        let err = ActiveHarness::run(&scenario, &mut adapter, &mut injector).unwrap_err();
        assert!(matches!(err, ActiveHarnessError::Injector(_)));
    }

    fn delivery_event(kind: MessageEventKind, family: &str, from: &str, to: &str) -> MessageDeliveryEvent {
        MessageDeliveryEvent {
            shared_var: 0,
            shared_var_name: format!("cnt_{family}"),
            sender: MessageIdentity {
                role: "Node".into(),
                process: Some(from.into()),
                key: None,
            },
            recipient: MessageIdentity {
                role: "Node".into(),
                process: Some(to.into()),
                key: None,
            },
            payload: MessagePayloadVariant {
                family: family.into(),
                fields: Vec::new(),
                variant: family.into(),
            },
            count: 1,
            kind,
            auth: MessageAuthMetadata {
                authenticated_channel: false,
                signature_key: None,
                key_owner_role: None,
                key_compromised: false,
                provenance: SignatureProvenance::Unknown,
            },
        }
    }

    #[test]
    fn scenario_from_counterexample_maps_drop_and_equivocation() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1],
                gamma: vec![],
                params: vec![],
            },
            steps: vec![TraceStep {
                smt_step: 1,
                rule_id: RuleId::from(0),
                delta: 1,
                deliveries: vec![
                    delivery_event(MessageEventKind::Drop, "Vote", "1", "2"),
                    delivery_event(MessageEventKind::Equivocate, "Vote", "7", "3"),
                ],
                config: Configuration {
                    kappa: vec![1],
                    gamma: vec![],
                    params: vec![],
                },
                por_status: None,
            }],
            param_values: Vec::new(),
        };

        let scenario =
            scenario_from_counterexample(&trace, "cx-1", ScenarioDerivationOptions::default());
        assert_eq!(scenario.faults.len(), 2);
        assert_eq!(scenario.faults[0].tick, 1);
        assert!(matches!(
            scenario.faults[0].action,
            FaultAction::DropMessage {
                ref channel,
                from_process: Some(1),
                to_process: Some(2)
            } if channel == "Vote"
        ));
        assert!(matches!(
            scenario.faults[1].action,
            FaultAction::SpawnTwin {
                process_id: 7,
                twin_id
            } if twin_id > 7
        ));
    }

    #[test]
    fn scenario_from_counterexample_can_include_delivery_delay_faults() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1],
                gamma: vec![],
                params: vec![],
            },
            steps: vec![TraceStep {
                smt_step: 1,
                rule_id: RuleId::from(0),
                delta: 1,
                deliveries: vec![delivery_event(MessageEventKind::Deliver, "QC", "10", "11")],
                config: Configuration {
                    kappa: vec![1],
                    gamma: vec![],
                    params: vec![],
                },
                por_status: None,
            }],
            param_values: Vec::new(),
        };

        let scenario = scenario_from_counterexample(
            &trace,
            "cx-2",
            ScenarioDerivationOptions {
                include_delivery_delay_faults: true,
                ..Default::default()
            },
        );
        assert_eq!(scenario.faults.len(), 1);
        assert!(matches!(
            scenario.faults[0].action,
            FaultAction::DelayMessage {
                ref channel,
                from_process: Some(10),
                to_process: Some(11),
                delay_ticks: 1
            } if channel == "QC"
        ));
    }

    #[test]
    fn scenario_from_counterexample_respects_max_faults() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1],
                gamma: vec![],
                params: vec![],
            },
            steps: vec![TraceStep {
                smt_step: 1,
                rule_id: RuleId::from(0),
                delta: 1,
                deliveries: vec![
                    delivery_event(MessageEventKind::Drop, "A", "1", "2"),
                    delivery_event(MessageEventKind::Drop, "B", "1", "3"),
                ],
                config: Configuration {
                    kappa: vec![1],
                    gamma: vec![],
                    params: vec![],
                },
                por_status: None,
            }],
            param_values: Vec::new(),
        };

        let scenario = scenario_from_counterexample(
            &trace,
            "cx-3",
            ScenarioDerivationOptions {
                max_faults: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(scenario.faults.len(), 1);
    }
}
