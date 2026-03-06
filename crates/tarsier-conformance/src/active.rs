use serde::{Deserialize, Serialize};
use tarsier_ir::counter_system::{MessageEventKind, Trace};

/// One adversarial/network-control action scheduled at a logical tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub tick: u64,
    pub action: FaultAction,
}

/// Active test scenario derived from model-level counterexamples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveScenario {
    pub scenario_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub faults: Vec<ScheduledFault>,
}

/// Fault/perturbation types emitted in executable active scenarios.
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

/// Controls for deriving active scenarios from model counterexamples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioDerivationOptions {
    /// If true, derive delay perturbations from benign delivery events.
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
/// Derivation is deterministic and stable:
/// - step order is preserved
/// - delivery order in each step is preserved
/// - mapped faults get monotonic schedule indices
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
                        twin_id: synthesize_twin_id(
                            process_id,
                            step_idx as u64,
                            delivery_idx as u64,
                        ),
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
        scenario_id,
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

    fn delivery_event(
        kind: MessageEventKind,
        family: &str,
        from: &str,
        to: &str,
    ) -> MessageDeliveryEvent {
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
