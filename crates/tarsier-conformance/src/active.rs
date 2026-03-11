use serde::{Deserialize, Serialize};
use tarsier_ir::counter_system::{MessageEventKind, Trace};

use crate::adapters::{AdapterFaultAction, ScheduledAdapterFault};
use crate::network_shim::{InMemoryNetworkShim, NetworkFaultAction, NetworkShimError, ShimMessage};

/// Scheduled fault for deterministic in-memory network-shim execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledNetworkFault {
    pub tick: u64,
    pub action: NetworkFaultAction,
}

/// Message emission scheduled at a logical tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledShimMessage {
    pub tick: u64,
    pub message: ShimMessage,
}

/// One fault applied by the deterministic shim runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedNetworkFault {
    pub tick: u64,
    pub schedule_index: usize,
    pub action: NetworkFaultAction,
}

/// One message delivered by the deterministic shim runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredShimMessage {
    pub tick: u64,
    pub message: ShimMessage,
}

/// Deterministic execution report for scheduled faults + scheduled message sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveExecutionReport {
    pub schema_version: u32,
    pub final_tick: u64,
    pub applied_faults: Vec<AppliedNetworkFault>,
    pub delivered_messages: Vec<DeliveredShimMessage>,
    pub dropped_messages: Vec<ShimMessage>,
    pub pending_messages: Vec<ShimMessage>,
}

/// Error returned by deterministic network-shim execution.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ActiveExecutionError {
    #[error("failed to advance shim to tick {tick}: {source}")]
    TickAdvance {
        tick: u64,
        #[source]
        source: NetworkShimError,
    },
    #[error("failed to apply fault at schedule_index {schedule_index}, tick {tick}: {source}")]
    FaultApply {
        schedule_index: usize,
        tick: u64,
        #[source]
        source: NetworkShimError,
    },
}

/// Convert adapter-specific scheduled faults into network-shim scheduled faults.
pub fn faults_from_adapter_schedule(
    scheduled_faults: &[ScheduledAdapterFault],
) -> Vec<ScheduledNetworkFault> {
    scheduled_faults
        .iter()
        .map(|fault| ScheduledNetworkFault {
            tick: fault.tick,
            action: adapter_fault_action_to_network(&fault.action),
        })
        .collect()
}

/// Convert adapter-level fault action to network-shim action.
pub fn adapter_fault_action_to_network(action: &AdapterFaultAction) -> NetworkFaultAction {
    match action {
        AdapterFaultAction::DelayMessage {
            channel,
            from_process,
            to_process,
            delay_ticks,
        } => NetworkFaultAction::DelayMessage {
            channel: channel.clone(),
            from_process: *from_process,
            to_process: *to_process,
            delay_ticks: *delay_ticks,
        },
        AdapterFaultAction::DropMessage {
            channel,
            from_process,
            to_process,
        } => NetworkFaultAction::DropMessage {
            channel: channel.clone(),
            from_process: *from_process,
            to_process: *to_process,
        },
        AdapterFaultAction::ReorderChannel { channel } => NetworkFaultAction::ReorderChannel {
            channel: channel.clone(),
        },
        AdapterFaultAction::PartitionLink {
            process_a,
            process_b,
        } => NetworkFaultAction::PartitionLink {
            process_a: *process_a,
            process_b: *process_b,
        },
        AdapterFaultAction::HealPartition => NetworkFaultAction::HealPartition,
        AdapterFaultAction::SpawnTwin {
            process_id,
            twin_id,
        } => NetworkFaultAction::SpawnTwin {
            process_id: *process_id,
            twin_id: *twin_id,
        },
        AdapterFaultAction::RetireTwin { twin_id } => {
            NetworkFaultAction::RetireTwin { twin_id: *twin_id }
        }
    }
}

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

/// Execute scheduled messages and scheduled network faults deterministically.
///
/// Semantics:
/// - Inputs are first ordered by `(tick, original_index)` to guarantee a stable run.
/// - At each tick, all messages are enqueued first, then all faults are applied.
/// - After enqueue/fault application at a tick, deliverable messages are drained.
pub fn execute_scheduled_faults(
    scheduled_faults: &[ScheduledNetworkFault],
    scheduled_messages: &[ScheduledShimMessage],
) -> Result<ActiveExecutionReport, ActiveExecutionError> {
    let mut ordered_faults = scheduled_faults
        .iter()
        .enumerate()
        .collect::<Vec<(usize, &ScheduledNetworkFault)>>();
    ordered_faults.sort_by_key(|(idx, fault)| (fault.tick, *idx));

    let mut ordered_messages = scheduled_messages
        .iter()
        .enumerate()
        .collect::<Vec<(usize, &ScheduledShimMessage)>>();
    ordered_messages.sort_by_key(|(idx, message)| (message.tick, *idx));

    let mut shim = InMemoryNetworkShim::new();
    let mut delivered_messages = Vec::new();
    let mut applied_faults = Vec::with_capacity(ordered_faults.len());
    let mut message_idx = 0usize;
    let mut fault_idx = 0usize;
    let mut final_tick = 0u64;

    while message_idx < ordered_messages.len() || fault_idx < ordered_faults.len() {
        let next_message_tick = ordered_messages.get(message_idx).map(|(_, m)| m.tick);
        let next_fault_tick = ordered_faults.get(fault_idx).map(|(_, f)| f.tick);
        let tick = match (next_message_tick, next_fault_tick) {
            (Some(msg), Some(fault)) => msg.min(fault),
            (Some(msg), None) => msg,
            (None, Some(fault)) => fault,
            (None, None) => break,
        };
        final_tick = tick;

        shim.advance_to_tick(tick)
            .map_err(|source| ActiveExecutionError::TickAdvance { tick, source })?;

        while message_idx < ordered_messages.len() && ordered_messages[message_idx].1.tick == tick {
            shim.enqueue(ordered_messages[message_idx].1.message.clone());
            message_idx += 1;
        }

        while fault_idx < ordered_faults.len() && ordered_faults[fault_idx].1.tick == tick {
            let (schedule_index, scheduled) = ordered_faults[fault_idx];
            shim.apply_fault_at_tick(tick, &scheduled.action)
                .map_err(|source| ActiveExecutionError::FaultApply {
                    schedule_index,
                    tick,
                    source,
                })?;
            applied_faults.push(AppliedNetworkFault {
                tick,
                schedule_index,
                action: scheduled.action.clone(),
            });
            fault_idx += 1;
        }

        for message in shim.drain_deliverable() {
            delivered_messages.push(DeliveredShimMessage { tick, message });
        }
    }

    Ok(ActiveExecutionReport {
        schema_version: 1,
        final_tick,
        applied_faults,
        delivered_messages,
        dropped_messages: shim.dropped_messages().to_vec(),
        pending_messages: shim.pending_messages(),
    })
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

    fn msg(channel: &str, from_process: u64, to_process: u64) -> ShimMessage {
        ShimMessage {
            message_id: 0,
            channel: channel.into(),
            from_process,
            to_process,
            payload: String::new(),
        }
    }

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
    fn execute_scheduled_faults_applies_spawn_twin_and_drop_deterministically() {
        let faults = vec![
            ScheduledNetworkFault {
                tick: 2,
                action: NetworkFaultAction::DropMessage {
                    channel: "vote".into(),
                    from_process: Some(1),
                    to_process: Some(2),
                },
            },
            ScheduledNetworkFault {
                tick: 1,
                action: NetworkFaultAction::SpawnTwin {
                    process_id: 1,
                    twin_id: 10,
                },
            },
        ];
        let messages = vec![
            ScheduledShimMessage {
                tick: 2,
                message: msg("vote", 1, 2),
            },
            ScheduledShimMessage {
                tick: 2,
                message: msg("vote", 3, 2),
            },
        ];

        let report = execute_scheduled_faults(&faults, &messages).expect("run should succeed");

        assert_eq!(report.final_tick, 2);
        assert_eq!(report.applied_faults.len(), 2);
        assert_eq!(report.delivered_messages.len(), 2);
        assert_eq!(
            report
                .delivered_messages
                .iter()
                .map(|delivery| delivery.message.from_process)
                .collect::<Vec<_>>(),
            vec![10, 3]
        );
        assert_eq!(report.dropped_messages.len(), 1);
        assert_eq!(report.dropped_messages[0].from_process, 1);
        assert!(report.pending_messages.is_empty());
    }

    #[test]
    fn execute_scheduled_faults_holds_messages_until_partition_is_healed() {
        let faults = vec![
            ScheduledNetworkFault {
                tick: 1,
                action: NetworkFaultAction::PartitionLink {
                    process_a: 1,
                    process_b: 2,
                },
            },
            ScheduledNetworkFault {
                tick: 3,
                action: NetworkFaultAction::HealPartition,
            },
        ];
        let messages = vec![ScheduledShimMessage {
            tick: 2,
            message: msg("qc", 1, 2),
        }];

        let report = execute_scheduled_faults(&faults, &messages).expect("run should succeed");
        assert_eq!(report.final_tick, 3);
        assert_eq!(report.delivered_messages.len(), 1);
        assert_eq!(report.delivered_messages[0].tick, 3);
        assert!(report.dropped_messages.is_empty());
        assert!(report.pending_messages.is_empty());
    }

    #[test]
    fn execute_scheduled_faults_propagates_fault_application_errors() {
        let faults = vec![
            ScheduledNetworkFault {
                tick: 0,
                action: NetworkFaultAction::SpawnTwin {
                    process_id: 1,
                    twin_id: 50,
                },
            },
            ScheduledNetworkFault {
                tick: 0,
                action: NetworkFaultAction::SpawnTwin {
                    process_id: 2,
                    twin_id: 50,
                },
            },
        ];

        let err = execute_scheduled_faults(&faults, &[]).expect_err("duplicate twin should fail");
        assert!(matches!(
            err,
            ActiveExecutionError::FaultApply {
                schedule_index: 1,
                tick: 0,
                source: NetworkShimError::DuplicateTwinId { twin_id: 50 },
            }
        ));
    }

    #[test]
    fn faults_from_adapter_schedule_maps_actions_one_to_one() {
        let adapter_faults = vec![
            ScheduledAdapterFault {
                tick: 1,
                action: AdapterFaultAction::DelayMessage {
                    channel: "vote".into(),
                    from_process: Some(1),
                    to_process: Some(2),
                    delay_ticks: 3,
                },
            },
            ScheduledAdapterFault {
                tick: 2,
                action: AdapterFaultAction::RetireTwin { twin_id: 99 },
            },
        ];

        let mapped = faults_from_adapter_schedule(&adapter_faults);
        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].tick, 1);
        assert!(matches!(
            mapped[0].action,
            NetworkFaultAction::DelayMessage {
                ref channel,
                from_process: Some(1),
                to_process: Some(2),
                delay_ticks: 3
            } if channel == "vote"
        ));
        assert!(matches!(
            mapped[1].action,
            NetworkFaultAction::RetireTwin { twin_id: 99 }
        ));
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
    fn adapter_fault_action_to_network_all_variants() {
        // DropMessage
        let drop = AdapterFaultAction::DropMessage {
            channel: "vote".into(),
            from_process: Some(1),
            to_process: Some(2),
        };
        let net_drop = adapter_fault_action_to_network(&drop);
        assert!(matches!(
            net_drop,
            NetworkFaultAction::DropMessage {
                ref channel,
                from_process: Some(1),
                to_process: Some(2),
            } if channel == "vote"
        ));

        // ReorderChannel
        let reorder = AdapterFaultAction::ReorderChannel {
            channel: "ack".into(),
        };
        let net_reorder = adapter_fault_action_to_network(&reorder);
        assert!(matches!(
            net_reorder,
            NetworkFaultAction::ReorderChannel { ref channel } if channel == "ack"
        ));

        // PartitionLink
        let partition = AdapterFaultAction::PartitionLink {
            process_a: 3,
            process_b: 4,
        };
        let net_partition = adapter_fault_action_to_network(&partition);
        assert!(matches!(
            net_partition,
            NetworkFaultAction::PartitionLink {
                process_a: 3,
                process_b: 4,
            }
        ));

        // HealPartition
        let heal = AdapterFaultAction::HealPartition;
        assert!(matches!(
            adapter_fault_action_to_network(&heal),
            NetworkFaultAction::HealPartition
        ));

        // SpawnTwin
        let spawn = AdapterFaultAction::SpawnTwin {
            process_id: 5,
            twin_id: 50,
        };
        assert!(matches!(
            adapter_fault_action_to_network(&spawn),
            NetworkFaultAction::SpawnTwin {
                process_id: 5,
                twin_id: 50,
            }
        ));
    }

    #[test]
    fn execute_scheduled_faults_empty_inputs() {
        let report = execute_scheduled_faults(&[], &[]).unwrap();
        assert_eq!(report.final_tick, 0);
        assert!(report.applied_faults.is_empty());
        assert!(report.delivered_messages.is_empty());
        assert!(report.dropped_messages.is_empty());
        assert!(report.pending_messages.is_empty());
    }

    #[test]
    fn execute_scheduled_faults_messages_only() {
        let messages = vec![
            ScheduledShimMessage {
                tick: 0,
                message: ShimMessage {
                    message_id: 1,
                    channel: "vote".into(),
                    from_process: 1,
                    to_process: 2,
                    payload: "hello".into(),
                },
            },
            ScheduledShimMessage {
                tick: 1,
                message: ShimMessage {
                    message_id: 2,
                    channel: "vote".into(),
                    from_process: 2,
                    to_process: 1,
                    payload: "world".into(),
                },
            },
        ];

        let report = execute_scheduled_faults(&[], &messages).unwrap();
        assert_eq!(report.final_tick, 1);
        assert_eq!(report.delivered_messages.len(), 2);
        assert!(report.applied_faults.is_empty());
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
