use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Message item tracked by the in-memory network shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimMessage {
    pub message_id: u64,
    pub channel: String,
    pub from_process: u64,
    pub to_process: u64,
    #[serde(default)]
    pub payload: String,
}

/// Fault actions supported by the in-memory network shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkFaultAction {
    DelayMessage {
        channel: String,
        from_process: Option<u64>,
        to_process: Option<u64>,
        delay_ticks: u64,
    },
    DropMessage {
        channel: String,
        from_process: Option<u64>,
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

#[derive(Debug, Clone)]
struct QueuedMessage {
    message: ShimMessage,
    available_at_tick: u64,
    enqueue_order: u64,
}

/// Error returned by in-memory network shim operations.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NetworkShimError {
    #[error("tick regression: current={current} requested={requested}")]
    TickRegression { current: u64, requested: u64 },
    #[error("invalid twin registration: process_id ({process_id}) == twin_id ({twin_id})")]
    InvalidTwinRegistration { process_id: u64, twin_id: u64 },
    #[error("twin_id {twin_id} already registered")]
    DuplicateTwinId { twin_id: u64 },
}

/// In-memory queue/shim for active conformance perturbations.
///
/// This shim is deterministic and intended for harness-level testing:
/// - `apply_fault_at_tick` applies perturbations at a logical tick.
/// - `enqueue` inserts messages that may be delayed, dropped, reordered, or blocked.
/// - `drain_deliverable` returns messages currently deliverable under active partitions.
#[derive(Debug, Default)]
pub struct InMemoryNetworkShim {
    current_tick: u64,
    next_order: u64,
    next_message_id: u64,
    queue: Vec<QueuedMessage>,
    dropped: Vec<ShimMessage>,
    partitions: BTreeSet<(u64, u64)>,
    twins_by_process: BTreeMap<u64, BTreeSet<u64>>,
}

impl InMemoryNetworkShim {
    pub fn new() -> Self {
        Self {
            current_tick: 0,
            next_order: 0,
            next_message_id: 1,
            queue: Vec::new(),
            dropped: Vec::new(),
            partitions: BTreeSet::new(),
            twins_by_process: BTreeMap::new(),
        }
    }

    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    pub fn advance_to_tick(&mut self, tick: u64) -> Result<(), NetworkShimError> {
        if tick < self.current_tick {
            return Err(NetworkShimError::TickRegression {
                current: self.current_tick,
                requested: tick,
            });
        }
        self.current_tick = tick;
        Ok(())
    }

    pub fn apply_fault_at_tick(
        &mut self,
        tick: u64,
        action: &NetworkFaultAction,
    ) -> Result<(), NetworkShimError> {
        self.advance_to_tick(tick)?;
        self.apply_fault(action)
    }

    pub fn enqueue(&mut self, mut message: ShimMessage) {
        if message.message_id == 0 {
            message.message_id = self.allocate_message_id();
        } else {
            self.next_message_id = self
                .next_message_id
                .max(message.message_id.saturating_add(1));
        }

        self.push_queued(message.clone());

        let twins = self
            .twins_by_process
            .get(&message.from_process)
            .cloned()
            .unwrap_or_default();

        for twin_id in twins {
            let mut twin_message = message.clone();
            twin_message.message_id = self.allocate_message_id();
            twin_message.from_process = twin_id;
            self.push_queued(twin_message);
        }
    }

    pub fn pending_messages(&self) -> Vec<ShimMessage> {
        self.sorted_pending()
            .into_iter()
            .map(|entry| entry.message.clone())
            .collect()
    }

    pub fn dropped_messages(&self) -> &[ShimMessage] {
        &self.dropped
    }

    pub fn active_partitions(&self) -> Vec<(u64, u64)> {
        self.partitions.iter().copied().collect()
    }

    pub fn active_twins_for_process(&self, process_id: u64) -> Vec<u64> {
        self.twins_by_process
            .get(&process_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn drain_deliverable(&mut self) -> Vec<ShimMessage> {
        let mut deliverable = Vec::new();
        let mut retained = Vec::with_capacity(self.queue.len());

        let mut sorted = self.sorted_pending();
        for queued in sorted.drain(..) {
            if queued.available_at_tick <= self.current_tick
                && !self.is_partitioned(queued.message.from_process, queued.message.to_process)
            {
                deliverable.push(queued.message);
            } else {
                retained.push(queued);
            }
        }

        self.queue = retained;
        deliverable
    }

    fn apply_fault(&mut self, action: &NetworkFaultAction) -> Result<(), NetworkShimError> {
        match action {
            NetworkFaultAction::DelayMessage {
                channel,
                from_process,
                to_process,
                delay_ticks,
            } => {
                self.delay_matching(channel, *from_process, *to_process, *delay_ticks);
                Ok(())
            }
            NetworkFaultAction::DropMessage {
                channel,
                from_process,
                to_process,
            } => {
                self.drop_matching(channel, *from_process, *to_process);
                Ok(())
            }
            NetworkFaultAction::ReorderChannel { channel } => {
                self.reorder_channel(channel);
                Ok(())
            }
            NetworkFaultAction::PartitionLink {
                process_a,
                process_b,
            } => {
                self.partitions
                    .insert(normalize_link(*process_a, *process_b));
                Ok(())
            }
            NetworkFaultAction::HealPartition => {
                self.partitions.clear();
                Ok(())
            }
            NetworkFaultAction::SpawnTwin {
                process_id,
                twin_id,
            } => self.spawn_twin(*process_id, *twin_id),
            NetworkFaultAction::RetireTwin { twin_id } => {
                self.retire_twin(*twin_id);
                Ok(())
            }
        }
    }

    fn delay_matching(
        &mut self,
        channel: &str,
        from_process: Option<u64>,
        to_process: Option<u64>,
        delay_ticks: u64,
    ) {
        for queued in &mut self.queue {
            if message_matches(&queued.message, channel, from_process, to_process) {
                queued.available_at_tick = queued.available_at_tick.saturating_add(delay_ticks);
            }
        }
    }

    fn drop_matching(&mut self, channel: &str, from_process: Option<u64>, to_process: Option<u64>) {
        let mut retained = Vec::with_capacity(self.queue.len());
        for queued in self.queue.drain(..) {
            if message_matches(&queued.message, channel, from_process, to_process) {
                self.dropped.push(queued.message);
            } else {
                retained.push(queued);
            }
        }
        self.queue = retained;
    }

    fn reorder_channel(&mut self, channel: &str) {
        let mut indices = Vec::new();
        let mut orders = Vec::new();
        for (idx, queued) in self.queue.iter().enumerate() {
            if queued.message.channel == channel {
                indices.push(idx);
                orders.push(queued.enqueue_order);
            }
        }
        orders.reverse();
        for (idx, order) in indices.into_iter().zip(orders.into_iter()) {
            self.queue[idx].enqueue_order = order;
        }
    }

    fn spawn_twin(&mut self, process_id: u64, twin_id: u64) -> Result<(), NetworkShimError> {
        if process_id == twin_id {
            return Err(NetworkShimError::InvalidTwinRegistration {
                process_id,
                twin_id,
            });
        }

        for twins in self.twins_by_process.values() {
            if twins.contains(&twin_id) {
                return Err(NetworkShimError::DuplicateTwinId { twin_id });
            }
        }

        self.twins_by_process
            .entry(process_id)
            .or_default()
            .insert(twin_id);
        Ok(())
    }

    fn retire_twin(&mut self, twin_id: u64) {
        let mut empty_keys = Vec::new();
        for (process, twins) in &mut self.twins_by_process {
            twins.remove(&twin_id);
            if twins.is_empty() {
                empty_keys.push(*process);
            }
        }
        for key in empty_keys {
            self.twins_by_process.remove(&key);
        }
    }

    fn push_queued(&mut self, message: ShimMessage) {
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        self.queue.push(QueuedMessage {
            message,
            available_at_tick: self.current_tick,
            enqueue_order: order,
        });
    }

    fn sorted_pending(&self) -> Vec<QueuedMessage> {
        let mut sorted = self.queue.clone();
        sorted.sort_by_key(|entry| (entry.available_at_tick, entry.enqueue_order));
        sorted
    }

    fn is_partitioned(&self, process_a: u64, process_b: u64) -> bool {
        self.partitions
            .contains(&normalize_link(process_a, process_b))
    }

    fn allocate_message_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1);
        id
    }
}

fn message_matches(
    message: &ShimMessage,
    channel: &str,
    from_process: Option<u64>,
    to_process: Option<u64>,
) -> bool {
    message.channel == channel
        && from_process.is_none_or(|sender| message.from_process == sender)
        && to_process.is_none_or(|recipient| message.to_process == recipient)
}

fn normalize_link(a: u64, b: u64) -> (u64, u64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: u64, channel: &str, from: u64, to: u64) -> ShimMessage {
        ShimMessage {
            message_id: id,
            channel: channel.into(),
            from_process: from,
            to_process: to,
            payload: String::new(),
        }
    }

    #[test]
    fn delay_and_drop_faults_apply_to_matching_messages() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "vote", 1, 2));
        shim.enqueue(msg(2, "vote", 3, 2));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::DelayMessage {
                channel: "vote".into(),
                from_process: Some(1),
                to_process: None,
                delay_ticks: 2,
            },
        )
        .unwrap();

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::DropMessage {
                channel: "vote".into(),
                from_process: Some(3),
                to_process: Some(2),
            },
        )
        .unwrap();

        assert_eq!(shim.dropped_messages().len(), 1);
        assert_eq!(shim.dropped_messages()[0].message_id, 2);

        shim.advance_to_tick(1).unwrap();
        assert!(shim.drain_deliverable().is_empty());

        shim.advance_to_tick(2).unwrap();
        let delivered = shim.drain_deliverable();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].message_id, 1);
    }

    #[test]
    fn reorder_channel_reverses_pending_order() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "a", 1, 2));
        shim.enqueue(msg(2, "a", 1, 2));
        shim.enqueue(msg(3, "a", 1, 2));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::ReorderChannel {
                channel: "a".into(),
            },
        )
        .unwrap();

        let delivered = shim.drain_deliverable();
        assert_eq!(
            delivered
                .into_iter()
                .map(|m| m.message_id)
                .collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
    }

    #[test]
    fn partition_blocks_until_healed() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "vote", 1, 2));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::PartitionLink {
                process_a: 1,
                process_b: 2,
            },
        )
        .unwrap();
        assert!(shim.drain_deliverable().is_empty());

        shim.apply_fault_at_tick(1, &NetworkFaultAction::HealPartition)
            .unwrap();
        let delivered = shim.drain_deliverable();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].message_id, 1);
    }

    #[test]
    fn spawn_and_retire_twin_control_message_duplication() {
        let mut shim = InMemoryNetworkShim::new();

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::SpawnTwin {
                process_id: 5,
                twin_id: 50,
            },
        )
        .unwrap();
        shim.enqueue(msg(10, "qc", 5, 9));

        let first_batch = shim.pending_messages();
        assert_eq!(first_batch.len(), 2);
        assert!(first_batch.iter().any(|m| m.from_process == 5));
        assert!(first_batch.iter().any(|m| m.from_process == 50));

        shim.apply_fault_at_tick(0, &NetworkFaultAction::RetireTwin { twin_id: 50 })
            .unwrap();

        shim.enqueue(msg(20, "qc", 5, 9));
        let second_batch = shim.pending_messages();
        let second_ids = second_batch
            .iter()
            .filter(|m| m.message_id == 20)
            .collect::<Vec<_>>();
        assert_eq!(second_ids.len(), 1);
        assert_eq!(second_ids[0].from_process, 5);
    }

    #[test]
    fn apply_fault_at_tick_rejects_tick_regression() {
        let mut shim = InMemoryNetworkShim::new();
        shim.apply_fault_at_tick(5, &NetworkFaultAction::HealPartition)
            .unwrap();
        let err = shim
            .apply_fault_at_tick(4, &NetworkFaultAction::HealPartition)
            .unwrap_err();
        assert!(matches!(err, NetworkShimError::TickRegression { .. }));
    }

    #[test]
    fn spawn_twin_rejects_duplicate_twin_id() {
        let mut shim = InMemoryNetworkShim::new();
        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::SpawnTwin {
                process_id: 1,
                twin_id: 20,
            },
        )
        .unwrap();

        let err = shim
            .apply_fault_at_tick(
                0,
                &NetworkFaultAction::SpawnTwin {
                    process_id: 2,
                    twin_id: 20,
                },
            )
            .unwrap_err();
        assert!(matches!(err, NetworkShimError::DuplicateTwinId { .. }));
    }

    #[test]
    fn drop_with_no_matching_messages_is_noop() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "vote", 1, 2));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::DropMessage {
                channel: "other".into(),
                from_process: None,
                to_process: None,
            },
        )
        .unwrap();

        assert!(shim.dropped_messages().is_empty());
        assert_eq!(shim.pending_messages().len(), 1);
    }

    #[test]
    fn reorder_nonexistent_channel_is_noop() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "vote", 1, 2));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::ReorderChannel {
                channel: "nonexistent".into(),
            },
        )
        .unwrap();

        let delivered = shim.drain_deliverable();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].message_id, 1);
    }

    #[test]
    fn multiple_partitions_coexist() {
        let mut shim = InMemoryNetworkShim::new();
        shim.enqueue(msg(1, "a", 1, 2));
        shim.enqueue(msg(2, "b", 3, 4));

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::PartitionLink {
                process_a: 1,
                process_b: 2,
            },
        )
        .unwrap();
        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::PartitionLink {
                process_a: 3,
                process_b: 4,
            },
        )
        .unwrap();

        assert_eq!(shim.active_partitions().len(), 2);
        assert!(shim.drain_deliverable().is_empty());

        // Heal just one partition
        shim.apply_fault_at_tick(1, &NetworkFaultAction::HealPartition)
            .unwrap();

        // All partitions healed
        let delivered = shim.drain_deliverable();
        assert_eq!(delivered.len(), 2);
    }

    #[test]
    fn advance_tick_rejects_regression() {
        let mut shim = InMemoryNetworkShim::new();
        shim.advance_to_tick(5).unwrap();
        assert_eq!(shim.current_tick(), 5);

        let err = shim.advance_to_tick(3).unwrap_err();
        assert!(matches!(err, NetworkShimError::TickRegression { .. }));
    }

    #[test]
    fn active_twins_for_process_returns_correct_twins() {
        let mut shim = InMemoryNetworkShim::new();
        assert!(shim.active_twins_for_process(1).is_empty());

        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::SpawnTwin {
                process_id: 1,
                twin_id: 10,
            },
        )
        .unwrap();
        shim.apply_fault_at_tick(
            0,
            &NetworkFaultAction::SpawnTwin {
                process_id: 1,
                twin_id: 11,
            },
        )
        .unwrap();

        let twins = shim.active_twins_for_process(1);
        assert_eq!(twins.len(), 2);
        assert!(twins.contains(&10));
        assert!(twins.contains(&11));

        shim.apply_fault_at_tick(0, &NetworkFaultAction::RetireTwin { twin_id: 10 })
            .unwrap();
        assert_eq!(shim.active_twins_for_process(1).len(), 1);
    }
}
