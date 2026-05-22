//! Reusable message-queue network simulator for protocol-specific simulations.
//!
//! Protocol adapters implement [`NetworkNode`] and keep their own local state.
//! The runner provides deterministic message delivery, configurable delays, and
//! a generic trace that can be embedded by higher-level simulations.

use serde::{Deserialize, Serialize};

use crate::DeterministicRng;

/// Concrete node identifier used by the queue simulator.
pub type NodeId = u64;

/// Message delivery order among messages that are already deliverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScheduler {
    /// Deliver earliest-time messages by priority, then enqueue order.
    Fifo,
    /// Deliver a random message among earliest-time, highest-priority messages.
    RandomReady,
}

impl Default for NetworkScheduler {
    fn default() -> Self {
        Self::Fifo
    }
}

/// Delay policy used for messages sent without an explicit delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDelay {
    Zero,
    Fixed(usize),
    Uniform { min: usize, max: usize },
}

impl Default for NetworkDelay {
    fn default() -> Self {
        Self::Zero
    }
}

/// Generic network-run options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkOptions {
    pub max_deliveries: usize,
    pub seed: u64,
    pub scheduler: NetworkScheduler,
    pub default_delay: NetworkDelay,
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            max_deliveries: 1_000,
            seed: 0,
            scheduler: NetworkScheduler::Fifo,
            default_delay: NetworkDelay::Zero,
        }
    }
}

/// Why a network run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkStopReason {
    QueueEmpty,
    MaxDeliveries,
}

/// Message delivered to a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredMessage<M> {
    pub id: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub sent_at: usize,
    pub deliver_at: usize,
    pub payload: M,
}

/// Generic trace entry emitted by the queue simulator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "M: Serialize, E: Serialize",
    deserialize = "M: Deserialize<'de>, E: Deserialize<'de>"
))]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NetworkTraceEvent<M, E> {
    Local {
        time: usize,
        node: NodeId,
        event: E,
    },
    Send {
        time: usize,
        message_id: u64,
        from: NodeId,
        to: NodeId,
        deliver_at: usize,
        priority: i32,
        payload: M,
    },
    Deliver {
        time: usize,
        message_id: u64,
        from: NodeId,
        to: NodeId,
        payload: M,
    },
    Drop {
        time: usize,
        message_id: u64,
        from: NodeId,
        to: NodeId,
        payload: M,
        reason: String,
    },
}

/// Completed network run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRun<N: NetworkNode> {
    pub nodes: Vec<N>,
    pub trace: Vec<NetworkTraceEvent<N::Message, N::Event>>,
    pub deliveries: usize,
    pub final_time: usize,
    pub stop_reason: NetworkStopReason,
}

/// Protocol-specific node state machine.
pub trait NetworkNode {
    type Message: Clone;
    type Event: Clone;

    fn id(&self) -> NodeId;

    fn on_start(&mut self, _ctx: &mut NetworkContext<'_, Self::Message, Self::Event>) {}

    fn on_message(
        &mut self,
        message: DeliveredMessage<Self::Message>,
        ctx: &mut NetworkContext<'_, Self::Message, Self::Event>,
    );
}

/// Context passed to protocol nodes while they handle one event.
pub struct NetworkContext<'a, M, E> {
    now: usize,
    self_id: NodeId,
    node_ids: &'a [NodeId],
    rng: &'a mut DeterministicRng,
    outbox: Vec<OutboundMessage<M>>,
    events: Vec<E>,
}

impl<'a, M, E> NetworkContext<'a, M, E> {
    fn new(
        now: usize,
        self_id: NodeId,
        node_ids: &'a [NodeId],
        rng: &'a mut DeterministicRng,
    ) -> Self {
        Self {
            now,
            self_id,
            node_ids,
            rng,
            outbox: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn now(&self) -> usize {
        self.now
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn node_ids(&self) -> &[NodeId] {
        self.node_ids
    }

    pub fn send(&mut self, to: NodeId, payload: M) {
        self.outbox.push(OutboundMessage {
            to,
            payload,
            delay: OutboundDelay::Default,
            priority: 0,
        });
    }

    pub fn send_after(&mut self, to: NodeId, payload: M, delay: usize) {
        self.send_after_with_priority(to, payload, delay, 0);
    }

    pub fn send_after_with_priority(
        &mut self,
        to: NodeId,
        payload: M,
        delay: usize,
        priority: i32,
    ) {
        self.outbox.push(OutboundMessage {
            to,
            payload,
            delay: OutboundDelay::Exact(delay),
            priority,
        });
    }

    pub fn broadcast<I>(&mut self, recipients: I, payload: M)
    where
        I: IntoIterator<Item = NodeId>,
        M: Clone,
    {
        for to in recipients {
            self.send(to, payload.clone());
        }
    }

    pub fn broadcast_after<I>(&mut self, recipients: I, payload: M, delay: usize)
    where
        I: IntoIterator<Item = NodeId>,
        M: Clone,
    {
        for to in recipients {
            self.send_after(to, payload.clone(), delay);
        }
    }

    pub fn broadcast_after_with_priority<I>(
        &mut self,
        recipients: I,
        payload: M,
        delay: usize,
        priority: i32,
    ) where
        I: IntoIterator<Item = NodeId>,
        M: Clone,
    {
        for to in recipients {
            self.send_after_with_priority(to, payload.clone(), delay, priority);
        }
    }

    pub fn record(&mut self, event: E) {
        self.events.push(event);
    }

    pub fn random_index(&mut self, len: usize) -> usize {
        self.rng.index(len)
    }
}

/// Run protocol nodes until the queue is empty or `max_deliveries` is reached.
pub fn run_network<N>(mut nodes: Vec<N>, options: NetworkOptions) -> NetworkRun<N>
where
    N: NetworkNode,
{
    let node_ids: Vec<NodeId> = nodes.iter().map(NetworkNode::id).collect();
    let mut rng = DeterministicRng::new(options.seed);
    let mut queue = Vec::new();
    let mut trace = Vec::new();
    let mut next_message_id = 1u64;
    let mut next_sequence = 0u64;

    for idx in 0..nodes.len() {
        let node_id = nodes[idx].id();
        let mut ctx = NetworkContext::new(0, node_id, &node_ids, &mut rng);
        nodes[idx].on_start(&mut ctx);
        drain_context(
            ctx,
            &options,
            &mut queue,
            &mut trace,
            &mut next_message_id,
            &mut next_sequence,
        );
    }

    let mut deliveries = 0usize;
    let mut final_time = 0usize;
    let mut stop_reason = NetworkStopReason::QueueEmpty;

    while !queue.is_empty() {
        if deliveries >= options.max_deliveries {
            stop_reason = NetworkStopReason::MaxDeliveries;
            break;
        }

        let queue_idx = choose_message_index(&queue, options.scheduler, &mut rng);
        let message = queue.remove(queue_idx);
        final_time = message.deliver_at;

        let Some(node_idx) = nodes.iter().position(|node| node.id() == message.to) else {
            trace.push(NetworkTraceEvent::Drop {
                time: final_time,
                message_id: message.id,
                from: message.from,
                to: message.to,
                payload: message.payload,
                reason: "recipient node is not present".into(),
            });
            deliveries += 1;
            continue;
        };

        trace.push(NetworkTraceEvent::Deliver {
            time: final_time,
            message_id: message.id,
            from: message.from,
            to: message.to,
            payload: message.payload.clone(),
        });
        let delivered = DeliveredMessage {
            id: message.id,
            from: message.from,
            to: message.to,
            sent_at: message.sent_at,
            deliver_at: message.deliver_at,
            payload: message.payload,
        };
        let mut ctx = NetworkContext::new(final_time, message.to, &node_ids, &mut rng);
        nodes[node_idx].on_message(delivered, &mut ctx);
        drain_context(
            ctx,
            &options,
            &mut queue,
            &mut trace,
            &mut next_message_id,
            &mut next_sequence,
        );
        deliveries += 1;
    }

    NetworkRun {
        nodes,
        trace,
        deliveries,
        final_time,
        stop_reason,
    }
}

#[derive(Debug, Clone)]
struct OutboundMessage<M> {
    to: NodeId,
    payload: M,
    delay: OutboundDelay,
    priority: i32,
}

#[derive(Debug, Clone, Copy)]
enum OutboundDelay {
    Default,
    Exact(usize),
}

#[derive(Debug, Clone)]
struct QueuedMessage<M> {
    id: u64,
    sequence: u64,
    priority: i32,
    sent_at: usize,
    deliver_at: usize,
    from: NodeId,
    to: NodeId,
    payload: M,
}

fn drain_context<M, E>(
    ctx: NetworkContext<'_, M, E>,
    options: &NetworkOptions,
    queue: &mut Vec<QueuedMessage<M>>,
    trace: &mut Vec<NetworkTraceEvent<M, E>>,
    next_message_id: &mut u64,
    next_sequence: &mut u64,
) where
    M: Clone,
{
    let now = ctx.now;
    let from = ctx.self_id;
    for event in ctx.events {
        trace.push(NetworkTraceEvent::Local {
            time: now,
            node: from,
            event,
        });
    }
    for outbound in ctx.outbox {
        let delay = match outbound.delay {
            OutboundDelay::Default => sample_delay(options.default_delay, ctx.rng),
            OutboundDelay::Exact(delay) => delay,
        };
        let id = *next_message_id;
        *next_message_id = next_message_id.saturating_add(1);
        let sequence = *next_sequence;
        *next_sequence = next_sequence.saturating_add(1);
        let deliver_at = now.saturating_add(delay);
        trace.push(NetworkTraceEvent::Send {
            time: now,
            message_id: id,
            from,
            to: outbound.to,
            deliver_at,
            priority: outbound.priority,
            payload: outbound.payload.clone(),
        });
        queue.push(QueuedMessage {
            id,
            sequence,
            priority: outbound.priority,
            sent_at: now,
            deliver_at,
            from,
            to: outbound.to,
            payload: outbound.payload,
        });
    }
}

fn sample_delay(delay: NetworkDelay, rng: &mut DeterministicRng) -> usize {
    match delay {
        NetworkDelay::Zero => 0,
        NetworkDelay::Fixed(delay) => delay,
        NetworkDelay::Uniform { min, max } => {
            debug_assert!(min <= max);
            min + rng.index(max - min + 1)
        }
    }
}

fn choose_message_index<M>(
    queue: &[QueuedMessage<M>],
    scheduler: NetworkScheduler,
    rng: &mut DeterministicRng,
) -> usize {
    let earliest = queue
        .iter()
        .map(|message| message.deliver_at)
        .min()
        .expect("caller checks non-empty queue");
    let highest_priority = queue
        .iter()
        .filter(|message| message.deliver_at == earliest)
        .map(|message| message.priority)
        .min()
        .expect("earliest message exists");
    let candidates: Vec<usize> = queue
        .iter()
        .enumerate()
        .filter(|(_, message)| {
            message.deliver_at == earliest && message.priority == highest_priority
        })
        .map(|(idx, _)| idx)
        .collect();

    match scheduler {
        NetworkScheduler::Fifo => candidates
            .into_iter()
            .min_by_key(|&idx| queue[idx].sequence)
            .expect("candidate message exists"),
        NetworkScheduler::RandomReady => candidates[rng.index(candidates.len())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum TestMessage {
        Start,
        Ping,
        Pong,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum TestEvent {
        SawPing,
        SawPong,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestNode {
        id: NodeId,
    }

    impl NetworkNode for TestNode {
        type Message = TestMessage;
        type Event = TestEvent;

        fn id(&self) -> NodeId {
            self.id
        }

        fn on_start(&mut self, ctx: &mut NetworkContext<'_, Self::Message, Self::Event>) {
            if self.id == 0 {
                ctx.send_after(1, TestMessage::Ping, 2);
            }
        }

        fn on_message(
            &mut self,
            message: DeliveredMessage<Self::Message>,
            ctx: &mut NetworkContext<'_, Self::Message, Self::Event>,
        ) {
            match message.payload {
                TestMessage::Start => {}
                TestMessage::Ping => {
                    ctx.record(TestEvent::SawPing);
                    ctx.send(message.from, TestMessage::Pong);
                }
                TestMessage::Pong => {
                    ctx.record(TestEvent::SawPong);
                }
            }
        }
    }

    #[test]
    fn fixed_delay_messages_are_delivered_by_time() {
        let run = run_network(
            vec![TestNode { id: 0 }, TestNode { id: 1 }],
            NetworkOptions {
                max_deliveries: 10,
                seed: 0,
                scheduler: NetworkScheduler::Fifo,
                default_delay: NetworkDelay::Fixed(3),
            },
        );

        assert_eq!(run.deliveries, 2);
        assert!(run.trace.iter().any(|event| {
            matches!(
                event,
                NetworkTraceEvent::Deliver {
                    time: 2,
                    payload: TestMessage::Ping,
                    ..
                }
            )
        }));
        assert!(run.trace.iter().any(|event| {
            matches!(
                event,
                NetworkTraceEvent::Deliver {
                    time: 5,
                    payload: TestMessage::Pong,
                    ..
                }
            )
        }));
    }

    #[test]
    fn priority_breaks_same_time_delivery_ties() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct PriorityNode;

        impl NetworkNode for PriorityNode {
            type Message = &'static str;
            type Event = &'static str;

            fn id(&self) -> NodeId {
                0
            }

            fn on_start(&mut self, ctx: &mut NetworkContext<'_, Self::Message, Self::Event>) {
                ctx.send_after_with_priority(0, "low", 1, 10);
                ctx.send_after_with_priority(0, "high", 1, 0);
            }

            fn on_message(
                &mut self,
                message: DeliveredMessage<Self::Message>,
                ctx: &mut NetworkContext<'_, Self::Message, Self::Event>,
            ) {
                ctx.record(message.payload);
            }
        }

        let run = run_network(vec![PriorityNode], NetworkOptions::default());
        let local_events: Vec<&str> = run
            .trace
            .iter()
            .filter_map(|event| match event {
                NetworkTraceEvent::Local { event, .. } => Some(*event),
                _ => None,
            })
            .collect();
        assert_eq!(local_events, vec!["high", "low"]);
    }
}
