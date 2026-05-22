//! HotStuff-style chained BFT simulation over the generic network queue.
//!
//! This is a bounded protocol adapter: it models local validator locks, leader
//! proposals, votes, quorum certificates, delayed QC visibility, and the
//! three-chain commit rule. It is intended as a reusable-network exercise and
//! experiment harness, not a production pacemaker implementation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::network::{
    run_network, DeliveredMessage, NetworkContext, NetworkDelay, NetworkNode, NetworkOptions,
    NetworkScheduler, NetworkTraceEvent, NodeId,
};

/// Binary payload value used by the HotStuff-style simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HotStuffValue {
    A,
    B,
}

impl std::fmt::Display for HotStuffValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HotStuffValue::A => write!(f, "A"),
            HotStuffValue::B => write!(f, "B"),
        }
    }
}

/// Proposal schedule for leader blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotStuffProposalPattern {
    /// Extend the highest delivered QC every view.
    Chained,
    /// Propose a conflicting B branch at view 2, then continue from highest QC.
    ForkAtTwo,
    /// Alternate values while extending the highest delivered QC.
    AlternateValues,
}

impl Default for HotStuffProposalPattern {
    fn default() -> Self {
        Self::Chained
    }
}

/// Byzantine validator behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotStuffByzantineStrategy {
    Silent,
    Vote,
}

impl Default for HotStuffByzantineStrategy {
    fn default() -> Self {
        Self::Silent
    }
}

/// Concrete options for one HotStuff-style run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffOptions {
    pub n: usize,
    pub byzantine: usize,
    pub views: usize,
    pub quorum_threshold: usize,
    pub network_delay: usize,
    pub seed: u64,
    pub proposal_pattern: HotStuffProposalPattern,
    pub byzantine_strategy: HotStuffByzantineStrategy,
}

/// Block proposed by a leader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffBlock {
    pub id: usize,
    pub view: usize,
    pub value: HotStuffValue,
    pub parent: usize,
    pub parent_qc_view: usize,
}

/// Quorum certificate for a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffQc {
    pub block_id: usize,
    pub view: usize,
    pub value: HotStuffValue,
    pub parent: usize,
    pub threshold: usize,
    pub signers: Vec<usize>,
    pub honest_signers: usize,
    pub byzantine_signers: usize,
}

/// Per-view summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffViewStep {
    pub view: usize,
    pub leader: usize,
    pub block: HotStuffBlock,
    pub votes: usize,
    pub qc_formed: bool,
    pub committed_block: Option<usize>,
    pub committed_value: Option<HotStuffValue>,
}

/// Final lock aggregate over honest validators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffLockSummary {
    pub locked_a: usize,
    pub locked_b: usize,
    pub unlocked: usize,
    pub highest_lock_view: usize,
}

/// Run-level summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffSummary {
    pub views_executed: usize,
    pub qcs_formed: usize,
    pub committed_blocks: usize,
    pub committed_a: usize,
    pub committed_b: usize,
    pub safety_violation: bool,
    pub highest_qc_view: usize,
    pub final_locks: HotStuffLockSummary,
}

/// Protocol messages used over the generic queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum HotStuffMessage {
    StartView {
        view: usize,
    },
    Proposal {
        block: HotStuffBlock,
    },
    Vote {
        view: usize,
        block_id: usize,
        voter: usize,
    },
    QcVisible {
        qc: HotStuffQc,
    },
}

/// Protocol-local network events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum HotStuffNodeEvent {
    ViewStarted {
        view: usize,
        leader: usize,
        block_id: usize,
        parent: usize,
        parent_qc_view: usize,
    },
    Voted {
        view: usize,
        block_id: usize,
    },
    ProposalRejected {
        view: usize,
        block_id: usize,
        lock_view: usize,
    },
    QcFormed {
        view: usize,
        block_id: usize,
        signers: usize,
    },
    Locked {
        view: usize,
        block_id: usize,
    },
    Committed {
        view: usize,
        block_id: usize,
        value: HotStuffValue,
    },
    QcObserved {
        view: usize,
        block_id: usize,
    },
}

pub type HotStuffNetworkTrace = Vec<NetworkTraceEvent<HotStuffMessage, HotStuffNodeEvent>>;

/// Complete simulation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffResult {
    pub options: HotStuffOptions,
    pub views: Vec<HotStuffViewStep>,
    pub qcs: Vec<HotStuffQc>,
    pub committed: Vec<HotStuffBlock>,
    pub summary: HotStuffSummary,
    pub network_trace: HotStuffNetworkTrace,
    pub warnings: Vec<String>,
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum HotStuffError {
    #[error("n must be at least 2, got {0}")]
    InvalidPopulation(usize),
    #[error("byzantine count ({byzantine}) must be less than n ({n})")]
    InvalidByzantineCount { n: usize, byzantine: usize },
    #[error("views must be at least one, got {0}")]
    InvalidViews(usize),
    #[error("quorum threshold must be in 1..=n, got threshold={threshold}, n={n}")]
    InvalidQuorum { n: usize, threshold: usize },
}

/// Run one bounded HotStuff-style simulation.
pub fn simulate_hotstuff(options: HotStuffOptions) -> Result<HotStuffResult, HotStuffError> {
    validate_options(&options)?;
    let nodes = hotstuff_nodes(&options);
    let run = run_network(
        nodes,
        NetworkOptions {
            max_deliveries: options
                .views
                .saturating_mul(options.n)
                .saturating_mul(12)
                .saturating_add(100),
            seed: options.seed,
            scheduler: NetworkScheduler::Fifo,
            default_delay: NetworkDelay::Zero,
        },
    );
    let coordinator = run
        .nodes
        .iter()
        .find_map(|node| match node {
            HotStuffNode::Coordinator(coordinator) => Some(coordinator),
            HotStuffNode::Validator(_) => None,
        })
        .expect("hotstuff_nodes always includes a coordinator");
    let final_locks = summarize_validator_locks(&run.nodes, &coordinator.blocks, &options);
    let summary = summarize(coordinator, final_locks);

    Ok(HotStuffResult {
        options: options.clone(),
        views: coordinator.views.clone(),
        qcs: coordinator.qcs.values().cloned().collect(),
        committed: coordinator.committed.clone(),
        summary,
        network_trace: run.trace,
        warnings: warnings(&options),
    })
}

fn validate_options(options: &HotStuffOptions) -> Result<(), HotStuffError> {
    if options.n < 2 {
        return Err(HotStuffError::InvalidPopulation(options.n));
    }
    if options.byzantine >= options.n {
        return Err(HotStuffError::InvalidByzantineCount {
            n: options.n,
            byzantine: options.byzantine,
        });
    }
    if options.views == 0 {
        return Err(HotStuffError::InvalidViews(options.views));
    }
    if options.quorum_threshold == 0 || options.quorum_threshold > options.n {
        return Err(HotStuffError::InvalidQuorum {
            n: options.n,
            threshold: options.quorum_threshold,
        });
    }
    Ok(())
}

fn hotstuff_nodes(options: &HotStuffOptions) -> Vec<HotStuffNode> {
    let mut nodes = Vec::with_capacity(options.n + 1);
    nodes.push(HotStuffNode::Coordinator(HotStuffCoordinator::new(
        options.clone(),
    )));
    for id in 0..options.n {
        nodes.push(HotStuffNode::Validator(HotStuffValidator::new(
            id,
            options.clone(),
        )));
    }
    nodes
}

#[derive(Debug, Clone)]
enum HotStuffNode {
    Coordinator(HotStuffCoordinator),
    Validator(HotStuffValidator),
}

impl NetworkNode for HotStuffNode {
    type Message = HotStuffMessage;
    type Event = HotStuffNodeEvent;

    fn id(&self) -> NodeId {
        match self {
            HotStuffNode::Coordinator(node) => node.id(),
            HotStuffNode::Validator(node) => node.id(),
        }
    }

    fn on_start(&mut self, ctx: &mut NetworkContext<'_, Self::Message, Self::Event>) {
        if let HotStuffNode::Coordinator(node) = self {
            node.on_start(ctx);
        }
    }

    fn on_message(
        &mut self,
        message: DeliveredMessage<Self::Message>,
        ctx: &mut NetworkContext<'_, Self::Message, Self::Event>,
    ) {
        match self {
            HotStuffNode::Coordinator(node) => node.on_message(message, ctx),
            HotStuffNode::Validator(node) => node.on_message(message, ctx),
        }
    }
}

#[derive(Debug, Clone)]
struct HotStuffCoordinator {
    options: HotStuffOptions,
    blocks: BTreeMap<usize, HotStuffBlock>,
    views: Vec<HotStuffViewStep>,
    votes: BTreeMap<usize, BTreeSet<usize>>,
    qcs: BTreeMap<usize, HotStuffQc>,
    highest_delivered_qc: usize,
    committed: Vec<HotStuffBlock>,
}

impl HotStuffCoordinator {
    fn new(options: HotStuffOptions) -> Self {
        let mut blocks = BTreeMap::new();
        blocks.insert(
            0,
            HotStuffBlock {
                id: 0,
                view: 0,
                value: HotStuffValue::A,
                parent: 0,
                parent_qc_view: 0,
            },
        );
        Self {
            options,
            blocks,
            views: Vec::new(),
            votes: BTreeMap::new(),
            qcs: BTreeMap::new(),
            highest_delivered_qc: 0,
            committed: Vec::new(),
        }
    }

    fn id(&self) -> NodeId {
        self.options.n as NodeId
    }

    fn validator_ids(&self) -> impl Iterator<Item = NodeId> {
        0..self.options.n as NodeId
    }

    fn on_start(&mut self, ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>) {
        ctx.send_after_with_priority(self.id(), HotStuffMessage::StartView { view: 1 }, 0, 10);
    }

    fn on_message(
        &mut self,
        message: DeliveredMessage<HotStuffMessage>,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        match message.payload {
            HotStuffMessage::StartView { view } => self.start_view(view, ctx),
            HotStuffMessage::Vote {
                view,
                block_id,
                voter,
            } => self.record_vote(view, block_id, voter, ctx),
            HotStuffMessage::QcVisible { qc } => self.observe_qc(qc, ctx),
            HotStuffMessage::Proposal { .. } => {}
        }
    }

    fn start_view(
        &mut self,
        view: usize,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        if view == 0 || view > self.options.views {
            return;
        }
        let parent = self.parent_for_view(view);
        let parent_qc_view = self
            .qcs
            .get(&parent)
            .map(|qc| qc.view)
            .unwrap_or_else(|| usize::from(parent == 0).saturating_sub(1));
        let value = self.value_for_view(view);
        let block = HotStuffBlock {
            id: view,
            view,
            value,
            parent,
            parent_qc_view,
        };
        self.blocks.insert(block.id, block.clone());
        self.views.push(HotStuffViewStep {
            view,
            leader: view % self.options.n,
            block: block.clone(),
            votes: 0,
            qc_formed: false,
            committed_block: None,
            committed_value: None,
        });
        ctx.record(HotStuffNodeEvent::ViewStarted {
            view,
            leader: view % self.options.n,
            block_id: block.id,
            parent,
            parent_qc_view,
        });
        ctx.broadcast_after(self.validator_ids(), HotStuffMessage::Proposal { block }, 0);
        if view < self.options.views {
            ctx.send_after_with_priority(
                self.id(),
                HotStuffMessage::StartView { view: view + 1 },
                1,
                10,
            );
        }
    }

    fn parent_for_view(&self, view: usize) -> usize {
        if self.options.proposal_pattern == HotStuffProposalPattern::ForkAtTwo && view == 2 {
            0
        } else {
            self.highest_delivered_qc
        }
    }

    fn value_for_view(&self, view: usize) -> HotStuffValue {
        match self.options.proposal_pattern {
            HotStuffProposalPattern::Chained => HotStuffValue::A,
            HotStuffProposalPattern::ForkAtTwo if view == 2 => HotStuffValue::B,
            HotStuffProposalPattern::ForkAtTwo => HotStuffValue::A,
            HotStuffProposalPattern::AlternateValues => {
                if view % 2 == 1 {
                    HotStuffValue::A
                } else {
                    HotStuffValue::B
                }
            }
        }
    }

    fn record_vote(
        &mut self,
        view: usize,
        block_id: usize,
        voter: usize,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        let voters = self.votes.entry(block_id).or_default();
        voters.insert(voter);
        if let Some(step) = self.views.iter_mut().find(|step| step.view == view) {
            step.votes = voters.len();
        }
        if voters.len() < self.options.quorum_threshold || self.qcs.contains_key(&block_id) {
            return;
        }

        let Some(block) = self.blocks.get(&block_id).cloned() else {
            return;
        };
        let signers: Vec<usize> = voters.iter().copied().collect();
        let honest = self.options.n - self.options.byzantine;
        let honest_signers = signers.iter().filter(|&&id| id < honest).count();
        let qc = HotStuffQc {
            block_id,
            view,
            value: block.value,
            parent: block.parent,
            threshold: self.options.quorum_threshold,
            signers,
            honest_signers,
            byzantine_signers: voters.len() - honest_signers,
        };
        self.qcs.insert(block_id, qc.clone());
        if let Some(step) = self.views.iter_mut().find(|step| step.view == view) {
            step.qc_formed = true;
        }
        ctx.record(HotStuffNodeEvent::QcFormed {
            view,
            block_id,
            signers: qc.signers.len(),
        });
        ctx.broadcast_after_with_priority(
            self.validator_ids().chain(std::iter::once(self.id())),
            HotStuffMessage::QcVisible { qc: qc.clone() },
            self.options.network_delay,
            0,
        );
        if let Some(committed) = self.commit_candidate(&qc) {
            if !self.committed.iter().any(|block| block.id == committed.id) {
                self.committed.push(committed.clone());
                if let Some(step) = self.views.iter_mut().find(|step| step.view == view) {
                    step.committed_block = Some(committed.id);
                    step.committed_value = Some(committed.value);
                }
                ctx.record(HotStuffNodeEvent::Committed {
                    view,
                    block_id: committed.id,
                    value: committed.value,
                });
            }
        }
    }

    fn observe_qc(
        &mut self,
        qc: HotStuffQc,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        if qc.view >= self.qc_view(self.highest_delivered_qc) {
            self.highest_delivered_qc = qc.block_id;
            ctx.record(HotStuffNodeEvent::QcObserved {
                view: qc.view,
                block_id: qc.block_id,
            });
        }
    }

    fn qc_view(&self, block_id: usize) -> usize {
        self.qcs.get(&block_id).map(|qc| qc.view).unwrap_or(0)
    }

    fn commit_candidate(&self, qc: &HotStuffQc) -> Option<HotStuffBlock> {
        let parent = self.blocks.get(&qc.parent)?;
        let grandparent = self.blocks.get(&parent.parent)?;
        let parent_qc = self.qcs.get(&parent.id)?;
        let grandparent_qc = self.qcs.get(&grandparent.id)?;
        (qc.view == parent_qc.view + 1 && parent_qc.view == grandparent_qc.view + 1)
            .then(|| grandparent.clone())
    }
}

#[derive(Debug, Clone)]
struct HotStuffValidator {
    id: usize,
    options: HotStuffOptions,
    blocks: BTreeMap<usize, HotStuffBlock>,
    voted_views: BTreeSet<usize>,
    locked_block: usize,
    lock_view: usize,
}

impl HotStuffValidator {
    fn new(id: usize, options: HotStuffOptions) -> Self {
        let mut blocks = BTreeMap::new();
        blocks.insert(
            0,
            HotStuffBlock {
                id: 0,
                view: 0,
                value: HotStuffValue::A,
                parent: 0,
                parent_qc_view: 0,
            },
        );
        Self {
            id,
            options,
            blocks,
            voted_views: BTreeSet::new(),
            locked_block: 0,
            lock_view: 0,
        }
    }

    fn id(&self) -> NodeId {
        self.id as NodeId
    }

    fn coordinator_id(&self) -> NodeId {
        self.options.n as NodeId
    }

    fn honest(&self) -> bool {
        self.id < self.options.n - self.options.byzantine
    }

    fn on_message(
        &mut self,
        message: DeliveredMessage<HotStuffMessage>,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        match message.payload {
            HotStuffMessage::Proposal { block } => self.handle_proposal(block, ctx),
            HotStuffMessage::QcVisible { qc } => self.observe_qc(qc, ctx),
            HotStuffMessage::StartView { .. } | HotStuffMessage::Vote { .. } => {}
        }
    }

    fn handle_proposal(
        &mut self,
        block: HotStuffBlock,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        self.blocks.insert(block.id, block.clone());
        let should_vote = if self.honest() {
            self.safe_to_vote(&block)
        } else {
            self.options.byzantine_strategy == HotStuffByzantineStrategy::Vote
        };

        if should_vote && self.voted_views.insert(block.view) {
            ctx.record(HotStuffNodeEvent::Voted {
                view: block.view,
                block_id: block.id,
            });
            ctx.send_after(
                self.coordinator_id(),
                HotStuffMessage::Vote {
                    view: block.view,
                    block_id: block.id,
                    voter: self.id,
                },
                0,
            );
        } else if self.honest() {
            ctx.record(HotStuffNodeEvent::ProposalRejected {
                view: block.view,
                block_id: block.id,
                lock_view: self.lock_view,
            });
        }
    }

    fn safe_to_vote(&self, block: &HotStuffBlock) -> bool {
        block.parent_qc_view >= self.lock_view || self.extends_locked_block(block)
    }

    fn extends_locked_block(&self, block: &HotStuffBlock) -> bool {
        let mut cursor = block.parent;
        while cursor != 0 {
            if cursor == self.locked_block {
                return true;
            }
            let Some(parent) = self.blocks.get(&cursor) else {
                return false;
            };
            cursor = parent.parent;
        }
        self.locked_block == 0
    }

    fn observe_qc(
        &mut self,
        qc: HotStuffQc,
        ctx: &mut NetworkContext<'_, HotStuffMessage, HotStuffNodeEvent>,
    ) {
        if qc.view > self.lock_view {
            self.locked_block = qc.block_id;
            self.lock_view = qc.view;
            ctx.record(HotStuffNodeEvent::Locked {
                view: qc.view,
                block_id: qc.block_id,
            });
        }
        ctx.record(HotStuffNodeEvent::QcObserved {
            view: qc.view,
            block_id: qc.block_id,
        });
    }
}

fn summarize_validator_locks(
    nodes: &[HotStuffNode],
    blocks: &BTreeMap<usize, HotStuffBlock>,
    options: &HotStuffOptions,
) -> HotStuffLockSummary {
    let honest = options.n - options.byzantine;
    let mut locked_a = 0;
    let mut locked_b = 0;
    let mut unlocked = 0;
    let mut highest_lock_view = 0;

    for node in nodes {
        let HotStuffNode::Validator(validator) = node else {
            continue;
        };
        if validator.id >= honest {
            continue;
        }
        highest_lock_view = highest_lock_view.max(validator.lock_view);
        if validator.lock_view == 0 {
            unlocked += 1;
            continue;
        }
        match blocks.get(&validator.locked_block).map(|block| block.value) {
            Some(HotStuffValue::A) => locked_a += 1,
            Some(HotStuffValue::B) => locked_b += 1,
            None => unlocked += 1,
        }
    }

    HotStuffLockSummary {
        locked_a,
        locked_b,
        unlocked,
        highest_lock_view,
    }
}

fn summarize(
    coordinator: &HotStuffCoordinator,
    final_locks: HotStuffLockSummary,
) -> HotStuffSummary {
    let committed_a = coordinator
        .committed
        .iter()
        .filter(|block| block.value == HotStuffValue::A)
        .count();
    let committed_b = coordinator
        .committed
        .iter()
        .filter(|block| block.value == HotStuffValue::B)
        .count();
    HotStuffSummary {
        views_executed: coordinator.views.len(),
        qcs_formed: coordinator.qcs.len(),
        committed_blocks: coordinator.committed.len(),
        committed_a,
        committed_b,
        safety_violation: committed_a > 0 && committed_b > 0,
        highest_qc_view: coordinator.qc_view(coordinator.highest_delivered_qc),
        final_locks,
    }
}

fn warnings(options: &HotStuffOptions) -> Vec<String> {
    let mut warnings = vec![
        "HotStuff simulation models a bounded chained-BFT core over the generic network queue; full pacemaker timeouts and leader replacement are not modeled yet".into(),
    ];
    if options.quorum_threshold <= options.byzantine {
        warnings.push(format!(
            "quorum threshold {} does not exceed Byzantine count {}; safety assumptions are intentionally weak",
            options.quorum_threshold, options.byzantine
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_options() -> HotStuffOptions {
        HotStuffOptions {
            n: 4,
            byzantine: 1,
            views: 3,
            quorum_threshold: 3,
            network_delay: 0,
            seed: 0,
            proposal_pattern: HotStuffProposalPattern::Chained,
            byzantine_strategy: HotStuffByzantineStrategy::Silent,
        }
    }

    #[test]
    fn chained_three_qcs_commit_first_block() {
        let result = simulate_hotstuff(base_options()).expect("valid HotStuff options");
        assert_eq!(result.summary.views_executed, 3);
        assert_eq!(result.summary.qcs_formed, 3);
        assert_eq!(result.summary.committed_blocks, 1);
        assert_eq!(result.committed[0].id, 1);
        assert_eq!(result.summary.committed_a, 1);
        assert!(!result.summary.safety_violation);
        assert!(result
            .network_trace
            .iter()
            .any(|event| matches!(event, NetworkTraceEvent::Deliver { .. })));
    }

    #[test]
    fn immediate_fork_is_rejected_by_locks() {
        let mut options = base_options();
        options.views = 2;
        options.proposal_pattern = HotStuffProposalPattern::ForkAtTwo;

        let result = simulate_hotstuff(options).expect("valid HotStuff options");
        assert_eq!(result.summary.qcs_formed, 1);
        assert_eq!(result.views[1].votes, 0);
        assert_eq!(result.summary.final_locks.locked_a, 3);
    }

    #[test]
    fn delayed_qc_visibility_allows_second_fork_qc() {
        let mut options = base_options();
        options.views = 2;
        options.network_delay = 2;
        options.proposal_pattern = HotStuffProposalPattern::ForkAtTwo;

        let result = simulate_hotstuff(options).expect("valid HotStuff options");
        assert_eq!(result.summary.qcs_formed, 2);
        assert_eq!(result.views[1].block.value, HotStuffValue::B);
        assert_eq!(result.views[1].votes, 3);
    }
}
