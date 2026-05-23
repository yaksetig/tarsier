//! Phoenixx-style endorser committee simulation.
//!
//! This module models the Phoenixx safety kernel: full-network confirms form an
//! NQC, a seeded endorser committee forms endorsements, and an EQC is checked
//! for honest NQC provenance. It can run either a one-round kernel or a bounded
//! multi-round experiment with locks, view-change carry-over, and message delay.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tarsier_prob::{analyze_committee, CommitteeSpec};

use crate::network::{
    run_network, DeliveredMessage, NetworkContext, NetworkNode, NetworkOptions, NetworkScheduler,
    NetworkTraceEvent, NodeId,
};

/// Binary proposal value used by the Phoenixx safety-kernel simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhoenixxValue {
    A,
    B,
}

impl std::fmt::Display for PhoenixxValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhoenixxValue::A => write!(f, "A"),
            PhoenixxValue::B => write!(f, "B"),
        }
    }
}

/// Byzantine confirm/endorsement behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoenixxByzantineStrategy {
    /// Byzantine validators do not confirm or endorse.
    #[default]
    Silent,
    /// Byzantine validators confirm and endorse A.
    StaticA,
    /// Byzantine validators confirm and endorse B.
    StaticB,
    /// Byzantine validators confirm and endorse both A and B.
    Equivocate,
}

/// Proposal schedule for multi-round Phoenixx experiments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoenixxProposalPattern {
    /// Propose A every round.
    StaticA,
    /// Propose B every round.
    StaticB,
    /// Alternate A/B by round.
    Alternate,
    /// Randomly choose A/B per round.
    Random,
    /// Carry forward the highest delivered certificate value when one exists;
    /// otherwise propose A.
    #[default]
    ViewChange,
}

/// Concrete options for one Phoenixx committee simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhoenixxOptions {
    /// Total validators.
    pub n: usize,
    /// Byzantine validators in the population.
    pub byzantine: usize,
    /// Random endorser committee size.
    pub committee_size: usize,
    /// Assumed bound on Byzantine endorsers in the sampled committee.
    pub committee_bound: usize,
    /// Committee analysis failure budget used to derive/report b_max.
    pub epsilon: f64,
    /// NQC threshold, usually 2f+1.
    pub nqc_threshold: usize,
    /// EQC endorsement threshold, usually committee_bound+1.
    pub eqc_threshold: usize,
    /// Honest validators initially confirming A; remaining honest validators
    /// confirm B.
    pub initial_honest_a: usize,
    /// Seed used for committee sampling.
    pub seed: u64,
    /// Byzantine response policy.
    pub byzantine_strategy: PhoenixxByzantineStrategy,
    /// Maximum protocol rounds to simulate.
    pub rounds: usize,
    /// Whole-round network delay before formed certificates are visible for
    /// view-change parent selection.
    pub network_delay_rounds: usize,
    /// Proposal schedule for multi-round experiments.
    pub proposal_pattern: PhoenixxProposalPattern,
}

/// Hypergeometric committee-bound analysis attached to a concrete run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhoenixxCommitteeBound {
    pub analyzed_b_max: usize,
    pub expected_byzantine: f64,
    pub tail_probability: f64,
    pub honest_guaranteed: usize,
}

/// Concrete committee draw for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxCommitteeDraw {
    pub members: Vec<usize>,
    pub honest_members: Vec<usize>,
    pub byzantine_members: Vec<usize>,
    pub byzantine_count: usize,
    pub exceeds_bound: bool,
}

/// Concrete signer set for an NQC or EQC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxCertificate {
    pub value: PhoenixxValue,
    pub threshold: usize,
    pub formed: bool,
    pub total_signers: usize,
    pub honest_signers: usize,
    pub byzantine_signers: usize,
    pub signers: Vec<usize>,
}

/// EQC certificate plus whether it is backed by at least one honest endorser
/// that could only endorse after observing an NQC for that value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxEqc {
    pub certificate: PhoenixxCertificate,
    pub honest_nqc_backed: bool,
}

/// Aggregate honest lock state after a round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxLockSummary {
    pub locked_a: usize,
    pub locked_b: usize,
    pub unlocked: usize,
    pub highest_lock_round: usize,
}

/// One multi-round simulation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxRoundStep {
    pub round: usize,
    pub proposal: PhoenixxValue,
    pub parent_round: usize,
    pub delivered_certificate_round: usize,
    pub committee: PhoenixxCommitteeDraw,
    pub nqc_a: PhoenixxCertificate,
    pub nqc_b: PhoenixxCertificate,
    pub eqc_a: PhoenixxEqc,
    pub eqc_b: PhoenixxEqc,
    pub locks: PhoenixxLockSummary,
}

/// Protocol messages used by the Phoenixx adapter over the generic queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PhoenixxMessage {
    StartRound {
        round: usize,
    },
    Proposal {
        round: usize,
        value: PhoenixxValue,
        parent_round: usize,
        committee: Vec<usize>,
    },
    Confirm {
        round: usize,
        value: PhoenixxValue,
        signer: usize,
    },
    NqcForEndorsement {
        round: usize,
        value: PhoenixxValue,
        signers: Vec<usize>,
    },
    CertificateVisible {
        round: usize,
        value: PhoenixxValue,
    },
    Endorse {
        round: usize,
        value: PhoenixxValue,
        signer: usize,
    },
}

/// Protocol-local events emitted into the generic network trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PhoenixxNodeEvent {
    RoundStarted {
        round: usize,
        proposal: PhoenixxValue,
        parent_round: usize,
    },
    Confirmed {
        round: usize,
        value: PhoenixxValue,
    },
    ProposalRejected {
        round: usize,
        value: PhoenixxValue,
        lock_round: usize,
    },
    NqcFormed {
        round: usize,
        value: PhoenixxValue,
        signers: usize,
    },
    Locked {
        round: usize,
        value: PhoenixxValue,
    },
    Endorsed {
        round: usize,
        value: PhoenixxValue,
    },
    EqcFormed {
        round: usize,
        value: PhoenixxValue,
        signers: usize,
    },
    CertificateObserved {
        round: usize,
        value: PhoenixxValue,
    },
}

/// Concrete Phoenixx network trace.
pub type PhoenixxNetworkTrace = Vec<NetworkTraceEvent<PhoenixxMessage, PhoenixxNodeEvent>>;

/// Run-level outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxSummary {
    pub rounds_executed: usize,
    pub decided_value: Option<PhoenixxValue>,
    pub agreement_violation: bool,
    pub committee_bound_violation: bool,
    pub eqc_without_honest_nqc: bool,
    pub nqc_a_formed: bool,
    pub nqc_b_formed: bool,
    pub eqc_a_formed: bool,
    pub eqc_b_formed: bool,
    pub final_locks: PhoenixxLockSummary,
}

/// Complete Phoenixx committee simulation output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhoenixxResult {
    pub options: PhoenixxOptions,
    pub committee_bound: PhoenixxCommitteeBound,
    pub committee: PhoenixxCommitteeDraw,
    pub nqc_a: PhoenixxCertificate,
    pub nqc_b: PhoenixxCertificate,
    pub eqc_a: PhoenixxEqc,
    pub eqc_b: PhoenixxEqc,
    pub rounds: Vec<PhoenixxRoundStep>,
    pub network_trace: PhoenixxNetworkTrace,
    pub summary: PhoenixxSummary,
    pub warnings: Vec<String>,
}

/// Per-run summary for a Phoenixx Monte Carlo batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoenixxBatchRunSummary {
    pub run: usize,
    pub seed: u64,
    pub rounds_executed: usize,
    pub committee_byzantine: usize,
    pub committee_bound_violation: bool,
    pub decided_value: Option<PhoenixxValue>,
    pub agreement_violation: bool,
    pub eqc_without_honest_nqc: bool,
    pub eqc_a_formed: bool,
    pub eqc_b_formed: bool,
}

/// Aggregate batch statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhoenixxBatchSummary {
    pub runs: usize,
    pub decided_a: usize,
    pub decided_b: usize,
    pub undecided_or_conflicted: usize,
    pub committee_bound_violations: usize,
    pub agreement_violations: usize,
    pub eqc_without_honest_nqc: usize,
    pub committee_bound_violation_rate: f64,
    pub agreement_violation_rate: f64,
    pub eqc_without_honest_nqc_rate: f64,
    pub mean_rounds_executed: f64,
}

/// Complete Phoenixx batch output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhoenixxBatchResult {
    pub options: PhoenixxOptions,
    pub committee_bound: PhoenixxCommitteeBound,
    pub summary: PhoenixxBatchSummary,
    pub runs: Vec<PhoenixxBatchRunSummary>,
    pub warnings: Vec<String>,
}

/// Configuration errors for Phoenixx simulation.
#[derive(Debug, thiserror::Error)]
pub enum PhoenixxError {
    #[error("n must be at least 2, got {0}")]
    InvalidPopulation(usize),
    #[error("byzantine count ({byzantine}) must be less than n ({n})")]
    InvalidByzantineCount { n: usize, byzantine: usize },
    #[error("committee size must be in 1..=n, got size={committee_size}, n={n}")]
    InvalidCommitteeSize { n: usize, committee_size: usize },
    #[error("committee bound ({committee_bound}) must be <= committee size ({committee_size})")]
    InvalidCommitteeBound {
        committee_size: usize,
        committee_bound: usize,
    },
    #[error("NQC threshold must be in 1..=n, got threshold={threshold}, n={n}")]
    InvalidNqcThreshold { n: usize, threshold: usize },
    #[error(
        "EQC threshold must be in 1..=committee_size, got threshold={threshold}, committee_size={committee_size}"
    )]
    InvalidEqcThreshold {
        committee_size: usize,
        threshold: usize,
    },
    #[error(
        "initial honest A count ({initial_honest_a}) exceeds honest validator count ({honest})"
    )]
    InvalidInitialSplit {
        honest: usize,
        initial_honest_a: usize,
    },
    #[error("rounds must be at least one, got {0}")]
    InvalidRounds(usize),
    #[error("epsilon must be positive, got {0}")]
    InvalidEpsilon(f64),
    #[error("batch simulation requires at least one run, got {0}")]
    InvalidRuns(usize),
    #[error("committee analysis failed: {0}")]
    CommitteeAnalysis(String),
}

/// Compute the hypergeometric committee bound used by Phoenixx simulations.
pub fn analyze_phoenixx_committee(
    n: usize,
    byzantine: usize,
    committee_size: usize,
    epsilon: f64,
) -> Result<PhoenixxCommitteeBound, PhoenixxError> {
    if epsilon <= 0.0 {
        return Err(PhoenixxError::InvalidEpsilon(epsilon));
    }
    let analysis = analyze_committee(&CommitteeSpec {
        name: "phoenixx_endorsers".into(),
        population: n as u64,
        byzantine: byzantine as u64,
        committee_size: committee_size as u64,
        epsilon,
    })
    .map_err(|e| PhoenixxError::CommitteeAnalysis(e.to_string()))?;

    Ok(PhoenixxCommitteeBound {
        analyzed_b_max: analysis.b_max as usize,
        expected_byzantine: analysis.expected_byzantine,
        tail_probability: analysis.tail_probability,
        honest_guaranteed: analysis.honest_majority as usize,
    })
}

/// Run one Phoenixx committee simulation.
pub fn simulate_phoenixx(options: PhoenixxOptions) -> Result<PhoenixxResult, PhoenixxError> {
    validate_options(&options)?;
    let committee_bound = analyze_phoenixx_committee(
        options.n,
        options.byzantine,
        options.committee_size,
        options.epsilon,
    )?;
    let (rounds, network_trace) = simulate_rounds(&options);
    let final_round = rounds
        .last()
        .expect("validate_options rejects zero-round simulations");
    let committee = final_round.committee.clone();
    let nqc_a = final_round.nqc_a.clone();
    let nqc_b = final_round.nqc_b.clone();
    let eqc_a = final_round.eqc_a.clone();
    let eqc_b = final_round.eqc_b.clone();

    let summary = summarize(&rounds);
    let warnings = warnings(&options, &committee_bound);

    Ok(PhoenixxResult {
        options,
        committee_bound,
        committee,
        nqc_a,
        nqc_b,
        eqc_a,
        eqc_b,
        rounds,
        network_trace,
        summary,
        warnings,
    })
}

/// Run a deterministic batch of Phoenixx committee simulations.
pub fn simulate_phoenixx_batch(
    base_options: PhoenixxOptions,
    runs: usize,
) -> Result<PhoenixxBatchResult, PhoenixxError> {
    if runs == 0 {
        return Err(PhoenixxError::InvalidRuns(runs));
    }
    validate_options(&base_options)?;
    let committee_bound = analyze_phoenixx_committee(
        base_options.n,
        base_options.byzantine,
        base_options.committee_size,
        base_options.epsilon,
    )?;

    let mut run_summaries = Vec::with_capacity(runs);
    for run in 0..runs {
        let mut options = base_options.clone();
        options.seed = base_options.seed.wrapping_add(run as u64);
        let result = simulate_phoenixx(options)?;
        run_summaries.push(PhoenixxBatchRunSummary {
            run: run + 1,
            seed: base_options.seed.wrapping_add(run as u64),
            rounds_executed: result.summary.rounds_executed,
            committee_byzantine: result.committee.byzantine_count,
            committee_bound_violation: result.summary.committee_bound_violation,
            decided_value: result.summary.decided_value,
            agreement_violation: result.summary.agreement_violation,
            eqc_without_honest_nqc: result.summary.eqc_without_honest_nqc,
            eqc_a_formed: result.summary.eqc_a_formed,
            eqc_b_formed: result.summary.eqc_b_formed,
        });
    }

    let summary = summarize_batch(&run_summaries);
    Ok(PhoenixxBatchResult {
        warnings: warnings(&base_options, &committee_bound),
        options: base_options,
        committee_bound,
        summary,
        runs: run_summaries,
    })
}

fn validate_options(options: &PhoenixxOptions) -> Result<(), PhoenixxError> {
    if options.n < 2 {
        return Err(PhoenixxError::InvalidPopulation(options.n));
    }
    if options.byzantine >= options.n {
        return Err(PhoenixxError::InvalidByzantineCount {
            n: options.n,
            byzantine: options.byzantine,
        });
    }
    if options.committee_size == 0 || options.committee_size > options.n {
        return Err(PhoenixxError::InvalidCommitteeSize {
            n: options.n,
            committee_size: options.committee_size,
        });
    }
    if options.committee_bound > options.committee_size {
        return Err(PhoenixxError::InvalidCommitteeBound {
            committee_size: options.committee_size,
            committee_bound: options.committee_bound,
        });
    }
    if options.nqc_threshold == 0 || options.nqc_threshold > options.n {
        return Err(PhoenixxError::InvalidNqcThreshold {
            n: options.n,
            threshold: options.nqc_threshold,
        });
    }
    if options.eqc_threshold == 0 || options.eqc_threshold > options.committee_size {
        return Err(PhoenixxError::InvalidEqcThreshold {
            committee_size: options.committee_size,
            threshold: options.eqc_threshold,
        });
    }
    let honest = options.n - options.byzantine;
    if options.initial_honest_a > honest {
        return Err(PhoenixxError::InvalidInitialSplit {
            honest,
            initial_honest_a: options.initial_honest_a,
        });
    }
    if options.rounds == 0 {
        return Err(PhoenixxError::InvalidRounds(options.rounds));
    }
    if options.epsilon <= 0.0 {
        return Err(PhoenixxError::InvalidEpsilon(options.epsilon));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ValidatorLock {
    value: Option<PhoenixxValue>,
    round: usize,
}

fn simulate_rounds(options: &PhoenixxOptions) -> (Vec<PhoenixxRoundStep>, PhoenixxNetworkTrace) {
    let nodes = phoenixx_nodes(options);
    let run = run_network(
        nodes,
        NetworkOptions {
            max_deliveries: options
                .rounds
                .saturating_mul(options.n)
                .saturating_mul(16)
                .saturating_add(100),
            seed: options.seed,
            scheduler: NetworkScheduler::Fifo,
            default_delay: crate::network::NetworkDelay::Zero,
        },
    );
    let rounds = run
        .nodes
        .iter()
        .find_map(|node| match node {
            PhoenixxNode::Coordinator(coordinator) => Some(coordinator.rounds.clone()),
            PhoenixxNode::Validator(_) => None,
        })
        .unwrap_or_default();
    (rounds, run.trace)
}

fn phoenixx_nodes(options: &PhoenixxOptions) -> Vec<PhoenixxNode> {
    let mut nodes = Vec::with_capacity(options.n + 1);
    nodes.push(PhoenixxNode::Coordinator(PhoenixxCoordinator::new(
        options.clone(),
    )));
    for id in 0..options.n {
        nodes.push(PhoenixxNode::Validator(PhoenixxValidator::new(
            id,
            options.clone(),
        )));
    }
    nodes
}

#[derive(Debug, Clone)]
enum PhoenixxNode {
    Coordinator(PhoenixxCoordinator),
    Validator(PhoenixxValidator),
}

impl NetworkNode for PhoenixxNode {
    type Message = PhoenixxMessage;
    type Event = PhoenixxNodeEvent;

    fn id(&self) -> NodeId {
        match self {
            PhoenixxNode::Coordinator(node) => node.id(),
            PhoenixxNode::Validator(node) => node.id(),
        }
    }

    fn on_start(&mut self, ctx: &mut NetworkContext<'_, Self::Message, Self::Event>) {
        if let PhoenixxNode::Coordinator(node) = self {
            node.on_start(ctx);
        }
    }

    fn on_message(
        &mut self,
        message: DeliveredMessage<Self::Message>,
        ctx: &mut NetworkContext<'_, Self::Message, Self::Event>,
    ) {
        match self {
            PhoenixxNode::Coordinator(node) => node.on_message(message, ctx),
            PhoenixxNode::Validator(node) => node.on_message(message, ctx),
        }
    }
}

#[derive(Debug, Clone)]
struct PhoenixxCoordinator {
    options: PhoenixxOptions,
    locks: Vec<ValidatorLock>,
    rounds: Vec<PhoenixxRoundStep>,
    confirms: BTreeMap<(usize, PhoenixxValue), BTreeSet<usize>>,
    endorsements: BTreeMap<(usize, PhoenixxValue), BTreeSet<usize>>,
    formed_nqcs: BTreeSet<(usize, PhoenixxValue)>,
    formed_eqcs: BTreeSet<(usize, PhoenixxValue)>,
    delivered_certificate_round: usize,
    delivered_certificate_value: Option<PhoenixxValue>,
    stopped: bool,
}

impl PhoenixxCoordinator {
    fn new(options: PhoenixxOptions) -> Self {
        let honest = options.n - options.byzantine;
        Self {
            options,
            locks: vec![ValidatorLock::default(); honest],
            rounds: Vec::new(),
            confirms: BTreeMap::new(),
            endorsements: BTreeMap::new(),
            formed_nqcs: BTreeSet::new(),
            formed_eqcs: BTreeSet::new(),
            delivered_certificate_round: 0,
            delivered_certificate_value: None,
            stopped: false,
        }
    }

    fn id(&self) -> NodeId {
        self.options.n as NodeId
    }

    fn validator_ids(&self) -> impl Iterator<Item = NodeId> {
        0..self.options.n as NodeId
    }

    fn on_start(&mut self, ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>) {
        ctx.send_after_with_priority(self.id(), PhoenixxMessage::StartRound { round: 1 }, 0, 10);
    }

    fn on_message(
        &mut self,
        message: DeliveredMessage<PhoenixxMessage>,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        match message.payload {
            PhoenixxMessage::StartRound { round } => self.start_round(round, ctx),
            PhoenixxMessage::Confirm {
                round,
                value,
                signer,
            } => self.record_confirm(round, value, signer, ctx),
            PhoenixxMessage::Endorse {
                round,
                value,
                signer,
            } => self.record_endorsement(round, value, signer, ctx),
            PhoenixxMessage::CertificateVisible { round, value } => {
                self.observe_certificate(round, value, ctx);
            }
            PhoenixxMessage::Proposal { .. } | PhoenixxMessage::NqcForEndorsement { .. } => {}
        }
    }

    fn start_round(
        &mut self,
        round: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if self.stopped || round > self.options.rounds {
            return;
        }

        let proposal = self.proposal_for_round(round, ctx);
        let parent_round = self.delivered_certificate_round;
        let committee = sample_committee(&self.options, ctx);
        let step = PhoenixxRoundStep {
            round,
            proposal,
            parent_round,
            delivered_certificate_round: self.delivered_certificate_round,
            committee: committee.clone(),
            nqc_a: empty_certificate(PhoenixxValue::A, self.options.nqc_threshold),
            nqc_b: empty_certificate(PhoenixxValue::B, self.options.nqc_threshold),
            eqc_a: empty_eqc(PhoenixxValue::A, self.options.eqc_threshold),
            eqc_b: empty_eqc(PhoenixxValue::B, self.options.eqc_threshold),
            locks: summarize_locks(&self.locks),
        };
        self.rounds.push(step);
        ctx.record(PhoenixxNodeEvent::RoundStarted {
            round,
            proposal,
            parent_round,
        });
        ctx.broadcast_after(
            self.validator_ids(),
            PhoenixxMessage::Proposal {
                round,
                value: proposal,
                parent_round,
                committee: committee.members,
            },
            0,
        );
        if round < self.options.rounds {
            ctx.send_after_with_priority(
                self.id(),
                PhoenixxMessage::StartRound { round: round + 1 },
                1,
                10,
            );
        }
    }

    fn proposal_for_round(
        &self,
        round: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) -> PhoenixxValue {
        match self.options.proposal_pattern {
            PhoenixxProposalPattern::StaticA => PhoenixxValue::A,
            PhoenixxProposalPattern::StaticB => PhoenixxValue::B,
            PhoenixxProposalPattern::Alternate => {
                if round % 2 == 1 {
                    PhoenixxValue::A
                } else {
                    PhoenixxValue::B
                }
            }
            PhoenixxProposalPattern::Random => {
                if ctx.random_index(2) == 0 {
                    PhoenixxValue::A
                } else {
                    PhoenixxValue::B
                }
            }
            PhoenixxProposalPattern::ViewChange => {
                self.delivered_certificate_value.unwrap_or(PhoenixxValue::A)
            }
        }
    }

    fn record_confirm(
        &mut self,
        round: usize,
        value: PhoenixxValue,
        signer: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if self.stopped || round == 0 || round > self.options.rounds {
            return;
        }
        let signers = self.confirms.entry((round, value)).or_default();
        signers.insert(signer);
        let cert = certificate(
            value,
            self.options.nqc_threshold,
            signers,
            self.options.n - self.options.byzantine,
        );
        if !cert.formed || !self.formed_nqcs.insert((round, value)) {
            return;
        }

        self.update_step_nqc(round, value, cert.clone());
        update_locks_for_value(&mut self.locks, round, &cert);
        self.update_step_locks(round);
        ctx.record(PhoenixxNodeEvent::NqcFormed {
            round,
            value,
            signers: cert.total_signers,
        });
        ctx.broadcast_after(
            self.validator_ids(),
            PhoenixxMessage::NqcForEndorsement {
                round,
                value,
                signers: cert.signers.clone(),
            },
            0,
        );
        ctx.broadcast_after_with_priority(
            self.validator_ids().chain(std::iter::once(self.id())),
            PhoenixxMessage::CertificateVisible { round, value },
            self.options.network_delay_rounds,
            0,
        );
    }

    fn record_endorsement(
        &mut self,
        round: usize,
        value: PhoenixxValue,
        signer: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if self.stopped || round == 0 || round > self.options.rounds {
            return;
        }
        let signers = self.endorsements.entry((round, value)).or_default();
        signers.insert(signer);
        let cert = certificate(
            value,
            self.options.eqc_threshold,
            signers,
            self.options.n - self.options.byzantine,
        );
        if !cert.formed || !self.formed_eqcs.insert((round, value)) {
            return;
        }

        let nqc_formed = self.formed_nqcs.contains(&(round, value));
        let eqc = PhoenixxEqc {
            honest_nqc_backed: cert.formed && cert.honest_signers > 0 && nqc_formed,
            certificate: cert,
        };
        self.update_step_eqc(round, value, eqc.clone());
        self.stopped = true;
        ctx.record(PhoenixxNodeEvent::EqcFormed {
            round,
            value,
            signers: eqc.certificate.total_signers,
        });
        ctx.broadcast_after_with_priority(
            self.validator_ids().chain(std::iter::once(self.id())),
            PhoenixxMessage::CertificateVisible { round, value },
            self.options.network_delay_rounds,
            0,
        );
    }

    fn observe_certificate(
        &mut self,
        round: usize,
        value: PhoenixxValue,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if round >= self.delivered_certificate_round {
            self.delivered_certificate_round = round;
            self.delivered_certificate_value = Some(value);
            ctx.record(PhoenixxNodeEvent::CertificateObserved { round, value });
        }
    }

    fn update_step_nqc(&mut self, round: usize, value: PhoenixxValue, cert: PhoenixxCertificate) {
        if let Some(step) = self.rounds.iter_mut().find(|step| step.round == round) {
            match value {
                PhoenixxValue::A => step.nqc_a = cert,
                PhoenixxValue::B => step.nqc_b = cert,
            }
        }
    }

    fn update_step_eqc(&mut self, round: usize, value: PhoenixxValue, eqc: PhoenixxEqc) {
        if let Some(step) = self.rounds.iter_mut().find(|step| step.round == round) {
            match value {
                PhoenixxValue::A => step.eqc_a = eqc,
                PhoenixxValue::B => step.eqc_b = eqc,
            }
        }
    }

    fn update_step_locks(&mut self, round: usize) {
        let locks = summarize_locks(&self.locks);
        if let Some(step) = self.rounds.iter_mut().find(|step| step.round == round) {
            step.locks = locks;
        }
    }
}

#[derive(Debug, Clone)]
struct PhoenixxValidator {
    id: usize,
    options: PhoenixxOptions,
    lock: ValidatorLock,
    committees: BTreeMap<usize, BTreeSet<usize>>,
    confirmed: BTreeSet<(usize, PhoenixxValue)>,
    endorsed: BTreeSet<(usize, PhoenixxValue)>,
}

impl PhoenixxValidator {
    fn new(id: usize, options: PhoenixxOptions) -> Self {
        Self {
            id,
            options,
            lock: ValidatorLock::default(),
            committees: BTreeMap::new(),
            confirmed: BTreeSet::new(),
            endorsed: BTreeSet::new(),
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
        message: DeliveredMessage<PhoenixxMessage>,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        match message.payload {
            PhoenixxMessage::Proposal {
                round,
                value,
                parent_round,
                committee,
            } => self.handle_proposal(round, value, parent_round, committee, ctx),
            PhoenixxMessage::NqcForEndorsement {
                round,
                value,
                signers,
            } => self.handle_nqc(round, value, &signers, ctx),
            PhoenixxMessage::CertificateVisible { round, value } => {
                ctx.record(PhoenixxNodeEvent::CertificateObserved { round, value });
            }
            PhoenixxMessage::StartRound { .. }
            | PhoenixxMessage::Confirm { .. }
            | PhoenixxMessage::Endorse { .. } => {}
        }
    }

    fn handle_proposal(
        &mut self,
        round: usize,
        proposal: PhoenixxValue,
        parent_round: usize,
        committee: Vec<usize>,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        self.committees
            .insert(round, committee.iter().copied().collect());
        if self.honest() {
            let value = self.honest_confirm_value(proposal);
            if lock_allows(self.lock, value, parent_round) {
                self.send_confirm(round, value, ctx);
            } else {
                ctx.record(PhoenixxNodeEvent::ProposalRejected {
                    round,
                    value,
                    lock_round: self.lock.round,
                });
            }
        } else {
            self.send_byzantine_confirms(round, ctx);
            self.send_byzantine_endorsements(round, ctx);
        }
    }

    fn honest_confirm_value(&self, proposal: PhoenixxValue) -> PhoenixxValue {
        if self.options.rounds == 1 {
            if self.id < self.options.initial_honest_a {
                PhoenixxValue::A
            } else {
                PhoenixxValue::B
            }
        } else {
            proposal
        }
    }

    fn send_confirm(
        &mut self,
        round: usize,
        value: PhoenixxValue,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if self.confirmed.insert((round, value)) {
            ctx.record(PhoenixxNodeEvent::Confirmed { round, value });
            ctx.send_after(
                self.coordinator_id(),
                PhoenixxMessage::Confirm {
                    round,
                    value,
                    signer: self.id,
                },
                0,
            );
        }
    }

    fn handle_nqc(
        &mut self,
        round: usize,
        value: PhoenixxValue,
        signers: &[usize],
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if self.honest() && signers.contains(&self.id) {
            self.lock = ValidatorLock {
                value: Some(value),
                round,
            };
            ctx.record(PhoenixxNodeEvent::Locked { round, value });
        }
        if self.honest()
            && self.is_committee_member(round)
            && self.confirmed.contains(&(round, value))
            && self.endorsed.insert((round, value))
        {
            ctx.record(PhoenixxNodeEvent::Endorsed { round, value });
            ctx.send_after(
                self.coordinator_id(),
                PhoenixxMessage::Endorse {
                    round,
                    value,
                    signer: self.id,
                },
                0,
            );
        }
    }

    fn is_committee_member(&self, round: usize) -> bool {
        self.committees
            .get(&round)
            .map(|committee| committee.contains(&self.id))
            .unwrap_or(false)
    }

    fn send_byzantine_confirms(
        &mut self,
        round: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        for value in self.byzantine_values() {
            self.send_confirm(round, value, ctx);
        }
    }

    fn send_byzantine_endorsements(
        &mut self,
        round: usize,
        ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
    ) {
        if !self.is_committee_member(round) {
            return;
        }
        for value in self.byzantine_values() {
            if self.endorsed.insert((round, value)) {
                ctx.record(PhoenixxNodeEvent::Endorsed { round, value });
                ctx.send_after(
                    self.coordinator_id(),
                    PhoenixxMessage::Endorse {
                        round,
                        value,
                        signer: self.id,
                    },
                    0,
                );
            }
        }
    }

    fn byzantine_values(&self) -> Vec<PhoenixxValue> {
        match self.options.byzantine_strategy {
            PhoenixxByzantineStrategy::Silent => Vec::new(),
            PhoenixxByzantineStrategy::StaticA => vec![PhoenixxValue::A],
            PhoenixxByzantineStrategy::StaticB => vec![PhoenixxValue::B],
            PhoenixxByzantineStrategy::Equivocate => vec![PhoenixxValue::A, PhoenixxValue::B],
        }
    }
}

fn sample_committee(
    options: &PhoenixxOptions,
    ctx: &mut NetworkContext<'_, PhoenixxMessage, PhoenixxNodeEvent>,
) -> PhoenixxCommitteeDraw {
    let honest = options.n - options.byzantine;
    let mut members: Vec<usize> = (0..options.n).collect();
    for i in 0..options.committee_size {
        let j = i + ctx.random_index(members.len() - i);
        members.swap(i, j);
    }
    members.truncate(options.committee_size);
    members.sort_unstable();

    let honest_members: Vec<usize> = members.iter().copied().filter(|&id| id < honest).collect();
    let byzantine_members: Vec<usize> =
        members.iter().copied().filter(|&id| id >= honest).collect();
    let byzantine_count = byzantine_members.len();

    PhoenixxCommitteeDraw {
        members,
        honest_members,
        byzantine_members,
        byzantine_count,
        exceeds_bound: byzantine_count > options.committee_bound,
    }
}

fn lock_allows(lock: ValidatorLock, proposal: PhoenixxValue, parent_round: usize) -> bool {
    match lock.value {
        None => true,
        Some(value) if value == proposal => true,
        Some(_) => parent_round >= lock.round,
    }
}

fn update_locks_for_value(
    locks: &mut [ValidatorLock],
    round: usize,
    certificate: &PhoenixxCertificate,
) {
    if !certificate.formed {
        return;
    }
    for &signer in &certificate.signers {
        if let Some(lock) = locks.get_mut(signer) {
            lock.value = Some(certificate.value);
            lock.round = round;
        }
    }
}

fn summarize_locks(locks: &[ValidatorLock]) -> PhoenixxLockSummary {
    let locked_a = locks
        .iter()
        .filter(|lock| lock.value == Some(PhoenixxValue::A))
        .count();
    let locked_b = locks
        .iter()
        .filter(|lock| lock.value == Some(PhoenixxValue::B))
        .count();
    let unlocked = locks.iter().filter(|lock| lock.value.is_none()).count();
    let highest_lock_round = locks.iter().map(|lock| lock.round).max().unwrap_or(0);

    PhoenixxLockSummary {
        locked_a,
        locked_b,
        unlocked,
        highest_lock_round,
    }
}

fn empty_certificate(value: PhoenixxValue, threshold: usize) -> PhoenixxCertificate {
    PhoenixxCertificate {
        value,
        threshold,
        formed: false,
        total_signers: 0,
        honest_signers: 0,
        byzantine_signers: 0,
        signers: Vec::new(),
    }
}

fn empty_eqc(value: PhoenixxValue, threshold: usize) -> PhoenixxEqc {
    PhoenixxEqc {
        certificate: empty_certificate(value, threshold),
        honest_nqc_backed: false,
    }
}

fn certificate(
    value: PhoenixxValue,
    threshold: usize,
    signers: &BTreeSet<usize>,
    honest: usize,
) -> PhoenixxCertificate {
    let signers_vec: Vec<usize> = signers.iter().copied().collect();
    let honest_signers = signers_vec.iter().filter(|&&id| id < honest).count();
    let byzantine_signers = signers_vec.len() - honest_signers;

    PhoenixxCertificate {
        value,
        threshold,
        formed: signers_vec.len() >= threshold,
        total_signers: signers_vec.len(),
        honest_signers,
        byzantine_signers,
        signers: signers_vec,
    }
}

fn summarize(rounds: &[PhoenixxRoundStep]) -> PhoenixxSummary {
    let rounds_executed = rounds.len();
    let committee_bound_violation = rounds.iter().any(|round| round.committee.exceeds_bound);
    let nqc_a_formed = rounds.iter().any(|round| round.nqc_a.formed);
    let nqc_b_formed = rounds.iter().any(|round| round.nqc_b.formed);
    let eqc_a_formed = rounds.iter().any(|round| round.eqc_a.certificate.formed);
    let eqc_b_formed = rounds.iter().any(|round| round.eqc_b.certificate.formed);
    let agreement_violation = eqc_a_formed && eqc_b_formed;
    let decided_value = if agreement_violation {
        None
    } else if eqc_a_formed {
        Some(PhoenixxValue::A)
    } else if eqc_b_formed {
        Some(PhoenixxValue::B)
    } else {
        None
    };
    let eqc_without_honest_nqc = rounds.iter().any(|round| {
        (round.eqc_a.certificate.formed && !round.eqc_a.honest_nqc_backed)
            || (round.eqc_b.certificate.formed && !round.eqc_b.honest_nqc_backed)
    });
    let final_locks =
        rounds
            .last()
            .map(|round| round.locks.clone())
            .unwrap_or(PhoenixxLockSummary {
                locked_a: 0,
                locked_b: 0,
                unlocked: 0,
                highest_lock_round: 0,
            });

    PhoenixxSummary {
        rounds_executed,
        decided_value,
        agreement_violation,
        committee_bound_violation,
        eqc_without_honest_nqc,
        nqc_a_formed,
        nqc_b_formed,
        eqc_a_formed,
        eqc_b_formed,
        final_locks,
    }
}

fn summarize_batch(runs: &[PhoenixxBatchRunSummary]) -> PhoenixxBatchSummary {
    let decided_a = runs
        .iter()
        .filter(|run| run.decided_value == Some(PhoenixxValue::A))
        .count();
    let decided_b = runs
        .iter()
        .filter(|run| run.decided_value == Some(PhoenixxValue::B))
        .count();
    let committee_bound_violations = runs
        .iter()
        .filter(|run| run.committee_bound_violation)
        .count();
    let agreement_violations = runs.iter().filter(|run| run.agreement_violation).count();
    let eqc_without_honest_nqc = runs.iter().filter(|run| run.eqc_without_honest_nqc).count();
    let len = runs.len();
    let total_rounds: usize = runs.iter().map(|run| run.rounds_executed).sum();

    PhoenixxBatchSummary {
        runs: len,
        decided_a,
        decided_b,
        undecided_or_conflicted: len - decided_a - decided_b,
        committee_bound_violations,
        agreement_violations,
        eqc_without_honest_nqc,
        committee_bound_violation_rate: committee_bound_violations as f64 / len as f64,
        agreement_violation_rate: agreement_violations as f64 / len as f64,
        eqc_without_honest_nqc_rate: eqc_without_honest_nqc as f64 / len as f64,
        mean_rounds_executed: total_rounds as f64 / len as f64,
    }
}

fn warnings(options: &PhoenixxOptions, analyzed: &PhoenixxCommitteeBound) -> Vec<String> {
    let mut warnings = vec![
        "Phoenixx simulation models a bounded NQC/EQC safety kernel with lock carry-over; full pacemaker/leader rotation is not modeled yet".into(),
        "network delay is modeled as whole-round certificate visibility delay for view-change parent selection".into(),
    ];
    if options.rounds == 1 {
        warnings.push(
            "single-round mode preserves initial split semantics; use --rounds > 1 for lock/view-change experiments"
                .into(),
        );
    }
    if options.committee_bound < analyzed.analyzed_b_max {
        warnings.push(format!(
            "configured committee bound {} is below analyzed b_max {}; bound violations are expected above epsilon",
            options.committee_bound, analyzed.analyzed_b_max
        ));
    }
    if options.eqc_threshold <= options.committee_bound {
        warnings.push(format!(
            "EQC threshold {} does not exceed committee bound {}; honest endorser inclusion is not guaranteed",
            options.eqc_threshold, options.committee_bound
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_options() -> PhoenixxOptions {
        PhoenixxOptions {
            n: 4,
            byzantine: 1,
            committee_size: 4,
            committee_bound: 1,
            epsilon: 1e-9,
            nqc_threshold: 3,
            eqc_threshold: 2,
            initial_honest_a: 3,
            seed: 3,
            byzantine_strategy: PhoenixxByzantineStrategy::Silent,
            rounds: 1,
            network_delay_rounds: 0,
            proposal_pattern: PhoenixxProposalPattern::ViewChange,
        }
    }

    #[test]
    fn honest_nqc_leads_to_honest_backed_eqc() {
        let result = simulate_phoenixx(base_options()).expect("valid Phoenixx options");
        assert_eq!(result.summary.decided_value, Some(PhoenixxValue::A));
        assert!(result.nqc_a.formed);
        assert!(result.eqc_a.certificate.formed);
        assert!(result.eqc_a.honest_nqc_backed);
        assert!(!result.summary.agreement_violation);
        assert!(!result.summary.eqc_without_honest_nqc);
    }

    #[test]
    fn byzantine_only_eqc_is_flagged_as_unbacked() {
        let mut options = base_options();
        options.initial_honest_a = 0;
        options.eqc_threshold = 1;
        options.byzantine_strategy = PhoenixxByzantineStrategy::StaticA;

        let result = simulate_phoenixx(options).expect("valid Phoenixx options");
        assert!(result.eqc_a.certificate.formed);
        assert!(!result.eqc_a.honest_nqc_backed);
        assert!(result.summary.eqc_without_honest_nqc);
    }

    #[test]
    fn same_seed_draws_same_committee() {
        let left = simulate_phoenixx(base_options()).expect("valid Phoenixx options");
        let right = simulate_phoenixx(base_options()).expect("valid Phoenixx options");
        assert_eq!(left.committee, right.committee);
        assert_eq!(left.summary, right.summary);
    }

    #[test]
    fn batch_counts_runs() {
        let batch = simulate_phoenixx_batch(base_options(), 5).expect("valid Phoenixx batch");
        assert_eq!(batch.summary.runs, 5);
        assert_eq!(batch.runs.len(), 5);
        assert_eq!(batch.summary.decided_a, 5);
    }

    #[test]
    fn delayed_view_change_parent_preserves_conflicting_lock() {
        let mut delayed = base_options();
        delayed.rounds = 2;
        delayed.eqc_threshold = 4;
        delayed.proposal_pattern = PhoenixxProposalPattern::Alternate;
        delayed.network_delay_rounds = 2;

        let delayed_result = simulate_phoenixx(delayed).expect("valid Phoenixx options");
        assert_eq!(delayed_result.summary.rounds_executed, 2);
        assert!(delayed_result.rounds[0].nqc_a.formed);
        assert!(!delayed_result.rounds[1].nqc_b.formed);
        assert_eq!(delayed_result.summary.final_locks.locked_a, 3);

        let mut visible = base_options();
        visible.rounds = 2;
        visible.eqc_threshold = 4;
        visible.proposal_pattern = PhoenixxProposalPattern::Alternate;
        visible.network_delay_rounds = 0;

        let visible_result = simulate_phoenixx(visible).expect("valid Phoenixx options");
        assert!(visible_result.rounds[1].nqc_b.formed);
        assert_eq!(visible_result.summary.final_locks.locked_b, 3);
    }
}
