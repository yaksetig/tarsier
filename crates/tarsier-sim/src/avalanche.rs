//! Avalanche/Snowball-style sampled consensus simulation.
//!
//! This module is a concrete stochastic simulator, not a proof engine. It is
//! useful for exploring convergence behavior, parameter sensitivity, and
//! adversarial response policies before writing a formal `.trs` abstraction.

use serde::{Deserialize, Serialize};

use crate::{DeterministicRng, Scheduler};

/// Binary value used by the sampled Snowball model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnowValue {
    A,
    B,
}

impl SnowValue {
    fn opposite(self) -> Self {
        match self {
            SnowValue::A => SnowValue::B,
            SnowValue::B => SnowValue::A,
        }
    }
}

impl std::fmt::Display for SnowValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnowValue::A => write!(f, "A"),
            SnowValue::B => write!(f, "B"),
        }
    }
}

/// Byzantine response strategy for sampled peers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByzantineStrategy {
    /// Byzantine validators always answer A.
    StaticA,
    /// Byzantine validators always answer B.
    StaticB,
    /// Byzantine validators answer the opposite of the polling validator's
    /// current preference.
    #[default]
    OpposeRequester,
    /// Byzantine validators choose a fresh random binary answer per response.
    Random,
}

/// Rule used to decide after successful polls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRule {
    /// Snowball-style: decide when the current preference confidence reaches beta.
    #[default]
    Confidence,
    /// Snowflake-style: decide after beta consecutive successful polls for the
    /// current preference.
    Consecutive,
}

/// Configuration for one Avalanche/Snowball simulation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballOptions {
    /// Total validators, including Byzantine validators.
    pub n: usize,
    /// Number of Byzantine validators.
    pub byzantine: usize,
    /// Sample size k.
    pub sample_size: usize,
    /// Successful poll threshold alpha. Must be a strict sample majority.
    pub alpha: usize,
    /// Decision confidence threshold beta.
    pub beta: usize,
    /// Maximum number of polling rounds. Each round gives every undecided
    /// honest validator one polling opportunity.
    pub max_rounds: usize,
    /// Seed for sampled peer selection and randomized scheduling.
    pub seed: u64,
    /// Honest validators initially preferring A. Remaining honest validators
    /// initially prefer B.
    pub initial_honest_a: usize,
    /// Polling order policy for honest validators within each round.
    pub scheduler: Scheduler,
    /// Byzantine response policy.
    pub byzantine_strategy: ByzantineStrategy,
    /// Decision rule.
    pub decision_rule: DecisionRule,
}

impl Default for SnowballOptions {
    fn default() -> Self {
        Self {
            n: 100,
            byzantine: 0,
            sample_size: 20,
            alpha: 15,
            beta: 20,
            max_rounds: 100,
            seed: 0,
            initial_honest_a: 100,
            scheduler: Scheduler::Random,
            byzantine_strategy: ByzantineStrategy::OpposeRequester,
            decision_rule: DecisionRule::Confidence,
        }
    }
}

/// Why a sampled simulation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowballStopReason {
    AllHonestDecided,
    AgreementViolation,
    MaxRounds,
}

/// Final aggregate statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballSummary {
    pub rounds_executed: usize,
    pub polls_executed: usize,
    pub stopped_reason: SnowballStopReason,
    pub honest_decided_a: usize,
    pub honest_decided_b: usize,
    pub honest_undecided: usize,
    pub final_honest_preference_a: usize,
    pub final_honest_preference_b: usize,
    pub first_decision_round: Option<usize>,
    pub last_decision_round: Option<usize>,
    pub agreement_violation: bool,
}

/// Validator state at the end of a simulation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballValidatorState {
    pub id: usize,
    pub byzantine: bool,
    pub preference: SnowValue,
    pub decided: bool,
    pub decision: Option<SnowValue>,
    pub confidence_a: usize,
    pub confidence_b: usize,
    pub consecutive_successes: usize,
    pub last_success: Option<SnowValue>,
    pub decision_round: Option<usize>,
}

/// One polling step in the sampled execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballPollStep {
    pub round: usize,
    pub poll: usize,
    pub validator_id: usize,
    pub old_preference: SnowValue,
    pub sample: Vec<usize>,
    pub responses_a: usize,
    pub responses_b: usize,
    pub byzantine_responses: usize,
    pub successful_value: Option<SnowValue>,
    pub new_preference: SnowValue,
    pub confidence_a: usize,
    pub confidence_b: usize,
    pub consecutive_successes: usize,
    pub decided: bool,
    pub decision: Option<SnowValue>,
}

/// Complete sampled simulation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballResult {
    pub options: SnowballOptions,
    pub summary: SnowballSummary,
    pub validators: Vec<SnowballValidatorState>,
    pub steps: Vec<SnowballPollStep>,
    pub warnings: Vec<String>,
}

/// Configuration for a Monte Carlo batch of sampled Snowball runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballBatchOptions {
    /// Base options. Each run uses the same options except for the seed.
    pub base: SnowballOptions,
    /// Number of independent seeds to execute.
    pub runs: usize,
}

/// One-line summary for a single run in a Monte Carlo batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowballBatchRunSummary {
    pub run: usize,
    pub seed: u64,
    pub stopped_reason: SnowballStopReason,
    pub rounds_executed: usize,
    pub polls_executed: usize,
    pub honest_decided_a: usize,
    pub honest_decided_b: usize,
    pub honest_undecided: usize,
    pub final_honest_preference_a: usize,
    pub final_honest_preference_b: usize,
    pub first_decision_round: Option<usize>,
    pub last_decision_round: Option<usize>,
    pub agreement_violation: bool,
}

/// Simple quantile summary for integer observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantileStats {
    pub count: usize,
    pub mean: f64,
    pub min: usize,
    pub p50: usize,
    pub p95: usize,
    pub p99: usize,
    pub max: usize,
}

/// Wilson score interval for a Bernoulli rate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WilsonInterval {
    pub estimate: f64,
    pub lower_95: f64,
    pub upper_95: f64,
}

/// Aggregate statistics over a Monte Carlo batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnowballBatchSummary {
    pub runs: usize,
    pub converged: usize,
    pub max_rounds_reached: usize,
    pub agreement_violations: usize,
    pub all_a: usize,
    pub all_b: usize,
    pub mixed_or_partial: usize,
    pub convergence_rate: f64,
    pub agreement_violation_rate: f64,
    pub convergence_95: WilsonInterval,
    pub agreement_violation_95: WilsonInterval,
    pub finality_rounds: Option<QuantileStats>,
    pub finality_polls: Option<QuantileStats>,
}

/// Complete Monte Carlo batch output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnowballBatchResult {
    pub options: SnowballBatchOptions,
    pub summary: SnowballBatchSummary,
    pub runs: Vec<SnowballBatchRunSummary>,
    pub warnings: Vec<String>,
}

/// Configuration errors for sampled simulation.
#[derive(Debug, thiserror::Error)]
pub enum SnowballError {
    #[error("n must be at least 2 to sample peers, got {0}")]
    InvalidPopulation(usize),
    #[error("byzantine count ({byzantine}) must be less than n ({n})")]
    InvalidByzantineCount { n: usize, byzantine: usize },
    #[error("sample size k must be in 1..n, got k={sample_size}, n={n}")]
    InvalidSampleSize { n: usize, sample_size: usize },
    #[error(
        "alpha must be in 1..=k and a strict sample majority, got alpha={alpha}, k={sample_size}"
    )]
    InvalidAlpha { sample_size: usize, alpha: usize },
    #[error("beta must be positive, got {0}")]
    InvalidBeta(usize),
    #[error(
        "initial honest A count ({initial_honest_a}) exceeds honest validator count ({honest})"
    )]
    InvalidInitialSplit {
        honest: usize,
        initial_honest_a: usize,
    },
    #[error("batch simulation requires at least one run, got {0}")]
    InvalidRuns(usize),
}

/// Run a two-value Avalanche/Snowball sampled consensus simulation.
pub fn simulate_snowball(options: SnowballOptions) -> Result<SnowballResult, SnowballError> {
    validate_options(&options)?;

    let mut rng = DeterministicRng::new(options.seed);
    let honest = options.n - options.byzantine;
    let mut validators = initialize_validators(&options);
    let mut steps = Vec::new();
    let mut stopped_reason = SnowballStopReason::MaxRounds;
    let mut poll_count = 0usize;

    for round in 1..=options.max_rounds {
        let mut order: Vec<usize> = validators
            .iter()
            .take(honest)
            .filter(|v| !v.decided)
            .map(|v| v.id)
            .collect();

        if order.is_empty() {
            stopped_reason = SnowballStopReason::AllHonestDecided;
            break;
        }
        if options.scheduler == Scheduler::Random {
            shuffle(&mut order, &mut rng);
        }

        for validator_id in order {
            if validators[validator_id].decided {
                continue;
            }
            poll_count += 1;
            let step = poll_validator(
                &mut validators,
                validator_id,
                round,
                poll_count,
                &options,
                &mut rng,
            );
            steps.push(step);

            if has_agreement_violation(&validators[..honest]) {
                stopped_reason = SnowballStopReason::AgreementViolation;
                break;
            }
            if validators[..honest].iter().all(|v| v.decided) {
                stopped_reason = SnowballStopReason::AllHonestDecided;
                break;
            }
        }

        if stopped_reason != SnowballStopReason::MaxRounds {
            break;
        }
    }

    let summary = summarize(honest, stopped_reason, &validators, &steps);
    Ok(SnowballResult {
        options,
        summary,
        validators,
        steps,
        warnings: vec![
            "sampled Snowball simulation uses equal validator weights; stake weighting is not modeled yet".into(),
            "network delay is abstracted to one completed query per polling step".into(),
        ],
    })
}

/// Run many independent Snowball simulations and summarize convergence rates.
///
/// Run `i` uses `base_options.seed + i` with wrapping arithmetic, so a batch is
/// deterministic and resumable from its base seed.
pub fn simulate_snowball_batch(
    base_options: SnowballOptions,
    runs: usize,
) -> Result<SnowballBatchResult, SnowballError> {
    if runs == 0 {
        return Err(SnowballError::InvalidRuns(runs));
    }
    validate_options(&base_options)?;

    let mut run_summaries = Vec::with_capacity(runs);
    let mut warnings = std::collections::BTreeSet::new();

    for run_index in 0..runs {
        let seed = base_options.seed.wrapping_add(run_index as u64);
        let mut options = base_options.clone();
        options.seed = seed;
        let result = simulate_snowball(options)?;

        for warning in result.warnings {
            warnings.insert(warning);
        }
        run_summaries.push(batch_run_summary(run_index + 1, seed, &result.summary));
    }

    warnings.insert(
        "batch mode stores per-run summaries only; use --runs 1 for the full poll trace".into(),
    );

    let honest = base_options.n - base_options.byzantine;
    let summary = summarize_batch(honest, &run_summaries);
    Ok(SnowballBatchResult {
        options: SnowballBatchOptions {
            base: base_options,
            runs,
        },
        summary,
        runs: run_summaries,
        warnings: warnings.into_iter().collect(),
    })
}

fn validate_options(options: &SnowballOptions) -> Result<(), SnowballError> {
    if options.n < 2 {
        return Err(SnowballError::InvalidPopulation(options.n));
    }
    if options.byzantine >= options.n {
        return Err(SnowballError::InvalidByzantineCount {
            n: options.n,
            byzantine: options.byzantine,
        });
    }
    if options.sample_size == 0 || options.sample_size >= options.n {
        return Err(SnowballError::InvalidSampleSize {
            n: options.n,
            sample_size: options.sample_size,
        });
    }
    if options.alpha == 0
        || options.alpha > options.sample_size
        || options.alpha * 2 <= options.sample_size
    {
        return Err(SnowballError::InvalidAlpha {
            sample_size: options.sample_size,
            alpha: options.alpha,
        });
    }
    if options.beta == 0 {
        return Err(SnowballError::InvalidBeta(options.beta));
    }
    let honest = options.n - options.byzantine;
    if options.initial_honest_a > honest {
        return Err(SnowballError::InvalidInitialSplit {
            honest,
            initial_honest_a: options.initial_honest_a,
        });
    }
    Ok(())
}

fn initialize_validators(options: &SnowballOptions) -> Vec<SnowballValidatorState> {
    let honest = options.n - options.byzantine;
    (0..options.n)
        .map(|id| {
            let byzantine = id >= honest;
            let preference = if id < options.initial_honest_a {
                SnowValue::A
            } else {
                SnowValue::B
            };
            SnowballValidatorState {
                id,
                byzantine,
                preference,
                decided: false,
                decision: None,
                confidence_a: 0,
                confidence_b: 0,
                consecutive_successes: 0,
                last_success: None,
                decision_round: None,
            }
        })
        .collect()
}

fn poll_validator(
    validators: &mut [SnowballValidatorState],
    validator_id: usize,
    round: usize,
    poll: usize,
    options: &SnowballOptions,
    rng: &mut DeterministicRng,
) -> SnowballPollStep {
    let old_preference = validators[validator_id].preference;
    let sample = sample_peers(options.n, validator_id, options.sample_size, rng);
    let mut responses_a = 0usize;
    let mut responses_b = 0usize;
    let mut byzantine_responses = 0usize;

    for &peer_id in &sample {
        let response = if validators[peer_id].byzantine {
            byzantine_responses += 1;
            byzantine_response(options.byzantine_strategy, old_preference, rng)
        } else {
            validators[peer_id].preference
        };
        match response {
            SnowValue::A => responses_a += 1,
            SnowValue::B => responses_b += 1,
        }
    }

    let successful_value = if responses_a >= options.alpha {
        Some(SnowValue::A)
    } else if responses_b >= options.alpha {
        Some(SnowValue::B)
    } else {
        None
    };

    if let Some(value) = successful_value {
        match value {
            SnowValue::A => validators[validator_id].confidence_a += 1,
            SnowValue::B => validators[validator_id].confidence_b += 1,
        }
        if validators[validator_id].last_success == Some(value) {
            validators[validator_id].consecutive_successes += 1;
        } else {
            validators[validator_id].last_success = Some(value);
            validators[validator_id].consecutive_successes = 1;
        }

        let confidence_value = confidence_for(&validators[validator_id], value);
        let confidence_preference = confidence_for(
            &validators[validator_id],
            validators[validator_id].preference,
        );
        if confidence_value > confidence_preference {
            validators[validator_id].preference = value;
        }
    } else {
        validators[validator_id].last_success = None;
        validators[validator_id].consecutive_successes = 0;
    }

    let should_decide = match options.decision_rule {
        DecisionRule::Confidence => {
            confidence_for(
                &validators[validator_id],
                validators[validator_id].preference,
            ) >= options.beta
        }
        DecisionRule::Consecutive => {
            validators[validator_id].last_success == Some(validators[validator_id].preference)
                && validators[validator_id].consecutive_successes >= options.beta
        }
    };

    if should_decide && !validators[validator_id].decided {
        validators[validator_id].decided = true;
        validators[validator_id].decision = Some(validators[validator_id].preference);
        validators[validator_id].decision_round = Some(round);
    }

    SnowballPollStep {
        round,
        poll,
        validator_id,
        old_preference,
        sample,
        responses_a,
        responses_b,
        byzantine_responses,
        successful_value,
        new_preference: validators[validator_id].preference,
        confidence_a: validators[validator_id].confidence_a,
        confidence_b: validators[validator_id].confidence_b,
        consecutive_successes: validators[validator_id].consecutive_successes,
        decided: validators[validator_id].decided,
        decision: validators[validator_id].decision,
    }
}

fn batch_run_summary(run: usize, seed: u64, summary: &SnowballSummary) -> SnowballBatchRunSummary {
    SnowballBatchRunSummary {
        run,
        seed,
        stopped_reason: summary.stopped_reason,
        rounds_executed: summary.rounds_executed,
        polls_executed: summary.polls_executed,
        honest_decided_a: summary.honest_decided_a,
        honest_decided_b: summary.honest_decided_b,
        honest_undecided: summary.honest_undecided,
        final_honest_preference_a: summary.final_honest_preference_a,
        final_honest_preference_b: summary.final_honest_preference_b,
        first_decision_round: summary.first_decision_round,
        last_decision_round: summary.last_decision_round,
        agreement_violation: summary.agreement_violation,
    }
}

fn summarize_batch(honest: usize, runs: &[SnowballBatchRunSummary]) -> SnowballBatchSummary {
    let converged = runs
        .iter()
        .filter(|run| run.stopped_reason == SnowballStopReason::AllHonestDecided)
        .count();
    let max_rounds_reached = runs
        .iter()
        .filter(|run| run.stopped_reason == SnowballStopReason::MaxRounds)
        .count();
    let agreement_violations = runs.iter().filter(|run| run.agreement_violation).count();
    let all_a = runs
        .iter()
        .filter(|run| {
            run.honest_decided_a == honest && run.honest_decided_b == 0 && run.honest_undecided == 0
        })
        .count();
    let all_b = runs
        .iter()
        .filter(|run| {
            run.honest_decided_b == honest && run.honest_decided_a == 0 && run.honest_undecided == 0
        })
        .count();
    let mixed_or_partial = runs.len() - all_a - all_b;
    let convergence_rate = converged as f64 / runs.len() as f64;
    let agreement_violation_rate = agreement_violations as f64 / runs.len() as f64;
    let finality_round_values: Vec<usize> = runs
        .iter()
        .filter(|run| run.stopped_reason == SnowballStopReason::AllHonestDecided)
        .filter_map(|run| run.last_decision_round)
        .collect();
    let finality_poll_values: Vec<usize> = runs
        .iter()
        .filter(|run| run.stopped_reason == SnowballStopReason::AllHonestDecided)
        .map(|run| run.polls_executed)
        .collect();

    SnowballBatchSummary {
        runs: runs.len(),
        converged,
        max_rounds_reached,
        agreement_violations,
        all_a,
        all_b,
        mixed_or_partial,
        convergence_rate,
        agreement_violation_rate,
        convergence_95: wilson_interval(converged, runs.len()),
        agreement_violation_95: wilson_interval(agreement_violations, runs.len()),
        finality_rounds: quantile_stats(&finality_round_values),
        finality_polls: quantile_stats(&finality_poll_values),
    }
}

fn quantile_stats(values: &[usize]) -> Option<QuantileStats> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum: f64 = sorted.iter().map(|&value| value as f64).sum();
    Some(QuantileStats {
        count: sorted.len(),
        mean: sum / sorted.len() as f64,
        min: sorted[0],
        p50: nearest_rank(&sorted, 0.50),
        p95: nearest_rank(&sorted, 0.95),
        p99: nearest_rank(&sorted, 0.99),
        max: *sorted.last().expect("checked non-empty"),
    })
}

fn nearest_rank(sorted_values: &[usize], quantile: f64) -> usize {
    let index = ((quantile * sorted_values.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_values.len() - 1);
    sorted_values[index]
}

fn wilson_interval(successes: usize, total: usize) -> WilsonInterval {
    if total == 0 {
        return WilsonInterval {
            estimate: 0.0,
            lower_95: 0.0,
            upper_95: 0.0,
        };
    }

    let n = total as f64;
    let p = successes as f64 / n;
    let z = 1.959_963_984_540_054_f64;
    let z2 = z * z;
    let denominator = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator;
    let margin = z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt() / denominator;

    WilsonInterval {
        estimate: p,
        lower_95: (center - margin).max(0.0),
        upper_95: (center + margin).min(1.0),
    }
}

fn confidence_for(validator: &SnowballValidatorState, value: SnowValue) -> usize {
    match value {
        SnowValue::A => validator.confidence_a,
        SnowValue::B => validator.confidence_b,
    }
}

fn byzantine_response(
    strategy: ByzantineStrategy,
    requester_preference: SnowValue,
    rng: &mut DeterministicRng,
) -> SnowValue {
    match strategy {
        ByzantineStrategy::StaticA => SnowValue::A,
        ByzantineStrategy::StaticB => SnowValue::B,
        ByzantineStrategy::OpposeRequester => requester_preference.opposite(),
        ByzantineStrategy::Random => {
            if rng.index(2) == 0 {
                SnowValue::A
            } else {
                SnowValue::B
            }
        }
    }
}

fn sample_peers(
    n: usize,
    requester: usize,
    sample_size: usize,
    rng: &mut DeterministicRng,
) -> Vec<usize> {
    let mut peers: Vec<usize> = (0..n).filter(|&id| id != requester).collect();
    for i in 0..sample_size {
        let j = i + rng.index(peers.len() - i);
        peers.swap(i, j);
    }
    peers.truncate(sample_size);
    peers
}

fn shuffle<T>(values: &mut [T], rng: &mut DeterministicRng) {
    for i in 0..values.len() {
        let j = i + rng.index(values.len() - i);
        values.swap(i, j);
    }
}

fn has_agreement_violation(honest_validators: &[SnowballValidatorState]) -> bool {
    let mut decided = honest_validators
        .iter()
        .filter_map(|validator| validator.decision);
    let Some(first) = decided.next() else {
        return false;
    };
    decided.any(|decision| decision != first)
}

fn summarize(
    honest: usize,
    stopped_reason: SnowballStopReason,
    validators: &[SnowballValidatorState],
    steps: &[SnowballPollStep],
) -> SnowballSummary {
    let honest_validators = &validators[..honest];
    let honest_decided_a = honest_validators
        .iter()
        .filter(|v| v.decision == Some(SnowValue::A))
        .count();
    let honest_decided_b = honest_validators
        .iter()
        .filter(|v| v.decision == Some(SnowValue::B))
        .count();
    let honest_undecided = honest_validators.iter().filter(|v| !v.decided).count();
    let final_honest_preference_a = honest_validators
        .iter()
        .filter(|v| v.preference == SnowValue::A)
        .count();
    let final_honest_preference_b = honest_validators
        .iter()
        .filter(|v| v.preference == SnowValue::B)
        .count();
    let mut decision_rounds: Vec<usize> = honest_validators
        .iter()
        .filter_map(|v| v.decision_round)
        .collect();
    decision_rounds.sort_unstable();

    SnowballSummary {
        rounds_executed: steps.last().map(|step| step.round).unwrap_or(0),
        polls_executed: steps.len(),
        stopped_reason,
        honest_decided_a,
        honest_decided_b,
        honest_undecided,
        final_honest_preference_a,
        final_honest_preference_b,
        first_decision_round: decision_rounds.first().copied(),
        last_decision_round: decision_rounds.last().copied(),
        agreement_violation: has_agreement_violation(honest_validators),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convergent_options() -> SnowballOptions {
        SnowballOptions {
            n: 10,
            byzantine: 0,
            sample_size: 5,
            alpha: 3,
            beta: 2,
            max_rounds: 10,
            seed: 11,
            initial_honest_a: 10,
            scheduler: Scheduler::Random,
            byzantine_strategy: ByzantineStrategy::OpposeRequester,
            decision_rule: DecisionRule::Confidence,
        }
    }

    #[test]
    fn all_a_converges_and_decides_a() {
        let result = simulate_snowball(convergent_options()).expect("valid options");
        assert_eq!(
            result.summary.stopped_reason,
            SnowballStopReason::AllHonestDecided
        );
        assert_eq!(result.summary.honest_decided_a, 10);
        assert!(!result.summary.agreement_violation);
    }

    #[test]
    fn same_seed_is_reproducible() {
        let left = simulate_snowball(convergent_options()).expect("valid options");
        let right = simulate_snowball(convergent_options()).expect("valid options");
        assert_eq!(left.summary, right.summary);
        assert_eq!(left.steps, right.steps);
    }

    #[test]
    fn invalid_alpha_must_be_strict_majority() {
        let mut options = convergent_options();
        options.alpha = 2;
        let err = simulate_snowball(options).expect_err("alpha <= k/2 should fail");
        assert!(matches!(err, SnowballError::InvalidAlpha { .. }));
    }

    #[test]
    fn batch_summarizes_convergent_runs() {
        let result = simulate_snowball_batch(convergent_options(), 5).expect("valid batch");
        assert_eq!(result.summary.runs, 5);
        assert_eq!(result.summary.converged, 5);
        assert_eq!(result.summary.all_a, 5);
        assert_eq!(result.summary.agreement_violations, 0);
        assert_eq!(result.summary.finality_rounds.as_ref().unwrap().count, 5);
        assert_eq!(result.runs[0].seed, 11);
        assert_eq!(result.runs[4].seed, 15);
    }

    #[test]
    fn batch_rejects_zero_runs() {
        let err = simulate_snowball_batch(convergent_options(), 0).expect_err("zero runs fail");
        assert!(matches!(err, SnowballError::InvalidRuns(0)));
    }

    #[test]
    fn wilson_interval_contains_estimate() {
        let interval = wilson_interval(7, 10);
        assert!(interval.lower_95 <= interval.estimate);
        assert!(interval.estimate <= interval.upper_95);
    }
}
