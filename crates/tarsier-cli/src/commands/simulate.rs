//! CLI command handler for finite protocol simulation.

use std::fs;
use std::path::PathBuf;

use clap::Args;
use miette::IntoDiagnostic;
use serde_json::json;
use tarsier_sim::avalanche::{
    ByzantineStrategy, DecisionRule, QuantileStats, SnowballBatchResult, SnowballOptions,
    SnowballResult, SnowballStopReason, WilsonInterval,
};
use tarsier_sim::hotstuff::{
    HotStuffByzantineStrategy, HotStuffOptions, HotStuffProposalPattern, HotStuffResult,
};
use tarsier_sim::network::NetworkTraceEvent;
use tarsier_sim::phoenixx::{
    PhoenixxBatchResult, PhoenixxByzantineStrategy, PhoenixxOptions, PhoenixxProposalPattern,
    PhoenixxResult, PhoenixxValue,
};
use tarsier_sim::{Scheduler, SimulationOptions};

#[derive(Args)]
pub(crate) struct SimulateCommandArgs {
    /// Path to the .trs protocol file
    pub(crate) file: PathBuf,

    /// Concrete parameter binding, e.g. --param n=4 --param t=1
    #[arg(long = "param", value_delimiter = ',')]
    pub(crate) params: Vec<String>,

    /// Initial message/shared-counter seed, e.g. --seed-message Init=1
    #[arg(long = "seed-message", value_delimiter = ',')]
    pub(crate) seed_messages: Vec<String>,

    /// Maximum number of rule firings
    #[arg(long, default_value_t = 50)]
    pub(crate) steps: usize,

    /// Scheduler policy: random | first
    #[arg(long, default_value = "random")]
    pub(crate) scheduler: String,

    /// Seed used by the random scheduler
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,

    /// Output format: text | json
    #[arg(long, default_value = "text")]
    pub(crate) format: String,

    /// Optional path to write the runtime trace JSON
    #[arg(long)]
    pub(crate) trace_out: Option<PathBuf>,

    /// Optional path to write the counter trace JSON
    #[arg(long)]
    pub(crate) counter_trace_out: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SimulateAvalancheCommandArgs {
    /// Total validators, including Byzantine validators
    #[arg(long)]
    pub(crate) n: usize,

    /// Byzantine validators
    #[arg(long, default_value_t = 0)]
    pub(crate) byzantine: usize,

    /// Sample size k
    #[arg(long = "k")]
    pub(crate) sample_size: usize,

    /// Successful poll threshold alpha
    #[arg(long)]
    pub(crate) alpha: usize,

    /// Decision threshold beta
    #[arg(long)]
    pub(crate) beta: usize,

    /// Maximum polling rounds
    #[arg(long, default_value_t = 100)]
    pub(crate) rounds: usize,

    /// Honest validators initially preferring A
    #[arg(long = "initial-a")]
    pub(crate) initial_a: usize,

    /// Polling order policy: random | first
    #[arg(long, default_value = "random")]
    pub(crate) scheduler: String,

    /// Byzantine response policy: oppose | random | a | b
    #[arg(long, default_value = "oppose")]
    pub(crate) byzantine_strategy: String,

    /// Decision rule: confidence | consecutive
    #[arg(long, default_value = "confidence")]
    pub(crate) decision_rule: String,

    /// Seed used for peer sampling and randomized scheduling
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,

    /// Independent seeds to run for Monte Carlo statistics
    #[arg(long, default_value_t = 1)]
    pub(crate) runs: usize,

    /// Output format: text | json
    #[arg(long, default_value = "text")]
    pub(crate) format: String,

    /// Optional output path
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SimulatePhoenixxCommandArgs {
    /// Total validators
    #[arg(long)]
    pub(crate) n: usize,

    /// Byzantine validators
    #[arg(long, default_value_t = 0)]
    pub(crate) byzantine: usize,

    /// Random endorser committee size
    #[arg(long = "committee-size")]
    pub(crate) committee_size: usize,

    /// Override committee Byzantine bound; default derives b_max from epsilon
    #[arg(long = "committee-bound")]
    pub(crate) committee_bound: Option<usize>,

    /// Committee analysis failure probability
    #[arg(long, default_value_t = 1e-14)]
    pub(crate) epsilon: f64,

    /// Override NQC threshold; default is 2*byzantine+1
    #[arg(long = "nqc-threshold")]
    pub(crate) nqc_threshold: Option<usize>,

    /// Override EQC threshold; default is committee_bound+1
    #[arg(long = "eqc-threshold")]
    pub(crate) eqc_threshold: Option<usize>,

    /// Honest validators initially confirming A
    #[arg(long = "initial-a")]
    pub(crate) initial_a: usize,

    /// Byzantine policy: silent | a | b | equivocate
    #[arg(long, default_value = "silent")]
    pub(crate) byzantine_strategy: String,

    /// Seed used for committee sampling
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,

    /// Maximum protocol rounds to simulate
    #[arg(long, default_value_t = 1)]
    pub(crate) rounds: usize,

    /// Whole-round certificate delivery delay for view-change parent selection
    #[arg(long = "network-delay", default_value_t = 0)]
    pub(crate) network_delay: usize,

    /// Proposal schedule: view-change | a | b | alternate | random
    #[arg(long = "proposal-pattern", default_value = "view-change")]
    pub(crate) proposal_pattern: String,

    /// Independent committee draws to run
    #[arg(long, default_value_t = 1)]
    pub(crate) runs: usize,

    /// Output format: text | json
    #[arg(long, default_value = "text")]
    pub(crate) format: String,

    /// Optional output path
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SimulateHotstuffCommandArgs {
    /// Total validators
    #[arg(long)]
    pub(crate) n: usize,

    /// Byzantine validators
    #[arg(long, default_value_t = 0)]
    pub(crate) byzantine: usize,

    /// Maximum views to simulate
    #[arg(long, default_value_t = 3)]
    pub(crate) views: usize,

    /// Override quorum threshold; default is 2*byzantine+1
    #[arg(long = "quorum-threshold")]
    pub(crate) quorum_threshold: Option<usize>,

    /// Whole-view QC delivery delay
    #[arg(long = "network-delay", default_value_t = 0)]
    pub(crate) network_delay: usize,

    /// Proposal schedule: chained | fork-at-two | alternate
    #[arg(long = "proposal-pattern", default_value = "chained")]
    pub(crate) proposal_pattern: String,

    /// Byzantine policy: silent | vote
    #[arg(long, default_value = "silent")]
    pub(crate) byzantine_strategy: String,

    /// Seed used by the network scheduler
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,

    /// Output format: text | json
    #[arg(long, default_value = "text")]
    pub(crate) format: String,

    /// Optional output path
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

pub(crate) fn run_simulate_command(args: SimulateCommandArgs) -> miette::Result<()> {
    let source = fs::read_to_string(&args.file).into_diagnostic()?;
    let filename = args.file.display().to_string();
    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    let scheduler = parse_scheduler(&args.scheduler)?;
    let params = parse_name_value_bindings("--param", &args.params)?;
    let seed_messages = parse_name_value_bindings("--seed-message", &args.seed_messages)?;
    let result = tarsier_sim::simulate(
        &ta,
        &params,
        SimulationOptions {
            max_steps: args.steps,
            seed: args.seed,
            scheduler,
            initial_shared: seed_messages,
        },
    )
    .map_err(|e| miette::miette!("Simulation failed: {e}"))?;

    if let Some(path) = args.trace_out {
        let json = serde_json::to_string_pretty(&result.runtime_trace).into_diagnostic()?;
        fs::write(path, json).into_diagnostic()?;
    }
    if let Some(path) = args.counter_trace_out {
        let json = serde_json::to_string_pretty(&result.counter_trace).into_diagnostic()?;
        fs::write(path, json).into_diagnostic()?;
    }

    match args.format.as_str() {
        "json" => {
            let payload = json!({
                "schema_version": 1,
                "summary": result.summary,
                "steps": result.steps,
                "warnings": result.warnings,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).into_diagnostic()?
            );
        }
        "text" => {
            print_text_report(&result);
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }

    Ok(())
}

pub(crate) fn run_simulate_avalanche_command(
    args: SimulateAvalancheCommandArgs,
) -> miette::Result<()> {
    let options = SnowballOptions {
        n: args.n,
        byzantine: args.byzantine,
        sample_size: args.sample_size,
        alpha: args.alpha,
        beta: args.beta,
        max_rounds: args.rounds,
        seed: args.seed,
        initial_honest_a: args.initial_a,
        scheduler: parse_scheduler(&args.scheduler)?,
        byzantine_strategy: parse_byzantine_strategy(&args.byzantine_strategy)?,
        decision_rule: parse_decision_rule(&args.decision_rule)?,
    };

    if args.runs == 0 {
        return Err(miette::miette!("--runs must be at least 1."));
    }
    if args.runs > 1 {
        let result = tarsier_sim::avalanche::simulate_snowball_batch(options, args.runs)
            .map_err(|e| miette::miette!("Avalanche batch simulation failed: {e}"))?;
        return write_avalanche_batch_result(&result, &args.format, args.out);
    }

    let result = tarsier_sim::avalanche::simulate_snowball(options)
        .map_err(|e| miette::miette!("Avalanche simulation failed: {e}"))?;

    match args.format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&result).into_diagnostic()?;
            if let Some(path) = args.out {
                fs::write(path, json).into_diagnostic()?;
            } else {
                println!("{json}");
            }
        }
        "text" => {
            let report = render_avalanche_text_report(&result);
            if let Some(path) = args.out {
                fs::write(path, report).into_diagnostic()?;
            } else {
                print!("{report}");
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }

    Ok(())
}

fn write_avalanche_batch_result(
    result: &SnowballBatchResult,
    format: &str,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(result).into_diagnostic()?;
            if let Some(path) = out {
                fs::write(path, json).into_diagnostic()?;
            } else {
                println!("{json}");
            }
        }
        "text" => {
            let report = render_avalanche_batch_text_report(result);
            if let Some(path) = out {
                fs::write(path, report).into_diagnostic()?;
            } else {
                print!("{report}");
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }

    Ok(())
}

pub(crate) fn run_simulate_phoenixx_command(
    args: SimulatePhoenixxCommandArgs,
) -> miette::Result<()> {
    if args.runs == 0 {
        return Err(miette::miette!("--runs must be at least 1."));
    }

    let analyzed = tarsier_sim::phoenixx::analyze_phoenixx_committee(
        args.n,
        args.byzantine,
        args.committee_size,
        args.epsilon,
    )
    .map_err(|e| miette::miette!("Phoenixx committee analysis failed: {e}"))?;
    let committee_bound = args.committee_bound.unwrap_or(analyzed.analyzed_b_max);
    let nqc_threshold = args.nqc_threshold.unwrap_or(2 * args.byzantine + 1);
    let eqc_threshold = args.eqc_threshold.unwrap_or(committee_bound + 1);

    let options = PhoenixxOptions {
        n: args.n,
        byzantine: args.byzantine,
        committee_size: args.committee_size,
        committee_bound,
        epsilon: args.epsilon,
        nqc_threshold,
        eqc_threshold,
        initial_honest_a: args.initial_a,
        seed: args.seed,
        byzantine_strategy: parse_phoenixx_byzantine_strategy(&args.byzantine_strategy)?,
        rounds: args.rounds,
        network_delay_rounds: args.network_delay,
        proposal_pattern: parse_phoenixx_proposal_pattern(&args.proposal_pattern)?,
    };

    if args.runs > 1 {
        let result = tarsier_sim::phoenixx::simulate_phoenixx_batch(options, args.runs)
            .map_err(|e| miette::miette!("Phoenixx batch simulation failed: {e}"))?;
        return write_phoenixx_batch_result(&result, &args.format, args.out);
    }

    let result = tarsier_sim::phoenixx::simulate_phoenixx(options)
        .map_err(|e| miette::miette!("Phoenixx simulation failed: {e}"))?;
    write_phoenixx_result(&result, &args.format, args.out)
}

pub(crate) fn run_simulate_hotstuff_command(
    args: SimulateHotstuffCommandArgs,
) -> miette::Result<()> {
    let quorum_threshold = args.quorum_threshold.unwrap_or(2 * args.byzantine + 1);
    let options = HotStuffOptions {
        n: args.n,
        byzantine: args.byzantine,
        views: args.views,
        quorum_threshold,
        network_delay: args.network_delay,
        seed: args.seed,
        proposal_pattern: parse_hotstuff_proposal_pattern(&args.proposal_pattern)?,
        byzantine_strategy: parse_hotstuff_byzantine_strategy(&args.byzantine_strategy)?,
    };
    let result = tarsier_sim::hotstuff::simulate_hotstuff(options)
        .map_err(|e| miette::miette!("HotStuff simulation failed: {e}"))?;
    write_hotstuff_result(&result, &args.format, args.out)
}

fn write_hotstuff_result(
    result: &HotStuffResult,
    format: &str,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(result).into_diagnostic()?;
            if let Some(path) = out {
                fs::write(path, json).into_diagnostic()?;
            } else {
                println!("{json}");
            }
        }
        "text" => {
            let report = render_hotstuff_text_report(result);
            if let Some(path) = out {
                fs::write(path, report).into_diagnostic()?;
            } else {
                print!("{report}");
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }
    Ok(())
}

fn write_phoenixx_result(
    result: &PhoenixxResult,
    format: &str,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(result).into_diagnostic()?;
            if let Some(path) = out {
                fs::write(path, json).into_diagnostic()?;
            } else {
                println!("{json}");
            }
        }
        "text" => {
            let report = render_phoenixx_text_report(result);
            if let Some(path) = out {
                fs::write(path, report).into_diagnostic()?;
            } else {
                print!("{report}");
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }
    Ok(())
}

fn write_phoenixx_batch_result(
    result: &PhoenixxBatchResult,
    format: &str,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(result).into_diagnostic()?;
            if let Some(path) = out {
                fs::write(path, json).into_diagnostic()?;
            } else {
                println!("{json}");
            }
        }
        "text" => {
            let report = render_phoenixx_batch_text_report(result);
            if let Some(path) = out {
                fs::write(path, report).into_diagnostic()?;
            } else {
                print!("{report}");
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown output format '{other}'. Expected text or json."
            ));
        }
    }
    Ok(())
}

fn parse_scheduler(raw: &str) -> miette::Result<Scheduler> {
    match raw {
        "random" => Ok(Scheduler::Random),
        "first" => Ok(Scheduler::First),
        other => Err(miette::miette!(
            "Unknown scheduler '{other}'. Expected random or first."
        )),
    }
}

fn parse_byzantine_strategy(raw: &str) -> miette::Result<ByzantineStrategy> {
    match raw {
        "a" | "static-a" => Ok(ByzantineStrategy::StaticA),
        "b" | "static-b" => Ok(ByzantineStrategy::StaticB),
        "oppose" | "opposite" | "oppose-requester" => Ok(ByzantineStrategy::OpposeRequester),
        "random" => Ok(ByzantineStrategy::Random),
        other => Err(miette::miette!(
            "Unknown Byzantine strategy '{other}'. Expected oppose, random, a, or b."
        )),
    }
}

fn parse_decision_rule(raw: &str) -> miette::Result<DecisionRule> {
    match raw {
        "confidence" | "snowball" => Ok(DecisionRule::Confidence),
        "consecutive" | "snowflake" => Ok(DecisionRule::Consecutive),
        other => Err(miette::miette!(
            "Unknown decision rule '{other}'. Expected confidence or consecutive."
        )),
    }
}

fn parse_phoenixx_byzantine_strategy(raw: &str) -> miette::Result<PhoenixxByzantineStrategy> {
    match raw {
        "silent" => Ok(PhoenixxByzantineStrategy::Silent),
        "a" | "static-a" => Ok(PhoenixxByzantineStrategy::StaticA),
        "b" | "static-b" => Ok(PhoenixxByzantineStrategy::StaticB),
        "equivocate" | "both" => Ok(PhoenixxByzantineStrategy::Equivocate),
        other => Err(miette::miette!(
            "Unknown Phoenixx Byzantine strategy '{other}'. Expected silent, a, b, or equivocate."
        )),
    }
}

fn parse_phoenixx_proposal_pattern(raw: &str) -> miette::Result<PhoenixxProposalPattern> {
    match raw {
        "a" | "static-a" => Ok(PhoenixxProposalPattern::StaticA),
        "b" | "static-b" => Ok(PhoenixxProposalPattern::StaticB),
        "alternate" | "alternating" => Ok(PhoenixxProposalPattern::Alternate),
        "random" => Ok(PhoenixxProposalPattern::Random),
        "view-change" | "viewchange" | "locked" => Ok(PhoenixxProposalPattern::ViewChange),
        other => Err(miette::miette!(
            "Unknown Phoenixx proposal pattern '{other}'. Expected view-change, a, b, alternate, or random."
        )),
    }
}

fn parse_hotstuff_proposal_pattern(raw: &str) -> miette::Result<HotStuffProposalPattern> {
    match raw {
        "chained" | "chain" => Ok(HotStuffProposalPattern::Chained),
        "fork-at-two" | "fork" => Ok(HotStuffProposalPattern::ForkAtTwo),
        "alternate" | "alternate-values" => Ok(HotStuffProposalPattern::AlternateValues),
        other => Err(miette::miette!(
            "Unknown HotStuff proposal pattern '{other}'. Expected chained, fork-at-two, or alternate."
        )),
    }
}

fn parse_hotstuff_byzantine_strategy(raw: &str) -> miette::Result<HotStuffByzantineStrategy> {
    match raw {
        "silent" => Ok(HotStuffByzantineStrategy::Silent),
        "vote" | "honest-vote" => Ok(HotStuffByzantineStrategy::Vote),
        other => Err(miette::miette!(
            "Unknown HotStuff Byzantine strategy '{other}'. Expected silent or vote."
        )),
    }
}

fn parse_name_value_bindings(flag: &str, raw: &[String]) -> miette::Result<Vec<(String, i64)>> {
    raw.iter()
        .map(|item| {
            let (name, value) = item
                .split_once('=')
                .ok_or_else(|| miette::miette!("Invalid {flag} '{item}'. Expected name=value."))?;
            if name.trim().is_empty() {
                return Err(miette::miette!("Invalid {flag} '{item}': empty name."));
            }
            let value = value
                .trim()
                .parse::<i64>()
                .map_err(|e| miette::miette!("Invalid value for {flag} '{item}': {e}"))?;
            Ok((name.trim().to_string(), value))
        })
        .collect()
}

fn render_avalanche_text_report(result: &SnowballResult) -> String {
    let mut out = String::new();
    let status = match result.summary.stopped_reason {
        SnowballStopReason::AllHonestDecided => "all_honest_decided",
        SnowballStopReason::AgreementViolation => "agreement_violation",
        SnowballStopReason::MaxRounds => "max_rounds",
    };

    out.push_str("Avalanche/Snowball simulation complete\n");
    out.push_str(&format!("  stopped: {status}\n"));
    out.push_str(&format!(
        "  rounds: {}  polls: {}\n",
        result.summary.rounds_executed, result.summary.polls_executed
    ));
    out.push_str(&format!(
        "  decided: A={} B={} undecided={}\n",
        result.summary.honest_decided_a,
        result.summary.honest_decided_b,
        result.summary.honest_undecided
    ));
    out.push_str(&format!(
        "  final preference: A={} B={}\n",
        result.summary.final_honest_preference_a, result.summary.final_honest_preference_b
    ));
    if let Some(first) = result.summary.first_decision_round {
        out.push_str(&format!(
            "  decision rounds: first={} last={}\n",
            first,
            result.summary.last_decision_round.unwrap_or(first)
        ));
    }
    out.push_str(&format!(
        "  agreement violation: {}\n",
        result.summary.agreement_violation
    ));

    if !result.steps.is_empty() {
        out.push_str("  last polls:\n");
        let start = result.steps.len().saturating_sub(10);
        for step in &result.steps[start..] {
            let success = step
                .successful_value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into());
            out.push_str(&format!(
                "    r{} v{} {}->{} responses(A={},B={},byz={}) success={} conf(A={},B={}) decided={}\n",
                step.round,
                step.validator_id,
                step.old_preference,
                step.new_preference,
                step.responses_a,
                step.responses_b,
                step.byzantine_responses,
                success,
                step.confidence_a,
                step.confidence_b,
                step.decided
            ));
        }
    }

    if !result.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for warning in &result.warnings {
            out.push_str(&format!("    {warning}\n"));
        }
    }
    out
}

fn render_avalanche_batch_text_report(result: &SnowballBatchResult) -> String {
    let mut out = String::new();
    let summary = &result.summary;

    out.push_str("Avalanche/Snowball batch simulation complete\n");
    out.push_str(&format!("  runs: {}\n", summary.runs));
    out.push_str(&format!(
        "  converged: {}/{} ({})  95% CI [{}]\n",
        summary.converged,
        summary.runs,
        format_percent(summary.convergence_rate),
        format_interval(&summary.convergence_95)
    ));
    out.push_str(&format!(
        "  agreement violations: {}/{} ({})  95% CI [{}]\n",
        summary.agreement_violations,
        summary.runs,
        format_percent(summary.agreement_violation_rate),
        format_interval(&summary.agreement_violation_95)
    ));
    out.push_str(&format!(
        "  outcomes: all_A={} all_B={} mixed_or_partial={} max_rounds={}\n",
        summary.all_a, summary.all_b, summary.mixed_or_partial, summary.max_rounds_reached
    ));

    if let Some(stats) = &summary.finality_rounds {
        out.push_str(&format!("  finality rounds: {}\n", format_quantiles(stats)));
    } else {
        out.push_str("  finality rounds: no converged runs\n");
    }
    if let Some(stats) = &summary.finality_polls {
        out.push_str(&format!("  finality polls: {}\n", format_quantiles(stats)));
    }

    if !result.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for warning in &result.warnings {
            out.push_str(&format!("    {warning}\n"));
        }
    }

    out
}

fn render_hotstuff_text_report(result: &HotStuffResult) -> String {
    let mut out = String::new();
    let deliveries = result
        .network_trace
        .iter()
        .filter(|event| matches!(event, NetworkTraceEvent::Deliver { .. }))
        .count();

    out.push_str("HotStuff-style simulation complete\n");
    out.push_str(&format!(
        "  views: executed={} configured={} network_delay={}\n",
        result.summary.views_executed, result.options.views, result.options.network_delay
    ));
    out.push_str(&format!(
        "  network trace: deliveries={} events={}\n",
        deliveries,
        result.network_trace.len()
    ));
    out.push_str(&format!(
        "  QCs: formed={} highest_qc_view={}\n",
        result.summary.qcs_formed, result.summary.highest_qc_view
    ));
    out.push_str(&format!(
        "  commits: total={} A={} B={} safety_violation={}\n",
        result.summary.committed_blocks,
        result.summary.committed_a,
        result.summary.committed_b,
        result.summary.safety_violation
    ));
    out.push_str(&format!(
        "  final locks: A={} B={} unlocked={} highest_view={}\n",
        result.summary.final_locks.locked_a,
        result.summary.final_locks.locked_b,
        result.summary.final_locks.unlocked,
        result.summary.final_locks.highest_lock_view
    ));
    if !result.views.is_empty() {
        out.push_str("  views detail:\n");
        let start = result.views.len().saturating_sub(6);
        for view in &result.views[start..] {
            let committed = view
                .committed_value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".into());
            out.push_str(&format!(
                "    v{} leader={} block={} value={} parent={} parent_qc={} votes={} qc={} commit={}\n",
                view.view,
                view.leader,
                view.block.id,
                view.block.value,
                view.block.parent,
                view.block.parent_qc_view,
                view.votes,
                view.qc_formed,
                committed
            ));
        }
    }
    if !result.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for warning in &result.warnings {
            out.push_str(&format!("    {warning}\n"));
        }
    }
    out
}

fn format_percent(rate: f64) -> String {
    format!("{:.2}%", rate * 100.0)
}

fn format_interval(interval: &WilsonInterval) -> String {
    format!(
        "{}..{}",
        format_percent(interval.lower_95),
        format_percent(interval.upper_95)
    )
}

fn format_quantiles(stats: &QuantileStats) -> String {
    format!(
        "count={} mean={:.2} min={} p50={} p95={} p99={} max={}",
        stats.count, stats.mean, stats.min, stats.p50, stats.p95, stats.p99, stats.max
    )
}

fn render_phoenixx_text_report(result: &PhoenixxResult) -> String {
    let mut out = String::new();
    out.push_str("Phoenixx committee simulation complete\n");
    out.push_str(&format!(
        "  rounds: executed={} configured={} network_delay={}\n",
        result.summary.rounds_executed, result.options.rounds, result.options.network_delay_rounds
    ));
    let deliveries = result
        .network_trace
        .iter()
        .filter(|event| matches!(event, NetworkTraceEvent::Deliver { .. }))
        .count();
    out.push_str(&format!(
        "  network trace: deliveries={} events={}\n",
        deliveries,
        result.network_trace.len()
    ));
    out.push_str(&format!(
        "  committee: size={} byzantine={} bound={} analyzed_b_max={} exceeds_bound={}\n",
        result.options.committee_size,
        result.committee.byzantine_count,
        result.options.committee_bound,
        result.committee_bound.analyzed_b_max,
        result.committee.exceeds_bound
    ));
    out.push_str(&format!(
        "  committee analysis: expected_byzantine={:.2} tail_probability={:.3e} honest_guaranteed={}\n",
        result.committee_bound.expected_byzantine,
        result.committee_bound.tail_probability,
        result.committee_bound.honest_guaranteed
    ));
    if result.rounds.len() > 1 {
        out.push_str(&format!(
            "  formed(any): NQC(A={},B={}) EQC(A={},B={})\n",
            result.summary.nqc_a_formed,
            result.summary.nqc_b_formed,
            result.summary.eqc_a_formed,
            result.summary.eqc_b_formed
        ));
        out.push_str(&format!(
            "  last NQC: A={} ({}/{}) B={} ({}/{})\n",
            result.nqc_a.formed,
            result.nqc_a.total_signers,
            result.nqc_a.threshold,
            result.nqc_b.formed,
            result.nqc_b.total_signers,
            result.nqc_b.threshold
        ));
        out.push_str(&format!(
            "  last EQC: A={} ({}/{}, honest={}, backed={}) B={} ({}/{}, honest={}, backed={})\n",
            result.eqc_a.certificate.formed,
            result.eqc_a.certificate.total_signers,
            result.eqc_a.certificate.threshold,
            result.eqc_a.certificate.honest_signers,
            result.eqc_a.honest_nqc_backed,
            result.eqc_b.certificate.formed,
            result.eqc_b.certificate.total_signers,
            result.eqc_b.certificate.threshold,
            result.eqc_b.certificate.honest_signers,
            result.eqc_b.honest_nqc_backed
        ));
    } else {
        out.push_str(&format!(
            "  NQC: A={} ({}/{}) B={} ({}/{})\n",
            result.nqc_a.formed,
            result.nqc_a.total_signers,
            result.nqc_a.threshold,
            result.nqc_b.formed,
            result.nqc_b.total_signers,
            result.nqc_b.threshold
        ));
        out.push_str(&format!(
            "  EQC: A={} ({}/{}, honest={}, backed={}) B={} ({}/{}, honest={}, backed={})\n",
            result.eqc_a.certificate.formed,
            result.eqc_a.certificate.total_signers,
            result.eqc_a.certificate.threshold,
            result.eqc_a.certificate.honest_signers,
            result.eqc_a.honest_nqc_backed,
            result.eqc_b.certificate.formed,
            result.eqc_b.certificate.total_signers,
            result.eqc_b.certificate.threshold,
            result.eqc_b.certificate.honest_signers,
            result.eqc_b.honest_nqc_backed
        ));
    }
    out.push_str(&format!(
        "  decided: {}\n",
        format_phoenixx_value(result.summary.decided_value)
    ));
    out.push_str(&format!(
        "  final locks: A={} B={} unlocked={} highest_round={}\n",
        result.summary.final_locks.locked_a,
        result.summary.final_locks.locked_b,
        result.summary.final_locks.unlocked,
        result.summary.final_locks.highest_lock_round
    ));
    out.push_str(&format!(
        "  agreement violation: {}\n",
        result.summary.agreement_violation
    ));
    out.push_str(&format!(
        "  EQC without honest NQC provenance: {}\n",
        result.summary.eqc_without_honest_nqc
    ));
    if result.rounds.len() > 1 {
        out.push_str("  rounds detail:\n");
        let start = result.rounds.len().saturating_sub(5);
        for round in &result.rounds[start..] {
            out.push_str(&format!(
                "    r{} proposal={} parent={} delivered={} NQC(A={},B={}) EQC(A={},B={}) locks(A={},B={},unlocked={})\n",
                round.round,
                round.proposal,
                round.parent_round,
                round.delivered_certificate_round,
                round.nqc_a.formed,
                round.nqc_b.formed,
                round.eqc_a.certificate.formed,
                round.eqc_b.certificate.formed,
                round.locks.locked_a,
                round.locks.locked_b,
                round.locks.unlocked
            ));
        }
    }
    if !result.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for warning in &result.warnings {
            out.push_str(&format!("    {warning}\n"));
        }
    }
    out
}

fn render_phoenixx_batch_text_report(result: &PhoenixxBatchResult) -> String {
    let mut out = String::new();
    let summary = &result.summary;
    out.push_str("Phoenixx committee batch simulation complete\n");
    out.push_str(&format!("  runs: {}\n", summary.runs));
    out.push_str(&format!(
        "  outcomes: decided_A={} decided_B={} undecided_or_conflicted={}\n",
        summary.decided_a, summary.decided_b, summary.undecided_or_conflicted
    ));
    out.push_str(&format!(
        "  committee bound violations: {}/{} ({})\n",
        summary.committee_bound_violations,
        summary.runs,
        format_percent(summary.committee_bound_violation_rate)
    ));
    out.push_str(&format!(
        "  agreement violations: {}/{} ({})\n",
        summary.agreement_violations,
        summary.runs,
        format_percent(summary.agreement_violation_rate)
    ));
    out.push_str(&format!(
        "  EQC without honest NQC provenance: {}/{} ({})\n",
        summary.eqc_without_honest_nqc,
        summary.runs,
        format_percent(summary.eqc_without_honest_nqc_rate)
    ));
    out.push_str(&format!(
        "  mean rounds executed: {:.2}\n",
        summary.mean_rounds_executed
    ));
    out.push_str(&format!(
        "  analyzed committee bound: b_max={} expected_byzantine={:.2} tail_probability={:.3e}\n",
        result.committee_bound.analyzed_b_max,
        result.committee_bound.expected_byzantine,
        result.committee_bound.tail_probability
    ));
    if !result.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for warning in &result.warnings {
            out.push_str(&format!("    {warning}\n"));
        }
    }
    out
}

fn format_phoenixx_value(value: Option<PhoenixxValue>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".into())
}

fn print_text_report(result: &tarsier_sim::SimulationResult) {
    println!("Simulation complete");
    println!("  steps: {}", result.summary.steps_executed);
    println!("  stopped: {:?}", result.summary.stopped_reason);

    if !result.summary.final_params.is_empty() {
        println!("  params:");
        for (name, value) in &result.summary.final_params {
            println!("    {name} = {value}");
        }
    }
    if !result.summary.final_location_counts.is_empty() {
        println!("  final locations:");
        for (name, count) in &result.summary.final_location_counts {
            println!("    {name}: {count}");
        }
    }
    if !result.summary.final_shared_vars.is_empty() {
        println!("  shared vars:");
        for (name, value) in &result.summary.final_shared_vars {
            println!("    {name}: {value}");
        }
    }
    if !result.summary.final_clocks.is_empty() {
        println!("  clocks:");
        for (name, value) in &result.summary.final_clocks {
            println!("    {name}: {value}");
        }
    }
    if !result.steps.is_empty() {
        println!("  trace:");
        for step in &result.steps {
            println!(
                "    {:>3}: p{} r{} {} -> {} (enabled={})",
                step.step,
                step.process_id,
                step.rule_id,
                step.from_location,
                step.to_location,
                step.enabled_rules_before
            );
        }
    }
    if !result.warnings.is_empty() {
        println!("  warnings:");
        for warning in &result.warnings {
            println!("    {warning}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_param_bindings_accepts_name_value_pairs() {
        let parsed = parse_name_value_bindings("--param", &["n=4".into(), "t=1".into()]).unwrap();
        assert_eq!(parsed, vec![("n".into(), 4), ("t".into(), 1)]);
    }

    #[test]
    fn parse_param_bindings_rejects_malformed_items() {
        assert!(parse_name_value_bindings("--param", &["n".into()]).is_err());
        assert!(parse_name_value_bindings("--param", &["=4".into()]).is_err());
        assert!(parse_name_value_bindings("--param", &["n=x".into()]).is_err());
    }

    #[test]
    fn parses_avalanche_strategy_aliases() {
        assert_eq!(
            parse_byzantine_strategy("oppose").unwrap(),
            ByzantineStrategy::OpposeRequester
        );
        assert_eq!(
            parse_byzantine_strategy("a").unwrap(),
            ByzantineStrategy::StaticA
        );
        assert_eq!(
            parse_decision_rule("snowflake").unwrap(),
            DecisionRule::Consecutive
        );
        assert_eq!(
            parse_phoenixx_byzantine_strategy("both").unwrap(),
            PhoenixxByzantineStrategy::Equivocate
        );
        assert_eq!(
            parse_phoenixx_proposal_pattern("view-change").unwrap(),
            PhoenixxProposalPattern::ViewChange
        );
        assert_eq!(
            parse_phoenixx_proposal_pattern("alternating").unwrap(),
            PhoenixxProposalPattern::Alternate
        );
        assert_eq!(
            parse_hotstuff_proposal_pattern("fork").unwrap(),
            HotStuffProposalPattern::ForkAtTwo
        );
        assert_eq!(
            parse_hotstuff_byzantine_strategy("vote").unwrap(),
            HotStuffByzantineStrategy::Vote
        );
    }

    #[test]
    fn simulate_avalanche_rejects_zero_batch_runs() {
        let err = run_simulate_avalanche_command(SimulateAvalancheCommandArgs {
            n: 10,
            byzantine: 0,
            sample_size: 5,
            alpha: 3,
            beta: 2,
            rounds: 10,
            initial_a: 10,
            scheduler: "random".into(),
            byzantine_strategy: "oppose".into(),
            decision_rule: "confidence".into(),
            seed: 0,
            runs: 0,
            format: "text".into(),
            out: None,
        })
        .expect_err("zero runs should fail");
        assert!(err.to_string().contains("--runs must be at least 1"));
    }
}
