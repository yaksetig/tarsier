// Prove command entrypoints.

use miette::IntoDiagnostic;
use serde_json::json;

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine};
use tarsier_engine::result::{UnboundedFairLivenessResult, UnboundedSafetyResult};

use crate::commands::helpers::{
    parse_fairness_mode, parse_output_format, parse_proof_engine, parse_solver_choice,
    parse_soundness_mode, sandbox_read_source,
};
use crate::{
    render_prove_fair_round_text, render_prove_round_text, unbounded_fair_result_details,
    unbounded_fair_result_kind, unbounded_safety_result_details, unbounded_safety_result_kind,
    validate_cli_network_semantics_mode, write_json_artifact, OutputFormat,
};

use super::execution::{
    run_prove_fair_liveness_branch, run_prove_fair_portfolio, run_prove_fair_single,
    run_prove_safety_auto_strengthen, run_prove_safety_portfolio, run_prove_safety_single,
};
use super::helpers::detect_prove_auto_target;
use super::types::{
    ProveAutoTarget, ProveCommandArgs, ProveExecutionConfig, ProveFairCommandArgs,
    ProveFairRoundCommandArgs, ProveRoundCommandArgs,
};

pub(crate) fn run_prove_command(args: ProveCommandArgs) -> miette::Result<()> {
    let output_format = parse_output_format(&args.format)?;
    let source = sandbox_read_source(&args.file)?;
    let filename = args.file.display().to_string();
    let soundness_mode = parse_soundness_mode(&args.soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, args.cli_network_mode)?;

    let options = PipelineOptions {
        solver: parse_solver_choice(&args.solver)?,
        max_depth: args.k,
        timeout_secs: args.timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: parse_proof_engine(&args.engine)?,
    };
    let fairness = parse_fairness_mode(&args.fairness)?;
    let exec = ProveExecutionConfig {
        fairness,
        cert_out: args.cert_out,
        cegar_iters: args.cegar_iters,
        cegar_report_out: args.cegar_report_out,
        timeout: args.timeout,
        output_format,
    };
    let prove_target = detect_prove_auto_target(&source, &filename)?;

    if prove_target == ProveAutoTarget::FairLiveness {
        run_prove_fair_liveness_branch(&source, &filename, &options, args.portfolio, exec)?;
    } else if args.auto_strengthen {
        run_prove_safety_auto_strengthen(&source, &filename, &options, exec.output_format)?;
    } else if args.portfolio {
        run_prove_safety_portfolio(&source, &filename, &options, exec)?;
    } else {
        run_prove_safety_single(
            &source,
            &filename,
            &options,
            exec.cert_out,
            exec.cegar_iters,
            exec.cegar_report_out,
            exec.output_format,
        )?;
    }
    Ok(())
}

/// Handler for `tarsier prove-fair`.
pub(crate) fn run_prove_fair_command(args: ProveFairCommandArgs) -> miette::Result<()> {
    let source = sandbox_read_source(&args.file)?;
    let filename = args.file.display().to_string();
    let soundness_mode = parse_soundness_mode(&args.soundness)?;
    let output_format = parse_output_format(&args.format)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, args.cli_network_mode)?;

    let options = PipelineOptions {
        solver: parse_solver_choice(&args.solver)?,
        max_depth: args.k,
        timeout_secs: args.timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::Pdr,
    };
    let exec = ProveExecutionConfig {
        fairness: parse_fairness_mode(&args.fairness)?,
        cert_out: args.cert_out,
        cegar_iters: args.cegar_iters,
        cegar_report_out: args.cegar_report_out,
        timeout: args.timeout,
        output_format,
    };

    if args.portfolio {
        run_prove_fair_portfolio(&source, &filename, &options, exec)?;
    } else {
        run_prove_fair_single(&source, &filename, &options, exec)?;
    }
    Ok(())
}

/// Handler for `tarsier prove-round`.
pub(crate) fn run_prove_round_command(args: ProveRoundCommandArgs) -> miette::Result<()> {
    if args.round_vars.is_empty() {
        miette::bail!("Provide at least one round variable name with --round-vars.");
    }

    let source = sandbox_read_source(&args.file)?;
    let filename = args.file.display().to_string();
    let soundness_mode = parse_soundness_mode(&args.soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, args.cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&args.solver)?,
        max_depth: args.k,
        timeout_secs: args.timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: parse_proof_engine(&args.engine)?,
    };

    let proved = tarsier_engine::pipeline::prove_safety_with_round_abstraction(
        &source,
        &filename,
        &options,
        &args.round_vars,
    )
    .into_diagnostic()?;

    match parse_output_format(&args.format)? {
        OutputFormat::Text => {
            println!(
                "{}",
                render_prove_round_text(&filename, &proved.summary, &proved.result)
            );
        }
        OutputFormat::Json => {
            let value = json!({
                "schema_version": 1,
                "file": filename,
                "result": unbounded_safety_result_kind(&proved.result),
                "summary": {
                    "erased_vars": proved.summary.erased_vars,
                    "original_locations": proved.summary.original_locations,
                    "abstract_locations": proved.summary.abstract_locations,
                    "original_shared_vars": proved.summary.original_shared_vars,
                    "abstract_shared_vars": proved.summary.abstract_shared_vars,
                    "original_message_counters": proved.summary.original_message_counters,
                    "abstract_message_counters": proved.summary.abstract_message_counters,
                },
                "details": unbounded_safety_result_details(&proved.result),
                "output": format!("{}", proved.result),
                "soundness_note": match proved.result {
                    UnboundedSafetyResult::Safe { .. }
                    | UnboundedSafetyResult::ProbabilisticallySafe { .. } =>
                        "SAFE is sound for concrete unbounded-round behavior under this over-approximation.",
                    UnboundedSafetyResult::Unsafe { .. } =>
                        "UNSAFE may be spurious under over-approximation; confirm on concrete model.",
                    _ =>
                        "Inconclusive result; try larger k or different engine.",
                },
            });
            if let Some(path) = args.out {
                write_json_artifact(&path, &value)?;
                println!("Round abstraction report written to {}", path.display());
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).into_diagnostic()?
                );
            }
        }
    }
    Ok(())
}

/// Handler for `tarsier prove-fair-round`.
pub(crate) fn run_prove_fair_round_command(args: ProveFairRoundCommandArgs) -> miette::Result<()> {
    if args.round_vars.is_empty() {
        miette::bail!("Provide at least one round variable name with --round-vars.");
    }
    let source = sandbox_read_source(&args.file)?;
    let filename = args.file.display().to_string();
    let fairness = parse_fairness_mode(&args.fairness)?;
    let soundness_mode = parse_soundness_mode(&args.soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, args.cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&args.solver)?,
        max_depth: args.k,
        timeout_secs: args.timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::Pdr,
    };

    let proved = tarsier_engine::pipeline::prove_fair_liveness_with_round_abstraction(
        &source,
        &filename,
        &options,
        fairness,
        &args.round_vars,
    )
    .into_diagnostic()?;

    match parse_output_format(&args.format)? {
        OutputFormat::Text => {
            println!(
                "{}",
                render_prove_fair_round_text(&filename, &proved.summary, &proved.result)
            );
        }
        OutputFormat::Json => {
            let value = json!({
                "schema_version": 1,
                "file": filename,
                "result": unbounded_fair_result_kind(&proved.result),
                "summary": {
                    "erased_vars": proved.summary.erased_vars,
                    "original_locations": proved.summary.original_locations,
                    "abstract_locations": proved.summary.abstract_locations,
                    "original_shared_vars": proved.summary.original_shared_vars,
                    "abstract_shared_vars": proved.summary.abstract_shared_vars,
                    "original_message_counters": proved.summary.original_message_counters,
                    "abstract_message_counters": proved.summary.abstract_message_counters,
                },
                "details": unbounded_fair_result_details(&proved.result),
                "output": format!("{}", proved.result),
                "soundness_note": match proved.result {
                    UnboundedFairLivenessResult::LiveProved { .. } =>
                        "LIVE_PROVED is sound for concrete unbounded-round behavior under this over-approximation.",
                    UnboundedFairLivenessResult::FairCycleFound { .. } =>
                        "FAIR_CYCLE_FOUND may be spurious under over-approximation; confirm on concrete model.",
                    _ =>
                        "Inconclusive result; try larger k or different fairness settings.",
                },
            });
            if let Some(path) = args.out {
                write_json_artifact(&path, &value)?;
                println!(
                    "Round abstraction fair-liveness report written to {}",
                    path.display()
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).into_diagnostic()?
                );
            }
        }
    }
    Ok(())
}
