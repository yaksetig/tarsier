use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde_json::json;

use tarsier_engine::pipeline::{
    take_run_diagnostics, PipelineOptions, PipelineRunDiagnostics, ProofEngine, SolverChoice,
};
use tarsier_engine::result::{CegarAuditReport, FairLivenessResult};

use crate::commands::helpers::{
    make_options, parse_fairness_mode, parse_output_format, parse_solver_choice,
    parse_soundness_mode, sandbox_read_source,
};
use crate::{
    network_faithfulness_section, render_fallback_summary, render_optimization_summary,
    render_phase_profile_summary, run_diagnostics_details, validate_cli_network_semantics_mode,
    CliNetworkSemanticsMode, OutputFormat,
};

use super::{
    apply_round_upper_bound, cegar_report_details, detect_round_sweep_cutoff,
    fair_liveness_result_details, fair_liveness_result_kind, liveness_result_details,
    liveness_result_kind, merge_portfolio_fair_liveness_results, merge_portfolio_verify_reports,
    render_round_sweep_text, verification_result_details, verification_result_kind,
    write_json_artifact, FairLivenessCommandArgs, LivenessCommandArgs, RoundSweepCommandArgs,
    RoundSweepPoint, RoundSweepReport, VerifyCommandArgs,
};

pub(crate) fn run_verify_command(args: VerifyCommandArgs) -> miette::Result<()> {
    let VerifyCommandArgs {
        file,
        solver,
        depth,
        timeout,
        soundness,
        dump_smt,
        cegar_iters,
        cegar_report_out,
        portfolio,
        format,
        cli_network_mode,
    } = args;
    let output_format = parse_output_format(&format)?;
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let network_faithfulness =
        network_faithfulness_section(&source, &filename, cli_network_mode, soundness_mode);

    let options = PipelineOptions {
        solver: parse_solver_choice(&solver)?,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    if portfolio {
        let mut z3_options = options.clone();
        z3_options.solver = SolverChoice::Z3;
        let mut cvc5_options = options.clone();
        cvc5_options.solver = SolverChoice::Cvc5;

        let src_z3 = source.clone();
        let file_z3 = filename.clone();
        let handle_z3 = std::thread::spawn(move || {
            let result = tarsier_engine::pipeline::verify_with_cegar_report(
                &src_z3,
                &file_z3,
                &z3_options,
                cegar_iters,
            )
            .map_err(|e| e.to_string());
            let diagnostics = take_run_diagnostics();
            (result, diagnostics)
        });

        let src_cvc5 = source.clone();
        let file_cvc5 = filename.clone();
        let handle_cvc5 = std::thread::spawn(move || {
            let result = tarsier_engine::pipeline::verify_with_cegar_report(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                cegar_iters,
            )
            .map_err(|e| e.to_string());
            let diagnostics = take_run_diagnostics();
            (result, diagnostics)
        });

        let (z3_result, z3_diag): (
            Result<CegarAuditReport, String>,
            Option<PipelineRunDiagnostics>,
        ) = match handle_z3.join() {
            Ok((result, diagnostics)) => (result, Some(diagnostics)),
            Err(_) => (Err("thread panicked".into()), None),
        };
        let (cvc5_result, cvc5_diag): (
            Result<CegarAuditReport, String>,
            Option<PipelineRunDiagnostics>,
        ) = match handle_cvc5.join() {
            Ok((result, diagnostics)) => (result, Some(diagnostics)),
            Err(_) => (Err("thread panicked".into()), None),
        };

        let (final_result, portfolio_details) =
            merge_portfolio_verify_reports(z3_result, cvc5_result);
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": verification_result_kind(&final_result),
                    "details": verification_result_details(&final_result),
                    "output": format!("{final_result}"),
                    "portfolio": portfolio_details,
                    "network_faithfulness": network_faithfulness,
                    "abstractions": {
                        "z3": z3_diag.as_ref().map(run_diagnostics_details),
                        "cvc5": cvc5_diag.as_ref().map(run_diagnostics_details),
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{final_result}");
                for (label, solver_diag) in [("z3", &z3_diag), ("cvc5", &cvc5_diag)] {
                    if let Some(diagnostics) = solver_diag {
                        if let Some(opt) = render_optimization_summary(diagnostics) {
                            eprintln!("[{label}] {opt}");
                        }
                        if let Some(fallback) = render_fallback_summary(diagnostics) {
                            eprintln!("[{label}] {fallback}");
                        }
                        if let Some(phase_profile) = render_phase_profile_summary(diagnostics) {
                            eprintln!("[{label}] {phase_profile}");
                        }
                    }
                }
            }
        }
        if let Some(out) = cegar_report_out {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "result": verification_result_kind(&final_result),
                "output": format!("{final_result}"),
                "portfolio": portfolio_details,
                "network_faithfulness": network_faithfulness,
                "abstractions": {
                    "z3": z3_diag.as_ref().map(run_diagnostics_details),
                    "cvc5": cvc5_diag.as_ref().map(run_diagnostics_details),
                },
            });
            write_json_artifact(&out, &artifact)?;
            if matches!(output_format, OutputFormat::Text) {
                println!("Portfolio CEGAR report written to {}", out.display());
            }
        }
    } else {
        match tarsier_engine::pipeline::verify_with_cegar_report(
            &source,
            &filename,
            &options,
            cegar_iters,
        ) {
            Ok(report) => {
                let diagnostics = take_run_diagnostics();
                match output_format {
                    OutputFormat::Json => {
                        let artifact = json!({
                            "schema_version": 1,
                            "file": filename,
                            "result": verification_result_kind(&report.final_result),
                            "details": verification_result_details(&report.final_result),
                            "output": format!("{}", report.final_result),
                            "cegar": cegar_report_details(&report),
                            "network_faithfulness": network_faithfulness,
                            "abstractions": run_diagnostics_details(&diagnostics),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&artifact).into_diagnostic()?
                        );
                    }
                    OutputFormat::Text => {
                        println!("{}", report.final_result);
                        if let Some(opt) = render_optimization_summary(&diagnostics) {
                            eprintln!("{opt}");
                        }
                        if let Some(fallback) = render_fallback_summary(&diagnostics) {
                            eprintln!("{fallback}");
                        }
                        if let Some(phase_profile) = render_phase_profile_summary(&diagnostics) {
                            eprintln!("{phase_profile}");
                        }
                    }
                }
                if let Some(out) = cegar_report_out {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": verification_result_kind(&report.final_result),
                        "output": format!("{}", report.final_result),
                        "cegar": cegar_report_details(&report),
                        "network_faithfulness": network_faithfulness,
                        "abstractions": run_diagnostics_details(&diagnostics),
                    });
                    write_json_artifact(&out, &artifact)?;
                    if matches!(output_format, OutputFormat::Text) {
                        println!("CEGAR report written to {}", out.display());
                    }
                }
            }
            Err(e) => {
                match output_format {
                    OutputFormat::Json => {
                        let err = json!({"error": e.to_string()});
                        println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                    }
                    OutputFormat::Text => {
                        eprintln!("Error: {e}");
                    }
                }
                return Err(miette::miette!("Error: {e}"));
            }
        }
    }

    Ok(())
}

pub(crate) fn run_round_sweep_command(args: RoundSweepCommandArgs) -> miette::Result<()> {
    let RoundSweepCommandArgs {
        file,
        solver,
        depth,
        timeout,
        soundness,
        vars,
        min_bound,
        max_bound,
        stable_window,
        format,
        out,
        cli_network_mode,
    } = args;
    if min_bound > max_bound {
        miette::bail!("min_bound must be <= max_bound");
    }
    if stable_window == 0 {
        miette::bail!("stable_window must be >= 1");
    }
    if vars.is_empty() {
        miette::bail!("Provide at least one variable name with --vars.");
    }

    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let base_program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver)?,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    let mut points: Vec<RoundSweepPoint> = Vec::new();
    let mut applied_target_count: Option<usize> = None;

    for upper_bound in min_bound..=max_bound {
        let mut program = base_program.clone();
        let stats = apply_round_upper_bound(&mut program, &vars, upper_bound);
        if stats.matched_targets == 0 {
            miette::bail!(
                "No bounded variables/fields matched {:?}. Ensure the model declares ranges for these names.",
                vars
            );
        }
        if !stats.unbounded_targets.is_empty() {
            miette::bail!(
                "Round sweep targets must be bounded (`in a..b`). Add bounds for: {}",
                stats.unbounded_targets.join(", ")
            );
        }
        applied_target_count = Some(stats.updated_ranges);

        let result =
            tarsier_engine::pipeline::verify_program_ast(&program, &options).into_diagnostic()?;
        points.push(RoundSweepPoint {
            upper_bound,
            result: verification_result_kind(&result).to_string(),
            details: verification_result_details(&result),
        });
    }

    let (candidate_cutoff, stabilized_result) =
        if let Some((cutoff, kind)) = detect_round_sweep_cutoff(&points, stable_window) {
            (Some(cutoff), Some(kind))
        } else {
            (None, None)
        };

    let report = RoundSweepReport {
        schema_version: 1,
        file: filename.clone(),
        vars: vars.clone(),
        min_bound,
        max_bound,
        stable_window,
        points,
        candidate_cutoff,
        stabilized_result,
        note: format!(
            "Convergence is empirical over bounded runs ({} targeted ranges mutated). Treat as cutoff evidence, not a universal proof.",
            applied_target_count.unwrap_or(0)
        ),
    };

    match parse_output_format(&format)? {
        OutputFormat::Text => {
            println!("{}", render_round_sweep_text(&report));
        }
        OutputFormat::Json => {
            let value = serde_json::to_value(&report).into_diagnostic()?;
            if let Some(path) = out {
                write_json_artifact(&path, &value)?;
                println!("Round sweep report written to {}", path.display());
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

pub(crate) fn run_liveness_command(args: LivenessCommandArgs) -> miette::Result<()> {
    let LivenessCommandArgs {
        file,
        solver,
        depth,
        timeout,
        soundness,
        dump_smt,
        format,
        cli_network_mode,
    } = args;
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness)?;
    let output_format = parse_output_format(&format)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;

    let options = PipelineOptions {
        solver: parse_solver_choice(&solver)?,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    match tarsier_engine::pipeline::check_liveness(&source, &filename, &options) {
        Ok(result) => match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": liveness_result_kind(&result),
                    "details": liveness_result_details(&result),
                    "output": format!("{result}"),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{result}");
            }
        },
        Err(e) => {
            match output_format {
                OutputFormat::Json => {
                    let err = json!({"error": e.to_string()});
                    println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                }
                OutputFormat::Text => {
                    eprintln!("Error: {e}");
                }
            }
            return Err(miette::miette!("Error: {e}"));
        }
    }

    Ok(())
}

pub(crate) fn run_fair_liveness_command(args: FairLivenessCommandArgs) -> miette::Result<()> {
    let FairLivenessCommandArgs {
        file,
        solver,
        depth,
        timeout,
        soundness,
        fairness,
        portfolio,
        format,
        cli_network_mode,
    } = args;
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness)?;
    let output_format = parse_output_format(&format)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;

    let options = make_options(
        parse_solver_choice(&solver)?,
        depth,
        timeout,
        soundness_mode,
    );
    let fairness = parse_fairness_mode(&fairness)?;
    if portfolio {
        let mut z3_options = options.clone();
        z3_options.solver = SolverChoice::Z3;
        let mut cvc5_options = options.clone();
        cvc5_options.solver = SolverChoice::Cvc5;

        let src_z3 = source.clone();
        let file_z3 = filename.clone();
        let handle_z3 = std::thread::spawn(move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &src_z3,
                &file_z3,
                &z3_options,
                fairness,
            )
            .map_err(|e| e.to_string())
        });

        let src_cvc5 = source.clone();
        let file_cvc5 = filename.clone();
        let handle_cvc5 = std::thread::spawn(move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                fairness,
            )
            .map_err(|e| e.to_string())
        });

        let z3_result: Result<FairLivenessResult, String> = match handle_z3.join() {
            Ok(result) => result,
            Err(_) => Err("thread panicked".into()),
        };
        let cvc5_result: Result<FairLivenessResult, String> = match handle_cvc5.join() {
            Ok(result) => result,
            Err(_) => Err("thread panicked".into()),
        };
        let (result, details) = merge_portfolio_fair_liveness_results(z3_result, cvc5_result);
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "result": fair_liveness_result_kind(&result),
                    "details": fair_liveness_result_details(&result),
                    "output": format!("{result}"),
                    "portfolio": details,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{result}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"portfolio": details}))
                        .into_diagnostic()?
                );
            }
        }
    } else {
        match tarsier_engine::pipeline::check_fair_liveness_with_mode(
            &source, &filename, &options, fairness,
        ) {
            Ok(result) => match output_format {
                OutputFormat::Json => {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": fair_liveness_result_kind(&result),
                        "details": fair_liveness_result_details(&result),
                        "output": format!("{result}"),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&artifact).into_diagnostic()?
                    );
                }
                OutputFormat::Text => {
                    println!("{result}");
                }
            },
            Err(e) => {
                match output_format {
                    OutputFormat::Json => {
                        let err = json!({"error": e.to_string()});
                        println!("{}", serde_json::to_string_pretty(&err).into_diagnostic()?);
                    }
                    OutputFormat::Text => {
                        eprintln!("Error: {e}");
                    }
                }
                return Err(miette::miette!("Error: {e}"));
            }
        }
    }

    Ok(())
}

pub(crate) fn run_comm_command(
    file: PathBuf,
    depth: usize,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    validate_cli_network_semantics_mode(
        &source,
        &filename,
        tarsier_engine::pipeline::SoundnessMode::Strict,
        cli_network_mode,
    )?;
    let output_format = parse_output_format(&format)?;

    match tarsier_engine::pipeline::comm_complexity(&source, &filename, depth) {
        Ok(report) => {
            let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
            if let Some(path) = out.as_ref() {
                write_json_artifact(path, &report_json_value)?;
                println!("Communication report written to {}", path.display());
            }

            match output_format {
                OutputFormat::Text => {
                    println!("{report}");
                }
                OutputFormat::Json => {
                    let json =
                        serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;
                    println!("{json}");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return Err(miette::miette!("Error: {e}"));
        }
    }
    Ok(())
}
