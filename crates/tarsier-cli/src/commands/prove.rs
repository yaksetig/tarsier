// Command handlers for: Prove, ProveRound, ProveFair, ProveFairRound
//
// These commands handle unbounded proof generation workflows (k-induction, PDR)
// for safety and fair-liveness properties, including portfolio mode, CEGAR
// refinement, round-erasure over-approximation, and certificate bundle output.

use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{FairnessMode, PipelineOptions, ProofEngine, SolverChoice};
use tarsier_engine::result::{UnboundedFairLivenessResult, UnboundedSafetyResult};

use crate::{
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety,
    merge_portfolio_prove_fair_results, merge_portfolio_prove_results, proof_engine_name,
    render_fallback_summary, render_optimization_summary, render_phase_profile_summary,
    render_prove_fair_round_text, render_prove_round_text, run_diagnostics_details,
    unbounded_fair_cegar_report_details, unbounded_fair_result_details, unbounded_fair_result_kind,
    unbounded_safety_cegar_report_details, unbounded_safety_result_details,
    unbounded_safety_result_kind, validate_cli_network_semantics_mode, write_certificate_bundle,
    write_json_artifact, AnalysisLayerReport, CliNetworkSemanticsMode, OutputFormat,
};

use super::helpers::{
    parse_fairness_mode, parse_output_format, parse_proof_engine, parse_solver_choice,
    parse_soundness_mode, sandbox_read_source,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProveAutoTarget {
    Safety,
    FairLiveness,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) engine: String,
    pub(crate) fairness: String,
    pub(crate) cert_out: Option<PathBuf>,
    pub(crate) cegar_iters: usize,
    pub(crate) cegar_report_out: Option<PathBuf>,
    pub(crate) portfolio: bool,
    pub(crate) auto_strengthen: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveFairCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) cert_out: Option<PathBuf>,
    pub(crate) cegar_iters: usize,
    pub(crate) cegar_report_out: Option<PathBuf>,
    pub(crate) portfolio: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveRoundCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) engine: String,
    pub(crate) round_vars: Vec<String>,
    pub(crate) format: String,
    pub(crate) out: Option<PathBuf>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveFairRoundCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) round_vars: Vec<String>,
    pub(crate) format: String,
    pub(crate) out: Option<PathBuf>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
struct ProveExecutionConfig {
    fairness: FairnessMode,
    cert_out: Option<PathBuf>,
    cegar_iters: usize,
    cegar_report_out: Option<PathBuf>,
    timeout: u64,
    output_format: OutputFormat,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

pub(crate) fn is_safety_property_kind(kind: tarsier_dsl::ast::PropertyKind) -> bool {
    matches!(
        kind,
        tarsier_dsl::ast::PropertyKind::Agreement
            | tarsier_dsl::ast::PropertyKind::Validity
            | tarsier_dsl::ast::PropertyKind::Safety
            | tarsier_dsl::ast::PropertyKind::Invariant
    )
}

pub(crate) fn detect_prove_auto_target(
    source: &str,
    filename: &str,
) -> miette::Result<ProveAutoTarget> {
    let program = tarsier_dsl::parse(source, filename).into_diagnostic()?;
    let has_safety = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind));
    let has_liveness = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| p.node.kind == tarsier_dsl::ast::PropertyKind::Liveness);

    Ok(if has_liveness && !has_safety {
        ProveAutoTarget::FairLiveness
    } else {
        ProveAutoTarget::Safety
    })
}

#[cfg(feature = "governance")]
pub(crate) fn parse_manifest_fairness_mode(raw: &str) -> Result<FairnessMode, String> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(format!(
            "Unknown fairness '{other}'. Use 'weak' or 'strong'."
        )),
    }
}

pub(crate) fn fairness_name(mode: FairnessMode) -> &'static str {
    match mode {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

pub(crate) fn fairness_semantics_json(mode: FairnessMode) -> Value {
    let semantics = mode.semantics();
    json!({
        "mode": semantics.mode,
        "formal_name": semantics.formal_name,
        "definition": semantics.definition,
        "verdict_interpretation": semantics.verdict_interpretation,
    })
}

pub(crate) fn gst_assumptions_json(source: &str, filename: &str) -> Value {
    match tarsier_engine::pipeline::parse(source, filename)
        .and_then(|program| tarsier_engine::pipeline::lower(&program))
    {
        Ok(ta) => {
            let gst_parameter = ta.semantics.gst_param.and_then(|pid| {
                ta.parameters
                    .get(pid.as_usize())
                    .map(|param| param.name.clone())
            });
            let requires_gst = matches!(
                ta.semantics.timing_model,
                tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
            );
            json!({
                "timing_model": format!("{:?}", ta.semantics.timing_model),
                "requires_gst": requires_gst,
                "gst_parameter": gst_parameter,
                "post_gst_assumed_for_fairness": requires_gst,
            })
        }
        Err(e) => json!({
            "status": "unavailable",
            "error": e.to_string(),
        }),
    }
}

pub(crate) fn fair_liveness_obligation_entries(layers: &[AnalysisLayerReport]) -> Vec<Value> {
    layers
        .iter()
        .filter(|layer| layer.layer.starts_with("certify[fair_liveness]"))
        .map(|layer| {
            let obligations = layer
                .details
                .get("obligations_checked")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let obligation_count = layer
                .details
                .get("obligation_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .unwrap_or(obligations.len());
            let integrity_ok = layer.details.get("integrity_ok").and_then(Value::as_bool);
            json!({
                "layer": layer.layer,
                "status": layer.status,
                "integrity_ok": integrity_ok,
                "obligation_count": obligation_count,
                "obligations": obligations,
            })
        })
        .collect()
}

pub(crate) fn build_liveness_governance_report(
    source: &str,
    filename: &str,
    fairness: FairnessMode,
    layers: &[AnalysisLayerReport],
) -> Value {
    let obligation_entries = fair_liveness_obligation_entries(layers);
    let total_obligations_checked = obligation_entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("obligation_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
        })
        .sum::<usize>();
    let obligations_note = if obligation_entries.is_empty() {
        Some(
            "No fair-liveness certification layer ran in this analysis; independent replay obligations were not checked."
                .to_string(),
        )
    } else {
        None
    };

    json!({
        "fairness_model": fairness_semantics_json(fairness),
        "gst_assumptions": gst_assumptions_json(source, filename),
        "obligations_checked": {
            "source": "fair_liveness_certificate",
            "entries": obligation_entries,
            "total_obligations_checked": total_obligations_checked,
            "note": obligations_note,
        }
    })
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Handler for `tarsier prove`.
///
/// Auto-detects whether the protocol specifies safety or fair-liveness
/// properties and dispatches accordingly.  Supports portfolio mode
/// (parallel Z3 + cvc5), CEGAR refinement, and certificate generation.
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

// ---------------------------------------------------------------------------
// Internal helpers for the Prove command
// ---------------------------------------------------------------------------

/// Run the fair-liveness branch of `tarsier prove` (auto-dispatched).
fn run_prove_fair_liveness_branch(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    portfolio: bool,
    config: ProveExecutionConfig,
) -> miette::Result<()> {
    let ProveExecutionConfig {
        fairness,
        cert_out,
        cegar_iters,
        cegar_report_out,
        timeout,
        output_format,
    } = config;
    if portfolio {
        let mut z3_options = options.clone();
        z3_options.solver = SolverChoice::Z3;
        let mut cvc5_options = options.clone();
        cvc5_options.solver = SolverChoice::Cvc5;

        let src_z3 = source.to_string();
        let file_z3 = filename.to_string();
        let handle_z3 = std::thread::spawn(move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &src_z3,
                    &file_z3,
                    &z3_options,
                    fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &src_z3,
                    &file_z3,
                    &z3_options,
                    fairness,
                )
            }
            .map_err(|e| e.to_string())
        });

        let src_cvc5 = source.to_string();
        let file_cvc5 = filename.to_string();
        let handle_cvc5 = std::thread::spawn(move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &src_cvc5,
                    &file_cvc5,
                    &cvc5_options,
                    fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &src_cvc5,
                    &file_cvc5,
                    &cvc5_options,
                    fairness,
                )
            }
            .map_err(|e| e.to_string())
        });

        let z3_result: Result<UnboundedFairLivenessResult, String> = match handle_z3.join() {
            Ok(res) => res,
            Err(_) => Err("thread panicked".into()),
        };
        let cvc5_result: Result<UnboundedFairLivenessResult, String> = match handle_cvc5.join() {
            Ok(res) => res,
            Err(_) => Err("thread panicked".into()),
        };
        let (result, details) = merge_portfolio_prove_fair_results(z3_result, cvc5_result);
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "mode": "prove",
                    "prove_target": "fair_liveness",
                    "result": unbounded_fair_result_kind(&result),
                    "details": unbounded_fair_result_details(&result),
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
                    serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                        .into_diagnostic()?
                );
            }
        }

        if let Some(out) = cegar_report_out.clone() {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "fair_liveness",
                "result": unbounded_fair_result_kind(&result),
                "details": unbounded_fair_result_details(&result),
                "output": format!("{result}"),
                "cegar_controls": {
                    "max_refinements": cegar_iters,
                    "timeout_secs": timeout,
                    "solver": "portfolio",
                    "proof_engine": proof_engine_name(options.proof_engine),
                    "fairness": fairness_name(fairness),
                },
                "portfolio": details,
            });
            write_json_artifact(&out, &artifact)?;
            if matches!(output_format, OutputFormat::Text) {
                println!("CEGAR proof report written to {}", out.display());
            }
        }

        if cert_out.is_some() && matches!(output_format, OutputFormat::Text) {
            eprintln!(
                "Skipping certificate generation in portfolio mode. Use `certify-fair-liveness` with an explicit solver."
            );
        }
    } else {
        let result = if let Some(report_path) = cegar_report_out.clone() {
            let report = tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
                source,
                filename,
                options,
                fairness,
                cegar_iters,
            )
            .map_err(|e| miette::miette!("Error: {e}"))?;
            let diagnostics = tarsier_engine::pipeline::take_run_diagnostics();
            let result = report.final_result.clone();
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "fair_liveness",
                "result": unbounded_fair_result_kind(&result),
                "details": unbounded_fair_result_details(&result),
                "output": format!("{result}"),
                "cegar": unbounded_fair_cegar_report_details(&report),
                "abstractions": run_diagnostics_details(&diagnostics),
            });
            write_json_artifact(&report_path, &artifact)?;
            println!("CEGAR proof report written to {}", report_path.display());
            result
        } else {
            let run = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    source,
                    filename,
                    options,
                    fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    source, filename, options, fairness,
                )
            };
            run.map_err(|e| miette::miette!("Error: {e}"))?
        };
        match output_format {
            OutputFormat::Json => {
                let artifact = json!({
                    "schema_version": 1,
                    "file": filename,
                    "mode": "prove",
                    "prove_target": "fair_liveness",
                    "result": unbounded_fair_result_kind(&result),
                    "details": unbounded_fair_result_details(&result),
                    "output": format!("{result}"),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&artifact).into_diagnostic()?
                );
            }
            OutputFormat::Text => {
                println!("{result}");
                let prove_diag = tarsier_engine::pipeline::take_run_diagnostics();
                if let Some(opt) = render_optimization_summary(&prove_diag) {
                    eprintln!("{opt}");
                }
                if let Some(fb) = render_fallback_summary(&prove_diag) {
                    eprintln!("{fb}");
                }
                if let Some(pp) = render_phase_profile_summary(&prove_diag) {
                    eprintln!("{pp}");
                }
            }
        }
        if let Some(out) = cert_out {
            match result {
                UnboundedFairLivenessResult::LiveProved { .. } => {
                    let cert =
                        tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                            source, filename, options, fairness,
                        )
                        .map_err(|e| {
                            miette::miette!("Error generating fair-liveness certificate: {e}")
                        })?;
                    let bundle = certificate_bundle_from_fair_liveness(&cert);
                    write_certificate_bundle(&out, &bundle, false, false)?;
                }
                _ => {
                    if matches!(output_format, OutputFormat::Text) {
                        eprintln!(
                            "Skipping certificate generation: fair-liveness proof did not conclude LIVE."
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Run `tarsier prove` in safety portfolio mode (parallel Z3 + cvc5).
fn run_prove_safety_portfolio(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    config: ProveExecutionConfig,
) -> miette::Result<()> {
    let ProveExecutionConfig {
        fairness,
        cert_out,
        cegar_iters,
        cegar_report_out,
        timeout,
        output_format,
    } = config;
    let mut z3_options = options.clone();
    z3_options.solver = SolverChoice::Z3;
    let mut cvc5_options = options.clone();
    cvc5_options.solver = SolverChoice::Cvc5;

    let src_z3 = source.to_string();
    let file_z3 = filename.to_string();
    let handle_z3 = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_safety_with_cegar(
                &src_z3,
                &file_z3,
                &z3_options,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_safety(&src_z3, &file_z3, &z3_options)
        }
        .map_err(|e| e.to_string())
    });

    let src_cvc5 = source.to_string();
    let file_cvc5 = filename.to_string();
    let handle_cvc5 = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_safety_with_cegar(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_safety(&src_cvc5, &file_cvc5, &cvc5_options)
        }
        .map_err(|e| e.to_string())
    });

    let z3_result: Result<UnboundedSafetyResult, String> = match handle_z3.join() {
        Ok(res) => res,
        Err(_) => Err("thread panicked".into()),
    };
    let cvc5_result: Result<UnboundedSafetyResult, String> = match handle_cvc5.join() {
        Ok(res) => res,
        Err(_) => Err("thread panicked".into()),
    };
    let (result, details) = merge_portfolio_prove_results(z3_result, cvc5_result);
    match output_format {
        OutputFormat::Json => {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "safety",
                "result": unbounded_safety_result_kind(&result),
                "details": unbounded_safety_result_details(&result),
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
                serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                    .into_diagnostic()?
            );
        }
    }

    if let Some(out) = cegar_report_out.clone() {
        let artifact = json!({
            "schema_version": 1,
            "file": filename,
            "mode": "prove",
            "prove_target": "safety",
            "result": unbounded_safety_result_kind(&result),
            "details": unbounded_safety_result_details(&result),
            "output": format!("{result}"),
            "cegar_controls": {
                "max_refinements": cegar_iters,
                "timeout_secs": timeout,
                "solver": "portfolio",
                "proof_engine": proof_engine_name(options.proof_engine),
                "fairness": fairness_name(fairness),
            },
            "portfolio": details,
        });
        write_json_artifact(&out, &artifact)?;
        if matches!(output_format, OutputFormat::Text) {
            println!("CEGAR proof report written to {}", out.display());
        }
    }

    if cert_out.is_some() && matches!(output_format, OutputFormat::Text) {
        eprintln!(
            "Skipping certificate generation in portfolio mode. Use `certify-safety` with an explicit solver."
        );
    }
    Ok(())
}

/// Run `tarsier prove` in safety single-solver mode.
fn run_prove_safety_single(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    cert_out: Option<PathBuf>,
    cegar_iters: usize,
    cegar_report_out: Option<PathBuf>,
    output_format: OutputFormat,
) -> miette::Result<()> {
    let result = if let Some(report_path) = cegar_report_out.clone() {
        let report = tarsier_engine::pipeline::prove_safety_with_cegar_report(
            source,
            filename,
            options,
            cegar_iters,
        )
        .map_err(|e| miette::miette!("Error: {e}"))?;
        let diagnostics = tarsier_engine::pipeline::take_run_diagnostics();
        let result = report.final_result.clone();
        let artifact = json!({
            "schema_version": 1,
            "file": filename,
            "mode": "prove",
            "prove_target": "safety",
            "result": unbounded_safety_result_kind(&result),
            "details": unbounded_safety_result_details(&result),
            "output": format!("{result}"),
            "cegar": unbounded_safety_cegar_report_details(&report),
            "abstractions": run_diagnostics_details(&diagnostics),
        });
        write_json_artifact(&report_path, &artifact)?;
        println!("CEGAR proof report written to {}", report_path.display());
        result
    } else {
        let run = if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_safety_with_cegar(
                source,
                filename,
                options,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_safety(source, filename, options)
        };
        run.map_err(|e| miette::miette!("Error: {e}"))?
    };
    match output_format {
        OutputFormat::Json => {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "safety",
                "result": unbounded_safety_result_kind(&result),
                "details": unbounded_safety_result_details(&result),
                "output": format!("{result}"),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&artifact).into_diagnostic()?
            );
        }
        OutputFormat::Text => {
            println!("{result}");
            let prove_diag = tarsier_engine::pipeline::take_run_diagnostics();
            if let Some(opt) = render_optimization_summary(&prove_diag) {
                eprintln!("{opt}");
            }
            if let Some(fb) = render_fallback_summary(&prove_diag) {
                eprintln!("{fb}");
            }
            if let Some(pp) = render_phase_profile_summary(&prove_diag) {
                eprintln!("{pp}");
            }
        }
    }
    if let Some(out) = cert_out {
        match result {
            UnboundedSafetyResult::Safe { .. }
            | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                let cert = tarsier_engine::pipeline::generate_safety_certificate(
                    source, filename, options,
                )
                .map_err(|e| miette::miette!("Error generating certificate: {e}"))?;
                let bundle = certificate_bundle_from_safety(&cert);
                write_certificate_bundle(&out, &bundle, false, false)?;
            }
            _ => {
                if matches!(output_format, OutputFormat::Text) {
                    eprintln!("Skipping certificate generation: proof did not conclude SAFE.");
                }
            }
        }
    }
    Ok(())
}

/// Run `tarsier prove` with auto-strengthen invariant inference pre-pass.
fn run_prove_safety_auto_strengthen(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    output_format: OutputFormat,
) -> miette::Result<()> {
    let result =
        tarsier_engine::pipeline::verification::prove_safety_with_auto_strengthen(
            source, filename, options,
        )
        .map_err(|e| miette::miette!("Error: {e}"))?;
    match output_format {
        OutputFormat::Json => {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "safety",
                "auto_strengthen": true,
                "result": unbounded_safety_result_kind(&result),
                "details": unbounded_safety_result_details(&result),
                "output": format!("{result}"),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&artifact).into_diagnostic()?
            );
        }
        OutputFormat::Text => {
            println!("{result}");
            let diag = tarsier_engine::pipeline::take_run_diagnostics();
            if let Some(opt) = render_optimization_summary(&diag) {
                eprintln!("{opt}");
            }
            if let Some(fb) = render_fallback_summary(&diag) {
                eprintln!("{fb}");
            }
            if let Some(pp) = render_phase_profile_summary(&diag) {
                eprintln!("{pp}");
            }
        }
    }
    Ok(())
}

/// Run `tarsier prove-fair` in portfolio mode (parallel Z3 + cvc5).
fn run_prove_fair_portfolio(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    config: ProveExecutionConfig,
) -> miette::Result<()> {
    let ProveExecutionConfig {
        fairness,
        cert_out,
        cegar_iters,
        cegar_report_out,
        timeout,
        output_format,
    } = config;
    let mut z3_options = options.clone();
    z3_options.solver = SolverChoice::Z3;
    let mut cvc5_options = options.clone();
    cvc5_options.solver = SolverChoice::Cvc5;

    let src_z3 = source.to_string();
    let file_z3 = filename.to_string();
    let handle_z3 = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                &src_z3,
                &file_z3,
                &z3_options,
                fairness,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                &src_z3,
                &file_z3,
                &z3_options,
                fairness,
            )
        }
        .map_err(|e| e.to_string())
    });

    let src_cvc5 = source.to_string();
    let file_cvc5 = filename.to_string();
    let handle_cvc5 = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                fairness,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                &src_cvc5,
                &file_cvc5,
                &cvc5_options,
                fairness,
            )
        }
        .map_err(|e| e.to_string())
    });

    let z3_result: Result<UnboundedFairLivenessResult, String> = match handle_z3.join() {
        Ok(res) => res,
        Err(_) => Err("thread panicked".into()),
    };
    let cvc5_result: Result<UnboundedFairLivenessResult, String> = match handle_cvc5.join() {
        Ok(res) => res,
        Err(_) => Err("thread panicked".into()),
    };
    let (result, details) = merge_portfolio_prove_fair_results(z3_result, cvc5_result);
    match output_format {
        OutputFormat::Json => {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove-fair",
                "result": unbounded_fair_result_kind(&result),
                "details": unbounded_fair_result_details(&result),
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
                serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                    .into_diagnostic()?
            );
        }
    }

    if let Some(out) = cegar_report_out.clone() {
        let artifact = json!({
            "schema_version": 1,
            "file": filename,
            "mode": "prove-fair",
            "result": unbounded_fair_result_kind(&result),
            "details": unbounded_fair_result_details(&result),
            "output": format!("{result}"),
            "cegar_controls": {
                "max_refinements": cegar_iters,
                "timeout_secs": timeout,
                "solver": "portfolio",
                "proof_engine": "pdr",
                "fairness": fairness_name(fairness),
            },
            "portfolio": details,
        });
        write_json_artifact(&out, &artifact)?;
        if matches!(output_format, OutputFormat::Text) {
            println!("CEGAR proof report written to {}", out.display());
        }
    }

    if cert_out.is_some() && matches!(output_format, OutputFormat::Text) {
        eprintln!(
            "Skipping certificate generation in portfolio mode. Use `certify-fair-liveness` with an explicit solver."
        );
    }
    Ok(())
}

/// Run `tarsier prove-fair` in single-solver mode.
fn run_prove_fair_single(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    config: ProveExecutionConfig,
) -> miette::Result<()> {
    let ProveExecutionConfig {
        fairness,
        cert_out,
        cegar_iters,
        cegar_report_out,
        output_format,
        ..
    } = config;
    let result = if let Some(report_path) = cegar_report_out.clone() {
        let report = tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
            source,
            filename,
            options,
            fairness,
            cegar_iters,
        )
        .map_err(|e| miette::miette!("Error: {e}"))?;
        let diagnostics = tarsier_engine::pipeline::take_run_diagnostics();
        let result = report.final_result.clone();
        let artifact = json!({
            "schema_version": 1,
            "file": filename,
            "mode": "prove-fair",
            "result": unbounded_fair_result_kind(&result),
            "details": unbounded_fair_result_details(&result),
            "output": format!("{result}"),
            "cegar": unbounded_fair_cegar_report_details(&report),
            "abstractions": run_diagnostics_details(&diagnostics),
        });
        write_json_artifact(&report_path, &artifact)?;
        println!("CEGAR proof report written to {}", report_path.display());
        result
    } else {
        let run = if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                source,
                filename,
                options,
                fairness,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                source, filename, options, fairness,
            )
        };
        run.map_err(|e| miette::miette!("Error: {e}"))?
    };
    match output_format {
        OutputFormat::Json => {
            let artifact = json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove-fair",
                "result": unbounded_fair_result_kind(&result),
                "details": unbounded_fair_result_details(&result),
                "output": format!("{result}"),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&artifact).into_diagnostic()?
            );
        }
        OutputFormat::Text => {
            println!("{result}");
            let prove_fair_diag = tarsier_engine::pipeline::take_run_diagnostics();
            if let Some(opt) = render_optimization_summary(&prove_fair_diag) {
                eprintln!("{opt}");
            }
            if let Some(fb) = render_fallback_summary(&prove_fair_diag) {
                eprintln!("{fb}");
            }
            if let Some(pp) = render_phase_profile_summary(&prove_fair_diag) {
                eprintln!("{pp}");
            }
        }
    }
    if let Some(out) = cert_out {
        match result {
            UnboundedFairLivenessResult::LiveProved { .. } => {
                let cert = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                    source, filename, options, fairness,
                )
                .map_err(|e| miette::miette!("Error generating fair-liveness certificate: {e}"))?;
                let bundle = certificate_bundle_from_fair_liveness(&cert);
                write_certificate_bundle(&out, &bundle, false, false)?;
            }
            _ => {
                if matches!(output_format, OutputFormat::Text) {
                    eprintln!(
                        "Skipping certificate generation: fair-liveness proof did not conclude LIVE."
                    );
                }
            }
        }
    }
    Ok(())
}
