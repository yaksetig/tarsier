// Command handler for: Analyze
//
// This module contains the analysis pipeline types, layer runners,
// interpretation/verdict computation, and the top-level `run_analyze_command`
// handler that was previously the `Commands::Analyze` match arm in main().

use std::path::Path;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{
    take_run_diagnostics, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{
    FairLivenessResult, LivenessResult, UnboundedFairLivenessResult, UnboundedSafetyResult,
    VerificationResult,
};
use tarsier_proof_kernel::check_bundle_integrity;

use crate::{
    build_liveness_governance_report, canonical_verdict_from_layer_result, cegar_report_details,
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety, cti_details,
    fairness_name, fairness_semantics_json, liveness_convergence_diagnostics,
    liveness_unknown_reason_payload, merge_portfolio_fair_liveness_results,
    merge_portfolio_liveness_results, merge_portfolio_prove_fair_results,
    merge_portfolio_prove_results, merge_portfolio_verify_reports, network_faithfulness_section,
    run_diagnostics_details, solver_name, trace_details, validate_cli_network_semantics_mode,
    write_certificate_bundle_quiet, AnalysisConfig, AnalysisInterpretation, AnalysisLayerReport,
    AnalysisMode, AnalysisReport, CanonicalVerdict, ClaimStatement, CliNetworkSemanticsMode,
    LayerRunCfg, NextAction, OutputFormat,
};

use super::helpers::{
    make_options, parse_analysis_mode, parse_fairness_mode, parse_output_format,
    parse_solver_choice, parse_soundness_mode, sandbox_read_source,
};

// ---------------------------------------------------------------------------
// Layer helpers
// ---------------------------------------------------------------------------

pub(crate) fn layer(
    layer_name: &str,
    status: &str,
    summary: impl Into<String>,
    details: Value,
    output: impl Into<String>,
) -> AnalysisLayerReport {
    let verdict = canonical_verdict_from_layer_result(layer_name, status);
    AnalysisLayerReport {
        layer: layer_name.to_string(),
        status: status.to_string(),
        verdict: verdict.as_str().to_string(),
        summary: summary.into(),
        details,
        output: output.into(),
    }
}

pub(crate) fn run_parse_layer(source: &str, filename: &str) -> AnalysisLayerReport {
    match tarsier_engine::pipeline::parse(source, filename) {
        Ok(program) => {
            // V2-07: Validate property fragment shapes after parse
            if let Err(diags) = tarsier_engine::pipeline::validate_property_fragments(&program) {
                let diagnostics: Vec<Value> = diags
                    .iter()
                    .map(|d| {
                        json!({
                            "property": d.property_name,
                            "message": d.message,
                            "hint": d.hint,
                        })
                    })
                    .collect();
                return layer(
                    "parse+lower",
                    "fail",
                    "Unsupported property shape detected.",
                    json!({"fragment_diagnostics": diagnostics}),
                    "INCONCLUSIVE",
                );
            }
            match tarsier_engine::pipeline::lower(&program) {
                Ok(ta) => layer(
                    "parse+lower",
                    "pass",
                    "Parsed and lowered protocol.",
                    json!({
                        "protocol": program.protocol.node.name,
                        "parameters": program.protocol.node.parameters.len(),
                        "roles": program.protocol.node.roles.len(),
                        "messages": program.protocol.node.messages.len(),
                        "locations": ta.locations.len(),
                        "rules": ta.rules.len(),
                    }),
                    "ok",
                ),
                Err(e) => layer(
                    "parse+lower",
                    "error",
                    "Lowering failed.",
                    json!({"error": e.to_string()}),
                    e.to_string(),
                ),
            }
        }
        Err(e) => layer(
            "parse+lower",
            "error",
            "Parse failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Verify layers
// ---------------------------------------------------------------------------

pub(crate) fn run_verify_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    cegar_iters: usize,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.depth, cfg.timeout, cfg.soundness);
    match tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        filename,
        &options,
        cegar_iters,
    ) {
        Ok(report) => {
            let cegar = cegar_report_details(&report);
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let result = report.final_result;
            let output = format!("{result}");
            match result {
                VerificationResult::Safe { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!("Safety holds up to depth {depth_checked}."),
                    json!({
                        "result": "safe",
                        "depth_checked": depth_checked,
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::ProbabilisticallySafe {
                    depth_checked,
                    failure_probability,
                    committee_analyses,
                } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "Probabilistic safety holds up to depth {depth_checked} (failure <= {:.0e}).",
                        failure_probability
                    ),
                    json!({
                        "result": "probabilistically_safe",
                        "depth_checked": depth_checked,
                        "failure_probability": failure_probability,
                        "committee_count": committee_analyses.len(),
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::Unsafe { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Safety violation found.",
                    json!({
                        "result": "unsafe",
                        "trace": trace_details(trace),
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Safety check inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Safety check failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

pub(crate) fn run_verify_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    cegar_iters: usize,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let (z3_result, cvc5_result) = run_portfolio_workers(
        move || {
            tarsier_engine::pipeline::verify_with_cegar_report(
                &source_z3,
                &filename_z3,
                &options_z3,
                cegar_iters,
            )
            .map_err(|e| e.to_string())
        },
        move || {
            tarsier_engine::pipeline::verify_with_cegar_report(
                &source_cvc5,
                &filename_cvc5,
                &options_cvc5,
                cegar_iters,
            )
            .map_err(|e| e.to_string())
        },
    );

    let (result, details) = merge_portfolio_verify_reports(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        VerificationResult::Safe { depth_checked } => layer(
            layer_name,
            "pass",
            format!("Safety holds up to depth {depth_checked}."),
            json!({
                "result": "safe",
                "depth_checked": depth_checked,
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => layer(
            layer_name,
            "pass",
            format!(
                "Probabilistic safety holds up to depth {depth_checked} (failure <= {:.0e}).",
                failure_probability
            ),
            json!({
                "result": "probabilistically_safe",
                "depth_checked": depth_checked,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len(),
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::Unsafe { ref trace } => layer(
            layer_name,
            "fail",
            "Safety violation found.",
            json!({
                "result": "unsafe",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Safety check inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

// ---------------------------------------------------------------------------
// Portfolio worker generic helper
// ---------------------------------------------------------------------------

pub(crate) fn run_portfolio_workers<T, FZ3, FCvc5>(
    z3_worker: FZ3,
    cvc5_worker: FCvc5,
) -> (Result<T, String>, Result<T, String>)
where
    T: Send + 'static,
    FZ3: FnOnce() -> Result<T, String> + Send + 'static,
    FCvc5: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let tx_z3 = tx.clone();
    let tx_cvc5 = tx;

    let z3_handle = std::thread::spawn(move || {
        let result = z3_worker();
        let _ = tx_z3.send(("z3", result));
    });
    let cvc5_handle = std::thread::spawn(move || {
        let result = cvc5_worker();
        let _ = tx_cvc5.send(("cvc5", result));
    });

    // Wait for both results, but process them as they arrive (first-result-wins
    // semantics for callers that check definitive verdicts).
    let mut z3_result: Option<Result<T, String>> = None;
    let mut cvc5_result: Option<Result<T, String>> = None;
    for _ in 0..2 {
        match rx.recv() {
            Ok(("z3", r)) => z3_result = Some(r),
            Ok(("cvc5", r)) => cvc5_result = Some(r),
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let _ = z3_handle.join();
    let _ = cvc5_handle.join();

    let z3_result = z3_result.unwrap_or_else(|| Err("z3 portfolio worker panicked".to_string()));
    let cvc5_result =
        cvc5_result.unwrap_or_else(|| Err("cvc5 portfolio worker panicked".to_string()));
    (z3_result, cvc5_result)
}

// ---------------------------------------------------------------------------
// Liveness layers
// ---------------------------------------------------------------------------

pub(crate) fn run_liveness_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    solver: SolverChoice,
    depth: usize,
    timeout: u64,
    soundness: SoundnessMode,
) -> AnalysisLayerReport {
    let options = make_options(solver, depth, timeout, soundness);
    match tarsier_engine::pipeline::check_liveness(source, filename, &options) {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            match result {
                LivenessResult::Live { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!("All processes decide by depth {depth_checked}."),
                    json!({
                        "result": "live",
                        "depth_checked": depth_checked,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                LivenessResult::NotLive { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Bounded liveness violation found.",
                    json!({
                        "result": "not_live",
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                LivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Bounded liveness check inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Bounded liveness check failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

pub(crate) fn run_liveness_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let (z3_result, cvc5_result) = run_portfolio_workers(
        move || {
            tarsier_engine::pipeline::check_liveness(&source_z3, &filename_z3, &options_z3)
                .map_err(|e| e.to_string())
        },
        move || {
            tarsier_engine::pipeline::check_liveness(&source_cvc5, &filename_cvc5, &options_cvc5)
                .map_err(|e| e.to_string())
        },
    );

    let (result, details) = merge_portfolio_liveness_results(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        LivenessResult::Live { depth_checked } => layer(
            layer_name,
            "pass",
            format!("All processes decide by depth {depth_checked}."),
            json!({
                "result": "live",
                "depth_checked": depth_checked,
                "portfolio": details,
            }),
            output,
        ),
        LivenessResult::NotLive { ref trace } => layer(
            layer_name,
            "fail",
            "Bounded liveness violation found.",
            json!({
                "result": "not_live",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        LivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Bounded liveness check inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

// ---------------------------------------------------------------------------
// Fair-liveness layers
// ---------------------------------------------------------------------------

pub(crate) fn run_fair_liveness_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.depth, cfg.timeout, cfg.soundness);
    match tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        filename,
        &options,
        cfg.fairness,
    ) {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            let fairness_name = fairness_name(cfg.fairness);
            match result {
                FairLivenessResult::NoFairCycleUpTo { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "No {fairness_name}-fair non-terminating lasso found up to depth {depth_checked}."
                    ),
                    json!({
                        "result": "no_fair_cycle_up_to",
                        "depth_checked": depth_checked,
                        "fairness": fairness_name,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                FairLivenessResult::FairCycleFound {
                    depth,
                    loop_start,
                    ref trace,
                } => layer(
                    layer_name,
                    "fail",
                    format!(
                        "{fairness_name}-fair non-terminating lasso found: {loop_start} -> {depth}."
                    ),
                    json!({
                        "result": "fair_cycle_found",
                        "depth": depth,
                        "loop_start": loop_start,
                        "fairness": fairness_name,
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                FairLivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Fair-liveness search inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Fair-liveness search failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

pub(crate) fn run_fair_liveness_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let fairness = cfg.fairness;
    let (z3_result, cvc5_result) = run_portfolio_workers(
        move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &source_z3,
                &filename_z3,
                &options_z3,
                fairness,
            )
            .map_err(|e| e.to_string())
        },
        move || {
            tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &source_cvc5,
                &filename_cvc5,
                &options_cvc5,
                fairness,
            )
            .map_err(|e| e.to_string())
        },
    );

    let (result, details) = merge_portfolio_fair_liveness_results(z3_result, cvc5_result);
    let output = format!("{result}");
    let fairness_name = fairness_name(cfg.fairness);
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => layer(
            layer_name,
            "pass",
            format!(
                "No {fairness_name}-fair non-terminating lasso found up to depth {depth_checked}."
            ),
            json!({
                "result": "no_fair_cycle_up_to",
                "depth_checked": depth_checked,
                "fairness": fairness_name,
                "portfolio": details,
            }),
            output,
        ),
        FairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            ref trace,
        } => layer(
            layer_name,
            "fail",
            format!("{fairness_name}-fair non-terminating lasso found: {loop_start} -> {depth}."),
            json!({
                "result": "fair_cycle_found",
                "depth": depth,
                "loop_start": loop_start,
                "fairness": fairness_name,
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        FairLivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Fair-liveness search inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

// ---------------------------------------------------------------------------
// Prove (safety) layers
// ---------------------------------------------------------------------------

pub(crate) fn run_prove_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    engine: ProofEngine,
) -> AnalysisLayerReport {
    let mut options = make_options(cfg.solver, cfg.k, cfg.timeout, cfg.soundness);
    options.proof_engine = engine;
    let run = if cfg.cegar_iters > 0 {
        tarsier_engine::pipeline::prove_safety_with_cegar(
            source,
            filename,
            &options,
            cfg.cegar_iters,
        )
    } else {
        tarsier_engine::pipeline::prove_safety(source, filename, &options)
    };
    match run {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            match result {
                UnboundedSafetyResult::Safe { induction_k } => layer(
                    layer_name,
                    "pass",
                    format!("Unbounded safety proved (k = {induction_k})."),
                    json!({
                        "result": "safe",
                        "induction_k": induction_k,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::ProbabilisticallySafe {
                    induction_k,
                    failure_probability,
                    committee_analyses,
                } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "Unbounded probabilistic safety proved (k = {induction_k}, failure <= {:.0e}).",
                        failure_probability
                    ),
                    json!({
                        "result": "probabilistically_safe",
                        "induction_k": induction_k,
                        "failure_probability": failure_probability,
                        "committee_count": committee_analyses.len(),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::Unsafe { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Unbounded safety violation found.",
                    json!({
                        "result": "unsafe",
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::NotProved { max_k, ref cti } => {
                    let summary = if let Some(witness) = cti {
                        format!(
                            "Unbounded proof did not close up to k = {max_k}; CTI available at k = {}.",
                            witness.k
                        )
                    } else {
                        format!("Unbounded proof did not close up to k = {max_k}.")
                    };
                    layer(
                        layer_name,
                        "unknown",
                        summary,
                        json!({
                            "result": "not_proved",
                            "max_k": max_k,
                            "cti": cti.as_ref().map(cti_details),
                            "abstractions": abstractions,
                        }),
                        output,
                    )
                }
                UnboundedSafetyResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Unbounded proof inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Unbounded safety proof failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

pub(crate) fn run_prove_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    engine: ProofEngine,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let cegar_iters = cfg.cegar_iters;
    let mut options_z3 = make_options(SolverChoice::Z3, cfg.k, cfg.timeout, cfg.soundness);
    options_z3.proof_engine = engine;
    let mut options_cvc5 = make_options(SolverChoice::Cvc5, cfg.k, cfg.timeout, cfg.soundness);
    options_cvc5.proof_engine = engine;

    let (z3_result, cvc5_result) = run_portfolio_workers(
        move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_safety_with_cegar(
                    &source_z3,
                    &filename_z3,
                    &options_z3,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_safety(&source_z3, &filename_z3, &options_z3)
            }
            .map_err(|e| e.to_string())
        },
        move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_safety_with_cegar(
                    &source_cvc5,
                    &filename_cvc5,
                    &options_cvc5,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_safety(&source_cvc5, &filename_cvc5, &options_cvc5)
            }
            .map_err(|e| e.to_string())
        },
    );

    let (result, details) = merge_portfolio_prove_results(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => layer(
            layer_name,
            "pass",
            format!("Unbounded safety proved (k = {induction_k})."),
            json!({
                "result": "safe",
                "induction_k": induction_k,
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => layer(
            layer_name,
            "pass",
            format!(
                "Unbounded probabilistic safety proved (k = {induction_k}, failure <= {:.0e}).",
                failure_probability
            ),
            json!({
                "result": "probabilistically_safe",
                "induction_k": induction_k,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len(),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::Unsafe { ref trace } => layer(
            layer_name,
            "fail",
            "Unbounded safety violation found.",
            json!({
                "result": "unsafe",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::NotProved { max_k, ref cti } => {
            let summary = if let Some(witness) = cti {
                format!(
                    "Unbounded proof did not close up to k = {max_k}; CTI available at k = {}.",
                    witness.k
                )
            } else {
                format!("Unbounded proof did not close up to k = {max_k}.")
            };
            layer(
                layer_name,
                "unknown",
                summary,
                json!({
                    "result": "not_proved",
                    "max_k": max_k,
                    "cti": cti.as_ref().map(cti_details),
                    "portfolio": details,
                }),
                output,
            )
        }
        UnboundedSafetyResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Unbounded proof inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

// ---------------------------------------------------------------------------
// Prove fair-liveness layers
// ---------------------------------------------------------------------------

pub(crate) fn run_prove_fair_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.k, cfg.timeout, cfg.soundness);
    let run = if cfg.cegar_iters > 0 {
        tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
            source,
            filename,
            &options,
            cfg.fairness,
            cfg.cegar_iters,
        )
    } else {
        tarsier_engine::pipeline::prove_fair_liveness_with_mode(
            source,
            filename,
            &options,
            cfg.fairness,
        )
    };
    match run {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            let fairness_name = fairness_name(cfg.fairness);
            let convergence = liveness_convergence_diagnostics(&result, Some(&diagnostics));
            match result {
                UnboundedFairLivenessResult::LiveProved { frame } => layer(
                    layer_name,
                    "pass",
                    format!("Unbounded {fairness_name}-fair liveness proved (frame = {frame})."),
                    json!({
                        "result": "live_proved",
                        "frame": frame,
                        "fairness": fairness_name,
                        "convergence": convergence.clone(),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::FairCycleFound {
                    depth,
                    loop_start,
                    ref trace,
                } => layer(
                    layer_name,
                    "fail",
                    format!(
                        "{fairness_name}-fair non-termination found: loop {loop_start} -> {depth}."
                    ),
                    json!({
                        "result": "fair_cycle_found",
                        "depth": depth,
                        "loop_start": loop_start,
                        "fairness": fairness_name,
                        "convergence": convergence.clone(),
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::NotProved { max_k } => layer(
                    layer_name,
                    "unknown",
                    format!("Unbounded fair-liveness proof did not converge up to frame {max_k}."),
                    json!({
                        "result": "not_proved",
                        "max_k": max_k,
                        "convergence": convergence.clone(),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Unbounded fair-liveness proof inconclusive.",
                    {
                        let payload = liveness_unknown_reason_payload(reason);
                        json!({
                            "result": "unknown",
                            "reason": payload["reason"],
                            "reason_code": payload["reason_code"],
                            "convergence": convergence.clone(),
                            "abstractions": abstractions,
                        })
                    },
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Unbounded fair-liveness proof failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

pub(crate) fn run_prove_fair_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let cegar_iters = cfg.cegar_iters;
    let options_z3 = make_options(SolverChoice::Z3, cfg.k, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.k, cfg.timeout, cfg.soundness);
    let fairness = cfg.fairness;

    let (z3_result, cvc5_result) = run_portfolio_workers(
        move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &source_z3,
                    &filename_z3,
                    &options_z3,
                    fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &source_z3,
                    &filename_z3,
                    &options_z3,
                    fairness,
                )
            }
            .map_err(|e| e.to_string())
        },
        move || {
            if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &source_cvc5,
                    &filename_cvc5,
                    &options_cvc5,
                    fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &source_cvc5,
                    &filename_cvc5,
                    &options_cvc5,
                    fairness,
                )
            }
            .map_err(|e| e.to_string())
        },
    );

    let (result, details) = merge_portfolio_prove_fair_results(z3_result, cvc5_result);
    let output = format!("{result}");
    let fairness_name = fairness_name(cfg.fairness);
    let convergence = liveness_convergence_diagnostics(&result, None);
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => layer(
            layer_name,
            "pass",
            format!("Unbounded {fairness_name}-fair liveness proved (frame = {frame})."),
            json!({
                "result": "live_proved",
                "frame": frame,
                "fairness": fairness_name,
                "convergence": convergence.clone(),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            ref trace,
        } => layer(
            layer_name,
            "fail",
            format!("{fairness_name}-fair non-termination found: loop {loop_start} -> {depth}."),
            json!({
                "result": "fair_cycle_found",
                "depth": depth,
                "loop_start": loop_start,
                "fairness": fairness_name,
                "convergence": convergence.clone(),
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::NotProved { max_k } => layer(
            layer_name,
            "unknown",
            format!("Unbounded fair-liveness proof did not converge up to frame {max_k}."),
            json!({
                "result": "not_proved",
                "max_k": max_k,
                "convergence": convergence.clone(),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Unbounded fair-liveness proof inconclusive.",
            {
                let payload = liveness_unknown_reason_payload(reason);
                json!({
                    "result": "unknown",
                    "reason": payload["reason"],
                    "reason_code": payload["reason_code"],
                    "convergence": convergence.clone(),
                    "portfolio": details,
                })
            },
            output,
        ),
    }
}

// ---------------------------------------------------------------------------
// Communication complexity layer
// ---------------------------------------------------------------------------

pub(crate) fn run_comm_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    depth: usize,
) -> AnalysisLayerReport {
    match tarsier_engine::pipeline::comm_complexity(source, filename, depth) {
        Ok(report) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let mut details = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("abstractions".to_string(), abstractions);
            }
            layer(
                layer_name,
                "pass",
                "Computed communication complexity bounds.",
                details,
                format!("{report}"),
            )
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Communication complexity analysis failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Overall status
// ---------------------------------------------------------------------------

pub(crate) fn overall_status(mode: AnalysisMode, layers: &[AnalysisLayerReport]) -> String {
    let has_fail = layers
        .iter()
        .any(|l| l.status == "fail" || l.status == "error");
    if has_fail {
        return "fail".to_string();
    }

    let has_unknown = layers.iter().any(|l| l.status == "unknown");
    match mode {
        AnalysisMode::Quick | AnalysisMode::Standard => {
            if has_unknown {
                "unknown".to_string()
            } else {
                "pass".to_string()
            }
        }
        AnalysisMode::Proof | AnalysisMode::Audit => {
            if has_unknown {
                "fail".to_string()
            } else {
                "pass".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interpretation helpers
// ---------------------------------------------------------------------------

pub(crate) fn is_safety_interpretation_layer(layer: &str) -> bool {
    layer.starts_with("verify")
        || (layer.starts_with("prove[") && !layer.starts_with("prove[fair"))
        || layer.starts_with("certify[safety]")
}

pub(crate) fn is_liveness_interpretation_layer(layer: &str) -> bool {
    layer.starts_with("liveness[")
        || layer.starts_with("prove[fair")
        || layer.starts_with("certify[fair_liveness]")
}

pub(crate) fn compute_analysis_interpretation(
    layers: &[AnalysisLayerReport],
    overall: &str,
) -> AnalysisInterpretation {
    let safety_layers: Vec<&AnalysisLayerReport> = layers
        .iter()
        .filter(|l| is_safety_interpretation_layer(&l.layer))
        .collect();
    let liveness_layers: Vec<&AnalysisLayerReport> = layers
        .iter()
        .filter(|l| is_liveness_interpretation_layer(&l.layer))
        .collect();

    let safety = if safety_layers.is_empty() {
        "NOT_CHECKED"
    } else if safety_layers.iter().any(|l| l.verdict == "UNSAFE") {
        "UNSAFE"
    } else if safety_layers.iter().any(|l| l.verdict == "SAFE") {
        "SAFE"
    } else {
        "UNKNOWN"
    };

    let liveness = if liveness_layers.is_empty() {
        "NOT_CHECKED"
    } else if liveness_layers.iter().any(|l| l.verdict == "LIVE_CEX") {
        "LIVE_CEX"
    } else if liveness_layers.iter().any(|l| l.verdict == "LIVE_PROVED") {
        "LIVE_PROVED"
    } else {
        "UNKNOWN"
    };

    let summary = match (safety, liveness) {
        ("UNSAFE", _) => "Safety violation found (counterexample exists).".to_string(),
        (_, "LIVE_CEX") => {
            "Liveness violation found (non-terminating/fair cycle trace exists).".to_string()
        }
        ("SAFE", "LIVE_PROVED") => "Safety and liveness hold in this analysis scope.".to_string(),
        ("SAFE", "UNKNOWN") => {
            "Safety holds in this analysis scope; liveness is inconclusive.".to_string()
        }
        ("SAFE", "NOT_CHECKED") => {
            "Safety holds in this analysis scope; liveness was not checked.".to_string()
        }
        ("UNKNOWN", "LIVE_PROVED") => {
            "Liveness holds in this analysis scope; safety is inconclusive.".to_string()
        }
        ("UNKNOWN", "UNKNOWN") => {
            "Both safety and liveness are inconclusive in this run.".to_string()
        }
        ("NOT_CHECKED", "NOT_CHECKED") => {
            "No safety/liveness property checks were executed in this run.".to_string()
        }
        _ => "Property interpretation requires deeper follow-up for this run.".to_string(),
    };

    let overall_status_meaning = if overall == "pass" {
        "overall=pass means all scheduled layers completed without failures for the selected mode."
            .to_string()
    } else {
        "overall reflects pipeline completion for the selected mode; rely on safety/liveness above for the property-level result."
            .to_string()
    };

    AnalysisInterpretation {
        safety: safety.to_string(),
        liveness: liveness.to_string(),
        summary,
        overall_status_meaning,
    }
}

// ---------------------------------------------------------------------------
// Certification layers (audit mode)
// ---------------------------------------------------------------------------

/// V2-01: Run safety certification as an analysis layer.
pub(crate) fn run_certify_safety_layer(
    source: &str,
    filename: &str,
    cfg: &LayerRunCfg,
    cert_out_dir: Option<&Path>,
) -> AnalysisLayerReport {
    let options = PipelineOptions {
        solver: cfg.solver,
        max_depth: cfg.k,
        timeout_secs: cfg.timeout,
        dump_smt: None,
        soundness: cfg.soundness,
        proof_engine: ProofEngine::Pdr,
    };
    match tarsier_engine::pipeline::generate_safety_certificate(source, filename, &options) {
        Ok(cert) => {
            let bundle = certificate_bundle_from_safety(&cert);
            let out_dir = cert_out_dir
                .map(|d| d.join("safety-cert"))
                .unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("tarsier-safety-cert-{}", std::process::id()))
                });
            match write_certificate_bundle_quiet(&out_dir, &bundle) {
                Ok(()) => match check_bundle_integrity(&out_dir) {
                    Ok(integrity) => {
                        let integrity_ok = integrity.issues.is_empty();
                        let issues: Vec<String> =
                            integrity.issues.iter().map(|i| i.message.clone()).collect();
                        layer(
                            "certify[safety]",
                            if integrity_ok { "pass" } else { "fail" },
                            if integrity_ok {
                                "Safety certificate generated and verified."
                            } else {
                                "Safety certificate generated but integrity check failed."
                            },
                            json!({
                                "bundle_dir": out_dir.display().to_string(),
                                "integrity_ok": integrity_ok,
                                "integrity_issues": issues,
                            }),
                            if integrity_ok { "SAFE" } else { "INCONCLUSIVE" },
                        )
                    }
                    Err(e) => layer(
                        "certify[safety]",
                        "fail",
                        "Integrity check failed to run.",
                        json!({"error": e.to_string(), "bundle_dir": out_dir.display().to_string()}),
                        "INCONCLUSIVE",
                    ),
                },
                Err(e) => layer(
                    "certify[safety]",
                    "error",
                    "Failed to write safety certificate bundle.",
                    json!({"error": e.to_string()}),
                    "INCONCLUSIVE",
                ),
            }
        }
        Err(e) => layer(
            "certify[safety]",
            "fail",
            "Safety certificate generation failed.",
            json!({"error": e.to_string()}),
            "INCONCLUSIVE",
        ),
    }
}

/// V2-01: Run fair-liveness certification as an analysis layer.
pub(crate) fn run_certify_fair_liveness_layer(
    source: &str,
    filename: &str,
    cfg: &LayerRunCfg,
    cert_out_dir: Option<&Path>,
) -> AnalysisLayerReport {
    let options = PipelineOptions {
        solver: cfg.solver,
        max_depth: cfg.k,
        timeout_secs: cfg.timeout,
        dump_smt: None,
        soundness: cfg.soundness,
        proof_engine: ProofEngine::Pdr,
    };
    match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        source,
        filename,
        &options,
        cfg.fairness,
    ) {
        Ok(cert) => {
            let mut obligations_checked: Vec<String> =
                cert.obligations.iter().map(|o| o.name.clone()).collect();
            obligations_checked.sort();
            let obligation_count = obligations_checked.len();
            let bundle = certificate_bundle_from_fair_liveness(&cert);
            let out_dir = cert_out_dir
                .map(|d| d.join("fair-liveness-cert"))
                .unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("tarsier-fair-cert-{}", std::process::id()))
                });
            match write_certificate_bundle_quiet(&out_dir, &bundle) {
                Ok(()) => match check_bundle_integrity(&out_dir) {
                    Ok(integrity) => {
                        let integrity_ok = integrity.issues.is_empty();
                        let issues: Vec<String> =
                            integrity.issues.iter().map(|i| i.message.clone()).collect();
                        layer(
                            "certify[fair_liveness]",
                            if integrity_ok { "pass" } else { "fail" },
                            if integrity_ok {
                                "Fair-liveness certificate generated and verified."
                            } else {
                                "Fair-liveness certificate generated but integrity check failed."
                            },
                            json!({
                                "bundle_dir": out_dir.display().to_string(),
                                "integrity_ok": integrity_ok,
                                "integrity_issues": issues,
                                "fairness_model": fairness_semantics_json(cert.fairness),
                                "obligation_count": obligation_count,
                                "obligations_checked": obligations_checked,
                            }),
                            if integrity_ok {
                                "LIVE_PROVED"
                            } else {
                                "INCONCLUSIVE"
                            },
                        )
                    }
                    Err(e) => layer(
                        "certify[fair_liveness]",
                        "fail",
                        "Integrity check failed to run.",
                        json!({"error": e.to_string(), "bundle_dir": out_dir.display().to_string()}),
                        "INCONCLUSIVE",
                    ),
                },
                Err(e) => layer(
                    "certify[fair_liveness]",
                    "error",
                    "Failed to write fair-liveness certificate bundle.",
                    json!({"error": e.to_string()}),
                    "INCONCLUSIVE",
                ),
            }
        }
        Err(e) => layer(
            "certify[fair_liveness]",
            "fail",
            "Fair-liveness certificate generation failed.",
            json!({"error": e.to_string()}),
            "INCONCLUSIVE",
        ),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render_analysis_text(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str("ANALYSIS REPORT\n");
    out.push_str(&format!("Mode: {}\n", report.mode));
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!("Verdict: {}\n", report.overall_verdict));
    out.push_str(&format!("Confidence: {}\n", report.confidence_tier));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str("Interpretation:\n");
    out.push_str(&format!("  Safety: {}\n", report.interpretation.safety));
    out.push_str(&format!("  Liveness: {}\n", report.interpretation.liveness));
    out.push_str(&format!("  Summary: {}\n", report.interpretation.summary));
    out.push_str(&format!(
        "  Note: {}\n",
        report.interpretation.overall_status_meaning
    ));

    // Model fidelity warnings (V1-10: hard-visible, not buried in logs)
    let nf_status = report
        .network_faithfulness
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let nf_summary = report
        .network_faithfulness
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("No network faithfulness summary.");
    if nf_status != "faithful" {
        out.push_str(&format!(
            "\n*** MODEL FIDELITY WARNING: [{}] {} ***\n",
            nf_status.to_uppercase(),
            nf_summary
        ));
    } else {
        out.push_str("Network Faithfulness:\n");
        out.push_str(&format!(
            "- [{}] {}\n",
            nf_status.to_uppercase(),
            nf_summary
        ));
    }
    if let Some(assumptions) = report
        .network_faithfulness
        .get("assumptions_enforced")
        .and_then(Value::as_array)
    {
        for item in assumptions.iter().filter_map(Value::as_str) {
            out.push_str(&format!("  - {item}\n"));
        }
    }

    if let Some(governance) = &report.liveness_governance {
        let fairness_mode = governance
            .get("fairness_model")
            .and_then(|v| v.get("mode"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let timing_model = governance
            .get("gst_assumptions")
            .and_then(|v| v.get("timing_model"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let gst_parameter = governance
            .get("gst_assumptions")
            .and_then(|v| v.get("gst_parameter"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        let obligation_count = governance
            .get("obligations_checked")
            .and_then(|v| v.get("total_obligations_checked"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        out.push_str("\nLiveness Governance:\n");
        out.push_str(&format!("  - fairness model: {fairness_mode}\n"));
        out.push_str(&format!("  - timing model: {timing_model}\n"));
        out.push_str(&format!("  - gst parameter: {gst_parameter}\n"));
        out.push_str(&format!("  - obligations checked: {obligation_count}\n"));
    }

    if !report.preflight_warnings.is_empty() {
        out.push_str("\nPreflight Warnings:\n");
        for w in &report.preflight_warnings {
            let code = w.get("code").and_then(Value::as_str).unwrap_or("unknown");
            let msg = w.get("message").and_then(Value::as_str).unwrap_or("");
            let hint = w.get("hint").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  [{code}] {msg}\n"));
            if !hint.is_empty() {
                out.push_str(&format!("    Hint: {hint}\n"));
            }
        }
    }

    out.push_str("\nLayers:\n");
    for layer in &report.layers {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            layer.verdict, layer.layer, layer.summary
        ));
        // V2-07: Render fragment diagnostics prominently
        if let Some(diags) = layer
            .details
            .get("fragment_diagnostics")
            .and_then(Value::as_array)
        {
            out.push_str("  *** UNSUPPORTED PROPERTY SHAPE ***\n");
            for d in diags {
                let prop = d.get("property").and_then(Value::as_str).unwrap_or("?");
                let msg = d.get("message").and_then(Value::as_str).unwrap_or("");
                let hint = d.get("hint").and_then(Value::as_str);
                out.push_str(&format!("  property '{prop}': {msg}\n"));
                if let Some(h) = hint {
                    out.push_str(&format!("    Hint: {h}\n"));
                }
            }
        }
    }

    // V1-06: Claim statement block
    if let Some(claim) = &report.claim {
        out.push_str("\nWhat was proven:\n");
        for item in &claim.proven {
            out.push_str(&format!("  + {item}\n"));
        }
        out.push_str("Assumptions:\n");
        for item in &claim.assumptions {
            out.push_str(&format!("  * {item}\n"));
        }
        out.push_str("Not covered:\n");
        for item in &claim.not_covered {
            out.push_str(&format!("  - {item}\n"));
        }
    }

    // V1-07: Next-action recommendation
    if let Some(next) = &report.next_action {
        out.push_str(&format!(
            "\nRecommended next step:\n  $ tarsier {}\n  ({})\n",
            next.command, next.reason
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// Verdict / confidence / claim / next-action
// ---------------------------------------------------------------------------

/// Compute overall canonical verdict from analysis layers.
pub(crate) fn compute_overall_verdict(layers: &[AnalysisLayerReport]) -> CanonicalVerdict {
    let mut has_unsafe = false;
    let mut has_live_cex = false;
    let mut has_inconclusive = false;
    let mut has_unknown = false;
    let mut has_safe = false;
    let mut has_live_proved = false;

    for layer in layers {
        match layer.verdict.as_str() {
            "UNSAFE" => has_unsafe = true,
            "LIVE_CEX" => has_live_cex = true,
            "INCONCLUSIVE" => has_inconclusive = true,
            "UNKNOWN" => has_unknown = true,
            "SAFE" => has_safe = true,
            "LIVE_PROVED" => has_live_proved = true,
            _ => {}
        }
    }

    if has_unsafe {
        CanonicalVerdict::Unsafe
    } else if has_live_cex {
        CanonicalVerdict::LiveCex
    } else if has_inconclusive {
        CanonicalVerdict::Inconclusive
    } else if has_unknown {
        CanonicalVerdict::Unknown
    } else if has_safe || has_live_proved {
        CanonicalVerdict::Safe
    } else {
        CanonicalVerdict::Unknown
    }
}

/// V2-03: Compute confidence tier from analysis mode and layer results.
pub(crate) fn compute_confidence_tier(
    mode: AnalysisMode,
    layers: &[AnalysisLayerReport],
) -> String {
    match mode {
        AnalysisMode::Quick => "quick".to_string(),
        AnalysisMode::Standard => {
            let has_passing_prove = layers.iter().any(|l| {
                l.layer.starts_with("prove[") && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
            });
            if has_passing_prove {
                "proof".to_string()
            } else {
                "bounded".to_string()
            }
        }
        AnalysisMode::Proof => {
            let has_passing_prove = layers.iter().any(|l| {
                l.layer.starts_with("prove[") && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
            });
            if has_passing_prove {
                "proof".to_string()
            } else {
                "bounded".to_string()
            }
        }
        AnalysisMode::Audit => {
            let cert_layers: Vec<_> = layers
                .iter()
                .filter(|l| l.layer.starts_with("certify["))
                .collect();
            let has_cert_layers = !cert_layers.is_empty();
            let all_cert_pass = has_cert_layers && cert_layers.iter().all(|l| l.status == "pass");
            if all_cert_pass {
                "certified".to_string()
            } else {
                let has_passing_prove = layers.iter().any(|l| {
                    l.layer.starts_with("prove[")
                        && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
                });
                if has_passing_prove {
                    "proof".to_string()
                } else {
                    "bounded".to_string()
                }
            }
        }
    }
}

/// V1-06: Build claim statement from analysis layers.
pub(crate) fn build_claim_statement(
    layers: &[AnalysisLayerReport],
    network_faithfulness: &Value,
    mode: &str,
    preflight_warnings: &[Value],
) -> ClaimStatement {
    let mut proven = Vec::new();
    let mut assumptions = Vec::new();
    let mut not_covered = Vec::new();

    // Collect what was proven
    for layer in layers {
        match layer.verdict.as_str() {
            "SAFE" => {
                if layer.layer.contains("prove") {
                    proven.push(format!("Safety: unbounded proof via {}", layer.layer));
                } else {
                    proven.push(format!("Safety: bounded check via {}", layer.layer));
                }
            }
            "LIVE_PROVED" => {
                if layer.layer.contains("prove") {
                    proven.push(format!("Liveness: unbounded proof via {}", layer.layer));
                } else {
                    proven.push(format!("Liveness: bounded check via {}", layer.layer));
                }
            }
            _ => {}
        }
    }

    if proven.is_empty() {
        proven.push("No properties were proven in this run.".to_string());
    }

    // Assumptions
    assumptions.push(
        "Threshold automaton counter abstraction is sound for the modeled protocol.".to_string(),
    );
    let nf_status = network_faithfulness
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if nf_status != "faithful" {
        assumptions.push(format!(
            "Network model: {} (not fully faithful -- results may be optimistic).",
            nf_status
        ));
    } else {
        assumptions.push("Network model: faithful semantics enforced.".to_string());
    }

    // V2-04: Surface preflight warnings in assumptions
    for w in preflight_warnings {
        if let Some(msg) = w.get("message").and_then(Value::as_str) {
            assumptions.push(format!("Preflight: {msg}"));
        }
    }

    // Not covered
    let has_liveness = layers
        .iter()
        .any(|l| l.layer.contains("liveness") || l.layer.contains("fair"));
    let has_safety = layers.iter().any(|l| {
        l.layer.contains("verify") || l.layer.contains("prove[k") || l.layer.contains("prove[pdr")
    });
    let has_proof = layers.iter().any(|l| l.layer.contains("prove"));

    if !has_liveness {
        not_covered.push("Liveness properties (not checked in this mode).".to_string());
    }
    if !has_safety {
        not_covered.push("Safety properties (not checked in this mode).".to_string());
    }
    if !has_proof && mode != "proof" && mode != "audit" {
        not_covered.push(
            "Unbounded proofs (use --mode proof or --goal safety for unbounded verification)."
                .to_string(),
        );
    }
    not_covered
        .push("Implementation bugs not captured by the threshold automaton model.".to_string());

    ClaimStatement {
        proven,
        assumptions,
        not_covered,
    }
}

/// V1-07: Build next-action recommendation from analysis results.
pub(crate) fn build_next_action(
    layers: &[AnalysisLayerReport],
    filename: &str,
    mode: &str,
) -> Option<NextAction> {
    let has_unsafe = layers.iter().any(|l| l.verdict == "UNSAFE");
    let has_live_cex = layers.iter().any(|l| l.verdict == "LIVE_CEX");
    let has_inconclusive = layers.iter().any(|l| l.verdict == "INCONCLUSIVE");
    let has_unknown = layers.iter().any(|l| l.verdict == "UNKNOWN");
    let has_proof = layers.iter().any(|l| l.layer.contains("prove"));
    let all_pass = !has_unsafe && !has_live_cex && !has_inconclusive && !has_unknown;

    if has_unsafe {
        return Some(NextAction {
            command: format!("visualize {filename} --check verify"),
            reason: "A counterexample was found. Visualize the trace to understand the bug."
                .to_string(),
        });
    }

    if has_live_cex {
        return Some(NextAction {
            command: format!("visualize {filename} --check fair-liveness"),
            reason: "A liveness counterexample was found. Visualize the trace to debug."
                .to_string(),
        });
    }

    if has_inconclusive && !has_proof {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof"),
            reason: "Bounded checks passed but unbounded proof was not attempted. Upgrade to proof mode.".to_string(),
        });
    }

    if has_inconclusive && has_proof {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof --depth 16 --k 20"),
            reason: "Proof did not converge. Try with increased depth and k bounds.".to_string(),
        });
    }

    if has_unknown {
        return Some(NextAction {
            command: format!("analyze {filename} --mode standard --timeout 600"),
            reason: "Some checks were inconclusive. Try with a longer timeout.".to_string(),
        });
    }

    if all_pass && mode == "quick" {
        return Some(NextAction {
            command: format!("analyze {filename} --mode standard"),
            reason: "Quick check passed. Run standard mode for full coverage.".to_string(),
        });
    }

    if all_pass && mode == "standard" {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof"),
            reason: "Standard checks passed. Run proof mode for unbounded guarantees.".to_string(),
        });
    }

    if all_pass && (mode == "proof" || mode == "audit") {
        return Some(NextAction {
            command: format!("certify-safety {filename} --out cert/"),
            reason: "All checks passed. Generate a proof certificate for independent verification."
                .to_string(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Analysis orchestrator
// ---------------------------------------------------------------------------

pub(crate) fn run_analysis(
    source: &str,
    filename: &str,
    mode: AnalysisMode,
    cfg: LayerRunCfg,
    network_mode: CliNetworkSemanticsMode,
    cert_out_dir: Option<&Path>,
    por_mode: &str,
) -> AnalysisReport {
    let mut layers = Vec::new();
    let network_faithfulness =
        network_faithfulness_section(source, filename, network_mode, cfg.soundness);
    let verify_cegar_iters = match mode {
        AnalysisMode::Quick => 1,
        AnalysisMode::Standard => 2,
        AnalysisMode::Proof => 2,
        AnalysisMode::Audit => 3,
    };
    let proof_cegar_iters = match mode {
        AnalysisMode::Proof => cfg.cegar_iters.max(2),
        AnalysisMode::Audit => cfg.cegar_iters.max(3),
        _ => cfg.cegar_iters,
    };

    layers.push(run_parse_layer(source, filename));

    // V2-04: Preflight model completeness warnings
    let preflight_warnings: Vec<Value> =
        if let Ok(program) = tarsier_engine::pipeline::parse(source, filename) {
            tarsier_engine::pipeline::completeness_preflight(&program)
                .into_iter()
                .map(|w| json!({"code": w.code, "message": w.message, "hint": w.hint}))
                .collect()
        } else {
            Vec::new()
        };

    let quick_depth = cfg.depth.min(4);
    match mode {
        AnalysisMode::Quick => {
            let quick_cfg = LayerRunCfg {
                depth: quick_depth,
                ..cfg
            };
            if quick_cfg.portfolio {
                layers.push(run_verify_layer_portfolio(
                    source,
                    filename,
                    "verify[quick]",
                    quick_cfg,
                    verify_cegar_iters,
                ));
            } else {
                layers.push(run_verify_layer(
                    source,
                    filename,
                    "verify[quick]",
                    quick_cfg,
                    verify_cegar_iters,
                ));
            }
        }
        AnalysisMode::Standard | AnalysisMode::Proof | AnalysisMode::Audit => {
            if cfg.portfolio {
                layers.push(run_verify_layer_portfolio(
                    source,
                    filename,
                    "verify",
                    cfg,
                    verify_cegar_iters,
                ));
                layers.push(run_liveness_layer_portfolio(
                    source,
                    filename,
                    "liveness[bounded]",
                    cfg,
                ));
                layers.push(run_fair_liveness_layer_portfolio(
                    source,
                    filename,
                    "liveness[fair_lasso]",
                    cfg,
                ));
            } else {
                layers.push(run_verify_layer(
                    source,
                    filename,
                    "verify",
                    cfg,
                    verify_cegar_iters,
                ));
                layers.push(run_liveness_layer(
                    source,
                    filename,
                    "liveness[bounded]",
                    cfg.solver,
                    cfg.depth,
                    cfg.timeout,
                    cfg.soundness,
                ));
                layers.push(run_fair_liveness_layer(
                    source,
                    filename,
                    "liveness[fair_lasso]",
                    cfg,
                ));
            }
            layers.push(run_comm_layer(source, filename, "comm", cfg.depth));
        }
    }

    if matches!(mode, AnalysisMode::Proof | AnalysisMode::Audit) {
        let proof_cfg = LayerRunCfg {
            cegar_iters: proof_cegar_iters,
            ..cfg
        };
        if cfg.portfolio {
            layers.push(run_prove_layer_portfolio(
                source,
                filename,
                "prove[kinduction]",
                proof_cfg,
                ProofEngine::KInduction,
            ));
            layers.push(run_prove_layer_portfolio(
                source,
                filename,
                "prove[pdr]",
                proof_cfg,
                ProofEngine::Pdr,
            ));
            layers.push(run_prove_fair_layer_portfolio(
                source,
                filename,
                "prove[fair_pdr]",
                proof_cfg,
            ));
        } else {
            layers.push(run_prove_layer(
                source,
                filename,
                "prove[kinduction]",
                proof_cfg,
                ProofEngine::KInduction,
            ));
            layers.push(run_prove_layer(
                source,
                filename,
                "prove[pdr]",
                proof_cfg,
                ProofEngine::Pdr,
            ));
            layers.push(run_prove_fair_layer(
                source,
                filename,
                "prove[fair_pdr]",
                proof_cfg,
            ));
        }
    }

    if matches!(mode, AnalysisMode::Audit) && !cfg.portfolio {
        let secondary = match cfg.solver {
            SolverChoice::Z3 => SolverChoice::Cvc5,
            SolverChoice::Cvc5 => SolverChoice::Z3,
        };
        let suffix = format!("[{}]", solver_name(secondary));
        let secondary_cfg = LayerRunCfg {
            solver: secondary,
            cegar_iters: proof_cegar_iters,
            ..cfg
        };

        layers.push(run_verify_layer(
            source,
            filename,
            &format!("verify{suffix}"),
            secondary_cfg,
            verify_cegar_iters,
        ));
        layers.push(run_fair_liveness_layer(
            source,
            filename,
            &format!("liveness[fair_lasso]{suffix}"),
            secondary_cfg,
        ));
        layers.push(run_prove_layer(
            source,
            filename,
            &format!("prove[pdr]{suffix}"),
            secondary_cfg,
            ProofEngine::Pdr,
        ));
        layers.push(run_prove_fair_layer(
            source,
            filename,
            &format!("prove[fair_pdr]{suffix}"),
            secondary_cfg,
        ));
    }

    // V2-01: Release certification layers (audit mode only)
    if matches!(mode, AnalysisMode::Audit) {
        let safety_passed = layers.iter().any(|l| {
            l.layer.starts_with("prove[") && !l.layer.contains("fair") && l.verdict == "SAFE"
        });
        let fair_passed = layers.iter().any(|l| {
            l.layer.contains("fair") && l.layer.starts_with("prove[") && l.verdict == "LIVE_PROVED"
        });
        if safety_passed {
            layers.push(run_certify_safety_layer(
                source,
                filename,
                &cfg,
                cert_out_dir,
            ));
        }
        if fair_passed {
            layers.push(run_certify_fair_liveness_layer(
                source,
                filename,
                &cfg,
                cert_out_dir,
            ));
        }
    }

    let overall = overall_status(mode, &layers);
    let overall_verdict = compute_overall_verdict(&layers);
    let interpretation = compute_analysis_interpretation(&layers, &overall);
    let mode_str = match mode {
        AnalysisMode::Quick => "quick",
        AnalysisMode::Standard => "standard",
        AnalysisMode::Proof => "proof",
        AnalysisMode::Audit => "audit",
    };
    let confidence_tier = compute_confidence_tier(mode, &layers);
    let claim = build_claim_statement(
        &layers,
        &network_faithfulness,
        mode_str,
        &preflight_warnings,
    );
    let next_action = build_next_action(&layers, filename, mode_str);
    let liveness_governance = if matches!(mode, AnalysisMode::Proof | AnalysisMode::Audit) {
        Some(build_liveness_governance_report(
            source,
            filename,
            cfg.fairness,
            &layers,
        ))
    } else {
        None
    };

    AnalysisReport {
        schema_version: "v1".to_string(),
        mode: mode_str.to_string(),
        file: filename.to_string(),
        config: AnalysisConfig {
            solver: solver_name(cfg.solver).to_string(),
            depth: cfg.depth,
            k: cfg.k,
            timeout_secs: cfg.timeout,
            soundness: match cfg.soundness {
                SoundnessMode::Strict => "strict",
                SoundnessMode::Permissive => "permissive",
            }
            .to_string(),
            fairness: fairness_name(cfg.fairness).to_string(),
            portfolio: cfg.portfolio,
            por_mode: por_mode.to_string(),
        },
        network_faithfulness,
        liveness_governance,
        layers,
        overall,
        overall_verdict: overall_verdict.as_str().to_string(),
        interpretation,
        claim: Some(claim),
        next_action,
        confidence_tier,
        preflight_warnings,
    }
}

// ---------------------------------------------------------------------------
// Command handler (extracted from Commands::Analyze match arm)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_analyze_command(
    file: &std::path::Path,
    goal: Option<String>,
    profile: &str,
    advanced: bool,
    mode: Option<String>,
    solver: Option<String>,
    depth: Option<usize>,
    k: Option<usize>,
    timeout: Option<u64>,
    soundness: Option<String>,
    fairness: Option<String>,
    portfolio: bool,
    format: &str,
    report_out: Option<&std::path::Path>,
    cli_network_mode: CliNetworkSemanticsMode,
    por_mode: &str,
) -> miette::Result<()> {
    let source = sandbox_read_source(file)?;
    let filename = file.display().to_string();

    // V1-04: Advanced gating -- reject low-level knobs in beginner profile
    let is_beginner = profile == "beginner";
    if is_beginner && !advanced {
        let advanced_flags_used: Vec<&str> = [
            mode.as_deref().map(|_| "--mode"),
            solver.as_deref().map(|_| "--solver"),
            depth.map(|_| "--depth"),
            k.map(|_| "--k"),
            timeout.map(|_| "--timeout"),
            soundness.as_deref().map(|_| "--soundness"),
            fairness.as_deref().map(|_| "--fairness"),
        ]
        .into_iter()
        .flatten()
        .collect();

        if !advanced_flags_used.is_empty() {
            eprintln!(
                "Error: {} {} advanced-only in beginner profile.",
                advanced_flags_used.join(", "),
                if advanced_flags_used.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            );
            eprintln!("Hint: Use --advanced to unlock, or use --profile pro for full control.");
            eprintln!(
                "Example: tarsier analyze {} --advanced --depth 20",
                file.display()
            );
            std::process::exit(1);
        }
    }

    // V2-06: release-gate profile forces goal=release if none specified
    let goal = if profile == "release-gate" && goal.is_none() {
        Some("release".to_string())
    } else {
        goal
    };

    // V1-02: Resolve goal -> mode mapping
    let effective_mode_str = if let Some(ref goal_str) = goal {
        match goal_str.as_str() {
            "bughunt" => "quick",
            "safety" => "proof",
            "safety+liveness" => "proof",
            "release" => "audit",
            other => {
                eprintln!("Error: unknown goal '{other}'. Valid goals: bughunt, safety, safety+liveness, release");
                std::process::exit(1);
            }
        }
        .to_string()
    } else {
        mode.unwrap_or_else(|| {
            // V1-08/V2-06: Profile-based default modes
            match profile {
                "beginner" => "standard".to_string(),
                "governance" => "audit".to_string(),
                "ci-fast" => "quick".to_string(),
                "ci-proof" => "proof".to_string(),
                "release-gate" => "audit".to_string(),
                _ => "standard".to_string(),
            }
        })
    };

    // V1-03/08/V2-06: Resolve profile -> defaults
    let (
        default_depth,
        default_k,
        default_timeout,
        default_soundness,
        default_fairness,
        default_solver,
    ) = match profile {
        "beginner" => (6_usize, 10_usize, 120_u64, "strict", "weak", "z3"),
        "governance" => (10, 12, 300, "strict", "weak", "z3"),
        "ci-fast" => (4, 6, 60, "strict", "weak", "z3"),
        "ci-proof" => (10, 12, 300, "strict", "weak", "z3"),
        "release-gate" => (12, 14, 600, "strict", "weak", "z3"),
        _ => (10, 12, 300, "strict", "weak", "z3"),
    };

    let eff_mode = parse_analysis_mode(&effective_mode_str);
    let eff_solver = parse_solver_choice(solver.as_deref().unwrap_or(default_solver));
    let eff_soundness = parse_soundness_mode(soundness.as_deref().unwrap_or(default_soundness));
    validate_cli_network_semantics_mode(&source, &filename, eff_soundness, cli_network_mode)?;
    let eff_fairness = parse_fairness_mode(fairness.as_deref().unwrap_or(default_fairness));
    let output_format = parse_output_format(format);
    let cfg = LayerRunCfg {
        solver: eff_solver,
        depth: depth.unwrap_or(default_depth),
        k: k.unwrap_or(default_k),
        timeout: timeout.unwrap_or(default_timeout),
        soundness: eff_soundness,
        fairness: eff_fairness,
        cegar_iters: 0,
        portfolio: portfolio || profile == "release-gate",
    };

    // V2-01: Derive cert output directory from report_out path
    let cert_dir = report_out.and_then(|p| p.parent()).map(Path::to_path_buf);
    let report = run_analysis(
        &source,
        &filename,
        eff_mode,
        cfg,
        cli_network_mode,
        cert_dir.as_deref(),
        por_mode,
    );

    let json_report = serde_json::to_string_pretty(&report).into_diagnostic()?;
    if let Some(path) = report_out {
        std::fs::write(path, &json_report).into_diagnostic()?;
    }

    // V2-08: Governance bundle for release/governance/release-gate profiles
    #[cfg(feature = "governance")]
    {
        let is_release_goal = goal.as_deref() == Some("release");
        let is_gov_profile = matches!(profile, "governance" | "release-gate");
        if is_release_goal || is_gov_profile {
            if let Some(ro_path) = report_out {
                let gov_bundle =
                    crate::build_governance_bundle(&report, &source, ro_path, &json_report)?;
                let gov_json = serde_json::to_string_pretty(&gov_bundle).into_diagnostic()?;
                let gov_path = ro_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("governance-bundle.json");
                std::fs::write(&gov_path, &gov_json).into_diagnostic()?;
            }
        }
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_analysis_text(&report)),
        OutputFormat::Json => println!("{json_report}"),
    }

    if report.overall != "pass" {
        std::process::exit(2);
    }

    Ok(())
}
