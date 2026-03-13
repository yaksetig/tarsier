use std::path::Path;

use serde_json::{json, Value};

use tarsier_engine::pipeline::{
    take_run_diagnostics, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{
    FairLivenessResult, LivenessResult, UnboundedFairLivenessResult, UnboundedSafetyResult,
    VerificationResult,
};
use tarsier_proof_kernel::check_bundle_integrity;

use crate::commands::helpers::make_options;
use crate::{
    canonical_verdict_from_layer_result, cegar_report_details,
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety, cti_details,
    fairness_name, fairness_semantics_json, liveness_convergence_diagnostics,
    liveness_unknown_reason_payload, merge_portfolio_fair_liveness_results,
    merge_portfolio_liveness_results, merge_portfolio_prove_fair_results,
    merge_portfolio_prove_results, merge_portfolio_verify_reports, run_diagnostics_details,
    trace_details, AnalysisLayerReport, LayerRunCfg,
};

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
            match crate::write_certificate_bundle_quiet(&out_dir, &bundle) {
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
            match crate::write_certificate_bundle_quiet(&out_dir, &bundle) {
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
