// Prove execution branches and portfolio helpers.

use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{PipelineOptions, SolverChoice};
use tarsier_engine::result::{UnboundedFairLivenessResult, UnboundedSafetyResult};

use crate::{
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety,
    merge_portfolio_prove_fair_results, merge_portfolio_prove_results, proof_engine_name,
    render_fallback_summary, render_optimization_summary, render_phase_profile_summary,
    run_diagnostics_details, unbounded_fair_cegar_report_details, unbounded_fair_result_details,
    unbounded_fair_result_kind, unbounded_safety_cegar_report_details,
    unbounded_safety_result_details, unbounded_safety_result_kind, write_certificate_bundle,
    write_json_artifact, OutputFormat,
};

use super::helpers::fairness_name;
use super::types::ProveExecutionConfig;

pub(super) fn run_prove_fair_liveness_branch(
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
pub(super) fn run_prove_safety_portfolio(
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
pub(super) fn run_prove_safety_single(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    cert_out: Option<PathBuf>,
    cegar_iters: usize,
    cegar_report_out: Option<PathBuf>,
    output_format: OutputFormat,
) -> miette::Result<()> {
    let mut cegar_artifact: Option<Value> = None;
    let result = if let Some(_report_path) = cegar_report_out.clone() {
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
        cegar_artifact = Some(artifact);
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
    if let Some(path) = cegar_report_out.as_ref() {
        let artifact = cegar_artifact.unwrap_or_else(|| {
            json!({
                "schema_version": 1,
                "file": filename,
                "mode": "prove",
                "prove_target": "safety",
                "result": unbounded_safety_result_kind(&result),
                "details": unbounded_safety_result_details(&result),
                "output": format!("{result}"),
                "cegar_controls": {
                    "max_refinements": cegar_iters,
                    "timeout_secs": options.timeout_secs,
                    "solver": format!("{:?}", options.solver).to_lowercase(),
                    "proof_engine": proof_engine_name(options.proof_engine),
                },
            })
        });
        write_json_artifact(path, &artifact)?;
        if matches!(output_format, OutputFormat::Text) {
            println!("CEGAR proof report written to {}", path.display());
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
pub(super) fn run_prove_safety_auto_strengthen(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    output_format: OutputFormat,
) -> miette::Result<()> {
    let result = tarsier_engine::pipeline::verification::prove_safety_with_auto_strengthen(
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
pub(super) fn run_prove_fair_portfolio(
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
pub(super) fn run_prove_fair_single(
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
