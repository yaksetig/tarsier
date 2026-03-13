//! Analysis command implementation and internal module wiring.

use std::path::Path;

use serde_json::{json, Value};

use tarsier_engine::pipeline::{ProofEngine, SolverChoice, SoundnessMode};

use crate::{
    build_liveness_governance_report, fairness_name, network_faithfulness_section, solver_name,
    AnalysisConfig, AnalysisMode, AnalysisReport, CliNetworkSemanticsMode, LayerRunCfg,
};
#[cfg(test)]
use crate::{
    AnalysisInterpretation, AnalysisLayerReport, CanonicalVerdict, ClaimStatement, NextAction,
};

mod command;
mod interpretation;
mod layers;
mod render;

pub(crate) use self::command::{run_analyze_command, AnalyzeCommandArgs};
pub(crate) use self::interpretation::{
    build_claim_statement, build_next_action, compute_analysis_interpretation,
    compute_confidence_tier, compute_overall_verdict, overall_status,
};
#[cfg(test)]
pub(crate) use self::interpretation::{
    is_liveness_interpretation_layer, is_safety_interpretation_layer,
};
#[cfg(test)]
pub(crate) use self::layers::layer;
#[cfg(any(test, feature = "governance"))]
pub(crate) use self::layers::run_portfolio_workers;
pub(crate) use self::layers::{
    run_certify_fair_liveness_layer, run_certify_safety_layer, run_comm_layer,
    run_fair_liveness_layer, run_fair_liveness_layer_portfolio, run_liveness_layer,
    run_liveness_layer_portfolio, run_parse_layer, run_prove_fair_layer,
    run_prove_fair_layer_portfolio, run_prove_layer, run_prove_layer_portfolio, run_verify_layer,
    run_verify_layer_portfolio,
};
pub(crate) use self::render::render_analysis_text;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_analysis(
    source: &str,
    filename: &str,
    mode: AnalysisMode,
    cfg: LayerRunCfg,
    network_mode: CliNetworkSemanticsMode,
    cert_out_dir: Option<&Path>,
    por_mode: &str,
    safety_only: bool,
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

    let preflight_warnings: Vec<Value> =
        if let Ok(program) = tarsier_engine::pipeline::parse(source, filename) {
            tarsier_engine::pipeline::completeness_preflight(&program)
                .into_iter()
                .map(|warning| {
                    json!({
                        "code": warning.code,
                        "message": warning.message,
                        "hint": warning.hint,
                    })
                })
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
                if !safety_only {
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
                }
            } else {
                layers.push(run_verify_layer(
                    source,
                    filename,
                    "verify",
                    cfg,
                    verify_cegar_iters,
                ));
                if !safety_only {
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
            if !safety_only {
                layers.push(run_prove_fair_layer_portfolio(
                    source,
                    filename,
                    "prove[fair_pdr]",
                    proof_cfg,
                ));
            }
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
            if !safety_only {
                layers.push(run_prove_fair_layer(
                    source,
                    filename,
                    "prove[fair_pdr]",
                    proof_cfg,
                ));
            }
        }
    }

    if matches!(mode, AnalysisMode::Audit) && !cfg.portfolio {
        let secondary_solver = match cfg.solver {
            SolverChoice::Z3 => SolverChoice::Cvc5,
            SolverChoice::Cvc5 => SolverChoice::Z3,
        };
        let suffix = format!("[{}]", solver_name(secondary_solver));
        let secondary_cfg = LayerRunCfg {
            solver: secondary_solver,
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
        if !safety_only {
            layers.push(run_fair_liveness_layer(
                source,
                filename,
                &format!("liveness[fair_lasso]{suffix}"),
                secondary_cfg,
            ));
        }
        layers.push(run_prove_layer(
            source,
            filename,
            &format!("prove[pdr]{suffix}"),
            secondary_cfg,
            ProofEngine::Pdr,
        ));
        if !safety_only {
            layers.push(run_prove_fair_layer(
                source,
                filename,
                &format!("prove[fair_pdr]{suffix}"),
                secondary_cfg,
            ));
        }
    }

    if matches!(mode, AnalysisMode::Audit) {
        let safety_passed = layers.iter().any(|layer| {
            layer.layer.starts_with("prove[")
                && !layer.layer.contains("fair")
                && layer.verdict == "SAFE"
        });
        let fair_passed = layers.iter().any(|layer| {
            layer.layer.contains("fair")
                && layer.layer.starts_with("prove[")
                && layer.verdict == "LIVE_PROVED"
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
    let liveness_governance =
        if !safety_only && matches!(mode, AnalysisMode::Proof | AnalysisMode::Audit) {
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

#[cfg(test)]
mod tests;
