#![doc = include_str!("../README.md")]

mod cli;
mod commands;
mod tui;
mod types;

#[cfg(test)]
pub(crate) use cli::CLI_LONG_ABOUT;
pub(crate) use cli::{Cli, Commands};
pub(crate) use types::*;

// Re-export items used by both binary code and the test module.
pub(crate) use commands::helpers::{
    canonical_verdict_from_layer_result, certificate_bundle_from_fair_liveness,
    certificate_bundle_from_safety, execution_controls_from_cli, network_faithfulness_section,
    obligations_all_unsat, parse_cli_network_semantics_mode, proof_engine_name,
    render_fallback_summary, render_optimization_summary, render_phase_profile_summary,
    run_diagnostics_details, sandbox_config_from_cli, solver_name,
    validate_cli_network_semantics_mode, write_certificate_bundle, write_certificate_bundle_quiet,
};
#[cfg(feature = "governance")]
pub(crate) use commands::helpers::{
    cli_network_mode_name, declared_network_mode_in_program, parse_manifest_proof_engine,
    parse_output_format, run_external_solver_with_proof, sanitize_artifact_component,
    soundness_name,
};

#[cfg(any(test, feature = "governance"))]
pub(crate) use commands::verify::verification_result_kind;
pub(crate) use commands::verify::{
    cegar_report_details, cti_details, liveness_convergence_diagnostics,
    liveness_unknown_reason_payload, merge_portfolio_fair_liveness_results,
    merge_portfolio_liveness_results, merge_portfolio_prove_fair_results,
    merge_portfolio_prove_results, merge_portfolio_verify_reports, render_prove_fair_round_text,
    render_prove_round_text, trace_details, unbounded_fair_cegar_report_details,
    unbounded_fair_result_details, unbounded_fair_result_kind,
    unbounded_safety_cegar_report_details, unbounded_safety_result_details,
    unbounded_safety_result_kind, write_json_artifact,
};
#[cfg(feature = "governance")]
pub(crate) use commands::verify::{fair_liveness_result_kind, liveness_result_kind};

#[cfg(feature = "governance")]
pub(crate) use commands::analyze::run_analysis;
#[cfg(any(test, feature = "governance"))]
pub(crate) use commands::conformance::run_conformance_suite;
pub(crate) use commands::lint::lint_protocol_file;
#[cfg(feature = "governance")]
pub(crate) use commands::prove::parse_manifest_fairness_mode;
pub(crate) use commands::prove::{
    build_liveness_governance_report, detect_prove_auto_target, fairness_name,
    fairness_semantics_json, ProveAutoTarget,
};

// Re-export governance build_governance_bundle (used by analyze command).
#[cfg(feature = "governance")]
pub(crate) use commands::governance::build_governance_bundle;

// Re-exports used only by the test module (via `super::*`).
#[cfg(test)]
pub(crate) use commands::analyze::{compute_analysis_interpretation, run_portfolio_workers};
#[cfg(test)]
pub(crate) use commands::conformance::{
    CONFORMANCE_TRIAGE_CATEGORIES, CONFORMANCE_TRIAGE_ENGINE_REGRESSION,
    CONFORMANCE_TRIAGE_IMPL_DIVERGENCE, CONFORMANCE_TRIAGE_MODEL_CHANGE,
};
#[cfg(test)]
#[cfg(feature = "governance")]
pub(crate) use commands::governance::{
    classify_cert_suite_check_triage, expected_matches, generate_trust_report,
    has_independent_solver, proof_object_looks_nontrivial,
    validate_cert_suite_report_triage_contract, validate_foundational_profile_requirements,
    validate_manifest_corpus_breadth, validate_manifest_entry_contract,
    validate_manifest_expected_result, validate_manifest_known_bug_sentinel_coverage,
    validate_manifest_library_coverage, validate_manifest_model_hash_consistency,
    validate_manifest_top_level_contract, validate_trusted_check_requirements,
    CertSuiteAssumptions, CertSuiteCheckReport, CertSuiteEntry, CertSuiteEntryReport,
    CertSuiteManifest, CertSuiteReport, GovernanceGateResult, GovernancePipelineReport,
    TrustReport, CERT_SUITE_SCHEMA_VERSION, TRUST_REPORT_SCHEMA_VERSION,
};
#[cfg(test)]
pub(crate) use commands::helpers::{
    assistant_template, augment_query_for_proof, canonicalize_obligation_smt2,
    parse_visualize_check, parse_visualize_format,
};
#[cfg(test)]
pub(crate) use commands::lint::render_lint_text;
#[cfg(test)]
pub(crate) use commands::verify::{
    cegar_diff_friendly_projection, cegar_with_provenance, prefer_trace_a, trace_fingerprint,
    trace_json,
};
#[cfg(test)]
pub(crate) use commands::visualize::DebugFilter;

use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

use tarsier_engine::pipeline::set_global_execution_controls;
#[cfg(test)]
pub(crate) use tarsier_engine::pipeline::{FairnessMode, SoundnessMode};

// External crate re-exports used only by the test module.
#[cfg(all(test, feature = "governance"))]
pub(crate) use tarsier_engine::pipeline::ProofEngine;
#[cfg(test)]
pub(crate) use tarsier_proof_kernel::{
    compute_bundle_sha256, sha256_hex_bytes, CertificateMetadata, CertificateObligationMeta,
    CERTIFICATE_SCHEMA_VERSION,
};

fn main() -> miette::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let cli_network_mode = parse_cli_network_semantics_mode(&cli.network_semantics);
    let exec_controls = execution_controls_from_cli(&cli);
    set_global_execution_controls(exec_controls);

    // Activate runtime sandbox with configured resource limits.
    // The guard is held for the lifetime of the process; dropping it
    // deactivates the sandbox.
    let sandbox_config = sandbox_config_from_cli(&cli);
    let _sandbox_guard =
        tarsier_engine::sandbox::SandboxGuard::activate(sandbox_config).map_err(|e| {
            miette::miette!(
                "Sandbox activation failed: {e}\n\
                 Tarsier requires sandbox enforcement for analysis execution.\n\
                 If you are on a platform without memory monitoring, use --allow-degraded-sandbox."
            )
        })?;

    match cli.command {
        Commands::Verify {
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
        } => {
            commands::verify::run_verify_command(
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
            )?;
        }
        Commands::RoundSweep {
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
        } => {
            commands::verify::run_round_sweep_command(
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
            )?;
        }
        Commands::Parse { file } => {
            commands::visualize::run_parse_command(file)?;
        }
        Commands::Prove {
            file,
            solver,
            k,
            timeout,
            soundness,
            engine,
            fairness,
            cert_out,
            cegar_iters,
            cegar_report_out,
            portfolio,
            format,
        } => {
            commands::prove::run_prove_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                engine,
                fairness,
                cert_out,
                cegar_iters,
                cegar_report_out,
                portfolio,
                format,
                cli_network_mode,
            )?;
        }
        Commands::ProveRound {
            file,
            solver,
            k,
            timeout,
            soundness,
            engine,
            round_vars,
            format,
            out,
        } => {
            commands::prove::run_prove_round_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                engine,
                round_vars,
                format,
                out,
                cli_network_mode,
            )?;
        }
        Commands::ProveFairRound {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            round_vars,
            format,
            out,
        } => {
            commands::prove::run_prove_fair_round_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                round_vars,
                format,
                out,
                cli_network_mode,
            )?;
        }
        Commands::ProveFair {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            cert_out,
            cegar_iters,
            cegar_report_out,
            portfolio,
            format,
        } => {
            commands::prove::run_prove_fair_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                cert_out,
                cegar_iters,
                cegar_report_out,
                portfolio,
                format,
                cli_network_mode,
            )?;
        }
        Commands::ShowTa { file } => {
            commands::visualize::run_show_ta_command(file, cli_network_mode)?;
        }
        Commands::ExportDot {
            file,
            cluster,
            svg,
            out,
        } => {
            commands::visualize::run_export_dot_command(file, cluster, svg, out)?;
        }
        Commands::ExportTa { file, out } => {
            commands::visualize::run_export_ta_command(file, out)?;
        }
        Commands::Committee {
            population,
            byzantine,
            size,
            epsilon,
        } => {
            commands::helpers::run_committee_command(population, byzantine, size, epsilon)?;
        }
        Commands::Liveness {
            file,
            solver,
            depth,
            timeout,
            soundness,
            dump_smt,
            format,
        } => {
            commands::verify::run_liveness_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                dump_smt,
                format,
                cli_network_mode,
            )?;
        }
        Commands::FairLiveness {
            file,
            solver,
            depth,
            timeout,
            soundness,
            fairness,
            portfolio,
            format,
        } => {
            commands::verify::run_fair_liveness_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                fairness,
                portfolio,
                format,
                cli_network_mode,
            )?;
        }
        Commands::Visualize {
            file,
            check,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            engine,
            format,
            out,
            bundle,
        } => {
            commands::visualize::run_visualize_command(
                file,
                check,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                engine,
                format,
                out,
                bundle,
                cli_network_mode,
            )?;
        }
        Commands::Explore {
            file,
            check: _,
            solver,
            depth,
            timeout,
            trace_json,
        } => {
            commands::visualize::run_explore_command(file, solver, depth, timeout, trace_json)?;
        }
        Commands::Comm {
            file,
            depth,
            format,
            out,
        } => {
            commands::verify::run_comm_command(file, depth, format, out, cli_network_mode)?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "tarsier", &mut std::io::stdout());
        }
        Commands::Watch {
            file,
            solver,
            k,
            timeout,
            soundness,
            engine,
            fairness,
            portfolio,
            format,
        } => {
            commands::watch::run_watch_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                engine,
                fairness,
                portfolio,
                format,
                cli_network_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::CertSuite {
            manifest,
            solver,
            depth,
            k,
            timeout,
            engine,
            soundness,
            fairness,
            format,
            out,
            artifacts_dir,
        } => {
            commands::governance::run_cert_suite_command(
                manifest,
                solver,
                depth,
                k,
                timeout,
                engine,
                soundness,
                fairness,
                format,
                out,
                artifacts_dir,
                cli_network_mode,
            )?;
        }
        Commands::Lint {
            file,
            soundness,
            format,
            out,
        } => {
            commands::lint::run_lint_command(file, soundness, format, out, cli_network_mode)?;
        }
        Commands::DebugCex {
            file,
            check,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            engine,
            filter_sender,
            filter_recipient,
            filter_message,
            filter_kind,
            filter_variant,
            filter_auth,
        } => {
            commands::visualize::run_debug_cex_command(
                file,
                check,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                engine,
                filter_sender,
                filter_recipient,
                filter_message,
                filter_kind,
                filter_variant,
                filter_auth,
                cli_network_mode,
            )?;
        }
        Commands::Assist {
            kind,
            out,
            properties,
        } => {
            commands::helpers::run_assist_command(kind, out, properties)?;
        }
        Commands::ComposeCheck { file } => {
            commands::compose::run_compose_check_command(file)?;
        }
        Commands::ConformanceCheck {
            file,
            trace,
            adapter,
            checker_mode,
            format,
        } => {
            commands::conformance::run_conformance_check_command(
                &file,
                &trace,
                &adapter,
                &checker_mode,
                &format,
            )?;
        }
        Commands::ConformanceReplay {
            file,
            check,
            solver,
            depth,
            timeout,
            soundness,
            export_trace,
        } => {
            commands::conformance::run_conformance_replay_command(
                &file,
                &check,
                &solver,
                depth,
                timeout,
                &soundness,
                export_trace.as_ref(),
            )?;
        }
        Commands::ConformanceObligations { file, out } => {
            commands::conformance::run_conformance_obligations_command(&file, out.as_ref())?;
        }
        Commands::ConformanceSuite {
            manifest,
            format,
            out,
            artifact_dir,
        } => {
            commands::conformance::run_conformance_suite_command(
                &manifest,
                &format,
                out.as_ref(),
                artifact_dir.as_deref(),
            )?;
        }
        Commands::Codegen {
            file,
            target,
            output,
            require_cert,
            allow_unverified,
        } => {
            commands::codegen::run_codegen_command(
                file,
                target,
                output,
                require_cert,
                allow_unverified,
            )?;
        }
        Commands::Analyze {
            file,
            goal,
            profile,
            advanced,
            mode,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            portfolio,
            format,
            report_out,
        } => {
            commands::analyze::run_analyze_command(commands::analyze::AnalyzeCommandArgs {
                file: &file,
                goal,
                profile: &profile,
                advanced,
                mode,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                portfolio,
                format: &format,
                report_out: report_out.as_deref(),
                cli_network_mode,
                por_mode: &cli.por_mode,
            })?;
        }
        #[cfg(feature = "governance")]
        Commands::CertifySafety {
            file,
            solver,
            k,
            engine,
            timeout,
            soundness,
            out,
            capture_proofs,
            allow_missing_proofs,
            trust_report,
        } => {
            commands::governance::run_certify_safety_command(
                file,
                solver,
                k,
                engine,
                timeout,
                soundness,
                out,
                capture_proofs,
                allow_missing_proofs,
                trust_report,
                cli_network_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::CertifyFairLiveness {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            out,
            capture_proofs,
            allow_missing_proofs,
            trust_report,
        } => {
            commands::governance::run_certify_fair_liveness_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                out,
                capture_proofs,
                allow_missing_proofs,
                trust_report,
                cli_network_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::CheckCertificate {
            bundle,
            profile,
            solvers,
            emit_proofs,
            require_proofs,
            proof_checker,
            allow_unchecked_proofs,
            rederive,
            rederive_timeout,
            trusted_check,
            min_solvers,
        } => {
            commands::governance::run_check_certificate_command(
                bundle,
                profile,
                solvers,
                emit_proofs,
                require_proofs,
                proof_checker,
                allow_unchecked_proofs,
                rederive,
                rederive_timeout,
                trusted_check,
                min_solvers,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::GenerateTrustReport {
            profile,
            protocol_file,
            solvers,
            engine,
            soundness,
            out,
        } => {
            commands::governance::run_generate_trust_report_command(
                profile,
                protocol_file,
                solvers,
                engine,
                soundness,
                out,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::GovernancePipeline {
            file,
            cert_manifest,
            conformance_manifest,
            benchmark_report,
            solver,
            depth,
            k,
            timeout,
            soundness,
            format,
            out,
        } => {
            commands::governance::run_governance_pipeline_command(
                file,
                cert_manifest,
                conformance_manifest,
                benchmark_report,
                solver,
                depth,
                k,
                timeout,
                soundness,
                format,
                out,
                cli_network_mode,
                &cli.por_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::VerifyGovernanceBundle { bundle, format } => {
            commands::governance::run_verify_governance_bundle_command(bundle, format)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
