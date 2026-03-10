// Shared helper functions used across CLI command handlers.
//
// These parse/convert CLI string arguments into typed enum values
// and provide sandbox/execution control configuration, as well as
// certificate-bundle, diagnostics, and template utilities.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{
    take_run_diagnostics, AutomatonFootprint, FairLivenessProofCertificate, FairnessMode,
    FaithfulFallbackConfig, FaithfulFallbackFloor, PipelineExecutionControls, PipelineOptions,
    PipelineRunDiagnostics, ProofEngine, SafetyProofCertificate, SolverChoice, SoundnessMode,
};
use tarsier_ir::threshold_automaton::PorMode;
use tarsier_proof_kernel::{
    compute_bundle_sha256, sha256_hex_file, CertificateMetadata, CertificateObligationMeta,
    CERTIFICATE_SCHEMA_VERSION,
};

use crate::{
    fairness_name, lint_protocol_file, AnalysisMode, CanonicalVerdict, CertificateBundleInput,
    CertificateBundleObligation, CertificateKind, Cli, CliNetworkSemanticsMode, OutputFormat,
    VisualizeCheck, VisualizeFormat,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliParseError {
    message: String,
}

impl CliParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliParseError {}
impl miette::Diagnostic for CliParseError {}

pub(crate) type CliParseResult<T> = Result<T, CliParseError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliExitError {
    pub(crate) code: i32,
    message: String,
}

impl CliExitError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliExitError {}
impl miette::Diagnostic for CliExitError {}

pub(crate) fn report_with_exit_code(code: i32, message: impl Into<String>) -> miette::Report {
    miette::Report::new(CliExitError::new(code, message))
}

pub(crate) fn exit_code_from_report(report: &miette::Report) -> Option<i32> {
    report.downcast_ref::<CliExitError>().map(|err| err.code)
}

pub(crate) fn parse_soundness_mode(raw: &str) -> CliParseResult<SoundnessMode> {
    match raw {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => Err(CliParseError::new(format!(
            "Unknown soundness mode: {other}. Use 'strict' or 'permissive'."
        ))),
    }
}

pub(crate) fn parse_proof_engine(raw: &str) -> CliParseResult<ProofEngine> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => Err(CliParseError::new(format!(
            "Unknown proof engine: {other}. Use 'kinduction' or 'pdr'."
        ))),
    }
}

#[cfg(feature = "governance")]
pub(crate) fn parse_manifest_proof_engine(raw: &str) -> Result<ProofEngine, String> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => Err(format!(
            "Unknown proof_engine '{other}'. Use 'kinduction' or 'pdr'."
        )),
    }
}

pub(crate) fn parse_solver_choice(raw: &str) -> CliParseResult<SolverChoice> {
    match raw {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => Err(CliParseError::new(format!(
            "Unknown solver: {other}. Use 'z3' or 'cvc5'."
        ))),
    }
}

pub(crate) fn parse_analysis_mode(raw: &str) -> CliParseResult<AnalysisMode> {
    match raw {
        "quick" => Ok(AnalysisMode::Quick),
        "standard" => Ok(AnalysisMode::Standard),
        "proof" => Ok(AnalysisMode::Proof),
        "audit" => Ok(AnalysisMode::Audit),
        other => Err(CliParseError::new(format!(
            "Unknown mode: {other}. Use 'quick', 'standard', 'proof', or 'audit'."
        ))),
    }
}

pub(crate) fn parse_output_format(raw: &str) -> CliParseResult<OutputFormat> {
    match raw {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(CliParseError::new(format!(
            "Unknown output format: {other}. Use 'text' or 'json'."
        ))),
    }
}

pub(crate) fn parse_conformance_adapter(
    raw: &str,
) -> CliParseResult<tarsier_conformance::adapters::AdapterKind> {
    use tarsier_conformance::adapters::AdapterKind;
    match raw.parse::<AdapterKind>() {
        Ok(kind) => Ok(kind),
        Err(err) => Err(CliParseError::new(err.to_string())),
    }
}

pub(crate) fn parse_conformance_mode(
    raw: &str,
) -> CliParseResult<tarsier_conformance::checker::ConformanceMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "permissive" => Ok(tarsier_conformance::checker::ConformanceMode::Permissive),
        "strict" => Ok(tarsier_conformance::checker::ConformanceMode::Strict),
        other => Err(CliParseError::new(format!(
            "Unknown checker mode: {other}. Use 'permissive' or 'strict'."
        ))),
    }
}

pub(crate) fn parse_cli_network_semantics_mode(
    raw: &str,
) -> CliParseResult<CliNetworkSemanticsMode> {
    match raw {
        "dsl" => Ok(CliNetworkSemanticsMode::Dsl),
        "faithful" => Ok(CliNetworkSemanticsMode::Faithful),
        other => Err(CliParseError::new(format!(
            "Unknown network semantics mode: {other}. Use 'dsl' or 'faithful'."
        ))),
    }
}

pub(crate) fn parse_cli_por_mode(raw: &str) -> CliParseResult<Option<PorMode>> {
    match raw {
        "full" => Ok(None), // default -- no override
        "static" | "static_only" => Ok(Some(PorMode::Static)),
        "off" | "none" | "disabled" => Ok(Some(PorMode::Off)),
        other => Err(CliParseError::new(format!(
            "Unknown POR mode: {other}. Use 'full', 'static', or 'off'."
        ))),
    }
}

pub(crate) fn cli_network_mode_name(mode: CliNetworkSemanticsMode) -> &'static str {
    match mode {
        CliNetworkSemanticsMode::Dsl => "dsl",
        CliNetworkSemanticsMode::Faithful => "faithful",
    }
}

pub(crate) fn parse_visualize_check(raw: &str) -> CliParseResult<VisualizeCheck> {
    match raw {
        "verify" => Ok(VisualizeCheck::Verify),
        "liveness" => Ok(VisualizeCheck::Liveness),
        "fair-liveness" | "fair_liveness" => Ok(VisualizeCheck::FairLiveness),
        "prove" => Ok(VisualizeCheck::Prove),
        "prove-fair" | "prove_fair" => Ok(VisualizeCheck::ProveFair),
        other => Err(CliParseError::new(format!(
            "Unknown visualize check: {other}. Use 'verify', 'liveness', 'fair-liveness', 'prove', or 'prove-fair'."
        ))),
    }
}

pub(crate) fn visualize_check_name(check: VisualizeCheck) -> &'static str {
    match check {
        VisualizeCheck::Verify => "verify",
        VisualizeCheck::Liveness => "liveness",
        VisualizeCheck::FairLiveness => "fair-liveness",
        VisualizeCheck::Prove => "prove",
        VisualizeCheck::ProveFair => "prove-fair",
    }
}

pub(crate) fn parse_visualize_format(raw: &str) -> CliParseResult<VisualizeFormat> {
    match raw {
        "timeline" => Ok(VisualizeFormat::Timeline),
        "mermaid" => Ok(VisualizeFormat::Mermaid),
        "markdown" => Ok(VisualizeFormat::Markdown),
        "json" => Ok(VisualizeFormat::Json),
        other => Err(CliParseError::new(format!(
            "Unknown visualize format: {other}. Use 'timeline', 'mermaid', 'markdown', or 'json'."
        ))),
    }
}

pub(crate) fn visualize_format_name(format: VisualizeFormat) -> &'static str {
    match format {
        VisualizeFormat::Timeline => "timeline",
        VisualizeFormat::Mermaid => "mermaid",
        VisualizeFormat::Markdown => "markdown",
        VisualizeFormat::Json => "json",
    }
}

pub(crate) fn parse_fairness_mode(raw: &str) -> CliParseResult<FairnessMode> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(CliParseError::new(format!(
            "Unknown fairness mode: {other}. Use 'weak' or 'strong'."
        ))),
    }
}

pub(crate) fn parse_faithful_fallback_floor(
    raw: &str,
) -> CliParseResult<Option<FaithfulFallbackFloor>> {
    match raw {
        "off" | "none" | "disabled" => Ok(None),
        "identity" | "faithful" => Ok(Some(FaithfulFallbackFloor::IdentitySelective)),
        "classic" => Ok(Some(FaithfulFallbackFloor::Classic)),
        other => Err(CliParseError::new(format!(
            "Unknown faithful fallback mode: {other}. Use 'off', 'identity', or 'classic'."
        ))),
    }
}

pub(crate) fn execution_controls_from_cli(cli: &Cli) -> CliParseResult<PipelineExecutionControls> {
    let faithful_fallback = parse_faithful_fallback_floor(&cli.faithful_fallback)?.map(|floor| {
        FaithfulFallbackConfig {
            max_locations: cli.fallback_max_locations,
            max_shared_vars: cli.fallback_max_shared_vars,
            max_message_counters: cli.fallback_max_message_counters,
            floor,
        }
    });
    let liveness_memory_budget_mb = if cli.liveness_memory_budget_mb == 0 {
        None
    } else {
        Some(cli.liveness_memory_budget_mb)
    };
    let por_mode_override = parse_cli_por_mode(&cli.por_mode)?;
    Ok(PipelineExecutionControls {
        faithful_fallback,
        liveness_memory_budget_mb,
        por_mode_override,
    })
}

pub(crate) fn sandbox_config_from_cli(cli: &Cli) -> tarsier_engine::sandbox::SandboxConfig {
    tarsier_engine::sandbox::SandboxConfig {
        timeout_secs: cli.sandbox_timeout_secs,
        memory_budget_mb: cli.sandbox_memory_budget_mb,
        max_input_bytes: cli.sandbox_max_input_bytes,
        allow_degraded: cli.allow_degraded_sandbox,
    }
}

/// Read a source file with sandbox input-size validation.
pub(crate) fn sandbox_read_source(path: &std::path::Path) -> miette::Result<String> {
    use miette::IntoDiagnostic;
    let metadata = std::fs::metadata(path).into_diagnostic()?;
    if let Some(config) = tarsier_engine::sandbox::active_sandbox_config() {
        if metadata.len() > config.max_input_bytes {
            miette::bail!(
                "Input file {} is {} bytes, exceeding sandbox limit of {} bytes",
                path.display(),
                metadata.len(),
                config.max_input_bytes
            );
        }
    }
    std::fs::read_to_string(path).into_diagnostic()
}

pub(crate) fn make_options(
    solver: SolverChoice,
    depth: usize,
    timeout: u64,
    soundness: SoundnessMode,
) -> PipelineOptions {
    PipelineOptions {
        solver,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness,
        proof_engine: ProofEngine::KInduction,
    }
}

// ---------------------------------------------------------------------------
// Utility functions migrated from main.rs
// ---------------------------------------------------------------------------

pub(crate) fn automaton_footprint_json(fp: AutomatonFootprint) -> Value {
    json!({
        "locations": fp.locations,
        "rules": fp.rules,
        "shared_vars": fp.shared_vars,
        "message_counters": fp.message_counters,
    })
}

pub(crate) fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

pub(crate) fn por_dynamic_ample_summary(diag: &PipelineRunDiagnostics) -> Value {
    let mut by_context: BTreeMap<String, (u64, u64, u64, u64)> = BTreeMap::new();
    let mut totals = (0_u64, 0_u64, 0_u64, 0_u64);

    for profile in &diag.smt_profiles {
        totals.0 = totals.0.saturating_add(profile.por_dynamic_ample_queries);
        totals.1 = totals.1.saturating_add(profile.por_dynamic_ample_fast_sat);
        totals.2 = totals
            .2
            .saturating_add(profile.por_dynamic_ample_unsat_rechecks);
        totals.3 = totals
            .3
            .saturating_add(profile.por_dynamic_ample_unsat_recheck_sat);

        let entry = by_context
            .entry(profile.context.clone())
            .or_insert((0, 0, 0, 0));
        entry.0 = entry.0.saturating_add(profile.por_dynamic_ample_queries);
        entry.1 = entry.1.saturating_add(profile.por_dynamic_ample_fast_sat);
        entry.2 = entry
            .2
            .saturating_add(profile.por_dynamic_ample_unsat_rechecks);
        entry.3 = entry
            .3
            .saturating_add(profile.por_dynamic_ample_unsat_recheck_sat);
    }

    let contexts = by_context
        .into_iter()
        .map(
            |(context, (queries, fast_sat, unsat_rechecks, unsat_recheck_sat))| {
                json!({
                    "context": context,
                    "queries": queries,
                    "fast_sat": fast_sat,
                    "unsat_rechecks": unsat_rechecks,
                    "unsat_recheck_sat": unsat_recheck_sat,
                    "fast_sat_rate": ratio(fast_sat, queries),
                    "unsat_recheck_rate": ratio(unsat_rechecks, queries),
                    "unsat_recheck_sat_rate": ratio(unsat_recheck_sat, unsat_rechecks),
                })
            },
        )
        .collect::<Vec<_>>();

    json!({
        "total_queries": totals.0,
        "total_fast_sat": totals.1,
        "total_unsat_rechecks": totals.2,
        "total_unsat_recheck_sat": totals.3,
        "total_fast_sat_rate": ratio(totals.1, totals.0),
        "total_unsat_recheck_rate": ratio(totals.2, totals.0),
        "total_unsat_recheck_sat_rate": ratio(totals.3, totals.2),
        "contexts": contexts,
    })
}

pub(crate) fn run_diagnostics_details(diag: &PipelineRunDiagnostics) -> Value {
    json!({
        "lowerings": diag.lowerings.iter().map(|entry| {
            json!({
                "context": entry.context,
                "requested_network": entry.requested_network,
                "effective_network": entry.effective_network,
                "fault_model": entry.fault_model,
                "authentication": entry.authentication,
                "equivocation": entry.equivocation,
                "delivery_control": entry.delivery_control,
                "fault_budget_scope": entry.fault_budget_scope,
                "identity_roles": entry.identity_roles,
                "process_identity_roles": entry.process_identity_roles,
                "requested_footprint": automaton_footprint_json(entry.requested_footprint),
                "effective_footprint": automaton_footprint_json(entry.effective_footprint),
                "fallback_budget": entry.fallback_budget.map(automaton_footprint_json),
                "budget_satisfied": entry.budget_satisfied,
                "fallback_applied": entry.fallback_applied,
                "fallback_steps": entry.fallback_steps,
                "fallback_exhausted": entry.fallback_exhausted,
                "independent_rule_pairs": entry.independent_rule_pairs,
                "por_stutter_rules_pruned": entry.por_stutter_rules_pruned,
                "por_commutative_duplicate_rules_pruned": entry.por_commutative_duplicate_rules_pruned,
                "por_guard_dominated_rules_pruned": entry.por_guard_dominated_rules_pruned,
                "por_effective_rule_count": entry.por_effective_rule_count,
                "por_enabled": entry.independent_rule_pairs > 0,
                "network_fallback_state": if entry.fallback_exhausted {
                    "exhausted"
                } else if entry.fallback_applied {
                    "applied"
                } else {
                    "not_applied"
                },
            })
        }).collect::<Vec<_>>(),
        "applied_reductions": diag.applied_reductions.iter().map(|step| {
            json!({
                "context": step.context,
                "kind": step.kind,
                "from": step.from,
                "to": step.to,
                "trigger": step.trigger,
                "before": automaton_footprint_json(step.before),
                "after": automaton_footprint_json(step.after),
            })
        }).collect::<Vec<_>>(),
        "reduction_notes": diag.reduction_notes,
        "property_compilations": diag.property_compilations.iter().map(|entry| {
            json!({
                "context": entry.context,
                "property_name": entry.property_name,
                "property_kind": entry.property_kind,
                "fragment": entry.fragment,
                "source_formula": entry.source_formula,
                "source_formula_sha256": entry.source_formula_sha256,
                "compilation_target": entry.compilation_target,
                "compiled_summary": entry.compiled_summary,
                "compiled_sha256": entry.compiled_sha256,
            })
        }).collect::<Vec<_>>(),
        "property_results": diag.property_results.iter().map(|entry| {
            json!({
                "property_id": entry.property_id,
                "property_name": entry.property_name,
                "property_kind": entry.property_kind,
                "fragment": entry.fragment,
                "verdict": entry.verdict,
                "assumptions": {
                    "solver": entry.assumptions.solver,
                    "soundness": entry.assumptions.soundness,
                    "max_depth": entry.assumptions.max_depth,
                    "network_semantics": entry.assumptions.network_semantics,
                    "committee_bounds": entry.assumptions.committee_bounds,
                    "failure_probability_bound": entry.assumptions.failure_probability_bound,
                },
                "witness": entry.witness.as_ref().map(|w| {
                    json!({
                        "witness_kind": w.witness_kind,
                        "trace_steps": w.trace_steps,
                        "violation_step": w.violation_step,
                        "temporal_monitor": w.temporal_monitor.as_ref().map(|steps| {
                            steps.iter().map(|s| {
                                json!({
                                    "step": s.step,
                                    "active_states": s.active_states,
                                    "true_atoms": s.true_atoms,
                                    "acceptance_sets_hit": s.acceptance_sets_hit,
                                })
                            }).collect::<Vec<_>>()
                        }),
                    })
                }),
            })
        }).collect::<Vec<_>>(),
        "phase_profiles": diag.phase_profiles.iter().map(|phase| {
            json!({
                "context": phase.context,
                "phase": phase.phase,
                "elapsed_ms": phase.elapsed_ms,
                "rss_bytes": phase.rss_bytes,
            })
        }).collect::<Vec<_>>(),
        "smt_profiles": diag.smt_profiles.iter().map(|profile| {
            let dedup_rate = if profile.assertion_candidates == 0 {
                0.0
            } else {
                profile.assertion_dedup_hits as f64 / profile.assertion_candidates as f64
            };
            let symmetry_prune_rate = if profile.symmetry_candidates == 0 {
                0.0
            } else {
                profile.symmetry_pruned as f64 / profile.symmetry_candidates as f64
            };
            let symmetry_enabled = profile.symmetry_candidates > 0
                || profile.symmetry_pruned > 0
                || profile.stutter_signature_normalizations > 0;
            let incremental_enabled = profile.incremental_depth_reuse_steps > 0
                || profile.incremental_decl_reuse_hits > 0
                || profile.incremental_assertion_reuse_hits > 0;
            json!({
                "context": profile.context,
                "encode_calls": profile.encode_calls,
                "encode_elapsed_ms": profile.encode_elapsed_ms,
                "solve_calls": profile.solve_calls,
                "solve_elapsed_ms": profile.solve_elapsed_ms,
                "assertion_candidates": profile.assertion_candidates,
                "assertion_unique": profile.assertion_unique,
                "assertion_dedup_hits": profile.assertion_dedup_hits,
                "assertion_dedup_rate": dedup_rate,
                "incremental_depth_reuse_steps": profile.incremental_depth_reuse_steps,
                "incremental_decl_reuse_hits": profile.incremental_decl_reuse_hits,
                "incremental_assertion_reuse_hits": profile.incremental_assertion_reuse_hits,
                "symmetry_candidates": profile.symmetry_candidates,
                "symmetry_pruned": profile.symmetry_pruned,
                "symmetry_prune_rate": symmetry_prune_rate,
                "stutter_signature_normalizations": profile.stutter_signature_normalizations,
                "por_pending_obligation_dedup_hits": profile.por_pending_obligation_dedup_hits,
                "por_dynamic_ample_queries": profile.por_dynamic_ample_queries,
                "por_dynamic_ample_fast_sat": profile.por_dynamic_ample_fast_sat,
                "por_dynamic_ample_unsat_rechecks": profile.por_dynamic_ample_unsat_rechecks,
                "por_dynamic_ample_unsat_recheck_sat": profile.por_dynamic_ample_unsat_recheck_sat,
                "symmetry_enabled": symmetry_enabled,
                "incremental_enabled": incremental_enabled,
            })
        }).collect::<Vec<_>>(),
        "por_dynamic_ample": por_dynamic_ample_summary(diag),
    })
}

pub(crate) fn render_optimization_summary(diag: &PipelineRunDiagnostics) -> Option<String> {
    let mut lines = Vec::new();

    for profile in &diag.smt_profiles {
        let ctx = if profile.context.is_empty() {
            String::new()
        } else {
            format!(" [{}]", profile.context)
        };

        if profile.assertion_candidates > 0 {
            let dedup_rate =
                profile.assertion_dedup_hits as f64 / profile.assertion_candidates as f64 * 100.0;
            if dedup_rate > 0.0 {
                lines.push(format!(
                    "  Structural-hash dedup{ctx}: {:.0}% ({}/{} assertions)",
                    dedup_rate, profile.assertion_dedup_hits, profile.assertion_candidates
                ));
            }
        }

        if profile.symmetry_candidates > 0 {
            let prune_rate =
                profile.symmetry_pruned as f64 / profile.symmetry_candidates as f64 * 100.0;
            if prune_rate > 0.0 {
                lines.push(format!(
                    "  Symmetry prune{ctx}: {:.0}% ({}/{} candidates)",
                    prune_rate, profile.symmetry_pruned, profile.symmetry_candidates
                ));
            }
        }

        let incr_hits = profile.incremental_depth_reuse_steps
            + profile.incremental_decl_reuse_hits
            + profile.incremental_assertion_reuse_hits;
        if incr_hits > 0 {
            lines.push(format!(
                "  Incremental reuse{ctx}: {} depth steps, {} decl hits, {} assertion hits",
                profile.incremental_depth_reuse_steps,
                profile.incremental_decl_reuse_hits,
                profile.incremental_assertion_reuse_hits
            ));
        }
    }

    for lowering in &diag.lowerings {
        if lowering.por_effective_rule_count > 0 || lowering.independent_rule_pairs > 0 {
            let total_pruned = lowering.por_stutter_rules_pruned
                + lowering.por_commutative_duplicate_rules_pruned
                + lowering.por_guard_dominated_rules_pruned;
            if total_pruned > 0 {
                lines.push(format!(
                    "  POR: {} rules pruned ({} stutter, {} commutative-dup, {} guard-dominated), {} effective rules, {} independent pairs",
                    total_pruned,
                    lowering.por_stutter_rules_pruned,
                    lowering.por_commutative_duplicate_rules_pruned,
                    lowering.por_guard_dominated_rules_pruned,
                    lowering.por_effective_rule_count,
                    lowering.independent_rule_pairs
                ));
            }
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(format!("Optimizations:\n{}", lines.join("\n")))
    }
}

pub(crate) fn render_phase_profile_summary(diag: &PipelineRunDiagnostics) -> Option<String> {
    if diag.phase_profiles.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    for phase in &diag.phase_profiles {
        let ctx = if phase.context.is_empty() {
            String::new()
        } else {
            format!(" [{}]", phase.context)
        };
        let mem = match phase.rss_bytes {
            Some(bytes) => format!(", rss={:.1} MB", bytes as f64 / (1024.0 * 1024.0)),
            None => String::new(),
        };
        lines.push(format!(
            "  {}{}: {} ms{}",
            phase.phase, ctx, phase.elapsed_ms, mem
        ));
    }
    Some(format!("Phase profiling:\n{}", lines.join("\n")))
}

pub(crate) fn render_fallback_summary(diag: &PipelineRunDiagnostics) -> Option<String> {
    let fallback_reductions: Vec<&tarsier_engine::pipeline::AppliedReductionDiagnostic> = diag
        .applied_reductions
        .iter()
        .filter(|r| r.kind == "network_fallback")
        .collect();

    if fallback_reductions.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    for step in &fallback_reductions {
        lines.push(format!("  {} -> {} ({})", step.from, step.to, step.trigger));
    }

    let exhausted = diag.lowerings.iter().any(|l| l.fallback_exhausted);

    let mut summary = format!("Network fallback chain:\n{}", lines.join("\n"));
    if exhausted {
        summary.push_str(
            "\n  Warning: fallback exhausted — floor mode reached, results may be less precise.",
        );
    }

    Some(summary)
}

pub(crate) fn declared_network_mode_in_program(
    program: &tarsier_dsl::ast::Program,
) -> &'static str {
    let proto = &program.protocol.node;
    let mode = proto
        .adversary
        .iter()
        .find(|item| item.key == "network" || item.key == "network_semantics")
        .map(|item| item.value.as_str())
        .unwrap_or("classic");
    if matches!(
        mode,
        "identity_selective"
            | "cohort_selective"
            | "process_selective"
            | "faithful"
            | "selective"
            | "selective_delivery"
    ) {
        "faithful"
    } else {
        "classic"
    }
}

pub(crate) fn validate_cli_network_semantics_mode(
    source: &str,
    filename: &str,
    soundness: SoundnessMode,
    mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    if mode == CliNetworkSemanticsMode::Dsl {
        return Ok(());
    }
    if soundness != SoundnessMode::Strict {
        miette::bail!(
            "`--network-semantics faithful` requires `--soundness strict` to avoid permissive fallbacks."
        );
    }
    let program = tarsier_dsl::parse(source, filename).into_diagnostic()?;
    if declared_network_mode_in_program(&program) != "faithful" {
        miette::bail!(
            "`--network-semantics faithful` requires an explicit faithful network in the model \
             (`adversary {{ network: process_selective|cohort_selective|identity_selective; }}`)."
        );
    }

    let lint = lint_protocol_file(source, filename, SoundnessMode::Strict);
    let blocking: Vec<String> = lint
        .issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .map(|issue| format!("{}: {}", issue.code, issue.message))
        .collect();
    if !blocking.is_empty() {
        let rendered = blocking
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n- ");
        miette::bail!(
            "Faithful network validation failed:\n- {}\nFix these strict-mode issues and retry.",
            rendered
        );
    }
    Ok(())
}

pub(crate) fn network_faithfulness_section(
    source: &str,
    filename: &str,
    requested_mode: CliNetworkSemanticsMode,
    soundness: SoundnessMode,
) -> Value {
    match tarsier_engine::pipeline::show_ta(source, filename) {
        Ok(_) => {
            let diagnostics = take_run_diagnostics();
            let lowering = diagnostics
                .lowerings
                .iter()
                .find(|entry| entry.context == "show_ta")
                .or_else(|| diagnostics.lowerings.last());
            if let Some(lowering) = lowering {
                let faithful_effective = lowering.effective_network != "classic";
                let assumptions = vec![
                    format!("fault_model={}", lowering.fault_model),
                    format!("network={}", lowering.effective_network),
                    format!("authentication={}", lowering.authentication),
                    format!("equivocation={}", lowering.equivocation),
                    format!("delivery_control={}", lowering.delivery_control),
                    format!("fault_budget_scope={}", lowering.fault_budget_scope),
                    format!(
                        "process_identity_roles={}/{}",
                        lowering.process_identity_roles, lowering.identity_roles
                    ),
                ];
                let status =
                    if requested_mode == CliNetworkSemanticsMode::Faithful && !faithful_effective {
                        "fail"
                    } else if faithful_effective {
                        "pass"
                    } else {
                        "warn"
                    };
                let summary = if faithful_effective {
                    format!(
                        "Faithful network semantics enforced ({})",
                        lowering.effective_network
                    )
                } else {
                    "Legacy network semantics enforced (classic)".into()
                };
                json!({
                    "status": status,
                    "summary": summary,
                    "requested_mode": cli_network_mode_name(requested_mode),
                    "soundness": soundness_name(soundness),
                    "assumptions_enforced": assumptions,
                    "details": run_diagnostics_details(&diagnostics),
                })
            } else {
                json!({
                    "status": "unknown",
                    "summary": "No lowering diagnostics were produced for network faithfulness.",
                    "requested_mode": cli_network_mode_name(requested_mode),
                    "soundness": soundness_name(soundness),
                    "details": run_diagnostics_details(&diagnostics),
                })
            }
        }
        Err(e) => json!({
            "status": "error",
            "summary": "Failed to lower protocol for network faithfulness report.",
            "requested_mode": cli_network_mode_name(requested_mode),
            "soundness": soundness_name(soundness),
            "error": e.to_string(),
        }),
    }
}

pub(crate) fn solver_cmd_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

pub(crate) fn proof_engine_name(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

pub(crate) fn soundness_name(mode: SoundnessMode) -> &'static str {
    match mode {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

pub(crate) fn certificate_bundle_from_safety(
    cert: &SafetyProofCertificate,
) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::SafetyProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: cert.induction_k,
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: None,
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

pub(crate) fn certificate_bundle_from_fair_liveness(
    cert: &FairLivenessProofCertificate,
) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::FairLivenessProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: Some(cert.frame),
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: Some(fairness_name(cert.fairness).to_string()),
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

pub(crate) fn obligations_all_unsat(metadata: &CertificateMetadata) -> bool {
    metadata
        .obligations
        .iter()
        .all(|obligation| obligation.expected == "unsat")
}

pub(crate) fn augment_query_for_proof(script: &str, solver_cmd: &str) -> String {
    let mut out = String::new();
    match solver_cmd {
        "z3" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        "cvc5" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        _ => {}
    }
    // The stored obligation already contains check-sat/exit. Remove exit and add get-proof.
    let body = script.replace("(exit)\n", "").replace("(exit)", "");
    out.push_str(&body);
    if !body.contains("(check-sat)") {
        out.push_str("\n(check-sat)\n");
    }
    out.push_str("(get-proof)\n");
    out.push_str("(exit)\n");
    out
}

pub(crate) fn run_external_solver_with_proof(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<(String, String)> {
    let base_script = fs::read_to_string(smt_file).into_diagnostic()?;
    let proof_script = augment_query_for_proof(&base_script, solver_cmd);

    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2")
                .arg("-in")
                .arg("sat.euf=true")
                .arg("tactic.default_tactic=smt")
                .arg("solver.proof.check=true");
        }
        "cvc5" => {
            cmd.arg("--lang")
                .arg("smt2")
                .arg("--check-proofs")
                .arg("--proof-format-mode=alethe")
                .arg("--proof-granularity=theory-rewrite")
                .arg("--proof-alethe-res-pivots")
                .arg("-");
        }
        _ => {
            miette::bail!(
                "Proof extraction for solver '{}' is unsupported; use z3 or cvc5.",
                solver_cmd
            );
        }
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().into_diagnostic()?;
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(proof_script.as_bytes()).into_diagnostic()?;
    }
    let output = child.wait_with_output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver `{solver_cmd}` failed on {} while extracting proofs: {}",
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let token = stdout
        .lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("unknown")
        .to_string();

    Ok((token, stdout))
}

/// Extract proof object from solver for a written .smt2 obligation file.
pub(crate) fn extract_proof_for_obligation(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<String> {
    let (result, proof_text) = run_external_solver_with_proof(solver_cmd, smt_file)?;
    if result != "unsat" {
        miette::bail!(
            "Cannot extract proof: solver returned '{}' instead of 'unsat' for {}",
            result,
            smt_file.display()
        );
    }
    Ok(proof_text)
}

pub(crate) fn canonicalize_obligation_smt2(script: &str) -> String {
    let mut set_logic: Option<String> = None;
    let mut preamble = Vec::new();
    let mut declarations = Vec::new();
    let mut assertions = Vec::new();
    let mut has_check_sat = false;
    let mut has_exit = false;

    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("(set-logic ") {
            if set_logic.is_none() {
                set_logic = Some(trimmed.to_string());
            }
            continue;
        }
        if trimmed.starts_with("(declare-const ") {
            declarations.push(trimmed.to_string());
            continue;
        }
        if trimmed.starts_with("(assert ") {
            assertions.push(trimmed.to_string());
            continue;
        }
        if trimmed == "(check-sat)" {
            has_check_sat = true;
            continue;
        }
        if trimmed == "(exit)" {
            has_exit = true;
            continue;
        }
        preamble.push(trimmed.to_string());
    }

    declarations.sort();
    declarations.dedup();
    assertions.sort();
    assertions.dedup();

    let mut out = String::new();
    out.push_str(set_logic.as_deref().unwrap_or("(set-logic QF_LIA)"));
    out.push('\n');
    for line in preamble {
        out.push_str(&line);
        out.push('\n');
    }
    for line in declarations {
        out.push_str(&line);
        out.push('\n');
    }
    for line in assertions {
        out.push_str(&line);
        out.push('\n');
    }
    if has_check_sat || !script.trim().is_empty() {
        out.push_str("(check-sat)\n");
    }
    if has_exit || !script.trim().is_empty() {
        out.push_str("(exit)\n");
    }
    out
}

pub(crate) fn write_certificate_bundle(
    out: &PathBuf,
    cert: &CertificateBundleInput,
    capture_proofs: bool,
    allow_missing_proofs: bool,
) -> miette::Result<()> {
    fs::create_dir_all(out).into_diagnostic()?;
    let metadata_file = out.join("certificate.json");

    let mut obligations = cert.obligations.clone();
    obligations.sort_by(|a, b| a.name.cmp(&b.name).then(a.expected.cmp(&b.expected)));

    let mut obligations_meta = Vec::new();
    for obligation in &obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = out.join(&file_name);
        let canonical_smt2 = canonicalize_obligation_smt2(&obligation.smt2);
        fs::write(&file_path, canonical_smt2).into_diagnostic()?;
        let hash = sha256_hex_file(&file_path).into_diagnostic()?;
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
            proof_file: None,
            proof_sha256: None,
        });
    }

    // If capture_proofs is enabled, extract proof objects from the solver for each obligation.
    if capture_proofs {
        let solver_cmd = &cert.solver_used;
        for meta in &mut obligations_meta {
            let smt_path = out.join(&meta.file);
            match extract_proof_for_obligation(solver_cmd, &smt_path) {
                Ok(proof_text) => {
                    let proof_file_name = format!("{}.proof", meta.name);
                    let proof_path = out.join(&proof_file_name);
                    fs::write(&proof_path, &proof_text).into_diagnostic()?;
                    let proof_hash = sha256_hex_file(&proof_path).into_diagnostic()?;
                    meta.proof_file = Some(proof_file_name);
                    meta.proof_sha256 = Some(proof_hash);
                    println!("  - {} (proof captured)", proof_path.display());
                }
                Err(e) => {
                    if allow_missing_proofs {
                        eprintln!(
                            "Warning: proof extraction failed for {} (--allow-missing-proofs): {}",
                            meta.name, e
                        );
                    } else {
                        miette::bail!(
                            "Proof extraction failed for obligation '{}': {}\n\
                             Use --allow-missing-proofs to continue without complete proofs.",
                            meta.name,
                            e
                        );
                    }
                }
            }
        }
    }

    let mut committee_bounds = cert.committee_bounds.clone();
    committee_bounds.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: cert.kind.as_str().to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: cert.proof_engine.clone(),
        induction_k: cert.induction_k,
        solver_used: cert.solver_used.clone(),
        soundness: cert.soundness.clone(),
        fairness: cert.fairness.clone(),
        committee_bounds,
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
    let metadata_json = serde_json::to_string_pretty(&metadata).into_diagnostic()?;
    fs::write(&metadata_file, metadata_json).into_diagnostic()?;

    println!("Certificate bundle written to {}", out.display());
    println!("  - {}", metadata_file.display());
    for obligation in &metadata.obligations {
        println!("  - {}", out.join(&obligation.file).display());
    }
    if let Some(k) = metadata.induction_k {
        println!("proof frame/k: {k}");
    }
    if let Some(ref fairness) = metadata.fairness {
        println!("fairness: {fairness}");
    }
    println!("proof engine: {}", metadata.proof_engine);
    println!("To verify independently:");
    println!(
        "  tarsier check-certificate {} --solvers z3,cvc5",
        out.display()
    );

    Ok(())
}

pub(crate) fn solver_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

/// Map an analysis layer result kind string to a canonical verdict.
pub(crate) fn canonical_verdict_from_layer_result(layer: &str, result: &str) -> CanonicalVerdict {
    match result {
        "safe" | "probabilistically_safe" => CanonicalVerdict::Safe,
        "unsafe" => CanonicalVerdict::Unsafe,
        "live" | "no_fair_cycle_up_to" | "live_proved" => CanonicalVerdict::LiveProved,
        "not_live" | "fair_cycle_found" => CanonicalVerdict::LiveCex,
        "not_proved" => CanonicalVerdict::Inconclusive,
        "unknown" => CanonicalVerdict::Unknown,
        // parse/comm layers use pass/fail/error
        "pass" => {
            if layer.contains("liveness") || layer.contains("fair") {
                CanonicalVerdict::LiveProved
            } else {
                CanonicalVerdict::Safe
            }
        }
        "fail" | "error" => CanonicalVerdict::Unknown,
        _ => CanonicalVerdict::Unknown,
    }
}

#[cfg(feature = "governance")]
pub(crate) fn sanitize_artifact_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '.' || ch == '/' || ch == '\\' || ch.is_whitespace() {
            out.push('_');
        }
    }
    let compact = out.trim_matches('_');
    if compact.is_empty() {
        "entry".to_string()
    } else {
        compact.to_string()
    }
}

/// V2-05: Return a vetted property template for the given kind.
pub(crate) fn property_template(kind: &str) -> Option<&'static str> {
    match kind {
        "agreement" => Some(
            r#"// Agreement: no two correct processes decide differently.
// Requires two universal quantifiers over the same role.
property agreement: agreement {
    forall p: Replica. forall q: Replica.
        (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
}
"#,
        ),
        "validity" => Some(
            r#"// Validity: if all correct processes propose the same value, they decide that value.
// Uses a single universal quantifier.
property validity: validity {
    forall p: Replica. (p.decided == true) ==> (p.decision == p.proposal)
}
"#,
        ),
        "termination" => Some(
            r#"// Termination: every correct process eventually decides.
// Liveness property with eventually operator.
property termination: liveness {
    forall p: Replica. <> (p.decided == true)
}
"#,
        ),
        "liveness" => Some(
            r#"// Liveness: the system always eventually makes progress.
// Uses always-eventually ([] <>) temporal pattern.
property progress: liveness {
    forall p: Replica. [] <> (p.decided == true)
}
"#,
        ),
        "integrity" => Some(
            r#"// Integrity: a correct process decides at most once.
// Safety invariant on the decision flag.
property integrity: safety {
    forall p: Replica. (p.decided == true) ==> (p.decision_count <= 1)
}
"#,
        ),
        _ => None,
    }
}

pub(crate) fn assistant_template(kind: &str) -> Option<&'static str> {
    match kind {
        "pbft" => Some(
            r#"protocol PBFTTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message PrePrepare;
    message Prepare;
    message Commit;

    role Replica {
        var decided: bool = false;
        var decision: bool = false;
        init start;

        // Phase 1: Await pre-prepare from leader, then broadcast prepare.
        phase start {
            when received >= 1 PrePrepare => {
                send Prepare;
                goto phase prepared;
            }
        }

        // Phase 2: Collect 2t+1 prepares, then broadcast commit.
        phase prepared {
            when received >= 2*t+1 Prepare => {
                send Commit;
                goto phase committed;
            }
        }

        // Phase 3: Collect 2t+1 commits and decide.
        phase committed {
            when received >= 2*t+1 Commit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Replica. p.decided == true
    }
}
"#,
        ),
        "hotstuff" => Some(
            r#"protocol HotStuffTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Vote;

    role Node {
        var decided: bool = false;
        var decision: bool = false;
        init propose;

        // Phase 1: Leader broadcasts proposal; nodes receive and vote.
        phase propose {
            when received >= 1 Proposal => {
                send Vote;
                goto phase voted;
            }
        }

        // Phase 2: Collect 2t+1 votes to form a quorum certificate and decide.
        phase voted {
            when received >= 2*t+1 Vote => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Node. p.decided == true
    }
}
"#,
        ),
        "raft" => Some(
            r#"protocol RaftTemplate {
    params n, t, f;
    resilience: n > 2*t;
    adversary {
        model: crash;
        bound: f;
    }

    message RequestVote;
    message VoteGranted;
    message AppendEntries;

    role Server {
        var decided: bool = false;
        var decision: bool = false;
        init follower;

        // Follower receives RequestVote from candidate, grants vote.
        phase follower {
            when received >= 1 RequestVote => {
                send VoteGranted;
                goto phase voting;
            }
        }

        // Candidate collects majority votes, becomes leader.
        phase voting {
            when received >= t+1 VoteGranted => {
                send AppendEntries;
                goto phase replicating;
            }
        }

        // Leader replicates entry; majority acknowledgment = commit.
        phase replicating {
            when received >= t+1 AppendEntries => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Server. forall q: Server.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Server. p.decided == true
    }
}
"#,
        ),
        "tendermint" => Some(
            r#"protocol TendermintTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Prevote;
    message Precommit;

    role Validator {
        var decided: bool = false;
        var decision: bool = false;
        init propose;

        // Phase 1: Proposer broadcasts; validators receive and prevote.
        phase propose {
            when received >= 1 Proposal => {
                send Prevote;
                goto phase prevote;
            }
        }

        // Phase 2: Collect 2t+1 prevotes (polka), then precommit.
        phase prevote {
            when received >= 2*t+1 Prevote => {
                send Precommit;
                goto phase precommit;
            }
        }

        // Phase 3: Collect 2t+1 precommits and decide.
        phase precommit {
            when received >= 2*t+1 Precommit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Validator. forall q: Validator.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Validator. p.decided == true
    }
}
"#,
        ),
        "streamlet" => Some(
            r#"protocol StreamletTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Vote;
    message Notarize;

    role Node {
        var decided: bool = false;
        var decision: bool = false;
        init wait;

        // Phase 1: Leader proposes a block; nodes receive and vote.
        phase wait {
            when received >= 1 Proposal => {
                send Vote;
                goto phase voted;
            }
        }

        // Phase 2: Collect 2t+1 votes to notarize the block.
        phase voted {
            when received >= 2*t+1 Vote => {
                send Notarize;
                goto phase notarized;
            }
        }

        // Phase 3: Observe notarization; finalize.
        phase notarized {
            when received >= 2*t+1 Notarize => {
                decision = true;
                decided = true;
                decide true;
                goto phase finalized;
            }
        }

        phase finalized {}
    }

    property agreement: agreement {
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Node. p.decided == true
    }
}
"#,
        ),
        "casper" => Some(
            r#"protocol CasperFFGTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Justify;
    message Finalize;

    role Validator {
        var decided: bool = false;
        var decision: bool = false;
        init attest;

        // Phase 1: Validators cast attestation votes for a checkpoint.
        phase attest {
            when received >= 1 Vote => {
                send Justify;
                goto phase justified;
            }
        }

        // Phase 2: Collect 2t+1 justifications (supermajority link).
        phase justified {
            when received >= 2*t+1 Justify => {
                send Finalize;
                goto phase finalizing;
            }
        }

        // Phase 3: Collect 2t+1 finalize attestations; checkpoint is finalized.
        phase finalizing {
            when received >= 2*t+1 Finalize => {
                decision = true;
                decided = true;
                decide true;
                goto phase finalized;
            }
        }

        phase finalized {}
    }

    property agreement: agreement {
        forall p: Validator. forall q: Validator.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Validator. p.decided == true
    }
}
"#,
        ),
        _ => None,
    }
}

/// Handler for the `committee` subcommand.
///
/// Performs committee selection analysis using hypergeometric probability.
pub(crate) fn run_committee_command(
    population: u64,
    byzantine: u64,
    size: u64,
    epsilon: f64,
) -> miette::Result<()> {
    let spec = tarsier_prob::CommitteeSpec {
        name: "committee".into(),
        population,
        byzantine,
        committee_size: size,
        epsilon,
    };

    let analysis =
        tarsier_prob::analyze_committee(&spec).map_err(|e| miette::miette!("Error: {e}"))?;
    println!("Committee Analysis:");
    println!("  Population: {} ({} Byzantine)", population, byzantine);
    println!("  Committee size: {}", size);
    println!("  Expected Byzantine: {:.1}", analysis.expected_byzantine);
    println!(
        "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
        analysis.b_max, epsilon
    );
    println!(
        "  Honest majority: {} of {}",
        analysis.honest_majority, size
    );
    Ok(())
}

/// Handler for the `assist` subcommand.
///
/// Generates protocol scaffolds or property templates.
pub(crate) fn run_assist_command(
    kind: String,
    out: Option<PathBuf>,
    properties: Option<String>,
) -> miette::Result<()> {
    // V2-05: Property template mode
    if let Some(ref prop_kind) = properties {
        let normalized = prop_kind.trim().to_lowercase();
        match property_template(&normalized) {
            Some(tmpl) => {
                println!("{tmpl}");
            }
            None => {
                return Err(miette::miette!(
                    "Unknown property template '{}'. Available: agreement, validity, termination, liveness, integrity",
                    prop_kind
                ));
            }
        }
    } else {
        let normalized = kind.trim().to_lowercase();
        let template = assistant_template(&normalized).ok_or_else(|| {
            miette::miette!(
                "Unknown scaffold kind '{}'. Use pbft | hotstuff | raft | tendermint | streamlet | casper.",
                kind
            )
        })?;

        if let Some(path) = out {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).into_diagnostic()?;
            }
            fs::write(&path, template).into_diagnostic()?;
            println!("Scaffold written to {}", path.display());
        } else {
            println!("{template}");
        }
    }
    Ok(())
}

/// V2-08: Build a governance artifact bundle.
/// V2-01: Write a certificate bundle without stdout output.
pub(crate) fn write_certificate_bundle_quiet(
    out: &PathBuf,
    cert: &CertificateBundleInput,
) -> miette::Result<()> {
    fs::create_dir_all(out).into_diagnostic()?;
    let metadata_file = out.join("certificate.json");

    let mut obligations = cert.obligations.clone();
    obligations.sort_by(|a, b| a.name.cmp(&b.name).then(a.expected.cmp(&b.expected)));

    let mut obligations_meta = Vec::new();
    for obligation in &obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = out.join(&file_name);
        let canonical_smt2 = canonicalize_obligation_smt2(&obligation.smt2);
        fs::write(&file_path, canonical_smt2).into_diagnostic()?;
        let hash = sha256_hex_file(&file_path).into_diagnostic()?;
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
            proof_file: None,
            proof_sha256: None,
        });
    }

    let mut committee_bounds = cert.committee_bounds.clone();
    committee_bounds.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: cert.kind.as_str().to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: cert.proof_engine.clone(),
        induction_k: cert.induction_k,
        solver_used: cert.solver_used.clone(),
        soundness: cert.soundness.clone(),
        fairness: cert.fairness.clone(),
        committee_bounds,
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
    let metadata_json = serde_json::to_string_pretty(&metadata).into_diagnostic()?;
    fs::write(&metadata_file, metadata_json).into_diagnostic()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_engine::pipeline::{FairnessMode, SolverChoice, SoundnessMode};

    // -- CliParseError --

    #[test]
    fn cli_parse_error_display() {
        let err = CliParseError::new("boom");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn cli_parse_error_implements_std_error() {
        let err = CliParseError::new("test");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn cli_parse_error_eq() {
        let a = CliParseError::new("x");
        let b = CliParseError::new("x");
        let c = CliParseError::new("y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -- CliExitError --

    #[test]
    fn cli_exit_error_display() {
        let err = CliExitError::new(2, "failed");
        assert_eq!(err.to_string(), "failed");
        assert_eq!(err.code, 2);
    }

    #[test]
    fn exit_code_round_trip() {
        let report = report_with_exit_code(42, "test");
        assert_eq!(exit_code_from_report(&report), Some(42));
    }

    #[test]
    fn exit_code_returns_none_for_other_errors() {
        let report = miette::Report::msg("generic error");
        assert_eq!(exit_code_from_report(&report), None);
    }

    // -- parse_soundness_mode --

    #[test]
    fn parse_soundness_mode_strict() {
        assert!(matches!(
            parse_soundness_mode("strict"),
            Ok(SoundnessMode::Strict)
        ));
    }

    #[test]
    fn parse_soundness_mode_permissive() {
        assert!(matches!(
            parse_soundness_mode("permissive"),
            Ok(SoundnessMode::Permissive)
        ));
    }

    #[test]
    fn parse_soundness_mode_unknown() {
        let err = parse_soundness_mode("foo").unwrap_err();
        assert!(err.to_string().contains("Unknown soundness mode"));
    }

    // -- parse_proof_engine --

    #[test]
    fn parse_proof_engine_valid() {
        assert!(matches!(
            parse_proof_engine("kinduction"),
            Ok(ProofEngine::KInduction)
        ));
        assert!(matches!(parse_proof_engine("pdr"), Ok(ProofEngine::Pdr)));
    }

    #[test]
    fn parse_proof_engine_invalid() {
        assert!(parse_proof_engine("abc").is_err());
    }

    // -- parse_solver_choice --

    #[test]
    fn parse_solver_choice_valid() {
        assert!(matches!(
            parse_solver_choice("z3"),
            Ok(SolverChoice::Z3)
        ));
        assert!(matches!(
            parse_solver_choice("cvc5"),
            Ok(SolverChoice::Cvc5)
        ));
    }

    #[test]
    fn parse_solver_choice_invalid() {
        let err = parse_solver_choice("minisat").unwrap_err();
        assert!(err.to_string().contains("Unknown solver"));
    }

    // -- parse_analysis_mode --

    #[test]
    fn parse_analysis_mode_all_variants() {
        assert!(matches!(
            parse_analysis_mode("quick"),
            Ok(AnalysisMode::Quick)
        ));
        assert!(matches!(
            parse_analysis_mode("standard"),
            Ok(AnalysisMode::Standard)
        ));
        assert!(matches!(
            parse_analysis_mode("proof"),
            Ok(AnalysisMode::Proof)
        ));
        assert!(matches!(
            parse_analysis_mode("audit"),
            Ok(AnalysisMode::Audit)
        ));
    }

    #[test]
    fn parse_analysis_mode_invalid() {
        assert!(parse_analysis_mode("turbo").is_err());
    }

    // -- parse_output_format --

    #[test]
    fn parse_output_format_valid() {
        assert!(matches!(
            parse_output_format("text"),
            Ok(OutputFormat::Text)
        ));
        assert!(matches!(
            parse_output_format("json"),
            Ok(OutputFormat::Json)
        ));
    }

    #[test]
    fn parse_output_format_invalid() {
        assert!(parse_output_format("xml").is_err());
    }

    // -- parse_cli_network_semantics_mode --

    #[test]
    fn parse_cli_network_semantics_mode_valid() {
        assert!(matches!(
            parse_cli_network_semantics_mode("dsl"),
            Ok(CliNetworkSemanticsMode::Dsl)
        ));
        assert!(matches!(
            parse_cli_network_semantics_mode("faithful"),
            Ok(CliNetworkSemanticsMode::Faithful)
        ));
    }

    #[test]
    fn parse_cli_network_semantics_mode_invalid() {
        assert!(parse_cli_network_semantics_mode("legacy").is_err());
    }

    // -- parse_cli_por_mode --

    #[test]
    fn parse_cli_por_mode_full() {
        assert_eq!(parse_cli_por_mode("full").unwrap(), None);
    }

    #[test]
    fn parse_cli_por_mode_static() {
        assert!(matches!(
            parse_cli_por_mode("static"),
            Ok(Some(PorMode::Static))
        ));
        assert!(matches!(
            parse_cli_por_mode("static_only"),
            Ok(Some(PorMode::Static))
        ));
    }

    #[test]
    fn parse_cli_por_mode_off_variants() {
        for name in &["off", "none", "disabled"] {
            assert!(matches!(
                parse_cli_por_mode(name),
                Ok(Some(PorMode::Off))
            ));
        }
    }

    #[test]
    fn parse_cli_por_mode_invalid() {
        assert!(parse_cli_por_mode("dynamic").is_err());
    }

    // -- parse_visualize_check --

    #[test]
    fn parse_visualize_check_valid_names() {
        assert!(matches!(
            parse_visualize_check("verify"),
            Ok(VisualizeCheck::Verify)
        ));
        assert!(matches!(
            parse_visualize_check("liveness"),
            Ok(VisualizeCheck::Liveness)
        ));
        assert!(matches!(
            parse_visualize_check("fair-liveness"),
            Ok(VisualizeCheck::FairLiveness)
        ));
        assert!(matches!(
            parse_visualize_check("fair_liveness"),
            Ok(VisualizeCheck::FairLiveness)
        ));
        assert!(matches!(
            parse_visualize_check("prove"),
            Ok(VisualizeCheck::Prove)
        ));
        assert!(matches!(
            parse_visualize_check("prove-fair"),
            Ok(VisualizeCheck::ProveFair)
        ));
        assert!(matches!(
            parse_visualize_check("prove_fair"),
            Ok(VisualizeCheck::ProveFair)
        ));
    }

    #[test]
    fn parse_visualize_check_invalid() {
        assert!(parse_visualize_check("debug").is_err());
    }

    // -- visualize_check_name round-trip --

    #[test]
    fn visualize_check_name_round_trip() {
        assert_eq!(visualize_check_name(VisualizeCheck::Verify), "verify");
        assert_eq!(visualize_check_name(VisualizeCheck::Liveness), "liveness");
        assert_eq!(
            visualize_check_name(VisualizeCheck::FairLiveness),
            "fair-liveness"
        );
        assert_eq!(visualize_check_name(VisualizeCheck::Prove), "prove");
        assert_eq!(
            visualize_check_name(VisualizeCheck::ProveFair),
            "prove-fair"
        );
    }

    // -- parse_visualize_format --

    #[test]
    fn parse_visualize_format_valid() {
        assert!(matches!(
            parse_visualize_format("timeline"),
            Ok(VisualizeFormat::Timeline)
        ));
        assert!(matches!(
            parse_visualize_format("mermaid"),
            Ok(VisualizeFormat::Mermaid)
        ));
        assert!(matches!(
            parse_visualize_format("markdown"),
            Ok(VisualizeFormat::Markdown)
        ));
        assert!(matches!(
            parse_visualize_format("json"),
            Ok(VisualizeFormat::Json)
        ));
    }

    #[test]
    fn parse_visualize_format_invalid() {
        assert!(parse_visualize_format("svg").is_err());
    }

    // -- visualize_format_name round-trip --

    #[test]
    fn visualize_format_name_round_trip() {
        assert_eq!(
            visualize_format_name(VisualizeFormat::Timeline),
            "timeline"
        );
        assert_eq!(visualize_format_name(VisualizeFormat::Mermaid), "mermaid");
        assert_eq!(
            visualize_format_name(VisualizeFormat::Markdown),
            "markdown"
        );
        assert_eq!(visualize_format_name(VisualizeFormat::Json), "json");
    }

    // -- parse_fairness_mode --

    #[test]
    fn parse_fairness_mode_valid() {
        assert!(matches!(
            parse_fairness_mode("weak"),
            Ok(FairnessMode::Weak)
        ));
        assert!(matches!(
            parse_fairness_mode("strong"),
            Ok(FairnessMode::Strong)
        ));
    }

    #[test]
    fn parse_fairness_mode_invalid() {
        assert!(parse_fairness_mode("fair").is_err());
    }

    // -- parse_faithful_fallback_floor --

    #[test]
    fn parse_faithful_fallback_floor_off_variants() {
        for name in &["off", "none", "disabled"] {
            assert!(parse_faithful_fallback_floor(name).unwrap().is_none());
        }
    }

    #[test]
    fn parse_faithful_fallback_floor_identity() {
        assert!(matches!(
            parse_faithful_fallback_floor("identity"),
            Ok(Some(FaithfulFallbackFloor::IdentitySelective))
        ));
        assert!(matches!(
            parse_faithful_fallback_floor("faithful"),
            Ok(Some(FaithfulFallbackFloor::IdentitySelective))
        ));
    }

    #[test]
    fn parse_faithful_fallback_floor_classic() {
        assert!(matches!(
            parse_faithful_fallback_floor("classic"),
            Ok(Some(FaithfulFallbackFloor::Classic))
        ));
    }

    #[test]
    fn parse_faithful_fallback_floor_invalid() {
        assert!(parse_faithful_fallback_floor("xyz").is_err());
    }

    // -- cli_network_mode_name --

    #[test]
    fn cli_network_mode_name_values() {
        assert_eq!(cli_network_mode_name(CliNetworkSemanticsMode::Dsl), "dsl");
        assert_eq!(
            cli_network_mode_name(CliNetworkSemanticsMode::Faithful),
            "faithful"
        );
    }

    // -- solver_name / solver_cmd_name --

    #[test]
    fn solver_name_values() {
        assert_eq!(solver_name(SolverChoice::Z3), "z3");
        assert_eq!(solver_name(SolverChoice::Cvc5), "cvc5");
    }

    #[test]
    fn solver_cmd_name_values() {
        assert_eq!(solver_cmd_name(SolverChoice::Z3), "z3");
        assert_eq!(solver_cmd_name(SolverChoice::Cvc5), "cvc5");
    }

    // -- proof_engine_name / soundness_name --

    #[test]
    fn proof_engine_name_values() {
        assert_eq!(proof_engine_name(ProofEngine::KInduction), "kinduction");
        assert_eq!(proof_engine_name(ProofEngine::Pdr), "pdr");
    }

    #[test]
    fn soundness_name_values() {
        assert_eq!(soundness_name(SoundnessMode::Strict), "strict");
        assert_eq!(soundness_name(SoundnessMode::Permissive), "permissive");
    }

    // -- ratio --

    #[test]
    fn ratio_normal() {
        assert!((ratio(1, 4) - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn ratio_zero_denominator() {
        assert!((ratio(5, 0) - 0.0).abs() < f64::EPSILON);
    }

    // -- canonical_verdict_from_layer_result --

    #[test]
    fn canonical_verdict_safe_variants() {
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "safe"),
            CanonicalVerdict::Safe
        );
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "probabilistically_safe"),
            CanonicalVerdict::Safe
        );
    }

    #[test]
    fn canonical_verdict_unsafe() {
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "unsafe"),
            CanonicalVerdict::Unsafe
        );
    }

    #[test]
    fn canonical_verdict_live_variants() {
        assert_eq!(
            canonical_verdict_from_layer_result("liveness", "live"),
            CanonicalVerdict::LiveProved
        );
        assert_eq!(
            canonical_verdict_from_layer_result("fair", "no_fair_cycle_up_to"),
            CanonicalVerdict::LiveProved
        );
        assert_eq!(
            canonical_verdict_from_layer_result("prove", "live_proved"),
            CanonicalVerdict::LiveProved
        );
    }

    #[test]
    fn canonical_verdict_live_cex() {
        assert_eq!(
            canonical_verdict_from_layer_result("liveness", "not_live"),
            CanonicalVerdict::LiveCex
        );
        assert_eq!(
            canonical_verdict_from_layer_result("fair", "fair_cycle_found"),
            CanonicalVerdict::LiveCex
        );
    }

    #[test]
    fn canonical_verdict_inconclusive() {
        assert_eq!(
            canonical_verdict_from_layer_result("prove", "not_proved"),
            CanonicalVerdict::Inconclusive
        );
    }

    #[test]
    fn canonical_verdict_unknown() {
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "unknown"),
            CanonicalVerdict::Unknown
        );
    }

    #[test]
    fn canonical_verdict_pass_liveness_layer() {
        assert_eq!(
            canonical_verdict_from_layer_result("fair_liveness", "pass"),
            CanonicalVerdict::LiveProved
        );
    }

    #[test]
    fn canonical_verdict_pass_safety_layer() {
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "pass"),
            CanonicalVerdict::Safe
        );
    }

    #[test]
    fn canonical_verdict_fail_maps_to_unknown() {
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "fail"),
            CanonicalVerdict::Unknown
        );
        assert_eq!(
            canonical_verdict_from_layer_result("verify", "error"),
            CanonicalVerdict::Unknown
        );
    }

    // -- make_options --

    #[test]
    fn make_options_builds_correct_struct() {
        let opts = make_options(SolverChoice::Z3, 10, 30, SoundnessMode::Strict);
        assert!(matches!(opts.solver, SolverChoice::Z3));
        assert_eq!(opts.max_depth, 10);
        assert_eq!(opts.timeout_secs, 30);
        assert!(matches!(opts.soundness, SoundnessMode::Strict));
        assert!(matches!(opts.proof_engine, ProofEngine::KInduction));
        assert!(opts.dump_smt.is_none());
    }

    // -- automaton_footprint_json --

    #[test]
    fn automaton_footprint_json_has_expected_keys() {
        let fp = AutomatonFootprint {
            locations: 5,
            rules: 3,
            shared_vars: 2,
            message_counters: 1,
        };
        let json = automaton_footprint_json(fp);
        assert_eq!(json["locations"], 5);
        assert_eq!(json["rules"], 3);
        assert_eq!(json["shared_vars"], 2);
        assert_eq!(json["message_counters"], 1);
    }

    // -- property_template --

    #[test]
    fn property_template_known_kinds() {
        for kind in &[
            "agreement",
            "validity",
            "termination",
            "liveness",
            "integrity",
        ] {
            assert!(
                property_template(kind).is_some(),
                "expected template for '{kind}'"
            );
        }
    }

    #[test]
    fn property_template_unknown() {
        assert!(property_template("finality").is_none());
    }

    // -- assistant_template --

    #[test]
    fn assistant_template_known_protocols() {
        for kind in &[
            "pbft",
            "hotstuff",
            "raft",
            "tendermint",
            "streamlet",
            "casper",
        ] {
            assert!(
                assistant_template(kind).is_some(),
                "expected scaffold for '{kind}'"
            );
        }
    }

    #[test]
    fn assistant_template_unknown() {
        assert!(assistant_template("paxos").is_none());
    }

    // -- augment_query_for_proof --

    #[test]
    fn augment_query_for_proof_adds_produce_proofs() {
        let script = "(declare-const x Int)\n(assert (> x 0))\n(check-sat)\n(exit)\n";
        let result = augment_query_for_proof(script, "z3");
        assert!(result.starts_with("(set-option :produce-proofs true)\n"));
        assert!(result.contains("(get-proof)\n"));
        assert!(result.ends_with("(exit)\n"));
        // (exit) from original should be stripped and re-added at end
        assert!(!result.contains("(exit)\n(exit)"));
    }

    #[test]
    fn augment_query_adds_check_sat_if_missing() {
        let script = "(assert (> x 0))\n";
        let result = augment_query_for_proof(script, "cvc5");
        assert!(result.contains("(check-sat)"));
        assert!(result.contains("(get-proof)"));
    }

    // -- canonicalize_obligation_smt2 --

    #[test]
    fn canonicalize_sorts_declarations_and_assertions() {
        let script = "(declare-const b Int)\n(declare-const a Int)\n(assert (> b 0))\n(assert (> a 0))\n(check-sat)\n(exit)\n";
        let canonical = canonicalize_obligation_smt2(script);
        let lines: Vec<&str> = canonical.lines().collect();
        // Declarations should be sorted
        let a_pos = lines.iter().position(|l| l.contains("declare-const a"));
        let b_pos = lines.iter().position(|l| l.contains("declare-const b"));
        assert!(a_pos.unwrap() < b_pos.unwrap());
        // Assertions should be sorted
        let assert_a_pos = lines.iter().position(|l| l.contains("(assert (> a"));
        let assert_b_pos = lines.iter().position(|l| l.contains("(assert (> b"));
        assert!(assert_a_pos.unwrap() < assert_b_pos.unwrap());
        // Should end with check-sat and exit
        assert!(canonical.contains("(check-sat)\n"));
        assert!(canonical.contains("(exit)\n"));
    }

    #[test]
    fn canonicalize_deduplicates() {
        let script = "(declare-const a Int)\n(declare-const a Int)\n(assert (> a 0))\n(assert (> a 0))\n(check-sat)\n";
        let canonical = canonicalize_obligation_smt2(script);
        assert_eq!(
            canonical.matches("(declare-const a Int)").count(),
            1
        );
        assert_eq!(canonical.matches("(assert (> a 0))").count(), 1);
    }

    #[test]
    fn canonicalize_default_logic() {
        let script = "(assert true)\n(check-sat)\n";
        let canonical = canonicalize_obligation_smt2(script);
        assert!(canonical.starts_with("(set-logic QF_LIA)\n"));
    }

    // -- obligations_all_unsat --

    #[test]
    fn obligations_all_unsat_empty() {
        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "x.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: None,
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![],
        };
        assert!(obligations_all_unsat(&metadata));
    }

    #[test]
    fn obligations_all_unsat_true() {
        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "x.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: None,
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![CertificateObligationMeta {
                name: "o1".into(),
                expected: "unsat".into(),
                file: "o1.smt2".into(),
                sha256: None,
                proof_file: None,
                proof_sha256: None,
            }],
        };
        assert!(obligations_all_unsat(&metadata));
    }

    #[test]
    fn obligations_all_unsat_false_when_sat_present() {
        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "x.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: None,
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![CertificateObligationMeta {
                name: "o1".into(),
                expected: "sat".into(),
                file: "o1.smt2".into(),
                sha256: None,
                proof_file: None,
                proof_sha256: None,
            }],
        };
        assert!(!obligations_all_unsat(&metadata));
    }

    // -- sanitize_artifact_component --

    #[cfg(feature = "governance")]
    #[test]
    fn sanitize_artifact_component_basic() {
        assert_eq!(sanitize_artifact_component("foo.trs"), "foo_trs");
        assert_eq!(
            sanitize_artifact_component("path/to/file.trs"),
            "path_to_file_trs"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn sanitize_artifact_component_empty() {
        assert_eq!(sanitize_artifact_component("..."), "entry");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn sanitize_artifact_component_special_chars() {
        assert_eq!(sanitize_artifact_component("a b"), "a_b");
        assert_eq!(
            sanitize_artifact_component("AB-cd_12"),
            "ab-cd_12"
        );
    }

    // -- CertificateKind --

    #[test]
    fn certificate_kind_as_str() {
        assert_eq!(CertificateKind::SafetyProof.as_str(), "safety_proof");
        assert_eq!(
            CertificateKind::FairLivenessProof.as_str(),
            "fair_liveness_proof"
        );
    }

    // -- CanonicalVerdict --

    #[test]
    fn canonical_verdict_as_str_and_display() {
        assert_eq!(CanonicalVerdict::Safe.as_str(), "SAFE");
        assert_eq!(CanonicalVerdict::Unsafe.as_str(), "UNSAFE");
        assert_eq!(CanonicalVerdict::LiveProved.as_str(), "LIVE_PROVED");
        assert_eq!(CanonicalVerdict::LiveCex.as_str(), "LIVE_CEX");
        assert_eq!(CanonicalVerdict::Inconclusive.as_str(), "INCONCLUSIVE");
        assert_eq!(CanonicalVerdict::Unknown.as_str(), "UNKNOWN");
        // Display should match as_str
        assert_eq!(format!("{}", CanonicalVerdict::Safe), "SAFE");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn parse_manifest_proof_engine_valid() {
        assert!(matches!(
            parse_manifest_proof_engine("kinduction"),
            Ok(ProofEngine::KInduction)
        ));
        assert!(matches!(
            parse_manifest_proof_engine("pdr"),
            Ok(ProofEngine::Pdr)
        ));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn parse_manifest_proof_engine_invalid() {
        assert!(parse_manifest_proof_engine("bmc").is_err());
    }
}
