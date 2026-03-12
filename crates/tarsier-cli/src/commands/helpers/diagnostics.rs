use std::collections::BTreeMap;

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{
    take_run_diagnostics, AutomatonFootprint, PipelineRunDiagnostics, SoundnessMode,
};

use super::{cli_network_mode_name, soundness_name};
use crate::{lint_protocol_file, CliNetworkSemanticsMode};

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
