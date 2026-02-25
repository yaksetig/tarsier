//! Diagnostic collection, profiling aggregation, and phase-level tracing helpers.

#![allow(unused_imports)]

use sha2::{Digest, Sha256};

use tarsier_dsl::ast;
use tarsier_smt::bmc::SmtRunProfile;

use super::*;

pub(super) fn push_lowering_diagnostic(diag: LoweringDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().lowerings.push(diag);
    });
}

pub(super) fn push_applied_reduction(diag: AppliedReductionDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().applied_reductions.push(diag);
    });
}

/// Add a reduction note once per run; duplicate notes are ignored.
pub(super) fn push_reduction_note(note: &str) {
    RUN_DIAGNOSTICS.with(|cell| {
        let mut guard = cell.borrow_mut();
        if !guard.reduction_notes.iter().any(|n| n == note) {
            guard.reduction_notes.push(note.to_string());
        }
    });
}

pub(super) fn sha256_hex_text(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(super) fn push_property_compilation_diagnostic(diag: PropertyCompilationDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().property_compilations.push(diag);
    });
}

pub(super) fn push_property_result_diagnostic(diag: PropertyResultDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().property_results.push(diag);
    });
}

pub(super) fn record_property_compilation(
    context: &str,
    prop: &ast::PropertyDecl,
    fragment: &str,
    compilation_target: &str,
    compiled_summary: String,
    compiled_payload: String,
) {
    let source_formula = prop.formula.to_string();
    push_property_compilation_diagnostic(PropertyCompilationDiagnostic {
        context: context.to_string(),
        property_name: prop.name.clone(),
        property_kind: prop.kind.to_string(),
        fragment: fragment.to_string(),
        source_formula_sha256: sha256_hex_text(&source_formula),
        source_formula,
        compilation_target: compilation_target.to_string(),
        compiled_sha256: sha256_hex_text(&compiled_payload),
        compiled_summary,
    });
}

pub(super) fn liveness_memory_budget_bytes() -> Option<u64> {
    current_execution_controls()
        .liveness_memory_budget_mb
        .filter(|mb| *mb > 0)
        .and_then(|mb| mb.checked_mul(1024 * 1024))
}

pub(super) fn liveness_memory_budget_reason(
    context: &str,
    frontier_frame: Option<usize>,
) -> Option<String> {
    let limit_bytes = liveness_memory_budget_bytes()?;
    let rss_bytes = current_rss_bytes()?;
    if rss_bytes <= limit_bytes {
        return None;
    }
    Some(match frontier_frame {
        Some(frame) => format!(
            "{context}: memory budget exceeded at frontier frame {frame} \
             (rss_bytes={rss_bytes}, limit_bytes={limit_bytes})."
        ),
        None => format!(
            "{context}: memory budget exceeded (rss_bytes={rss_bytes}, limit_bytes={limit_bytes})."
        ),
    })
}

/// Record a coarse phase runtime sample tagged with context and optional RSS.
pub(super) fn push_phase_profile(context: &str, phase: &str, elapsed_ms: u128) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut()
            .phase_profiles
            .push(PhaseProfileDiagnostic {
                context: context.to_string(),
                phase: phase.to_string(),
                elapsed_ms,
                rss_bytes: current_rss_bytes(),
            });
    });
}

pub(super) fn push_smt_profile(context: &str, profile: SmtRunProfile) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().smt_profiles.push(SmtProfileDiagnostic {
            context: context.to_string(),
            encode_calls: profile.encode_calls,
            encode_elapsed_ms: profile.encode_elapsed_ms,
            solve_calls: profile.solve_calls,
            solve_elapsed_ms: profile.solve_elapsed_ms,
            assertion_candidates: profile.assertion_candidates,
            assertion_unique: profile.assertion_unique,
            assertion_dedup_hits: profile.assertion_dedup_hits,
            incremental_depth_reuse_steps: profile.incremental_depth_reuse_steps,
            incremental_decl_reuse_hits: profile.incremental_decl_reuse_hits,
            incremental_assertion_reuse_hits: profile.incremental_assertion_reuse_hits,
            symmetry_candidates: profile.symmetry_candidates,
            symmetry_pruned: profile.symmetry_pruned,
            stutter_signature_normalizations: profile.stutter_signature_normalizations,
            por_pending_obligation_dedup_hits: profile.por_pending_obligation_dedup_hits,
            por_dynamic_ample_queries: profile.por_dynamic_ample_queries,
            por_dynamic_ample_fast_sat: profile.por_dynamic_ample_fast_sat,
            por_dynamic_ample_unsat_rechecks: profile.por_dynamic_ample_unsat_rechecks,
            por_dynamic_ample_unsat_recheck_sat: profile.por_dynamic_ample_unsat_recheck_sat,
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_property_decl() -> ast::PropertyDecl {
        let src = r#"
protocol DiagnosticsHelpers {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    role R {
        var decided: bool = false;
        init start;
        phase start {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let program = tarsier_dsl::parse(src, "diagnostics_helpers.trs").expect("parse");
        program.protocol.node.properties[0].node.clone()
    }

    #[test]
    fn push_reduction_note_deduplicates_identical_entries() {
        reset_run_diagnostics();
        push_reduction_note("encoder.structural_hashing=on");
        push_reduction_note("encoder.structural_hashing=on");
        push_reduction_note("por.stutter_time_signature_collapse=on");

        let diag = current_run_diagnostics();
        assert_eq!(
            diag.reduction_notes,
            vec![
                "encoder.structural_hashing=on".to_string(),
                "por.stutter_time_signature_collapse=on".to_string()
            ]
        );
    }

    #[test]
    fn sha256_hex_text_matches_known_vector() {
        assert_eq!(
            sha256_hex_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn record_property_compilation_captures_hashes_and_metadata() {
        reset_run_diagnostics();
        let prop = test_property_decl();
        let source_formula = prop.formula.to_string();

        record_property_compilation(
            "diag.test",
            &prop,
            "universal_safety",
            "safety_property",
            "agreement/invariant summary".into(),
            "compiled payload".into(),
        );

        let diag = take_run_diagnostics();
        assert_eq!(diag.property_compilations.len(), 1);
        let entry = &diag.property_compilations[0];
        assert_eq!(entry.context, "diag.test");
        assert_eq!(entry.property_name, "inv");
        assert_eq!(entry.property_kind, "safety");
        assert_eq!(entry.fragment, "universal_safety");
        assert_eq!(entry.compilation_target, "safety_property");
        assert_eq!(entry.source_formula, source_formula);
        assert_eq!(
            entry.source_formula_sha256,
            sha256_hex_text(&entry.source_formula)
        );
        assert_eq!(entry.compiled_sha256, sha256_hex_text("compiled payload"));
    }

    #[test]
    fn liveness_memory_budget_bytes_respects_override_presence_and_scaling() {
        clear_execution_controls_override();
        assert_eq!(liveness_memory_budget_bytes(), None);

        set_execution_controls(PipelineExecutionControls {
            liveness_memory_budget_mb: Some(0),
            ..Default::default()
        });
        assert_eq!(liveness_memory_budget_bytes(), None);

        set_execution_controls(PipelineExecutionControls {
            liveness_memory_budget_mb: Some(7),
            ..Default::default()
        });
        assert_eq!(liveness_memory_budget_bytes(), Some(7 * 1024 * 1024));
        clear_execution_controls_override();
    }

    #[test]
    fn liveness_memory_budget_reason_formats_frontier_context_when_exceeded() {
        set_execution_controls(PipelineExecutionControls {
            liveness_memory_budget_mb: Some(1),
            ..Default::default()
        });
        let reason = liveness_memory_budget_reason("fair-pdr", Some(3));
        clear_execution_controls_override();

        if let Some(rss) = current_rss_bytes() {
            if rss > 1024 * 1024 {
                let reason = reason.expect("expected memory-budget reason when rss > 1 MiB");
                assert!(reason.contains("fair-pdr"));
                assert!(reason.contains("frontier frame 3"));
                assert!(reason.contains("rss_bytes="));
                assert!(reason.contains("limit_bytes=1048576"));
            } else {
                assert!(
                    reason.is_none(),
                    "rss <= 1 MiB should not exceed a 1 MiB budget"
                );
            }
        } else {
            assert!(
                reason.is_none(),
                "unsupported RSS platform should return no budget reason"
            );
        }
    }

    #[test]
    fn push_phase_and_smt_profiles_capture_expected_fields() {
        reset_run_diagnostics();
        push_phase_profile("verify", "encode", 12);
        push_smt_profile(
            "verify",
            SmtRunProfile {
                encode_calls: 2,
                solve_calls: 3,
                encode_elapsed_ms: 10,
                solve_elapsed_ms: 15,
                assertion_candidates: 22,
                assertion_unique: 20,
                assertion_dedup_hits: 2,
                por_dynamic_ample_queries: 5,
                por_dynamic_ample_fast_sat: 4,
                por_dynamic_ample_unsat_rechecks: 1,
                por_dynamic_ample_unsat_recheck_sat: 0,
                ..Default::default()
            },
        );

        let diag = current_run_diagnostics();
        assert_eq!(diag.phase_profiles.len(), 1);
        assert_eq!(diag.phase_profiles[0].context, "verify");
        assert_eq!(diag.phase_profiles[0].phase, "encode");
        assert_eq!(diag.phase_profiles[0].elapsed_ms, 12);

        assert_eq!(diag.smt_profiles.len(), 1);
        let smt = &diag.smt_profiles[0];
        assert_eq!(smt.context, "verify");
        assert_eq!(smt.encode_calls, 2);
        assert_eq!(smt.solve_calls, 3);
        assert_eq!(smt.assertion_dedup_hits, 2);
        assert_eq!(smt.por_dynamic_ample_queries, 5);
    }
}
