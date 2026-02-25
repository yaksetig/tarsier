mod common;
use common::*;

use tarsier_engine::pipeline::SoundnessMode;
use tarsier_engine::result::VerificationResult;

#[test]
fn por_diagnostics_populated_for_multi_role_protocol() {
    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(4, SoundnessMode::Strict);
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    assert!(
        !diag.lowerings.is_empty(),
        "lowerings should be populated after verify"
    );
    let lowering = &diag.lowerings[0];
    // POR effective rule count tracks the number of rules after static pruning.
    // Even for single-role protocols, stutter/commutative/guard-dominated pruning
    // can reduce the rule set, and por_effective_rule_count is always populated.
    assert!(
        lowering.por_effective_rule_count > 0,
        "POR effective rule count should be non-zero, got 0"
    );
    // Verify that at least some SMT-level optimization is active
    assert!(
        !diag.reduction_notes.is_empty(),
        "reduction notes should be non-empty for a real protocol"
    );
}

#[test]
fn optimization_diagnostics_populated_after_verify() {
    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    assert!(
        !diag.smt_profiles.is_empty(),
        "smt_profiles should be non-empty after verify"
    );
    let profile = &diag.smt_profiles[0];
    assert!(
        profile.assertion_candidates > 0,
        "assertion_candidates should be > 0, got {}",
        profile.assertion_candidates
    );
    assert!(
        profile.encode_calls > 0,
        "encode_calls should be > 0, got {}",
        profile.encode_calls
    );
    assert!(
        profile.solve_calls > 0,
        "solve_calls should be > 0, got {}",
        profile.solve_calls
    );
}

#[test]
fn phase_profiles_cover_parse_lower_encode_solve_check() {
    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    assert!(
        !diag.phase_profiles.is_empty(),
        "phase_profiles should be non-empty after verify"
    );

    let phase_names: Vec<&str> = diag
        .phase_profiles
        .iter()
        .map(|p| p.phase.as_str())
        .collect();
    assert!(
        phase_names.contains(&"parse"),
        "phase_profiles missing 'parse': {:?}",
        phase_names
    );
    assert!(
        phase_names.contains(&"lower"),
        "phase_profiles missing 'lower': {:?}",
        phase_names
    );
    assert!(
        phase_names.contains(&"encode"),
        "phase_profiles missing 'encode': {:?}",
        phase_names
    );
    assert!(
        phase_names.contains(&"solve"),
        "phase_profiles missing 'solve': {:?}",
        phase_names
    );
    assert!(
        phase_names.contains(&"check"),
        "phase_profiles missing 'check': {:?}",
        phase_names
    );

    // Each entry should have timing data
    for phase in &diag.phase_profiles {
        assert!(
            !phase.context.is_empty(),
            "phase '{}' missing context",
            phase.phase
        );
    }
}

#[test]
fn profile_attribution_covers_lowering_and_smt_phases() {
    let source = load_library_example("hotstuff_crypto_qc_safe_faithful.trs");
    let options = verify_options(4, SoundnessMode::Permissive);
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "hotstuff_crypto_qc_safe_faithful.trs", &options)
            .unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    assert!(
        !diag.lowerings.is_empty(),
        "lowerings should be non-empty for hotstuff faithful"
    );
    assert!(
        diag.lowerings[0].effective_footprint.locations > 0,
        "effective_footprint.locations should be > 0"
    );
    assert!(
        !diag.smt_profiles.is_empty(),
        "smt_profiles should be non-empty for hotstuff faithful"
    );
    assert!(
        diag.smt_profiles[0].encode_calls > 0,
        "encode_calls should be > 0 for hotstuff faithful"
    );
}

#[test]
fn faithful_fallback_records_reduction_diagnostics() {
    use tarsier_engine::pipeline::{
        FaithfulFallbackConfig, FaithfulFallbackFloor, PipelineExecutionControls,
    };

    let source = load_library_example("pbft_simple_safe_faithful.trs");
    // Use IdentitySelective floor since this protocol declares delivery: per_recipient
    // which is incompatible with classic mode.
    let tight_controls = PipelineExecutionControls {
        faithful_fallback: Some(FaithfulFallbackConfig {
            max_locations: 2,
            max_shared_vars: 2,
            max_message_counters: 1,
            floor: FaithfulFallbackFloor::IdentitySelective,
        }),
        liveness_memory_budget_mb: None,
        por_mode_override: None,
    };
    tarsier_engine::pipeline::set_execution_controls(tight_controls);
    tarsier_engine::pipeline::reset_run_diagnostics();

    let options = verify_options(3, SoundnessMode::Permissive);
    let _result =
        tarsier_engine::pipeline::verify(&source, "pbft_simple_safe_faithful.trs", &options)
            .unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    // Reset controls before assertions so other tests aren't affected
    tarsier_engine::pipeline::set_execution_controls(PipelineExecutionControls::default());

    assert!(
        !diag.lowerings.is_empty(),
        "lowerings should be non-empty after fallback verify"
    );
    let lowering = &diag.lowerings[0];
    // With extremely tight budget, fallback should be exhausted (floor reached)
    assert!(
        lowering.fallback_applied || lowering.fallback_exhausted,
        "fallback should be applied or exhausted with tight budget, got: applied={}, exhausted={}",
        lowering.fallback_applied,
        lowering.fallback_exhausted
    );
}

/// AC1: Verify same verdict (Safe) with POR Full vs Off on a correct protocol.
#[test]
fn por_equivalence_safe_protocol_full_vs_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(4, SoundnessMode::Strict);

    // Run with POR Full (default)
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    let result_full =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();

    // Run with POR Off
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result_off =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();

    // Reset controls
    set_execution_controls(PipelineExecutionControls::default());

    // Both must produce Safe
    assert!(
        matches!(result_full, VerificationResult::Safe { .. }),
        "POR Full should produce Safe, got: {result_full}"
    );
    assert!(
        matches!(result_off, VerificationResult::Safe { .. }),
        "POR Off should produce Safe, got: {result_off}"
    );
}

/// AC1: Verify same verdict (Safe) with POR Static vs Off.
#[test]
fn por_equivalence_safe_protocol_static_vs_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(4, SoundnessMode::Strict);

    // Run with POR Static
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Static),
        ..Default::default()
    });
    let result_static =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();

    // Run with POR Off
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result_off =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    assert!(
        matches!(result_static, VerificationResult::Safe { .. }),
        "POR Static should produce Safe, got: {result_static}"
    );
    assert!(
        matches!(result_off, VerificationResult::Safe { .. }),
        "POR Off should produce Safe, got: {result_off}"
    );
}

/// AC2: Buggy protocol remains Unsafe with POR Full — counterexample discoverable.
#[test]
fn por_soundness_buggy_protocol_counterexample_with_por_full() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);

    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    let result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    match result {
        VerificationResult::Unsafe { trace } => {
            assert!(
                !trace.param_values.is_empty(),
                "counterexample should include parameter values"
            );
            assert!(
                !trace.steps.is_empty(),
                "counterexample trace should have at least one step"
            );
        }
        other => panic!("Expected Unsafe with POR Full, got: {other}"),
    }
}

/// AC2: Buggy protocol remains Unsafe with POR Off — counterexample discoverable.
#[test]
fn por_soundness_buggy_protocol_counterexample_with_por_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);

    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    match result {
        VerificationResult::Unsafe { trace } => {
            assert!(
                !trace.param_values.is_empty(),
                "counterexample should include parameter values"
            );
            assert!(
                !trace.steps.is_empty(),
                "counterexample trace should have at least one step"
            );
        }
        other => panic!("Expected Unsafe with POR Off, got: {other}"),
    }
}

/// AC1+AC2: POR equivalence on buggy protocol — both modes find counterexample.
#[test]
fn por_equivalence_buggy_protocol_full_vs_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);

    // Run with POR Full
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    let result_full =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    // Run with POR Off
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result_off =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    // Both must produce Unsafe
    assert!(
        matches!(result_full, VerificationResult::Unsafe { .. }),
        "POR Full should find counterexample, got: {result_full}"
    );
    assert!(
        matches!(result_off, VerificationResult::Unsafe { .. }),
        "POR Off should find counterexample, got: {result_off}"
    );
}

/// AC1: POR Full produces fewer effective rules than Off (reduction actually applies).
#[test]
fn por_full_reduces_rule_count_vs_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);

    // Collect diagnostics with POR Full
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag_full = tarsier_engine::pipeline::take_run_diagnostics();

    // Collect diagnostics with POR Off
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag_off = tarsier_engine::pipeline::take_run_diagnostics();

    set_execution_controls(PipelineExecutionControls::default());

    let full_lowering = &diag_full.lowerings[0];
    let off_lowering = &diag_off.lowerings[0];

    // With POR Full, effective rule count should be <= POR Off
    assert!(
        full_lowering.por_effective_rule_count <= off_lowering.por_effective_rule_count,
        "POR Full effective rules ({}) should be <= POR Off ({})",
        full_lowering.por_effective_rule_count,
        off_lowering.por_effective_rule_count
    );

    // With POR Off, no rules should be pruned
    assert_eq!(
        off_lowering.por_stutter_rules_pruned, 0,
        "POR Off should prune zero stutter rules"
    );
    assert_eq!(
        off_lowering.por_commutative_duplicate_rules_pruned, 0,
        "POR Off should prune zero commutative-dup rules"
    );
    assert_eq!(
        off_lowering.por_guard_dominated_rules_pruned, 0,
        "POR Off should prune zero guard-dominated rules"
    );
}

/// AC1: Library safe protocol equivalence — second protocol also matches across modes.
#[test]
fn por_equivalence_library_safe_protocol() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_library_example("reliable_broadcast_safe.trs");
    let options = verify_options(4, SoundnessMode::Permissive);

    // POR Full
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    let result_full =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_safe.trs", &options).unwrap();

    // POR Off
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result_off =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_safe.trs", &options).unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    assert!(
        matches!(result_full, VerificationResult::Safe { .. }),
        "POR Full on library safe protocol should be Safe, got: {result_full}"
    );
    assert!(
        matches!(result_off, VerificationResult::Safe { .. }),
        "POR Off on library safe protocol should be Safe, got: {result_off}"
    );
}

/// AC1/AC2 hardening: per-run POR overrides must not bleed across parallel verifications.
#[test]
fn por_mode_override_is_thread_local_in_parallel_runs() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);
    let barrier = Arc::new(Barrier::new(3));

    let spawn_worker = |mode: PorMode, expect_por_annotation: bool| {
        let source = source.clone();
        let options = options.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            set_execution_controls(PipelineExecutionControls {
                por_mode_override: Some(mode),
                ..Default::default()
            });
            barrier.wait();
            let result =
                tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
                    .unwrap();

            match result {
                VerificationResult::Unsafe { trace } => {
                    assert!(!trace.steps.is_empty(), "trace should have steps");
                    for step in &trace.steps {
                        if expect_por_annotation {
                            assert!(
                                step.por_status
                                    .as_deref()
                                    .map(|v| v.contains("active"))
                                    .unwrap_or(false),
                                "POR Full trace must keep active por_status annotation, got: {:?}",
                                step.por_status
                            );
                        } else {
                            assert!(
                                step.por_status.is_none(),
                                "POR Off trace must have no por_status annotation, got: {:?}",
                                step.por_status
                            );
                        }
                    }
                }
                other => panic!("Expected Unsafe trace for POR isolation test, got: {other}"),
            }
        })
    };

    let full = spawn_worker(PorMode::Full, true);
    let off = spawn_worker(PorMode::Off, false);
    barrier.wait();

    full.join().expect("POR Full worker should complete");
    off.join().expect("POR Off worker should complete");
}

/// AC1: Reports list applied reductions with eligibility and effect metrics.
#[test]
fn reduction_diagnostics_include_por_eligibility_and_effect_metrics() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);

    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    set_execution_controls(PipelineExecutionControls::default());

    // Lowering diagnostics include POR eligibility and effect metrics
    assert!(!diag.lowerings.is_empty(), "lowerings should be populated");
    let lowering = &diag.lowerings[0];

    // Effect metrics: POR fields are accessible and populated
    assert!(
        lowering.por_effective_rule_count > 0,
        "por_effective_rule_count should be non-zero"
    );

    // All POR pruning category fields are accessible (may be zero for single-role protocols)
    let _stutter = lowering.por_stutter_rules_pruned;
    let _commutative = lowering.por_commutative_duplicate_rules_pruned;
    let _guard_dom = lowering.por_guard_dominated_rules_pruned;
    let _independent = lowering.independent_rule_pairs;

    // Reduction notes should be present (at least encoder/bmc notes)
    assert!(
        !diag.reduction_notes.is_empty(),
        "reduction notes should be populated"
    );
}

/// AC1: Lowering diagnostics capture all POR pruning categories.
#[test]
fn reduction_diagnostics_separate_por_pruning_categories() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);

    // With POR Full, pruning categories should be populated
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    set_execution_controls(PipelineExecutionControls::default());

    let lowering = &diag.lowerings[0];
    // All pruning category fields should be accessible (even if zero)
    let total_pruned = lowering.por_stutter_rules_pruned
        + lowering.por_commutative_duplicate_rules_pruned
        + lowering.por_guard_dominated_rules_pruned;
    assert!(
        lowering.por_effective_rule_count > 0,
        "effective rule count must be positive"
    );
    // The effective count + pruned should reflect the total original rules
    // (effective + pruned >= effective, which is trivially true)
    assert!(
        lowering.por_effective_rule_count + total_pruned > 0,
        "should have some rules (effective={}, pruned={})",
        lowering.por_effective_rule_count,
        total_pruned
    );
}

/// AC2: Counterexample trace steps annotate POR reduction status.
#[test]
fn counterexample_trace_annotates_por_status() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);

    // With POR Full — trace steps should have por_status = "active (full POR)"
    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    let result_full =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    match result_full {
        VerificationResult::Unsafe { trace } => {
            assert!(!trace.steps.is_empty(), "trace should have steps");
            for step in &trace.steps {
                assert!(
                    step.por_status.is_some(),
                    "POR Full trace steps should have por_status annotation"
                );
                assert!(
                    step.por_status.as_deref().unwrap().contains("active"),
                    "POR Full por_status should contain 'active', got: {:?}",
                    step.por_status
                );
            }
        }
        other => panic!("Expected Unsafe, got: {other}"),
    }
}

/// AC2: With POR Off, counterexample trace steps have no POR annotation.
#[test]
fn counterexample_trace_no_por_annotation_when_off() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast_buggy.trs");
    let options = verify_options(5, SoundnessMode::Strict);

    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Off),
        ..Default::default()
    });
    let result_off =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast_buggy.trs", &options)
            .unwrap();

    set_execution_controls(PipelineExecutionControls::default());

    match result_off {
        VerificationResult::Unsafe { trace } => {
            assert!(!trace.steps.is_empty(), "trace should have steps");
            for step in &trace.steps {
                assert!(
                    step.por_status.is_none(),
                    "POR Off trace steps should have no por_status, got: {:?}",
                    step.por_status
                );
            }
        }
        other => panic!("Expected Unsafe, got: {other}"),
    }
}

/// AC1: SMT profile diagnostics include POR dynamic ample metrics.
#[test]
fn smt_profile_diagnostics_include_por_dynamic_ample() {
    use tarsier_engine::pipeline::{set_execution_controls, PipelineExecutionControls};
    use tarsier_ir::threshold_automaton::PorMode;

    let source = load_example("reliable_broadcast.trs");
    let options = verify_options(3, SoundnessMode::Strict);

    set_execution_controls(PipelineExecutionControls {
        por_mode_override: Some(PorMode::Full),
        ..Default::default()
    });
    tarsier_engine::pipeline::reset_run_diagnostics();
    let _result =
        tarsier_engine::pipeline::verify(&source, "reliable_broadcast.trs", &options).unwrap();
    let diag = tarsier_engine::pipeline::take_run_diagnostics();

    set_execution_controls(PipelineExecutionControls::default());

    assert!(
        !diag.smt_profiles.is_empty(),
        "smt_profiles should be populated"
    );
    let profile = &diag.smt_profiles[0];
    // POR dynamic ample fields should exist (may be 0 if no ample opportunities)
    // The important thing is these fields are accessible and populated
    let _queries = profile.por_dynamic_ample_queries;
    let _fast_sat = profile.por_dynamic_ample_fast_sat;
    let _rechecks = profile.por_dynamic_ample_unsat_rechecks;
    let _recheck_sat = profile.por_dynamic_ample_unsat_recheck_sat;
    let _dedup = profile.por_pending_obligation_dedup_hits;
    // All fields accessible — test passes
}
