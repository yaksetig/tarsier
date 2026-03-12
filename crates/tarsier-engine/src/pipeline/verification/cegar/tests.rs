use super::*;
use std::collections::BTreeSet;

// ── Helper builders ──────────────────────────────────────────────

fn atom_global_equivocation() -> CegarAtomicRefinement {
    CegarAtomicRefinement::global(
        CegarRefinementKind::GlobalEquivocationNone,
        "equivocation:none",
        "adversary.equivocation=none",
    )
}

fn atom_global_auth() -> CegarAtomicRefinement {
    CegarAtomicRefinement::global(
        CegarRefinementKind::GlobalAuthSigned,
        "auth:signed",
        "adversary.auth=signed",
    )
}

fn atom_global_values() -> CegarAtomicRefinement {
    CegarAtomicRefinement::global(
        CegarRefinementKind::GlobalValuesExact,
        "values:exact",
        "adversary.values=exact",
    )
}

fn atom_global_network_identity() -> CegarAtomicRefinement {
    CegarAtomicRefinement::global(
        CegarRefinementKind::GlobalNetworkIdentitySelective,
        "network:identity_selective",
        "adversary.network=identity_selective",
    )
}

fn atom_global_network_process() -> CegarAtomicRefinement {
    CegarAtomicRefinement::global(
        CegarRefinementKind::GlobalNetworkProcessSelective,
        "network:process_selective",
        "adversary.network=process_selective",
    )
}

fn default_signals() -> CegarTraceSignals {
    CegarTraceSignals::default()
}

fn signals_conflicting_variants() -> CegarTraceSignals {
    CegarTraceSignals {
        conflicting_variants: true,
        ..Default::default()
    }
}

fn signals_cross_recipient() -> CegarTraceSignals {
    CegarTraceSignals {
        cross_recipient_delivery: true,
        ..Default::default()
    }
}

fn signals_sign_abstract() -> CegarTraceSignals {
    CegarTraceSignals {
        sign_abstract_values: true,
        ..Default::default()
    }
}

fn signals_all() -> CegarTraceSignals {
    CegarTraceSignals {
        conflicting_variants: true,
        cross_recipient_delivery: true,
        sign_abstract_values: true,
        identity_scoped_channels: true,
        conflicting_variant_families: BTreeSet::from(["Vote".to_string()]),
        cross_recipient_families: BTreeSet::from(["Vote".to_string()]),
    }
}

fn parse_test_program(source: &str) -> ast::Program {
    tarsier_dsl::parse(source, "cegar_test.trs").expect("test program should parse")
}

// ── CegarAtomicRefinement constructors ───────────────────────────

#[test]
fn atomic_refinement_global_constructor() {
    let atom = atom_global_equivocation();
    assert_eq!(atom.label, "equivocation:none");
    assert_eq!(atom.predicate, "adversary.equivocation=none");
    assert_eq!(atom.kind, CegarRefinementKind::GlobalEquivocationNone);
}

#[test]
fn atomic_refinement_message_equivocation_none() {
    let atom = CegarAtomicRefinement::message_equivocation_none("Vote");
    assert_eq!(atom.label, "equivocation:Vote=none");
    assert_eq!(atom.predicate, "equivocation(Vote)=none");
    assert_eq!(
        atom.kind,
        CegarRefinementKind::MessageEquivocationNone {
            message: "Vote".to_string()
        }
    );
}

#[test]
fn atomic_refinement_message_auth_authenticated() {
    let atom = CegarAtomicRefinement::message_auth_authenticated("Propose");
    assert_eq!(atom.label, "channel:Propose=authenticated");
    assert_eq!(atom.predicate, "channel(Propose)=authenticated");
    assert_eq!(
        atom.kind,
        CegarRefinementKind::MessageAuthAuthenticated {
            message: "Propose".to_string()
        }
    );
}

// ── CegarRefinement label and refinements ────────────────────────

#[test]
fn refinement_label_single_atom() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation()],
    };
    assert_eq!(r.label(), "equivocation:none");
}

#[test]
fn refinement_label_multiple_atoms_joined_with_plus() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation(), atom_global_auth()],
    };
    assert_eq!(r.label(), "equivocation:none+auth:signed");
}

#[test]
fn refinement_label_empty_atoms() {
    let r = CegarRefinement { atoms: vec![] };
    assert_eq!(r.label(), "");
}

#[test]
fn refinement_refinements_collects_predicates() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation(), atom_global_values()],
    };
    assert_eq!(
        r.refinements(),
        vec![
            "adversary.equivocation=none".to_string(),
            "adversary.values=exact".to_string()
        ]
    );
}

#[test]
fn refinement_refinements_empty() {
    let r = CegarRefinement { atoms: vec![] };
    assert!(r.refinements().is_empty());
}

// ── parse_counter_signature ──────────────────────────────────────

#[test]
fn parse_counter_signature_basic() {
    let result = parse_counter_signature("cnt_Vote@R1");
    assert_eq!(
        result,
        Some((
            "Vote".to_string(),
            "Vote".to_string(),
            Some("R1".to_string())
        ))
    );
}

#[test]
fn parse_counter_signature_with_variant_fields() {
    // variant_suffix is derived from the full stripped string, so
    // includes everything after the first '[' in the stripped name.
    let result = parse_counter_signature("cnt_Vote[v=true]@R1");
    assert_eq!(
        result,
        Some((
            "Vote".to_string(),
            "Vote[v=true]@R1".to_string(),
            Some("R1".to_string())
        ))
    );
}

#[test]
fn parse_counter_signature_with_recipient_and_sender() {
    let result = parse_counter_signature("cnt_Vote@R1<-S1");
    assert_eq!(
        result,
        Some((
            "Vote".to_string(),
            "Vote".to_string(),
            Some("R1".to_string())
        ))
    );
}

#[test]
fn parse_counter_signature_no_cnt_prefix() {
    assert_eq!(parse_counter_signature("Vote@R1"), None);
}

#[test]
fn parse_counter_signature_no_at_sign() {
    assert_eq!(parse_counter_signature("cnt_Vote"), None);
}

#[test]
fn parse_counter_signature_identity_scoped_recipient() {
    let result = parse_counter_signature("cnt_Vote@R1#0");
    assert_eq!(
        result,
        Some((
            "Vote".to_string(),
            "Vote".to_string(),
            Some("R1#0".to_string())
        ))
    );
}

#[test]
fn parse_counter_signature_recipient_with_bracket_suffix() {
    // When recipient part has brackets, variant_suffix picks up from
    // the first '[' in the full stripped string.
    let result = parse_counter_signature("cnt_Vote@R1[x]");
    assert_eq!(
        result,
        Some((
            "Vote".to_string(),
            "Vote[x]".to_string(),
            Some("R1".to_string())
        ))
    );
}

// ── cegar_core_compound_predicate ────────────────────────────────

#[test]
fn compound_predicate_with_multiple_predicates() {
    let preds = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    assert_eq!(
        cegar_core_compound_predicate(&preds),
        Some("cegar.core.min(a && b && c)".to_string())
    );
}

#[test]
fn compound_predicate_single_returns_none() {
    let preds = vec!["a".to_string()];
    assert_eq!(cegar_core_compound_predicate(&preds), None);
}

#[test]
fn compound_predicate_empty_returns_none() {
    let preds: Vec<String> = vec![];
    assert_eq!(cegar_core_compound_predicate(&preds), None);
}

// ── cegar_selection_timeout_secs ─────────────────────────────────

#[test]
fn selection_timeout_clamps_to_range() {
    assert_eq!(cegar_selection_timeout_secs(0), 1);
    assert_eq!(cegar_selection_timeout_secs(1), 1);
    assert_eq!(cegar_selection_timeout_secs(10), 10);
    assert_eq!(cegar_selection_timeout_secs(15), 15);
    assert_eq!(cegar_selection_timeout_secs(100), 15);
}

// ── cegar_refinement_score ───────────────────────────────────────

#[test]
fn score_global_equivocation_base() {
    let score = cegar_refinement_score(&atom_global_equivocation(), &default_signals());
    assert_eq!(score, 40);
}

#[test]
fn score_global_equivocation_with_conflicting_variants() {
    let score =
        cegar_refinement_score(&atom_global_equivocation(), &signals_conflicting_variants());
    assert_eq!(score, 40 + 220);
}

#[test]
fn score_global_auth_with_both_signals() {
    let signals = CegarTraceSignals {
        conflicting_variants: true,
        cross_recipient_delivery: true,
        ..Default::default()
    };
    let score = cegar_refinement_score(&atom_global_auth(), &signals);
    // base 30 + 60 (conflicting||cross) + 25 (evidence_count=2)
    assert_eq!(score, 30 + 60 + 25);
}

#[test]
fn score_global_values_with_sign_abstract() {
    let score = cegar_refinement_score(&atom_global_values(), &signals_sign_abstract());
    assert_eq!(score, 80 + 120);
}

#[test]
fn score_global_network_identity_with_cross_recipient() {
    let score = cegar_refinement_score(&atom_global_network_identity(), &signals_cross_recipient());
    assert_eq!(score, 30 + 70);
}

#[test]
fn score_global_network_process_with_cross_and_identity() {
    let signals = CegarTraceSignals {
        cross_recipient_delivery: true,
        identity_scoped_channels: true,
        ..Default::default()
    };
    let score = cegar_refinement_score(&atom_global_network_process(), &signals);
    // base 20 + 95 (cross) + 10 (identity) + 25 (evidence_count=2)
    assert_eq!(score, 20 + 95 + 10 + 25);
}

#[test]
fn score_message_equivocation_with_matching_family() {
    let mut signals = default_signals();
    signals
        .conflicting_variant_families
        .insert("Vote".to_string());
    let atom = CegarAtomicRefinement::message_equivocation_none("Vote");
    let score = cegar_refinement_score(&atom, &signals);
    assert_eq!(score, 50 + 205);
}

#[test]
fn score_message_auth_with_cross_recipient_family() {
    let mut signals = default_signals();
    signals.cross_recipient_families.insert("Vote".to_string());
    let atom = CegarAtomicRefinement::message_auth_authenticated("Vote");
    let score = cegar_refinement_score(&atom, &signals);
    assert_eq!(score, 35 + 145);
}

// ── cegar_atom_evidence_tag_count ─────────────────────────────────

#[test]
fn evidence_tag_count_zero_on_no_signals() {
    let count = cegar_atom_evidence_tag_count(&atom_global_equivocation(), &default_signals());
    assert_eq!(count, 0);
}

#[test]
fn evidence_tag_count_one_for_equivocation_conflicting() {
    let count =
        cegar_atom_evidence_tag_count(&atom_global_equivocation(), &signals_conflicting_variants());
    assert_eq!(count, 1);
}

#[test]
fn evidence_tag_count_two_for_auth_both_signals() {
    let signals = CegarTraceSignals {
        conflicting_variants: true,
        cross_recipient_delivery: true,
        ..Default::default()
    };
    let count = cegar_atom_evidence_tag_count(&atom_global_auth(), &signals);
    assert_eq!(count, 2);
}

#[test]
fn evidence_tag_count_process_selective_two_signals() {
    let signals = CegarTraceSignals {
        cross_recipient_delivery: true,
        identity_scoped_channels: true,
        ..Default::default()
    };
    let count = cegar_atom_evidence_tag_count(&atom_global_network_process(), &signals);
    assert_eq!(count, 2);
}

// ── cegar_atom_evidence_tags ──────────────────────────────────────

#[test]
fn evidence_tags_empty_on_no_signals() {
    let tags = cegar_atom_evidence_tags(&atom_global_equivocation(), &default_signals());
    assert!(tags.is_empty());
}

#[test]
fn evidence_tags_for_message_equivocation() {
    let atom = CegarAtomicRefinement::message_equivocation_none("Vote");
    let signals = signals_all();
    let tags = cegar_atom_evidence_tags(&atom, &signals);
    assert!(tags.contains(&"conflicting_variants".to_string()));
    assert!(tags.contains(&"conflicting_variants:Vote".to_string()));
    assert!(tags.contains(&"cross_recipient_delivery:Vote".to_string()));
}

#[test]
fn evidence_tags_for_message_auth() {
    let atom = CegarAtomicRefinement::message_auth_authenticated("Vote");
    let signals = signals_all();
    let tags = cegar_atom_evidence_tags(&atom, &signals);
    assert!(tags.contains(&"cross_recipient_delivery".to_string()));
    assert!(tags.contains(&"cross_recipient_delivery:Vote".to_string()));
    assert!(tags.contains(&"conflicting_variants:Vote".to_string()));
}

// ── cegar_signal_tags ────────────────────────────────────────────

#[test]
fn signal_tags_empty_default() {
    let tags = cegar_signal_tags(&default_signals());
    assert!(tags.is_empty());
}

#[test]
fn signal_tags_all_flags() {
    let signals = CegarTraceSignals {
        conflicting_variants: true,
        cross_recipient_delivery: true,
        sign_abstract_values: true,
        identity_scoped_channels: true,
        ..Default::default()
    };
    let tags = cegar_signal_tags(&signals);
    assert_eq!(tags.len(), 4);
    assert!(tags.contains(&"conflicting_variants"));
    assert!(tags.contains(&"cross_recipient_delivery"));
    assert!(tags.contains(&"sign_abstract_values"));
    assert!(tags.contains(&"identity_scoped_channels"));
}

// ── cegar_signals_note ───────────────────────────────────────────

#[test]
fn signals_note_none_when_empty() {
    assert!(cegar_signals_note(&default_signals()).is_none());
}

#[test]
fn signals_note_some_when_signals_present() {
    let note = cegar_signals_note(&signals_conflicting_variants());
    assert!(note.is_some());
    assert!(note.unwrap().contains("conflicting_variants"));
}

// ── CegarTraceSignals default ────────────────────────────────────

#[test]
fn trace_signals_default_all_false() {
    let s = CegarTraceSignals::default();
    assert!(!s.conflicting_variants);
    assert!(!s.cross_recipient_delivery);
    assert!(!s.sign_abstract_values);
    assert!(!s.identity_scoped_channels);
    assert!(s.conflicting_variant_families.is_empty());
    assert!(s.cross_recipient_families.is_empty());
}

#[test]
fn liveness_realizability_atoms_filter_existing_and_prioritize_signal_atoms() {
    let program = parse_test_program(
        r#"
protocol CegarRealizabilityCandidates {
params n, t;
resilience: n > 3*t;
adversary { model: byzantine; bound: t; equivocation: full; auth: none; }
message Vote(v: bool);
role R {
    init s;
    phase s {}
}
}
"#,
    );
    let mut signals = CegarTraceSignals {
        conflicting_variants: true,
        ..Default::default()
    };
    signals.conflicting_variant_families.insert("Vote".into());
    let existing = vec!["adversary.equivocation=none".to_string()];
    let atoms = cegar_liveness_realizability_atoms(&program, &signals, &existing);

    assert!(!atoms.is_empty());
    assert!(
        atoms
            .iter()
            .all(|a| a.predicate != "adversary.equivocation=none"),
        "existing predicates must be filtered out"
    );
    assert_eq!(
        atoms[0].predicate, "equivocation(Vote)=none",
        "signal-derived message refinement should be prioritized"
    );
}

// ── combinations_of_size ─────────────────────────────────────────

#[test]
fn combinations_pick_zero() {
    let result = combinations_of_size(5, 0);
    assert_eq!(result, vec![Vec::<usize>::new()]);
}

#[test]
fn combinations_pick_exceeds_len() {
    let result = combinations_of_size(2, 5);
    assert!(result.is_empty());
}

#[test]
fn combinations_pick_one() {
    let result = combinations_of_size(3, 1);
    assert_eq!(result, vec![vec![0], vec![1], vec![2]]);
}

#[test]
fn combinations_pick_two_from_four() {
    let result = combinations_of_size(4, 2);
    assert_eq!(result.len(), 6);
    assert_eq!(
        result,
        vec![
            vec![0, 1],
            vec![0, 2],
            vec![0, 3],
            vec![1, 2],
            vec![1, 3],
            vec![2, 3]
        ]
    );
}

#[test]
fn combinations_pick_all() {
    let result = combinations_of_size(3, 3);
    assert_eq!(result, vec![vec![0, 1, 2]]);
}

// ── sorted_unique_strings ────────────────────────────────────────

#[test]
fn sorted_unique_deduplicates_and_sorts() {
    let input = vec![
        "c".to_string(),
        "a".to_string(),
        "b".to_string(),
        "a".to_string(),
    ];
    let result = sorted_unique_strings(input);
    assert_eq!(
        result,
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
}

#[test]
fn sorted_unique_empty() {
    let result = sorted_unique_strings(vec![]);
    assert!(result.is_empty());
}

// ── CegarStageEvalCache ──────────────────────────────────────────

#[test]
fn eval_cache_default_counts_zero() {
    let cache: CegarStageEvalCache<i32> = CegarStageEvalCache::default();
    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 0);
}

#[test]
fn eval_cache_key_baseline() {
    let r = CegarRefinement { atoms: vec![] };
    let key = CegarStageEvalCache::<i32>::key(&r);
    assert_eq!(key, "<baseline>");
}

#[test]
fn eval_cache_key_single_atom() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation()],
    };
    let key = CegarStageEvalCache::<i32>::key(&r);
    assert_eq!(key, "adversary.equivocation=none");
}

#[test]
fn eval_cache_key_multiple_atoms_sorted() {
    let r = CegarRefinement {
        atoms: vec![atom_global_auth(), atom_global_equivocation()],
    };
    let key = CegarStageEvalCache::<i32>::key(&r);
    assert_eq!(key, "adversary.auth=signed && adversary.equivocation=none");
}

#[test]
fn eval_cache_miss_then_hit() {
    let mut cache: CegarStageEvalCache<i32> = CegarStageEvalCache::default();
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation()],
    };
    let val = cache.eval(&r, || Ok(42)).unwrap();
    assert_eq!(val, 42);
    assert_eq!(cache.misses, 1);
    assert_eq!(cache.hits, 0);

    let val2 = cache.eval(&r, || Ok(99)).unwrap();
    assert_eq!(val2, 42);
    assert_eq!(cache.misses, 1);
    assert_eq!(cache.hits, 1);
}

#[test]
fn eval_cache_propagates_error() {
    let mut cache: CegarStageEvalCache<i32> = CegarStageEvalCache::default();
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation()],
    };
    let result = cache.eval(&r, || Err(PipelineError::Solver("fail".into())));
    assert!(result.is_err());
}

// ── cegar_shrink_refinement_core ─────────────────────────────────

#[test]
fn shrink_core_single_atom_returns_none() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation()],
    };
    let result = cegar_shrink_refinement_core(&r, |_| Ok(Some(true))).unwrap();
    assert!(result.is_none());
}

#[test]
fn shrink_core_empty_returns_none() {
    let r = CegarRefinement { atoms: vec![] };
    let result = cegar_shrink_refinement_core(&r, |_| Ok(Some(true))).unwrap();
    assert!(result.is_none());
}

#[test]
fn shrink_core_removes_unnecessary_atom() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation(), atom_global_auth()],
    };
    let result = cegar_shrink_refinement_core(&r, |_candidate| Ok(Some(true))).unwrap();
    assert!(result.is_some());
    let shrunk = result.unwrap();
    assert_eq!(shrunk.atoms.len(), 1);
}

#[test]
fn shrink_core_keeps_all_when_all_needed() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation(), atom_global_auth()],
    };
    let result = cegar_shrink_refinement_core(&r, |_| Ok(Some(false))).unwrap();
    assert!(result.is_none());
}

#[test]
fn shrink_core_returns_none_on_eval_none() {
    let r = CegarRefinement {
        atoms: vec![atom_global_equivocation(), atom_global_auth()],
    };
    let result = cegar_shrink_refinement_core(&r, |_| Ok(None)).unwrap();
    assert!(result.is_none());
}

// ── cegar_stage_counterexample_analysis ───────────────────────────

#[test]
fn counterexample_analysis_baseline_not_unsafe_returns_none() {
    let result = cegar_stage_counterexample_analysis(
        0,
        &[],
        &VerificationResult::Safe { depth_checked: 3 },
        false,
        None,
    );
    assert!(result.is_none());
}

#[test]
fn counterexample_analysis_baseline_stage_0_unsafe() {
    let result = cegar_stage_counterexample_analysis(
        0,
        &[],
        &VerificationResult::Unsafe {
            trace: tarsier_ir::counter_system::Trace {
                initial_config: tarsier_ir::counter_system::Configuration {
                    kappa: vec![],
                    gamma: vec![],
                    params: vec![],
                },
                steps: vec![],
                param_values: vec![],
            },
        },
        true,
        None,
    );
    let analysis = result.unwrap();
    assert_eq!(analysis.classification, "potentially_spurious");
    assert!(analysis
        .rationale
        .contains("Baseline stage reported UNSAFE"));
}

#[test]
fn counterexample_analysis_later_stage_unsafe_is_concrete() {
    let result = cegar_stage_counterexample_analysis(
        1,
        &["adversary.equivocation=none".to_string()],
        &VerificationResult::Unsafe {
            trace: tarsier_ir::counter_system::Trace {
                initial_config: tarsier_ir::counter_system::Configuration {
                    kappa: vec![],
                    gamma: vec![],
                    params: vec![],
                },
                steps: vec![],
                param_values: vec![],
            },
        },
        true,
        None,
    );
    let analysis = result.unwrap();
    assert_eq!(analysis.classification, "concrete");
    assert!(analysis.rationale.contains("persists"));
}

#[test]
fn counterexample_analysis_safe_result_is_potentially_spurious() {
    let result = cegar_stage_counterexample_analysis(
        1,
        &["adversary.equivocation=none".to_string()],
        &VerificationResult::Safe { depth_checked: 3 },
        true,
        None,
    );
    let analysis = result.unwrap();
    assert_eq!(analysis.classification, "potentially_spurious");
    assert!(analysis.rationale.contains("eliminated"));
}

#[test]
fn counterexample_analysis_unknown_result_is_inconclusive() {
    let result = cegar_stage_counterexample_analysis(
        1,
        &["adversary.equivocation=none".to_string()],
        &VerificationResult::Unknown {
            reason: "timeout".into(),
        },
        true,
        None,
    );
    let analysis = result.unwrap();
    assert_eq!(analysis.classification, "inconclusive");
}

// ── stage_outcome_from_verification ───────────────────────────────

#[test]
fn stage_outcome_safe() {
    let outcome = stage_outcome_from_verification(&VerificationResult::Safe { depth_checked: 5 });
    assert!(matches!(
        outcome,
        CegarStageOutcome::Safe { depth_checked: 5 }
    ));
}

#[test]
fn stage_outcome_unknown() {
    let outcome = stage_outcome_from_verification(&VerificationResult::Unknown {
        reason: "timeout".into(),
    });
    match outcome {
        CegarStageOutcome::Unknown { reason } => assert_eq!(reason, "timeout"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn lasso_witness_extraction_slices_loop_segment() {
    let trace = tarsier_ir::counter_system::Trace {
        initial_config: tarsier_ir::counter_system::Configuration {
            kappa: vec![1, 0],
            gamma: vec![0],
            params: vec![4, 1],
        },
        steps: vec![
            tarsier_ir::counter_system::TraceStep {
                smt_step: 0,
                rule_id: 2.into(),
                delta: 1,
                deliveries: vec![],
                config: tarsier_ir::counter_system::Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![0],
                    params: vec![4, 1],
                },
                por_status: None,
            },
            tarsier_ir::counter_system::TraceStep {
                smt_step: 1,
                rule_id: 3.into(),
                delta: 1,
                deliveries: vec![],
                config: tarsier_ir::counter_system::Configuration {
                    kappa: vec![1, 0],
                    gamma: vec![1],
                    params: vec![4, 1],
                },
                por_status: None,
            },
            tarsier_ir::counter_system::TraceStep {
                smt_step: 2,
                rule_id: 2.into(),
                delta: 1,
                deliveries: vec![],
                config: tarsier_ir::counter_system::Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![1],
                    params: vec![4, 1],
                },
                por_status: None,
            },
        ],
        param_values: vec![("n".into(), 4), ("t".into(), 1)],
    };

    let witness = cegar_extract_lasso_witness(3, 1, &trace);
    assert_eq!(witness.depth, 3);
    assert_eq!(witness.loop_start, 1);
    assert_eq!(witness.prefix_len, 1);
    assert_eq!(witness.loop_len, 2);
    assert_eq!(witness.trace_steps, 3);
    assert_eq!(witness.loop_steps.len(), 2);
    assert_eq!(witness.loop_steps[0].rule_id, 3);
    assert_eq!(witness.loop_steps[1].rule_id, 2);
    assert_eq!(witness.loop_rule_ids, vec![3, 2]);
    assert_eq!(witness.param_values, trace.param_values);
}

#[test]
fn lasso_witness_extraction_from_result_only_for_fair_cycle() {
    let trace = tarsier_ir::counter_system::Trace {
        initial_config: tarsier_ir::counter_system::Configuration {
            kappa: vec![1],
            gamma: vec![0],
            params: vec![3],
        },
        steps: vec![tarsier_ir::counter_system::TraceStep {
            smt_step: 0,
            rule_id: 0.into(),
            delta: 1,
            deliveries: vec![],
            config: tarsier_ir::counter_system::Configuration {
                kappa: vec![1],
                gamma: vec![1],
                params: vec![3],
            },
            por_status: None,
        }],
        param_values: vec![("n".into(), 3)],
    };
    let cycle = UnboundedFairLivenessResult::FairCycleFound {
        depth: 1,
        loop_start: 0,
        trace: trace.clone(),
    };
    let witness = cegar_extract_lasso_witness_from_result(&cycle)
        .expect("fair-cycle result should produce lasso witness");
    assert_eq!(witness.loop_rule_ids, vec![0]);
    assert_eq!(witness.trace_steps, 1);

    let proved = UnboundedFairLivenessResult::LiveProved { frame: 2 };
    assert!(cegar_extract_lasso_witness_from_result(&proved).is_none());
}

// ── cegar_evidence_requirements ───────────────────────────────────

#[test]
fn evidence_requirements_empty_atomics() {
    let reqs = cegar_evidence_requirements(&[], &default_signals());
    assert!(reqs.is_empty());
}

#[test]
fn evidence_requirements_groups_by_tag() {
    let atomics = vec![atom_global_equivocation(), atom_global_auth()];
    let signals = CegarTraceSignals {
        conflicting_variants: true,
        cross_recipient_delivery: true,
        ..Default::default()
    };
    let reqs = cegar_evidence_requirements(&atomics, &signals);
    assert!(reqs.len() >= 2);
    let cv_req = reqs.iter().find(|r| r.tag == "conflicting_variants");
    assert!(cv_req.is_some());
    let supporters = &cv_req.unwrap().supporters;
    assert!(supporters.contains(&0));
    assert!(supporters.contains(&1));
}

// ── cegar_build_termination_from_iterations ──────────────────────

#[test]
fn termination_budget_not_reached() {
    let t = cegar_build_termination_from_iterations("test_reason", 5, 2, 30, Instant::now(), false);
    assert_eq!(t.reason, "test_reason");
    assert_eq!(t.iteration_budget, 5);
    assert_eq!(t.iterations_used, 2);
    assert_eq!(t.timeout_secs, 30);
    assert!(!t.reached_iteration_budget);
    assert!(!t.reached_timeout_budget);
}

#[test]
fn termination_budget_reached() {
    let t = cegar_build_termination_from_iterations(
        "budget_exhausted",
        3,
        3,
        30,
        Instant::now(),
        false,
    );
    assert!(t.reached_iteration_budget);
}

#[test]
fn termination_zero_budget_never_reached() {
    let t = cegar_build_termination_from_iterations("test", 0, 0, 30, Instant::now(), false);
    assert!(!t.reached_iteration_budget);
}

// ── CegarRefinementPlanEntry ─────────────────────────────────────

#[test]
fn refinement_plan_entry_fields() {
    let entry = CegarRefinementPlanEntry {
        refinement: CegarRefinement {
            atoms: vec![atom_global_equivocation()],
        },
        rationale: "test rationale".to_string(),
    };
    assert_eq!(entry.rationale, "test rationale");
    assert_eq!(entry.refinement.label(), "equivocation:none");
}

// ── CegarOracleOutcome variants ──────────────────────────────────

#[test]
fn oracle_outcome_variants_debug() {
    let sat = CegarOracleOutcome::Sat;
    let unsat = CegarOracleOutcome::Unsat {
        core_indices: vec![0, 2],
    };
    let unknown = CegarOracleOutcome::Unknown;
    assert!(format!("{sat:?}").contains("Sat"));
    assert!(format!("{unsat:?}").contains("core_indices"));
    assert!(format!("{unknown:?}").contains("Unknown"));
}

// ── CegarUnsatCoreSelection ──────────────────────────────────────

#[test]
fn unsat_core_selection_fields() {
    let sel = CegarUnsatCoreSelection {
        selected_indices: vec![1, 3],
        cores_considered: 2,
    };
    assert_eq!(sel.selected_indices, vec![1, 3]);
    assert_eq!(sel.cores_considered, 2);
}

// ── Multi-signal correlation bonus in scoring ────────────────────

#[test]
fn score_double_evidence_bonus() {
    let signals = CegarTraceSignals {
        cross_recipient_delivery: true,
        identity_scoped_channels: true,
        ..Default::default()
    };
    let atom = atom_global_network_process();
    let count = cegar_atom_evidence_tag_count(&atom, &signals);
    assert_eq!(count, 2);
    let score = cegar_refinement_score(&atom, &signals);
    // base 20 + 95 + 10 + 25 (double correlation) = 150
    assert_eq!(score, 150);
}
