use super::*;
use tarsier_ir::counter_system::Configuration;

// --- Fairness semantics tests ---

#[test]
fn fairness_semantics_weak_fields() {
    let sem = FairnessSemantics::weak();
    assert_eq!(sem.mode, "weak");
    assert!(sem.formal_name.contains("Justice"));
    assert!(sem.definition.contains("continuously enabled"));
    assert!(sem.verdict_interpretation.contains("LiveProved"));
}

#[test]
fn fairness_semantics_strong_fields() {
    let sem = FairnessSemantics::strong();
    assert_eq!(sem.mode, "strong");
    assert!(sem.formal_name.contains("Compassion"));
    assert!(sem.definition.contains("infinitely often"));
    assert!(
        sem.verdict_interpretation.contains("strictly stronger"),
        "should document relation to weak fairness"
    );
}

#[test]
fn fairness_semantics_display() {
    assert_eq!(
        FairnessSemantics::weak().to_string(),
        "Justice (weak fairness) (weak)"
    );
    assert_eq!(
        FairnessSemantics::strong().to_string(),
        "Compassion (strong fairness) (strong)"
    );
}

// --- Unknown reason taxonomy tests ---

#[test]
fn unknown_reason_classify_timeout() {
    let reason = "Fair PDR: overall timeout exceeded at frontier frame 5.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "timeout");
    match classified {
        LivenessUnknownReason::Timeout {
            frontier_frame,
            phase,
        } => {
            assert_eq!(frontier_frame, 5);
            assert_eq!(phase, "fair_pdr");
        }
        _ => panic!("expected Timeout"),
    }
}

#[test]
fn unknown_reason_classify_cegar_timeout() {
    let reason = "CEGAR fair-liveness proof timed out.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "timeout");
    match classified {
        LivenessUnknownReason::Timeout { phase, .. } => {
            assert_eq!(phase, "cegar");
        }
        _ => panic!("expected Timeout"),
    }
}

#[test]
fn unknown_reason_classify_cube_budget() {
    let reason = "Fair PDR: blocked over 5000 bad cubes \
                  at frame 3 (adaptive budget); state space appears too large \
                  for current abstraction.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "cube_budget_exhausted");
    match classified {
        LivenessUnknownReason::CubeBudgetExhausted {
            cubes_blocked,
            frontier_frame,
        } => {
            assert_eq!(cubes_blocked, 5000);
            assert_eq!(frontier_frame, 3);
        }
        _ => panic!("expected CubeBudgetExhausted"),
    }
}

#[test]
fn unknown_reason_classify_memory_budget() {
    let reason = "Fair PDR: memory budget exceeded at frontier frame 4 \
                  (rss_bytes=8388608, limit_bytes=4194304).";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "memory_budget_exceeded");
    match classified {
        LivenessUnknownReason::MemoryBudgetExceeded {
            rss_bytes,
            limit_bytes,
            frontier_frame,
            phase,
        } => {
            assert_eq!(rss_bytes, 8_388_608);
            assert_eq!(limit_bytes, 4_194_304);
            assert_eq!(frontier_frame, 4);
            assert_eq!(phase, "fair_pdr");
        }
        _ => panic!("expected MemoryBudgetExceeded"),
    }
}

#[test]
fn unknown_reason_classify_lasso_recovery() {
    let reason = "Fair PDR found a reachable accepting state, \
                  but bounded lasso recovery did not return a trace.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "lasso_recovery_failed");
}

#[test]
fn unknown_reason_classify_cegar_inconclusive() {
    let reason = "CEGAR refinements eliminated the baseline fair-cycle witness, \
                  but no refined fair cycle was found.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "cegar_refinement_inconclusive");
}

#[test]
fn unknown_reason_classify_cegar_ladder() {
    let reason = "CEGAR refinement ladder exhausted without a confirmed fair cycle.";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "cegar_ladder_exhausted");
}

#[test]
fn unknown_reason_classify_solver() {
    let reason = "Z3 returned unknown: resourceout";
    let classified = LivenessUnknownReason::classify(reason);
    assert_eq!(classified.code(), "solver_unknown");
    match classified {
        LivenessUnknownReason::SolverUnknown { solver_reason } => {
            assert_eq!(solver_reason, reason);
        }
        _ => panic!("expected SolverUnknown"),
    }
}

#[test]
fn unknown_reason_code_exhaustive() {
    // Verify all codes are distinct strings.
    let codes: Vec<&str> = vec![
        LivenessUnknownReason::Timeout {
            frontier_frame: 0,
            phase: "test".into(),
        }
        .code(),
        LivenessUnknownReason::MemoryBudgetExceeded {
            rss_bytes: 0,
            limit_bytes: 0,
            frontier_frame: 0,
            phase: "test".into(),
        }
        .code(),
        LivenessUnknownReason::CubeBudgetExhausted {
            cubes_blocked: 0,
            frontier_frame: 0,
        }
        .code(),
        LivenessUnknownReason::SolverUnknown {
            solver_reason: String::new(),
        }
        .code(),
        LivenessUnknownReason::LassoRecoveryFailed.code(),
        LivenessUnknownReason::CegarRefinementInconclusive {
            discovered_predicates: vec![],
        }
        .code(),
        LivenessUnknownReason::CegarLadderExhausted.code(),
    ];
    let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "all codes must be distinct");
}

#[test]
fn unknown_reason_display_roundtrip() {
    // Display should produce a human-readable string that classifies back correctly.
    let reason = LivenessUnknownReason::Timeout {
        frontier_frame: 7,
        phase: "fair_pdr".into(),
    };
    let display = reason.to_string();
    assert!(display.contains("7"));
    assert!(display.contains("fair_pdr"));
}

// --- Verdict class tests ---

#[test]
fn verification_result_verdict_class_safe() {
    let r = VerificationResult::Safe { depth_checked: 5 };
    assert_eq!(r.verdict_class(), "safe");
}

#[test]
fn verification_result_verdict_class_unsafe() {
    let r = VerificationResult::Unsafe {
        trace: Trace {
            param_values: vec![],
            initial_config: Configuration::new(0, 0, 0),
            steps: vec![],
        },
    };
    assert_eq!(r.verdict_class(), "unsafe");
}

#[test]
fn verification_result_verdict_class_unknown() {
    let r = VerificationResult::Unknown {
        reason: "test".into(),
    };
    assert_eq!(r.verdict_class(), "unknown");
}

#[test]
fn verification_result_verdict_class_prob_safe() {
    let r = VerificationResult::ProbabilisticallySafe {
        depth_checked: 3,
        failure_probability: 1e-9,
        committee_analyses: vec![],
    };
    assert_eq!(r.verdict_class(), "probabilistically_safe");
}

#[test]
fn unbounded_fair_liveness_verdict_class_all_variants() {
    assert_eq!(
        UnboundedFairLivenessResult::LiveProved { frame: 1 }.verdict_class(),
        "live_proved"
    );
    assert_eq!(
        UnboundedFairLivenessResult::FairCycleFound {
            depth: 2,
            loop_start: 0,
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        }
        .verdict_class(),
        "fair_cycle_found"
    );
    assert_eq!(
        UnboundedFairLivenessResult::NotProved { max_k: 5 }.verdict_class(),
        "not_proved"
    );
    assert_eq!(
        UnboundedFairLivenessResult::Unknown { reason: "x".into() }.verdict_class(),
        "unknown"
    );
}

// --- Multi-property result tests (from previous session, verified here too) ---

#[test]
fn multi_property_result_empty_is_safe() {
    let result = MultiPropertyResult { verdicts: vec![] };
    assert!(result.all_safe());
    assert!(!result.any_unsafe());
    assert_eq!(result.overall_verdict(), "safe");
}

// --- CTI classification tests ---

#[test]
fn cti_classification_display() {
    assert_eq!(format!("{}", CtiClassification::Concrete), "concrete");
    assert_eq!(
        format!("{}", CtiClassification::LikelySpurious),
        "likely-spurious"
    );
}

#[test]
fn cti_classification_serializes_snake_case() {
    let concrete = serde_json::to_value(&CtiClassification::Concrete).unwrap();
    assert_eq!(concrete, serde_json::Value::String("concrete".into()));
    let spurious = serde_json::to_value(&CtiClassification::LikelySpurious).unwrap();
    assert_eq!(
        spurious,
        serde_json::Value::String("likely_spurious".into())
    );
}

#[test]
fn cti_summary_has_classification_fields() {
    let cti = InductionCtiSummary {
        k: 3,
        params: vec![("n".into(), 4)],
        hypothesis_locations: vec![("Init".into(), 4)],
        hypothesis_shared: vec![],
        violating_locations: vec![("Decided_v0".into(), 2), ("Decided_v1".into(), 2)],
        violating_shared: vec![],
        final_step_rules: vec![("r0 (Propose -> Decided_v0)".into(), 2)],
        violated_condition: "agreement violated: Decided_v0 and Decided_v1 both occupied".into(),
        classification: CtiClassification::LikelySpurious,
        classification_evidence: vec![
            "BMC base case verified no reachable violation through depth 3; \
             CTI hypothesis state at step 2 is outside the reachable state space."
                .into(),
        ],
        rationale: "The inductive step failed at k = 3".into(),
    };
    assert_eq!(cti.classification, CtiClassification::LikelySpurious);
    assert!(!cti.classification_evidence.is_empty());
    assert!(cti.rationale.contains("inductive step failed"));
}

#[test]
fn cti_summary_display_includes_classification() {
    let cti = InductionCtiSummary {
        k: 2,
        params: vec![],
        hypothesis_locations: vec![("Loc_A".into(), 3)],
        hypothesis_shared: vec![],
        violating_locations: vec![("Bad".into(), 1)],
        violating_shared: vec![],
        final_step_rules: vec![],
        violated_condition: "invariant violated".into(),
        classification: CtiClassification::LikelySpurious,
        classification_evidence: vec!["BMC passed at depth 2.".into()],
        rationale: "Likely unreachable from init.".into(),
    };
    let result = UnboundedSafetyResult::NotProved {
        max_k: 4,
        cti: Some(cti),
    };
    let display = format!("{result}");
    assert!(
        display.contains("likely-spurious"),
        "Display should contain classification: {display}"
    );
    assert!(
        display.contains("BMC passed at depth 2"),
        "Display should contain evidence: {display}"
    );
    assert!(
        display.contains("Likely unreachable from init"),
        "Display should contain rationale: {display}"
    );
    assert!(
        display.contains("NOT PROVED"),
        "Display should contain NOT PROVED: {display}"
    );
}

// --- VerificationResult Display tests ---

#[test]
fn display_verification_result_safe() {
    let r = VerificationResult::Safe { depth_checked: 10 };
    let s = format!("{r}");
    assert!(s.contains("RESULT: SAFE"));
    assert!(s.contains("depth 10"));
}

#[test]
fn display_verification_result_unsafe() {
    let r = VerificationResult::Unsafe {
        trace: Trace {
            param_values: vec![("n".into(), 4)],
            initial_config: Configuration::new(2, 1, 1),
            steps: vec![],
        },
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNSAFE"));
    assert!(s.contains("Counterexample trace"));
}

#[test]
fn display_verification_result_unknown() {
    let r = VerificationResult::Unknown {
        reason: "solver timeout".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNKNOWN"));
    assert!(s.contains("solver timeout"));
}

#[test]
fn display_verification_result_probabilistically_safe() {
    let r = VerificationResult::ProbabilisticallySafe {
        depth_checked: 5,
        failure_probability: 1e-9,
        committee_analyses: vec![CommitteeAnalysisSummary {
            name: "validators".into(),
            committee_size: 100,
            population: 1000,
            byzantine: 333,
            b_max: 61,
            epsilon: 1e-9,
            tail_probability: 5e-10,
            honest_majority: 39,
            expected_byzantine: 33.3,
        }],
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: SAFE (probabilistic)"));
    assert!(s.contains("depth 5"));
    assert!(s.contains("validators"));
    assert!(s.contains("100 from 1000"));
    assert!(s.contains("1 - 1e-9") || s.contains("1e-9"));
}

// --- UnboundedSafetyResult Display tests ---

#[test]
fn display_unbounded_safety_safe() {
    let r = UnboundedSafetyResult::Safe { induction_k: 3 };
    let s = format!("{r}");
    assert!(s.contains("RESULT: SAFE (unbounded)"));
    assert!(s.contains("k = 3"));
}

#[test]
fn display_unbounded_safety_prob_safe() {
    let r = UnboundedSafetyResult::ProbabilisticallySafe {
        induction_k: 2,
        failure_probability: 1e-6,
        committee_analyses: vec![],
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: SAFE (unbounded, probabilistic)"));
    assert!(s.contains("k = 2"));
}

#[test]
fn display_unbounded_safety_unsafe() {
    let r = UnboundedSafetyResult::Unsafe {
        trace: Trace {
            param_values: vec![],
            initial_config: Configuration::new(0, 0, 0),
            steps: vec![],
        },
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNSAFE"));
}

#[test]
fn display_unbounded_safety_not_proved_no_cti() {
    let r = UnboundedSafetyResult::NotProved {
        max_k: 10,
        cti: None,
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: NOT PROVED"));
    assert!(s.contains("k = 10"));
    // No CTI section should appear
    assert!(!s.contains("Counterexample to induction"));
}

#[test]
fn display_unbounded_safety_unknown() {
    let r = UnboundedSafetyResult::Unknown {
        reason: "solver gave up".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNKNOWN"));
    assert!(s.contains("solver gave up"));
}

// --- LivenessResult Display tests ---

#[test]
fn display_liveness_live() {
    let r = LivenessResult::Live { depth_checked: 7 };
    let s = format!("{r}");
    assert!(s.contains("RESULT: LIVE (bounded)"));
    assert!(s.contains("depth 7"));
}

#[test]
fn display_liveness_not_live() {
    let r = LivenessResult::NotLive {
        trace: Trace {
            param_values: vec![],
            initial_config: Configuration::new(0, 0, 0),
            steps: vec![],
        },
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: NOT LIVE (bounded)"));
}

#[test]
fn display_liveness_unknown() {
    let r = LivenessResult::Unknown {
        reason: "incomplete".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNKNOWN"));
    assert!(s.contains("incomplete"));
}

// --- FairLivenessResult Display tests ---

#[test]
fn display_fair_liveness_no_fair_cycle() {
    let r = FairLivenessResult::NoFairCycleUpTo { depth_checked: 12 };
    let s = format!("{r}");
    assert!(s.contains("NO FAIR LIVENESS COUNTEREXAMPLE"));
    assert!(s.contains("depth 12"));
}

#[test]
fn display_fair_liveness_fair_cycle_found() {
    let r = FairLivenessResult::FairCycleFound {
        depth: 5,
        loop_start: 2,
        trace: Trace {
            param_values: vec![],
            initial_config: Configuration::new(0, 0, 0),
            steps: vec![],
        },
    };
    let s = format!("{r}");
    assert!(s.contains("FAIR LIVENESS COUNTEREXAMPLE FOUND"));
    assert!(s.contains("step 2 -> step 5"));
}

#[test]
fn display_fair_liveness_unknown() {
    let r = FairLivenessResult::Unknown {
        reason: "resource limit".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNKNOWN"));
    assert!(s.contains("resource limit"));
}

// --- UnboundedFairLivenessResult Display tests ---

#[test]
fn display_unbounded_fair_liveness_live_proved() {
    let r = UnboundedFairLivenessResult::LiveProved { frame: 4 };
    let s = format!("{r}");
    assert!(s.contains("RESULT: LIVE (unbounded, fair)"));
    assert!(s.contains("frame 4"));
}

#[test]
fn display_unbounded_fair_liveness_fair_cycle() {
    let r = UnboundedFairLivenessResult::FairCycleFound {
        depth: 8,
        loop_start: 3,
        trace: Trace {
            param_values: vec![],
            initial_config: Configuration::new(0, 0, 0),
            steps: vec![],
        },
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: NOT LIVE (unbounded, fair)"));
    assert!(s.contains("step 3 -> step 8"));
}

#[test]
fn display_unbounded_fair_liveness_not_proved() {
    let r = UnboundedFairLivenessResult::NotProved { max_k: 15 };
    let s = format!("{r}");
    assert!(s.contains("RESULT: NOT PROVED"));
    assert!(s.contains("frame 15"));
}

#[test]
fn display_unbounded_fair_liveness_unknown() {
    let r = UnboundedFairLivenessResult::Unknown {
        reason: "z3 unknown".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("RESULT: UNKNOWN"));
    assert!(s.contains("z3 unknown"));
}

// --- MultiPropertyResult tests ---

#[test]
fn multi_property_all_safe_with_mixed_safe_variants() {
    let result = MultiPropertyResult {
        verdicts: vec![
            PropertyVerdict {
                name: "agreement".into(),
                fragment: "safety".into(),
                result: VerificationResult::Safe { depth_checked: 5 },
            },
            PropertyVerdict {
                name: "validity".into(),
                fragment: "safety".into(),
                result: VerificationResult::ProbabilisticallySafe {
                    depth_checked: 5,
                    failure_probability: 1e-9,
                    committee_analyses: vec![],
                },
            },
        ],
    };
    assert!(result.all_safe());
    assert!(!result.any_unsafe());
    assert_eq!(result.overall_verdict(), "safe");
}

#[test]
fn multi_property_unsafe_overrides_safe() {
    let result = MultiPropertyResult {
        verdicts: vec![
            PropertyVerdict {
                name: "agreement".into(),
                fragment: "safety".into(),
                result: VerificationResult::Safe { depth_checked: 5 },
            },
            PropertyVerdict {
                name: "validity".into(),
                fragment: "safety".into(),
                result: VerificationResult::Unsafe {
                    trace: Trace {
                        param_values: vec![],
                        initial_config: Configuration::new(0, 0, 0),
                        steps: vec![],
                    },
                },
            },
        ],
    };
    assert!(!result.all_safe());
    assert!(result.any_unsafe());
    assert_eq!(result.overall_verdict(), "unsafe");
}

#[test]
fn multi_property_unknown_yields_inconclusive() {
    let result = MultiPropertyResult {
        verdicts: vec![
            PropertyVerdict {
                name: "agreement".into(),
                fragment: "safety".into(),
                result: VerificationResult::Safe { depth_checked: 5 },
            },
            PropertyVerdict {
                name: "termination".into(),
                fragment: "liveness".into(),
                result: VerificationResult::Unknown {
                    reason: "timeout".into(),
                },
            },
        ],
    };
    assert!(!result.all_safe());
    assert!(!result.any_unsafe());
    assert_eq!(result.overall_verdict(), "inconclusive");
}

// --- Serde serialization tests ---

#[test]
fn bound_kind_serializes_correctly() {
    let upper = serde_json::to_value(&BoundKind::UpperBound).unwrap();
    assert_eq!(upper, serde_json::json!("upper_bound"));
    let lower = serde_json::to_value(&BoundKind::LowerBound).unwrap();
    assert_eq!(lower, serde_json::json!("lower_bound"));
    let est = serde_json::to_value(&BoundKind::Estimate).unwrap();
    assert_eq!(est, serde_json::json!("estimate"));
    let exact = serde_json::to_value(&BoundKind::Exact).unwrap();
    assert_eq!(exact, serde_json::json!("exact"));
}

#[test]
fn bound_evidence_class_serializes_correctly() {
    let tb = serde_json::to_value(&BoundEvidenceClass::TheoremBacked).unwrap();
    assert_eq!(tb, serde_json::json!("theorem_backed"));
    let he = serde_json::to_value(&BoundEvidenceClass::HeuristicEstimate).unwrap();
    assert_eq!(he, serde_json::json!("heuristic_estimate"));
}

#[test]
fn bound_annotation_serializes_all_fields() {
    let ann = BoundAnnotation {
        field: "per_step_bound".into(),
        kind: BoundKind::UpperBound,
        evidence_class: BoundEvidenceClass::TheoremBacked,
        description: "Sound upper bound on messages per step".into(),
        assumptions: vec!["authenticated channels".into()],
    };
    let json = serde_json::to_value(&ann).unwrap();
    assert_eq!(json["field"], "per_step_bound");
    assert_eq!(json["kind"], "upper_bound");
    assert_eq!(json["evidence_class"], "theorem_backed");
    assert!(json["assumptions"].as_array().unwrap().len() == 1);
}

#[test]
fn model_assumptions_serializes_with_optional_gst() {
    let assumptions = ModelAssumptions {
        fault_model: "byzantine".into(),
        timing_model: "asynchronous".into(),
        authentication_mode: "signed".into(),
        equivocation_mode: "allowed".into(),
        network_semantics: "point_to_point".into(),
        gst_param: Some("GST".into()),
    };
    let json = serde_json::to_value(&assumptions).unwrap();
    assert_eq!(json["fault_model"], "byzantine");
    assert_eq!(json["gst_param"], "GST");

    let no_gst = ModelAssumptions {
        gst_param: None,
        ..assumptions.clone()
    };
    let json2 = serde_json::to_value(&no_gst).unwrap();
    assert!(json2["gst_param"].is_null());
}

#[test]
fn assumption_note_serializes_level_and_message() {
    let note = AssumptionNote {
        level: "warning".into(),
        message: "Equivocation is not modeled".into(),
    };
    let json = serde_json::to_value(&note).unwrap();
    assert_eq!(json["level"], "warning");
    assert_eq!(json["message"], "Equivocation is not modeled");
}

// --- LivenessUnknownReason Display tests ---

#[test]
fn display_unknown_reason_memory_budget() {
    let reason = LivenessUnknownReason::MemoryBudgetExceeded {
        rss_bytes: 8_000_000,
        limit_bytes: 4_000_000,
        frontier_frame: 3,
        phase: "fair_pdr".into(),
    };
    let s = reason.to_string();
    assert!(s.contains("Memory budget exceeded"));
    assert!(s.contains("frame 3"));
    assert!(s.contains("rss_bytes=8000000"));
    assert!(s.contains("limit_bytes=4000000"));
}

#[test]
fn display_unknown_reason_cube_budget() {
    let reason = LivenessUnknownReason::CubeBudgetExhausted {
        cubes_blocked: 5000,
        frontier_frame: 2,
    };
    let s = reason.to_string();
    assert!(s.contains("5000"));
    assert!(s.contains("frame 2"));
    assert!(s.contains("adaptive budget"));
}

#[test]
fn display_unknown_reason_cegar_inconclusive_with_predicates() {
    let reason = LivenessUnknownReason::CegarRefinementInconclusive {
        discovered_predicates: vec!["no_equivocation".into(), "exact_values".into()],
    };
    let s = reason.to_string();
    assert!(s.contains("no_equivocation, exact_values"));
    assert!(s.contains("predicates:"));
}

#[test]
fn display_unknown_reason_cegar_inconclusive_no_predicates() {
    let reason = LivenessUnknownReason::CegarRefinementInconclusive {
        discovered_predicates: vec![],
    };
    let s = reason.to_string();
    assert!(!s.contains("predicates:"));
}

#[test]
fn display_unknown_reason_lasso_recovery_failed() {
    let reason = LivenessUnknownReason::LassoRecoveryFailed;
    let s = reason.to_string();
    assert!(s.contains("bounded lasso recovery"));
}

#[test]
fn display_unknown_reason_cegar_ladder_exhausted() {
    let reason = LivenessUnknownReason::CegarLadderExhausted;
    let s = reason.to_string();
    assert!(s.contains("refinement ladder exhausted"));
}

// --- CommitteeAnalysisSummary construction ---

#[test]
fn committee_analysis_summary_field_access() {
    let ca = CommitteeAnalysisSummary {
        name: "validators".into(),
        committee_size: 100,
        population: 1000,
        byzantine: 333,
        b_max: 61,
        epsilon: 1e-9,
        tail_probability: 5e-10,
        honest_majority: 39,
        expected_byzantine: 33.3,
    };
    assert_eq!(ca.name, "validators");
    assert_eq!(ca.committee_size, 100);
    assert_eq!(ca.population, 1000);
    assert_eq!(ca.byzantine, 333);
    assert_eq!(ca.b_max, 61);
    assert!(ca.tail_probability < ca.epsilon);
    assert_eq!(ca.honest_majority, 39);
}

// --- CEGAR types construction ---

#[test]
fn cegar_stage_outcome_variants_are_constructible() {
    let safe = CegarStageOutcome::Safe { depth_checked: 5 };
    assert!(matches!(safe, CegarStageOutcome::Safe { depth_checked: 5 }));

    let prob = CegarStageOutcome::ProbabilisticallySafe {
        depth_checked: 5,
        failure_probability: 1e-9,
        committee_count: 2,
    };
    assert!(matches!(
        prob,
        CegarStageOutcome::ProbabilisticallySafe { .. }
    ));

    let unknown = CegarStageOutcome::Unknown {
        reason: "test".into(),
    };
    assert!(matches!(unknown, CegarStageOutcome::Unknown { .. }));
}

#[test]
fn cegar_termination_fields() {
    let term = CegarTermination {
        reason: "proof_found".into(),
        iteration_budget: 10,
        iterations_used: 3,
        timeout_secs: 60,
        elapsed_ms: 1234,
        reached_iteration_budget: false,
        reached_timeout_budget: false,
    };
    assert_eq!(term.reason, "proof_found");
    assert_eq!(term.iterations_used, 3);
    assert!(!term.reached_iteration_budget);
    assert!(!term.reached_timeout_budget);
    assert!(term.elapsed_ms < term.timeout_secs as u128 * 1000);
}

#[test]
fn cegar_model_change_construction() {
    let change = CegarModelChange {
        category: "adversary".into(),
        target: "Vote".into(),
        before: "unbounded".into(),
        after: "bounded(3)".into(),
        predicate: "adversary_bound".into(),
    };
    assert_eq!(change.category, "adversary");
    assert_eq!(change.predicate, "adversary_bound");
}

#[test]
fn cegar_predicate_score_construction() {
    let score = CegarPredicateScore {
        predicate: "equivocation_none".into(),
        score: 42,
        evidence_tags: vec!["single_variant".into()],
        affected_steps: 3,
        unsat_core_selected: true,
    };
    assert_eq!(score.score, 42);
    assert!(score.unsat_core_selected);
    assert_eq!(score.affected_steps, 3);
}

// --- Quantitative schema constants ---

#[test]
fn quantitative_schema_paths_are_non_empty() {
    assert!(!QUANTITATIVE_SCHEMA_DOC_PATH.is_empty());
    assert!(!QUANTITATIVE_SCHEMA_JSON_PATH.is_empty());
    assert!(QUANTITATIVE_SCHEMA_JSON_PATH.ends_with(".json"));
}
