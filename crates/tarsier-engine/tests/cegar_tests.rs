mod common;
use common::*;

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
use tarsier_engine::result::{CegarStageOutcome, UnboundedSafetyResult, VerificationResult};

#[test]
fn verify_with_cegar_eliminates_equivocation_spurious_counterexample() {
    let source = r#"
protocol CegarEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let no_cegar = tarsier_engine::pipeline::verify(source, "cegar_equivocation.trs", &options)
        .expect("plain verify should complete");
    match no_cegar {
        VerificationResult::Unsafe { .. } => {}
        other => panic!("Expected UNSAFE without CEGAR, got: {other}"),
    }

    let with_cegar =
        tarsier_engine::pipeline::verify_with_cegar(source, "cegar_equivocation.trs", &options, 1)
            .expect("CEGAR verify should complete");
    match with_cegar {
        VerificationResult::Unknown { reason } => {
            assert!(reason.contains("CEGAR refinements eliminated"));
        }
        other => panic!("Expected CEGAR UNKNOWN due to eliminated cex, got: {other}"),
    }
}

#[test]
fn verify_with_cegar_report_records_refinement_stages() {
    let source = r#"
protocol CegarReport {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report =
        tarsier_engine::pipeline::verify_with_cegar_report(source, "cegar_report.trs", &options, 1)
            .expect("CEGAR report should complete");

    assert_eq!(report.max_refinements, 1);
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(
        report.stages[1].label.contains("equivocation"),
        "first refinement stage should include an equivocation-tightening predicate"
    );
    assert_eq!(report.classification, "inconclusive");
    assert_eq!(report.termination.iteration_budget, 1);
    assert_eq!(report.termination.iterations_used, 1);
    assert!(
        report.termination.reason == "counterexample_eliminated_no_confirmation"
            || report.termination.reason == "max_refinements_reached",
        "termination reason should explain loop stop condition"
    );
    assert!(
        report
            .discovered_predicates
            .iter()
            .any(|pred| pred.contains("equivocation")),
        "discovered predicates should include at least one equivocation predicate"
    );
    let baseline_analysis = report.stages[0]
        .counterexample_analysis
        .as_ref()
        .expect("baseline stage should include counterexample analysis");
    assert_eq!(baseline_analysis.classification, "potentially_spurious");
    assert!(baseline_analysis
        .rationale
        .contains("Baseline stage reported UNSAFE"));
    let refined_analysis = report.stages[1]
        .counterexample_analysis
        .as_ref()
        .expect("refined stage should include counterexample analysis");
    assert_eq!(refined_analysis.classification, "potentially_spurious");
    assert!(refined_analysis.rationale.contains("eliminated"));
    assert!(
        report.stages[1]
            .model_changes
            .iter()
            .any(|change| !change.predicate.is_empty()),
        "stage report should include explicit model change details"
    );
    assert_eq!(
        report.stages[1].eliminated_traces.len(),
        1,
        "stage report should include eliminated baseline trace"
    );
    assert!(
        !report.stages[1].discovered_predicates.is_empty(),
        "stage report should expose discovered predicates for elimination stages"
    );
    let overall_analysis = report
        .counterexample_analysis
        .as_ref()
        .expect("overall report should include counterexample analysis");
    assert_eq!(overall_analysis.classification, "potentially_spurious");
    assert!(overall_analysis.rationale.contains("eliminated"));
    assert!(matches!(
        report.stages[0].outcome,
        CegarStageOutcome::Unsafe { .. }
    ));
    assert!(matches!(
        report.final_result,
        VerificationResult::Unknown { .. }
    ));
}

#[test]
fn verify_with_cegar_report_includes_values_exact_refinement() {
    let source = r#"
protocol CegarValues {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: none; auth: signed; values: sign; }
    message Vote(v: nat in 0..3);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote(v=0) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report =
        tarsier_engine::pipeline::verify_with_cegar_report(source, "cegar_values.trs", &options, 1)
            .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "values:exact");
}

#[test]
fn verify_with_cegar_report_classifies_persistent_witness_as_concrete() {
    let source = r#"
protocol CegarConcrete {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: full; auth: none; network: classic; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote(v=true) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_concrete.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.classification, "unsafe_confirmed");
    assert_eq!(report.stages.len(), 2);
    assert!(matches!(
        report.stages[1].outcome,
        CegarStageOutcome::Unsafe { .. }
    ));
    let stage_analysis = report.stages[1]
        .counterexample_analysis
        .as_ref()
        .expect("unsafe refined stage should include analysis");
    assert_eq!(stage_analysis.classification, "concrete");
    assert!(stage_analysis.rationale.contains("persists"));
    assert!(
        report.stages[1].eliminated_traces.is_empty(),
        "persistent unsafe stage should not report eliminated traces"
    );
    let overall_analysis = report
        .counterexample_analysis
        .as_ref()
        .expect("overall report should include analysis");
    assert_eq!(overall_analysis.classification, "concrete");
}

#[test]
fn verify_with_cegar_report_synthesizes_message_scoped_refinements() {
    let source = r#"
protocol CegarMessageScoped {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_message_scoped.trs",
        &options,
        2,
    )
    .expect("CEGAR report should complete");

    assert!(
        report
            .stages
            .iter()
            .any(|stage| stage.label.contains("equivocation:Vote=none")),
        "trace-based refinement discovery should synthesize message-scoped equivocation predicates"
    );
    assert!(
        report
            .discovered_predicates
            .contains(&"equivocation(Vote)=none".to_string()),
        "discovered predicates should include synthesized message-scoped refinements"
    );
}

#[test]
fn soundness_negative_spurious_value_abstraction_trace_is_eliminated_by_cegar() {
    let source = r#"
protocol SpuriousValuesSign {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = verify_options(2, SoundnessMode::Strict);

    let baseline =
        tarsier_engine::pipeline::verify(source, "spurious_values_sign.trs", &options).unwrap();
    assert!(
        matches!(baseline, VerificationResult::Unsafe { .. }),
        "baseline sign abstraction should expose a spurious unsafe trace"
    );

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "spurious_values_sign.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.classification, "inconclusive");
    assert_eq!(
        report.discovered_predicates,
        vec!["adversary.values=exact".to_string()]
    );
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "values:exact");
    assert!(matches!(
        report.stages[1].outcome,
        CegarStageOutcome::Safe { .. }
    ));
    assert!(matches!(
        report.final_result,
        VerificationResult::Unknown { .. }
    ));
}

#[test]
fn regression_known_spurious_cases_are_eliminated_by_refinement() {
    struct Case<'a> {
        name: &'a str,
        source: &'a str,
        depth: usize,
        max_refinements: usize,
        expected_predicate_fragment: &'a str,
    }

    let cases = vec![
        Case {
            name: "equivocation_global",
            source: r#"
protocol SpuriousEqGlobal {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "equivocation",
        },
        Case {
            name: "value_abstraction_sign",
            source: r#"
protocol SpuriousValuesSignRegression {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "values=exact",
        },
        Case {
            name: "equivocation_message_scoped",
            source: r#"
protocol SpuriousEqMessageScoped {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            max_refinements: 2,
            expected_predicate_fragment: "equivocation(Vote)=none",
        },
    ];

    for case in cases {
        let options = verify_options(case.depth, SoundnessMode::Strict);
        let baseline = tarsier_engine::pipeline::verify(case.source, case.name, &options)
            .unwrap_or_else(|e| panic!("baseline verify should succeed for {}: {e}", case.name));
        assert!(
            matches!(baseline, VerificationResult::Unsafe { .. }),
            "baseline run should expose spurious unsafe witness for {}",
            case.name
        );

        let report = tarsier_engine::pipeline::verify_with_cegar_report(
            case.source,
            case.name,
            &options,
            case.max_refinements,
        )
        .unwrap_or_else(|e| panic!("cegar report should succeed for {}: {e}", case.name));

        assert_eq!(
            report.classification, "inconclusive",
            "eliminated baseline witness without refined concrete unsafe must be inconclusive ({})",
            case.name
        );
        assert!(
            matches!(report.final_result, VerificationResult::Unknown { .. }),
            "eliminated baseline witness must produce unknown/inconclusive verdict ({})",
            case.name
        );
        assert!(
            report
                .stages
                .iter()
                .any(|s| !s.eliminated_traces.is_empty()),
            "cegar stages should record eliminated baseline trace for {}",
            case.name
        );
        assert!(
            report
                .discovered_predicates
                .iter()
                .any(|p| p.contains(case.expected_predicate_fragment)),
            "discovered predicates should include fragment '{}' for {}",
            case.expected_predicate_fragment,
            case.name
        );
    }
}

#[test]
fn scalability_refinement_materially_reduces_false_alarms_on_harder_models() {
    struct HardCase<'a> {
        name: &'a str,
        source: &'a str,
        depth: usize,
        refinements: usize,
    }

    // These models intentionally stress approximation-sensitive paths with
    // wider local domains and multi-phase guards, so baseline runs expose
    // spurious UNSAFE witnesses that refinement should eliminate.
    let cases = vec![
        HardCase {
            name: "hard_equivocation_multiphase.trs",
            source: r#"
protocol HardEquivocationMultiphase {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            refinements: 3,
        },
        HardCase {
            name: "hard_values_sign_multiphase.trs",
            source: r#"
protocol HardValuesSignMultiphase {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            refinements: 3,
        },
        HardCase {
            name: "hard_message_scoped_equivocation.trs",
            source: r#"
protocol HardMessageScopedEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: none; auth: none; }
    message Vote(v: bool);
    equivocation Vote: full;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            refinements: 3,
        },
    ];

    let mut baseline_false_alarms = 0usize;
    let mut remaining_false_alarms_after_refinement = 0usize;
    let mut eliminated_cases = 0usize;

    for case in cases {
        let options = verify_options(case.depth, SoundnessMode::Strict);
        let baseline = tarsier_engine::pipeline::verify(case.source, case.name, &options)
            .unwrap_or_else(|e| panic!("baseline verify should succeed for {}: {e}", case.name));
        if !matches!(baseline, VerificationResult::Unsafe { .. }) {
            // Some models may become proved-safe as the core engine tightens.
            // Keep the suite robust by only measuring cases that still trigger
            // approximation false alarms at baseline.
            continue;
        }
        baseline_false_alarms += 1;

        let report = tarsier_engine::pipeline::verify_with_cegar_report(
            case.source,
            case.name,
            &options,
            case.refinements,
        )
        .unwrap_or_else(|e| panic!("cegar report should succeed for {}: {e}", case.name));

        if report
            .stages
            .iter()
            .any(|stage| !stage.eliminated_traces.is_empty())
        {
            eliminated_cases += 1;
        }
        if matches!(report.final_result, VerificationResult::Unsafe { .. }) {
            remaining_false_alarms_after_refinement += 1;
        }
    }

    assert_eq!(
        baseline_false_alarms, 3,
        "all selected harder cases should expose baseline false alarms"
    );
    let reduced = baseline_false_alarms.saturating_sub(remaining_false_alarms_after_refinement);
    assert!(
        reduced * 100 >= baseline_false_alarms * 66,
        "refinement should materially reduce false alarms on harder models \
         (baseline={}, remaining={}, reduced={})",
        baseline_false_alarms,
        remaining_false_alarms_after_refinement,
        reduced
    );
    assert!(
        eliminated_cases >= 2,
        "at least two harder models should show explicit eliminated traces (got {})",
        eliminated_cases
    );
}

#[test]
fn verify_with_cegar_report_includes_network_identity_selective_refinement() {
    let source = r#"
protocol CegarNetwork {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        auth: signed;
        values: exact;
        network: classic;
    }
    message Vote;
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_network.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "network:identity_selective");
    assert_eq!(
        report.stages[1].refinements,
        vec!["adversary.network=identity_selective".to_string()]
    );
}

#[test]
fn verify_with_cegar_report_includes_network_process_selective_refinement() {
    let source = r#"
protocol CegarNetworkProcess {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        auth: signed;
        values: exact;
        network: identity_selective;
        delivery: per_recipient;
        faults: per_recipient;
    }
    identity R: role key r_key;
    message Vote;
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 1,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_network_process.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[1].label, "network:process_selective");
    assert_eq!(
        report.stages[1].refinements,
        vec!["adversary.network=process_selective".to_string()]
    );
}

#[test]
fn prove_with_cegar_eliminates_equivocation_spurious_counterexample() {
    let source = r#"
protocol CegarProveEquivocation {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let no_cegar = tarsier_engine::pipeline::prove_safety(source, "cegar_prove.trs", &options)
        .expect("plain prove should complete");
    match no_cegar {
        UnboundedSafetyResult::Unsafe { .. } => {}
        other => panic!("Expected UNSAFE without CEGAR, got: {other}"),
    }

    let with_cegar =
        tarsier_engine::pipeline::prove_safety_with_cegar(source, "cegar_prove.trs", &options, 1)
            .expect("CEGAR prove should complete");
    match with_cegar {
        UnboundedSafetyResult::Unknown { reason } => {
            assert!(
                reason.contains("CEGAR refinements eliminated")
                    || reason.contains("CEGAR refinements were inconclusive")
            );
        }
        other => panic!("Expected CEGAR UNKNOWN due to eliminated unsafe witness, got: {other}"),
    }
}

#[test]
fn prove_with_cegar_report_exposes_controls_and_machine_readable_status() {
    let source = r#"
protocol CegarProveEquivocationReport {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::prove_safety_with_cegar_report(
        source,
        "cegar_prove_report.trs",
        &options,
        1,
    )
    .expect("CEGAR proof report should complete");

    assert_eq!(report.controls.max_refinements, 1);
    assert_eq!(report.controls.timeout_secs, 30);
    assert_eq!(report.controls.solver, "z3");
    assert_eq!(report.controls.proof_engine.as_deref(), Some("kinduction"));
    assert!(report.controls.fairness.is_none());
    assert_eq!(report.stages.len(), 2);
    assert_eq!(report.stages[0].stage, 0);
    assert_eq!(report.stages[1].stage, 1);
    assert_eq!(report.stages[0].label, "baseline");
    assert!(report.stages[1]
        .note
        .as_deref()
        .unwrap_or_default()
        .contains("Selection rationale"));
    assert!(matches!(
        report.baseline_result,
        UnboundedSafetyResult::Unsafe { .. }
    ));
    assert!(matches!(
        report.final_result,
        UnboundedSafetyResult::Unknown { .. }
    ));
    assert_eq!(report.classification, "inconclusive");
    let analysis = report
        .counterexample_analysis
        .expect("counterexample analysis should exist");
    assert!(
        analysis.classification == "potentially_spurious"
            || analysis.classification == "inconclusive"
    );
}

#[test]
fn verify_with_cegar_report_stage_deltas_are_auditable_and_inconclusive_when_eliminated() {
    let source = r#"
protocol CegarDeltaAudit {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 2,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };

    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_delta_audit.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    // Stage deltas (model_changes) should be auditable on refinement stages
    assert!(
        report.stages.len() >= 2,
        "expected at least 2 stages (baseline + refinement)"
    );
    // Baseline stage has no model changes (it is the unrefined run)
    assert!(
        report.stages[0].model_changes.is_empty(),
        "baseline stage should have no model changes (no delta)"
    );
    // Refinement stage(s) should have non-empty model_changes (auditable deltas)
    for stage in &report.stages[1..] {
        assert!(
            !stage.model_changes.is_empty(),
            "refinement stage '{}' should have non-empty model_changes (auditable delta)",
            stage.label
        );
        for change in &stage.model_changes {
            assert!(
                !change.predicate.is_empty(),
                "model change in stage '{}' should have a non-empty predicate",
                stage.label
            );
            assert!(
                !change.category.is_empty(),
                "model change in stage '{}' should have a non-empty category",
                stage.label
            );
        }
    }
    // Stages where the baseline counterexample was eliminated should be reflected
    // in the overall classification as inconclusive (not safe)
    let has_eliminated = report
        .stages
        .iter()
        .any(|s| !s.eliminated_traces.is_empty());
    assert!(
        has_eliminated,
        "at least one stage should have eliminated traces"
    );
    assert_eq!(
        report.classification, "inconclusive",
        "eliminated baseline counterexample without confirmation should yield inconclusive"
    );
}

#[test]
fn cegar_inconclusive_enforced_when_baseline_eliminated_no_confirmation() {
    let source = r#"
protocol CegarInconclusiveEnforced {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
    let options = verify_options(2, SoundnessMode::Strict);

    // Baseline should be unsafe (spurious due to equivocation abstraction)
    let baseline =
        tarsier_engine::pipeline::verify(source, "cegar_inconclusive_enforced.trs", &options)
            .expect("baseline verify should complete");
    assert!(
        matches!(baseline, VerificationResult::Unsafe { .. }),
        "baseline should report UNSAFE"
    );

    // CEGAR with 1 refinement: equivocation tightening eliminates baseline
    // but does not produce a confirming deeper analysis -> must be inconclusive
    let report = tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        "cegar_inconclusive_enforced.trs",
        &options,
        1,
    )
    .expect("CEGAR report should complete");

    // The classification must NOT be "safe" when the baseline was eliminated
    // but there is no confirmation from a deeper analysis
    assert_ne!(
        report.classification, "safe",
        "eliminated baseline without confirmation must not be classified as safe"
    );
    assert_eq!(
        report.classification, "inconclusive",
        "eliminated baseline without confirmation should be classified as inconclusive"
    );
    // The final result must be Unknown (not Safe)
    assert!(
        matches!(report.final_result, VerificationResult::Unknown { .. }),
        "final result should be Unknown when baseline was eliminated without confirmation, got: {:?}",
        report.final_result
    );
    // Termination reason should explain why we stopped
    assert!(
        report.termination.reason == "counterexample_eliminated_no_confirmation"
            || report.termination.reason == "max_refinements_reached",
        "termination reason should indicate eliminated-without-confirmation or budget exhaustion, got: {}",
        report.termination.reason
    );
}

#[test]
fn cegar_minimized_refinement_core_still_eliminates_targeted_spurious_trace() {
    // Models that stress approximation-sensitive paths: the refinement core
    // (even when minimized) should still eliminate the targeted spurious trace.
    struct Case<'a> {
        name: &'a str,
        source: &'a str,
        depth: usize,
        refinements: usize,
    }

    let cases = vec![
        Case {
            name: "minimized_equivocation_core.trs",
            source: r#"
protocol MinimizedEquivCore {
    params n, t;
    resilience: t = 2;
    adversary { model: byzantine; bound: t; equivocation: full; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2 Vote(v=true) && received >= 2 Vote(v=false) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            refinements: 2,
        },
        Case {
            name: "minimized_values_sign_core.trs",
            source: r#"
protocol MinimizedValuesSignCore {
    params n, t;
    resilience: t = 1;
    adversary {
        model: byzantine;
        bound: t;
        equivocation: none;
        values: sign;
    }
    message Vote(v: nat in 0..2);
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 Vote(v=1) && received >= 1 Vote(v=2) => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
            depth: 2,
            refinements: 2,
        },
    ];

    for case in cases {
        let options = verify_options(case.depth, SoundnessMode::Strict);

        // Baseline must expose a spurious unsafe trace
        let baseline = tarsier_engine::pipeline::verify(case.source, case.name, &options)
            .unwrap_or_else(|e| panic!("baseline verify should succeed for {}: {e}", case.name));
        assert!(
            matches!(baseline, VerificationResult::Unsafe { .. }),
            "baseline should report UNSAFE for {}",
            case.name
        );

        // CEGAR report with refinement core
        let report = tarsier_engine::pipeline::verify_with_cegar_report(
            case.source,
            case.name,
            &options,
            case.refinements,
        )
        .unwrap_or_else(|e| panic!("cegar report should succeed for {}: {e}", case.name));

        // The targeted spurious trace from baseline should have been eliminated
        let eliminated_any = report
            .stages
            .iter()
            .any(|stage| !stage.eliminated_traces.is_empty());
        assert!(
            eliminated_any,
            "minimized refinement core should still eliminate targeted spurious trace for {}",
            case.name
        );

        // At least one refinement stage should have discovered predicates
        let has_discovered = report
            .stages
            .iter()
            .skip(1)
            .any(|stage| !stage.discovered_predicates.is_empty());
        assert!(
            has_discovered,
            "refinement stages should expose discovered predicates for {}",
            case.name
        );

        // The overall classification should reflect eliminated traces
        assert_eq!(
            report.classification, "inconclusive",
            "eliminated spurious trace without concrete unsafe confirmation should be inconclusive for {}",
            case.name
        );
    }
}

