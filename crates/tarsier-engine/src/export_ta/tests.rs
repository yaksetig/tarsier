use super::*;

fn load_and_export(trs_source: &str) -> String {
    let program = tarsier_dsl::parse(trs_source, "test.trs").expect("parse failed");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
    export_ta(&ta)
}

#[test]
fn export_reliable_broadcast_structural() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    // Structural checks
    assert!(output.contains("skel"), "missing skel keyword");
    assert!(output.contains("local pc;"), "missing local pc");
    assert!(output.contains("shared "), "missing shared vars");
    assert!(output.contains("parameters "), "missing parameters");
    assert!(output.contains("assumptions"), "missing assumptions");
    assert!(output.contains("locations"), "missing locations");
    assert!(output.contains("inits"), "missing inits");
    assert!(output.contains("rules"), "missing rules");
    assert!(output.contains("->"), "missing rule transitions");
}

#[test]
fn export_pbft_structural() {
    let source = include_str!("../../../../examples/library/pbft_simple_safe.trs");
    let output = load_and_export(source);

    assert!(output.contains("skel"), "missing skel keyword");
    assert!(output.contains("parameters "), "missing parameters");
    assert!(output.contains("locations"), "missing locations");
    assert!(output.contains("rules"), "missing rules");
}

#[test]
fn export_buggy_rb_structural() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_buggy.trs");
    let output = load_and_export(source);

    assert!(output.contains("skel"), "missing skel keyword");
    assert!(output.contains("rules"), "missing rules");
    // Buggy has weaker thresholds (t+1 instead of 2t+1)
    assert!(output.contains("->"), "missing transitions");
}

#[test]
fn exported_ta_has_balanced_braces() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    let opens = output.chars().filter(|&c| c == '{').count();
    let closes = output.chars().filter(|&c| c == '}').count();
    assert_eq!(opens, closes, "unbalanced braces in .ta output");
}

#[test]
fn uppercase_parameters() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    // Parameters should be uppercased in ByMC format
    assert!(
        output.contains("N") && output.contains("T") && output.contains("F"),
        "parameters not uppercased"
    );
}

// T1-TEST-1: Golden tests for .ta export property content

#[test]
fn export_includes_agreement_spec_safe() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    // Safe RB should have non-empty specifications (stability or mutual exclusion)
    assert!(
        !output.contains("specifications (0)"),
        "safe RB should not have empty specifications (0):\n{output}"
    );
    assert!(
        output.contains("specifications ("),
        "missing specifications section in safe RB"
    );
    assert!(
        output.contains("agreement:"),
        "missing agreement label in safe RB"
    );
    assert!(
        output.contains("[]"),
        "missing temporal operator [] in safe RB"
    );
}

#[test]
fn export_includes_agreement_spec_buggy() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_buggy.trs");
    let output = load_and_export(source);

    // Buggy RB has conflicting pairs → mutual exclusion
    assert!(
        output.contains("-> false"),
        "missing mutual exclusion (-> false) in buggy RB:\n{output}"
    );
    assert!(
        output.contains("agreement:"),
        "missing agreement label in buggy RB:\n{output}"
    );
}

#[test]
fn export_includes_guards_and_updates() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    assert!(
        output.contains("when ("),
        "missing guard 'when (' in output:\n{output}"
    );
    assert!(
        output.contains("do {"),
        "missing update 'do {{' in output:\n{output}"
    );
    assert!(
        output.contains("' =="),
        "missing primed variable assignment in output:\n{output}"
    );
}

#[test]
fn export_includes_assumptions_invariant() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let output = load_and_export(source);

    assert!(
        output.contains("assumptions"),
        "missing assumptions section:\n{output}"
    );
    // Resilience condition should be an inequality
    assert!(
        output.contains(">") || output.contains(">="),
        "missing inequality in assumptions:\n{output}"
    );
}

#[test]
fn export_ta_with_no_property() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
    let output = export_ta_with_property(&ta, None);

    assert!(
        output.contains("specifications (0)"),
        "None property should produce specifications (0):\n{output}"
    );
    assert!(
        output.contains("no property provided"),
        "None property should have explanatory comment:\n{output}"
    );
}

#[test]
fn export_includes_termination_spec_when_property_is_termination() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe_live.trs");
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
    let goal_locs: Vec<LocationId> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.phase == "done")
        .map(|(id, _)| id.into())
        .collect();
    assert!(!goal_locs.is_empty(), "expected at least one done location");

    let output = export_ta_with_property(&ta, Some(&SafetyProperty::Termination { goal_locs }));
    assert!(
        output.contains("termination:"),
        "termination label should be present:\n{output}"
    );
    assert!(
        output.contains("<>"),
        "termination spec should use eventuality operator:\n{output}"
    );
    assert!(
        output.contains("specifications (1)"),
        "termination export should emit one specification:\n{output}"
    );
}

#[test]
fn export_termination_with_empty_goals_emits_empty_specs_with_comment() {
    let source = include_str!("../../../../examples/library/reliable_broadcast_safe.trs");
    let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
    let output = export_ta_with_property(
        &ta,
        Some(&SafetyProperty::Termination { goal_locs: vec![] }),
    );
    assert!(
        output.contains("termination property has no goal locations"),
        "empty-goal termination export should explain fallback:\n{output}"
    );
    assert!(
        output.contains("specifications (0)"),
        "empty-goal termination export should emit empty specs:\n{output}"
    );
}

#[test]
fn export_ta_for_program_includes_termination_spec_when_declared() {
    let source = r#"
protocol ExportTerminationOnly {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property termination: liveness {
        forall p: Replica. p.decided == true
    }
}
"#;
    let program = tarsier_dsl::parse(source, "export_term_only.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
    let output = export_ta_for_program(&ta, &program);

    assert!(
        output.contains("termination:"),
        "program-aware export should emit termination spec label:\n{output}"
    );
    assert!(
        output.contains("<>"),
        "program-aware export should emit eventuality for termination:\n{output}"
    );
}

#[test]
fn export_ta_for_program_includes_temporal_liveness_spec_when_declared() {
    let source = r#"
protocol ExportTemporalLiveness {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_decide: liveness {
        forall p: Replica. <> (p.decided == true)
    }
}
"#;
    let program = tarsier_dsl::parse(source, "export_temporal.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    let output = export_ta_for_program(&ta, &program);

    assert!(
        output.contains("liveness:"),
        "temporal-liveness export should emit liveness label:\n{output}"
    );
    assert!(
        output.contains("<>"),
        "temporal-liveness export should emit eventuality operator:\n{output}"
    );
    assert!(
        !output.contains("agreement:"),
        "temporal-liveness export should not fall back to agreement:\n{output}"
    );
}

#[test]
fn export_ta_for_program_temporal_liveness_with_unknown_field_falls_back_to_agreement() {
    let source = r#"
protocol ExportTemporalLivenessUnknownField {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_missing: liveness {
        forall p: Replica. <> (p.not_a_real_field == true)
    }
}
"#;
    let program = tarsier_dsl::parse(source, "export_temporal_unknown_field.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    let output = export_ta_for_program(&ta, &program);

    assert!(
        output.contains("agreement:"),
        "invalid temporal liveness should fall back to agreement:\n{output}"
    );
    assert!(
        !output.contains("liveness:"),
        "invalid temporal liveness should not emit temporal spec:\n{output}"
    );
}

#[test]
fn export_ta_for_program_temporal_liveness_supports_mixed_quantifier_roles() {
    let source = r#"
protocol ExportTemporalMixedQuantifiers {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role A {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    role B {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_pair: liveness {
        forall p: A. exists q: B. <> ((p.decided == true) && (q.decided == true))
    }
}
"#;
    let program =
        tarsier_dsl::parse(source, "export_temporal_mixed_quantifiers.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    let output = export_ta_for_program(&ta, &program);

    assert!(
        output.contains("liveness:"),
        "mixed-quantifier temporal export should emit liveness label:\n{output}"
    );
    assert!(
        output.contains("<>"),
        "mixed-quantifier temporal export should keep eventual operator:\n{output}"
    );
    assert!(
        !output.contains("agreement:"),
        "mixed-quantifier temporal export should not fall back:\n{output}"
    );
}

#[test]
fn export_ta_for_program_temporal_leads_to_is_desugared_in_bymc_spec() {
    let source = r#"
protocol ExportTemporalLeadsTo {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property progress: liveness {
        forall p: Replica. (p.decided == false) ~> (p.decided == true)
    }
}
"#;
    let program = tarsier_dsl::parse(source, "export_temporal_leads_to.trs").expect("parse");
    let ta = tarsier_ir::lowering::lower(&program).expect("lower");
    let output = export_ta_for_program(&ta, &program);

    assert!(
        output.contains("liveness:"),
        "leads-to export should emit liveness label:\n{output}"
    );
    assert!(
        output.contains("[]"),
        "leads-to export should desugar to global always form:\n{output}"
    );
    assert!(
        output.contains("<>"),
        "leads-to export should include eventuality in desugared body:\n{output}"
    );
}
