use super::*;
use serde_json::json;

fn make_layer(layer_name: &str, status: &str, verdict: &str) -> AnalysisLayerReport {
    AnalysisLayerReport {
        layer: layer_name.into(),
        status: status.into(),
        verdict: verdict.into(),
        summary: "test summary".into(),
        details: json!({}),
        output: "test output".into(),
    }
}

// -----------------------------------------------------------------------
// layer() helper
// -----------------------------------------------------------------------

#[test]
fn layer_helper_builds_report() {
    let report = layer("verify", "pass", "All good", json!({"x": 1}), "ok");
    assert_eq!(report.layer, "verify");
    assert_eq!(report.status, "pass");
    assert_eq!(report.summary, "All good");
    assert_eq!(report.output, "ok");
    assert_eq!(report.details["x"], 1);
    // verdict should be computed from canonical_verdict_from_layer_result
    assert_eq!(report.verdict, "SAFE");
}

#[test]
fn layer_helper_fail_verdict() {
    let report = layer("verify", "fail", "Safety violation", json!({}), "bad");
    assert_eq!(report.verdict, "UNKNOWN");
}

// -----------------------------------------------------------------------
// overall_status
// -----------------------------------------------------------------------

#[test]
fn overall_status_all_pass_quick() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    assert_eq!(overall_status(AnalysisMode::Quick, &layers), "pass");
}

#[test]
fn overall_status_has_fail() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("prove[k]", "fail", "UNSAFE"),
    ];
    assert_eq!(overall_status(AnalysisMode::Quick, &layers), "fail");
}

#[test]
fn overall_status_has_error() {
    let layers = vec![make_layer("verify", "error", "UNKNOWN")];
    assert_eq!(overall_status(AnalysisMode::Standard, &layers), "fail");
}

#[test]
fn overall_status_unknown_quick_vs_proof() {
    let layers = vec![make_layer("prove[k]", "unknown", "UNKNOWN")];
    assert_eq!(overall_status(AnalysisMode::Quick, &layers), "unknown");
    assert_eq!(overall_status(AnalysisMode::Proof, &layers), "fail");
    assert_eq!(overall_status(AnalysisMode::Audit, &layers), "fail");
}

#[test]
fn overall_status_empty_layers() {
    let layers: Vec<AnalysisLayerReport> = vec![];
    assert_eq!(overall_status(AnalysisMode::Quick, &layers), "pass");
}

// -----------------------------------------------------------------------
// is_safety_interpretation_layer
// -----------------------------------------------------------------------

#[test]
fn safety_layer_detection() {
    assert!(is_safety_interpretation_layer("verify"));
    assert!(is_safety_interpretation_layer("verify[d=5]"));
    assert!(is_safety_interpretation_layer("prove[k=3]"));
    assert!(is_safety_interpretation_layer("prove[pdr]"));
    assert!(is_safety_interpretation_layer("certify[safety]"));
    assert!(!is_safety_interpretation_layer("prove[fair-liveness]"));
    assert!(!is_safety_interpretation_layer("liveness[d=5]"));
}

// -----------------------------------------------------------------------
// is_liveness_interpretation_layer
// -----------------------------------------------------------------------

#[test]
fn liveness_layer_detection() {
    assert!(is_liveness_interpretation_layer("liveness[d=5]"));
    assert!(is_liveness_interpretation_layer("prove[fair-liveness]"));
    assert!(is_liveness_interpretation_layer("certify[fair_liveness]"));
    assert!(!is_liveness_interpretation_layer("verify"));
    assert!(!is_liveness_interpretation_layer("prove[k=3]"));
}

// -----------------------------------------------------------------------
// compute_analysis_interpretation
// -----------------------------------------------------------------------

#[test]
fn interpretation_safe_and_live() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("prove[fair-liveness]", "pass", "LIVE_PROVED"),
    ];
    let interp = compute_analysis_interpretation(&layers, "pass");
    assert_eq!(interp.safety, "SAFE");
    assert_eq!(interp.liveness, "LIVE_PROVED");
    assert!(interp.summary.contains("Safety and liveness hold"));
}

#[test]
fn interpretation_unsafe() {
    let layers = vec![make_layer("verify", "fail", "UNSAFE")];
    let interp = compute_analysis_interpretation(&layers, "fail");
    assert_eq!(interp.safety, "UNSAFE");
    assert!(interp.summary.contains("Safety violation"));
}

#[test]
fn interpretation_no_layers() {
    let layers: Vec<AnalysisLayerReport> = vec![];
    let interp = compute_analysis_interpretation(&layers, "pass");
    assert_eq!(interp.safety, "NOT_CHECKED");
    assert_eq!(interp.liveness, "NOT_CHECKED");
}

#[test]
fn interpretation_safe_liveness_unknown() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("liveness[d=5]", "unknown", "UNKNOWN"),
    ];
    let interp = compute_analysis_interpretation(&layers, "unknown");
    assert_eq!(interp.safety, "SAFE");
    assert_eq!(interp.liveness, "UNKNOWN");
    assert!(interp.summary.contains("liveness is inconclusive"));
}

#[test]
fn interpretation_overall_pass_meaning() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    let interp = compute_analysis_interpretation(&layers, "pass");
    assert!(interp.overall_status_meaning.contains("overall=pass"));
}

// -----------------------------------------------------------------------
// compute_overall_verdict
// -----------------------------------------------------------------------

#[test]
fn overall_verdict_unsafe_wins() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("prove[k]", "fail", "UNSAFE"),
    ];
    assert_eq!(compute_overall_verdict(&layers), CanonicalVerdict::Unsafe);
}

#[test]
fn overall_verdict_live_cex() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("liveness[d]", "fail", "LIVE_CEX"),
    ];
    assert_eq!(compute_overall_verdict(&layers), CanonicalVerdict::LiveCex);
}

#[test]
fn overall_verdict_inconclusive() {
    let layers = vec![make_layer("prove[k]", "unknown", "INCONCLUSIVE")];
    assert_eq!(
        compute_overall_verdict(&layers),
        CanonicalVerdict::Inconclusive
    );
}

#[test]
fn overall_verdict_unknown() {
    let layers = vec![make_layer("verify", "unknown", "UNKNOWN")];
    assert_eq!(compute_overall_verdict(&layers), CanonicalVerdict::Unknown);
}

#[test]
fn overall_verdict_all_safe() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    assert_eq!(compute_overall_verdict(&layers), CanonicalVerdict::Safe);
}

#[test]
fn overall_verdict_empty() {
    let layers: Vec<AnalysisLayerReport> = vec![];
    assert_eq!(compute_overall_verdict(&layers), CanonicalVerdict::Unknown);
}

// -----------------------------------------------------------------------
// compute_confidence_tier
// -----------------------------------------------------------------------

#[test]
fn confidence_quick() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    assert_eq!(
        compute_confidence_tier(AnalysisMode::Quick, &layers),
        "quick"
    );
}

#[test]
fn confidence_standard_bounded() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    assert_eq!(
        compute_confidence_tier(AnalysisMode::Standard, &layers),
        "bounded"
    );
}

#[test]
fn confidence_standard_proof() {
    let layers = vec![
        make_layer("verify", "pass", "SAFE"),
        make_layer("prove[k=3]", "pass", "SAFE"),
    ];
    assert_eq!(
        compute_confidence_tier(AnalysisMode::Standard, &layers),
        "proof"
    );
}

#[test]
fn confidence_audit_certified() {
    let layers = vec![
        make_layer("prove[k=3]", "pass", "SAFE"),
        make_layer("certify[safety]", "pass", "SAFE"),
    ];
    assert_eq!(
        compute_confidence_tier(AnalysisMode::Audit, &layers),
        "certified"
    );
}

#[test]
fn confidence_audit_without_cert() {
    let layers = vec![make_layer("prove[k=3]", "pass", "SAFE")];
    assert_eq!(
        compute_confidence_tier(AnalysisMode::Audit, &layers),
        "proof"
    );
}

// -----------------------------------------------------------------------
// build_claim_statement
// -----------------------------------------------------------------------

#[test]
fn claim_statement_safe_proof() {
    let layers = vec![make_layer("prove[k=3]", "pass", "SAFE")];
    let nf = json!({"status": "faithful"});
    let claim = build_claim_statement(&layers, &nf, "proof", &[]);
    assert!(claim.proven.iter().any(|p| p.contains("Safety")));
    assert!(claim.proven.iter().any(|p| p.contains("unbounded")));
    assert!(claim.assumptions.iter().any(|a| a.contains("faithful")));
}

#[test]
fn claim_statement_no_proven() {
    let layers = vec![make_layer("verify", "unknown", "UNKNOWN")];
    let nf = json!({"status": "classic"});
    let claim = build_claim_statement(&layers, &nf, "quick", &[]);
    assert!(claim.proven.iter().any(|p| p.contains("No properties")));
}

#[test]
fn claim_statement_not_covered_liveness() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    let nf = json!({"status": "faithful"});
    let claim = build_claim_statement(&layers, &nf, "quick", &[]);
    assert!(claim.not_covered.iter().any(|n| n.contains("Liveness")));
}

#[test]
fn claim_statement_with_preflight_warnings() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    let nf = json!({"status": "faithful"});
    let warnings = vec![json!({"message": "Missing resilience"})];
    let claim = build_claim_statement(&layers, &nf, "standard", &warnings);
    assert!(claim
        .assumptions
        .iter()
        .any(|a| a.contains("Missing resilience")));
}

// -----------------------------------------------------------------------
// build_next_action
// -----------------------------------------------------------------------

#[test]
fn next_action_unsafe() {
    let layers = vec![make_layer("verify", "fail", "UNSAFE")];
    let next = build_next_action(&layers, "test.trs", "quick");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("visualize"));
    assert!(n.reason.contains("counterexample"));
}

#[test]
fn next_action_live_cex() {
    let layers = vec![make_layer("liveness[d=5]", "fail", "LIVE_CEX")];
    let next = build_next_action(&layers, "test.trs", "quick");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("fair-liveness"));
}

#[test]
fn next_action_pass_quick() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    let next = build_next_action(&layers, "test.trs", "quick");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("standard"));
}

#[test]
fn next_action_pass_standard() {
    let layers = vec![make_layer("verify", "pass", "SAFE")];
    let next = build_next_action(&layers, "test.trs", "standard");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("proof"));
}

#[test]
fn next_action_pass_proof() {
    let layers = vec![make_layer("prove[k=3]", "pass", "SAFE")];
    let next = build_next_action(&layers, "test.trs", "proof");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("certify"));
}

#[test]
fn next_action_unknown() {
    let layers = vec![make_layer("verify", "unknown", "UNKNOWN")];
    let next = build_next_action(&layers, "test.trs", "quick");
    assert!(next.is_some());
    let n = next.unwrap();
    assert!(n.command.contains("timeout"));
}

// -----------------------------------------------------------------------
// render_analysis_text
// -----------------------------------------------------------------------

#[test]
fn render_analysis_text_basic() {
    let report = AnalysisReport {
        schema_version: "1".into(),
        mode: "quick".into(),
        file: "test.trs".into(),
        config: AnalysisConfig {
            solver: "z3".into(),
            depth: 5,
            k: 10,
            timeout_secs: 60,
            soundness: "strict".into(),
            fairness: "weak".into(),
            portfolio: false,
            por_mode: "full".into(),
        },
        network_faithfulness: json!({"status": "pass", "summary": "Legacy"}),
        liveness_governance: None,
        layers: vec![make_layer("verify", "pass", "SAFE")],
        overall: "pass".into(),
        overall_verdict: "SAFE".into(),
        interpretation: AnalysisInterpretation {
            safety: "SAFE".into(),
            liveness: "NOT_CHECKED".into(),
            summary: "Safety holds.".into(),
            overall_status_meaning: "all ok".into(),
        },
        claim: None,
        next_action: None,
        confidence_tier: "bounded".into(),
        preflight_warnings: vec![],
    };
    let text = render_analysis_text(&report);
    assert!(text.contains("ANALYSIS REPORT"));
    assert!(text.contains("Mode: quick"));
    assert!(text.contains("File: test.trs"));
    assert!(text.contains("Verdict: SAFE"));
    assert!(text.contains("Safety: SAFE"));
    assert!(text.contains("[SAFE] verify: test summary"));
}

#[test]
fn render_analysis_text_with_claim() {
    let report = AnalysisReport {
        schema_version: "1".into(),
        mode: "proof".into(),
        file: "test.trs".into(),
        config: AnalysisConfig {
            solver: "z3".into(),
            depth: 5,
            k: 10,
            timeout_secs: 60,
            soundness: "strict".into(),
            fairness: "weak".into(),
            portfolio: false,
            por_mode: "full".into(),
        },
        network_faithfulness: json!({"status": "pass", "summary": "ok"}),
        liveness_governance: None,
        layers: vec![],
        overall: "pass".into(),
        overall_verdict: "SAFE".into(),
        interpretation: AnalysisInterpretation {
            safety: "SAFE".into(),
            liveness: "NOT_CHECKED".into(),
            summary: "ok".into(),
            overall_status_meaning: "ok".into(),
        },
        claim: Some(ClaimStatement {
            proven: vec!["Safety proved".into()],
            assumptions: vec!["TA abstraction".into()],
            not_covered: vec!["Liveness".into()],
        }),
        next_action: Some(NextAction {
            command: "certify-safety test.trs".into(),
            reason: "Generate cert".into(),
        }),
        confidence_tier: "proof".into(),
        preflight_warnings: vec![],
    };
    let text = render_analysis_text(&report);
    assert!(text.contains("What was proven:"));
    assert!(text.contains("+ Safety proved"));
    assert!(text.contains("Assumptions:"));
    assert!(text.contains("* TA abstraction"));
    assert!(text.contains("Not covered:"));
    assert!(text.contains("- Liveness"));
    assert!(text.contains("Recommended next step:"));
    assert!(text.contains("$ tarsier certify-safety test.trs"));
}

// -----------------------------------------------------------------------
// AnalysisReport serialization
// -----------------------------------------------------------------------

#[test]
fn analysis_report_serializes() {
    let report = AnalysisReport {
        schema_version: "1".into(),
        mode: "quick".into(),
        file: "test.trs".into(),
        config: AnalysisConfig {
            solver: "z3".into(),
            depth: 5,
            k: 10,
            timeout_secs: 60,
            soundness: "strict".into(),
            fairness: "weak".into(),
            portfolio: false,
            por_mode: "full".into(),
        },
        network_faithfulness: json!({}),
        liveness_governance: None,
        layers: vec![],
        overall: "pass".into(),
        overall_verdict: "SAFE".into(),
        interpretation: AnalysisInterpretation {
            safety: "SAFE".into(),
            liveness: "NOT_CHECKED".into(),
            summary: "ok".into(),
            overall_status_meaning: "ok".into(),
        },
        claim: None,
        next_action: None,
        confidence_tier: "bounded".into(),
        preflight_warnings: vec![],
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], "1");
    assert_eq!(json["mode"], "quick");
    // liveness_governance should be absent (skip_serializing_if = None)
    assert!(json.get("liveness_governance").is_none());
    // claim should be absent
    assert!(json.get("claim").is_none());
}
