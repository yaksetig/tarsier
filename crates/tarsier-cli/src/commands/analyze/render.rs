use serde_json::Value;

use crate::AnalysisReport;

pub(crate) fn render_analysis_text(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str("ANALYSIS REPORT\n");
    out.push_str(&format!("Mode: {}\n", report.mode));
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!("Verdict: {}\n", report.overall_verdict));
    out.push_str(&format!("Confidence: {}\n", report.confidence_tier));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str("Interpretation:\n");
    out.push_str(&format!("  Safety: {}\n", report.interpretation.safety));
    out.push_str(&format!("  Liveness: {}\n", report.interpretation.liveness));
    out.push_str(&format!("  Summary: {}\n", report.interpretation.summary));
    out.push_str(&format!(
        "  Note: {}\n",
        report.interpretation.overall_status_meaning
    ));

    let nf_status = report
        .network_faithfulness
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let nf_summary = report
        .network_faithfulness
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("No network faithfulness summary.");
    if nf_status != "faithful" {
        out.push_str(&format!(
            "\n*** MODEL FIDELITY WARNING: [{}] {} ***\n",
            nf_status.to_uppercase(),
            nf_summary
        ));
    } else {
        out.push_str("Network Faithfulness:\n");
        out.push_str(&format!(
            "- [{}] {}\n",
            nf_status.to_uppercase(),
            nf_summary
        ));
    }
    if let Some(assumptions) = report
        .network_faithfulness
        .get("assumptions_enforced")
        .and_then(Value::as_array)
    {
        for item in assumptions.iter().filter_map(Value::as_str) {
            out.push_str(&format!("  - {item}\n"));
        }
    }

    if let Some(governance) = &report.liveness_governance {
        let fairness_mode = governance
            .get("fairness_model")
            .and_then(|v| v.get("mode"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let timing_model = governance
            .get("gst_assumptions")
            .and_then(|v| v.get("timing_model"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let gst_parameter = governance
            .get("gst_assumptions")
            .and_then(|v| v.get("gst_parameter"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        let obligation_count = governance
            .get("obligations_checked")
            .and_then(|v| v.get("total_obligations_checked"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        out.push_str("\nLiveness Governance:\n");
        out.push_str(&format!("  - fairness model: {fairness_mode}\n"));
        out.push_str(&format!("  - timing model: {timing_model}\n"));
        out.push_str(&format!("  - gst parameter: {gst_parameter}\n"));
        out.push_str(&format!("  - obligations checked: {obligation_count}\n"));
    }

    if !report.preflight_warnings.is_empty() {
        out.push_str("\nPreflight Warnings:\n");
        for w in &report.preflight_warnings {
            let code = w.get("code").and_then(Value::as_str).unwrap_or("unknown");
            let msg = w.get("message").and_then(Value::as_str).unwrap_or("");
            let hint = w.get("hint").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  [{code}] {msg}\n"));
            if !hint.is_empty() {
                out.push_str(&format!("    Hint: {hint}\n"));
            }
        }
    }

    out.push_str("\nLayers:\n");
    for layer in &report.layers {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            layer.verdict, layer.layer, layer.summary
        ));
        if let Some(diags) = layer
            .details
            .get("fragment_diagnostics")
            .and_then(Value::as_array)
        {
            out.push_str("  *** UNSUPPORTED PROPERTY SHAPE ***\n");
            for d in diags {
                let prop = d.get("property").and_then(Value::as_str).unwrap_or("?");
                let msg = d.get("message").and_then(Value::as_str).unwrap_or("");
                let hint = d.get("hint").and_then(Value::as_str);
                out.push_str(&format!("  property '{prop}': {msg}\n"));
                if let Some(h) = hint {
                    out.push_str(&format!("    Hint: {h}\n"));
                }
            }
        }
    }

    if let Some(claim) = &report.claim {
        out.push_str("\nWhat was proven:\n");
        for item in &claim.proven {
            out.push_str(&format!("  + {item}\n"));
        }
        out.push_str("Assumptions:\n");
        for item in &claim.assumptions {
            out.push_str(&format!("  * {item}\n"));
        }
        out.push_str("Not covered:\n");
        for item in &claim.not_covered {
            out.push_str(&format!("  - {item}\n"));
        }
    }

    if let Some(next) = &report.next_action {
        out.push_str(&format!(
            "\nRecommended next step:\n  $ tarsier {}\n  ({})\n",
            next.command, next.reason
        ));
    }

    out
}
