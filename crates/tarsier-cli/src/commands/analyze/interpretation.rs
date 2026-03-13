use serde_json::Value;

use crate::{
    AnalysisInterpretation, AnalysisLayerReport, AnalysisMode, CanonicalVerdict, ClaimStatement,
    NextAction,
};

pub(crate) fn overall_status(mode: AnalysisMode, layers: &[AnalysisLayerReport]) -> String {
    let has_fail = layers
        .iter()
        .any(|l| l.status == "fail" || l.status == "error");
    if has_fail {
        return "fail".to_string();
    }

    let has_unknown = layers.iter().any(|l| l.status == "unknown");
    match mode {
        AnalysisMode::Quick | AnalysisMode::Standard => {
            if has_unknown {
                "unknown".to_string()
            } else {
                "pass".to_string()
            }
        }
        AnalysisMode::Proof | AnalysisMode::Audit => {
            if has_unknown {
                "fail".to_string()
            } else {
                "pass".to_string()
            }
        }
    }
}

pub(crate) fn is_safety_interpretation_layer(layer: &str) -> bool {
    layer.starts_with("verify")
        || (layer.starts_with("prove[") && !layer.starts_with("prove[fair"))
        || layer.starts_with("certify[safety]")
}

pub(crate) fn is_liveness_interpretation_layer(layer: &str) -> bool {
    layer.starts_with("liveness[")
        || layer.starts_with("prove[fair")
        || layer.starts_with("certify[fair_liveness]")
}

pub(crate) fn compute_analysis_interpretation(
    layers: &[AnalysisLayerReport],
    overall: &str,
) -> AnalysisInterpretation {
    let safety_layers: Vec<&AnalysisLayerReport> = layers
        .iter()
        .filter(|l| is_safety_interpretation_layer(&l.layer))
        .collect();
    let liveness_layers: Vec<&AnalysisLayerReport> = layers
        .iter()
        .filter(|l| is_liveness_interpretation_layer(&l.layer))
        .collect();

    let safety = if safety_layers.is_empty() {
        "NOT_CHECKED"
    } else if safety_layers.iter().any(|l| l.verdict == "UNSAFE") {
        "UNSAFE"
    } else if safety_layers.iter().any(|l| l.verdict == "SAFE") {
        "SAFE"
    } else {
        "UNKNOWN"
    };

    let liveness = if liveness_layers.is_empty() {
        "NOT_CHECKED"
    } else if liveness_layers.iter().any(|l| l.verdict == "LIVE_CEX") {
        "LIVE_CEX"
    } else if liveness_layers.iter().any(|l| l.verdict == "LIVE_PROVED") {
        "LIVE_PROVED"
    } else {
        "UNKNOWN"
    };

    let summary = match (safety, liveness) {
        ("UNSAFE", _) => "Safety violation found (counterexample exists).".to_string(),
        (_, "LIVE_CEX") => {
            "Liveness violation found (non-terminating/fair cycle trace exists).".to_string()
        }
        ("SAFE", "LIVE_PROVED") => "Safety and liveness hold in this analysis scope.".to_string(),
        ("SAFE", "UNKNOWN") => {
            "Safety holds in this analysis scope; liveness is inconclusive.".to_string()
        }
        ("SAFE", "NOT_CHECKED") => {
            "Safety holds in this analysis scope; liveness was not checked.".to_string()
        }
        ("UNKNOWN", "LIVE_PROVED") => {
            "Liveness holds in this analysis scope; safety is inconclusive.".to_string()
        }
        ("UNKNOWN", "UNKNOWN") => {
            "Both safety and liveness are inconclusive in this run.".to_string()
        }
        ("NOT_CHECKED", "NOT_CHECKED") => {
            "No safety/liveness property checks were executed in this run.".to_string()
        }
        _ => "Property interpretation requires deeper follow-up for this run.".to_string(),
    };

    let overall_status_meaning = if overall == "pass" {
        "overall=pass means all scheduled layers completed without failures for the selected mode."
            .to_string()
    } else {
        "overall reflects pipeline completion for the selected mode; rely on safety/liveness above for the property-level result."
            .to_string()
    };

    AnalysisInterpretation {
        safety: safety.to_string(),
        liveness: liveness.to_string(),
        summary,
        overall_status_meaning,
    }
}

pub(crate) fn compute_overall_verdict(layers: &[AnalysisLayerReport]) -> CanonicalVerdict {
    let mut has_unsafe = false;
    let mut has_live_cex = false;
    let mut has_inconclusive = false;
    let mut has_unknown = false;
    let mut has_safe = false;
    let mut has_live_proved = false;

    for layer in layers {
        match layer.verdict.as_str() {
            "UNSAFE" => has_unsafe = true,
            "LIVE_CEX" => has_live_cex = true,
            "INCONCLUSIVE" => has_inconclusive = true,
            "UNKNOWN" => has_unknown = true,
            "SAFE" => has_safe = true,
            "LIVE_PROVED" => has_live_proved = true,
            _ => {}
        }
    }

    if has_unsafe {
        CanonicalVerdict::Unsafe
    } else if has_live_cex {
        CanonicalVerdict::LiveCex
    } else if has_inconclusive {
        CanonicalVerdict::Inconclusive
    } else if has_unknown {
        CanonicalVerdict::Unknown
    } else if has_safe || has_live_proved {
        CanonicalVerdict::Safe
    } else {
        CanonicalVerdict::Unknown
    }
}

pub(crate) fn compute_confidence_tier(
    mode: AnalysisMode,
    layers: &[AnalysisLayerReport],
) -> String {
    match mode {
        AnalysisMode::Quick => "quick".to_string(),
        AnalysisMode::Standard => {
            let has_passing_prove = layers.iter().any(|l| {
                l.layer.starts_with("prove[") && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
            });
            if has_passing_prove {
                "proof".to_string()
            } else {
                "bounded".to_string()
            }
        }
        AnalysisMode::Proof => {
            let has_passing_prove = layers.iter().any(|l| {
                l.layer.starts_with("prove[") && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
            });
            if has_passing_prove {
                "proof".to_string()
            } else {
                "bounded".to_string()
            }
        }
        AnalysisMode::Audit => {
            let cert_layers: Vec<_> = layers
                .iter()
                .filter(|l| l.layer.starts_with("certify["))
                .collect();
            let has_cert_layers = !cert_layers.is_empty();
            let all_cert_pass = has_cert_layers && cert_layers.iter().all(|l| l.status == "pass");
            if all_cert_pass {
                "certified".to_string()
            } else {
                let has_passing_prove = layers.iter().any(|l| {
                    l.layer.starts_with("prove[")
                        && (l.verdict == "SAFE" || l.verdict == "LIVE_PROVED")
                });
                if has_passing_prove {
                    "proof".to_string()
                } else {
                    "bounded".to_string()
                }
            }
        }
    }
}

pub(crate) fn build_claim_statement(
    layers: &[AnalysisLayerReport],
    network_faithfulness: &Value,
    mode: &str,
    preflight_warnings: &[Value],
) -> ClaimStatement {
    let mut proven = Vec::new();
    let mut assumptions = Vec::new();
    let mut not_covered = Vec::new();

    for layer in layers {
        match layer.verdict.as_str() {
            "SAFE" => {
                if layer.layer.contains("prove") {
                    proven.push(format!("Safety: unbounded proof via {}", layer.layer));
                } else {
                    proven.push(format!("Safety: bounded check via {}", layer.layer));
                }
            }
            "LIVE_PROVED" => {
                if layer.layer.contains("prove") {
                    proven.push(format!("Liveness: unbounded proof via {}", layer.layer));
                } else {
                    proven.push(format!("Liveness: bounded check via {}", layer.layer));
                }
            }
            _ => {}
        }
    }

    if proven.is_empty() {
        proven.push("No properties were proven in this run.".to_string());
    }

    assumptions.push(
        "Threshold automaton counter abstraction is sound for the modeled protocol.".to_string(),
    );
    let nf_status = network_faithfulness
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if nf_status != "faithful" {
        assumptions.push(format!(
            "Network model: {} (not fully faithful -- results may be optimistic).",
            nf_status
        ));
    } else {
        assumptions.push("Network model: faithful semantics enforced.".to_string());
    }

    for w in preflight_warnings {
        if let Some(msg) = w.get("message").and_then(Value::as_str) {
            assumptions.push(format!("Preflight: {msg}"));
        }
    }

    let has_liveness = layers
        .iter()
        .any(|l| l.layer.contains("liveness") || l.layer.contains("fair"));
    let has_safety = layers.iter().any(|l| {
        l.layer.contains("verify") || l.layer.contains("prove[k") || l.layer.contains("prove[pdr")
    });
    let has_proof = layers.iter().any(|l| l.layer.contains("prove"));

    if !has_liveness {
        not_covered.push("Liveness properties (not checked in this mode).".to_string());
    }
    if !has_safety {
        not_covered.push("Safety properties (not checked in this mode).".to_string());
    }
    if !has_proof && mode != "proof" && mode != "audit" {
        not_covered.push(
            "Unbounded proofs (use --mode proof or --goal safety for unbounded verification)."
                .to_string(),
        );
    }
    not_covered
        .push("Implementation bugs not captured by the threshold automaton model.".to_string());

    ClaimStatement {
        proven,
        assumptions,
        not_covered,
    }
}

pub(crate) fn build_next_action(
    layers: &[AnalysisLayerReport],
    filename: &str,
    mode: &str,
) -> Option<NextAction> {
    let has_unsafe = layers.iter().any(|l| l.verdict == "UNSAFE");
    let has_live_cex = layers.iter().any(|l| l.verdict == "LIVE_CEX");
    let has_inconclusive = layers.iter().any(|l| l.verdict == "INCONCLUSIVE");
    let has_unknown = layers.iter().any(|l| l.verdict == "UNKNOWN");
    let has_proof = layers.iter().any(|l| l.layer.contains("prove"));
    let all_pass = !has_unsafe && !has_live_cex && !has_inconclusive && !has_unknown;

    if has_unsafe {
        return Some(NextAction {
            command: format!("visualize {filename} --check verify"),
            reason: "A counterexample was found. Visualize the trace to understand the bug."
                .to_string(),
        });
    }

    if has_live_cex {
        return Some(NextAction {
            command: format!("visualize {filename} --check fair-liveness"),
            reason: "A liveness counterexample was found. Visualize the trace to debug."
                .to_string(),
        });
    }

    if has_inconclusive && !has_proof {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof"),
            reason: "Bounded checks passed but unbounded proof was not attempted. Upgrade to proof mode.".to_string(),
        });
    }

    if has_inconclusive && has_proof {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof --depth 16 --k 20"),
            reason: "Proof did not converge. Try with increased depth and k bounds.".to_string(),
        });
    }

    if has_unknown {
        return Some(NextAction {
            command: format!("analyze {filename} --mode standard --timeout 600"),
            reason: "Some checks were inconclusive. Try with a longer timeout.".to_string(),
        });
    }

    if all_pass && mode == "quick" {
        return Some(NextAction {
            command: format!("analyze {filename} --mode standard"),
            reason: "Quick check passed. Run standard mode for full coverage.".to_string(),
        });
    }

    if all_pass && mode == "standard" {
        return Some(NextAction {
            command: format!("analyze {filename} --mode proof"),
            reason: "Standard checks passed. Run proof mode for unbounded guarantees.".to_string(),
        });
    }

    if all_pass && (mode == "proof" || mode == "audit") {
        return Some(NextAction {
            command: format!("certify-safety {filename} --out cert/"),
            reason: "All checks passed. Generate a proof certificate for independent verification."
                .to_string(),
        });
    }

    None
}
