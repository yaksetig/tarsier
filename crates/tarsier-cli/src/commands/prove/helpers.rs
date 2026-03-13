// Prove command helper functions.

use miette::IntoDiagnostic;
use serde_json::{json, Value};

use tarsier_engine::pipeline::FairnessMode;

use crate::AnalysisLayerReport;

use super::types::ProveAutoTarget;

pub(crate) fn is_safety_property_kind(kind: tarsier_dsl::ast::PropertyKind) -> bool {
    matches!(
        kind,
        tarsier_dsl::ast::PropertyKind::Agreement
            | tarsier_dsl::ast::PropertyKind::Validity
            | tarsier_dsl::ast::PropertyKind::Safety
            | tarsier_dsl::ast::PropertyKind::Invariant
    )
}

pub(crate) fn detect_prove_auto_target(
    source: &str,
    filename: &str,
) -> miette::Result<ProveAutoTarget> {
    let program = tarsier_dsl::parse(source, filename).into_diagnostic()?;
    let has_safety = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind));
    let has_liveness = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| p.node.kind == tarsier_dsl::ast::PropertyKind::Liveness);

    Ok(if has_liveness && !has_safety {
        ProveAutoTarget::FairLiveness
    } else {
        ProveAutoTarget::Safety
    })
}

#[cfg(feature = "governance")]
pub(crate) fn parse_manifest_fairness_mode(raw: &str) -> Result<FairnessMode, String> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(format!(
            "Unknown fairness '{other}'. Use 'weak' or 'strong'."
        )),
    }
}

pub(crate) fn fairness_name(mode: FairnessMode) -> &'static str {
    match mode {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

pub(crate) fn fairness_semantics_json(mode: FairnessMode) -> Value {
    let semantics = mode.semantics();
    json!({
        "mode": semantics.mode,
        "formal_name": semantics.formal_name,
        "definition": semantics.definition,
        "verdict_interpretation": semantics.verdict_interpretation,
    })
}

pub(crate) fn gst_assumptions_json(source: &str, filename: &str) -> Value {
    match tarsier_engine::pipeline::parse(source, filename)
        .and_then(|program| tarsier_engine::pipeline::lower(&program))
    {
        Ok(ta) => {
            let gst_parameter = ta.semantics.gst_param.and_then(|pid| {
                ta.parameters
                    .get(pid.as_usize())
                    .map(|param| param.name.clone())
            });
            let requires_gst = matches!(
                ta.semantics.timing_model,
                tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
            );
            json!({
                "timing_model": format!("{:?}", ta.semantics.timing_model),
                "requires_gst": requires_gst,
                "gst_parameter": gst_parameter,
                "post_gst_assumed_for_fairness": requires_gst,
            })
        }
        Err(e) => json!({
            "status": "unavailable",
            "error": e.to_string(),
        }),
    }
}

pub(crate) fn fair_liveness_obligation_entries(layers: &[AnalysisLayerReport]) -> Vec<Value> {
    layers
        .iter()
        .filter(|layer| layer.layer.starts_with("certify[fair_liveness]"))
        .map(|layer| {
            let obligations = layer
                .details
                .get("obligations_checked")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let obligation_count = layer
                .details
                .get("obligation_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .unwrap_or(obligations.len());
            let integrity_ok = layer.details.get("integrity_ok").and_then(Value::as_bool);
            json!({
                "layer": layer.layer,
                "status": layer.status,
                "integrity_ok": integrity_ok,
                "obligation_count": obligation_count,
                "obligations": obligations,
            })
        })
        .collect()
}

pub(crate) fn build_liveness_governance_report(
    source: &str,
    filename: &str,
    fairness: FairnessMode,
    layers: &[AnalysisLayerReport],
) -> Value {
    let obligation_entries = fair_liveness_obligation_entries(layers);
    let total_obligations_checked = obligation_entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("obligation_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
        })
        .sum::<usize>();
    let obligations_note = if obligation_entries.is_empty() {
        Some(
            "No fair-liveness certification layer ran in this analysis; independent replay obligations were not checked."
                .to_string(),
        )
    } else {
        None
    };

    json!({
        "fairness_model": fairness_semantics_json(fairness),
        "gst_assumptions": gst_assumptions_json(source, filename),
        "obligations_checked": {
            "source": "fair_liveness_certificate",
            "entries": obligation_entries,
            "total_obligations_checked": total_obligations_checked,
            "note": obligations_note,
        }
    })
}
