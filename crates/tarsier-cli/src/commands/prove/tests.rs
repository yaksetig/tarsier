use std::path::PathBuf;

use tarsier_engine::pipeline::FairnessMode;

use super::*;
use crate::{AnalysisLayerReport, CliNetworkSemanticsMode};

// -- ProveAutoTarget --

#[test]
fn prove_auto_target_debug() {
    assert_eq!(format!("{:?}", ProveAutoTarget::Safety), "Safety");
    assert_eq!(
        format!("{:?}", ProveAutoTarget::FairLiveness),
        "FairLiveness"
    );
}

#[test]
fn prove_auto_target_eq() {
    assert_eq!(ProveAutoTarget::Safety, ProveAutoTarget::Safety);
    assert_ne!(ProveAutoTarget::Safety, ProveAutoTarget::FairLiveness);
}

#[test]
fn prove_auto_target_copy() {
    let t = ProveAutoTarget::FairLiveness;
    let t2 = t;
    assert_eq!(t, t2);
}

// -- ProveCommandArgs --

#[test]
fn prove_command_args_clone() {
    let args = ProveCommandArgs {
        file: PathBuf::from("test.trs"),
        solver: "z3".into(),
        k: 12,
        timeout: 60,
        soundness: "strict".into(),
        engine: "pdr".into(),
        fairness: "weak".into(),
        cert_out: None,
        cegar_iters: 0,
        cegar_report_out: None,
        portfolio: false,
        auto_strengthen: false,
        format: "text".into(),
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let cloned = args.clone();
    assert_eq!(cloned.file, PathBuf::from("test.trs"));
    assert_eq!(cloned.solver, "z3");
    assert_eq!(cloned.k, 12);
    assert!(!cloned.portfolio);
}

#[test]
fn prove_command_args_debug() {
    let args = ProveCommandArgs {
        file: PathBuf::from("t.trs"),
        solver: "z3".into(),
        k: 1,
        timeout: 1,
        soundness: "strict".into(),
        engine: "pdr".into(),
        fairness: "weak".into(),
        cert_out: None,
        cegar_iters: 0,
        cegar_report_out: None,
        portfolio: false,
        auto_strengthen: false,
        format: "text".into(),
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let debug = format!("{:?}", args);
    assert!(debug.contains("ProveCommandArgs"));
    assert!(debug.contains("t.trs"));
}

// -- ProveFairCommandArgs --

#[test]
fn prove_fair_args_clone() {
    let args = ProveFairCommandArgs {
        file: PathBuf::from("fair.trs"),
        solver: "cvc5".into(),
        k: 24,
        timeout: 120,
        soundness: "permissive".into(),
        fairness: "strong".into(),
        cert_out: Some(PathBuf::from("cert/")),
        cegar_iters: 3,
        cegar_report_out: None,
        portfolio: true,
        format: "json".into(),
        cli_network_mode: CliNetworkSemanticsMode::Faithful,
    };
    let cloned = args.clone();
    assert_eq!(cloned.fairness, "strong");
    assert!(cloned.portfolio);
    assert_eq!(
        cloned.cert_out.as_deref(),
        Some(std::path::Path::new("cert/"))
    );
}

// -- ProveRoundCommandArgs --

#[test]
fn prove_round_args_clone() {
    let args = ProveRoundCommandArgs {
        file: PathBuf::from("round.trs"),
        solver: "z3".into(),
        k: 8,
        timeout: 30,
        soundness: "strict".into(),
        engine: "kinduction".into(),
        round_vars: vec!["r".into(), "v".into()],
        format: "text".into(),
        out: None,
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let cloned = args.clone();
    assert_eq!(cloned.round_vars, vec!["r", "v"]);
}

// -- ProveFairRoundCommandArgs --

#[test]
fn prove_fair_round_args_clone() {
    let args = ProveFairRoundCommandArgs {
        file: PathBuf::from("fr.trs"),
        solver: "z3".into(),
        k: 4,
        timeout: 10,
        soundness: "strict".into(),
        fairness: "weak".into(),
        round_vars: vec![],
        format: "json".into(),
        out: Some(PathBuf::from("out.json")),
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let cloned = args.clone();
    assert!(cloned.round_vars.is_empty());
    assert!(cloned.out.is_some());
}

// -- is_safety_property_kind --

#[test]
fn safety_property_kinds() {
    use tarsier_dsl::ast::PropertyKind;
    assert!(is_safety_property_kind(PropertyKind::Agreement));
    assert!(is_safety_property_kind(PropertyKind::Validity));
    assert!(is_safety_property_kind(PropertyKind::Safety));
    assert!(is_safety_property_kind(PropertyKind::Invariant));
}

#[test]
fn liveness_is_not_safety_kind() {
    use tarsier_dsl::ast::PropertyKind;
    assert!(!is_safety_property_kind(PropertyKind::Liveness));
}

// -- fairness_name --

#[test]
fn fairness_name_weak() {
    assert_eq!(fairness_name(FairnessMode::Weak), "weak");
}

#[test]
fn fairness_name_strong() {
    assert_eq!(fairness_name(FairnessMode::Strong), "strong");
}

// -- fairness_semantics_json --

#[test]
fn fairness_semantics_json_has_fields() {
    let val = fairness_semantics_json(FairnessMode::Weak);
    assert!(val.get("mode").is_some());
    assert!(val.get("formal_name").is_some());
    assert!(val.get("definition").is_some());
    assert!(val.get("verdict_interpretation").is_some());
}

#[test]
fn fairness_semantics_json_strong_has_fields() {
    let val = fairness_semantics_json(FairnessMode::Strong);
    assert!(val.get("mode").is_some());
}

// -- fair_liveness_obligation_entries --

#[test]
fn fair_liveness_obligation_entries_empty_layers() {
    let entries = fair_liveness_obligation_entries(&[]);
    assert!(entries.is_empty());
}

#[test]
fn fair_liveness_obligation_entries_filters_non_fair() {
    let layers = vec![AnalysisLayerReport {
        layer: "verify".into(),
        status: "pass".into(),
        verdict: "SAFE".into(),
        summary: "safe".into(),
        details: serde_json::json!({}),
        output: String::new(),
    }];
    let entries = fair_liveness_obligation_entries(&layers);
    assert!(entries.is_empty());
}

#[test]
fn fair_liveness_obligation_entries_captures_matching_layers() {
    let layers = vec![AnalysisLayerReport {
        layer: "certify[fair_liveness]_0".into(),
        status: "pass".into(),
        verdict: "LIVE_PROVED".into(),
        summary: "live".into(),
        details: serde_json::json!({
            "obligations_checked": ["init", "step"],
            "obligation_count": 2,
            "integrity_ok": true,
        }),
        output: String::new(),
    }];
    let entries = fair_liveness_obligation_entries(&layers);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["obligation_count"], 2);
}

// -- parse_manifest_fairness_mode (governance only) --

#[cfg(feature = "governance")]
#[test]
fn parse_manifest_fairness_mode_weak() {
    assert_eq!(
        parse_manifest_fairness_mode("weak").unwrap(),
        FairnessMode::Weak
    );
}

#[cfg(feature = "governance")]
#[test]
fn parse_manifest_fairness_mode_strong() {
    assert_eq!(
        parse_manifest_fairness_mode("strong").unwrap(),
        FairnessMode::Strong
    );
}

#[cfg(feature = "governance")]
#[test]
fn parse_manifest_fairness_mode_invalid() {
    assert!(parse_manifest_fairness_mode("none").is_err());
}
