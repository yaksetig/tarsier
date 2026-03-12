use super::*;
use tarsier_ir::counter_system::{
    Configuration, MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind, MessageIdentity,
    MessagePayloadVariant, SignatureProvenance, Trace, TraceStep,
};
use tarsier_ir::threshold_automaton::RuleId;

// -----------------------------------------------------------------------
// RoundSweepPoint struct
// -----------------------------------------------------------------------

#[test]
fn round_sweep_point_serialization() {
    let point = RoundSweepPoint {
        upper_bound: 5,
        result: "safe".into(),
        details: json!({"depth_checked": 10}),
    };
    let json = serde_json::to_value(&point).unwrap();
    assert_eq!(json["upper_bound"], 5);
    assert_eq!(json["result"], "safe");
}

// -----------------------------------------------------------------------
// RoundSweepReport struct
// -----------------------------------------------------------------------

#[test]
fn round_sweep_report_serialization() {
    let report = RoundSweepReport {
        schema_version: 1,
        file: "test.trs".into(),
        vars: vec!["round".into()],
        min_bound: 1,
        max_bound: 10,
        stable_window: 3,
        points: vec![],
        candidate_cutoff: None,
        stabilized_result: None,
        note: "test note".into(),
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["file"], "test.trs");
    assert_eq!(json["note"], "test note");
}

// -----------------------------------------------------------------------
// trace_details
// -----------------------------------------------------------------------

#[test]
fn trace_details_empty_trace() {
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![],
            gamma: vec![],
            params: vec![],
        },
        steps: vec![],
        param_values: vec![],
    };
    let details = trace_details(&trace);
    assert_eq!(details["steps"], 0);
    assert_eq!(details["deliveries"], 0);
}

#[test]
fn trace_details_counts_deliveries() {
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![],
            gamma: vec![],
            params: vec![],
        },
        steps: vec![TraceStep {
            smt_step: 0,
            rule_id: RuleId::new(0),
            delta: 1,
            config: Configuration {
                kappa: vec![],
                gamma: vec![],
                params: vec![],
            },
            deliveries: vec![
                MessageDeliveryEvent {
                    kind: MessageEventKind::Deliver,
                    count: 3,
                    shared_var: 0,
                    shared_var_name: "cnt".into(),
                    sender: MessageIdentity {
                        role: "A".into(),
                        process: None,
                        key: None,
                    },
                    recipient: MessageIdentity {
                        role: "B".into(),
                        process: None,
                        key: None,
                    },
                    payload: MessagePayloadVariant {
                        family: "Vote".into(),
                        fields: vec![],
                        variant: "default".into(),
                    },
                    auth: MessageAuthMetadata {
                        authenticated_channel: false,
                        signature_key: None,
                        key_owner_role: None,
                        key_compromised: false,
                        provenance: SignatureProvenance::OwnedKey,
                    },
                },
                MessageDeliveryEvent {
                    kind: MessageEventKind::Send,
                    count: 2,
                    shared_var: 1,
                    shared_var_name: "cnt2".into(),
                    sender: MessageIdentity {
                        role: "A".into(),
                        process: None,
                        key: None,
                    },
                    recipient: MessageIdentity {
                        role: "B".into(),
                        process: None,
                        key: None,
                    },
                    payload: MessagePayloadVariant {
                        family: "Propose".into(),
                        fields: vec![],
                        variant: "default".into(),
                    },
                    auth: MessageAuthMetadata {
                        authenticated_channel: false,
                        signature_key: None,
                        key_owner_role: None,
                        key_compromised: false,
                        provenance: SignatureProvenance::OwnedKey,
                    },
                },
            ],
            por_status: None,
        }],
        param_values: vec![("n".into(), 4), ("t".into(), 1)],
    };
    let details = trace_details(&trace);
    assert_eq!(details["steps"], 1);
    // Only Deliver kind is counted
    assert_eq!(details["deliveries"], 3);
}

// -----------------------------------------------------------------------
// verification_result_kind
// -----------------------------------------------------------------------

#[test]
fn verification_result_kind_safe() {
    let r = VerificationResult::Safe { depth_checked: 5 };
    assert_eq!(verification_result_kind(&r), "safe");
}

#[test]
fn verification_result_kind_unsafe() {
    let r = VerificationResult::Unsafe {
        trace: Trace {
            initial_config: Configuration {
                kappa: vec![],
                gamma: vec![],
                params: vec![],
            },
            steps: vec![],
            param_values: vec![],
        },
    };
    assert_eq!(verification_result_kind(&r), "unsafe");
}

#[test]
fn verification_result_kind_unknown() {
    let r = VerificationResult::Unknown {
        reason: "timeout".into(),
    };
    assert_eq!(verification_result_kind(&r), "unknown");
}

#[test]
fn verification_result_kind_probabilistically_safe() {
    let r = VerificationResult::ProbabilisticallySafe {
        depth_checked: 5,
        failure_probability: 1e-9,
        committee_analyses: vec![],
    };
    assert_eq!(verification_result_kind(&r), "probabilistically_safe");
}

// -----------------------------------------------------------------------
// unbounded_safety_result_kind
// -----------------------------------------------------------------------

#[test]
fn unbounded_safety_result_kind_all() {
    assert_eq!(
        unbounded_safety_result_kind(&UnboundedSafetyResult::Safe { induction_k: 3 }),
        "safe"
    );
    assert_eq!(
        unbounded_safety_result_kind(&UnboundedSafetyResult::Unknown { reason: "x".into() }),
        "unknown"
    );
    assert_eq!(
        unbounded_safety_result_kind(&UnboundedSafetyResult::NotProved {
            max_k: 5,
            cti: None
        }),
        "not_proved"
    );
}

// -----------------------------------------------------------------------
// liveness_result_kind / fair_liveness_result_kind
// -----------------------------------------------------------------------

#[test]
fn liveness_result_kind_variants() {
    assert_eq!(
        liveness_result_kind(&LivenessResult::Live { depth_checked: 3 }),
        "live"
    );
    assert_eq!(
        liveness_result_kind(&LivenessResult::Unknown { reason: "x".into() }),
        "unknown"
    );
}

#[test]
fn fair_liveness_result_kind_variants() {
    assert_eq!(
        fair_liveness_result_kind(&FairLivenessResult::NoFairCycleUpTo { depth_checked: 3 }),
        "no_fair_cycle_up_to"
    );
    assert_eq!(
        fair_liveness_result_kind(&FairLivenessResult::Unknown { reason: "x".into() }),
        "unknown"
    );
}

// -----------------------------------------------------------------------
// round_name_matches
// -----------------------------------------------------------------------

#[test]
fn round_name_matches_basic() {
    let names = vec!["round".to_string(), "view".to_string()];
    assert!(round_name_matches(&names, "round"));
    assert!(round_name_matches(&names, "Round")); // case-insensitive
    assert!(round_name_matches(&names, "VIEW"));
    assert!(!round_name_matches(&names, "epoch"));
}

#[test]
fn round_name_matches_empty_name_ignored() {
    let names = vec!["  ".to_string(), "round".to_string()];
    assert!(!round_name_matches(&names, ""));
    assert!(round_name_matches(&names, "round"));
}

#[test]
fn round_name_matches_empty_list() {
    let names: Vec<String> = vec![];
    assert!(!round_name_matches(&names, "anything"));
}

// -----------------------------------------------------------------------
// detect_round_sweep_cutoff
// -----------------------------------------------------------------------

#[test]
fn cutoff_empty_points() {
    assert!(detect_round_sweep_cutoff(&[], 3).is_none());
}

#[test]
fn cutoff_zero_window() {
    let points = vec![RoundSweepPoint {
        upper_bound: 1,
        result: "safe".into(),
        details: json!({}),
    }];
    assert!(detect_round_sweep_cutoff(&points, 0).is_none());
}

#[test]
fn cutoff_stable_suffix() {
    let points = vec![
        RoundSweepPoint {
            upper_bound: 1,
            result: "unsafe".into(),
            details: json!({}),
        },
        RoundSweepPoint {
            upper_bound: 2,
            result: "safe".into(),
            details: json!({}),
        },
        RoundSweepPoint {
            upper_bound: 3,
            result: "safe".into(),
            details: json!({}),
        },
        RoundSweepPoint {
            upper_bound: 4,
            result: "safe".into(),
            details: json!({}),
        },
    ];
    let result = detect_round_sweep_cutoff(&points, 3);
    assert!(result.is_some());
    let (cutoff, kind) = result.unwrap();
    assert_eq!(cutoff, 2);
    assert_eq!(kind, "safe");
}

#[test]
fn cutoff_insufficient_window() {
    let points = vec![
        RoundSweepPoint {
            upper_bound: 1,
            result: "unsafe".into(),
            details: json!({}),
        },
        RoundSweepPoint {
            upper_bound: 2,
            result: "safe".into(),
            details: json!({}),
        },
    ];
    assert!(detect_round_sweep_cutoff(&points, 3).is_none());
}

// -----------------------------------------------------------------------
// render_round_sweep_text
// -----------------------------------------------------------------------

#[test]
fn render_round_sweep_text_basic() {
    let report = RoundSweepReport {
        schema_version: 1,
        file: "test.trs".into(),
        vars: vec!["round".into()],
        min_bound: 1,
        max_bound: 5,
        stable_window: 3,
        points: vec![RoundSweepPoint {
            upper_bound: 1,
            result: "safe".into(),
            details: json!({}),
        }],
        candidate_cutoff: Some(2),
        stabilized_result: Some("safe".into()),
        note: "test".into(),
    };
    let text = render_round_sweep_text(&report);
    assert!(text.contains("ROUND SWEEP"));
    assert!(text.contains("round"));
    assert!(text.contains("Candidate cutoff: 2"));
}

#[test]
fn render_round_sweep_text_no_cutoff() {
    let report = RoundSweepReport {
        schema_version: 1,
        file: "test.trs".into(),
        vars: vec!["round".into()],
        min_bound: 1,
        max_bound: 5,
        stable_window: 3,
        points: vec![],
        candidate_cutoff: None,
        stabilized_result: None,
        note: "incomplete".into(),
    };
    let text = render_round_sweep_text(&report);
    assert!(text.contains("not detected"));
}

// -----------------------------------------------------------------------
// strip_cegar_volatile_fields
// -----------------------------------------------------------------------

#[test]
fn strip_cegar_volatile_removes_elapsed_ms() {
    let mut val = json!({
        "result": "safe",
        "elapsed_ms": 123,
        "inner": {
            "name": "test",
            "elapsed_ms": 456,
        }
    });
    strip_cegar_volatile_fields(&mut val);
    assert!(val.get("elapsed_ms").is_none());
    assert!(val["inner"].get("elapsed_ms").is_none());
    assert_eq!(val["inner"]["name"], "test");
}

#[test]
fn strip_cegar_volatile_array() {
    let mut val = json!([
        {"elapsed_ms": 1, "x": 2},
        {"elapsed_ms": 3, "y": 4},
    ]);
    strip_cegar_volatile_fields(&mut val);
    assert!(val[0].get("elapsed_ms").is_none());
    assert_eq!(val[0]["x"], 2);
}

// -----------------------------------------------------------------------
// cegar_diff_friendly_projection
// -----------------------------------------------------------------------

#[test]
fn cegar_diff_friendly_removes_timing() {
    let val = json!({
        "result": "safe",
        "elapsed_ms": 999
    });
    let projected = cegar_diff_friendly_projection(&val);
    assert!(projected.get("elapsed_ms").is_none());
    assert_eq!(projected["result"], "safe");
}

// -----------------------------------------------------------------------
// VerifyCommandArgs struct
// -----------------------------------------------------------------------

#[test]
fn verify_command_args_debug() {
    let args = VerifyCommandArgs {
        file: PathBuf::from("test.trs"),
        solver: "z3".into(),
        depth: 10,
        timeout: 60,
        soundness: "strict".into(),
        dump_smt: None,
        cegar_iters: 0,
        cegar_report_out: None,
        portfolio: false,
        format: "text".into(),
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let dbg = format!("{:?}", args);
    assert!(dbg.contains("test.trs"));
}

// -----------------------------------------------------------------------
// LivenessCommandArgs struct
// -----------------------------------------------------------------------

#[test]
fn liveness_command_args_debug() {
    let args = LivenessCommandArgs {
        file: PathBuf::from("test.trs"),
        solver: "z3".into(),
        depth: 5,
        timeout: 30,
        soundness: "strict".into(),
        dump_smt: None,
        format: "json".into(),
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
    };
    let dbg = format!("{:?}", args);
    assert!(dbg.contains("test.trs"));
}

// -----------------------------------------------------------------------
// trace_json
// -----------------------------------------------------------------------

#[test]
fn trace_json_empty_trace() {
    let trace = Trace {
        initial_config: Configuration {
            kappa: vec![1, 2],
            gamma: vec![0, 0],
            params: vec![],
        },
        steps: vec![],
        param_values: vec![("n".into(), 4), ("t".into(), 1)],
    };
    let j = trace_json(&trace);
    assert_eq!(j["params"], json!([["n", 4], ["t", 1]]));
    assert_eq!(j["initial"]["kappa"], json!([1, 2]));
    assert!(j["steps"].as_array().unwrap().is_empty());
}

// -----------------------------------------------------------------------
// verification_result_details
// -----------------------------------------------------------------------

#[test]
fn verification_result_details_safe() {
    let r = VerificationResult::Safe { depth_checked: 7 };
    let d = verification_result_details(&r);
    assert_eq!(d["depth_checked"], 7);
}

#[test]
fn verification_result_details_unknown() {
    let r = VerificationResult::Unknown {
        reason: "timeout".into(),
    };
    let d = verification_result_details(&r);
    assert_eq!(d["reason"], "timeout");
}

// -----------------------------------------------------------------------
// liveness_unknown_reason_payload
// -----------------------------------------------------------------------

#[test]
fn liveness_unknown_reason_payload_basic() {
    let p = liveness_unknown_reason_payload("solver timeout");
    assert_eq!(p["reason"], "solver timeout");
    assert!(p.get("reason_code").is_some());
}
