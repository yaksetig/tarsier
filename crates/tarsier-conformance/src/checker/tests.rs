use super::*;
use tarsier_ir::runtime_trace::*;
use tarsier_ir::threshold_automaton::*;

/// Build a minimal test automaton:
/// L0 (Init) --[guard: cnt_Vote >= t+1]--> L1 (Decided)
/// L0 (Init) --[trivial]--> L2 (Abort)
fn make_test_automaton() -> ThresholdAutomaton {
    let mut ta = ThresholdAutomaton::new();
    let _n = ta.add_parameter(Parameter {
        name: "n".into(),
        time_varying: false,
    });
    let t = ta.add_parameter(Parameter {
        name: "t".into(),
        time_varying: false,
    });

    // L0: Init
    ta.add_location(Location {
        name: "Process_Init".into(),
        role: "Process".into(),
        phase: "Init".into(),
        local_vars: Default::default(),
    });
    // L1: Decided
    let mut decided_vars = indexmap::IndexMap::new();
    decided_vars.insert("decided".into(), LocalValue::Bool(true));
    ta.add_location(Location {
        name: "Process_Decided".into(),
        role: "Process".into(),
        phase: "Decided".into(),
        local_vars: decided_vars,
    });
    // L2: Abort
    ta.add_location(Location {
        name: "Process_Abort".into(),
        role: "Process".into(),
        phase: "Abort".into(),
        local_vars: Default::default(),
    });

    ta.initial_locations = vec![LocationId::from(0)];

    // Shared var: cnt_Vote
    ta.add_shared_var(SharedVar {
        name: "cnt_Vote".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: false,
        distinct_role: None,
    });

    // Rule 0: L0 -> L1, guard: cnt_Vote >= t+1
    ta.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 1,
                terms: vec![(1, t)],
            },
            distinct: false,
        }),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    // Rule 1: L0 -> L2, trivial guard
    ta.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(2),
        guard: Guard::trivial(),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    ta
}

fn make_params() -> Vec<(String, i64)> {
    vec![("n".into(), 4), ("t".into(), 1)]
}

#[test]
fn test_valid_trace_passes() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                // Receive enough votes to satisfy guard (t+1 = 2)
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 2,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 2,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 3,
                    kind: ProcessEventKind::Transition {
                        from_location: "Process_Init".into(),
                        to_location: "Process_Decided".into(),
                        rule_id: None,
                    },
                },
                ProcessEvent {
                    sequence: 4,
                    kind: ProcessEventKind::Decide {
                        value: "commit".into(),
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(result.passed, "violations: {:?}", result.violations);
    assert!(result.violations.is_empty());
}

#[test]
fn test_invalid_initial_location() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![ProcessEvent {
                sequence: 0,
                kind: ProcessEventKind::Init {
                    location: "Process_Decided".into(),
                },
            }],
        }],
    };

    let result = checker.check(&trace);
    assert!(!result.passed);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(
        result.violations[0].kind,
        ViolationKind::InvalidInitialLocation
    );
}

#[test]
fn test_no_matching_rule() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    // Try to transition from L1 -> L0 (no rule exists)
    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Transition {
                        from_location: "Process_Decided".into(),
                        to_location: "Process_Init".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(!result.passed);
    assert_eq!(result.violations[0].kind, ViolationKind::NoMatchingRule);
}

#[test]
fn test_guard_not_satisfied() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    // Try to transition L0 -> L1 without receiving enough votes
    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                // Only 1 vote, but need t+1 = 2
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 2,
                    kind: ProcessEventKind::Transition {
                        from_location: "Process_Init".into(),
                        to_location: "Process_Decided".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(!result.passed);
    assert_eq!(result.violations[0].kind, ViolationKind::GuardNotSatisfied);
}

#[test]
fn test_unknown_location() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![ProcessEvent {
                sequence: 0,
                kind: ProcessEventKind::Init {
                    location: "Nonexistent_Location".into(),
                },
            }],
        }],
    };

    let result = checker.check(&trace);
    assert!(!result.passed);
    assert_eq!(result.violations[0].kind, ViolationKind::UnknownLocation);
}

#[test]
fn strict_mode_rejects_unknown_message_type_mapping() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new_with_mode(&ta, &make_params(), ConformanceMode::Strict);

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "mystery_message".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        !result.passed,
        "strict mode should reject unknown message types"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::UnknownMessageType),
        "expected UnknownMessageType violation, got: {:?}",
        result.violations
    );
}

#[test]
fn permissive_mode_allows_unknown_message_type_mapping() {
    let ta = make_test_automaton();
    let checker =
        ConformanceChecker::new_with_mode(&ta, &make_params(), ConformanceMode::Permissive);

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "mystery_message".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::UnknownMessageType),
        "permissive mode should not report UnknownMessageType"
    );
}

#[test]
fn strict_mode_rejects_invalid_decide_context() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new_with_mode(&ta, &make_params(), ConformanceMode::Strict);

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Decide {
                        value: "commit".into(),
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        !result.passed,
        "strict mode should reject invalid decide context"
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::InvalidDecideContext),
        "expected InvalidDecideContext violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_deterministic_output() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Transition {
                        from_location: "Process_Init".into(),
                        to_location: "Process_Decided".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result1 = checker.check(&trace);
    let result2 = checker.check(&trace);

    let json1 = serde_json::to_string(&result1).unwrap();
    let json2 = serde_json::to_string(&result2).unwrap();
    assert_eq!(json1, json2, "deterministic output");
}

#[test]
fn permissive_mode_allows_decide_outside_decided_location() {
    let ta = make_test_automaton();
    let checker =
        ConformanceChecker::new_with_mode(&ta, &make_params(), ConformanceMode::Permissive);

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Decide {
                        value: "commit".into(),
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.kind == ViolationKind::InvalidDecideContext),
        "permissive mode should allow decide outside decided location"
    );
}

#[test]
fn process_with_no_events_passes() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        result.passed,
        "empty event list should pass: {:?}",
        result.violations
    );
}

#[test]
fn var_update_events_are_accepted_silently() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::VarUpdate {
                        var_name: "cnt_Vote".into(),
                        new_value: "5".into(),
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        result.passed,
        "VarUpdate should be accepted silently: {:?}",
        result.violations
    );
}

#[test]
fn distinct_sender_guard_counts_unique_senders() {
    let mut ta = ThresholdAutomaton::new();
    let t = ta.add_parameter(Parameter {
        name: "t".into(),
        time_varying: false,
    });

    ta.add_location(Location {
        name: "P_Init".into(),
        role: "P".into(),
        phase: "Init".into(),
        local_vars: Default::default(),
    });
    ta.add_location(Location {
        name: "P_Done".into(),
        role: "P".into(),
        phase: "Done".into(),
        local_vars: Default::default(),
    });
    ta.initial_locations = vec![LocationId::from(0)];

    ta.add_shared_var(SharedVar {
        name: "cnt_Vote".into(),
        kind: SharedVarKind::MessageCounter,
        distinct: true,
        distinct_role: None,
    });

    // Rule: P_Init -> P_Done, guard: distinct(cnt_Vote) >= t+1
    ta.add_rule(Rule {
        from: LocationId::from(0),
        to: LocationId::from(1),
        guard: Guard::single(GuardAtom::Threshold {
            vars: vec![SharedVarId::from(0)],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 1,
                terms: vec![(1, t)],
            },
            distinct: true,
        }),
        updates: vec![],
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    });

    let params = vec![("t".into(), 2)];
    let checker = ConformanceChecker::new(&ta, &params);

    // 3 messages from only 2 distinct senders: should satisfy >= t+1 = 3? No, 2 < 3.
    let trace_fail = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: params.clone(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "P".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "P_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 2,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 3,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 2,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 4,
                    kind: ProcessEventKind::Transition {
                        from_location: "P_Init".into(),
                        to_location: "P_Done".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace_fail);
    assert!(!result.passed, "distinct count is 2, need 3 — should fail");

    // 3 messages from 3 distinct senders: should satisfy >= t+1 = 3
    let trace_pass = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: params.clone(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "P".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "P_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 1,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 2,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 2,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 3,
                    kind: ProcessEventKind::Receive {
                        message_type: "cnt_Vote".into(),
                        from_process: 3,
                        fields: vec![],
                    },
                },
                ProcessEvent {
                    sequence: 4,
                    kind: ProcessEventKind::Transition {
                        from_location: "P_Init".into(),
                        to_location: "P_Done".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace_pass);
    assert!(
        result.passed,
        "distinct count is 3 >= 3, should pass: {:?}",
        result.violations
    );
}

#[test]
fn checker_options_strict_and_permissive_presets() {
    let strict = CheckerOptions::strict();
    assert!(strict.reject_unknown_message_type);
    assert!(strict.reject_invalid_decide_context);

    let permissive = CheckerOptions::permissive();
    assert!(!permissive.reject_unknown_message_type);
    assert!(!permissive.reject_invalid_decide_context);
}

#[test]
fn multiple_processes_checked_independently() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![
            // Process 0: valid
            ProcessTrace {
                process_id: 0,
                role: "Process".into(),
                events: vec![ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                }],
            },
            // Process 1: invalid (bad initial location)
            ProcessTrace {
                process_id: 1,
                role: "Process".into(),
                events: vec![ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Decided".into(),
                    },
                }],
            },
        ],
    };

    let result = checker.check(&trace);
    assert!(!result.passed);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].process_id, 1);
}

#[test]
fn trivial_guard_allows_transition_without_messages() {
    let ta = make_test_automaton();
    let checker = ConformanceChecker::new(&ta, &make_params());

    // Transition from L0 to L2 (Abort) using rule 1 (trivial guard)
    let trace = RuntimeTrace {
        schema_version: 1,
        protocol_name: "Test".into(),
        params: make_params(),
        processes: vec![ProcessTrace {
            process_id: 0,
            role: "Process".into(),
            events: vec![
                ProcessEvent {
                    sequence: 0,
                    kind: ProcessEventKind::Init {
                        location: "Process_Init".into(),
                    },
                },
                ProcessEvent {
                    sequence: 1,
                    kind: ProcessEventKind::Transition {
                        from_location: "Process_Init".into(),
                        to_location: "Process_Abort".into(),
                        rule_id: None,
                    },
                },
            ],
        }],
    };

    let result = checker.check(&trace);
    assert!(
        result.passed,
        "trivial guard should allow transition without messages: {:?}",
        result.violations
    );
}
