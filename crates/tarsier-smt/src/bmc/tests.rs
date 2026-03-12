use super::*;

#[test]
fn pdr_bad_cube_budget_scales_beyond_legacy_floor() {
    let budget = pdr_bad_cube_budget(120, 8);
    assert!(budget > 5_000);
    assert!(budget <= 200_000);
}

#[test]
fn pdr_obligation_budget_scales_with_state_and_level() {
    let base = pdr_obligation_budget(10, 1);
    let larger = pdr_obligation_budget(200, 12);
    assert!(larger > base);
    assert!(base >= 10_000);
    assert!(larger <= 300_000);
}

#[test]
fn pdr_literal_drop_order_prefers_time_and_message_zeroes() {
    let state_vars = vec![
        ("kappa_1_0".to_string(), SmtSort::Int),
        ("g_1_0".to_string(), SmtSort::Int),
        ("time_1".to_string(), SmtSort::Int),
        ("g_1_1".to_string(), SmtSort::Int),
        ("kappa_1_2".to_string(), SmtSort::Int),
    ];
    let cube = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0,
                value: 2,
            },
            CubeLiteral {
                state_var_idx: 1,
                value: 0,
            },
            CubeLiteral {
                state_var_idx: 2,
                value: 7,
            },
            CubeLiteral {
                state_var_idx: 3,
                value: 4,
            },
            CubeLiteral {
                state_var_idx: 4,
                value: 0,
            },
        ],
    };
    let order = pdr_literal_drop_order(&cube, &state_vars);
    assert_eq!(order[0], 2, "time literal should be considered first");
    assert_eq!(
        order[1], 1,
        "zero-valued message counters should be considered early"
    );
    assert!(
        order.iter().position(|idx| *idx == 3).unwrap()
            < order.iter().position(|idx| *idx == 0).unwrap(),
        "message counters should be prioritized before non-zero location counters"
    );
}

#[test]
fn dynamic_ample_disables_rules_unrelated_to_cube_constraints() {
    let rule_effects = vec![
        PdrRuleEffect {
            from_loc: 0,
            to_loc: 1,
            updated_shared_vars: vec![0],
            delta_var: pdr_delta_var(0),
        },
        PdrRuleEffect {
            from_loc: 2,
            to_loc: 2,
            updated_shared_vars: vec![1],
            delta_var: pdr_delta_var(1),
        },
        PdrRuleEffect {
            from_loc: 1,
            to_loc: 2,
            updated_shared_vars: Vec::new(),
            delta_var: pdr_delta_var(2),
        },
    ];
    let cube = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0, // location 0
                value: 1,
            },
            CubeLiteral {
                state_var_idx: 4, // shared var 1 (num_locations + 1)
                value: 2,
            },
        ],
    };

    let disabled = dynamic_ample_disabled_rules_for_cube(&cube, 3, 2, &rule_effects);
    assert_eq!(
        disabled,
        vec![2],
        "only rules unrelated to constrained locations/shared vars should be disabled"
    );
}

#[test]
fn dynamic_ample_can_disable_all_rules_for_time_only_cube() {
    let rule_effects = vec![
        PdrRuleEffect {
            from_loc: 0,
            to_loc: 1,
            updated_shared_vars: vec![0],
            delta_var: pdr_delta_var(0),
        },
        PdrRuleEffect {
            from_loc: 1,
            to_loc: 2,
            updated_shared_vars: Vec::new(),
            delta_var: pdr_delta_var(1),
        },
    ];
    let cube = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 5, // time var index (num_locations + num_shared_vars)
            value: 7,
        }],
    };

    let disabled = dynamic_ample_disabled_rules_for_cube(&cube, 3, 2, &rule_effects);
    assert_eq!(disabled, vec![0, 1]);
}

#[test]
fn pdr_frame_insert_uses_cube_subsumption() {
    let specific = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0,
                value: 1,
            },
            CubeLiteral {
                state_var_idx: 1,
                value: 2,
            },
        ],
    };
    let general = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 0,
            value: 1,
        }],
    };
    let unrelated = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 2,
            value: 0,
        }],
    };

    let mut frame = PdrFrame::default();
    frame.insert(specific.clone());
    frame.insert(general.clone());
    frame.insert(unrelated.clone());

    assert!(
        frame.contains(&general),
        "more general cube should be retained"
    );
    assert!(
        !frame.contains(&specific),
        "subsumed specific cube should be removed"
    );
    assert!(
        frame.contains(&unrelated),
        "non-subsumed cube should remain"
    );
}

#[test]
fn wildcard_process_ids_rewrites_identity_channels() {
    let input = "cnt_Vote@R#12<-L#3[view=7]";
    let rewritten = wildcard_process_ids(input);
    assert_eq!(rewritten, "cnt_Vote@R#*<-L#*[view=7]");
}

#[test]
fn cube_symmetry_signature_is_pid_agnostic_under_templates() {
    let cube_a = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0,
                value: 1,
            },
            CubeLiteral {
                state_var_idx: 1,
                value: 0,
            },
        ],
    };
    let cube_b = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 2,
                value: 1,
            },
            CubeLiteral {
                state_var_idx: 3,
                value: 0,
            },
        ],
    };
    let templates = vec![
        "msg|cnt_Vote@R#*<-L#*[value=true]".to_string(),
        "msg|cnt_Vote@R#*<-L#*[value=false]".to_string(),
        "msg|cnt_Vote@R#*<-L#*[value=true]".to_string(),
        "msg|cnt_Vote@R#*<-L#*[value=false]".to_string(),
    ];
    assert_eq!(
        cube_symmetry_signature(&cube_a, &templates),
        cube_symmetry_signature(&cube_b, &templates)
    );
}

// --- SmtRunProfile tests ---

#[test]
fn smt_run_profile_default_has_all_zeroes() {
    let profile = SmtRunProfile::default();
    assert_eq!(profile.encode_calls, 0);
    assert_eq!(profile.encode_elapsed_ms, 0);
    assert_eq!(profile.solve_calls, 0);
    assert_eq!(profile.solve_elapsed_ms, 0);
    assert_eq!(profile.assertion_candidates, 0);
    assert_eq!(profile.assertion_unique, 0);
    assert_eq!(profile.assertion_dedup_hits, 0);
    assert_eq!(profile.incremental_depth_reuse_steps, 0);
    assert_eq!(profile.incremental_decl_reuse_hits, 0);
    assert_eq!(profile.incremental_assertion_reuse_hits, 0);
    assert_eq!(profile.symmetry_candidates, 0);
    assert_eq!(profile.symmetry_pruned, 0);
    assert_eq!(profile.stutter_signature_normalizations, 0);
    assert_eq!(profile.por_pending_obligation_dedup_hits, 0);
    assert_eq!(profile.por_dynamic_ample_queries, 0);
    assert_eq!(profile.por_dynamic_ample_fast_sat, 0);
    assert_eq!(profile.por_dynamic_ample_unsat_rechecks, 0);
    assert_eq!(profile.por_dynamic_ample_unsat_recheck_sat, 0);
}

#[test]
fn smt_run_profile_fields_are_mutable_and_cloneable() {
    let profile = SmtRunProfile {
        encode_calls: 5,
        solve_calls: 10,
        symmetry_pruned: 42,
        ..SmtRunProfile::default()
    };
    let cloned = profile.clone();
    assert_eq!(cloned.encode_calls, 5);
    assert_eq!(cloned.solve_calls, 10);
    assert_eq!(cloned.symmetry_pruned, 42);
}

// --- Thread-local profiling tests ---

#[test]
fn reset_smt_run_profile_clears_thread_local() {
    // Mutate the thread-local profile directly.
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.encode_calls = 99;
        p.solve_calls = 77;
    });
    let before = current_smt_run_profile();
    assert_eq!(before.encode_calls, 99);

    reset_smt_run_profile();
    let after = current_smt_run_profile();
    assert_eq!(after.encode_calls, 0);
    assert_eq!(after.solve_calls, 0);
}

#[test]
fn take_smt_run_profile_returns_and_resets() {
    reset_smt_run_profile();
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.encode_calls = 33;
        p.solve_elapsed_ms = 1234;
    });

    let taken = take_smt_run_profile();
    assert_eq!(taken.encode_calls, 33);
    assert_eq!(taken.solve_elapsed_ms, 1234);

    // After take, the thread-local should be default (all zeroes).
    let after = current_smt_run_profile();
    assert_eq!(after.encode_calls, 0);
    assert_eq!(after.solve_elapsed_ms, 0);
}

#[test]
fn current_smt_run_profile_returns_clone_not_reference() {
    reset_smt_run_profile();
    SMT_RUN_PROFILE.with(|cell| {
        cell.borrow_mut().solve_calls = 7;
    });
    let snapshot = current_smt_run_profile();
    // Mutating the thread-local after snapshot should not affect snapshot.
    SMT_RUN_PROFILE.with(|cell| {
        cell.borrow_mut().solve_calls = 100;
    });
    assert_eq!(snapshot.solve_calls, 7);
    // Clean up
    reset_smt_run_profile();
}

// --- record_* profiling helper tests ---

#[test]
fn record_solve_profile_increments_counters() {
    reset_smt_run_profile();
    record_solve_profile(50);
    record_solve_profile(25);
    let p = current_smt_run_profile();
    assert_eq!(p.solve_calls, 2);
    assert_eq!(p.solve_elapsed_ms, 75);
    reset_smt_run_profile();
}

#[test]
fn record_incremental_reuse_no_op_for_zero_values() {
    reset_smt_run_profile();
    record_incremental_reuse(0, 0);
    let p = current_smt_run_profile();
    assert_eq!(p.incremental_depth_reuse_steps, 0);
    assert_eq!(p.incremental_decl_reuse_hits, 0);
    assert_eq!(p.incremental_assertion_reuse_hits, 0);
    reset_smt_run_profile();
}

#[test]
fn record_incremental_reuse_accumulates_nonzero_values() {
    reset_smt_run_profile();
    record_incremental_reuse(3, 7);
    record_incremental_reuse(2, 0);
    let p = current_smt_run_profile();
    assert_eq!(p.incremental_depth_reuse_steps, 2);
    assert_eq!(p.incremental_decl_reuse_hits, 5);
    assert_eq!(p.incremental_assertion_reuse_hits, 7);
    reset_smt_run_profile();
}

#[test]
fn record_symmetry_candidate_tracks_pruned_and_total() {
    reset_smt_run_profile();
    record_symmetry_candidate(false);
    record_symmetry_candidate(true);
    record_symmetry_candidate(true);
    let p = current_smt_run_profile();
    assert_eq!(p.symmetry_candidates, 3);
    assert_eq!(p.symmetry_pruned, 2);
    reset_smt_run_profile();
}

#[test]
fn record_stutter_signature_normalization_skips_zero() {
    reset_smt_run_profile();
    record_stutter_signature_normalization(0);
    let p = current_smt_run_profile();
    assert_eq!(p.stutter_signature_normalizations, 0);
    record_stutter_signature_normalization(5);
    let p = current_smt_run_profile();
    assert_eq!(p.stutter_signature_normalizations, 5);
    reset_smt_run_profile();
}

#[test]
fn record_por_counters_increment_independently() {
    reset_smt_run_profile();
    record_por_dynamic_ample_query();
    record_por_dynamic_ample_query();
    record_por_dynamic_ample_fast_sat();
    record_por_dynamic_ample_unsat_recheck();
    record_por_dynamic_ample_unsat_recheck_sat();
    record_por_pending_obligation_dedup_hit();
    record_por_pending_obligation_dedup_hit();
    record_por_pending_obligation_dedup_hit();
    let p = current_smt_run_profile();
    assert_eq!(p.por_dynamic_ample_queries, 2);
    assert_eq!(p.por_dynamic_ample_fast_sat, 1);
    assert_eq!(p.por_dynamic_ample_unsat_rechecks, 1);
    assert_eq!(p.por_dynamic_ample_unsat_recheck_sat, 1);
    assert_eq!(p.por_pending_obligation_dedup_hits, 3);
    reset_smt_run_profile();
}

// --- deadline_exceeded tests ---

#[test]
fn deadline_exceeded_returns_false_when_none() {
    assert!(!deadline_exceeded(None));
}

#[test]
fn deadline_exceeded_returns_true_for_past_instant() {
    use std::time::Duration;
    // Create an instant in the past by subtracting duration from now.
    let past = Instant::now() - Duration::from_secs(10);
    assert!(deadline_exceeded(Some(past)));
}

#[test]
fn deadline_exceeded_returns_false_for_future_instant() {
    use std::time::Duration;
    let future = Instant::now() + Duration::from_secs(300);
    assert!(!deadline_exceeded(Some(future)));
}

// --- local_value_key tests ---

#[test]
fn local_value_key_formats_all_variants() {
    assert_eq!(local_value_key(&LocalValue::Bool(true)), "b:true");
    assert_eq!(local_value_key(&LocalValue::Bool(false)), "b:false");
    assert_eq!(local_value_key(&LocalValue::Int(42)), "i:42");
    assert_eq!(local_value_key(&LocalValue::Int(-7)), "i:-7");
    assert_eq!(
        local_value_key(&LocalValue::Enum("Phase1".into())),
        "e:Phase1"
    );
}

// --- Cube tests ---

#[test]
fn cube_from_model_extracts_int_and_bool_literals() {
    use crate::solver::{Model, ModelValue};
    let mut values = HashMap::new();
    values.insert("kappa_0_0".to_string(), ModelValue::Int(3));
    values.insert("flag".to_string(), ModelValue::Bool(true));
    let model = Model { values };

    let state_vars = vec![
        ("kappa_0_0".to_string(), SmtSort::Int),
        ("flag".to_string(), SmtSort::Bool),
    ];
    let cube = Cube::from_model(&model, &state_vars).expect("should extract cube");
    assert_eq!(cube.lits.len(), 2);
    assert_eq!(cube.lits[0].state_var_idx, 0);
    assert_eq!(cube.lits[0].value, 3);
    assert_eq!(cube.lits[1].state_var_idx, 1);
    assert_eq!(cube.lits[1].value, 1); // true -> 1
}

#[test]
fn cube_from_model_returns_none_on_missing_variable() {
    use crate::solver::{Model, ModelValue};
    let mut values = HashMap::new();
    values.insert("kappa_0_0".to_string(), ModelValue::Int(3));
    // "missing_var" is not in the model
    let model = Model { values };

    let state_vars = vec![
        ("kappa_0_0".to_string(), SmtSort::Int),
        ("missing_var".to_string(), SmtSort::Int),
    ];
    assert!(Cube::from_model(&model, &state_vars).is_none());
}

#[test]
fn cube_to_conjunction_term_empty_lits_returns_true() {
    let cube = Cube { lits: vec![] };
    let state_vars: Vec<(String, SmtSort)> = vec![];
    let term = cube.to_conjunction_term(&state_vars);
    assert_eq!(term, SmtTerm::BoolLit(true));
}

#[test]
fn cube_to_conjunction_and_blocking_clause_are_negation_related() {
    let cube = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 0,
            value: 5,
        }],
    };
    let state_vars = vec![("x".to_string(), SmtSort::Int)];

    let conj = cube.to_conjunction_term(&state_vars);
    let blocking = cube.to_blocking_clause_term(&state_vars);

    // blocking should be (not conj)
    assert_eq!(blocking, SmtTerm::Not(Box::new(conj)));
}

#[test]
fn cube_to_conjunction_bool_literal_values() {
    let cube = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0,
                value: 1,
            }, // true
            CubeLiteral {
                state_var_idx: 1,
                value: 0,
            }, // false
        ],
    };
    let state_vars = vec![
        ("a".to_string(), SmtSort::Bool),
        ("b".to_string(), SmtSort::Bool),
    ];
    let conj = cube.to_conjunction_term(&state_vars);
    // For Bool, value!=0 => var, value==0 => (not var)
    let expected = SmtTerm::and(vec![SmtTerm::var("a"), SmtTerm::not(SmtTerm::var("b"))]);
    assert_eq!(conj, expected);
}

#[test]
fn cube_subsumes_reflexive() {
    let cube = Cube {
        lits: vec![
            CubeLiteral {
                state_var_idx: 0,
                value: 1,
            },
            CubeLiteral {
                state_var_idx: 1,
                value: 2,
            },
        ],
    };
    assert!(cube.subsumes(&cube));
}

#[test]
fn cube_subsumes_empty_subsumes_everything() {
    let empty = Cube { lits: vec![] };
    let nonempty = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 0,
            value: 1,
        }],
    };
    assert!(empty.subsumes(&nonempty));
    assert!(empty.subsumes(&empty));
}

#[test]
fn cube_subsumes_different_values_not_subsumed() {
    let a = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 0,
            value: 1,
        }],
    };
    let b = Cube {
        lits: vec![CubeLiteral {
            state_var_idx: 0,
            value: 2,
        }],
    };
    assert!(!a.subsumes(&b));
    assert!(!b.subsumes(&a));
}

// --- rename_state_vars_in_term tests ---

#[test]
fn rename_state_vars_substitutes_var_names() {
    let mut map = HashMap::new();
    map.insert("x_0".to_string(), "x_1".to_string());
    map.insert("y_0".to_string(), "y_1".to_string());

    let term = SmtTerm::var("x_0").add(SmtTerm::var("y_0"));
    let renamed = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::var("x_1").add(SmtTerm::var("y_1"));
    assert_eq!(renamed, expected);
}

#[test]
fn rename_state_vars_leaves_unmapped_vars_unchanged() {
    let mut map = HashMap::new();
    map.insert("x".to_string(), "x_prime".to_string());

    let term = SmtTerm::var("z").add(SmtTerm::var("x"));
    let renamed = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::var("z").add(SmtTerm::var("x_prime"));
    assert_eq!(renamed, expected);
}

#[test]
fn rename_state_vars_recursively_handles_all_term_variants() {
    let mut map = HashMap::new();
    map.insert("a".to_string(), "a_prime".to_string());

    // Test with Not, And, Or, Implies, Eq, Lt, Le, Gt, Ge, Sub, Mul, Ite
    let not_term = SmtTerm::var("a").not();
    assert_eq!(
        rename_state_vars_in_term(&not_term, &map),
        SmtTerm::var("a_prime").not()
    );

    let and_term = SmtTerm::and(vec![SmtTerm::var("a"), SmtTerm::var("b")]);
    let renamed_and = rename_state_vars_in_term(&and_term, &map);
    assert_eq!(
        renamed_and,
        SmtTerm::and(vec![SmtTerm::var("a_prime"), SmtTerm::var("b")])
    );

    let ite = SmtTerm::Ite(
        Box::new(SmtTerm::var("a")),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::int(0)),
    );
    let renamed_ite = rename_state_vars_in_term(&ite, &map);
    assert_eq!(
        renamed_ite,
        SmtTerm::Ite(
            Box::new(SmtTerm::var("a_prime")),
            Box::new(SmtTerm::int(1)),
            Box::new(SmtTerm::int(0)),
        )
    );
}

#[test]
fn rename_state_vars_preserves_literals() {
    let map = HashMap::new();
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::int(42), &map),
        SmtTerm::int(42)
    );
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::bool(true), &map),
        SmtTerm::bool(true)
    );
}

// --- wildcard_process_ids edge cases ---

#[test]
fn wildcard_process_ids_handles_no_hash() {
    assert_eq!(wildcard_process_ids("plain_name"), "plain_name");
}

#[test]
fn wildcard_process_ids_handles_hash_at_end() {
    assert_eq!(wildcard_process_ids("prefix#5"), "prefix#*");
}

#[test]
fn wildcard_process_ids_handles_multiple_hashes() {
    assert_eq!(wildcard_process_ids("A#1B#2C#30"), "A#*B#*C#*");
}

// --- Budget helper edge cases ---

#[test]
fn pdr_budgets_respect_lower_bounds() {
    assert!(pdr_bad_cube_budget(0, 0) >= 5_000);
    assert!(pdr_obligation_budget(0, 0) >= 10_000);
    assert!(pdr_single_literal_query_budget(0) >= 128);
}

#[test]
fn pdr_budgets_respect_upper_bounds() {
    assert!(pdr_bad_cube_budget(usize::MAX, usize::MAX) <= 200_000);
    assert!(pdr_obligation_budget(usize::MAX, usize::MAX) <= 300_000);
    assert!(pdr_single_literal_query_budget(usize::MAX) <= 16_384);
    assert!(pdr_pair_literal_query_budget(usize::MAX) <= 2_048);
}

#[test]
fn pdr_pair_literal_query_budget_zero_and_one_return_zero() {
    assert_eq!(pdr_pair_literal_query_budget(0), 0);
    assert_eq!(pdr_pair_literal_query_budget(1), 0);
}
