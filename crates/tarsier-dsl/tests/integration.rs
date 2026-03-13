//! Integration tests for the tarsier-dsl parser.
//!
//! These tests exercise the public `parse` API against real `.trs` example files,
//! malformed inputs, and edge cases.

use tarsier_dsl::parse;

// ---------------------------------------------------------------------------
// 1. Round-trip tests: parse every example .trs file without error
// ---------------------------------------------------------------------------

macro_rules! roundtrip_test {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let source = std::fs::read_to_string($path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", $path));
            let result = parse(&source, $path);
            assert!(
                result.is_ok(),
                "parsing {} failed: {:?}",
                $path,
                result.err()
            );
        }
    };
}

// Top-level examples
roundtrip_test!(
    roundtrip_reliable_broadcast,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/reliable_broadcast.trs"
    )
);
roundtrip_test!(
    roundtrip_reliable_broadcast_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/reliable_broadcast_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_algorand_committee,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/algorand_committee.trs"
    )
);
roundtrip_test!(
    roundtrip_pbft_simple,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/pbft_simple.trs"
    )
);
roundtrip_test!(
    roundtrip_trivial_live,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/trivial_live.trs"
    )
);
roundtrip_test!(
    roundtrip_pbft_faithful_liveness,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/pbft_faithful_liveness.trs"
    )
);
roundtrip_test!(
    roundtrip_temporal_liveness,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/temporal_liveness.trs"
    )
);
roundtrip_test!(
    roundtrip_crypto_objects,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/crypto_objects.trs"
    )
);
roundtrip_test!(
    roundtrip_crash_recovery_demo,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/crash_recovery_demo.trs"
    )
);
roundtrip_test!(
    roundtrip_leader_role_demo,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/leader_role_demo.trs"
    )
);
roundtrip_test!(
    roundtrip_bounded_log_demo,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/bounded_log_demo.trs"
    )
);
roundtrip_test!(
    roundtrip_fifo_channel_demo,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/fifo_channel_demo.trs"
    )
);

// Library examples (representative selection covering diverse protocol features)
roundtrip_test!(
    roundtrip_lib_pbft_core,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/pbft_core.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_pbft_view_change,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/pbft_view_change.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_tendermint_locking,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/tendermint_locking.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_hotstuff_chained,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/hotstuff_chained.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_streamlet,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/streamlet.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_zyzzyva_fastpath,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/zyzzyva_fastpath.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_paxos_basic,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/paxos_basic.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_raft_election_safety,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/raft_election_safety.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_grandpa_finality,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/grandpa_finality.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_multi_paxos_round,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/multi_paxos_round.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_dls_partial_sync,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/dls_partial_sync.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_casper_ffg_like,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/casper_ffg_like.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_safe.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_pbft_simple_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/pbft_simple_safe.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_voting_enum_phases,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/voting_enum_phases.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_process_selective,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_process_selective.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_cohort_selective,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_cohort_selective.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_pbft_simple_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/pbft_simple_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_hotstuff_simple_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/hotstuff_simple_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_viewstamped_replication,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/viewstamped_replication.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_zab_atomic_broadcast,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/zab_atomic_broadcast.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_pbft_crypto_qc_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/pbft_crypto_qc_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_hotstuff_crypto_qc_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/hotstuff_crypto_qc_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_tendermint_crypto_qc_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/tendermint_crypto_qc_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_safe_live,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_safe_live.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_sbft_committee,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/sbft_committee.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_algorand_vote_cert,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/algorand_vote_cert.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_narwhal_bullshark_vote,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/narwhal_bullshark_vote.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_minimmit_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/minimmit_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_phoenixx_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/phoenixx_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_rbft_qbft_safe_faithful,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/rbft_qbft_safe_faithful.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_reconfig_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_reconfig_safe.trs"
    )
);

// Experimental examples
roundtrip_test!(
    roundtrip_exp_dag_round_alpha_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/experimental/dag_round_alpha_safe.trs"
    )
);

roundtrip_test!(
    roundtrip_exp_dag_diamond_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/experimental/dag_diamond_safe.trs"
    )
);
roundtrip_test!(
    roundtrip_exp_dag_deep_chain_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/experimental/dag_deep_chain_safe.trs"
    )
);
roundtrip_test!(
    roundtrip_exp_dag_multi_root_safe,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/experimental/dag_multi_root_safe.trs"
    )
);
roundtrip_test!(
    roundtrip_exp_dag_self_loop_invalid,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/experimental/dag_self_loop_invalid.trs"
    )
);

// Buggy examples (should still parse successfully, bugs are semantic)
roundtrip_test!(
    roundtrip_lib_reliable_broadcast_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reliable_broadcast_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_viewstamped_replication_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/viewstamped_replication_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_zab_atomic_broadcast_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/zab_atomic_broadcast_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_reconfig_threshold_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/reconfig_threshold_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_clock_premature_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/clock_premature_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_fifo_weak_guard_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/fifo_weak_guard_buggy.trs"
    )
);
roundtrip_test!(
    roundtrip_lib_dag_conflicting_buggy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/library/dag_conflicting_buggy.trs"
    )
);

// Also test the glob-based approach for completeness: parse ALL .trs files
#[test]
fn roundtrip_all_trs_files() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let examples_dir = std::path::Path::new(manifest_dir).join("../../examples");
    let mut count = 0;
    let mut failures = Vec::new();

    fn visit_dir(dir: &std::path::Path, count: &mut usize, failures: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_dir(&path, count, failures);
                } else if path.extension().is_some_and(|e| e == "trs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    let display = path.display().to_string();
                    if let Err(e) = parse(&source, &display) {
                        failures.push(format!("{}: {e}", display));
                    }
                    *count += 1;
                }
            }
        }
    }

    visit_dir(&examples_dir, &mut count, &mut failures);

    assert!(count > 0, "no .trs files found under examples/");
    assert!(
        failures.is_empty(),
        "failed to parse {} / {} files:\n{}",
        failures.len(),
        count,
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// 2. Malformed input tests
// ---------------------------------------------------------------------------

#[test]
fn malformed_empty_input() {
    let result = parse("", "empty.trs");
    assert!(result.is_err(), "empty input should fail to parse");
}

#[test]
fn malformed_whitespace_only() {
    let result = parse("   \n\t\n  ", "whitespace.trs");
    assert!(result.is_err(), "whitespace-only input should fail");
}

#[test]
fn malformed_missing_closing_brace() {
    let src = r#"
protocol Broken {
    parameters {
        n: nat;
    }
    resilience { n > 0; }
    message M;
    role R {
        init s;
        phase s {
            when received >= 1 M => {
                decide true;
            }
        }
    // missing closing brace for role
}
"#;
    let result = parse(src, "missing_brace.trs");
    assert!(result.is_err(), "missing closing brace should fail");
}

#[test]
fn malformed_missing_protocol_closing_brace() {
    let src = r#"
protocol Broken {
    parameters {
        n: nat;
    }
"#;
    let result = parse(src, "missing_protocol_brace.trs");
    assert!(
        result.is_err(),
        "missing protocol closing brace should fail"
    );
}

#[test]
fn malformed_unknown_keyword_at_top_level() {
    let src = r#"
protocol Broken {
    parameters { n: nat; }
    resilience { n > 0; }
    foobar { something: wrong; }
}
"#;
    let result = parse(src, "unknown_kw.trs");
    assert!(result.is_err(), "unknown keyword should fail to parse");
}

#[test]
fn malformed_invalid_threshold_no_arrow() {
    // Threshold guard is missing the `=>` arrow after the message type
    let src = r#"
protocol Broken {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role P {
        init s;
        phase s {
            when received >= 2*t+1 Vote {
                decide true;
            }
        }
    }
}
"#;
    let result = parse(src, "invalid_threshold.trs");
    assert!(
        result.is_err(),
        "threshold guard missing => arrow should fail"
    );
}

#[test]
fn malformed_invalid_threshold_bare_operator() {
    // Threshold expression with just an operator and no operands
    let src = r#"
protocol Broken {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role P {
        init s;
        phase s {
            when received >= >= Vote => {
                decide true;
            }
        }
    }
}
"#;
    let result = parse(src, "invalid_threshold2.trs");
    assert!(result.is_err(), "doubled comparison operator should fail");
}

#[test]
fn malformed_missing_params_declaration() {
    // A protocol with resilience but no parameters should still parse at grammar
    // level -- the resilience expr references undefined names, but parsing itself
    // may or may not reject it. We just verify no panic.
    let src = r#"
protocol NoParams {
    resilience { n > 0; }
    message M;
    role R {
        init s;
        phase s {}
    }
}
"#;
    let result = parse(src, "no_params.trs");
    // Whether this is Ok or Err depends on semantic validation, but it must not panic.
    let _ = result;
}

#[test]
fn malformed_duplicate_param_name() {
    let src = r#"
protocol DupParam {
    parameters {
        n: nat;
        n: nat;
    }
    resilience { n > 0; }
    message M;
    role R { init s; phase s {} }
}
"#;
    // Must not panic. Whether it errors depends on whether duplicate checking
    // is done at parse time.
    let _ = parse(src, "dup_param.trs");
}

#[test]
fn malformed_invalid_param_type() {
    let src = r#"
protocol BadType {
    parameters {
        n: string;
    }
}
"#;
    let result = parse(src, "bad_type.trs");
    assert!(result.is_err(), "invalid param type should fail to parse");
}

#[test]
fn malformed_missing_semicolon_in_params() {
    let src = r#"
protocol MissingSemicolon {
    parameters {
        n: nat
        t: nat;
    }
}
"#;
    let result = parse(src, "missing_semi.trs");
    assert!(result.is_err(), "missing semicolon should fail to parse");
}

#[test]
fn malformed_unclosed_phase() {
    let src = r#"
protocol UnclosedPhase {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message M;
    role R {
        init s;
        phase s {
            when received >= 1 M => {
                decide true;
            }
        // missing closing brace for phase
    }
}
"#;
    let result = parse(src, "unclosed_phase.trs");
    assert!(result.is_err(), "unclosed phase should fail to parse");
}

#[test]
fn malformed_no_protocol_keyword() {
    let src = r#"
something NotAProtocol {
    parameters { n: nat; }
}
"#;
    let result = parse(src, "no_protocol.trs");
    assert!(result.is_err(), "missing 'protocol' keyword should fail");
}

#[test]
fn malformed_junk_after_protocol() {
    let src = r#"
protocol Valid {
    parameters { n: nat; }
    resilience { n > 0; }
    message M;
    role R { init s; phase s {} }
}
extra stuff here
"#;
    let result = parse(src, "junk_after.trs");
    assert!(
        result.is_err(),
        "junk after protocol closing brace should fail"
    );
}

// ---------------------------------------------------------------------------
// 3. Edge case tests
// ---------------------------------------------------------------------------

#[test]
fn edge_case_protocol_with_no_roles() {
    let src = r#"
protocol NoRoles {
    parameters { n: nat; }
    resilience { n > 0; }
    message M;
}
"#;
    let result = parse(src, "no_roles.trs");
    // Should parse successfully -- having no roles is syntactically valid.
    assert!(
        result.is_ok(),
        "protocol with no roles should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert!(prog.protocol.node.roles.is_empty());
}

#[test]
fn edge_case_protocol_with_empty_phase() {
    let src = r#"
protocol EmptyPhase {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message M;
    role R {
        init waiting;
        phase waiting {}
    }
}
"#;
    let result = parse(src, "empty_phase.trs");
    assert!(
        result.is_ok(),
        "empty phase should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    let role = &prog.protocol.node.roles[0].node;
    assert_eq!(role.phases[0].node.transitions.len(), 0);
}

#[test]
fn edge_case_very_long_identifier() {
    let long_name = "A".repeat(500);
    let src = format!(
        r#"
protocol {long_name} {{
    parameters {{ n: nat; }}
    resilience {{ n > 0; }}
    message M;
    role {long_name}Role {{
        init s;
        phase s {{}}
    }}
}}
"#
    );
    let result = parse(&src, "long_ident.trs");
    assert!(
        result.is_ok(),
        "very long identifiers should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.name, long_name);
}

#[test]
fn edge_case_unicode_in_line_comment() {
    let src = r#"
// This is a comment with unicode: e, pi, sigma, delta
protocol Unicode {
    parameters { n: nat; } // more unicode: alpha, beta
    resilience { n > 0; }
    message M;
    role R {
        init s;
        phase s {}
    }
}
"#;
    let result = parse(src, "unicode_comment.trs");
    assert!(
        result.is_ok(),
        "unicode in comments should parse: {:?}",
        result.err()
    );
}

#[test]
fn edge_case_unicode_in_block_comment() {
    let src = r#"
/* Block comment with unicode: some chars here */
protocol UnicodeBlock {
    parameters { n: nat; }
    resilience { n > 0; }
    message M;
    role R {
        init s;
        phase s {}
    }
}
"#;
    let result = parse(src, "unicode_block_comment.trs");
    assert!(
        result.is_ok(),
        "unicode in block comments should parse: {:?}",
        result.err()
    );
}

#[test]
fn edge_case_multiple_roles() {
    let src = r#"
protocol MultiRole {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    message Prepare;
    role Leader {
        init start;
        phase start {
            when received >= 1 Vote => {
                send Prepare;
                goto phase done;
            }
        }
        phase done {}
    }
    role Replica {
        init waiting;
        phase waiting {
            when received >= 2*t+1 Prepare => {
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Leader. forall q: Replica. p.phase == q.phase
    }
}
"#;
    let result = parse(src, "multi_role.trs");
    assert!(
        result.is_ok(),
        "multi-role protocol should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.roles.len(), 2);
    assert_eq!(prog.protocol.node.roles[0].node.name, "Leader");
    assert_eq!(prog.protocol.node.roles[1].node.name, "Replica");
}

#[test]
fn edge_case_multiple_properties() {
    let src = r#"
protocol MultiProp {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role R {
        var decided: bool = false;
        var decision: bool = false;
        init s;
        phase s {
            when received >= 2*t+1 Vote => {
                decided = true;
                decision = true;
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agr: agreement {
        forall p: R. forall q: R.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
    property val: validity {
        forall p: R. p.decided == true ==> p.decision == true
    }
}
"#;
    let result = parse(src, "multi_prop.trs");
    assert!(
        result.is_ok(),
        "multiple properties should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.properties.len(), 2);
}

#[test]
fn edge_case_params_shorthand_syntax() {
    // The grammar supports both `parameters { ... }` and `params n, t;`
    let src = r#"
protocol Shorthand {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
    let result = parse(src, "shorthand.trs");
    assert!(
        result.is_ok(),
        "params shorthand should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.parameters.len(), 2);
}

#[test]
fn edge_case_resilience_colon_syntax() {
    // Resilience can use either `resilience { expr; }` or `resilience: expr;`
    let src = r#"
protocol ResColon {
    parameters { n: nat; t: nat; }
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
    let result = parse(src, "res_colon.trs");
    assert!(
        result.is_ok(),
        "resilience colon syntax should parse: {:?}",
        result.err()
    );
}

#[test]
fn edge_case_many_phases() {
    let src = r#"
protocol ManyPhases {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message M;
    role R {
        init phase0;
        phase phase0 {
            when received >= 1 M => { goto phase phase1; }
        }
        phase phase1 {
            when received >= 1 M => { goto phase phase2; }
        }
        phase phase2 {
            when received >= 1 M => { goto phase phase3; }
        }
        phase phase3 {
            when received >= 1 M => { goto phase phase4; }
        }
        phase phase4 {}
    }
}
"#;
    let result = parse(src, "many_phases.trs");
    assert!(
        result.is_ok(),
        "many phases should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.roles[0].node.phases.len(), 5);
}

#[test]
fn edge_case_underscore_identifiers() {
    let src = r#"
protocol _under_score {
    parameters { _n: nat; _t: nat; }
    resilience { _n > 3*_t; }
    message _Msg;
    role _Role {
        var _v: bool = false;
        init _start;
        phase _start {}
    }
}
"#;
    let result = parse(src, "underscores.trs");
    assert!(
        result.is_ok(),
        "underscore identifiers should parse: {:?}",
        result.err()
    );
}

#[test]
fn edge_case_enum_declaration() {
    let src = r#"
protocol WithEnum {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    enum Phase { Propose, Prevote, Precommit }
    message M;
    role R {
        var p: Phase = Propose;
        init s;
        phase s {}
    }
}
"#;
    let result = parse(src, "enum_decl.trs");
    assert!(
        result.is_ok(),
        "enum declaration should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.enums.len(), 1);
    assert_eq!(prog.protocol.node.enums[0].variants.len(), 3);
}

#[test]
fn edge_case_adversary_block() {
    let src = r#"
protocol WithAdversary {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary {
        model: byzantine;
        bound: f;
    }
    message M;
    role R { init s; phase s {} }
}
"#;
    let result = parse(src, "adversary.trs");
    assert!(
        result.is_ok(),
        "adversary block should parse: {:?}",
        result.err()
    );
    let prog = result.unwrap();
    assert_eq!(prog.protocol.node.adversary.len(), 2);
}

#[test]
fn edge_case_complex_threshold_expression() {
    let src = r#"
protocol ComplexThreshold {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    message Vote;
    role R {
        init s;
        phase s {
            when received >= n - t Vote => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
    let result = parse(src, "complex_threshold.trs");
    assert!(
        result.is_ok(),
        "complex threshold expression should parse: {:?}",
        result.err()
    );
}
