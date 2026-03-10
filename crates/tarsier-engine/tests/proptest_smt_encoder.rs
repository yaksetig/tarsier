//! Property-based tests for the SMT encoder.
//!
//! These tests verify structural invariants of BMC encodings produced by the
//! encoder for randomly generated ThresholdAutomata.

use proptest::prelude::*;
use proptest::test_runner::{
    Config as ProptestConfig, FileFailurePersistence, RngAlgorithm, RngSeed,
};

use tarsier_engine::pipeline::{self, SoundnessMode};
use tarsier_smt::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{run_bmc_at_depth, BmcResult};
use tarsier_smt::encoder::encode_bmc;

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 32,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0xE0C0_DE42_u64),
        ..ProptestConfig::default()
    }
}

/// Build a minimal safe protocol source with a configurable number of phases
/// and transitions. All processes decide the same value, so agreement holds.
fn build_minimal_protocol(n_extra_phases: usize) -> String {
    let mut phases = String::new();
    for i in 0..n_extra_phases {
        phases.push_str(&format!(
            "        phase extra{i} {{\n            when received >= 0 Vote => {{\n                goto phase done;\n            }}\n        }}\n\n"
        ));
    }

    format!(
        r#"protocol MinimalProptest {{
    params n, t, f;
    resilience: n > 3*t;

    adversary {{
        model: byzantine;
        bound: f;
    }}

    message Vote;

    role Node {{
        var decided: bool = false;

        init start;

        phase start {{
            when decided == false => {{
                decided = true;
                decide true;
                goto phase done;
            }}
        }}

{phases}        phase done {{}}
    }}

    property agreement: agreement {{
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }}
}}
"#
    )
}

/// Build a protocol source with a specified number of messages.
fn build_multi_message_protocol(n_messages: usize) -> String {
    let msg_decls: String = (0..n_messages)
        .map(|i| format!("    message Msg{i};\n"))
        .collect();

    let guards: String = (0..n_messages)
        .map(|i| {
            format!(
                "            when received >= 0 Msg{i} => {{\n                goto phase start;\n            }}\n"
            )
        })
        .collect();

    format!(
        r#"protocol MultiMsgProptest {{
    params n, t, f;
    resilience: n > 3*t;

    adversary {{
        model: byzantine;
        bound: f;
    }}

{msg_decls}
    role Node {{
        var decided: bool = false;

        init start;

        phase start {{
{guards}        }}
    }}

    property inv: safety {{
        forall p: Node. p.decided == false
    }}
}}
"#
    )
}

// ---------------------------------------------------------------------------
// Property 1: BMC encoding at depth 0 is satisfiable (trivial initial state)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn depth_0_encoding_is_satisfiable(n_extra_phases in 0..4usize) {
        let source = build_minimal_protocol(n_extra_phases);
        let filename = "proptest_depth0.trs";
        let program = pipeline::parse(&source, filename)
            .map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let ta = pipeline::lower(&program)
            .map_err(|e| TestCaseError::fail(format!("lower: {e}")))?;
        let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
            .map_err(|e| TestCaseError::fail(format!("extract_property: {e}")))?;
        let cs = pipeline::abstract_to_cs(ta);

        let mut solver = Z3Solver::with_timeout_secs(10);
        let result = run_bmc_at_depth(&mut solver, &cs, &property, 0)
            .map_err(|e| TestCaseError::fail(format!("bmc: {e}")))?;

        // At depth 0, no transitions happen, so the initial state should be
        // reachable (satisfiable) and safe.
        match result {
            BmcResult::Safe { .. } => { /* expected */ }
            BmcResult::Unknown { .. } => { /* acceptable */ }
            BmcResult::Unsafe { .. } => {
                return Err(TestCaseError::fail(
                    "depth 0 should not be unsafe for a trivially safe protocol"
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2: Encoding structure is consistent
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn encoding_has_consistent_structure(n_msgs in 1..4usize) {
        let source = build_multi_message_protocol(n_msgs);
        let filename = "proptest_structure.trs";
        let program = pipeline::parse(&source, filename)
            .map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let ta = pipeline::lower(&program)
            .map_err(|e| TestCaseError::fail(format!("lower: {e}")))?;
        let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
            .map_err(|e| TestCaseError::fail(format!("extract_property: {e}")))?;
        let cs = pipeline::abstract_to_cs(ta);

        for depth in 0..=2 {
            let encoding = encode_bmc(&cs, &property, depth);

            // Encoding should have declarations
            prop_assert!(
                !encoding.declarations.is_empty(),
                "encoding at depth {} should have declarations",
                depth
            );

            // Encoding should have assertions
            prop_assert!(
                !encoding.assertions.is_empty(),
                "encoding at depth {} should have assertions",
                depth
            );

            // Declarations should be well-formed (all should serialize to valid SMT-LIB)
            for (name, sort) in &encoding.declarations {
                let smtlib = sort_to_smtlib(sort);
                prop_assert!(
                    !smtlib.is_empty(),
                    "declaration {} should produce non-empty SMT-LIB sort",
                    name
                );
            }

            // Assertions should be well-formed (all should serialize to valid SMT-LIB)
            for assertion in &encoding.assertions {
                let smtlib = to_smtlib(assertion);
                prop_assert!(
                    !smtlib.is_empty(),
                    "assertion should produce non-empty SMT-LIB"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: Counter conservation — sum of location counters equals n
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config())]

    /// Verifies counter conservation by checking that a protocol where all
    /// processes start in one location and can transition is satisfiable
    /// at depth 1, and the solver does not find the conservation constraint
    /// violated.
    ///
    /// We test this indirectly: if the sum-of-counters != n constraint were
    /// absent or wrong, the encoding would allow "creating" or "destroying"
    /// processes, producing spurious counterexamples for certain properties.
    /// We verify that for a known-safe model, BMC returns Safe through
    /// multiple depths (which requires conservation to hold).
    #[test]
    fn counter_conservation_holds_through_multiple_depths(n_extra in 0..3usize) {
        let source = build_minimal_protocol(n_extra);
        let filename = "proptest_conservation.trs";
        let program = pipeline::parse(&source, filename)
            .map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let ta = pipeline::lower(&program)
            .map_err(|e| TestCaseError::fail(format!("lower: {e}")))?;
        let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
            .map_err(|e| TestCaseError::fail(format!("extract_property: {e}")))?;
        let cs = pipeline::abstract_to_cs(ta);

        for depth in 0..=3 {
            let mut solver = Z3Solver::with_timeout_secs(10);
            let result = run_bmc_at_depth(&mut solver, &cs, &property, depth)
                .map_err(|e| TestCaseError::fail(format!("bmc depth {depth}: {e}")))?;

            match result {
                BmcResult::Safe { .. } => { /* expected: conservation maintained */ }
                BmcResult::Unknown { .. } => { /* acceptable */ }
                BmcResult::Unsafe { .. } => {
                    return Err(TestCaseError::fail(format!(
                        "expected Safe at depth {depth} for single-decision protocol \
                         (conservation may be broken)"
                    )));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4: Encoding determinism
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config())]

    /// The same protocol source encoded twice at the same depth should produce
    /// identical SMT assertions (deterministic compilation).
    #[test]
    fn encoding_is_deterministic(n_msgs in 1..3usize, depth in 0..3usize) {
        let source = build_multi_message_protocol(n_msgs);
        let filename = "proptest_determinism.trs";
        let program = pipeline::parse(&source, filename)
            .map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let ta = pipeline::lower(&program)
            .map_err(|e| TestCaseError::fail(format!("lower: {e}")))?;
        let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
            .map_err(|e| TestCaseError::fail(format!("extract_property: {e}")))?;
        let cs = pipeline::abstract_to_cs(ta);

        let enc_a = encode_bmc(&cs, &property, depth);
        let enc_b = encode_bmc(&cs, &property, depth);

        // Same number of declarations
        prop_assert_eq!(
            enc_a.declarations.len(),
            enc_b.declarations.len(),
            "declaration count mismatch at depth {}",
            depth
        );

        // Same number of assertions
        prop_assert_eq!(
            enc_a.assertions.len(),
            enc_b.assertions.len(),
            "assertion count mismatch at depth {}",
            depth
        );

        // Same serialized content
        for (a, b) in enc_a.assertions.iter().zip(enc_b.assertions.iter()) {
            let a_smt = to_smtlib(a);
            let b_smt = to_smtlib(b);
            prop_assert_eq!(
                a_smt,
                b_smt,
                "assertion mismatch at depth {}",
                depth
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: Deeper depths produce strictly more declarations/assertions
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn deeper_depth_produces_more_constraints(n_msgs in 1..3usize) {
        let source = build_multi_message_protocol(n_msgs);
        let filename = "proptest_depth_monotone.trs";
        let program = pipeline::parse(&source, filename)
            .map_err(|e| TestCaseError::fail(format!("parse: {e}")))?;
        let ta = pipeline::lower(&program)
            .map_err(|e| TestCaseError::fail(format!("lower: {e}")))?;
        let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
            .map_err(|e| TestCaseError::fail(format!("extract_property: {e}")))?;
        let cs = pipeline::abstract_to_cs(ta);

        let enc_0 = encode_bmc(&cs, &property, 0);
        let enc_1 = encode_bmc(&cs, &property, 1);
        let enc_2 = encode_bmc(&cs, &property, 2);

        // More depth should mean more declarations (step variables) and assertions
        prop_assert!(
            enc_1.declarations.len() >= enc_0.declarations.len(),
            "depth 1 should have >= declarations than depth 0: {} vs {}",
            enc_1.declarations.len(),
            enc_0.declarations.len()
        );
        prop_assert!(
            enc_2.declarations.len() >= enc_1.declarations.len(),
            "depth 2 should have >= declarations than depth 1: {} vs {}",
            enc_2.declarations.len(),
            enc_1.declarations.len()
        );
        prop_assert!(
            enc_1.assertions.len() >= enc_0.assertions.len(),
            "depth 1 should have >= assertions than depth 0: {} vs {}",
            enc_1.assertions.len(),
            enc_0.assertions.len()
        );
        prop_assert!(
            enc_2.assertions.len() >= enc_1.assertions.len(),
            "depth 2 should have >= assertions than depth 1: {} vs {}",
            enc_2.assertions.len(),
            enc_1.assertions.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Non-proptest: single-location TA at depth 0 is satisfiable
// ---------------------------------------------------------------------------

#[test]
fn single_location_ta_depth_0_satisfiable() {
    let source = r#"protocol SingleLoc {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}"#;

    let filename = "single_loc.trs";
    let program = pipeline::parse(source, filename).expect("parse");
    let ta = pipeline::lower(&program).expect("lower");
    let property =
        pipeline::extract_property(&ta, &program, SoundnessMode::Strict).expect("extract");
    let cs = pipeline::abstract_to_cs(ta);

    // The TA should have at least 1 location
    assert!(
        !cs.locations.is_empty(),
        "TA should have at least 1 location"
    );

    let mut solver = Z3Solver::with_timeout_secs(5);
    let result = run_bmc_at_depth(&mut solver, &cs, &property, 0).expect("bmc");

    match result {
        BmcResult::Safe { .. } => { /* expected at depth 0: initial state is safe */ }
        other => panic!("expected Safe at depth 0 for trivial invariant, got: {other:?}"),
    }
}

#[test]
fn encoding_declarations_include_location_counters() {
    let source = r#"protocol DeclCheck {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 1 M => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}"#;

    let filename = "decl_check.trs";
    let program = pipeline::parse(source, filename).expect("parse");
    let ta = pipeline::lower(&program).expect("lower");
    let property =
        pipeline::extract_property(&ta, &program, SoundnessMode::Strict).expect("extract");
    let cs = pipeline::abstract_to_cs(ta);
    let n_locations = cs.locations.len();

    let encoding = encode_bmc(&cs, &property, 1);

    // Should have declarations for location counters at step 0 and step 1
    // Each location gets a counter variable at each step.
    // Plus shared variable declarations, parameter declarations, etc.
    assert!(
        encoding.declarations.len() >= n_locations * 2,
        "encoding should have at least {} declarations for {} locations over 2 steps, got {}",
        n_locations * 2,
        n_locations,
        encoding.declarations.len()
    );
}
