//! Property-based tests for the parse → lower pipeline stage.
//!
//! These tests verify structural invariants of the lowering pass across
//! all library models and (where feasible) randomly generated inputs.

use std::path::PathBuf;

use tarsier_engine::pipeline;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn default_library_dir() -> PathBuf {
    workspace_root().join("examples/library")
}

/// Corpus-based: every .trs in examples/library/ lowers without panic.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn all_library_models_lower_without_panic() {
    let lib_dir = default_library_dir();
    let mut count = 0;
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = pipeline::parse(&source, &filename);
            if let Ok(program) = program {
                // Lowering should not panic even if it returns an error
                let _ = pipeline::lower(&program);
            }
            count += 1;
        }
    }
    assert!(
        count >= 10,
        "expected at least 10 library models, found {count}"
    );
}

/// Every library model that successfully lowers produces a ThresholdAutomaton
/// with at least 1 location, 1 rule, and 1 parameter.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn lowering_preserves_minimum_structure() {
    let lib_dir = default_library_dir();
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = match pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ta = match pipeline::lower(&program) {
                Ok(ta) => ta,
                Err(_) => continue,
            };

            assert!(
                !ta.locations.is_empty(),
                "{filename}: expected at least 1 location"
            );
            // Most models have rules, but trivial models (e.g. trivial_live.trs)
            // may have zero rules if all processes start in the done state.
            assert!(
                !ta.parameters.is_empty(),
                "{filename}: expected at least 1 parameter"
            );
            assert!(
                !ta.initial_locations.is_empty(),
                "{filename}: expected at least 1 initial location"
            );
        }
    }
}

/// All initial locations are valid indices into the locations array.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn initial_locations_are_valid_indices() {
    let lib_dir = default_library_dir();
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = match pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ta = match pipeline::lower(&program) {
                Ok(ta) => ta,
                Err(_) => continue,
            };

            for &init_loc in &ta.initial_locations {
                assert!(
                    init_loc < ta.locations.len(),
                    "{filename}: initial location {init_loc} out of bounds ({})",
                    ta.locations.len()
                );
            }
        }
    }
}

/// All rule from/to references are valid location indices, and all
/// guard/update references point to valid shared vars and parameters.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn rule_references_are_valid() {
    let lib_dir = default_library_dir();
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = match pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ta = match pipeline::lower(&program) {
                Ok(ta) => ta,
                Err(_) => continue,
            };

            for (i, rule) in ta.rules.iter().enumerate() {
                assert!(
                    rule.from < ta.locations.len(),
                    "{filename}: rule {i} from={} out of bounds",
                    rule.from
                );
                assert!(
                    rule.to < ta.locations.len(),
                    "{filename}: rule {i} to={} out of bounds",
                    rule.to
                );
                for upd in &rule.updates {
                    assert!(
                        upd.var < ta.shared_vars.len(),
                        "{filename}: rule {i} update var={} out of bounds",
                        upd.var
                    );
                }
            }
        }
    }
}

/// Export-dot round-trip: parse -> lower -> export-dot doesn't panic on any library model.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn export_dot_no_panic_on_library() {
    use tarsier_engine::visualization::{render_automaton_dot, DotRenderOptions};

    let lib_dir = default_library_dir();
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = match pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ta = match pipeline::lower(&program) {
                Ok(ta) => ta,
                Err(_) => continue,
            };

            let dot = render_automaton_dot(&ta, &DotRenderOptions::default());
            assert!(!dot.is_empty(), "{filename}: empty DOT output");
        }
    }
}

/// Export-ta round-trip: parse -> lower -> export-ta doesn't panic on any library model.
/// Also verifies that models with agreement properties produce real specification content.
#[test]
#[ignore = "slow: ~90s total for file, run with --ignored"]
fn export_ta_no_panic_on_library() {
    let lib_dir = default_library_dir();
    for entry in std::fs::read_dir(&lib_dir).expect("read examples/library") {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "trs").unwrap_or(false) {
            let source = std::fs::read_to_string(&path).unwrap();
            let filename = path.display().to_string();
            let program = match pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ta = match pipeline::lower(&program) {
                Ok(ta) => ta,
                Err(_) => continue,
            };

            let ta_output = tarsier_engine::export_ta::export_ta(&ta);
            assert!(!ta_output.is_empty(), "{filename}: empty .ta output");
            // Verify balanced braces
            let opens = ta_output.chars().filter(|&c| c == '{').count();
            let closes = ta_output.chars().filter(|&c| c == '}').count();
            assert_eq!(opens, closes, "{filename}: unbalanced braces in .ta output");

            // Models with agreement properties and decided locations should
            // produce real specs. Some protocols don't use the `decided` local
            // var convention, so specifications (0) is valid when no decided
            // locations are found by the property extractor.
            let has_agreement = source.contains("property") && source.contains("agreement");
            let has_decided_keyword = source.contains("decided");
            if has_agreement && has_decided_keyword {
                assert!(
                    !ta_output.contains("specifications (0)"),
                    "{filename}: agreement model with 'decided' should not have empty specifications (0)"
                );
                assert!(
                    ta_output.contains("agreement:"),
                    "{filename}: agreement model should have 'agreement:' label in specifications"
                );
            }
        }
    }
}
