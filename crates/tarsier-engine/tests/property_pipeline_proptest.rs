//! Randomized + metamorphic property tests for parse -> lower -> encode -> solve.
//!
//! This suite is intentionally separate from corpus regression tests: it
//! synthesizes protocol variants and checks semantic invariants.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use proptest::test_runner::{
    Config as ProptestConfig, FileFailurePersistence, RngAlgorithm, RngSeed,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tarsier_engine::pipeline::{self, SoundnessMode};
use tarsier_smt::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{run_bmc_at_depth, BmcResult};
use tarsier_smt::encoder::encode_bmc;

#[derive(Debug, Clone, Serialize)]
struct MiniCase {
    protocol_suffix: u32,
    p_var: String,
    q_var: String,
    alt_p_var: String,
    alt_q_var: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleOrder {
    Canonical,
    Reversed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerdictClass {
    Safe,
    Unsafe,
    Unknown,
}

const RESERVED_IDENTIFIERS: &[&str] = &[
    "protocol",
    "params",
    "resilience",
    "adversary",
    "model",
    "bound",
    "role",
    "var",
    "init",
    "phase",
    "when",
    "send",
    "goto",
    "decide",
    "property",
    "agreement",
    "safety",
    "liveness",
    "forall",
    "exists",
    "true",
    "false",
    "n",
    "t",
    "f",
    "Node",
    "decided",
    "decision",
    "start",
    "done",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate should have workspace root parent")
        .parent()
        .expect("workspace root should exist")
        .to_path_buf()
}

fn property_cases() -> u32 {
    env::var("TARSIER_PROPTEST_CASES")
        .ok()
        .or_else(|| env::var("PROPTEST_CASES").ok())
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(24)
}

fn property_seed(default_seed: u64) -> u64 {
    env::var("TARSIER_PROPTEST_SEED")
        .ok()
        .or_else(|| env::var("PROPTEST_RNG_SEED").ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default_seed)
}

fn proptest_config(source_file: &'static str) -> ProptestConfig {
    ProptestConfig {
        cases: property_cases(),
        source_file: Some(source_file),
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(property_seed(0x7A55_1EED_u64)),
        ..ProptestConfig::default()
    }
}

fn identifier_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,7}"
        .prop_map(|s| s.to_string())
        .prop_filter("identifier must not be reserved", |name| {
            !RESERVED_IDENTIFIERS.contains(&name.as_str())
        })
}

fn mini_case_strategy() -> impl Strategy<Value = MiniCase> {
    (
        1_u32..10_000_u32,
        identifier_strategy(),
        identifier_strategy(),
        identifier_strategy(),
        identifier_strategy(),
    )
        .prop_filter(
            "quantifier variables must be pairwise distinct",
            |(_, p, q, alt_p, alt_q)| {
                p != q && p != alt_p && p != alt_q && q != alt_p && q != alt_q && alt_p != alt_q
            },
        )
        .prop_map(
            |(protocol_suffix, p_var, q_var, alt_p_var, alt_q_var)| MiniCase {
                protocol_suffix,
                p_var,
                q_var,
                alt_p_var,
                alt_q_var,
            },
        )
}

fn build_safe_source(case: &MiniCase, quant_vars: (&str, &str), order: RuleOrder) -> String {
    let rule_a = r#"
            when decided == false => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
"#;
    let rule_b = r#"
            when (decided == false && decision == false) => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
"#;

    let rules = match order {
        RuleOrder::Canonical => format!("{rule_a}{rule_b}"),
        RuleOrder::Reversed => format!("{rule_b}{rule_a}"),
    };

    format!(
        r#"protocol RandomizedMiniSafe{protocol_suffix} {{
    params n, t, f;
    resilience: n > 3*t;

    adversary {{
        model: byzantine;
        bound: f;
    }}

    role Node {{
        var decided: bool = false;
        var decision: bool = false;

        init start;

        phase start {{{rules}        }}

        phase done {{}}
    }}

    property agreement: agreement {{
        forall {p}: Node. forall {q}: Node.
            ({p}.decided == true && {q}.decided == true) ==> ({p}.decision == {q}.decision)
    }}
}}
"#,
        protocol_suffix = case.protocol_suffix,
        rules = rules,
        p = quant_vars.0,
        q = quant_vars.1,
    )
}

fn build_buggy_source(case: &MiniCase) -> String {
    format!(
        r#"protocol RandomizedMiniBuggy{protocol_suffix} {{
    params n, t, f;
    resilience: n > 3*t;

    adversary {{
        model: byzantine;
        bound: f;
    }}

    role Node {{
        var decided: bool = false;
        var decision: bool = false;

        init start;

        phase start {{
            when decided == false => {{
                decision = true;
                decided = true;
                decide true;
                goto phase done_true;
            }}
            when decided == false => {{
                decision = false;
                decided = true;
                decide false;
                goto phase done_false;
            }}
        }}

        phase done_true {{}}
        phase done_false {{}}
    }}

    property agreement: agreement {{
        forall {p}: Node. forall {q}: Node.
            ({p}.decided == true && {q}.decided == true) ==> ({p}.decision == {q}.decision)
    }}
}}
"#,
        protocol_suffix = case.protocol_suffix,
        p = case.p_var,
        q = case.q_var,
    )
}

fn encode_and_solve_exact_depth(source: &str, depth: usize) -> Result<VerdictClass, String> {
    let filename = "property_pipeline_proptest_generated.trs";
    let program = pipeline::parse(source, filename).map_err(|e| format!("parse failed: {e}"))?;
    let ta = pipeline::lower(&program).map_err(|e| format!("lower failed: {e}"))?;
    let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
        .map_err(|e| format!("extract_property failed: {e}"))?;
    let cs = pipeline::abstract_to_cs(ta);

    let mut solver = Z3Solver::with_timeout_secs(10);
    let bmc = run_bmc_at_depth(&mut solver, &cs, &property, depth)
        .map_err(|e| format!("bmc failed: {e}"))?;

    Ok(match bmc {
        BmcResult::Safe { .. } => VerdictClass::Safe,
        BmcResult::Unsafe { .. } => VerdictClass::Unsafe,
        BmcResult::Unknown { .. } => VerdictClass::Unknown,
    })
}

fn encoding_fingerprint(source: &str, depth: usize) -> Result<String, String> {
    let filename = "property_pipeline_proptest_generated.trs";
    let program = pipeline::parse(source, filename).map_err(|e| format!("parse failed: {e}"))?;
    let ta = pipeline::lower(&program).map_err(|e| format!("lower failed: {e}"))?;
    let property = pipeline::extract_property(&ta, &program, SoundnessMode::Strict)
        .map_err(|e| format!("extract_property failed: {e}"))?;
    let cs = pipeline::abstract_to_cs(ta);
    let encoding = encode_bmc(&cs, &property, depth);

    let mut lines = Vec::new();
    for (name, sort) in &encoding.declarations {
        lines.push(format!("(declare-fun {name} () {})", sort_to_smtlib(sort)));
    }
    for assertion in &encoding.assertions {
        lines.push(format!("(assert {})", to_smtlib(assertion)));
    }

    let joined = lines.join("\n");
    let hash = Sha256::digest(joined.as_bytes());
    Ok(format!("{:x}", hash))
}

fn failure_artifact_dir() -> PathBuf {
    if let Ok(dir) = env::var("TARSIER_PROPTEST_ARTIFACT_DIR") {
        return PathBuf::from(dir);
    }
    workspace_root().join("target/property-test-failures")
}

fn write_failure_artifact(kind: &str, case: &MiniCase, payload: serde_json::Value) -> PathBuf {
    let dir = failure_artifact_dir();
    let _ = fs::create_dir_all(&dir);

    let mut hasher = Sha256::new();
    hasher.update(format!("{kind}:{:?}", case));
    let hash = format!("{:x}", hasher.finalize());
    let path = dir.join(format!("{kind}-{hash}.json"));

    let artifact = json!({
        "kind": kind,
        "case": case,
        "payload": payload,
    });
    let _ = fs::write(
        &path,
        serde_json::to_string_pretty(&artifact).unwrap_or_else(|_| "{}".into()),
    );
    path
}

fn assert_verdict_eq_or_artifact(
    kind: &str,
    case: &MiniCase,
    lhs: VerdictClass,
    rhs: VerdictClass,
    payload: serde_json::Value,
) {
    if lhs != rhs {
        let artifact = write_failure_artifact(kind, case, payload);
        panic!(
            "metamorphic property `{kind}` failed; artifact={} lhs={lhs:?} rhs={rhs:?}",
            artifact.display()
        );
    }
}

fn assert_eq_or_artifact(
    kind: &str,
    case: &MiniCase,
    lhs: &str,
    rhs: &str,
    payload: serde_json::Value,
) {
    if lhs != rhs {
        let artifact = write_failure_artifact(kind, case, payload);
        panic!(
            "determinism property `{kind}` failed; artifact={} lhs={} rhs={}",
            artifact.display(),
            lhs,
            rhs
        );
    }
}

fn assert_safe_or_artifact(kind: &str, case: &MiniCase, verdict: VerdictClass, source: &str) {
    if verdict != VerdictClass::Safe {
        let artifact = write_failure_artifact(
            kind,
            case,
            json!({
                "unexpected_verdict": format!("{verdict:?}"),
                "source": source,
            }),
        );
        panic!(
            "expected SAFE verdict for randomized model; artifact={} verdict={verdict:?}",
            artifact.display()
        );
    }
}

fn assert_unsafe_or_artifact(kind: &str, case: &MiniCase, verdict: VerdictClass, source: &str) {
    if verdict != VerdictClass::Unsafe {
        let artifact = write_failure_artifact(
            kind,
            case,
            json!({
                "unexpected_verdict": format!("{verdict:?}"),
                "source": source,
            }),
        );
        panic!(
            "expected UNSAFE verdict for buggy mutant; artifact={} verdict={verdict:?}",
            artifact.display()
        );
    }
}

proptest! {
    #![proptest_config(proptest_config(file!()))]

    #[test]
    fn parse_lower_encode_solve_randomized_safe_models(case in mini_case_strategy()) {
        let source = build_safe_source(&case, (&case.p_var, &case.q_var), RuleOrder::Canonical);
        let verdict = encode_and_solve_exact_depth(&source, 2).expect("pipeline should succeed");
        assert_safe_or_artifact("randomized_safe", &case, verdict, &source);
    }

    #[test]
    fn metamorphic_alpha_rename_and_rule_reorder_invariance(case in mini_case_strategy()) {
        let canonical = build_safe_source(&case, (&case.p_var, &case.q_var), RuleOrder::Canonical);
        let renamed = build_safe_source(&case, (&case.alt_p_var, &case.alt_q_var), RuleOrder::Canonical);
        let reordered = build_safe_source(&case, (&case.p_var, &case.q_var), RuleOrder::Reversed);

        let canonical_verdict = encode_and_solve_exact_depth(&canonical, 2).expect("canonical pipeline should succeed");
        let renamed_verdict = encode_and_solve_exact_depth(&renamed, 2).expect("renamed pipeline should succeed");
        let reordered_verdict = encode_and_solve_exact_depth(&reordered, 2).expect("reordered pipeline should succeed");

        assert_verdict_eq_or_artifact(
            "alpha_rename_invariance",
            &case,
            canonical_verdict,
            renamed_verdict,
            json!({"canonical": canonical, "renamed": renamed}),
        );

        assert_verdict_eq_or_artifact(
            "rule_reorder_invariance",
            &case,
            canonical_verdict,
            reordered_verdict,
            json!({"canonical": canonical, "reordered": reordered}),
        );

        let canonical_fp_a = encoding_fingerprint(&canonical, 2).expect("canonical fingerprint should succeed");
        let canonical_fp_b = encoding_fingerprint(&canonical, 2).expect("canonical fingerprint should succeed");
        assert_eq_or_artifact(
            "deterministic_compilation_fingerprint",
            &case,
            &canonical_fp_a,
            &canonical_fp_b,
            json!({"canonical": canonical, "fingerprint_a": canonical_fp_a, "fingerprint_b": canonical_fp_b}),
        );
    }

    #[test]
    fn randomized_buggy_mutant_is_caught(case in mini_case_strategy()) {
        let safe_source = build_safe_source(&case, (&case.p_var, &case.q_var), RuleOrder::Canonical);
        let buggy_source = build_buggy_source(&case);

        let safe_verdict = encode_and_solve_exact_depth(&safe_source, 2).expect("safe pipeline should succeed");
        let buggy_verdict = encode_and_solve_exact_depth(&buggy_source, 2).expect("buggy pipeline should succeed");

        assert_safe_or_artifact("bugcatch_safe_baseline", &case, safe_verdict, &safe_source);
        assert_unsafe_or_artifact("bugcatch_buggy_mutant", &case, buggy_verdict, &buggy_source);
    }
}

#[test]
fn failure_artifact_directory_is_workspace_scoped() {
    let dir = failure_artifact_dir();
    let root = workspace_root();
    assert!(
        dir.starts_with(root),
        "failure artifacts should stay under workspace target by default"
    );
    assert!(
        Path::new(&dir).is_absolute(),
        "artifact dir should be absolute for CI diagnostics"
    );
}
