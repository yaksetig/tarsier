use proptest::prelude::*;
use proptest::test_runner::{
    Config as ProptestConfig, FileFailurePersistence, RngAlgorithm, RngSeed,
};
use sha2::{Digest, Sha256};

use crate::pipeline::{self, SoundnessMode};
use tarsier_smt::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{run_bmc_at_depth, BmcResult};
use tarsier_smt::encoder::encode_bmc;

#[derive(Debug, Clone)]
struct MiniUnitCase {
    protocol_suffix: u32,
    p_var: String,
    q_var: String,
    alt_p_var: String,
    alt_q_var: String,
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
    "goto",
    "decide",
    "property",
    "agreement",
    "forall",
    "true",
    "false",
    "n",
    "t",
    "f",
    "Node",
    "decided",
    "decision",
];

fn property_cases() -> u32 {
    std::env::var("TARSIER_PROPTEST_CASES")
        .ok()
        .or_else(|| std::env::var("PROPTEST_CASES").ok())
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(16)
}

fn property_seed(default_seed: u64) -> u64 {
    std::env::var("TARSIER_PROPTEST_SEED")
        .ok()
        .or_else(|| std::env::var("PROPTEST_RNG_SEED").ok())
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
        rng_seed: RngSeed::Fixed(property_seed(0x7151_0001_u64)),
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

fn mini_case_strategy() -> impl Strategy<Value = MiniUnitCase> {
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
            |(protocol_suffix, p_var, q_var, alt_p_var, alt_q_var)| MiniUnitCase {
                protocol_suffix,
                p_var,
                q_var,
                alt_p_var,
                alt_q_var,
            },
        )
}

fn build_safe_source(case: &MiniUnitCase, quant_vars: (&str, &str)) -> String {
    format!(
        r#"protocol UnitRandomizedSafe{protocol_suffix} {{
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
                goto phase done;
            }}
            when (decided == false && decision == false) => {{
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }}
        }}

        phase done {{}}
    }}

    property agreement: agreement {{
        forall {p}: Node. forall {q}: Node.
            ({p}.decided == true && {q}.decided == true) ==> ({p}.decision == {q}.decision)
    }}
}}
"#,
        protocol_suffix = case.protocol_suffix,
        p = quant_vars.0,
        q = quant_vars.1,
    )
}

fn build_buggy_source(case: &MiniUnitCase) -> String {
    format!(
        r#"protocol UnitRandomizedBuggy{protocol_suffix} {{
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
    let filename = "property_pipeline_unit_generated.trs";
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
    let filename = "property_pipeline_unit_generated.trs";
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

proptest! {
    #![proptest_config(proptest_config(file!()))]

    #[test]
    fn unit_metamorphic_alpha_rename_and_compilation_are_deterministic(case in mini_case_strategy()) {
        let canonical = build_safe_source(&case, (&case.p_var, &case.q_var));
        let renamed = build_safe_source(&case, (&case.alt_p_var, &case.alt_q_var));

        let canonical_verdict = encode_and_solve_exact_depth(&canonical, 2).expect("canonical should verify");
        let renamed_verdict = encode_and_solve_exact_depth(&renamed, 2).expect("renamed should verify");
        prop_assert_eq!(canonical_verdict, VerdictClass::Safe);
        prop_assert_eq!(renamed_verdict, canonical_verdict);

        let fp_a = encoding_fingerprint(&canonical, 2).expect("fingerprint a");
        let fp_b = encoding_fingerprint(&canonical, 2).expect("fingerprint b");
        prop_assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn unit_negative_buggy_mutants_are_unsafety_reachable(case in mini_case_strategy()) {
        let buggy = build_buggy_source(&case);
        let verdict = encode_and_solve_exact_depth(&buggy, 2).expect("buggy should verify");
        prop_assert_eq!(verdict, VerdictClass::Unsafe);
    }
}
