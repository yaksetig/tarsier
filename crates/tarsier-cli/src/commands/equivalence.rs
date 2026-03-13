//! `equivalence-check` CLI command handler.
//!
//! Parses two protocols, builds bidirectional product automata, runs Z3 solver
//! on both simulation directions, and reports the equivalence verdict.

use std::path::Path;
use std::process;

use serde::Serialize;
use tarsier_dsl::parse;
use tarsier_ir::equivalence::build_equivalence_products;
use tarsier_ir::lowering::lower;
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::equivalence_encoder::{run_equivalence_solver, EquivalenceCheckResult};

/// Schema version for equivalence-check JSON output.
pub const SCHEMA_VERSION: u32 = 2;

/// Structured equivalence-check report.
#[derive(Debug, Clone, Serialize)]
pub struct EquivalenceReport {
    pub schema_version: u32,
    pub protocol_a: String,
    pub protocol_b: String,
    pub depth: usize,
    pub timeout_secs: u64,
    pub forward_product_locations: usize,
    pub forward_product_rules: usize,
    pub forward_mismatches: usize,
    pub backward_product_locations: usize,
    pub backward_product_rules: usize,
    pub backward_mismatches: usize,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_witness: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backward_witness: Option<serde_json::Value>,
}

/// Run the equivalence-check command.
pub(crate) fn run_equivalence_check(
    file_a: &Path,
    file_b: &Path,
    depth: usize,
    format: &str,
    timeout_secs: u64,
) -> miette::Result<()> {
    // 1. Parse both protocols.
    let src_a =
        std::fs::read_to_string(file_a).map_err(|e| miette::miette!("read protocol A: {e}"))?;
    let src_b =
        std::fs::read_to_string(file_b).map_err(|e| miette::miette!("read protocol B: {e}"))?;

    let name_a = file_a.display().to_string();
    let name_b = file_b.display().to_string();

    let ast_a = parse(&src_a, &name_a).map_err(|e| miette::miette!("parse A: {e}"))?;
    let ast_b = parse(&src_b, &name_b).map_err(|e| miette::miette!("parse B: {e}"))?;

    // 2. Lower both to IR.
    let ta_a = lower(&ast_a).map_err(|e| miette::miette!("lower A: {e}"))?;
    let ta_b = lower(&ast_b).map_err(|e| miette::miette!("lower B: {e}"))?;

    // 3. Build bidirectional products.
    let products = build_equivalence_products(&ta_a, &ta_b).map_err(|e| miette::miette!("{e}"))?;

    // 4. Run solver on both directions.
    let mut fwd_solver = Z3Solver::with_timeout_secs(timeout_secs);
    let mut bwd_solver = Z3Solver::with_timeout_secs(timeout_secs);
    let result = run_equivalence_solver(&mut fwd_solver, &mut bwd_solver, &products, depth)
        .map_err(|e| miette::miette!("solver error: {e}"))?;

    // 5. Build report.
    let report = build_report(file_a, file_b, depth, timeout_secs, &products, &result);

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
            println!("{json}");
        }
        _ => {
            println!("Equivalence Check Report");
            println!("========================");
            println!("Protocol A: {}", report.protocol_a);
            println!("Protocol B: {}", report.protocol_b);
            println!("Depth:      {}", report.depth);
            println!("Timeout:    {}s", report.timeout_secs);
            println!();
            println!("Forward (A → B):");
            println!("  Product locations: {}", report.forward_product_locations);
            println!("  Product rules:     {}", report.forward_product_rules);
            println!("  Mismatches:        {}", report.forward_mismatches);
            println!();
            println!("Backward (B → A):");
            println!("  Product locations: {}", report.backward_product_locations);
            println!("  Product rules:     {}", report.backward_product_rules);
            println!("  Mismatches:        {}", report.backward_mismatches);
            println!();
            match &result {
                EquivalenceCheckResult::TriviallyEquivalent => {
                    println!(
                        "Result: TRIVIALLY EQUIVALENT (no mismatch locations in either direction)"
                    );
                }
                EquivalenceCheckResult::EquivalentUpTo { depth } => {
                    println!("Result: EQUIVALENT up to depth {depth}");
                }
                EquivalenceCheckResult::ForwardDivergence { witness, .. } => {
                    println!("Result: FORWARD DIVERGENCE (A has behavior B cannot match)");
                    if let Some(w) = witness {
                        println!();
                        super::witness_format::print_witness_text_with_direction(
                            "Forward",
                            &w.minimized(),
                            &products.forward,
                        );
                    }
                }
                EquivalenceCheckResult::BackwardDivergence { witness, .. } => {
                    println!("Result: BACKWARD DIVERGENCE (B has behavior A cannot match)");
                    if let Some(w) = witness {
                        println!();
                        super::witness_format::print_witness_text_with_direction(
                            "Backward",
                            &w.minimized(),
                            &products.backward,
                        );
                    }
                }
                EquivalenceCheckResult::BidirectionalDivergence {
                    forward_witness,
                    backward_witness,
                    ..
                } => {
                    println!(
                        "Result: BIDIRECTIONAL DIVERGENCE (neither protocol simulates the other)"
                    );
                    if let Some(w) = forward_witness {
                        println!();
                        super::witness_format::print_witness_text_with_direction(
                            "Forward",
                            &w.minimized(),
                            &products.forward,
                        );
                    }
                    if let Some(w) = backward_witness {
                        println!();
                        super::witness_format::print_witness_text_with_direction(
                            "Backward",
                            &w.minimized(),
                            &products.backward,
                        );
                    }
                }
                EquivalenceCheckResult::Unknown { reason, .. } => {
                    println!("Result: UNKNOWN ({reason})");
                }
            }
        }
    }

    // Exit code: 0=equivalent, 1=divergence, 2=unknown
    match &result {
        EquivalenceCheckResult::TriviallyEquivalent
        | EquivalenceCheckResult::EquivalentUpTo { .. } => Ok(()),
        EquivalenceCheckResult::ForwardDivergence { .. }
        | EquivalenceCheckResult::BackwardDivergence { .. }
        | EquivalenceCheckResult::BidirectionalDivergence { .. } => process::exit(1),
        EquivalenceCheckResult::Unknown { .. } => process::exit(2),
    }
}

fn build_report(
    file_a: &Path,
    file_b: &Path,
    depth: usize,
    timeout_secs: u64,
    products: &tarsier_ir::equivalence::EquivalenceProducts,
    result: &EquivalenceCheckResult,
) -> EquivalenceReport {
    let result_str = match result {
        EquivalenceCheckResult::TriviallyEquivalent => "trivially_equivalent",
        EquivalenceCheckResult::EquivalentUpTo { .. } => "equivalent",
        EquivalenceCheckResult::ForwardDivergence { .. } => "forward_divergence",
        EquivalenceCheckResult::BackwardDivergence { .. } => "backward_divergence",
        EquivalenceCheckResult::BidirectionalDivergence { .. } => "bidirectional_divergence",
        EquivalenceCheckResult::Unknown { .. } => "unknown",
    };

    let unknown_reason = if let EquivalenceCheckResult::Unknown { reason, .. } = result {
        Some(reason.clone())
    } else {
        None
    };

    let (fw, bw) = extract_witnesses(result, products);

    EquivalenceReport {
        schema_version: SCHEMA_VERSION,
        protocol_a: file_a.display().to_string(),
        protocol_b: file_b.display().to_string(),
        depth,
        timeout_secs,
        forward_product_locations: products.forward.num_locations(),
        forward_product_rules: products.forward.num_rules(),
        forward_mismatches: products.forward.mismatch_locations.len(),
        backward_product_locations: products.backward.num_locations(),
        backward_product_rules: products.backward.num_rules(),
        backward_mismatches: products.backward.mismatch_locations.len(),
        result: result_str.into(),
        unknown_reason,
        forward_witness: fw,
        backward_witness: bw,
    }
}

fn extract_witnesses(
    result: &EquivalenceCheckResult,
    products: &tarsier_ir::equivalence::EquivalenceProducts,
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    match result {
        EquivalenceCheckResult::ForwardDivergence { witness, .. } => (
            witness.as_ref().map(|w| {
                super::witness_format::witness_to_json_with_violation(
                    &w.minimized(),
                    &products.forward,
                )
            }),
            None,
        ),
        EquivalenceCheckResult::BackwardDivergence { witness, .. } => (
            None,
            witness.as_ref().map(|w| {
                super::witness_format::witness_to_json_with_violation(
                    &w.minimized(),
                    &products.backward,
                )
            }),
        ),
        EquivalenceCheckResult::BidirectionalDivergence {
            forward_witness,
            backward_witness,
            ..
        } => (
            forward_witness.as_ref().map(|w| {
                super::witness_format::witness_to_json_with_violation(
                    &w.minimized(),
                    &products.forward,
                )
            }),
            backward_witness.as_ref().map(|w| {
                super::witness_format::witness_to_json_with_violation(
                    &w.minimized(),
                    &products.backward,
                )
            }),
        ),
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> EquivalenceReport {
        EquivalenceReport {
            schema_version: SCHEMA_VERSION,
            protocol_a: "a.trs".into(),
            protocol_b: "b.trs".into(),
            depth: 10,
            timeout_secs: 60,
            forward_product_locations: 4,
            forward_product_rules: 2,
            forward_mismatches: 1,
            backward_product_locations: 4,
            backward_product_rules: 2,
            backward_mismatches: 0,
            result: "equivalent".into(),
            unknown_reason: None,
            forward_witness: None,
            backward_witness: None,
        }
    }

    #[test]
    fn schema_version_is_current() {
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn report_serializes_equivalent() {
        let report = sample_report();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["result"], "equivalent");
        assert!(json.get("unknown_reason").is_none());
    }

    #[test]
    fn report_serializes_unknown() {
        let report = EquivalenceReport {
            result: "unknown".into(),
            unknown_reason: Some("timeout".into()),
            ..sample_report()
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["result"], "unknown");
        assert_eq!(json["unknown_reason"], "timeout");
    }

    #[test]
    fn report_has_required_fields() {
        let report = sample_report();
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        for field in &[
            "schema_version",
            "protocol_a",
            "protocol_b",
            "depth",
            "timeout_secs",
            "forward_product_locations",
            "forward_product_rules",
            "forward_mismatches",
            "backward_product_locations",
            "backward_product_rules",
            "backward_mismatches",
            "result",
        ] {
            assert!(obj.contains_key(*field), "missing field: {field}");
        }
    }
}
