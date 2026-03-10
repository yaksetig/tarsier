//! `refinement-check` CLI command handler.
//!
//! Parses concrete and abstract protocols, builds the product automaton,
//! encodes bounded simulation obligations, and runs the Z3 solver to produce
//! a SAT/UNSAT/UNKNOWN verdict with optional witness extraction.

use std::path::Path;
use std::process;

use serde::Serialize;
use tarsier_dsl::parser::parse;
use tarsier_ir::lowering::lower;
use tarsier_ir::product::build_product;
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::refinement_encoder::{run_refinement_solver, SimulationCheckResult};

/// Schema version for the refinement-check JSON output.
pub const SCHEMA_VERSION: u32 = 3;

/// Structured refinement-check report (JSON-serializable).
#[derive(Debug, Clone, Serialize)]
pub struct RefinementReport {
    pub schema_version: u32,
    pub concrete: String,
    #[serde(rename = "abstract")]
    pub abstract_path: String,
    pub depth: usize,
    pub timeout_secs: u64,
    pub product_locations: usize,
    pub product_rules: usize,
    pub mismatch_locations: usize,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_step: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_detail: Option<ViolationDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<serde_json::Value>,
}

/// Violation location detail.
#[derive(Debug, Clone, Serialize)]
pub struct ViolationDetail {
    pub concrete_location: usize,
    pub abstract_location: usize,
}

/// Run the refinement-check command.
pub(crate) fn run_refinement_check(
    concrete_path: &Path,
    abstract_path_override: Option<&Path>,
    depth: usize,
    format: &str,
    timeout_secs: u64,
) -> miette::Result<()> {
    // 1. Parse concrete protocol.
    let concrete_src = std::fs::read_to_string(concrete_path)
        .map_err(|e| miette::miette!("read concrete: {e}"))?;
    let filename = concrete_path.display().to_string();
    let concrete_ast =
        parse(&concrete_src, &filename).map_err(|e| miette::miette!("parse concrete: {e}"))?;

    // 2. Determine abstract protocol path.
    let abstract_path = if let Some(p) = abstract_path_override {
        p.to_path_buf()
    } else if let Some(ref refines) = concrete_ast.protocol.node.refines {
        let base = concrete_path.parent().unwrap_or(Path::new("."));
        base.join(&refines.path)
    } else {
        return Err(miette::miette!(
            "concrete protocol has no `refines` declaration; use --abstract-file to specify"
        ));
    };

    // 3. Parse abstract protocol.
    let abstract_src = std::fs::read_to_string(&abstract_path)
        .map_err(|e| miette::miette!("read abstract: {e}"))?;
    let abs_filename = abstract_path.display().to_string();
    let abstract_ast =
        parse(&abstract_src, &abs_filename).map_err(|e| miette::miette!("parse abstract: {e}"))?;

    // 4. Lower both to IR.
    let concrete_ta = lower(&concrete_ast).map_err(|e| miette::miette!("lower concrete: {e}"))?;
    let abstract_ta = lower(&abstract_ast).map_err(|e| miette::miette!("lower abstract: {e}"))?;

    // 5. Build refinement mapping (name-based auto-mapping).
    let mapping = build_auto_mapping(
        &concrete_ta,
        &abstract_ta,
        abstract_path.to_string_lossy().to_string(),
    );

    // 6. Build product automaton.
    let relation = RefinementRelation::new(mapping);
    let product =
        build_product(&concrete_ta, &abstract_ta, &relation).map_err(|e| miette::miette!("{e}"))?;

    // 7. Run solver.
    let mut solver = Z3Solver::with_timeout_secs(timeout_secs);
    let result = run_refinement_solver(&mut solver, &product, depth)
        .map_err(|e| miette::miette!("solver error: {e}"))?;

    // 8. Build structured report.
    let report = build_report(
        concrete_path,
        &abstract_path,
        depth,
        timeout_secs,
        &product,
        &result,
    );

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
            println!("{json}");
        }
        _ => {
            println!("Refinement Check Report");
            println!("=======================");
            println!("Concrete: {}", report.concrete);
            println!("Abstract: {}", report.abstract_path);
            println!("Depth:    {}", report.depth);
            println!("Timeout:  {}s", report.timeout_secs);
            println!();
            println!("Product automaton:");
            println!("  Locations:  {}", report.product_locations);
            println!("  Rules:      {}", report.product_rules);
            println!("  Mismatches: {}", report.mismatch_locations);
            println!();
            match &result {
                SimulationCheckResult::SimulationHolds { .. } => {
                    if product.mismatch_locations.is_empty() {
                        println!("Result: SIMULATION TRIVIALLY HOLDS (no mismatch locations)");
                    } else {
                        println!("Result: SIMULATION HOLDS (no mismatch reachable within depth {depth})");
                    }
                }
                SimulationCheckResult::SimulationViolated {
                    violation_step,
                    mismatch_location,
                    witness,
                    ..
                } => {
                    println!("Result: SIMULATION VIOLATED");
                    println!("  Violation at step {violation_step}");
                    println!(
                        "  Mismatch location: concrete={}, abstract={}",
                        mismatch_location.concrete.as_usize(),
                        mismatch_location.abstract_loc.as_usize()
                    );
                    if let Some(w) = witness {
                        println!();
                        super::witness_format::print_witness_text(w, &product);
                    }
                }
                SimulationCheckResult::Unknown { reason, .. } => {
                    println!("Result: UNKNOWN ({reason})");
                }
            }
        }
    }

    // Exit with appropriate code: 0=holds, 1=violated, 2=unknown
    match &result {
        SimulationCheckResult::SimulationHolds { .. } => Ok(()),
        SimulationCheckResult::SimulationViolated { .. } => process::exit(1),
        SimulationCheckResult::Unknown { .. } => process::exit(2),
    }
}

/// Build a structured report from the solver result.
fn build_report(
    concrete_path: &Path,
    abstract_path: &Path,
    depth: usize,
    timeout_secs: u64,
    product: &tarsier_ir::product::ProductAutomaton,
    result: &SimulationCheckResult,
) -> RefinementReport {
    let mut report = RefinementReport {
        schema_version: SCHEMA_VERSION,
        concrete: concrete_path.display().to_string(),
        abstract_path: abstract_path.display().to_string(),
        depth,
        timeout_secs,
        product_locations: product.num_locations(),
        product_rules: product.num_rules(),
        mismatch_locations: product.mismatch_locations.len(),
        result: String::new(),
        violation_step: None,
        violation_detail: None,
        unknown_reason: None,
        witness: None,
    };

    match result {
        SimulationCheckResult::SimulationHolds { .. } => {
            report.result = if product.mismatch_locations.is_empty() {
                "trivially_holds".into()
            } else {
                "simulation_holds".into()
            };
        }
        SimulationCheckResult::SimulationViolated {
            violation_step,
            mismatch_location,
            witness,
            ..
        } => {
            report.result = "simulation_violated".into();
            report.violation_step = Some(*violation_step);
            report.violation_detail = Some(ViolationDetail {
                concrete_location: mismatch_location.concrete.as_usize(),
                abstract_location: mismatch_location.abstract_loc.as_usize(),
            });
            if let Some(w) = witness {
                report.witness = Some(super::witness_format::witness_to_json(w, product));
            }
        }
        SimulationCheckResult::Unknown { reason, .. } => {
            report.result = "unknown".into();
            report.unknown_reason = Some(reason.clone());
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_holds_report() -> RefinementReport {
        RefinementReport {
            schema_version: SCHEMA_VERSION,
            concrete: "concrete.trs".into(),
            abstract_path: "abstract.trs".into(),
            depth: 10,
            timeout_secs: 60,
            product_locations: 4,
            product_rules: 3,
            mismatch_locations: 0,
            result: "trivially_holds".into(),
            violation_step: None,
            violation_detail: None,
            unknown_reason: None,
            witness: None,
        }
    }

    #[test]
    fn schema_version_is_current() {
        assert_eq!(SCHEMA_VERSION, 3);
    }

    #[test]
    fn report_serializes_holds() {
        let report = sample_holds_report();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 3);
        assert_eq!(json["result"], "trivially_holds");
        assert_eq!(json["abstract"], "abstract.trs");
        assert!(json.get("violation_step").is_none());
        assert!(json.get("violation_detail").is_none());
        assert!(json.get("unknown_reason").is_none());
        assert!(json.get("witness").is_none());
    }

    #[test]
    fn report_serializes_violated() {
        let report = RefinementReport {
            result: "simulation_violated".into(),
            violation_step: Some(3),
            violation_detail: Some(ViolationDetail {
                concrete_location: 1,
                abstract_location: 2,
            }),
            ..sample_holds_report()
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["result"], "simulation_violated");
        assert_eq!(json["violation_step"], 3);
        assert_eq!(json["violation_detail"]["concrete_location"], 1);
        assert_eq!(json["violation_detail"]["abstract_location"], 2);
    }

    #[test]
    fn report_serializes_unknown() {
        let report = RefinementReport {
            result: "unknown".into(),
            unknown_reason: Some("timeout".into()),
            ..sample_holds_report()
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["result"], "unknown");
        assert_eq!(json["unknown_reason"], "timeout");
    }

    #[test]
    fn report_has_required_fields() {
        let report = sample_holds_report();
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        for field in &[
            "schema_version",
            "concrete",
            "abstract",
            "depth",
            "timeout_secs",
            "product_locations",
            "product_rules",
            "mismatch_locations",
            "result",
        ] {
            assert!(obj.contains_key(*field), "missing required field: {field}");
        }
    }

    #[test]
    fn report_omits_none_fields() {
        let report = sample_holds_report();
        let json_str = serde_json::to_string(&report).unwrap();
        assert!(!json_str.contains("violation_step"));
        assert!(!json_str.contains("violation_detail"));
        assert!(!json_str.contains("unknown_reason"));
        assert!(!json_str.contains("witness"));
    }

    #[test]
    fn violation_detail_structured() {
        let detail = ViolationDetail {
            concrete_location: 5,
            abstract_location: 3,
        };
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["concrete_location"], 5);
        assert_eq!(json["abstract_location"], 3);
    }
}

/// Auto-map concrete locations/variables to abstract by name matching.
fn build_auto_mapping(
    concrete: &tarsier_ir::threshold_automaton::ThresholdAutomaton,
    abstract_ta: &tarsier_ir::threshold_automaton::ThresholdAutomaton,
    abstract_path: String,
) -> RefinementMapping {
    let mut mapping = RefinementMapping::new(abstract_path);

    for (c_idx, c_loc) in concrete.locations.iter().enumerate() {
        let c_id = tarsier_ir::threshold_automaton::LocationId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_location_by_name(&c_loc.name) {
            mapping.map_location(c_id, a_id);
        } else {
            mapping.mark_location_internal(c_id);
        }
    }

    for (c_idx, c_var) in concrete.shared_vars.iter().enumerate() {
        let c_id = tarsier_ir::threshold_automaton::SharedVarId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_shared_var_by_name(&c_var.name) {
            mapping.map_variable(c_id, a_id);
        } else {
            mapping.mark_variable_internal(c_id);
        }
    }

    mapping
}
