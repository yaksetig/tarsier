//! `refinement-check` CLI command handler.
//!
//! Parses concrete and abstract protocols, builds the product automaton,
//! and reports the result. Full solver integration is deferred to engine wiring.

use std::path::Path;

use serde_json::json;
use tarsier_dsl::parser::parse;
use tarsier_ir::lowering::lower;
use tarsier_ir::product::build_product;
use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::refinement_encoder::{run_refinement_solver, SimulationCheckResult};

/// Run the refinement-check command.
pub(crate) fn run_refinement_check(
    concrete_path: &Path,
    abstract_path_override: Option<&Path>,
    depth: usize,
    format: &str,
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
    let mut solver = Z3Solver::with_timeout_secs(60);
    let result = run_refinement_solver(&mut solver, &product, depth)
        .map_err(|e| miette::miette!("solver error: {e}"))?;

    // 8. Report.
    let (result_str, violation_step, violation_detail) = match &result {
        SimulationCheckResult::SimulationHolds { .. } => {
            if product.mismatch_locations.is_empty() {
                ("trivially_holds".to_string(), None, None)
            } else {
                ("simulation_holds".to_string(), None, None)
            }
        }
        SimulationCheckResult::SimulationViolated {
            violation_step,
            mismatch_location,
            ..
        } => (
            "simulation_violated".to_string(),
            Some(*violation_step),
            Some(format!(
                "concrete={}, abstract={}",
                mismatch_location.concrete.as_usize(),
                mismatch_location.abstract_loc.as_usize()
            )),
        ),
        SimulationCheckResult::Unknown { reason, .. } => {
            (format!("unknown: {reason}"), None, None)
        }
    };

    match format {
        "json" => {
            let mut report = json!({
                "schema_version": 1,
                "concrete": concrete_path.display().to_string(),
                "abstract": abstract_path.display().to_string(),
                "depth": depth,
                "product_locations": product.num_locations(),
                "product_rules": product.num_rules(),
                "mismatch_locations": product.mismatch_locations.len(),
                "result": result_str,
            });
            if let Some(step) = violation_step {
                report["violation_step"] = json!(step);
            }
            if let Some(detail) = &violation_detail {
                report["violation_detail"] = json!(detail);
            }
            println!("{}", report);
        }
        _ => {
            println!("Refinement Check Report");
            println!("=======================");
            println!("Concrete: {}", concrete_path.display());
            println!("Abstract: {}", abstract_path.display());
            println!("Depth:    {depth}");
            println!();
            println!("Product automaton:");
            println!("  Locations:  {}", product.num_locations());
            println!("  Rules:      {}", product.num_rules());
            println!("  Mismatches: {}", product.mismatch_locations.len());
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
                    ..
                } => {
                    println!("Result: SIMULATION VIOLATED");
                    println!("  Violation at step {violation_step}");
                    println!(
                        "  Mismatch location: concrete={}, abstract={}",
                        mismatch_location.concrete.as_usize(),
                        mismatch_location.abstract_loc.as_usize()
                    );
                }
                SimulationCheckResult::Unknown { reason, .. } => {
                    println!("Result: UNKNOWN ({reason})");
                }
            }
        }
    }

    Ok(())
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
