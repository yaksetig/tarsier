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
    let base_report = json!({
        "schema_version": 2,
        "concrete": concrete_path.display().to_string(),
        "abstract": abstract_path.display().to_string(),
        "depth": depth,
        "product_locations": product.num_locations(),
        "product_rules": product.num_rules(),
        "mismatch_locations": product.mismatch_locations.len(),
    });

    match format {
        "json" => {
            let mut report = base_report;
            match &result {
                SimulationCheckResult::SimulationHolds { .. } => {
                    report["result"] = json!(if product.mismatch_locations.is_empty() {
                        "trivially_holds"
                    } else {
                        "simulation_holds"
                    });
                }
                SimulationCheckResult::SimulationViolated {
                    violation_step,
                    mismatch_location,
                    witness,
                    ..
                } => {
                    report["result"] = json!("simulation_violated");
                    report["violation_step"] = json!(violation_step);
                    report["violation_detail"] = json!(format!(
                        "concrete={}, abstract={}",
                        mismatch_location.concrete.as_usize(),
                        mismatch_location.abstract_loc.as_usize()
                    ));
                    if let Some(w) = witness {
                        report["witness"] = witness_to_json(w, &product);
                    }
                }
                SimulationCheckResult::Unknown { reason, .. } => {
                    report["result"] = json!(format!("unknown: {reason}"));
                }
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
                        print_witness_text(w, &product);
                    }
                }
                SimulationCheckResult::Unknown { reason, .. } => {
                    println!("Result: UNKNOWN ({reason})");
                }
            }
        }
    }

    Ok(())
}

/// Convert a witness to JSON for structured output.
fn witness_to_json(
    witness: &tarsier_smt::refinement_encoder::RefinementWitness,
    product: &tarsier_ir::product::ProductAutomaton,
) -> serde_json::Value {
    let params: Vec<serde_json::Value> = witness
        .parameter_values
        .iter()
        .map(|(idx, val)| {
            let name = product
                .parameters
                .get(*idx)
                .map(|p| p.name.as_str())
                .unwrap_or("?");
            json!({"index": idx, "name": name, "value": val})
        })
        .collect();

    let steps: Vec<serde_json::Value> = witness
        .trace
        .iter()
        .map(|step| {
            let locs: Vec<serde_json::Value> = step
                .location_counters
                .iter()
                .map(|(loc, count)| {
                    json!({
                        "concrete": loc.concrete.as_usize(),
                        "abstract": loc.abstract_loc.as_usize(),
                        "count": count,
                    })
                })
                .collect();

            let vars: Vec<serde_json::Value> = step
                .shared_var_values
                .iter()
                .map(|(idx, val)| {
                    let name = product
                        .shared_vars
                        .get(*idx)
                        .map(|v| v.name.as_str())
                        .unwrap_or("?");
                    json!({"index": idx, "name": name, "value": val})
                })
                .collect();

            let firings: Vec<serde_json::Value> = step
                .rule_firings
                .iter()
                .map(|(idx, count)| json!({"rule": idx, "count": count}))
                .collect();

            json!({
                "step": step.step,
                "occupied_locations": locs,
                "shared_vars": vars,
                "rule_firings": firings,
            })
        })
        .collect();

    json!({
        "parameters": params,
        "trace": steps,
    })
}

/// Print a witness trace in human-readable text format.
fn print_witness_text(
    witness: &tarsier_smt::refinement_encoder::RefinementWitness,
    product: &tarsier_ir::product::ProductAutomaton,
) {
    println!("Witness Trace");
    println!("-------------");

    if !witness.parameter_values.is_empty() {
        print!("  Parameters: ");
        for (i, (idx, val)) in witness.parameter_values.iter().enumerate() {
            let name = product
                .parameters
                .get(*idx)
                .map(|p| p.name.as_str())
                .unwrap_or("?");
            if i > 0 {
                print!(", ");
            }
            print!("{name}={val}");
        }
        println!();
    }

    for step in &witness.trace {
        println!();
        println!("  Step {}:", step.step);

        if !step.location_counters.is_empty() {
            print!("    Occupied: ");
            for (i, (loc, count)) in step.location_counters.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!(
                    "(c={}, a={})×{}",
                    loc.concrete.as_usize(),
                    loc.abstract_loc.as_usize(),
                    count
                );
            }
            println!();
        }

        if !step.shared_var_values.is_empty() {
            print!("    Vars: ");
            for (i, (idx, val)) in step.shared_var_values.iter().enumerate() {
                let name = product
                    .shared_vars
                    .get(*idx)
                    .map(|v| v.name.as_str())
                    .unwrap_or("?");
                if i > 0 {
                    print!(", ");
                }
                print!("{name}={val}");
            }
            println!();
        }

        if !step.rule_firings.is_empty() {
            print!("    Rules fired: ");
            for (i, (idx, count)) in step.rule_firings.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("r{idx}×{count}");
            }
            println!();
        }
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
