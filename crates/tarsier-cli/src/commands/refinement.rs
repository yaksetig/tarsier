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
    let concrete_ast = parse(&concrete_src, &filename)
        .map_err(|e| miette::miette!("parse concrete: {e}"))?;

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
    let abstract_ast = parse(&abstract_src, &abs_filename)
        .map_err(|e| miette::miette!("parse abstract: {e}"))?;

    // 4. Lower both to IR.
    let concrete_ta =
        lower(&concrete_ast).map_err(|e| miette::miette!("lower concrete: {e}"))?;
    let abstract_ta =
        lower(&abstract_ast).map_err(|e| miette::miette!("lower abstract: {e}"))?;

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

    // 7. Report.
    match format {
        "json" => {
            let result_str = if product.mismatch_locations.is_empty() {
                "trivially_holds"
            } else {
                "encoding_ready"
            };
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "concrete": concrete_path.display().to_string(),
                    "abstract": abstract_path.display().to_string(),
                    "depth": depth,
                    "product_locations": product.num_locations(),
                    "product_rules": product.num_rules(),
                    "mismatch_locations": product.mismatch_locations.len(),
                    "result": result_str,
                })
            );
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
            if product.mismatch_locations.is_empty() {
                println!("Result: SIMULATION TRIVIALLY HOLDS (no mismatch locations)");
            } else {
                println!(
                    "Result: ENCODING READY ({} mismatch locations, depth {})",
                    product.mismatch_locations.len(),
                    depth
                );
                println!("  (Full solver integration pending engine wiring)");
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
