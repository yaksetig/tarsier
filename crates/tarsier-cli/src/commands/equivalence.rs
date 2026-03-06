//! `equivalence-check` CLI command handler.
//!
//! Parses two protocols, builds bidirectional product automata, and reports
//! whether they are behaviorally equivalent (within the bounded depth).

use std::path::Path;

use tarsier_dsl::parser::parse;
use tarsier_ir::equivalence::build_equivalence_products;
use tarsier_ir::lowering::lower;

/// Run the equivalence-check command.
pub(crate) fn run_equivalence_check(
    file_a: &Path,
    file_b: &Path,
    depth: usize,
    format: &str,
) -> miette::Result<()> {
    // 1. Parse both protocols.
    let src_a = std::fs::read_to_string(file_a)
        .map_err(|e| miette::miette!("read protocol A: {e}"))?;
    let src_b = std::fs::read_to_string(file_b)
        .map_err(|e| miette::miette!("read protocol B: {e}"))?;

    let name_a = file_a.display().to_string();
    let name_b = file_b.display().to_string();

    let ast_a = parse(&src_a, &name_a).map_err(|e| miette::miette!("parse A: {e}"))?;
    let ast_b = parse(&src_b, &name_b).map_err(|e| miette::miette!("parse B: {e}"))?;

    // 2. Lower both to IR.
    let ta_a = lower(&ast_a).map_err(|e| miette::miette!("lower A: {e}"))?;
    let ta_b = lower(&ast_b).map_err(|e| miette::miette!("lower B: {e}"))?;

    // 3. Build bidirectional products.
    let products = build_equivalence_products(&ta_a, &ta_b)
        .map_err(|e| miette::miette!("{e}"))?;

    // 4. Report.
    let trivial = products.is_trivially_equivalent();
    let fwd_mismatches = products.forward.mismatch_locations.len();
    let bwd_mismatches = products.backward.mismatch_locations.len();

    match format {
        "json" => {
            let result_str = if trivial {
                "trivially_equivalent"
            } else {
                "encoding_ready"
            };
            println!(
                r#"{{"protocol_a":"{}","protocol_b":"{}","depth":{},"forward_product_locations":{},"forward_product_rules":{},"forward_mismatches":{},"backward_product_locations":{},"backward_product_rules":{},"backward_mismatches":{},"result":"{}"}}"#,
                file_a.display(),
                file_b.display(),
                depth,
                products.forward.num_locations(),
                products.forward.num_rules(),
                fwd_mismatches,
                products.backward.num_locations(),
                products.backward.num_rules(),
                bwd_mismatches,
                result_str,
            );
        }
        _ => {
            println!("Equivalence Check Report");
            println!("========================");
            println!("Protocol A: {}", file_a.display());
            println!("Protocol B: {}", file_b.display());
            println!("Depth:      {depth}");
            println!();
            println!("Forward (A → B):");
            println!("  Product locations: {}", products.forward.num_locations());
            println!("  Product rules:     {}", products.forward.num_rules());
            println!("  Mismatches:        {fwd_mismatches}");
            println!();
            println!("Backward (B → A):");
            println!("  Product locations: {}", products.backward.num_locations());
            println!("  Product rules:     {}", products.backward.num_rules());
            println!("  Mismatches:        {bwd_mismatches}");
            println!();
            if trivial {
                println!("Result: TRIVIALLY EQUIVALENT (no mismatch locations in either direction)");
            } else {
                println!(
                    "Result: ENCODING READY ({} total mismatches, depth {})",
                    products.total_mismatches(),
                    depth
                );
                println!("  (Full solver integration pending engine wiring)");
            }
        }
    }

    Ok(())
}
