//! Shared witness formatting utilities for refinement and equivalence commands.
//!
//! Provides JSON and text formatting for `RefinementWitness` traces, used by
//! both the refinement-check and equivalence-check CLI commands.

use serde_json::json;
use tarsier_ir::product::ProductAutomaton;
use tarsier_smt::refinement_encoder::RefinementWitness;

/// Convert the parameter values of a witness to JSON.
fn params_to_json(
    witness: &RefinementWitness,
    product: &ProductAutomaton,
) -> Vec<serde_json::Value> {
    witness
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
        .collect()
}

/// Convert the trace steps of a witness to JSON.
fn steps_to_json(
    witness: &RefinementWitness,
    product: &ProductAutomaton,
) -> Vec<serde_json::Value> {
    witness
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
        .collect()
}

/// Convert a witness to JSON with parameters and trace only (no violation metadata).
///
/// Used by the refinement-check command which stores violation info separately.
pub fn witness_to_json(
    witness: &RefinementWitness,
    product: &ProductAutomaton,
) -> serde_json::Value {
    json!({
        "parameters": params_to_json(witness, product),
        "trace": steps_to_json(witness, product),
    })
}

/// Convert a witness to JSON including violation_step and mismatch_location.
///
/// Used by the equivalence-check command which embeds violation info in the witness.
pub fn witness_to_json_with_violation(
    witness: &RefinementWitness,
    product: &ProductAutomaton,
) -> serde_json::Value {
    json!({
        "violation_step": witness.violation_step,
        "mismatch_location": {
            "concrete": witness.mismatch_location.concrete.as_usize(),
            "abstract": witness.mismatch_location.abstract_loc.as_usize(),
        },
        "parameters": params_to_json(witness, product),
        "trace": steps_to_json(witness, product),
    })
}

/// Print parameter values in human-readable text.
fn print_parameters(witness: &RefinementWitness, product: &ProductAutomaton) {
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
}

/// Print trace steps in human-readable text.
fn print_steps(witness: &RefinementWitness, product: &ProductAutomaton) {
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
                    "(c={}, a={})x{}",
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
                print!("r{idx}x{count}");
            }
            println!();
        }
    }
}

/// Print a witness trace in human-readable text (no direction header).
///
/// Used by the refinement-check command.
pub fn print_witness_text(witness: &RefinementWitness, product: &ProductAutomaton) {
    println!("Witness Trace");
    println!("-------------");
    print_parameters(witness, product);
    print_steps(witness, product);
}

/// Print a witness trace with a direction header and violation info.
///
/// Used by the equivalence-check command.
pub fn print_witness_text_with_direction(
    direction: &str,
    witness: &RefinementWitness,
    product: &ProductAutomaton,
) {
    println!("{direction} Witness Trace");
    println!("{}", "-".repeat(direction.len() + 14));
    println!(
        "  Violation at step {}, mismatch (c={}, a={})",
        witness.violation_step,
        witness.mismatch_location.concrete.as_usize(),
        witness.mismatch_location.abstract_loc.as_usize()
    );
    print_parameters(witness, product);
    print_steps(witness, product);
}
