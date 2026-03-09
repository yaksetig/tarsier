//! `infer-invariants` CLI command handler.
//!
//! Parses a protocol, generates candidate invariant predicates, checks their
//! inductiveness (init + consecution), and reports the results.

use std::path::Path;

use serde_json::json;
use tarsier_dsl::parser::parse;
use tarsier_engine::pipeline::verification::{
    generate_linear_predicate_candidates, score_candidates, InductivenessResult,
};
use tarsier_ir::abstraction::abstract_to_counter_system;
use tarsier_ir::lowering::lower;
use tarsier_ir::properties::extract_agreement_property;
use tarsier_smt::backends::z3_backend::Z3Solver;

/// Run the infer-invariants command.
pub(crate) fn run_infer_invariants(
    file: &Path,
    solver_name: &str,
    depth: usize,
    timeout: u64,
    format: &str,
) -> miette::Result<()> {
    // 1. Parse protocol.
    let src =
        std::fs::read_to_string(file).map_err(|e| miette::miette!("read protocol: {e}"))?;
    let filename = file.display().to_string();
    let ast = parse(&src, &filename).map_err(|e| miette::miette!("parse: {e}"))?;

    // 2. Lower to IR.
    let ta = lower(&ast).map_err(|e| miette::miette!("lower: {e}"))?;

    // 3. Extract property and build counter system.
    let property = extract_agreement_property(&ta);
    let cs = abstract_to_counter_system(ta.clone());

    // 4. Generate candidates.
    let candidates = generate_linear_predicate_candidates(&ta, &property, None);
    if candidates.is_empty() {
        match format {
            "json" => println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "protocol": filename,
                    "candidates": 0,
                    "inductive": [],
                    "init_only": [],
                    "result": "no_candidates"
                })
            ),
            _ => {
                println!("Invariant Inference Report");
                println!("=========================");
                println!("Protocol: {filename}");
                println!();
                println!("No candidate predicates generated.");
            }
        }
        return Ok(());
    }

    // 5. Score candidates using SMT solver.
    let results = match solver_name {
        "z3" => {
            let mut solver = Z3Solver::with_timeout_secs(timeout);
            score_candidates(&mut solver, &cs, &candidates, &[])
                .map_err(|e| miette::miette!("solver: {e}"))?
        }
        "cvc5" => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(timeout)
                .map_err(|e| miette::miette!("solver: {e}"))?;
            score_candidates(&mut solver, &cs, &candidates, &[])
                .map_err(|e| miette::miette!("solver: {e}"))?
        }
        other => {
            return Err(miette::miette!(
                "Unknown solver: {other}. Use 'z3' or 'cvc5'."
            ));
        }
    };

    // 6. Partition results.
    let inductive: Vec<&InductivenessResult> =
        results.iter().filter(|r| r.score == 2).collect();
    let init_only: Vec<&InductivenessResult> =
        results.iter().filter(|r| r.score == 1).collect();

    // 7. Report.
    match format {
        "json" => print_json_report(&filename, depth, &inductive, &init_only, &results),
        _ => print_text_report(&filename, depth, &inductive, &init_only, &results),
    }

    Ok(())
}

fn print_text_report(
    filename: &str,
    _depth: usize,
    inductive: &[&InductivenessResult],
    init_only: &[&InductivenessResult],
    all: &[InductivenessResult],
) {
    println!("Invariant Inference Report");
    println!("=========================");
    println!("Protocol:   {filename}");
    println!("Candidates: {}", all.len());
    println!("Inductive:  {}", inductive.len());
    println!("Init-only:  {}", init_only.len());
    println!();

    if !inductive.is_empty() {
        println!("Fully Inductive Predicates (init + consecution):");
        for r in inductive {
            println!("  [INDUCTIVE] {}", r.candidate.label);
        }
        println!();
    }

    if !init_only.is_empty() {
        println!("Init-Only Predicates (hold at init but not preserved):");
        for r in init_only {
            println!("  [INIT-ONLY] {}", r.candidate.label);
        }
        println!();
    }

    if inductive.is_empty() {
        println!("Result: NO INDUCTIVE INVARIANTS FOUND");
    } else {
        println!(
            "Result: {} inductive invariant(s) discovered",
            inductive.len()
        );
    }
}

fn print_json_report(
    filename: &str,
    _depth: usize,
    inductive: &[&InductivenessResult],
    init_only: &[&InductivenessResult],
    all: &[InductivenessResult],
) {
    let inductive_labels: Vec<&str> = inductive.iter().map(|r| r.candidate.label.as_str()).collect();
    let init_only_labels: Vec<&str> = init_only.iter().map(|r| r.candidate.label.as_str()).collect();
    let result = if inductive.is_empty() {
        "no_inductive_invariants"
    } else {
        "inductive_invariants_found"
    };
    println!(
        "{}",
        json!({
            "schema_version": 1,
            "protocol": filename,
            "candidates": all.len(),
            "inductive": inductive_labels,
            "init_only": init_only_labels,
            "result": result,
        })
    );
}
