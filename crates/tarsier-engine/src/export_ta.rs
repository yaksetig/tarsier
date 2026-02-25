//! Export a `ThresholdAutomaton` in ByMC `.ta` format.
//!
//! The ByMC (Byzantine Model Checker) tool operates on threshold automata
//! specified in a custom `.ta` text format. This module converts Tarsier's
//! internal representation into that format for cross-tool comparison.

use tarsier_ir::properties::{extract_agreement_property, SafetyProperty};
use tarsier_ir::threshold_automaton::{
    CmpOp, GuardAtom, LinearCombination, ThresholdAutomaton, UpdateKind,
};

/// Convert a `ThresholdAutomaton` into ByMC `.ta` format text.
///
/// Automatically extracts the agreement property from the automaton and
/// encodes it in the specifications section.
pub fn export_ta(ta: &ThresholdAutomaton) -> String {
    let prop = extract_agreement_property(ta);
    export_ta_with_property(ta, Some(&prop))
}

/// Convert a `ThresholdAutomaton` into ByMC `.ta` format text with an
/// explicit safety property for the specifications section.
pub fn export_ta_with_property(ta: &ThresholdAutomaton, prop: Option<&SafetyProperty>) -> String {
    let mut out = String::new();

    // Skeleton header — use first role name or "Proc"
    let skel_name = ta
        .locations
        .first()
        .map(|l| l.role.as_str())
        .unwrap_or("Proc");
    out.push_str(&format!("skel {skel_name} {{\n"));

    // Local variable (pc)
    out.push_str("  local pc;\n");

    // Shared variables
    if !ta.shared_vars.is_empty() {
        let names: Vec<String> = ta
            .shared_vars
            .iter()
            .map(|v| sanitize_name(&v.name))
            .collect();
        out.push_str(&format!("  shared {};\n", names.join(", ")));
    }

    // Parameters
    if !ta.parameters.is_empty() {
        let names: Vec<String> = ta
            .parameters
            .iter()
            .map(|p| p.name.to_uppercase())
            .collect();
        out.push_str(&format!("  parameters {};\n", names.join(", ")));
    }

    // Assumptions (resilience condition)
    if let Some(ref rc) = ta.resilience_condition {
        let lhs = format_lc_bymc(&rc.lhs, ta);
        let rhs = format_lc_bymc(&rc.rhs, ta);
        let op = format_cmp_op(rc.op);
        out.push_str(&format!("  assumptions (1) {{ {lhs} {op} {rhs}; }}\n"));
    }

    // Locations
    let nlocs = ta.locations.len();
    let loc_entries: Vec<String> = ta
        .locations
        .iter()
        .enumerate()
        .map(|(i, _loc)| format!("loc{i}: [{i}]"))
        .collect();
    out.push_str(&format!(
        "  locations ({nlocs}) {{ {}; }}\n",
        loc_entries.join("; ")
    ));

    // Initial conditions
    let mut init_parts: Vec<String> = Vec::new();
    // Sum of initial locations == N (or all processes)
    if !ta.initial_locations.is_empty() {
        let init_locs: Vec<String> = ta
            .initial_locations
            .iter()
            .map(|&id| format!("loc{id}"))
            .collect();
        let n_param = ta
            .find_param_by_name("n")
            .map(|_| "N".to_string())
            .unwrap_or_else(|| "N".to_string());
        if init_locs.len() == 1 {
            init_parts.push(format!("{} == {n_param}", init_locs[0]));
        } else {
            init_parts.push(format!("({}) == {n_param}", init_locs.join(" + ")));
        }
    }
    // Non-initial locations start at 0
    for (i, _) in ta.locations.iter().enumerate() {
        if !ta.initial_locations.contains(&i) {
            init_parts.push(format!("loc{i} == 0"));
        }
    }
    // Shared vars start at 0
    for sv in &ta.shared_vars {
        init_parts.push(format!("{} == 0", sanitize_name(&sv.name)));
    }
    let ninits = init_parts.len();
    out.push_str(&format!(
        "  inits ({ninits}) {{ {}; }}\n",
        init_parts.join("; ")
    ));

    // Rules
    let nrules = ta.rules.len();
    let mut rule_lines: Vec<String> = Vec::new();
    for (i, rule) in ta.rules.iter().enumerate() {
        let guard_str = format_guard_bymc(&rule.guard.atoms, ta);
        let mut updates: Vec<String> = Vec::new();
        // For each shared var, either it's updated by this rule or unchanged
        for (sv_id, sv) in ta.shared_vars.iter().enumerate() {
            let sv_name = sanitize_name(&sv.name);
            if let Some(upd) = rule.updates.iter().find(|u| u.var == sv_id) {
                match &upd.kind {
                    UpdateKind::Increment => {
                        updates.push(format!("{sv_name}' == {sv_name} + 1"));
                    }
                    UpdateKind::Set(lc) => {
                        updates.push(format!("{sv_name}' == {}", format_lc_bymc(lc, ta)));
                    }
                }
            } else {
                updates.push(format!("{sv_name}' == {sv_name}"));
            }
        }
        let when_str = if guard_str.is_empty() {
            String::new()
        } else {
            format!(" when ({guard_str})")
        };
        let do_str = if updates.is_empty() {
            String::new()
        } else {
            format!(" do {{ {}; }}", updates.join("; "))
        };
        rule_lines.push(format!(
            "    {i}: loc{} -> loc{}{when_str}{do_str};",
            rule.from, rule.to
        ));
    }
    out.push_str(&format!("  rules ({nrules}) {{\n"));
    for line in &rule_lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("  }\n");

    // Specifications — encode the safety property
    emit_specifications(&mut out, prop, ta);

    out.push_str("}\n");
    out
}

/// Emit the `specifications` block for the `.ta` output.
fn emit_specifications(out: &mut String, prop: Option<&SafetyProperty>, ta: &ThresholdAutomaton) {
    match prop {
        Some(SafetyProperty::Agreement { conflicting_pairs }) => {
            if conflicting_pairs.is_empty() {
                // Single decision value — trivially safe.
                // Find decided locations and emit stability spec.
                let decided_locs: Vec<usize> = ta
                    .locations
                    .iter()
                    .enumerate()
                    .filter(|(_, loc)| {
                        loc.local_vars.get("decided")
                            == Some(&tarsier_ir::threshold_automaton::LocalValue::Bool(true))
                    })
                    .map(|(id, _)| id)
                    .collect();
                if decided_locs.is_empty() {
                    out.push_str("  specifications (0) {\n");
                    out.push_str("    /* no decided locations found */\n");
                    out.push_str("  }\n");
                } else {
                    out.push_str(&format!("  specifications ({}) {{\n", decided_locs.len()));
                    for &loc in &decided_locs {
                        out.push_str(&format!(
                            "    agreement: [](loc{loc} > 0 -> [](loc{loc} > 0));\n"
                        ));
                    }
                    out.push_str("  }\n");
                }
            } else {
                // Multiple decision values — emit mutual exclusion specs.
                out.push_str(&format!(
                    "  specifications ({}) {{\n",
                    conflicting_pairs.len()
                ));
                for &(a, b) in conflicting_pairs {
                    out.push_str(&format!(
                        "    agreement: []((loc{a} > 0 && loc{b} > 0) -> false);\n"
                    ));
                }
                out.push_str("  }\n");
            }
        }
        Some(SafetyProperty::Invariant { bad_sets }) => {
            out.push_str(&format!("  specifications ({}) {{\n", bad_sets.len()));
            for (i, bad_set) in bad_sets.iter().enumerate() {
                let conds: Vec<String> =
                    bad_set.iter().map(|&loc| format!("loc{loc} > 0")).collect();
                out.push_str(&format!(
                    "    invariant_{i}: [](({}) -> false);\n",
                    conds.join(" && ")
                ));
            }
            out.push_str("  }\n");
        }
        Some(SafetyProperty::Termination { .. }) => {
            out.push_str(
                "  /* unsupported: Termination properties cannot be encoded in ByMC .ta specifications */\n",
            );
            out.push_str("  specifications (0) {\n");
            out.push_str("  }\n");
        }
        None => {
            out.push_str("  /* no property provided */\n");
            out.push_str("  specifications (0) {\n");
            out.push_str("  }\n");
        }
    }
}

/// Sanitize a Tarsier shared-var name for ByMC (replace @ and [] with _).
#[allow(clippy::collapsible_str_replace)]
fn sanitize_name(name: &str) -> String {
    name.replace('@', "_at_")
        .replace('[', "_")
        .replace(']', "_")
        .replace('=', "_eq_")
        .replace(',', "_")
        .replace(' ', "")
}

/// Format a `LinearCombination` in ByMC syntax with uppercase parameter names.
fn format_lc_bymc(lc: &LinearCombination, ta: &ThresholdAutomaton) -> String {
    if lc.terms.is_empty() {
        return lc.constant.to_string();
    }

    let mut parts: Vec<String> = Vec::new();
    let mut first = true;

    if lc.constant != 0 {
        parts.push(lc.constant.to_string());
        first = false;
    }

    for &(coeff, pid) in &lc.terms {
        if coeff == 0 {
            continue;
        }
        let pname = ta
            .parameters
            .get(pid)
            .map(|p| p.name.to_uppercase())
            .unwrap_or_else(|| format!("P{pid}"));
        if first {
            if coeff == 1 {
                parts.push(pname);
            } else if coeff == -1 {
                parts.push(format!("-{pname}"));
            } else {
                parts.push(format!("{coeff}*{pname}"));
            }
            first = false;
        } else if coeff > 0 {
            if coeff == 1 {
                parts.push(format!("+ {pname}"));
            } else {
                parts.push(format!("+ {coeff}*{pname}"));
            }
        } else if coeff == -1 {
            parts.push(format!("- {pname}"));
        } else {
            parts.push(format!("- {}*{pname}", -coeff));
        }
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        parts.join(" ")
    }
}

/// Format a comparison operator.
fn format_cmp_op(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Ge => ">=",
        CmpOp::Le => "<=",
        CmpOp::Gt => ">",
        CmpOp::Lt => "<",
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
    }
}

/// Format guard atoms as ByMC guard expression.
fn format_guard_bymc(atoms: &[GuardAtom], ta: &ThresholdAutomaton) -> String {
    let parts: Vec<String> = atoms
        .iter()
        .map(|atom| match atom {
            GuardAtom::Threshold {
                vars,
                op,
                bound,
                distinct: _,
            } => {
                let lhs = if vars.is_empty() {
                    "0".to_string()
                } else {
                    vars.iter()
                        .map(|&v| sanitize_name(&ta.shared_vars[v].name))
                        .collect::<Vec<_>>()
                        .join(" + ")
                };
                let rhs = format_lc_bymc(bound, ta);
                format!("{lhs} {} {rhs}", format_cmp_op(*op))
            }
        })
        .collect();
    parts.join(" && ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_and_export(trs_source: &str) -> String {
        let program = tarsier_dsl::parse(trs_source, "test.trs").expect("parse failed");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
        export_ta(&ta)
    }

    #[test]
    fn export_reliable_broadcast_structural() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        // Structural checks
        assert!(output.contains("skel"), "missing skel keyword");
        assert!(output.contains("local pc;"), "missing local pc");
        assert!(output.contains("shared "), "missing shared vars");
        assert!(output.contains("parameters "), "missing parameters");
        assert!(output.contains("assumptions"), "missing assumptions");
        assert!(output.contains("locations"), "missing locations");
        assert!(output.contains("inits"), "missing inits");
        assert!(output.contains("rules"), "missing rules");
        assert!(output.contains("->"), "missing rule transitions");
    }

    #[test]
    fn export_pbft_structural() {
        let source = include_str!("../../../examples/library/pbft_simple_safe.trs");
        let output = load_and_export(source);

        assert!(output.contains("skel"), "missing skel keyword");
        assert!(output.contains("parameters "), "missing parameters");
        assert!(output.contains("locations"), "missing locations");
        assert!(output.contains("rules"), "missing rules");
    }

    #[test]
    fn export_buggy_rb_structural() {
        let source = include_str!("../../../examples/library/reliable_broadcast_buggy.trs");
        let output = load_and_export(source);

        assert!(output.contains("skel"), "missing skel keyword");
        assert!(output.contains("rules"), "missing rules");
        // Buggy has weaker thresholds (t+1 instead of 2t+1)
        assert!(output.contains("->"), "missing transitions");
    }

    #[test]
    fn exported_ta_has_balanced_braces() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        let opens = output.chars().filter(|&c| c == '{').count();
        let closes = output.chars().filter(|&c| c == '}').count();
        assert_eq!(opens, closes, "unbalanced braces in .ta output");
    }

    #[test]
    fn uppercase_parameters() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        // Parameters should be uppercased in ByMC format
        assert!(
            output.contains("N") && output.contains("T") && output.contains("F"),
            "parameters not uppercased"
        );
    }

    // T1-TEST-1: Golden tests for .ta export property content

    #[test]
    fn export_includes_agreement_spec_safe() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        // Safe RB should have non-empty specifications (stability or mutual exclusion)
        assert!(
            !output.contains("specifications (0)"),
            "safe RB should not have empty specifications (0):\n{output}"
        );
        assert!(
            output.contains("specifications ("),
            "missing specifications section in safe RB"
        );
        assert!(
            output.contains("agreement:"),
            "missing agreement label in safe RB"
        );
        assert!(
            output.contains("[]"),
            "missing temporal operator [] in safe RB"
        );
    }

    #[test]
    fn export_includes_agreement_spec_buggy() {
        let source = include_str!("../../../examples/library/reliable_broadcast_buggy.trs");
        let output = load_and_export(source);

        // Buggy RB has conflicting pairs → mutual exclusion
        assert!(
            output.contains("-> false"),
            "missing mutual exclusion (-> false) in buggy RB:\n{output}"
        );
        assert!(
            output.contains("agreement:"),
            "missing agreement label in buggy RB:\n{output}"
        );
    }

    #[test]
    fn export_includes_guards_and_updates() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        assert!(
            output.contains("when ("),
            "missing guard 'when (' in output:\n{output}"
        );
        assert!(
            output.contains("do {"),
            "missing update 'do {{' in output:\n{output}"
        );
        assert!(
            output.contains("' =="),
            "missing primed variable assignment in output:\n{output}"
        );
    }

    #[test]
    fn export_includes_assumptions_invariant() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let output = load_and_export(source);

        assert!(
            output.contains("assumptions"),
            "missing assumptions section:\n{output}"
        );
        // Resilience condition should be an inequality
        assert!(
            output.contains(">") || output.contains(">="),
            "missing inequality in assumptions:\n{output}"
        );
    }

    #[test]
    fn export_ta_with_no_property() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
        let output = export_ta_with_property(&ta, None);

        assert!(
            output.contains("specifications (0)"),
            "None property should produce specifications (0):\n{output}"
        );
        assert!(
            output.contains("no property provided"),
            "None property should have explanatory comment:\n{output}"
        );
    }
}
