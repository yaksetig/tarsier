//! Export a `ThresholdAutomaton` in ByMC `.ta` format.
//!
//! The ByMC (Byzantine Model Checker) tool operates on threshold automata
//! specified in a custom `.ta` text format. This module converts Tarsier's
//! internal representation into that format for cross-tool comparison.

use std::collections::{BTreeMap, HashMap};

use tarsier_dsl::ast;
use tarsier_ir::properties::{extract_agreement_property, SafetyProperty};
use tarsier_ir::threshold_automaton::{
    CmpOp, GuardAtom, LinearCombination, LocalValue, ThresholdAutomaton, UpdateKind,
};

/// Convert a `ThresholdAutomaton` into ByMC `.ta` format text.
///
/// Automatically extracts the agreement property from the automaton and
/// encodes it in the specifications section.
pub fn export_ta(ta: &ThresholdAutomaton) -> String {
    let prop = extract_agreement_property(ta);
    export_ta_with_property(ta, Some(&prop))
}

/// Convert a `ThresholdAutomaton` into ByMC `.ta` format text, selecting
/// the export property from the original program declarations.
///
/// Selection policy is delegated to `pipeline::property::select_ta_export_property`:
/// - safety property if declared;
/// - otherwise liveness (temporal and non-temporal) when representable;
/// - otherwise fallback to structural agreement.
pub fn export_ta_for_program(ta: &ThresholdAutomaton, program: &ast::Program) -> String {
    match crate::pipeline::property::select_ta_export_property(ta, program) {
        crate::pipeline::property::TaExportProperty::Safety(prop) => {
            export_ta_with_property(ta, Some(&prop))
        }
        crate::pipeline::property::TaExportProperty::Temporal {
            quantifiers,
            formula,
        } => match export_ta_with_temporal_liveness(ta, &quantifiers, &formula) {
            Ok(output) => output,
            Err(err) => {
                tracing::warn!(
                    "failed to format temporal liveness property for TA export ({err}); \
                     falling back to agreement"
                );
                let prop = extract_agreement_property(ta);
                export_ta_with_property(ta, Some(&prop))
            }
        },
    }
}

/// Convert a `ThresholdAutomaton` into ByMC `.ta` format text with an
/// explicit safety property for the specifications section.
pub fn export_ta_with_property(ta: &ThresholdAutomaton, prop: Option<&SafetyProperty>) -> String {
    export_ta_with_spec_block(ta, |out, ta| emit_specifications(out, prop, ta))
}

fn export_ta_with_spec_block<F>(ta: &ThresholdAutomaton, mut emit_specs: F) -> String
where
    F: FnMut(&mut String, &ThresholdAutomaton),
{
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

    emit_specs(&mut out, ta);

    out.push_str("}\n");
    out
}

fn export_ta_with_temporal_liveness(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
) -> Result<String, String> {
    let rendered = format_quantified_temporal_formula_bymc(ta, quantifiers, formula)?;
    Ok(export_ta_with_spec_block(ta, |out, _| {
        out.push_str("  specifications (1) {\n");
        out.push_str(&format!("    liveness: {rendered};\n"));
        out.push_str("  }\n");
    }))
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
        Some(SafetyProperty::Termination { goal_locs }) => {
            if goal_locs.is_empty() {
                out.push_str(
                    "  /* termination property has no goal locations; exported as empty specs */\n",
                );
                out.push_str("  specifications (0) {\n");
                out.push_str("  }\n");
            } else {
                let n_param = ta
                    .find_param_by_name("n")
                    .map(|_| "N".to_string())
                    .unwrap_or_else(|| "N".to_string());
                let lhs = goal_locs
                    .iter()
                    .map(|loc| format!("loc{loc}"))
                    .collect::<Vec<_>>()
                    .join(" + ");
                out.push_str("  specifications (1) {\n");
                out.push_str(&format!("    termination: <>(({lhs}) == {n_param});\n"));
                out.push_str("  }\n");
            }
        }
        None => {
            out.push_str("  /* no property provided */\n");
            out.push_str("  specifications (0) {\n");
            out.push_str("  }\n");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FormulaValue {
    Bool(bool),
    Int(i64),
    Enum(String),
}

fn formula_contains_temporal(expr: &ast::FormulaExpr) -> bool {
    match expr {
        ast::FormulaExpr::Comparison { .. } => false,
        ast::FormulaExpr::Not(inner) => formula_contains_temporal(inner),
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => true,
        ast::FormulaExpr::And(lhs, rhs)
        | ast::FormulaExpr::Or(lhs, rhs)
        | ast::FormulaExpr::Implies(lhs, rhs)
        | ast::FormulaExpr::Iff(lhs, rhs) => {
            formula_contains_temporal(lhs) || formula_contains_temporal(rhs)
        }
    }
}

fn formula_value_from_local(value: &LocalValue) -> FormulaValue {
    match value {
        LocalValue::Bool(b) => FormulaValue::Bool(*b),
        LocalValue::Int(i) => FormulaValue::Int(*i),
        LocalValue::Enum(v) => FormulaValue::Enum(v.clone()),
    }
}

fn eval_formula_atom_for_assignment(
    ta: &ThresholdAutomaton,
    atom: &ast::FormulaAtom,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<FormulaValue, String> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(loc_id) = assignment.get(default_quantified_var) {
                let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                    format!("invalid location id {loc_id} while evaluating liveness formula")
                })?;
                if let Some(value) = loc.local_vars.get(name) {
                    return Ok(formula_value_from_local(value));
                }
            }
            // Unresolved identifiers are treated as enum literals.
            Ok(FormulaValue::Enum(name.clone()))
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            let loc_id = assignment
                .get(object)
                .ok_or_else(|| format!("unsupported quantified variable '{object}'"))?;
            let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                format!("invalid location id {loc_id} while evaluating liveness formula")
            })?;
            let value = loc
                .local_vars
                .get(field)
                .ok_or_else(|| format!("unknown local variable '{field}' in liveness formula"))?;
            Ok(formula_value_from_local(value))
        }
    }
}

fn eval_formula_comparison(
    op: ast::CmpOp,
    lhs: FormulaValue,
    rhs: FormulaValue,
) -> Result<bool, String> {
    use ast::CmpOp;

    match (lhs, rhs) {
        (FormulaValue::Bool(l), FormulaValue::Bool(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err("boolean comparisons only support == and !=".into()),
        },
        (FormulaValue::Int(l), FormulaValue::Int(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            CmpOp::Ge => Ok(l >= r),
            CmpOp::Gt => Ok(l > r),
            CmpOp::Le => Ok(l <= r),
            CmpOp::Lt => Ok(l < r),
        },
        (FormulaValue::Enum(l), FormulaValue::Enum(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err("enum comparisons only support == and !=".into()),
        },
        _ => Err("type mismatch in liveness formula comparison".into()),
    }
}

fn eval_formula_expr_for_assignment(
    ta: &ThresholdAutomaton,
    expr: &ast::FormulaExpr,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<bool, String> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let left =
                eval_formula_atom_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let right =
                eval_formula_atom_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            eval_formula_comparison(*op, left, right)
        }
        ast::FormulaExpr::Not(inner) => Ok(!eval_formula_expr_for_assignment(
            ta,
            inner,
            assignment,
            default_quantified_var,
        )?),
        ast::FormulaExpr::And(lhs, rhs) => {
            Ok(
                eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    && eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            Ok(
                eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    || eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            Ok(
                !eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?
                    || eval_formula_expr_for_assignment(
                        ta,
                        rhs,
                        assignment,
                        default_quantified_var,
                    )?,
            )
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let left =
                eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let right =
                eval_formula_expr_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            Ok(left == right)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => {
            Err("temporal operators are not valid inside single-state predicate evaluation".into())
        }
    }
}

fn join_logic(op: &str, terms: Vec<String>, empty: &str) -> String {
    if terms.is_empty() {
        return empty.to_string();
    }
    if terms.len() == 1 {
        return terms
            .into_iter()
            .next()
            .unwrap_or_else(|| empty.to_string());
    }
    format!("({})", terms.join(&format!(" {op} ")))
}

fn format_quantified_state_predicate_bymc(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    state_expr: &ast::FormulaExpr,
) -> Result<String, String> {
    if quantifiers.is_empty() {
        return Err("temporal liveness export requires at least one quantifier".into());
    }

    let default_quantified_var = quantifiers[0].var.as_str();
    let mut role_locations: HashMap<String, Vec<usize>> = HashMap::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        role_locations.entry(loc.role.clone()).or_default().push(id);
    }

    fn encode_nested_quantifiers(
        ta: &ThresholdAutomaton,
        quantifiers: &[ast::QuantifierBinding],
        role_locations: &HashMap<String, Vec<usize>>,
        state_expr: &ast::FormulaExpr,
        default_quantified_var: &str,
        idx: usize,
        assignment: &mut BTreeMap<String, usize>,
    ) -> Result<String, String> {
        if idx == quantifiers.len() {
            let holds = eval_formula_expr_for_assignment(
                ta,
                state_expr,
                assignment,
                default_quantified_var,
            )?;
            return Ok(if holds { "true" } else { "false" }.to_string());
        }

        let binding = &quantifiers[idx];
        let locations = role_locations
            .get(&binding.domain)
            .map(|ids| ids.as_slice())
            .unwrap_or(&[]);

        match binding.quantifier {
            ast::Quantifier::ForAll => {
                if locations.is_empty() {
                    return Ok("true".to_string());
                }
                let mut clauses = Vec::with_capacity(locations.len());
                for loc_id in locations {
                    assignment.insert(binding.var.clone(), *loc_id);
                    let nested = encode_nested_quantifiers(
                        ta,
                        quantifiers,
                        role_locations,
                        state_expr,
                        default_quantified_var,
                        idx + 1,
                        assignment,
                    )?;
                    assignment.remove(&binding.var);
                    clauses.push(format!("(!(loc{loc_id} > 0) || ({nested}))"));
                }
                Ok(join_logic("&&", clauses, "true"))
            }
            ast::Quantifier::Exists => {
                if locations.is_empty() {
                    return Ok("false".to_string());
                }
                let mut disjuncts = Vec::with_capacity(locations.len());
                for loc_id in locations {
                    assignment.insert(binding.var.clone(), *loc_id);
                    let nested = encode_nested_quantifiers(
                        ta,
                        quantifiers,
                        role_locations,
                        state_expr,
                        default_quantified_var,
                        idx + 1,
                        assignment,
                    )?;
                    assignment.remove(&binding.var);
                    disjuncts.push(format!("((loc{loc_id} > 0) && ({nested}))"));
                }
                Ok(join_logic("||", disjuncts, "false"))
            }
        }
    }

    let mut assignment = BTreeMap::new();
    encode_nested_quantifiers(
        ta,
        quantifiers,
        &role_locations,
        state_expr,
        default_quantified_var,
        0,
        &mut assignment,
    )
}

fn format_quantified_temporal_formula_bymc(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
) -> Result<String, String> {
    if !formula_contains_temporal(formula) {
        return format_quantified_state_predicate_bymc(ta, quantifiers, formula);
    }

    match formula {
        ast::FormulaExpr::Comparison { .. } => {
            format_quantified_state_predicate_bymc(ta, quantifiers, formula)
        }
        ast::FormulaExpr::Not(inner) => Ok(format!(
            "!({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, inner)?
        )),
        ast::FormulaExpr::And(lhs, rhs) => Ok(format!(
            "({}) && ({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?,
            format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?,
        )),
        ast::FormulaExpr::Or(lhs, rhs) => Ok(format!(
            "({}) || ({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?,
            format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?,
        )),
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let left = format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?;
            let right = format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?;
            Ok(format!("((!({left})) || ({right}))"))
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let left = format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?;
            let right = format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?;
            Ok(format!(
                "((({left}) && ({right})) || ((!({left})) && (!({right}))))"
            ))
        }
        ast::FormulaExpr::Next(inner) => Ok(format!(
            "X({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, inner)?
        )),
        ast::FormulaExpr::Always(inner) => Ok(format!(
            "[]({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, inner)?
        )),
        ast::FormulaExpr::Eventually(inner) => Ok(format!(
            "<>({})",
            format_quantified_temporal_formula_bymc(ta, quantifiers, inner)?
        )),
        ast::FormulaExpr::Until(lhs, rhs) => Ok(format!(
            "(({}) U ({}))",
            format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?,
            format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?,
        )),
        ast::FormulaExpr::WeakUntil(lhs, rhs) => {
            let left = format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?;
            let right = format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?;
            Ok(format!("((({left}) U ({right})) || []({left}))"))
        }
        ast::FormulaExpr::Release(lhs, rhs) => {
            let left = format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?;
            let right = format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?;
            Ok(format!("!((!({left})) U (!({right})))"))
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let left = format_quantified_temporal_formula_bymc(ta, quantifiers, lhs)?;
            let right = format_quantified_temporal_formula_bymc(ta, quantifiers, rhs)?;
            Ok(format!("[]((!({left})) || <>({right}))"))
        }
    }
}

/// Sanitize a Tarsier shared-var name for ByMC (replace @ and [] with _).
fn sanitize_name(name: &str) -> String {
    name.replace('@', "_at_")
        .replace(['[', ']', ','], "_")
        .replace('=', "_eq_")
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

    #[test]
    fn export_includes_termination_spec_when_property_is_termination() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe_live.trs");
        let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
        let goal_locs: Vec<usize> = ta
            .locations
            .iter()
            .enumerate()
            .filter(|(_, loc)| loc.phase == "done")
            .map(|(id, _)| id)
            .collect();
        assert!(!goal_locs.is_empty(), "expected at least one done location");

        let output = export_ta_with_property(&ta, Some(&SafetyProperty::Termination { goal_locs }));
        assert!(
            output.contains("termination:"),
            "termination label should be present:\n{output}"
        );
        assert!(
            output.contains("<>"),
            "termination spec should use eventuality operator:\n{output}"
        );
        assert!(
            output.contains("specifications (1)"),
            "termination export should emit one specification:\n{output}"
        );
    }

    #[test]
    fn export_termination_with_empty_goals_emits_empty_specs_with_comment() {
        let source = include_str!("../../../examples/library/reliable_broadcast_safe.trs");
        let program = tarsier_dsl::parse(source, "test.trs").expect("parse failed");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
        let output = export_ta_with_property(
            &ta,
            Some(&SafetyProperty::Termination { goal_locs: vec![] }),
        );
        assert!(
            output.contains("termination property has no goal locations"),
            "empty-goal termination export should explain fallback:\n{output}"
        );
        assert!(
            output.contains("specifications (0)"),
            "empty-goal termination export should emit empty specs:\n{output}"
        );
    }

    #[test]
    fn export_ta_for_program_includes_termination_spec_when_declared() {
        let source = r#"
protocol ExportTerminationOnly {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Vote => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property termination: liveness {
        forall p: Replica. p.decided == true
    }
}
"#;
        let program = tarsier_dsl::parse(source, "export_term_only.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower failed");
        let output = export_ta_for_program(&ta, &program);

        assert!(
            output.contains("termination:"),
            "program-aware export should emit termination spec label:\n{output}"
        );
        assert!(
            output.contains("<>"),
            "program-aware export should emit eventuality for termination:\n{output}"
        );
    }

    #[test]
    fn export_ta_for_program_includes_temporal_liveness_spec_when_declared() {
        let source = r#"
protocol ExportTemporalLiveness {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_decide: liveness {
        forall p: Replica. <> (p.decided == true)
    }
}
"#;
        let program = tarsier_dsl::parse(source, "export_temporal.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        let output = export_ta_for_program(&ta, &program);

        assert!(
            output.contains("liveness:"),
            "temporal-liveness export should emit liveness label:\n{output}"
        );
        assert!(
            output.contains("<>"),
            "temporal-liveness export should emit eventuality operator:\n{output}"
        );
        assert!(
            !output.contains("agreement:"),
            "temporal-liveness export should not fall back to agreement:\n{output}"
        );
    }

    #[test]
    fn export_ta_for_program_temporal_liveness_with_unknown_field_falls_back_to_agreement() {
        let source = r#"
protocol ExportTemporalLivenessUnknownField {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_missing: liveness {
        forall p: Replica. <> (p.not_a_real_field == true)
    }
}
"#;
        let program =
            tarsier_dsl::parse(source, "export_temporal_unknown_field.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        let output = export_ta_for_program(&ta, &program);

        assert!(
            output.contains("agreement:"),
            "invalid temporal liveness should fall back to agreement:\n{output}"
        );
        assert!(
            !output.contains("liveness:"),
            "invalid temporal liveness should not emit temporal spec:\n{output}"
        );
    }

    #[test]
    fn export_ta_for_program_temporal_liveness_supports_mixed_quantifier_roles() {
        let source = r#"
protocol ExportTemporalMixedQuantifiers {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role A {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    role B {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property eventual_pair: liveness {
        forall p: A. exists q: B. <> ((p.decided == true) && (q.decided == true))
    }
}
"#;
        let program =
            tarsier_dsl::parse(source, "export_temporal_mixed_quantifiers.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        let output = export_ta_for_program(&ta, &program);

        assert!(
            output.contains("liveness:"),
            "mixed-quantifier temporal export should emit liveness label:\n{output}"
        );
        assert!(
            output.contains("<>"),
            "mixed-quantifier temporal export should keep eventual operator:\n{output}"
        );
        assert!(
            !output.contains("agreement:"),
            "mixed-quantifier temporal export should not fall back:\n{output}"
        );
    }

    #[test]
    fn export_ta_for_program_temporal_leads_to_is_desugared_in_bymc_spec() {
        let source = r#"
protocol ExportTemporalLeadsTo {
    params n, t;
    resilience: n > 3*t;
    message Ping;
    role Replica {
        var decided: bool = false;
        init start;
        phase start {
            when received >= 1 Ping => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property progress: liveness {
        forall p: Replica. (p.decided == false) ~> (p.decided == true)
    }
}
"#;
        let program = tarsier_dsl::parse(source, "export_temporal_leads_to.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        let output = export_ta_for_program(&ta, &program);

        assert!(
            output.contains("liveness:"),
            "leads-to export should emit liveness label:\n{output}"
        );
        assert!(
            output.contains("[]"),
            "leads-to export should desugar to global always form:\n{output}"
        );
        assert!(
            output.contains("<>"),
            "leads-to export should include eventuality in desugared body:\n{output}"
        );
    }
}
