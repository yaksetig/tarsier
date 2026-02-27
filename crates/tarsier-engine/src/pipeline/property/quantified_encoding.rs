//! `build_quantified_state_predicate_term*` functions.

use super::super::verification::pdr_kappa_var;
use super::*;

/// Encode a quantified state predicate at one time-step.
pub(crate) fn build_quantified_state_predicate_term_with_bindings(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    state_expr: &ast::FormulaExpr,
    step: usize,
) -> Result<SmtTerm, PipelineError> {
    if quantifiers.is_empty() {
        return Err(PipelineError::Property(
            "Liveness state predicate requires at least one quantifier.".into(),
        ));
    }
    if quantifiers.len() == 1 {
        let binding = &quantifiers[0];
        let mut satisfying_locs = Vec::new();
        let mut disallowed_locs = Vec::new();
        for (id, loc) in ta.locations.iter().enumerate() {
            if loc.role != binding.domain {
                continue;
            }
            let holds = eval_formula_expr_on_location(state_expr, &binding.var, loc)?;
            if holds {
                satisfying_locs.push(id);
            } else {
                disallowed_locs.push(id);
            }
        }
        return match binding.quantifier {
            ast::Quantifier::ForAll => {
                if disallowed_locs.is_empty() {
                    Ok(SmtTerm::bool(true))
                } else {
                    let clauses = disallowed_locs
                        .into_iter()
                        .map(|id| SmtTerm::var(pdr_kappa_var(step, id)).eq(SmtTerm::int(0)))
                        .collect::<Vec<_>>();
                    Ok(SmtTerm::and(clauses))
                }
            }
            ast::Quantifier::Exists => {
                if satisfying_locs.is_empty() {
                    Ok(SmtTerm::bool(false))
                } else {
                    let disjuncts = satisfying_locs
                        .into_iter()
                        .map(|id| SmtTerm::var(pdr_kappa_var(step, id)).gt(SmtTerm::int(0)))
                        .collect::<Vec<_>>();
                    Ok(SmtTerm::or(disjuncts))
                }
            }
        };
    }

    let quantifier_var_names: HashSet<&str> = quantifiers
        .iter()
        .map(|binding| binding.var.as_str())
        .collect();
    let referenced_quantified_vars: HashSet<String> =
        formula_quantified_var_refs(state_expr, &quantifier_var_names)
            .into_iter()
            .collect();

    let default_quantified_var = quantifiers[0].var.as_str();
    let mut role_locations: HashMap<String, Vec<usize>> = HashMap::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        role_locations.entry(loc.role.clone()).or_default().push(id);
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_nested_quantifiers(
        ta: &ThresholdAutomaton,
        quantifiers: &[ast::QuantifierBinding],
        role_locations: &HashMap<String, Vec<usize>>,
        state_expr: &ast::FormulaExpr,
        step: usize,
        default_quantified_var: &str,
        referenced_quantified_vars: &HashSet<String>,
        idx: usize,
        assignment: &mut BTreeMap<String, usize>,
    ) -> Result<SmtTerm, PipelineError> {
        if idx == quantifiers.len() {
            let holds = eval_formula_expr_for_assignment(
                ta,
                state_expr,
                assignment,
                default_quantified_var,
            )?;
            return Ok(SmtTerm::bool(holds));
        }

        let binding = &quantifiers[idx];
        let locations = role_locations
            .get(&binding.domain)
            .map(|ids| ids.as_slice())
            .unwrap_or(&[]);
        let binding_is_referenced = referenced_quantified_vars.contains(binding.var.as_str());

        match binding.quantifier {
            ast::Quantifier::ForAll => {
                if locations.is_empty() {
                    return Ok(SmtTerm::bool(true));
                }
                let mut clauses = Vec::with_capacity(locations.len());
                if binding_is_referenced {
                    for loc_id in locations {
                        assignment.insert(binding.var.clone(), *loc_id);
                        let nested = encode_nested_quantifiers(
                            ta,
                            quantifiers,
                            role_locations,
                            state_expr,
                            step,
                            default_quantified_var,
                            referenced_quantified_vars,
                            idx + 1,
                            assignment,
                        )?;
                        assignment.remove(&binding.var);
                        let occupied =
                            SmtTerm::var(pdr_kappa_var(step, *loc_id)).gt(SmtTerm::int(0));
                        clauses.push(SmtTerm::or(vec![SmtTerm::not(occupied), nested]));
                    }
                } else {
                    // If the bound variable is not referenced in the predicate, the
                    // nested subterm is identical for every location and can be shared.
                    let nested = encode_nested_quantifiers(
                        ta,
                        quantifiers,
                        role_locations,
                        state_expr,
                        step,
                        default_quantified_var,
                        referenced_quantified_vars,
                        idx + 1,
                        assignment,
                    )?;
                    for loc_id in locations {
                        let occupied =
                            SmtTerm::var(pdr_kappa_var(step, *loc_id)).gt(SmtTerm::int(0));
                        clauses.push(SmtTerm::or(vec![SmtTerm::not(occupied), nested.clone()]));
                    }
                }
                Ok(SmtTerm::and(clauses))
            }
            ast::Quantifier::Exists => {
                if locations.is_empty() {
                    return Ok(SmtTerm::bool(false));
                }
                let mut disjuncts = Vec::with_capacity(locations.len());
                if binding_is_referenced {
                    for loc_id in locations {
                        assignment.insert(binding.var.clone(), *loc_id);
                        let nested = encode_nested_quantifiers(
                            ta,
                            quantifiers,
                            role_locations,
                            state_expr,
                            step,
                            default_quantified_var,
                            referenced_quantified_vars,
                            idx + 1,
                            assignment,
                        )?;
                        assignment.remove(&binding.var);
                        let occupied =
                            SmtTerm::var(pdr_kappa_var(step, *loc_id)).gt(SmtTerm::int(0));
                        disjuncts.push(SmtTerm::and(vec![occupied, nested]));
                    }
                } else {
                    // If the bound variable is not referenced in the predicate, the
                    // nested subterm is identical for every location and can be shared.
                    let nested = encode_nested_quantifiers(
                        ta,
                        quantifiers,
                        role_locations,
                        state_expr,
                        step,
                        default_quantified_var,
                        referenced_quantified_vars,
                        idx + 1,
                        assignment,
                    )?;
                    for loc_id in locations {
                        let occupied =
                            SmtTerm::var(pdr_kappa_var(step, *loc_id)).gt(SmtTerm::int(0));
                        disjuncts.push(SmtTerm::and(vec![occupied, nested.clone()]));
                    }
                }
                Ok(SmtTerm::or(disjuncts))
            }
        }
    }

    let mut assignment = BTreeMap::new();
    encode_nested_quantifiers(
        ta,
        quantifiers,
        &role_locations,
        state_expr,
        step,
        default_quantified_var,
        &referenced_quantified_vars,
        0,
        &mut assignment,
    )
}

/// Encode a quantified state predicate at one time-step.
#[cfg(test)]
pub(crate) fn build_quantified_state_predicate_term(
    ta: &ThresholdAutomaton,
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    state_expr: &ast::FormulaExpr,
    step: usize,
) -> Result<SmtTerm, PipelineError> {
    let quantifiers = vec![ast::QuantifierBinding {
        quantifier,
        var: quantified_var.to_string(),
        domain: role.to_string(),
    }];
    build_quantified_state_predicate_term_with_bindings(ta, &quantifiers, state_expr, step)
}
