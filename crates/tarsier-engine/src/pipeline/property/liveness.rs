//! Liveness spec extraction.

use crate::pipeline::*;
use crate::pipeline::property::*;

/// Extract and validate one liveness declaration into an executable liveness spec.
pub(crate) fn extract_liveness_spec_from_decl(
    ta: &ThresholdAutomaton,
    prop: &ast::PropertyDecl,
) -> Result<LivenessSpec, PipelineError> {
    let reachable = graph_reachable_locations(ta);
    let q = &prop.formula.quantifiers;
    let (active_index, normalized_formula) =
        normalize_liveness_quantified_formula(q, &prop.formula.body)
            .map_err(PipelineError::Property)?;
    for binding in q {
        let role_exists = ta.locations.iter().any(|loc| loc.role == binding.domain);
        if !role_exists {
            return Err(PipelineError::Property(format!(
                "Property references unknown role '{}'.",
                binding.domain
            )));
        }
    }
    let quantifier = q[active_index].quantifier;
    let quantified_var = &q[active_index].var;
    let role = &q[active_index].domain;
    let quantifier_var_names: HashSet<&str> =
        q.iter().map(|binding| binding.var.as_str()).collect();
    let referenced_vars = formula_quantified_var_refs(&normalized_formula, &quantifier_var_names);
    let temporal_quantifiers: Vec<ast::QuantifierBinding> = if referenced_vars.len() > 1 {
        q.iter()
            .filter(|binding| referenced_vars.contains(&binding.var))
            .cloned()
            .collect()
    } else {
        vec![q[active_index].clone()]
    };

    let has_temporal_ops = formula_contains_temporal(&normalized_formula);
    if has_temporal_ops {
        return Ok(LivenessSpec::Temporal {
            quantifiers: temporal_quantifiers,
            formula: normalized_formula,
        });
    }
    let multi_ref_non_temporal = referenced_vars.len() > 1;

    // Existential quantification and safety-kind state predicates are routed
    // through the temporal backend with explicit wrappers that preserve kind
    // semantics:
    //   - safety/invariant/validity: []phi
    //   - liveness exists:           <>phi
    let wrapped_temporal = match (prop.kind, quantifier) {
        // Propositional liveness over multiple referenced quantified variables
        // cannot be soundly reduced to one-role goal locations; preserve exact
        // semantics via temporal monitoring on <>phi.
        (ast::PropertyKind::Liveness, _) if multi_ref_non_temporal => Some(
            ast::FormulaExpr::Eventually(Box::new(normalized_formula.clone())),
        ),
        (
            ast::PropertyKind::Invariant | ast::PropertyKind::Safety | ast::PropertyKind::Validity,
            _,
        ) => Some(ast::FormulaExpr::Always(Box::new(
            normalized_formula.clone(),
        ))),
        (ast::PropertyKind::Liveness, ast::Quantifier::Exists) => Some(
            ast::FormulaExpr::Eventually(Box::new(normalized_formula.clone())),
        ),
        _ => None,
    };
    if let Some(formula) = wrapped_temporal {
        return Ok(LivenessSpec::Temporal {
            quantifiers: temporal_quantifiers,
            formula,
        });
    }

    let mut goal_locs = Vec::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != *role {
            // Liveness predicate scopes one role; other roles are unconstrained.
            goal_locs.push(id);
            continue;
        }
        if eval_formula_expr_on_location(&normalized_formula, quantified_var, loc)? {
            goal_locs.push(id);
        }
    }
    Ok(LivenessSpec::TerminationGoalLocs(goal_locs))
}

pub(crate) fn extract_liveness_spec(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
) -> Result<LivenessSpec, PipelineError> {
    let liveness_props: Vec<&ast::Spanned<ast::PropertyDecl>> = program
        .protocol
        .node
        .properties
        .iter()
        .filter(|p| is_liveness_property_kind(p.node.kind))
        .collect();

    if liveness_props.len() > 1 {
        return Err(PipelineError::Validation(
            "This entry point checks one liveness property at a time. Multiple named \
             liveness properties can be verified independently via verify_all_properties()."
                .into(),
        ));
    }

    if liveness_props.is_empty() {
        return Ok(LivenessSpec::TerminationGoalLocs(
            collect_decided_goal_locs(ta),
        ));
    }

    let prop = &liveness_props[0].node;
    extract_liveness_spec_from_decl(ta, prop)
}

pub(crate) fn fair_liveness_target_from_spec(
    ta: &ThresholdAutomaton,
    spec: LivenessSpec,
) -> Result<FairLivenessTarget, PipelineError> {
    match spec {
        LivenessSpec::TerminationGoalLocs(goal_locs) => Ok(FairLivenessTarget::NonGoalLocs(
            collect_non_goal_reachable_locs(ta, &goal_locs),
        )),
        LivenessSpec::Temporal {
            quantifiers,
            formula,
            ..
        } => Ok(FairLivenessTarget::Temporal(
            compile_temporal_buchi_automaton_with_bindings(&quantifiers, &formula)?,
        )),
    }
}

/// Resolve a ParamOrConst to a concrete i64 value.
/// For Const, returns the value directly.
/// For Param, this is only valid for concrete committee specs (not parametric).
pub(crate) fn resolve_param_or_const(
    poc: &ParamOrConst,
    _ta: &ThresholdAutomaton,
) -> Result<i64, PipelineError> {
    match poc {
        ParamOrConst::Const(c) => Ok(*c),
        ParamOrConst::Param(_pid) => {
            // For now, committee specs must use concrete values
            Err(PipelineError::Solver(
                "Committee parameters must be concrete values, not protocol parameters".into(),
            ))
        }
    }
}
