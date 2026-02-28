//! Fragment classification and quantifier analysis.

use crate::pipeline::*;
use crate::pipeline::property::*;

fn collect_formula_quantified_var_refs(
    expr: &ast::FormulaExpr,
    quantifier_vars: &HashSet<&str>,
    out: &mut BTreeSet<String>,
) {
    fn collect_atom_refs(
        atom: &ast::FormulaAtom,
        quantifier_vars: &HashSet<&str>,
        out: &mut BTreeSet<String>,
    ) {
        match atom {
            ast::FormulaAtom::Var(name) => {
                if quantifier_vars.contains(name.as_str()) {
                    out.insert(name.clone());
                }
            }
            ast::FormulaAtom::QualifiedVar { object, .. } => {
                if quantifier_vars.contains(object.as_str()) {
                    out.insert(object.clone());
                }
            }
            ast::FormulaAtom::IntLit(_) | ast::FormulaAtom::BoolLit(_) => {}
        }
    }

    match expr {
        ast::FormulaExpr::Comparison { lhs, rhs, .. } => {
            collect_atom_refs(lhs, quantifier_vars, out);
            collect_atom_refs(rhs, quantifier_vars, out);
        }
        ast::FormulaExpr::Not(inner)
        | ast::FormulaExpr::Next(inner)
        | ast::FormulaExpr::Always(inner)
        | ast::FormulaExpr::Eventually(inner) => {
            collect_formula_quantified_var_refs(inner, quantifier_vars, out);
        }
        ast::FormulaExpr::Until(lhs, rhs)
        | ast::FormulaExpr::WeakUntil(lhs, rhs)
        | ast::FormulaExpr::Release(lhs, rhs)
        | ast::FormulaExpr::LeadsTo(lhs, rhs)
        | ast::FormulaExpr::And(lhs, rhs)
        | ast::FormulaExpr::Or(lhs, rhs)
        | ast::FormulaExpr::Implies(lhs, rhs)
        | ast::FormulaExpr::Iff(lhs, rhs) => {
            collect_formula_quantified_var_refs(lhs, quantifier_vars, out);
            collect_formula_quantified_var_refs(rhs, quantifier_vars, out);
        }
    }
}

pub(crate) fn resolve_effective_quantifier_index(
    quantifiers: &[ast::QuantifierBinding],
    body: &ast::FormulaExpr,
    context_label: &str,
) -> Result<usize, String> {
    if quantifiers.is_empty() {
        return Err(format!(
            "{context_label} requires at least 1 quantifier, found 0."
        ));
    }

    let quantifier_var_names: HashSet<&str> = quantifiers
        .iter()
        .map(|binding| binding.var.as_str())
        .collect();
    let mut referenced_vars = BTreeSet::new();
    collect_formula_quantified_var_refs(body, &quantifier_var_names, &mut referenced_vars);

    if referenced_vars.len() > 1 {
        let vars = referenced_vars.into_iter().collect::<Vec<_>>().join(", ");
        return Err(format!(
            "{context_label} currently supports formulas that reference exactly one quantified \
             variable, found references to: {vars}."
        ));
    }

    let active_index = quantifiers
        .iter()
        .position(|binding| referenced_vars.contains(&binding.var))
        .unwrap_or(0);

    let invalid_extra_exists = quantifiers
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != active_index)
        .filter(|(_, binding)| binding.quantifier == ast::Quantifier::Exists)
        .map(|(_, binding)| binding.var.clone())
        .collect::<Vec<_>>();
    if !invalid_extra_exists.is_empty() {
        return Err(format!(
            "{context_label} allows additional quantifiers only when they are unused universal \
             (`forall`) quantifiers; unsupported existential extras: {}.",
            invalid_extra_exists.join(", ")
        ));
    }

    Ok(active_index)
}

pub(crate) fn formula_quantified_var_refs(
    expr: &ast::FormulaExpr,
    quantifier_vars: &HashSet<&str>,
) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    collect_formula_quantified_var_refs(expr, quantifier_vars, &mut refs);
    refs
}

pub(crate) fn normalize_liveness_quantified_formula(
    quantifiers: &[ast::QuantifierBinding],
    body: &ast::FormulaExpr,
) -> Result<(usize, ast::FormulaExpr), String> {
    if quantifiers.is_empty() {
        return Err("liveness requires at least 1 quantifier, found 0.".into());
    }

    let quantifier_var_names: HashSet<&str> = quantifiers
        .iter()
        .map(|binding| binding.var.as_str())
        .collect();
    let referenced_vars = formula_quantified_var_refs(body, &quantifier_var_names);

    let active_index = quantifiers
        .iter()
        .position(|binding| referenced_vars.contains(&binding.var))
        .unwrap_or(0);

    if referenced_vars.len() <= 1 {
        let invalid_extra_exists = quantifiers
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != active_index)
            .filter(|(_, binding)| binding.quantifier == ast::Quantifier::Exists)
            .map(|(_, binding)| binding.var.clone())
            .collect::<Vec<_>>();
        if !invalid_extra_exists.is_empty() {
            return Err(format!(
                "liveness allows additional quantifiers only when they are unused universal \
                 (`forall`) quantifiers; unsupported existential extras: {}.",
                invalid_extra_exists.join(", ")
            ));
        }
        return Ok((active_index, body.clone()));
    }

    let referenced_indices: BTreeSet<usize> = quantifiers
        .iter()
        .enumerate()
        .filter_map(|(idx, binding)| referenced_vars.contains(&binding.var).then_some(idx))
        .collect();

    let invalid_extra_exists = quantifiers
        .iter()
        .enumerate()
        .filter(|(idx, _)| !referenced_indices.contains(idx))
        .filter(|(_, binding)| binding.quantifier == ast::Quantifier::Exists)
        .map(|(_, binding)| binding.var.clone())
        .collect::<Vec<_>>();
    if !invalid_extra_exists.is_empty() {
        return Err(format!(
            "liveness allows additional quantifiers only when they are unused universal \
             (`forall`) quantifiers; unsupported existential extras: {}.",
            invalid_extra_exists.join(", ")
        ));
    }

    if formula_contains_temporal(body) {
        return Ok((active_index, body.clone()));
    }

    // Multi-referenced propositional liveness is preserved and routed through
    // temporal monitoring (wrapped as <>phi) by extraction. This keeps the
    // formula semantically faithful without lossy collapse to one variable.
    Ok((active_index, body.clone()))
}

/// Classify a property declaration into a supported quantified fragment.
///
/// Returns `Ok(fragment)` if the property is supported, or `Err(diagnostic)`
/// with an actionable explanation of why the property is rejected.
pub fn classify_property_fragment(
    prop: &ast::PropertyDecl,
) -> Result<QuantifiedFragment, FragmentDiagnostic> {
    let name = prop.name.clone();
    let q = &prop.formula.quantifiers;
    let body = &prop.formula.body;

    match prop.kind {
        ast::PropertyKind::Agreement => {
            // Must have exactly 2 universal quantifiers over the same role.
            if q.len() != 2 {
                return Err(FragmentDiagnostic {
                    property_name: name,
                    message: format!(
                        "agreement requires exactly 2 universal quantifiers, found {}.",
                        q.len()
                    ),
                    hint: Some("Use: `forall p: Role. forall q: Role. p.x == q.x`".into()),
                });
            }
            if q.iter().any(|b| b.quantifier != ast::Quantifier::ForAll) {
                return Err(FragmentDiagnostic {
                    property_name: name,
                    message: "agreement supports only universal quantifiers (`forall`).".into(),
                    hint: Some("Use: `forall p: Role. forall q: Role. p.x == q.x`".into()),
                });
            }
            if q[0].domain != q[1].domain {
                return Err(FragmentDiagnostic {
                    property_name: name,
                    message: "agreement quantifiers must range over the same role.".into(),
                    hint: Some(format!(
                        "Both quantifiers should use the same role, e.g., `forall p: {}. forall q: {}. ...`",
                        q[0].domain, q[0].domain
                    )),
                });
            }
            if formula_contains_temporal(body) {
                Ok(QuantifiedFragment::UniversalTemporal)
            } else {
                Ok(QuantifiedFragment::UniversalAgreement)
            }
        }
        ast::PropertyKind::Invariant | ast::PropertyKind::Safety | ast::PropertyKind::Validity => {
            let active_index = resolve_effective_quantifier_index(q, body, &prop.kind.to_string())
                .map_err(|message| FragmentDiagnostic {
                    property_name: name.clone(),
                    message,
                    hint: Some(
                        "Use: `forall p: Role. p.x == true` or `exists p: Role. p.x == true`"
                            .into(),
                    ),
                })?;
            match q[active_index].quantifier {
                ast::Quantifier::ForAll => {
                    if formula_contains_temporal(body) {
                        Ok(QuantifiedFragment::UniversalTemporal)
                    } else {
                        Ok(QuantifiedFragment::UniversalInvariant)
                    }
                }
                ast::Quantifier::Exists => Ok(QuantifiedFragment::ExistentialTemporal),
            }
        }
        ast::PropertyKind::Liveness => {
            let (active_index, normalized_body) = normalize_liveness_quantified_formula(q, body)
                .map_err(|message| FragmentDiagnostic {
                    property_name: name.clone(),
                    message,
                    hint: Some(
                        "Use: `forall p: Role. <> p.decided == true` or `exists p: Role. <> p.decided == true`"
                            .into(),
                    ),
                })?;
            let quantifier_var_names: HashSet<&str> =
                q.iter().map(|binding| binding.var.as_str()).collect();
            let referenced_vars =
                formula_quantified_var_refs(&normalized_body, &quantifier_var_names);
            let multi_ref_non_temporal =
                referenced_vars.len() > 1 && !formula_contains_temporal(&normalized_body);

            match q[active_index].quantifier {
                ast::Quantifier::ForAll => {
                    if formula_contains_temporal(&normalized_body) || multi_ref_non_temporal {
                        Ok(QuantifiedFragment::UniversalTemporal)
                    } else {
                        Ok(QuantifiedFragment::UniversalTermination)
                    }
                }
                ast::Quantifier::Exists => Ok(QuantifiedFragment::ExistentialTemporal),
            }
        }
    }
}

/// Validate all property declarations in a program, returning fragment
/// classifications or fail-fast diagnostics for unsupported shapes.
///
/// This should be called early in the pipeline (before lowering or SMT
/// encoding) to give users immediate feedback about unsupported formulas.
pub fn validate_property_fragments(
    program: &ast::Program,
) -> Result<Vec<(String, QuantifiedFragment)>, Vec<FragmentDiagnostic>> {
    let mut fragments = Vec::new();
    let mut errors = Vec::new();

    for prop_spanned in &program.protocol.node.properties {
        let prop = &prop_spanned.node;
        match classify_property_fragment(prop) {
            Ok(frag) => {
                fragments.push((prop.name.clone(), frag));
            }
            Err(diag) => errors.push(diag),
        }
    }

    if errors.is_empty() {
        Ok(fragments)
    } else {
        Err(errors)
    }
}
