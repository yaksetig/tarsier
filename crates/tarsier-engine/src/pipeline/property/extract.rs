//! Property extraction & selection, `TaExportProperty`.

use crate::pipeline::property::*;
use crate::pipeline::*;

/// Extract the safety property from the protocol.
///
/// Supported (sound) fragments:
/// - Agreement: `forall p: R. forall q: R. p.x == q.x` where `x` is a boolean or enum local var.
/// - Invariant/Safety/Validity: `forall p: R. p.x == true/false` where `x` is boolean.
///
/// Any other property shape returns an error rather than silently falling back.
pub(crate) fn select_single_safety_property_decl(
    program: &ast::Program,
    soundness: SoundnessMode,
) -> Result<Option<&ast::PropertyDecl>, PipelineError> {
    let safety_props: Vec<&ast::Spanned<ast::PropertyDecl>> = program
        .protocol
        .node
        .properties
        .iter()
        .filter(|p| is_safety_property_kind(p.node.kind))
        .collect();

    if safety_props.is_empty() {
        if soundness == SoundnessMode::Strict {
            return Err(PipelineError::Validation(
                "Strict mode requires an explicit property declaration.".into(),
            ));
        }
        return Ok(None);
    }

    if safety_props.len() > 1 {
        return Err(PipelineError::Validation(
            "This entry point checks one safety property at a time. Use verify_all_properties() \
             to verify multiple named properties with independent verdicts."
                .into(),
        ));
    }

    Ok(Some(&safety_props[0].node))
}

/// Extract the safety property from the protocol.
///
/// Supported (sound) fragments:
/// - Agreement: `forall p: R. forall q: R. p.x == q.x` where `x` is a boolean or enum local var.
/// - Invariant/Safety/Validity: `forall p: R. p.x == true/false` where `x` is boolean.
///
/// Any other property shape returns an error rather than silently falling back.
pub fn extract_property(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
    soundness: SoundnessMode,
) -> Result<SafetyProperty, PipelineError> {
    let Some(prop) = select_single_safety_property_decl(program, soundness)? else {
        // Default to agreement on `decided` if no property provided.
        tracing::warn!("No property declared; defaulting to structural agreement on `decided`.");
        return Ok(extract_agreement_property(ta));
    };
    extract_property_from_decl(ta, prop)
}

#[derive(Debug, Clone)]
pub(crate) enum TaExportProperty {
    Safety(SafetyProperty),
    Temporal {
        quantifiers: Vec<ast::QuantifierBinding>,
        formula: ast::FormulaExpr,
    },
}

/// Select a property for ByMC `.ta` export, preserving temporal liveness when
/// possible for downstream emitters.
///
/// Selection policy:
/// - If the model declares a safety property, select that safety property.
/// - Else if the model declares a liveness property:
///   - select non-temporal liveness as `SafetyProperty::Termination`;
///   - select temporal liveness as `TaExportProperty::Temporal`.
/// - Else (or extraction errors), fall back to structural agreement.
pub(crate) fn select_ta_export_property(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
) -> TaExportProperty {
    if has_safety_properties(program) {
        match extract_property(ta, program, SoundnessMode::Permissive) {
            Ok(prop) => return TaExportProperty::Safety(prop),
            Err(err) => {
                tracing::warn!(
                    "failed to extract safety property for TA export ({err}); \
                     falling back to agreement"
                );
            }
        }
    }

    if has_liveness_properties(program) {
        match extract_liveness_spec(ta, program) {
            Ok(LivenessSpec::TerminationGoalLocs(goal_locs)) => {
                return TaExportProperty::Safety(SafetyProperty::Termination {
                    goal_locs: goal_locs.into_iter().map(Into::into).collect(),
                });
            }
            Ok(LivenessSpec::Temporal {
                quantifiers,
                formula,
            }) => {
                return TaExportProperty::Temporal {
                    quantifiers,
                    formula,
                };
            }
            Err(err) => {
                tracing::warn!(
                    "failed to extract liveness property for TA export ({err}); \
                     falling back to agreement"
                );
            }
        }
    }

    TaExportProperty::Safety(extract_agreement_property(ta))
}

/// Select a property for ByMC `.ta` export.
///
/// Selection policy:
/// - If the model declares a safety property, export that safety property.
/// - Else if the model declares a liveness property that is a non-temporal
///   termination predicate, export it as `SafetyProperty::Termination`.
/// - Else (temporal-only liveness or extraction errors), fall back to
///   structural agreement to keep export best-effort and non-failing.
pub fn select_property_for_ta_export(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
) -> SafetyProperty {
    match select_ta_export_property(ta, program) {
        TaExportProperty::Safety(prop) => prop,
        TaExportProperty::Temporal { .. } => {
            tracing::warn!(
                "temporal liveness property is not representable in this \
                 compatibility TA-export selector; falling back to agreement"
            );
            extract_agreement_property(ta)
        }
    }
}

pub(crate) fn extract_property_from_decl(
    ta: &ThresholdAutomaton,
    prop: &ast::PropertyDecl,
) -> Result<SafetyProperty, PipelineError> {
    use tarsier_dsl::ast::{PropertyKind, Quantifier};
    let reachable = graph_reachable_locations(ta);

    let q = &prop.formula.quantifiers;
    let body = &prop.formula.body;

    match prop.kind {
        PropertyKind::Agreement => {
            // Expect either:
            // 1) forall p:R. forall q:R. p.x == q.x
            // 2) forall p:R. forall q:R. (p.d == true && q.d == true) ==> (p.x == q.x)
            if q.len() != 2 || q.iter().any(|b| b.quantifier != Quantifier::ForAll) {
                return Err(PipelineError::Property(
                    "Agreement property must use two universal quantifiers.".into(),
                ));
            }
            let role = &q[0].domain;
            if q[1].domain != *role {
                return Err(PipelineError::Property(
                    "Agreement quantifiers must be over the same role.".into(),
                ));
            }
            if let Some((guard_field, decision_field, var_l, var_r)) = parse_guarded_agreement(body)
            {
                if !((var_l == q[0].var && var_r == q[1].var)
                    || (var_l == q[1].var && var_r == q[0].var))
                {
                    return Err(PipelineError::Property(
                        "Agreement formula must reference the quantified variables in order."
                            .into(),
                    ));
                }
                let groups = locs_by_local_var_with_guard(
                    ta,
                    role,
                    &decision_field,
                    &guard_field,
                    &reachable,
                )?;
                let mut conflicting_pairs = Vec::new();
                build_conflicts_from_groups(&groups, &mut conflicting_pairs);
                return Ok(SafetyProperty::Agreement {
                    conflicting_pairs: conflicting_pairs
                        .into_iter()
                        .map(|(a, b)| (a.into(), b.into()))
                        .collect(),
                });
            }

            let (var_l, var_r, field) = parse_qualified_eq(body).ok_or_else(|| {
                PipelineError::Property(
                    "Agreement formula must be of the form `p.x == q.x` or a guarded agreement."
                        .into(),
                )
            })?;
            if !((var_l == q[0].var && var_r == q[1].var)
                || (var_l == q[1].var && var_r == q[0].var))
            {
                return Err(PipelineError::Property(
                    "Agreement formula must reference the quantified variables in order.".into(),
                ));
            }
            let groups = locs_by_local_var(ta, role, &field, &reachable)?;
            let mut conflicting_pairs = Vec::new();
            build_conflicts_from_groups(&groups, &mut conflicting_pairs);
            Ok(SafetyProperty::Agreement {
                conflicting_pairs: conflicting_pairs
                    .into_iter()
                    .map(|(a, b)| (a.into(), b.into()))
                    .collect(),
            })
        }
        PropertyKind::Invariant | PropertyKind::Safety | PropertyKind::Validity => {
            let active_index = resolve_effective_quantifier_index(
                q,
                body,
                "Invariant/safety property",
            )
            .map_err(PipelineError::Property)?;
            if q[active_index].quantifier != Quantifier::ForAll {
                return Err(PipelineError::Property(
                    "Invariant/safety property must use one universal quantifier.".into(),
                ));
            }
            let active_binding = &q[active_index];
            let role = &active_binding.domain;
            let (var, field, value) = parse_qualified_eq_bool(body).ok_or_else(|| {
                PipelineError::Property(
                    "Invariant/safety formula must be of the form `p.x == true/false`.".into(),
                )
            })?;
            if var != active_binding.var {
                return Err(PipelineError::Property(
                    "Invariant/safety formula must reference the quantified variable.".into(),
                ));
            }
            let (true_locs, false_locs) = locs_by_bool_var(ta, role, &field, &reachable)?;
            let bad_locs = if value { false_locs } else { true_locs };
            let bad_sets = bad_locs
                .into_iter()
                .map(|l| vec![l.into()])
                .collect();
            Ok(SafetyProperty::Invariant { bad_sets })
        }
        PropertyKind::Liveness => Err(PipelineError::Property(
            "Liveness properties are not safety properties; use `liveness`, `fair-liveness`, or `prove-fair`."
                .into(),
        )),
    }
}

#[cfg(test)]
mod tests;
