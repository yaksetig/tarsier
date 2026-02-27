//! Property extraction, classification, validation, temporal formula compilation.

use super::verification::pdr_kappa_var;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantifiedFragment {
    /// `forall p:R. forall q:R. p.x == q.x` (or guarded variant with `==>`)
    ///
    /// Verified via counter abstraction: conflicting location pairs.
    UniversalAgreement,

    /// `forall p:R. p.x == true/false`
    ///
    /// Verified via counter abstraction: bad-set invariant checking.
    UniversalInvariant,

    /// `forall p:R. <propositional formula>` (no temporal operators, liveness kind)
    ///
    /// Verified via termination goal-location reachability.
    UniversalTermination,

    /// `forall ... . <temporal formula>` (contains temporal operators)
    ///
    /// Verified via Büchi automaton construction + fair-cycle detection.
    UniversalTemporal,

    /// `exists ... . <formula>` handled through temporal encoding.
    ///
    /// This includes explicit temporal formulas, plus non-temporal formulas
    /// rewritten by property-kind semantics (for example `[]phi` for safety
    /// kinds, `<>phi` for liveness kinds).
    ExistentialTemporal,
}

impl QuantifiedFragment {
    /// Returns a human-readable soundness statement for this fragment.
    ///
    /// The soundness statement describes what a "Safe" or "Unsafe" verdict means
    /// under the counter-abstraction model and the specific fragment.
    pub fn soundness_statement(&self) -> &'static str {
        match self {
            QuantifiedFragment::UniversalAgreement => {
                "Under the counter-abstraction model, if the verifier reports Safe, then \
                 no reachable state exists in which two correct processes simultaneously \
                 occupy locations with conflicting decision values. This is sound for \
                 universally quantified agreement over a single local variable, assuming \
                 the adversary model (f <= t Byzantine faults) faithfully represents the \
                 protocol's fault tolerance."
            }

            QuantifiedFragment::UniversalInvariant => {
                "Under the counter-abstraction model, if the verifier reports Safe, then \
                 no reachable state exists in which any correct process occupies a location \
                 where the invariant predicate is violated. This is sound for universally \
                 quantified state predicates (p.x == true/false) under the declared \
                 adversary model."
            }

            QuantifiedFragment::UniversalTermination => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then every fair execution eventually reaches a \
                 state where all correct processes satisfy the goal predicate. Soundness \
                 depends on the fairness assumption: weak fairness requires continuously-\
                 enabled transitions to eventually fire; strong fairness requires \
                 infinitely-often-enabled transitions to eventually fire."
            }

            QuantifiedFragment::UniversalTemporal => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then no fair execution violates the temporal \
                 specification (encoded as a Büchi automaton). The temporal formula is \
                 negated and checked for fair-cycle emptiness. Soundness depends on: \
                 (1) correct Büchi construction from the LTL formula, (2) the fairness \
                 assumption, and (3) faithful counter-abstraction of the protocol."
            }

            QuantifiedFragment::ExistentialTemporal => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then no fair execution violates the existentially \
                 quantified temporal specification. Existential state predicates are encoded \
                 as occupancy constraints (some role process satisfies the predicate). \
                 Soundness depends on faithful counter abstraction and fairness assumptions."
            }
        }
    }
}

impl std::fmt::Display for QuantifiedFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuantifiedFragment::UniversalAgreement => write!(f, "universal-agreement"),
            QuantifiedFragment::UniversalInvariant => write!(f, "universal-invariant"),
            QuantifiedFragment::UniversalTermination => write!(f, "universal-termination"),
            QuantifiedFragment::UniversalTemporal => write!(f, "universal-temporal"),
            QuantifiedFragment::ExistentialTemporal => write!(f, "existential-temporal"),
        }
    }
}

/// Diagnostic produced when a property formula falls outside supported fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentDiagnostic {
    pub property_name: String,
    pub message: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for FragmentDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "property '{}': {}", self.property_name, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

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

fn resolve_effective_quantifier_index(
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

fn formula_quantified_var_refs(
    expr: &ast::FormulaExpr,
    quantifier_vars: &HashSet<&str>,
) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    collect_formula_quantified_var_refs(expr, quantifier_vars, &mut refs);
    refs
}

fn normalize_liveness_quantified_formula(
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

/// Extract the safety property from the protocol.
///
/// Supported (sound) fragments:
/// - Agreement: `forall p: R. forall q: R. p.x == q.x` where `x` is a boolean or enum local var.
/// - Invariant/Safety/Validity: `forall p: R. p.x == true/false` where `x` is boolean.
///
/// Any other property shape returns an error rather than silently falling back.
pub(super) fn select_single_safety_property_decl(
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
                return TaExportProperty::Safety(SafetyProperty::Termination { goal_locs });
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

pub(super) fn extract_property_from_decl(
    ta: &ThresholdAutomaton,
    prop: &ast::PropertyDecl,
) -> Result<SafetyProperty, PipelineError> {
    use ast::{PropertyKind, Quantifier};
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
                return Ok(SafetyProperty::Agreement { conflicting_pairs });
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
            Ok(SafetyProperty::Agreement { conflicting_pairs })
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
            let bad_sets = bad_locs.into_iter().map(|l| vec![l]).collect();
            Ok(SafetyProperty::Invariant { bad_sets })
        }
        PropertyKind::Liveness => Err(PipelineError::Property(
            "Liveness properties are not safety properties; use `liveness`, `fair-liveness`, or `prove-fair`."
                .into(),
        )),
    }
}

pub(super) fn graph_reachable_locations(ta: &ThresholdAutomaton) -> HashSet<usize> {
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = ta.initial_locations.clone();
    while let Some(lid) = stack.pop() {
        if !reachable.insert(lid) {
            continue;
        }
        for rule in &ta.rules {
            if rule.from == lid && !reachable.contains(&rule.to) {
                stack.push(rule.to);
            }
        }
    }
    reachable
}

/// Parse `p.x == q.x` (optionally wrapped by outer `[]`) into `(p, q, x)`.
pub(super) fn parse_qualified_eq(body: &ast::FormulaExpr) -> Option<(String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (
                ast::FormulaAtom::QualifiedVar {
                    object: lobj,
                    field,
                },
                ast::FormulaAtom::QualifiedVar {
                    object: robj,
                    field: rfield,
                },
            ) if field == rfield => Some((lobj.clone(), robj.clone(), field.clone())),
            _ => None,
        }
    } else {
        None
    }
}

/// Parse `p.x == true/false` (either orientation, optionally wrapped by outer `[]`).
pub(super) fn parse_qualified_eq_bool(body: &ast::FormulaExpr) -> Option<(String, String, bool)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (ast::FormulaAtom::QualifiedVar { object, field }, ast::FormulaAtom::BoolLit(b)) => {
                Some((object.clone(), field.clone(), *b))
            }
            (ast::FormulaAtom::BoolLit(b), ast::FormulaAtom::QualifiedVar { object, field }) => {
                Some((object.clone(), field.clone(), *b))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Parse guarded agreement shape:
/// `(p.g == true && q.g == true) ==> (p.x == q.x)`.
pub(super) fn parse_guarded_agreement(
    body: &ast::FormulaExpr,
) -> Option<(String, String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Implies(lhs, rhs) = body {
        let (var_l, var_r, decision_field) = parse_qualified_eq(rhs)?;
        let mut guards = Vec::new();
        if !collect_guard_comparisons(lhs, &mut guards) {
            return None;
        }
        if guards.len() != 2 {
            return None;
        }
        let (g1_var, g1_field, g1_val) = &guards[0];
        let (g2_var, g2_field, g2_val) = &guards[1];
        if g1_field != g2_field || !*g1_val || !*g2_val {
            return None;
        }
        if (g1_var == &var_l && g2_var == &var_r) || (g1_var == &var_r && g2_var == &var_l) {
            Some((g1_field.clone(), decision_field, var_l, var_r))
        } else {
            None
        }
    } else {
        None
    }
}

/// Strip any leading stack of outer `[]` wrappers.
pub(super) fn strip_outer_always(body: &ast::FormulaExpr) -> &ast::FormulaExpr {
    if let ast::FormulaExpr::Always(inner) = body {
        strip_outer_always(inner)
    } else {
        body
    }
}

/// Collect boolean guard comparisons from a conjunction tree.
pub(super) fn collect_guard_comparisons(
    expr: &ast::FormulaExpr,
    out: &mut Vec<(String, String, bool)>,
) -> bool {
    match expr {
        ast::FormulaExpr::And(lhs, rhs) => {
            collect_guard_comparisons(lhs, out) && collect_guard_comparisons(rhs, out)
        }
        ast::FormulaExpr::Comparison { .. } => {
            if let Some((var, field, val)) = parse_qualified_eq_bool(expr) {
                out.push((var, field, val));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub(super) fn locs_by_bool_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<(Vec<usize>, Vec<usize>), PipelineError> {
    let mut true_locs = Vec::new();
    let mut false_locs = Vec::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            match val {
                LocalValue::Bool(b) => {
                    if *b {
                        true_locs.push(id);
                    } else {
                        false_locs.push(id);
                    }
                }
                _ => {
                    return Err(PipelineError::Property(format!(
                        "Local variable '{field}' in role '{role}' is not boolean."
                    )));
                }
            }
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown boolean local variable '{field}' in role '{role}'."
        )));
    }
    Ok((true_locs, false_locs))
}

pub(super) fn locs_by_local_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

pub(super) fn locs_by_local_var_with_guard(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    guard_field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found_field = false;
    let mut found_guard = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        let guard_val = match loc.local_vars.get(guard_field) {
            Some(LocalValue::Bool(b)) => {
                found_guard = true;
                *b
            }
            Some(_) => {
                return Err(PipelineError::Property(format!(
                    "Guard variable '{guard_field}' in role '{role}' is not boolean."
                )))
            }
            None => false,
        };
        if !guard_val {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found_field = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found_field || !found_guard {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' or guard '{guard_field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

pub(super) fn build_conflicts_from_groups(
    groups: &std::collections::HashMap<LocalValue, Vec<usize>>,
    out: &mut Vec<(usize, usize)>,
) {
    let group_vec: Vec<&Vec<usize>> = groups.values().collect();
    for i in 0..group_vec.len() {
        for j in (i + 1)..group_vec.len() {
            for &li in group_vec[i] {
                for &lj in group_vec[j] {
                    out.push((li, lj));
                }
            }
        }
    }
}

pub(super) fn is_safety_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(
        kind,
        ast::PropertyKind::Agreement
            | ast::PropertyKind::Validity
            | ast::PropertyKind::Safety
            | ast::PropertyKind::Invariant
    )
}

pub(super) fn is_liveness_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(kind, ast::PropertyKind::Liveness)
}

pub(super) fn has_safety_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind))
}

pub(super) fn has_liveness_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_liveness_property_kind(p.node.kind))
}

pub(super) fn collect_decided_goal_locs(ta: &ThresholdAutomaton) -> Vec<usize> {
    ta.locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.local_vars.get("decided") == Some(&LocalValue::Bool(true)))
        .map(|(id, _)| id)
        .collect()
}

pub(super) fn collect_non_goal_reachable_locs(
    ta: &ThresholdAutomaton,
    goal_locs: &[usize],
) -> Vec<usize> {
    let reachable = graph_reachable_locations(ta);
    let goals: HashSet<usize> = goal_locs.iter().copied().collect();
    ta.locations
        .iter()
        .enumerate()
        .filter(|(id, _)| reachable.contains(id) && !goals.contains(id))
        .map(|(id, _)| id)
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) enum LivenessSpec {
    TerminationGoalLocs(Vec<usize>),
    Temporal {
        quantifiers: Vec<ast::QuantifierBinding>,
        formula: ast::FormulaExpr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum TemporalFormula {
    True,
    False,
    Atom(usize),
    NotAtom(usize),
    Next(Box<TemporalFormula>),
    And(Box<TemporalFormula>, Box<TemporalFormula>),
    Or(Box<TemporalFormula>, Box<TemporalFormula>),
    Until(Box<TemporalFormula>, Box<TemporalFormula>),
    Release(Box<TemporalFormula>, Box<TemporalFormula>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum TemporalAtomLit {
    Pos(usize),
    Neg(usize),
}

#[derive(Debug, Clone)]
pub(crate) struct TemporalBuchiState {
    pub(crate) old: BTreeSet<TemporalFormula>,
    pub(crate) label_lits: Vec<TemporalAtomLit>,
    pub(crate) transitions: Vec<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct TemporalBuchiAutomaton {
    pub(crate) quantifier: ast::Quantifier,
    pub(crate) quantified_var: String,
    pub(crate) role: String,
    pub(crate) quantifiers: Vec<ast::QuantifierBinding>,
    pub(crate) atoms: Vec<ast::FormulaExpr>,
    pub(crate) states: Vec<TemporalBuchiState>,
    pub(crate) initial_states: Vec<usize>,
    pub(crate) acceptance_sets: Vec<Vec<usize>>,
}

#[derive(Debug, Clone)]
pub(crate) enum FairLivenessTarget {
    NonGoalLocs(Vec<usize>),
    Temporal(TemporalBuchiAutomaton),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FormulaValue {
    Bool(bool),
    Int(i64),
    Enum(String),
}

pub(super) fn formula_value_from_local(value: &LocalValue) -> FormulaValue {
    match value {
        LocalValue::Bool(b) => FormulaValue::Bool(*b),
        LocalValue::Int(i) => FormulaValue::Int(*i),
        LocalValue::Enum(v) => FormulaValue::Enum(v.clone()),
    }
}

pub(super) fn eval_formula_atom_on_location(
    atom: &ast::FormulaAtom,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<FormulaValue, PipelineError> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(v) = loc.local_vars.get(name) {
                Ok(formula_value_from_local(v))
            } else {
                // Unresolved identifiers are treated as enum literals.
                Ok(FormulaValue::Enum(name.clone()))
            }
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            if object != quantified_var {
                return Err(PipelineError::Property(format!(
                    "Liveness formula references unsupported quantified variable '{object}'."
                )));
            }
            let value = loc.local_vars.get(field).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Unknown local variable '{field}' in liveness formula."
                ))
            })?;
            Ok(formula_value_from_local(value))
        }
    }
}

pub(super) fn eval_formula_comparison(
    op: ast::CmpOp,
    lhs: FormulaValue,
    rhs: FormulaValue,
) -> Result<bool, PipelineError> {
    use ast::CmpOp;
    match (lhs, rhs) {
        (FormulaValue::Bool(l), FormulaValue::Bool(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err(PipelineError::Property(
                "Boolean liveness comparisons only support == and !=.".into(),
            )),
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
            _ => Err(PipelineError::Property(
                "Enum liveness comparisons only support == and !=.".into(),
            )),
        },
        _ => Err(PipelineError::Property(
            "Type mismatch in liveness formula comparison.".into(),
        )),
    }
}

pub(super) fn eval_formula_expr_on_location(
    expr: &ast::FormulaExpr,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<bool, PipelineError> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let l = eval_formula_atom_on_location(lhs, quantified_var, loc)?;
            let r = eval_formula_atom_on_location(rhs, quantified_var, loc)?;
            eval_formula_comparison(*op, l, r)
        }
        ast::FormulaExpr::Not(inner) => {
            Ok(!eval_formula_expr_on_location(inner, quantified_var, loc)?)
        }
        ast::FormulaExpr::And(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                && eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            Ok(!eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let lv = eval_formula_expr_on_location(lhs, quantified_var, loc)?;
            let rv = eval_formula_expr_on_location(rhs, quantified_var, loc)?;
            Ok(lv == rv)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => Err(PipelineError::Property(
            "Temporal operators are not valid inside a single-state predicate context.".into(),
        )),
    }
}

fn eval_formula_atom_for_assignment(
    ta: &ThresholdAutomaton,
    atom: &ast::FormulaAtom,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<FormulaValue, PipelineError> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(loc_id) = assignment.get(default_quantified_var) {
                let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                    PipelineError::Property(format!(
                        "Invalid location id {loc_id} while evaluating liveness formula."
                    ))
                })?;
                if let Some(v) = loc.local_vars.get(name) {
                    return Ok(formula_value_from_local(v));
                }
            }
            // Unresolved identifiers are treated as enum literals.
            Ok(FormulaValue::Enum(name.clone()))
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            let loc_id = assignment.get(object).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Liveness formula references unsupported quantified variable '{object}'."
                ))
            })?;
            let loc = ta.locations.get(*loc_id).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Invalid location id {loc_id} while evaluating liveness formula."
                ))
            })?;
            let value = loc.local_vars.get(field).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Unknown local variable '{field}' in liveness formula."
                ))
            })?;
            Ok(formula_value_from_local(value))
        }
    }
}

fn eval_formula_expr_for_assignment(
    ta: &ThresholdAutomaton,
    expr: &ast::FormulaExpr,
    assignment: &BTreeMap<String, usize>,
    default_quantified_var: &str,
) -> Result<bool, PipelineError> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let l = eval_formula_atom_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let r = eval_formula_atom_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            eval_formula_comparison(*op, l, r)
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
            let lv = eval_formula_expr_for_assignment(ta, lhs, assignment, default_quantified_var)?;
            let rv = eval_formula_expr_for_assignment(ta, rhs, assignment, default_quantified_var)?;
            Ok(lv == rv)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => Err(PipelineError::Property(
            "Temporal operators are not valid inside a single-state predicate context.".into(),
        )),
    }
}

pub(super) fn formula_contains_temporal(expr: &ast::FormulaExpr) -> bool {
    match expr {
        ast::FormulaExpr::Comparison { .. } => false,
        ast::FormulaExpr::Not(inner) => formula_contains_temporal(inner),
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_) => true,
        ast::FormulaExpr::Until(_, _)
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

#[derive(Debug, Clone, Default)]
pub(super) struct TemporalAtomTable {
    atoms: Vec<ast::FormulaExpr>,
}

impl TemporalAtomTable {
    fn intern(&mut self, expr: &ast::FormulaExpr) -> usize {
        if let Some(idx) = self.atoms.iter().position(|existing| existing == expr) {
            idx
        } else {
            let idx = self.atoms.len();
            self.atoms.push(expr.clone());
            idx
        }
    }
}

pub(super) fn temporal_and(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::False, _) | (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) | (other, TemporalFormula::True) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::And(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::And(Box::new(right), Box::new(left))
            }
        }
    }
}

pub(super) fn temporal_or(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::True, _) | (_, TemporalFormula::True) => TemporalFormula::True,
        (TemporalFormula::False, other) | (other, TemporalFormula::False) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::Or(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::Or(Box::new(right), Box::new(left))
            }
        }
    }
}

pub(super) fn temporal_until(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::False, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Until(Box::new(left), Box::new(right)),
    }
}

pub(super) fn temporal_release(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Release(Box::new(left), Box::new(right)),
    }
}

pub(super) fn formula_to_temporal_nnf(
    expr: &ast::FormulaExpr,
    atoms: &mut TemporalAtomTable,
    negated: bool,
) -> Result<TemporalFormula, PipelineError> {
    if !formula_contains_temporal(expr) {
        let atom = atoms.intern(expr);
        return Ok(if negated {
            TemporalFormula::NotAtom(atom)
        } else {
            TemporalFormula::Atom(atom)
        });
    }

    match expr {
        ast::FormulaExpr::Comparison { .. } => {
            let atom = atoms.intern(expr);
            Ok(if negated {
                TemporalFormula::NotAtom(atom)
            } else {
                TemporalFormula::Atom(atom)
            })
        }
        ast::FormulaExpr::Not(inner) => formula_to_temporal_nnf(inner, atoms, !negated),
        ast::FormulaExpr::And(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_or(l, r)
            } else {
                temporal_and(l, r)
            })
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_and(l, r)
            } else {
                temporal_or(l, r)
            })
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let desugared =
                ast::FormulaExpr::Or(Box::new(ast::FormulaExpr::Not(lhs.clone())), rhs.clone());
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::And(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::And(
                    Box::new(ast::FormulaExpr::Not(lhs.clone())),
                    Box::new(ast::FormulaExpr::Not(rhs.clone())),
                )),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Next(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(TemporalFormula::Next(Box::new(inner_nnf)))
        }
        ast::FormulaExpr::Always(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_until(TemporalFormula::True, inner_nnf)
            } else {
                temporal_release(TemporalFormula::False, inner_nnf)
            })
        }
        ast::FormulaExpr::Eventually(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_release(TemporalFormula::False, inner_nnf)
            } else {
                temporal_until(TemporalFormula::True, inner_nnf)
            })
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_release(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_until(l, r))
            }
        }
        ast::FormulaExpr::Release(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_until(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_release(l, r))
            }
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::Until(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::Always(lhs.clone())),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Implies(
                lhs.clone(),
                Box::new(ast::FormulaExpr::Eventually(rhs.clone())),
            )));
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
    }
}

pub(super) fn collect_until_formulas(
    formula: &TemporalFormula,
    out: &mut BTreeSet<TemporalFormula>,
) {
    match formula {
        TemporalFormula::Until(lhs, rhs) => {
            out.insert(formula.clone());
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::And(lhs, rhs)
        | TemporalFormula::Or(lhs, rhs)
        | TemporalFormula::Release(lhs, rhs) => {
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::Next(inner) => {
            collect_until_formulas(inner, out);
        }
        TemporalFormula::True
        | TemporalFormula::False
        | TemporalFormula::Atom(_)
        | TemporalFormula::NotAtom(_) => {}
    }
}

pub(super) fn temporal_formula_canonical(formula: &TemporalFormula) -> String {
    match formula {
        TemporalFormula::True => "true".to_string(),
        TemporalFormula::False => "false".to_string(),
        TemporalFormula::Atom(id) => format!("atom({id})"),
        TemporalFormula::NotAtom(id) => format!("not_atom({id})"),
        TemporalFormula::Next(inner) => format!("X({})", temporal_formula_canonical(inner)),
        TemporalFormula::And(lhs, rhs) => format!(
            "and({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Or(lhs, rhs) => format!(
            "or({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Until(lhs, rhs) => format!(
            "until({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Release(lhs, rhs) => format!(
            "release({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
    }
}

pub(super) fn temporal_buchi_monitor_canonical(automaton: &TemporalBuchiAutomaton) -> String {
    let mut chunks = Vec::new();
    chunks.push(format!(
        "quantifier={};quantified_var={};role={}",
        automaton.quantifier, automaton.quantified_var, automaton.role
    ));
    let quantifiers = automaton
        .quantifiers
        .iter()
        .map(|binding| format!("{}:{}:{}", binding.quantifier, binding.var, binding.domain))
        .collect::<Vec<_>>()
        .join(",");
    chunks.push(format!("quantifiers=[{quantifiers}]"));
    for (idx, atom) in automaton.atoms.iter().enumerate() {
        chunks.push(format!("atom[{idx}]={atom}"));
    }
    chunks.push(format!("initial={:?}", automaton.initial_states));
    for (acc_id, acc) in automaton.acceptance_sets.iter().enumerate() {
        chunks.push(format!("acceptance[{acc_id}]={acc:?}"));
    }
    for (sid, state) in automaton.states.iter().enumerate() {
        let old = state
            .old
            .iter()
            .map(temporal_formula_canonical)
            .collect::<Vec<_>>()
            .join(",");
        let labels = state
            .label_lits
            .iter()
            .map(|lit| match lit {
                TemporalAtomLit::Pos(id) => format!("+{id}"),
                TemporalAtomLit::Neg(id) => format!("-{id}"),
            })
            .collect::<Vec<_>>()
            .join(",");
        chunks.push(format!(
            "state[{sid}]:old=[{old}] labels=[{labels}] trans={:?}",
            state.transitions
        ));
    }
    chunks.join("\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TemporalExpansionOutcome {
    old: BTreeSet<TemporalFormula>,
    next: BTreeSet<TemporalFormula>,
    literals: BTreeMap<usize, bool>,
}

pub(super) fn temporal_push_todo(
    todo: &mut Vec<TemporalFormula>,
    old: &BTreeSet<TemporalFormula>,
    formula: TemporalFormula,
) {
    if old.contains(&formula) || todo.iter().any(|f| f == &formula) {
        return;
    }
    todo.push(formula);
}

pub(super) fn expand_temporal_seed(
    seed: &BTreeSet<TemporalFormula>,
) -> Vec<TemporalExpansionOutcome> {
    fn recurse(
        mut todo: Vec<TemporalFormula>,
        old: BTreeSet<TemporalFormula>,
        next: BTreeSet<TemporalFormula>,
        literals: BTreeMap<usize, bool>,
        outcomes: &mut Vec<TemporalExpansionOutcome>,
    ) {
        let Some(formula) = todo.pop() else {
            outcomes.push(TemporalExpansionOutcome {
                old,
                next,
                literals,
            });
            return;
        };

        if old.contains(&formula) {
            recurse(todo, old, next, literals, outcomes);
            return;
        }

        match formula {
            TemporalFormula::True => {
                let mut old2 = old;
                old2.insert(TemporalFormula::True);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::False => {}
            TemporalFormula::Atom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(false)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::Atom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, true);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::NotAtom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(true)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::NotAtom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, false);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::Next(inner) => {
                let mut old2 = old;
                let next_formula = TemporalFormula::Next(inner.clone());
                old2.insert(next_formula);
                let mut next2 = next;
                next2.insert(*inner);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::And(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::And(lhs.clone(), rhs.clone()));
                temporal_push_todo(&mut todo, &old2, *lhs);
                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Or(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::Or(lhs.clone(), rhs.clone()));

                let mut left_todo = todo.clone();
                temporal_push_todo(&mut left_todo, &old2, *lhs.clone());
                recurse(
                    left_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Until(lhs, rhs) => {
                let mut old2 = old;
                let until_formula = TemporalFormula::Until(lhs.clone(), rhs.clone());
                old2.insert(until_formula.clone());

                let mut rhs_todo = todo.clone();
                temporal_push_todo(&mut rhs_todo, &old2, *rhs.clone());
                recurse(
                    rhs_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *lhs);
                let mut next2 = next;
                next2.insert(until_formula);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::Release(lhs, rhs) => {
                let mut old2 = old;
                let rel_formula = TemporalFormula::Release(lhs.clone(), rhs.clone());
                old2.insert(rel_formula.clone());

                let mut keep_todo = todo.clone();
                temporal_push_todo(&mut keep_todo, &old2, *lhs.clone());
                temporal_push_todo(&mut keep_todo, &old2, *rhs.clone());
                let mut keep_next = next.clone();
                keep_next.insert(rel_formula.clone());
                recurse(
                    keep_todo,
                    old2.clone(),
                    keep_next,
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
        }
    }

    let mut outcomes = Vec::new();
    recurse(
        seed.iter().cloned().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        &mut outcomes,
    );

    let mut unique = Vec::new();
    for outcome in outcomes {
        if !unique.iter().any(|existing| existing == &outcome) {
            unique.push(outcome);
        }
    }
    unique
}

/// Compile a temporal property into an explicit Büchi monitor.
#[cfg(test)]
pub(super) fn compile_temporal_buchi_automaton(
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
) -> Result<TemporalBuchiAutomaton, PipelineError> {
    let quantifiers = vec![ast::QuantifierBinding {
        quantifier,
        var: quantified_var.to_string(),
        domain: role.to_string(),
    }];
    compile_temporal_buchi_automaton_with_bindings(&quantifiers, formula)
}

/// Compile a temporal property into an explicit Büchi monitor.
pub(super) fn compile_temporal_buchi_automaton_with_bindings(
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
) -> Result<TemporalBuchiAutomaton, PipelineError> {
    let representative_binding = quantifiers.first().ok_or_else(|| {
        PipelineError::Property("Temporal monitor requires at least one quantifier binding.".into())
    })?;
    let quantifier = representative_binding.quantifier;
    let quantified_var = representative_binding.var.as_str();
    let role = representative_binding.domain.as_str();

    let mut atoms = TemporalAtomTable::default();
    let negated = formula_to_temporal_nnf(formula, &mut atoms, true)?;

    let mut initial_seed = BTreeSet::new();
    initial_seed.insert(negated.clone());

    let mut seed_to_state_ids: BTreeMap<BTreeSet<TemporalFormula>, Vec<usize>> = BTreeMap::new();
    let mut pending_seeds = VecDeque::new();
    pending_seeds.push_back(initial_seed.clone());

    let mut state_by_old: BTreeMap<BTreeSet<TemporalFormula>, usize> = BTreeMap::new();
    let mut states = Vec::<TemporalBuchiState>::new();
    let mut pending_next_per_state = Vec::<Vec<BTreeSet<TemporalFormula>>>::new();

    while let Some(seed) = pending_seeds.pop_front() {
        if seed_to_state_ids.contains_key(&seed) {
            continue;
        }

        let expansions = expand_temporal_seed(&seed);
        let mut state_ids = Vec::new();

        for expansion in expansions {
            let label_lits: Vec<TemporalAtomLit> = expansion
                .literals
                .iter()
                .map(|(atom_id, value)| {
                    if *value {
                        TemporalAtomLit::Pos(*atom_id)
                    } else {
                        TemporalAtomLit::Neg(*atom_id)
                    }
                })
                .collect();

            let state_id = if let Some(existing) = state_by_old.get(&expansion.old) {
                let id = *existing;
                if states[id].label_lits != label_lits {
                    return Err(PipelineError::Property(
                        "Temporal automaton construction conflict: same logical state produced incompatible labels."
                            .into(),
                    ));
                }
                id
            } else {
                let id = states.len();
                state_by_old.insert(expansion.old.clone(), id);
                states.push(TemporalBuchiState {
                    old: expansion.old.clone(),
                    label_lits,
                    transitions: Vec::new(),
                });
                pending_next_per_state.push(Vec::new());
                id
            };

            if !pending_next_per_state[state_id]
                .iter()
                .any(|existing| existing == &expansion.next)
            {
                pending_next_per_state[state_id].push(expansion.next.clone());
            }
            if !seed_to_state_ids.contains_key(&expansion.next) {
                pending_seeds.push_back(expansion.next.clone());
            }
            state_ids.push(state_id);
        }

        state_ids.sort_unstable();
        state_ids.dedup();
        seed_to_state_ids.insert(seed, state_ids);
    }

    for (state_id, next_seeds) in pending_next_per_state.iter().enumerate() {
        let mut transitions = Vec::new();
        for next_seed in next_seeds {
            if let Some(ids) = seed_to_state_ids.get(next_seed) {
                transitions.extend(ids.iter().copied());
            }
        }
        transitions.sort_unstable();
        transitions.dedup();
        states[state_id].transitions = transitions;
    }

    let mut initial_states = seed_to_state_ids
        .get(&initial_seed)
        .cloned()
        .unwrap_or_default();
    initial_states.sort_unstable();
    initial_states.dedup();

    let mut until_formulas = BTreeSet::new();
    collect_until_formulas(&negated, &mut until_formulas);
    let mut acceptance_sets = Vec::new();
    for until_formula in until_formulas {
        let TemporalFormula::Until(_, rhs) = &until_formula else {
            continue;
        };
        let mut acc = Vec::new();
        for (sid, st) in states.iter().enumerate() {
            if !st.old.contains(&until_formula) || st.old.contains(rhs.as_ref()) {
                acc.push(sid);
            }
        }
        acceptance_sets.push(acc);
    }

    Ok(TemporalBuchiAutomaton {
        quantifier,
        quantified_var: quantified_var.to_string(),
        role: role.to_string(),
        quantifiers: quantifiers.to_vec(),
        atoms: atoms.atoms,
        states,
        initial_states,
        acceptance_sets,
    })
}

/// Encode a quantified state predicate at one time-step.
pub(super) fn build_quantified_state_predicate_term_with_bindings(
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
pub(super) fn build_quantified_state_predicate_term(
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

/// Encode a (possibly temporal) quantified formula on a bounded trace suffix.
#[cfg(test)]
pub(super) fn encode_quantified_temporal_formula_term(
    ta: &ThresholdAutomaton,
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
) -> Result<SmtTerm, PipelineError> {
    let quantifiers = vec![ast::QuantifierBinding {
        quantifier,
        var: quantified_var.to_string(),
        domain: role.to_string(),
    }];
    encode_quantified_temporal_formula_term_with_bindings(ta, &quantifiers, formula, step, depth)
}

/// Encode a (possibly temporal) quantified formula on a bounded trace suffix.
pub(super) fn encode_quantified_temporal_formula_term_with_bindings(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
) -> Result<SmtTerm, PipelineError> {
    let mut memo = HashMap::new();
    encode_quantified_temporal_formula_term_with_bindings_cached(
        ta,
        quantifiers,
        formula,
        step,
        depth,
        &mut memo,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TemporalEncodingMemoKey {
    formula_ptr: usize,
    step: usize,
}

fn temporal_encoding_memo_key(formula: &ast::FormulaExpr, step: usize) -> TemporalEncodingMemoKey {
    TemporalEncodingMemoKey {
        formula_ptr: formula as *const ast::FormulaExpr as usize,
        step,
    }
}

fn encode_quantified_temporal_always_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    inner: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let terms = (step..=depth)
        .map(|i| {
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                i,
                depth,
                memo,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SmtTerm::and(terms))
}

fn encode_quantified_temporal_eventually_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    inner: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let terms = (step..=depth)
        .map(|i| {
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                i,
                depth,
                memo,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SmtTerm::or(terms))
}

fn encode_quantified_temporal_until_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    lhs: &ast::FormulaExpr,
    rhs: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let mut disjuncts = Vec::new();
    for j in step..=depth {
        let rhs_at_j = encode_quantified_temporal_formula_term_with_bindings_cached(
            ta,
            quantifiers,
            rhs,
            j,
            depth,
            memo,
        )?;
        let mut conjuncts = vec![rhs_at_j];
        for i in step..j {
            conjuncts.push(
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?,
            );
        }
        disjuncts.push(SmtTerm::and(conjuncts));
    }
    Ok(SmtTerm::or(disjuncts))
}

fn encode_quantified_temporal_release_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    lhs: &ast::FormulaExpr,
    rhs: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    // Finite-trace expansion equivalent to dual translation:
    //   lhs R rhs == !((!lhs) U (!rhs))
    // and expanded as:
    //   /\_{j=step..depth} ( rhs@j \/ \/_{i=step..j-1} lhs@i )
    let mut conjuncts = Vec::new();
    for j in step..=depth {
        let rhs_at_j = encode_quantified_temporal_formula_term_with_bindings_cached(
            ta,
            quantifiers,
            rhs,
            j,
            depth,
            memo,
        )?;
        let mut disjuncts = vec![rhs_at_j];
        for i in step..j {
            disjuncts.push(
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?,
            );
        }
        conjuncts.push(SmtTerm::or(disjuncts));
    }
    Ok(SmtTerm::and(conjuncts))
}

fn encode_quantified_temporal_formula_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    if step > depth {
        return Ok(SmtTerm::bool(false));
    }
    let memo_key = temporal_encoding_memo_key(formula, step);
    if let Some(cached) = memo.get(&memo_key) {
        return Ok(cached.clone());
    }

    if !formula_contains_temporal(formula) {
        let term =
            build_quantified_state_predicate_term_with_bindings(ta, quantifiers, formula, step)?;
        memo.insert(memo_key, term.clone());
        return Ok(term);
    }
    let encoded = match formula {
        ast::FormulaExpr::Comparison { .. } => {
            build_quantified_state_predicate_term_with_bindings(ta, quantifiers, formula, step)
        }
        ast::FormulaExpr::Not(inner) => Ok(SmtTerm::not(
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )?,
        )),
        ast::FormulaExpr::And(lhs, rhs) => Ok(SmtTerm::and(vec![
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Or(lhs, rhs) => Ok(SmtTerm::or(vec![
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let l = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?;
            let r = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?;
            Ok(SmtTerm::or(vec![SmtTerm::not(l), r]))
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let l = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?;
            let r = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?;
            Ok(SmtTerm::or(vec![
                SmtTerm::and(vec![l.clone(), r.clone()]),
                SmtTerm::and(vec![SmtTerm::not(l), SmtTerm::not(r)]),
            ]))
        }
        ast::FormulaExpr::Next(inner) => {
            if step == depth {
                Ok(SmtTerm::bool(false))
            } else {
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    inner,
                    step + 1,
                    depth,
                    memo,
                )
            }
        }
        ast::FormulaExpr::Always(inner) => {
            encode_quantified_temporal_always_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::Eventually(inner) => {
            encode_quantified_temporal_eventually_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            encode_quantified_temporal_until_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => Ok(SmtTerm::or(vec![
            encode_quantified_temporal_until_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_always_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Release(lhs, rhs) => {
            encode_quantified_temporal_release_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let mut conjuncts = Vec::new();
            for i in step..=depth {
                let lhs_i = encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?;
                let future_rhs = (i..=depth)
                    .map(|j| {
                        encode_quantified_temporal_formula_term_with_bindings_cached(
                            ta,
                            quantifiers,
                            rhs,
                            j,
                            depth,
                            memo,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                conjuncts.push(SmtTerm::or(vec![
                    SmtTerm::not(lhs_i),
                    SmtTerm::or(future_rhs),
                ]));
            }
            Ok(SmtTerm::and(conjuncts))
        }
    }?;

    memo.insert(memo_key, encoded.clone());
    Ok(encoded)
}

/// Extract and validate one liveness declaration into an executable liveness spec.
pub(super) fn extract_liveness_spec_from_decl(
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

pub(super) fn extract_liveness_spec(
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

pub(super) fn fair_liveness_target_from_spec(
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
pub(super) fn resolve_param_or_const(
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

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::{Guard, Location, Parameter, Rule};
    use tarsier_smt::terms::SmtTerm;

    fn qvar(object: &str, field: &str) -> ast::FormulaAtom {
        ast::FormulaAtom::QualifiedVar {
            object: object.to_string(),
            field: field.to_string(),
        }
    }

    fn cmp(lhs: ast::FormulaAtom, op: ast::CmpOp, rhs: ast::FormulaAtom) -> ast::FormulaExpr {
        ast::FormulaExpr::Comparison { lhs, op, rhs }
    }

    fn forall(var: &str, domain: &str) -> ast::QuantifierBinding {
        ast::QuantifierBinding {
            quantifier: ast::Quantifier::ForAll,
            var: var.to_string(),
            domain: domain.to_string(),
        }
    }

    fn exists(var: &str, domain: &str) -> ast::QuantifierBinding {
        ast::QuantifierBinding {
            quantifier: ast::Quantifier::Exists,
            var: var.to_string(),
            domain: domain.to_string(),
        }
    }

    fn liveness_prop(
        name: &str,
        quantifiers: Vec<ast::QuantifierBinding>,
        body: ast::FormulaExpr,
    ) -> ast::PropertyDecl {
        ast::PropertyDecl {
            name: name.to_string(),
            kind: ast::PropertyKind::Liveness,
            formula: ast::QuantifiedFormula { quantifiers, body },
        }
    }

    fn test_ta() -> ThresholdAutomaton {
        fn mk_loc(
            name: &str,
            role: &str,
            phase: &str,
            decided: bool,
            flag: bool,
            mode: &str,
            round: i64,
        ) -> Location {
            let mut loc = Location {
                name: name.to_string(),
                role: role.to_string(),
                phase: phase.to_string(),
                local_vars: Default::default(),
            };
            loc.local_vars
                .insert("decided".to_string(), LocalValue::Bool(decided));
            loc.local_vars
                .insert("flag".to_string(), LocalValue::Bool(flag));
            loc.local_vars
                .insert("mode".to_string(), LocalValue::Enum(mode.to_string()));
            loc.local_vars
                .insert("round".to_string(), LocalValue::Int(round));
            loc
        }

        let mut ta = ThresholdAutomaton::new();
        ta.parameters.push(Parameter {
            name: "n".to_string(),
        });
        ta.locations
            .push(mk_loc("r0", "R", "p0", false, true, "Init", 0)); // 0
        ta.locations
            .push(mk_loc("r1", "R", "p1", true, true, "Commit", 1)); // 1
        ta.locations
            .push(mk_loc("r2", "R", "p2", false, false, "Alt", 2)); // 2
        ta.locations
            .push(mk_loc("s0", "S", "s0", false, true, "Other", 0)); // 3
        ta.locations
            .push(mk_loc("ghost", "R", "u", true, true, "Ghost", 99)); // 4 unreachable
        ta.initial_locations = vec![0, 3];

        ta.rules.push(Rule {
            from: 0,
            to: 1,
            guard: Guard::trivial(),
            updates: vec![],
        });
        ta.rules.push(Rule {
            from: 1,
            to: 2,
            guard: Guard::trivial(),
            updates: vec![],
        });
        ta.rules.push(Rule {
            from: 3,
            to: 3,
            guard: Guard::trivial(),
            updates: vec![],
        });
        ta
    }

    #[test]
    fn parse_helpers_handle_outer_always_and_guarded_agreement_shape() {
        let eq = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Always(Box::new(cmp(
            qvar("p", "x"),
            ast::CmpOp::Eq,
            qvar("q", "x"),
        )))));
        assert_eq!(
            parse_qualified_eq(&eq),
            Some(("p".to_string(), "q".to_string(), "x".to_string()))
        );
        assert_eq!(
            parse_qualified_eq_bool(&cmp(
                ast::FormulaAtom::BoolLit(true),
                ast::CmpOp::Eq,
                qvar("p", "decided")
            )),
            Some(("p".to_string(), "decided".to_string(), true))
        );
        assert_eq!(
            parse_qualified_eq(&cmp(qvar("p", "x"), ast::CmpOp::Ne, qvar("q", "x"))),
            None
        );

        let guarded = ast::FormulaExpr::Implies(
            Box::new(ast::FormulaExpr::And(
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
            )),
            Box::new(cmp(qvar("p", "vote"), ast::CmpOp::Eq, qvar("q", "vote"))),
        );
        assert_eq!(
            parse_guarded_agreement(&guarded),
            Some((
                "decided".to_string(),
                "vote".to_string(),
                "p".to_string(),
                "q".to_string()
            ))
        );
    }

    #[test]
    fn collect_guard_comparisons_rejects_non_boolean_clauses() {
        let mut out = Vec::new();
        let expr = ast::FormulaExpr::And(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
            Box::new(cmp(
                qvar("q", "round"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::IntLit(1),
            )),
        );
        assert!(!collect_guard_comparisons(&expr, &mut out));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn reachability_and_goal_helpers_respect_unreachable_locations() {
        let ta = test_ta();
        let reachable = graph_reachable_locations(&ta);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
        assert!(!reachable.contains(&4));

        assert_eq!(collect_decided_goal_locs(&ta), vec![1, 4]);
        assert_eq!(collect_non_goal_reachable_locs(&ta, &[1]), vec![0, 2, 3]);
    }

    #[test]
    fn location_group_helpers_cover_success_and_error_branches() {
        let ta = test_ta();
        let reachable = graph_reachable_locations(&ta);

        let (true_locs, false_locs) =
            locs_by_bool_var(&ta, "R", "decided", &reachable).expect("bool grouping");
        assert_eq!(true_locs, vec![1]);
        assert_eq!(false_locs, vec![0, 2]);

        let err = locs_by_bool_var(&ta, "R", "mode", &reachable).expect_err("non-bool must fail");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("not boolean")),
            other => panic!("unexpected error: {other}"),
        }
        assert!(locs_by_bool_var(&ta, "R", "missing", &reachable).is_err());

        let by_mode = locs_by_local_var(&ta, "R", "mode", &reachable).expect("mode groups");
        assert_eq!(by_mode.len(), 3);
        assert_eq!(
            by_mode.get(&LocalValue::Enum("Init".to_string())).cloned(),
            Some(vec![0])
        );
        assert!(locs_by_local_var(&ta, "R", "missing", &reachable).is_err());

        let guarded = locs_by_local_var_with_guard(&ta, "R", "mode", "flag", &reachable)
            .expect("guarded groups");
        assert_eq!(guarded.len(), 2);
        assert_eq!(
            guarded.get(&LocalValue::Enum("Init".to_string())).cloned(),
            Some(vec![0])
        );
        assert_eq!(
            guarded
                .get(&LocalValue::Enum("Commit".to_string()))
                .cloned(),
            Some(vec![1])
        );
        assert!(locs_by_local_var_with_guard(&ta, "R", "decided", "mode", &reachable).is_err());
        assert!(locs_by_local_var_with_guard(&ta, "R", "mode", "missing", &reachable).is_err());
    }

    #[test]
    fn conflict_builder_emits_cartesian_pairs_across_distinct_value_groups() {
        let mut groups = std::collections::HashMap::new();
        groups.insert(LocalValue::Bool(true), vec![1, 2]);
        groups.insert(LocalValue::Bool(false), vec![5]);
        let mut out = Vec::new();
        build_conflicts_from_groups(&groups, &mut out);
        for (a, b) in &mut out {
            if *a > *b {
                std::mem::swap(a, b);
            }
        }
        out.sort_unstable();
        assert_eq!(out, vec![(1, 5), (2, 5)]);
    }

    #[test]
    fn formula_atom_and_comparison_evaluation_enforces_type_rules() {
        let ta = test_ta();
        let loc = &ta.locations[0];

        assert_eq!(
            eval_formula_atom_on_location(&ast::FormulaAtom::IntLit(7), "p", loc).unwrap(),
            FormulaValue::Int(7)
        );
        assert_eq!(
            eval_formula_atom_on_location(&ast::FormulaAtom::Var("mode".to_string()), "p", loc)
                .unwrap(),
            FormulaValue::Enum("Init".to_string())
        );
        assert_eq!(
            eval_formula_atom_on_location(
                &ast::FormulaAtom::Var("UNRESOLVED".to_string()),
                "p",
                loc
            )
            .unwrap(),
            FormulaValue::Enum("UNRESOLVED".to_string())
        );
        assert!(eval_formula_atom_on_location(&qvar("q", "decided"), "p", loc).is_err());
        assert!(eval_formula_atom_on_location(&qvar("p", "missing"), "p", loc).is_err());

        assert!(eval_formula_comparison(
            ast::CmpOp::Eq,
            FormulaValue::Bool(true),
            FormulaValue::Bool(true)
        )
        .unwrap());
        assert!(eval_formula_comparison(
            ast::CmpOp::Lt,
            FormulaValue::Int(1),
            FormulaValue::Int(2)
        )
        .unwrap());
        assert!(eval_formula_comparison(
            ast::CmpOp::Eq,
            FormulaValue::Enum("A".to_string()),
            FormulaValue::Enum("A".to_string())
        )
        .unwrap());
        assert!(eval_formula_comparison(
            ast::CmpOp::Ge,
            FormulaValue::Bool(true),
            FormulaValue::Bool(false)
        )
        .is_err());
        assert!(eval_formula_comparison(
            ast::CmpOp::Gt,
            FormulaValue::Enum("A".to_string()),
            FormulaValue::Enum("B".to_string())
        )
        .is_err());
        assert!(eval_formula_comparison(
            ast::CmpOp::Eq,
            FormulaValue::Bool(true),
            FormulaValue::Int(1)
        )
        .is_err());
    }

    #[test]
    fn formula_expr_eval_and_temporal_detection_cover_key_branches() {
        let ta = test_ta();
        let loc = &ta.locations[0];
        let decided_false = cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(false),
        );
        let round_is_zero = cmp(
            qvar("p", "round"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::IntLit(0),
        );
        let round_is_one = cmp(
            qvar("p", "round"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::IntLit(1),
        );

        assert!(eval_formula_expr_on_location(
            &ast::FormulaExpr::And(
                Box::new(decided_false.clone()),
                Box::new(round_is_zero.clone())
            ),
            "p",
            loc
        )
        .unwrap());
        assert!(!eval_formula_expr_on_location(
            &ast::FormulaExpr::Or(
                Box::new(round_is_one.clone()),
                Box::new(ast::FormulaExpr::Not(Box::new(round_is_zero.clone())))
            ),
            "p",
            loc
        )
        .unwrap());
        assert!(eval_formula_expr_on_location(
            &ast::FormulaExpr::Implies(
                Box::new(round_is_one.clone()),
                Box::new(round_is_zero.clone())
            ),
            "p",
            loc
        )
        .unwrap());
        assert!(eval_formula_expr_on_location(
            &ast::FormulaExpr::Iff(
                Box::new(decided_false.clone()),
                Box::new(decided_false.clone())
            ),
            "p",
            loc
        )
        .unwrap());
        assert!(eval_formula_expr_on_location(
            &ast::FormulaExpr::Always(Box::new(decided_false.clone())),
            "p",
            loc
        )
        .is_err());

        assert!(!formula_contains_temporal(&decided_false));
        assert!(formula_contains_temporal(&ast::FormulaExpr::Eventually(
            Box::new(round_is_zero)
        )));
    }

    #[test]
    fn temporal_simplifiers_and_nnf_translation_behave_canonically() {
        assert_eq!(
            temporal_and(TemporalFormula::False, TemporalFormula::Atom(1)),
            TemporalFormula::False
        );
        assert_eq!(
            temporal_and(TemporalFormula::Atom(2), TemporalFormula::Atom(1)),
            TemporalFormula::And(
                Box::new(TemporalFormula::Atom(1)),
                Box::new(TemporalFormula::Atom(2))
            )
        );
        assert_eq!(
            temporal_or(TemporalFormula::False, TemporalFormula::Atom(1)),
            TemporalFormula::Atom(1)
        );
        assert_eq!(
            temporal_until(TemporalFormula::False, TemporalFormula::Atom(3)),
            TemporalFormula::Atom(3)
        );
        assert_eq!(
            temporal_release(TemporalFormula::True, TemporalFormula::Atom(4)),
            TemporalFormula::Atom(4)
        );

        let mut atoms = TemporalAtomTable::default();
        let weak = ast::FormulaExpr::WeakUntil(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(false),
            )),
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
        );
        let nnf = formula_to_temporal_nnf(&weak, &mut atoms, false).expect("weak-until nnf");
        let mut untils = BTreeSet::new();
        collect_until_formulas(&nnf, &mut untils);
        assert!(!untils.is_empty());
        assert!(!temporal_formula_canonical(&nnf).is_empty());
    }

    #[test]
    fn temporal_seed_expansion_handles_conflicts_dedup_and_branching() {
        let mut todo = vec![TemporalFormula::Atom(1)];
        let mut old = BTreeSet::new();
        old.insert(TemporalFormula::Atom(0));
        temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(0));
        temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(1));
        temporal_push_todo(&mut todo, &old, TemporalFormula::Atom(2));
        assert_eq!(todo.len(), 2);

        let conflict_seed = BTreeSet::from([TemporalFormula::Atom(0), TemporalFormula::NotAtom(0)]);
        let conflict_outcomes = expand_temporal_seed(&conflict_seed);
        assert!(conflict_outcomes.is_empty());

        let or_seed = BTreeSet::from([TemporalFormula::Or(
            Box::new(TemporalFormula::Atom(0)),
            Box::new(TemporalFormula::Atom(1)),
        )]);
        let outcomes = expand_temporal_seed(&or_seed);
        assert_eq!(outcomes.len(), 2);
    }

    #[test]
    fn temporal_compilation_and_encoding_helpers_cover_boundary_branches() {
        let ta = test_ta();
        let always_true = ast::FormulaExpr::Always(Box::new(cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        )));
        let monitor =
            compile_temporal_buchi_automaton(ast::Quantifier::ForAll, "p", "R", &always_true)
                .expect("temporal compile");
        assert!(!monitor.states.is_empty());
        assert!(!monitor.initial_states.is_empty());
        let canonical = temporal_buchi_monitor_canonical(&monitor);
        assert!(canonical.contains("quantifier=forall;quantified_var=p;role=R"));

        let decided_true = cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        );
        let state_term = build_quantified_state_predicate_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &decided_true,
            2,
        )
        .unwrap();
        assert_eq!(
            state_term,
            SmtTerm::and(vec![
                SmtTerm::var(pdr_kappa_var(2, 0)).eq(SmtTerm::int(0)),
                SmtTerm::var(pdr_kappa_var(2, 2)).eq(SmtTerm::int(0)),
            ])
        );

        let always_nonnegative = cmp(
            qvar("p", "round"),
            ast::CmpOp::Ge,
            ast::FormulaAtom::IntLit(0),
        );
        assert_eq!(
            build_quantified_state_predicate_term(
                &ta,
                ast::Quantifier::ForAll,
                "p",
                "R",
                &always_nonnegative,
                0,
            )
            .unwrap(),
            SmtTerm::bool(true)
        );
        assert_eq!(
            build_quantified_state_predicate_term(
                &ta,
                ast::Quantifier::Exists,
                "p",
                "R",
                &decided_true,
                0,
            )
            .unwrap(),
            SmtTerm::or(vec![
                SmtTerm::var(pdr_kappa_var(0, 1)).gt(SmtTerm::int(0)),
                SmtTerm::var(pdr_kappa_var(0, 4)).gt(SmtTerm::int(0)),
            ])
        );
        assert_eq!(
            build_quantified_state_predicate_term(
                &ta,
                ast::Quantifier::Exists,
                "p",
                "R",
                &cmp(
                    qvar("p", "round"),
                    ast::CmpOp::Gt,
                    ast::FormulaAtom::IntLit(1000)
                ),
                0,
            )
            .unwrap(),
            SmtTerm::bool(false)
        );

        assert_eq!(
            encode_quantified_temporal_formula_term(
                &ta,
                ast::Quantifier::ForAll,
                "p",
                "R",
                &decided_true,
                3,
                2,
            )
            .unwrap(),
            SmtTerm::bool(false)
        );
        assert_eq!(
            encode_quantified_temporal_formula_term(
                &ta,
                ast::Quantifier::ForAll,
                "p",
                "R",
                &ast::FormulaExpr::Next(Box::new(decided_true.clone())),
                2,
                2
            )
            .unwrap(),
            SmtTerm::bool(false)
        );
        assert_eq!(
            encode_quantified_temporal_formula_term(
                &ta,
                ast::Quantifier::ForAll,
                "p",
                "R",
                &decided_true,
                1,
                2,
            )
            .unwrap(),
            build_quantified_state_predicate_term(
                &ta,
                ast::Quantifier::ForAll,
                "p",
                "R",
                &decided_true,
                1,
            )
            .unwrap()
        );

        let weak_until = ast::FormulaExpr::WeakUntil(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(false),
            )),
            Box::new(decided_true.clone()),
        );
        match encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &weak_until,
            0,
            2,
        )
        .unwrap()
        {
            SmtTerm::Or(parts) => assert_eq!(parts.len(), 2),
            other => panic!("expected weak-until desugaring to OR, got {other:?}"),
        }

        let release_lhs = cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(false),
        );
        let release_rhs = decided_true.clone();
        let release =
            ast::FormulaExpr::Release(Box::new(release_lhs.clone()), Box::new(release_rhs.clone()));
        let release_dual = ast::FormulaExpr::Not(Box::new(ast::FormulaExpr::Until(
            Box::new(ast::FormulaExpr::Not(Box::new(release_lhs))),
            Box::new(ast::FormulaExpr::Not(Box::new(release_rhs))),
        )));
        let release_term = encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &release,
            0,
            2,
        )
        .unwrap();
        let release_dual_term = encode_quantified_temporal_formula_term(
            &ta,
            ast::Quantifier::ForAll,
            "p",
            "R",
            &release_dual,
            0,
            2,
        )
        .unwrap();
        match release_term {
            SmtTerm::And(parts) => assert_eq!(parts.len(), 3),
            other => panic!("expected release expansion to AND, got {other:?}"),
        }
        match release_dual_term {
            SmtTerm::Not(_) => {}
            other => panic!("expected release dual form to be wrapped by NOT, got {other:?}"),
        }
    }

    #[test]
    fn liveness_extraction_and_target_resolution_cover_error_and_success_paths() {
        let ta = test_ta();
        let propositional = cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        );
        let temporal = ast::FormulaExpr::Eventually(Box::new(propositional.clone()));

        let err = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop("bad", vec![], propositional.clone()),
        )
        .expect_err("missing quantifier must fail");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("at least 1 quantifier")),
            other => panic!("unexpected error: {other}"),
        }
        let err = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "bad_role",
                vec![forall("p", "UnknownRole")],
                propositional.clone(),
            ),
        )
        .expect_err("unknown role must fail");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("unknown role")),
            other => panic!("unexpected error: {other}"),
        }

        let spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "live_extra_forall",
                vec![forall("p", "R"), forall("q", "R")],
                propositional.clone(),
            ),
        )
        .expect("unused universal quantifier should be accepted");
        match spec {
            LivenessSpec::TerminationGoalLocs(goal_locs) => assert_eq!(goal_locs, vec![1, 3]),
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let err = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "bad_extra_exists",
                vec![forall("p", "R"), exists("q", "R")],
                propositional.clone(),
            ),
        )
        .expect_err("unused existential quantifier should be rejected");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("unused universal")),
            other => panic!("unexpected error: {other}"),
        }

        let spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop("live", vec![forall("p", "R")], propositional.clone()),
        )
        .expect("propositional liveness should compile");
        match spec.clone() {
            LivenessSpec::TerminationGoalLocs(goal_locs) => assert_eq!(goal_locs, vec![1, 3]),
            other => panic!("expected termination spec, got {other:?}"),
        }

        let temporal_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop("live_t", vec![forall("p", "R")], temporal),
        )
        .expect("temporal liveness should compile");
        match temporal_spec.clone() {
            LivenessSpec::Temporal { quantifiers, .. } => {
                assert_eq!(quantifiers, vec![forall("p", "R")]);
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let exists_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop("exists_live", vec![exists("p", "R")], propositional.clone()),
        )
        .expect("existential liveness should compile");
        match exists_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![exists("p", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(propositional.clone()))
                );
            }
            other => panic!("expected temporal exists spec, got {other:?}"),
        }

        match fair_liveness_target_from_spec(&ta, spec).expect("termination target") {
            FairLivenessTarget::NonGoalLocs(locs) => assert_eq!(locs, vec![0, 2]),
            other => panic!("expected non-goal target, got {other:?}"),
        }
        match fair_liveness_target_from_spec(&ta, temporal_spec).expect("temporal target") {
            FairLivenessTarget::Temporal(automaton) => assert!(!automaton.states.is_empty()),
            other => panic!("expected temporal target, got {other:?}"),
        }
    }

    #[test]
    fn liveness_multi_quantifier_normalization_enforces_soundness_guards() {
        let ta = test_ta();

        let forall_multi_ref_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "forall_multi_ref",
                vec![forall("p", "R"), forall("q", "R")],
                ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                ),
            ),
        )
        .expect("propositional forall multi-ref should route to temporal monitoring");
        match forall_multi_ref_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                        Box::new(cmp(
                            qvar("p", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                        Box::new(cmp(
                            qvar("q", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                    )))
                );
            }
            other => panic!("expected termination spec, got {other:?}"),
        }

        let exists_multi_ref_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "exists_multi_ref_or",
                vec![exists("p", "R"), exists("q", "R")],
                ast::FormulaExpr::Or(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                ),
            ),
        )
        .expect("disjunctive exists multi-ref should preserve both quantified refs");
        match exists_multi_ref_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![exists("p", "R"), exists("q", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::Or(
                        Box::new(cmp(
                            qvar("p", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                        Box::new(cmp(
                            qvar("q", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                    )))
                );
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let err = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_extra_exists",
                vec![forall("p", "R"), forall("q", "R"), exists("z", "R")],
                ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                ),
            ),
        )
        .expect_err("unreferenced existential extras should be rejected in multi-ref path");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("unsupported existential extras")),
            other => panic!("unexpected error: {other}"),
        }

        let mixed_quantifiers_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_mixed_quantifiers",
                vec![forall("p", "R"), exists("q", "R")],
                ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                ),
            ),
        )
        .expect("mixed quantifier kinds in multi-ref liveness should be supported");
        match mixed_quantifiers_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), exists("q", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                        Box::new(cmp(
                            qvar("p", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                        Box::new(cmp(
                            qvar("q", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                    )))
                );
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let mixed_roles_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_mixed_roles",
                vec![forall("p", "R"), forall("q", "S")],
                ast::FormulaExpr::And(
                    Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                    Box::new(cmp(
                        qvar("q", "decided"),
                        ast::CmpOp::Eq,
                        ast::FormulaAtom::BoolLit(true),
                    )),
                ),
            ),
        )
        .expect("mixed roles in multi-ref liveness should be supported");
        match mixed_roles_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "S")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
                        Box::new(cmp(
                            qvar("p", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                        Box::new(cmp(
                            qvar("q", "decided"),
                            ast::CmpOp::Eq,
                            ast::FormulaAtom::BoolLit(true),
                        )),
                    )))
                );
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let temporal_formula = ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
            Box::new(cmp(
                qvar("q", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
        )));
        let temporal_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_temporal",
                vec![forall("p", "R"), forall("q", "R")],
                temporal_formula.clone(),
            ),
        )
        .expect("temporal multi-ref liveness should now be supported");
        match temporal_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
                assert_eq!(formula, temporal_formula);
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let mixed_temporal = ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::And(
            Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )),
            Box::new(cmp(
                qvar("q", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(false),
            )),
        )));
        let mixed_temporal_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_temporal_mixed",
                vec![forall("p", "R"), exists("q", "S")],
                mixed_temporal.clone(),
            ),
        )
        .expect("temporal multi-ref with mixed quantifier/role should be supported");
        match mixed_temporal_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), exists("q", "S")]);
                assert_eq!(formula, mixed_temporal);
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let cross_compare_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_cross_compare",
                vec![forall("p", "R"), forall("q", "R")],
                cmp(qvar("p", "decided"), ast::CmpOp::Eq, qvar("q", "decided")),
            ),
        )
        .expect("cross-variable comparisons should be supported via temporal monitoring");
        match cross_compare_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(cmp(
                        qvar("p", "decided"),
                        ast::CmpOp::Eq,
                        qvar("q", "decided")
                    )))
                );
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }

        let complex_multi_ref = ast::FormulaExpr::Iff(
            Box::new(ast::FormulaExpr::Not(Box::new(cmp(
                qvar("p", "decided"),
                ast::CmpOp::Eq,
                ast::FormulaAtom::BoolLit(true),
            )))),
            Box::new(ast::FormulaExpr::Implies(
                Box::new(cmp(
                    qvar("q", "decided"),
                    ast::CmpOp::Eq,
                    ast::FormulaAtom::BoolLit(true),
                )),
                Box::new(cmp(
                    qvar("p", "decided"),
                    ast::CmpOp::Eq,
                    qvar("q", "decided"),
                )),
            )),
        );
        let complex_multi_ref_spec = extract_liveness_spec_from_decl(
            &ta,
            &liveness_prop(
                "multi_ref_not_implies_iff",
                vec![forall("p", "R"), forall("q", "R")],
                complex_multi_ref.clone(),
            ),
        )
        .expect("complex multi-ref propositional forms should be supported");
        match complex_multi_ref_spec {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![forall("p", "R"), forall("q", "R")]);
                assert_eq!(
                    formula,
                    ast::FormulaExpr::Eventually(Box::new(complex_multi_ref))
                );
            }
            other => panic!("expected temporal spec, got {other:?}"),
        }
    }

    #[test]
    fn safety_kind_exists_predicate_is_wrapped_as_always_temporal_spec() {
        let ta = test_ta();
        let body = cmp(
            qvar("p", "decided"),
            ast::CmpOp::Eq,
            ast::FormulaAtom::BoolLit(true),
        );
        let prop = ast::PropertyDecl {
            name: "safe_exists".to_string(),
            kind: ast::PropertyKind::Safety,
            formula: ast::QuantifiedFormula {
                quantifiers: vec![exists("p", "R")],
                body: body.clone(),
            },
        };
        match extract_liveness_spec_from_decl(&ta, &prop).expect("safety exists wraps to temporal")
        {
            LivenessSpec::Temporal {
                quantifiers,
                formula,
                ..
            } => {
                assert_eq!(quantifiers, vec![exists("p", "R")]);
                assert_eq!(formula, ast::FormulaExpr::Always(Box::new(body)));
            }
            other => panic!("expected wrapped temporal spec, got {other:?}"),
        }
    }

    #[test]
    fn extract_liveness_spec_program_level_and_param_resolution_helpers_work() {
        let ta = test_ta();

        let src_no_liveness = r#"
protocol NoLive {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
        let program = tarsier_dsl::parse(src_no_liveness, "no_live.trs").expect("parse");
        match extract_liveness_spec(&ta, &program).expect("default liveness spec") {
            LivenessSpec::TerminationGoalLocs(goal_locs) => {
                assert_eq!(goal_locs, collect_decided_goal_locs(&ta))
            }
            other => panic!("expected default decided-goal spec, got {other:?}"),
        }

        let src_multi = r#"
protocol MultiLive {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property l1: liveness {
        forall p: R. p.decided == true
    }
    property l2: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
        let program_multi = tarsier_dsl::parse(src_multi, "multi_live.trs").expect("parse");
        assert!(extract_liveness_spec(&ta, &program_multi).is_err());

        assert_eq!(
            resolve_param_or_const(&ParamOrConst::Const(7), &ta).unwrap(),
            7
        );
        assert!(resolve_param_or_const(&ParamOrConst::Param(0), &ta).is_err());
    }

    #[test]
    fn property_kind_helpers_and_program_scans_are_consistent() {
        assert!(is_safety_property_kind(ast::PropertyKind::Agreement));
        assert!(is_safety_property_kind(ast::PropertyKind::Safety));
        assert!(!is_safety_property_kind(ast::PropertyKind::Liveness));
        assert!(is_liveness_property_kind(ast::PropertyKind::Liveness));
        assert!(!is_liveness_property_kind(ast::PropertyKind::Invariant));

        let src = r#"
protocol KindScan {
    params n, t;
    resilience: n > 3*t;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
        let program = tarsier_dsl::parse(src, "kind_scan.trs").expect("parse");
        assert!(has_safety_properties(&program));
        assert!(has_liveness_properties(&program));
    }

    #[test]
    fn select_property_for_ta_export_prefers_liveness_termination_when_no_safety() {
        let src = r#"
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
        let program = tarsier_dsl::parse(src, "export_term_only.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        match select_property_for_ta_export(&ta, &program) {
            SafetyProperty::Termination { goal_locs } => {
                assert!(
                    !goal_locs.is_empty(),
                    "termination goals should be non-empty"
                );
            }
            other => panic!("expected termination export property, got {other:?}"),
        }
    }

    #[test]
    fn select_property_for_ta_export_falls_back_from_temporal_liveness() {
        let src = r#"
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
        let program = tarsier_dsl::parse(src, "export_temporal.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");
        match select_property_for_ta_export(&ta, &program) {
            SafetyProperty::Agreement { .. } => {}
            other => panic!("expected agreement fallback for temporal liveness, got {other:?}"),
        }
    }

    #[test]
    fn select_ta_export_property_preserves_temporal_liveness() {
        let src = r#"
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
        let program = tarsier_dsl::parse(src, "export_temporal_selector.trs").expect("parse");
        let ta = tarsier_ir::lowering::lower(&program).expect("lower");

        match select_ta_export_property(&ta, &program) {
            TaExportProperty::Temporal {
                quantifiers,
                formula,
            } => {
                assert_eq!(quantifiers.len(), 1, "expected one temporal quantifier");
                assert!(
                    formula_contains_temporal(&formula),
                    "expected preserved temporal formula"
                );
            }
            other => panic!("expected temporal export property, got {other:?}"),
        }
    }
}
