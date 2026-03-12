//! CEGAR types, refinement logic, oracle, scoring, and reporting.

use crate::pipeline::verification::*;
use crate::pipeline::*;

mod oracle;
pub(crate) use oracle::*;

mod reporting;
pub(crate) use reporting::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CegarRefinementKind {
    GlobalEquivocationNone,
    GlobalAuthSigned,
    GlobalValuesExact,
    GlobalNetworkIdentitySelective,
    GlobalNetworkProcessSelective,
    MessageEquivocationNone { message: String },
    MessageAuthAuthenticated { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CegarAtomicRefinement {
    pub(crate) kind: CegarRefinementKind,
    pub(crate) label: String,
    pub(crate) predicate: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CegarRefinement {
    pub(crate) atoms: Vec<CegarAtomicRefinement>,
}

#[derive(Debug, Clone)]
pub(crate) struct CegarRefinementPlanEntry {
    pub(crate) refinement: CegarRefinement,
    pub(crate) rationale: String,
}

impl CegarRefinement {
    pub(crate) fn label(&self) -> String {
        self.atoms
            .iter()
            .map(|atom| atom.label.clone())
            .collect::<Vec<_>>()
            .join("+")
    }

    pub(crate) fn refinements(&self) -> Vec<String> {
        self.atoms
            .iter()
            .map(|atom| atom.predicate.clone())
            .collect()
    }

    pub(crate) fn apply(&self, program: &mut ast::Program) {
        let proto = &mut program.protocol.node;
        for atom in &self.atoms {
            atom.apply(proto);
        }
        let network = adversary_value(proto, "network")
            .or_else(|| adversary_value(proto, "network_semantics"))
            .unwrap_or("classic")
            .to_string();
        ensure_identity_and_auth_for_faithful_mode(proto, &network);
    }
}

impl CegarAtomicRefinement {
    pub(crate) fn global(
        kind: CegarRefinementKind,
        label: &'static str,
        predicate: &'static str,
    ) -> Self {
        Self {
            kind,
            label: label.to_string(),
            predicate: predicate.to_string(),
        }
    }

    pub(crate) fn message_equivocation_none(message: &str) -> Self {
        Self {
            kind: CegarRefinementKind::MessageEquivocationNone {
                message: message.to_string(),
            },
            label: format!("equivocation:{message}=none"),
            predicate: format!("equivocation({message})=none"),
        }
    }

    pub(crate) fn message_auth_authenticated(message: &str) -> Self {
        Self {
            kind: CegarRefinementKind::MessageAuthAuthenticated {
                message: message.to_string(),
            },
            label: format!("channel:{message}=authenticated"),
            predicate: format!("channel({message})=authenticated"),
        }
    }

    pub(crate) fn apply(&self, proto: &mut ast::ProtocolDecl) {
        match &self.kind {
            CegarRefinementKind::GlobalEquivocationNone => {
                upsert_adversary_item(proto, "equivocation", "none");
            }
            CegarRefinementKind::GlobalAuthSigned => {
                upsert_adversary_item(proto, "auth", "signed");
            }
            CegarRefinementKind::GlobalValuesExact => {
                upsert_adversary_item(proto, "values", "exact");
            }
            CegarRefinementKind::GlobalNetworkIdentitySelective => {
                upsert_adversary_item(proto, "network", "identity_selective");
            }
            CegarRefinementKind::GlobalNetworkProcessSelective => {
                upsert_adversary_item(proto, "network", "process_selective");
            }
            CegarRefinementKind::MessageEquivocationNone { message } => {
                upsert_message_equivocation_policy(
                    proto,
                    message,
                    ast::EquivocationPolicyMode::None,
                );
            }
            CegarRefinementKind::MessageAuthAuthenticated { message } => {
                upsert_message_channel_policy(proto, message, ast::ChannelAuthMode::Authenticated);
            }
        }
    }
}

pub(crate) fn cegar_atomic_refinements(program: &ast::Program) -> Vec<CegarAtomicRefinement> {
    let proto = &program.protocol.node;
    let model = adversary_value(proto, "model").unwrap_or("byzantine");
    let equivocation = adversary_value(proto, "equivocation").unwrap_or("full");
    let auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let values = adversary_value(proto, "values")
        .or_else(|| adversary_value(proto, "value_abstraction"))
        .unwrap_or("exact");
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");

    let mut atomics: Vec<CegarAtomicRefinement> = Vec::new();
    if model == "byzantine" && equivocation != "none" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalEquivocationNone,
            "equivocation:none",
            "adversary.equivocation=none",
        ));
    }
    if auth != "signed" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalAuthSigned,
            "auth:signed",
            "adversary.auth=signed",
        ));
    }
    if values != "exact" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalValuesExact,
            "values:exact",
            "adversary.values=exact",
        ));
    }
    if model == "byzantine"
        && network != "identity_selective"
        && network != "cohort_selective"
        && network != "process_selective"
    {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalNetworkIdentitySelective,
            "network:identity_selective",
            "adversary.network=identity_selective",
        ));
    }
    if model == "byzantine" && network != "process_selective" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalNetworkProcessSelective,
            "network:process_selective",
            "adversary.network=process_selective",
        ));
    }

    atomics
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CegarTraceSignals {
    pub(crate) conflicting_variants: bool,
    pub(crate) cross_recipient_delivery: bool,
    pub(crate) sign_abstract_values: bool,
    pub(crate) identity_scoped_channels: bool,
    pub(crate) conflicting_variant_families: BTreeSet<String>,
    pub(crate) cross_recipient_families: BTreeSet<String>,
}

pub(crate) fn parse_counter_signature(name: &str) -> Option<(String, String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped.split_once('@')?;
    let channel = recipient_part
        .split_once('[')
        .map(|(r, _)| r)
        .unwrap_or(recipient_part);
    let recipient = channel
        .split_once("<-")
        .map(|(r, _)| r)
        .unwrap_or(channel)
        .to_string();
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    let variant_suffix = stripped
        .split_once('[')
        .map(|(_, fields)| format!("[{fields}"))
        .unwrap_or_default();
    let variant = format!("{family}{variant_suffix}");
    Some((family, variant, Some(recipient)))
}

pub(crate) fn cegar_trace_signals_from_trace(
    ta: &ThresholdAutomaton,
    trace: &tarsier_ir::counter_system::Trace,
) -> CegarTraceSignals {
    let mut active_vars: HashSet<usize> = trace
        .initial_config
        .gamma
        .iter()
        .enumerate()
        .filter(|(_, value)| **value > 0)
        .map(|(idx, _)| idx)
        .collect();
    for step in &trace.steps {
        for (idx, value) in step.config.gamma.iter().enumerate() {
            if *value > 0 {
                active_vars.insert(idx);
            }
        }
    }

    let mut variants_by_family: HashMap<String, HashSet<String>> = HashMap::new();
    let mut recipients_by_variant: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut sign_abstract_values = false;
    let mut identity_scoped_channels = false;

    for var_id in active_vars {
        let Some(shared) = ta.shared_vars.get(var_id) else {
            continue;
        };
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        if let Some((family, variant, recipient)) = parse_counter_signature(&shared.name) {
            variants_by_family
                .entry(family.clone())
                .or_default()
                .insert(variant.clone());
            if let Some(recipient) = recipient {
                if recipient.contains('#') {
                    identity_scoped_channels = true;
                }
                recipients_by_variant
                    .entry((family, variant))
                    .or_default()
                    .insert(recipient);
            }
        }
        if shared.name.contains("=neg")
            || shared.name.contains("=pos")
            || shared.name.contains("=zero")
        {
            sign_abstract_values = true;
        }
    }

    let conflicting_variants = variants_by_family
        .values()
        .any(|variants| variants.len() > 1);
    let cross_recipient_delivery = recipients_by_variant
        .values()
        .any(|recipients| recipients.len() > 1);
    let conflicting_variant_families: BTreeSet<String> = variants_by_family
        .iter()
        .filter_map(|(family, variants)| {
            if variants.len() > 1 {
                Some(family.clone())
            } else {
                None
            }
        })
        .collect();
    let cross_recipient_families: BTreeSet<String> = recipients_by_variant
        .iter()
        .filter_map(|((family, _variant), recipients)| {
            if recipients.len() > 1 {
                Some(family.clone())
            } else {
                None
            }
        })
        .collect();

    CegarTraceSignals {
        conflicting_variants,
        cross_recipient_delivery,
        sign_abstract_values,
        identity_scoped_channels,
        conflicting_variant_families,
        cross_recipient_families,
    }
}

pub(crate) fn cegar_trace_generated_refinements(
    program: &ast::Program,
    signals: &CegarTraceSignals,
) -> Vec<CegarAtomicRefinement> {
    let proto = &program.protocol.node;
    let declared_messages: HashSet<&str> = proto.messages.iter().map(|m| m.name.as_str()).collect();
    let global_auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let global_equivocation = adversary_value(proto, "equivocation").unwrap_or("full");

    let mut generated = Vec::new();
    for message in &signals.conflicting_variant_families {
        if !declared_messages.contains(message.as_str()) {
            continue;
        }
        if !effective_message_non_equivocating(proto, message, global_equivocation) {
            generated.push(CegarAtomicRefinement::message_equivocation_none(message));
        }
    }
    for message in &signals.cross_recipient_families {
        if !declared_messages.contains(message.as_str()) {
            continue;
        }
        if !effective_message_authenticated(proto, message, global_auth) {
            generated.push(CegarAtomicRefinement::message_auth_authenticated(message));
        }
    }
    generated
}

/// Build ordered candidate atoms for fair-lasso realizability replay.
///
/// Candidates are signal-driven first (derived from the current lasso), then
/// fall back to generic adversary-tightening atoms. Existing predicates are
/// filtered out so replay only explores genuinely new distinctions.
pub(crate) fn cegar_liveness_realizability_atoms(
    program: &ast::Program,
    signals: &CegarTraceSignals,
    existing_predicates: &[String],
) -> Vec<CegarAtomicRefinement> {
    let existing: HashSet<&str> = existing_predicates.iter().map(|p| p.as_str()).collect();
    let mut seen_predicates: HashSet<String> = HashSet::new();
    let mut atoms: Vec<CegarAtomicRefinement> = Vec::new();

    for atom in cegar_trace_generated_refinements(program, signals) {
        if existing.contains(atom.predicate.as_str()) {
            continue;
        }
        if seen_predicates.insert(atom.predicate.clone()) {
            atoms.push(atom);
        }
    }
    for atom in cegar_atomic_refinements(program) {
        if existing.contains(atom.predicate.as_str()) {
            continue;
        }
        if seen_predicates.insert(atom.predicate.clone()) {
            atoms.push(atom);
        }
    }

    atoms.sort_by(|a, b| {
        let sa = cegar_refinement_score(a, signals);
        let sb = cegar_refinement_score(b, signals);
        sb.cmp(&sa).then_with(|| a.label.cmp(&b.label))
    });
    atoms
}

pub(crate) fn cegar_core_compound_predicate(predicates: &[String]) -> Option<String> {
    if predicates.len() <= 1 {
        return None;
    }
    Some(format!("cegar.core.min({})", predicates.join(" && ")))
}

pub(crate) fn cegar_refinement_score(
    atom: &CegarAtomicRefinement,
    signals: &CegarTraceSignals,
) -> i32 {
    let mut score = match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => 40,
        CegarRefinementKind::GlobalAuthSigned => 30,
        CegarRefinementKind::GlobalValuesExact => 80,
        CegarRefinementKind::GlobalNetworkIdentitySelective => 30,
        CegarRefinementKind::GlobalNetworkProcessSelective => 20,
        CegarRefinementKind::MessageEquivocationNone { .. } => 50,
        CegarRefinementKind::MessageAuthAuthenticated { .. } => 35,
    };
    match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => {
            if signals.conflicting_variants {
                score += 220;
            }
        }
        CegarRefinementKind::GlobalAuthSigned => {
            if signals.conflicting_variants || signals.cross_recipient_delivery {
                score += 60;
            }
        }
        CegarRefinementKind::GlobalValuesExact => {
            if signals.sign_abstract_values {
                // Recover exact value semantics before network refinements when
                // the trace clearly exercised sign abstraction.
                score += 120;
            }
        }
        CegarRefinementKind::GlobalNetworkIdentitySelective => {
            if signals.cross_recipient_delivery {
                score += 70;
            }
        }
        CegarRefinementKind::GlobalNetworkProcessSelective => {
            if signals.cross_recipient_delivery {
                score += 95;
            }
            if signals.identity_scoped_channels {
                score += 10;
            }
        }
        CegarRefinementKind::MessageEquivocationNone { message } => {
            if signals.conflicting_variant_families.contains(message) {
                score += 205;
            }
            if signals.cross_recipient_families.contains(message) {
                score += 30;
            }
        }
        CegarRefinementKind::MessageAuthAuthenticated { message } => {
            if signals.cross_recipient_families.contains(message) {
                score += 145;
            }
            if signals.conflicting_variant_families.contains(message) {
                score += 55;
            }
        }
    }
    // Multi-signal correlation bonus: when multiple independent evidence
    // signals converge on the same refinement, the confidence increases.
    let evidence_count = cegar_atom_evidence_tag_count(atom, signals);
    if evidence_count >= 3 {
        score += 50; // triple+ correlation
    } else if evidence_count >= 2 {
        score += 25; // double correlation
    }
    score
}

/// Count how many distinct evidence tags support a refinement atom.
pub(crate) fn cegar_atom_evidence_tag_count(
    atom: &CegarAtomicRefinement,
    signals: &CegarTraceSignals,
) -> usize {
    let mut count = 0;
    match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => {
            if signals.conflicting_variants {
                count += 1;
            }
        }
        CegarRefinementKind::GlobalAuthSigned => {
            if signals.conflicting_variants {
                count += 1;
            }
            if signals.cross_recipient_delivery {
                count += 1;
            }
        }
        CegarRefinementKind::GlobalValuesExact => {
            if signals.sign_abstract_values {
                count += 1;
            }
        }
        CegarRefinementKind::GlobalNetworkIdentitySelective => {
            if signals.cross_recipient_delivery {
                count += 1;
            }
        }
        CegarRefinementKind::GlobalNetworkProcessSelective => {
            if signals.cross_recipient_delivery {
                count += 1;
            }
            if signals.identity_scoped_channels {
                count += 1;
            }
        }
        CegarRefinementKind::MessageEquivocationNone { message } => {
            if signals.conflicting_variant_families.contains(message) {
                count += 1;
            }
            if signals.cross_recipient_families.contains(message) {
                count += 1;
            }
        }
        CegarRefinementKind::MessageAuthAuthenticated { message } => {
            if signals.cross_recipient_families.contains(message) {
                count += 1;
            }
            if signals.conflicting_variant_families.contains(message) {
                count += 1;
            }
        }
    }
    count
}

/// Estimate how many trace steps are affected by a refinement atom.
///
/// Looks at which shared variables in the trace are related to the
/// refinement (message counters matching the refinement's target) and
/// counts the trace steps where those variables change.
pub(crate) fn cegar_step_impact_estimate(
    atom: &CegarAtomicRefinement,
    ta: &ThresholdAutomaton,
    trace: &tarsier_ir::counter_system::Trace,
) -> usize {
    // Identify which shared variable indices are relevant to this atom.
    let relevant_indices: Vec<usize> = ta
        .shared_vars
        .iter()
        .enumerate()
        .filter(|(_, sv)| {
            if sv.kind != SharedVarKind::MessageCounter {
                return false;
            }
            match &atom.kind {
                CegarRefinementKind::GlobalEquivocationNone
                | CegarRefinementKind::GlobalAuthSigned
                | CegarRefinementKind::GlobalNetworkIdentitySelective
                | CegarRefinementKind::GlobalNetworkProcessSelective => true,
                CegarRefinementKind::GlobalValuesExact => {
                    sv.name.contains("=neg")
                        || sv.name.contains("=pos")
                        || sv.name.contains("=zero")
                }
                CegarRefinementKind::MessageEquivocationNone { message }
                | CegarRefinementKind::MessageAuthAuthenticated { message } => {
                    sv.name.starts_with(&format!("cnt_{message}"))
                }
            }
        })
        .map(|(idx, _)| idx)
        .collect();

    if relevant_indices.is_empty() {
        return 0;
    }

    // Count steps where any relevant shared variable changes.
    let mut affected = 0;
    let mut prev_gamma = trace.initial_config.gamma.clone();
    for step in &trace.steps {
        let changed = relevant_indices
            .iter()
            .any(|&idx| step.config.gamma.get(idx) != prev_gamma.get(idx));
        if changed {
            affected += 1;
        }
        prev_gamma.clone_from(&step.config.gamma);
    }
    affected
}

/// Build scored predicate entries for all atoms in a refinement plan, given trace context.
pub(crate) fn cegar_build_scored_predicates(
    atomics: &[CegarAtomicRefinement],
    signals: &CegarTraceSignals,
    ta: &ThresholdAutomaton,
    trace: &tarsier_ir::counter_system::Trace,
    unsat_core_indices: &[usize],
) -> Vec<CegarPredicateScore> {
    let core_set: HashSet<usize> = unsat_core_indices.iter().copied().collect();
    atomics
        .iter()
        .enumerate()
        .map(|(idx, atom)| {
            let score = cegar_refinement_score(atom, signals);
            let evidence_tags = cegar_atom_evidence_tags(atom, signals);
            let affected_steps = cegar_step_impact_estimate(atom, ta, trace);
            CegarPredicateScore {
                predicate: atom.predicate.clone(),
                score,
                evidence_tags,
                affected_steps,
                unsat_core_selected: core_set.contains(&idx),
            }
        })
        .collect()
}

pub(crate) fn cegar_atom_evidence_tags(
    atom: &CegarAtomicRefinement,
    signals: &CegarTraceSignals,
) -> Vec<String> {
    let mut tags = Vec::new();
    match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => {
            if signals.conflicting_variants {
                tags.push("conflicting_variants".to_string());
            }
        }
        CegarRefinementKind::GlobalAuthSigned => {
            if signals.conflicting_variants {
                tags.push("conflicting_variants".to_string());
            }
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
        }
        CegarRefinementKind::GlobalValuesExact => {
            if signals.sign_abstract_values {
                tags.push("sign_abstract_values".to_string());
            }
        }
        CegarRefinementKind::GlobalNetworkIdentitySelective => {
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
        }
        CegarRefinementKind::GlobalNetworkProcessSelective => {
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
            if signals.identity_scoped_channels {
                tags.push("identity_scoped_channels".to_string());
            }
        }
        CegarRefinementKind::MessageEquivocationNone { message } => {
            if signals.conflicting_variant_families.contains(message) {
                tags.push("conflicting_variants".to_string());
                tags.push(format!("conflicting_variants:{message}"));
            }
            if signals.cross_recipient_families.contains(message) {
                tags.push(format!("cross_recipient_delivery:{message}"));
            }
        }
        CegarRefinementKind::MessageAuthAuthenticated { message } => {
            if signals.cross_recipient_families.contains(message) {
                tags.push("cross_recipient_delivery".to_string());
                tags.push(format!("cross_recipient_delivery:{message}"));
            }
            if signals.conflicting_variant_families.contains(message) {
                tags.push(format!("conflicting_variants:{message}"));
            }
        }
    }
    tags
}

pub(crate) fn cegar_refinement_plan_with_signals(
    program: &ast::Program,
    signals: Option<&CegarTraceSignals>,
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Vec<CegarRefinementPlanEntry> {
    let mut atomics = cegar_atomic_refinements(program);
    if let Some(signals) = signals {
        atomics.extend(cegar_trace_generated_refinements(program, signals));
    }
    if atomics.is_empty() {
        return Vec::new();
    }
    let mut seen_labels = HashSet::new();
    atomics.retain(|atom| seen_labels.insert(atom.label.clone()));

    let mut plan = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();
    let mut push_plan = |atoms: Vec<CegarAtomicRefinement>, rationale: String| {
        let refinement = CegarRefinement { atoms };
        let label = refinement.label();
        if emitted.insert(label) {
            plan.push(CegarRefinementPlanEntry {
                refinement,
                rationale,
            });
        }
    };

    if let Some(signals) = signals {
        let requirements = cegar_evidence_requirements(&atomics, signals);
        if let Some(seed) =
            cegar_unsat_core_seed(&atomics, &requirements, solver_choice, timeout_secs)
        {
            if !seed.selected_indices.is_empty() {
                let atoms: Vec<CegarAtomicRefinement> = seed
                    .selected_indices
                    .iter()
                    .filter_map(|idx| atomics.get(*idx).cloned())
                    .collect();
                if !atoms.is_empty() {
                    let requirement_tags: Vec<String> =
                        requirements.iter().map(|req| req.tag.clone()).collect();
                    push_plan(
                        atoms,
                        format!(
                            "unsat-core minimized evidence cover: solver-backed seed over [{}] (cores={}, selected={})",
                            requirement_tags.join(", "),
                            seed.cores_considered,
                            seed.selected_indices.len()
                        ),
                    );
                }
            }
        }

        atomics.sort_by(|a, b| {
            let sa = cegar_refinement_score(a, signals);
            let sb = cegar_refinement_score(b, signals);
            sb.cmp(&sa).then_with(|| a.label.cmp(&b.label))
        });

        let mut evidence_backed: Vec<(CegarAtomicRefinement, Vec<String>, i32)> = atomics
            .iter()
            .cloned()
            .filter_map(|atom| {
                let tags = cegar_atom_evidence_tags(&atom, signals);
                if tags.is_empty() {
                    None
                } else {
                    let score = cegar_refinement_score(&atom, signals);
                    Some((atom, tags, score))
                }
            })
            .collect();
        evidence_backed.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.label.cmp(&b.0.label)));

        for (atom, tags, score) in &evidence_backed {
            push_plan(
                vec![atom.clone()],
                format!(
                    "evidence-driven: selected by trace signals [{}] (score={score})",
                    tags.join(", ")
                ),
            );
        }

        if evidence_backed.len() > 1 {
            let atoms: Vec<CegarAtomicRefinement> = evidence_backed
                .iter()
                .map(|(atom, _, _)| atom.clone())
                .collect();
            push_plan(
                atoms,
                "evidence-driven: combined evidence-backed refinements to eliminate correlated artifacts".into(),
            );
        }

        for atom in &atomics {
            let tags = cegar_atom_evidence_tags(atom, signals);
            if tags.is_empty() {
                let score = cegar_refinement_score(atom, signals);
                push_plan(
                    vec![atom.clone()],
                    format!(
                        "fallback: no direct trace signal matched; trying next best ranked refinement (score={score})"
                    ),
                );
            }
        }
    } else {
        for atom in &atomics {
            push_plan(
                vec![atom.clone()],
                "baseline: no counterexample evidence available; using default refinement ordering"
                    .into(),
            );
        }
    }

    // Final cumulative fallback to avoid being locked into single-atom refinements only.
    let mut prefix = Vec::new();
    for atom in atomics {
        prefix.push(atom);
        if prefix.len() > 1 {
            push_plan(
                prefix.clone(),
                "fallback: cumulative strengthening after single-refinement attempts".into(),
            );
        }
    }

    plan
}

pub(crate) fn cegar_refinement_ladder_with_signals(
    program: &ast::Program,
    signals: Option<&CegarTraceSignals>,
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Vec<CegarRefinement> {
    cegar_refinement_plan_with_signals(program, signals, solver_choice, timeout_secs)
        .into_iter()
        .map(|entry| entry.refinement)
        .collect()
}

#[derive(Debug)]
pub(crate) struct CegarStageEvalCache<T> {
    entries: HashMap<String, T>,
    hits: usize,
    misses: usize,
}

impl<T> Default for CegarStageEvalCache<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            hits: 0,
            misses: 0,
        }
    }
}

impl<T: Clone> CegarStageEvalCache<T> {
    fn key(refinement: &CegarRefinement) -> String {
        let mut predicates = sorted_unique_strings(refinement.refinements());
        if predicates.is_empty() {
            "<baseline>".into()
        } else {
            predicates.sort();
            predicates.join(" && ")
        }
    }

    pub(crate) fn eval<F>(
        &mut self,
        refinement: &CegarRefinement,
        compute: F,
    ) -> Result<T, PipelineError>
    where
        F: FnOnce() -> Result<T, PipelineError>,
    {
        let key = Self::key(refinement);
        if let Some(existing) = self.entries.get(&key) {
            self.hits = self.hits.saturating_add(1);
            return Ok(existing.clone());
        }
        self.misses = self.misses.saturating_add(1);
        let value = compute()?;
        self.entries.insert(key, value.clone());
        Ok(value)
    }

    pub(crate) fn emit_notes(&self) {
        if self.hits == 0 && self.misses == 0 {
            return;
        }
        push_reduction_note("cegar.incremental_stage_cache=on");
        push_reduction_note(&format!("cegar.incremental_stage_cache_hits={}", self.hits));
        push_reduction_note(&format!(
            "cegar.incremental_stage_cache_misses={}",
            self.misses
        ));
    }
}

pub(crate) fn cegar_shrink_refinement_core<Eval>(
    refinement: &CegarRefinement,
    mut eval: Eval,
) -> Result<Option<CegarRefinement>, PipelineError>
where
    Eval: FnMut(&CegarRefinement) -> Result<Option<bool>, PipelineError>,
{
    if refinement.atoms.len() <= 1 {
        return Ok(None);
    }
    let mut core = refinement.atoms.clone();
    let mut changed = true;
    let mut attempted = false;
    while changed && core.len() > 1 {
        changed = false;
        let mut idx = 0;
        while idx < core.len() {
            let mut candidate = core.clone();
            candidate.remove(idx);
            if candidate.is_empty() {
                idx += 1;
                continue;
            }
            attempted = true;
            match eval(&CegarRefinement {
                atoms: candidate.clone(),
            })? {
                Some(true) => {
                    core = candidate;
                    changed = true;
                    break;
                }
                Some(false) => {
                    idx += 1;
                }
                None => return Ok(None),
            }
        }
    }
    if attempted && core.len() < refinement.atoms.len() {
        Ok(Some(CegarRefinement { atoms: core }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
