//! CEGAR types, refinement logic, oracle, scoring, and reporting.

use super::*;

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

#[derive(Debug, Clone)]
pub(crate) struct CegarEvidenceRequirement {
    tag: String,
    supporters: Vec<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct CegarUnsatCoreSelection {
    pub(crate) selected_indices: Vec<usize>,
    pub(crate) cores_considered: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum CegarOracleOutcome {
    Sat,
    Unsat { core_indices: Vec<usize> },
    Unknown,
}

pub(crate) fn cegar_selection_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, 15)
}

pub(crate) fn cegar_evidence_requirements(
    atomics: &[CegarAtomicRefinement],
    signals: &CegarTraceSignals,
) -> Vec<CegarEvidenceRequirement> {
    let mut supporters_by_tag: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for (idx, atom) in atomics.iter().enumerate() {
        for tag in cegar_atom_evidence_tags(atom, signals) {
            supporters_by_tag.entry(tag).or_default().insert(idx);
        }
    }

    supporters_by_tag
        .into_iter()
        .filter_map(|(tag, supporters)| {
            if supporters.is_empty() {
                None
            } else {
                Some(CegarEvidenceRequirement {
                    tag,
                    supporters: supporters.into_iter().collect(),
                })
            }
        })
        .collect()
}

pub(crate) fn combinations_of_size(indices_len: usize, pick: usize) -> Vec<Vec<usize>> {
    if pick == 0 {
        return vec![Vec::new()];
    }
    if pick > indices_len {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(pick);
    fn rec(
        start: usize,
        remaining: usize,
        total: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            out.push(current.clone());
            return;
        }
        let last_start = total.saturating_sub(remaining);
        for idx in start..=last_start {
            current.push(idx);
            rec(idx + 1, remaining - 1, total, current, out);
            current.pop();
        }
    }
    rec(0, pick, indices_len, &mut current, &mut out);
    out
}

pub(crate) fn at_most_k_bool_terms(vars: &[String], k: usize) -> Vec<SmtTerm> {
    if k >= vars.len() {
        return Vec::new();
    }
    if k == 0 {
        return vars
            .iter()
            .map(|name| SmtTerm::var(name.clone()).not())
            .collect();
    }
    let mut terms = Vec::new();
    for combo in combinations_of_size(vars.len(), k + 1) {
        let clause = combo
            .into_iter()
            .map(|idx| SmtTerm::var(vars[idx].clone()).not())
            .collect();
        terms.push(SmtTerm::or(clause));
    }
    terms
}

pub(crate) fn cegar_oracle_outcome_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
    enabled_indices: &BTreeSet<usize>,
) -> Result<CegarOracleOutcome, S::Error> {
    if !solver.supports_assumption_unsat_core() {
        return Ok(CegarOracleOutcome::Unknown);
    }

    let select_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_select_{idx}"))
        .collect();
    for name in &select_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }

    for req in requirements {
        let disjuncts: Vec<SmtTerm> = req
            .supporters
            .iter()
            .map(|idx| SmtTerm::var(select_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disjuncts))?;
    }

    let mut disable_by_index: HashMap<usize, String> = HashMap::with_capacity(atomics_len);
    for (idx, selected_name) in select_vars.iter().enumerate() {
        let disable_name = format!("__cegar_disable_{idx}");
        solver.declare_var(&disable_name, &SmtSort::Bool)?;
        solver.assert(
            &SmtTerm::var(disable_name.clone()).implies(SmtTerm::var(selected_name.clone()).not()),
        )?;
        disable_by_index.insert(idx, disable_name);
    }

    let assumptions: Vec<String> = (0..atomics_len)
        .filter(|idx| !enabled_indices.contains(idx))
        .filter_map(|idx| disable_by_index.get(&idx).cloned())
        .collect();
    match solver.check_sat_assuming(&assumptions)? {
        SatResult::Sat => Ok(CegarOracleOutcome::Sat),
        SatResult::Unsat => {
            let core_names = solver.get_unsat_core_assumptions()?;
            let mut index_by_disable: HashMap<String, usize> =
                HashMap::with_capacity(disable_by_index.len());
            for (idx, name) in disable_by_index {
                index_by_disable.insert(name, idx);
            }
            let mut core_indices: Vec<usize> = core_names
                .into_iter()
                .filter_map(|name| index_by_disable.get(&name).copied())
                .collect();
            core_indices.sort_unstable();
            core_indices.dedup();
            if core_indices.is_empty() {
                Ok(CegarOracleOutcome::Unknown)
            } else {
                Ok(CegarOracleOutcome::Unsat { core_indices })
            }
        }
        SatResult::Unknown(_) => Ok(CegarOracleOutcome::Unknown),
    }
}

pub(crate) fn cegar_min_hitting_set_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    discovered_cores: &[Vec<usize>],
) -> Result<Option<BTreeSet<usize>>, S::Error> {
    if atomics_len == 0 {
        return Ok(Some(BTreeSet::new()));
    }
    let choice_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_pick_{idx}"))
        .collect();
    for name in &choice_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }
    for core in discovered_cores {
        let disj = core
            .iter()
            .map(|idx| SmtTerm::var(choice_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disj))?;
    }

    for k in 0..=atomics_len {
        solver.push()?;
        for term in at_most_k_bool_terms(&choice_vars, k) {
            solver.assert(&term)?;
        }
        let sat = solver.check_sat()?;
        match sat {
            SatResult::Sat => {
                let mut selected = BTreeSet::new();
                // Deterministic tie-break: lexicographically minimize the
                // selected-index bitvector by trying to force each variable to
                // false in index order, and only forcing true when UNSAT.
                for (idx, name) in choice_vars.iter().enumerate() {
                    solver.push()?;
                    solver.assert(&SmtTerm::var(name.clone()).not())?;
                    match solver.check_sat()? {
                        SatResult::Sat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()).not())?;
                        }
                        SatResult::Unsat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()))?;
                            selected.insert(idx);
                        }
                        SatResult::Unknown(_) => {
                            solver.pop()?;
                            solver.pop()?;
                            return Ok(None);
                        }
                    }
                }
                solver.pop()?;
                return Ok(Some(selected));
            }
            SatResult::Unsat => {
                solver.pop()?;
            }
            SatResult::Unknown(_) => {
                solver.pop()?;
                return Ok(None);
            }
        }
    }

    Ok(None)
}

pub(crate) fn cegar_unsat_core_seed_with_factory<S, E, F>(
    mut solver_factory: F,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
) -> Result<Option<CegarUnsatCoreSelection>, PipelineError>
where
    S: SmtSolver<Error = E>,
    E: std::error::Error,
    F: FnMut() -> Result<S, E>,
{
    if atomics_len == 0 || requirements.is_empty() {
        return Ok(None);
    }

    {
        let solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
        if !solver.supports_assumption_unsat_core() {
            return Ok(None);
        }
    }

    let mut discovered_cores: Vec<Vec<usize>> = Vec::new();
    let mut seen_cores: HashSet<Vec<usize>> = HashSet::new();
    let max_iters = atomics_len.saturating_mul(8).max(8);

    for _ in 0..max_iters {
        let candidate = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_min_hitting_set_with_solver(&mut solver, atomics_len, &discovered_cores)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        let Some(candidate) = candidate else {
            return Ok(None);
        };

        let outcome = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_oracle_outcome_with_solver(&mut solver, atomics_len, requirements, &candidate)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        match outcome {
            CegarOracleOutcome::Sat => {
                return Ok(Some(CegarUnsatCoreSelection {
                    selected_indices: candidate.into_iter().collect(),
                    cores_considered: discovered_cores.len(),
                }));
            }
            CegarOracleOutcome::Unsat { core_indices } => {
                if seen_cores.insert(core_indices.clone()) {
                    discovered_cores.push(core_indices);
                } else {
                    return Ok(None);
                }
            }
            CegarOracleOutcome::Unknown => {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

pub(crate) fn cegar_unsat_core_seed(
    atomics: &[CegarAtomicRefinement],
    requirements: &[CegarEvidenceRequirement],
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Option<CegarUnsatCoreSelection> {
    let timeout_secs = cegar_selection_timeout_secs(timeout_secs);
    let result = match solver_choice {
        SolverChoice::Z3 => cegar_unsat_core_seed_with_factory(
            || {
                Ok::<_, tarsier_smt::backends::z3_backend::Z3Error>(Z3Solver::with_timeout_secs(
                    timeout_secs,
                ))
            },
            atomics.len(),
            requirements,
        ),
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            cegar_unsat_core_seed_with_factory(
                || Cvc5Solver::with_timeout_secs(timeout_secs),
                atomics.len(),
                requirements,
            )
        }
    };

    match result {
        Ok(seed) => seed,
        Err(err) => {
            info!("CEGAR UNSAT-core refinement selection fallback: {err}");
            None
        }
    }
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

pub(crate) fn cegar_signals_note(signals: &CegarTraceSignals) -> Option<String> {
    let tags = cegar_signal_tags(signals);
    if tags.is_empty() {
        None
    } else {
        Some(format!("Adaptive CEGAR trace signals: {}", tags.join(", ")))
    }
}

pub(crate) fn cegar_signal_tags(signals: &CegarTraceSignals) -> Vec<&'static str> {
    let mut tags = Vec::new();
    if signals.conflicting_variants {
        tags.push("conflicting_variants");
    }
    if signals.cross_recipient_delivery {
        tags.push("cross_recipient_delivery");
    }
    if signals.sign_abstract_values {
        tags.push("sign_abstract_values");
    }
    if signals.identity_scoped_channels {
        tags.push("identity_scoped_channels");
    }
    tags
}

pub(crate) fn cegar_stage_counterexample_analysis(
    stage: usize,
    refinements: &[String],
    result: &VerificationResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        VerificationResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        VerificationResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

pub(crate) fn stage_outcome_from_verification(result: &VerificationResult) -> CegarStageOutcome {
    match result {
        VerificationResult::Safe { depth_checked } => CegarStageOutcome::Safe {
            depth_checked: *depth_checked,
        },
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => CegarStageOutcome::ProbabilisticallySafe {
            depth_checked: *depth_checked,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        VerificationResult::Unsafe { trace } => CegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        VerificationResult::Unknown { reason } => CegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

pub(crate) fn stage_outcome_from_unbounded_safety(
    result: &UnboundedSafetyResult,
) -> UnboundedSafetyCegarStageOutcome {
    match result {
        UnboundedSafetyResult::Safe { induction_k } => UnboundedSafetyCegarStageOutcome::Safe {
            induction_k: *induction_k,
        },
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => UnboundedSafetyCegarStageOutcome::ProbabilisticallySafe {
            induction_k: *induction_k,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        UnboundedSafetyResult::Unsafe { trace } => UnboundedSafetyCegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        UnboundedSafetyResult::NotProved { max_k, cti } => {
            UnboundedSafetyCegarStageOutcome::NotProved {
                max_k: *max_k,
                cti: cti.clone(),
            }
        }
        UnboundedSafetyResult::Unknown { reason } => UnboundedSafetyCegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

pub(crate) fn stage_outcome_from_unbounded_fair_liveness(
    result: &UnboundedFairLivenessResult,
) -> UnboundedFairLivenessCegarStageOutcome {
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => {
            UnboundedFairLivenessCegarStageOutcome::LiveProved { frame: *frame }
        }
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => UnboundedFairLivenessCegarStageOutcome::FairCycleFound {
            depth: *depth,
            loop_start: *loop_start,
            trace: trace.clone(),
        },
        UnboundedFairLivenessResult::NotProved { max_k } => {
            UnboundedFairLivenessCegarStageOutcome::NotProved { max_k: *max_k }
        }
        UnboundedFairLivenessResult::Unknown { reason } => {
            UnboundedFairLivenessCegarStageOutcome::Unknown {
                reason: reason.clone(),
            }
        }
    }
}

pub(crate) fn cegar_stage_counterexample_analysis_unbounded_safety(
    stage: usize,
    refinements: &[String],
    result: &UnboundedSafetyResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedSafetyResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
            let reason = match result {
                UnboundedSafetyResult::NotProved { max_k, .. } => {
                    format!("proof did not close up to k={max_k}")
                }
                UnboundedSafetyResult::Unknown { reason } => reason.clone(),
                _ => unreachable!(),
            };
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: format!(
                    "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                    stage, refinements_text, reason
                ),
            })
        }
    }
}

pub(crate) fn cegar_stage_counterexample_analysis_unbounded_fair(
    stage: usize,
    refinements: &[String],
    result: &UnboundedFairLivenessResult,
    baseline_has_cycle: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_has_cycle {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported a fair-cycle witness before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Fair-cycle witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this witness is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedFairLivenessResult::LiveProved { .. } => Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline fair-cycle witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                stage, refinements_text
            ),
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: proof did not converge up to frame {}.",
                stage, refinements_text, max_k
            ),
        }),
        UnboundedFairLivenessResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

pub(crate) fn sorted_unique_strings(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

pub(crate) fn effective_message_equivocation_mode(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_equivocation: &str,
) -> String {
    if effective_message_non_equivocating(proto, msg, global_equivocation) {
        "none".to_string()
    } else {
        "full".to_string()
    }
}

pub(crate) fn effective_message_auth_mode(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_auth: &str,
) -> String {
    if effective_message_authenticated(proto, msg, global_auth) {
        "authenticated".to_string()
    } else {
        "unauthenticated".to_string()
    }
}

pub(crate) fn cegar_stage_model_changes(
    program: &ast::Program,
    refinement: &CegarRefinement,
) -> Vec<CegarModelChange> {
    let proto = &program.protocol.node;
    let global_auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let global_equivocation = adversary_value(proto, "equivocation").unwrap_or("full");
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");
    let values = adversary_value(proto, "values")
        .or_else(|| adversary_value(proto, "value_abstraction"))
        .unwrap_or("exact");

    let mut changes = Vec::new();
    for atom in &refinement.atoms {
        match &atom.kind {
            CegarRefinementKind::GlobalEquivocationNone => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "equivocation".into(),
                before: global_equivocation.to_string(),
                after: "none".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalAuthSigned => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "auth".into(),
                before: global_auth.to_string(),
                after: "signed".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalValuesExact => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "values".into(),
                before: values.to_string(),
                after: "exact".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkIdentitySelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "identity_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkProcessSelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "process_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::MessageEquivocationNone { message } => {
                changes.push(CegarModelChange {
                    category: "equivocation".into(),
                    target: message.clone(),
                    before: effective_message_equivocation_mode(
                        proto,
                        message,
                        global_equivocation,
                    ),
                    after: "none".into(),
                    predicate: atom.predicate.clone(),
                })
            }
            CegarRefinementKind::MessageAuthAuthenticated { message } => {
                changes.push(CegarModelChange {
                    category: "channel".into(),
                    target: message.clone(),
                    before: effective_message_auth_mode(proto, message, global_auth),
                    after: "authenticated".into(),
                    predicate: atom.predicate.clone(),
                })
            }
        }
    }

    changes.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.predicate.cmp(&b.predicate))
    });
    changes.dedup_by(|a, b| {
        a.category == b.category
            && a.target == b.target
            && a.before == b.before
            && a.after == b.after
            && a.predicate == b.predicate
    });
    changes
}

pub(crate) fn cegar_stage_eliminated_traces(
    stage: usize,
    result: &VerificationResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe trace is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_stage_eliminated_traces_unbounded_safety(
    stage: usize,
    result: &UnboundedSafetyResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe proof witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_stage_eliminated_traces_unbounded_fair(
    stage: usize,
    result: &UnboundedFairLivenessResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(result, UnboundedFairLivenessResult::LiveProved { .. }) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_fair_cycle_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline fair-cycle witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

pub(crate) fn cegar_build_termination(
    reason: &str,
    max_refinements: usize,
    stages: &[CegarStageReport],
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let iterations_used = stages.iter().filter(|stage| stage.stage > 0).count();
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}

pub(crate) fn cegar_build_termination_from_iterations(
    reason: &str,
    max_refinements: usize,
    iterations_used: usize,
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}
