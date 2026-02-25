//! Network semantics, POR analysis, and controlled lowering helpers.

use super::*;

pub(crate) fn adversary_value<'a>(proto: &'a ast::ProtocolDecl, key: &str) -> Option<&'a str> {
    proto
        .adversary
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
}

pub(crate) fn upsert_adversary_item(proto: &mut ast::ProtocolDecl, key: &str, value: &str) {
    if let Some(existing) = proto.adversary.iter_mut().find(|item| item.key == key) {
        existing.value = value.to_string();
        return;
    }

    let span = proto
        .adversary
        .first()
        .map(|item| item.span)
        .unwrap_or(ast::Span::new(0, 0));
    proto.adversary.push(ast::AdversaryItem {
        key: key.to_string(),
        value: value.to_string(),
        span,
    });
}

pub(crate) fn upsert_message_channel_policy(
    proto: &mut ast::ProtocolDecl,
    message: &str,
    auth: ast::ChannelAuthMode,
) {
    if let Some(existing) = proto
        .channels
        .iter_mut()
        .find(|decl| decl.message == message)
    {
        existing.auth = auth;
        return;
    }

    let span = proto
        .channels
        .first()
        .map(|decl| decl.span)
        .or_else(|| {
            proto
                .messages
                .iter()
                .find(|decl| decl.name == message)
                .map(|decl| decl.span)
        })
        .or_else(|| proto.adversary.first().map(|decl| decl.span))
        .unwrap_or(ast::Span::new(0, 0));
    proto.channels.push(ast::ChannelDecl {
        message: message.to_string(),
        auth,
        span,
    });
}

pub(crate) fn upsert_message_equivocation_policy(
    proto: &mut ast::ProtocolDecl,
    message: &str,
    mode: ast::EquivocationPolicyMode,
) {
    if let Some(existing) = proto
        .equivocation_policies
        .iter_mut()
        .find(|decl| decl.message == message)
    {
        existing.mode = mode;
        return;
    }

    let span = proto
        .equivocation_policies
        .first()
        .map(|decl| decl.span)
        .or_else(|| {
            proto
                .messages
                .iter()
                .find(|decl| decl.name == message)
                .map(|decl| decl.span)
        })
        .or_else(|| proto.adversary.first().map(|decl| decl.span))
        .unwrap_or(ast::Span::new(0, 0));
    proto.equivocation_policies.push(ast::EquivocationDecl {
        message: message.to_string(),
        mode,
        span,
    });
}

pub(crate) fn ensure_identity_and_auth_for_faithful_mode(
    proto: &mut ast::ProtocolDecl,
    network: &str,
) {
    let faithful = matches!(
        network,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if !faithful {
        return;
    }
    let span = proto
        .identities
        .first()
        .map(|id| id.span)
        .or_else(|| proto.adversary.first().map(|a| a.span))
        .unwrap_or(ast::Span::new(0, 0));
    for role in &proto.roles {
        let role_name = role.node.name.clone();
        if let Some(existing) = proto.identities.iter_mut().find(|id| id.role == role_name) {
            if network == "process_selective" {
                existing.scope = ast::IdentityScope::Process;
                if existing.process_var.is_none() {
                    existing.process_var = Some("pid".into());
                }
            }
            if existing.key.is_none() {
                existing.key = Some(format!("{}_key", role_name.to_lowercase()));
            }
            continue;
        }
        proto.identities.push(ast::IdentityDecl {
            role: role_name.clone(),
            scope: if network == "process_selective" {
                ast::IdentityScope::Process
            } else {
                ast::IdentityScope::Role
            },
            process_var: if network == "process_selective" {
                Some("pid".into())
            } else {
                None
            },
            key: Some(format!("{}_key", role_name.to_lowercase())),
            span,
        });
    }

    let has_auth_field = proto
        .adversary
        .iter()
        .any(|i| i.key == "auth" || i.key == "authentication");
    if !has_auth_field {
        upsert_adversary_item(proto, "auth", "none");
    }
}

pub(crate) fn network_semantics_name(mode: NetworkSemantics) -> &'static str {
    match mode {
        NetworkSemantics::Classic => "classic",
        NetworkSemantics::IdentitySelective => "identity_selective",
        NetworkSemantics::CohortSelective => "cohort_selective",
        NetworkSemantics::ProcessSelective => "process_selective",
    }
}

pub(crate) fn fault_model_name(mode: FaultModel) -> &'static str {
    match mode {
        FaultModel::Byzantine => "byzantine",
        FaultModel::Crash => "crash",
        FaultModel::Omission => "omission",
    }
}

pub(crate) fn authentication_mode_name(mode: AuthenticationMode) -> &'static str {
    match mode {
        AuthenticationMode::None => "none",
        AuthenticationMode::Signed => "signed",
    }
}

pub(crate) fn equivocation_mode_name(mode: EquivocationMode) -> &'static str {
    match mode {
        EquivocationMode::Full => "full",
        EquivocationMode::None => "none",
    }
}

pub(crate) fn delivery_control_mode_name(
    mode: tarsier_ir::threshold_automaton::DeliveryControlMode,
) -> &'static str {
    match mode {
        tarsier_ir::threshold_automaton::DeliveryControlMode::LegacyCounter => "legacy_counter",
        tarsier_ir::threshold_automaton::DeliveryControlMode::PerRecipient => "per_recipient",
        tarsier_ir::threshold_automaton::DeliveryControlMode::Global => "global",
    }
}

pub(crate) fn fault_budget_scope_name(
    mode: tarsier_ir::threshold_automaton::FaultBudgetScope,
) -> &'static str {
    match mode {
        tarsier_ir::threshold_automaton::FaultBudgetScope::LegacyCounter => "legacy_counter",
        tarsier_ir::threshold_automaton::FaultBudgetScope::PerRecipient => "per_recipient",
        tarsier_ir::threshold_automaton::FaultBudgetScope::Global => "global",
    }
}

pub(crate) fn parse_declared_network_semantics(raw: &str) -> NetworkSemantics {
    match raw {
        "identity_selective" | "faithful" | "selective" | "selective_delivery" => {
            NetworkSemantics::IdentitySelective
        }
        "cohort_selective" | "lane_selective" => NetworkSemantics::CohortSelective,
        "process_selective" | "per_process" | "process_scoped" => {
            NetworkSemantics::ProcessSelective
        }
        _ => NetworkSemantics::Classic,
    }
}

pub(crate) fn declared_network_semantics(program: &ast::Program) -> NetworkSemantics {
    let proto = &program.protocol.node;
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");
    parse_declared_network_semantics(network)
}

pub(crate) fn is_faithful_network(mode: NetworkSemantics) -> bool {
    matches!(
        mode,
        NetworkSemantics::IdentitySelective
            | NetworkSemantics::CohortSelective
            | NetworkSemantics::ProcessSelective
    )
}

pub(crate) fn next_coarser_network_mode(
    current: NetworkSemantics,
    floor: FaithfulFallbackFloor,
) -> Option<NetworkSemantics> {
    match current {
        NetworkSemantics::ProcessSelective => Some(NetworkSemantics::CohortSelective),
        NetworkSemantics::CohortSelective => Some(NetworkSemantics::IdentitySelective),
        NetworkSemantics::IdentitySelective => match floor {
            FaithfulFallbackFloor::IdentitySelective => None,
            FaithfulFallbackFloor::Classic => Some(NetworkSemantics::Classic),
        },
        NetworkSemantics::Classic => None,
    }
}

pub(crate) fn automaton_footprint(ta: &ThresholdAutomaton) -> AutomatonFootprint {
    let message_counters = ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();
    AutomatonFootprint {
        locations: ta.locations.len(),
        rules: ta.rules.len(),
        shared_vars: ta.shared_vars.len(),
        message_counters,
    }
}

pub(crate) fn guard_read_vars(guard: &tarsier_ir::threshold_automaton::Guard) -> HashSet<usize> {
    let mut out = HashSet::new();
    for atom in &guard.atoms {
        let GuardAtom::Threshold { vars, .. } = atom;
        out.extend(vars.iter().copied());
    }
    out
}

pub(crate) fn update_write_vars(
    updates: &[tarsier_ir::threshold_automaton::Update],
) -> HashSet<usize> {
    updates.iter().map(|u| u.var).collect()
}

pub(crate) fn por_normalized_vars(vars: &[usize]) -> Vec<usize> {
    let mut out = vars.to_vec();
    out.sort();
    out.dedup();
    out
}

pub(crate) fn por_normalized_lc_terms(lc: &LinearCombination) -> Vec<(i64, usize)> {
    let mut coeff_by_param: HashMap<usize, i64> = HashMap::new();
    for (coeff, pid) in &lc.terms {
        if *coeff == 0 {
            continue;
        }
        *coeff_by_param.entry(*pid).or_insert(0) += *coeff;
    }
    let mut terms: Vec<(i64, usize)> = coeff_by_param
        .into_iter()
        .filter_map(|(pid, coeff)| (coeff != 0).then_some((coeff, pid)))
        .collect();
    terms.sort_by_key(|(_, pid)| *pid);
    terms
}

pub(crate) fn por_comparable_lc_constants(
    lhs: &LinearCombination,
    rhs: &LinearCombination,
) -> Option<(i64, i64)> {
    let lhs_terms = por_normalized_lc_terms(lhs);
    let rhs_terms = por_normalized_lc_terms(rhs);
    if lhs_terms == rhs_terms {
        Some((lhs.constant, rhs.constant))
    } else {
        None
    }
}

pub(crate) fn por_threshold_op_entails(
    lhs_op: CmpOp,
    lhs_const: i64,
    rhs_op: CmpOp,
    rhs_const: i64,
) -> bool {
    match (lhs_op, rhs_op) {
        (CmpOp::Eq, CmpOp::Eq) => lhs_const == rhs_const,
        (CmpOp::Eq, CmpOp::Ge) => lhs_const >= rhs_const,
        (CmpOp::Eq, CmpOp::Gt) => lhs_const > rhs_const,
        (CmpOp::Eq, CmpOp::Le) => lhs_const <= rhs_const,
        (CmpOp::Eq, CmpOp::Lt) => lhs_const < rhs_const,
        (CmpOp::Eq, CmpOp::Ne) => lhs_const != rhs_const,
        (CmpOp::Ge, CmpOp::Ge) => lhs_const >= rhs_const,
        (CmpOp::Ge, CmpOp::Gt) => lhs_const > rhs_const,
        (CmpOp::Gt, CmpOp::Gt) => lhs_const >= rhs_const,
        (CmpOp::Gt, CmpOp::Ge) => lhs_const >= rhs_const,
        (CmpOp::Le, CmpOp::Le) => lhs_const <= rhs_const,
        (CmpOp::Le, CmpOp::Lt) => lhs_const < rhs_const,
        (CmpOp::Lt, CmpOp::Lt) => lhs_const <= rhs_const,
        (CmpOp::Lt, CmpOp::Le) => lhs_const <= rhs_const,
        (CmpOp::Ne, CmpOp::Ne) => lhs_const == rhs_const,
        _ => false,
    }
}

pub(crate) fn por_guard_atom_implies(lhs: &GuardAtom, rhs: &GuardAtom) -> bool {
    match (lhs, rhs) {
        (
            GuardAtom::Threshold {
                vars: lhs_vars,
                op: lhs_op,
                bound: lhs_bound,
                distinct: lhs_distinct,
            },
            GuardAtom::Threshold {
                vars: rhs_vars,
                op: rhs_op,
                bound: rhs_bound,
                distinct: rhs_distinct,
            },
        ) => {
            if lhs_distinct != rhs_distinct
                || por_normalized_vars(lhs_vars) != por_normalized_vars(rhs_vars)
            {
                return false;
            }
            let Some((lhs_const, rhs_const)) = por_comparable_lc_constants(lhs_bound, rhs_bound)
            else {
                return false;
            };
            por_threshold_op_entails(*lhs_op, lhs_const, *rhs_op, rhs_const)
        }
    }
}

pub(crate) fn por_guard_implies(
    lhs: &tarsier_ir::threshold_automaton::Guard,
    rhs: &tarsier_ir::threshold_automaton::Guard,
) -> bool {
    rhs.atoms.iter().all(|rhs_atom| {
        lhs.atoms
            .iter()
            .any(|lhs_atom| por_guard_atom_implies(lhs_atom, rhs_atom))
    })
}

pub(crate) fn por_linear_combination_signature(lc: &LinearCombination) -> String {
    let mut terms = lc.terms.clone();
    terms.sort_by_key(|(_, pid)| *pid);
    let mut out = format!("c={}", lc.constant);
    for (coeff, pid) in terms {
        out.push('|');
        out.push_str(&format!("{coeff}*p{pid}"));
    }
    out
}

pub(crate) fn por_rule_effect_signature(rule: &tarsier_ir::threshold_automaton::Rule) -> String {
    let updates = rule
        .updates
        .iter()
        .map(por_update_signature)
        .collect::<Vec<_>>()
        .join(";");
    format!("from={};to={};updates=[{updates}]", rule.from, rule.to)
}

pub(crate) fn por_guard_atom_signature(atom: &GuardAtom) -> String {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            let lhs = vars
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let op = match op {
                CmpOp::Ge => ">=",
                CmpOp::Le => "<=",
                CmpOp::Gt => ">",
                CmpOp::Lt => "<",
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
            };
            format!(
                "thr(distinct={distinct};lhs={lhs};op={op};rhs={})",
                por_linear_combination_signature(bound)
            )
        }
    }
}

pub(crate) fn por_update_signature(update: &tarsier_ir::threshold_automaton::Update) -> String {
    match &update.kind {
        tarsier_ir::threshold_automaton::UpdateKind::Increment => format!("inc@{}", update.var),
        tarsier_ir::threshold_automaton::UpdateKind::Set(lc) => {
            format!(
                "set@{}={}",
                update.var,
                por_linear_combination_signature(lc)
            )
        }
    }
}

pub(crate) fn por_rule_signature(rule: &tarsier_ir::threshold_automaton::Rule) -> String {
    let mut guards = rule
        .guard
        .atoms
        .iter()
        .map(por_guard_atom_signature)
        .collect::<Vec<_>>();
    guards.sort();
    let updates = rule
        .updates
        .iter()
        .map(por_update_signature)
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "from={};to={};guards=[{}];updates=[{}]",
        rule.from,
        rule.to,
        guards.join(";"),
        updates
    )
}

pub(crate) fn is_pure_stutter_rule(rule: &tarsier_ir::threshold_automaton::Rule) -> bool {
    rule.from == rule.to && rule.updates.is_empty()
}

pub(crate) fn por_rule_pruning_summary(ta: &ThresholdAutomaton) -> (usize, usize, usize, usize) {
    if ta.por_mode == PorMode::Off {
        return (0, 0, 0, ta.rules.len());
    }
    let mut stutter_pruned = 0usize;
    let mut duplicate_pruned = 0usize;
    let mut dominated_pruned = 0usize;
    let mut seen_signatures: HashSet<String> = HashSet::new();
    let mut disabled_rules = vec![false; ta.rules.len()];

    for (rule_id, rule) in ta.rules.iter().enumerate() {
        if is_pure_stutter_rule(rule) {
            stutter_pruned = stutter_pruned.saturating_add(1);
            disabled_rules[rule_id] = true;
            continue;
        }
        let signature = por_rule_signature(rule);
        if !seen_signatures.insert(signature) {
            duplicate_pruned = duplicate_pruned.saturating_add(1);
            disabled_rules[rule_id] = true;
        }
    }

    let rule_effects: Vec<String> = ta.rules.iter().map(por_rule_effect_signature).collect();
    for rule_id in 0..ta.rules.len() {
        if disabled_rules[rule_id] {
            continue;
        }
        for other_id in 0..ta.rules.len() {
            if other_id == rule_id || disabled_rules[other_id] {
                continue;
            }
            if rule_effects[rule_id] != rule_effects[other_id] {
                continue;
            }
            if !por_guard_implies(&ta.rules[rule_id].guard, &ta.rules[other_id].guard) {
                continue;
            }
            let other_implies =
                por_guard_implies(&ta.rules[other_id].guard, &ta.rules[rule_id].guard);
            if other_implies && other_id > rule_id {
                continue;
            }
            disabled_rules[rule_id] = true;
            dominated_pruned = dominated_pruned.saturating_add(1);
            break;
        }
    }

    let effective_rules = ta
        .rules
        .len()
        .saturating_sub(stutter_pruned)
        .saturating_sub(duplicate_pruned)
        .saturating_sub(dominated_pruned);
    (
        stutter_pruned,
        duplicate_pruned,
        dominated_pruned,
        effective_rules,
    )
}

pub(crate) fn rules_independent(
    ta: &ThresholdAutomaton,
    lhs: &tarsier_ir::threshold_automaton::Rule,
    rhs: &tarsier_ir::threshold_automaton::Rule,
) -> bool {
    // Conservative independence: no shared source/target locations and no
    // read/write conflicts over shared variables.
    if lhs.from == rhs.from || lhs.from == rhs.to || lhs.to == rhs.from || lhs.to == rhs.to {
        return false;
    }
    if ta.locations[lhs.from].role == ta.locations[rhs.from].role {
        return false;
    }
    let lhs_reads = guard_read_vars(&lhs.guard);
    let rhs_reads = guard_read_vars(&rhs.guard);
    let lhs_writes = update_write_vars(&lhs.updates);
    let rhs_writes = update_write_vars(&rhs.updates);

    lhs_writes.is_disjoint(&rhs_writes)
        && lhs_writes.is_disjoint(&rhs_reads)
        && rhs_writes.is_disjoint(&lhs_reads)
}

pub(crate) fn independent_rule_pair_count(ta: &ThresholdAutomaton) -> usize {
    let mut count = 0usize;
    for i in 0..ta.rules.len() {
        for j in (i + 1)..ta.rules.len() {
            if rules_independent(ta, &ta.rules[i], &ta.rules[j]) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

pub(crate) fn footprint_exceeds_budget(
    footprint: &AutomatonFootprint,
    cfg: &FaithfulFallbackConfig,
) -> bool {
    footprint.locations > cfg.max_locations
        || footprint.shared_vars > cfg.max_shared_vars
        || footprint.message_counters > cfg.max_message_counters
}

pub(crate) fn apply_network_semantics_override(program: &mut ast::Program, mode: NetworkSemantics) {
    let proto = &mut program.protocol.node;
    let mode_name = network_semantics_name(mode);
    upsert_adversary_item(proto, "network", mode_name);
    if is_faithful_network(mode) {
        ensure_identity_and_auth_for_faithful_mode(proto, mode_name);
    }
}

pub(crate) fn lower_with_controls(
    program: &ast::Program,
    context: &str,
    controls: PipelineExecutionControls,
) -> Result<ThresholdAutomaton, PipelineError> {
    let requested_network = declared_network_semantics(program);
    let mut current_mode = requested_network;
    let initial_lower_started = Instant::now();
    let mut current_ta = lower(program)?;
    push_phase_profile(
        context,
        "lower",
        initial_lower_started.elapsed().as_millis(),
    );

    // Apply CLI POR mode override if specified.
    if let Some(por_override) = controls.por_mode_override {
        current_ta.por_mode = por_override;
    }

    let requested_footprint = automaton_footprint(&current_ta);
    let mut effective_footprint = requested_footprint;
    let mut budget = None;
    let mut budget_satisfied = true;
    let mut fallback_steps = 0usize;
    let mut fallback_exhausted = false;

    if let Some(cfg) = controls.faithful_fallback {
        budget = Some(AutomatonFootprint {
            locations: cfg.max_locations,
            rules: 0,
            shared_vars: cfg.max_shared_vars,
            message_counters: cfg.max_message_counters,
        });

        if is_faithful_network(current_mode) && footprint_exceeds_budget(&effective_footprint, &cfg)
        {
            loop {
                let Some(next_mode) = next_coarser_network_mode(current_mode, cfg.floor) else {
                    fallback_exhausted = true;
                    break;
                };
                let mut rewritten = program.clone();
                apply_network_semantics_override(&mut rewritten, next_mode);
                let fallback_lower_started = Instant::now();
                let next_ta = lower(&rewritten)?;
                push_phase_profile(
                    context,
                    "lower",
                    fallback_lower_started.elapsed().as_millis(),
                );
                let next_footprint = automaton_footprint(&next_ta);

                push_applied_reduction(AppliedReductionDiagnostic {
                    context: context.to_string(),
                    kind: "network_fallback".into(),
                    from: network_semantics_name(current_mode).into(),
                    to: network_semantics_name(next_mode).into(),
                    trigger: format!(
                        "model footprint exceeded budget: loc={} (<= {}), shared={} (<= {}), msg={} (<= {})",
                        effective_footprint.locations,
                        cfg.max_locations,
                        effective_footprint.shared_vars,
                        cfg.max_shared_vars,
                        effective_footprint.message_counters,
                        cfg.max_message_counters,
                    ),
                    before: effective_footprint,
                    after: next_footprint,
                });
                fallback_steps = fallback_steps.saturating_add(1);

                current_mode = next_mode;
                current_ta = next_ta;
                effective_footprint = next_footprint;

                if !footprint_exceeds_budget(&effective_footprint, &cfg) {
                    break;
                }
            }
            budget_satisfied = !footprint_exceeds_budget(&effective_footprint, &cfg);
            if !budget_satisfied {
                push_reduction_note(
                    "faithful fallback exhausted before reaching size budget; running with coarsest allowed network semantics",
                );
                push_reduction_note("fast_fail.network_size_guard=triggered");
            }
        }
    }
    let independent_pairs = independent_rule_pair_count(&current_ta);
    let (
        por_stutter_rules_pruned,
        por_commutative_duplicate_rules_pruned,
        por_guard_dominated_rules_pruned,
        por_effective_rule_count,
    ) = por_rule_pruning_summary(&current_ta);
    if independent_pairs > 0 {
        push_reduction_note(&format!("por.independent_rule_pairs={independent_pairs}"));
        push_reduction_note("por.transition_multiset_semantics=on");
    }
    if por_stutter_rules_pruned > 0 {
        push_reduction_note(&format!(
            "por.stutter_rules_pruned={por_stutter_rules_pruned}"
        ));
    }
    if por_commutative_duplicate_rules_pruned > 0 {
        push_reduction_note(&format!(
            "por.commutative_duplicate_rules_pruned={por_commutative_duplicate_rules_pruned}"
        ));
    }
    if por_guard_dominated_rules_pruned > 0 {
        push_reduction_note(&format!(
            "por.guard_dominated_rules_pruned={por_guard_dominated_rules_pruned}"
        ));
    }
    if por_stutter_rules_pruned > 0
        || por_commutative_duplicate_rules_pruned > 0
        || por_guard_dominated_rules_pruned > 0
    {
        push_reduction_note(&format!("por.effective_rules={por_effective_rule_count}"));
    }

    push_lowering_diagnostic(LoweringDiagnostic {
        context: context.to_string(),
        requested_network: network_semantics_name(requested_network).into(),
        effective_network: network_semantics_name(current_mode).into(),
        fault_model: fault_model_name(current_ta.fault_model).into(),
        authentication: authentication_mode_name(current_ta.authentication_mode).into(),
        equivocation: equivocation_mode_name(current_ta.equivocation_mode).into(),
        delivery_control: delivery_control_mode_name(current_ta.delivery_control).into(),
        fault_budget_scope: fault_budget_scope_name(current_ta.fault_budget_scope).into(),
        identity_roles: current_ta.role_identities.len(),
        process_identity_roles: current_ta
            .role_identities
            .values()
            .filter(|cfg| cfg.scope == tarsier_ir::threshold_automaton::RoleIdentityScope::Process)
            .count(),
        requested_footprint,
        effective_footprint,
        fallback_budget: budget,
        budget_satisfied,
        fallback_applied: fallback_steps > 0,
        fallback_steps,
        fallback_exhausted,
        independent_rule_pairs: independent_pairs,
        por_stutter_rules_pruned,
        por_commutative_duplicate_rules_pruned,
        por_guard_dominated_rules_pruned,
        por_effective_rule_count,
    });

    Ok(current_ta)
}

pub(crate) fn lower_with_active_controls(
    program: &ast::Program,
    context: &str,
) -> Result<ThresholdAutomaton, PipelineError> {
    lower_with_controls(program, context, current_execution_controls())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::{Guard, LinearCombination, Rule, Update, UpdateKind};

    // Helper: create a minimal ProtocolDecl for testing
    fn empty_proto() -> ast::ProtocolDecl {
        ast::ProtocolDecl {
            name: "Test".into(),
            imports: vec![],
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            adversary: vec![],
            identities: vec![],
            channels: vec![],
            equivocation_policies: vec![],
            committees: vec![],
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        }
    }

    #[test]
    fn adversary_value_returns_matching_key() {
        let mut proto = empty_proto();
        proto.adversary.push(ast::AdversaryItem {
            key: "model".into(),
            value: "byzantine".into(),
            span: ast::Span::new(0, 0),
        });
        assert_eq!(adversary_value(&proto, "model"), Some("byzantine"));
    }

    #[test]
    fn adversary_value_returns_none_for_missing_key() {
        let proto = empty_proto();
        assert_eq!(adversary_value(&proto, "model"), None);
    }

    #[test]
    fn upsert_adversary_item_inserts_new() {
        let mut proto = empty_proto();
        upsert_adversary_item(&mut proto, "auth", "signed");
        assert_eq!(adversary_value(&proto, "auth"), Some("signed"));
        assert_eq!(proto.adversary.len(), 1);
    }

    #[test]
    fn upsert_adversary_item_updates_existing() {
        let mut proto = empty_proto();
        proto.adversary.push(ast::AdversaryItem {
            key: "auth".into(),
            value: "none".into(),
            span: ast::Span::new(0, 0),
        });
        upsert_adversary_item(&mut proto, "auth", "signed");
        assert_eq!(adversary_value(&proto, "auth"), Some("signed"));
        assert_eq!(proto.adversary.len(), 1);
    }

    #[test]
    fn network_semantics_name_all_variants() {
        assert_eq!(network_semantics_name(NetworkSemantics::Classic), "classic");
        assert_eq!(
            network_semantics_name(NetworkSemantics::IdentitySelective),
            "identity_selective"
        );
        assert_eq!(
            network_semantics_name(NetworkSemantics::CohortSelective),
            "cohort_selective"
        );
        assert_eq!(
            network_semantics_name(NetworkSemantics::ProcessSelective),
            "process_selective"
        );
    }

    #[test]
    fn fault_model_name_all_variants() {
        assert_eq!(fault_model_name(FaultModel::Byzantine), "byzantine");
        assert_eq!(fault_model_name(FaultModel::Crash), "crash");
        assert_eq!(fault_model_name(FaultModel::Omission), "omission");
    }

    #[test]
    fn authentication_mode_name_all_variants() {
        assert_eq!(authentication_mode_name(AuthenticationMode::None), "none");
        assert_eq!(
            authentication_mode_name(AuthenticationMode::Signed),
            "signed"
        );
    }

    #[test]
    fn equivocation_mode_name_all_variants() {
        assert_eq!(equivocation_mode_name(EquivocationMode::Full), "full");
        assert_eq!(equivocation_mode_name(EquivocationMode::None), "none");
    }

    #[test]
    fn parse_declared_network_semantics_classic_default() {
        assert_eq!(
            parse_declared_network_semantics("classic"),
            NetworkSemantics::Classic
        );
        assert_eq!(
            parse_declared_network_semantics("unknown_value"),
            NetworkSemantics::Classic
        );
    }

    #[test]
    fn parse_declared_network_semantics_identity_selective_aliases() {
        assert_eq!(
            parse_declared_network_semantics("identity_selective"),
            NetworkSemantics::IdentitySelective
        );
        assert_eq!(
            parse_declared_network_semantics("faithful"),
            NetworkSemantics::IdentitySelective
        );
        assert_eq!(
            parse_declared_network_semantics("selective"),
            NetworkSemantics::IdentitySelective
        );
        assert_eq!(
            parse_declared_network_semantics("selective_delivery"),
            NetworkSemantics::IdentitySelective
        );
    }

    #[test]
    fn parse_declared_network_semantics_cohort_selective_aliases() {
        assert_eq!(
            parse_declared_network_semantics("cohort_selective"),
            NetworkSemantics::CohortSelective
        );
        assert_eq!(
            parse_declared_network_semantics("lane_selective"),
            NetworkSemantics::CohortSelective
        );
    }

    #[test]
    fn parse_declared_network_semantics_process_selective_aliases() {
        assert_eq!(
            parse_declared_network_semantics("process_selective"),
            NetworkSemantics::ProcessSelective
        );
        assert_eq!(
            parse_declared_network_semantics("per_process"),
            NetworkSemantics::ProcessSelective
        );
        assert_eq!(
            parse_declared_network_semantics("process_scoped"),
            NetworkSemantics::ProcessSelective
        );
    }

    #[test]
    fn is_faithful_network_correct() {
        assert!(!is_faithful_network(NetworkSemantics::Classic));
        assert!(is_faithful_network(NetworkSemantics::IdentitySelective));
        assert!(is_faithful_network(NetworkSemantics::CohortSelective));
        assert!(is_faithful_network(NetworkSemantics::ProcessSelective));
    }

    #[test]
    fn next_coarser_network_mode_process_to_cohort() {
        assert_eq!(
            next_coarser_network_mode(
                NetworkSemantics::ProcessSelective,
                FaithfulFallbackFloor::IdentitySelective
            ),
            Some(NetworkSemantics::CohortSelective)
        );
    }

    #[test]
    fn next_coarser_network_mode_cohort_to_identity() {
        assert_eq!(
            next_coarser_network_mode(
                NetworkSemantics::CohortSelective,
                FaithfulFallbackFloor::IdentitySelective
            ),
            Some(NetworkSemantics::IdentitySelective)
        );
    }

    #[test]
    fn next_coarser_network_mode_identity_floors() {
        // With IdentitySelective floor, identity cannot go lower
        assert_eq!(
            next_coarser_network_mode(
                NetworkSemantics::IdentitySelective,
                FaithfulFallbackFloor::IdentitySelective
            ),
            None
        );
        // With Classic floor, identity can fall back to classic
        assert_eq!(
            next_coarser_network_mode(
                NetworkSemantics::IdentitySelective,
                FaithfulFallbackFloor::Classic
            ),
            Some(NetworkSemantics::Classic)
        );
    }

    #[test]
    fn next_coarser_network_mode_classic_is_bottom() {
        assert_eq!(
            next_coarser_network_mode(NetworkSemantics::Classic, FaithfulFallbackFloor::Classic),
            None
        );
    }

    #[test]
    fn footprint_exceeds_budget_all_within() {
        let footprint = AutomatonFootprint {
            locations: 10,
            rules: 5,
            shared_vars: 8,
            message_counters: 3,
        };
        let cfg = FaithfulFallbackConfig {
            max_locations: 20,
            max_shared_vars: 20,
            max_message_counters: 10,
            floor: FaithfulFallbackFloor::IdentitySelective,
        };
        assert!(!footprint_exceeds_budget(&footprint, &cfg));
    }

    #[test]
    fn footprint_exceeds_budget_locations_over() {
        let footprint = AutomatonFootprint {
            locations: 25,
            rules: 5,
            shared_vars: 8,
            message_counters: 3,
        };
        let cfg = FaithfulFallbackConfig {
            max_locations: 20,
            max_shared_vars: 20,
            max_message_counters: 10,
            floor: FaithfulFallbackFloor::IdentitySelective,
        };
        assert!(footprint_exceeds_budget(&footprint, &cfg));
    }

    #[test]
    fn por_normalized_vars_sorts_and_deduplicates() {
        let vars = vec![3, 1, 2, 1, 3];
        assert_eq!(por_normalized_vars(&vars), vec![1, 2, 3]);
    }

    #[test]
    fn por_normalized_vars_empty() {
        let vars: Vec<usize> = vec![];
        assert_eq!(por_normalized_vars(&vars), Vec::<usize>::new());
    }

    #[test]
    fn por_normalized_lc_terms_merges_and_filters() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(2, 0), (3, 0), (1, 1), (0, 2)],
        };
        let result = por_normalized_lc_terms(&lc);
        // pid=0: 2+3=5, pid=1: 1, pid=2: coeff 0 is filtered
        assert_eq!(result, vec![(5, 0), (1, 1)]);
    }

    #[test]
    fn por_comparable_lc_constants_same_terms() {
        let lhs = LinearCombination {
            constant: 10,
            terms: vec![(1, 0)],
        };
        let rhs = LinearCombination {
            constant: 20,
            terms: vec![(1, 0)],
        };
        assert_eq!(por_comparable_lc_constants(&lhs, &rhs), Some((10, 20)));
    }

    #[test]
    fn por_comparable_lc_constants_different_terms() {
        let lhs = LinearCombination {
            constant: 10,
            terms: vec![(1, 0)],
        };
        let rhs = LinearCombination {
            constant: 20,
            terms: vec![(1, 1)],
        };
        assert_eq!(por_comparable_lc_constants(&lhs, &rhs), None);
    }

    #[test]
    fn por_threshold_op_entails_basic_cases() {
        // Eq entails Eq only if same constant
        assert!(por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 5));
        assert!(!por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 6));
        // Eq entails Ge if lhs_const >= rhs_const
        assert!(por_threshold_op_entails(CmpOp::Eq, 5, CmpOp::Ge, 3));
        assert!(!por_threshold_op_entails(CmpOp::Eq, 3, CmpOp::Ge, 5));
        // Ge entails Ge if lhs_const >= rhs_const
        assert!(por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Ge, 3));
        assert!(por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Ge, 5));
        assert!(!por_threshold_op_entails(CmpOp::Ge, 3, CmpOp::Ge, 5));
        // Gt entails Ge
        assert!(por_threshold_op_entails(CmpOp::Gt, 5, CmpOp::Ge, 5));
        // Le entails Le
        assert!(por_threshold_op_entails(CmpOp::Le, 3, CmpOp::Le, 5));
        // Ne entails Ne only if same constant
        assert!(por_threshold_op_entails(CmpOp::Ne, 5, CmpOp::Ne, 5));
        assert!(!por_threshold_op_entails(CmpOp::Ne, 5, CmpOp::Ne, 6));
        // Cross that should not entail
        assert!(!por_threshold_op_entails(CmpOp::Ge, 5, CmpOp::Le, 5));
    }

    #[test]
    fn is_pure_stutter_rule_true_case() {
        let rule = Rule {
            from: 0,
            to: 0,
            guard: Guard::trivial(),
            updates: vec![],
        };
        assert!(is_pure_stutter_rule(&rule));
    }

    #[test]
    fn is_pure_stutter_rule_false_different_locations() {
        let rule = Rule {
            from: 0,
            to: 1,
            guard: Guard::trivial(),
            updates: vec![],
        };
        assert!(!is_pure_stutter_rule(&rule));
    }

    #[test]
    fn is_pure_stutter_rule_false_has_updates() {
        let rule = Rule {
            from: 0,
            to: 0,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        };
        assert!(!is_pure_stutter_rule(&rule));
    }

    #[test]
    fn guard_read_vars_extracts_vars() {
        let guard = Guard {
            atoms: vec![
                GuardAtom::Threshold {
                    vars: vec![0, 1],
                    op: CmpOp::Ge,
                    bound: LinearCombination::constant(1),
                    distinct: false,
                },
                GuardAtom::Threshold {
                    vars: vec![2],
                    op: CmpOp::Gt,
                    bound: LinearCombination::constant(0),
                    distinct: false,
                },
            ],
        };
        let reads = guard_read_vars(&guard);
        assert!(reads.contains(&0));
        assert!(reads.contains(&1));
        assert!(reads.contains(&2));
        assert_eq!(reads.len(), 3);
    }

    #[test]
    fn update_write_vars_extracts_vars() {
        let updates = vec![
            Update {
                var: 0,
                kind: UpdateKind::Increment,
            },
            Update {
                var: 3,
                kind: UpdateKind::Increment,
            },
        ];
        let writes = update_write_vars(&updates);
        assert!(writes.contains(&0));
        assert!(writes.contains(&3));
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn por_linear_combination_signature_format() {
        let lc = LinearCombination {
            constant: 5,
            terms: vec![(2, 0), (1, 1)],
        };
        let sig = por_linear_combination_signature(&lc);
        assert_eq!(sig, "c=5|2*p0|1*p1");
    }

    #[test]
    fn por_update_signature_increment() {
        let update = Update {
            var: 3,
            kind: UpdateKind::Increment,
        };
        assert_eq!(por_update_signature(&update), "inc@3");
    }

    #[test]
    fn por_update_signature_set() {
        let update = Update {
            var: 1,
            kind: UpdateKind::Set(LinearCombination {
                constant: 0,
                terms: vec![(1, 0)],
            }),
        };
        assert_eq!(por_update_signature(&update), "set@1=c=0|1*p0");
    }

    #[test]
    fn upsert_message_channel_policy_inserts_new() {
        let mut proto = empty_proto();
        upsert_message_channel_policy(&mut proto, "Vote", ast::ChannelAuthMode::Authenticated);
        assert_eq!(proto.channels.len(), 1);
        assert_eq!(proto.channels[0].message, "Vote");
        assert_eq!(proto.channels[0].auth, ast::ChannelAuthMode::Authenticated);
    }

    #[test]
    fn upsert_message_channel_policy_updates_existing() {
        let mut proto = empty_proto();
        proto.channels.push(ast::ChannelDecl {
            message: "Vote".into(),
            auth: ast::ChannelAuthMode::Unauthenticated,
            span: ast::Span::new(0, 0),
        });
        upsert_message_channel_policy(&mut proto, "Vote", ast::ChannelAuthMode::Authenticated);
        assert_eq!(proto.channels.len(), 1);
        assert_eq!(proto.channels[0].auth, ast::ChannelAuthMode::Authenticated);
    }

    #[test]
    fn upsert_message_equivocation_policy_inserts_new() {
        let mut proto = empty_proto();
        upsert_message_equivocation_policy(&mut proto, "Vote", ast::EquivocationPolicyMode::None);
        assert_eq!(proto.equivocation_policies.len(), 1);
        assert_eq!(proto.equivocation_policies[0].message, "Vote");
        assert_eq!(
            proto.equivocation_policies[0].mode,
            ast::EquivocationPolicyMode::None
        );
    }

    #[test]
    fn upsert_message_equivocation_policy_updates_existing() {
        let mut proto = empty_proto();
        proto.equivocation_policies.push(ast::EquivocationDecl {
            message: "Vote".into(),
            mode: ast::EquivocationPolicyMode::Full,
            span: ast::Span::new(0, 0),
        });
        upsert_message_equivocation_policy(&mut proto, "Vote", ast::EquivocationPolicyMode::None);
        assert_eq!(proto.equivocation_policies.len(), 1);
        assert_eq!(
            proto.equivocation_policies[0].mode,
            ast::EquivocationPolicyMode::None
        );
    }
}
