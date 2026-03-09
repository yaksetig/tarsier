//! Partial-order reduction, guard implication analysis, message grouping,
//! and shared encoding helpers.

use std::collections::HashMap;

use tarsier_ir::threshold_automaton::*;

use crate::terms::SmtTerm;

use super::variables::*;
use super::BmcEncoding;

/// Result of static partial-order reduction analysis.
///
/// Tracks which rules are disabled and the reason for each pruning, enabling
/// diagnostic reporting of how many rules were eliminated.
#[derive(Debug, Clone)]
pub(super) struct PorRulePruning {
    disabled_rules: Vec<bool>,
    pub(super) stutter_pruned: usize,
    pub(super) commutative_duplicate_pruned: usize,
    pub(super) guard_dominated_pruned: usize,
}

impl PorRulePruning {
    /// Check if a rule has been pruned by any POR strategy.
    pub(super) fn is_disabled(&self, rule_id: usize) -> bool {
        self.disabled_rules.get(rule_id).copied().unwrap_or(false)
    }

    /// Return the IDs of rules that survived pruning.
    pub(super) fn active_rule_ids(&self) -> Vec<usize> {
        self.disabled_rules
            .iter()
            .enumerate()
            .filter_map(|(idx, disabled)| (!disabled).then_some(idx))
            .collect()
    }
}

/// Normalize a linear combination into a canonical string for comparing guards.
pub(super) fn linear_combination_signature(lc: &LinearCombination) -> String {
    let mut terms = lc.terms.clone();
    terms.sort_by_key(|(_, pid)| *pid);
    let mut out = format!("c={}", lc.constant);
    for (coeff, pid) in terms {
        out.push('|');
        out.push_str(&format!("{coeff}*p{pid}"));
    }
    out
}

/// Sort and deduplicate a variable index list for comparison.
pub(super) fn normalized_vars(vars: &[impl Copy + Into<usize>]) -> Vec<usize> {
    let mut out: Vec<usize> = vars.iter().map(|v| (*v).into()).collect();
    out.sort();
    out.dedup();
    out
}

/// Merge duplicate parameter coefficients and drop zeros.
pub(super) fn normalized_lc_terms(lc: &LinearCombination) -> Vec<(i64, usize)> {
    let mut coeff_by_param: HashMap<usize, i64> = HashMap::new();
    for (coeff, pid) in &lc.terms {
        if *coeff == 0 {
            continue;
        }
        *coeff_by_param.entry(pid.as_usize()).or_insert(0) += *coeff;
    }
    let mut terms: Vec<(i64, usize)> = coeff_by_param
        .into_iter()
        .filter_map(|(pid, coeff)| (coeff != 0).then_some((coeff, pid)))
        .collect();
    terms.sort_by_key(|(_, pid)| *pid);
    terms
}

/// If two linear combinations have identical parameter terms, return their constants for comparison.
pub(super) fn comparable_lc_constants(
    lhs: &LinearCombination,
    rhs: &LinearCombination,
) -> Option<(i64, i64)> {
    let lhs_terms = normalized_lc_terms(lhs);
    let rhs_terms = normalized_lc_terms(rhs);
    if lhs_terms == rhs_terms {
        Some((lhs.constant, rhs.constant))
    } else {
        None
    }
}

/// Check whether one threshold guard logically implies another, given
/// that both share the same parameter-coefficient structure.
pub(super) fn threshold_op_entails(
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

/// Check whether one guard atom logically implies another.
pub(super) fn guard_atom_implies(lhs: &GuardAtom, rhs: &GuardAtom) -> bool {
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
                || normalized_vars(lhs_vars) != normalized_vars(rhs_vars)
            {
                return false;
            }
            let Some((lhs_const, rhs_const)) = comparable_lc_constants(lhs_bound, rhs_bound) else {
                return false;
            };
            threshold_op_entails(*lhs_op, lhs_const, *rhs_op, rhs_const)
        }
    }
}

/// Check whether a guard (conjunction of atoms) implies another.
pub(super) fn guard_implies(lhs: &Guard, rhs: &Guard) -> bool {
    rhs.atoms.iter().all(|rhs_atom| {
        lhs.atoms
            .iter()
            .any(|lhs_atom| guard_atom_implies(lhs_atom, rhs_atom))
    })
}

/// Serialize a guard atom to a canonical string for deduplication.
pub(super) fn guard_atom_signature(atom: &GuardAtom) -> String {
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
                linear_combination_signature(bound)
            )
        }
    }
}

/// Canonical signature of a rule's effect (source, target, updates) without its guard.
pub(super) fn rule_effect_signature(rule: &Rule) -> String {
    let updates = rule
        .updates
        .iter()
        .map(update_signature)
        .collect::<Vec<_>>()
        .join(";");
    format!("from={};to={};updates=[{updates}]", rule.from, rule.to)
}

/// Canonical signature of a single shared-var update.
pub(super) fn update_signature(update: &Update) -> String {
    match &update.kind {
        UpdateKind::Increment => format!("inc@{}", update.var),
        UpdateKind::Set(lc) => format!("set@{}={}", update.var, linear_combination_signature(lc)),
    }
}

/// Full canonical signature of a rule (guards + effect) for commutative-duplicate detection.
pub(super) fn rule_signature(rule: &Rule) -> String {
    let mut guards = rule
        .guard
        .atoms
        .iter()
        .map(guard_atom_signature)
        .collect::<Vec<_>>();
    guards.sort();
    let updates = rule
        .updates
        .iter()
        .map(update_signature)
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

/// A pure stutter rule is a self-loop with no updates — always prunable.
pub(super) fn is_pure_stutter_rule(rule: &Rule) -> bool {
    rule.from == rule.to && rule.updates.is_empty()
}

/// Analyze the threshold automaton and disable rules that are provably redundant.
///
/// Three pruning strategies applied in order:
/// 1. **Stutter**: identity transitions (self-loop, no updates)
/// 2. **Commutative duplicates**: rules with identical signatures
/// 3. **Guard-dominated**: rules whose guard is implied by a cheaper alternative
pub(super) fn compute_por_rule_pruning(ta: &ThresholdAutomaton) -> PorRulePruning {
    if ta.semantics.por_mode == PorMode::Off {
        return PorRulePruning {
            disabled_rules: vec![false; ta.rules.len()],
            stutter_pruned: 0,
            commutative_duplicate_pruned: 0,
            guard_dominated_pruned: 0,
        };
    }
    let mut disabled_rules = vec![false; ta.rules.len()];
    let mut stutter_pruned = 0usize;
    let mut commutative_duplicate_pruned = 0usize;
    let mut guard_dominated_pruned = 0usize;
    let mut canonical_by_signature: HashMap<String, usize> = HashMap::new();

    for (rule_id, rule) in ta.rules.iter().enumerate() {
        if is_pure_stutter_rule(rule) {
            disabled_rules[rule_id] = true;
            stutter_pruned = stutter_pruned.saturating_add(1);
            continue;
        }
        let signature = rule_signature(rule);
        if canonical_by_signature.insert(signature, rule_id).is_some() {
            disabled_rules[rule_id] = true;
            commutative_duplicate_pruned = commutative_duplicate_pruned.saturating_add(1);
        }
    }

    let rule_effects: Vec<String> = ta.rules.iter().map(rule_effect_signature).collect();
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
            if !guard_implies(&ta.rules[rule_id].guard, &ta.rules[other_id].guard) {
                continue;
            }
            let other_implies = guard_implies(&ta.rules[other_id].guard, &ta.rules[rule_id].guard);
            // Preserve deterministic tie-breaking for equivalent guards.
            if other_implies && other_id > rule_id {
                continue;
            }
            disabled_rules[rule_id] = true;
            guard_dominated_pruned = guard_dominated_pruned.saturating_add(1);
            break;
        }
    }

    PorRulePruning {
        disabled_rules,
        stutter_pruned,
        commutative_duplicate_pruned,
        guard_dominated_pruned,
    }
}

const DEFAULT_PROCESS_ID_VAR: &str = "pid";

/// Look up the process-identity local variable name for a role.
pub(super) fn role_process_identity_var<'a>(
    ta: &'a ThresholdAutomaton,
    role: &str,
) -> Option<&'a str> {
    ta.security
        .role_identities
        .get(role)
        .and_then(|cfg| {
            if cfg.scope == RoleIdentityScope::Process {
                cfg.process_var.as_deref()
            } else {
                None
            }
        })
        .or(Some(DEFAULT_PROCESS_ID_VAR))
}

/// Check whether a location has a non-negative process identity value.
pub(super) fn location_has_valid_process_identity(ta: &ThresholdAutomaton, loc: &Location) -> bool {
    let Some(pid_var) = role_process_identity_var(ta, &loc.role) else {
        return false;
    };
    matches!(loc.local_vars.get(pid_var), Some(LocalValue::Int(pid)) if *pid >= 0)
}

/// Group locations by (role, process-id) for process-selective network constraints.
pub(super) fn process_identity_buckets(
    ta: &ThresholdAutomaton,
) -> HashMap<(String, i64), Vec<usize>> {
    let mut buckets: HashMap<(String, i64), Vec<usize>> = HashMap::new();
    for (loc_id, loc) in ta.locations.iter().enumerate() {
        let Some(pid_var) = role_process_identity_var(ta, &loc.role) else {
            continue;
        };
        if let Some(LocalValue::Int(pid)) = loc.local_vars.get(pid_var) {
            buckets
                .entry((loc.role.clone(), *pid))
                .or_default()
                .push(loc_id);
        }
    }
    buckets
}

/// Assert that each (role, pid) bucket occupies exactly one location at each step.
pub(super) fn assert_process_identity_uniqueness(
    enc: &mut BmcEncoding,
    step: usize,
    buckets: &HashMap<(String, i64), Vec<usize>>,
) {
    for locs in buckets.values() {
        if locs.is_empty() {
            continue;
        }
        let total = locs
            .iter()
            .map(|l| SmtTerm::var(kappa_var(step, *l)))
            .collect::<Vec<_>>();
        let total = sum_terms_balanced(total);
        enc.assert_term(total.eq(SmtTerm::int(1)));
    }
}

/// Parse a message-counter variable name to extract (family, optional recipient).
pub(super) fn message_family_and_recipient_from_counter_name(
    name: &str,
) -> Option<(String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, recipient) = match stripped.split_once('@') {
        Some((family, tail)) => {
            let channel = tail.split_once('[').map(|(r, _)| r).unwrap_or(tail);
            let recipient = channel
                .split_once("<-")
                .map(|(r, _)| r)
                .unwrap_or(channel)
                .to_string();
            (family, Some(recipient))
        }
        None => (stripped, None),
    };
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    Some((family, recipient))
}

/// Parse a message-counter variable name to extract (family, optional sender channel).
pub(super) fn message_family_and_sender_from_counter_name(
    name: &str,
) -> Option<(String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, sender) = match stripped.split_once('@') {
        Some((family, tail)) => {
            let channel = tail.split_once('[').map(|(r, _)| r).unwrap_or(tail);
            let sender = channel
                .split_once("<-")
                .map(|(_, sender)| sender.to_string());
            (family, sender)
        }
        None => (stripped, None),
    };
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    Some((family, sender))
}

/// Extract the role name from a sender channel key (before the `#` separator).
pub(super) fn sender_channel_role(sender_channel: &str) -> &str {
    sender_channel
        .split_once('#')
        .map(|(role, _)| role)
        .unwrap_or(sender_channel)
}

/// Check if a sender channel's signing key has been marked as compromised.
pub(super) fn sender_channel_key_compromised(
    ta: &ThresholdAutomaton,
    sender_channel: &str,
) -> bool {
    let role = sender_channel_role(sender_channel);
    ta.security
        .role_identities
        .get(role)
        .map(|cfg| ta.security.compromised_keys.contains(&cfg.key_name))
        .unwrap_or(false)
}

/// Parse a counter name to extract (variant key, family name) for message grouping.
pub(super) fn message_variant_and_family_from_counter_name(name: &str) -> Option<(String, String)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (variant, family) = match stripped.split_once('@') {
        Some((family_part, tail)) => {
            let field_suffix = tail
                .split_once('[')
                .map(|(_, fields)| format!("[{fields}"))
                .unwrap_or_default();
            let family = family_part
                .split_once('[')
                .map(|(base, _)| base)
                .unwrap_or(family_part)
                .to_string();
            (format!("{family}{field_suffix}"), family)
        }
        None => {
            let family = stripped
                .split_once('[')
                .map(|(base, _)| base)
                .unwrap_or(stripped)
                .to_string();
            (stripped.to_string(), family)
        }
    };
    Some((variant, family))
}

/// Collect message-counter shared vars into groups by variant, for encoding message semantics.
pub(super) fn collect_message_variant_groups(ta: &ThresholdAutomaton) -> MessageVariantGroups {
    let mut group_index_by_variant: HashMap<String, usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut group_families: Vec<String> = Vec::new();
    let mut family_groups: HashMap<String, Vec<usize>> = HashMap::new();

    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((variant, family)) = message_variant_and_family_from_counter_name(&shared.name)
        else {
            continue;
        };

        let group_id = if let Some(existing) = group_index_by_variant.get(&variant) {
            *existing
        } else {
            let new_id = groups.len();
            groups.push(Vec::new());
            group_families.push(family.clone());
            group_index_by_variant.insert(variant, new_id);
            family_groups.entry(family).or_default().push(new_id);
            new_id
        };
        groups[group_id].push(var_id);
    }

    (groups, group_families, family_groups)
}

/// Collect crypto-object message groups with exclusive conflict policy.
pub(super) fn collect_exclusive_crypto_variant_groups(
    ta: &ThresholdAutomaton,
) -> HashMap<(String, String), Vec<Vec<usize>>> {
    let mut by_variant: HashMap<(String, String, String), Vec<usize>> = HashMap::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient)) =
            message_family_and_recipient_from_counter_name(&shared.name)
        else {
            continue;
        };
        let Some(recipient) = recipient else {
            continue;
        };
        let Some(spec) = ta.security.crypto_objects.get(&family) else {
            continue;
        };
        if spec.conflict_policy != CryptoConflictPolicy::Exclusive {
            continue;
        }
        let Some((variant, _)) = message_variant_and_family_from_counter_name(&shared.name) else {
            continue;
        };
        by_variant
            .entry((family.clone(), recipient, variant))
            .or_default()
            .push(var_id);
    }

    let mut grouped: CryptoVariantBuckets = HashMap::new();
    for ((family, recipient, variant), vars) in by_variant {
        grouped
            .entry((family, recipient))
            .or_default()
            .push((variant, vars));
    }

    let mut result: HashMap<(String, String), Vec<Vec<usize>>> = HashMap::new();
    for (key, mut variants) in grouped {
        variants.sort_by(|a, b| a.0.cmp(&b.0));
        result.insert(key, variants.into_iter().map(|(_, vars)| vars).collect());
    }
    result
}

/// Resolve a message family's effective authentication policy (inheriting from global if needed).
pub(super) fn message_effective_signed_auth(ta: &ThresholdAutomaton, family: &str) -> bool {
    match ta
        .security
        .message_policies
        .get(family)
        .map(|p| p.auth)
        .unwrap_or(MessageAuthPolicy::Inherit)
    {
        MessageAuthPolicy::Authenticated => true,
        MessageAuthPolicy::Unauthenticated => false,
        MessageAuthPolicy::Inherit => {
            ta.semantics.authentication_mode == AuthenticationMode::Signed
        }
    }
}

/// Resolve a message family's effective equivocation policy (inheriting from global if needed).
pub(super) fn message_effective_non_equivocating(ta: &ThresholdAutomaton, family: &str) -> bool {
    match ta
        .security
        .message_policies
        .get(family)
        .map(|p| p.equivocation)
        .unwrap_or(MessageEquivocationPolicy::Inherit)
    {
        MessageEquivocationPolicy::None => true,
        MessageEquivocationPolicy::Full => false,
        MessageEquivocationPolicy::Inherit => {
            ta.semantics.equivocation_mode == EquivocationMode::None
        }
    }
}

/// Group message-counter shared vars by recipient, plus a flat list of all counters.
pub(super) fn collect_message_counter_recipient_groups(
    ta: &ThresholdAutomaton,
) -> (HashMap<String, Vec<usize>>, Vec<usize>) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut all: Vec<usize> = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let recipient = message_family_and_recipient_from_counter_name(&shared.name)
            .and_then(|(_, r)| r)
            .unwrap_or_else(|| "*".to_string());
        groups.entry(recipient).or_default().push(var_id);
        all.push(var_id);
    }
    (groups, all)
}

/// Boolean flag per shared var: true if it is a message counter.
pub(super) fn collect_message_counter_flags(ta: &ThresholdAutomaton) -> Vec<bool> {
    ta.shared_vars
        .iter()
        .map(|shared| shared.kind == SharedVarKind::MessageCounter)
        .collect()
}

/// Build a balanced arithmetic sum tree to avoid very deep left-associated terms.
pub(super) fn sum_terms_balanced(mut terms: Vec<SmtTerm>) -> SmtTerm {
    if terms.is_empty() {
        return SmtTerm::int(0);
    }
    while terms.len() > 1 {
        let mut next = Vec::with_capacity(terms.len().div_ceil(2));
        let mut iter = terms.into_iter();
        while let Some(lhs) = iter.next() {
            if let Some(rhs) = iter.next() {
                next.push(lhs.add(rhs));
            } else {
                next.push(lhs);
            }
        }
        terms = next;
    }
    terms.pop().unwrap_or_else(|| SmtTerm::int(0))
}

/// Encode a linear combination as an SmtTerm.
pub(super) fn encode_lc(lc: &LinearCombination) -> SmtTerm {
    let mut terms = Vec::with_capacity(lc.terms.len() + usize::from(lc.constant != 0));
    if lc.constant != 0 {
        terms.push(SmtTerm::int(lc.constant));
    }
    for &(coeff, pid) in &lc.terms {
        let param_term = SmtTerm::var(param_var(pid));
        let scaled = if coeff == 1 {
            param_term
        } else {
            SmtTerm::int(coeff).mul(param_term)
        };
        terms.push(scaled);
    }
    sum_terms_balanced(terms)
}

/// Encode a [`LinearCombination`] using step-dependent variables for time-varying
/// parameters. Fixed parameters use global `p_i`; time-varying parameters use
/// `p_i_step`.
pub(super) fn encode_lc_at_step(
    lc: &LinearCombination,
    step: usize,
    time_varying_ids: &[usize],
) -> SmtTerm {
    let mut terms = Vec::with_capacity(lc.terms.len() + usize::from(lc.constant != 0));
    if lc.constant != 0 {
        terms.push(SmtTerm::int(lc.constant));
    }
    for &(coeff, pid) in &lc.terms {
        let pid_usize = pid.as_usize();
        let param_term = if time_varying_ids.contains(&pid_usize) {
            SmtTerm::var(param_var_at_step(step, pid))
        } else {
            SmtTerm::var(param_var(pid))
        };
        let scaled = if coeff == 1 {
            param_term
        } else {
            SmtTerm::int(coeff).mul(param_term)
        };
        terms.push(scaled);
    }
    sum_terms_balanced(terms)
}

/// Encode a threshold guard atom as an SmtTerm for a given step.
pub(super) fn encode_threshold_guard_at_step(
    step: usize,
    vars: &[impl Copy + std::fmt::Display],
    op: CmpOp,
    bound: &LinearCombination,
    distinct: bool,
) -> SmtTerm {
    let lhs = if distinct {
        let terms: Vec<SmtTerm> = vars
            .iter()
            .map(|var| {
                let gv = SmtTerm::var(gamma_var(step, *var));
                SmtTerm::Ite(
                    Box::new(gv.gt(SmtTerm::int(0))),
                    Box::new(SmtTerm::int(1)),
                    Box::new(SmtTerm::int(0)),
                )
            })
            .collect();
        sum_terms_balanced(terms)
    } else {
        let terms: Vec<SmtTerm> = vars
            .iter()
            .map(|var| SmtTerm::var(gamma_var(step, *var)))
            .collect();
        sum_terms_balanced(terms)
    };
    let rhs = encode_lc(bound);
    match op {
        CmpOp::Ge => lhs.ge(rhs),
        CmpOp::Gt => lhs.gt(rhs),
        CmpOp::Le => lhs.le(rhs),
        CmpOp::Lt => lhs.lt(rhs),
        CmpOp::Eq => lhs.eq(rhs),
        CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
    }
}

/// Like [`encode_threshold_guard_at_step`] but uses step-dependent variables
/// for time-varying parameters.
pub(super) fn encode_threshold_guard_at_step_epoch(
    step: usize,
    vars: &[impl Copy + std::fmt::Display],
    op: CmpOp,
    bound: &LinearCombination,
    distinct: bool,
    time_varying_ids: &[usize],
) -> SmtTerm {
    let lhs = if distinct {
        let terms: Vec<SmtTerm> = vars
            .iter()
            .map(|var| {
                let gv = SmtTerm::var(gamma_var(step, *var));
                SmtTerm::Ite(
                    Box::new(gv.gt(SmtTerm::int(0))),
                    Box::new(SmtTerm::int(1)),
                    Box::new(SmtTerm::int(0)),
                )
            })
            .collect();
        sum_terms_balanced(terms)
    } else {
        let terms: Vec<SmtTerm> = vars
            .iter()
            .map(|var| SmtTerm::var(gamma_var(step, *var)))
            .collect();
        sum_terms_balanced(terms)
    };
    let rhs = encode_lc_at_step(bound, step, time_varying_ids);
    match op {
        CmpOp::Ge => lhs.ge(rhs),
        CmpOp::Gt => lhs.gt(rhs),
        CmpOp::Le => lhs.le(rhs),
        CmpOp::Lt => lhs.lt(rhs),
        CmpOp::Eq => lhs.eq(rhs),
        CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
    }
}
