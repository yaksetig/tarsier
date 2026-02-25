use std::collections::{HashMap, HashSet};
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::*;

use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

/// Variables and assertions for a BMC encoding of a counter system.
pub struct BmcEncoding {
    /// Variable declarations: (name, sort).
    pub declarations: Vec<(String, SmtSort)>,
    /// Assertions (constraints).
    pub assertions: Vec<SmtTerm>,
    /// Names of variables to extract for counterexample.
    pub model_vars: Vec<(String, SmtSort)>,
    assertion_keys: HashSet<String>,
    assertion_candidates: usize,
    assertion_dedup_hits: usize,
}

impl BmcEncoding {
    fn new() -> Self {
        Self {
            declarations: Vec::new(),
            assertions: Vec::new(),
            model_vars: Vec::new(),
            assertion_keys: HashSet::new(),
            assertion_candidates: 0,
            assertion_dedup_hits: 0,
        }
    }

    fn declare(&mut self, name: String, sort: SmtSort) {
        self.model_vars.push((name.clone(), sort.clone()));
        self.declarations.push((name, sort));
    }

    fn assert_term(&mut self, term: SmtTerm) {
        self.assertion_candidates = self.assertion_candidates.saturating_add(1);
        let key = canonical_term_key(&term);
        if self.assertion_keys.insert(key) {
            self.assertions.push(term);
        } else {
            self.assertion_dedup_hits = self.assertion_dedup_hits.saturating_add(1);
        }
    }

    pub fn assertion_candidates(&self) -> usize {
        self.assertion_candidates
    }

    pub fn assertion_unique(&self) -> usize {
        self.assertions.len()
    }

    pub fn assertion_dedup_hits(&self) -> usize {
        self.assertion_dedup_hits
    }
}

fn canonical_binary_commutative(tag: &str, lhs: &SmtTerm, rhs: &SmtTerm) -> String {
    let left = canonical_term_key(lhs);
    let right = canonical_term_key(rhs);
    if left <= right {
        format!("({tag} {left} {right})")
    } else {
        format!("({tag} {right} {left})")
    }
}

fn canonical_term_key(term: &SmtTerm) -> String {
    match term {
        SmtTerm::Var(name) => format!("(var {name})"),
        SmtTerm::IntLit(v) => format!("(int {v})"),
        SmtTerm::BoolLit(v) => format!("(bool {v})"),
        SmtTerm::Add(lhs, rhs) => canonical_binary_commutative("+", lhs, rhs),
        SmtTerm::Sub(lhs, rhs) => {
            format!(
                "(- {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::Mul(lhs, rhs) => canonical_binary_commutative("*", lhs, rhs),
        SmtTerm::Eq(lhs, rhs) => canonical_binary_commutative("=", lhs, rhs),
        SmtTerm::Lt(lhs, rhs) => {
            format!(
                "(< {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::Le(lhs, rhs) => {
            format!(
                "(<= {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::Gt(lhs, rhs) => {
            format!(
                "(> {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::Ge(lhs, rhs) => {
            format!(
                "(>= {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::And(terms) => {
            let mut items = terms.iter().map(canonical_term_key).collect::<Vec<_>>();
            items.sort();
            format!("(and {})", items.join(" "))
        }
        SmtTerm::Or(terms) => {
            let mut items = terms.iter().map(canonical_term_key).collect::<Vec<_>>();
            items.sort();
            format!("(or {})", items.join(" "))
        }
        SmtTerm::Not(inner) => format!("(not {})", canonical_term_key(inner)),
        SmtTerm::Implies(lhs, rhs) => {
            format!(
                "(=> {} {})",
                canonical_term_key(lhs),
                canonical_term_key(rhs)
            )
        }
        SmtTerm::ForAll(vars, body) => {
            let vars_key = vars
                .iter()
                .map(|(name, sort)| format!("{name}:{sort:?}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("(forall [{vars_key}] {})", canonical_term_key(body))
        }
        SmtTerm::Exists(vars, body) => {
            let vars_key = vars
                .iter()
                .map(|(name, sort)| format!("{name}:{sort:?}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("(exists [{vars_key}] {})", canonical_term_key(body))
        }
        SmtTerm::Ite(cond, then_term, else_term) => format!(
            "(ite {} {} {})",
            canonical_term_key(cond),
            canonical_term_key(then_term),
            canonical_term_key(else_term)
        ),
    }
}

type MessageVariantGroups = (Vec<Vec<usize>>, Vec<String>, HashMap<String, Vec<usize>>);
type CryptoVariantBuckets = HashMap<(String, String), Vec<(String, Vec<usize>)>>;

/// Variable naming conventions:
/// - `p_i` — parameter i
/// - `kappa_k_l` — counter for location l at step k
/// - `g_k_v` — shared variable v at step k
/// - `delta_k_r` — firing count for rule r at step k
fn param_var(i: usize) -> String {
    format!("p_{i}")
}

pub(crate) fn kappa_var(step: usize, loc: usize) -> String {
    format!("kappa_{step}_{loc}")
}

pub(crate) fn gamma_var(step: usize, var: usize) -> String {
    format!("g_{step}_{var}")
}

pub(crate) fn time_var(step: usize) -> String {
    format!("time_{step}")
}

pub(crate) fn delta_var(step: usize, rule: usize) -> String {
    format!("delta_{step}_{rule}")
}

fn drop_var(step: usize, var: usize) -> String {
    format!("drop_{step}_{var}")
}

fn adv_send_var(step: usize, group: usize) -> String {
    format!("advsend_{step}_{group}")
}

fn byz_sender_var(step: usize, sender: usize) -> String {
    format!("byzsender_{step}_{sender}")
}

fn byz_sender_static_var(sender: usize) -> String {
    format!("byzsender_static_{sender}")
}

fn net_pending_var(step: usize, var: usize) -> String {
    format!("net_pending_{step}_{var}")
}

fn net_send_var(step: usize, var: usize) -> String {
    format!("net_send_{step}_{var}")
}

fn net_forge_var(step: usize, var: usize) -> String {
    format!("net_forge_{step}_{var}")
}

fn net_deliver_var(step: usize, var: usize) -> String {
    format!("net_deliver_{step}_{var}")
}

fn net_drop_var(step: usize, var: usize) -> String {
    format!("net_drop_{step}_{var}")
}

fn parse_internal_sent_flag_var(name: &str) -> Option<usize> {
    name.strip_prefix("__sent_g")?.parse::<usize>().ok()
}

#[derive(Debug, Clone)]
struct PorRulePruning {
    disabled_rules: Vec<bool>,
    stutter_pruned: usize,
    commutative_duplicate_pruned: usize,
    guard_dominated_pruned: usize,
}

impl PorRulePruning {
    fn is_disabled(&self, rule_id: usize) -> bool {
        self.disabled_rules.get(rule_id).copied().unwrap_or(false)
    }

    fn active_rule_ids(&self) -> Vec<usize> {
        self.disabled_rules
            .iter()
            .enumerate()
            .filter_map(|(idx, disabled)| (!disabled).then_some(idx))
            .collect()
    }
}

fn linear_combination_signature(lc: &LinearCombination) -> String {
    let mut terms = lc.terms.clone();
    terms.sort_by_key(|(_, pid)| *pid);
    let mut out = format!("c={}", lc.constant);
    for (coeff, pid) in terms {
        out.push('|');
        out.push_str(&format!("{coeff}*p{pid}"));
    }
    out
}

fn normalized_vars(vars: &[usize]) -> Vec<usize> {
    let mut out = vars.to_vec();
    out.sort();
    out.dedup();
    out
}

fn normalized_lc_terms(lc: &LinearCombination) -> Vec<(i64, usize)> {
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

fn comparable_lc_constants(lhs: &LinearCombination, rhs: &LinearCombination) -> Option<(i64, i64)> {
    let lhs_terms = normalized_lc_terms(lhs);
    let rhs_terms = normalized_lc_terms(rhs);
    if lhs_terms == rhs_terms {
        Some((lhs.constant, rhs.constant))
    } else {
        None
    }
}

fn threshold_op_entails(lhs_op: CmpOp, lhs_const: i64, rhs_op: CmpOp, rhs_const: i64) -> bool {
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

fn guard_atom_implies(lhs: &GuardAtom, rhs: &GuardAtom) -> bool {
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

fn guard_implies(lhs: &Guard, rhs: &Guard) -> bool {
    rhs.atoms.iter().all(|rhs_atom| {
        lhs.atoms
            .iter()
            .any(|lhs_atom| guard_atom_implies(lhs_atom, rhs_atom))
    })
}

fn guard_atom_signature(atom: &GuardAtom) -> String {
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

fn rule_effect_signature(rule: &Rule) -> String {
    let updates = rule
        .updates
        .iter()
        .map(update_signature)
        .collect::<Vec<_>>()
        .join(";");
    format!("from={};to={};updates=[{updates}]", rule.from, rule.to)
}

fn update_signature(update: &Update) -> String {
    match &update.kind {
        UpdateKind::Increment => format!("inc@{}", update.var),
        UpdateKind::Set(lc) => format!("set@{}={}", update.var, linear_combination_signature(lc)),
    }
}

fn rule_signature(rule: &Rule) -> String {
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

fn is_pure_stutter_rule(rule: &Rule) -> bool {
    rule.from == rule.to && rule.updates.is_empty()
}

fn compute_por_rule_pruning(ta: &ThresholdAutomaton) -> PorRulePruning {
    if ta.por_mode == PorMode::Off {
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

fn role_process_identity_var<'a>(ta: &'a ThresholdAutomaton, role: &str) -> Option<&'a str> {
    ta.role_identities
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

fn location_has_valid_process_identity(ta: &ThresholdAutomaton, loc: &Location) -> bool {
    let Some(pid_var) = role_process_identity_var(ta, &loc.role) else {
        return false;
    };
    matches!(loc.local_vars.get(pid_var), Some(LocalValue::Int(pid)) if *pid >= 0)
}

fn process_identity_buckets(ta: &ThresholdAutomaton) -> HashMap<(String, i64), Vec<usize>> {
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

fn assert_process_identity_uniqueness(
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

fn message_family_and_recipient_from_counter_name(name: &str) -> Option<(String, Option<String>)> {
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

fn message_family_and_sender_from_counter_name(name: &str) -> Option<(String, Option<String>)> {
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

fn sender_channel_role(sender_channel: &str) -> &str {
    sender_channel
        .split_once('#')
        .map(|(role, _)| role)
        .unwrap_or(sender_channel)
}

fn sender_channel_key_compromised(ta: &ThresholdAutomaton, sender_channel: &str) -> bool {
    let role = sender_channel_role(sender_channel);
    ta.role_identities
        .get(role)
        .map(|cfg| ta.compromised_keys.contains(&cfg.key_name))
        .unwrap_or(false)
}

fn message_variant_and_family_from_counter_name(name: &str) -> Option<(String, String)> {
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

fn collect_message_variant_groups(ta: &ThresholdAutomaton) -> MessageVariantGroups {
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

fn collect_exclusive_crypto_variant_groups(
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
        let Some(spec) = ta.crypto_objects.get(&family) else {
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

fn message_effective_signed_auth(ta: &ThresholdAutomaton, family: &str) -> bool {
    match ta
        .message_policies
        .get(family)
        .map(|p| p.auth)
        .unwrap_or(MessageAuthPolicy::Inherit)
    {
        MessageAuthPolicy::Authenticated => true,
        MessageAuthPolicy::Unauthenticated => false,
        MessageAuthPolicy::Inherit => ta.authentication_mode == AuthenticationMode::Signed,
    }
}

fn message_effective_non_equivocating(ta: &ThresholdAutomaton, family: &str) -> bool {
    match ta
        .message_policies
        .get(family)
        .map(|p| p.equivocation)
        .unwrap_or(MessageEquivocationPolicy::Inherit)
    {
        MessageEquivocationPolicy::None => true,
        MessageEquivocationPolicy::Full => false,
        MessageEquivocationPolicy::Inherit => ta.equivocation_mode == EquivocationMode::None,
    }
}

fn collect_message_counter_recipient_groups(
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

fn collect_message_counter_flags(ta: &ThresholdAutomaton) -> Vec<bool> {
    ta.shared_vars
        .iter()
        .map(|shared| shared.kind == SharedVarKind::MessageCounter)
        .collect()
}

/// Build a balanced arithmetic sum tree to avoid very deep left-associated terms.
fn sum_terms_balanced(mut terms: Vec<SmtTerm>) -> SmtTerm {
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
fn encode_lc(lc: &LinearCombination) -> SmtTerm {
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

fn encode_threshold_guard_at_step(
    step: usize,
    vars: &[usize],
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

/// Encode the full BMC problem up to a given depth.
pub fn encode_bmc(cs: &CounterSystem, property: &SafetyProperty, max_depth: usize) -> BmcEncoding {
    let ta = &cs.automaton;
    let mut enc = BmcEncoding::new();
    let num_locs = cs.num_locations();
    let num_svars = cs.num_shared_vars();
    let num_rules = cs.num_rules();
    let por_pruning = compute_por_rule_pruning(ta);
    let _por_pruned_rules_total = por_pruning
        .stutter_pruned
        .saturating_add(por_pruning.commutative_duplicate_pruned)
        .saturating_add(por_pruning.guard_dominated_pruned);
    let active_rule_ids = por_pruning.active_rule_ids();
    let num_params = cs.num_parameters();
    let distinct_vars: Vec<(usize, Option<String>)> = ta
        .shared_vars
        .iter()
        .enumerate()
        .filter(|(_, v)| v.distinct)
        .map(|(i, v)| (i, v.distinct_role.clone()))
        .collect();
    let omission_style_faults = ta.fault_model == FaultModel::Omission;
    let crash_faults = ta.fault_model == FaultModel::Crash;
    let byzantine_faults = ta.fault_model == FaultModel::Byzantine;
    let selective_network = matches!(
        ta.network_semantics,
        NetworkSemantics::IdentitySelective
            | NetworkSemantics::CohortSelective
            | NetworkSemantics::ProcessSelective
    );
    let lossy_delivery = omission_style_faults || (byzantine_faults && selective_network);
    let crash_counter_var = if crash_faults {
        ta.find_shared_var_by_name("__crashed_count")
    } else {
        None
    };
    let n_param = if num_params > 0 {
        ta.find_param_by_name("n")
    } else {
        None
    };
    let mut role_pop_params: HashMap<String, usize> = HashMap::new();
    if num_params > 0 {
        for loc in &ta.locations {
            let role_name = loc.role.clone();
            if role_pop_params.contains_key(&role_name) {
                continue;
            }
            let candidate = format!("n_{}", role_name.to_lowercase());
            if let Some(pid) = ta.find_param_by_name(&candidate) {
                role_pop_params.insert(role_name, pid);
            }
        }
    }

    let mut role_loc_ids: HashMap<String, Vec<usize>> = HashMap::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        role_loc_ids.entry(loc.role.clone()).or_default().push(id);
    }
    let process_scoped_network = ta.network_semantics == NetworkSemantics::ProcessSelective;
    let process_id_buckets = process_scoped_network.then(|| process_identity_buckets(ta));
    let missing_process_ids = process_scoped_network
        && ta
            .locations
            .iter()
            .any(|loc| !location_has_valid_process_identity(ta, loc));
    let mut message_family_recipients: HashMap<(String, Option<String>), Vec<usize>> =
        HashMap::new();
    let mut signed_senderless_vars: HashMap<String, Vec<usize>> = HashMap::new();
    let mut signed_uncompromised_sender_vars: HashMap<String, Vec<usize>> = HashMap::new();
    let mut family_sender_variant_vars: HashMap<(String, String, String), Vec<usize>> =
        HashMap::new();
    let mut family_sender_variants: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut crypto_object_counter_vars: Vec<usize> = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        if let Some((family, recipient)) =
            message_family_and_recipient_from_counter_name(&shared.name)
        {
            if ta.crypto_objects.contains_key(&family) {
                crypto_object_counter_vars.push(var_id);
            }
            message_family_recipients
                .entry((family, recipient))
                .or_default()
                .push(var_id);
        }
        if let Some((family, sender)) = message_family_and_sender_from_counter_name(&shared.name) {
            if let Some(sender_channel) = sender.clone() {
                if let Some((variant, _)) =
                    message_variant_and_family_from_counter_name(&shared.name)
                {
                    family_sender_variant_vars
                        .entry((family.clone(), sender_channel.clone(), variant.clone()))
                        .or_default()
                        .push(var_id);
                    family_sender_variants
                        .entry((family.clone(), sender_channel.clone()))
                        .or_default()
                        .insert(variant);
                }
                if message_effective_signed_auth(ta, &family)
                    && !sender_channel_key_compromised(ta, &sender_channel)
                {
                    signed_uncompromised_sender_vars
                        .entry(sender_channel)
                        .or_default()
                        .push(var_id);
                }
            } else if message_effective_signed_auth(ta, &family) {
                signed_senderless_vars
                    .entry(family)
                    .or_default()
                    .push(var_id);
            }
        }
    }
    let mut family_sender_variants_vec: HashMap<(String, String), Vec<String>> = HashMap::new();
    for (key, variants) in family_sender_variants {
        let mut variants_vec: Vec<String> = variants.into_iter().collect();
        variants_vec.sort();
        family_sender_variants_vec.insert(key, variants_vec);
    }
    let mut signed_sender_channels: Vec<String> =
        signed_uncompromised_sender_vars.keys().cloned().collect();
    signed_sender_channels.sort();
    let exclusive_crypto_variant_groups = collect_exclusive_crypto_variant_groups(ta);
    let (message_variant_groups, _message_variant_group_families, message_family_variants) =
        collect_message_variant_groups(ta);
    let (recipient_groups, all_message_counter_vars) = collect_message_counter_recipient_groups(ta);
    let message_counter_flags = collect_message_counter_flags(ta);
    let signed_sender_channel_idx: HashMap<String, usize> = signed_sender_channels
        .iter()
        .enumerate()
        .map(|(idx, channel)| (channel.clone(), idx))
        .collect();
    let mut signed_uncompromised_sender_idx_by_var: Vec<Option<usize>> = vec![None; num_svars];
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, sender_opt)) = message_family_and_sender_from_counter_name(&shared.name)
        else {
            continue;
        };
        let Some(sender_channel) = sender_opt else {
            continue;
        };
        if !message_effective_signed_auth(ta, &family)
            || sender_channel_key_compromised(ta, &sender_channel)
        {
            continue;
        }
        if let Some(idx) = signed_sender_channel_idx.get(&sender_channel).copied() {
            signed_uncompromised_sender_idx_by_var[var_id] = Some(idx);
        }
    }

    // 1. Declare parameter variables
    for i in 0..num_params {
        enc.declare(param_var(i), SmtSort::Int);
        // Parameters are non-negative
        enc.assert_term(SmtTerm::var(param_var(i)).ge(SmtTerm::int(0)));
    }

    // 2. Encode resilience condition
    if let Some(ref rc) = ta.resilience_condition {
        let lhs = encode_lc(&rc.lhs);
        let rhs = encode_lc(&rc.rhs);
        let constraint = match rc.op {
            CmpOp::Gt => lhs.gt(rhs),
            CmpOp::Ge => lhs.ge(rhs),
            CmpOp::Lt => lhs.lt(rhs),
            CmpOp::Le => lhs.le(rhs),
            CmpOp::Eq => lhs.eq(rhs),
            CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
        };
        enc.assert_term(constraint);
    }

    // 3. Declare step 0 variables (initial configuration)
    for l in 0..num_locs {
        enc.declare(kappa_var(0, l), SmtSort::Int);
    }
    for v in 0..num_svars {
        enc.declare(gamma_var(0, v), SmtSort::Int);
        if message_counter_flags.get(v).copied().unwrap_or(false) {
            let pending = net_pending_var(0, v);
            enc.declare(pending.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(pending).eq(SmtTerm::int(0)));
        }
    }
    enc.declare(time_var(0), SmtSort::Int);
    for (v, role) in &distinct_vars {
        if let Some(role) = role {
            if let Some(&pid) = role_pop_params.get(role) {
                enc.assert_term(SmtTerm::var(gamma_var(0, *v)).le(SmtTerm::var(param_var(pid))));
                continue;
            }
        }
        if let Some(n_param) = n_param {
            enc.assert_term(SmtTerm::var(gamma_var(0, *v)).le(SmtTerm::var(param_var(n_param))));
        } else {
            // Distinct sender counting requires a population bound.
            enc.assert_term(SmtTerm::bool(false));
        }
    }

    // 4. Initial configuration constraints
    // All processes start in initial locations
    // Sum of all kappa_0_l = n (the process count parameter)
    {
        let mut sum_parts = Vec::new();
        for l in 0..num_locs {
            let kv = SmtTerm::var(kappa_var(0, l));
            // Non-negativity
            enc.assert_term(kv.clone().ge(SmtTerm::int(0)));

            if ta.initial_locations.contains(&l) {
                sum_parts.push(kv);
            } else {
                // Non-initial locations start empty
                enc.assert_term(SmtTerm::var(kappa_var(0, l)).eq(SmtTerm::int(0)));
            }
        }

        // Total processes = n.
        if num_params > 0 && !sum_parts.is_empty() {
            if let Some(n_param) = n_param {
                let total = sum_terms_balanced(sum_parts);
                enc.assert_term(total.eq(SmtTerm::var(param_var(n_param))));
            } else {
                // Counter-system semantics require an explicit `n` parameter.
                enc.assert_term(SmtTerm::bool(false));
            }
        }
    }

    // Shared vars start at 0
    for v in 0..num_svars {
        enc.assert_term(SmtTerm::var(gamma_var(0, v)).eq(SmtTerm::int(0)));
    }
    enc.assert_term(SmtTerm::var(time_var(0)).eq(SmtTerm::int(0)));
    if missing_process_ids {
        enc.assert_term(SmtTerm::bool(false));
    }
    if let Some(buckets) = &process_id_buckets {
        assert_process_identity_uniqueness(&mut enc, 0, buckets);
    }
    if byzantine_faults {
        for (sender_idx, _) in signed_sender_channels.iter().enumerate() {
            let static_name = byz_sender_static_var(sender_idx);
            enc.declare(static_name.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(static_name.clone()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(static_name).le(SmtTerm::int(1)));
        }
    }

    // 5. Encode transitions for each step k = 0..max_depth-1
    // At each step, the adversary (up to t faulty processes) can inject
    // messages of any type. We model this with adversary injection variables.
    for k in 0..max_depth {
        // Declare step k+1 vars and delta vars for step k
        for l in 0..num_locs {
            enc.declare(kappa_var(k + 1, l), SmtSort::Int);
        }
        for v in 0..num_svars {
            enc.declare(gamma_var(k + 1, v), SmtSort::Int);
            if message_counter_flags.get(v).copied().unwrap_or(false) {
                let pending = net_pending_var(k + 1, v);
                enc.declare(pending.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(pending).ge(SmtTerm::int(0)));
            }
        }
        enc.declare(time_var(k + 1), SmtSort::Int);
        for (v, role) in &distinct_vars {
            if let Some(role) = role {
                if let Some(&pid) = role_pop_params.get(role) {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(k + 1, *v)).le(SmtTerm::var(param_var(pid))),
                    );
                    continue;
                }
            }
            if let Some(n_param) = n_param {
                enc.assert_term(
                    SmtTerm::var(gamma_var(k + 1, *v)).le(SmtTerm::var(param_var(n_param))),
                );
            } else {
                // Distinct sender counting requires a population bound.
                enc.assert_term(SmtTerm::bool(false));
            }
        }
        for r in 0..num_rules {
            enc.declare(delta_var(k, r), SmtSort::Int);
            let delta = SmtTerm::var(delta_var(k, r));
            enc.assert_term(delta.clone().ge(SmtTerm::int(0)));
            if por_pruning.is_disabled(r) {
                enc.assert_term(delta.eq(SmtTerm::int(0)));
            }
        }
        if let Some(buckets) = &process_id_buckets {
            assert_process_identity_uniqueness(&mut enc, k + 1, buckets);
        }

        // Adversary injection variables: adv_k_v = messages injected by
        // Byzantine processes for shared variable v at step k.
        // Non-negative only; upper bounds are added after the loop.
        for v in 0..num_svars {
            let adv_name = format!("adv_{k}_{v}");
            enc.declare(adv_name.clone(), SmtSort::Int);
            // Non-negative
            enc.assert_term(SmtTerm::var(adv_name.clone()).ge(SmtTerm::int(0)));
            if message_counter_flags.get(v).copied().unwrap_or(false) {
                let send_name = net_send_var(k, v);
                let forge_name = net_forge_var(k, v);
                let deliver_name = net_deliver_var(k, v);
                let net_drop_name = net_drop_var(k, v);
                enc.declare(send_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(send_name).ge(SmtTerm::int(0)));
                enc.declare(forge_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(forge_name).ge(SmtTerm::int(0)));
                enc.declare(deliver_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(deliver_name).ge(SmtTerm::int(0)));
                enc.declare(net_drop_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(net_drop_name).ge(SmtTerm::int(0)));
            }
            if lossy_delivery {
                let drop_name = drop_var(k, v);
                enc.declare(drop_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(drop_name).ge(SmtTerm::int(0)));
            }
        }
        if byzantine_faults {
            for (sender_idx, _) in signed_sender_channels.iter().enumerate() {
                let name = byz_sender_var(k, sender_idx);
                enc.declare(name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(name.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(name).le(SmtTerm::int(1)));
                enc.assert_term(
                    SmtTerm::var(byz_sender_var(k, sender_idx))
                        .le(SmtTerm::var(byz_sender_static_var(sender_idx))),
                );
            }
        }
        if byzantine_faults && selective_network {
            for (group_id, group_vars) in message_variant_groups.iter().enumerate() {
                let send_name = adv_send_var(k, group_id);
                enc.declare(send_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(send_name.clone()).ge(SmtTerm::int(0)));
                for &var_id in group_vars {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{k}_{var_id}"))
                            .le(SmtTerm::var(send_name.clone())),
                    );
                }
            }
        }
        if selective_network && ta.delivery_control == DeliveryControlMode::Global {
            for group_vars in &message_variant_groups {
                if group_vars.len() <= 1 {
                    continue;
                }
                let first = group_vars[0];
                for &other in &group_vars[1..] {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{k}_{other}"))
                            .eq(SmtTerm::var(format!("adv_{k}_{first}"))),
                    );
                    if lossy_delivery {
                        enc.assert_term(
                            SmtTerm::var(drop_var(k, other)).eq(SmtTerm::var(drop_var(k, first))),
                        );
                    }
                }
            }
        }

        // Location counter updates:
        // kappa_{k+1}_l = kappa_k_l - sum(delta_k_r for rules leaving l)
        //                            + sum(delta_k_r for rules entering l)
        for l in 0..num_locs {
            let mut outgoing = Vec::new();
            let mut incoming = Vec::new();
            for &r in &active_rule_ids {
                let rule = &ta.rules[r];
                if rule.from == l {
                    outgoing.push(SmtTerm::var(delta_var(k, r)));
                }
                if rule.to == l {
                    incoming.push(SmtTerm::var(delta_var(k, r)));
                }
            }
            let mut expr = SmtTerm::var(kappa_var(k, l));
            if !incoming.is_empty() {
                expr = expr.add(sum_terms_balanced(incoming));
            }
            if !outgoing.is_empty() {
                expr = expr.sub(sum_terms_balanced(outgoing));
            }

            enc.assert_term(SmtTerm::var(kappa_var(k + 1, l)).eq(expr));

            // Non-negativity of resulting counters
            enc.assert_term(SmtTerm::var(kappa_var(k + 1, l)).ge(SmtTerm::int(0)));
        }

        // Guard enablement: delta_k_r > 0 → guard is satisfied
        for &r in &active_rule_ids {
            let rule = &ta.rules[r];
            let dr_pos = SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0));

            for atom in &rule.guard.atoms {
                let guard_term = match atom {
                    GuardAtom::Threshold {
                        vars,
                        op,
                        bound,
                        distinct,
                    } => encode_threshold_guard_at_step(k, vars, *op, bound, *distinct),
                };
                enc.assert_term(dr_pos.clone().implies(guard_term));
            }

            // delta_k_r <= kappa_k_{from_loc} (can't fire more than available processes)
            enc.assert_term(
                SmtTerm::var(delta_var(k, r)).le(SmtTerm::var(kappa_var(k, rule.from))),
            );
        }

        // Sum-of-outgoing delta constraint: for each location, the total number
        // of processes leaving cannot exceed the number present.
        // sum(delta_k_r for rules from l) <= kappa_k_l
        for l in 0..num_locs {
            let outgoing: Vec<SmtTerm> = active_rule_ids
                .iter()
                .copied()
                .filter(|r| ta.rules[*r].from == l)
                .map(|r| SmtTerm::var(delta_var(k, r)))
                .collect();
            if outgoing.len() > 1 {
                let sum = sum_terms_balanced(outgoing);
                enc.assert_term(sum.le(SmtTerm::var(kappa_var(k, l))));
            }
            // If only 0 or 1 outgoing rules, the individual constraint suffices.
        }

        // Logical time progression.
        enc.assert_term(
            SmtTerm::var(time_var(k + 1)).eq(SmtTerm::var(time_var(k)).add(SmtTerm::int(1))),
        );

        // Shared variable updates (including adversary injection and omission drops)
        for v in 0..num_svars {
            let is_message_counter = message_counter_flags.get(v).copied().unwrap_or(false);
            let adv_term = SmtTerm::var(format!("adv_{k}_{v}"));
            let drop_term = lossy_delivery.then(|| SmtTerm::var(drop_var(k, v)));
            let net_deliver_term = is_message_counter.then(|| SmtTerm::var(net_deliver_var(k, v)));
            let mut sent_parts = Vec::new();

            for &r in &active_rule_ids {
                let rule = &ta.rules[r];
                for upd in &rule.updates {
                    if upd.var == v {
                        match &upd.kind {
                            UpdateKind::Increment => {
                                sent_parts.push(SmtTerm::var(delta_var(k, r)));
                            }
                            UpdateKind::Set(lc) => {
                                // For set updates, if delta > 0 we set the value
                                let dr_pos = SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0));
                                let set_val = encode_lc(lc);
                                enc.assert_term(
                                    dr_pos.implies(SmtTerm::var(gamma_var(k + 1, v)).eq(set_val)),
                                );
                            }
                        }
                    }
                }
            }
            let sent_expr = sum_terms_balanced(sent_parts);
            if is_message_counter {
                let net_send = SmtTerm::var(net_send_var(k, v));
                let net_forge = SmtTerm::var(net_forge_var(k, v));
                let net_deliver = SmtTerm::var(net_deliver_var(k, v));
                let net_drop = SmtTerm::var(net_drop_var(k, v));
                let net_pending_k = SmtTerm::var(net_pending_var(k, v));
                let net_pending_next = SmtTerm::var(net_pending_var(k + 1, v));
                enc.assert_term(net_send.clone().eq(sent_expr.clone()));
                enc.assert_term(net_forge.clone().eq(adv_term.clone()));
                if let Some(drop_term) = drop_term.clone() {
                    enc.assert_term(net_drop.clone().eq(drop_term));
                } else {
                    enc.assert_term(net_drop.clone().eq(SmtTerm::int(0)));
                }
                let available = net_pending_k.add(net_send).add(net_forge);
                enc.assert_term(
                    net_deliver
                        .clone()
                        .add(net_drop.clone())
                        .le(available.clone()),
                );
                enc.assert_term(
                    net_pending_next.eq(available
                        .clone()
                        .sub(net_deliver.clone())
                        .sub(net_drop.clone())),
                );
                if ta.timing_model == TimingModel::PartialSynchrony && selective_network {
                    if let Some(gst_pid) = ta.gst_param {
                        let post_gst =
                            SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(k)));
                        if byzantine_faults {
                            if let Some(sender_idx) = signed_uncompromised_sender_idx_by_var
                                .get(v)
                                .copied()
                                .flatten()
                            {
                                let honest_sender =
                                    SmtTerm::var(byz_sender_var(k, sender_idx)).eq(SmtTerm::int(0));
                                enc.assert_term(
                                    SmtTerm::and(vec![post_gst.clone(), honest_sender])
                                        .implies(net_deliver.clone().eq(available.clone())),
                                );
                            }
                        } else {
                            enc.assert_term(
                                post_gst.implies(net_deliver.clone().eq(available.clone())),
                            );
                        }
                    }
                }
                if ta.timing_model == TimingModel::PartialSynchrony
                    && lossy_delivery
                    && ta.gst_param.is_some()
                {
                    if let Some(gst_pid) = ta.gst_param {
                        let post_gst =
                            SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(k)));
                        enc.assert_term(post_gst.implies(net_drop.eq(SmtTerm::int(0))));
                    }
                }
            }

            // Only assert direct equality for increment-only variables
            let has_set_update = ta.rules.iter().any(|rule| {
                rule.updates
                    .iter()
                    .any(|u| u.var == v && matches!(u.kind, UpdateKind::Set(_)))
            });
            if !has_set_update {
                let expr = if let Some(net_deliver) = net_deliver_term.clone() {
                    SmtTerm::var(gamma_var(k, v)).add(net_deliver)
                } else {
                    let mut expr = SmtTerm::var(gamma_var(k, v))
                        .add(sent_expr.clone())
                        .add(adv_term.clone());
                    if let Some(drop_term) = drop_term.clone() {
                        expr = expr.sub(drop_term);
                    }
                    expr
                };
                let mut next_expr: Option<SmtTerm> = Some(expr);
                let mut is_distinct = false;
                for (var_id, role) in &distinct_vars {
                    if *var_id != v {
                        continue;
                    }
                    is_distinct = true;
                    if let Some(role) = role {
                        if !role_loc_ids.contains_key(role) {
                            // Distinct-role references must point to an existing role.
                            enc.assert_term(SmtTerm::bool(false));
                            next_expr = None;
                            continue;
                        }
                        let mut recv_sum = Vec::new();
                        for &r in &active_rule_ids {
                            let rule = &ta.rules[r];
                            if rule.updates.iter().any(|u| u.var == v) {
                                let from_role = &ta.locations[rule.from].role;
                                if from_role == role {
                                    recv_sum.push(SmtTerm::var(delta_var(k, r)));
                                }
                            }
                        }
                        let total_recv = if recv_sum.is_empty() {
                            SmtTerm::int(0)
                        } else {
                            sum_terms_balanced(recv_sum)
                        };
                        let gamma_k = SmtTerm::var(gamma_var(k, v));
                        // exact distinct update with sender uniqueness:
                        // gamma_{k+1} = gamma_k + honest_new + adversary_new - dropped
                        let sum_term = if let Some(net_deliver) = net_deliver_term.clone() {
                            gamma_k.clone().add(net_deliver)
                        } else {
                            let mut sum_term =
                                gamma_k.clone().add(total_recv).add(adv_term.clone());
                            if let Some(drop_term) = drop_term.clone() {
                                sum_term = sum_term.sub(drop_term);
                            }
                            sum_term
                        };
                        let gamma_next = SmtTerm::var(gamma_var(k + 1, v));
                        enc.assert_term(gamma_next.clone().ge(sum_term.clone()));
                        enc.assert_term(gamma_next.clone().le(sum_term.clone()));
                        if let Some(&pid) = role_pop_params.get(role) {
                            let pop = SmtTerm::var(param_var(pid));
                            enc.assert_term(gamma_next.le(pop));
                        } else if let Some(n_param) = n_param {
                            let pop = SmtTerm::var(param_var(n_param));
                            enc.assert_term(gamma_next.le(pop));
                        }
                        // distinct counters should not be updated by the generic sum
                        next_expr = None;
                    }
                }
                if is_distinct {
                    // If no distinct-specific constraint applied (e.g., missing role), fall back to generic sum.
                    if let Some(expr) = next_expr {
                        enc.assert_term(SmtTerm::var(gamma_var(k + 1, v)).eq(expr));
                    }
                } else if let Some(expr) = next_expr {
                    enc.assert_term(SmtTerm::var(gamma_var(k + 1, v)).eq(expr));
                }

                if !is_message_counter {
                    if let Some(drop_term) = drop_term {
                        // Omission/crash can only drop messages that are in-flight at this step.
                        enc.assert_term(drop_term.clone().le(sent_expr.add(adv_term)));
                        if ta.timing_model == TimingModel::PartialSynchrony {
                            if let Some(gst_pid) = ta.gst_param {
                                let post_gst =
                                    SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(k)));
                                enc.assert_term(post_gst.implies(drop_term.eq(SmtTerm::int(0))));
                            }
                        }
                    }
                }
            }
        }
    }

    // Crypto objects are formed by protocol transitions from source-message witnesses.
    // They are not adversarially forgeable as standalone traffic families.
    for k in 0..max_depth {
        for v in &crypto_object_counter_vars {
            enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
        }
    }

    // Exclusive crypto-object admissibility:
    // once a variant is present for (object, recipient), conflicting variants must be absent.
    for k in 0..max_depth {
        for variant_groups in exclusive_crypto_variant_groups.values() {
            if variant_groups.len() <= 1 {
                continue;
            }
            let sums: Vec<SmtTerm> = variant_groups
                .iter()
                .map(|vars| {
                    sum_terms_balanced(
                        vars.iter()
                            .map(|v| SmtTerm::var(gamma_var(k + 1, *v)))
                            .collect(),
                    )
                })
                .collect();
            for (i, sum_i) in sums.iter().enumerate() {
                for (j, sum_j) in sums.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    enc.assert_term(
                        sum_i
                            .clone()
                            .gt(SmtTerm::int(0))
                            .implies(sum_j.clone().eq(SmtTerm::int(0))),
                    );
                }
            }
        }
    }

    // 5b. Fault bounds:
    // - Byzantine: per-step, per-message-type adversary injection bound.
    // - Omission: no forged injections, bounded per-step drop budget.
    // - Crash: no forged injections; bounded cumulative crashed-process counter.
    if let Some(adv_param) = ta.adversary_bound_param {
        // Constrain the adversary bound: 0 <= f
        enc.assert_term(SmtTerm::var(param_var(adv_param)).ge(SmtTerm::int(0)));
        // f <= t (adversary bound <= fault tolerance, look up "t" by name)
        if let Some(t_param) = ta.find_param_by_name("t") {
            if adv_param != t_param {
                enc.assert_term(
                    SmtTerm::var(param_var(adv_param)).le(SmtTerm::var(param_var(t_param))),
                );
            }
        }
        if byzantine_faults && !signed_sender_channels.is_empty() {
            let static_terms = signed_sender_channels
                .iter()
                .enumerate()
                .map(|(idx, _)| SmtTerm::var(byz_sender_static_var(idx)))
                .collect::<Vec<_>>();
            enc.assert_term(
                sum_terms_balanced(static_terms).le(SmtTerm::var(param_var(adv_param))),
            );
        }

        for k in 0..max_depth {
            for v in 0..num_svars {
                if byzantine_faults {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{k}_{v}")).le(SmtTerm::var(param_var(adv_param))),
                    );
                } else if omission_style_faults {
                    enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
                    enc.assert_term(
                        SmtTerm::var(drop_var(k, v)).le(SmtTerm::var(param_var(adv_param))),
                    );
                } else {
                    enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
                }
            }
            match ta.fault_budget_scope {
                FaultBudgetScope::LegacyCounter => {}
                FaultBudgetScope::PerRecipient => {
                    if byzantine_faults {
                        for vars in recipient_groups.values() {
                            if vars.is_empty() {
                                continue;
                            }
                            let sum = vars
                                .iter()
                                .map(|v| SmtTerm::var(format!("adv_{k}_{v}")))
                                .collect::<Vec<_>>();
                            enc.assert_term(
                                sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                            );
                        }
                    }
                    if lossy_delivery {
                        for vars in recipient_groups.values() {
                            if vars.is_empty() {
                                continue;
                            }
                            let sum = vars
                                .iter()
                                .map(|v| SmtTerm::var(drop_var(k, *v)))
                                .collect::<Vec<_>>();
                            enc.assert_term(
                                sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                            );
                        }
                    }
                }
                FaultBudgetScope::Global => {
                    if byzantine_faults && !all_message_counter_vars.is_empty() {
                        let sum = all_message_counter_vars
                            .iter()
                            .map(|v| SmtTerm::var(format!("adv_{k}_{v}")))
                            .collect::<Vec<_>>();
                        enc.assert_term(
                            sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                    if lossy_delivery && !all_message_counter_vars.is_empty() {
                        let sum = all_message_counter_vars
                            .iter()
                            .map(|v| SmtTerm::var(drop_var(k, *v)))
                            .collect::<Vec<_>>();
                        enc.assert_term(
                            sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                }
            }
            if lossy_delivery && selective_network {
                for ((_family, recipient), vars) in &message_family_recipients {
                    if recipient.is_none() || vars.is_empty() {
                        continue;
                    }
                    let sum = vars
                        .iter()
                        .map(|v| SmtTerm::var(drop_var(k, *v)))
                        .collect::<Vec<_>>();
                    enc.assert_term(sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))));
                }
            }
            if byzantine_faults && selective_network {
                for group_id in 0..message_variant_groups.len() {
                    enc.assert_term(
                        SmtTerm::var(adv_send_var(k, group_id))
                            .le(SmtTerm::var(param_var(adv_param))),
                    );
                }
            }
            if crash_faults {
                for v in &all_message_counter_vars {
                    enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                    enc.assert_term(SmtTerm::var(net_drop_var(k, *v)).eq(SmtTerm::int(0)));
                }
                if let Some(crash_var) = crash_counter_var {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(k + 1, crash_var))
                            .le(SmtTerm::var(param_var(adv_param))),
                    );
                } else {
                    // Crash mode requires internal crash-counter instrumentation.
                    enc.assert_term(SmtTerm::bool(false));
                }
            }
        }

        if byzantine_faults {
            // Signed-channel origin/auth constraints:
            // - senderless signed counters cannot be adversarially injected
            // - uncompromised sender channels require activating a Byzantine sender identity
            // - total active Byzantine sender identities per step is bounded by f
            for k in 0..max_depth {
                for vars in signed_senderless_vars.values() {
                    for v in vars {
                        enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                    }
                }
                let mut byz_sender_terms = Vec::new();
                for (sender_idx, sender_channel) in signed_sender_channels.iter().enumerate() {
                    let byz_sender = SmtTerm::var(byz_sender_var(k, sender_idx));
                    byz_sender_terms.push(byz_sender.clone());
                    if let Some(vars) = signed_uncompromised_sender_vars.get(sender_channel) {
                        for v in vars {
                            enc.assert_term(
                                byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                    SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)),
                                ),
                            );
                            enc.assert_term(
                                byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                    SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)),
                                ),
                            );
                        }
                    }
                }
                if !byz_sender_terms.is_empty() {
                    let active = sum_terms_balanced(byz_sender_terms);
                    enc.assert_term(active.le(SmtTerm::var(param_var(adv_param))));
                }
            }

            // Sender-scoped equivocation semantics in selective networks:
            // - full equivocation: sender may split deliveries across variants;
            // - none: sender must pick at most one payload variant per family per step.
            if selective_network {
                for k in 0..max_depth {
                    for ((family, sender), variants) in &family_sender_variants_vec {
                        if variants.len() <= 1 || !message_effective_non_equivocating(ta, family) {
                            continue;
                        }
                        for i in 0..variants.len() {
                            let vars_i = family_sender_variant_vars
                                .get(&(family.clone(), sender.clone(), variants[i].clone()))
                                .cloned()
                                .unwrap_or_default();
                            if vars_i.is_empty() {
                                continue;
                            }
                            let sum_i = sum_terms_balanced(
                                vars_i
                                    .iter()
                                    .map(|v| SmtTerm::var(net_forge_var(k, *v)))
                                    .collect::<Vec<_>>(),
                            );
                            for (j, variant_j) in variants.iter().enumerate() {
                                if i == j {
                                    continue;
                                }
                                let vars_j = family_sender_variant_vars
                                    .get(&(family.clone(), sender.clone(), variant_j.clone()))
                                    .cloned()
                                    .unwrap_or_default();
                                if vars_j.is_empty() {
                                    continue;
                                }
                                let sum_j = sum_terms_balanced(
                                    vars_j
                                        .iter()
                                        .map(|v| SmtTerm::var(net_forge_var(k, *v)))
                                        .collect::<Vec<_>>(),
                                );
                                enc.assert_term(
                                    sum_i
                                        .clone()
                                        .gt(SmtTerm::int(0))
                                        .implies(sum_j.eq(SmtTerm::int(0))),
                                );
                            }
                        }
                    }
                }
            }

            // For distinct-sender counters, adversarial contribution must also be
            // distinct across time: total Byzantine "new senders" per counter <= f.
            for (v, _) in &distinct_vars {
                let mut parts = Vec::new();
                for k in 0..max_depth {
                    parts.push(SmtTerm::var(format!("adv_{k}_{v}")));
                }
                if !parts.is_empty() {
                    let total = sum_terms_balanced(parts);
                    enc.assert_term(total.le(SmtTerm::var(param_var(adv_param))));
                }
            }
            // Identity-aware cap: if a message family is authenticated or configured
            // as non-equivocating, each Byzantine identity contributes at most one
            // accepted send per (message family, recipient) per step.
            for k in 0..max_depth {
                for ((family, _recipient), vars) in &message_family_recipients {
                    if vars.is_empty() {
                        continue;
                    }
                    let identity_capped = message_effective_signed_auth(ta, family)
                        || message_effective_non_equivocating(ta, family);
                    if !identity_capped {
                        continue;
                    }
                    let sum = vars
                        .iter()
                        .map(|v| SmtTerm::var(format!("adv_{k}_{v}")))
                        .collect::<Vec<_>>();
                    let sum = sum_terms_balanced(sum);
                    enc.assert_term(sum.le(SmtTerm::var(param_var(adv_param))));
                }
            }
            if selective_network {
                // In non-equivocating families, variant choices are identity-scoped:
                // each Byzantine identity can choose at most one variant per family.
                for k in 0..max_depth {
                    for (family, group_ids) in &message_family_variants {
                        if group_ids.is_empty() || !message_effective_non_equivocating(ta, family) {
                            continue;
                        }
                        let sum = group_ids
                            .iter()
                            .map(|gid| SmtTerm::var(adv_send_var(k, *gid)))
                            .collect::<Vec<_>>();
                        let sum = sum_terms_balanced(sum);
                        enc.assert_term(sum.le(SmtTerm::var(param_var(adv_param))));
                    }
                }
            }
        }
    } else if omission_style_faults || crash_faults {
        // Omission/crash without explicit bound defaults to no faults.
        for k in 0..max_depth {
            for v in 0..num_svars {
                enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
                if omission_style_faults {
                    enc.assert_term(SmtTerm::var(drop_var(k, v)).eq(SmtTerm::int(0)));
                }
            }
            if crash_faults {
                for v in &all_message_counter_vars {
                    enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                    enc.assert_term(SmtTerm::var(net_drop_var(k, *v)).eq(SmtTerm::int(0)));
                }
                if let Some(crash_var) = crash_counter_var {
                    enc.assert_term(SmtTerm::var(gamma_var(k + 1, crash_var)).eq(SmtTerm::int(0)));
                } else {
                    enc.assert_term(SmtTerm::bool(false));
                }
            }
        }
    }

    // 6. Encode safety property violation (we check if it can be violated)
    let violation = encode_property_violation(ta, property, max_depth);
    enc.assert_term(violation);

    enc
}

/// Encode the inductive-step query for k-induction.
///
/// The query is SAT iff there exists a k-step execution fragment such that:
/// - property holds on steps 0..k-1
/// - transition relation holds on each step i -> i+1
/// - property is violated at step k
///
/// Note: unlike `encode_bmc`, this encoding does not constrain step 0 to be
/// an initial state; this is the standard induction step over arbitrary states.
pub fn encode_k_induction_step(
    cs: &CounterSystem,
    property: &SafetyProperty,
    k: usize,
) -> BmcEncoding {
    let ta = &cs.automaton;
    let mut enc = BmcEncoding::new();
    let num_locs = cs.num_locations();
    let num_svars = cs.num_shared_vars();
    let num_rules = cs.num_rules();
    let por_pruning = compute_por_rule_pruning(ta);
    let _por_pruned_rules_total = por_pruning
        .stutter_pruned
        .saturating_add(por_pruning.commutative_duplicate_pruned)
        .saturating_add(por_pruning.guard_dominated_pruned);
    let active_rule_ids = por_pruning.active_rule_ids();
    let num_params = cs.num_parameters();
    let distinct_vars: Vec<(usize, Option<String>)> = ta
        .shared_vars
        .iter()
        .enumerate()
        .filter(|(_, v)| v.distinct)
        .map(|(i, v)| (i, v.distinct_role.clone()))
        .collect();
    let omission_style_faults = ta.fault_model == FaultModel::Omission;
    let crash_faults = ta.fault_model == FaultModel::Crash;
    let byzantine_faults = ta.fault_model == FaultModel::Byzantine;
    let selective_network = matches!(
        ta.network_semantics,
        NetworkSemantics::IdentitySelective
            | NetworkSemantics::CohortSelective
            | NetworkSemantics::ProcessSelective
    );
    let lossy_delivery = omission_style_faults || (byzantine_faults && selective_network);
    let crash_counter_var = if crash_faults {
        ta.find_shared_var_by_name("__crashed_count")
    } else {
        None
    };
    let n_param = if num_params > 0 {
        ta.find_param_by_name("n")
    } else {
        None
    };
    let mut role_pop_params: HashMap<String, usize> = HashMap::new();
    if num_params > 0 {
        for loc in &ta.locations {
            let role_name = loc.role.clone();
            if role_pop_params.contains_key(&role_name) {
                continue;
            }
            let candidate = format!("n_{}", role_name.to_lowercase());
            if let Some(pid) = ta.find_param_by_name(&candidate) {
                role_pop_params.insert(role_name, pid);
            }
        }
    }
    let mut role_loc_ids: HashMap<String, Vec<usize>> = HashMap::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        role_loc_ids.entry(loc.role.clone()).or_default().push(id);
    }
    let process_scoped_network = ta.network_semantics == NetworkSemantics::ProcessSelective;
    let process_id_buckets = process_scoped_network.then(|| process_identity_buckets(ta));
    let missing_process_ids = process_scoped_network
        && ta
            .locations
            .iter()
            .any(|loc| !location_has_valid_process_identity(ta, loc));
    let mut message_family_recipients: HashMap<(String, Option<String>), Vec<usize>> =
        HashMap::new();
    let mut signed_senderless_vars: HashMap<String, Vec<usize>> = HashMap::new();
    let mut signed_uncompromised_sender_vars: HashMap<String, Vec<usize>> = HashMap::new();
    let mut family_sender_variant_vars: HashMap<(String, String, String), Vec<usize>> =
        HashMap::new();
    let mut family_sender_variants: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut crypto_object_counter_vars: Vec<usize> = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        if let Some((family, recipient)) =
            message_family_and_recipient_from_counter_name(&shared.name)
        {
            if ta.crypto_objects.contains_key(&family) {
                crypto_object_counter_vars.push(var_id);
            }
            message_family_recipients
                .entry((family, recipient))
                .or_default()
                .push(var_id);
        }
        if let Some((family, sender)) = message_family_and_sender_from_counter_name(&shared.name) {
            if let Some(sender_channel) = sender.clone() {
                if let Some((variant, _)) =
                    message_variant_and_family_from_counter_name(&shared.name)
                {
                    family_sender_variant_vars
                        .entry((family.clone(), sender_channel.clone(), variant.clone()))
                        .or_default()
                        .push(var_id);
                    family_sender_variants
                        .entry((family.clone(), sender_channel.clone()))
                        .or_default()
                        .insert(variant);
                }
                if message_effective_signed_auth(ta, &family)
                    && !sender_channel_key_compromised(ta, &sender_channel)
                {
                    signed_uncompromised_sender_vars
                        .entry(sender_channel)
                        .or_default()
                        .push(var_id);
                }
            } else if message_effective_signed_auth(ta, &family) {
                signed_senderless_vars
                    .entry(family)
                    .or_default()
                    .push(var_id);
            }
        }
    }
    let mut family_sender_variants_vec: HashMap<(String, String), Vec<String>> = HashMap::new();
    for (key, variants) in family_sender_variants {
        let mut variants_vec: Vec<String> = variants.into_iter().collect();
        variants_vec.sort();
        family_sender_variants_vec.insert(key, variants_vec);
    }
    let mut signed_sender_channels: Vec<String> =
        signed_uncompromised_sender_vars.keys().cloned().collect();
    signed_sender_channels.sort();
    let exclusive_crypto_variant_groups = collect_exclusive_crypto_variant_groups(ta);
    let (message_variant_groups, _message_variant_group_families, message_family_variants) =
        collect_message_variant_groups(ta);
    let (recipient_groups, all_message_counter_vars) = collect_message_counter_recipient_groups(ta);
    let message_counter_flags = collect_message_counter_flags(ta);
    let signed_sender_channel_idx: HashMap<String, usize> = signed_sender_channels
        .iter()
        .enumerate()
        .map(|(idx, channel)| (channel.clone(), idx))
        .collect();
    let mut signed_uncompromised_sender_idx_by_var: Vec<Option<usize>> = vec![None; num_svars];
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, sender_opt)) = message_family_and_sender_from_counter_name(&shared.name)
        else {
            continue;
        };
        let Some(sender_channel) = sender_opt else {
            continue;
        };
        if !message_effective_signed_auth(ta, &family)
            || sender_channel_key_compromised(ta, &sender_channel)
        {
            continue;
        }
        if let Some(idx) = signed_sender_channel_idx.get(&sender_channel).copied() {
            signed_uncompromised_sender_idx_by_var[var_id] = Some(idx);
        }
    }
    let role_count = role_loc_ids.len();
    let mut role_population_targets: HashMap<String, usize> = HashMap::new();
    for role in role_loc_ids.keys() {
        let candidate = format!("n_{}", role.to_lowercase());
        if let Some(pid) = ta.find_param_by_name(&candidate) {
            role_population_targets.insert(role.clone(), pid);
        }
    }
    if role_count == 1 {
        if let Some(n_pid) = n_param {
            if let Some(role_name) = role_loc_ids.keys().next() {
                role_population_targets
                    .entry(role_name.clone())
                    .or_insert(n_pid);
            }
        }
    }
    let increment_only_var: Vec<bool> = (0..num_svars)
        .map(|v| {
            !ta.rules.iter().any(|rule| {
                rule.updates
                    .iter()
                    .any(|u| u.var == v && matches!(u.kind, UpdateKind::Set(_)))
            })
        })
        .collect();
    let mut sent_flag_true_locs: HashMap<usize, Vec<usize>> = HashMap::new();
    for (loc_id, loc) in ta.locations.iter().enumerate() {
        for (name, value) in &loc.local_vars {
            if let Some(counter_id) = parse_internal_sent_flag_var(name) {
                if counter_id < num_svars && matches!(value, LocalValue::Bool(true)) {
                    sent_flag_true_locs
                        .entry(counter_id)
                        .or_default()
                        .push(loc_id);
                }
            }
        }
    }

    // Parameters and resilience
    for i in 0..num_params {
        enc.declare(param_var(i), SmtSort::Int);
        enc.assert_term(SmtTerm::var(param_var(i)).ge(SmtTerm::int(0)));
    }
    if let Some(ref rc) = ta.resilience_condition {
        let lhs = encode_lc(&rc.lhs);
        let rhs = encode_lc(&rc.rhs);
        let constraint = match rc.op {
            CmpOp::Gt => lhs.gt(rhs),
            CmpOp::Ge => lhs.ge(rhs),
            CmpOp::Lt => lhs.lt(rhs),
            CmpOp::Le => lhs.le(rhs),
            CmpOp::Eq => lhs.eq(rhs),
            CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
        };
        enc.assert_term(constraint);
    }

    // Declare state variables for steps 0..k
    for step in 0..=k {
        for l in 0..num_locs {
            enc.declare(kappa_var(step, l), SmtSort::Int);
            enc.assert_term(SmtTerm::var(kappa_var(step, l)).ge(SmtTerm::int(0)));
            if let Some(n_pid) = n_param {
                enc.assert_term(
                    SmtTerm::var(kappa_var(step, l)).le(SmtTerm::var(param_var(n_pid))),
                );
            }
        }
        for v in 0..num_svars {
            enc.declare(gamma_var(step, v), SmtSort::Int);
            enc.assert_term(SmtTerm::var(gamma_var(step, v)).ge(SmtTerm::int(0)));
            if message_counter_flags.get(v).copied().unwrap_or(false) {
                let pending = net_pending_var(step, v);
                enc.declare(pending.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(pending).ge(SmtTerm::int(0)));
            }
        }
        enc.declare(time_var(step), SmtSort::Int);
        enc.assert_term(SmtTerm::var(time_var(step)).ge(SmtTerm::int(0)));
        for (v, role) in &distinct_vars {
            if let Some(role) = role {
                if let Some(&pid) = role_pop_params.get(role) {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(step, *v)).le(SmtTerm::var(param_var(pid))),
                    );
                    continue;
                }
            }
            if let Some(n_param) = n_param {
                enc.assert_term(
                    SmtTerm::var(gamma_var(step, *v)).le(SmtTerm::var(param_var(n_param))),
                );
            } else {
                enc.assert_term(SmtTerm::bool(false));
            }
        }

        // Strengthening: global process conservation.
        if let Some(n_pid) = n_param {
            let total = (0..num_locs)
                .map(|l| SmtTerm::var(kappa_var(step, l)))
                .collect::<Vec<_>>();
            let total = sum_terms_balanced(total);
            enc.assert_term(total.eq(SmtTerm::var(param_var(n_pid))));
        }

        // Strengthening: per-role conservation when a role-population parameter exists.
        for (role, locs) in &role_loc_ids {
            if let Some(&pid) = role_population_targets.get(role) {
                let total = locs
                    .iter()
                    .map(|l| SmtTerm::var(kappa_var(step, *l)))
                    .collect::<Vec<_>>();
                let total = sum_terms_balanced(total);
                enc.assert_term(total.eq(SmtTerm::var(param_var(pid))));
            }
        }
        if let Some(buckets) = &process_id_buckets {
            assert_process_identity_uniqueness(&mut enc, step, buckets);
        }

        // Strengthening: internal sender-uniqueness flags imply message-counter lower bounds.
        // number_of_processes_with(__sent_gv = true) <= g_v
        for (counter_id, locs) in &sent_flag_true_locs {
            if locs.is_empty() {
                continue;
            }
            let total_true = locs
                .iter()
                .map(|l| SmtTerm::var(kappa_var(step, *l)))
                .collect::<Vec<_>>();
            let total_true = sum_terms_balanced(total_true);
            enc.assert_term(total_true.le(SmtTerm::var(gamma_var(step, *counter_id))));
        }
    }
    if missing_process_ids {
        enc.assert_term(SmtTerm::bool(false));
    }
    if byzantine_faults {
        for (sender_idx, _) in signed_sender_channels.iter().enumerate() {
            let static_name = byz_sender_static_var(sender_idx);
            enc.declare(static_name.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(static_name.clone()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(static_name).le(SmtTerm::int(1)));
        }
    }

    // Declare transition variables for steps 0..k-1
    for step in 0..k {
        for r in 0..num_rules {
            enc.declare(delta_var(step, r), SmtSort::Int);
            let delta = SmtTerm::var(delta_var(step, r));
            enc.assert_term(delta.clone().ge(SmtTerm::int(0)));
            if por_pruning.is_disabled(r) {
                enc.assert_term(delta.eq(SmtTerm::int(0)));
            }
        }
        for v in 0..num_svars {
            let adv_name = format!("adv_{step}_{v}");
            enc.declare(adv_name.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(adv_name).ge(SmtTerm::int(0)));
            if message_counter_flags.get(v).copied().unwrap_or(false) {
                let send_name = net_send_var(step, v);
                let forge_name = net_forge_var(step, v);
                let deliver_name = net_deliver_var(step, v);
                let net_drop_name = net_drop_var(step, v);
                enc.declare(send_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(send_name).ge(SmtTerm::int(0)));
                enc.declare(forge_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(forge_name).ge(SmtTerm::int(0)));
                enc.declare(deliver_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(deliver_name).ge(SmtTerm::int(0)));
                enc.declare(net_drop_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(net_drop_name).ge(SmtTerm::int(0)));
            }
            if lossy_delivery {
                let drop_name = drop_var(step, v);
                enc.declare(drop_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(drop_name).ge(SmtTerm::int(0)));
            }
        }
        if byzantine_faults {
            for (sender_idx, _) in signed_sender_channels.iter().enumerate() {
                let name = byz_sender_var(step, sender_idx);
                enc.declare(name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(name.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(name).le(SmtTerm::int(1)));
                enc.assert_term(
                    SmtTerm::var(byz_sender_var(step, sender_idx))
                        .le(SmtTerm::var(byz_sender_static_var(sender_idx))),
                );
            }
        }
        if byzantine_faults && selective_network {
            for (group_id, group_vars) in message_variant_groups.iter().enumerate() {
                let send_name = adv_send_var(step, group_id);
                enc.declare(send_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(send_name.clone()).ge(SmtTerm::int(0)));
                for &var_id in group_vars {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{step}_{var_id}"))
                            .le(SmtTerm::var(send_name.clone())),
                    );
                }
            }
        }
        if selective_network && ta.delivery_control == DeliveryControlMode::Global {
            for group_vars in &message_variant_groups {
                if group_vars.len() <= 1 {
                    continue;
                }
                let first = group_vars[0];
                for &other in &group_vars[1..] {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{step}_{other}"))
                            .eq(SmtTerm::var(format!("adv_{step}_{first}"))),
                    );
                    if lossy_delivery {
                        enc.assert_term(
                            SmtTerm::var(drop_var(step, other))
                                .eq(SmtTerm::var(drop_var(step, first))),
                        );
                    }
                }
            }
        }
    }

    // Transition relation for each step
    for step in 0..k {
        // Location counter updates
        for l in 0..num_locs {
            let mut outgoing = Vec::new();
            let mut incoming = Vec::new();
            for &r in &active_rule_ids {
                let rule = &ta.rules[r];
                if rule.from == l {
                    outgoing.push(SmtTerm::var(delta_var(step, r)));
                }
                if rule.to == l {
                    incoming.push(SmtTerm::var(delta_var(step, r)));
                }
            }
            let mut expr = SmtTerm::var(kappa_var(step, l));
            if !incoming.is_empty() {
                expr = expr.add(sum_terms_balanced(incoming));
            }
            if !outgoing.is_empty() {
                expr = expr.sub(sum_terms_balanced(outgoing));
            }
            enc.assert_term(SmtTerm::var(kappa_var(step + 1, l)).eq(expr));
            enc.assert_term(SmtTerm::var(kappa_var(step + 1, l)).ge(SmtTerm::int(0)));
        }

        // Guard enablement and individual delta bound
        for &r in &active_rule_ids {
            let rule = &ta.rules[r];
            let dr_pos = SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
            for atom in &rule.guard.atoms {
                let guard_term = match atom {
                    GuardAtom::Threshold {
                        vars,
                        op,
                        bound,
                        distinct,
                    } => encode_threshold_guard_at_step(step, vars, *op, bound, *distinct),
                };
                enc.assert_term(dr_pos.clone().implies(guard_term));
            }
            enc.assert_term(
                SmtTerm::var(delta_var(step, r)).le(SmtTerm::var(kappa_var(step, rule.from))),
            );
        }

        // Outgoing sum bound per location
        for l in 0..num_locs {
            let outgoing: Vec<SmtTerm> = active_rule_ids
                .iter()
                .copied()
                .filter(|r| ta.rules[*r].from == l)
                .map(|r| SmtTerm::var(delta_var(step, r)))
                .collect();
            if outgoing.len() > 1 {
                let sum = sum_terms_balanced(outgoing);
                enc.assert_term(sum.le(SmtTerm::var(kappa_var(step, l))));
            }
        }

        // Logical time progression.
        enc.assert_term(
            SmtTerm::var(time_var(step + 1)).eq(SmtTerm::var(time_var(step)).add(SmtTerm::int(1))),
        );

        // Shared variable updates (with adversary and omission drops)
        for (v, inc_only) in increment_only_var.iter().enumerate() {
            let is_message_counter = message_counter_flags.get(v).copied().unwrap_or(false);
            let adv_term = SmtTerm::var(format!("adv_{step}_{v}"));
            let drop_term = lossy_delivery.then(|| SmtTerm::var(drop_var(step, v)));
            let net_deliver_term =
                is_message_counter.then(|| SmtTerm::var(net_deliver_var(step, v)));
            let mut sent_parts = Vec::new();
            for &r in &active_rule_ids {
                let rule = &ta.rules[r];
                for upd in &rule.updates {
                    if upd.var == v {
                        match &upd.kind {
                            UpdateKind::Increment => {
                                sent_parts.push(SmtTerm::var(delta_var(step, r)));
                            }
                            UpdateKind::Set(lc) => {
                                let dr_pos = SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
                                let set_val = encode_lc(lc);
                                enc.assert_term(
                                    dr_pos
                                        .implies(SmtTerm::var(gamma_var(step + 1, v)).eq(set_val)),
                                );
                            }
                        }
                    }
                }
            }
            let sent_expr = sum_terms_balanced(sent_parts);
            if is_message_counter {
                let net_send = SmtTerm::var(net_send_var(step, v));
                let net_forge = SmtTerm::var(net_forge_var(step, v));
                let net_deliver = SmtTerm::var(net_deliver_var(step, v));
                let net_drop = SmtTerm::var(net_drop_var(step, v));
                let net_pending_k = SmtTerm::var(net_pending_var(step, v));
                let net_pending_next = SmtTerm::var(net_pending_var(step + 1, v));
                enc.assert_term(net_send.clone().eq(sent_expr.clone()));
                enc.assert_term(net_forge.clone().eq(adv_term.clone()));
                if let Some(drop_term) = drop_term.clone() {
                    enc.assert_term(net_drop.clone().eq(drop_term));
                } else {
                    enc.assert_term(net_drop.clone().eq(SmtTerm::int(0)));
                }
                let available = net_pending_k.add(net_send).add(net_forge);
                enc.assert_term(
                    net_deliver
                        .clone()
                        .add(net_drop.clone())
                        .le(available.clone()),
                );
                enc.assert_term(
                    net_pending_next.eq(available
                        .clone()
                        .sub(net_deliver.clone())
                        .sub(net_drop.clone())),
                );
                if ta.timing_model == TimingModel::PartialSynchrony && selective_network {
                    if let Some(gst_pid) = ta.gst_param {
                        let post_gst =
                            SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(step)));
                        if byzantine_faults {
                            if let Some(sender_idx) = signed_uncompromised_sender_idx_by_var
                                .get(v)
                                .copied()
                                .flatten()
                            {
                                let honest_sender = SmtTerm::var(byz_sender_var(step, sender_idx))
                                    .eq(SmtTerm::int(0));
                                enc.assert_term(
                                    SmtTerm::and(vec![post_gst.clone(), honest_sender])
                                        .implies(net_deliver.clone().eq(available.clone())),
                                );
                            }
                        } else {
                            enc.assert_term(
                                post_gst.implies(net_deliver.clone().eq(available.clone())),
                            );
                        }
                    }
                }
                if ta.timing_model == TimingModel::PartialSynchrony
                    && lossy_delivery
                    && ta.gst_param.is_some()
                {
                    if let Some(gst_pid) = ta.gst_param {
                        let post_gst =
                            SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(step)));
                        enc.assert_term(post_gst.implies(net_drop.eq(SmtTerm::int(0))));
                    }
                }
            }
            let has_set_update = ta.rules.iter().any(|rule| {
                rule.updates
                    .iter()
                    .any(|u| u.var == v && matches!(u.kind, UpdateKind::Set(_)))
            });
            if !has_set_update {
                let expr = if let Some(net_deliver) = net_deliver_term.clone() {
                    SmtTerm::var(gamma_var(step, v)).add(net_deliver)
                } else {
                    let mut expr = SmtTerm::var(gamma_var(step, v))
                        .add(sent_expr.clone())
                        .add(adv_term.clone());
                    if let Some(drop_term) = drop_term.clone() {
                        expr = expr.sub(drop_term);
                    }
                    expr
                };
                let mut next_expr: Option<SmtTerm> = Some(expr);
                let mut is_distinct = false;
                for (var_id, role) in &distinct_vars {
                    if *var_id != v {
                        continue;
                    }
                    is_distinct = true;
                    if let Some(role) = role {
                        if !role_loc_ids.contains_key(role) {
                            enc.assert_term(SmtTerm::bool(false));
                            next_expr = None;
                            continue;
                        }
                        let mut recv_sum = Vec::new();
                        for &r in &active_rule_ids {
                            let rule = &ta.rules[r];
                            if rule.updates.iter().any(|u| u.var == v) {
                                let from_role = &ta.locations[rule.from].role;
                                if from_role == role {
                                    recv_sum.push(SmtTerm::var(delta_var(step, r)));
                                }
                            }
                        }
                        let total_recv = if recv_sum.is_empty() {
                            SmtTerm::int(0)
                        } else {
                            sum_terms_balanced(recv_sum)
                        };
                        let gamma_k = SmtTerm::var(gamma_var(step, v));
                        let sum_term = if let Some(net_deliver) = net_deliver_term.clone() {
                            gamma_k.clone().add(net_deliver)
                        } else {
                            let mut sum_term =
                                gamma_k.clone().add(total_recv).add(adv_term.clone());
                            if let Some(drop_term) = drop_term.clone() {
                                sum_term = sum_term.sub(drop_term);
                            }
                            sum_term
                        };
                        let gamma_next = SmtTerm::var(gamma_var(step + 1, v));
                        enc.assert_term(gamma_next.clone().ge(sum_term.clone()));
                        enc.assert_term(gamma_next.clone().le(sum_term.clone()));
                        if let Some(&pid) = role_pop_params.get(role) {
                            let pop = SmtTerm::var(param_var(pid));
                            enc.assert_term(gamma_next.le(pop));
                        } else if let Some(n_param) = n_param {
                            let pop = SmtTerm::var(param_var(n_param));
                            enc.assert_term(gamma_next.le(pop));
                        }
                        next_expr = None;
                    }
                }
                if is_distinct {
                    if let Some(expr) = next_expr {
                        enc.assert_term(SmtTerm::var(gamma_var(step + 1, v)).eq(expr));
                    }
                } else if let Some(expr) = next_expr {
                    enc.assert_term(SmtTerm::var(gamma_var(step + 1, v)).eq(expr));
                }

                if !is_message_counter {
                    if let Some(drop_term) = drop_term {
                        enc.assert_term(drop_term.clone().le(sent_expr.add(adv_term)));
                        if ta.timing_model == TimingModel::PartialSynchrony {
                            if let Some(gst_pid) = ta.gst_param {
                                let post_gst = SmtTerm::var(param_var(gst_pid))
                                    .le(SmtTerm::var(time_var(step)));
                                enc.assert_term(post_gst.implies(drop_term.eq(SmtTerm::int(0))));
                            }
                        }
                    }
                }
            }
            if *inc_only {
                enc.assert_term(
                    SmtTerm::var(gamma_var(step + 1, v)).ge(SmtTerm::var(gamma_var(step, v))),
                );
            }
        }
    }

    // Crypto objects are derived artifacts; do not allow standalone adversarial forge traffic.
    for step in 0..k {
        for v in &crypto_object_counter_vars {
            enc.assert_term(SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
        }
    }

    // Exclusive crypto-object admissibility in inductive steps.
    for step in 0..k {
        for variant_groups in exclusive_crypto_variant_groups.values() {
            if variant_groups.len() <= 1 {
                continue;
            }
            let sums: Vec<SmtTerm> = variant_groups
                .iter()
                .map(|vars| {
                    sum_terms_balanced(
                        vars.iter()
                            .map(|v| SmtTerm::var(gamma_var(step + 1, *v)))
                            .collect(),
                    )
                })
                .collect();
            for (i, sum_i) in sums.iter().enumerate() {
                for (j, sum_j) in sums.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    enc.assert_term(
                        sum_i
                            .clone()
                            .gt(SmtTerm::int(0))
                            .implies(sum_j.clone().eq(SmtTerm::int(0))),
                    );
                }
            }
        }
    }

    // Fault bounds (same model as BMC)
    if let Some(adv_param) = ta.adversary_bound_param {
        enc.assert_term(SmtTerm::var(param_var(adv_param)).ge(SmtTerm::int(0)));
        if let Some(t_param) = ta.find_param_by_name("t") {
            if adv_param != t_param {
                enc.assert_term(
                    SmtTerm::var(param_var(adv_param)).le(SmtTerm::var(param_var(t_param))),
                );
            }
        }
        if byzantine_faults && !signed_sender_channels.is_empty() {
            let static_terms = signed_sender_channels
                .iter()
                .enumerate()
                .map(|(idx, _)| SmtTerm::var(byz_sender_static_var(idx)))
                .collect::<Vec<_>>();
            enc.assert_term(
                sum_terms_balanced(static_terms).le(SmtTerm::var(param_var(adv_param))),
            );
        }
        for step in 0..k {
            for v in 0..num_svars {
                if byzantine_faults {
                    enc.assert_term(
                        SmtTerm::var(format!("adv_{step}_{v}"))
                            .le(SmtTerm::var(param_var(adv_param))),
                    );
                } else if omission_style_faults {
                    enc.assert_term(SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)));
                    enc.assert_term(
                        SmtTerm::var(drop_var(step, v)).le(SmtTerm::var(param_var(adv_param))),
                    );
                } else {
                    enc.assert_term(SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)));
                }
            }
            match ta.fault_budget_scope {
                FaultBudgetScope::LegacyCounter => {}
                FaultBudgetScope::PerRecipient => {
                    if byzantine_faults {
                        for vars in recipient_groups.values() {
                            if vars.is_empty() {
                                continue;
                            }
                            let sum = vars
                                .iter()
                                .map(|v| SmtTerm::var(format!("adv_{step}_{v}")))
                                .collect::<Vec<_>>();
                            enc.assert_term(
                                sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                            );
                        }
                    }
                    if lossy_delivery {
                        for vars in recipient_groups.values() {
                            if vars.is_empty() {
                                continue;
                            }
                            let sum = vars
                                .iter()
                                .map(|v| SmtTerm::var(drop_var(step, *v)))
                                .collect::<Vec<_>>();
                            enc.assert_term(
                                sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                            );
                        }
                    }
                }
                FaultBudgetScope::Global => {
                    if byzantine_faults && !all_message_counter_vars.is_empty() {
                        let sum = all_message_counter_vars
                            .iter()
                            .map(|v| SmtTerm::var(format!("adv_{step}_{v}")))
                            .collect::<Vec<_>>();
                        enc.assert_term(
                            sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                    if lossy_delivery && !all_message_counter_vars.is_empty() {
                        let sum = all_message_counter_vars
                            .iter()
                            .map(|v| SmtTerm::var(drop_var(step, *v)))
                            .collect::<Vec<_>>();
                        enc.assert_term(
                            sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                }
            }
            if lossy_delivery && selective_network {
                for ((_family, recipient), vars) in &message_family_recipients {
                    if recipient.is_none() || vars.is_empty() {
                        continue;
                    }
                    let sum = vars
                        .iter()
                        .map(|v| SmtTerm::var(drop_var(step, *v)))
                        .collect::<Vec<_>>();
                    enc.assert_term(sum_terms_balanced(sum).le(SmtTerm::var(param_var(adv_param))));
                }
            }
            if byzantine_faults && selective_network {
                for group_id in 0..message_variant_groups.len() {
                    enc.assert_term(
                        SmtTerm::var(adv_send_var(step, group_id))
                            .le(SmtTerm::var(param_var(adv_param))),
                    );
                }
            }
            if crash_faults {
                for v in &all_message_counter_vars {
                    enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
                    enc.assert_term(SmtTerm::var(net_drop_var(step, *v)).eq(SmtTerm::int(0)));
                }
                if let Some(crash_var) = crash_counter_var {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(step + 1, crash_var))
                            .le(SmtTerm::var(param_var(adv_param))),
                    );
                } else {
                    enc.assert_term(SmtTerm::bool(false));
                }
            }
        }
        if byzantine_faults {
            // Signed-channel origin/auth constraints:
            // - senderless signed counters cannot be adversarially injected
            // - uncompromised sender channels require activating a Byzantine sender identity
            // - total active Byzantine sender identities per step is bounded by f
            for step in 0..k {
                for vars in signed_senderless_vars.values() {
                    for v in vars {
                        enc.assert_term(
                            SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)),
                        );
                        enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
                    }
                }
                let mut byz_sender_terms = Vec::new();
                for (sender_idx, sender_channel) in signed_sender_channels.iter().enumerate() {
                    let byz_sender = SmtTerm::var(byz_sender_var(step, sender_idx));
                    byz_sender_terms.push(byz_sender.clone());
                    if let Some(vars) = signed_uncompromised_sender_vars.get(sender_channel) {
                        for v in vars {
                            enc.assert_term(byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)),
                            ));
                            enc.assert_term(byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)),
                            ));
                        }
                    }
                }
                if !byz_sender_terms.is_empty() {
                    let active = sum_terms_balanced(byz_sender_terms);
                    enc.assert_term(active.le(SmtTerm::var(param_var(adv_param))));
                }
            }

            // Sender-scoped equivocation semantics in selective networks:
            // - full equivocation: sender may split deliveries across variants;
            // - none: sender must pick at most one payload variant per family per step.
            if selective_network {
                for step in 0..k {
                    for ((family, sender), variants) in &family_sender_variants_vec {
                        if variants.len() <= 1 || !message_effective_non_equivocating(ta, family) {
                            continue;
                        }
                        for i in 0..variants.len() {
                            let vars_i = family_sender_variant_vars
                                .get(&(family.clone(), sender.clone(), variants[i].clone()))
                                .cloned()
                                .unwrap_or_default();
                            if vars_i.is_empty() {
                                continue;
                            }
                            let sum_i = sum_terms_balanced(
                                vars_i
                                    .iter()
                                    .map(|v| SmtTerm::var(net_forge_var(step, *v)))
                                    .collect::<Vec<_>>(),
                            );
                            for (j, variant_j) in variants.iter().enumerate() {
                                if i == j {
                                    continue;
                                }
                                let vars_j = family_sender_variant_vars
                                    .get(&(family.clone(), sender.clone(), variant_j.clone()))
                                    .cloned()
                                    .unwrap_or_default();
                                if vars_j.is_empty() {
                                    continue;
                                }
                                let sum_j = sum_terms_balanced(
                                    vars_j
                                        .iter()
                                        .map(|v| SmtTerm::var(net_forge_var(step, *v)))
                                        .collect::<Vec<_>>(),
                                );
                                enc.assert_term(
                                    sum_i
                                        .clone()
                                        .gt(SmtTerm::int(0))
                                        .implies(sum_j.eq(SmtTerm::int(0))),
                                );
                            }
                        }
                    }
                }
            }

            for (v, _) in &distinct_vars {
                let mut parts = Vec::new();
                for step in 0..k {
                    parts.push(SmtTerm::var(format!("adv_{step}_{v}")));
                }
                if !parts.is_empty() {
                    let total = sum_terms_balanced(parts);
                    enc.assert_term(total.le(SmtTerm::var(param_var(adv_param))));
                }
            }
            for step in 0..k {
                for ((family, _recipient), vars) in &message_family_recipients {
                    if vars.is_empty() {
                        continue;
                    }
                    let identity_capped = message_effective_signed_auth(ta, family)
                        || message_effective_non_equivocating(ta, family);
                    if !identity_capped {
                        continue;
                    }
                    let sum = vars
                        .iter()
                        .map(|v| SmtTerm::var(format!("adv_{step}_{v}")))
                        .collect::<Vec<_>>();
                    let sum = sum_terms_balanced(sum);
                    enc.assert_term(sum.le(SmtTerm::var(param_var(adv_param))));
                }
            }
            if selective_network {
                for step in 0..k {
                    for (family, group_ids) in &message_family_variants {
                        if group_ids.is_empty() || !message_effective_non_equivocating(ta, family) {
                            continue;
                        }
                        let sum = group_ids
                            .iter()
                            .map(|gid| SmtTerm::var(adv_send_var(step, *gid)))
                            .collect::<Vec<_>>();
                        let sum = sum_terms_balanced(sum);
                        enc.assert_term(sum.le(SmtTerm::var(param_var(adv_param))));
                    }
                }
            }
        }
    } else if omission_style_faults || crash_faults {
        for step in 0..k {
            for v in 0..num_svars {
                enc.assert_term(SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)));
                if omission_style_faults {
                    enc.assert_term(SmtTerm::var(drop_var(step, v)).eq(SmtTerm::int(0)));
                }
            }
            if crash_faults {
                for v in &all_message_counter_vars {
                    enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
                    enc.assert_term(SmtTerm::var(net_drop_var(step, *v)).eq(SmtTerm::int(0)));
                }
                if let Some(crash_var) = crash_counter_var {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(step + 1, crash_var)).eq(SmtTerm::int(0)),
                    );
                } else {
                    enc.assert_term(SmtTerm::bool(false));
                }
            }
        }
    }

    // Induction hypotheses: property holds for 0..k-1
    for step in 0..k {
        let viol = encode_property_violation_at_step(ta, property, step);
        enc.assert_term(SmtTerm::not(viol));
    }
    // Step goal: property violated at k
    enc.assert_term(encode_property_violation_at_step(ta, property, k));

    enc
}

/// Encode the negation of a safety property at some step.
/// Returns a term that is SAT iff the property is violated.
fn encode_property_violation_at_step(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    step: usize,
) -> SmtTerm {
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            let mut violation_disjuncts = Vec::new();
            for &(loc_i, loc_j) in conflicting_pairs {
                let ki_pos = SmtTerm::var(kappa_var(step, loc_i)).gt(SmtTerm::int(0));
                let kj_pos = SmtTerm::var(kappa_var(step, loc_j)).gt(SmtTerm::int(0));
                violation_disjuncts.push(SmtTerm::and(vec![ki_pos, kj_pos]));
            }
            if violation_disjuncts.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(violation_disjuncts)
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            let mut violation_disjuncts = Vec::new();
            for bad_set in bad_sets {
                let occupied: Vec<SmtTerm> = bad_set
                    .iter()
                    .map(|&l| SmtTerm::var(kappa_var(step, l)).gt(SmtTerm::int(0)))
                    .collect();
                violation_disjuncts.push(SmtTerm::and(occupied));
            }
            if violation_disjuncts.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(violation_disjuncts)
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            let goals: std::collections::HashSet<_> = goal_locs.iter().copied().collect();
            let mut violation_disjuncts = Vec::new();
            for l in 0..ta.locations.len() {
                if !goals.contains(&l) {
                    violation_disjuncts.push(SmtTerm::var(kappa_var(step, l)).gt(SmtTerm::int(0)));
                }
            }
            if violation_disjuncts.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(violation_disjuncts)
            }
        }
    }
}

fn encode_property_violation(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    max_depth: usize,
) -> SmtTerm {
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            let mut violation_disjuncts = Vec::new();
            if conflicting_pairs.is_empty() {
                return SmtTerm::bool(false);
            }
            for k in 0..=max_depth {
                violation_disjuncts.push(encode_property_violation_at_step(ta, property, k));
            }
            SmtTerm::or(violation_disjuncts)
        }
        SafetyProperty::Invariant { bad_sets } => {
            let mut violation_disjuncts = Vec::new();
            if bad_sets.is_empty() {
                return SmtTerm::bool(false);
            }
            for k in 0..=max_depth {
                violation_disjuncts.push(encode_property_violation_at_step(ta, property, k));
            }
            SmtTerm::or(violation_disjuncts)
        }
        SafetyProperty::Termination { .. } => {
            encode_property_violation_at_step(ta, property, max_depth)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::smtlib_printer::to_smtlib;
    use crate::backends::z3_backend::Z3Solver;
    use crate::solver::{SatResult, SmtSolver};
    use indexmap::IndexMap;

    fn make_simple_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();

        // Parameters: n, t
        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_parameter(Parameter { name: "t".into() });

        // Resilience: n > 3*t
        ta.resilience_condition = Some(LinearConstraint {
            lhs: LinearCombination::param(0), // n
            op: CmpOp::Gt,
            rhs: LinearCombination::param(1).scale(3), // 3*t
        });

        // 1 message counter
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        // 2 locations: waiting, done
        ta.add_location(Location {
            name: "waiting".into(),
            role: "P".into(),
            phase: "waiting".into(),
            local_vars: IndexMap::new(),
        });
        ta.add_location(Location {
            name: "done".into(),
            role: "P".into(),
            phase: "done".into(),
            local_vars: IndexMap::new(),
        });

        ta.initial_locations = vec![0];

        // Rule: waiting -> done when cnt_Echo >= 2*t+1, sends Echo
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0],
                op: CmpOp::Ge,
                bound: LinearCombination {
                    constant: 1,
                    terms: vec![(2, 1)], // 2*t + 1
                },
                distinct: false,
            }),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });

        ta
    }

    fn make_signer_set_threshold_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();

        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_parameter(Parameter { name: "t".into() });
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );

        ta.add_location(Location {
            name: "waiting".into(),
            role: "P".into(),
            phase: "waiting".into(),
            local_vars: IndexMap::new(),
        });
        ta.add_location(Location {
            name: "done".into(),
            role: "P".into(),
            phase: "done".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations = vec![0];

        let vote_sender_0 = ta.add_shared_var(SharedVar {
            name: "cnt_Vote@P#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let vote_sender_1 = ta.add_shared_var(SharedVar {
            name: "cnt_Vote@P#0<-P#1[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let sig = ta.add_shared_var(SharedVar {
            name: "cnt_Sig@P#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![vote_sender_0, vote_sender_1],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(2),
                distinct: true,
            }),
            updates: vec![Update {
                var: sig,
                kind: UpdateKind::Increment,
            }],
        });

        ta
    }

    fn solve_with_extra_assertions(enc: &BmcEncoding, extra: &[SmtTerm]) -> SatResult {
        let mut solver = Z3Solver::with_default_config();
        for (name, sort) in &enc.declarations {
            solver
                .declare_var(name, sort)
                .expect("encoding variable declaration should be valid");
        }
        for assertion in &enc.assertions {
            solver
                .assert(assertion)
                .expect("encoding assertion should be valid");
        }
        for assertion in extra {
            solver
                .assert(assertion)
                .expect("extra assertion should be valid");
        }
        solver
            .check_sat()
            .expect("solver should return SAT/UNSAT for finite encoding")
    }

    #[test]
    fn encoding_produces_declarations() {
        let ta = make_simple_ta();
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 2);
        // Should have parameter vars + location vars + shared vars + delta vars
        assert!(!enc.declarations.is_empty());
        assert!(!enc.assertions.is_empty());
    }

    fn add_depth(term: &SmtTerm) -> usize {
        match term {
            SmtTerm::Add(lhs, rhs) => 1 + add_depth(lhs).max(add_depth(rhs)),
            _ => 0,
        }
    }

    #[test]
    fn balanced_sum_builder_stays_shallow() {
        let terms = (0..1024)
            .map(|i| SmtTerm::var(format!("x_{i}")))
            .collect::<Vec<_>>();
        let sum = sum_terms_balanced(terms);
        // 1024 leaves should fit in a depth-10 balanced tree.
        assert!(add_depth(&sum) <= 10);
    }

    #[test]
    fn structural_hashing_deduplicates_commutative_identity_constraints() {
        let mut enc = BmcEncoding::new();
        enc.assert_term(SmtTerm::var("a").eq(SmtTerm::var("b")));
        enc.assert_term(SmtTerm::var("b").eq(SmtTerm::var("a")));
        enc.assert_term(SmtTerm::and(vec![SmtTerm::var("x"), SmtTerm::var("y")]));
        enc.assert_term(SmtTerm::and(vec![SmtTerm::var("y"), SmtTerm::var("x")]));
        assert_eq!(enc.assertions.len(), 2);
    }

    #[test]
    fn por_prunes_stutter_rules_by_forcing_zero_delta() {
        let mut ta = make_simple_ta();
        ta.add_rule(Rule {
            from: 0,
            to: 0,
            guard: Guard::trivial(),
            updates: vec![],
        });
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let bmc = encode_bmc(&cs, &property, 1);
        let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
        assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

        let step = encode_k_induction_step(&cs, &property, 1);
        let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(step_assertions.iter().any(|a| a == "(= delta_0_1 0)"));
    }

    #[test]
    fn por_prunes_commutative_duplicate_rules_by_forcing_zero_delta() {
        let mut ta = make_simple_ta();
        ta.add_rule(ta.rules[0].clone());
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let bmc = encode_bmc(&cs, &property, 1);
        let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
        assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

        let step = encode_k_induction_step(&cs, &property, 1);
        let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(step_assertions.iter().any(|a| a == "(= delta_0_1 0)"));
    }

    #[test]
    fn por_prunes_guard_dominated_rules_by_forcing_zero_delta() {
        let mut ta = make_simple_ta();
        ta.rules.clear();
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(2),
                distinct: false,
            }),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let bmc = encode_bmc(&cs, &property, 1);
        let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
        assert!(bmc_assertions.iter().any(|a| a == "(= delta_0_0 0)"));

        let step = encode_k_induction_step(&cs, &property, 1);
        let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(step_assertions.iter().any(|a| a == "(= delta_0_0 0)"));
    }

    #[test]
    fn omission_partial_sync_encodes_drop_and_post_gst_delivery() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.add_parameter(Parameter { name: "gst".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Omission;
        ta.timing_model = TimingModel::PartialSynchrony;
        ta.gst_param = Some(3);
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("drop_0_0"));
        assert!(decls.contains("time_0"));
        assert!(decls.contains("time_1"));

        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
        assert!(assertions.iter().any(|a| a == "(<= drop_0_0 p_2)"));
        assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 drop_0_0)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (<= p_3 time_0) (= net_drop_0_0 0))"));
        assert!(assertions.iter().any(|a| a == "(= time_0 0)"));
        assert!(assertions.iter().any(|a| a == "(= time_1 (+ time_0 1))"));
    }

    #[test]
    fn message_network_flow_is_explicitly_modeled_per_edge() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);

        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("net_pending_0_0"));
        assert!(decls.contains("net_pending_1_0"));
        assert!(decls.contains("net_send_0_0"));
        assert!(decls.contains("net_forge_0_0"));
        assert!(decls.contains("net_deliver_0_0"));
        assert!(decls.contains("net_drop_0_0"));

        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= net_pending_0_0 0)"));
        assert!(assertions.iter().any(|a| a == "(= net_send_0_0 delta_0_0)"));
        assert!(assertions.iter().any(|a| a == "(= net_forge_0_0 adv_0_0)"));
        assert!(assertions.iter().any(
            |a| a == "(<= (+ net_deliver_0_0 net_drop_0_0) (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0))"
        ));
        assert!(assertions.iter().any(
            |a| a == "(= net_pending_1_0 (- (- (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0) net_deliver_0_0) net_drop_0_0))"
        ));
        assert!(assertions
            .iter()
            .any(|a| a == "(= g_1_0 (+ g_0_0 net_deliver_0_0))"));
    }

    #[test]
    fn byzantine_model_does_not_declare_drop_variables() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(!decls.iter().any(|n| n.starts_with("drop_")));
    }

    #[test]
    fn byzantine_identity_selective_declares_drop_and_advsend_variables() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("drop_0_0"));
        assert!(decls.contains("drop_0_1"));
        assert!(decls.contains("drop_0_2"));
        assert!(decls.contains("advsend_0_0"));
        assert!(decls.contains("advsend_0_1"));
    }

    #[test]
    fn byzantine_cohort_selective_couples_lane_variants_with_sender_budget() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::CohortSelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica#1[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("drop_0_0"));
        assert!(decls.contains("drop_0_1"));
        assert!(decls.contains("advsend_0_0"));

        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(<= adv_0_0 advsend_0_0)"));
        assert!(assertions.iter().any(|a| a == "(<= adv_0_1 advsend_0_0)"));
    }

    #[test]
    fn fault_scope_per_recipient_adds_recipient_aggregate_bounds() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.fault_budget_scope = FaultBudgetScope::PerRecipient;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
        assert!(assertions.iter().any(|a| a == "(<= adv_0_2 p_2)"));
    }

    #[test]
    fn omission_selective_adds_per_message_per_recipient_drop_bounds() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Omission;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica<-P#1[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ drop_0_0 drop_0_1) p_2)"));
        assert!(assertions.iter().any(|a| a == "(<= drop_0_2 p_2)"));
    }

    #[test]
    fn fault_scope_global_adds_global_aggregate_bound() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.fault_budget_scope = FaultBudgetScope::Global;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ (+ adv_0_0 adv_0_1) adv_0_2) p_2)"));
    }

    #[test]
    fn delivery_control_global_couples_variant_injections_across_recipients() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.delivery_control = DeliveryControlMode::Global;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_1 adv_0_0)"));
    }

    #[test]
    fn process_selective_adds_pid_bucket_uniqueness_constraints() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::ProcessSelective;
        ta.shared_vars[0].name = "cnt_Echo@P#0".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@P#1".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        ta.locations[0]
            .local_vars
            .insert("pid".into(), LocalValue::Int(0));
        ta.locations[1]
            .local_vars
            .insert("pid".into(), LocalValue::Int(0));
        ta.add_location(Location {
            name: "waiting_pid1".into(),
            role: "P".into(),
            phase: "waiting".into(),
            local_vars: indexmap::indexmap! {"pid".into() => LocalValue::Int(1)},
        });
        ta.add_location(Location {
            name: "done_pid1".into(),
            role: "P".into(),
            phase: "done".into(),
            local_vars: indexmap::indexmap! {"pid".into() => LocalValue::Int(1)},
        });
        ta.rules[0].from = 2;
        ta.rules[0].to = 3;
        ta.initial_locations = vec![0, 2];

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(= (+ kappa_0_0 kappa_0_1) 1)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(= (+ kappa_1_0 kappa_1_1) 1)"));
    }

    #[test]
    fn process_selective_uses_declared_identity_variable_for_uniqueness() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::ProcessSelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("node_id".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_Echo@P#0".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@P#1".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        ta.locations[0]
            .local_vars
            .insert("node_id".into(), LocalValue::Int(0));
        ta.locations[1]
            .local_vars
            .insert("node_id".into(), LocalValue::Int(0));
        ta.add_location(Location {
            name: "waiting_id1".into(),
            role: "P".into(),
            phase: "waiting".into(),
            local_vars: indexmap::indexmap! {"node_id".into() => LocalValue::Int(1)},
        });
        ta.add_location(Location {
            name: "done_id1".into(),
            role: "P".into(),
            phase: "done".into(),
            local_vars: indexmap::indexmap! {"node_id".into() => LocalValue::Int(1)},
        });
        ta.rules[0].from = 2;
        ta.rules[0].to = 3;
        ta.initial_locations = vec![0, 2];

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(= (+ kappa_0_0 kappa_0_1) 1)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(= (+ kappa_1_0 kappa_1_1) 1)"));
    }

    #[test]
    fn byzantine_identity_selective_couples_variant_delivery_across_recipients() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.equivocation_mode = EquivocationMode::None;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        // Replica and client counters for the same variant are tied to one sender budget.
        assert!(assertions.iter().any(|a| a == "(<= adv_0_0 advsend_0_0)"));
        assert!(assertions.iter().any(|a| a == "(<= adv_0_2 advsend_0_0)"));
        assert!(assertions.iter().any(|a| a == "(<= adv_0_1 advsend_0_1)"));
        assert!(assertions.iter().any(|a| a == "(<= adv_0_3 advsend_0_1)"));
        // Non-equivocation globally caps Byzantine variant choices per family.
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ advsend_0_0 advsend_0_1) p_2)"));
    }

    #[test]
    fn byzantine_equivocation_none_bounds_family_sum() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.equivocation_mode = EquivocationMode::None;
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
    }

    #[test]
    fn byzantine_equivocation_none_bounds_family_sum_per_recipient() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.equivocation_mode = EquivocationMode::None;

        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_2 adv_0_3) p_2)"));
    }

    #[test]
    fn byzantine_signed_auth_bounds_family_sum_even_with_full_equivocation() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.equivocation_mode = EquivocationMode::Full;
        ta.authentication_mode = AuthenticationMode::Signed;

        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_2 adv_0_3) p_2)"));
    }

    #[test]
    fn message_auth_policy_authenticated_enforces_identity_cap() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.equivocation_mode = EquivocationMode::Full;
        ta.authentication_mode = AuthenticationMode::None;
        ta.message_policies.insert(
            "Echo".into(),
            MessagePolicy {
                auth: MessageAuthPolicy::Authenticated,
                equivocation: MessageEquivocationPolicy::Inherit,
            },
        );

        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ adv_0_0 adv_0_1) p_2)"));
    }

    #[test]
    fn signed_senderless_messages_forbid_adversary_injection() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
    }

    #[test]
    fn signed_sender_scoped_messages_require_byzantine_sender_activation() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("byzsender_0_0"));
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (= byzsender_0_0 0) (= adv_0_0 0))"));
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (= byzsender_0_0 0) (= adv_0_1 0))"));
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (= byzsender_0_0 0) (= net_forge_0_0 0))"));
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (= byzsender_0_0 0) (= net_forge_0_1 0))"));
        assert!(assertions.iter().any(|a| a == "(<= byzsender_0_0 p_2)"));
    }

    #[test]
    fn byzantine_sender_set_is_static_and_step_activation_is_subset() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica<-P#1[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("byzsender_static_0"));
        assert!(decls.contains("byzsender_static_1"));

        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions
            .iter()
            .any(|a| a == "(<= byzsender_0_0 byzsender_static_0)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(<= byzsender_0_1 byzsender_static_1)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(<= (+ byzsender_static_0 byzsender_static_1) p_2)"));
    }

    #[test]
    fn partial_synchrony_faithful_channels_force_honest_post_gst_delivery() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.add_parameter(Parameter { name: "gst".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.timing_model = TimingModel::PartialSynchrony;
        ta.gst_param = Some(3);
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| {
            a.contains("(=> (and (<= p_3 time_0) (= byzsender_0_0 0))")
                && a.contains(
                    "(= net_deliver_0_0 (+ (+ net_pending_0_0 net_send_0_0) net_forge_0_0))",
                )
        }));
    }

    #[test]
    fn compromised_signing_key_allows_sender_channel_forge_without_byzsender_gate() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.compromised_keys.insert("p_key".into());
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(
            !decls.contains("byzsender_0_0"),
            "compromised key channels should not require byzsender activation"
        );
    }

    #[test]
    fn compromised_key_allows_signed_forge_sat() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.compromised_keys.insert("p_key".into());
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);

        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(sat, SatResult::Sat);
    }

    #[test]
    fn signer_set_threshold_requires_distinct_signer_identities_not_counter_magnitude() {
        let ta = make_signer_set_threshold_ta();
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 2);

        let repeated_single_signer = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(1)),
                SmtTerm::var("p_1").eq(SmtTerm::int(2)),
                SmtTerm::var("p_2").eq(SmtTerm::int(2)),
                SmtTerm::var("delta_0_0").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_1_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_1").eq(SmtTerm::int(0)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_1").eq(SmtTerm::int(0)),
                SmtTerm::var("g_1_0").eq(SmtTerm::int(2)),
                SmtTerm::var("g_1_1").eq(SmtTerm::int(0)),
                SmtTerm::var("g_1_2").eq(SmtTerm::int(0)),
            ],
        );
        assert_eq!(repeated_single_signer, SatResult::Unsat);

        let two_distinct_signers = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(1)),
                SmtTerm::var("p_1").eq(SmtTerm::int(2)),
                SmtTerm::var("p_2").eq(SmtTerm::int(2)),
                SmtTerm::var("delta_0_0").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_1_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_1").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_1").eq(SmtTerm::int(1)),
                SmtTerm::var("g_1_0").eq(SmtTerm::int(1)),
                SmtTerm::var("g_1_1").eq(SmtTerm::int(1)),
                SmtTerm::var("g_1_2").eq(SmtTerm::int(0)),
            ],
        );
        assert_eq!(two_distinct_signers, SatResult::Sat);
    }

    #[test]
    fn forging_signed_message_without_compromise_and_without_byzantine_sender_is_unsat() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("byzsender_0_0"));
        assert!(decls.contains("net_forge_0_0"));

        let baseline_sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
                SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(baseline_sat, SatResult::Sat);

        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(0)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(0)),
                SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(sat, SatResult::Unsat);
    }

    #[test]
    fn forging_crypto_object_family_is_unsat_even_with_byzantine_budget() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_QC@P#0<-P#0[value=false]".into();
        ta.crypto_objects.insert(
            "QC".into(),
            IrCryptoObjectSpec {
                name: "QC".into(),
                kind: IrCryptoObjectKind::QuorumCertificate,
                source_message: "Vote".into(),
                threshold: LinearCombination::constant(1),
                signer_role: Some("P".into()),
                conflict_policy: CryptoConflictPolicy::Allow,
            },
        );

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);

        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
                SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(sat, SatResult::Unsat);
    }

    #[test]
    fn valid_crypto_object_formation_path_is_sat() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_parameter(Parameter { name: "t".into() });
        ta.add_location(Location {
            name: "waiting".into(),
            role: "P".into(),
            phase: "waiting".into(),
            local_vars: IndexMap::new(),
        });
        ta.add_location(Location {
            name: "done".into(),
            role: "P".into(),
            phase: "done".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations = vec![0];
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );

        let vote = ta.add_shared_var(SharedVar {
            name: "cnt_Vote@P#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let qc = ta.add_shared_var(SharedVar {
            name: "cnt_QC@P#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.crypto_objects.insert(
            "QC".into(),
            IrCryptoObjectSpec {
                name: "QC".into(),
                kind: IrCryptoObjectKind::QuorumCertificate,
                source_message: "Vote".into(),
                threshold: LinearCombination::constant(1),
                signer_role: Some("P".into()),
                conflict_policy: CryptoConflictPolicy::Allow,
            },
        );
        ta.add_rule(Rule {
            from: 0,
            to: 0,
            guard: Guard::trivial(),
            updates: vec![Update {
                var: vote,
                kind: UpdateKind::Increment,
            }],
        });
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![vote],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: true,
            }),
            updates: vec![Update {
                var: qc,
                kind: UpdateKind::Increment,
            }],
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 2);
        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(1)),
                SmtTerm::var("p_1").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("delta_0_1").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_1_0").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_1_1").eq(SmtTerm::int(1)),
                SmtTerm::var("g_2_1").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(sat, SatResult::Sat);
    }

    #[test]
    fn exclusive_crypto_policy_blocks_conflicting_variants_in_same_state() {
        let build_ta = |policy: CryptoConflictPolicy| {
            let mut ta = ThresholdAutomaton::new();
            ta.add_parameter(Parameter { name: "n".into() });
            ta.add_parameter(Parameter { name: "t".into() });
            ta.add_location(Location {
                name: "s".into(),
                role: "P".into(),
                phase: "s".into(),
                local_vars: IndexMap::new(),
            });
            ta.initial_locations = vec![0];
            let qc_false = ta.add_shared_var(SharedVar {
                name: "cnt_QC@P#0<-P#0[value=false]".into(),
                kind: SharedVarKind::MessageCounter,
                distinct: false,
                distinct_role: None,
            });
            let qc_true = ta.add_shared_var(SharedVar {
                name: "cnt_QC@P#0<-P#0[value=true]".into(),
                kind: SharedVarKind::MessageCounter,
                distinct: false,
                distinct_role: None,
            });
            ta.add_rule(Rule {
                from: 0,
                to: 0,
                guard: Guard::trivial(),
                updates: vec![Update {
                    var: qc_false,
                    kind: UpdateKind::Increment,
                }],
            });
            ta.add_rule(Rule {
                from: 0,
                to: 0,
                guard: Guard::trivial(),
                updates: vec![Update {
                    var: qc_true,
                    kind: UpdateKind::Increment,
                }],
            });
            ta.crypto_objects.insert(
                "QC".into(),
                IrCryptoObjectSpec {
                    name: "QC".into(),
                    kind: IrCryptoObjectKind::QuorumCertificate,
                    source_message: "Vote".into(),
                    threshold: LinearCombination::constant(1),
                    signer_role: Some("P".into()),
                    conflict_policy: policy,
                },
            );
            ta
        };

        let make_goal = |ta| {
            let cs = CounterSystem::new(ta);
            let property = SafetyProperty::Termination { goal_locs: vec![] };
            encode_bmc(&cs, &property, 1)
        };

        let allow_enc = make_goal(build_ta(CryptoConflictPolicy::Allow));
        let allow_sat = solve_with_extra_assertions(
            &allow_enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(2)),
                SmtTerm::var("p_1").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("delta_0_1").eq(SmtTerm::int(1)),
                SmtTerm::var("g_1_0").gt(SmtTerm::int(0)),
                SmtTerm::var("g_1_1").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(allow_sat, SatResult::Sat);

        let exclusive_enc = make_goal(build_ta(CryptoConflictPolicy::Exclusive));
        let exclusive_sat = solve_with_extra_assertions(
            &exclusive_enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(2)),
                SmtTerm::var("p_1").eq(SmtTerm::int(0)),
                SmtTerm::var("delta_0_0").eq(SmtTerm::int(1)),
                SmtTerm::var("delta_0_1").eq(SmtTerm::int(1)),
                SmtTerm::var("g_1_0").gt(SmtTerm::int(0)),
                SmtTerm::var("g_1_1").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(exclusive_sat, SatResult::Unsat);
    }

    #[test]
    fn full_equivocation_can_split_byzantine_payloads_across_recipients_sat() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.equivocation_mode = EquivocationMode::Full;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_Vote@A#0<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote@B#0<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote@A#0<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote@B#0<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Termination { goal_locs: vec![] };
        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("byzsender_0_0"));

        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_static_0").eq(SmtTerm::int(1)),
                SmtTerm::var("byzsender_0_0").eq(SmtTerm::int(1)),
                // Same Byzantine sender forges different payloads to different recipients.
                SmtTerm::var("net_forge_0_0").gt(SmtTerm::int(0)),
                SmtTerm::var("net_forge_0_3").gt(SmtTerm::int(0)),
            ],
        );
        assert_eq!(sat, SatResult::Sat);
    }

    #[test]
    fn equivocation_none_enforces_sender_scoped_variant_exclusivity() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.equivocation_mode = EquivocationMode::None;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a
            == "(=> (> (+ net_forge_0_0 net_forge_0_1) 0) (= (+ net_forge_0_2 net_forge_0_3) 0))"));
        assert!(assertions.iter().any(|a| a
            == "(=> (> (+ net_forge_0_2 net_forge_0_3) 0) (= (+ net_forge_0_0 net_forge_0_1) 0))"));
    }

    #[test]
    fn equivocation_full_allows_sender_scoped_split_variants() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        ta.authentication_mode = AuthenticationMode::Signed;
        ta.network_semantics = NetworkSemantics::IdentitySelective;
        ta.equivocation_mode = EquivocationMode::Full;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(!assertions.iter().any(|a| a
            == "(=> (> (+ net_forge_0_0 net_forge_0_1) 0) (= (+ net_forge_0_2 net_forge_0_3) 0))"));
    }

    #[test]
    fn crash_model_uses_crash_counter_not_drop_variables() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        let crash_counter = ta.add_shared_var(SharedVar {
            name: "__crashed_count".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Crash;
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(!decls.iter().any(|n| n.starts_with("drop_")));
        assert!(decls.contains("net_pending_0_0"));
        assert!(decls.contains("net_pending_1_0"));
        assert!(decls.contains("net_send_0_0"));
        assert!(decls.contains("net_forge_0_0"));
        assert!(decls.contains("net_deliver_0_0"));
        assert!(decls.contains("net_drop_0_0"));
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
        assert!(assertions.iter().any(|a| a == "(= net_forge_0_0 adv_0_0)"));
        assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 0)"));
        assert!(assertions
            .iter()
            .any(|a| a == &format!("(<= g_1_{} p_2)", crash_counter)));
    }

    #[test]
    fn adversary_bound_is_capped_by_t_in_bmc_and_kinduction() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Byzantine;
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let bmc = encode_bmc(&cs, &property, 1);
        let bmc_assertions: Vec<String> = bmc.assertions.iter().map(to_smtlib).collect();
        assert!(bmc_assertions.iter().any(|a| a == "(<= p_2 p_1)"));

        let step = encode_k_induction_step(&cs, &property, 1);
        let step_assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(step_assertions.iter().any(|a| a == "(<= p_2 p_1)"));
    }

    #[test]
    fn omission_without_bound_forces_zero_injection_and_drops() {
        let mut ta = make_simple_ta();
        ta.fault_model = FaultModel::Omission;
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let decls: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(decls.contains("drop_0_0"));
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
        assert!(assertions.iter().any(|a| a == "(= drop_0_0 0)"));
    }

    #[test]
    fn crash_without_bound_forces_zero_crashes() {
        let mut ta = make_simple_ta();
        let crash_counter = ta.add_shared_var(SharedVar {
            name: "__crashed_count".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });
        ta.fault_model = FaultModel::Crash;
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
        assert!(assertions
            .iter()
            .any(|a| a == &format!("(= g_1_{} 0)", crash_counter)));
    }

    #[test]
    fn kinduction_omission_partial_sync_encodes_drop_bound_and_post_gst_delivery() {
        let mut ta = make_simple_ta();
        ta.add_parameter(Parameter { name: "f".into() });
        ta.add_parameter(Parameter { name: "gst".into() });
        ta.adversary_bound_param = Some(2);
        ta.fault_model = FaultModel::Omission;
        ta.timing_model = TimingModel::PartialSynchrony;
        ta.gst_param = Some(3);
        let cs = CounterSystem::new(ta);
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let step = encode_k_induction_step(&cs, &property, 1);
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(assertions.iter().any(|a| a == "(= adv_0_0 0)"));
        assert!(assertions.iter().any(|a| a == "(<= drop_0_0 p_2)"));
        assert!(assertions.iter().any(|a| a == "(= net_drop_0_0 drop_0_0)"));
        assert!(assertions
            .iter()
            .any(|a| a == "(=> (<= p_3 time_0) (= net_drop_0_0 0))"));
    }

    #[test]
    fn por_mode_off_disables_all_pruning() {
        let mut ta = make_simple_ta();
        // Add a duplicate rule (same signature as rule 0) to test pruning
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0],
                op: CmpOp::Ge,
                bound: LinearCombination {
                    constant: 1,
                    terms: vec![(2, 1)],
                },
                distinct: false,
            }),
            updates: vec![Update {
                var: 0,
                kind: UpdateKind::Increment,
            }],
        });

        // With Full POR, duplicate should be pruned
        ta.por_mode = PorMode::Full;
        let pruning_full = compute_por_rule_pruning(&ta);
        let active_full = pruning_full.active_rule_ids().len();

        // With POR Off, no rules should be pruned
        ta.por_mode = PorMode::Off;
        let pruning_off = compute_por_rule_pruning(&ta);
        assert_eq!(pruning_off.stutter_pruned, 0);
        assert_eq!(pruning_off.commutative_duplicate_pruned, 0);
        assert_eq!(pruning_off.guard_dominated_pruned, 0);
        let active_off = pruning_off.active_rule_ids().len();
        assert_eq!(active_off, ta.rules.len());
        assert!(active_off > active_full);
    }

    // ── canonical_term_key tests ─────────────────────────────────────

    #[test]
    fn canonical_term_key_commutative_add() {
        let ab = SmtTerm::var("a").add(SmtTerm::var("b"));
        let ba = SmtTerm::var("b").add(SmtTerm::var("a"));
        assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
    }

    #[test]
    fn canonical_term_key_commutative_mul() {
        let ab = SmtTerm::var("a").mul(SmtTerm::var("b"));
        let ba = SmtTerm::var("b").mul(SmtTerm::var("a"));
        assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
    }

    #[test]
    fn canonical_term_key_commutative_eq() {
        let ab = SmtTerm::var("a").eq(SmtTerm::var("b"));
        let ba = SmtTerm::var("b").eq(SmtTerm::var("a"));
        assert_eq!(canonical_term_key(&ab), canonical_term_key(&ba));
    }

    #[test]
    fn canonical_term_key_noncommutative_sub() {
        let ab = SmtTerm::var("a").sub(SmtTerm::var("b"));
        let ba = SmtTerm::var("b").sub(SmtTerm::var("a"));
        assert_ne!(canonical_term_key(&ab), canonical_term_key(&ba));
    }

    #[test]
    fn canonical_term_key_noncommutative_lt_le_gt_ge() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        assert_ne!(
            canonical_term_key(&a.clone().lt(b.clone())),
            canonical_term_key(&b.clone().lt(a.clone()))
        );
        assert_ne!(
            canonical_term_key(&a.clone().le(b.clone())),
            canonical_term_key(&b.clone().le(a.clone()))
        );
        assert_ne!(
            canonical_term_key(&a.clone().gt(b.clone())),
            canonical_term_key(&b.clone().gt(a.clone()))
        );
        assert_ne!(
            canonical_term_key(&a.clone().ge(b.clone())),
            canonical_term_key(&b.ge(a))
        );
    }

    #[test]
    fn canonical_term_key_and_or_sorts_children() {
        let xy = SmtTerm::and(vec![SmtTerm::var("x"), SmtTerm::var("y")]);
        let yx = SmtTerm::and(vec![SmtTerm::var("y"), SmtTerm::var("x")]);
        assert_eq!(canonical_term_key(&xy), canonical_term_key(&yx));

        let or_xy = SmtTerm::or(vec![SmtTerm::var("x"), SmtTerm::var("y")]);
        let or_yx = SmtTerm::or(vec![SmtTerm::var("y"), SmtTerm::var("x")]);
        assert_eq!(canonical_term_key(&or_xy), canonical_term_key(&or_yx));
    }

    // ── sum_terms_balanced tests ─────────────────────────────────────

    #[test]
    fn sum_terms_balanced_empty_is_zero() {
        assert_eq!(sum_terms_balanced(vec![]), SmtTerm::int(0));
    }

    #[test]
    fn sum_terms_balanced_single_term() {
        let t = SmtTerm::var("x");
        assert_eq!(sum_terms_balanced(vec![t.clone()]), t);
    }

    #[test]
    fn sum_terms_balanced_two_terms() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        assert_eq!(
            sum_terms_balanced(vec![a.clone(), b.clone()]),
            SmtTerm::Add(Box::new(a), Box::new(b))
        );
    }

    // ── encode_lc tests ──────────────────────────────────────────────

    #[test]
    fn encode_lc_constant_only() {
        let lc = LinearCombination {
            constant: 42,
            terms: vec![],
        };
        assert_eq!(encode_lc(&lc), SmtTerm::int(42));
    }

    #[test]
    fn encode_lc_zero_constant_with_params() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(1, 0)],
        };
        // constant=0 is skipped, only p_0
        assert_eq!(encode_lc(&lc), SmtTerm::var("p_0"));
    }

    #[test]
    fn encode_lc_scaled_param() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(3, 1)],
        };
        assert_eq!(
            encode_lc(&lc),
            SmtTerm::Mul(Box::new(SmtTerm::int(3)), Box::new(SmtTerm::var("p_1")))
        );
    }

    // ── encode_threshold_guard tests ─────────────────────────────────

    #[test]
    fn encode_threshold_guard_distinct_uses_ite() {
        let term = encode_threshold_guard_at_step(
            0,
            &[0, 1],
            CmpOp::Ge,
            &LinearCombination::constant(2),
            true,
        );
        let s = to_smtlib(&term);
        assert!(s.contains("ite"), "distinct guard should use ite: {s}");
    }

    #[test]
    fn encode_threshold_guard_ne_uses_not_eq() {
        let term = encode_threshold_guard_at_step(
            0,
            &[0],
            CmpOp::Ne,
            &LinearCombination::constant(1),
            false,
        );
        let s = to_smtlib(&term);
        assert!(s.contains("not"), "Ne guard should use Not: {s}");
        assert!(s.contains("="), "Ne guard should use Eq inside Not: {s}");
    }

    // ── encode_property_violation tests ──────────────────────────────

    #[test]
    fn encode_property_violation_empty_pairs_is_false() {
        let ta = make_simple_ta();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let term = encode_property_violation(&ta, &property, 2);
        assert_eq!(term, SmtTerm::bool(false));
    }

    #[test]
    fn encode_property_violation_agreement_single_pair() {
        let ta = make_simple_ta();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0, 1)],
        };
        let term = encode_property_violation_at_step(&ta, &property, 0);
        let s = to_smtlib(&term);
        assert!(s.contains("kappa_0_0"), "should reference loc 0: {s}");
        assert!(s.contains("kappa_0_1"), "should reference loc 1: {s}");
    }

    // ── proptest ─────────────────────────────────────────────────────

    use proptest::prelude::*;
    use tarsier_ir::proptest_generators::arb_threshold_automaton;

    fn arb_ta_and_property() -> impl Strategy<Value = (CounterSystem, SafetyProperty, usize)> {
        arb_threshold_automaton()
            .prop_flat_map(|ta| {
                let nlocs = ta.locations.len();
                let cs = CounterSystem::new(ta);
                // depth 0-3
                (Just(cs), Just(nlocs), 0..=3usize)
            })
            .prop_map(|(cs, nlocs, depth)| {
                // Generate a trivially-empty agreement property (safe for any TA)
                let property = if nlocs >= 2 {
                    SafetyProperty::Agreement {
                        conflicting_pairs: vec![(0, 1)],
                    }
                } else {
                    SafetyProperty::Agreement {
                        conflicting_pairs: vec![],
                    }
                };
                (cs, property, depth)
            })
    }

    fn smt_proptest_config() -> ProptestConfig {
        ProptestConfig {
            cases: 32,
            source_file: Some(file!()),
            failure_persistence: Some(Box::new(
                proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
            )),
            rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
            ..ProptestConfig::default()
        }
    }

    fn collect_all_var_refs(term: &SmtTerm, out: &mut std::collections::HashSet<String>) {
        match term {
            SmtTerm::Var(name) => {
                out.insert(name.clone());
            }
            SmtTerm::IntLit(_) | SmtTerm::BoolLit(_) => {}
            SmtTerm::Add(l, r)
            | SmtTerm::Sub(l, r)
            | SmtTerm::Mul(l, r)
            | SmtTerm::Eq(l, r)
            | SmtTerm::Lt(l, r)
            | SmtTerm::Le(l, r)
            | SmtTerm::Gt(l, r)
            | SmtTerm::Ge(l, r)
            | SmtTerm::Implies(l, r) => {
                collect_all_var_refs(l, out);
                collect_all_var_refs(r, out);
            }
            SmtTerm::And(ts) | SmtTerm::Or(ts) => {
                for t in ts {
                    collect_all_var_refs(t, out);
                }
            }
            SmtTerm::Not(inner) => collect_all_var_refs(inner, out),
            SmtTerm::ForAll(_, body) | SmtTerm::Exists(_, body) => {
                collect_all_var_refs(body, out);
            }
            SmtTerm::Ite(c, t, e) => {
                collect_all_var_refs(c, out);
                collect_all_var_refs(t, out);
                collect_all_var_refs(e, out);
            }
        }
    }

    proptest! {
        #![proptest_config(smt_proptest_config())]

        #[test]
        fn encode_bmc_never_panics((cs, property, depth) in arb_ta_and_property()) {
            let _enc = encode_bmc(&cs, &property, depth);
        }

        #[test]
        fn encode_bmc_produces_nonempty_encoding((cs, property, depth) in arb_ta_and_property()) {
            let enc = encode_bmc(&cs, &property, depth);
            prop_assert!(!enc.declarations.is_empty(), "declarations must be non-empty");
            prop_assert!(!enc.assertions.is_empty(), "assertions must be non-empty");
        }

        #[test]
        fn encode_bmc_all_declared_vars_appear_in_model_vars((cs, property, depth) in arb_ta_and_property()) {
            let enc = encode_bmc(&cs, &property, depth);
            let model_var_names: std::collections::HashSet<_> =
                enc.model_vars.iter().map(|(n, _)| n.clone()).collect();
            for (name, _) in &enc.declarations {
                prop_assert!(
                    model_var_names.contains(name),
                    "declared var {} not in model_vars", name
                );
            }
        }

        #[test]
        fn encode_bmc_assertions_are_structurally_valid((cs, property, depth) in arb_ta_and_property()) {
            let enc = encode_bmc(&cs, &property, depth);
            let declared: std::collections::HashSet<_> =
                enc.declarations.iter().map(|(n, _)| n.clone()).collect();
            // Collect all var references from assertions
            let mut referenced = std::collections::HashSet::new();
            for assertion in &enc.assertions {
                collect_all_var_refs(assertion, &mut referenced);
            }
            // Every referenced variable must be declared
            for var_name in &referenced {
                prop_assert!(
                    declared.contains(var_name),
                    "undeclared variable {} referenced in assertions", var_name
                );
            }
        }
    }

    // ── Parse-and-lower integration tests ─────────────────────────────

    fn parse_and_lower(source: &str) -> CounterSystem {
        let program = tarsier_dsl::parse(source, "test.trs").unwrap();
        let ta = tarsier_ir::lowering::lower(&program).unwrap();
        CounterSystem::new(ta)
    }

    const RELIABLE_BROADCAST_SAFE: &str = r#"
protocol RB {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
    }

    message Init;
    message Echo;
    message Ready;

    role Process {
        var accepted: bool = false;
        var decided: bool = false;
        var decision: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Init => {
                accepted = true;
                send Echo;
                goto phase echoed;
            }
        }

        phase echoed {
            when received >= 2*t+1 Echo => {
                send Ready;
                goto phase readied;
            }
        }

        phase readied {
            when received >= 2*t+1 Ready => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

    const BUGGY_BROADCAST: &str = r#"
protocol BuggyBroadcast {
    params n, t, f;
    resilience: n > 3*t;

    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Commit;
    message Abort;

    role Process {
        var decided: bool = false;
        var decision: bool = false;

        init propose;

        phase propose {
            when received >= 1 Vote => {
                send Vote;
                goto phase voted;
            }
            when received >= 1 Abort => {
                decision = false;
                decided = true;
                goto phase done_no;
            }
        }

        phase voted {
            when received >= t+1 Vote => {
                send Commit;
                goto phase ready_yes;
            }
        }

        phase ready_yes {
            when received >= t+1 Commit => {
                decision = true;
                decided = true;
                goto phase done_yes;
            }
        }

        phase done_yes {}
        phase done_no {}
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

    #[test]
    fn parsed_protocol_encoding_has_expected_param_declarations() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let decl_names: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        // Should have parameter variables for n, t, f
        assert!(decl_names.contains("p_0"), "missing param p_0 (n)");
        assert!(decl_names.contains("p_1"), "missing param p_1 (t)");
        assert!(decl_names.contains("p_2"), "missing param p_2 (f)");
    }

    #[test]
    fn parsed_protocol_encoding_has_kappa_gamma_delta_time_vars() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let decl_names: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();
        let num_locs = cs.num_locations();
        let num_svars = cs.num_shared_vars();
        let num_rules = cs.num_rules();

        // Step 0 kappa variables
        for l in 0..num_locs {
            assert!(decl_names.contains(&kappa_var(0, l)), "missing kappa_0_{l}");
        }
        // Step 1 kappa variables
        for l in 0..num_locs {
            assert!(decl_names.contains(&kappa_var(1, l)), "missing kappa_1_{l}");
        }
        // Gamma variables at step 0 and 1
        for v in 0..num_svars {
            assert!(decl_names.contains(&gamma_var(0, v)), "missing g_0_{v}");
            assert!(decl_names.contains(&gamma_var(1, v)), "missing g_1_{v}");
        }
        // Delta variables for step 0
        for r in 0..num_rules {
            assert!(decl_names.contains(&delta_var(0, r)), "missing delta_0_{r}");
        }
        // Time variables
        assert!(decl_names.contains(&time_var(0)), "missing time_0");
        assert!(decl_names.contains(&time_var(1)), "missing time_1");
    }

    #[test]
    fn parsed_protocol_initial_state_constraints() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        let ta = &cs.automaton;

        // All shared vars start at 0
        for v in 0..cs.num_shared_vars() {
            let expected = format!("(= g_0_{v} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "missing initial zero constraint for g_0_{v}: {expected}"
            );
        }

        // time_0 = 0
        assert!(
            assertions.iter().any(|a| a == "(= time_0 0)"),
            "missing time_0 = 0"
        );

        // Non-initial locations start empty
        for l in 0..cs.num_locations() {
            if !ta.initial_locations.contains(&l) {
                let expected = format!("(= kappa_0_{l} 0)");
                assert!(
                    assertions.iter().any(|a| a == &expected),
                    "non-initial loc {l} should start at 0: {expected}"
                );
            }
        }

        // Parameters are non-negative
        for i in 0..cs.num_parameters() {
            let expected = format!("(>= p_{i} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "missing non-negative param constraint: {expected}"
            );
        }
    }

    #[test]
    fn parsed_protocol_transition_location_updates() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

        // For each location, kappa_{k+1}_l depends on kappa_k_l plus incoming minus outgoing.
        // At minimum, each kappa_1_l should appear in an equality assertion.
        for l in 0..cs.num_locations() {
            let kappa_next = format!("kappa_1_{l}");
            let has_update = assertions
                .iter()
                .any(|a| a.starts_with(&format!("(= {kappa_next}")));
            assert!(
                has_update,
                "missing location counter update for kappa_1_{l}"
            );
        }

        // Delta variables are non-negative
        for r in 0..cs.num_rules() {
            let expected = format!("(>= delta_0_{r} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "missing non-negativity for delta_0_{r}"
            );
        }

        // kappa_{k+1}_l >= 0
        for l in 0..cs.num_locations() {
            let expected = format!("(>= kappa_1_{l} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "missing non-negativity for kappa_1_{l}"
            );
        }
    }

    #[test]
    fn parsed_protocol_time_progression() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 2);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

        assert!(
            assertions.iter().any(|a| a == "(= time_1 (+ time_0 1))"),
            "missing time_1 = time_0 + 1"
        );
        assert!(
            assertions.iter().any(|a| a == "(= time_2 (+ time_1 1))"),
            "missing time_2 = time_1 + 1"
        );
    }

    #[test]
    fn encoding_depth_scales_declarations() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);

        let enc1 = encode_bmc(&cs, &property, 1);
        let enc2 = encode_bmc(&cs, &property, 2);
        let enc4 = encode_bmc(&cs, &property, 4);

        // More depth = more declarations and assertions
        assert!(
            enc2.declarations.len() > enc1.declarations.len(),
            "depth 2 should have more declarations than depth 1: {} vs {}",
            enc2.declarations.len(),
            enc1.declarations.len()
        );
        assert!(
            enc4.declarations.len() > enc2.declarations.len(),
            "depth 4 should have more declarations than depth 2: {} vs {}",
            enc4.declarations.len(),
            enc2.declarations.len()
        );
        assert!(
            enc2.assertions.len() > enc1.assertions.len(),
            "depth 2 should have more assertions than depth 1"
        );
        assert!(
            enc4.assertions.len() > enc2.assertions.len(),
            "depth 4 should have more assertions than depth 2"
        );

        // Verify depth-specific variables exist
        let decl4: std::collections::HashSet<_> =
            enc4.declarations.iter().map(|(n, _)| n.clone()).collect();
        // Step 4 kappa variables should exist
        assert!(decl4.contains(&kappa_var(4, 0)));
        // Step 3 delta variables should exist (transitions 0..3)
        assert!(decl4.contains(&delta_var(3, 0)));
        // Time variable at step 4
        assert!(decl4.contains(&time_var(4)));
    }

    #[test]
    fn k_induction_step_parsed_protocol() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);

        let step = encode_k_induction_step(&cs, &property, 2);

        // k-induction step should have declarations for steps 0..=k
        let decl_names: std::collections::HashSet<_> =
            step.declarations.iter().map(|(n, _)| n.clone()).collect();
        // Should have kappa at all three steps (0, 1, 2)
        for s in 0..=2 {
            for l in 0..cs.num_locations() {
                assert!(
                    decl_names.contains(&kappa_var(s, l)),
                    "k-induction step missing kappa_{s}_{l}"
                );
            }
        }
        // Delta variables for steps 0..k-1 (i.e., step 0 and step 1)
        for s in 0..2 {
            for r in 0..cs.num_rules() {
                assert!(
                    decl_names.contains(&delta_var(s, r)),
                    "k-induction step missing delta_{s}_{r}"
                );
            }
        }

        // k-induction does NOT constrain step 0 to be initial
        // so there should be no "kappa_0_l = 0" for non-initial locations
        // as there is in BMC. Instead, kappa_0 values are free.
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();

        // But it should still have non-negativity for all kappa
        for l in 0..cs.num_locations() {
            let expected = format!("(>= kappa_0_{l} 0)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "k-induction step missing non-negativity for kappa_0_{l}"
            );
        }
    }

    #[test]
    fn parsed_protocol_property_violation_agreement() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);

        // The agreement property should have conflicting pairs
        // (at least for protocols with multiple decision phases)
        match &property {
            SafetyProperty::Agreement { conflicting_pairs } => {
                // Reliable broadcast has a single decision value, so
                // conflicting_pairs might be empty (single phase).
                // Regardless, the encoding should work.
                let enc = encode_bmc(&cs, &property, 1);
                if conflicting_pairs.is_empty() {
                    // Violation should be trivially false => UNSAT
                    let sat = solve_with_extra_assertions(
                        &enc,
                        &[
                            SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                            SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                            SmtTerm::var("p_2").eq(SmtTerm::int(1)),
                        ],
                    );
                    assert_eq!(sat, SatResult::Unsat);
                }
            }
            _ => panic!("expected Agreement property"),
        }
    }

    #[test]
    fn parsed_buggy_protocol_violation_is_reachable() {
        let cs = parse_and_lower(BUGGY_BROADCAST);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);

        // The buggy protocol should have conflicting pairs (done_yes vs done_no)
        match &property {
            SafetyProperty::Agreement { conflicting_pairs } => {
                assert!(
                    !conflicting_pairs.is_empty(),
                    "buggy protocol should have conflicting decision pairs"
                );
            }
            _ => panic!("expected Agreement property"),
        }

        // At sufficient depth, the violation should be SAT (reachable)
        let enc = encode_bmc(&cs, &property, 4);
        let sat = solve_with_extra_assertions(
            &enc,
            &[
                SmtTerm::var("p_0").eq(SmtTerm::int(4)),
                SmtTerm::var("p_1").eq(SmtTerm::int(1)),
                SmtTerm::var("p_2").eq(SmtTerm::int(1)),
            ],
        );
        assert_eq!(
            sat,
            SatResult::Sat,
            "buggy protocol agreement violation should be reachable"
        );
    }

    #[test]
    fn parsed_protocol_adversary_injection_bounded() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

        // The adversary bound parameter (f = p_2) should cap each adv variable
        for v in 0..cs.num_shared_vars() {
            let expected = format!("(<= adv_0_{v} p_2)");
            assert!(
                assertions.iter().any(|a| a == &expected),
                "missing adversary bound for adv_0_{v}: {expected}"
            );
        }

        // f <= t constraint
        assert!(
            assertions.iter().any(|a| a == "(<= p_2 p_1)"),
            "missing f <= t constraint"
        );
    }

    #[test]
    fn depth_zero_encoding_checks_only_initial_state() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 0);
        let decl_names: std::collections::HashSet<_> =
            enc.declarations.iter().map(|(n, _)| n.clone()).collect();

        // At depth 0, there are no transition steps, so no delta variables
        assert!(
            !decl_names.iter().any(|n| n.starts_with("delta_")),
            "depth 0 should have no delta variables"
        );

        // Should still have step 0 kappa and gamma
        assert!(decl_names.contains(&kappa_var(0, 0)));
        assert!(decl_names.contains(&gamma_var(0, 0)));
        assert!(decl_names.contains(&time_var(0)));
    }

    #[test]
    fn property_violation_invariant_encoding() {
        let ta = make_simple_ta();
        // Invariant: bad set = both locations occupied
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![0, 1]],
        };
        let term = encode_property_violation_at_step(&ta, &property, 0);
        let s = to_smtlib(&term);
        assert!(
            s.contains("kappa_0_0") && s.contains("kappa_0_1"),
            "invariant violation should reference both locations: {s}"
        );
    }

    #[test]
    fn property_violation_termination_encoding() {
        let ta = make_simple_ta();
        // Termination: goal is location 1 (done)
        let property = SafetyProperty::Termination { goal_locs: vec![1] };
        let term = encode_property_violation_at_step(&ta, &property, 0);
        let s = to_smtlib(&term);
        // Termination violation means some process is NOT in a goal location
        // So kappa_0_0 > 0 should appear (location 0 is not a goal)
        assert!(
            s.contains("kappa_0_0"),
            "termination violation should reference non-goal location: {s}"
        );
    }

    #[test]
    fn property_violation_empty_invariant_is_false() {
        let ta = make_simple_ta();
        let property = SafetyProperty::Invariant { bad_sets: vec![] };
        let term = encode_property_violation(&ta, &property, 2);
        assert_eq!(term, SmtTerm::bool(false));
    }

    #[test]
    fn dedup_stats_are_consistent() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 2);

        assert_eq!(
            enc.assertion_candidates(),
            enc.assertion_unique() + enc.assertion_dedup_hits(),
            "candidates should equal unique + dedup hits"
        );
        assert!(
            enc.assertion_unique() > 0,
            "should have at least one unique assertion"
        );
    }

    #[test]
    fn resilience_condition_encoded_from_parsed_protocol() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();

        // Resilience condition: n > 3*t should appear as (> p_0 (* 3 p_1))
        let has_resilience = assertions.iter().any(|a| {
            a.contains("p_0") && a.contains("p_1") && (a.contains(">") || a.contains("<"))
        });
        assert!(
            has_resilience,
            "missing resilience condition encoding involving p_0 and p_1"
        );
    }

    #[test]
    fn k_induction_step_has_conservation_strengthening() {
        let cs = parse_and_lower(RELIABLE_BROADCAST_SAFE);
        let property = tarsier_ir::properties::extract_agreement_property(&cs.automaton);
        let step = encode_k_induction_step(&cs, &property, 1);
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();

        // k-induction step should have process conservation: sum of kappa = n
        // This appears as an equality involving p_0 (the n parameter)
        let has_conservation = assertions
            .iter()
            .any(|a| a.contains("kappa_0_") && a.contains("p_0") && a.contains("="));
        assert!(
            has_conservation,
            "k-induction step should have process conservation strengthening"
        );
    }
}
