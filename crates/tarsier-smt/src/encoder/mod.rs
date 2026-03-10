//! BMC encoder: translates a [`CounterSystem`] and [`SafetyProperty`] into a
//! quantifier-free linear integer arithmetic (QF_LIA) encoding suitable for
//! bounded model checking, k-induction, and PDR/IC3.
//!
//! The main entry point is [`encode_bmc`], which produces a [`BmcEncoding`]
//! containing variable declarations and assertions that can be fed to any
//! [`SmtSolver`](crate::solver::SmtSolver) backend.

mod context;
mod k_induction;
mod por;
mod variables;

pub use k_induction::encode_k_induction_step;
pub(crate) use variables::{delta_var, gamma_var, kappa_var, time_var};

use context::{build_common_encoder_context, CommonEncoderContext};
use k_induction::encode_property_violation;
#[cfg(test)]
use k_induction::encode_property_violation_at_step;
use por::*;
use variables::*;

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

    /// Register a variable declaration and add it to the model-extraction list.
    fn declare(&mut self, name: String, sort: SmtSort) {
        self.model_vars.push((name.clone(), sort.clone()));
        self.declarations.push((name, sort));
    }

    /// Assert a constraint, deduplicating by canonical term key.
    fn assert_term(&mut self, term: SmtTerm) {
        self.assertion_candidates = self.assertion_candidates.saturating_add(1);
        let key = canonical_term_key(&term);
        if self.assertion_keys.insert(key) {
            self.assertions.push(term);
        } else {
            self.assertion_dedup_hits = self.assertion_dedup_hits.saturating_add(1);
        }
    }

    /// Total number of assertions considered before deduplication.
    pub fn assertion_candidates(&self) -> usize {
        self.assertion_candidates
    }

    /// Number of unique assertions after deduplication.
    pub fn assertion_unique(&self) -> usize {
        self.assertions.len()
    }

    /// Number of duplicate assertions that were discarded.
    pub fn assertion_dedup_hits(&self) -> usize {
        self.assertion_dedup_hits
    }
}

/// Canonical key for commutative binary operators — sorts operands lexicographically.
fn canonical_binary_commutative(tag: &str, lhs: &SmtTerm, rhs: &SmtTerm) -> String {
    let left = canonical_term_key(lhs);
    let right = canonical_term_key(rhs);
    if left <= right {
        format!("({tag} {left} {right})")
    } else {
        format!("({tag} {right} {left})")
    }
}

/// Compute a canonical string key for an [`SmtTerm`] for assertion deduplication.
///
/// Normalizes commutative operators so `a+b` and `b+a` produce the same key,
/// and sorts conjuncts/disjuncts to catch reorderings.
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

/// Encode the full BMC problem up to a given depth.
///
/// Produces a QF_LIA encoding in several phases:
/// 1. Parameter declarations and resilience constraints (n > 3t, etc.)
/// 2. Initial state — counter distribution across locations and shared-var values
/// 3. Per-step transition relation — rule deltas, guards, shared-var updates
/// 4. Fault model (Byzantine / Omission / Crash) and network semantics
/// 5. Property-violation encoding (negation of the safety property at each step)
///
/// The final assertion in the returned [`BmcEncoding`] is the property-violation
/// disjunction; callers typically push/assert it under a scope so the base
/// constraints can be reused across depths.
pub fn encode_bmc(cs: &CounterSystem, property: &SafetyProperty, max_depth: usize) -> BmcEncoding {
    BmcEncoderBuilder::new(cs, property, max_depth).build()
}

struct BmcEncoderBuilder<'a> {
    ta: &'a ThresholdAutomaton,
    property: &'a SafetyProperty,
    max_depth: usize,
    enc: BmcEncoding,
    context: CommonEncoderContext,
}

impl<'a> BmcEncoderBuilder<'a> {
    fn new(cs: &'a CounterSystem, property: &'a SafetyProperty, max_depth: usize) -> Self {
        Self {
            ta: cs,
            property,
            max_depth,
            enc: BmcEncoding::new(),
            context: build_common_encoder_context(cs),
        }
    }

    fn build(mut self) -> BmcEncoding {
        self.phase_declare_parameters_and_resilience();
        self.phase_declare_initial_state();
        self.phase_encode_transitions_and_fault_bounds();
        self.phase_encode_property_violation();
        self.enc
    }

    pub(super) fn phase_declare_parameters_and_resilience(&mut self) {
        let ta = self.ta;
        let num_params = self.context.num_params;
        let enc = &mut self.enc;
        // 1. Declare parameter variables
        for i in 0..num_params {
            enc.declare(param_var(i), SmtSort::Int);
            // Parameters are non-negative
            enc.assert_term(SmtTerm::var(param_var(i)).ge(SmtTerm::int(0)));
        }

        // 1b. For time-varying parameters, declare step-0 variables and equate to initial values
        for &i in &self.context.time_varying_param_ids {
            enc.declare(param_var_at_step(0, i), SmtSort::Int);
            // p_i_0 = p_i (initial value)
            enc.assert_term(SmtTerm::var(param_var_at_step(0, i)).eq(SmtTerm::var(param_var(i))));
        }

        // 2. Encode resilience condition
        if let Some(ref rc) = ta.constraints.resilience_condition {
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
    }

    pub(super) fn phase_declare_initial_state(&mut self) {
        let ta = self.ta;
        let num_locs = self.context.num_locs;
        let num_svars = self.context.num_svars;
        let num_params = self.context.num_params;
        let distinct_vars = &self.context.distinct_vars;
        let n_param = self.context.n_param;
        let role_pop_params = &self.context.role_pop_params;
        let process_id_buckets = &self.context.process_id_buckets;
        let missing_process_ids = self.context.missing_process_ids;
        let byzantine_faults = self.context.byzantine_faults;
        let signed_sender_channels = &self.context.signed_sender_channels;
        let message_counter_flags = &self.context.message_counter_flags;
        let enc = &mut self.enc;
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
        for (v, role) in distinct_vars {
            if let Some(role) = role {
                if let Some(&pid) = role_pop_params.get(role) {
                    enc.assert_term(
                        SmtTerm::var(gamma_var(0, *v)).le(SmtTerm::var(param_var(pid))),
                    );
                    continue;
                }
            }
            if let Some(n_param) = n_param {
                enc.assert_term(
                    SmtTerm::var(gamma_var(0, *v)).le(SmtTerm::var(param_var(n_param))),
                );
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

                if ta.initial_locations.contains(&LocationId::from(l)) {
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

        // Leader role constraint at step 0: exactly one process in leader locations.
        for leader_locs in &self.context.leader_role_locs {
            let parts: Vec<SmtTerm> = leader_locs
                .iter()
                .map(|&l| SmtTerm::var(kappa_var(0, l)))
                .collect();
            if !parts.is_empty() {
                enc.assert_term(sum_terms_balanced(parts).eq(SmtTerm::int(1)));
            }
        }

        // Shared vars start at 0
        for v in 0..num_svars {
            enc.assert_term(SmtTerm::var(gamma_var(0, v)).eq(SmtTerm::int(0)));
        }
        // Clocks start at 0.
        for c in 0..ta.clocks.len() {
            let name = clock_var(0, c);
            enc.declare(name.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(name.clone()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(name).eq(SmtTerm::int(0)));
        }
        enc.assert_term(SmtTerm::var(time_var(0)).eq(SmtTerm::int(0)));

        // DAG rounds: inactive at step 0.
        for rid in 0..ta.dag_rounds.len() {
            let active = dag_round_active_var(0, rid);
            enc.declare(active.clone(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(active.clone()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(active.clone()).le(SmtTerm::int(1)));
            enc.assert_term(SmtTerm::var(active).eq(SmtTerm::int(0)));
        }

        // Bounded collections: declare and initialize length variables at step 0
        for (cid, spec) in ta.collections.iter().enumerate() {
            enc.declare(coll_len_var(0, cid), SmtSort::Int);
            // Length starts at 0
            enc.assert_term(SmtTerm::var(coll_len_var(0, cid)).eq(SmtTerm::int(0)));
            // Length bounded by capacity
            let cap = encode_lc(&spec.capacity);
            enc.assert_term(SmtTerm::var(coll_len_var(0, cid)).le(cap));

            // FIFO channels: declare and initialize head/tail indices
            if spec.queue_model == QueueModel::LinearFifo {
                enc.declare(queue_head_var(0, cid), SmtSort::Int);
                enc.declare(queue_tail_var(0, cid), SmtSort::Int);
                enc.assert_term(SmtTerm::var(queue_head_var(0, cid)).eq(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(queue_tail_var(0, cid)).eq(SmtTerm::int(0)));
            }
        }
        if missing_process_ids {
            enc.assert_term(SmtTerm::bool(false));
        }
        if let Some(buckets) = &process_id_buckets {
            assert_process_identity_uniqueness(enc, 0, buckets);
        }
        if byzantine_faults {
            for (sender_idx, _) in signed_sender_channels.iter().enumerate() {
                let static_name = byz_sender_static_var(sender_idx);
                enc.declare(static_name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(static_name.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(static_name).le(SmtTerm::int(1)));
            }
        }
    }

    pub(super) fn phase_encode_transitions_and_fault_bounds(&mut self) {
        let ta = self.ta;
        let max_depth = self.max_depth;
        let num_locs = self.context.num_locs;
        let num_svars = self.context.num_svars;
        let num_rules = self.context.num_rules;
        let por_pruning = &self.context.por_pruning;
        let active_rule_ids = &self.context.active_rule_ids;
        let distinct_vars = &self.context.distinct_vars;
        let omission_style_faults = self.context.omission_style_faults;
        let crash_faults = self.context.crash_faults;
        let crash_recovery = self.context.crash_recovery;
        let byzantine_faults = self.context.byzantine_faults;
        let selective_network = self.context.selective_network;
        let lossy_delivery = self.context.lossy_delivery;
        let crash_counter_var = self.context.crash_counter_var;
        let dead_loc_ids = &self.context.dead_loc_ids;
        let n_param = self.context.n_param;
        let role_pop_params = &self.context.role_pop_params;
        let role_loc_ids = &self.context.role_loc_ids;
        let process_id_buckets = &self.context.process_id_buckets;
        let message_family_recipients = &self.context.message_family_recipients;
        let signed_senderless_vars = &self.context.signed_senderless_vars;
        let signed_uncompromised_sender_vars = &self.context.signed_uncompromised_sender_vars;
        let family_sender_variant_vars = &self.context.family_sender_variant_vars;
        let family_sender_variants_vec = &self.context.family_sender_variants_vec;
        let signed_sender_channels = &self.context.signed_sender_channels;
        let crypto_object_counter_vars = &self.context.crypto_object_counter_vars;
        let exclusive_crypto_variant_groups = &self.context.exclusive_crypto_variant_groups;
        let message_variant_groups = &self.context.message_variant_groups;
        let message_family_variants = &self.context.message_family_variants;
        let recipient_groups = &self.context.recipient_groups;
        let all_message_counter_vars = &self.context.all_message_counter_vars;
        let message_counter_flags = &self.context.message_counter_flags;
        let dag_parent_indices: Vec<Vec<usize>> = {
            let index: HashMap<&str, usize> = ta
                .dag_rounds
                .iter()
                .enumerate()
                .map(|(i, r)| (r.name.as_str(), i))
                .collect();
            ta.dag_rounds
                .iter()
                .map(|r| {
                    r.parent_rounds
                        .iter()
                        .filter_map(|p| index.get(p.as_str()).copied())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let signed_uncompromised_sender_idx_by_var =
            &self.context.signed_uncompromised_sender_idx_by_var;
        let time_varying_param_ids = &self.context.time_varying_param_ids;
        let enc = &mut self.enc;
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
            for c in 0..ta.clocks.len() {
                let name = clock_var(k + 1, c);
                enc.declare(name.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(name).ge(SmtTerm::int(0)));
            }
            enc.declare(time_var(k + 1), SmtSort::Int);
            for (v, role) in distinct_vars {
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

            // DAG round execution model:
            // - Activation flags are booleans encoded as Int in {0,1}.
            // - Activation is monotonic over time.
            // - Child activation at step k+1 requires each parent active at step k.
            for (rid, parents) in dag_parent_indices.iter().enumerate() {
                let curr = dag_round_active_var(k, rid);
                let next = dag_round_active_var(k + 1, rid);
                enc.declare(next.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(next.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(next.clone()).le(SmtTerm::int(1)));
                enc.assert_term(SmtTerm::var(next.clone()).ge(SmtTerm::var(curr)));
                for parent_id in parents {
                    enc.assert_term(
                        SmtTerm::var(next.clone())
                            .le(SmtTerm::var(dag_round_active_var(k, *parent_id))),
                    );
                }
            }
            if let Some(buckets) = &process_id_buckets {
                assert_process_identity_uniqueness(enc, k + 1, buckets);
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
            if selective_network && ta.semantics.delivery_control == DeliveryControlMode::Global {
                for group_vars in message_variant_groups {
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
                                SmtTerm::var(drop_var(k, other))
                                    .eq(SmtTerm::var(drop_var(k, first))),
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
                for &r in active_rule_ids {
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

            // Leader role constraint at step k+1: exactly one process in leader locations.
            for leader_locs in &self.context.leader_role_locs {
                let parts: Vec<SmtTerm> = leader_locs
                    .iter()
                    .map(|&l| SmtTerm::var(kappa_var(k + 1, l)))
                    .collect();
                if !parts.is_empty() {
                    enc.assert_term(sum_terms_balanced(parts).eq(SmtTerm::int(1)));
                }
            }

            // Guard enablement: delta_k_r > 0 → guard is satisfied
            for &r in active_rule_ids {
                let rule = &ta.rules[r];
                let dr_pos = SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0));

                for atom in &rule.guard.atoms {
                    let guard_term = match atom {
                        GuardAtom::Threshold {
                            vars,
                            op,
                            bound,
                            distinct,
                        } => {
                            if time_varying_param_ids.is_empty() {
                                encode_threshold_guard_at_step(k, vars, *op, bound, *distinct)
                            } else {
                                encode_threshold_guard_at_step_epoch(
                                    k,
                                    vars,
                                    *op,
                                    bound,
                                    *distinct,
                                    time_varying_param_ids,
                                )
                            }
                        }
                    };
                    enc.assert_term(dr_pos.clone().implies(guard_term));
                }
                for guard in &rule.clock_guards {
                    let lhs = SmtTerm::var(clock_var(k, guard.clock.as_usize()));
                    let rhs = encode_lc(&guard.bound);
                    let guard_term = match guard.op {
                        CmpOp::Ge => lhs.ge(rhs),
                        CmpOp::Gt => lhs.gt(rhs),
                        CmpOp::Le => lhs.le(rhs),
                        CmpOp::Lt => lhs.lt(rhs),
                        CmpOp::Eq => lhs.eq(rhs),
                        CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
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

            // Clock updates and frame conditions.
            for c in 0..ta.clocks.len() {
                let curr = SmtTerm::var(clock_var(k, c));
                let next = SmtTerm::var(clock_var(k + 1, c));
                let mut updating_rules = Vec::new();
                for &r in active_rule_ids {
                    if ta.rules[r]
                        .clock_updates
                        .iter()
                        .any(|u| u.clock.as_usize() == c)
                    {
                        updating_rules.push(r);
                        let mut updated = curr.clone();
                        for upd in ta.rules[r]
                            .clock_updates
                            .iter()
                            .filter(|u| u.clock.as_usize() == c)
                        {
                            match &upd.kind {
                                ClockUpdateKind::Reset => {
                                    updated = SmtTerm::int(0);
                                }
                                ClockUpdateKind::TickBy(delta) => {
                                    updated = updated.add(encode_lc(delta));
                                }
                            }
                        }
                        let fired = SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0));
                        enc.assert_term(fired.implies(next.clone().eq(updated)));
                    }
                }
                if updating_rules.is_empty() {
                    enc.assert_term(next.eq(curr));
                } else {
                    let no_updates = SmtTerm::and(
                        updating_rules
                            .iter()
                            .map(|r| SmtTerm::var(delta_var(k, *r)).eq(SmtTerm::int(0)))
                            .collect(),
                    );
                    enc.assert_term(no_updates.implies(next.eq(curr)));
                }
            }

            // Shared variable updates (including adversary injection and omission drops)
            for v in 0..num_svars {
                let is_message_counter = message_counter_flags.get(v).copied().unwrap_or(false);
                let adv_term = SmtTerm::var(format!("adv_{k}_{v}"));
                let drop_term = lossy_delivery.then(|| SmtTerm::var(drop_var(k, v)));
                let net_deliver_term =
                    is_message_counter.then(|| SmtTerm::var(net_deliver_var(k, v)));
                let mut sent_parts = Vec::new();

                for &r in active_rule_ids {
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
                                    let set_val = if time_varying_param_ids.is_empty() {
                                        encode_lc(lc)
                                    } else {
                                        encode_lc_at_step(lc, k, time_varying_param_ids)
                                    };
                                    enc.assert_term(
                                        dr_pos
                                            .implies(SmtTerm::var(gamma_var(k + 1, v)).eq(set_val)),
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
                    if ta.semantics.timing_model == TimingModel::PartialSynchrony
                        && selective_network
                    {
                        if let Some(gst_pid) = ta.semantics.gst_param {
                            let post_gst =
                                SmtTerm::var(param_var(gst_pid)).le(SmtTerm::var(time_var(k)));
                            if byzantine_faults {
                                if let Some(sender_idx) = signed_uncompromised_sender_idx_by_var
                                    .get(v)
                                    .copied()
                                    .flatten()
                                {
                                    let honest_sender = SmtTerm::var(byz_sender_var(k, sender_idx))
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
                    if ta.semantics.timing_model == TimingModel::PartialSynchrony
                        && lossy_delivery
                        && ta.semantics.gst_param.is_some()
                    {
                        if let Some(gst_pid) = ta.semantics.gst_param {
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
                    for (var_id, role) in distinct_vars {
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
                            for &r in active_rule_ids {
                                let rule = &ta.rules[r];
                                if rule.updates.iter().any(|u| u.var == v) {
                                    let from_role = &ta.locations[rule.from.as_usize()].role;
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
                            if ta.semantics.timing_model == TimingModel::PartialSynchrony {
                                if let Some(gst_pid) = ta.semantics.gst_param {
                                    let post_gst = SmtTerm::var(param_var(gst_pid))
                                        .le(SmtTerm::var(time_var(k)));
                                    enc.assert_term(
                                        post_gst.implies(drop_term.eq(SmtTerm::int(0))),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Bounded collection length updates for step k → k+1
            for (cid, spec) in ta.collections.iter().enumerate() {
                enc.declare(coll_len_var(k + 1, cid), SmtSort::Int);
                enc.assert_term(SmtTerm::var(coll_len_var(k + 1, cid)).ge(SmtTerm::int(0)));
                let cap = encode_lc(&spec.capacity);
                enc.assert_term(SmtTerm::var(coll_len_var(k + 1, cid)).le(cap.clone()));

                if spec.queue_model == QueueModel::LinearFifo {
                    // FIFO queue: track head and tail separately
                    enc.declare(queue_head_var(k + 1, cid), SmtSort::Int);
                    enc.declare(queue_tail_var(k + 1, cid), SmtSort::Int);

                    // Collect enqueue and dequeue deltas
                    let mut enqueue_deltas: Vec<SmtTerm> = Vec::new();
                    let mut dequeue_deltas: Vec<SmtTerm> = Vec::new();
                    for &r in active_rule_ids {
                        for cu in &ta.rules[r].collection_updates {
                            if cu.collection.as_usize() == cid {
                                match &cu.kind {
                                    CollectionUpdateKind::Enqueue(_) => {
                                        enqueue_deltas.push(SmtTerm::var(delta_var(k, r)));
                                    }
                                    CollectionUpdateKind::Dequeue => {
                                        dequeue_deltas.push(SmtTerm::var(delta_var(k, r)));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    let head_k = SmtTerm::var(queue_head_var(k, cid));
                    let head_next = SmtTerm::var(queue_head_var(k + 1, cid));
                    let tail_k = SmtTerm::var(queue_tail_var(k, cid));
                    let tail_next = SmtTerm::var(queue_tail_var(k + 1, cid));

                    // tail_{k+1} = tail_k + enqueue_deltas
                    if enqueue_deltas.is_empty() {
                        enc.assert_term(tail_next.clone().eq(tail_k.clone()));
                    } else {
                        let total_enqueues = sum_terms_balanced(enqueue_deltas);
                        enc.assert_term(tail_next.clone().eq(tail_k.clone().add(total_enqueues)));
                    }

                    // head_{k+1} = head_k + dequeue_deltas
                    if dequeue_deltas.is_empty() {
                        enc.assert_term(head_next.clone().eq(head_k.clone()));
                    } else {
                        let total_dequeues = sum_terms_balanced(dequeue_deltas);
                        enc.assert_term(head_next.clone().eq(head_k.clone().add(total_dequeues)));
                    }

                    // head <= tail (can't dequeue more than enqueued)
                    enc.assert_term(
                        SmtTerm::var(queue_head_var(k + 1, cid))
                            .le(SmtTerm::var(queue_tail_var(k + 1, cid))),
                    );

                    // Occupancy = tail - head = collection length
                    let occupancy = SmtTerm::var(queue_tail_var(k + 1, cid))
                        .sub(SmtTerm::var(queue_head_var(k + 1, cid)));
                    enc.assert_term(SmtTerm::var(coll_len_var(k + 1, cid)).eq(occupancy));

                    // Capacity bound on occupancy (already bounded via coll_len above)
                } else {
                    // Non-FIFO: track length via appends only
                    let mut append_deltas: Vec<SmtTerm> = Vec::new();
                    for &r in active_rule_ids {
                        for cu in &ta.rules[r].collection_updates {
                            if cu.collection.as_usize() == cid {
                                if matches!(cu.kind, CollectionUpdateKind::Append(_)) {
                                    append_deltas.push(SmtTerm::var(delta_var(k, r)));
                                }
                            }
                        }
                    }

                    let len_k = SmtTerm::var(coll_len_var(k, cid));
                    let len_next = SmtTerm::var(coll_len_var(k + 1, cid));
                    if append_deltas.is_empty() {
                        enc.assert_term(len_next.eq(len_k));
                    } else {
                        let total_appends = sum_terms_balanced(append_deltas);
                        enc.assert_term(len_next.eq(len_k.add(total_appends)));
                    }
                }
            }

            // Time-varying parameter updates: reconfiguration constraints
            if !time_varying_param_ids.is_empty() {
                // Declare step k+1 parameter variables
                for &i in time_varying_param_ids {
                    enc.declare(param_var_at_step(k + 1, i), SmtSort::Int);
                    enc.assert_term(SmtTerm::var(param_var_at_step(k + 1, i)).ge(SmtTerm::int(0)));
                }

                // For each time-varying param, collect rules that update it
                for &pid in time_varying_param_ids {
                    let mut update_rules: Vec<(usize, &LinearCombination)> = Vec::new();
                    for &r in active_rule_ids {
                        for pu in &ta.rules[r].param_updates {
                            if pu.param.as_usize() == pid {
                                update_rules.push((r, &pu.value));
                            }
                        }
                    }

                    if update_rules.is_empty() {
                        // Frame constraint: param unchanged at this step
                        enc.assert_term(
                            SmtTerm::var(param_var_at_step(k + 1, pid))
                                .eq(SmtTerm::var(param_var_at_step(k, pid))),
                        );
                    } else {
                        // If any updating rule fires, apply its value;
                        // otherwise frame (keep old value).
                        // For each updating rule: delta > 0 → p_{k+1} = value(old params at k)
                        for &(r, value) in &update_rules {
                            let dr_pos = SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0));
                            let new_val = encode_lc_at_step(value, k, time_varying_param_ids);
                            enc.assert_term(
                                dr_pos.implies(
                                    SmtTerm::var(param_var_at_step(k + 1, pid)).eq(new_val),
                                ),
                            );
                        }
                        // Frame: if no updating rule fires, param stays the same
                        let any_fires = sum_terms_balanced(
                            update_rules
                                .iter()
                                .map(|&(r, _)| SmtTerm::var(delta_var(k, r)))
                                .collect(),
                        )
                        .gt(SmtTerm::int(0));
                        enc.assert_term(
                            SmtTerm::not(any_fires).implies(
                                SmtTerm::var(param_var_at_step(k + 1, pid))
                                    .eq(SmtTerm::var(param_var_at_step(k, pid))),
                            ),
                        );
                    }
                }
            }
        }

        // Crypto objects are formed by protocol transitions from source-message witnesses.
        // They are not adversarially forgeable as standalone traffic families.
        for k in 0..max_depth {
            for v in crypto_object_counter_vars {
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
        if let Some(adv_param) = ta.constraints.adversary_bound_param {
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
                            SmtTerm::var(format!("adv_{k}_{v}"))
                                .le(SmtTerm::var(param_var(adv_param))),
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
                match ta.semantics.fault_budget_scope {
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
                    for ((_family, recipient), vars) in message_family_recipients {
                        if recipient.is_none() || vars.is_empty() {
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
                if byzantine_faults && selective_network {
                    for group_id in 0..message_variant_groups.len() {
                        enc.assert_term(
                            SmtTerm::var(adv_send_var(k, group_id))
                                .le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                }
                if crash_faults {
                    for v in all_message_counter_vars {
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
                if crash_recovery {
                    // No message forgery or dropping in crash-recovery model.
                    for v in all_message_counter_vars {
                        enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_drop_var(k, *v)).eq(SmtTerm::int(0)));
                    }
                    // At most f processes simultaneously crashed (dead-location sum bound).
                    if !dead_loc_ids.is_empty() {
                        let dead_sum: Vec<SmtTerm> = dead_loc_ids
                            .iter()
                            .map(|&l| SmtTerm::var(kappa_var(k + 1, l)))
                            .collect();
                        enc.assert_term(
                            sum_terms_balanced(dead_sum).le(SmtTerm::var(param_var(adv_param))),
                        );
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
                            enc.assert_term(
                                SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)),
                            );
                            enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                        }
                    }
                    let mut byz_sender_terms = Vec::new();
                    for (sender_idx, sender_channel) in signed_sender_channels.iter().enumerate() {
                        let byz_sender = SmtTerm::var(byz_sender_var(k, sender_idx));
                        byz_sender_terms.push(byz_sender.clone());
                        if let Some(vars) = signed_uncompromised_sender_vars.get(sender_channel) {
                            for v in vars {
                                enc.assert_term(byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                    SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)),
                                ));
                                enc.assert_term(byz_sender.clone().eq(SmtTerm::int(0)).implies(
                                    SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)),
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
                    for k in 0..max_depth {
                        for ((family, sender), variants) in family_sender_variants_vec {
                            if variants.len() <= 1
                                || !message_effective_non_equivocating(ta, family)
                            {
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
                for (v, _) in distinct_vars {
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
                    for ((family, _recipient), vars) in message_family_recipients {
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
                        for (family, group_ids) in message_family_variants {
                            if group_ids.is_empty()
                                || !message_effective_non_equivocating(ta, family)
                            {
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
        } else if omission_style_faults || crash_faults || crash_recovery {
            // Omission/crash/crash-recovery without explicit bound defaults to no faults.
            for k in 0..max_depth {
                for v in 0..num_svars {
                    enc.assert_term(SmtTerm::var(format!("adv_{k}_{v}")).eq(SmtTerm::int(0)));
                    if omission_style_faults {
                        enc.assert_term(SmtTerm::var(drop_var(k, v)).eq(SmtTerm::int(0)));
                    }
                }
                if crash_faults {
                    for v in all_message_counter_vars {
                        enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_drop_var(k, *v)).eq(SmtTerm::int(0)));
                    }
                    if let Some(crash_var) = crash_counter_var {
                        enc.assert_term(
                            SmtTerm::var(gamma_var(k + 1, crash_var)).eq(SmtTerm::int(0)),
                        );
                    } else {
                        enc.assert_term(SmtTerm::bool(false));
                    }
                }
                if crash_recovery {
                    // No faults: zero forge/drop and no crashed processes.
                    for v in all_message_counter_vars {
                        enc.assert_term(SmtTerm::var(net_forge_var(k, *v)).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_drop_var(k, *v)).eq(SmtTerm::int(0)));
                    }
                    for &l in dead_loc_ids {
                        enc.assert_term(SmtTerm::var(kappa_var(k + 1, l)).eq(SmtTerm::int(0)));
                    }
                }
            }
        }
    }

    pub(super) fn phase_encode_property_violation(&mut self) {
        let ta = self.ta;
        let property = self.property;
        let max_depth = self.max_depth;
        let enc = &mut self.enc;

        let violation = encode_property_violation(ta, property, max_depth);
        enc.assert_term(violation);
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
        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "t".into(),
            time_varying: false,
        });

        // Resilience: n > 3*t
        ta.constraints.resilience_condition = Some(LinearConstraint {
            lhs: LinearCombination::param(0.into()), // n
            op: CmpOp::Gt,
            rhs: LinearCombination::param(1.into()).scale(3), // 3*t
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

        ta.initial_locations = vec![0.into()];

        // Rule: waiting -> done when cnt_Echo >= 2*t+1, sends Echo
        ta.add_rule(Rule {
            from: 0.into(),
            to: 1.into(),
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0.into()],
                op: CmpOp::Ge,
                bound: LinearCombination {
                    constant: 1,
                    terms: vec![(2, 1.into())], // 2*t + 1
                },
                distinct: false,
            }),
            updates: vec![Update {
                var: 0.into(),
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });

        ta
    }

    fn make_signer_set_threshold_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();

        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "t".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
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
        ta.initial_locations = vec![0.into()];

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
            from: 0.into(),
            to: 1.into(),
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
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
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
    fn bmc_builder_phases_are_unit_testable() {
        let ta = make_simple_ta();
        let cs = ta;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let mut builder = BmcEncoderBuilder::new(&cs, &property, 1);
        builder.phase_declare_parameters_and_resilience();
        assert!(
            builder
                .enc
                .declarations
                .iter()
                .any(|(name, _)| name == "p_0"),
            "parameter declarations should be emitted in phase 1"
        );

        builder.phase_declare_initial_state();
        assert!(
            builder
                .enc
                .declarations
                .iter()
                .any(|(name, _)| name == "kappa_0_0"),
            "initial-state declarations should be emitted in phase 2"
        );

        builder.phase_encode_transitions_and_fault_bounds();
        builder.phase_encode_property_violation();
        assert!(
            !builder.enc.assertions.is_empty(),
            "phase composition should produce non-empty constraints"
        );
    }

    #[test]
    fn k_induction_builder_phases_are_unit_testable() {
        let ta = make_simple_ta();
        let cs = ta;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let mut builder = super::k_induction::KInductionEncoderBuilder::new(&cs, &property, 1);
        builder.phase_declare_parameters_and_resilience();
        assert!(
            builder
                .encoding()
                .declarations
                .iter()
                .any(|(name, _)| name == "p_0"),
            "parameter declarations should be emitted in phase 1"
        );

        builder.phase_declare_state_and_transition_variables();
        assert!(
            builder
                .encoding()
                .declarations
                .iter()
                .any(|(name, _)| name == "kappa_0_0"),
            "state declarations should be emitted in phase 2"
        );

        builder.phase_encode_transition_relation_and_fault_bounds();
        builder.phase_encode_induction_goal();
        assert!(
            !builder.encoding().assertions.is_empty(),
            "phase composition should produce non-empty constraints"
        );
    }

    #[test]
    fn encoding_produces_declarations() {
        let ta = make_simple_ta();
        let cs = ta;
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
            from: 0.into(),
            to: 0.into(),
            guard: Guard::trivial(),
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        let cs = ta;
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
        let cs = ta;
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
            from: 0.into(),
            to: 1.into(),
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0.into()],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(2),
                distinct: false,
            }),
            updates: vec![Update {
                var: 0.into(),
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.add_rule(Rule {
            from: 0.into(),
            to: 1.into(),
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0.into()],
                op: CmpOp::Ge,
                bound: LinearCombination::constant(1),
                distinct: false,
            }),
            updates: vec![Update {
                var: 0.into(),
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "gst".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Omission;
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = Some(3.into());
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::CohortSelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica#1[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.fault_budget_scope = FaultBudgetScope::PerRecipient;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Omission;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.fault_budget_scope = FaultBudgetScope::Global;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.delivery_control = DeliveryControlMode::Global;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
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
        ta.rules[0].from = 2.into();
        ta.rules[0].to = 3.into();
        ta.initial_locations = vec![0.into(), 2.into()];

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
        ta.security.role_identities.insert(
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
        ta.rules[0].from = 2.into();
        ta.rules[0].to = 3.into();
        ta.initial_locations = vec![0.into(), 2.into()];

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.equivocation_mode = EquivocationMode::None;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.equivocation_mode = EquivocationMode::None;
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo[value=true]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.equivocation_mode = EquivocationMode::None;

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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.equivocation_mode = EquivocationMode::Full;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;

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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.equivocation_mode = EquivocationMode::Full;
        ta.semantics.authentication_mode = AuthenticationMode::None;
        ta.security.message_policies.insert(
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.shared_vars[0].name = "cnt_Echo@Replica[value=false]".into();

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Client<-P#0[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();
        ta.add_shared_var(SharedVar {
            name: "cnt_Echo@Replica<-P#1[value=false]".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "gst".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = Some(3.into());
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.security.compromised_keys.insert("p_key".into());
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.security.compromised_keys.insert("p_key".into());
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = ta;
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
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_Echo@Replica<-P#0[value=false]".into();

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        ta.shared_vars[0].name = "cnt_QC@P#0<-P#0[value=false]".into();
        ta.security.crypto_objects.insert(
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "t".into(),
            time_varying: false,
        });
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
        ta.initial_locations = vec![0.into()];
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.security.role_identities.insert(
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
        ta.security.crypto_objects.insert(
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
            from: 0.into(),
            to: 0.into(),
            guard: Guard::trivial(),
            updates: vec![Update {
                var: vote,
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        ta.add_rule(Rule {
            from: 0.into(),
            to: 1.into(),
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
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });

        let cs = ta;
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
            ta.add_parameter(Parameter {
                name: "n".into(),
                time_varying: false,
            });
            ta.add_parameter(Parameter {
                name: "t".into(),
                time_varying: false,
            });
            ta.add_location(Location {
                name: "s".into(),
                role: "P".into(),
                phase: "s".into(),
                local_vars: IndexMap::new(),
            });
            ta.initial_locations = vec![0.into()];
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
                from: 0.into(),
                to: 0.into(),
                guard: Guard::trivial(),
                updates: vec![Update {
                    var: qc_false,
                    kind: UpdateKind::Increment,
                }],
                collection_updates: vec![],
                clock_guards: vec![],
                clock_updates: vec![],
                param_updates: vec![],
            });
            ta.add_rule(Rule {
                from: 0.into(),
                to: 0.into(),
                guard: Guard::trivial(),
                updates: vec![Update {
                    var: qc_true,
                    kind: UpdateKind::Increment,
                }],
                collection_updates: vec![],
                clock_guards: vec![],
                clock_updates: vec![],
                param_updates: vec![],
            });
            ta.security.crypto_objects.insert(
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
            let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.equivocation_mode = EquivocationMode::Full;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.security.role_identities.insert(
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.equivocation_mode = EquivocationMode::None;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        ta.semantics.authentication_mode = AuthenticationMode::Signed;
        ta.semantics.network_semantics = NetworkSemantics::IdentitySelective;
        ta.semantics.equivocation_mode = EquivocationMode::Full;
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

        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        let crash_counter = ta.add_shared_var(SharedVar {
            name: "__crashed_count".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Crash;
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Byzantine;
        let cs = ta;
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
        ta.semantics.fault_model = FaultModel::Omission;
        let cs = ta;
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
        ta.semantics.fault_model = FaultModel::Crash;
        let cs = ta;
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
        ta.add_parameter(Parameter {
            name: "f".into(),
            time_varying: false,
        });
        ta.add_parameter(Parameter {
            name: "gst".into(),
            time_varying: false,
        });
        ta.constraints.adversary_bound_param = Some(2.into());
        ta.semantics.fault_model = FaultModel::Omission;
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = Some(3.into());
        let cs = ta;
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
    fn kinduction_depth_zero_declares_no_transition_step_variables() {
        let ta = make_simple_ta();
        let cs = ta;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0.into(), 1.into())],
        };

        let step = encode_k_induction_step(&cs, &property, 0);
        let decls: std::collections::HashSet<_> =
            step.declarations.iter().map(|(n, _)| n.clone()).collect();
        assert!(!decls.iter().any(|n| n.starts_with("delta_")));
        assert!(!decls.iter().any(|n| n.starts_with("adv_")));
        assert!(decls.contains("kappa_0_0"));
        assert!(decls.contains("g_0_0"));
    }

    #[test]
    fn kinduction_process_selective_missing_pid_is_unsat() {
        let mut ta = make_simple_ta();
        ta.semantics.network_semantics = NetworkSemantics::ProcessSelective;
        ta.security.role_identities.insert(
            "P".into(),
            RoleIdentityConfig {
                scope: RoleIdentityScope::Process,
                process_var: Some("pid".into()),
                key_name: "p_key".into(),
            },
        );
        let cs = ta;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0.into(), 1.into())],
        };

        let step = encode_k_induction_step(&cs, &property, 1);
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions.iter().any(|a| a == "false"),
            "missing process identities should force UNSAT in process-selective mode"
        );
    }

    #[test]
    fn kinduction_distinct_counter_without_population_bound_is_unsat() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_shared_var(SharedVar {
            name: "cnt_M".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: true,
            distinct_role: None,
        });
        ta.add_location(Location {
            name: "s0".into(),
            role: "P".into(),
            phase: "s0".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations = vec![0.into()];
        let cs = ta;
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![0.into()]],
        };

        let step = encode_k_induction_step(&cs, &property, 1);
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions.iter().any(|a| a == "false"),
            "distinct counters require n or n_<role> population bounds"
        );
    }

    #[test]
    fn kinduction_por_off_does_not_force_duplicate_delta_to_zero() {
        let mut ta_full = make_simple_ta();
        ta_full.add_rule(ta_full.rules[0].clone());
        ta_full.semantics.por_mode = PorMode::Full;
        let cs_full = ta_full;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let full = encode_k_induction_step(&cs_full, &property, 1);
        let full_assertions: Vec<String> = full.assertions.iter().map(to_smtlib).collect();
        assert!(full_assertions.iter().any(|a| a == "(= delta_0_1 0)"));

        let mut ta_off = make_simple_ta();
        ta_off.add_rule(ta_off.rules[0].clone());
        ta_off.semantics.por_mode = PorMode::Off;
        let cs_off = ta_off;
        let off = encode_k_induction_step(&cs_off, &property, 1);
        let off_assertions: Vec<String> = off.assertions.iter().map(to_smtlib).collect();
        assert!(
            !off_assertions.iter().any(|a| a == "(= delta_0_1 0)"),
            "POR off should keep duplicate-rule deltas unconstrained by pruning"
        );
    }

    #[test]
    fn kinduction_crash_model_without_crash_counter_is_unsat() {
        let mut ta = make_simple_ta();
        ta.semantics.fault_model = FaultModel::Crash;
        ta.constraints.adversary_bound_param = Some(1.into());
        let cs = ta;
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };

        let step = encode_k_induction_step(&cs, &property, 1);
        let assertions: Vec<String> = step.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions.iter().any(|a| a == "false"),
            "crash model requires __crashed_count instrumentation"
        );
    }

    #[test]
    fn por_mode_off_disables_all_pruning() {
        let mut ta = make_simple_ta();
        // Add a duplicate rule (same signature as rule 0) to test pruning
        ta.add_rule(Rule {
            from: 0.into(),
            to: 1.into(),
            guard: Guard::single(GuardAtom::Threshold {
                vars: vec![0.into()],
                op: CmpOp::Ge,
                bound: LinearCombination {
                    constant: 1,
                    terms: vec![(2, 1.into())],
                },
                distinct: false,
            }),
            updates: vec![Update {
                var: 0.into(),
                kind: UpdateKind::Increment,
            }],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });

        // With Full POR, duplicate should be pruned
        ta.semantics.por_mode = PorMode::Full;
        let pruning_full = compute_por_rule_pruning(&ta);
        let active_full = pruning_full.active_rule_ids().len();

        // With POR Off, no rules should be pruned
        ta.semantics.por_mode = PorMode::Off;
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
            terms: vec![(1, 0.into())],
        };
        // constant=0 is skipped, only p_0
        assert_eq!(encode_lc(&lc), SmtTerm::var("p_0"));
    }

    #[test]
    fn encode_lc_scaled_param() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(3, 1.into())],
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
            conflicting_pairs: vec![(0.into(), 1.into())],
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
                let cs = ta;
                // depth 0-3
                (Just(cs), Just(nlocs), 0..=3usize)
            })
            .prop_map(|(cs, nlocs, depth)| {
                // Generate a trivially-empty agreement property (safe for any TA)
                let property = if nlocs >= 2 {
                    SafetyProperty::Agreement {
                        conflicting_pairs: vec![(0.into(), 1.into())],
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
        ta
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
        let enc = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = enc.assertions.iter().map(to_smtlib).collect();
        let ta = &cs;

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
            if !ta.initial_locations.contains(&l.into()) {
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);

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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);

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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);

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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);

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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
            bad_sets: vec![vec![0.into(), 1.into()]],
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
        let property = SafetyProperty::Termination {
            goal_locs: vec![1.into()],
        };
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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
        let property = tarsier_ir::properties::extract_agreement_property(&cs);
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

    #[test]
    fn collection_length_variables_are_declared_and_bounded() {
        let mut ta = make_simple_ta();

        // Add a bounded collection with capacity = n
        ta.add_collection(IrCollectionSpec {
            name: "Votes".into(),
            kind: IrCollectionKind::Log,
            element_type: "int".into(),
            capacity: LinearCombination::param(ParamId::from(0)), // n
            queue_model: QueueModel::None,
        });

        // Add an append rule (waiting->done appends to Votes)
        ta.rules[0].collection_updates.push(CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Append(LinearCombination::constant(1)),
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();

        // Check collection length var at step 0 is declared and initialized to 0
        let has_len_init = assertions
            .iter()
            .any(|a| a.contains("clen_0_0") && a.contains("0"));
        assert!(has_len_init, "Collection length should be initialized to 0");

        // Check collection length var at step 1 is declared
        let has_len_step1 = assertions.iter().any(|a| a.contains("clen_1_0"));
        assert!(has_len_step1, "Collection length at step 1 should exist");

        // Check capacity bound exists (clen <= p_0 which is n)
        let has_cap_bound = assertions
            .iter()
            .any(|a| a.contains("clen_") && a.contains("p_0"));
        assert!(
            has_cap_bound,
            "Collection length should be bounded by capacity"
        );
    }

    #[test]
    fn collection_length_update_encodes_append_deltas() {
        let mut ta = make_simple_ta();

        // Add a log collection with constant capacity 5
        ta.add_collection(IrCollectionSpec {
            name: "Log".into(),
            kind: IrCollectionKind::Log,
            element_type: "int".into(),
            capacity: LinearCombination::constant(5),
            queue_model: QueueModel::None,
        });

        // The existing rule (waiting->done) appends to the log
        ta.rules[0].collection_updates.push(CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Append(LinearCombination::constant(42)),
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();

        // Length at step 1 should reference delta from rule 0 and clen_0_0
        let has_len_update = assertions
            .iter()
            .any(|a| a.contains("clen_1_0") && (a.contains("clen_0_0") || a.contains("delta_0_")));
        assert!(
            has_len_update,
            "Step 1 length should be updated based on step 0 length + deltas"
        );

        // Capacity bound of 5 should appear
        let has_const_cap = assertions
            .iter()
            .any(|a| a.contains("clen_") && a.contains("5"));
        assert!(has_const_cap, "Constant capacity 5 should appear in bounds");
    }

    #[test]
    fn collection_no_appends_preserves_length() {
        let mut ta = make_simple_ta();

        // Add a collection but no rules reference it
        ta.add_collection(IrCollectionSpec {
            name: "Unused".into(),
            kind: IrCollectionKind::Sequence,
            element_type: "int".into(),
            capacity: LinearCombination::constant(10),
            queue_model: QueueModel::None,
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();

        // Length should be preserved across all steps (= equality constraints)
        let step0_eq = assertions
            .iter()
            .any(|a| a.contains("clen_1_0") && a.contains("clen_0_0"));
        let step1_eq = assertions
            .iter()
            .any(|a| a.contains("clen_2_0") && a.contains("clen_1_0"));
        assert!(
            step0_eq,
            "Unused collection length should be preserved step 0→1"
        );
        assert!(
            step1_eq,
            "Unused collection length should be preserved step 1→2"
        );
    }

    #[test]
    fn queue_variable_naming_conventions() {
        // Verify the queue head/tail variable naming follows conventions
        assert_eq!(queue_head_var(0, 0), "qhead_0_0");
        assert_eq!(queue_head_var(3, 1), "qhead_3_1");
        assert_eq!(queue_tail_var(0, 0), "qtail_0_0");
        assert_eq!(queue_tail_var(2, 5), "qtail_2_5");
        assert_eq!(dag_round_active_var(1, 2), "dag_active_1_2");
        assert_eq!(clock_var(1, 2), "clk_1_2");
    }

    #[test]
    fn clock_encoding_applies_timeout_guards_and_updates() {
        let mut ta = make_simple_ta();
        let clock_id = ta.add_clock(IrClockSpec {
            name: "deadline".into(),
        });
        ta.rules[0].clock_guards.push(ClockGuard {
            clock: clock_id,
            op: CmpOp::Ge,
            bound: LinearCombination::constant(2),
        });
        ta.rules[0].clock_updates.push(ClockUpdate {
            clock: clock_id,
            kind: ClockUpdateKind::TickBy(LinearCombination::constant(3)),
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);
        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();

        assert!(
            assertions.iter().any(|a| a.contains("(= clk_0_0 0)")),
            "clock must be initialized at step 0"
        );
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(=> (> delta_0_0 0) (>= clk_0_0 2))")),
            "timeout guard should gate rule firing"
        );
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(=> (> delta_0_0 0) (= clk_1_0 (+ clk_0_0 3)))")),
            "tick update should advance clock on rule firing"
        );
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(=> (= delta_0_0 0) (= clk_1_0 clk_0_0))")),
            "clock should frame when no clock-updating rule fires"
        );
    }

    #[test]
    fn dag_round_encoding_declares_activation_and_parent_constraints() {
        let mut ta = make_simple_ta();
        ta.dag_rounds.push(IrDagRoundSpec {
            name: "r0".into(),
            parent_rounds: vec![],
        });
        ta.dag_rounds.push(IrDagRoundSpec {
            name: "r1".into(),
            parent_rounds: vec!["r0".into()],
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);

        let declarations: std::collections::HashSet<_> = encoding
            .declarations
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        assert!(declarations.contains("dag_active_0_0"));
        assert!(declarations.contains("dag_active_0_1"));
        assert!(declarations.contains("dag_active_1_0"));
        assert!(declarations.contains("dag_active_1_1"));
        assert!(declarations.contains("dag_active_2_0"));
        assert!(declarations.contains("dag_active_2_1"));

        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(= dag_active_0_0 0)")),
            "step-0 DAG root should initialize to 0"
        );
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(>= dag_active_2_1 dag_active_1_1)")),
            "DAG round activation should be monotonic"
        );
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("(<= dag_active_2_1 dag_active_1_0)")),
            "child DAG round activation must depend on prior parent activation"
        );
    }

    #[test]
    fn fifo_queue_encoding_declares_head_tail_variables() {
        let mut ta = make_simple_ta();

        // Add a FIFO channel collection with capacity = n
        ta.add_collection(IrCollectionSpec {
            name: "MsgQueue".into(),
            kind: IrCollectionKind::FifoChannel,
            element_type: "int".into(),
            capacity: LinearCombination::param(ParamId::from(0)), // n
            queue_model: QueueModel::LinearFifo,
        });

        // Rule: waiting->done enqueues to MsgQueue
        ta.rules[0].collection_updates.push(CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Enqueue(LinearCombination::constant(1)),
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();

        // Check head and tail variables are declared at step 0
        let has_head_init = assertions
            .iter()
            .any(|a| a.contains("qhead_0_0") && a.contains("0"));
        let has_tail_init = assertions
            .iter()
            .any(|a| a.contains("qtail_0_0") && a.contains("0"));
        assert!(has_head_init, "Queue head should be initialized to 0");
        assert!(has_tail_init, "Queue tail should be initialized to 0");

        // Check head/tail variables exist at step 1
        let has_head_1 = assertions.iter().any(|a| a.contains("qhead_1_0"));
        let has_tail_1 = assertions.iter().any(|a| a.contains("qtail_1_0"));
        assert!(has_head_1, "Queue head at step 1 should exist");
        assert!(has_tail_1, "Queue tail at step 1 should exist");

        // Check head <= tail constraint
        let has_ordering = assertions
            .iter()
            .any(|a| a.contains("qhead_1_0") && a.contains("qtail_1_0") && a.contains("<="));
        assert!(
            has_ordering,
            "head <= tail ordering constraint should exist"
        );

        // Check occupancy = tail - head = length
        let has_occupancy = assertions
            .iter()
            .any(|a| a.contains("clen_1_0") && a.contains("qtail_1_0") && a.contains("qhead_1_0"));
        assert!(
            has_occupancy,
            "Occupancy (tail - head) should equal collection length"
        );
    }

    #[test]
    fn fifo_queue_dequeue_updates_head() {
        let mut ta = make_simple_ta();

        ta.add_collection(IrCollectionSpec {
            name: "Q".into(),
            kind: IrCollectionKind::FifoChannel,
            element_type: "int".into(),
            capacity: LinearCombination::constant(10),
            queue_model: QueueModel::LinearFifo,
        });

        // Rule: waiting->done dequeues from Q
        ta.rules[0].collection_updates.push(CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Dequeue,
        });

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 1);
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();

        // head_1 should reference head_0 and delta (dequeue delta)
        let has_head_update = assertions.iter().any(|a| {
            a.contains("qhead_1_0") && (a.contains("qhead_0_0") || a.contains("delta_0_"))
        });
        assert!(has_head_update, "Dequeue should update queue head");
    }

    #[test]
    fn fifo_queue_with_enqueue_and_dequeue_combined() {
        let mut ta = make_simple_ta();

        ta.add_collection(IrCollectionSpec {
            name: "Chan".into(),
            kind: IrCollectionKind::FifoChannel,
            element_type: "int".into(),
            capacity: LinearCombination::constant(5),
            queue_model: QueueModel::LinearFifo,
        });

        // Rule 0: waiting->done enqueues
        ta.rules[0].collection_updates.push(CollectionUpdate {
            collection: CollectionId::new(0),
            kind: CollectionUpdateKind::Enqueue(LinearCombination::constant(1)),
        });

        // Add a second rule for dequeue (done->waiting)
        let dequeue_rule = Rule {
            from: ta.rules[0].to, // done
            to: ta.rules[0].from, // waiting
            guard: Guard::trivial(),
            updates: vec![],
            collection_updates: vec![CollectionUpdate {
                collection: CollectionId::new(0),
                kind: CollectionUpdateKind::Dequeue,
            }],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        };
        ta.rules.push(dequeue_rule);

        let cs: CounterSystem = ta.into();
        let property = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let encoding = encode_bmc(&cs, &property, 2);
        let declarations: Vec<String> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.clone())
            .collect();

        // Verify head/tail variables exist at steps 0, 1, 2
        for step in 0..=2 {
            assert!(
                declarations.contains(&queue_head_var(step, 0)),
                "qhead_{step}_0 should be declared"
            );
            assert!(
                declarations.contains(&queue_tail_var(step, 0)),
                "qtail_{step}_0 should be declared"
            );
        }

        // Verify capacity bound (5) appears in assertions
        let assertions: Vec<String> = encoding.assertions.iter().map(|t| to_smtlib(t)).collect();
        let has_cap = assertions
            .iter()
            .any(|a| a.contains("clen_") && a.contains("5"));
        assert!(has_cap, "Capacity bound of 5 should appear");
    }

    // ── RECONF-04: epoch-aware parameter encoding tests ─────────────

    #[test]
    fn encode_lc_at_step_fixed_params_use_global_vars() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(1, ParamId::from(0))],
        };
        // No time-varying params → should use global p_0
        let term = encode_lc_at_step(&lc, 3, &[]);
        assert_eq!(term, SmtTerm::var("p_0"));
    }

    #[test]
    fn encode_lc_at_step_varying_params_use_step_vars() {
        let lc = LinearCombination {
            constant: 5,
            terms: vec![(2, ParamId::from(1))],
        };
        // Param 1 is time-varying → should use p_1_2 at step 2
        let term = encode_lc_at_step(&lc, 2, &[1]);
        // Expected: 5 + 2*p_1_2
        let expected = SmtTerm::int(5).add(SmtTerm::int(2).mul(SmtTerm::var("p_1_2")));
        assert_eq!(term, expected);
    }

    #[test]
    fn encode_lc_at_step_mixed_fixed_and_varying() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(1, ParamId::from(0)), (1, ParamId::from(1))],
        };
        // Param 0 fixed, param 1 varying, at step 5
        let term = encode_lc_at_step(&lc, 5, &[1]);
        // Expected: p_0 + p_1_5
        let expected = SmtTerm::var("p_0").add(SmtTerm::var("p_1_5"));
        assert_eq!(term, expected);
    }

    #[test]
    fn epoch_encoding_declares_step_param_vars() {
        // Build a minimal TA with a time-varying parameter and a reconfigure rule
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter::fixed("n".to_string()));
        let t_id = ta.add_parameter(Parameter::varying("t".to_string()));
        let l0 = ta.add_location(Location {
            name: "Init".into(),
            role: "R".into(),
            phase: "init".into(),
            local_vars: IndexMap::new(),
        });
        let l1 = ta.add_location(Location {
            name: "Done".into(),
            role: "R".into(),
            phase: "done".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations.push(l0);
        ta.add_shared_var(SharedVar {
            name: "votes".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_rule(Rule {
            from: l0,
            to: l1,
            guard: Guard::trivial(),
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![ParamUpdate {
                param: t_id,
                value: LinearCombination::constant(5),
            }],
        });
        ta.constraints.adversary_bound_param = Some(t_id);

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_bmc(&cs, &property, 2);

        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();

        // Should have step-dependent param vars for the varying param (index 1)
        assert!(
            decl_names.contains(&"p_1_0"),
            "should declare p_1_0 (step-0 varying param)"
        );
        assert!(
            decl_names.contains(&"p_1_1"),
            "should declare p_1_1 (step-1 varying param)"
        );
        assert!(
            decl_names.contains(&"p_1_2"),
            "should declare p_1_2 (step-2 varying param)"
        );

        // Global p_0 (fixed) and p_1 (initial value) should also exist
        assert!(decl_names.contains(&"p_0"), "should declare global p_0");
        assert!(
            decl_names.contains(&"p_1"),
            "should declare global p_1 (initial)"
        );
    }
}
