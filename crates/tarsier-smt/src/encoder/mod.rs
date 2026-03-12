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
pub(crate) use variables::{delta_var, gamma_var, gst_step_var, kappa_var, time_var};

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
        let max_depth = self.max_depth;
        let enc = &mut self.enc;
        if matches!(
            ta.reconfiguration.as_ref().map(|s| s.semantics),
            Some(ReconfigurationSemantics::Immediate)
        ) {
            // Fail closed when callers bypass IR validation.
            enc.assert_term(SmtTerm::bool(false));
            return;
        }
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

        if ta.semantics.timing_model == TimingModel::PartialSynchrony {
            enc.declare(gst_step_var(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(gst_step_var()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(gst_step_var()).le(SmtTerm::int(max_depth as i64)));

            if let Some(gst_pid) = ta.semantics.gst_param {
                let gst_source = if self
                    .context
                    .time_varying_param_ids
                    .contains(&gst_pid.as_usize())
                {
                    SmtTerm::var(param_var_at_step(0, gst_pid))
                } else {
                    SmtTerm::var(param_var(gst_pid))
                };
                enc.assert_term(SmtTerm::var(gst_step_var()).eq(gst_source));
            }
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
        if let Some(spec) = &ta.reconfiguration {
            if spec.max_reconfigurations > 0 {
                enc.declare(reconf_count_var(0), SmtSort::Int);
                enc.assert_term(SmtTerm::var(reconf_count_var(0)).eq(SmtTerm::int(0)));
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
        let max_reconfigurations = ta
            .reconfiguration
            .as_ref()
            .map(|spec| spec.max_reconfigurations)
            .unwrap_or(0);
        let reconfig_rule_ids: Vec<usize> = active_rule_ids
            .iter()
            .copied()
            .filter(|r| !ta.rules[*r].param_updates.is_empty())
            .collect();
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
            if max_reconfigurations > 0 {
                enc.declare(reconf_count_var(k + 1), SmtSort::Int);
                enc.assert_term(SmtTerm::var(reconf_count_var(k + 1)).ge(SmtTerm::int(0)));
            }
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
            // - Activation delta: dag_delta_{k}_{rid} = next - curr (0 or 1).
            //   This variable is 1 exactly on the step when the round activates,
            //   useful for witness extraction and rule conditioning.
            for (rid, parents) in dag_parent_indices.iter().enumerate() {
                let curr = dag_round_active_var(k, rid);
                let next = dag_round_active_var(k + 1, rid);
                enc.declare(next.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(next.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(next.clone()).le(SmtTerm::int(1)));
                enc.assert_term(SmtTerm::var(next.clone()).ge(SmtTerm::var(curr.clone())));

                // Activation delta variable.
                let delta_name = format!("dag_delta_{k}_{rid}");
                enc.declare(delta_name.clone(), SmtSort::Int);
                enc.assert_term(
                    SmtTerm::var(delta_name.clone())
                        .eq(SmtTerm::var(next.clone()).sub(SmtTerm::var(curr))),
                );

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
                        let post_gst = SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(k)));
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
                    if ta.semantics.timing_model == TimingModel::PartialSynchrony && lossy_delivery
                    {
                        let post_gst = SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(k)));
                        enc.assert_term(post_gst.implies(net_drop.eq(SmtTerm::int(0))));
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
                                let post_gst =
                                    SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(k)));
                                enc.assert_term(post_gst.implies(drop_term.eq(SmtTerm::int(0))));
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
                            if cu.collection.as_usize() == cid
                                && matches!(cu.kind, CollectionUpdateKind::Append(_))
                            {
                                append_deltas.push(SmtTerm::var(delta_var(k, r)));
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

                        // RECONF-02 (GAP-2): at most one updating rule fires per step
                        // to avoid contradictory parameter constraints.
                        if update_rules.len() > 1 {
                            let fire_indicators: Vec<SmtTerm> = update_rules
                                .iter()
                                .map(|&(r, _)| {
                                    SmtTerm::Ite(
                                        Box::new(SmtTerm::var(delta_var(k, r)).gt(SmtTerm::int(0))),
                                        Box::new(SmtTerm::int(1)),
                                        Box::new(SmtTerm::int(0)),
                                    )
                                })
                                .collect();
                            let total = sum_terms_balanced(fire_indicators);
                            enc.assert_term(total.le(SmtTerm::int(1)));
                        }
                    }
                }

                // RECONF-02 (GAP-1): re-assert resilience condition using
                // epoch-aware parameter values at step k+1.
                if let Some(ref rc) = ta.constraints.resilience_condition {
                    let lhs = encode_lc_at_step(&rc.lhs, k + 1, time_varying_param_ids);
                    let rhs = encode_lc_at_step(&rc.rhs, k + 1, time_varying_param_ids);
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

            if max_reconfigurations > 0 {
                let any_reconfigure_fire = if reconfig_rule_ids.is_empty() {
                    SmtTerm::bool(false)
                } else {
                    sum_terms_balanced(
                        reconfig_rule_ids
                            .iter()
                            .map(|r| SmtTerm::var(delta_var(k, *r)))
                            .collect(),
                    )
                    .gt(SmtTerm::int(0))
                };
                let inc = SmtTerm::Ite(
                    Box::new(any_reconfigure_fire),
                    Box::new(SmtTerm::int(1)),
                    Box::new(SmtTerm::int(0)),
                );
                let max_bound =
                    SmtTerm::int(i64::try_from(max_reconfigurations).unwrap_or(i64::MAX));
                enc.assert_term(
                    SmtTerm::var(reconf_count_var(k + 1))
                        .eq(SmtTerm::var(reconf_count_var(k)).add(inc)),
                );
                enc.assert_term(SmtTerm::var(reconf_count_var(k + 1)).le(max_bound));
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
mod tests;
