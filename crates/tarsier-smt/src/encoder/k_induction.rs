//! K-induction encoding and property violation helpers.

use std::collections::HashMap;

use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::*;

use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

use super::context::{build_common_encoder_context, CommonEncoderContext};
use super::por::*;
use super::variables::*;
use super::BmcEncoding;

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
    KInductionEncoderBuilder::new(cs, property, k).build()
}

pub(super) struct KInductionEncoderBuilder<'a> {
    ta: &'a ThresholdAutomaton,
    property: &'a SafetyProperty,
    k: usize,
    enc: BmcEncoding,
    context: CommonEncoderContext,
    role_population_targets: HashMap<String, usize>,
    increment_only_var: Vec<bool>,
    sent_flag_true_locs: HashMap<usize, Vec<usize>>,
}

fn param_term_at_step(step: usize, param_id: usize, time_varying_param_ids: &[usize]) -> SmtTerm {
    if time_varying_param_ids.contains(&param_id) {
        SmtTerm::var(param_var_at_step(step, param_id))
    } else {
        SmtTerm::var(param_var(param_id))
    }
}

impl<'a> KInductionEncoderBuilder<'a> {
    pub(super) fn new(cs: &'a CounterSystem, property: &'a SafetyProperty, k: usize) -> Self {
        let ta = cs;
        let context = build_common_encoder_context(cs);

        let mut role_population_targets: HashMap<String, usize> = HashMap::new();
        for role in context.role_loc_ids.keys() {
            let candidate = format!("n_{}", role.to_lowercase());
            if let Some(pid) = ta.find_param_by_name(&candidate) {
                role_population_targets.insert(role.clone(), pid.as_usize());
            }
        }
        if context.role_loc_ids.len() == 1 {
            if let Some(n_pid) = context.n_param {
                if let Some(role_name) = context.role_loc_ids.keys().next() {
                    role_population_targets
                        .entry(role_name.clone())
                        .or_insert(n_pid);
                }
            }
        }

        let increment_only_var: Vec<bool> = (0..context.num_svars)
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
                    if counter_id < context.num_svars && matches!(value, LocalValue::Bool(true)) {
                        sent_flag_true_locs
                            .entry(counter_id)
                            .or_default()
                            .push(loc_id);
                    }
                }
            }
        }

        Self {
            ta,
            property,
            k,
            enc: BmcEncoding::new(),
            context,
            role_population_targets,
            increment_only_var,
            sent_flag_true_locs,
        }
    }

    fn build(mut self) -> BmcEncoding {
        self.phase_declare_parameters_and_resilience();
        self.phase_declare_state_and_transition_variables();
        self.phase_encode_transition_relation_and_fault_bounds();
        self.phase_encode_induction_goal();
        self.enc
    }

    #[cfg(test)]
    pub(super) fn encoding(&self) -> &BmcEncoding {
        &self.enc
    }

    pub(super) fn phase_declare_parameters_and_resilience(&mut self) {
        let ta = self.ta;
        let num_params = self.context.num_params;
        let time_varying_param_ids = &self.context.time_varying_param_ids;
        let k = self.k;
        let enc = &mut self.enc;
        if matches!(
            ta.reconfiguration.as_ref().map(|s| s.semantics),
            Some(ReconfigurationSemantics::Immediate)
        ) {
            // Fail closed when callers bypass IR validation.
            enc.assert_term(SmtTerm::bool(false));
            return;
        }
        // Parameters and resilience
        for i in 0..num_params {
            enc.declare(param_var(i), SmtSort::Int);
            enc.assert_term(SmtTerm::var(param_var(i)).ge(SmtTerm::int(0)));
        }
        if ta.semantics.timing_model == TimingModel::PartialSynchrony {
            enc.declare(gst_step_var(), SmtSort::Int);
            enc.assert_term(SmtTerm::var(gst_step_var()).ge(SmtTerm::int(0)));
            enc.assert_term(SmtTerm::var(gst_step_var()).le(SmtTerm::int(k as i64)));
            if let Some(gst_pid) = ta.semantics.gst_param {
                let gst_idx = gst_pid.as_usize();
                enc.assert_term(
                    SmtTerm::var(gst_step_var())
                        .eq(param_term_at_step(0, gst_idx, time_varying_param_ids)),
                );
            }
        }
        for &i in time_varying_param_ids {
            for step in 0..=k {
                enc.declare(param_var_at_step(step, i), SmtSort::Int);
                enc.assert_term(SmtTerm::var(param_var_at_step(step, i)).ge(SmtTerm::int(0)));
            }
            enc.assert_term(SmtTerm::var(param_var_at_step(0, i)).eq(SmtTerm::var(param_var(i))));
        }
        if let Some(ref rc) = ta.constraints.resilience_condition {
            if time_varying_param_ids.is_empty() {
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
            } else {
                for step in 0..=k {
                    let lhs = encode_lc_at_step(&rc.lhs, step, time_varying_param_ids);
                    let rhs = encode_lc_at_step(&rc.rhs, step, time_varying_param_ids);
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
        }
    }

    pub(super) fn phase_declare_state_and_transition_variables(&mut self) {
        let ta = self.ta;
        let k = self.k;
        let num_locs = self.context.num_locs;
        let num_svars = self.context.num_svars;
        let num_rules = self.context.num_rules;
        let por_pruning = &self.context.por_pruning;
        let distinct_vars = &self.context.distinct_vars;
        let role_pop_params = &self.context.role_pop_params;
        let n_param = self.context.n_param;
        let role_loc_ids = &self.context.role_loc_ids;
        let role_population_targets = &self.role_population_targets;
        let process_id_buckets = &self.context.process_id_buckets;
        let missing_process_ids = self.context.missing_process_ids;
        let byzantine_faults = self.context.byzantine_faults;
        let signed_sender_channels = &self.context.signed_sender_channels;
        let message_counter_flags = &self.context.message_counter_flags;
        let time_varying_param_ids = &self.context.time_varying_param_ids;
        let max_reconfigurations = ta
            .reconfiguration
            .as_ref()
            .map(|spec| spec.max_reconfigurations)
            .unwrap_or(0);
        let lossy_delivery = self.context.lossy_delivery;
        let selective_network = self.context.selective_network;
        let message_variant_groups = &self.context.message_variant_groups;
        let sent_flag_true_locs = &self.sent_flag_true_locs;
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
        let enc = &mut self.enc;
        // Declare state variables for steps 0..k
        for step in 0..=k {
            for l in 0..num_locs {
                enc.declare(kappa_var(step, l), SmtSort::Int);
                enc.assert_term(SmtTerm::var(kappa_var(step, l)).ge(SmtTerm::int(0)));
                if let Some(n_pid) = n_param {
                    enc.assert_term(SmtTerm::var(kappa_var(step, l)).le(param_term_at_step(
                        step,
                        n_pid,
                        time_varying_param_ids,
                    )));
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
            for c in 0..ta.clocks.len() {
                enc.declare(clock_var(step, c), SmtSort::Int);
                enc.assert_term(SmtTerm::var(clock_var(step, c)).ge(SmtTerm::int(0)));
                if step == 0 {
                    enc.assert_term(SmtTerm::var(clock_var(step, c)).eq(SmtTerm::int(0)));
                }
            }
            enc.declare(time_var(step), SmtSort::Int);
            enc.assert_term(SmtTerm::var(time_var(step)).ge(SmtTerm::int(0)));
            if max_reconfigurations > 0 {
                enc.declare(reconf_count_var(step), SmtSort::Int);
                enc.assert_term(SmtTerm::var(reconf_count_var(step)).ge(SmtTerm::int(0)));
                if step == 0 {
                    enc.assert_term(SmtTerm::var(reconf_count_var(step)).eq(SmtTerm::int(0)));
                }
            }

            // DAG rounds: boolean activation flags with parent dependency across steps.
            for (rid, parents) in dag_parent_indices.iter().enumerate() {
                let active = dag_round_active_var(step, rid);
                enc.declare(active.clone(), SmtSort::Int);
                enc.assert_term(SmtTerm::var(active.clone()).ge(SmtTerm::int(0)));
                enc.assert_term(SmtTerm::var(active.clone()).le(SmtTerm::int(1)));
                if step == 0 {
                    enc.assert_term(SmtTerm::var(active).eq(SmtTerm::int(0)));
                } else {
                    let prev = dag_round_active_var(step - 1, rid);
                    enc.assert_term(SmtTerm::var(active.clone()).ge(SmtTerm::var(prev)));
                    for parent_id in parents {
                        enc.assert_term(
                            SmtTerm::var(active.clone())
                                .le(SmtTerm::var(dag_round_active_var(step - 1, *parent_id))),
                        );
                    }
                }
            }

            for (v, role) in distinct_vars {
                if let Some(role) = role {
                    if let Some(&pid) = role_pop_params.get(role) {
                        enc.assert_term(SmtTerm::var(gamma_var(step, *v)).le(param_term_at_step(
                            step,
                            pid,
                            time_varying_param_ids,
                        )));
                        continue;
                    }
                }
                if let Some(n_param) = n_param {
                    enc.assert_term(SmtTerm::var(gamma_var(step, *v)).le(param_term_at_step(
                        step,
                        n_param,
                        time_varying_param_ids,
                    )));
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
                enc.assert_term(total.eq(param_term_at_step(step, n_pid, time_varying_param_ids)));
            }

            // Strengthening: per-role conservation when a role-population parameter exists.
            for (role, locs) in role_loc_ids {
                if let Some(&pid) = role_population_targets.get(role) {
                    let total = locs
                        .iter()
                        .map(|l| SmtTerm::var(kappa_var(step, *l)))
                        .collect::<Vec<_>>();
                    let total = sum_terms_balanced(total);
                    enc.assert_term(total.eq(param_term_at_step(
                        step,
                        pid,
                        time_varying_param_ids,
                    )));
                }
            }

            // Leader role constraint: exactly one process in leader locations at each step.
            for leader_locs in &self.context.leader_role_locs {
                let parts: Vec<SmtTerm> = leader_locs
                    .iter()
                    .map(|&l| SmtTerm::var(kappa_var(step, l)))
                    .collect();
                if !parts.is_empty() {
                    enc.assert_term(sum_terms_balanced(parts).eq(SmtTerm::int(1)));
                }
            }

            if let Some(buckets) = process_id_buckets {
                assert_process_identity_uniqueness(enc, step, buckets);
            }

            // Strengthening: internal sender-uniqueness flags imply message-counter lower bounds.
            // number_of_processes_with(__sent_gv = true) <= g_v
            for (counter_id, locs) in sent_flag_true_locs {
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
            if selective_network && ta.semantics.delivery_control == DeliveryControlMode::Global {
                for group_vars in message_variant_groups {
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
    }

    pub(super) fn phase_encode_transition_relation_and_fault_bounds(&mut self) {
        let ta = self.ta;
        let k = self.k;
        let num_locs = self.context.num_locs;
        let num_svars = self.context.num_svars;
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
        let signed_uncompromised_sender_idx_by_var =
            &self.context.signed_uncompromised_sender_idx_by_var;
        let increment_only_var = &self.increment_only_var;
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
        // Transition relation for each step
        for step in 0..k {
            // Location counter updates
            for l in 0..num_locs {
                let mut outgoing = Vec::new();
                let mut incoming = Vec::new();
                for &r in active_rule_ids {
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

            // Leader role constraint at step+1: exactly one process in leader locations.
            for leader_locs in &self.context.leader_role_locs {
                let parts: Vec<SmtTerm> = leader_locs
                    .iter()
                    .map(|&l| SmtTerm::var(kappa_var(step + 1, l)))
                    .collect();
                if !parts.is_empty() {
                    enc.assert_term(sum_terms_balanced(parts).eq(SmtTerm::int(1)));
                }
            }

            // Guard enablement and individual delta bound
            for &r in active_rule_ids {
                let rule = &ta.rules[r];
                let dr_pos = SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
                for atom in &rule.guard.atoms {
                    let guard_term = match atom {
                        GuardAtom::Threshold {
                            vars,
                            op,
                            bound,
                            distinct,
                        } => {
                            if time_varying_param_ids.is_empty() {
                                encode_threshold_guard_at_step(step, vars, *op, bound, *distinct)
                            } else {
                                encode_threshold_guard_at_step_epoch(
                                    step,
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
                    let lhs = SmtTerm::var(clock_var(step, guard.clock.as_usize()));
                    let rhs = if time_varying_param_ids.is_empty() {
                        encode_lc(&guard.bound)
                    } else {
                        encode_lc_at_step(&guard.bound, step, time_varying_param_ids)
                    };
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
                SmtTerm::var(time_var(step + 1))
                    .eq(SmtTerm::var(time_var(step)).add(SmtTerm::int(1))),
            );

            // Clock updates and frame conditions.
            for c in 0..ta.clocks.len() {
                let curr = SmtTerm::var(clock_var(step, c));
                let next = SmtTerm::var(clock_var(step + 1, c));
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
                                    updated = if time_varying_param_ids.is_empty() {
                                        updated.add(encode_lc(delta))
                                    } else {
                                        updated.add(encode_lc_at_step(
                                            delta,
                                            step,
                                            time_varying_param_ids,
                                        ))
                                    };
                                }
                            }
                        }
                        let fired = SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
                        enc.assert_term(fired.implies(next.clone().eq(updated)));
                    }
                }
                if updating_rules.is_empty() {
                    enc.assert_term(next.eq(curr));
                } else {
                    let no_updates = SmtTerm::and(
                        updating_rules
                            .iter()
                            .map(|r| SmtTerm::var(delta_var(step, *r)).eq(SmtTerm::int(0)))
                            .collect(),
                    );
                    enc.assert_term(no_updates.implies(next.eq(curr)));
                }
            }

            // Shared variable updates (with adversary and omission drops)
            for (v, inc_only) in increment_only_var.iter().enumerate() {
                let is_message_counter = message_counter_flags.get(v).copied().unwrap_or(false);
                let adv_term = SmtTerm::var(format!("adv_{step}_{v}"));
                let drop_term = lossy_delivery.then(|| SmtTerm::var(drop_var(step, v)));
                let net_deliver_term =
                    is_message_counter.then(|| SmtTerm::var(net_deliver_var(step, v)));
                let mut sent_parts = Vec::new();
                for &r in active_rule_ids {
                    let rule = &ta.rules[r];
                    for upd in &rule.updates {
                        if upd.var == v {
                            match &upd.kind {
                                UpdateKind::Increment => {
                                    sent_parts.push(SmtTerm::var(delta_var(step, r)));
                                }
                                UpdateKind::Set(lc) => {
                                    let dr_pos =
                                        SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
                                    let set_val = if time_varying_param_ids.is_empty() {
                                        encode_lc(lc)
                                    } else {
                                        encode_lc_at_step(lc, step, time_varying_param_ids)
                                    };
                                    enc.assert_term(
                                        dr_pos.implies(
                                            SmtTerm::var(gamma_var(step + 1, v)).eq(set_val),
                                        ),
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
                    if ta.semantics.timing_model == TimingModel::PartialSynchrony
                        && selective_network
                    {
                        let post_gst =
                            SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(step)));
                        if byzantine_faults {
                            if let Some(sender_idx) = signed_uncompromised_sender_idx_by_var
                                .get(v)
                                .copied()
                                .flatten()
                            {
                                let honest_sender =
                                    SmtTerm::var(byz_sender_var(step, sender_idx))
                                        .eq(SmtTerm::int(0));
                                enc.assert_term(
                                    SmtTerm::and(vec![post_gst.clone(), honest_sender])
                                        .implies(net_deliver.clone().eq(available.clone())),
                                );
                            }
                        } else {
                            enc.assert_term(post_gst.implies(net_deliver.clone().eq(available.clone())));
                        }
                    }
                    if ta.semantics.timing_model == TimingModel::PartialSynchrony && lossy_delivery
                    {
                        let post_gst =
                            SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(step)));
                        enc.assert_term(post_gst.implies(net_drop.eq(SmtTerm::int(0))));
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
                    for (var_id, role) in distinct_vars {
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
                            for &r in active_rule_ids {
                                let rule = &ta.rules[r];
                                if rule.updates.iter().any(|u| u.var == v) {
                                    let from_role = &ta.locations[rule.from.as_usize()].role;
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
                                let pop = param_term_at_step(step + 1, pid, time_varying_param_ids);
                                enc.assert_term(gamma_next.le(pop));
                            } else if let Some(n_param) = n_param {
                                let pop =
                                    param_term_at_step(step + 1, n_param, time_varying_param_ids);
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
                            if ta.semantics.timing_model == TimingModel::PartialSynchrony {
                                let post_gst =
                                    SmtTerm::var(gst_step_var()).le(SmtTerm::var(time_var(step)));
                                enc.assert_term(post_gst.implies(drop_term.eq(SmtTerm::int(0))));
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

            if !time_varying_param_ids.is_empty() {
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
                        enc.assert_term(
                            SmtTerm::var(param_var_at_step(step + 1, pid))
                                .eq(SmtTerm::var(param_var_at_step(step, pid))),
                        );
                    } else {
                        for &(r, value) in &update_rules {
                            let dr_pos = SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0));
                            let new_val = encode_lc_at_step(value, step, time_varying_param_ids);
                            enc.assert_term(dr_pos.implies(
                                SmtTerm::var(param_var_at_step(step + 1, pid)).eq(new_val),
                            ));
                        }
                        let any_fires = sum_terms_balanced(
                            update_rules
                                .iter()
                                .map(|&(r, _)| SmtTerm::var(delta_var(step, r)))
                                .collect(),
                        )
                        .gt(SmtTerm::int(0));
                        enc.assert_term(
                            SmtTerm::not(any_fires).implies(
                                SmtTerm::var(param_var_at_step(step + 1, pid))
                                    .eq(SmtTerm::var(param_var_at_step(step, pid))),
                            ),
                        );

                        if update_rules.len() > 1 {
                            let fire_indicators: Vec<SmtTerm> = update_rules
                                .iter()
                                .map(|&(r, _)| {
                                    SmtTerm::Ite(
                                        Box::new(
                                            SmtTerm::var(delta_var(step, r)).gt(SmtTerm::int(0)),
                                        ),
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
            }

            if max_reconfigurations > 0 {
                let any_reconfigure_fire = if reconfig_rule_ids.is_empty() {
                    SmtTerm::bool(false)
                } else {
                    sum_terms_balanced(
                        reconfig_rule_ids
                            .iter()
                            .map(|r| SmtTerm::var(delta_var(step, *r)))
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
                    SmtTerm::var(reconf_count_var(step + 1))
                        .eq(SmtTerm::var(reconf_count_var(step)).add(inc)),
                );
                enc.assert_term(SmtTerm::var(reconf_count_var(step + 1)).le(max_bound));
            }
        }

        // Crypto objects are derived artifacts; do not allow standalone adversarial forge traffic.
        for step in 0..k {
            for v in crypto_object_counter_vars {
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
        if let Some(adv_param) = ta.constraints.adversary_bound_param {
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
                        enc.assert_term(
                            SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)),
                        );
                        enc.assert_term(
                            SmtTerm::var(drop_var(step, v)).le(SmtTerm::var(param_var(adv_param))),
                        );
                    } else {
                        enc.assert_term(
                            SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)),
                        );
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
                    for ((_family, recipient), vars) in message_family_recipients {
                        if recipient.is_none() || vars.is_empty() {
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
                if byzantine_faults && selective_network {
                    for group_id in 0..message_variant_groups.len() {
                        enc.assert_term(
                            SmtTerm::var(adv_send_var(step, group_id))
                                .le(SmtTerm::var(param_var(adv_param))),
                        );
                    }
                }
                if crash_faults {
                    for v in all_message_counter_vars {
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
                if crash_recovery {
                    for v in all_message_counter_vars {
                        enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_drop_var(step, *v)).eq(SmtTerm::int(0)));
                    }
                    if !dead_loc_ids.is_empty() {
                        let dead_sum: Vec<SmtTerm> = dead_loc_ids
                            .iter()
                            .map(|&l| SmtTerm::var(kappa_var(step + 1, l)))
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
                for step in 0..k {
                    for vars in signed_senderless_vars.values() {
                        for v in vars {
                            enc.assert_term(
                                SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)),
                            );
                            enc.assert_term(
                                SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)),
                            );
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

                for (v, _) in distinct_vars {
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
                            .map(|v| SmtTerm::var(format!("adv_{step}_{v}")))
                            .collect::<Vec<_>>();
                        let sum = sum_terms_balanced(sum);
                        enc.assert_term(sum.le(SmtTerm::var(param_var(adv_param))));
                    }
                }
                if selective_network {
                    for step in 0..k {
                        for (family, group_ids) in message_family_variants {
                            if group_ids.is_empty()
                                || !message_effective_non_equivocating(ta, family)
                            {
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
        } else if omission_style_faults || crash_faults || crash_recovery {
            for step in 0..k {
                for v in 0..num_svars {
                    enc.assert_term(SmtTerm::var(format!("adv_{step}_{v}")).eq(SmtTerm::int(0)));
                    if omission_style_faults {
                        enc.assert_term(SmtTerm::var(drop_var(step, v)).eq(SmtTerm::int(0)));
                    }
                }
                if crash_faults {
                    for v in all_message_counter_vars {
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
                if crash_recovery {
                    for v in all_message_counter_vars {
                        enc.assert_term(SmtTerm::var(net_forge_var(step, *v)).eq(SmtTerm::int(0)));
                        enc.assert_term(SmtTerm::var(net_drop_var(step, *v)).eq(SmtTerm::int(0)));
                    }
                    for &l in dead_loc_ids {
                        enc.assert_term(SmtTerm::var(kappa_var(step + 1, l)).eq(SmtTerm::int(0)));
                    }
                }
            }
        }
    }

    pub(super) fn phase_encode_induction_goal(&mut self) {
        let ta = self.ta;
        let property = self.property;
        let k = self.k;
        let enc = &mut self.enc;

        // Induction hypotheses: property holds for 0..k-1
        for step in 0..k {
            let viol = encode_property_violation_at_step(ta, property, step);
            enc.assert_term(SmtTerm::not(viol));
        }
        // Step goal: property violated at k
        enc.assert_term(encode_property_violation_at_step(ta, property, k));
    }
}
/// Encode the negation of a safety property at some step.
/// Returns a term that is SAT iff the property is violated.
pub(super) fn encode_property_violation_at_step(
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
                if !goals.contains(&LocationId::from(l)) {
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

/// Build the property-violation disjunction: ∨_{k=0}^{max_depth} bad(k).
///
/// Each step's violation is produced by [`encode_property_violation_at_step`].
pub(super) fn encode_property_violation(
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
    use indexmap::IndexMap;

    fn build_reconfig_ta() -> (ThresholdAutomaton, LocationId) {
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
        ta.constraints.resilience_condition = Some(LinearConstraint {
            lhs: LinearCombination {
                constant: 0,
                terms: vec![(1, ParamId::from(0))], // n
            },
            op: CmpOp::Gt,
            rhs: LinearCombination {
                constant: 0,
                terms: vec![(3, ParamId::from(1))], // 3*t
            },
        });
        (ta, l1)
    }

    #[test]
    fn k_induction_declares_epoch_param_vars_for_reconfigure() {
        let (ta, l1) = build_reconfig_ta();
        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 2);
        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        assert!(decl_names.contains(&"p_1_0"));
        assert!(decl_names.contains(&"p_1_1"));
        assert!(decl_names.contains(&"p_1_2"));
    }

    #[test]
    fn k_induction_emits_reconfiguration_counter_when_bounded() {
        let (mut ta, l1) = build_reconfig_ta();
        ta.reconfiguration = Some(ReconfigurationSpec {
            semantics: ReconfigurationSemantics::NextStep,
            max_reconfigurations: 1,
        });

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 1);
        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(decl_names.contains(&"reconf_count_0"));
        assert!(decl_names.contains(&"reconf_count_1"));

        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("reconf_count_1") && a.contains("<=") && a.contains("1")),
            "expected max_reconfigurations upper bound constraint"
        );
    }

    #[test]
    fn k_induction_fail_closed_on_immediate_reconfiguration_semantics() {
        let (mut ta, l1) = build_reconfig_ta();
        ta.reconfiguration = Some(ReconfigurationSpec {
            semantics: ReconfigurationSemantics::Immediate,
            max_reconfigurations: 0,
        });

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 1);
        assert!(
            encoding.assertions.contains(&SmtTerm::bool(false)),
            "encoder should fail closed when immediate semantics is requested"
        );
    }

    #[test]
    fn k_induction_partial_synchrony_with_varying_gst_binds_gst_step_to_epoch_zero_param() {
        let (mut ta, l1) = build_reconfig_ta();
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = Some(ParamId::from(1)); // varying "t"

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 2);

        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(decl_names.contains(&"gst_step"));
        assert!(decl_names.contains(&"p_1_0"));

        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("gst_step") && a.contains("p_1_0") && a.contains("=")),
            "expected gst_step to be bound to epoch-0 varying GST parameter"
        );
    }

    #[test]
    fn k_induction_partial_synchrony_with_fixed_gst_binds_gst_step_to_global_param() {
        let (mut ta, l1) = build_reconfig_ta();
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = Some(ParamId::from(0)); // fixed "n"

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 2);

        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(decl_names.contains(&"gst_step"));
        assert!(decl_names.contains(&"p_0"));

        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
        assert!(
            assertions
                .iter()
                .any(|a| a.contains("gst_step") && a.contains("p_0") && a.contains("=")),
            "expected gst_step to be bound to fixed GST parameter p_0"
        );
    }

    #[test]
    fn k_induction_partial_synchrony_without_gst_param_has_unbound_gst_step() {
        let (mut ta, l1) = build_reconfig_ta();
        ta.semantics.timing_model = TimingModel::PartialSynchrony;
        ta.semantics.gst_param = None;

        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 2);

        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(decl_names.contains(&"gst_step"));

        let assertions: Vec<String> = encoding.assertions.iter().map(to_smtlib).collect();
        assert!(
            !assertions
                .iter()
                .any(|a| a.contains("(= gst_step p_") || a.contains("(= p_") && a.contains("gst_step")),
            "gst_step should not be tied to a parameter when gst_param is absent"
        );
    }

    #[test]
    fn k_induction_without_partial_synchrony_does_not_declare_gst_step() {
        let (ta, l1) = build_reconfig_ta();
        let cs = CounterSystem::from(ta);
        let property = SafetyProperty::Invariant {
            bad_sets: vec![vec![l1]],
        };
        let encoding = encode_k_induction_step(&cs, &property, 2);
        let decl_names: Vec<&str> = encoding
            .declarations
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(!decl_names.contains(&"gst_step"));
    }
}
