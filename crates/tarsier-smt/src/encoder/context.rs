//! Shared precomputation context for BMC and k-induction encoders.

use std::collections::{HashMap, HashSet};

use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::threshold_automaton::*;

use super::por::{
    collect_exclusive_crypto_variant_groups, collect_message_counter_flags,
    collect_message_counter_recipient_groups, collect_message_variant_groups,
    compute_por_rule_pruning, location_has_valid_process_identity, message_effective_signed_auth,
    message_family_and_recipient_from_counter_name, message_family_and_sender_from_counter_name,
    message_variant_and_family_from_counter_name, process_identity_buckets,
    sender_channel_key_compromised, PorRulePruning,
};

/// Shared encoder preamble values used by both BMC and k-induction.
pub(super) struct CommonEncoderContext {
    pub(super) num_locs: usize,
    pub(super) num_svars: usize,
    pub(super) num_rules: usize,
    pub(super) num_params: usize,
    pub(super) por_pruning: PorRulePruning,
    pub(super) active_rule_ids: Vec<usize>,
    pub(super) distinct_vars: Vec<(usize, Option<String>)>,
    pub(super) omission_style_faults: bool,
    pub(super) crash_faults: bool,
    pub(super) byzantine_faults: bool,
    pub(super) selective_network: bool,
    pub(super) lossy_delivery: bool,
    pub(super) crash_counter_var: Option<usize>,
    pub(super) n_param: Option<usize>,
    pub(super) role_pop_params: HashMap<String, usize>,
    pub(super) role_loc_ids: HashMap<String, Vec<usize>>,
    pub(super) process_id_buckets: Option<HashMap<(String, i64), Vec<usize>>>,
    pub(super) missing_process_ids: bool,
    pub(super) message_family_recipients: HashMap<(String, Option<String>), Vec<usize>>,
    pub(super) signed_senderless_vars: HashMap<String, Vec<usize>>,
    pub(super) signed_uncompromised_sender_vars: HashMap<String, Vec<usize>>,
    pub(super) family_sender_variant_vars: HashMap<(String, String, String), Vec<usize>>,
    pub(super) family_sender_variants_vec: HashMap<(String, String), Vec<String>>,
    pub(super) signed_sender_channels: Vec<String>,
    pub(super) crypto_object_counter_vars: Vec<usize>,
    pub(super) exclusive_crypto_variant_groups: HashMap<(String, String), Vec<Vec<usize>>>,
    pub(super) message_variant_groups: Vec<Vec<usize>>,
    pub(super) message_family_variants: HashMap<String, Vec<usize>>,
    pub(super) recipient_groups: HashMap<String, Vec<usize>>,
    pub(super) all_message_counter_vars: Vec<usize>,
    pub(super) message_counter_flags: Vec<bool>,
    pub(super) signed_uncompromised_sender_idx_by_var: Vec<Option<usize>>,
    /// Location IDs for each leader role (exactly one process in these locations at all times).
    pub(super) leader_role_locs: Vec<Vec<usize>>,
    /// Whether crash-recovery fault model is active.
    pub(super) crash_recovery: bool,
    /// Location IDs where `__alive=false` (dead locations), for crash-recovery fault budget.
    pub(super) dead_loc_ids: Vec<usize>,
    /// Parameter indices that are time-varying (updated by reconfigure actions).
    pub(super) time_varying_param_ids: Vec<usize>,
}

/// Build the shared preamble context for encoder front-ends.
pub(super) fn build_common_encoder_context(cs: &CounterSystem) -> CommonEncoderContext {
    let ta = cs;
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
    let omission_style_faults = ta.semantics.fault_model == FaultModel::Omission;
    let crash_faults = ta.semantics.fault_model == FaultModel::Crash;
    let crash_recovery = ta.semantics.fault_model == FaultModel::CrashRecovery;
    let byzantine_faults = ta.semantics.fault_model == FaultModel::Byzantine;
    let selective_network = matches!(
        ta.semantics.network_semantics,
        NetworkSemantics::IdentitySelective
            | NetworkSemantics::CohortSelective
            | NetworkSemantics::ProcessSelective
    );
    let lossy_delivery = omission_style_faults || (byzantine_faults && selective_network);
    let crash_counter_var = if crash_faults {
        ta.find_shared_var_by_name("__crashed_count")
            .map(|id| id.as_usize())
    } else {
        None
    };
    let n_param = if num_params > 0 {
        ta.find_param_by_name("n").map(|id| id.as_usize())
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
                role_pop_params.insert(role_name, pid.as_usize());
            }
        }
    }
    let mut role_loc_ids: HashMap<String, Vec<usize>> = HashMap::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        role_loc_ids.entry(loc.role.clone()).or_default().push(id);
    }
    let process_scoped_network =
        ta.semantics.network_semantics == NetworkSemantics::ProcessSelective;
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
            if ta.security.crypto_objects.contains_key(&family) {
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

    let leader_role_locs: Vec<Vec<usize>> = ta
        .leader_roles
        .iter()
        .filter_map(|role| role_loc_ids.get(role).cloned())
        .collect();

    let dead_loc_ids: Vec<usize> = if crash_recovery {
        ta.locations
            .iter()
            .enumerate()
            .filter(|(_, loc)| {
                loc.local_vars.get("__alive").map_or(false, |v| {
                    v == &tarsier_ir::threshold_automaton::LocalValue::Bool(false)
                })
            })
            .map(|(i, _)| i)
            .collect()
    } else {
        Vec::new()
    };

    let time_varying_param_ids: Vec<usize> = ta
        .parameters
        .iter()
        .enumerate()
        .filter(|(_, p)| p.time_varying)
        .map(|(i, _)| i)
        .collect();

    CommonEncoderContext {
        num_locs,
        num_svars,
        num_rules,
        num_params,
        por_pruning,
        active_rule_ids,
        distinct_vars,
        omission_style_faults,
        crash_faults,
        byzantine_faults,
        selective_network,
        lossy_delivery,
        crash_counter_var,
        n_param,
        role_pop_params,
        role_loc_ids,
        process_id_buckets,
        missing_process_ids,
        message_family_recipients,
        signed_senderless_vars,
        signed_uncompromised_sender_vars,
        family_sender_variant_vars,
        family_sender_variants_vec,
        signed_sender_channels,
        crypto_object_counter_vars,
        exclusive_crypto_variant_groups,
        message_variant_groups,
        message_family_variants,
        recipient_groups,
        all_message_counter_vars,
        message_counter_flags,
        signed_uncompromised_sender_idx_by_var,
        leader_role_locs,
        crash_recovery,
        dead_loc_ids,
        time_varying_param_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::*;

    fn minimal_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.parameters.push(Parameter {
            name: "n".into(),
            time_varying: false,
        });
        ta.locations.push(Location {
            name: "Init".into(),
            role: "R".into(),
            phase: "init".into(),
            local_vars: Default::default(),
        });
        ta.locations.push(Location {
            name: "Done".into(),
            role: "R".into(),
            phase: "done".into(),
            local_vars: Default::default(),
        });
        ta.initial_locations = vec![0.into()];
        ta.shared_vars.push(SharedVar {
            name: "x".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });
        ta
    }

    #[test]
    fn context_counts_match_ta() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.num_locs, 2);
        assert_eq!(ctx.num_svars, 1);
        assert_eq!(ctx.num_params, 1);
        assert_eq!(ctx.num_rules, 0);
    }

    #[test]
    fn context_n_param_found() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.n_param, Some(0));
    }

    #[test]
    fn context_n_param_missing_when_no_params() {
        let mut ta = ThresholdAutomaton::new();
        ta.locations.push(Location {
            name: "A".into(),
            role: "R".into(),
            phase: "a".into(),
            local_vars: Default::default(),
        });
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.n_param, None);
    }

    #[test]
    fn context_default_fault_model_is_byzantine() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert!(ctx.byzantine_faults);
        assert!(!ctx.crash_faults);
        assert!(!ctx.omission_style_faults);
        assert!(!ctx.crash_recovery);
    }

    #[test]
    fn context_crash_faults_detected() {
        let mut ta = minimal_ta();
        ta.semantics.fault_model = FaultModel::Crash;
        let ctx = build_common_encoder_context(&ta);
        assert!(ctx.crash_faults);
        assert!(!ctx.byzantine_faults);
    }

    #[test]
    fn context_role_loc_ids_grouped() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.role_loc_ids.get("R").unwrap(), &vec![0, 1]);
    }

    #[test]
    fn context_message_counter_flags_all_false_when_no_counters() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.message_counter_flags, vec![false]);
        assert!(ctx.all_message_counter_vars.is_empty());
    }

    #[test]
    fn context_message_counter_flags_detected() {
        let mut ta = minimal_ta();
        ta.shared_vars.push(SharedVar {
            name: "cnt_vote@Alice".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.message_counter_flags, vec![false, true]);
        assert_eq!(ctx.all_message_counter_vars, vec![1]);
    }

    #[test]
    fn context_distinct_vars_collected() {
        let mut ta = minimal_ta();
        ta.shared_vars[0].distinct = true;
        ta.shared_vars[0].distinct_role = Some("R".into());
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.distinct_vars, vec![(0, Some("R".to_string()))]);
    }

    #[test]
    fn context_active_rules_all_when_por_off() {
        let mut ta = minimal_ta();
        ta.semantics.por_mode = PorMode::Off;
        ta.rules.push(Rule {
            from: 0.into(),
            to: 1.into(),
            guard: Guard { atoms: vec![] },
            updates: vec![],
            collection_updates: vec![],
            clock_guards: vec![],
            clock_updates: vec![],
            param_updates: vec![],
        });
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.active_rule_ids, vec![0]);
    }

    #[test]
    fn context_time_varying_params_collected() {
        let mut ta = minimal_ta();
        ta.parameters.push(Parameter {
            name: "epoch_n".into(),
            time_varying: true,
        });
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.time_varying_param_ids, vec![1]);
    }

    #[test]
    fn context_dead_locs_empty_when_not_crash_recovery() {
        let ta = minimal_ta();
        let ctx = build_common_encoder_context(&ta);
        assert!(ctx.dead_loc_ids.is_empty());
    }

    #[test]
    fn context_dead_locs_found_for_crash_recovery() {
        let mut ta = minimal_ta();
        ta.semantics.fault_model = FaultModel::CrashRecovery;
        ta.locations[1]
            .local_vars
            .insert("__alive".into(), LocalValue::Bool(false));
        let ctx = build_common_encoder_context(&ta);
        assert_eq!(ctx.dead_loc_ids, vec![1]);
    }

    #[test]
    fn context_lossy_delivery_for_omission() {
        let mut ta = minimal_ta();
        ta.semantics.fault_model = FaultModel::Omission;
        let ctx = build_common_encoder_context(&ta);
        assert!(ctx.lossy_delivery);
        assert!(ctx.omission_style_faults);
    }
}
