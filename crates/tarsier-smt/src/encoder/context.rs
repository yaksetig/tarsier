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
    }
}
