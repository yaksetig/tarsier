//! Variable naming conventions for BMC and k-induction encodings.

use std::collections::HashMap;

pub(crate) type MessageVariantGroups = (Vec<Vec<usize>>, Vec<String>, HashMap<String, Vec<usize>>);
pub(crate) type CryptoVariantBuckets = HashMap<(String, String), Vec<(String, Vec<usize>)>>;

/// Variable naming conventions:
/// - `p_i` — parameter i
/// - `kappa_k_l` — counter for location l at step k
/// - `g_k_v` — shared variable v at step k
/// - `delta_k_r` — firing count for rule r at step k
pub(super) fn param_var(i: usize) -> String {
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

pub(super) fn drop_var(step: usize, var: usize) -> String {
    format!("drop_{step}_{var}")
}

pub(super) fn adv_send_var(step: usize, group: usize) -> String {
    format!("advsend_{step}_{group}")
}

pub(super) fn byz_sender_var(step: usize, sender: usize) -> String {
    format!("byzsender_{step}_{sender}")
}

pub(super) fn byz_sender_static_var(sender: usize) -> String {
    format!("byzsender_static_{sender}")
}

pub(super) fn net_pending_var(step: usize, var: usize) -> String {
    format!("net_pending_{step}_{var}")
}

pub(super) fn net_send_var(step: usize, var: usize) -> String {
    format!("net_send_{step}_{var}")
}

pub(super) fn net_forge_var(step: usize, var: usize) -> String {
    format!("net_forge_{step}_{var}")
}

pub(super) fn net_deliver_var(step: usize, var: usize) -> String {
    format!("net_deliver_{step}_{var}")
}

pub(super) fn net_drop_var(step: usize, var: usize) -> String {
    format!("net_drop_{step}_{var}")
}

pub(super) fn parse_internal_sent_flag_var(name: &str) -> Option<usize> {
    name.strip_prefix("__sent_g")?.parse::<usize>().ok()
}
