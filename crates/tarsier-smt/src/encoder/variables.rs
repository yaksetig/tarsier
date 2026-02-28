//! Variable naming conventions for BMC and k-induction encodings.

use std::collections::HashMap;

/// (groups of var ids, family name per group, family → group ids).
pub(crate) type MessageVariantGroups = (Vec<Vec<usize>>, Vec<String>, HashMap<String, Vec<usize>>);
/// (family, recipient) → list of (variant name, var ids).
pub(crate) type CryptoVariantBuckets = HashMap<(String, String), Vec<(String, Vec<usize>)>>;

/// Variable naming conventions:
/// - `p_i` — parameter i
/// - `kappa_k_l` — counter for location l at step k
/// - `g_k_v` — shared variable v at step k
/// - `delta_k_r` — firing count for rule r at step k
pub(super) fn param_var(i: impl std::fmt::Display) -> String {
    format!("p_{i}")
}

/// Counter variable: number of processes at location `loc` at step `step`.
pub(crate) fn kappa_var(step: usize, loc: impl std::fmt::Display) -> String {
    format!("kappa_{step}_{loc}")
}

/// Shared variable `var` at step `step`.
pub(crate) fn gamma_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("g_{step}_{var}")
}

/// Logical timestamp at step `step` (for ordering constraints).
pub(crate) fn time_var(step: usize) -> String {
    format!("time_{step}")
}

/// Firing count for rule `rule` at step `step`.
pub(crate) fn delta_var(step: usize, rule: usize) -> String {
    format!("delta_{step}_{rule}")
}

/// Message drop count for shared var `var` at step `step` (omission faults).
pub(super) fn drop_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("drop_{step}_{var}")
}

/// Adversary message-send count for group `group` at step `step`.
pub(super) fn adv_send_var(step: usize, group: usize) -> String {
    format!("advsend_{step}_{group}")
}

/// Per-step Byzantine sender equivocation variable.
pub(super) fn byz_sender_var(step: usize, sender: usize) -> String {
    format!("byzsender_{step}_{sender}")
}

/// Static Byzantine sender indicator (fixed across all steps).
pub(super) fn byz_sender_static_var(sender: usize) -> String {
    format!("byzsender_static_{sender}")
}

/// Network pending-message count for shared var `var` at step `step`.
pub(super) fn net_pending_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("net_pending_{step}_{var}")
}

/// Network send count for shared var `var` at step `step`.
pub(super) fn net_send_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("net_send_{step}_{var}")
}

/// Adversary-forged message count for shared var `var` at step `step`.
pub(super) fn net_forge_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("net_forge_{step}_{var}")
}

/// Network delivery count for shared var `var` at step `step`.
pub(super) fn net_deliver_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("net_deliver_{step}_{var}")
}

/// Network drop count for shared var `var` at step `step`.
pub(super) fn net_drop_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("net_drop_{step}_{var}")
}

/// Parse `__sent_g<N>` variable names back to their shared-var index.
pub(super) fn parse_internal_sent_flag_var(name: &str) -> Option<usize> {
    name.strip_prefix("__sent_g")?.parse::<usize>().ok()
}
