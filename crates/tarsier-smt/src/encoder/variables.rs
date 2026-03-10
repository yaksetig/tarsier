//! Variable naming conventions for BMC and k-induction encodings.

use std::collections::HashMap;

/// (groups of var ids, family name per group, family → group ids).
pub(crate) type MessageVariantGroups = (Vec<Vec<usize>>, Vec<String>, HashMap<String, Vec<usize>>);
/// (family, recipient) → list of (variant name, var ids).
pub(crate) type CryptoVariantBuckets = HashMap<(String, String), Vec<(String, Vec<usize>)>>;

/// Variable naming conventions:
/// - `p_i` — parameter i (fixed, global)
/// - `p_i_k` — parameter i at step k (time-varying)
/// - `kappa_k_l` — counter for location l at step k
/// - `g_k_v` — shared variable v at step k
/// - `delta_k_r` — firing count for rule r at step k
pub(super) fn param_var(i: impl std::fmt::Display) -> String {
    format!("p_{i}")
}

/// Step-dependent parameter variable for time-varying parameters.
pub(super) fn param_var_at_step(step: usize, i: impl std::fmt::Display) -> String {
    format!("p_{i}_{step}")
}

/// Counter variable: number of processes at location `loc` at step `step`.
pub(crate) fn kappa_var(step: usize, loc: impl std::fmt::Display) -> String {
    format!("kappa_{step}_{loc}")
}

/// Shared variable `var` at step `step`.
pub(crate) fn gamma_var(step: usize, var: impl std::fmt::Display) -> String {
    format!("g_{step}_{var}")
}

/// Logical clock `clock` at step `step`.
pub(crate) fn clock_var(step: usize, clock: impl std::fmt::Display) -> String {
    format!("clk_{step}_{clock}")
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

/// Length of bounded collection `coll` at step `step`.
pub(super) fn coll_len_var(step: usize, coll: usize) -> String {
    format!("clen_{step}_{coll}")
}

/// Head index of FIFO queue `coll` at step `step`.
pub(super) fn queue_head_var(step: usize, coll: usize) -> String {
    format!("qhead_{step}_{coll}")
}

/// Tail index of FIFO queue `coll` at step `step`.
pub(super) fn queue_tail_var(step: usize, coll: usize) -> String {
    format!("qtail_{step}_{coll}")
}

/// DAG-round active flag for round `round` at step `step`.
pub(super) fn dag_round_active_var(step: usize, round: usize) -> String {
    format!("dag_active_{step}_{round}")
}

/// Parse `__sent_g<N>` variable names back to their shared-var index.
pub(super) fn parse_internal_sent_flag_var(name: &str) -> Option<usize> {
    name.strip_prefix("__sent_g")?.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── param_var ──

    #[test]
    fn param_var_basic() {
        assert_eq!(param_var(0), "p_0");
        assert_eq!(param_var(42), "p_42");
    }

    #[test]
    fn param_var_string_index() {
        assert_eq!(param_var("n"), "p_n");
    }

    // ── param_var_at_step ──

    #[test]
    fn param_var_at_step_basic() {
        assert_eq!(param_var_at_step(0, 1), "p_1_0");
        assert_eq!(param_var_at_step(3, 2), "p_2_3");
    }

    // ── kappa_var ──

    #[test]
    fn kappa_var_format() {
        assert_eq!(kappa_var(0, 5), "kappa_0_5");
        assert_eq!(kappa_var(10, 3), "kappa_10_3");
    }

    // ── gamma_var ──

    #[test]
    fn gamma_var_format() {
        assert_eq!(gamma_var(0, 0), "g_0_0");
        assert_eq!(gamma_var(2, "myvar"), "g_2_myvar");
    }

    // ── clock_var ──

    #[test]
    fn clock_var_format() {
        assert_eq!(clock_var(1, "deadline"), "clk_1_deadline");
        assert_eq!(clock_var(0, 0), "clk_0_0");
    }

    // ── time_var ──

    #[test]
    fn time_var_format() {
        assert_eq!(time_var(0), "time_0");
        assert_eq!(time_var(99), "time_99");
    }

    // ── delta_var ──

    #[test]
    fn delta_var_format() {
        assert_eq!(delta_var(0, 0), "delta_0_0");
        assert_eq!(delta_var(3, 7), "delta_3_7");
    }

    // ── drop_var ──

    #[test]
    fn drop_var_format() {
        assert_eq!(drop_var(1, 2), "drop_1_2");
        assert_eq!(drop_var(0, "x"), "drop_0_x");
    }

    // ── adv_send_var ──

    #[test]
    fn adv_send_var_format() {
        assert_eq!(adv_send_var(0, 0), "advsend_0_0");
        assert_eq!(adv_send_var(5, 3), "advsend_5_3");
    }

    // ── byz_sender_var ──

    #[test]
    fn byz_sender_var_format() {
        assert_eq!(byz_sender_var(1, 2), "byzsender_1_2");
    }

    // ── byz_sender_static_var ──

    #[test]
    fn byz_sender_static_var_format() {
        assert_eq!(byz_sender_static_var(0), "byzsender_static_0");
        assert_eq!(byz_sender_static_var(7), "byzsender_static_7");
    }

    // ── net_* vars ──

    #[test]
    fn net_pending_var_format() {
        assert_eq!(net_pending_var(0, 1), "net_pending_0_1");
    }

    #[test]
    fn net_send_var_format() {
        assert_eq!(net_send_var(2, 3), "net_send_2_3");
    }

    #[test]
    fn net_forge_var_format() {
        assert_eq!(net_forge_var(1, "x"), "net_forge_1_x");
    }

    #[test]
    fn net_deliver_var_format() {
        assert_eq!(net_deliver_var(0, 0), "net_deliver_0_0");
    }

    #[test]
    fn net_drop_var_format() {
        assert_eq!(net_drop_var(4, 2), "net_drop_4_2");
    }

    // ── collection vars ──

    #[test]
    fn coll_len_var_format() {
        assert_eq!(coll_len_var(0, 1), "clen_0_1");
    }

    #[test]
    fn queue_head_var_format() {
        assert_eq!(queue_head_var(2, 3), "qhead_2_3");
    }

    #[test]
    fn queue_tail_var_format() {
        assert_eq!(queue_tail_var(1, 0), "qtail_1_0");
    }

    // ── dag_round_active_var ──

    #[test]
    fn dag_round_active_var_format() {
        assert_eq!(dag_round_active_var(0, 1), "dag_active_0_1");
    }

    // ── parse_internal_sent_flag_var ──

    #[test]
    fn parse_sent_flag_valid() {
        assert_eq!(parse_internal_sent_flag_var("__sent_g0"), Some(0));
        assert_eq!(parse_internal_sent_flag_var("__sent_g42"), Some(42));
    }

    #[test]
    fn parse_sent_flag_invalid_prefix() {
        assert_eq!(parse_internal_sent_flag_var("__recv_g0"), None);
        assert_eq!(parse_internal_sent_flag_var("sent_g0"), None);
        assert_eq!(parse_internal_sent_flag_var(""), None);
    }

    #[test]
    fn parse_sent_flag_non_numeric_suffix() {
        assert_eq!(parse_internal_sent_flag_var("__sent_gabc"), None);
        assert_eq!(parse_internal_sent_flag_var("__sent_g"), None);
    }

    #[test]
    fn all_var_names_unique_at_same_step() {
        // Verify no accidental collisions between naming conventions at same step
        let step = 0;
        let names: Vec<String> = vec![
            param_var(0),
            kappa_var(step, 0),
            gamma_var(step, 0),
            clock_var(step, 0),
            time_var(step),
            delta_var(step, 0),
            drop_var(step, 0),
            adv_send_var(step, 0),
            byz_sender_var(step, 0),
            byz_sender_static_var(0),
            net_pending_var(step, 0),
            net_send_var(step, 0),
            net_forge_var(step, 0),
            net_deliver_var(step, 0),
            net_drop_var(step, 0),
            coll_len_var(step, 0),
            queue_head_var(step, 0),
            queue_tail_var(step, 0),
            dag_round_active_var(step, 0),
        ];
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "variable names must be unique: {:?}", names);
    }
}
