//! Committee analysis, quantitative analysis functions, round erasure abstraction.
// Submodules use `use super::*` to access these imports; the unused_imports
// lint fires because the items are not referenced directly in this file.
#![allow(unused_imports)]

use sha2::Digest; // trait needed for Sha256::new()/update()/finalize()
use tarsier_ir::threshold_automaton::{LocationId, ParamId, SharedVarId};

use super::property::resolve_param_or_const;
use super::verification::lower_with_active_controls;
use crate::pipeline::*;

mod comm;
mod committee;
mod quantitative;
mod round_abstraction;

pub use comm::{comm_complexity, show_ta};
pub(super) use committee::{analyze_and_constrain_committees, ensure_n_parameter};
pub(super) use quantitative::{
    add_bounds, format_bound, format_scaled_term, format_sum_bounds,
    geometric_rounds_for_confidence, push_prob_sample, push_prob_sensitivity_point, quantile,
    quantitative_reproducibility_fingerprint, scale_bound_by_depth, sha256_hex,
};
pub(super) use round_abstraction::{
    apply_round_erasure_abstraction, base_message_name, build_location_merge_key,
    erase_round_fields_from_message_counter_name, is_erased_var_name,
    message_family_and_recipient_from_counter_name, normalize_erased_var_names,
};

#[cfg(test)]
mod tests;
