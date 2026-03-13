//! Prove command module facade.

mod command;
mod execution;
mod helpers;
mod types;

pub(crate) use command::{
    run_prove_command, run_prove_fair_command, run_prove_fair_round_command,
    run_prove_round_command,
};
#[cfg(feature = "governance")]
pub(crate) use helpers::parse_manifest_fairness_mode;
pub(crate) use helpers::{
    build_liveness_governance_report, detect_prove_auto_target, fairness_name,
    fairness_semantics_json,
};
#[cfg(test)]
pub(crate) use helpers::{fair_liveness_obligation_entries, is_safety_property_kind};
pub(crate) use types::{
    ProveAutoTarget, ProveCommandArgs, ProveFairCommandArgs, ProveFairRoundCommandArgs,
    ProveRoundCommandArgs,
};

#[cfg(test)]
mod tests;
