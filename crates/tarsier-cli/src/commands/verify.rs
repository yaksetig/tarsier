//! Verification command module wiring.

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use serde_json::json;

#[cfg(test)]
use tarsier_engine::result::{
    FairLivenessResult, LivenessResult, UnboundedSafetyResult, VerificationResult,
};

#[cfg(test)]
use crate::CliNetworkSemanticsMode;

mod cegar;
mod command;
mod portfolio;
mod results;
mod rounds;
mod types;

#[cfg(test)]
pub(crate) use self::cegar::{
    cegar_diff_friendly_projection, cegar_with_provenance, strip_cegar_volatile_fields,
};
pub(crate) use self::cegar::{
    cegar_report_details, unbounded_fair_cegar_report_details,
    unbounded_safety_cegar_report_details,
};
pub(crate) use self::command::{
    run_comm_command, run_fair_liveness_command, run_liveness_command, run_round_sweep_command,
    run_verify_command,
};
pub(crate) use self::portfolio::{
    merge_portfolio_fair_liveness_results, merge_portfolio_liveness_results,
    merge_portfolio_prove_fair_results, merge_portfolio_prove_results,
    merge_portfolio_verify_reports, write_json_artifact,
};
#[cfg(test)]
pub(crate) use self::portfolio::{prefer_trace_a, trace_fingerprint};
pub(crate) use self::results::{
    cti_details, fair_liveness_result_details, fair_liveness_result_kind,
    liveness_convergence_diagnostics, liveness_result_details, liveness_result_kind,
    liveness_unknown_reason_payload, trace_details, trace_json, unbounded_fair_result_details,
    unbounded_fair_result_kind, unbounded_safety_result_details, unbounded_safety_result_kind,
    verification_result_details, verification_result_kind,
};
#[cfg(test)]
pub(crate) use self::rounds::round_name_matches;
pub(crate) use self::rounds::{
    apply_round_upper_bound, detect_round_sweep_cutoff, render_prove_fair_round_text,
    render_prove_round_text, render_round_sweep_text,
};
pub(crate) use self::types::{
    FairLivenessCommandArgs, LivenessCommandArgs, RoundBoundMutationStats, RoundSweepCommandArgs,
    RoundSweepPoint, RoundSweepReport, VerifyCommandArgs,
};

#[cfg(test)]
mod tests;
