use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use crate::CliNetworkSemanticsMode;

#[derive(Debug, Serialize)]
pub(crate) struct RoundSweepPoint {
    pub(crate) upper_bound: i64,
    pub(crate) result: String,
    pub(crate) details: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoundSweepReport {
    pub(crate) schema_version: u32,
    pub(crate) file: String,
    pub(crate) vars: Vec<String>,
    pub(crate) min_bound: i64,
    pub(crate) max_bound: i64,
    pub(crate) stable_window: usize,
    pub(crate) points: Vec<RoundSweepPoint>,
    pub(crate) candidate_cutoff: Option<i64>,
    pub(crate) stabilized_result: Option<String>,
    pub(crate) note: String,
}

#[derive(Default)]
pub(crate) struct RoundBoundMutationStats {
    pub(crate) matched_targets: usize,
    pub(crate) updated_ranges: usize,
    pub(crate) unbounded_targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifyCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) dump_smt: Option<String>,
    pub(crate) cegar_iters: usize,
    pub(crate) cegar_report_out: Option<PathBuf>,
    pub(crate) portfolio: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct RoundSweepCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) vars: Vec<String>,
    pub(crate) min_bound: i64,
    pub(crate) max_bound: i64,
    pub(crate) stable_window: usize,
    pub(crate) format: String,
    pub(crate) out: Option<PathBuf>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct LivenessCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) dump_smt: Option<String>,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct FairLivenessCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) portfolio: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}
