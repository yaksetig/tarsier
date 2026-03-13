use std::path::PathBuf;

use tarsier_engine::pipeline::FairnessMode;

use crate::{CliNetworkSemanticsMode, OutputFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProveAutoTarget {
    Safety,
    FairLiveness,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) engine: String,
    pub(crate) fairness: String,
    pub(crate) cert_out: Option<PathBuf>,
    pub(crate) cegar_iters: usize,
    pub(crate) cegar_report_out: Option<PathBuf>,
    pub(crate) portfolio: bool,
    pub(crate) auto_strengthen: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveFairCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) cert_out: Option<PathBuf>,
    pub(crate) cegar_iters: usize,
    pub(crate) cegar_report_out: Option<PathBuf>,
    pub(crate) portfolio: bool,
    pub(crate) format: String,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveRoundCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) engine: String,
    pub(crate) round_vars: Vec<String>,
    pub(crate) format: String,
    pub(crate) out: Option<PathBuf>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(crate) struct ProveFairRoundCommandArgs {
    pub(crate) file: PathBuf,
    pub(crate) solver: String,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) round_vars: Vec<String>,
    pub(crate) format: String,
    pub(crate) out: Option<PathBuf>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
}

#[derive(Debug, Clone)]
pub(super) struct ProveExecutionConfig {
    pub(super) fairness: FairnessMode,
    pub(super) cert_out: Option<PathBuf>,
    pub(super) cegar_iters: usize,
    pub(super) cegar_report_out: Option<PathBuf>,
    pub(super) timeout: u64,
    pub(super) output_format: OutputFormat,
}
