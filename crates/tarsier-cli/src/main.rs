#![doc = include_str!("../README.md")]

mod commands;
mod tui;

// Re-export items used by both binary code and the test module.
pub(crate) use commands::helpers::{
    canonical_verdict_from_layer_result, certificate_bundle_from_fair_liveness,
    certificate_bundle_from_safety, execution_controls_from_cli, network_faithfulness_section,
    obligations_all_unsat, parse_cli_network_semantics_mode, proof_engine_name,
    render_fallback_summary, render_optimization_summary, render_phase_profile_summary,
    run_diagnostics_details, sandbox_config_from_cli, solver_name,
    validate_cli_network_semantics_mode, write_certificate_bundle, write_certificate_bundle_quiet,
};
#[cfg(feature = "governance")]
pub(crate) use commands::helpers::{
    cli_network_mode_name, declared_network_mode_in_program, parse_manifest_proof_engine,
    parse_output_format, run_external_solver_with_proof, sanitize_artifact_component,
    soundness_name,
};

#[cfg(any(test, feature = "governance"))]
pub(crate) use commands::verify::verification_result_kind;
pub(crate) use commands::verify::{
    cegar_report_details, cti_details, liveness_convergence_diagnostics,
    liveness_unknown_reason_payload, merge_portfolio_fair_liveness_results,
    merge_portfolio_liveness_results, merge_portfolio_prove_fair_results,
    merge_portfolio_prove_results, merge_portfolio_verify_reports, render_prove_fair_round_text,
    render_prove_round_text, trace_details, unbounded_fair_cegar_report_details,
    unbounded_fair_result_details, unbounded_fair_result_kind,
    unbounded_safety_cegar_report_details, unbounded_safety_result_details,
    unbounded_safety_result_kind, write_json_artifact,
};
#[cfg(feature = "governance")]
pub(crate) use commands::verify::{fair_liveness_result_kind, liveness_result_kind};

#[cfg(feature = "governance")]
pub(crate) use commands::analyze::run_analysis;
#[cfg(any(test, feature = "governance"))]
pub(crate) use commands::conformance::run_conformance_suite;
pub(crate) use commands::lint::lint_protocol_file;
#[cfg(feature = "governance")]
pub(crate) use commands::prove::parse_manifest_fairness_mode;
pub(crate) use commands::prove::{
    build_liveness_governance_report, detect_prove_auto_target, fairness_name,
    fairness_semantics_json, ProveAutoTarget,
};

// Re-export governance build_governance_bundle (used by analyze command).
#[cfg(feature = "governance")]
pub(crate) use commands::governance::build_governance_bundle;

// Re-exports used only by the test module (via `super::*`).
#[cfg(test)]
pub(crate) use commands::analyze::{compute_analysis_interpretation, run_portfolio_workers};
#[cfg(test)]
pub(crate) use commands::conformance::{
    CONFORMANCE_TRIAGE_CATEGORIES, CONFORMANCE_TRIAGE_ENGINE_REGRESSION,
    CONFORMANCE_TRIAGE_IMPL_DIVERGENCE, CONFORMANCE_TRIAGE_MODEL_CHANGE,
};
#[cfg(test)]
#[cfg(feature = "governance")]
pub(crate) use commands::governance::{
    classify_cert_suite_check_triage, expected_matches, generate_trust_report,
    has_independent_solver, proof_object_looks_nontrivial,
    validate_cert_suite_report_triage_contract, validate_foundational_profile_requirements,
    validate_manifest_corpus_breadth, validate_manifest_entry_contract,
    validate_manifest_expected_result, validate_manifest_known_bug_sentinel_coverage,
    validate_manifest_library_coverage, validate_manifest_model_hash_consistency,
    validate_manifest_top_level_contract, validate_trusted_check_requirements,
    CertSuiteAssumptions, CertSuiteCheckReport, CertSuiteEntry, CertSuiteEntryReport,
    CertSuiteManifest, CertSuiteReport, GovernanceGateResult, GovernancePipelineReport,
    TrustReport, CERT_SUITE_SCHEMA_VERSION, TRUST_REPORT_SCHEMA_VERSION,
};
#[cfg(test)]
pub(crate) use commands::helpers::{
    assistant_template, augment_query_for_proof, canonicalize_obligation_smt2,
    parse_visualize_check, parse_visualize_format,
};
#[cfg(test)]
pub(crate) use commands::lint::render_lint_text;
#[cfg(test)]
pub(crate) use commands::verify::{
    cegar_diff_friendly_projection, cegar_with_provenance, prefer_trace_a, trace_fingerprint,
    trace_json,
};
#[cfg(test)]
pub(crate) use commands::visualize::DebugFilter;

use clap::{CommandFactory, Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use tarsier_engine::pipeline::{
    set_global_execution_controls, FairnessMode, SolverChoice, SoundnessMode,
};

// External crate re-exports used only by the test module.
#[cfg(all(test, feature = "governance"))]
pub(crate) use tarsier_engine::pipeline::ProofEngine;
#[cfg(test)]
pub(crate) use tarsier_proof_kernel::{
    compute_bundle_sha256, sha256_hex_bytes, CertificateMetadata, CertificateObligationMeta,
    CERTIFICATE_SCHEMA_VERSION,
};

#[cfg(not(feature = "governance"))]
const CLI_LONG_ABOUT: &str =
    "Formal verification tool for consensus protocols using threshold automata.\n\n\
    Canonical beginner path:\n  \
    1. tarsier assist --kind pbft --out my_protocol.trs\n  \
    2. tarsier analyze my_protocol.trs --goal safety\n  \
    3. tarsier visualize my_protocol.trs --check verify\n\n\
    Advanced (optional):\n  \
    - tarsier prove my_protocol.trs --k 12\n\n\
    Use --goal to select what to check (bughunt, safety, safety+liveness, release).\n\
    Use --profile to select expertise level (beginner, pro, governance).";

#[cfg(feature = "governance")]
const CLI_LONG_ABOUT: &str =
    "Formal verification tool for consensus protocols using threshold automata.\n\n\
    Canonical beginner path:\n  \
    1. tarsier assist --kind pbft --out my_protocol.trs\n  \
    2. tarsier analyze my_protocol.trs --goal safety\n  \
    3. tarsier visualize my_protocol.trs --check verify\n\n\
    Governance (optional):\n  \
    - tarsier certify-safety my_protocol.trs --out certs/my_protocol\n\n\
    Use --goal to select what to check (bughunt, safety, safety+liveness, release).\n\
    Use --profile to select expertise level (beginner, pro, governance).";

#[derive(Parser)]
#[command(name = "tarsier")]
#[command(about = "Formal verification tool for consensus protocols using threshold automata")]
#[command(long_about = CLI_LONG_ABOUT)]
#[command(version)]
pub(crate) struct Cli {
    /// Network semantics mode: dsl | faithful
    #[arg(long, global = true, default_value = "dsl")]
    pub(crate) network_semantics: String,

    /// Automatic faithful-network fallback: off | identity | classic
    #[arg(long, global = true, default_value = "off")]
    pub(crate) faithful_fallback: String,

    /// Fallback budget cap for lowered location count
    #[arg(long, global = true, default_value_t = 6000)]
    pub(crate) fallback_max_locations: usize,

    /// Fallback budget cap for lowered shared-variable count
    #[arg(long, global = true, default_value_t = 30000)]
    pub(crate) fallback_max_shared_vars: usize,

    /// Fallback budget cap for lowered message-counter count
    #[arg(long, global = true, default_value_t = 20000)]
    pub(crate) fallback_max_message_counters: usize,

    /// RSS memory budget (MiB) for unbounded fair-liveness proving (0 disables)
    #[arg(long, global = true, default_value_t = 0)]
    pub(crate) liveness_memory_budget_mb: u64,

    /// Global wall-clock timeout (seconds) for sandbox enforcement (default: 600)
    #[arg(long, global = true, default_value_t = 600)]
    pub(crate) sandbox_timeout_secs: u64,

    /// Global RSS memory budget (MiB) for sandbox enforcement (default: 4096)
    #[arg(long, global = true, default_value_t = 4096)]
    pub(crate) sandbox_memory_budget_mb: u64,

    /// Maximum input file size in bytes (default: 1 MiB)
    #[arg(long, global = true, default_value_t = 1048576)]
    pub(crate) sandbox_max_input_bytes: u64,

    /// Allow execution with degraded sandbox controls (e.g., when memory
    /// monitoring is unavailable on the current platform)
    #[arg(long, global = true, default_value_t = false)]
    pub(crate) allow_degraded_sandbox: bool,

    /// Partial-order reduction mode: full | static | off
    #[arg(long, global = true, default_value = "full")]
    pub(crate) por_mode: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a protocol file (advanced — prefer `analyze --goal bughunt`)
    #[command(display_order = 10)]
    Verify {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum BMC depth
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Dump SMT encoding to file
        #[arg(long)]
        dump_smt: Option<String>,

        /// Lightweight CEGAR refinement iterations (0 disables refinement)
        #[arg(long, default_value_t = 0)]
        cegar_iters: usize,

        /// Optional path to write a machine-readable CEGAR stage report (JSON)
        #[arg(long)]
        cegar_report_out: Option<PathBuf>,

        /// Run Z3 and cvc5 in parallel and combine results conservatively
        #[arg(long, default_value_t = false)]
        portfolio: bool,
    },

    /// Sweep round/view upper bounds and report verdict convergence (advanced)
    #[command(display_order = 11)]
    RoundSweep {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Verification depth used for each sweep point
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Round/view variable or field names to sweep (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "view")]
        vars: Vec<String>,

        /// Inclusive lower bound for the swept upper range
        #[arg(long, default_value_t = 2)]
        min_bound: i64,

        /// Inclusive upper bound for the swept upper range
        #[arg(long, default_value_t = 16)]
        max_bound: i64,

        /// Number of trailing equal verdicts required for convergence
        #[arg(long, default_value_t = 3)]
        stable_window: usize,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional JSON output path (used when --format json)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Prove unbounded safety (advanced — prefer `analyze --goal safety`)
    #[command(display_order = 12)]
    Prove {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum induction depth k to try
        #[arg(long, default_value_t = 10)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Unbounded proof engine: kinduction or pdr (IC3/PDR)
        #[arg(long, default_value = "kinduction")]
        engine: String,

        /// Fairness mode used when auto-dispatching to liveness proof: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Optional output directory for proof certificate bundle
        #[arg(long)]
        cert_out: Option<PathBuf>,

        /// Lightweight CEGAR refinement iterations for disproved/unsafe witnesses (0 disables)
        #[arg(long, default_value_t = 0)]
        cegar_iters: usize,

        /// Optional path to write a machine-readable CEGAR proof report (JSON)
        #[arg(long)]
        cegar_report_out: Option<PathBuf>,

        /// Run Z3 and cvc5 in parallel and combine proof outcomes conservatively
        #[arg(long, default_value_t = false)]
        portfolio: bool,
    },

    /// Prove safety via round-erasure over-approximation (advanced)
    #[command(display_order = 13)]
    ProveRound {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum induction/frame depth to try
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Unbounded proof engine: kinduction or pdr (IC3/PDR)
        #[arg(long, default_value = "pdr")]
        engine: String,

        /// Round/view variable names to erase (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "view,round,epoch,height")]
        round_vars: Vec<String>,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional output path for JSON format
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Prove unbounded liveness under fairness (advanced — prefer `analyze --goal safety+liveness`)
    #[command(display_order = 14)]
    ProveFair {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum frame bound k to explore (0 = unbounded until convergence/timeout)
        #[arg(long, default_value_t = 0)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Optional output directory for proof certificate bundle
        #[arg(long)]
        cert_out: Option<PathBuf>,

        /// Lightweight CEGAR refinement iterations for fair-cycle witnesses (0 disables)
        #[arg(long, default_value_t = 0)]
        cegar_iters: usize,

        /// Optional path to write a machine-readable CEGAR proof report (JSON)
        #[arg(long)]
        cegar_report_out: Option<PathBuf>,

        /// Run Z3 and cvc5 in parallel and combine outcomes conservatively
        #[arg(long, default_value_t = false)]
        portfolio: bool,
    },

    /// Prove fair-liveness via round-erasure over-approximation (advanced)
    #[command(display_order = 15)]
    ProveFairRound {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum frame bound k to explore (0 = unbounded until convergence/timeout)
        #[arg(long, default_value_t = 0)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Round/view variable names to erase (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "view,round,epoch,height")]
        round_vars: Vec<String>,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional output path for JSON format
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Parse a protocol file and print the AST (advanced)
    #[command(display_order = 30)]
    Parse {
        /// Path to the .trs protocol file
        file: PathBuf,
    },

    /// Show the threshold automaton for a protocol (advanced)
    #[command(display_order = 31)]
    ShowTa {
        /// Path to the .trs protocol file
        file: PathBuf,
    },

    /// Export the threshold automaton as a Graphviz DOT graph
    #[command(display_order = 32)]
    ExportDot {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Group locations into phase clusters
        #[arg(long, default_value_t = true)]
        cluster: bool,

        /// Pipe through `dot -Tsvg` if available and write SVG output
        #[arg(long)]
        svg: bool,

        /// Output file path (prints to stdout if omitted)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Export the threshold automaton in ByMC .ta format
    #[command(display_order = 33)]
    ExportTa {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Output file path (prints to stdout if omitted)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Analyze committee selection (standalone, no protocol file needed)
    Committee {
        /// Total population size N
        #[arg(long)]
        population: u64,

        /// Number of Byzantine nodes in population K
        #[arg(long)]
        byzantine: u64,

        /// Committee size S
        #[arg(long)]
        size: u64,

        /// Target failure probability epsilon
        #[arg(long, default_value_t = 1e-9)]
        epsilon: f64,
    },

    /// Check bounded liveness: all processes satisfy the liveness target by the given depth
    Liveness {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum depth (bound) for liveness
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Dump SMT encoding to file
        #[arg(long)]
        dump_smt: Option<String>,
    },

    /// Search for bounded fair non-termination lassos
    FairLiveness {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum depth (bound) for lasso search
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Run Z3 and cvc5 in parallel and combine outcomes conservatively
        #[arg(long, default_value_t = false)]
        portfolio: bool,
    },

    /// Visualize counterexample traces from a failing analysis run
    #[command(display_order = 2)]
    Visualize {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Which analysis should produce the trace: verify | liveness | fair-liveness | prove | prove-fair
        #[arg(long, default_value = "verify")]
        check: String,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum BMC depth for verify/liveness/fair-liveness
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Maximum induction/frame bound for prove/prove-fair
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode for fair-liveness / prove-fair: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Proof engine for `check=prove`: kinduction | pdr
        #[arg(long, default_value = "kinduction")]
        engine: String,

        /// Output format: timeline | mermaid | markdown | json
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Optional output file path. If omitted, prints to stdout.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Export all visualization formats into a directory bundle.
        #[arg(long)]
        bundle: Option<PathBuf>,
    },

    /// Interactive counterexample trace explorer (TUI)
    #[command(display_order = 5)]
    Explore {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Which analysis should produce the trace: verify | liveness | fair-liveness
        #[arg(long, default_value = "verify")]
        check: String,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum BMC depth
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Load trace from JSON instead of running analysis
        #[arg(long)]
        trace_json: Option<PathBuf>,
    },

    /// Analyze communication complexity (sound upper bounds)
    Comm {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Maximum depth (bound) for the analysis
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional path to write the JSON report artifact.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Analyze a protocol: the primary entry point for verification.
    ///
    /// Runs a multi-layer analysis pipeline covering safety, liveness, and proof
    /// layers based on the selected goal and profile. Start here if you are new.
    ///
    /// Examples:
    ///   tarsier analyze my_protocol.trs
    ///   tarsier analyze my_protocol.trs --goal safety
    ///   tarsier analyze my_protocol.trs --goal release --profile governance
    #[command(display_order = 0)]
    Analyze {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Analysis goal: what do you want to check?
        ///   bughunt    — quick bug-finding (bounded safety + liveness)
        ///   safety     — bounded + unbounded safety proof
        ///   safety+liveness — full safety + liveness coverage
        ///   release    — audit-grade analysis for governance/CI
        #[arg(long)]
        goal: Option<String>,

        /// Profile preset: beginner | pro | governance | ci-fast | ci-proof | release-gate
        ///   beginner     — safe defaults, actionable output (default)
        ///   pro          — all knobs exposed, expert-level control
        ///   governance   — deterministic CI/audit preset
        ///   ci-fast      — fast CI gate (quick mode, low depth)
        ///   ci-proof     — CI proof gate (proof mode, medium depth)
        ///   release-gate — release gating (audit mode, high depth, portfolio)
        #[arg(long, default_value = "beginner")]
        profile: String,

        /// Enable advanced knobs (required for low-level flags in beginner profile)
        #[arg(long, default_value_t = false)]
        advanced: bool,

        /// Analysis mode: quick | standard | proof | audit (advanced)
        #[arg(long)]
        mode: Option<String>,

        /// Primary solver backend (advanced)
        #[arg(long)]
        solver: Option<String>,

        /// Bounded depth for verify/liveness/fair-liveness layers (advanced)
        #[arg(long)]
        depth: Option<usize>,

        /// Maximum k for unbounded proof layers (advanced)
        #[arg(long)]
        k: Option<usize>,

        /// Timeout in seconds per layer (advanced)
        #[arg(long)]
        timeout: Option<u64>,

        /// Soundness profile: strict | permissive (advanced)
        #[arg(long)]
        soundness: Option<String>,

        /// Fairness mode for fair-liveness layers: weak | strong (advanced)
        #[arg(long)]
        fairness: Option<String>,

        /// Run Z3 and cvc5 in parallel (advanced)
        #[arg(long, default_value_t = false)]
        portfolio: bool,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional path to write the JSON report artifact
        #[arg(long)]
        report_out: Option<PathBuf>,
    },

    /// Run protocol corpus certification suite against expected outcomes
    #[cfg(feature = "governance")]
    CertSuite {
        /// Path to certification manifest JSON
        #[arg(long, default_value = "examples/library/cert_suite.json")]
        manifest: PathBuf,

        /// Solver backend for checks
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Bounded depth for verify checks
        #[arg(long, default_value_t = 6)]
        depth: usize,

        /// Maximum k for unbounded prove/prove-fair checks
        #[arg(long, default_value_t = 8)]
        k: usize,

        /// Timeout in seconds per protocol
        #[arg(long, default_value_t = 120)]
        timeout: u64,

        /// Proof engine default for prove checks: kinduction | pdr
        #[arg(long, default_value = "kinduction")]
        engine: String,

        /// Soundness profile: strict or permissive
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode for optional fair-liveness checks
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional path to write suite report JSON
        #[arg(long)]
        out: Option<PathBuf>,

        /// Optional directory for per-protocol and per-check artifacts
        #[arg(long)]
        artifacts_dir: Option<PathBuf>,
    },

    /// Lint a protocol model for common issues
    #[command(display_order = 3)]
    Lint {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Lint profile: strict or permissive
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Optional report output path (for json mode or CI artifacts)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Interactive counterexample debugger/replayer
    DebugCex {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Which analysis should produce the trace: verify | liveness | fair-liveness | prove | prove-fair
        #[arg(long, default_value = "verify")]
        check: String,

        /// Solver backend to use
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum BMC depth for verify/liveness/fair-liveness
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Maximum induction/frame bound for prove/prove-fair
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict or permissive
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode for fair-liveness / prove-fair: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Proof engine for `check=prove`: kinduction | pdr
        #[arg(long, default_value = "kinduction")]
        engine: String,

        /// Pre-set filter: show only deliveries from this sender role
        #[arg(long)]
        filter_sender: Option<String>,

        /// Pre-set filter: show only deliveries to this recipient role
        #[arg(long)]
        filter_recipient: Option<String>,

        /// Pre-set filter: show only deliveries of this message family
        #[arg(long)]
        filter_message: Option<String>,

        /// Pre-set filter: show only deliveries of this kind (send/deliver/drop/forge/equivocate)
        #[arg(long)]
        filter_kind: Option<String>,

        /// Pre-set filter: show only deliveries whose payload variant contains this substring
        #[arg(long)]
        filter_variant: Option<String>,

        /// Pre-set filter: show only deliveries matching auth metadata
        /// (authenticated|unauthenticated|compromised|uncompromised|`<provenance substring>`)
        #[arg(long)]
        filter_auth: Option<String>,
    },

    /// Scaffold a new protocol from a template
    #[command(display_order = 1)]
    Assist {
        /// Protocol family scaffold: pbft | hotstuff | raft
        #[arg(long, default_value = "pbft")]
        kind: String,

        /// Optional output file path (prints to stdout if omitted)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Print a vetted property template: agreement | validity | termination | liveness | integrity
        #[arg(long)]
        properties: Option<String>,
    },

    /// Check compositional module contracts (assume-guarantee)
    #[command(display_order = 6)]
    ComposeCheck {
        /// Path to the .trs protocol file containing module declarations
        file: PathBuf,
    },

    /// Generate implementation code from a verified .trs protocol (advanced)
    #[command(display_order = 20)]
    Codegen {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Target language: rust | go
        #[arg(long, default_value = "rust")]
        target: String,

        /// Output directory (defaults to current directory)
        #[arg(long, short = 'o', default_value = ".")]
        output: PathBuf,

        /// Path to a certificate bundle directory. Codegen verifies bundle integrity
        /// and that all obligations are unsat before generating code. Required by
        /// default — use --allow-unverified to bypass.
        #[arg(long)]
        require_cert: Option<PathBuf>,

        /// Bypass certificate verification requirement. Generated artifacts will be
        /// marked as unverified with an UNVERIFIED_CODEGEN audit tag.
        #[arg(long, default_value_t = false)]
        allow_unverified: bool,
    },

    /// Validate a runtime trace against a protocol model
    #[command(display_order = 21)]
    ConformanceCheck {
        /// Path to the .trs protocol file
        file: PathBuf,
        /// Path to the runtime trace JSON file
        #[arg(long)]
        trace: PathBuf,
        /// Trace adapter family: runtime | cometbft | etcd-raft
        #[arg(long, default_value = "runtime")]
        adapter: String,
        /// Checker mode: permissive | strict
        #[arg(long, default_value = "permissive")]
        checker_mode: String,
        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Run verification, concretize counterexample to process-level, and self-validate
    #[command(display_order = 22)]
    ConformanceReplay {
        /// Path to the .trs protocol file
        file: PathBuf,
        /// Which analysis: verify | liveness | fair-liveness
        #[arg(long, default_value = "verify")]
        check: String,
        /// Solver backend
        #[arg(long, default_value = "z3")]
        solver: String,
        /// Maximum BMC depth
        #[arg(long, default_value_t = 10)]
        depth: usize,
        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        /// Soundness profile
        #[arg(long, default_value = "strict")]
        soundness: String,
        /// Export the concretized runtime trace to a JSON file
        #[arg(long)]
        export_trace: Option<PathBuf>,
    },

    /// Generate obligation map JSON from a verified protocol model
    #[command(display_order = 23)]
    ConformanceObligations {
        /// Path to the .trs protocol file
        file: PathBuf,
        /// Output file path (stdout if omitted)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Run a conformance test suite from a manifest deterministically
    #[command(display_order = 24)]
    ConformanceSuite {
        /// Path to conformance manifest JSON
        #[arg(long, default_value = "examples/conformance/conformance_suite.json")]
        manifest: PathBuf,
        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
        /// Optional path to write suite report JSON
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional directory for per-entry artifact files (populates artifact_link)
        #[arg(long)]
        artifact_dir: Option<PathBuf>,
    },

    /// Generate shell completions for the given shell
    #[command(display_order = 99)]
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Generate a machine-readable trust report with trust-boundary sections
    #[cfg(feature = "governance")]
    #[command(display_order = 25)]
    GenerateTrustReport {
        /// Governance profile: standard | reinforced | high-assurance
        #[arg(long, default_value = "standard")]
        profile: String,
        /// Protocol file (optional, for report context)
        #[arg(long)]
        protocol_file: Option<String>,
        /// Solver(s) used (comma-separated)
        #[arg(long, default_value = "z3")]
        solvers: String,
        /// Proof engine: kinduction | pdr
        #[arg(long, default_value = "kinduction")]
        engine: String,
        /// Soundness mode: strict | permissive
        #[arg(long, default_value = "strict")]
        soundness: String,
        /// Output path for trust report JSON
        #[arg(long)]
        out: PathBuf,
    },

    /// Generate a safety proof certificate bundle for independent checking
    #[cfg(feature = "governance")]
    #[command(display_order = 4)]
    CertifySafety {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend used for finding the induction k
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum induction depth k to try while searching for a certificate
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Proof engine for certificate generation: kinduction | pdr
        #[arg(long, default_value = "kinduction")]
        engine: String,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Output directory for certificate bundle
        #[arg(long)]
        out: PathBuf,

        /// Capture solver proof objects and bind them to certificate obligations
        #[arg(long, default_value_t = false)]
        capture_proofs: bool,

        /// Allow certificate generation to continue when proof extraction fails
        /// for one or more obligations (default: fail on missing proof)
        #[arg(long, default_value_t = false)]
        allow_missing_proofs: bool,

        /// Write a trust report JSON to the specified path
        #[arg(long)]
        trust_report: Option<PathBuf>,
    },

    /// Generate an independently checkable fair-liveness proof certificate bundle
    #[cfg(feature = "governance")]
    CertifyFairLiveness {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Solver backend used for finding the proof frame
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Maximum frame bound k to explore (0 = unbounded until convergence/timeout)
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Output directory for certificate bundle
        #[arg(long)]
        out: PathBuf,

        /// Capture solver proof objects and bind them to certificate obligations
        #[arg(long, default_value_t = false)]
        capture_proofs: bool,

        /// Allow certificate generation to continue when proof extraction fails
        /// for one or more obligations (default: fail on missing proof)
        #[arg(long, default_value_t = false)]
        allow_missing_proofs: bool,

        /// Write a trust report JSON to the specified path
        #[arg(long)]
        trust_report: Option<PathBuf>,
    },

    /// Check a certificate bundle with external SMT solvers
    #[cfg(feature = "governance")]
    CheckCertificate {
        /// Path to certificate bundle directory
        bundle: PathBuf,

        /// Named governance profile (standard, reinforced, high-assurance).
        /// Sets floor requirements; explicit flags can only strengthen.
        /// high-assurance additionally requires `cvc5` in `--solvers` and
        /// `TARSIER_REQUIRE_CARCARA=1` for external Alethe proof checking.
        #[arg(long)]
        profile: Option<String>,

        /// Comma-separated solver commands to run (e.g. z3,cvc5)
        #[arg(long, default_value = "z3,cvc5")]
        solvers: String,

        /// Optional directory where raw solver proof objects are written
        #[arg(long)]
        emit_proofs: Option<PathBuf>,

        /// Require each UNSAT obligation to include a non-empty solver proof object
        #[arg(long, default_value_t = false)]
        require_proofs: bool,

        /// Optional external proof checker executable.
        /// Called as: <checker> --solver <solver> --smt2 <obligation.smt2> --proof <proof_file>
        #[arg(long)]
        proof_checker: Option<PathBuf>,

        /// Allow trusted-check to proceed without an external proof checker.
        /// This falls back to solver UNSAT + proof-shape heuristics and weakens trust.
        #[arg(long, default_value_t = false)]
        allow_unchecked_proofs: bool,

        /// Re-derive obligations from source and compare hashes before solver checks
        #[arg(long, default_value_t = false)]
        rederive: bool,

        /// Timeout (seconds) for obligation re-derivation
        #[arg(long, default_value_t = 300)]
        rederive_timeout: u64,

        /// Strengthened trust mode (requires --rederive):
        /// N-of-M independent solver confirmations, strict soundness, and UNSAT-only obligations
        #[arg(long, default_value_t = false)]
        trusted_check: bool,

        /// Minimum solver confirmations required per obligation in trusted-check mode
        #[arg(long, default_value_t = 2)]
        min_solvers: usize,
    },

    /// Run all governance gates (proof/cert/corpus/perf) in a single command.
    ///
    /// Orchestrates the full governance pipeline and produces a machine-readable
    /// report with gate-by-gate pass/fail results.
    #[cfg(feature = "governance")]
    #[command(display_order = 26)]
    GovernancePipeline {
        /// Path to the .trs protocol file (used for the proof gate)
        file: PathBuf,

        /// Cert-suite manifest path (cert gate)
        #[arg(long, default_value = "examples/library/cert_suite.json")]
        cert_manifest: PathBuf,

        /// Conformance-suite manifest path (corpus gate)
        #[arg(long, default_value = "examples/conformance/conformance_suite.json")]
        conformance_manifest: PathBuf,

        /// Path to a pre-generated benchmark report JSON (perf gate).
        /// If omitted the perf gate is skipped.
        #[arg(long)]
        benchmark_report: Option<PathBuf>,

        /// Solver backend
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Bounded depth for verify/liveness layers
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Maximum k for unbounded proof layers
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds per layer
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict | permissive
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,

        /// Output path for the governance pipeline report JSON
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a governance bundle signature, schema, and artifact completeness.
    #[cfg(feature = "governance")]
    #[command(display_order = 27)]
    VerifyGovernanceBundle {
        /// Path to governance-bundle.json
        bundle: PathBuf,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AnalysisMode {
    Quick,
    Standard,
    Proof,
    Audit,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CliNetworkSemanticsMode {
    Dsl,
    Faithful,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum VisualizeCheck {
    Verify,
    Liveness,
    FairLiveness,
    Prove,
    ProveFair,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum VisualizeFormat {
    Timeline,
    Mermaid,
    Markdown,
    Json,
}

#[derive(Clone, Copy)]
pub(crate) struct LayerRunCfg {
    pub(crate) solver: SolverChoice,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout: u64,
    pub(crate) soundness: SoundnessMode,
    pub(crate) fairness: FairnessMode,
    pub(crate) cegar_iters: usize,
    pub(crate) portfolio: bool,
}

#[derive(Serialize)]
pub(crate) struct AnalysisConfig {
    pub(crate) solver: String,
    pub(crate) depth: usize,
    pub(crate) k: usize,
    pub(crate) timeout_secs: u64,
    pub(crate) soundness: String,
    pub(crate) fairness: String,
    pub(crate) portfolio: bool,
    pub(crate) por_mode: String,
}

#[derive(Clone, Copy)]
enum CertificateKind {
    SafetyProof,
    FairLivenessProof,
}

impl CertificateKind {
    fn as_str(self) -> &'static str {
        match self {
            CertificateKind::SafetyProof => "safety_proof",
            CertificateKind::FairLivenessProof => "fair_liveness_proof",
        }
    }
}

#[derive(Clone)]
struct CertificateBundleObligation {
    name: String,
    expected: String,
    smt2: String,
}

#[derive(Clone)]
struct CertificateBundleInput {
    kind: CertificateKind,
    protocol_file: String,
    proof_engine: String,
    induction_k: Option<usize>,
    solver_used: String,
    soundness: String,
    fairness: Option<String>,
    committee_bounds: Vec<(String, u64)>,
    obligations: Vec<CertificateBundleObligation>,
}

#[derive(Serialize)]
pub(crate) struct AnalysisLayerReport {
    pub(crate) layer: String,
    pub(crate) status: String,
    pub(crate) verdict: String,
    pub(crate) summary: String,
    pub(crate) details: Value,
    pub(crate) output: String,
}

#[derive(Serialize)]
pub(crate) struct AnalysisReport {
    pub(crate) schema_version: String,
    pub(crate) mode: String,
    pub(crate) file: String,
    pub(crate) config: AnalysisConfig,
    pub(crate) network_faithfulness: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) liveness_governance: Option<Value>,
    pub(crate) layers: Vec<AnalysisLayerReport>,
    pub(crate) overall: String,
    pub(crate) overall_verdict: String,
    pub(crate) interpretation: AnalysisInterpretation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) claim: Option<ClaimStatement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_action: Option<NextAction>,
    pub(crate) confidence_tier: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) preflight_warnings: Vec<Value>,
}

/// Beginner-facing property interpretation.
#[derive(Serialize)]
pub(crate) struct AnalysisInterpretation {
    pub(crate) safety: String,
    pub(crate) liveness: String,
    pub(crate) summary: String,
    pub(crate) overall_status_meaning: String,
}

/// V1-06: What was proven / assumptions / not covered.
#[derive(Serialize)]
pub(crate) struct ClaimStatement {
    pub(crate) proven: Vec<String>,
    pub(crate) assumptions: Vec<String>,
    pub(crate) not_covered: Vec<String>,
}

/// V1-07: Deterministic next-best-command recommendation.
#[derive(Serialize)]
pub(crate) struct NextAction {
    pub(crate) command: String,
    pub(crate) reason: String,
}

// ---------------------------------------------------------------------------
// V1-05: Unified verdict taxonomy
// ---------------------------------------------------------------------------
// Every command maps its native result to one of these canonical labels so
// that text output, JSON reports, and the analyze pipeline all share a single
// vocabulary.

/// Canonical verdict labels shared across all commands and output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CanonicalVerdict {
    Safe,
    Unsafe,
    LiveProved,
    LiveCex,
    Inconclusive,
    Unknown,
}

impl CanonicalVerdict {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CanonicalVerdict::Safe => "SAFE",
            CanonicalVerdict::Unsafe => "UNSAFE",
            CanonicalVerdict::LiveProved => "LIVE_PROVED",
            CanonicalVerdict::LiveCex => "LIVE_CEX",
            CanonicalVerdict::Inconclusive => "INCONCLUSIVE",
            CanonicalVerdict::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for CanonicalVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn main() -> miette::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let cli_network_mode = parse_cli_network_semantics_mode(&cli.network_semantics);
    let exec_controls = execution_controls_from_cli(&cli);
    set_global_execution_controls(exec_controls);

    // Activate runtime sandbox with configured resource limits.
    // The guard is held for the lifetime of the process; dropping it
    // deactivates the sandbox.
    let sandbox_config = sandbox_config_from_cli(&cli);
    let _sandbox_guard =
        tarsier_engine::sandbox::SandboxGuard::activate(sandbox_config).map_err(|e| {
            miette::miette!(
                "Sandbox activation failed: {e}\n\
                 Tarsier requires sandbox enforcement for analysis execution.\n\
                 If you are on a platform without memory monitoring, use --allow-degraded-sandbox."
            )
        })?;

    match cli.command {
        Commands::Verify {
            file,
            solver,
            depth,
            timeout,
            soundness,
            dump_smt,
            cegar_iters,
            cegar_report_out,
            portfolio,
        } => {
            commands::verify::run_verify_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                dump_smt,
                cegar_iters,
                cegar_report_out,
                portfolio,
                cli_network_mode,
            )?;
        }
        Commands::RoundSweep {
            file,
            solver,
            depth,
            timeout,
            soundness,
            vars,
            min_bound,
            max_bound,
            stable_window,
            format,
            out,
        } => {
            commands::verify::run_round_sweep_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                vars,
                min_bound,
                max_bound,
                stable_window,
                format,
                out,
                cli_network_mode,
            )?;
        }
        Commands::Parse { file } => {
            commands::visualize::run_parse_command(file)?;
        }
        Commands::Prove {
            file,
            solver,
            k,
            timeout,
            soundness,
            engine,
            fairness,
            cert_out,
            cegar_iters,
            cegar_report_out,
            portfolio,
        } => {
            commands::prove::run_prove_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                engine,
                fairness,
                cert_out,
                cegar_iters,
                cegar_report_out,
                portfolio,
                cli_network_mode,
            )?;
        }
        Commands::ProveRound {
            file,
            solver,
            k,
            timeout,
            soundness,
            engine,
            round_vars,
            format,
            out,
        } => {
            commands::prove::run_prove_round_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                engine,
                round_vars,
                format,
                out,
                cli_network_mode,
            )?;
        }
        Commands::ProveFairRound {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            round_vars,
            format,
            out,
        } => {
            commands::prove::run_prove_fair_round_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                round_vars,
                format,
                out,
                cli_network_mode,
            )?;
        }
        Commands::ProveFair {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            cert_out,
            cegar_iters,
            cegar_report_out,
            portfolio,
        } => {
            commands::prove::run_prove_fair_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                cert_out,
                cegar_iters,
                cegar_report_out,
                portfolio,
                cli_network_mode,
            )?;
        }
        Commands::ShowTa { file } => {
            commands::visualize::run_show_ta_command(file, cli_network_mode)?;
        }
        Commands::ExportDot {
            file,
            cluster,
            svg,
            out,
        } => {
            commands::visualize::run_export_dot_command(file, cluster, svg, out)?;
        }
        Commands::ExportTa { file, out } => {
            commands::visualize::run_export_ta_command(file, out)?;
        }
        Commands::Committee {
            population,
            byzantine,
            size,
            epsilon,
        } => {
            commands::helpers::run_committee_command(population, byzantine, size, epsilon)?;
        }
        Commands::Liveness {
            file,
            solver,
            depth,
            timeout,
            soundness,
            dump_smt,
        } => {
            commands::verify::run_liveness_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                dump_smt,
                cli_network_mode,
            )?;
        }
        Commands::FairLiveness {
            file,
            solver,
            depth,
            timeout,
            soundness,
            fairness,
            portfolio,
        } => {
            commands::verify::run_fair_liveness_command(
                file,
                solver,
                depth,
                timeout,
                soundness,
                fairness,
                portfolio,
                cli_network_mode,
            )?;
        }
        Commands::Visualize {
            file,
            check,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            engine,
            format,
            out,
            bundle,
        } => {
            commands::visualize::run_visualize_command(
                file,
                check,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                engine,
                format,
                out,
                bundle,
                cli_network_mode,
            )?;
        }
        Commands::Explore {
            file,
            check: _,
            solver,
            depth,
            timeout,
            trace_json,
        } => {
            commands::visualize::run_explore_command(file, solver, depth, timeout, trace_json)?;
        }
        Commands::Comm {
            file,
            depth,
            format,
            out,
        } => {
            commands::verify::run_comm_command(file, depth, format, out, cli_network_mode)?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "tarsier", &mut std::io::stdout());
        }
        #[cfg(feature = "governance")]
        Commands::CertSuite {
            manifest,
            solver,
            depth,
            k,
            timeout,
            engine,
            soundness,
            fairness,
            format,
            out,
            artifacts_dir,
        } => {
            commands::governance::run_cert_suite_command(
                manifest,
                solver,
                depth,
                k,
                timeout,
                engine,
                soundness,
                fairness,
                format,
                out,
                artifacts_dir,
                cli_network_mode,
            )?;
        }
        Commands::Lint {
            file,
            soundness,
            format,
            out,
        } => {
            commands::lint::run_lint_command(file, soundness, format, out, cli_network_mode)?;
        }
        Commands::DebugCex {
            file,
            check,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            engine,
            filter_sender,
            filter_recipient,
            filter_message,
            filter_kind,
            filter_variant,
            filter_auth,
        } => {
            commands::visualize::run_debug_cex_command(
                file,
                check,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                engine,
                filter_sender,
                filter_recipient,
                filter_message,
                filter_kind,
                filter_variant,
                filter_auth,
                cli_network_mode,
            )?;
        }
        Commands::Assist {
            kind,
            out,
            properties,
        } => {
            commands::helpers::run_assist_command(kind, out, properties)?;
        }
        Commands::ComposeCheck { file } => {
            commands::compose::run_compose_check_command(file)?;
        }
        Commands::ConformanceCheck {
            file,
            trace,
            adapter,
            checker_mode,
            format,
        } => {
            commands::conformance::run_conformance_check_command(
                &file,
                &trace,
                &adapter,
                &checker_mode,
                &format,
            )?;
        }
        Commands::ConformanceReplay {
            file,
            check,
            solver,
            depth,
            timeout,
            soundness,
            export_trace,
        } => {
            commands::conformance::run_conformance_replay_command(
                &file,
                &check,
                &solver,
                depth,
                timeout,
                &soundness,
                export_trace.as_ref(),
            )?;
        }
        Commands::ConformanceObligations { file, out } => {
            commands::conformance::run_conformance_obligations_command(&file, out.as_ref())?;
        }
        Commands::ConformanceSuite {
            manifest,
            format,
            out,
            artifact_dir,
        } => {
            commands::conformance::run_conformance_suite_command(
                &manifest,
                &format,
                out.as_ref(),
                artifact_dir.as_deref(),
            )?;
        }
        Commands::Codegen {
            file,
            target,
            output,
            require_cert,
            allow_unverified,
        } => {
            commands::codegen::run_codegen_command(
                file,
                target,
                output,
                require_cert,
                allow_unverified,
            )?;
        }
        Commands::Analyze {
            file,
            goal,
            profile,
            advanced,
            mode,
            solver,
            depth,
            k,
            timeout,
            soundness,
            fairness,
            portfolio,
            format,
            report_out,
        } => {
            commands::analyze::run_analyze_command(commands::analyze::AnalyzeCommandArgs {
                file: &file,
                goal,
                profile: &profile,
                advanced,
                mode,
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                portfolio,
                format: &format,
                report_out: report_out.as_deref(),
                cli_network_mode,
                por_mode: &cli.por_mode,
            })?;
        }
        #[cfg(feature = "governance")]
        Commands::CertifySafety {
            file,
            solver,
            k,
            engine,
            timeout,
            soundness,
            out,
            capture_proofs,
            allow_missing_proofs,
            trust_report,
        } => {
            commands::governance::run_certify_safety_command(
                file,
                solver,
                k,
                engine,
                timeout,
                soundness,
                out,
                capture_proofs,
                allow_missing_proofs,
                trust_report,
                cli_network_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::CertifyFairLiveness {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            out,
            capture_proofs,
            allow_missing_proofs,
            trust_report,
        } => {
            commands::governance::run_certify_fair_liveness_command(
                file,
                solver,
                k,
                timeout,
                soundness,
                fairness,
                out,
                capture_proofs,
                allow_missing_proofs,
                trust_report,
                cli_network_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::CheckCertificate {
            bundle,
            profile,
            solvers,
            emit_proofs,
            require_proofs,
            proof_checker,
            allow_unchecked_proofs,
            rederive,
            rederive_timeout,
            trusted_check,
            min_solvers,
        } => {
            commands::governance::run_check_certificate_command(
                bundle,
                profile,
                solvers,
                emit_proofs,
                require_proofs,
                proof_checker,
                allow_unchecked_proofs,
                rederive,
                rederive_timeout,
                trusted_check,
                min_solvers,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::GenerateTrustReport {
            profile,
            protocol_file,
            solvers,
            engine,
            soundness,
            out,
        } => {
            commands::governance::run_generate_trust_report_command(
                profile,
                protocol_file,
                solvers,
                engine,
                soundness,
                out,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::GovernancePipeline {
            file,
            cert_manifest,
            conformance_manifest,
            benchmark_report,
            solver,
            depth,
            k,
            timeout,
            soundness,
            format,
            out,
        } => {
            commands::governance::run_governance_pipeline_command(
                file,
                cert_manifest,
                conformance_manifest,
                benchmark_report,
                solver,
                depth,
                k,
                timeout,
                soundness,
                format,
                out,
                cli_network_mode,
                &cli.por_mode,
            )?;
        }
        #[cfg(feature = "governance")]
        Commands::VerifyGovernanceBundle { bundle, format } => {
            commands::governance::run_verify_governance_bundle_command(bundle, format)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        assistant_template, augment_query_for_proof, build_liveness_governance_report,
        canonicalize_obligation_smt2, cegar_diff_friendly_projection, cegar_with_provenance,
        compute_analysis_interpretation, compute_bundle_sha256, detect_prove_auto_target,
        lint_protocol_file, merge_portfolio_fair_liveness_results,
        merge_portfolio_liveness_results, merge_portfolio_prove_fair_results,
        merge_portfolio_prove_results, merge_portfolio_verify_reports, obligations_all_unsat,
        parse_cli_network_semantics_mode, parse_visualize_check, parse_visualize_format,
        prefer_trace_a, render_lint_text, render_phase_profile_summary, run_conformance_suite,
        run_diagnostics_details, run_portfolio_workers, sha256_hex_bytes, trace_fingerprint,
        trace_json, unbounded_fair_result_details, verification_result_kind,
        write_certificate_bundle, AnalysisConfig, AnalysisLayerReport, CertificateBundleInput,
        CertificateBundleObligation, CertificateKind, CertificateMetadata,
        CertificateObligationMeta, Cli, CliNetworkSemanticsMode, Commands, DebugFilter,
        FairnessMode, ProveAutoTarget, SoundnessMode, VisualizeCheck, VisualizeFormat,
        CERTIFICATE_SCHEMA_VERSION, CLI_LONG_ABOUT, CONFORMANCE_TRIAGE_CATEGORIES,
        CONFORMANCE_TRIAGE_ENGINE_REGRESSION, CONFORMANCE_TRIAGE_IMPL_DIVERGENCE,
        CONFORMANCE_TRIAGE_MODEL_CHANGE,
    };
    #[cfg(feature = "governance")]
    use super::{
        classify_cert_suite_check_triage, expected_matches, has_independent_solver,
        parse_manifest_fairness_mode, parse_manifest_proof_engine, proof_object_looks_nontrivial,
        validate_cert_suite_report_triage_contract, validate_foundational_profile_requirements,
        validate_manifest_corpus_breadth, validate_manifest_entry_contract,
        validate_manifest_expected_result, validate_manifest_known_bug_sentinel_coverage,
        validate_manifest_library_coverage, validate_manifest_model_hash_consistency,
        validate_manifest_top_level_contract, validate_trusted_check_requirements,
        CertSuiteAssumptions, CertSuiteCheckReport, CertSuiteEntry, CertSuiteEntryReport,
        CertSuiteManifest, CertSuiteReport, GovernanceGateResult, GovernancePipelineReport,
        ProofEngine, CERT_SUITE_SCHEMA_VERSION, TRUST_REPORT_SCHEMA_VERSION,
    };
    use clap::{CommandFactory, Parser};
    use serde_json::json;
    #[cfg(feature = "governance")]
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tarsier_engine::pipeline::{
        AppliedReductionDiagnostic, AutomatonFootprint, PhaseProfileDiagnostic,
        PipelineRunDiagnostics, PropertyAssumptionsDiagnostic, PropertyCompilationDiagnostic,
        PropertyResultDiagnostic, PropertyTemporalMonitorStepDiagnostic,
        PropertyWitnessMetadataDiagnostic, SmtProfileDiagnostic,
    };
    use tarsier_engine::result::{
        CegarAuditReport, CegarTermination, FairLivenessResult, LivenessResult,
        UnboundedFairLivenessResult, UnboundedSafetyResult, VerificationResult,
    };
    use tarsier_ir::counter_system::{
        Configuration, MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind,
        MessageIdentity, MessagePayloadVariant, SignatureProvenance, Trace, TraceStep,
    };

    fn tmp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        path.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
        path
    }

    fn sample_metadata() -> CertificateMetadata {
        CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("f".into(), 1)],
            bundle_sha256: None,
            obligations: vec![CertificateObligationMeta {
                name: "init_implies_inv".into(),
                expected: "unsat".into(),
                file: "init_implies_inv.smt2".into(),
                sha256: Some("abc".into()),
                proof_file: None,
                proof_sha256: None,
            }],
        }
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn bundle_hash_changes_when_metadata_changes() {
        let a = sample_metadata();
        let mut b = sample_metadata();
        b.obligations[0].sha256 = Some("def".into());
        assert_ne!(compute_bundle_sha256(&a), compute_bundle_sha256(&b));
    }

    #[test]
    fn augment_query_for_proof_removes_exit_and_adds_get_proof() {
        let script = "(set-logic QF_LIA)\n(check-sat)\n(exit)\n";
        let augmented = augment_query_for_proof(script, "z3");
        assert!(!augmented.contains("(exit)\n(exit)"));
        assert_eq!(augmented.matches("(check-sat)").count(), 1);
        assert!(augmented.contains("(set-option :produce-proofs true)"));
        assert!(augmented.contains("(get-proof)"));
        assert!(augmented.trim_end().ends_with("(exit)"));
    }

    #[test]
    fn augment_query_for_proof_adds_check_sat_when_missing() {
        let script = "(set-logic QF_LIA)\n(assert true)\n(exit)\n";
        let augmented = augment_query_for_proof(script, "cvc5");
        assert!(augmented.contains("(check-sat)"));
        assert!(augmented.contains("(get-proof)"));
    }

    #[test]
    fn canonicalize_obligation_sorts_decls_and_asserts() {
        let script = r#"
(set-logic QF_LIA)
(declare-const b Int)
(assert (>= b 0))
(declare-const a Int)
(assert (>= a 0))
(check-sat)
(exit)
"#;
        let canonical = canonicalize_obligation_smt2(script);
        let lines: Vec<&str> = canonical.lines().collect();
        let pos_decl_a = lines
            .iter()
            .position(|line| *line == "(declare-const a Int)")
            .expect("a declaration should exist");
        let pos_decl_b = lines
            .iter()
            .position(|line| *line == "(declare-const b Int)")
            .expect("b declaration should exist");
        assert!(pos_decl_a < pos_decl_b);

        let pos_assert_a = lines
            .iter()
            .position(|line| *line == "(assert (>= a 0))")
            .expect("a assertion should exist");
        let pos_assert_b = lines
            .iter()
            .position(|line| *line == "(assert (>= b 0))")
            .expect("b assertion should exist");
        assert!(pos_assert_a < pos_assert_b);
    }

    #[test]
    fn write_certificate_bundle_is_canonical_for_equivalent_inputs() {
        let out_a = tmp_dir("tarsier_cli_bundle_det_a");
        let out_b = tmp_dir("tarsier_cli_bundle_det_b");
        fs::create_dir_all(&out_a).expect("output dir a should be created");
        fs::create_dir_all(&out_b).expect("output dir b should be created");

        let input_a = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "examples/reliable_broadcast.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("n".into(), 4), ("f".into(), 1)],
            obligations: vec![
                CertificateBundleObligation {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    smt2: "(set-logic QF_LIA)\n(declare-const b Int)\n(assert (>= b 0))\n(declare-const a Int)\n(assert (>= a 0))\n(check-sat)\n(exit)\n".into(),
                },
                CertificateBundleObligation {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    smt2: "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(exit)\n".into(),
                },
            ],
        };
        let input_b = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "examples/reliable_broadcast.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("f".into(), 1), ("n".into(), 4)],
            obligations: vec![
                CertificateBundleObligation {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    smt2: "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(exit)\n".into(),
                },
                CertificateBundleObligation {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    smt2: "(set-logic QF_LIA)\n(declare-const a Int)\n(assert (>= a 0))\n(assert (>= b 0))\n(declare-const b Int)\n(check-sat)\n(exit)\n".into(),
                },
            ],
        };

        write_certificate_bundle(&out_a, &input_a, false, false)
            .expect("bundle a should be written");
        write_certificate_bundle(&out_b, &input_b, false, false)
            .expect("bundle b should be written");

        let cert_a = fs::read_to_string(out_a.join("certificate.json"))
            .expect("certificate a should be readable");
        let cert_b = fs::read_to_string(out_b.join("certificate.json"))
            .expect("certificate b should be readable");
        assert_eq!(cert_a, cert_b, "metadata should be byte-identical");

        let base_a = fs::read_to_string(out_a.join("base_case.smt2"))
            .expect("base obligation a should be readable");
        let base_b = fs::read_to_string(out_b.join("base_case.smt2"))
            .expect("base obligation b should be readable");
        assert_eq!(base_a, base_b);

        let step_a = fs::read_to_string(out_a.join("inductive_step.smt2"))
            .expect("step obligation a should be readable");
        let step_b = fs::read_to_string(out_b.join("inductive_step.smt2"))
            .expect("step obligation b should be readable");
        assert_eq!(step_a, step_b);

        fs::remove_dir_all(&out_a).ok();
        fs::remove_dir_all(&out_b).ok();
    }

    #[test]
    fn cegar_diff_friendly_projection_strips_elapsed_ms_recursively() {
        let raw = json!({
            "termination": {
                "reason": "max_refinements_reached",
                "elapsed_ms": 42
            },
            "stages": [
                {
                    "termination": {
                        "elapsed_ms": 7
                    }
                }
            ]
        });
        let canonical = cegar_diff_friendly_projection(&raw);
        assert!(canonical["termination"].get("elapsed_ms").is_none());
        assert!(canonical["stages"][0]["termination"]
            .get("elapsed_ms")
            .is_none());
    }

    #[test]
    fn cegar_provenance_fingerprint_is_stable_when_only_elapsed_changes() {
        let base = json!({
            "classification": "inconclusive",
            "termination": {
                "reason": "counterexample_eliminated_no_confirmation",
                "elapsed_ms": 11
            },
            "stages": []
        });
        let changed_elapsed = json!({
            "classification": "inconclusive",
            "termination": {
                "reason": "counterexample_eliminated_no_confirmation",
                "elapsed_ms": 9999
            },
            "stages": []
        });

        let with_provenance_a = cegar_with_provenance(base);
        let with_provenance_b = cegar_with_provenance(changed_elapsed);
        assert_eq!(
            with_provenance_a["provenance"]["fingerprint_sha256"],
            with_provenance_b["provenance"]["fingerprint_sha256"]
        );
        assert!(with_provenance_a["diff_friendly"]["termination"]
            .get("elapsed_ms")
            .is_none());
    }

    #[cfg(feature = "governance")]
    #[test]
    fn proof_object_nontrivial_heuristic_rejects_empty_or_malformed() {
        assert!(!proof_object_looks_nontrivial("unsat\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(error \"oops\")\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(abc\n"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn proof_object_nontrivial_heuristic_accepts_balanced_structure() {
        let proof = "unsat\n(proof\n  (step1)\n)\n";
        assert!(proof_object_looks_nontrivial(proof));
    }

    #[test]
    fn parse_visualize_modes() {
        assert!(matches!(
            parse_visualize_check("fair-liveness"),
            VisualizeCheck::FairLiveness
        ));
        assert!(matches!(
            parse_visualize_check("prove-fair"),
            VisualizeCheck::ProveFair
        ));
        assert!(matches!(
            parse_visualize_format("mermaid"),
            VisualizeFormat::Mermaid
        ));
        assert!(matches!(
            parse_visualize_format("timeline"),
            VisualizeFormat::Timeline
        ));
    }

    #[test]
    fn interpretation_disambiguates_safe_vs_inconclusive_liveness() {
        let layers = vec![
            AnalysisLayerReport {
                layer: "verify".into(),
                status: "pass".into(),
                verdict: "SAFE".into(),
                summary: "safety holds".into(),
                details: json!({}),
                output: String::new(),
            },
            AnalysisLayerReport {
                layer: "liveness[bounded]".into(),
                status: "fail".into(),
                verdict: "UNKNOWN".into(),
                summary: "liveness inconclusive".into(),
                details: json!({}),
                output: String::new(),
            },
        ];
        let interpretation = compute_analysis_interpretation(&layers, "fail");
        assert_eq!(interpretation.safety, "SAFE");
        assert_eq!(interpretation.liveness, "UNKNOWN");
        assert!(
            interpretation.summary.contains("Safety holds"),
            "summary should explain safety/liveness split: {}",
            interpretation.summary
        );
        assert!(
            interpretation
                .overall_status_meaning
                .contains("overall reflects pipeline completion"),
            "overall note should explain pipeline-vs-property distinction"
        );
    }

    #[test]
    fn help_text_contains_canonical_beginner_path_steps() {
        let mut cmd = Cli::command();
        let mut buffer = Vec::new();
        cmd.write_long_help(&mut buffer)
            .expect("long help should render");
        let help = String::from_utf8(buffer).expect("help should be valid utf-8");
        let idx_assist = help
            .find("tarsier assist --kind pbft --out my_protocol.trs")
            .expect("help should contain canonical assist step");
        let idx_analyze = help
            .find("tarsier analyze my_protocol.trs --goal safety")
            .expect("help should contain canonical analyze step");
        let idx_visualize = help
            .find("tarsier visualize my_protocol.trs --check verify")
            .expect("help should contain canonical visualize step");
        assert!(
            idx_assist < idx_analyze && idx_analyze < idx_visualize,
            "canonical beginner path order must be assist -> analyze -> visualize"
        );
    }

    #[test]
    fn parse_prove_accepts_cegar_report_out_flag() {
        let cli = Cli::try_parse_from([
            "tarsier",
            "prove",
            "examples/pbft_simple.trs",
            "--cegar-report-out",
            "artifacts/prove_cegar.json",
        ])
        .expect("prove command with cegar-report-out should parse");

        match cli.command {
            Commands::Prove {
                cegar_report_out, ..
            } => {
                assert_eq!(
                    cegar_report_out,
                    Some(PathBuf::from("artifacts/prove_cegar.json"))
                );
            }
            _ => panic!("expected prove command"),
        }
    }

    #[test]
    fn parse_prove_fair_accepts_cegar_report_out_flag() {
        let cli = Cli::try_parse_from([
            "tarsier",
            "prove-fair",
            "examples/trivial_live.trs",
            "--cegar-report-out",
            "artifacts/prove_fair_cegar.json",
        ])
        .expect("prove-fair command with cegar-report-out should parse");

        match cli.command {
            Commands::ProveFair {
                cegar_report_out, ..
            } => {
                assert_eq!(
                    cegar_report_out,
                    Some(PathBuf::from("artifacts/prove_fair_cegar.json"))
                );
            }
            _ => panic!("expected prove-fair command"),
        }
    }

    #[test]
    fn parse_comm_accepts_json_out_flag() {
        let cli = Cli::try_parse_from([
            "tarsier",
            "comm",
            "examples/pbft_simple.trs",
            "--depth",
            "8",
            "--format",
            "json",
            "--out",
            "artifacts/comm.json",
        ])
        .expect("comm command with --out should parse");

        match cli.command {
            Commands::Comm {
                file,
                depth,
                format,
                out,
            } => {
                assert_eq!(file, PathBuf::from("examples/pbft_simple.trs"));
                assert_eq!(depth, 8);
                assert_eq!(format, "json");
                assert_eq!(out, Some(PathBuf::from("artifacts/comm.json")));
            }
            _ => panic!("expected comm command"),
        }
    }

    #[test]
    fn parse_debug_cex_accepts_auth_filter_flag() {
        let cli = Cli::try_parse_from([
            "tarsier",
            "debug-cex",
            "examples/reliable_broadcast_buggy.trs",
            "--filter-auth",
            "OwnedKey",
        ])
        .expect("debug-cex command with --filter-auth should parse");

        match cli.command {
            Commands::DebugCex { filter_auth, .. } => {
                assert_eq!(filter_auth, Some("OwnedKey".into()));
            }
            _ => panic!("expected debug-cex command"),
        }
    }

    #[test]
    fn parse_network_semantics_mode_accepts_known_values() {
        assert!(matches!(
            parse_cli_network_semantics_mode("dsl"),
            CliNetworkSemanticsMode::Dsl
        ));
        assert!(matches!(
            parse_cli_network_semantics_mode("faithful"),
            CliNetworkSemanticsMode::Faithful
        ));
    }

    #[cfg(not(feature = "governance"))]
    #[test]
    fn default_build_hides_governance_commands_from_help_and_parser() {
        let mut cmd = Cli::command();
        let mut rendered = Vec::new();
        cmd.write_long_help(&mut rendered)
            .expect("long help should render");
        let help = String::from_utf8(rendered).expect("help should be utf-8");
        assert!(
            !help.contains("cert-suite"),
            "default help must not list governance-only subcommands"
        );
        assert!(
            !help.contains("certify-safety"),
            "default help must not list governance-only subcommands"
        );
        assert!(
            !help.contains("governance-pipeline"),
            "default help must not list governance-only subcommands"
        );
        assert!(
            !CLI_LONG_ABOUT.contains("certify-safety"),
            "default long help example should avoid governance-only commands"
        );

        let err = match Cli::try_parse_from([
            "tarsier",
            "certify-safety",
            "examples/reliable_broadcast.trs",
            "--out",
            "certs/pbft",
        ]) {
            Ok(_) => panic!("default build should reject governance-only subcommands"),
            Err(err) => err,
        };
        let err_text = err.to_string();
        assert!(
            err_text.contains("certify-safety"),
            "unexpected parse error text: {err_text}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_build_exposes_governance_commands_in_help_and_parser() {
        let mut cmd = Cli::command();
        let mut rendered = Vec::new();
        cmd.write_long_help(&mut rendered)
            .expect("long help should render");
        let help = String::from_utf8(rendered).expect("help should be utf-8");
        assert!(
            help.contains("cert-suite"),
            "governance help should list cert-suite command"
        );
        assert!(
            help.contains("certify-safety"),
            "governance help should list certify-safety command"
        );
        assert!(
            help.contains("governance-pipeline"),
            "governance help should list governance-pipeline command"
        );
        assert!(
            CLI_LONG_ABOUT.contains("certify-safety"),
            "governance long help should include governance cert flow"
        );

        let cli = Cli::try_parse_from([
            "tarsier",
            "certify-safety",
            "examples/reliable_broadcast.trs",
            "--out",
            "certs/pbft",
        ])
        .expect("governance build should parse governance-only subcommands");
        assert!(matches!(cli.command, Commands::CertifySafety { .. }));
    }

    #[test]
    fn lint_faithful_mode_suggests_exact_missing_declarations() {
        let src = r#"
protocol FaithfulLint {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; network: process_selective; }
    message Vote(v: bool);
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let report = lint_protocol_file(src, "faithful_lint.trs", SoundnessMode::Strict);
        let identity_issue = report
            .issues
            .iter()
            .find(|i| i.code == "faithful_mode_missing_identity_declarations")
            .expect("expected missing identity issue");
        let identity_suggestion = identity_issue
            .suggestion
            .as_deref()
            .expect("identity suggestion should exist");
        assert!(identity_suggestion.contains("identity R: process(pid) key r_key;"));

        let auth_issue = report
            .issues
            .iter()
            .find(|i| i.code == "faithful_mode_missing_auth_semantics")
            .expect("expected missing auth issue");
        let auth_suggestion = auth_issue
            .suggestion
            .as_deref()
            .expect("auth suggestion should exist");
        assert!(auth_suggestion.contains("adversary { auth: signed; }"));
        assert!(auth_suggestion.contains("channel Vote: authenticated;"));
    }

    #[test]
    fn lint_faithful_mode_requires_explicit_equivocation_policy() {
        let src = r#"
protocol FaithfulEquivocationLint {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; auth: signed; network: process_selective; }
    identity R: process(pid) key r_key;
    message Vote(v: bool);
    channel Vote: authenticated;
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let report =
            lint_protocol_file(src, "faithful_equivocation_lint.trs", SoundnessMode::Strict);
        let issue = report
            .issues
            .iter()
            .find(|i| i.code == "faithful_mode_missing_equivocation_policy")
            .expect("expected missing equivocation policy issue");
        assert_eq!(issue.severity, "error");
        let suggestion = issue
            .suggestion
            .as_deref()
            .expect("equivocation suggestion should exist");
        assert!(suggestion.contains("equivocation: full"));
        assert!(suggestion.contains("equivocation: none"));
    }

    #[test]
    fn lint_classic_byzantine_suggests_faithful_scaffold() {
        let src = r#"
protocol ClassicLint {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Vote(v: bool);
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let report = lint_protocol_file(src, "classic_lint.trs", SoundnessMode::Strict);
        let issue = report
            .issues
            .iter()
            .find(|i| i.code == "byzantine_network_not_identity_selective")
            .expect("expected byzantine network issue");
        let suggestion = issue
            .suggestion
            .as_deref()
            .expect("scaffold suggestion should exist");
        assert!(suggestion.contains("adversary { network: process_selective; auth: signed; }"));
        assert!(suggestion.contains("identity R"));
    }

    #[test]
    fn lint_report_emits_source_spans_for_semantic_issues() {
        let src = r#"
protocol SpanLint {
    params n, t, f;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let report = lint_protocol_file(src, "span_lint.trs", SoundnessMode::Strict);
        let issue = report
            .issues
            .iter()
            .find(|i| i.code == "missing_resilience")
            .expect("missing resilience issue should be present");
        let span = issue
            .source_span
            .expect("missing_resilience should include source span");
        assert!(span.start < span.end);
        assert!(span.line >= 1);
        assert!(span.column >= 1);
        assert!(
            issue.soundness_impact.is_some(),
            "semantic lint issue should explain soundness impact"
        );
    }

    #[test]
    fn lint_parse_error_includes_source_span_and_soundness_impact() {
        let src = "this is not valid trs";
        let report = lint_protocol_file(src, "parse_error_lint.trs", SoundnessMode::Strict);
        let issue = report
            .issues
            .iter()
            .find(|i| i.code == "parse_error")
            .expect("parse_error issue should be present");
        let span = issue
            .source_span
            .expect("parse_error should include inferred source span");
        assert!(span.start < span.end);
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
        let impact = issue
            .soundness_impact
            .as_deref()
            .expect("parse_error should include soundness impact");
        assert!(impact.contains("no soundness claim"));
    }

    #[test]
    fn lint_text_output_includes_soundness_impact_lines() {
        let src = r#"
protocol LintTextImpact {
    params n, f;
    role R { init s; phase s {} }
}
"#;
        let report = lint_protocol_file(src, "lint_text_impact.trs", SoundnessMode::Strict);
        let rendered = render_lint_text(&report);
        assert!(
            rendered.contains("soundness impact:"),
            "lint text should render soundness impact details"
        );
    }

    #[test]
    fn debug_filter_matches_payload_variant_and_field() {
        let event = MessageDeliveryEvent {
            shared_var: 0,
            shared_var_name: "msg_vote".into(),
            sender: MessageIdentity {
                role: "Replica".into(),
                process: Some("p0".into()),
                key: Some("replica_key".into()),
            },
            recipient: MessageIdentity {
                role: "Replica".into(),
                process: Some("p1".into()),
                key: Some("replica_key".into()),
            },
            payload: MessagePayloadVariant {
                family: "Vote".into(),
                fields: vec![("view".into(), "2".into()), ("value".into(), "true".into())],
                variant: "Vote[view=2,value=true]".into(),
            },
            count: 1,
            kind: MessageEventKind::Deliver,
            auth: MessageAuthMetadata {
                authenticated_channel: true,
                signature_key: Some("replica_key".into()),
                key_owner_role: Some("Replica".into()),
                key_compromised: false,
                provenance: SignatureProvenance::OwnedKey,
            },
        };

        let mut variant_filter = DebugFilter {
            payload_variant: Some("view=2".into()),
            ..DebugFilter::default()
        };
        assert!(variant_filter.matches(&event));
        variant_filter.payload_variant = Some("view=3".into());
        assert!(!variant_filter.matches(&event));

        let mut field_filter = DebugFilter {
            payload_field: Some(("value".into(), "true".into())),
            ..DebugFilter::default()
        };
        assert!(field_filter.matches(&event));
        field_filter.payload_field = Some(("value".into(), "false".into()));
        assert!(!field_filter.matches(&event));

        let mut auth_filter = DebugFilter {
            auth: Some("authenticated".into()),
            ..DebugFilter::default()
        };
        assert!(auth_filter.matches(&event));
        auth_filter.auth = Some("unauthenticated".into());
        assert!(!auth_filter.matches(&event));

        let mut provenance_filter = DebugFilter {
            auth: Some("OwnedKey".into()),
            ..DebugFilter::default()
        };
        assert!(provenance_filter.matches(&event));
        provenance_filter.auth = Some("ByzantineSigner".into());
        assert!(!provenance_filter.matches(&event));
    }

    #[test]
    fn assistant_template_supports_known_kinds() {
        assert!(assistant_template("pbft").is_some());
        assert!(assistant_template("hotstuff").is_some());
        assert!(assistant_template("raft").is_some());
        assert!(assistant_template("tendermint").is_some());
        assert!(assistant_template("streamlet").is_some());
        assert!(assistant_template("casper").is_some());
        assert!(assistant_template("unknown").is_none());
    }

    #[test]
    fn assistant_templates_parse_lower_and_verify_safe() {
        let opts = tarsier_engine::pipeline::PipelineOptions::default();
        for kind in &[
            "pbft",
            "hotstuff",
            "raft",
            "tendermint",
            "streamlet",
            "casper",
        ] {
            let src = assistant_template(kind).unwrap();
            let filename = format!("{kind}_template.trs");

            // Verify parse + lower produce rules.
            let prog = tarsier_engine::pipeline::parse(src, &filename)
                .unwrap_or_else(|e| panic!("{kind} template failed to parse: {e:?}"));
            let ta = tarsier_engine::pipeline::lower(&prog)
                .unwrap_or_else(|e| panic!("{kind} template failed to lower: {e:?}"));
            assert!(
                !ta.rules.is_empty(),
                "{kind} template should produce at least one transition rule"
            );

            // Verify scaffold templates pass baseline permissive lint.
            let lint = lint_protocol_file(src, &filename, SoundnessMode::Permissive);
            assert!(
                !lint.issues.iter().any(|i| i.severity == "error"),
                "{kind} template lint should not contain errors, got: {:?}",
                lint.issues
            );

            // Verify safety via the full pipeline.
            let result = tarsier_engine::pipeline::verify(src, &filename, &opts)
                .unwrap_or_else(|e| panic!("{kind} template verify error: {e:?}"));
            assert!(
                matches!(
                    result,
                    tarsier_engine::result::VerificationResult::Safe { .. }
                ),
                "{kind} template should verify as SAFE, got: {result:?}"
            );
        }
    }

    #[cfg(feature = "governance")]
    #[test]
    fn expected_match_is_case_insensitive() {
        assert!(expected_matches("SAFE", "safe"));
        assert!(!expected_matches("unsafe", "safe"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn triage_classifies_model_change_first() {
        let triage = classify_cert_suite_check_triage(
            "verify",
            "safe",
            "unsafe",
            Some("expected_safe"),
            true,
        );
        assert_eq!(triage, "model_change");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn triage_classifies_expected_update_for_known_bug_polarity_match() {
        let triage = classify_cert_suite_check_triage(
            "prove",
            "not_proved",
            "unsafe",
            Some("known_bug"),
            false,
        );
        assert_eq!(triage, "expected_update");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_report_triage_contract_accepts_only_allowed_categories() {
        let mut report = sample_cert_suite_report();
        report.entries[0].status = "fail".into();
        report.entries[0].verdict = "fail".into();
        report.entries[0].triage = Some("engine_regression".into());
        report.entries[0].checks[0].status = "fail".into();
        report.entries[0].checks[0].triage = Some("expected_update".into());
        report.triage.insert("engine_regression".into(), 1);
        assert!(
            validate_cert_suite_report_triage_contract(&report).is_ok(),
            "valid triage categories should pass contract"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_report_triage_contract_rejects_unknown_top_level_key() {
        let mut report = sample_cert_suite_report();
        report.triage.insert("other".into(), 1);
        let err = validate_cert_suite_report_triage_contract(&report)
            .expect_err("unknown triage key should be rejected");
        assert!(err.contains("Invalid report triage key"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_report_triage_contract_rejects_unknown_entry_or_check_triage() {
        let mut report = sample_cert_suite_report();
        report.entries[0].triage = Some("bad_entry".into());
        let err = validate_cert_suite_report_triage_contract(&report)
            .expect_err("unknown entry triage should be rejected");
        assert!(err.contains("invalid triage"));

        let mut report = sample_cert_suite_report();
        report.entries[0].checks[0].triage = Some("bad_check".into());
        let err = validate_cert_suite_report_triage_contract(&report)
            .expect_err("unknown check triage should be rejected");
        assert!(err.contains("invalid triage"));
    }

    #[cfg(feature = "governance")]
    fn sample_cert_suite_entry() -> CertSuiteEntry {
        CertSuiteEntry {
            file: "sample.trs".into(),
            verify: Some("safe".into()),
            liveness: None,
            fair_liveness: None,
            prove: None,
            prove_fair: None,
            proof_engine: None,
            fairness: None,
            cegar_iters: None,
            depth: None,
            k: None,
            timeout: None,
            family: Some("sample".into()),
            class: Some("expected_safe".into()),
            variant: None,
            variant_group: None,
            notes: Some("Expected baseline-safe sample.".into()),
            model_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        }
    }

    #[cfg(feature = "governance")]
    fn sample_cert_suite_manifest() -> CertSuiteManifest {
        CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![sample_cert_suite_entry()],
        }
    }

    #[cfg(feature = "governance")]
    fn sample_cert_suite_assumptions() -> CertSuiteAssumptions {
        CertSuiteAssumptions {
            solver: "z3".into(),
            proof_engine: "kinduction".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            network_semantics: "classic".into(),
            depth: 6,
            k: 8,
            timeout_secs: 120,
            cegar_iters: 0,
        }
    }

    #[cfg(feature = "governance")]
    fn sample_cert_suite_report() -> CertSuiteReport {
        let entry = CertSuiteEntryReport {
            file: "sample.trs".into(),
            family: Some("sample".into()),
            class: Some("expected_safe".into()),
            variant: None,
            variant_group: None,
            verdict: "pass".into(),
            status: "pass".into(),
            triage: None,
            duration_ms: 1,
            assumptions: sample_cert_suite_assumptions(),
            model_sha256_expected: None,
            model_sha256_actual: None,
            model_changed: false,
            notes: Some("sample".into()),
            artifact_links: Vec::new(),
            checks: vec![CertSuiteCheckReport {
                check: "verify".into(),
                expected: "safe".into(),
                actual: "safe".into(),
                status: "pass".into(),
                duration_ms: 1,
                triage: None,
                artifact_link: None,
                output: "ok".into(),
            }],
            errors: Vec::new(),
        };
        CertSuiteReport {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            manifest: "examples/library/cert_suite.json".into(),
            solver: "z3".into(),
            proof_engine: "kinduction".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            entries: vec![entry],
            passed: 1,
            failed: 0,
            errors: 0,
            triage: BTreeMap::new(),
            by_family: BTreeMap::new(),
            by_class: BTreeMap::new(),
            overall: "pass".into(),
        }
    }

    #[cfg(feature = "governance")]
    fn cert_suite_manifest_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/library/cert_suite.json")
    }

    #[cfg(feature = "governance")]
    fn cert_suite_schema_json_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/cert-suite-schema-v2.json")
    }

    #[cfg(feature = "governance")]
    fn cert_suite_schema_doc_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/CERT_SUITE_SCHEMA.md")
    }

    #[cfg(feature = "governance")]
    fn load_cert_suite_schema_json() -> serde_json::Value {
        let path = cert_suite_schema_json_path();
        let raw = fs::read_to_string(&path).expect("cert-suite JSON schema should be readable");
        serde_json::from_str(&raw).expect("cert-suite JSON schema should decode")
    }

    #[cfg(feature = "governance")]
    fn load_cert_suite_schema_doc() -> String {
        let path = cert_suite_schema_doc_path();
        fs::read_to_string(&path).expect("cert-suite schema doc should be readable")
    }

    #[cfg(feature = "governance")]
    #[test]
    fn manifest_expected_outcomes_accept_known_kinds() {
        for (check, expected) in [
            ("verify", "safe"),
            ("verify", "unsafe"),
            ("verify", "unknown"),
            ("liveness", "live"),
            ("liveness", "not_live"),
            ("fair_liveness", "no_fair_cycle_up_to"),
            ("fair_liveness", "fair_cycle_found"),
            ("prove", "not_proved"),
            ("prove_fair", "live_proved"),
        ] {
            validate_manifest_expected_result(check, expected)
                .unwrap_or_else(|e| panic!("{check}={expected} should be accepted: {e}"));
        }
    }

    #[cfg(feature = "governance")]
    #[test]
    fn manifest_expected_outcomes_reject_invalid_values() {
        let err = validate_manifest_expected_result("verify", "live")
            .expect_err("verify should reject liveness outcomes");
        assert!(err.contains("Invalid expected outcome"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_v2_requires_rationale_notes() {
        let mut entry = sample_cert_suite_entry();
        entry.notes = None;
        let errors = validate_manifest_entry_contract(&entry, 2);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("requires a non-empty 'notes' rationale")),
            "expected rationale requirement error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_v2_requires_model_sha256() {
        let mut entry = sample_cert_suite_entry();
        entry.model_sha256 = None;
        let errors = validate_manifest_entry_contract(&entry, 2);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("requires a non-empty 'model_sha256'")),
            "expected model_sha256 requirement error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_v2_rejects_invalid_model_sha256() {
        let mut entry = sample_cert_suite_entry();
        entry.model_sha256 = Some("not-a-sha".into());
        let errors = validate_manifest_entry_contract(&entry, 2);
        assert!(
            errors.iter().any(|e| e.contains("invalid model_sha256")),
            "expected invalid model_sha256 error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_variant_requires_pairing_fields() {
        let mut entry = sample_cert_suite_entry();
        entry.variant = Some("faithful".into());
        entry.variant_group = None;
        let errors = validate_manifest_entry_contract(&entry, 2);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("sets 'variant' but is missing non-empty 'variant_group'")),
            "expected variant/variant_group contract error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_variant_group_must_include_minimal_and_faithful() {
        let mut entry = sample_cert_suite_entry();
        entry.variant = Some("minimal".into());
        entry.variant_group = Some("demo".into());
        let mut known_bug = sample_cert_suite_entry();
        known_bug.file = "buggy.trs".into();
        known_bug.class = Some("known_bug".into());
        known_bug.verify = Some("unsafe".into());
        known_bug.variant = None;
        known_bug.variant_group = None;
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![entry, known_bug],
        };
        let errors = validate_manifest_top_level_contract(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("must define both minimal and faithful entries")),
            "expected variant pair completeness error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_library_coverage_requires_manifest_entry_for_new_protocol_file() {
        let dir = tmp_dir("tarsier_cli_cert_suite_cov_missing");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            "protocol Alpha { params n,t,f; resilience: n > 3*t; role R { init s; phase s {} } }\n",
        )
        .expect("alpha file should be written");
        fs::write(
            dir.join("beta.trs"),
            "protocol Beta { params n,t,f; resilience: n > 3*t; role R { init s; phase s {} } }\n",
        )
        .expect("beta file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: true,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_library_coverage(&manifest, &manifest_path);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("has no cert-suite expectation entry")),
            "expected missing-protocol coverage error, got {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_library_coverage_can_be_disabled_for_subset_manifests() {
        let dir = tmp_dir("tarsier_cli_cert_suite_cov_disabled");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            "protocol Alpha { params n,t,f; resilience: n > 3*t; role R { init s; phase s {} } }\n",
        )
        .expect("alpha file should be written");
        fs::write(
            dir.join("beta.trs"),
            "protocol Beta { params n,t,f; resilience: n > 3*t; role R { init s; phase s {} } }\n",
        )
        .expect("beta file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_library_coverage(&manifest, &manifest_path);
        assert!(
            errors.is_empty(),
            "coverage-disabled manifest should not fail coverage checks: {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    fn protocol_with_fault_model(name: &str, model: &str) -> String {
        format!(
            r#"
protocol {name} {{
    params n, t, f;
    resilience: n > 3*t;
    adversary {{ model: {model}; bound: f; }}
    role R {{
        var decided: bool = false;
        init s;
        phase s {{}}
    }}
}}
"#
        )
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_corpus_breadth_can_be_disabled_for_subset_manifests() {
        let dir = tmp_dir("tarsier_cli_cert_suite_breadth_disabled");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            protocol_with_fault_model("Alpha", "byzantine"),
        )
        .expect("alpha file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_corpus_breadth(&manifest, &manifest_path);
        assert!(
            errors.is_empty(),
            "breadth-disabled manifest should not fail breadth checks: {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_corpus_breadth_requires_fault_model_mix_and_family_floor() {
        let dir = tmp_dir("tarsier_cli_cert_suite_breadth_missing");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            protocol_with_fault_model("Alpha", "byzantine"),
        )
        .expect("alpha file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        entry.family = Some("alpha".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: true,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_corpus_breadth(&manifest, &manifest_path);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("at least one 'omission' model entry")),
            "expected omission coverage error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("at least one 'crash' model entry")),
            "expected crash coverage error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("at least 12 distinct families")),
            "expected family breadth error, got {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_corpus_breadth_passes_for_canonical_library_manifest() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/library/cert_suite.json");
        let raw = fs::read_to_string(&manifest_path).expect("manifest should be readable");
        let manifest: CertSuiteManifest =
            serde_json::from_str(&raw).expect("manifest should decode");
        let errors = validate_manifest_corpus_breadth(&manifest, &manifest_path);
        assert!(
            errors.is_empty(),
            "canonical manifest should satisfy breadth checks: {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_model_hash_consistency_can_be_disabled_for_subset_manifests() {
        let dir = tmp_dir("tarsier_cli_cert_suite_hash_disabled");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            protocol_with_fault_model("Alpha", "byzantine"),
        )
        .expect("alpha file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        entry.model_sha256 =
            Some("0000000000000000000000000000000000000000000000000000000000000000".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_model_hash_consistency(&manifest, &manifest_path);
        assert!(
            errors.is_empty(),
            "hash-consistency-disabled manifest should not fail hash checks: {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_model_hash_consistency_rejects_stale_hashes() {
        let dir = tmp_dir("tarsier_cli_cert_suite_hash_mismatch");
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(
            dir.join("alpha.trs"),
            protocol_with_fault_model("Alpha", "byzantine"),
        )
        .expect("alpha file should be written");
        let manifest_path = dir.join("cert_suite.json");

        let mut entry = sample_cert_suite_entry();
        entry.file = "alpha.trs".into();
        entry.model_sha256 =
            Some("0000000000000000000000000000000000000000000000000000000000000000".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: true,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: Some(".".into()),
            entries: vec![entry],
        };
        let errors = validate_manifest_model_hash_consistency(&manifest, &manifest_path);
        assert!(
            errors.iter().any(|e| e.contains("model_sha256 mismatch")),
            "expected model-hash mismatch error, got {errors:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_model_hash_consistency_passes_for_canonical_library_manifest() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/library/cert_suite.json");
        let raw = fs::read_to_string(&manifest_path).expect("manifest should be readable");
        let manifest: CertSuiteManifest =
            serde_json::from_str(&raw).expect("manifest should decode");
        let errors = validate_manifest_model_hash_consistency(&manifest, &manifest_path);
        assert!(
            errors.is_empty(),
            "canonical manifest should satisfy model-hash consistency: {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_known_bug_sentinel_coverage_can_be_disabled_for_subset_manifests() {
        let mut known_bug = sample_cert_suite_entry();
        known_bug.file = "buggy.trs".into();
        known_bug.family = Some("sample".into());
        known_bug.class = Some("known_bug".into());
        known_bug.verify = Some("unsafe".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: vec!["pbft".into()],
            required_variant_groups: vec!["pbft_simple_safe".into()],
            library_dir: None,
            entries: vec![known_bug],
        };
        let errors = validate_manifest_known_bug_sentinel_coverage(&manifest);
        assert!(
            errors.is_empty(),
            "coverage-disabled manifest should not fail sentinel checks: {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_known_bug_sentinel_coverage_requires_declared_targets() {
        let mut known_bug = sample_cert_suite_entry();
        known_bug.file = "buggy.trs".into();
        known_bug.family = Some("sample".into());
        known_bug.class = Some("known_bug".into());
        known_bug.verify = Some("unsafe".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: true,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![known_bug],
        };
        let errors = validate_manifest_known_bug_sentinel_coverage(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("required_known_bug_families")),
            "expected required-known-bug-families error, got {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("required_variant_groups")),
            "expected required-variant-groups error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_known_bug_sentinel_coverage_rejects_missing_family_or_group() {
        let mut minimal = sample_cert_suite_entry();
        minimal.file = "pair_min.trs".into();
        minimal.family = Some("pairfam".into());
        minimal.class = Some("expected_safe".into());
        minimal.variant = Some("minimal".into());
        minimal.variant_group = Some("pair_group".into());

        let mut faithful = sample_cert_suite_entry();
        faithful.file = "pair_faithful.trs".into();
        faithful.family = Some("pairfam".into());
        faithful.class = Some("expected_safe".into());
        faithful.variant = Some("faithful".into());
        faithful.variant_group = Some("pair_group".into());

        let mut unrelated_bug = sample_cert_suite_entry();
        unrelated_bug.file = "other_bug.trs".into();
        unrelated_bug.family = Some("other".into());
        unrelated_bug.class = Some("known_bug".into());
        unrelated_bug.verify = Some("unsafe".into());

        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: true,
            required_known_bug_families: vec!["pairfam".into()],
            required_variant_groups: vec!["pair_group".into(), "missing_group".into()],
            library_dir: None,
            entries: vec![minimal, faithful, unrelated_bug],
        };
        let errors = validate_manifest_known_bug_sentinel_coverage(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Required known-bug sentinel family 'pairfam'")),
            "expected missing required known-bug family error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Required variant group 'missing_group'")),
            "expected missing required variant group error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("family 'pairfam' but that family has no class=known_bug")),
            "expected variant-group/family sentinel coupling error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_known_bug_sentinel_coverage_passes_for_canonical_library_manifest() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/library/cert_suite.json");
        let raw = fs::read_to_string(&manifest_path).expect("manifest should be readable");
        let manifest: CertSuiteManifest =
            serde_json::from_str(&raw).expect("manifest should decode");
        let errors = validate_manifest_known_bug_sentinel_coverage(&manifest);
        assert!(
            errors.is_empty(),
            "canonical manifest should satisfy known-bug sentinel coverage: {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_requires_expected_outcome_per_entry() {
        let mut entry = sample_cert_suite_entry();
        entry.verify = None;
        entry.prove = None;
        entry.liveness = None;
        entry.fair_liveness = None;
        entry.prove_fair = None;
        let errors = validate_manifest_entry_contract(&entry, 2);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("no expected outcomes configured")),
            "expected missing expected-outcome error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_requires_exact_version_match() {
        let mut manifest = sample_cert_suite_manifest();
        manifest.schema_version = CERT_SUITE_SCHEMA_VERSION + 1;
        let errors = validate_manifest_top_level_contract(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Unsupported certification manifest schema")),
            "expected schema version mismatch error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_json_and_manifest_keys_are_in_sync() {
        let schema = load_cert_suite_schema_json();
        let manifest_raw =
            fs::read_to_string(cert_suite_manifest_path()).expect("manifest should be readable");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_raw).expect("manifest should decode");

        let top_level_schema_keys: std::collections::HashSet<String> = schema["properties"]
            .as_object()
            .expect("schema.properties should be an object")
            .keys()
            .cloned()
            .collect();
        let top_level_manifest = manifest
            .as_object()
            .expect("manifest top-level should be an object");
        for key in top_level_manifest.keys() {
            assert!(
                top_level_schema_keys.contains(key),
                "Manifest top-level key '{}' missing from docs/cert-suite-schema-v2.json properties.",
                key
            );
        }

        let entry_schema_keys: std::collections::HashSet<String> = schema["$defs"]["entry"]
            ["properties"]
            .as_object()
            .expect("schema.$defs.entry.properties should be an object")
            .keys()
            .cloned()
            .collect();
        for entry in manifest["entries"]
            .as_array()
            .expect("manifest entries should be an array")
        {
            let entry_obj = entry
                .as_object()
                .expect("manifest entry should be an object");
            for key in entry_obj.keys() {
                assert!(
                    entry_schema_keys.contains(key),
                    "Manifest entry key '{}' missing from docs/cert-suite-schema-v2.json entry properties.",
                    key
                );
            }
        }
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_json_required_sets_cover_contract_basics() {
        let schema = load_cert_suite_schema_json();
        let top_required = schema["required"]
            .as_array()
            .expect("schema.required should be an array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(
            top_required.contains("schema_version"),
            "schema.required should include schema_version"
        );
        assert!(
            top_required.contains("entries"),
            "schema.required should include entries"
        );

        let entry_required = schema["$defs"]["entry"]["required"]
            .as_array()
            .expect("schema.$defs.entry.required should be an array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<std::collections::HashSet<_>>();
        for field in ["file", "family", "class", "notes", "model_sha256"] {
            assert!(
                entry_required.contains(field),
                "entry.required should include '{}'",
                field
            );
        }
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_docs_track_current_flags_and_version() {
        let schema = load_cert_suite_schema_json();
        let doc = load_cert_suite_schema_doc();
        let version = schema["properties"]["schema_version"]["const"]
            .as_u64()
            .expect("schema schema_version.const should be an integer");
        assert_eq!(
            version,
            u64::from(CERT_SUITE_SCHEMA_VERSION),
            "docs/cert-suite-schema-v2.json schema_version const should match CLI constant"
        );
        assert!(
            doc.contains(&format!("schema_version == {}", CERT_SUITE_SCHEMA_VERSION)),
            "docs/CERT_SUITE_SCHEMA.md should document exact-match schema version contract"
        );
        for needle in [
            "`enforce_library_coverage`",
            "`enforce_corpus_breadth`",
            "`enforce_model_hash_consistency`",
            "`enforce_known_bug_sentinels`",
            "`required_known_bug_families`",
            "`required_variant_groups`",
            "`model_sha256`",
            "`notes`",
            "`family`",
            "`class`",
            "docs/cert-suite-schema-v2.json",
        ] {
            assert!(
                doc.contains(needle),
                "docs/CERT_SUITE_SCHEMA.md missing expected contract reference: {needle}"
            );
        }
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_canonical_manifest_enables_all_validation_gates() {
        let manifest_raw =
            fs::read_to_string(cert_suite_manifest_path()).expect("manifest should be readable");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_raw).expect("manifest should decode");
        assert_eq!(
            manifest["enforce_library_coverage"].as_bool(),
            Some(true),
            "Canonical manifest should enable enforce_library_coverage"
        );
        assert_eq!(
            manifest["enforce_corpus_breadth"].as_bool(),
            Some(true),
            "Canonical manifest should enable enforce_corpus_breadth"
        );
        assert_eq!(
            manifest["enforce_model_hash_consistency"].as_bool(),
            Some(true),
            "Canonical manifest should enable enforce_model_hash_consistency"
        );
        assert_eq!(
            manifest["enforce_known_bug_sentinels"].as_bool(),
            Some(true),
            "Canonical manifest should enable enforce_known_bug_sentinels"
        );
        let required_bug_families = manifest["required_known_bug_families"]
            .as_array()
            .expect("required_known_bug_families should be an array");
        assert!(
            !required_bug_families.is_empty(),
            "Canonical manifest should declare required_known_bug_families"
        );
        let required_variant_groups = manifest["required_variant_groups"]
            .as_array()
            .expect("required_variant_groups should be an array");
        assert!(
            !required_variant_groups.is_empty(),
            "Canonical manifest should declare required_variant_groups"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_v2_requires_family_and_valid_class() {
        let mut entry = sample_cert_suite_entry();
        entry.family = None;
        entry.class = Some("other".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![entry],
        };
        let errors = validate_manifest_top_level_contract(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("missing required 'family'")),
            "expected missing family error, got {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("invalid class")),
            "expected invalid class error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_v2_requires_known_bug_regression_sentinel_presence() {
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![sample_cert_suite_entry()],
        };
        let errors = validate_manifest_top_level_contract(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("at least one class=known_bug regression sentinel")),
            "expected known_bug sentinel presence error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_known_bug_entries_require_bug_sentinel_outcome() {
        let mut entry = sample_cert_suite_entry();
        entry.class = Some("known_bug".into());
        entry.verify = Some("safe".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            enforce_corpus_breadth: false,
            enforce_model_hash_consistency: false,
            enforce_known_bug_sentinels: false,
            required_known_bug_families: Vec::new(),
            required_variant_groups: Vec::new(),
            library_dir: None,
            entries: vec![entry],
        };
        let errors = validate_manifest_top_level_contract(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("has no bug sentinel expected outcome")),
            "expected known_bug outcome error, got {errors:?}"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn cert_suite_schema_rejects_unknown_fields() {
        let raw = r#"
{
  "schema_version": 2,
  "entries": [
    {
      "file": "sample.trs",
      "verify": "safe",
      "notes": "ok",
      "family": "sample",
      "class": "expected_safe",
      "unexpected": true
    }
  ],
  "extra_top_level": 1
}
"#;
        let parsed = serde_json::from_str::<CertSuiteManifest>(raw);
        assert!(
            parsed.is_err(),
            "manifest decode should fail on unknown fields"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn manifest_proof_engine_parser_accepts_known_engines() {
        assert!(matches!(
            parse_manifest_proof_engine("kinduction"),
            Ok(ProofEngine::KInduction)
        ));
        assert!(matches!(
            parse_manifest_proof_engine("pdr"),
            Ok(ProofEngine::Pdr)
        ));
        assert!(parse_manifest_proof_engine("unknown").is_err());
    }

    #[cfg(feature = "governance")]
    #[test]
    fn manifest_fairness_parser_accepts_known_modes() {
        assert!(matches!(
            parse_manifest_fairness_mode("weak"),
            Ok(FairnessMode::Weak)
        ));
        assert!(matches!(
            parse_manifest_fairness_mode("strong"),
            Ok(FairnessMode::Strong)
        ));
        assert!(parse_manifest_fairness_mode("other").is_err());
    }

    #[test]
    fn prove_auto_target_detects_liveness_only_specs() {
        let src = r#"
protocol LiveOnly {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
        let target = detect_prove_auto_target(src, "live_only.trs").expect("parse should succeed");
        assert_eq!(target, ProveAutoTarget::FairLiveness);
    }

    #[test]
    fn prove_auto_target_prefers_safety_when_present() {
        let src = r#"
protocol MixedProps {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
    property live: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
        let target =
            detect_prove_auto_target(src, "mixed_props.trs").expect("parse should succeed");
        assert_eq!(target, ProveAutoTarget::Safety);
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trusted_check_requires_independent_solver() {
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        assert!(has_independent_solver(&solvers, "z3"));
        let only_same = vec!["z3".to_string()];
        assert!(!has_independent_solver(&only_same, "z3"));
    }

    #[test]
    fn trusted_check_unsat_only_helper() {
        let mut metadata = sample_metadata();
        assert!(obligations_all_unsat(&metadata));
        metadata.obligations[0].expected = "sat".into();
        assert!(!obligations_all_unsat(&metadata));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trusted_check_requires_proof_checker_by_default() {
        let metadata = sample_metadata();
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        let err =
            validate_trusted_check_requirements(true, 2, &solvers, &metadata, true, None, false)
                .expect_err("trusted-check should fail without proof checker");
        assert!(err.to_string().contains("--proof-checker"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trusted_check_allows_unchecked_proofs_only_with_explicit_override() {
        let metadata = sample_metadata();
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        validate_trusted_check_requirements(true, 2, &solvers, &metadata, true, None, true)
            .expect("explicit override should allow weaker trusted-check mode");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn high_assurance_profile_requires_cvc5_solver() {
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        validate_foundational_profile_requirements(&solvers, false)
            .expect("z3+cvc5 should satisfy foundational solver coverage");

        let missing_cvc5 = vec!["z3".to_string()];
        let err = validate_foundational_profile_requirements(&missing_cvc5, false)
            .expect_err("missing cvc5 should be rejected for high-assurance profile");
        assert!(err.to_string().contains("requires cvc5"));
    }

    #[test]
    fn por_dynamic_ample_summary_reports_deterministic_totals_and_rates() {
        let mut diag = PipelineRunDiagnostics::default();
        diag.smt_profiles.push(SmtProfileDiagnostic {
            context: "z_ctx".into(),
            encode_calls: 0,
            encode_elapsed_ms: 0,
            solve_calls: 0,
            solve_elapsed_ms: 0,
            assertion_candidates: 0,
            assertion_unique: 0,
            assertion_dedup_hits: 0,
            incremental_depth_reuse_steps: 0,
            incremental_decl_reuse_hits: 0,
            incremental_assertion_reuse_hits: 0,
            symmetry_candidates: 0,
            symmetry_pruned: 0,
            stutter_signature_normalizations: 0,
            por_pending_obligation_dedup_hits: 0,
            por_dynamic_ample_queries: 4,
            por_dynamic_ample_fast_sat: 2,
            por_dynamic_ample_unsat_rechecks: 1,
            por_dynamic_ample_unsat_recheck_sat: 1,
        });
        diag.smt_profiles.push(SmtProfileDiagnostic {
            context: "a_ctx".into(),
            encode_calls: 0,
            encode_elapsed_ms: 0,
            solve_calls: 0,
            solve_elapsed_ms: 0,
            assertion_candidates: 0,
            assertion_unique: 0,
            assertion_dedup_hits: 0,
            incremental_depth_reuse_steps: 0,
            incremental_decl_reuse_hits: 0,
            incremental_assertion_reuse_hits: 0,
            symmetry_candidates: 0,
            symmetry_pruned: 0,
            stutter_signature_normalizations: 0,
            por_pending_obligation_dedup_hits: 0,
            por_dynamic_ample_queries: 6,
            por_dynamic_ample_fast_sat: 3,
            por_dynamic_ample_unsat_rechecks: 2,
            por_dynamic_ample_unsat_recheck_sat: 0,
        });

        let details = run_diagnostics_details(&diag);
        let summary = &details["por_dynamic_ample"];
        assert_eq!(summary["total_queries"].as_u64(), Some(10));
        assert_eq!(summary["total_fast_sat"].as_u64(), Some(5));
        assert_eq!(summary["total_unsat_rechecks"].as_u64(), Some(3));
        assert_eq!(summary["total_unsat_recheck_sat"].as_u64(), Some(1));
        assert_eq!(summary["total_fast_sat_rate"].as_f64(), Some(0.5));
        assert_eq!(
            summary["total_unsat_recheck_sat_rate"].as_f64(),
            Some(1.0 / 3.0)
        );

        let contexts = summary["contexts"]
            .as_array()
            .expect("contexts should be an array");
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts[0]["context"].as_str(),
            Some("a_ctx"),
            "contexts should be sorted lexicographically"
        );
        assert_eq!(contexts[1]["context"].as_str(), Some("z_ctx"));
    }

    #[test]
    fn run_diagnostics_details_includes_property_compilation_traces() {
        let mut diag = PipelineRunDiagnostics::default();
        diag.property_compilations
            .push(PropertyCompilationDiagnostic {
                context: "verify_all_properties".into(),
                property_name: "live_temporal".into(),
                property_kind: "liveness".into(),
                fragment: "universal-temporal".into(),
                source_formula: "forall p: R. [] (p.decided == true)".into(),
                source_formula_sha256: "a".repeat(64),
                compilation_target: "temporal_buchi_monitor".into(),
                compiled_summary: "target=temporal_buchi_monitor states=1".into(),
                compiled_sha256: "b".repeat(64),
            });

        let details = run_diagnostics_details(&diag);
        let entries = details["property_compilations"]
            .as_array()
            .expect("property_compilations should be an array");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["compilation_target"].as_str(),
            Some("temporal_buchi_monitor")
        );
        assert_eq!(entries[0]["property_name"].as_str(), Some("live_temporal"));
    }

    #[test]
    fn run_diagnostics_details_includes_machine_readable_property_result_fields() {
        let mut diag = PipelineRunDiagnostics::default();
        diag.property_results.push(PropertyResultDiagnostic {
            property_id: "live_progress".into(),
            property_name: "live_progress".into(),
            property_kind: "liveness".into(),
            fragment: "universal-temporal".into(),
            verdict: "unsafe".into(),
            assumptions: PropertyAssumptionsDiagnostic {
                solver: "z3".into(),
                soundness: "strict".into(),
                max_depth: 6,
                network_semantics: "identity_selective".into(),
                committee_bounds: vec![("f".into(), 1)],
                failure_probability_bound: Some(0.0001),
            },
            witness: Some(PropertyWitnessMetadataDiagnostic {
                witness_kind: "temporal_monitor_counterexample".into(),
                trace_steps: 3,
                violation_step: Some(3),
                temporal_monitor: Some(vec![PropertyTemporalMonitorStepDiagnostic {
                    step: 0,
                    active_states: vec![0],
                    true_atoms: vec![0],
                    acceptance_sets_hit: vec![0],
                }]),
            }),
        });

        let details = run_diagnostics_details(&diag);
        let entries = details["property_results"]
            .as_array()
            .expect("property_results should be an array");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["property_id"].as_str(), Some("live_progress"));
        assert_eq!(entry["property_name"].as_str(), Some("live_progress"));
        assert_eq!(entry["verdict"].as_str(), Some("unsafe"));
        assert_eq!(entry["assumptions"]["solver"].as_str(), Some("z3"));
        assert_eq!(entry["assumptions"]["max_depth"].as_u64(), Some(6));
        assert_eq!(
            entry["witness"]["witness_kind"].as_str(),
            Some("temporal_monitor_counterexample")
        );
        assert_eq!(
            entry["witness"]["temporal_monitor"]
                .as_array()
                .expect("temporal monitor array")
                .len(),
            1
        );
    }

    #[test]
    fn unbounded_fair_unknown_details_include_stable_reason_codes() {
        let timeout_details =
            unbounded_fair_result_details(&UnboundedFairLivenessResult::Unknown {
                reason: "Fair PDR: overall timeout exceeded at frontier frame 5.".into(),
            });
        assert_eq!(timeout_details["reason_code"].as_str(), Some("timeout"));

        let memory_details =
            unbounded_fair_result_details(&UnboundedFairLivenessResult::Unknown {
                reason: "Fair PDR: memory budget exceeded at frontier frame 3 (rss_bytes=8388608, limit_bytes=4194304).".into(),
            });
        assert_eq!(
            memory_details["reason_code"].as_str(),
            Some("memory_budget_exceeded")
        );
    }

    #[test]
    fn unbounded_fair_result_details_include_convergence_diagnostics() {
        let proved =
            unbounded_fair_result_details(&UnboundedFairLivenessResult::LiveProved { frame: 4 });
        assert_eq!(proved["convergence"]["outcome"].as_str(), Some("converged"));
        assert_eq!(proved["convergence"]["frontier_frame"].as_u64(), Some(4));

        let not_proved =
            unbounded_fair_result_details(&UnboundedFairLivenessResult::NotProved { max_k: 9 });
        assert_eq!(
            not_proved["convergence"]["outcome"].as_str(),
            Some("not_converged")
        );
        assert_eq!(
            not_proved["convergence"]["frontier_frame"].as_u64(),
            Some(9)
        );
        assert_eq!(
            not_proved["convergence"]["bound_exhausted"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn liveness_governance_report_includes_fairness_gst_and_obligations() {
        let source = r#"
protocol GovernanceLiveness {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        timing: partial_synchrony;
        gst: gst;
    }

    role Replica {
        var decided: bool = false;
        init idle;
        phase idle {}
    }
}
"#;

        let layers = vec![AnalysisLayerReport {
            layer: "certify[fair_liveness]".into(),
            status: "pass".into(),
            verdict: "LIVE_PROVED".into(),
            summary: "Fair-liveness certificate generated.".into(),
            details: serde_json::json!({
                "integrity_ok": true,
                "obligation_count": 3,
                "obligations_checked": [
                    "init_implies_inv",
                    "inv_and_transition_implies_inv_prime",
                    "inv_implies_no_fair_bad"
                ],
            }),
            output: "LIVE_PROVED".into(),
        }];

        let report = build_liveness_governance_report(
            source,
            "governance_liveness.trs",
            FairnessMode::Strong,
            &layers,
        );
        assert_eq!(report["fairness_model"]["mode"].as_str(), Some("strong"));
        assert_eq!(
            report["gst_assumptions"]["requires_gst"].as_bool(),
            Some(true)
        );
        assert_eq!(
            report["gst_assumptions"]["gst_parameter"].as_str(),
            Some("gst")
        );
        assert_eq!(
            report["obligations_checked"]["total_obligations_checked"].as_u64(),
            Some(3)
        );
        assert_eq!(
            report["obligations_checked"]["entries"][0]["obligation_count"].as_u64(),
            Some(3)
        );
    }

    // --- Conformance Manifest Schema Tests ---

    fn conformance_manifest_schema_json_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/conformance-manifest-schema-v1.json")
    }

    fn conformance_manifest_schema_doc_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONFORMANCE_MANIFEST_SCHEMA.md")
    }

    fn conformance_adapter_manifest_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/conformance_suite_adapters.json")
    }

    #[test]
    fn conformance_manifest_schema_json_exists_and_parses() {
        let path = conformance_manifest_schema_json_path();
        let raw =
            fs::read_to_string(&path).expect("conformance manifest JSON schema should be readable");
        let _: serde_json::Value =
            serde_json::from_str(&raw).expect("conformance manifest JSON schema should decode");
    }

    #[test]
    fn conformance_manifest_schema_doc_exists() {
        let path = conformance_manifest_schema_doc_path();
        let content =
            fs::read_to_string(&path).expect("conformance manifest schema doc should be readable");
        assert!(
            content.contains("schema_version"),
            "doc should mention schema_version"
        );
        assert!(
            content.contains("suite_name"),
            "doc should mention suite_name"
        );
        assert!(
            content.contains("expected_verdict"),
            "doc should mention expected_verdict"
        );
        assert!(
            content.contains("trace_adapter"),
            "doc should mention trace_adapter"
        );
        assert!(
            content.contains("checker_mode"),
            "doc should mention checker_mode"
        );
        assert!(
            content.contains("mismatch_hint"),
            "doc should mention mismatch_hint"
        );
    }

    #[test]
    fn conformance_manifest_schema_version_matches() {
        use tarsier_conformance::manifest::CONFORMANCE_MANIFEST_SCHEMA_VERSION;
        let path = conformance_manifest_schema_json_path();
        let raw = fs::read_to_string(&path).unwrap();
        let schema: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let json_version = schema["properties"]["schema_version"]["const"]
            .as_u64()
            .expect("JSON schema should have schema_version const");
        assert_eq!(
            json_version, CONFORMANCE_MANIFEST_SCHEMA_VERSION as u64,
            "JSON schema version const should match Rust constant"
        );
    }

    #[test]
    fn conformance_manifest_reference_suite_validates() {
        use tarsier_conformance::manifest::{validate_manifest, ConformanceManifest};
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/conformance_suite.json");
        let raw = fs::read_to_string(&path).expect("reference manifest should be readable");
        let manifest: ConformanceManifest =
            serde_json::from_str(&raw).expect("reference manifest should deserialize");
        let errors = validate_manifest(&manifest);
        assert!(
            errors.is_empty(),
            "reference manifest should validate cleanly: {:?}",
            errors.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn conformance_adapter_manifest_validates() {
        use tarsier_conformance::manifest::{validate_manifest, ConformanceManifest};
        let path = conformance_adapter_manifest_path();
        let raw = fs::read_to_string(&path).expect("adapter manifest should be readable");
        let manifest: ConformanceManifest =
            serde_json::from_str(&raw).expect("adapter manifest should deserialize");
        let errors = validate_manifest(&manifest);
        assert!(
            errors.is_empty(),
            "adapter manifest should validate cleanly: {:?}",
            errors.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn conformance_manifest_triage_categories_are_valid() {
        for cat in &CONFORMANCE_TRIAGE_CATEGORIES {
            assert!(!cat.is_empty(), "triage category should be non-empty");
        }
        // Check the doc mentions each category
        let path = conformance_manifest_schema_doc_path();
        let content = fs::read_to_string(&path).unwrap();
        for cat in &CONFORMANCE_TRIAGE_CATEGORIES {
            assert!(
                content.contains(cat),
                "schema doc should mention triage category '{}'",
                cat
            );
        }
    }

    // --- Trust Report Schema Tests ---

    #[cfg(feature = "governance")]
    fn trust_report_schema_json_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/trust-report-schema-v1.json")
    }

    #[cfg(feature = "governance")]
    fn trust_report_schema_doc_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/TRUST_REPORT_SCHEMA.md")
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_schema_json_exists_and_parses() {
        let path = trust_report_schema_json_path();
        let raw = fs::read_to_string(&path).expect("trust report JSON schema should be readable");
        let _: serde_json::Value =
            serde_json::from_str(&raw).expect("trust report JSON schema should decode");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_schema_version_matches() {
        let path = trust_report_schema_json_path();
        let raw = fs::read_to_string(&path).unwrap();
        let schema: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let json_version = schema["properties"]["schema_version"]["const"]
            .as_u64()
            .expect("JSON schema should have schema_version const");
        assert_eq!(
            json_version, TRUST_REPORT_SCHEMA_VERSION as u64,
            "JSON schema version const should match Rust constant"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_schema_doc_exists() {
        let path = trust_report_schema_doc_path();
        let content =
            fs::read_to_string(&path).expect("trust report schema doc should be readable");
        assert!(
            content.contains("schema_version"),
            "doc should mention schema_version"
        );
        assert!(
            content.contains("governance_profile"),
            "doc should mention governance_profile"
        );
        assert!(
            content.contains("claim_layers"),
            "doc should mention claim_layers"
        );
        assert!(
            content.contains("threat_model"),
            "doc should mention threat_model"
        );
        assert!(
            content.contains("residual_assumptions"),
            "doc should mention residual_assumptions"
        );
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_generator_standard_profile() {
        use super::generate_trust_report;
        let report = generate_trust_report(
            "standard",
            Some("test.trs"),
            &["z3"],
            "kinduction",
            "strict",
        );
        assert_eq!(report.schema_version, TRUST_REPORT_SCHEMA_VERSION);
        assert_eq!(report.governance_profile, "standard");
        assert!(!report.trust_boundary.claim_layers.is_empty());
        assert!(!report.trust_boundary.threat_model.is_empty());
        assert!(!report.residual_assumptions.is_empty());
        assert_eq!(report.verification_scope.solvers, vec!["z3"]);
        assert_eq!(report.verification_scope.proof_engine, "kinduction");
        assert_eq!(report.verification_scope.soundness, "strict");
        assert_eq!(
            report.verification_scope.protocol_file,
            Some("test.trs".into())
        );
        // multi_solver_replay should be not_applicable with single solver
        let multi_solver_layer = report
            .trust_boundary
            .claim_layers
            .iter()
            .find(|l| l.name == "multi_solver_replay")
            .expect("should have multi_solver_replay layer");
        assert_eq!(multi_solver_layer.status, "not_applicable");
        // proof_object_path should be optional for standard profile
        let proof_layer = report
            .trust_boundary
            .claim_layers
            .iter()
            .find(|l| l.name == "proof_object_path")
            .expect("should have proof_object_path layer");
        assert_eq!(proof_layer.status, "optional");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_generator_high_assurance_profile() {
        use super::generate_trust_report;
        let report = generate_trust_report(
            "high-assurance",
            Some("test.trs"),
            &["z3", "cvc5"],
            "kinduction",
            "strict",
        );
        assert_eq!(report.governance_profile, "high-assurance");
        // multi_solver_replay should be enforced with two solvers
        let multi_solver_layer = report
            .trust_boundary
            .claim_layers
            .iter()
            .find(|l| l.name == "multi_solver_replay")
            .expect("should have multi_solver_replay layer");
        assert_eq!(multi_solver_layer.status, "enforced");
        // proof_object_path should be enforced for high-assurance
        let proof_layer = report
            .trust_boundary
            .claim_layers
            .iter()
            .find(|l| l.name == "proof_object_path")
            .expect("should have proof_object_path layer");
        assert_eq!(proof_layer.status, "enforced");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_serde_roundtrip() {
        use super::{generate_trust_report, TrustReport};
        let report = generate_trust_report("reinforced", None, &["z3"], "pdr", "permissive");
        let json = serde_json::to_string_pretty(&report).unwrap();
        let deserialized: TrustReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, report.schema_version);
        assert_eq!(deserialized.governance_profile, report.governance_profile);
        assert_eq!(
            deserialized.trust_boundary.claim_layers.len(),
            report.trust_boundary.claim_layers.len()
        );
        assert_eq!(
            deserialized.trust_boundary.threat_model.len(),
            report.trust_boundary.threat_model.len()
        );
        assert_eq!(
            deserialized.residual_assumptions.len(),
            report.residual_assumptions.len()
        );
        assert!(deserialized.verification_scope.protocol_file.is_none());
    }

    #[cfg(feature = "governance")]
    #[test]
    fn trust_report_schema_doc_references_json_schema() {
        let path = trust_report_schema_doc_path();
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("trust-report-schema-v1.json"),
            "schema doc should reference the JSON schema file"
        );
    }

    #[test]
    fn capture_proofs_strict_fails_on_missing_proof() {
        let out = tmp_dir("tarsier_cli_strict_proof_fail");
        fs::create_dir_all(&out).expect("output dir should be created");

        let input = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "test_protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            // Use a solver that does not exist, so proof extraction will fail.
            solver_used: "nonexistent-solver-binary-xyz".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            obligations: vec![CertificateBundleObligation {
                name: "base_case".into(),
                expected: "unsat".into(),
                smt2: "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n".into(),
            }],
        };

        // capture_proofs=true, allow_missing_proofs=false → should fail
        let result = write_certificate_bundle(&out, &input, true, false);
        assert!(
            result.is_err(),
            "strict proof capture should fail when extraction fails"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Proof extraction failed")
                || err_msg.contains("--allow-missing-proofs"),
            "error should mention proof extraction failure or escape hatch; got: {err_msg}"
        );
    }

    #[test]
    fn capture_proofs_with_allow_missing_continues() {
        let out = tmp_dir("tarsier_cli_allow_missing_proof");
        fs::create_dir_all(&out).expect("output dir should be created");

        let input = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "test_protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "nonexistent-solver-binary-xyz".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            obligations: vec![CertificateBundleObligation {
                name: "base_case".into(),
                expected: "unsat".into(),
                smt2: "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n".into(),
            }],
        };

        // capture_proofs=true, allow_missing_proofs=true → should succeed (warn-and-continue)
        let result = write_certificate_bundle(&out, &input, true, true);
        assert!(
            result.is_ok(),
            "allow_missing_proofs should let bundle generation continue; err: {:?}",
            result.err()
        );

        // Certificate should exist but without proof files
        let cert_json = fs::read_to_string(out.join("certificate.json"))
            .expect("certificate.json should exist");
        let meta: CertificateMetadata =
            serde_json::from_str(&cert_json).expect("certificate should be valid JSON");
        assert!(
            meta.obligations[0].proof_file.is_none(),
            "proof_file should be None when extraction failed"
        );
    }

    #[test]
    fn capture_proofs_false_skips_extraction_entirely() {
        let out = tmp_dir("tarsier_cli_no_capture");
        fs::create_dir_all(&out).expect("output dir should be created");

        let input = CertificateBundleInput {
            kind: CertificateKind::SafetyProof,
            protocol_file: "test_protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "nonexistent-solver-binary-xyz".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            obligations: vec![CertificateBundleObligation {
                name: "base_case".into(),
                expected: "unsat".into(),
                smt2: "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n".into(),
            }],
        };

        // capture_proofs=false → should succeed regardless of solver availability
        let result = write_certificate_bundle(&out, &input, false, false);
        assert!(
            result.is_ok(),
            "capture_proofs=false should skip extraction entirely; err: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------
    // Conformance suite: artifact_link population tests
    // ---------------------------------------------------------------

    #[test]
    fn conformance_suite_artifact_links_populated_with_artifact_dir() {
        // Run the conformance suite with an artifact_dir; every entry should
        // have artifact_link set and the referenced file should exist on disk.
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/conformance_suite.json");

        let tmp = std::env::temp_dir().join(format!(
            "tarsier_conformance_artifacts_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);

        let report = run_conformance_suite(&manifest_path, Some(&tmp)).unwrap();

        assert!(
            !report.entries.is_empty(),
            "suite should have at least one entry"
        );

        for entry in &report.entries {
            let link = entry.artifact_link.as_ref().unwrap_or_else(|| {
                panic!("entry '{}' should have artifact_link, got None", entry.name)
            });
            let path = std::path::Path::new(link);
            assert!(
                path.exists(),
                "artifact_link for '{}' points to non-existent file: {}",
                entry.name,
                link
            );
            // Verify the artifact is valid JSON with expected fields
            let content = fs::read_to_string(path).unwrap();
            let detail: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("artifact for '{}' is not valid JSON: {e}", entry.name));
            assert_eq!(detail["name"], entry.name);
            assert_eq!(detail["status"], entry.status);
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn conformance_suite_no_artifact_links_without_artifact_dir() {
        // Without an artifact_dir, artifact_link should be None for all entries.
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/conformance_suite.json");

        let report = run_conformance_suite(&manifest_path, None).unwrap();

        for entry in &report.entries {
            assert!(
                entry.artifact_link.is_none(),
                "entry '{}' should have artifact_link=None without artifact_dir, got {:?}",
                entry.name,
                entry.artifact_link
            );
        }
    }

    #[test]
    fn conformance_suite_json_output_includes_artifact_links() {
        // Verify the JSON serialization includes artifact_link fields when present.
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/conformance_suite.json");

        let tmp =
            std::env::temp_dir().join(format!("tarsier_conformance_json_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);

        let report = run_conformance_suite(&manifest_path, Some(&tmp)).unwrap();
        let json_value = serde_json::to_value(&report).unwrap();
        let entries = json_value["entries"].as_array().unwrap();

        for entry_json in entries {
            let name = entry_json["name"].as_str().unwrap();
            assert!(
                entry_json.get("artifact_link").is_some() && !entry_json["artifact_link"].is_null(),
                "JSON entry '{}' should have non-null artifact_link",
                name
            );
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn conformance_suite_adapter_manifest_passes() {
        let report = run_conformance_suite(&conformance_adapter_manifest_path(), None).unwrap();
        assert_eq!(report.overall, "pass");
        assert!(report.failed == 0 && report.errors == 0);
        assert!(report
            .entries
            .iter()
            .any(|e| e.trace_adapter == "cometbft" && e.status == "match"));
        assert!(report
            .entries
            .iter()
            .any(|e| e.trace_adapter == "etcd-raft" && e.status == "match"));
    }

    #[test]
    fn conformance_suite_mismatch_taxonomy_uses_model_impl_and_engine_categories() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let protocol_file =
            workspace_root.join("crates/tarsier-conformance/tests/fixtures/simple_vote.trs");
        let pass_trace =
            workspace_root.join("crates/tarsier-conformance/tests/fixtures/valid_trace.json");
        let fail_trace = workspace_root
            .join("crates/tarsier-conformance/tests/fixtures/guard_not_satisfied.json");

        let tmp_dir = std::env::temp_dir().join(format!(
            "tarsier_conformance_taxonomy_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let manifest_path = tmp_dir.join("manifest.json");

        let manifest = serde_json::json!({
            "schema_version": 1,
            "suite_name": "taxonomy-contract",
            "entries": [
                {
                    "name": "model-change-hash-mismatch",
                    "protocol_file": protocol_file.display().to_string(),
                    "trace_file": pass_trace.display().to_string(),
                    "trace_adapter": "runtime",
                    "checker_mode": "strict",
                    "expected_verdict": "pass",
                    "model_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                {
                    "name": "impl-divergence-default",
                    "protocol_file": protocol_file.display().to_string(),
                    "trace_file": fail_trace.display().to_string(),
                    "trace_adapter": "runtime",
                    "checker_mode": "strict",
                    "expected_verdict": "pass"
                },
                {
                    "name": "engine-regression-hint",
                    "protocol_file": protocol_file.display().to_string(),
                    "trace_file": fail_trace.display().to_string(),
                    "trace_adapter": "runtime",
                    "checker_mode": "strict",
                    "expected_verdict": "pass",
                    "mismatch_hint": "engine_regression"
                }
            ]
        });
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = run_conformance_suite(&manifest_path, None).unwrap();
        assert_eq!(report.overall, "fail");
        let by_name: std::collections::HashMap<_, _> = report
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.triage.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(
            by_name.get("model-change-hash-mismatch").copied(),
            Some(CONFORMANCE_TRIAGE_MODEL_CHANGE)
        );
        assert_eq!(
            by_name.get("impl-divergence-default").copied(),
            Some(CONFORMANCE_TRIAGE_IMPL_DIVERGENCE)
        );
        assert_eq!(
            by_name.get("engine-regression-hint").copied(),
            Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION)
        );
        assert!(report.triage.contains_key(CONFORMANCE_TRIAGE_MODEL_CHANGE));
        assert!(report
            .triage
            .contains_key(CONFORMANCE_TRIAGE_IMPL_DIVERGENCE));
        assert!(report
            .triage
            .contains_key(CONFORMANCE_TRIAGE_ENGINE_REGRESSION));
    }

    // ---------------------------------------------------------------
    // Portfolio merge determinism tests (P1-05)
    // ---------------------------------------------------------------

    fn make_trace(steps: usize, param_vals: Vec<(String, i64)>) -> Trace {
        let config = Configuration {
            kappa: vec![1, 0],
            gamma: vec![0],
            params: vec![3, 1],
        };
        let trace_steps: Vec<TraceStep> = (0..steps)
            .map(|i| TraceStep {
                smt_step: i,
                rule_id: 0,
                delta: 1,
                deliveries: vec![],
                config: config.clone(),
                por_status: None,
            })
            .collect();
        Trace {
            initial_config: config,
            steps: trace_steps,
            param_values: param_vals,
        }
    }

    fn make_cegar_report(result: VerificationResult) -> CegarAuditReport {
        CegarAuditReport {
            max_refinements: 0,
            stages: vec![],
            discovered_predicates: vec![],
            classification: "safe".into(),
            counterexample_analysis: None,
            termination: CegarTermination {
                reason: "baseline_safe".into(),
                iteration_budget: 0,
                iterations_used: 0,
                timeout_secs: 60,
                elapsed_ms: 10,
                reached_iteration_budget: false,
                reached_timeout_budget: false,
            },
            final_result: result,
        }
    }

    #[test]
    fn trace_fingerprint_is_deterministic() {
        let t1 = make_trace(3, vec![("n".into(), 5)]);
        let t2 = make_trace(3, vec![("n".into(), 5)]);
        assert_eq!(trace_fingerprint(&t1), trace_fingerprint(&t2));
    }

    #[test]
    fn prefer_trace_shorter_wins() {
        let short = make_trace(2, vec![("n".into(), 5)]);
        let long = make_trace(5, vec![("n".into(), 5)]);
        assert!(prefer_trace_a(&short, &long));
        assert!(!prefer_trace_a(&long, &short));
    }

    #[test]
    fn prefer_trace_equal_length_uses_lexicographic_fingerprint() {
        let t_a = make_trace(3, vec![("a".into(), 1)]);
        let t_b = make_trace(3, vec![("b".into(), 1)]);
        // One of them must be preferred, and the relationship must be total
        let a_over_b = prefer_trace_a(&t_a, &t_b);
        let b_over_a = prefer_trace_a(&t_b, &t_a);
        // Exactly one should be preferred (or equal → both true via <=)
        assert!(
            a_over_b || b_over_a,
            "lexicographic comparison must be total"
        );
    }

    #[test]
    fn prefer_trace_reflexive() {
        let t = make_trace(3, vec![("n".into(), 5)]);
        // Same trace compared to itself: fingerprint(t) <= fingerprint(t) → true
        assert!(prefer_trace_a(&t, &t));
    }

    #[test]
    fn merge_portfolio_both_safe_picks_z3() {
        let z3 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 10,
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 12,
        }));
        let (result, details) = merge_portfolio_verify_reports(z3, cvc5);
        assert_eq!(verification_result_kind(&result), "safe");
        // Should pick z3's depth (10), not cvc5's (12)
        match &result {
            VerificationResult::Safe { depth_checked } => assert_eq!(*depth_checked, 10),
            _ => panic!("expected Safe"),
        }
        assert_eq!(details["merge_policy"]["deterministic"], true);
    }

    #[test]
    fn merge_portfolio_safe_vs_unsafe_is_disagreement() {
        // When solvers disagree (one safe, one unsafe), merge yields unknown
        // (portfolio disagreement) — this is the correct conservative policy.
        let trace = make_trace(3, vec![("n".into(), 5)]);
        let z3 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 10,
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Unsafe {
            trace: trace.clone(),
        }));
        let (result, _) = merge_portfolio_verify_reports(z3, cvc5);
        assert_eq!(verification_result_kind(&result), "unknown");
        match &result {
            VerificationResult::Unknown { reason } => {
                assert!(
                    reason.contains("disagreement"),
                    "should explain disagreement: {reason}"
                );
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn merge_portfolio_both_unsafe_picks_shorter_trace() {
        let short = make_trace(2, vec![("n".into(), 5)]);
        let long = make_trace(5, vec![("n".into(), 5)]);
        let z3 = Ok(make_cegar_report(VerificationResult::Unsafe {
            trace: long.clone(),
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Unsafe {
            trace: short.clone(),
        }));
        let (result, _) = merge_portfolio_verify_reports(z3, cvc5);
        match &result {
            VerificationResult::Unsafe { trace } => {
                assert_eq!(trace.steps.len(), 2, "should pick shorter trace");
            }
            _ => panic!("expected Unsafe"),
        }
    }

    #[test]
    fn merge_portfolio_both_unknown_combines_reasons() {
        let z3 = Ok(make_cegar_report(VerificationResult::Unknown {
            reason: "z3 timeout".into(),
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Unknown {
            reason: "cvc5 timeout".into(),
        }));
        let (result, _) = merge_portfolio_verify_reports(z3, cvc5);
        match &result {
            VerificationResult::Unknown { reason } => {
                assert!(reason.contains("z3"));
                assert!(reason.contains("cvc5"));
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn merge_portfolio_disagreement_yields_unknown() {
        let z3 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 10,
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Unknown {
            reason: "timeout".into(),
        }));
        let (result, _) = merge_portfolio_verify_reports(z3, cvc5);
        assert_eq!(verification_result_kind(&result), "unknown");
    }

    #[test]
    fn merge_portfolio_one_error_yields_unknown() {
        let z3: Result<CegarAuditReport, String> = Err("z3 crashed".into());
        let cvc5 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 10,
        }));
        let (result, _) = merge_portfolio_verify_reports(z3, cvc5);
        assert_eq!(verification_result_kind(&result), "unknown");
    }

    #[test]
    fn merge_portfolio_liveness_both_live_takes_min_depth() {
        let z3 = Ok(LivenessResult::Live { depth_checked: 8 });
        let cvc5 = Ok(LivenessResult::Live { depth_checked: 12 });
        let (result, details) = merge_portfolio_liveness_results(z3, cvc5);
        match &result {
            LivenessResult::Live { depth_checked } => {
                assert_eq!(*depth_checked, 8, "should take min depth");
            }
            _ => panic!("expected Live"),
        }
        assert_eq!(details["merge_policy"]["deterministic"], true);
    }

    #[test]
    fn merge_portfolio_liveness_not_live_picks_shorter_trace() {
        let short = make_trace(2, vec![("n".into(), 5)]);
        let long = make_trace(5, vec![("n".into(), 5)]);
        let z3 = Ok(LivenessResult::NotLive {
            trace: long.clone(),
        });
        let cvc5 = Ok(LivenessResult::NotLive {
            trace: short.clone(),
        });
        let (result, _) = merge_portfolio_liveness_results(z3, cvc5);
        match &result {
            LivenessResult::NotLive { trace } => {
                assert_eq!(trace.steps.len(), 2, "should pick shorter trace");
            }
            _ => panic!("expected NotLive"),
        }
    }

    #[test]
    fn merge_portfolio_verify_reports_is_idempotent() {
        // Running the same merge twice with the same inputs yields identical results.
        let trace_a = make_trace(3, vec![("n".into(), 5)]);
        let trace_b = make_trace(4, vec![("n".into(), 7)]);

        for _ in 0..5 {
            let z3 = Ok(make_cegar_report(VerificationResult::Unsafe {
                trace: trace_a.clone(),
            }));
            let cvc5 = Ok(make_cegar_report(VerificationResult::Unsafe {
                trace: trace_b.clone(),
            }));
            let (result, details) = merge_portfolio_verify_reports(z3, cvc5);
            // trace_a is shorter (3 vs 4), so it should always be selected
            match &result {
                VerificationResult::Unsafe { trace } => {
                    assert_eq!(trace.steps.len(), 3);
                }
                _ => panic!("expected Unsafe"),
            }
            assert_eq!(details["merge_policy"]["deterministic"], true);
            assert_eq!(
                details["merge_policy"]["trace_tiebreak"],
                "shortest_trace_then_lexicographic"
            );
        }
    }

    #[test]
    fn portfolio_stress_worker_completion_order_does_not_change_solver_labeling() {
        for i in 0..64 {
            let z3_delay_ms = if i % 2 == 0 { 2 } else { 0 };
            let cvc5_delay_ms = if i % 2 == 0 { 0 } else { 2 };
            let (z3_result, cvc5_result) = run_portfolio_workers(
                move || {
                    std::thread::sleep(std::time::Duration::from_millis(z3_delay_ms));
                    Ok::<String, String>("z3".to_string())
                },
                move || {
                    std::thread::sleep(std::time::Duration::from_millis(cvc5_delay_ms));
                    Ok::<String, String>("cvc5".to_string())
                },
            );

            assert_eq!(z3_result.unwrap(), "z3");
            assert_eq!(cvc5_result.unwrap(), "cvc5");
        }
    }

    #[test]
    fn portfolio_stress_identical_inputs_produce_identical_artifacts() {
        let mut baseline: Option<String> = None;
        for i in 0..64 {
            let z3_delay_ms = if i % 2 == 0 { 2 } else { 0 };
            let cvc5_delay_ms = if i % 2 == 0 { 0 } else { 2 };
            let (z3_result, cvc5_result) = run_portfolio_workers(
                move || {
                    std::thread::sleep(std::time::Duration::from_millis(z3_delay_ms));
                    Ok::<CegarAuditReport, String>(make_cegar_report(VerificationResult::Safe {
                        depth_checked: 9,
                    }))
                },
                move || {
                    std::thread::sleep(std::time::Duration::from_millis(cvc5_delay_ms));
                    Ok::<CegarAuditReport, String>(make_cegar_report(VerificationResult::Safe {
                        depth_checked: 11,
                    }))
                },
            );
            let (merged_result, details) = merge_portfolio_verify_reports(z3_result, cvc5_result);
            let artifact = serde_json::to_string(&json!({
                "result": verification_result_kind(&merged_result),
                "portfolio": details,
            }))
            .expect("artifact serialization should succeed");
            if let Some(expected) = &baseline {
                assert_eq!(
                    artifact, *expected,
                    "portfolio artifact changed across identical runs at iteration {i}"
                );
            } else {
                baseline = Some(artifact);
            }
        }
    }

    #[test]
    fn portfolio_merge_provenance_verify_reports_selected_solver_and_reason() {
        let z3 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 9,
        }));
        let cvc5 = Ok(make_cegar_report(VerificationResult::Safe {
            depth_checked: 11,
        }));
        let (_result, details) = merge_portfolio_verify_reports(z3, cvc5);
        assert_eq!(details["selected_solver"], "z3");
        assert!(details["merge_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("safety-equivalent"));
        assert_eq!(details["per_solver_outcomes"]["z3"]["result"], "safe");
        assert_eq!(details["per_solver_outcomes"]["cvc5"]["result"], "safe");
    }

    #[test]
    fn portfolio_merge_provenance_liveness_reports_outcomes_and_reason() {
        let z3 = Ok(LivenessResult::Live { depth_checked: 8 });
        let cvc5 = Ok(LivenessResult::Live { depth_checked: 12 });
        let (_result, details) = merge_portfolio_liveness_results(z3, cvc5);
        assert_eq!(details["selected_solver"], "both");
        assert!(details["merge_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("minimum checked depth"));
        assert_eq!(details["per_solver_outcomes"]["z3"]["result"], "live");
        assert_eq!(details["per_solver_outcomes"]["cvc5"]["result"], "live");
    }

    #[test]
    fn portfolio_merge_provenance_prove_reports_outcomes_and_reason() {
        let z3 = Ok(UnboundedSafetyResult::NotProved {
            max_k: 6,
            cti: None,
        });
        let cvc5 = Ok(UnboundedSafetyResult::NotProved {
            max_k: 9,
            cti: None,
        });
        let (_result, details) = merge_portfolio_prove_results(z3, cvc5);
        assert_eq!(details["selected_solver"], "both");
        assert!(details["merge_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("not_proved"));
        assert_eq!(details["per_solver_outcomes"]["z3"]["result"], "not_proved");
        assert_eq!(
            details["per_solver_outcomes"]["cvc5"]["result"],
            "not_proved"
        );
    }

    #[test]
    fn portfolio_merge_provenance_fair_liveness_reports_outcomes_and_reason() {
        let z3 = Ok(FairLivenessResult::NoFairCycleUpTo { depth_checked: 4 });
        let cvc5: Result<FairLivenessResult, String> = Err("solver crash".into());
        let (_result, details) = merge_portfolio_fair_liveness_results(z3, cvc5);
        assert_eq!(details["selected_solver"], "none");
        assert!(details["merge_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("incomplete portfolio"));
        assert_eq!(
            details["per_solver_outcomes"]["z3"]["result"],
            "no_fair_cycle_up_to"
        );
        assert_eq!(details["per_solver_outcomes"]["cvc5"]["status"], "error");
    }

    #[test]
    fn portfolio_merge_provenance_prove_fair_reports_outcomes_and_reason() {
        let z3 = Ok(UnboundedFairLivenessResult::Unknown {
            reason: "timeout".into(),
        });
        let cvc5 = Ok(UnboundedFairLivenessResult::Unknown {
            reason: "resource_exhausted".into(),
        });
        let (_result, details) = merge_portfolio_prove_fair_results(z3, cvc5);
        assert_eq!(details["selected_solver"], "none");
        assert!(details["merge_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("inconclusive"));
        assert_eq!(details["per_solver_outcomes"]["z3"]["result"], "unknown");
        assert_eq!(details["per_solver_outcomes"]["cvc5"]["result"], "unknown");
    }

    #[test]
    fn analysis_config_includes_por_mode() {
        let cfg = AnalysisConfig {
            solver: "z3".to_string(),
            depth: 10,
            k: 12,
            timeout_secs: 300,
            soundness: "strict".to_string(),
            fairness: "weak".to_string(),
            portfolio: false,
            por_mode: "full".to_string(),
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["por_mode"], "full");

        let cfg_off = AnalysisConfig {
            por_mode: "off".to_string(),
            ..cfg
        };
        let json_off = serde_json::to_value(&cfg_off).unwrap();
        assert_eq!(json_off["por_mode"], "off");
    }

    #[test]
    fn phase_profile_summary_renders_all_phases() {
        let diag = PipelineRunDiagnostics {
            phase_profiles: vec![
                PhaseProfileDiagnostic {
                    context: "ctx".into(),
                    phase: "parse".into(),
                    elapsed_ms: 5,
                    rss_bytes: Some(50 * 1024 * 1024),
                },
                PhaseProfileDiagnostic {
                    context: "ctx".into(),
                    phase: "lower".into(),
                    elapsed_ms: 12,
                    rss_bytes: Some(55 * 1024 * 1024),
                },
                PhaseProfileDiagnostic {
                    context: "ctx".into(),
                    phase: "encode".into(),
                    elapsed_ms: 30,
                    rss_bytes: None,
                },
                PhaseProfileDiagnostic {
                    context: "ctx".into(),
                    phase: "solve".into(),
                    elapsed_ms: 200,
                    rss_bytes: Some(60 * 1024 * 1024),
                },
                PhaseProfileDiagnostic {
                    context: "ctx".into(),
                    phase: "check".into(),
                    elapsed_ms: 250,
                    rss_bytes: Some(62 * 1024 * 1024),
                },
            ],
            ..Default::default()
        };
        let summary = render_phase_profile_summary(&diag).expect("should produce summary");
        assert!(
            summary.contains("Phase profiling:"),
            "Header missing: {summary}"
        );
        assert!(summary.contains("parse"), "parse phase missing: {summary}");
        assert!(summary.contains("lower"), "lower phase missing: {summary}");
        assert!(
            summary.contains("encode"),
            "encode phase missing: {summary}"
        );
        assert!(summary.contains("solve"), "solve phase missing: {summary}");
        assert!(summary.contains("check"), "check phase missing: {summary}");
        assert!(summary.contains("rss="), "rss field missing: {summary}");
        assert!(summary.contains("MB"), "MB unit missing: {summary}");
    }

    #[test]
    fn phase_profile_summary_none_when_empty() {
        let diag = PipelineRunDiagnostics::default();
        assert!(render_phase_profile_summary(&diag).is_none());
    }

    #[test]
    fn phase_profile_json_output_has_all_fields() {
        let diag = PipelineRunDiagnostics {
            phase_profiles: vec![PhaseProfileDiagnostic {
                context: "test_ctx".into(),
                phase: "parse".into(),
                elapsed_ms: 42,
                rss_bytes: Some(1024),
            }],
            ..Default::default()
        };
        let json = run_diagnostics_details(&diag);
        let profiles = json["phase_profiles"]
            .as_array()
            .expect("phase_profiles array");
        assert_eq!(profiles.len(), 1);
        let entry = &profiles[0];
        assert_eq!(entry["context"], "test_ctx");
        assert_eq!(entry["phase"], "parse");
        assert_eq!(entry["elapsed_ms"], 42);
        assert_eq!(entry["rss_bytes"], 1024);
    }

    #[test]
    fn reduction_diagnostics_json_includes_applied_reductions_and_notes() {
        let diag = PipelineRunDiagnostics {
            applied_reductions: vec![AppliedReductionDiagnostic {
                context: "test".into(),
                kind: "network_fallback".into(),
                from: "process_selective".into(),
                to: "identity_selective".into(),
                trigger: "footprint exceeded".into(),
                before: AutomatonFootprint {
                    locations: 10,
                    rules: 8,
                    shared_vars: 5,
                    message_counters: 3,
                },
                after: AutomatonFootprint {
                    locations: 4,
                    rules: 3,
                    shared_vars: 2,
                    message_counters: 1,
                },
            }],
            reduction_notes: vec![
                "por.independent_rule_pairs=7".into(),
                "por.transition_multiset_semantics=on".into(),
            ],
            ..Default::default()
        };

        let json = run_diagnostics_details(&diag);

        // applied_reductions present with correct fields
        let reductions = json["applied_reductions"]
            .as_array()
            .expect("applied_reductions array");
        assert_eq!(reductions.len(), 1);
        assert_eq!(reductions[0]["kind"], "network_fallback");
        assert_eq!(reductions[0]["from"], "process_selective");
        assert_eq!(reductions[0]["to"], "identity_selective");
        assert_eq!(reductions[0]["trigger"], "footprint exceeded");
        assert!(reductions[0]["before"]["locations"].as_u64().unwrap() > 0);
        assert!(reductions[0]["after"]["locations"].as_u64().unwrap() > 0);

        // reduction_notes present
        let notes = json["reduction_notes"]
            .as_array()
            .expect("reduction_notes array");
        assert_eq!(notes.len(), 2);
        assert!(notes[0].as_str().unwrap().starts_with("por."));
    }

    #[test]
    fn trace_json_includes_por_status_field() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![3],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![1],
                    params: vec![3],
                },
                por_status: Some("active (full POR)".into()),
            }],
            param_values: vec![("n".into(), 3)],
        };

        let json = trace_json(&trace);

        let steps = json["steps"].as_array().expect("steps array");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0]["por_status"], "active (full POR)");
    }

    #[test]
    fn trace_json_por_status_null_when_off() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![3],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 1,
                deliveries: vec![],
                config: Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![1],
                    params: vec![3],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 3)],
        };

        let json = trace_json(&trace);

        let steps = json["steps"].as_array().expect("steps array");
        assert_eq!(steps.len(), 1);
        assert!(steps[0]["por_status"].is_null());
    }

    // --- P2-09: Governance pipeline tests ---

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_report_schema_v1_structure() {
        let report = GovernancePipelineReport {
            schema_version: "v1".to_string(),
            tarsier_version: "0.1.0".to_string(),
            gates: vec![
                GovernanceGateResult {
                    gate: "proof".to_string(),
                    status: "pass".to_string(),
                    elapsed_ms: 100,
                    details: json!({"mode": "audit", "overall": "pass"}),
                    error: None,
                },
                GovernanceGateResult {
                    gate: "cert".to_string(),
                    status: "pass".to_string(),
                    elapsed_ms: 200,
                    details: json!({"passed": 5, "failed": 0}),
                    error: None,
                },
                GovernanceGateResult {
                    gate: "corpus".to_string(),
                    status: "fail".to_string(),
                    elapsed_ms: 50,
                    details: json!({"passed": 3, "failed": 1}),
                    error: None,
                },
                GovernanceGateResult {
                    gate: "perf".to_string(),
                    status: "skip".to_string(),
                    elapsed_ms: 0,
                    details: json!({"reason": "no --benchmark-report provided"}),
                    error: None,
                },
            ],
            overall: "fail".to_string(),
            elapsed_ms: 350,
        };

        let json: serde_json::Value =
            serde_json::to_value(&report).expect("serialize pipeline report");
        assert_eq!(json["schema_version"], "v1");
        assert_eq!(json["tarsier_version"], "0.1.0");
        assert_eq!(json["overall"], "fail");

        let gates = json["gates"].as_array().expect("gates array");
        assert_eq!(gates.len(), 4);
        assert_eq!(gates[0]["gate"], "proof");
        assert_eq!(gates[0]["status"], "pass");
        assert_eq!(gates[1]["gate"], "cert");
        assert_eq!(gates[2]["gate"], "corpus");
        assert_eq!(gates[2]["status"], "fail");
        assert_eq!(gates[3]["gate"], "perf");
        assert_eq!(gates[3]["status"], "skip");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_report_overall_pass_when_all_pass_or_skip() {
        let gates = vec![
            GovernanceGateResult {
                gate: "proof".to_string(),
                status: "pass".to_string(),
                elapsed_ms: 10,
                details: json!({}),
                error: None,
            },
            GovernanceGateResult {
                gate: "cert".to_string(),
                status: "pass".to_string(),
                elapsed_ms: 10,
                details: json!({}),
                error: None,
            },
            GovernanceGateResult {
                gate: "corpus".to_string(),
                status: "pass".to_string(),
                elapsed_ms: 10,
                details: json!({}),
                error: None,
            },
            GovernanceGateResult {
                gate: "perf".to_string(),
                status: "skip".to_string(),
                elapsed_ms: 0,
                details: json!({}),
                error: None,
            },
        ];
        let overall = if gates
            .iter()
            .all(|g| g.status == "pass" || g.status == "skip")
        {
            "pass"
        } else {
            "fail"
        };
        assert_eq!(overall, "pass");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_report_overall_fail_when_any_gate_fails() {
        let gates = vec![
            GovernanceGateResult {
                gate: "proof".to_string(),
                status: "pass".to_string(),
                elapsed_ms: 10,
                details: json!({}),
                error: None,
            },
            GovernanceGateResult {
                gate: "cert".to_string(),
                status: "fail".to_string(),
                elapsed_ms: 10,
                details: json!({}),
                error: None,
            },
        ];
        let overall = if gates
            .iter()
            .all(|g| g.status == "pass" || g.status == "skip")
        {
            "pass"
        } else {
            "fail"
        };
        assert_eq!(overall, "fail");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_report_overall_fail_when_error() {
        let gates = vec![GovernanceGateResult {
            gate: "proof".to_string(),
            status: "error".to_string(),
            elapsed_ms: 1,
            details: json!({}),
            error: Some("file not found".to_string()),
        }];
        let overall = if gates
            .iter()
            .all(|g| g.status == "pass" || g.status == "skip")
        {
            "pass"
        } else {
            "fail"
        };
        assert_eq!(overall, "fail");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_gate_result_error_field_skipped_when_none() {
        let gate = GovernanceGateResult {
            gate: "proof".to_string(),
            status: "pass".to_string(),
            elapsed_ms: 10,
            details: json!({"mode": "audit"}),
            error: None,
        };
        let json = serde_json::to_value(&gate).expect("serialize");
        assert!(!json.as_object().unwrap().contains_key("error"));
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_gate_result_error_field_present_when_some() {
        let gate = GovernanceGateResult {
            gate: "cert".to_string(),
            status: "error".to_string(),
            elapsed_ms: 5,
            details: json!({}),
            error: Some("manifest not found".to_string()),
        };
        let json = serde_json::to_value(&gate).expect("serialize");
        assert_eq!(json["error"], "manifest not found");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_perf_gate_validates_benchmark_report() {
        let bench_report = json!({
            "schema_version": 1,
            "performance_gate": {"pass": true, "threshold_ms": 1000},
            "scale_band_gate": {"pass": true},
            "summary": {"total": 5, "ok": 5, "failed": 0},
        });
        let perf_gate_obj = bench_report.get("performance_gate");
        let perf_pass = perf_gate_obj
            .and_then(|g| g.get("pass"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let scale_gate_obj = bench_report.get("scale_band_gate");
        let scale_pass = scale_gate_obj
            .and_then(|g| g.get("pass"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        assert!(perf_pass);
        assert!(scale_pass);

        // Failing perf gate
        let bench_fail = json!({
            "performance_gate": {"pass": false},
            "scale_band_gate": {"pass": true},
        });
        let perf_fail = bench_fail
            .get("performance_gate")
            .and_then(|g| g.get("pass"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        assert!(!perf_fail);
    }

    #[cfg(feature = "governance")]
    #[test]
    fn governance_pipeline_command_parses() {
        let args = Cli::try_parse_from([
            "tarsier",
            "governance-pipeline",
            "proto.trs",
            "--solver",
            "z3",
            "--depth",
            "8",
            "--format",
            "json",
        ]);
        assert!(args.is_ok(), "governance-pipeline command should parse");
    }

    #[cfg(feature = "governance")]
    #[test]
    fn verify_governance_bundle_command_parses() {
        let args = Cli::try_parse_from([
            "tarsier",
            "verify-governance-bundle",
            "governance-bundle.json",
            "--format",
            "json",
        ]);
        assert!(
            args.is_ok(),
            "verify-governance-bundle command should parse"
        );
    }
}
