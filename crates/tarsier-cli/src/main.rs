use clap::{Parser, Subcommand};
use miette::IntoDiagnostic;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

use tarsier_dsl::ast::Span as DslSpan;
use tarsier_engine::pipeline::{
    set_execution_controls, take_run_diagnostics, AutomatonFootprint, FairLivenessProofCertificate,
    FairnessMode, FaithfulFallbackConfig, FaithfulFallbackFloor, PipelineExecutionControls,
    PipelineOptions, PipelineRunDiagnostics, ProofEngine, SafetyProofCertificate, SolverChoice,
    SoundnessMode,
};
use tarsier_engine::result::{
    CegarAuditReport, CegarCounterexampleAnalysis, CegarRunControls, CegarStageOutcome,
    FairLivenessResult, InductionCtiSummary, LivenessResult, UnboundedFairLivenessCegarAuditReport,
    UnboundedFairLivenessCegarStageOutcome, UnboundedFairLivenessResult,
    UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome, UnboundedSafetyResult,
    VerificationResult,
};
use tarsier_engine::visualization::{
    config_snapshot, render_trace_markdown, render_trace_mermaid, render_trace_timeline,
};
use tarsier_ir::counter_system::Trace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;
use tarsier_proof_kernel::{
    check_bundle_integrity, compute_bundle_sha256, sha256_hex_bytes, sha256_hex_file,
    CertificateMetadata, CertificateObligationMeta, CERTIFICATE_SCHEMA_VERSION,
};

const CERT_SUITE_SCHEMA_VERSION: u32 = 2;
const CERT_SUITE_SCHEMA_DOC_PATH: &str = "docs/CERT_SUITE_SCHEMA.md";

#[derive(Parser)]
#[command(name = "tarsier")]
#[command(about = "Formal verification tool for consensus protocols using threshold automata")]
#[command(version)]
struct Cli {
    /// Network semantics mode: dsl | faithful
    #[arg(long, global = true, default_value = "dsl")]
    network_semantics: String,

    /// Automatic faithful-network fallback: off | identity | classic
    #[arg(long, global = true, default_value = "off")]
    faithful_fallback: String,

    /// Fallback budget cap for lowered location count
    #[arg(long, global = true, default_value_t = 6000)]
    fallback_max_locations: usize,

    /// Fallback budget cap for lowered shared-variable count
    #[arg(long, global = true, default_value_t = 30000)]
    fallback_max_shared_vars: usize,

    /// Fallback budget cap for lowered message-counter count
    #[arg(long, global = true, default_value_t = 20000)]
    fallback_max_message_counters: usize,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a protocol file
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

    /// Sweep round/view upper bounds and report verdict convergence (cutoff evidence).
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

    /// Prove unbounded safety (or fair-liveness when only liveness properties are declared)
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

    /// Prove safety using a sound round/view-erasure over-approximation (unbounded rounds)
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

    /// Prove unbounded liveness under weak/strong fairness via fair-cycle exclusion (IC3/PDR)
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

    /// Prove fair-liveness using a round/view-erasure over-approximation (unbounded rounds)
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

    /// Parse a protocol file and print the AST
    Parse {
        /// Path to the .trs protocol file
        file: PathBuf,
    },

    /// Show the threshold automaton for a protocol
    ShowTa {
        /// Path to the .trs protocol file
        file: PathBuf,
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

    /// Generate a counterexample visualization (timeline + MSC) from a failing analysis run
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
    },

    /// Deterministic multi-layer analysis pipeline for CI/governance
    Analyze {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Analysis mode: quick | standard | proof | audit
        #[arg(long, default_value = "standard")]
        mode: String,

        /// Primary solver backend
        #[arg(long, default_value = "z3")]
        solver: String,

        /// Bounded depth for verify/liveness/fair-liveness layers
        #[arg(long, default_value_t = 10)]
        depth: usize,

        /// Maximum k for unbounded proof layers
        #[arg(long, default_value_t = 12)]
        k: usize,

        /// Timeout in seconds per layer
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Soundness profile: strict (recommended) or permissive (prototype mode)
        #[arg(long, default_value = "strict")]
        soundness: String,

        /// Fairness mode for fair-liveness layers: weak | strong
        #[arg(long, default_value = "weak")]
        fairness: String,

        /// Run Z3 and cvc5 in parallel for solver-sensitive layers and merge conservatively
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

    /// Semantic linting for protocol models
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
    },

    /// Guided protocol scaffold assistant
    Assist {
        /// Protocol family scaffold: pbft | hotstuff | raft
        #[arg(long, default_value = "pbft")]
        kind: String,

        /// Optional output file path (prints to stdout if omitted)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Generate skeleton implementation code from a verified .trs protocol
    Codegen {
        /// Path to the .trs protocol file
        file: PathBuf,

        /// Target language: rust | go
        #[arg(long, default_value = "rust")]
        target: String,

        /// Output directory (defaults to current directory)
        #[arg(long, short = 'o', default_value = ".")]
        output: PathBuf,
    },

    /// Generate an independently checkable safety proof certificate bundle
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
    },

    /// Generate an independently checkable fair-liveness proof certificate bundle
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
    },

    /// Check a certificate bundle with external SMT solvers
    CheckCertificate {
        /// Path to certificate bundle directory
        bundle: PathBuf,

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
}

#[derive(Clone, Copy, Debug)]
enum AnalysisMode {
    Quick,
    Standard,
    Proof,
    Audit,
}

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliNetworkSemanticsMode {
    Dsl,
    Faithful,
}

#[derive(Clone, Copy, Debug)]
enum VisualizeCheck {
    Verify,
    Liveness,
    FairLiveness,
    Prove,
    ProveFair,
}

#[derive(Clone, Copy, Debug)]
enum VisualizeFormat {
    Timeline,
    Mermaid,
    Markdown,
    Json,
}

#[derive(Clone, Copy)]
struct LayerRunCfg {
    solver: SolverChoice,
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: SoundnessMode,
    fairness: FairnessMode,
    cegar_iters: usize,
    portfolio: bool,
}

#[derive(Serialize)]
struct AnalysisConfig {
    solver: String,
    depth: usize,
    k: usize,
    timeout_secs: u64,
    soundness: String,
    fairness: String,
    portfolio: bool,
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
struct AnalysisLayerReport {
    layer: String,
    status: String,
    summary: String,
    details: Value,
    output: String,
}

#[derive(Serialize)]
struct AnalysisReport {
    schema_version: u32,
    mode: String,
    file: String,
    config: AnalysisConfig,
    network_faithfulness: Value,
    layers: Vec<AnalysisLayerReport>,
    overall: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertSuiteManifest {
    schema_version: u32,
    #[serde(default)]
    enforce_library_coverage: bool,
    #[serde(default)]
    library_dir: Option<String>,
    entries: Vec<CertSuiteEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertSuiteEntry {
    file: String,
    #[serde(default)]
    verify: Option<String>,
    #[serde(default)]
    liveness: Option<String>,
    #[serde(default)]
    fair_liveness: Option<String>,
    #[serde(default)]
    prove: Option<String>,
    #[serde(default)]
    prove_fair: Option<String>,
    #[serde(default)]
    proof_engine: Option<String>,
    #[serde(default)]
    fairness: Option<String>,
    #[serde(default)]
    cegar_iters: Option<usize>,
    #[serde(default)]
    depth: Option<usize>,
    #[serde(default)]
    k: Option<usize>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    variant_group: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    model_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertSuiteCheckReport {
    check: String,
    expected: String,
    actual: String,
    status: String,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    triage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_link: Option<String>,
    output: String,
}

#[derive(Debug, Serialize, Clone)]
struct CertSuiteAssumptions {
    solver: String,
    proof_engine: String,
    soundness: String,
    fairness: String,
    network_semantics: String,
    depth: usize,
    k: usize,
    timeout_secs: u64,
    cegar_iters: usize,
}

#[derive(Debug, Serialize)]
struct CertSuiteEntryReport {
    file: String,
    family: Option<String>,
    class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant_group: Option<String>,
    verdict: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    triage: Option<String>,
    duration_ms: u64,
    assumptions: CertSuiteAssumptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_sha256_expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_sha256_actual: Option<String>,
    model_changed: bool,
    notes: Option<String>,
    artifact_links: Vec<String>,
    checks: Vec<CertSuiteCheckReport>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
struct CertSuiteBucketSummary {
    total: usize,
    passed: usize,
    failed: usize,
    errors: usize,
}

#[derive(Debug, Serialize)]
struct CertSuiteReport {
    schema_version: u32,
    manifest: String,
    solver: String,
    proof_engine: String,
    soundness: String,
    fairness: String,
    entries: Vec<CertSuiteEntryReport>,
    passed: usize,
    failed: usize,
    errors: usize,
    triage: BTreeMap<String, usize>,
    by_family: BTreeMap<String, CertSuiteBucketSummary>,
    by_class: BTreeMap<String, CertSuiteBucketSummary>,
    overall: String,
}

#[derive(Debug, Clone, Copy)]
struct CertSuiteDefaults {
    solver: SolverChoice,
    depth: usize,
    k: usize,
    timeout_secs: u64,
    soundness: SoundnessMode,
    fairness: FairnessMode,
    proof_engine: ProofEngine,
}

#[derive(Debug, Serialize)]
struct LintFix {
    label: String,
    snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    insert_offset: Option<usize>,
}

#[derive(Debug, Serialize, Clone, Copy)]
struct LintSourceSpan {
    start: usize,
    end: usize,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Debug, Serialize)]
struct LintIssue {
    severity: String,
    code: String,
    message: String,
    suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<LintFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_span: Option<LintSourceSpan>,
}

#[derive(Debug, Serialize)]
struct LintReport {
    schema_version: u32,
    file: String,
    soundness: String,
    issues: Vec<LintIssue>,
}

#[derive(Debug, Serialize)]
struct RoundSweepPoint {
    upper_bound: i64,
    result: String,
    details: Value,
}

#[derive(Debug, Serialize)]
struct RoundSweepReport {
    schema_version: u32,
    file: String,
    vars: Vec<String>,
    min_bound: i64,
    max_bound: i64,
    stable_window: usize,
    points: Vec<RoundSweepPoint>,
    candidate_cutoff: Option<i64>,
    stabilized_result: Option<String>,
    note: String,
}

fn parse_soundness_mode(raw: &str) -> SoundnessMode {
    match raw {
        "strict" => SoundnessMode::Strict,
        "permissive" => SoundnessMode::Permissive,
        other => {
            eprintln!("Unknown soundness mode: {other}. Use 'strict' or 'permissive'.");
            std::process::exit(1);
        }
    }
}

fn parse_proof_engine(raw: &str) -> ProofEngine {
    match raw {
        "kinduction" => ProofEngine::KInduction,
        "pdr" => ProofEngine::Pdr,
        other => {
            eprintln!("Unknown proof engine: {other}. Use 'kinduction' or 'pdr'.");
            std::process::exit(1);
        }
    }
}

fn parse_manifest_proof_engine(raw: &str) -> Result<ProofEngine, String> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => Err(format!(
            "Unknown proof_engine '{other}'. Use 'kinduction' or 'pdr'."
        )),
    }
}

fn parse_solver_choice(raw: &str) -> SolverChoice {
    match raw {
        "z3" => SolverChoice::Z3,
        "cvc5" => SolverChoice::Cvc5,
        other => {
            eprintln!("Unknown solver: {other}. Use 'z3' or 'cvc5'.");
            std::process::exit(1);
        }
    }
}

fn parse_analysis_mode(raw: &str) -> AnalysisMode {
    match raw {
        "quick" => AnalysisMode::Quick,
        "standard" => AnalysisMode::Standard,
        "proof" => AnalysisMode::Proof,
        "audit" => AnalysisMode::Audit,
        other => {
            eprintln!("Unknown mode: {other}. Use 'quick', 'standard', 'proof', or 'audit'.");
            std::process::exit(1);
        }
    }
}

fn parse_output_format(raw: &str) -> OutputFormat {
    match raw {
        "text" => OutputFormat::Text,
        "json" => OutputFormat::Json,
        other => {
            eprintln!("Unknown output format: {other}. Use 'text' or 'json'.");
            std::process::exit(1);
        }
    }
}

fn parse_cli_network_semantics_mode(raw: &str) -> CliNetworkSemanticsMode {
    match raw {
        "dsl" => CliNetworkSemanticsMode::Dsl,
        "faithful" => CliNetworkSemanticsMode::Faithful,
        other => {
            eprintln!("Unknown network semantics mode: {other}. Use 'dsl' or 'faithful'.");
            std::process::exit(1);
        }
    }
}

fn cli_network_mode_name(mode: CliNetworkSemanticsMode) -> &'static str {
    match mode {
        CliNetworkSemanticsMode::Dsl => "dsl",
        CliNetworkSemanticsMode::Faithful => "faithful",
    }
}

fn parse_visualize_check(raw: &str) -> VisualizeCheck {
    match raw {
        "verify" => VisualizeCheck::Verify,
        "liveness" => VisualizeCheck::Liveness,
        "fair-liveness" | "fair_liveness" => VisualizeCheck::FairLiveness,
        "prove" => VisualizeCheck::Prove,
        "prove-fair" | "prove_fair" => VisualizeCheck::ProveFair,
        other => {
            eprintln!(
                "Unknown visualize check: {other}. Use 'verify', 'liveness', 'fair-liveness', 'prove', or 'prove-fair'."
            );
            std::process::exit(1);
        }
    }
}

fn visualize_check_name(check: VisualizeCheck) -> &'static str {
    match check {
        VisualizeCheck::Verify => "verify",
        VisualizeCheck::Liveness => "liveness",
        VisualizeCheck::FairLiveness => "fair-liveness",
        VisualizeCheck::Prove => "prove",
        VisualizeCheck::ProveFair => "prove-fair",
    }
}

fn parse_visualize_format(raw: &str) -> VisualizeFormat {
    match raw {
        "timeline" => VisualizeFormat::Timeline,
        "mermaid" => VisualizeFormat::Mermaid,
        "markdown" => VisualizeFormat::Markdown,
        "json" => VisualizeFormat::Json,
        other => {
            eprintln!(
                "Unknown visualize format: {other}. Use 'timeline', 'mermaid', 'markdown', or 'json'."
            );
            std::process::exit(1);
        }
    }
}

fn visualize_format_name(format: VisualizeFormat) -> &'static str {
    match format {
        VisualizeFormat::Timeline => "timeline",
        VisualizeFormat::Mermaid => "mermaid",
        VisualizeFormat::Markdown => "markdown",
        VisualizeFormat::Json => "json",
    }
}

fn parse_fairness_mode(raw: &str) -> FairnessMode {
    match raw {
        "weak" => FairnessMode::Weak,
        "strong" => FairnessMode::Strong,
        other => {
            eprintln!("Unknown fairness mode: {other}. Use 'weak' or 'strong'.");
            std::process::exit(1);
        }
    }
}

fn parse_faithful_fallback_floor(raw: &str) -> Option<FaithfulFallbackFloor> {
    match raw {
        "off" | "none" | "disabled" => None,
        "identity" | "faithful" => Some(FaithfulFallbackFloor::IdentitySelective),
        "classic" => Some(FaithfulFallbackFloor::Classic),
        other => {
            eprintln!(
                "Unknown faithful fallback mode: {other}. Use 'off', 'identity', or 'classic'."
            );
            std::process::exit(1);
        }
    }
}

fn execution_controls_from_cli(cli: &Cli) -> PipelineExecutionControls {
    let faithful_fallback =
        parse_faithful_fallback_floor(&cli.faithful_fallback).map(|floor| FaithfulFallbackConfig {
            max_locations: cli.fallback_max_locations,
            max_shared_vars: cli.fallback_max_shared_vars,
            max_message_counters: cli.fallback_max_message_counters,
            floor,
        });
    PipelineExecutionControls { faithful_fallback }
}

fn automaton_footprint_json(fp: AutomatonFootprint) -> Value {
    json!({
        "locations": fp.locations,
        "rules": fp.rules,
        "shared_vars": fp.shared_vars,
        "message_counters": fp.message_counters,
    })
}

fn run_diagnostics_details(diag: &PipelineRunDiagnostics) -> Value {
    json!({
        "lowerings": diag.lowerings.iter().map(|entry| {
            json!({
                "context": entry.context,
                "requested_network": entry.requested_network,
                "effective_network": entry.effective_network,
                "fault_model": entry.fault_model,
                "authentication": entry.authentication,
                "equivocation": entry.equivocation,
                "delivery_control": entry.delivery_control,
                "fault_budget_scope": entry.fault_budget_scope,
                "identity_roles": entry.identity_roles,
                "process_identity_roles": entry.process_identity_roles,
                "requested_footprint": automaton_footprint_json(entry.requested_footprint),
                "effective_footprint": automaton_footprint_json(entry.effective_footprint),
                "fallback_budget": entry.fallback_budget.map(automaton_footprint_json),
                "budget_satisfied": entry.budget_satisfied,
                "fallback_applied": entry.fallback_applied,
                "fallback_steps": entry.fallback_steps,
                "fallback_exhausted": entry.fallback_exhausted,
                "independent_rule_pairs": entry.independent_rule_pairs,
                "por_stutter_rules_pruned": entry.por_stutter_rules_pruned,
                "por_commutative_duplicate_rules_pruned": entry.por_commutative_duplicate_rules_pruned,
                "por_effective_rule_count": entry.por_effective_rule_count,
                "por_enabled": entry.independent_rule_pairs > 0,
                "network_fallback_state": if entry.fallback_exhausted {
                    "exhausted"
                } else if entry.fallback_applied {
                    "applied"
                } else {
                    "not_applied"
                },
            })
        }).collect::<Vec<_>>(),
        "applied_reductions": diag.applied_reductions.iter().map(|step| {
            json!({
                "context": step.context,
                "kind": step.kind,
                "from": step.from,
                "to": step.to,
                "trigger": step.trigger,
                "before": automaton_footprint_json(step.before),
                "after": automaton_footprint_json(step.after),
            })
        }).collect::<Vec<_>>(),
        "reduction_notes": diag.reduction_notes,
        "phase_profiles": diag.phase_profiles.iter().map(|phase| {
            json!({
                "context": phase.context,
                "phase": phase.phase,
                "elapsed_ms": phase.elapsed_ms,
                "rss_bytes": phase.rss_bytes,
            })
        }).collect::<Vec<_>>(),
        "smt_profiles": diag.smt_profiles.iter().map(|profile| {
            let dedup_rate = if profile.assertion_candidates == 0 {
                0.0
            } else {
                profile.assertion_dedup_hits as f64 / profile.assertion_candidates as f64
            };
            let symmetry_prune_rate = if profile.symmetry_candidates == 0 {
                0.0
            } else {
                profile.symmetry_pruned as f64 / profile.symmetry_candidates as f64
            };
            let symmetry_enabled = profile.symmetry_candidates > 0
                || profile.symmetry_pruned > 0
                || profile.stutter_signature_normalizations > 0;
            let incremental_enabled = profile.incremental_depth_reuse_steps > 0
                || profile.incremental_decl_reuse_hits > 0
                || profile.incremental_assertion_reuse_hits > 0;
            json!({
                "context": profile.context,
                "encode_calls": profile.encode_calls,
                "encode_elapsed_ms": profile.encode_elapsed_ms,
                "solve_calls": profile.solve_calls,
                "solve_elapsed_ms": profile.solve_elapsed_ms,
                "assertion_candidates": profile.assertion_candidates,
                "assertion_unique": profile.assertion_unique,
                "assertion_dedup_hits": profile.assertion_dedup_hits,
                "assertion_dedup_rate": dedup_rate,
                "incremental_depth_reuse_steps": profile.incremental_depth_reuse_steps,
                "incremental_decl_reuse_hits": profile.incremental_decl_reuse_hits,
                "incremental_assertion_reuse_hits": profile.incremental_assertion_reuse_hits,
                "symmetry_candidates": profile.symmetry_candidates,
                "symmetry_pruned": profile.symmetry_pruned,
                "symmetry_prune_rate": symmetry_prune_rate,
                "stutter_signature_normalizations": profile.stutter_signature_normalizations,
                "symmetry_enabled": symmetry_enabled,
                "incremental_enabled": incremental_enabled,
            })
        }).collect::<Vec<_>>(),
    })
}

fn declared_network_mode_in_program(program: &tarsier_dsl::ast::Program) -> &'static str {
    let proto = &program.protocol.node;
    let mode = proto
        .adversary
        .iter()
        .find(|item| item.key == "network" || item.key == "network_semantics")
        .map(|item| item.value.as_str())
        .unwrap_or("classic");
    if matches!(
        mode,
        "identity_selective"
            | "cohort_selective"
            | "process_selective"
            | "faithful"
            | "selective"
            | "selective_delivery"
    ) {
        "faithful"
    } else {
        "classic"
    }
}

fn validate_cli_network_semantics_mode(
    source: &str,
    filename: &str,
    soundness: SoundnessMode,
    mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    if mode == CliNetworkSemanticsMode::Dsl {
        return Ok(());
    }
    if soundness != SoundnessMode::Strict {
        miette::bail!(
            "`--network-semantics faithful` requires `--soundness strict` to avoid permissive fallbacks."
        );
    }
    let program = tarsier_dsl::parse(source, filename).into_diagnostic()?;
    if declared_network_mode_in_program(&program) != "faithful" {
        miette::bail!(
            "`--network-semantics faithful` requires an explicit faithful network in the model \
             (`adversary {{ network: process_selective|cohort_selective|identity_selective; }}`)."
        );
    }

    let lint = lint_protocol_file(source, filename, SoundnessMode::Strict);
    let blocking: Vec<String> = lint
        .issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .map(|issue| format!("{}: {}", issue.code, issue.message))
        .collect();
    if !blocking.is_empty() {
        let rendered = blocking
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n- ");
        miette::bail!(
            "Faithful network validation failed:\n- {}\nFix these strict-mode issues and retry.",
            rendered
        );
    }
    Ok(())
}

fn network_faithfulness_section(
    source: &str,
    filename: &str,
    requested_mode: CliNetworkSemanticsMode,
    soundness: SoundnessMode,
) -> Value {
    match tarsier_engine::pipeline::show_ta(source, filename) {
        Ok(_) => {
            let diagnostics = take_run_diagnostics();
            let lowering = diagnostics
                .lowerings
                .iter()
                .find(|entry| entry.context == "show_ta")
                .or_else(|| diagnostics.lowerings.last());
            if let Some(lowering) = lowering {
                let faithful_effective = lowering.effective_network != "classic";
                let assumptions = vec![
                    format!("fault_model={}", lowering.fault_model),
                    format!("network={}", lowering.effective_network),
                    format!("authentication={}", lowering.authentication),
                    format!("equivocation={}", lowering.equivocation),
                    format!("delivery_control={}", lowering.delivery_control),
                    format!("fault_budget_scope={}", lowering.fault_budget_scope),
                    format!(
                        "process_identity_roles={}/{}",
                        lowering.process_identity_roles, lowering.identity_roles
                    ),
                ];
                let status =
                    if requested_mode == CliNetworkSemanticsMode::Faithful && !faithful_effective {
                        "fail"
                    } else if faithful_effective {
                        "pass"
                    } else {
                        "warn"
                    };
                let summary = if faithful_effective {
                    format!(
                        "Faithful network semantics enforced ({})",
                        lowering.effective_network
                    )
                } else {
                    "Legacy network semantics enforced (classic)".into()
                };
                json!({
                    "status": status,
                    "summary": summary,
                    "requested_mode": cli_network_mode_name(requested_mode),
                    "soundness": soundness_name(soundness),
                    "assumptions_enforced": assumptions,
                    "details": run_diagnostics_details(&diagnostics),
                })
            } else {
                json!({
                    "status": "unknown",
                    "summary": "No lowering diagnostics were produced for network faithfulness.",
                    "requested_mode": cli_network_mode_name(requested_mode),
                    "soundness": soundness_name(soundness),
                    "details": run_diagnostics_details(&diagnostics),
                })
            }
        }
        Err(e) => json!({
            "status": "error",
            "summary": "Failed to lower protocol for network faithfulness report.",
            "requested_mode": cli_network_mode_name(requested_mode),
            "soundness": soundness_name(soundness),
            "error": e.to_string(),
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProveAutoTarget {
    Safety,
    FairLiveness,
}

fn is_safety_property_kind(kind: tarsier_dsl::ast::PropertyKind) -> bool {
    matches!(
        kind,
        tarsier_dsl::ast::PropertyKind::Agreement
            | tarsier_dsl::ast::PropertyKind::Validity
            | tarsier_dsl::ast::PropertyKind::Safety
            | tarsier_dsl::ast::PropertyKind::Invariant
    )
}

fn detect_prove_auto_target(source: &str, filename: &str) -> miette::Result<ProveAutoTarget> {
    let program = tarsier_dsl::parse(source, filename).into_diagnostic()?;
    let has_safety = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind));
    let has_liveness = program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| p.node.kind == tarsier_dsl::ast::PropertyKind::Liveness);

    Ok(if has_liveness && !has_safety {
        ProveAutoTarget::FairLiveness
    } else {
        ProveAutoTarget::Safety
    })
}

fn parse_manifest_fairness_mode(raw: &str) -> Result<FairnessMode, String> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(format!(
            "Unknown fairness '{other}'. Use 'weak' or 'strong'."
        )),
    }
}

fn fairness_name(mode: FairnessMode) -> &'static str {
    match mode {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

fn solver_cmd_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn proof_engine_name(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

fn soundness_name(mode: SoundnessMode) -> &'static str {
    match mode {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

fn certificate_bundle_from_safety(cert: &SafetyProofCertificate) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::SafetyProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: cert.induction_k,
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: None,
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

fn certificate_bundle_from_fair_liveness(
    cert: &FairLivenessProofCertificate,
) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::FairLivenessProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: Some(cert.frame),
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: Some(fairness_name(cert.fairness).to_string()),
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

fn parse_solver_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn has_independent_solver(solvers: &[String], certificate_solver: &str) -> bool {
    solvers.iter().any(|solver| solver != certificate_solver)
}

fn obligations_all_unsat(metadata: &CertificateMetadata) -> bool {
    metadata
        .obligations
        .iter()
        .all(|obligation| obligation.expected == "unsat")
}

fn validate_trusted_check_requirements(
    trusted_check: bool,
    min_solvers: usize,
    solver_cmds: &[String],
    metadata: &CertificateMetadata,
    rederive: bool,
    proof_checker: Option<&PathBuf>,
    allow_unchecked_proofs: bool,
) -> miette::Result<()> {
    if !trusted_check {
        return Ok(());
    }
    if min_solvers < 2 {
        miette::bail!("--trusted-check requires --min-solvers >= 2.");
    }
    if solver_cmds.len() < min_solvers {
        miette::bail!(
            "--trusted-check requires at least {} distinct solvers; got {}.",
            min_solvers,
            solver_cmds.len()
        );
    }
    if metadata.soundness != "strict" {
        miette::bail!(
            "--trusted-check requires certificate soundness=strict, got '{}'.",
            metadata.soundness
        );
    }
    if !rederive {
        miette::bail!(
            "--trusted-check requires --rederive to validate freshly regenerated obligations."
        );
    }
    if !obligations_all_unsat(metadata) {
        miette::bail!(
            "--trusted-check currently supports UNSAT-only obligations; found non-UNSAT expected outcomes."
        );
    }
    if !has_independent_solver(solver_cmds, &metadata.solver_used) {
        miette::bail!(
            "--trusted-check requires at least one solver different from certificate solver_used='{}'.",
            metadata.solver_used
        );
    }
    if proof_checker.is_none() && !allow_unchecked_proofs {
        miette::bail!(
            "--trusted-check requires --proof-checker for independently validated UNSAT proofs. \
             Pass --allow-unchecked-proofs only if you explicitly accept weaker trust."
        );
    }
    Ok(())
}

fn run_external_solver_on_file(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<String> {
    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2").arg(smt_file);
        }
        "cvc5" => {
            cmd.arg("--lang").arg("smt2").arg(smt_file);
        }
        _ => {
            cmd.arg(smt_file);
        }
    }

    let output = cmd.output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver `{solver_cmd}` failed on {}: {}",
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let token = stdout
        .lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("unknown")
        .to_string();
    Ok(token)
}

fn augment_query_for_proof(script: &str, solver_cmd: &str) -> String {
    let mut out = String::new();
    match solver_cmd {
        "z3" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        "cvc5" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        _ => {}
    }
    // The stored obligation already contains check-sat/exit. Remove exit and add get-proof.
    let body = script.replace("(exit)\n", "").replace("(exit)", "");
    out.push_str(&body);
    if !body.contains("(check-sat)") {
        out.push_str("\n(check-sat)\n");
    }
    out.push_str("(get-proof)\n");
    out.push_str("(exit)\n");
    out
}

fn run_external_solver_with_proof(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<(String, String)> {
    let base_script = fs::read_to_string(smt_file).into_diagnostic()?;
    let proof_script = augment_query_for_proof(&base_script, solver_cmd);

    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2").arg("-in");
        }
        "cvc5" => {
            cmd.arg("--lang").arg("smt2").arg("-");
        }
        _ => {
            miette::bail!(
                "Proof extraction for solver '{}' is unsupported; use z3 or cvc5.",
                solver_cmd
            );
        }
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().into_diagnostic()?;
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(proof_script.as_bytes()).into_diagnostic()?;
    }
    let output = child.wait_with_output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver `{solver_cmd}` failed on {} while extracting proofs: {}",
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let token = stdout
        .lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("unknown")
        .to_string();

    Ok((token, stdout))
}

fn proof_object_looks_nontrivial(proof_text: &str) -> bool {
    let non_empty_lines = proof_text.lines().filter(|l| !l.trim().is_empty()).count();
    if non_empty_lines <= 1 {
        return false;
    }
    let lowered = proof_text.to_ascii_lowercase();
    if lowered.contains("error") || lowered.contains("unsupported") {
        return false;
    }
    let mut balance = 0i64;
    for ch in proof_text.chars() {
        match ch {
            '(' => balance += 1,
            ')' => {
                balance -= 1;
                if balance < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    balance == 0 && proof_text.contains('(')
}

fn run_external_proof_checker(
    checker: &std::path::Path,
    solver_cmd: &str,
    smt_file: &std::path::Path,
    proof_file: &std::path::Path,
) -> miette::Result<()> {
    let output = Command::new(checker)
        .arg("--solver")
        .arg(solver_cmd)
        .arg("--smt2")
        .arg(smt_file)
        .arg("--proof")
        .arg(proof_file)
        .output()
        .into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "proof checker `{}` rejected {} with {}: {}",
            checker.display(),
            smt_file.display(),
            proof_file.display(),
            stderr.trim()
        );
    }
    Ok(())
}

fn canonicalize_obligation_smt2(script: &str) -> String {
    let mut set_logic: Option<String> = None;
    let mut preamble = Vec::new();
    let mut declarations = Vec::new();
    let mut assertions = Vec::new();
    let mut has_check_sat = false;
    let mut has_exit = false;

    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("(set-logic ") {
            if set_logic.is_none() {
                set_logic = Some(trimmed.to_string());
            }
            continue;
        }
        if trimmed.starts_with("(declare-const ") {
            declarations.push(trimmed.to_string());
            continue;
        }
        if trimmed.starts_with("(assert ") {
            assertions.push(trimmed.to_string());
            continue;
        }
        if trimmed == "(check-sat)" {
            has_check_sat = true;
            continue;
        }
        if trimmed == "(exit)" {
            has_exit = true;
            continue;
        }
        preamble.push(trimmed.to_string());
    }

    declarations.sort();
    declarations.dedup();
    assertions.sort();
    assertions.dedup();

    let mut out = String::new();
    out.push_str(set_logic.as_deref().unwrap_or("(set-logic QF_LIA)"));
    out.push('\n');
    for line in preamble {
        out.push_str(&line);
        out.push('\n');
    }
    for line in declarations {
        out.push_str(&line);
        out.push('\n');
    }
    for line in assertions {
        out.push_str(&line);
        out.push('\n');
    }
    if has_check_sat || !script.trim().is_empty() {
        out.push_str("(check-sat)\n");
    }
    if has_exit || !script.trim().is_empty() {
        out.push_str("(exit)\n");
    }
    out
}

fn write_certificate_bundle(out: &PathBuf, cert: &CertificateBundleInput) -> miette::Result<()> {
    fs::create_dir_all(out).into_diagnostic()?;
    let metadata_file = out.join("certificate.json");

    let mut obligations = cert.obligations.clone();
    obligations.sort_by(|a, b| a.name.cmp(&b.name).then(a.expected.cmp(&b.expected)));

    let mut obligations_meta = Vec::new();
    for obligation in &obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = out.join(&file_name);
        let canonical_smt2 = canonicalize_obligation_smt2(&obligation.smt2);
        fs::write(&file_path, canonical_smt2).into_diagnostic()?;
        let hash = sha256_hex_file(&file_path).into_diagnostic()?;
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
        });
    }

    let mut committee_bounds = cert.committee_bounds.clone();
    committee_bounds.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: cert.kind.as_str().to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: cert.proof_engine.clone(),
        induction_k: cert.induction_k,
        solver_used: cert.solver_used.clone(),
        soundness: cert.soundness.clone(),
        fairness: cert.fairness.clone(),
        committee_bounds,
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
    let metadata_json = serde_json::to_string_pretty(&metadata).into_diagnostic()?;
    fs::write(&metadata_file, metadata_json).into_diagnostic()?;

    println!("Certificate bundle written to {}", out.display());
    println!("  - {}", metadata_file.display());
    for obligation in &metadata.obligations {
        println!("  - {}", out.join(&obligation.file).display());
    }
    if let Some(k) = metadata.induction_k {
        println!("proof frame/k: {k}");
    }
    if let Some(ref fairness) = metadata.fairness {
        println!("fairness: {fairness}");
    }
    println!("proof engine: {}", metadata.proof_engine);
    println!("To verify independently:");
    println!(
        "  tarsier check-certificate {} --solvers z3,cvc5",
        out.display()
    );

    Ok(())
}

fn parse_solver_choice_checked(raw: &str) -> miette::Result<SolverChoice> {
    match raw {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => miette::bail!("Unknown solver in certificate metadata: {other}"),
    }
}

fn parse_soundness_mode_checked(raw: &str) -> miette::Result<SoundnessMode> {
    match raw {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => miette::bail!("Unknown soundness mode in certificate metadata: {other}"),
    }
}

fn parse_proof_engine_checked(raw: &str) -> miette::Result<ProofEngine> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => miette::bail!("Unknown proof engine in certificate metadata: {other}"),
    }
}

fn parse_fairness_mode_checked(raw: &str) -> miette::Result<FairnessMode> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => miette::bail!("Unknown fairness mode in certificate metadata: {other}"),
    }
}

fn obligation_triplets_from_bundle(
    bundle: &CertificateBundleInput,
) -> Vec<(String, String, String)> {
    let mut out = Vec::with_capacity(bundle.obligations.len());
    for o in &bundle.obligations {
        out.push((
            o.name.clone(),
            o.expected.clone(),
            sha256_hex_bytes(o.smt2.as_bytes()),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn obligation_triplets_from_metadata(
    metadata: &CertificateMetadata,
) -> Vec<(String, String, String)> {
    let mut out = Vec::with_capacity(metadata.obligations.len());
    for o in &metadata.obligations {
        out.push((
            o.name.clone(),
            o.expected.clone(),
            o.sha256.clone().unwrap_or_default(),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn rederive_certificate_bundle_input(
    metadata: &CertificateMetadata,
    timeout_secs: u64,
) -> miette::Result<CertificateBundleInput> {
    let protocol_path = PathBuf::from(&metadata.protocol_file);
    let source = fs::read_to_string(&protocol_path).into_diagnostic()?;
    let solver = parse_solver_choice_checked(&metadata.solver_used)?;
    let soundness = parse_soundness_mode_checked(&metadata.soundness)?;
    let proof_engine = parse_proof_engine_checked(&metadata.proof_engine)?;
    let k = metadata.induction_k.unwrap_or(12);
    let options = PipelineOptions {
        solver,
        max_depth: k,
        timeout_secs,
        dump_smt: None,
        soundness,
        proof_engine,
    };

    match metadata.kind.as_str() {
        "safety_proof" => {
            let cert = tarsier_engine::pipeline::generate_safety_certificate(
                &source,
                &metadata.protocol_file,
                &options,
            )
            .into_diagnostic()?;
            Ok(certificate_bundle_from_safety(&cert))
        }
        "fair_liveness_proof" => {
            let fairness_raw = metadata.fairness.as_ref().ok_or_else(|| {
                miette::miette!("fair_liveness_proof metadata is missing fairness")
            })?;
            let fairness = parse_fairness_mode_checked(fairness_raw)?;
            let cert = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                &source,
                &metadata.protocol_file,
                &options,
                fairness,
            )
            .into_diagnostic()?;
            Ok(certificate_bundle_from_fair_liveness(&cert))
        }
        other => miette::bail!("Unsupported certificate kind for re-derivation: {other}"),
    }
}

fn solver_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn make_options(
    solver: SolverChoice,
    max_depth: usize,
    timeout_secs: u64,
    soundness: SoundnessMode,
) -> PipelineOptions {
    PipelineOptions {
        solver,
        max_depth,
        timeout_secs,
        dump_smt: None,
        soundness,
        proof_engine: ProofEngine::KInduction,
    }
}

fn trace_details(trace: &tarsier_ir::counter_system::Trace) -> Value {
    let deliveries: i64 = trace
        .steps
        .iter()
        .flat_map(|step| step.deliveries.iter())
        .filter(|d| d.kind == tarsier_ir::counter_system::MessageEventKind::Deliver)
        .map(|d| d.count)
        .sum();
    json!({
        "steps": trace.steps.len(),
        "deliveries": deliveries,
        "params": trace.param_values,
    })
}

fn cti_details(cti: &InductionCtiSummary) -> Value {
    json!({
        "k": cti.k,
        "params": cti.params,
        "hypothesis": {
            "locations": cti.hypothesis_locations,
            "shared": cti.hypothesis_shared,
        },
        "violating": {
            "locations": cti.violating_locations,
            "shared": cti.violating_shared,
        },
        "final_step_rules": cti.final_step_rules,
        "violated_condition": cti.violated_condition,
    })
}

fn trace_json(trace: &Trace) -> Value {
    let steps: Vec<Value> = trace
        .steps
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            let deliveries: Vec<Value> = step
                .deliveries
                .iter()
                .map(|delivery| {
                    json!({
                        "kind": format!("{:?}", delivery.kind),
                        "count": delivery.count,
                        "shared_var": delivery.shared_var,
                        "shared_var_name": delivery.shared_var_name,
                        "sender": {
                            "role": delivery.sender.role.clone(),
                            "process": delivery.sender.process.clone(),
                            "key": delivery.sender.key.clone(),
                        },
                        "recipient": {
                            "role": delivery.recipient.role.clone(),
                            "process": delivery.recipient.process.clone(),
                            "key": delivery.recipient.key.clone(),
                        },
                        "payload": {
                            "family": delivery.payload.family.clone(),
                            "fields": delivery.payload.fields.clone(),
                            "variant": delivery.payload.variant.clone(),
                        },
                        "auth": {
                            "authenticated_channel": delivery.auth.authenticated_channel,
                            "signature_key": delivery.auth.signature_key.clone(),
                            "key_owner_role": delivery.auth.key_owner_role.clone(),
                            "key_compromised": delivery.auth.key_compromised,
                            "provenance": format!("{:?}", delivery.auth.provenance),
                        }
                    })
                })
                .collect();
            json!({
                "step": idx + 1,
                "smt_step": step.smt_step,
                "rule_id": step.rule_id,
                "delta": step.delta,
                "deliveries": deliveries,
                "kappa": step.config.kappa,
                "gamma": step.config.gamma,
            })
        })
        .collect();
    json!({
        "params": trace.param_values,
        "initial": {
            "kappa": trace.initial_config.kappa,
            "gamma": trace.initial_config.gamma,
        },
        "steps": steps,
    })
}

fn verification_result_kind(result: &VerificationResult) -> &'static str {
    match result {
        VerificationResult::Safe { .. } => "safe",
        VerificationResult::ProbabilisticallySafe { .. } => "probabilistically_safe",
        VerificationResult::Unsafe { .. } => "unsafe",
        VerificationResult::Unknown { .. } => "unknown",
    }
}

fn verification_result_details(result: &VerificationResult) -> Value {
    match result {
        VerificationResult::Safe { depth_checked } => {
            json!({"depth_checked": depth_checked})
        }
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => json!({
            "depth_checked": depth_checked,
            "failure_probability": failure_probability,
            "committee_count": committee_analyses.len(),
        }),
        VerificationResult::Unsafe { trace } => json!({
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        VerificationResult::Unknown { reason } => {
            json!({"reason": reason})
        }
    }
}

#[derive(Default)]
struct RoundBoundMutationStats {
    matched_targets: usize,
    updated_ranges: usize,
    unbounded_targets: Vec<String>,
}

fn round_name_matches(names: &[String], candidate: &str) -> bool {
    names
        .iter()
        .any(|name| !name.trim().is_empty() && name.trim().eq_ignore_ascii_case(candidate))
}

fn apply_round_upper_bound(
    program: &mut tarsier_dsl::ast::Program,
    vars: &[String],
    new_max: i64,
) -> RoundBoundMutationStats {
    let mut stats = RoundBoundMutationStats::default();
    let proto = &mut program.protocol.node;

    for role in &mut proto.roles {
        for var in &mut role.node.vars {
            if !round_name_matches(vars, &var.name) {
                continue;
            }
            stats.matched_targets += 1;
            match var.range.as_mut() {
                Some(range) => {
                    range.max = new_max;
                    if range.min > range.max {
                        range.min = range.max;
                    }
                    stats.updated_ranges += 1;
                }
                None => {
                    stats
                        .unbounded_targets
                        .push(format!("{}.{}", role.node.name, var.name));
                }
            }
        }
    }

    for msg in &mut proto.messages {
        for field in &mut msg.fields {
            if !round_name_matches(vars, &field.name) {
                continue;
            }
            stats.matched_targets += 1;
            match field.range.as_mut() {
                Some(range) => {
                    range.max = new_max;
                    if range.min > range.max {
                        range.min = range.max;
                    }
                    stats.updated_ranges += 1;
                }
                None => {
                    stats
                        .unbounded_targets
                        .push(format!("{}.{}", msg.name, field.name));
                }
            }
        }
    }

    stats
}

fn detect_round_sweep_cutoff(
    points: &[RoundSweepPoint],
    stable_window: usize,
) -> Option<(i64, String)> {
    if points.is_empty() || stable_window == 0 {
        return None;
    }
    let tail_kind = points.last()?.result.as_str();
    let mut tail_len = 0usize;
    for point in points.iter().rev() {
        if point.result == tail_kind {
            tail_len += 1;
        } else {
            break;
        }
    }
    if tail_len < stable_window {
        return None;
    }
    let cutoff_index = points.len() - tail_len;
    Some((points[cutoff_index].upper_bound, tail_kind.to_string()))
}

fn render_round_sweep_text(report: &RoundSweepReport) -> String {
    let mut out = String::new();
    out.push_str("ROUND SWEEP\n");
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!("Swept vars: {}\n", report.vars.join(", ")));
    out.push_str(&format!(
        "Upper bounds: {}..={}\n",
        report.min_bound, report.max_bound
    ));
    out.push_str(&format!("Convergence window: {}\n", report.stable_window));
    out.push_str("Results:\n");
    for point in &report.points {
        out.push_str(&format!(
            "  - <= {} => {}\n",
            point.upper_bound, point.result
        ));
    }
    match (report.candidate_cutoff, report.stabilized_result.as_deref()) {
        (Some(cutoff), Some(kind)) => {
            out.push_str(&format!(
                "Candidate cutoff: {} (stable suffix result = {}).\n",
                cutoff, kind
            ));
        }
        _ => {
            out.push_str("Candidate cutoff: not detected (increase max bound or window).\n");
        }
    }
    out.push_str(&format!("Note: {}\n", report.note));
    out
}

fn render_prove_round_text(
    file: &str,
    summary: &tarsier_engine::pipeline::RoundAbstractionSummary,
    result: &UnboundedSafetyResult,
) -> String {
    let mut out = String::new();
    out.push_str("ROUND ABSTRACTION PROOF\n");
    out.push_str(&format!("File: {file}\n"));
    out.push_str(&format!(
        "Erased vars: {}\n",
        summary.erased_vars.join(", ")
    ));
    out.push_str(&format!(
        "Locations: {} -> {}\n",
        summary.original_locations, summary.abstract_locations
    ));
    out.push_str(&format!(
        "Shared vars: {} -> {}\n",
        summary.original_shared_vars, summary.abstract_shared_vars
    ));
    out.push_str(&format!(
        "Message counters: {} -> {}\n",
        summary.original_message_counters, summary.abstract_message_counters
    ));
    out.push_str(&format!(
        "Result: {}\n",
        unbounded_safety_result_kind(result)
    ));
    out.push_str(&format!("{result}\n"));
    match result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            out.push_str(
                "Soundness note: SAFE on this abstraction is sound for unbounded rounds (over-approximation).\n",
            );
        }
        UnboundedSafetyResult::Unsafe { .. } => {
            out.push_str(
                "Soundness note: UNSAFE may be spurious under over-approximation; confirm on concrete model.\n",
            );
        }
        _ => {}
    }
    out
}

fn render_prove_fair_round_text(
    file: &str,
    summary: &tarsier_engine::pipeline::RoundAbstractionSummary,
    result: &UnboundedFairLivenessResult,
) -> String {
    let mut out = String::new();
    out.push_str("ROUND ABSTRACTION FAIR-LIVENESS PROOF\n");
    out.push_str(&format!("File: {file}\n"));
    out.push_str(&format!(
        "Erased vars: {}\n",
        summary.erased_vars.join(", ")
    ));
    out.push_str(&format!(
        "Locations: {} -> {}\n",
        summary.original_locations, summary.abstract_locations
    ));
    out.push_str(&format!(
        "Shared vars: {} -> {}\n",
        summary.original_shared_vars, summary.abstract_shared_vars
    ));
    out.push_str(&format!(
        "Message counters: {} -> {}\n",
        summary.original_message_counters, summary.abstract_message_counters
    ));
    out.push_str(&format!("Result: {}\n", unbounded_fair_result_kind(result)));
    out.push_str(&format!("{result}\n"));
    match result {
        UnboundedFairLivenessResult::LiveProved { .. } => {
            out.push_str(
                "Soundness note: LIVE_PROVED on this abstraction is sound for unbounded rounds (over-approximation).\n",
            );
        }
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            out.push_str(
                "Soundness note: FAIR_CYCLE_FOUND may be spurious under over-approximation; confirm on concrete model.\n",
            );
        }
        _ => {}
    }
    out
}

fn cegar_stage_outcome_json(outcome: &CegarStageOutcome) -> Value {
    match outcome {
        CegarStageOutcome::Safe { depth_checked } => {
            json!({"result": "safe", "depth_checked": depth_checked})
        }
        CegarStageOutcome::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_count,
        } => json!({
            "result": "probabilistically_safe",
            "depth_checked": depth_checked,
            "failure_probability": failure_probability,
            "committee_count": committee_count,
        }),
        CegarStageOutcome::Unsafe { trace } => {
            json!({"result": "unsafe", "trace": trace_json(trace)})
        }
        CegarStageOutcome::Unknown { reason } => {
            json!({"result": "unknown", "reason": reason})
        }
    }
}

fn cegar_counterexample_analysis_json(analysis: &CegarCounterexampleAnalysis) -> Value {
    json!({
        "classification": analysis.classification,
        "rationale": analysis.rationale,
    })
}

fn cegar_model_change_json(change: &tarsier_engine::result::CegarModelChange) -> Value {
    json!({
        "category": change.category,
        "target": change.target,
        "before": change.before,
        "after": change.after,
        "predicate": change.predicate,
    })
}

fn cegar_eliminated_trace_json(trace: &tarsier_engine::result::CegarEliminatedTrace) -> Value {
    json!({
        "kind": trace.kind,
        "source_stage": trace.source_stage,
        "eliminated_by": trace.eliminated_by,
        "rationale": trace.rationale,
        "trace": trace_json(&trace.trace),
    })
}

fn cegar_report_details(report: &CegarAuditReport) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    json!({
        "max_refinements": report.max_refinements,
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "final_result": verification_result_kind(&report.final_result),
        "discovered_predicates": report.discovered_predicates,
        "stages": stages,
    })
}

fn cegar_controls_json(controls: &CegarRunControls) -> Value {
    json!({
        "max_refinements": controls.max_refinements,
        "timeout_secs": controls.timeout_secs,
        "solver": controls.solver,
        "proof_engine": controls.proof_engine,
        "fairness": controls.fairness,
    })
}

fn unbounded_safety_cegar_stage_outcome_json(outcome: &UnboundedSafetyCegarStageOutcome) -> Value {
    match outcome {
        UnboundedSafetyCegarStageOutcome::Safe { induction_k } => {
            json!({"result": "safe", "induction_k": induction_k})
        }
        UnboundedSafetyCegarStageOutcome::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_count,
        } => json!({
            "result": "probabilistically_safe",
            "induction_k": induction_k,
            "failure_probability": failure_probability,
            "committee_count": committee_count,
        }),
        UnboundedSafetyCegarStageOutcome::Unsafe { trace } => {
            json!({"result": "unsafe", "trace": trace_json(trace)})
        }
        UnboundedSafetyCegarStageOutcome::NotProved { max_k, cti } => json!({
            "result": "not_proved",
            "max_k": max_k,
            "cti": cti.as_ref().map(cti_details),
        }),
        UnboundedSafetyCegarStageOutcome::Unknown { reason } => {
            json!({"result": "unknown", "reason": reason})
        }
    }
}

fn unbounded_fair_cegar_stage_outcome_json(
    outcome: &UnboundedFairLivenessCegarStageOutcome,
) -> Value {
    match outcome {
        UnboundedFairLivenessCegarStageOutcome::LiveProved { frame } => {
            json!({"result": "live_proved", "frame": frame})
        }
        UnboundedFairLivenessCegarStageOutcome::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => json!({
            "result": "fair_cycle_found",
            "depth": depth,
            "loop_start": loop_start,
            "trace": trace_json(trace),
        }),
        UnboundedFairLivenessCegarStageOutcome::NotProved { max_k } => {
            json!({"result": "not_proved", "max_k": max_k})
        }
        UnboundedFairLivenessCegarStageOutcome::Unknown { reason } => {
            json!({"result": "unknown", "reason": reason})
        }
    }
}

fn unbounded_safety_cegar_report_details(report: &UnboundedSafetyCegarAuditReport) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": unbounded_safety_cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    json!({
        "controls": cegar_controls_json(&report.controls),
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "discovered_predicates": report.discovered_predicates,
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "stages": stages,
        "baseline_result": {
            "result": unbounded_safety_result_kind(&report.baseline_result),
            "details": unbounded_safety_result_details(&report.baseline_result),
            "output": format!("{}", report.baseline_result),
        },
        "final_result": {
            "result": unbounded_safety_result_kind(&report.final_result),
            "details": unbounded_safety_result_details(&report.final_result),
            "output": format!("{}", report.final_result),
        },
    })
}

fn unbounded_fair_cegar_report_details(report: &UnboundedFairLivenessCegarAuditReport) -> Value {
    let stages: Vec<Value> = report
        .stages
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.stage,
                "label": stage.label,
                "refinements": stage.refinements,
                "model_changes": stage.model_changes.iter().map(cegar_model_change_json).collect::<Vec<_>>(),
                "eliminated_traces": stage.eliminated_traces.iter().map(cegar_eliminated_trace_json).collect::<Vec<_>>(),
                "discovered_predicates": stage.discovered_predicates,
                "note": stage.note,
                "outcome": unbounded_fair_cegar_stage_outcome_json(&stage.outcome),
                "counterexample_analysis": stage
                    .counterexample_analysis
                    .as_ref()
                    .map(cegar_counterexample_analysis_json),
            })
        })
        .collect();
    json!({
        "controls": cegar_controls_json(&report.controls),
        "classification": report.classification,
        "termination": {
            "reason": report.termination.reason,
            "iteration_budget": report.termination.iteration_budget,
            "iterations_used": report.termination.iterations_used,
            "timeout_secs": report.termination.timeout_secs,
            "elapsed_ms": report.termination.elapsed_ms,
            "reached_iteration_budget": report.termination.reached_iteration_budget,
            "reached_timeout_budget": report.termination.reached_timeout_budget,
        },
        "discovered_predicates": report.discovered_predicates,
        "counterexample_analysis": report
            .counterexample_analysis
            .as_ref()
            .map(cegar_counterexample_analysis_json),
        "stages": stages,
        "baseline_result": {
            "result": unbounded_fair_result_kind(&report.baseline_result),
            "details": unbounded_fair_result_details(&report.baseline_result),
            "output": format!("{}", report.baseline_result),
        },
        "final_result": {
            "result": unbounded_fair_result_kind(&report.final_result),
            "details": unbounded_fair_result_details(&report.final_result),
            "output": format!("{}", report.final_result),
        },
    })
}

fn write_json_artifact(path: &PathBuf, value: &Value) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(path, serde_json::to_string_pretty(value).into_diagnostic()?).into_diagnostic()?;
    Ok(())
}

fn unbounded_safety_result_kind(result: &UnboundedSafetyResult) -> &'static str {
    match result {
        UnboundedSafetyResult::Safe { .. } => "safe",
        UnboundedSafetyResult::ProbabilisticallySafe { .. } => "probabilistically_safe",
        UnboundedSafetyResult::Unsafe { .. } => "unsafe",
        UnboundedSafetyResult::NotProved { .. } => "not_proved",
        UnboundedSafetyResult::Unknown { .. } => "unknown",
    }
}

fn unbounded_safety_result_details(result: &UnboundedSafetyResult) -> Value {
    match result {
        UnboundedSafetyResult::Safe { induction_k } => json!({
            "induction_k": induction_k,
        }),
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => json!({
            "induction_k": induction_k,
            "failure_probability": failure_probability,
            "committee_count": committee_analyses.len(),
        }),
        UnboundedSafetyResult::Unsafe { trace } => json!({
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        UnboundedSafetyResult::NotProved { max_k, cti } => json!({
            "max_k": max_k,
            "cti": cti.as_ref().map(cti_details),
        }),
        UnboundedSafetyResult::Unknown { reason } => json!({
            "reason": reason,
        }),
    }
}

fn solver_result_json<T>(res: &Result<T, String>, render_ok: impl Fn(&T) -> Value) -> Value {
    match res {
        Ok(v) => json!({"status": "ok", "data": render_ok(v)}),
        Err(e) => json!({"status": "error", "error": e}),
    }
}

fn trace_fingerprint(trace: &Trace) -> String {
    serde_json::to_string(&trace_json(trace))
        .unwrap_or_else(|_| format!("{:?}:{:?}", trace.param_values, trace.steps))
}

fn prefer_trace_a(trace_a: &Trace, trace_b: &Trace) -> bool {
    match trace_a.steps.len().cmp(&trace_b.steps.len()) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => trace_fingerprint(trace_a) <= trace_fingerprint(trace_b),
    }
}

fn portfolio_merge_policy(result_precedence: &[&str], trace_tiebreak: &str) -> Value {
    json!({
        "deterministic": true,
        "result_precedence": result_precedence,
        "trace_tiebreak": trace_tiebreak,
    })
}

fn choose_unsafe_trace(
    a: &VerificationResult,
    b: &VerificationResult,
) -> Option<VerificationResult> {
    match (a, b) {
        (VerificationResult::Unsafe { trace: ta }, VerificationResult::Unsafe { trace: tb }) => {
            if prefer_trace_a(ta, tb) {
                Some(VerificationResult::Unsafe { trace: ta.clone() })
            } else {
                Some(VerificationResult::Unsafe { trace: tb.clone() })
            }
        }
        _ => None,
    }
}

fn merge_portfolio_verify_reports(
    z3: Result<tarsier_engine::result::CegarAuditReport, String>,
    cvc5: Result<tarsier_engine::result::CegarAuditReport, String>,
) -> (VerificationResult, Value) {
    let details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["unsafe", "safe", "probabilistically_safe", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({
            "result": verification_result_kind(&r.final_result),
            "cegar": cegar_report_details(r),
        })),
        "cvc5": solver_result_json(&cvc5, |r| json!({
            "result": verification_result_kind(&r.final_result),
            "cegar": cegar_report_details(r),
        })),
    });

    let final_result = match (&z3, &cvc5) {
        (Ok(z), Ok(c)) => {
            let zr = &z.final_result;
            let cr = &c.final_result;
            if let Some(u) = choose_unsafe_trace(zr, cr) {
                u
            } else {
                match (zr, cr) {
                    (VerificationResult::Safe { .. }, VerificationResult::Safe { .. })
                    | (
                        VerificationResult::Safe { .. },
                        VerificationResult::ProbabilisticallySafe { .. },
                    )
                    | (
                        VerificationResult::ProbabilisticallySafe { .. },
                        VerificationResult::Safe { .. },
                    )
                    | (
                        VerificationResult::ProbabilisticallySafe { .. },
                        VerificationResult::ProbabilisticallySafe { .. },
                    ) => zr.clone(),
                    (
                        VerificationResult::Unknown { reason: rz },
                        VerificationResult::Unknown { reason: rc },
                    ) => VerificationResult::Unknown {
                        reason: format!(
                            "Portfolio: both solvers inconclusive (z3: {rz}; cvc5: {rc})."
                        ),
                    },
                    _ => VerificationResult::Unknown {
                        reason: format!(
                            "Portfolio disagreement (z3: {}, cvc5: {}).",
                            verification_result_kind(zr),
                            verification_result_kind(cr)
                        ),
                    },
                }
            }
        }
        (Ok(z), Err(e)) => VerificationResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3={}, cvc5 error={e}.",
                verification_result_kind(&z.final_result)
            ),
        },
        (Err(e), Ok(c)) => VerificationResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3 error={e}, cvc5={}.",
                verification_result_kind(&c.final_result)
            ),
        },
        (Err(e1), Err(e2)) => VerificationResult::Unknown {
            reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
        },
    };

    (final_result, details)
}

fn merge_portfolio_liveness_results(
    z3: Result<LivenessResult, String>,
    cvc5: Result<LivenessResult, String>,
) -> (LivenessResult, Value) {
    let details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["not_live", "live", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": liveness_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": liveness_result_kind(r), "output": format!("{r}")})),
    });

    let final_result = match (&z3, &cvc5) {
        (Ok(LivenessResult::NotLive { trace: ta }), Ok(LivenessResult::NotLive { trace: tb })) => {
            if prefer_trace_a(ta, tb) {
                LivenessResult::NotLive { trace: ta.clone() }
            } else {
                LivenessResult::NotLive { trace: tb.clone() }
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                LivenessResult::Live { depth_checked: da },
                LivenessResult::Live { depth_checked: db },
            ) => LivenessResult::Live {
                depth_checked: (*da).min(*db),
            },
            (LivenessResult::Unknown { reason: ra }, LivenessResult::Unknown { reason: rb }) => {
                LivenessResult::Unknown {
                    reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
                }
            }
            _ => LivenessResult::Unknown {
                reason: format!(
                    "Portfolio disagreement (z3: {}, cvc5: {}).",
                    liveness_result_kind(a),
                    liveness_result_kind(b)
                ),
            },
        },
        (Ok(a), Err(e)) => LivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3={}, cvc5 error={e}.",
                liveness_result_kind(a)
            ),
        },
        (Err(e), Ok(b)) => LivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3 error={e}, cvc5={}.",
                liveness_result_kind(b)
            ),
        },
        (Err(e1), Err(e2)) => LivenessResult::Unknown {
            reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
        },
    };

    (final_result, details)
}

fn merge_portfolio_prove_results(
    z3: Result<UnboundedSafetyResult, String>,
    cvc5: Result<UnboundedSafetyResult, String>,
) -> (UnboundedSafetyResult, Value) {
    let details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["unsafe", "safe", "probabilistically_safe", "not_proved", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": unbounded_safety_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": unbounded_safety_result_kind(r), "output": format!("{r}")})),
    });

    let final_result = match (&z3, &cvc5) {
        (
            Ok(UnboundedSafetyResult::Unsafe { trace: ta }),
            Ok(UnboundedSafetyResult::Unsafe { trace: tb }),
        ) => {
            if prefer_trace_a(ta, tb) {
                UnboundedSafetyResult::Unsafe { trace: ta.clone() }
            } else {
                UnboundedSafetyResult::Unsafe { trace: tb.clone() }
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (UnboundedSafetyResult::Safe { .. }, UnboundedSafetyResult::Safe { .. })
            | (
                UnboundedSafetyResult::Safe { .. },
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
            )
            | (
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
                UnboundedSafetyResult::Safe { .. },
            )
            | (
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
                UnboundedSafetyResult::ProbabilisticallySafe { .. },
            ) => a.clone(),
            (
                UnboundedSafetyResult::NotProved {
                    max_k: ka,
                    cti: cti_a,
                },
                UnboundedSafetyResult::NotProved {
                    max_k: kb,
                    cti: cti_b,
                },
            ) => UnboundedSafetyResult::NotProved {
                max_k: (*ka).max(*kb),
                cti: match (cti_a, cti_b) {
                    (Some(a), Some(b)) => {
                        if a.k >= b.k {
                            Some(a.clone())
                        } else {
                            Some(b.clone())
                        }
                    }
                    (Some(a), None) => Some(a.clone()),
                    (None, Some(b)) => Some(b.clone()),
                    (None, None) => None,
                },
            },
            (
                UnboundedSafetyResult::Unknown { reason: ra },
                UnboundedSafetyResult::Unknown { reason: rb },
            ) => UnboundedSafetyResult::Unknown {
                reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
            },
            _ => UnboundedSafetyResult::Unknown {
                reason: format!(
                    "Portfolio disagreement (z3: {}, cvc5: {}).",
                    unbounded_safety_result_kind(a),
                    unbounded_safety_result_kind(b)
                ),
            },
        },
        (Ok(a), Err(e)) => UnboundedSafetyResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3={}, cvc5 error={e}.",
                unbounded_safety_result_kind(a)
            ),
        },
        (Err(e), Ok(b)) => UnboundedSafetyResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3 error={e}, cvc5={}.",
                unbounded_safety_result_kind(b)
            ),
        },
        (Err(e1), Err(e2)) => UnboundedSafetyResult::Unknown {
            reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
        },
    };

    (final_result, details)
}

fn unbounded_fair_result_kind(result: &UnboundedFairLivenessResult) -> &'static str {
    match result {
        UnboundedFairLivenessResult::LiveProved { .. } => "live_proved",
        UnboundedFairLivenessResult::FairCycleFound { .. } => "fair_cycle_found",
        UnboundedFairLivenessResult::NotProved { .. } => "not_proved",
        UnboundedFairLivenessResult::Unknown { .. } => "unknown",
    }
}

fn unbounded_fair_result_details(result: &UnboundedFairLivenessResult) -> Value {
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => json!({
            "frame": frame,
        }),
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => json!({
            "depth": depth,
            "loop_start": loop_start,
            "trace_len": trace.steps.len(),
            "trace": trace_json(trace),
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => json!({
            "max_k": max_k,
        }),
        UnboundedFairLivenessResult::Unknown { reason } => json!({
            "reason": reason,
        }),
    }
}

fn merge_portfolio_fair_liveness_results(
    z3: Result<FairLivenessResult, String>,
    cvc5: Result<FairLivenessResult, String>,
) -> (FairLivenessResult, Value) {
    let details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["fair_cycle_found", "no_fair_cycle_up_to", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": fair_liveness_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": fair_liveness_result_kind(r), "output": format!("{r}")})),
    });

    let final_result = match (&z3, &cvc5) {
        (
            Ok(FairLivenessResult::FairCycleFound {
                depth: da,
                loop_start: la,
                trace: ta,
            }),
            Ok(FairLivenessResult::FairCycleFound {
                depth: db,
                loop_start: lb,
                trace: tb,
            }),
        ) => {
            if prefer_trace_a(ta, tb) {
                FairLivenessResult::FairCycleFound {
                    depth: *da,
                    loop_start: *la,
                    trace: ta.clone(),
                }
            } else {
                FairLivenessResult::FairCycleFound {
                    depth: *db,
                    loop_start: *lb,
                    trace: tb.clone(),
                }
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                FairLivenessResult::NoFairCycleUpTo { depth_checked: da },
                FairLivenessResult::NoFairCycleUpTo { depth_checked: db },
            ) => FairLivenessResult::NoFairCycleUpTo {
                depth_checked: (*da).min(*db),
            },
            (
                FairLivenessResult::Unknown { reason: ra },
                FairLivenessResult::Unknown { reason: rb },
            ) => FairLivenessResult::Unknown {
                reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
            },
            _ => FairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio disagreement (z3: {}, cvc5: {}).",
                    fair_liveness_result_kind(a),
                    fair_liveness_result_kind(b)
                ),
            },
        },
        (Ok(a), Err(e)) => FairLivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3={}, cvc5 error={e}.",
                fair_liveness_result_kind(a)
            ),
        },
        (Err(e), Ok(b)) => FairLivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3 error={e}, cvc5={}.",
                fair_liveness_result_kind(b)
            ),
        },
        (Err(e1), Err(e2)) => FairLivenessResult::Unknown {
            reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
        },
    };

    (final_result, details)
}

fn merge_portfolio_prove_fair_results(
    z3: Result<UnboundedFairLivenessResult, String>,
    cvc5: Result<UnboundedFairLivenessResult, String>,
) -> (UnboundedFairLivenessResult, Value) {
    let details = json!({
        "mode": "portfolio",
        "merge_policy": portfolio_merge_policy(
            &["fair_cycle_found", "live_proved", "not_proved", "unknown"],
            "shortest_trace_then_lexicographic",
        ),
        "z3": solver_result_json(&z3, |r| json!({"result": unbounded_fair_result_kind(r), "output": format!("{r}")})),
        "cvc5": solver_result_json(&cvc5, |r| json!({"result": unbounded_fair_result_kind(r), "output": format!("{r}")})),
    });

    let final_result = match (&z3, &cvc5) {
        (
            Ok(UnboundedFairLivenessResult::FairCycleFound {
                depth: da,
                loop_start: la,
                trace: ta,
            }),
            Ok(UnboundedFairLivenessResult::FairCycleFound {
                depth: db,
                loop_start: lb,
                trace: tb,
            }),
        ) => {
            if prefer_trace_a(ta, tb) {
                UnboundedFairLivenessResult::FairCycleFound {
                    depth: *da,
                    loop_start: *la,
                    trace: ta.clone(),
                }
            } else {
                UnboundedFairLivenessResult::FairCycleFound {
                    depth: *db,
                    loop_start: *lb,
                    trace: tb.clone(),
                }
            }
        }
        (Ok(a), Ok(b)) => match (a, b) {
            (
                UnboundedFairLivenessResult::LiveProved { frame: fa },
                UnboundedFairLivenessResult::LiveProved { frame: fb },
            ) => UnboundedFairLivenessResult::LiveProved {
                frame: (*fa).max(*fb),
            },
            (
                UnboundedFairLivenessResult::NotProved { max_k: ka },
                UnboundedFairLivenessResult::NotProved { max_k: kb },
            ) => UnboundedFairLivenessResult::NotProved {
                max_k: (*ka).max(*kb),
            },
            (
                UnboundedFairLivenessResult::Unknown { reason: ra },
                UnboundedFairLivenessResult::Unknown { reason: rb },
            ) => UnboundedFairLivenessResult::Unknown {
                reason: format!("Portfolio: both solvers inconclusive (z3: {ra}; cvc5: {rb})."),
            },
            _ => UnboundedFairLivenessResult::Unknown {
                reason: format!(
                    "Portfolio disagreement (z3: {}, cvc5: {}).",
                    unbounded_fair_result_kind(a),
                    unbounded_fair_result_kind(b)
                ),
            },
        },
        (Ok(a), Err(e)) => UnboundedFairLivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3={}, cvc5 error={e}.",
                unbounded_fair_result_kind(a)
            ),
        },
        (Err(e), Ok(b)) => UnboundedFairLivenessResult::Unknown {
            reason: format!(
                "Portfolio incomplete: z3 error={e}, cvc5={}.",
                unbounded_fair_result_kind(b)
            ),
        },
        (Err(e1), Err(e2)) => UnboundedFairLivenessResult::Unknown {
            reason: format!("Portfolio failed: z3 error={e1}; cvc5 error={e2}."),
        },
    };

    (final_result, details)
}

fn liveness_result_kind(result: &LivenessResult) -> &'static str {
    match result {
        LivenessResult::Live { .. } => "live",
        LivenessResult::NotLive { .. } => "not_live",
        LivenessResult::Unknown { .. } => "unknown",
    }
}

fn fair_liveness_result_kind(result: &FairLivenessResult) -> &'static str {
    match result {
        FairLivenessResult::NoFairCycleUpTo { .. } => "no_fair_cycle_up_to",
        FairLivenessResult::FairCycleFound { .. } => "fair_cycle_found",
        FairLivenessResult::Unknown { .. } => "unknown",
    }
}

fn expected_matches(expected: &str, actual: &str) -> bool {
    expected.trim().eq_ignore_ascii_case(actual.trim())
}

fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

fn classify_cert_suite_check_triage(
    check: &str,
    expected: &str,
    actual: &str,
    class: Option<&str>,
    model_changed: bool,
) -> String {
    if model_changed {
        return "model_change".into();
    }

    fn is_bug_sentinel(check: &str, outcome: &str) -> bool {
        match check {
            "verify" | "prove" => outcome.eq_ignore_ascii_case("unsafe"),
            "liveness" => outcome.eq_ignore_ascii_case("not_live"),
            "fair_liveness" | "prove_fair" => outcome.eq_ignore_ascii_case("fair_cycle_found"),
            _ => false,
        }
    }

    let class = class.unwrap_or("");
    let class_known_bug = class.eq_ignore_ascii_case("known_bug");
    let class_expected_safe = class.eq_ignore_ascii_case("expected_safe");
    let expected_bug = is_bug_sentinel(check, expected);
    let actual_bug = is_bug_sentinel(check, actual);
    let actual_unknown = actual.eq_ignore_ascii_case("unknown");

    // Mismatch that preserves expected benchmark polarity usually indicates manifest drift.
    if class_known_bug && actual_bug {
        return "expected_update".into();
    }
    if class_expected_safe && !actual_bug && !actual_unknown {
        return "expected_update".into();
    }
    if expected_bug == actual_bug
        && !expected.eq_ignore_ascii_case("unknown")
        && !actual.eq_ignore_ascii_case("unknown")
    {
        return "expected_update".into();
    }

    "engine_regression".into()
}

fn classify_cert_suite_entry_triage(entry: &CertSuiteEntryReport) -> Option<String> {
    if entry.status == "pass" {
        return None;
    }
    if !entry.errors.is_empty() {
        return Some(if entry.model_changed {
            "model_change".into()
        } else {
            "engine_regression".into()
        });
    }
    let mut categories: Vec<String> = entry
        .checks
        .iter()
        .filter(|c| c.status == "fail")
        .filter_map(|c| c.triage.clone())
        .collect();
    if categories.is_empty() {
        return Some("engine_regression".into());
    }
    categories.sort();
    categories.dedup();
    if categories.len() == 1 {
        return categories.into_iter().next();
    }
    if categories.iter().any(|c| c == "engine_regression") {
        return Some("engine_regression".into());
    }
    if categories.iter().any(|c| c == "model_change") {
        return Some("model_change".into());
    }
    Some("expected_update".into())
}

fn validate_manifest_expected_result(check: &str, expected: &str) -> Result<(), String> {
    let allowed: &[&str] = match check {
        "verify" => &["safe", "probabilistically_safe", "unsafe", "unknown"],
        "liveness" => &["live", "not_live", "unknown"],
        "fair_liveness" => &["no_fair_cycle_up_to", "fair_cycle_found", "unknown"],
        "prove" => &[
            "safe",
            "probabilistically_safe",
            "unsafe",
            "not_proved",
            "unknown",
        ],
        "prove_fair" => &["live_proved", "fair_cycle_found", "not_proved", "unknown"],
        other => {
            return Err(format!(
                "Unsupported manifest check '{other}' while validating expected outcome."
            ));
        }
    };
    let normalized = expected.trim().to_ascii_lowercase();
    if allowed.iter().any(|candidate| *candidate == normalized) {
        return Ok(());
    }

    Err(format!(
        "Invalid expected outcome '{}' for '{}'. Allowed: {}.",
        expected.trim(),
        check,
        allowed.join(", ")
    ))
}

fn validate_manifest_entry_contract(entry: &CertSuiteEntry, schema_version: u32) -> Vec<String> {
    let mut errors = Vec::new();
    let configured_checks = usize::from(entry.verify.is_some())
        + usize::from(entry.liveness.is_some())
        + usize::from(entry.fair_liveness.is_some())
        + usize::from(entry.prove.is_some())
        + usize::from(entry.prove_fair.is_some());
    if configured_checks == 0 {
        errors.push("Entry has no expected outcomes configured.".into());
    }

    if schema_version >= 2 {
        let has_rationale = entry
            .notes
            .as_deref()
            .map(|notes| !notes.trim().is_empty())
            .unwrap_or(false);
        if !has_rationale {
            errors.push(
                "Schema v2 requires a non-empty 'notes' rationale for each protocol entry.".into(),
            );
        }
        match entry.model_sha256.as_deref().map(str::trim) {
            Some("") | None => errors.push(
                "Schema v2 requires a non-empty 'model_sha256' (hex SHA-256 of the protocol file)."
                    .into(),
            ),
            Some(hash) if !is_valid_sha256_hex(hash) => errors.push(format!(
                "Entry '{}' has invalid model_sha256 '{}'; expected 64 hex chars.",
                entry.file, hash
            )),
            _ => {}
        }

        let variant = entry.variant.as_deref().map(str::trim);
        let variant_group = entry.variant_group.as_deref().map(str::trim);
        match (variant, variant_group) {
            (None, None) | (Some(""), None) | (None, Some("")) => {}
            (Some(""), Some(_)) | (None, Some(_)) => errors.push(format!(
                "Entry '{}' sets 'variant_group' but is missing non-empty 'variant'.",
                entry.file
            )),
            (Some(_), Some("")) | (Some(_), None) => errors.push(format!(
                "Entry '{}' sets 'variant' but is missing non-empty 'variant_group'.",
                entry.file
            )),
            (Some(v), Some(_)) => match v {
                "minimal" | "faithful" => {}
                other => errors.push(format!(
                    "Entry '{}' has invalid variant '{}'. Allowed: minimal, faithful.",
                    entry.file, other
                )),
            },
        }
    }

    for (check, expected) in [
        ("verify", entry.verify.as_deref()),
        ("liveness", entry.liveness.as_deref()),
        ("fair_liveness", entry.fair_liveness.as_deref()),
        ("prove", entry.prove.as_deref()),
        ("prove_fair", entry.prove_fair.as_deref()),
    ] {
        if let Some(expected) = expected {
            if let Err(msg) = validate_manifest_expected_result(check, expected) {
                errors.push(msg);
            }
        }
    }

    errors
}

fn validate_manifest_top_level_contract(manifest: &CertSuiteManifest) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.schema_version != CERT_SUITE_SCHEMA_VERSION {
        errors.push(format!(
            "Unsupported certification manifest schema {} (expected {}). See {}.",
            manifest.schema_version, CERT_SUITE_SCHEMA_VERSION, CERT_SUITE_SCHEMA_DOC_PATH
        ));
    }
    if manifest.entries.is_empty() {
        errors.push("Manifest must contain at least one protocol entry.".into());
    }

    fn has_bug_sentinel_outcome(entry: &CertSuiteEntry) -> bool {
        let is = |value: Option<&str>, expected: &str| {
            value
                .map(|v| v.trim().eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        };
        is(entry.verify.as_deref(), "unsafe")
            || is(entry.prove.as_deref(), "unsafe")
            || is(entry.liveness.as_deref(), "not_live")
            || is(entry.fair_liveness.as_deref(), "fair_cycle_found")
            || is(entry.prove_fair.as_deref(), "fair_cycle_found")
    }

    let mut seen_files: HashSet<String> = HashSet::new();
    let mut known_bug_entries = 0usize;
    let mut variant_groups: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut variant_group_files: BTreeMap<(String, String), String> = BTreeMap::new();
    for entry in &manifest.entries {
        let file = entry.file.trim();
        if file.is_empty() {
            errors.push("Manifest entry has an empty 'file' path.".into());
            continue;
        }
        if !file.ends_with(".trs") {
            errors.push(format!(
                "Manifest entry '{}' must reference a .trs protocol file.",
                entry.file
            ));
        }
        if !seen_files.insert(file.to_string()) {
            errors.push(format!("Duplicate manifest entry for file '{}'.", file));
        }

        if manifest.schema_version >= 2 {
            let family = entry.family.as_deref().map(str::trim).unwrap_or("");
            if family.is_empty() {
                errors.push(format!(
                    "Entry '{}' is missing required 'family' (schema v2).",
                    entry.file
                ));
            }
            match entry.class.as_deref().map(str::trim).unwrap_or("") {
                "expected_safe" | "known_bug" => {}
                "" => errors.push(format!(
                    "Entry '{}' is missing required 'class' (schema v2).",
                    entry.file
                )),
                other => errors.push(format!(
                    "Entry '{}' has invalid class '{}'. Allowed: expected_safe, known_bug.",
                    entry.file, other
                )),
            }
            if entry.class.as_deref() == Some("known_bug") {
                known_bug_entries += 1;
                if !has_bug_sentinel_outcome(entry) {
                    errors.push(format!(
                        "Entry '{}' is class=known_bug but has no bug sentinel expected outcome (unsafe/not_live/fair_cycle_found).",
                        entry.file
                    ));
                }
            }

            let variant = entry.variant.as_deref().map(str::trim).unwrap_or("");
            let variant_group = entry.variant_group.as_deref().map(str::trim).unwrap_or("");
            if !variant.is_empty() && !variant_group.is_empty() {
                variant_groups
                    .entry(variant_group.to_string())
                    .or_default()
                    .insert(variant.to_string());
                let key = (variant_group.to_string(), variant.to_string());
                if let Some(existing) = variant_group_files.insert(key.clone(), entry.file.clone())
                {
                    errors.push(format!(
                        "Variant pair duplicate for group '{}' variant '{}': '{}' and '{}'.",
                        key.0, key.1, existing, entry.file
                    ));
                }
            }
        }
    }
    if manifest.schema_version >= 2 && known_bug_entries == 0 {
        errors.push("Schema v2 manifest must include at least one class=known_bug regression sentinel entry.".into());
    }
    if manifest.schema_version >= 2 {
        for (group, variants) in variant_groups {
            if !variants.contains("minimal") || !variants.contains("faithful") {
                errors.push(format!(
                    "Variant group '{}' must define both minimal and faithful entries.",
                    group
                ));
            }
        }
    }

    errors
}

fn validate_manifest_library_coverage(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_library_coverage {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let library_dir_raw = manifest.library_dir.as_deref().unwrap_or(".");
    let library_dir = {
        let candidate = PathBuf::from(library_dir_raw);
        if candidate.is_absolute() {
            candidate
        } else {
            base_dir.join(candidate)
        }
    };

    if !library_dir.exists() {
        errors.push(format!(
            "Library coverage directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Library coverage path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    let mut on_disk_files: HashSet<String> = HashSet::new();
    let read_dir = match fs::read_dir(&library_dir) {
        Ok(entries) => entries,
        Err(e) => {
            errors.push(format!(
                "Failed reading library directory '{}': {e}",
                library_dir.display()
            ));
            return errors;
        }
    };
    for item in read_dir {
        let item = match item {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!(
                    "Failed listing library directory '{}': {e}",
                    library_dir.display()
                ));
                continue;
            }
        };
        let path = item.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("trs"))
                .unwrap_or(false)
        {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                on_disk_files.insert(name.to_string());
            }
        }
    }

    let manifest_files: HashSet<String> = manifest
        .entries
        .iter()
        .filter_map(|entry| {
            let path = Path::new(entry.file.trim());
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string())
        })
        .collect();

    for missing in on_disk_files.difference(&manifest_files) {
        errors.push(format!(
            "Protocol '{}' exists in '{}' but has no cert-suite expectation entry.",
            missing,
            library_dir.display()
        ));
    }
    for stale in manifest_files.difference(&on_disk_files) {
        errors.push(format!(
            "Manifest contains '{}' but '{}' has no such protocol file.",
            stale,
            library_dir.display()
        ));
    }

    errors
}

fn sanitize_artifact_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '.' || ch == '/' || ch == '\\' || ch.is_whitespace() {
            out.push('_');
        }
    }
    let compact = out.trim_matches('_');
    if compact.is_empty() {
        "entry".to_string()
    } else {
        compact.to_string()
    }
}

fn write_artifact_text(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

fn finalize_cert_suite_entry(
    entry_report: &mut CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    let refresh_status = |report: &mut CertSuiteEntryReport| {
        if !report.errors.is_empty() {
            report.status = "error".into();
        } else if report.checks.iter().any(|c| c.status == "fail") {
            report.status = "fail".into();
        } else {
            report.status = "pass".into();
        }
        report.verdict = report.status.clone();
        report.triage = classify_cert_suite_entry_triage(report);
    };

    entry_report.duration_ms = entry_started.elapsed().as_millis() as u64;
    refresh_status(entry_report);

    if let Some(dir) = entry_artifact_dir {
        let entry_json = match serde_json::to_string_pretty(entry_report) {
            Ok(json) => json,
            Err(e) => {
                entry_report
                    .errors
                    .push(format!("entry artifact serialization failed: {e}"));
                return;
            }
        };
        let summary_path = dir.join("entry.json");
        match write_artifact_text(&summary_path, &entry_json) {
            Ok(()) => entry_report
                .artifact_links
                .push(summary_path.display().to_string()),
            Err(msg) => entry_report
                .errors
                .push(format!("entry artifact write failed: {msg}")),
        }
    }

    refresh_status(entry_report);
}

fn finalize_and_push_cert_suite_entry(
    reports: &mut Vec<CertSuiteEntryReport>,
    passed: &mut usize,
    failed: &mut usize,
    errors: &mut usize,
    mut entry_report: CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    finalize_cert_suite_entry(&mut entry_report, entry_started, entry_artifact_dir);
    match entry_report.status.as_str() {
        "pass" => *passed += 1,
        "fail" => *failed += 1,
        _ => *errors += 1,
    }
    reports.push(entry_report);
}

fn write_check_artifact(
    entry_artifact_dir: Option<&Path>,
    check_name: &str,
    output: &str,
) -> Result<Option<String>, String> {
    let Some(dir) = entry_artifact_dir else {
        return Ok(None);
    };
    let filename = format!("check_{}.txt", sanitize_artifact_component(check_name));
    let artifact_path = dir.join(filename);
    write_artifact_text(&artifact_path, output)?;
    Ok(Some(artifact_path.display().to_string()))
}

fn render_suite_text(report: &CertSuiteReport) -> String {
    let mut out = String::new();
    out.push_str("CERTIFICATION SUITE\n");
    out.push_str(&format!("Manifest: {}\n", report.manifest));
    out.push_str(&format!(
        "Config: solver={}, proof_engine={}, soundness={}, fairness={}\n",
        report.solver, report.proof_engine, report.soundness, report.fairness
    ));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str(&format!(
        "Summary: {} pass, {} fail, {} error\n",
        report.passed, report.failed, report.errors
    ));
    if !report.triage.is_empty() {
        out.push_str("Failure triage:\n");
        for (kind, count) in &report.triage {
            out.push_str(&format!("  - {}: {}\n", kind, count));
        }
    }
    if !report.by_class.is_empty() {
        out.push_str("By class:\n");
        for (class, bucket) in &report.by_class {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                class, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    if !report.by_family.is_empty() {
        out.push_str("By family:\n");
        for (family, bucket) in &report.by_family {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                family, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    out.push_str("Entries:\n");
    for entry in &report.entries {
        let mut tags: Vec<String> = Vec::new();
        if let Some(family) = &entry.family {
            tags.push(format!("family={family}"));
        }
        if let Some(class) = &entry.class {
            tags.push(format!("class={class}"));
        }
        if let Some(variant) = &entry.variant {
            tags.push(format!("variant={variant}"));
        }
        if let Some(group) = &entry.variant_group {
            tags.push(format!("group={group}"));
        }
        let tag_suffix = if tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", tags.join(", "))
        };
        out.push_str(&format!(
            "- [{}] {}{} verdict={} time={}ms\n",
            entry.status.to_uppercase(),
            entry.file,
            tag_suffix,
            entry.verdict,
            entry.duration_ms
        ));
        if let Some(triage) = &entry.triage {
            out.push_str(&format!("    triage: {triage}\n"));
        }
        out.push_str(&format!(
            "    assumptions: solver={} proof_engine={} soundness={} fairness={} network={} depth={} k={} timeout={}s cegar={}\n",
            entry.assumptions.solver,
            entry.assumptions.proof_engine,
            entry.assumptions.soundness,
            entry.assumptions.fairness,
            entry.assumptions.network_semantics,
            entry.assumptions.depth,
            entry.assumptions.k,
            entry.assumptions.timeout_secs,
            entry.assumptions.cegar_iters
        ));
        if let Some(expected_hash) = &entry.model_sha256_expected {
            out.push_str(&format!(
                "    model_sha256: expected={} actual={} changed={}\n",
                expected_hash,
                entry.model_sha256_actual.as_deref().unwrap_or("n/a"),
                entry.model_changed
            ));
        }
        for link in &entry.artifact_links {
            out.push_str(&format!("    artifact: {link}\n"));
        }
        for check in &entry.checks {
            out.push_str(&format!(
                "    {}: expected {}, got {} [{}] ({}ms)\n",
                check.check,
                check.expected,
                check.actual,
                check.status.to_uppercase(),
                check.duration_ms
            ));
            if let Some(triage) = &check.triage {
                out.push_str(&format!("      triage: {triage}\n"));
            }
            if let Some(link) = &check.artifact_link {
                out.push_str(&format!("      artifact: {link}\n"));
            }
        }
        for error in &entry.errors {
            out.push_str(&format!("    error: {error}\n"));
        }
    }
    out
}

fn run_cert_suite(
    manifest_path: &PathBuf,
    defaults: &CertSuiteDefaults,
    network_mode: CliNetworkSemanticsMode,
    artifacts_dir: Option<&Path>,
) -> miette::Result<CertSuiteReport> {
    let manifest_raw = fs::read_to_string(manifest_path).into_diagnostic()?;
    let manifest: CertSuiteManifest = serde_json::from_str(&manifest_raw).into_diagnostic()?;
    let mut manifest_errors = validate_manifest_top_level_contract(&manifest);
    manifest_errors.extend(validate_manifest_library_coverage(&manifest, manifest_path));
    if !manifest_errors.is_empty() {
        miette::bail!(
            "Certification manifest validation failed:\n{}",
            manifest_errors
                .into_iter()
                .map(|msg| format!("  - {msg}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let artifacts_root = artifacts_dir.map(Path::to_path_buf);
    if let Some(dir) = &artifacts_root {
        fs::create_dir_all(dir).into_diagnostic()?;
    }

    let mut reports: Vec<CertSuiteEntryReport> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;

    for (entry_idx, entry) in manifest.entries.into_iter().enumerate() {
        let entry_started = Instant::now();
        let entry_artifact_dir = artifacts_root.as_ref().map(|root| {
            root.join(format!(
                "{:03}_{}",
                entry_idx + 1,
                sanitize_artifact_component(&entry.file)
            ))
        });

        let protocol_path = {
            let p = PathBuf::from(&entry.file);
            if p.is_absolute() {
                p
            } else {
                base_dir.join(p)
            }
        };
        let entry_depth = entry.depth.unwrap_or(defaults.depth);
        let entry_k = entry.k.unwrap_or(defaults.k);
        let entry_timeout = entry.timeout.unwrap_or(defaults.timeout_secs);
        let cegar_iters = entry.cegar_iters.unwrap_or(2);

        let mut entry_report = CertSuiteEntryReport {
            file: protocol_path.display().to_string(),
            family: entry.family.clone(),
            class: entry.class.clone(),
            variant: entry.variant.clone(),
            variant_group: entry.variant_group.clone(),
            verdict: "pending".into(),
            status: "pass".into(),
            triage: None,
            duration_ms: 0,
            assumptions: CertSuiteAssumptions {
                solver: solver_name(defaults.solver).to_string(),
                proof_engine: proof_engine_name(defaults.proof_engine).to_string(),
                soundness: soundness_name(defaults.soundness).to_string(),
                fairness: fairness_name(defaults.fairness).to_string(),
                network_semantics: cli_network_mode_name(network_mode).to_string(),
                depth: entry_depth,
                k: entry_k,
                timeout_secs: entry_timeout,
                cegar_iters,
            },
            model_sha256_expected: entry.model_sha256.clone(),
            model_sha256_actual: None,
            model_changed: false,
            notes: entry.notes.clone(),
            artifact_links: Vec::new(),
            checks: Vec::new(),
            errors: Vec::new(),
        };
        if let Some(dir) = &entry_artifact_dir {
            if let Err(e) = fs::create_dir_all(dir) {
                entry_report.errors.push(format!(
                    "Failed creating artifact directory {}: {e}",
                    dir.display()
                ));
            }
        }

        let contract_errors = validate_manifest_entry_contract(&entry, manifest.schema_version);
        if !contract_errors.is_empty() {
            entry_report.errors.extend(contract_errors);
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                entry_report.errors.push(format!(
                    "Failed reading {}: {}",
                    protocol_path.display(),
                    e
                ));
                finalize_and_push_cert_suite_entry(
                    &mut reports,
                    &mut passed,
                    &mut failed,
                    &mut errors,
                    entry_report,
                    entry_started,
                    entry_artifact_dir.as_deref(),
                );
                continue;
            }
        };
        let model_sha_actual = sha256_hex_bytes(source.as_bytes());
        entry_report.model_sha256_actual = Some(model_sha_actual.clone());
        if let Some(expected_hash) = entry.model_sha256.as_deref() {
            entry_report.model_changed = !expected_hash.eq_ignore_ascii_case(&model_sha_actual);
        }
        let filename = protocol_path.display().to_string();
        if let Err(e) = validate_cli_network_semantics_mode(
            &source,
            &filename,
            defaults.soundness,
            network_mode,
        ) {
            entry_report
                .errors
                .push(format!("network semantics validation failed: {e}"));
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        // Structural guarantee: entries tagged variant=faithful MUST declare
        // faithful network semantics in the model and pass strict-mode lint.
        if entry.variant.as_deref() == Some("faithful") {
            match tarsier_dsl::parse(&source, &filename) {
                Ok(program) => {
                    if declared_network_mode_in_program(&program) != "faithful" {
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but the model does not declare \
                             faithful network semantics (need `adversary {{ network: identity_selective; }}` \
                             or equivalent).",
                            entry.file
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                    let lint = lint_protocol_file(&source, &filename, SoundnessMode::Strict);
                    let blocking: Vec<String> = lint
                        .issues
                        .iter()
                        .filter(|issue| issue.severity == "error")
                        .map(|issue| format!("{}: {}", issue.code, issue.message))
                        .collect();
                    if !blocking.is_empty() {
                        let rendered = blocking
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ");
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but fails strict-mode lint: {}",
                            entry.file, rendered
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                }
                Err(e) => {
                    entry_report.errors.push(format!(
                        "Entry '{}' has variant=faithful but failed to parse for validation: {}",
                        entry.file, e
                    ));
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            }
        }

        let entry_proof_engine = match entry.proof_engine.as_deref() {
            Some(raw) => match parse_manifest_proof_engine(raw) {
                Ok(engine) => engine,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.proof_engine,
        };
        let entry_fairness = match entry.fairness.as_deref() {
            Some(raw) => match parse_manifest_fairness_mode(raw) {
                Ok(mode) => mode,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.fairness,
        };
        entry_report.assumptions = CertSuiteAssumptions {
            solver: solver_name(defaults.solver).to_string(),
            proof_engine: proof_engine_name(entry_proof_engine).to_string(),
            soundness: soundness_name(defaults.soundness).to_string(),
            fairness: fairness_name(entry_fairness).to_string(),
            network_semantics: cli_network_mode_name(network_mode).to_string(),
            depth: entry_depth,
            k: entry_k,
            timeout_secs: entry_timeout,
            cegar_iters,
        };

        let bounded_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_depth,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };
        let proof_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_k,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };

        if let Some(expected) = entry.verify {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::verify_with_cegar_report(
                &source,
                &filename,
                &bounded_options,
                cegar_iters,
            ) {
                Ok(result) => {
                    let actual = verification_result_kind(&result.final_result).to_string();
                    let output = format!("{}", result.final_result);
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "verify",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("verify artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "verify",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "verify".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("verify failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_liveness(&source, &filename, &bounded_options) {
                Ok(result) => {
                    let actual = liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.fair_liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &source,
                &filename,
                &bounded_options,
                entry_fairness,
            ) {
                Ok(result) => {
                    let actual = fair_liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "fair_liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("fair_liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "fair_liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "fair_liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report
                        .errors
                        .push(format!("fair_liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_safety_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_safety(&source, &filename, &proof_options)
            };
            match prove_result {
                Ok(result) => {
                    let actual = unbounded_safety_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link =
                        match write_check_artifact(entry_artifact_dir.as_deref(), "prove", &output)
                        {
                            Ok(link) => link,
                            Err(msg) => {
                                entry_report
                                    .errors
                                    .push(format!("prove artifact write failed: {msg}"));
                                None
                            }
                        };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove_fair {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                )
            };
            match prove_result {
                Ok(result) => {
                    let actual = unbounded_fair_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "prove_fair",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("prove_fair artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove_fair",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove_fair".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove_fair failed: {e}"));
                }
            }
        }
        finalize_and_push_cert_suite_entry(
            &mut reports,
            &mut passed,
            &mut failed,
            &mut errors,
            entry_report,
            entry_started,
            entry_artifact_dir.as_deref(),
        );
    }

    let overall = if errors > 0 || failed > 0 {
        "fail".to_string()
    } else {
        "pass".to_string()
    };

    let mut by_family: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut by_class: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut triage: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &reports {
        if let Some(family) = &entry.family {
            let bucket = by_family.entry(family.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(class) = &entry.class {
            let bucket = by_class.entry(class.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(kind) = &entry.triage {
            *triage.entry(kind.clone()).or_default() += 1;
        }
    }

    Ok(CertSuiteReport {
        schema_version: CERT_SUITE_SCHEMA_VERSION,
        manifest: manifest_path.display().to_string(),
        solver: solver_name(defaults.solver).to_string(),
        proof_engine: proof_engine_name(defaults.proof_engine).to_string(),
        soundness: soundness_name(defaults.soundness).to_string(),
        fairness: fairness_name(defaults.fairness).to_string(),
        entries: reports,
        passed,
        failed,
        errors,
        triage,
        by_family,
        by_class,
        overall,
    })
}

fn guard_has_non_monotone_threshold(guard: &tarsier_dsl::ast::GuardExpr) -> bool {
    use tarsier_dsl::ast::{CmpOp, GuardExpr};
    match guard {
        GuardExpr::Threshold(t) => !matches!(t.op, CmpOp::Ge | CmpOp::Gt),
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            guard_has_non_monotone_threshold(l) || guard_has_non_monotone_threshold(r)
        }
        _ => false,
    }
}

fn guard_uses_distinct_threshold(guard: &tarsier_dsl::ast::GuardExpr) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    match guard {
        GuardExpr::Threshold(t) => t.distinct,
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            guard_uses_distinct_threshold(l) || guard_uses_distinct_threshold(r)
        }
        _ => false,
    }
}

fn collect_distinct_roles_from_guard(guard: &tarsier_dsl::ast::GuardExpr, out: &mut Vec<String>) {
    use tarsier_dsl::ast::GuardExpr;
    match guard {
        GuardExpr::Threshold(t) => {
            if t.distinct {
                if let Some(role) = &t.distinct_role {
                    if !out.contains(role) {
                        out.push(role.clone());
                    }
                }
            }
        }
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            collect_distinct_roles_from_guard(l, out);
            collect_distinct_roles_from_guard(r, out);
        }
        _ => {}
    }
}

fn protocol_uses_thresholds(program: &tarsier_dsl::ast::Program) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase.node.transitions.iter().any(|tr| {
                fn has_threshold(guard: &GuardExpr) -> bool {
                    match guard {
                        GuardExpr::Threshold(_) => true,
                        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
                            has_threshold(l) || has_threshold(r)
                        }
                        _ => false,
                    }
                }
                has_threshold(&tr.node.guard)
            })
        })
    })
}

fn protocol_uses_distinct_thresholds(program: &tarsier_dsl::ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_distinct_threshold(&tr.node.guard))
        })
    })
}

fn protocol_distinct_roles(program: &tarsier_dsl::ast::Program) -> Vec<String> {
    let mut roles = Vec::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_roles_from_guard(&tr.node.guard, &mut roles);
            }
        }
    }
    roles
}

fn faithful_identity_decl_snippet(
    role: &str,
    scope: tarsier_dsl::ast::IdentityScope,
    process_var: Option<&str>,
    key: &str,
) -> String {
    match scope {
        tarsier_dsl::ast::IdentityScope::Role => {
            format!("identity {role}: role key {key};")
        }
        tarsier_dsl::ast::IdentityScope::Process => format!(
            "identity {role}: process({}) key {key};",
            process_var.unwrap_or("pid")
        ),
    }
}

fn suggested_identity_scope_for_network(
    network_mode: &str,
) -> (tarsier_dsl::ast::IdentityScope, Option<&'static str>) {
    if network_mode == "process_selective" {
        (tarsier_dsl::ast::IdentityScope::Process, Some("pid"))
    } else {
        (tarsier_dsl::ast::IdentityScope::Role, None)
    }
}

fn faithful_missing_identity_suggestion(
    missing_roles: &[String],
    network_mode: &str,
) -> Option<String> {
    if missing_roles.is_empty() {
        return None;
    }
    let (scope, process_var) = suggested_identity_scope_for_network(network_mode);
    let mut lines = Vec::new();
    lines.push("Add these identity declarations:".to_string());
    for role in missing_roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

fn faithful_missing_identity_key_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    roles_without_key: &[String],
    network_mode: &str,
) -> Option<String> {
    if roles_without_key.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Add explicit keys to these identity declarations:".to_string());
    for role in roles_without_key {
        let scope = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .map(|id| id.scope)
            .unwrap_or_else(|| suggested_identity_scope_for_network(network_mode).0);
        let process_var = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .and_then(|id| id.process_var.as_deref())
            .or_else(|| suggested_identity_scope_for_network(network_mode).1);
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

fn faithful_missing_process_identity_suggestion(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Use process-scoped identities for these roles:".to_string());
    for role in roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!("  identity {role}: process(pid) key {key};"));
    }
    Some(lines.join("\n"))
}

fn faithful_missing_auth_suggestion(messages: &[String]) -> Option<String> {
    if messages.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Choose one auth strategy for faithful proofs:".to_string());
    lines.push("  Option A: adversary { auth: signed; }".to_string());
    lines.push("  Option B: add per-message channels:".to_string());
    for msg in messages {
        lines.push(format!("    channel {msg}: authenticated;"));
    }
    Some(lines.join("\n"))
}

fn faithful_proof_scaffold_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    network_mode: &str,
) -> String {
    let role_names: std::collections::HashSet<String> =
        proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let identity_roles: std::collections::HashSet<String> =
        proto.identities.iter().map(|id| id.role.clone()).collect();
    let mut missing_identity_roles: Vec<String> =
        role_names.difference(&identity_roles).cloned().collect();
    missing_identity_roles.sort();
    let channel_covered: std::collections::HashSet<String> =
        proto.channels.iter().map(|c| c.message.clone()).collect();
    let mut missing_auth_messages: Vec<String> = proto
        .messages
        .iter()
        .map(|m| m.name.clone())
        .filter(|m| !channel_covered.contains(m))
        .collect();
    missing_auth_messages.sort();
    let mut lines = Vec::new();
    lines.push("Use faithful-proof baseline:".to_string());
    lines.push("  adversary { network: process_selective; auth: signed; }".to_string());
    if let Some(s) =
        faithful_missing_identity_suggestion(&missing_identity_roles, "process_selective")
    {
        lines.push(s);
    }
    if let Some(s) = faithful_missing_auth_suggestion(&missing_auth_messages) {
        lines.push(s);
    }
    if lines.len() == 1 {
        lines.push(format!(
            "  (network currently `{network_mode}`; add the adversary line above to switch to faithful semantics)"
        ));
    }
    lines.join("\n")
}

fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let clamped = offset.min(source.len());
    for (idx, ch) in source.char_indices() {
        if idx >= clamped {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn lint_source_span(source: &str, span: DslSpan) -> LintSourceSpan {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len()).max(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let (end_line, end_column) = byte_offset_to_line_col(source, end);
    LintSourceSpan {
        start,
        end,
        line,
        column,
        end_line,
        end_column,
    }
}

fn lint_issue(
    source: &str,
    severity: &str,
    code: impl Into<String>,
    message: impl Into<String>,
    suggestion: Option<String>,
    fix: Option<LintFix>,
    span: Option<DslSpan>,
) -> LintIssue {
    LintIssue {
        severity: severity.into(),
        code: code.into(),
        message: message.into(),
        suggestion,
        fix,
        source_span: span.map(|s| lint_source_span(source, s)),
    }
}

fn lint_protocol_file(source: &str, filename: &str, soundness: SoundnessMode) -> LintReport {
    let mut issues: Vec<LintIssue> = Vec::new();
    let (program, parse_diags) = match tarsier_dsl::parse_with_diagnostics(source, filename) {
        Ok(p) => p,
        Err(e) => {
            issues.push(lint_issue(
                source,
                "error",
                "parse_error",
                e.to_string(),
                None,
                None,
                None,
            ));
            return LintReport {
                schema_version: 1,
                file: filename.to_string(),
                soundness: soundness_name(soundness).to_string(),
                issues,
            };
        }
    };
    for diag in parse_diags {
        issues.push(lint_issue(
            source,
            "warn",
            diag.code,
            diag.message,
            diag.suggestion,
            None,
            diag.span,
        ));
    }

    let proto = &program.protocol.node;
    let protocol_span = Some(program.protocol.span);
    let has_n = proto.parameters.iter().any(|p| p.name == "n");
    let has_t = proto.parameters.iter().any(|p| p.name == "t");
    let adversary_item_span = |key: &str| -> Option<DslSpan> {
        proto
            .adversary
            .iter()
            .find(|i| i.key == key)
            .map(|i| i.span)
    };
    if !has_n {
        issues.push(lint_issue(
            source,
            "error",
            "missing_n_param",
            "Missing required parameter `n`.",
            Some("Add `params n, ...;`.".into()),
            None,
            protocol_span,
        ));
    }
    if !has_t {
        issues.push(lint_issue(
            source,
            "warn",
            "missing_t_param",
            "Parameter `t` is missing; many BFT resilience checks assume it.",
            Some("Add `t` or explain resilience with explicit bounds.".into()),
            None,
            protocol_span,
        ));
    }
    if proto.resilience.is_none() {
        let insert_offset = proto.parameters.last().map(|p| p.span.end);
        issues.push(lint_issue(
            source,
            "error",
            "missing_resilience",
            "Missing resilience declaration.",
            Some("Add `resilience: n = 3*f+1;` (or protocol-specific bound).".into()),
            Some(LintFix {
                label: "insert resilience".into(),
                snippet: "\n    resilience: n = 3*f + 1;".into(),
                insert_offset,
            }),
            protocol_span,
        ));
    }

    let safety_props = proto
        .properties
        .iter()
        .filter(|p| {
            matches!(
                p.node.kind,
                tarsier_dsl::ast::PropertyKind::Agreement
                    | tarsier_dsl::ast::PropertyKind::Safety
                    | tarsier_dsl::ast::PropertyKind::Invariant
                    | tarsier_dsl::ast::PropertyKind::Validity
            )
        })
        .count();
    if safety_props == 0 {
        // Insert before the closing } of the protocol
        let insert_offset = Some(program.protocol.span.end.saturating_sub(1));
        issues.push(lint_issue(
            source,
            "error",
            "missing_safety_property",
            "No safety property found.",
            Some("Declare one `property ...: safety|agreement|invariant|validity { ... }`.".into()),
            Some(LintFix {
                label: "insert safety property".into(),
                snippet:
                    "\n    property safety_inv: safety { forall p: Role. p.decided == false }\n"
                        .into(),
                insert_offset,
            }),
            protocol_span,
        ));
    } else if safety_props > 1 {
        issues.push(lint_issue(
            source,
            "warn",
            "multiple_safety_properties",
            "Multiple safety properties found; current verify path expects one primary safety objective.",
            Some("Split checks or keep one canonical safety property for CI.".into()),
            None,
            proto.properties.first().map(|p| p.span).or(protocol_span),
        ));
    }

    for role in &proto.roles {
        for var in &role.node.vars {
            if matches!(
                var.ty,
                tarsier_dsl::ast::VarType::Nat | tarsier_dsl::ast::VarType::Int
            ) && var.range.is_none()
            {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "unbounded_local_int",
                    format!(
                        "Unbounded local numeric variable '{}.{}'.",
                        role.node.name, var.name
                    ),
                    Some("Add `in a..b` bounds to keep abstraction finite.".into()),
                    Some(LintFix {
                        label: "append range bound".into(),
                        snippet: " in 0..N".into(),
                        insert_offset: Some(var.span.end),
                    }),
                    Some(var.span),
                ));
            }
        }
    }

    for msg in &proto.messages {
        for field in &msg.fields {
            if (field.ty == "nat" || field.ty == "int") && field.range.is_none() {
                issues.push(lint_issue(
                    source,
                    "warn",
                    "unbounded_message_field",
                    format!(
                        "Unbounded numeric message field '{}.{}'.",
                        msg.name, field.name
                    ),
                    Some("Add `in a..b` or use `adversary { values: sign; }` abstraction.".into()),
                    None,
                    Some(msg.span),
                ));
            }
        }
    }

    let uses_thresholds = protocol_uses_thresholds(&program);
    let uses_distinct_thresholds = protocol_uses_distinct_thresholds(&program);
    let mut adv_model: Option<&str> = None;
    let mut adv_bound = false;
    let mut timing_partial = false;
    let mut gst = false;
    let mut equivocation: &str = "full";
    let mut auth_mode: &str = "none";
    let mut has_auth_field = false;
    let mut network_mode: &str = "classic";
    for item in &proto.adversary {
        match item.key.as_str() {
            "model" => adv_model = Some(item.value.as_str()),
            "bound" => adv_bound = true,
            "timing" if item.value == "partial_synchrony" || item.value == "partial_sync" => {
                timing_partial = true
            }
            "gst" => gst = true,
            "equivocation" => equivocation = item.value.as_str(),
            "auth" | "authentication" => {
                auth_mode = item.value.as_str();
                has_auth_field = true;
            }
            "network" => network_mode = item.value.as_str(),
            _ => {}
        }
    }

    if uses_thresholds && !adv_bound {
        issues.push(lint_issue(
            source,
            "error",
            "missing_adversary_bound",
            "Threshold guards present but adversary bound is missing.",
            Some("Add `adversary { bound: f; }`.".into()),
            None,
            adversary_item_span("model").or(protocol_span),
        ));
    }
    if timing_partial && !gst {
        issues.push(lint_issue(
            source,
            "error",
            "missing_gst",
            "Partial synchrony configured without GST parameter.",
            Some("Add `adversary { gst: gst; }` and declare `gst` parameter.".into()),
            None,
            adversary_item_span("timing")
                .or(adversary_item_span("gst"))
                .or(protocol_span),
        ));
    }
    if adv_model == Some("byzantine")
        && equivocation != "none"
        && proto.roles.iter().any(|role| {
            role.node.phases.iter().any(|phase| {
                phase
                    .node
                    .transitions
                    .iter()
                    .any(|tr| guard_has_non_monotone_threshold(&tr.node.guard))
            })
        })
    {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "non_monotone_threshold_full_equivocation",
            "Non-monotone threshold guard with Byzantine full equivocation can introduce unsoundness.",
            Some("Use monotone `>=`/`>` threshold guards or set `equivocation: none`.".into()),
            None,
            adversary_item_span("equivocation")
                .or(adversary_item_span("model"))
                .or(protocol_span),
        ));
    }
    if uses_distinct_thresholds && auth_mode != "signed" {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "distinct_requires_signed_auth",
            "Distinct-sender thresholds are modeled soundly only with authenticated sender identities.",
            Some("Add `adversary { auth: signed; }`.".into()),
            None,
            adversary_item_span("auth")
                .or(adversary_item_span("authentication"))
                .or(protocol_span),
        ));
    }
    let faithful_network = matches!(
        network_mode,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if faithful_network {
        let role_names: std::collections::HashSet<String> =
            proto.roles.iter().map(|r| r.node.name.clone()).collect();
        let identity_roles: std::collections::HashSet<String> =
            proto.identities.iter().map(|id| id.role.clone()).collect();
        let mut missing_identity_roles: Vec<String> =
            role_names.difference(&identity_roles).cloned().collect();
        missing_identity_roles.sort();
        if !missing_identity_roles.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_identity_declarations",
                format!(
                    "Faithful network mode is missing explicit `identity` declarations for roles: {}.",
                    missing_identity_roles.join(", ")
                ),
                faithful_missing_identity_suggestion(&missing_identity_roles, network_mode),
                None,
                adversary_item_span("network").or(protocol_span),
            ));
        }
        let mut identities_without_key: Vec<String> = proto
            .identities
            .iter()
            .filter(|id| id.key.is_none())
            .map(|id| id.role.clone())
            .collect();
        identities_without_key.sort();
        identities_without_key.dedup();
        if !identities_without_key.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_identity_keys",
                format!(
                    "Faithful network mode should pin explicit key namespaces for roles: {}.",
                    identities_without_key.join(", ")
                ),
                faithful_missing_identity_key_suggestion(
                    proto,
                    &identities_without_key,
                    network_mode,
                ),
                None,
                proto.identities.first().map(|id| id.span).or(protocol_span),
            ));
        }
        if network_mode == "process_selective" {
            let mut non_process_roles: Vec<String> = proto
                .identities
                .iter()
                .filter(|id| id.scope != tarsier_dsl::ast::IdentityScope::Process)
                .map(|id| id.role.clone())
                .collect();
            non_process_roles.sort();
            non_process_roles.dedup();
            if !non_process_roles.is_empty() {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "process_selective_requires_process_identity",
                    format!(
                        "`network: process_selective` requires process-scoped identities; found non-process identities for: {}.",
                        non_process_roles.join(", ")
                    ),
                    faithful_missing_process_identity_suggestion(&non_process_roles),
                    None,
                    adversary_item_span("network").or(protocol_span),
                ));
            }
        }
        let channel_covered: std::collections::HashSet<String> =
            proto.channels.iter().map(|c| c.message.clone()).collect();
        let mut missing_auth_messages: Vec<String> = proto
            .messages
            .iter()
            .map(|m| m.name.clone())
            .filter(|m| !channel_covered.contains(m))
            .collect();
        missing_auth_messages.sort();
        if !has_auth_field && !missing_auth_messages.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_auth_semantics",
                format!(
                    "Faithful network mode has no explicit global auth and missing per-message channel auth for: {}.",
                    missing_auth_messages.join(", ")
                ),
                faithful_missing_auth_suggestion(&missing_auth_messages),
                None,
                adversary_item_span("auth")
                    .or(adversary_item_span("authentication"))
                    .or(adversary_item_span("network"))
                    .or(protocol_span),
            ));
        }
    }
    if adv_model == Some("byzantine")
        && network_mode != "identity_selective"
        && network_mode != "cohort_selective"
        && network_mode != "process_selective"
    {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "byzantine_network_not_identity_selective",
            "Byzantine model is using legacy `network: classic`; recipient channels remain weakly coupled and may introduce spuriousness.",
            Some(faithful_proof_scaffold_suggestion(proto, network_mode)),
            None,
            adversary_item_span("network").or(adversary_item_span("model")).or(protocol_span),
        ));
    }
    if uses_distinct_thresholds && proto.roles.len() > 1 {
        for role_name in protocol_distinct_roles(&program) {
            let param_name = format!("n_{}", role_name.to_lowercase());
            if !proto.parameters.iter().any(|p| p.name == param_name) {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "distinct_role_missing_population_param",
                    format!(
                        "Distinct sender domain role `{role_name}` is missing population parameter `{param_name}`."
                    ),
                    Some(format!(
                        "Add `params {param_name};` (or avoid role-scoped distinct counting)."
                    )),
                    None,
                    protocol_span,
                ));
            }
        }
    }

    if !proto.committees.is_empty() {
        let has_bound_param = proto.committees.iter().any(|c| {
            c.items
                .iter()
                .any(|i| i.key == "bound_param" || i.key == "bound")
        });
        if !has_bound_param {
            issues.push(lint_issue(
                source,
                "warn",
                "committee_missing_bound_param",
                "Committee analysis exists but no `bound_param` is configured.",
                Some("Set `committee ... { bound_param: f; }` to enforce SMT bounds.".into()),
                None,
                proto.committees.first().map(|c| c.span),
            ));
        }
    }

    if !proto
        .properties
        .iter()
        .any(|p| p.node.kind == tarsier_dsl::ast::PropertyKind::Liveness)
    {
        issues.push(lint_issue(
            source,
            "info",
            "missing_liveness_property",
            "No explicit liveness property; tool will fall back to `decided == true` target.",
            Some("Add `property live: liveness { forall p: Role. ... }`.".into()),
            None,
            protocol_span,
        ));
    }

    if proto.pacemaker.is_none() {
        issues.push(lint_issue(
            source,
            "info",
            "missing_pacemaker",
            "No pacemaker/view-change helper declared.",
            Some("Consider `pacemaker { ... }` for protocols with explicit views.".into()),
            None,
            protocol_span,
        ));
    }

    LintReport {
        schema_version: 1,
        file: filename.to_string(),
        soundness: soundness_name(soundness).to_string(),
        issues,
    }
}

fn render_lint_text(report: &LintReport) -> String {
    let mut out = String::new();
    let errors = report
        .issues
        .iter()
        .filter(|i| i.severity == "error")
        .count();
    let warns = report
        .issues
        .iter()
        .filter(|i| i.severity == "warn")
        .count();
    let infos = report
        .issues
        .iter()
        .filter(|i| i.severity == "info")
        .count();
    out.push_str("LINT REPORT\n");
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!(
        "Summary: {} error(s), {} warning(s), {} info\n",
        errors, warns, infos
    ));
    for issue in &report.issues {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            issue.severity.to_uppercase(),
            issue.code,
            issue.message
        ));
        if let Some(span) = issue.source_span {
            out.push_str(&format!(
                "    span: {}:{} -> {}:{} (bytes {}..{})\n",
                span.line, span.column, span.end_line, span.end_column, span.start, span.end
            ));
        }
        if let Some(suggestion) = &issue.suggestion {
            out.push_str(&format!("    suggestion: {suggestion}\n"));
        }
        if let Some(fix) = &issue.fix {
            out.push_str(&format!(
                "    fix ({}): {}\n",
                fix.label,
                fix.snippet.replace('\n', "\n      ")
            ));
        }
    }
    out
}

#[derive(Default)]
struct DebugFilter {
    sender_role: Option<String>,
    recipient_role: Option<String>,
    message_family: Option<String>,
    kind: Option<String>,
    payload_variant: Option<String>,
    payload_field: Option<(String, String)>,
}

impl DebugFilter {
    fn matches(&self, d: &tarsier_ir::counter_system::MessageDeliveryEvent) -> bool {
        if let Some(ref role) = self.sender_role {
            if !d.sender.role.eq_ignore_ascii_case(role) {
                return false;
            }
        }
        if let Some(ref role) = self.recipient_role {
            if !d.recipient.role.eq_ignore_ascii_case(role) {
                return false;
            }
        }
        if let Some(ref family) = self.message_family {
            if !d.payload.family.eq_ignore_ascii_case(family) {
                return false;
            }
        }
        if let Some(ref kind) = self.kind {
            let kind_str = format!("{:?}", d.kind);
            if !kind_str.eq_ignore_ascii_case(kind) {
                return false;
            }
        }
        if let Some(ref variant) = self.payload_variant {
            if !d
                .payload
                .variant
                .to_ascii_lowercase()
                .contains(&variant.to_ascii_lowercase())
            {
                return false;
            }
        }
        if let Some((ref key, ref value)) = self.payload_field {
            let has_match = d
                .payload
                .fields
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.eq_ignore_ascii_case(value));
            if !has_match {
                return false;
            }
        }
        true
    }

    fn is_active(&self) -> bool {
        self.sender_role.is_some()
            || self.recipient_role.is_some()
            || self.message_family.is_some()
            || self.kind.is_some()
            || self.payload_variant.is_some()
            || self.payload_field.is_some()
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref v) = self.sender_role {
            parts.push(format!("sender={v}"));
        }
        if let Some(ref v) = self.recipient_role {
            parts.push(format!("recipient={v}"));
        }
        if let Some(ref v) = self.message_family {
            parts.push(format!("message={v}"));
        }
        if let Some(ref v) = self.kind {
            parts.push(format!("kind={v}"));
        }
        if let Some(ref v) = self.payload_variant {
            parts.push(format!("variant~={v}"));
        }
        if let Some((ref key, ref value)) = self.payload_field {
            parts.push(format!("field:{key}={value}"));
        }
        if parts.is_empty() {
            "(none)".into()
        } else {
            parts.join(", ")
        }
    }
}

fn parse_counter_metadata_for_crypto(
    counter_name: &str,
) -> Option<(String, String, Option<String>, Vec<(String, String)>)> {
    let stripped = counter_name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped
        .split_once('@')
        .map(|(f, r)| (f, r))
        .unwrap_or((stripped, "*"));
    let channel = recipient_part
        .split_once('[')
        .map(|(recipient, _)| recipient)
        .unwrap_or(recipient_part);
    let (recipient_channel, sender_channel) = channel
        .split_once("<-")
        .map(|(recipient, sender)| (recipient.to_string(), Some(sender.to_string())))
        .unwrap_or_else(|| (channel.to_string(), None));
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    let fields: Vec<(String, String)> = stripped
        .split_once('[')
        .and_then(|(_, rest)| rest.strip_suffix(']'))
        .map(|field_blob| {
            field_blob
                .split(',')
                .filter_map(|entry| {
                    let (k, v) = entry.split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Some((family, recipient_channel, sender_channel, fields))
}

fn sender_role_from_channel(sender_channel: Option<&str>) -> Option<&str> {
    sender_channel.map(|sender| {
        sender
            .split_once('#')
            .map(|(role, _)| role)
            .unwrap_or(sender)
    })
}

fn eval_threshold_lc(
    lc: &tarsier_ir::threshold_automaton::LinearCombination,
    params: &[i64],
) -> i64 {
    let mut value = lc.constant;
    for (coeff, pid) in &lc.terms {
        value += coeff * params.get(*pid).copied().unwrap_or(0);
    }
    value
}

fn crypto_replay_summary(
    ta: &ThresholdAutomaton,
    pre_config: &tarsier_ir::counter_system::Configuration,
    delivery: &tarsier_ir::counter_system::MessageDeliveryEvent,
) -> Option<String> {
    let spec = ta.crypto_objects.get(&delivery.payload.family)?;
    let recipient_channel = delivery
        .recipient
        .process
        .as_ref()
        .map(|pid| format!("{}#{pid}", delivery.recipient.role))
        .unwrap_or_else(|| delivery.recipient.role.clone());
    let mut witness_vars = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != tarsier_ir::threshold_automaton::SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient, sender_channel, fields)) =
            parse_counter_metadata_for_crypto(&shared.name)
        else {
            continue;
        };
        if family != spec.source_message || recipient != recipient_channel {
            continue;
        }
        if fields != delivery.payload.fields {
            continue;
        }
        if let Some(expected_role) = spec.signer_role.as_deref() {
            if sender_role_from_channel(sender_channel.as_deref()) != Some(expected_role) {
                continue;
            }
        }
        witness_vars.push(var_id);
    }
    let observed = witness_vars
        .iter()
        .filter(|var_id| pre_config.gamma.get(**var_id).copied().unwrap_or(0) > 0)
        .count() as i64;
    let required = eval_threshold_lc(&spec.threshold, &pre_config.params);
    Some(format!(
        "crypto={} source={} signer={} threshold={} observed_distinct={} required={} conflicts={}",
        spec.kind,
        spec.source_message,
        spec.signer_role.as_deref().unwrap_or("-"),
        spec.threshold,
        observed,
        required,
        spec.conflict_policy
    ))
}

fn print_replay_state(
    trace: &Trace,
    index: usize,
    loop_start: Option<usize>,
    ta: Option<&ThresholdAutomaton>,
    filter: &DebugFilter,
) {
    println!("----------------------------------------");
    println!("Counterexample Replay");
    if index == 0 {
        println!("Step 0 (initial)");
        if let Some(ta) = ta {
            print!("{}", config_snapshot(&trace.initial_config, ta));
        } else {
            println!("kappa: {:?}", trace.initial_config.kappa);
            println!("gamma: {:?}", trace.initial_config.gamma);
        }
    } else {
        let step = &trace.steps[index - 1];
        let pre_config = if index == 1 {
            &trace.initial_config
        } else {
            &trace.steps[index - 2].config
        };
        println!(
            "Step {}: rule r{} (delta={})",
            index, step.rule_id, step.delta
        );
        if step.deliveries.is_empty() {
            println!("deliveries: (none)");
        } else {
            let matching: Vec<_> = step
                .deliveries
                .iter()
                .filter(|d| filter.matches(d))
                .collect();
            let hidden = step.deliveries.len() - matching.len();
            if matching.is_empty() && hidden > 0 {
                println!("deliveries: ({hidden} hidden by filter)");
            } else {
                println!("deliveries:");
                for d in &matching {
                    println!(
                        "  - kind={:?} sender={}#{} recipient={}#{} value={} fields={} auth={} provenance={:?}",
                        d.kind,
                        d.sender.role,
                        d.sender.process.as_deref().unwrap_or("-"),
                        d.recipient.role,
                        d.recipient.process.as_deref().unwrap_or("-"),
                        d.payload.family,
                        if d.payload.fields.is_empty() {
                            "(none)".into()
                        } else {
                            d.payload
                                .fields
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        },
                        if d.auth.authenticated_channel {
                            "authenticated"
                        } else {
                            "unauthenticated"
                        },
                        d.auth.provenance
                    );
                    if let Some(ta) = ta {
                        if let Some(summary) = crypto_replay_summary(ta, pre_config, d) {
                            println!("    {summary}");
                        }
                    }
                }
                if hidden > 0 {
                    println!("  ({hidden} deliveries hidden by filter)");
                }
            }
        }
        if let Some(ta) = ta {
            print!("{}", config_snapshot(&step.config, ta));
        } else {
            println!("kappa: {:?}", step.config.kappa);
            println!("gamma: {:?}", step.config.gamma);
        }
    }
    if let Some(ls) = loop_start {
        println!("Lasso loop starts at step {ls}");
    }
    if filter.is_active() {
        println!("Active filters: {}", filter.summary());
    }
    println!(
        "Use: n (next), p (prev), j <k>, fs/fr/fm/fk/fv/ff/fc/fl (filter), h (help), q (quit)"
    );
}

fn run_trace_debugger(
    trace: &Trace,
    loop_start: Option<usize>,
    ta: Option<&ThresholdAutomaton>,
) -> miette::Result<()> {
    use std::io::{self, Write};
    let mut index = 0usize;
    let max_index = trace.steps.len();
    let mut filter = DebugFilter::default();
    print_replay_state(trace, index, loop_start, ta, &filter);

    loop {
        print!("debug> ");
        io::stdout().flush().into_diagnostic()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).into_diagnostic()? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "n" || trimmed == "next" {
            if index < max_index {
                index += 1;
            }
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "p" || trimmed == "prev" {
            index = index.saturating_sub(1);
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "q" || trimmed == "quit" || trimmed == "exit" {
            break;
        }
        if trimmed == "h" || trimmed == "help" {
            println!("Commands:");
            println!("  n|next       - advance to next step");
            println!("  p|prev       - go back to previous step");
            println!("  j <k>        - jump to step k");
            println!("  fs <role>    - filter deliveries by sender role");
            println!("  fr <role>    - filter deliveries by recipient role");
            println!("  fm <family>  - filter deliveries by message family");
            println!(
                "  fk <kind>    - filter deliveries by kind (send/deliver/drop/forge/equivocate)"
            );
            println!("  fv <text>    - filter deliveries by payload variant substring");
            println!("  ff <k=v>     - filter deliveries by payload field equality");
            println!("  fc           - clear all filters");
            println!("  fl           - list active filters");
            println!("  h|help       - show this help");
            println!("  q|quit       - exit debugger");
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("j ") {
            match rest.trim().parse::<usize>() {
                Ok(k) if k <= max_index => {
                    index = k;
                    print_replay_state(trace, index, loop_start, ta, &filter);
                }
                _ => {
                    println!("Invalid jump target. Expected 0..{max_index}.");
                }
            }
            continue;
        }
        // Filter commands
        if let Some(rest) = trimmed.strip_prefix("fs ") {
            filter.sender_role = Some(rest.trim().to_string());
            println!("Filter: sender={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fr ") {
            filter.recipient_role = Some(rest.trim().to_string());
            println!("Filter: recipient={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fm ") {
            filter.message_family = Some(rest.trim().to_string());
            println!("Filter: message={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fk ") {
            filter.kind = Some(rest.trim().to_string());
            println!("Filter: kind={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fv ") {
            let needle = rest.trim();
            if needle.is_empty() {
                println!("Usage: fv <text>");
            } else {
                filter.payload_variant = Some(needle.to_string());
                println!("Filter: variant~={needle}");
                print_replay_state(trace, index, loop_start, ta, &filter);
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("ff ") {
            let spec = rest.trim();
            let Some((key_raw, value_raw)) = spec.split_once('=') else {
                println!("Invalid field filter. Usage: ff <field=value>");
                continue;
            };
            let key = key_raw.trim();
            let value = value_raw.trim();
            if key.is_empty() || value.is_empty() {
                println!("Invalid field filter. Usage: ff <field=value>");
                continue;
            }
            filter.payload_field = Some((key.to_string(), value.to_string()));
            println!("Filter: field:{key}={value}");
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "fc" {
            filter = DebugFilter::default();
            println!("All filters cleared.");
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "fl" {
            if filter.is_active() {
                println!("Active filters: {}", filter.summary());
            } else {
                println!("No active filters.");
            }
            continue;
        }
        println!("Unknown command: {trimmed}. Type 'h' for help.");
    }
    Ok(())
}

fn assistant_template(kind: &str) -> Option<&'static str> {
    match kind {
        "pbft" => Some(
            r#"protocol PBFTTemplate {
    params n, f, v;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: v;
    }

    // Message types
    message PrePrepare(view: nat in 0..32, value: bool);
    message Prepare(view: nat in 0..32, value: bool);
    message Commit(view: nat in 0..32, value: bool);

    role Replica {
        var view: nat in 0..32 = 0;
        var decided: bool = false;
        var val: bool = false;
        init idle;

        phase idle {
            // TODO: leader proposal + prepare quorum
        }
        phase prepared {
            // TODO: commit quorum + decision
        }
        phase done {}
    }

    property safety_inv: safety { forall p: Replica. p.decided == false }
    property live: liveness { forall p: Replica. p.decided == true }
}
"#,
        ),
        "hotstuff" => Some(
            r#"protocol HotStuffTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    // Suggested modeling objects:
    // - QC message carrying (view, block_id, justify_qc)
    // - lock/commit local state
    // - pacemaker-driven view changes

    message Proposal(view: nat in 0..64, block: nat in 0..128);
    message Vote(view: nat in 0..64, block: nat in 0..128);
    message NewView(view: nat in 0..64);

    role Node {
        var view: nat in 0..64 = 0;
        var decided: bool = false;
        var locked_block: nat in 0..128 = 0;
        init wait;
        phase wait {}
        phase voted {}
        phase done {}
    }

    property safety_inv: safety { forall p: Node. p.decided == false }
    property live: liveness { forall p: Node. p.decided == true }
}
"#,
        ),
        "raft" => Some(
            r#"protocol RaftTemplate {
    params n, f;
    resilience: n = 2*f + 1;
    adversary {
        model: crash;
        bound: f;
        timing: partial_synchrony;
        gst: f;
    }

    message RequestVote(term: nat in 0..32);
    message VoteGranted(term: nat in 0..32);
    message AppendEntries(term: nat in 0..32);

    role Server {
        var term: nat in 0..32 = 0;
        var leader: bool = false;
        var decided: bool = false;
        init follower;
        phase follower {}
        phase candidate {}
        phase leader {}
    }

    property election_safety: safety { forall p: Server. p.leader == false }
    property live: liveness { forall p: Server. p.decided == true }
}
"#,
        ),
        "tendermint" => Some(
            r#"protocol TendermintTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(round: nat in 0..32, value: bool);
    message Prevote(round: nat in 0..32, value: bool);
    message Precommit(round: nat in 0..32, value: bool);

    role Validator {
        var round: nat in 0..32 = 0;
        var decided: bool = false;
        var locked_round: nat in 0..32 = 0;
        var locked_value: bool = false;
        init propose;

        phase propose {}
        phase prevote {}
        phase precommit {}
        phase done {}
    }

    property safety_inv: safety {
        forall p, q: Validator.
            (p.decided == true && q.decided == true) ==> (p.locked_value == q.locked_value)
    }
    property live: liveness { forall p: Validator. p.decided == true }
}
"#,
        ),
        "streamlet" => Some(
            r#"protocol StreamletTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(epoch: nat in 0..32, block: nat in 0..128);
    message Vote(epoch: nat in 0..32, block: nat in 0..128);
    message Notarize(epoch: nat in 0..32, block: nat in 0..128);

    role Node {
        var epoch: nat in 0..32 = 0;
        var decided: bool = false;
        var finalized_block: nat in 0..128 = 0;
        init wait;

        phase wait {}
        phase voted {}
        phase finalized {}
    }

    property safety_inv: safety {
        forall p, q: Node.
            (p.decided == true && q.decided == true) ==> (p.finalized_block == q.finalized_block)
    }
    property live: liveness { forall p: Node. p.decided == true }
}
"#,
        ),
        "casper" => Some(
            r#"protocol CasperFFGTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(epoch: nat in 0..32, checkpoint: nat in 0..128);
    message Vote(epoch: nat in 0..32, source: nat in 0..128, target: nat in 0..128);
    message Justify(epoch: nat in 0..32, checkpoint: nat in 0..128);

    role Validator {
        var epoch: nat in 0..32 = 0;
        var decided: bool = false;
        var justified_checkpoint: nat in 0..128 = 0;
        var finalized_checkpoint: nat in 0..128 = 0;
        init attest;

        phase attest {}
        phase justified {}
        phase finalized {}
    }

    property safety_inv: safety {
        forall p, q: Validator.
            (p.decided == true && q.decided == true) ==> (p.finalized_checkpoint == q.finalized_checkpoint)
    }
    property live: liveness { forall p: Validator. p.decided == true }
}
"#,
        ),
        _ => None,
    }
}

fn layer(
    layer: &str,
    status: &str,
    summary: impl Into<String>,
    details: Value,
    output: impl Into<String>,
) -> AnalysisLayerReport {
    AnalysisLayerReport {
        layer: layer.to_string(),
        status: status.to_string(),
        summary: summary.into(),
        details,
        output: output.into(),
    }
}

fn run_parse_layer(source: &str, filename: &str) -> AnalysisLayerReport {
    match tarsier_engine::pipeline::parse(source, filename) {
        Ok(program) => match tarsier_engine::pipeline::lower(&program) {
            Ok(ta) => layer(
                "parse+lower",
                "pass",
                "Parsed and lowered protocol.",
                json!({
                    "protocol": program.protocol.node.name,
                    "parameters": program.protocol.node.parameters.len(),
                    "roles": program.protocol.node.roles.len(),
                    "messages": program.protocol.node.messages.len(),
                    "locations": ta.locations.len(),
                    "rules": ta.rules.len(),
                }),
                "ok",
            ),
            Err(e) => layer(
                "parse+lower",
                "error",
                "Lowering failed.",
                json!({"error": e.to_string()}),
                e.to_string(),
            ),
        },
        Err(e) => layer(
            "parse+lower",
            "error",
            "Parse failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_verify_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    cegar_iters: usize,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.depth, cfg.timeout, cfg.soundness);
    match tarsier_engine::pipeline::verify_with_cegar_report(
        source,
        filename,
        &options,
        cegar_iters,
    ) {
        Ok(report) => {
            let cegar = cegar_report_details(&report);
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let result = report.final_result;
            let output = format!("{result}");
            match result {
                VerificationResult::Safe { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!("Safety holds up to depth {depth_checked}."),
                    json!({
                        "result": "safe",
                        "depth_checked": depth_checked,
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::ProbabilisticallySafe {
                    depth_checked,
                    failure_probability,
                    committee_analyses,
                } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "Probabilistic safety holds up to depth {depth_checked} (failure <= {:.0e}).",
                        failure_probability
                    ),
                    json!({
                        "result": "probabilistically_safe",
                        "depth_checked": depth_checked,
                        "failure_probability": failure_probability,
                        "committee_count": committee_analyses.len(),
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::Unsafe { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Safety violation found.",
                    json!({
                        "result": "unsafe",
                        "trace": trace_details(trace),
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                VerificationResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Safety check inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "cegar": cegar,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Safety check failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_verify_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    cegar_iters: usize,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let z3_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::verify_with_cegar_report(
            &source_z3,
            &filename_z3,
            &options_z3,
            cegar_iters,
        )
    });
    let cvc5_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::verify_with_cegar_report(
            &source_cvc5,
            &filename_cvc5,
            &options_cvc5,
            cegar_iters,
        )
    });

    let z3_result = z3_handle
        .join()
        .map_err(|_| "z3 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let cvc5_result = cvc5_handle
        .join()
        .map_err(|_| "cvc5 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));

    let (result, details) = merge_portfolio_verify_reports(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        VerificationResult::Safe { depth_checked } => layer(
            layer_name,
            "pass",
            format!("Safety holds up to depth {depth_checked}."),
            json!({
                "result": "safe",
                "depth_checked": depth_checked,
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => layer(
            layer_name,
            "pass",
            format!(
                "Probabilistic safety holds up to depth {depth_checked} (failure <= {:.0e}).",
                failure_probability
            ),
            json!({
                "result": "probabilistically_safe",
                "depth_checked": depth_checked,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len(),
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::Unsafe { ref trace } => layer(
            layer_name,
            "fail",
            "Safety violation found.",
            json!({
                "result": "unsafe",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        VerificationResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Safety check inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

fn run_liveness_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    solver: SolverChoice,
    depth: usize,
    timeout: u64,
    soundness: SoundnessMode,
) -> AnalysisLayerReport {
    let options = make_options(solver, depth, timeout, soundness);
    match tarsier_engine::pipeline::check_liveness(source, filename, &options) {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            match result {
                LivenessResult::Live { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!("All processes decide by depth {depth_checked}."),
                    json!({
                        "result": "live",
                        "depth_checked": depth_checked,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                LivenessResult::NotLive { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Bounded liveness violation found.",
                    json!({
                        "result": "not_live",
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                LivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Bounded liveness check inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Bounded liveness check failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_liveness_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let z3_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::check_liveness(&source_z3, &filename_z3, &options_z3)
    });
    let cvc5_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::check_liveness(&source_cvc5, &filename_cvc5, &options_cvc5)
    });

    let z3_result = z3_handle
        .join()
        .map_err(|_| "z3 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let cvc5_result = cvc5_handle
        .join()
        .map_err(|_| "cvc5 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));

    let (result, details) = merge_portfolio_liveness_results(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        LivenessResult::Live { depth_checked } => layer(
            layer_name,
            "pass",
            format!("All processes decide by depth {depth_checked}."),
            json!({
                "result": "live",
                "depth_checked": depth_checked,
                "portfolio": details,
            }),
            output,
        ),
        LivenessResult::NotLive { ref trace } => layer(
            layer_name,
            "fail",
            "Bounded liveness violation found.",
            json!({
                "result": "not_live",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        LivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Bounded liveness check inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

fn run_fair_liveness_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.depth, cfg.timeout, cfg.soundness);
    match tarsier_engine::pipeline::check_fair_liveness_with_mode(
        source,
        filename,
        &options,
        cfg.fairness,
    ) {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            let fairness_name = fairness_name(cfg.fairness);
            match result {
                FairLivenessResult::NoFairCycleUpTo { depth_checked } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "No {fairness_name}-fair non-terminating lasso found up to depth {depth_checked}."
                    ),
                    json!({
                        "result": "no_fair_cycle_up_to",
                        "depth_checked": depth_checked,
                        "fairness": fairness_name,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                FairLivenessResult::FairCycleFound {
                    depth,
                    loop_start,
                    ref trace,
                } => layer(
                    layer_name,
                    "fail",
                    format!(
                        "{fairness_name}-fair non-terminating lasso found: {loop_start} -> {depth}."
                    ),
                    json!({
                        "result": "fair_cycle_found",
                        "depth": depth,
                        "loop_start": loop_start,
                        "fairness": fairness_name,
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                FairLivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Fair-liveness search inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Fair-liveness search failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_fair_liveness_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let options_z3 = make_options(SolverChoice::Z3, cfg.depth, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.depth, cfg.timeout, cfg.soundness);

    let fairness = cfg.fairness;
    let z3_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::check_fair_liveness_with_mode(
            &source_z3,
            &filename_z3,
            &options_z3,
            fairness,
        )
    });
    let cvc5_handle = std::thread::spawn(move || {
        tarsier_engine::pipeline::check_fair_liveness_with_mode(
            &source_cvc5,
            &filename_cvc5,
            &options_cvc5,
            fairness,
        )
    });

    let z3_result = z3_handle
        .join()
        .map_err(|_| "z3 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let cvc5_result = cvc5_handle
        .join()
        .map_err(|_| "cvc5 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));

    let (result, details) = merge_portfolio_fair_liveness_results(z3_result, cvc5_result);
    let output = format!("{result}");
    let fairness_name = fairness_name(cfg.fairness);
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => layer(
            layer_name,
            "pass",
            format!(
                "No {fairness_name}-fair non-terminating lasso found up to depth {depth_checked}."
            ),
            json!({
                "result": "no_fair_cycle_up_to",
                "depth_checked": depth_checked,
                "fairness": fairness_name,
                "portfolio": details,
            }),
            output,
        ),
        FairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            ref trace,
        } => layer(
            layer_name,
            "fail",
            format!("{fairness_name}-fair non-terminating lasso found: {loop_start} -> {depth}."),
            json!({
                "result": "fair_cycle_found",
                "depth": depth,
                "loop_start": loop_start,
                "fairness": fairness_name,
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        FairLivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Fair-liveness search inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

fn run_prove_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    engine: ProofEngine,
) -> AnalysisLayerReport {
    let mut options = make_options(cfg.solver, cfg.k, cfg.timeout, cfg.soundness);
    options.proof_engine = engine;
    let run = if cfg.cegar_iters > 0 {
        tarsier_engine::pipeline::prove_safety_with_cegar(
            source,
            filename,
            &options,
            cfg.cegar_iters,
        )
    } else {
        tarsier_engine::pipeline::prove_safety(source, filename, &options)
    };
    match run {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            match result {
                UnboundedSafetyResult::Safe { induction_k } => layer(
                    layer_name,
                    "pass",
                    format!("Unbounded safety proved (k = {induction_k})."),
                    json!({
                        "result": "safe",
                        "induction_k": induction_k,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::ProbabilisticallySafe {
                    induction_k,
                    failure_probability,
                    committee_analyses,
                } => layer(
                    layer_name,
                    "pass",
                    format!(
                        "Unbounded probabilistic safety proved (k = {induction_k}, failure <= {:.0e}).",
                        failure_probability
                    ),
                    json!({
                        "result": "probabilistically_safe",
                        "induction_k": induction_k,
                        "failure_probability": failure_probability,
                        "committee_count": committee_analyses.len(),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::Unsafe { ref trace } => layer(
                    layer_name,
                    "fail",
                    "Unbounded safety violation found.",
                    json!({
                        "result": "unsafe",
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedSafetyResult::NotProved { max_k, ref cti } => {
                    let summary = if let Some(witness) = cti {
                        format!(
                            "Unbounded proof did not close up to k = {max_k}; CTI available at k = {}.",
                            witness.k
                        )
                    } else {
                        format!("Unbounded proof did not close up to k = {max_k}.")
                    };
                    layer(
                        layer_name,
                        "unknown",
                        summary,
                        json!({
                            "result": "not_proved",
                            "max_k": max_k,
                            "cti": cti.as_ref().map(cti_details),
                            "abstractions": abstractions,
                        }),
                        output,
                    )
                }
                UnboundedSafetyResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Unbounded proof inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Unbounded safety proof failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_prove_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
    engine: ProofEngine,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let cegar_iters = cfg.cegar_iters;
    let mut options_z3 = make_options(SolverChoice::Z3, cfg.k, cfg.timeout, cfg.soundness);
    options_z3.proof_engine = engine;
    let mut options_cvc5 = make_options(SolverChoice::Cvc5, cfg.k, cfg.timeout, cfg.soundness);
    options_cvc5.proof_engine = engine;

    let z3_handle = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_safety_with_cegar(
                &source_z3,
                &filename_z3,
                &options_z3,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_safety(&source_z3, &filename_z3, &options_z3)
        }
    });
    let cvc5_handle = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_safety_with_cegar(
                &source_cvc5,
                &filename_cvc5,
                &options_cvc5,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_safety(&source_cvc5, &filename_cvc5, &options_cvc5)
        }
    });

    let z3_result = z3_handle
        .join()
        .map_err(|_| "z3 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let cvc5_result = cvc5_handle
        .join()
        .map_err(|_| "cvc5 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));

    let (result, details) = merge_portfolio_prove_results(z3_result, cvc5_result);
    let output = format!("{result}");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => layer(
            layer_name,
            "pass",
            format!("Unbounded safety proved (k = {induction_k})."),
            json!({
                "result": "safe",
                "induction_k": induction_k,
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => layer(
            layer_name,
            "pass",
            format!(
                "Unbounded probabilistic safety proved (k = {induction_k}, failure <= {:.0e}).",
                failure_probability
            ),
            json!({
                "result": "probabilistically_safe",
                "induction_k": induction_k,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len(),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::Unsafe { ref trace } => layer(
            layer_name,
            "fail",
            "Unbounded safety violation found.",
            json!({
                "result": "unsafe",
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedSafetyResult::NotProved { max_k, ref cti } => {
            let summary = if let Some(witness) = cti {
                format!(
                    "Unbounded proof did not close up to k = {max_k}; CTI available at k = {}.",
                    witness.k
                )
            } else {
                format!("Unbounded proof did not close up to k = {max_k}.")
            };
            layer(
                layer_name,
                "unknown",
                summary,
                json!({
                    "result": "not_proved",
                    "max_k": max_k,
                    "cti": cti.as_ref().map(cti_details),
                    "portfolio": details,
                }),
                output,
            )
        }
        UnboundedSafetyResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Unbounded proof inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

fn run_prove_fair_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let options = make_options(cfg.solver, cfg.k, cfg.timeout, cfg.soundness);
    let run = if cfg.cegar_iters > 0 {
        tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
            source,
            filename,
            &options,
            cfg.fairness,
            cfg.cegar_iters,
        )
    } else {
        tarsier_engine::pipeline::prove_fair_liveness_with_mode(
            source,
            filename,
            &options,
            cfg.fairness,
        )
    };
    match run {
        Ok(result) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let output = format!("{result}");
            let fairness_name = fairness_name(cfg.fairness);
            match result {
                UnboundedFairLivenessResult::LiveProved { frame } => layer(
                    layer_name,
                    "pass",
                    format!("Unbounded {fairness_name}-fair liveness proved (frame = {frame})."),
                    json!({
                        "result": "live_proved",
                        "frame": frame,
                        "fairness": fairness_name,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::FairCycleFound {
                    depth,
                    loop_start,
                    ref trace,
                } => layer(
                    layer_name,
                    "fail",
                    format!(
                        "{fairness_name}-fair non-termination found: loop {loop_start} -> {depth}."
                    ),
                    json!({
                        "result": "fair_cycle_found",
                        "depth": depth,
                        "loop_start": loop_start,
                        "fairness": fairness_name,
                        "trace": trace_details(trace),
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::NotProved { max_k } => layer(
                    layer_name,
                    "unknown",
                    format!("Unbounded fair-liveness proof did not converge up to frame {max_k}."),
                    json!({
                        "result": "not_proved",
                        "max_k": max_k,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
                UnboundedFairLivenessResult::Unknown { ref reason } => layer(
                    layer_name,
                    "unknown",
                    "Unbounded fair-liveness proof inconclusive.",
                    json!({
                        "result": "unknown",
                        "reason": reason,
                        "abstractions": abstractions,
                    }),
                    output,
                ),
            }
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Unbounded fair-liveness proof failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn run_prove_fair_layer_portfolio(
    source: &str,
    filename: &str,
    layer_name: &str,
    cfg: LayerRunCfg,
) -> AnalysisLayerReport {
    let source_z3 = source.to_string();
    let source_cvc5 = source.to_string();
    let filename_z3 = filename.to_string();
    let filename_cvc5 = filename.to_string();
    let cegar_iters = cfg.cegar_iters;
    let options_z3 = make_options(SolverChoice::Z3, cfg.k, cfg.timeout, cfg.soundness);
    let options_cvc5 = make_options(SolverChoice::Cvc5, cfg.k, cfg.timeout, cfg.soundness);
    let fairness = cfg.fairness;

    let z3_handle = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                &source_z3,
                &filename_z3,
                &options_z3,
                fairness,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                &source_z3,
                &filename_z3,
                &options_z3,
                fairness,
            )
        }
    });
    let cvc5_handle = std::thread::spawn(move || {
        if cegar_iters > 0 {
            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                &source_cvc5,
                &filename_cvc5,
                &options_cvc5,
                fairness,
                cegar_iters,
            )
        } else {
            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                &source_cvc5,
                &filename_cvc5,
                &options_cvc5,
                fairness,
            )
        }
    });

    let z3_result = z3_handle
        .join()
        .map_err(|_| "z3 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    let cvc5_result = cvc5_handle
        .join()
        .map_err(|_| "cvc5 portfolio worker panicked".to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));

    let (result, details) = merge_portfolio_prove_fair_results(z3_result, cvc5_result);
    let output = format!("{result}");
    let fairness_name = fairness_name(cfg.fairness);
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => layer(
            layer_name,
            "pass",
            format!("Unbounded {fairness_name}-fair liveness proved (frame = {frame})."),
            json!({
                "result": "live_proved",
                "frame": frame,
                "fairness": fairness_name,
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            ref trace,
        } => layer(
            layer_name,
            "fail",
            format!("{fairness_name}-fair non-termination found: loop {loop_start} -> {depth}."),
            json!({
                "result": "fair_cycle_found",
                "depth": depth,
                "loop_start": loop_start,
                "fairness": fairness_name,
                "trace": trace_details(trace),
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::NotProved { max_k } => layer(
            layer_name,
            "unknown",
            format!("Unbounded fair-liveness proof did not converge up to frame {max_k}."),
            json!({
                "result": "not_proved",
                "max_k": max_k,
                "portfolio": details,
            }),
            output,
        ),
        UnboundedFairLivenessResult::Unknown { ref reason } => layer(
            layer_name,
            "unknown",
            "Unbounded fair-liveness proof inconclusive.",
            json!({
                "result": "unknown",
                "reason": reason,
                "portfolio": details,
            }),
            output,
        ),
    }
}

fn run_comm_layer(
    source: &str,
    filename: &str,
    layer_name: &str,
    depth: usize,
) -> AnalysisLayerReport {
    match tarsier_engine::pipeline::comm_complexity(source, filename, depth) {
        Ok(report) => {
            let diagnostics = take_run_diagnostics();
            let abstractions = run_diagnostics_details(&diagnostics);
            let mut details = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("abstractions".to_string(), abstractions);
            }
            layer(
                layer_name,
                "pass",
                "Computed communication complexity bounds.",
                details,
                format!("{report}"),
            )
        }
        Err(e) => layer(
            layer_name,
            "error",
            "Communication complexity analysis failed.",
            json!({"error": e.to_string()}),
            e.to_string(),
        ),
    }
}

fn overall_status(mode: AnalysisMode, layers: &[AnalysisLayerReport]) -> String {
    let has_fail = layers
        .iter()
        .any(|l| l.status == "fail" || l.status == "error");
    if has_fail {
        return "fail".to_string();
    }

    let has_unknown = layers.iter().any(|l| l.status == "unknown");
    match mode {
        AnalysisMode::Quick | AnalysisMode::Standard => {
            if has_unknown {
                "unknown".to_string()
            } else {
                "pass".to_string()
            }
        }
        AnalysisMode::Proof | AnalysisMode::Audit => {
            if has_unknown {
                "fail".to_string()
            } else {
                "pass".to_string()
            }
        }
    }
}

fn render_analysis_text(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str("ANALYSIS REPORT\n");
    out.push_str(&format!("Mode: {}\n", report.mode));
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str("Network Faithfulness:\n");
    let nf_status = report
        .network_faithfulness
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let nf_summary = report
        .network_faithfulness
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("No network faithfulness summary.");
    out.push_str(&format!(
        "- [{}] {}\n",
        nf_status.to_uppercase(),
        nf_summary
    ));
    if let Some(assumptions) = report
        .network_faithfulness
        .get("assumptions_enforced")
        .and_then(Value::as_array)
    {
        for item in assumptions.iter().filter_map(Value::as_str) {
            out.push_str(&format!("  - {item}\n"));
        }
    }
    out.push_str("Layers:\n");
    for layer in &report.layers {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            layer.status.to_uppercase(),
            layer.layer,
            layer.summary
        ));
    }
    out
}

fn run_analysis(
    source: &str,
    filename: &str,
    mode: AnalysisMode,
    cfg: LayerRunCfg,
    network_mode: CliNetworkSemanticsMode,
) -> AnalysisReport {
    let mut layers = Vec::new();
    let network_faithfulness =
        network_faithfulness_section(source, filename, network_mode, cfg.soundness);
    let verify_cegar_iters = match mode {
        AnalysisMode::Quick => 1,
        AnalysisMode::Standard => 2,
        AnalysisMode::Proof => 2,
        AnalysisMode::Audit => 3,
    };
    let proof_cegar_iters = match mode {
        AnalysisMode::Proof => cfg.cegar_iters.max(2),
        AnalysisMode::Audit => cfg.cegar_iters.max(3),
        _ => cfg.cegar_iters,
    };

    layers.push(run_parse_layer(source, filename));

    let quick_depth = cfg.depth.min(4);
    match mode {
        AnalysisMode::Quick => {
            let quick_cfg = LayerRunCfg {
                depth: quick_depth,
                ..cfg
            };
            if quick_cfg.portfolio {
                layers.push(run_verify_layer_portfolio(
                    source,
                    filename,
                    "verify[quick]",
                    quick_cfg,
                    verify_cegar_iters,
                ));
            } else {
                layers.push(run_verify_layer(
                    source,
                    filename,
                    "verify[quick]",
                    quick_cfg,
                    verify_cegar_iters,
                ));
            }
        }
        AnalysisMode::Standard | AnalysisMode::Proof | AnalysisMode::Audit => {
            if cfg.portfolio {
                layers.push(run_verify_layer_portfolio(
                    source,
                    filename,
                    "verify",
                    cfg,
                    verify_cegar_iters,
                ));
                layers.push(run_liveness_layer_portfolio(
                    source,
                    filename,
                    "liveness[bounded]",
                    cfg,
                ));
                layers.push(run_fair_liveness_layer_portfolio(
                    source,
                    filename,
                    "liveness[fair_lasso]",
                    cfg,
                ));
            } else {
                layers.push(run_verify_layer(
                    source,
                    filename,
                    "verify",
                    cfg,
                    verify_cegar_iters,
                ));
                layers.push(run_liveness_layer(
                    source,
                    filename,
                    "liveness[bounded]",
                    cfg.solver,
                    cfg.depth,
                    cfg.timeout,
                    cfg.soundness,
                ));
                layers.push(run_fair_liveness_layer(
                    source,
                    filename,
                    "liveness[fair_lasso]",
                    cfg,
                ));
            }
            layers.push(run_comm_layer(source, filename, "comm", cfg.depth));
        }
    }

    if matches!(mode, AnalysisMode::Proof | AnalysisMode::Audit) {
        let proof_cfg = LayerRunCfg {
            cegar_iters: proof_cegar_iters,
            ..cfg
        };
        if cfg.portfolio {
            layers.push(run_prove_layer_portfolio(
                source,
                filename,
                "prove[kinduction]",
                proof_cfg,
                ProofEngine::KInduction,
            ));
            layers.push(run_prove_layer_portfolio(
                source,
                filename,
                "prove[pdr]",
                proof_cfg,
                ProofEngine::Pdr,
            ));
            layers.push(run_prove_fair_layer_portfolio(
                source,
                filename,
                "prove[fair_pdr]",
                proof_cfg,
            ));
        } else {
            layers.push(run_prove_layer(
                source,
                filename,
                "prove[kinduction]",
                proof_cfg,
                ProofEngine::KInduction,
            ));
            layers.push(run_prove_layer(
                source,
                filename,
                "prove[pdr]",
                proof_cfg,
                ProofEngine::Pdr,
            ));
            layers.push(run_prove_fair_layer(
                source,
                filename,
                "prove[fair_pdr]",
                proof_cfg,
            ));
        }
    }

    if matches!(mode, AnalysisMode::Audit) && !cfg.portfolio {
        let secondary = match cfg.solver {
            SolverChoice::Z3 => SolverChoice::Cvc5,
            SolverChoice::Cvc5 => SolverChoice::Z3,
        };
        let suffix = format!("[{}]", solver_name(secondary));
        let secondary_cfg = LayerRunCfg {
            solver: secondary,
            cegar_iters: proof_cegar_iters,
            ..cfg
        };

        layers.push(run_verify_layer(
            source,
            filename,
            &format!("verify{suffix}"),
            secondary_cfg,
            verify_cegar_iters,
        ));
        layers.push(run_fair_liveness_layer(
            source,
            filename,
            &format!("liveness[fair_lasso]{suffix}"),
            secondary_cfg,
        ));
        layers.push(run_prove_layer(
            source,
            filename,
            &format!("prove[pdr]{suffix}"),
            secondary_cfg,
            ProofEngine::Pdr,
        ));
        layers.push(run_prove_fair_layer(
            source,
            filename,
            &format!("prove[fair_pdr]{suffix}"),
            secondary_cfg,
        ));
    }

    let overall = overall_status(mode, &layers);
    AnalysisReport {
        schema_version: 1,
        mode: match mode {
            AnalysisMode::Quick => "quick",
            AnalysisMode::Standard => "standard",
            AnalysisMode::Proof => "proof",
            AnalysisMode::Audit => "audit",
        }
        .to_string(),
        file: filename.to_string(),
        config: AnalysisConfig {
            solver: solver_name(cfg.solver).to_string(),
            depth: cfg.depth,
            k: cfg.k,
            timeout_secs: cfg.timeout,
            soundness: match cfg.soundness {
                SoundnessMode::Strict => "strict",
                SoundnessMode::Permissive => "permissive",
            }
            .to_string(),
            fairness: fairness_name(cfg.fairness).to_string(),
            portfolio: cfg.portfolio,
        },
        network_faithfulness,
        layers,
        overall,
    }
}

struct VisualizedCounterexample {
    trace: Trace,
    loop_start: Option<usize>,
    result_output: String,
    check: VisualizeCheck,
}

fn write_visualization_output(output: &str, out: Option<&PathBuf>) -> miette::Result<()> {
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        std::fs::write(path, output).into_diagnostic()?;
        println!("Visualization written to {}", path.display());
    } else {
        println!("{output}");
    }
    Ok(())
}

fn find_counterexample_for_visualization(
    source: &str,
    filename: &str,
    check: VisualizeCheck,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> miette::Result<VisualizedCounterexample> {
    match check {
        VisualizeCheck::Verify => {
            let result =
                tarsier_engine::pipeline::verify(source, filename, options).into_diagnostic()?;
            let output = format!("{result}");
            match result {
                VerificationResult::Unsafe { trace } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: None,
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=verify (result was not UNSAFE)."
                    );
                }
            }
        }
        VisualizeCheck::Liveness => {
            let result = tarsier_engine::pipeline::check_liveness(source, filename, options)
                .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                LivenessResult::NotLive { trace } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: None,
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=liveness (result was not NOT LIVE)."
                    );
                }
            }
        }
        VisualizeCheck::FairLiveness => {
            let result = tarsier_engine::pipeline::check_fair_liveness_with_mode(
                source, filename, options, fairness,
            )
            .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                FairLivenessResult::FairCycleFound {
                    loop_start, trace, ..
                } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: Some(loop_start),
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=fair-liveness (result was not FAIR CYCLE FOUND)."
                    );
                }
            }
        }
        VisualizeCheck::Prove => {
            if detect_prove_auto_target(source, filename)? == ProveAutoTarget::FairLiveness {
                let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    source, filename, options, fairness,
                )
                .into_diagnostic()?;
                let output = format!("{result}");
                match result {
                    UnboundedFairLivenessResult::FairCycleFound {
                        loop_start, trace, ..
                    } => Ok(VisualizedCounterexample {
                        trace,
                        loop_start: Some(loop_start),
                        result_output: output,
                        check,
                    }),
                    _ => {
                        println!("{output}");
                        miette::bail!(
                            "No counterexample trace available for check=prove (auto-dispatched to liveness proof; result was not FAIR CYCLE FOUND)."
                        );
                    }
                }
            } else {
                let result = tarsier_engine::pipeline::prove_safety(source, filename, options)
                    .into_diagnostic()?;
                let output = format!("{result}");
                match result {
                    UnboundedSafetyResult::Unsafe { trace } => Ok(VisualizedCounterexample {
                        trace,
                        loop_start: None,
                        result_output: output,
                        check,
                    }),
                    _ => {
                        println!("{output}");
                        miette::bail!(
                            "No counterexample trace available for check=prove (result was not UNSAFE)."
                        );
                    }
                }
            }
        }
        VisualizeCheck::ProveFair => {
            let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                source, filename, options, fairness,
            )
            .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                UnboundedFairLivenessResult::FairCycleFound {
                    loop_start, trace, ..
                } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: Some(loop_start),
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=prove-fair (result was not FAIR CYCLE FOUND)."
                    );
                }
            }
        }
    }
}

fn main() -> miette::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let cli_network_mode = parse_cli_network_semantics_mode(&cli.network_semantics);
    let exec_controls = execution_controls_from_cli(&cli);
    set_execution_controls(exec_controls);

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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let network_faithfulness =
                network_faithfulness_section(&source, &filename, cli_network_mode, soundness_mode);

            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: depth,
                timeout_secs: timeout,
                dump_smt,
                soundness: soundness_mode,
                proof_engine: ProofEngine::KInduction,
            };

            if portfolio {
                let mut z3_options = options.clone();
                z3_options.solver = SolverChoice::Z3;
                let mut cvc5_options = options.clone();
                cvc5_options.solver = SolverChoice::Cvc5;

                let src_z3 = source.clone();
                let file_z3 = filename.clone();
                let handle_z3 = std::thread::spawn(move || {
                    let result = tarsier_engine::pipeline::verify_with_cegar_report(
                        &src_z3,
                        &file_z3,
                        &z3_options,
                        cegar_iters,
                    )
                    .map_err(|e| e.to_string());
                    let diagnostics = take_run_diagnostics();
                    (result, diagnostics)
                });

                let src_cvc5 = source.clone();
                let file_cvc5 = filename.clone();
                let handle_cvc5 = std::thread::spawn(move || {
                    let result = tarsier_engine::pipeline::verify_with_cegar_report(
                        &src_cvc5,
                        &file_cvc5,
                        &cvc5_options,
                        cegar_iters,
                    )
                    .map_err(|e| e.to_string());
                    let diagnostics = take_run_diagnostics();
                    (result, diagnostics)
                });

                let (z3_result, z3_diag): (
                    Result<tarsier_engine::result::CegarAuditReport, String>,
                    Option<PipelineRunDiagnostics>,
                ) = match handle_z3.join() {
                    Ok((res, diag)) => (res, Some(diag)),
                    Err(_) => (Err("thread panicked".into()), None),
                };
                let (cvc5_result, cvc5_diag): (
                    Result<tarsier_engine::result::CegarAuditReport, String>,
                    Option<PipelineRunDiagnostics>,
                ) = match handle_cvc5.join() {
                    Ok((res, diag)) => (res, Some(diag)),
                    Err(_) => (Err("thread panicked".into()), None),
                };

                let (final_result, portfolio_details) =
                    merge_portfolio_verify_reports(z3_result, cvc5_result);
                println!("{final_result}");
                if let Some(out) = cegar_report_out {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": verification_result_kind(&final_result),
                        "output": format!("{final_result}"),
                        "portfolio": portfolio_details,
                        "network_faithfulness": network_faithfulness,
                        "abstractions": {
                            "z3": z3_diag.as_ref().map(run_diagnostics_details),
                            "cvc5": cvc5_diag.as_ref().map(run_diagnostics_details),
                        },
                    });
                    write_json_artifact(&out, &artifact)?;
                    println!("Portfolio CEGAR report written to {}", out.display());
                }
            } else {
                match tarsier_engine::pipeline::verify_with_cegar_report(
                    &source,
                    &filename,
                    &options,
                    cegar_iters,
                ) {
                    Ok(report) => {
                        let diagnostics = take_run_diagnostics();
                        println!("{}", report.final_result);
                        if let Some(out) = cegar_report_out {
                            let artifact = json!({
                                "schema_version": 1,
                                "file": filename,
                                "result": verification_result_kind(&report.final_result),
                                "output": format!("{}", report.final_result),
                                "cegar": cegar_report_details(&report),
                                "network_faithfulness": network_faithfulness,
                                "abstractions": run_diagnostics_details(&diagnostics),
                            });
                            write_json_artifact(&out, &artifact)?;
                            println!("CEGAR report written to {}", out.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
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
            if min_bound > max_bound {
                miette::bail!("min_bound must be <= max_bound");
            }
            if stable_window == 0 {
                miette::bail!("stable_window must be >= 1");
            }
            if vars.is_empty() {
                miette::bail!("Provide at least one variable name with --vars.");
            }

            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let base_program =
                tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: depth,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: ProofEngine::KInduction,
            };

            let mut points: Vec<RoundSweepPoint> = Vec::new();
            let mut applied_target_count: Option<usize> = None;

            for upper_bound in min_bound..=max_bound {
                let mut program = base_program.clone();
                let stats = apply_round_upper_bound(&mut program, &vars, upper_bound);
                if stats.matched_targets == 0 {
                    miette::bail!(
                        "No bounded variables/fields matched {:?}. Ensure the model declares ranges for these names.",
                        vars
                    );
                }
                if !stats.unbounded_targets.is_empty() {
                    miette::bail!(
                        "Round sweep targets must be bounded (`in a..b`). Add bounds for: {}",
                        stats.unbounded_targets.join(", ")
                    );
                }
                applied_target_count = Some(stats.updated_ranges);

                let result = tarsier_engine::pipeline::verify_program_ast(&program, &options)
                    .into_diagnostic()?;
                points.push(RoundSweepPoint {
                    upper_bound,
                    result: verification_result_kind(&result).to_string(),
                    details: verification_result_details(&result),
                });
            }

            let (candidate_cutoff, stabilized_result) =
                if let Some((cutoff, kind)) = detect_round_sweep_cutoff(&points, stable_window) {
                    (Some(cutoff), Some(kind))
                } else {
                    (None, None)
                };

            let report = RoundSweepReport {
                schema_version: 1,
                file: filename.clone(),
                vars: vars.clone(),
                min_bound,
                max_bound,
                stable_window,
                points,
                candidate_cutoff,
                stabilized_result,
                note: format!(
                    "Convergence is empirical over bounded runs ({} targeted ranges mutated). Treat as cutoff evidence, not a universal proof.",
                    applied_target_count.unwrap_or(0)
                ),
            };

            match parse_output_format(&format) {
                OutputFormat::Text => {
                    println!("{}", render_round_sweep_text(&report));
                }
                OutputFormat::Json => {
                    let value = serde_json::to_value(&report).into_diagnostic()?;
                    if let Some(path) = out {
                        write_json_artifact(&path, &value)?;
                        println!("Round sweep report written to {}", path.display());
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).into_diagnostic()?
                        );
                    }
                }
            }
        }
        Commands::Parse { file } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();

            match tarsier_dsl::parse(&source, &filename) {
                Ok(program) => {
                    println!("{:#?}", program);
                }
                Err(e) => {
                    eprintln!("Parse error: {e}");
                    std::process::exit(1);
                }
            }
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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;

            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: parse_proof_engine(&engine),
            };
            let fairness = parse_fairness_mode(&fairness);
            let prove_target = detect_prove_auto_target(&source, &filename)?;

            if prove_target == ProveAutoTarget::FairLiveness {
                if portfolio {
                    let mut z3_options = options.clone();
                    z3_options.solver = SolverChoice::Z3;
                    let mut cvc5_options = options.clone();
                    cvc5_options.solver = SolverChoice::Cvc5;

                    let src_z3 = source.clone();
                    let file_z3 = filename.clone();
                    let handle_z3 = std::thread::spawn(move || {
                        if cegar_iters > 0 {
                            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                                &src_z3,
                                &file_z3,
                                &z3_options,
                                fairness,
                                cegar_iters,
                            )
                        } else {
                            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                                &src_z3,
                                &file_z3,
                                &z3_options,
                                fairness,
                            )
                        }
                        .map_err(|e| e.to_string())
                    });

                    let src_cvc5 = source.clone();
                    let file_cvc5 = filename.clone();
                    let handle_cvc5 = std::thread::spawn(move || {
                        if cegar_iters > 0 {
                            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                                &src_cvc5,
                                &file_cvc5,
                                &cvc5_options,
                                fairness,
                                cegar_iters,
                            )
                        } else {
                            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                                &src_cvc5,
                                &file_cvc5,
                                &cvc5_options,
                                fairness,
                            )
                        }
                        .map_err(|e| e.to_string())
                    });

                    let z3_result: Result<UnboundedFairLivenessResult, String> =
                        match handle_z3.join() {
                            Ok(res) => res,
                            Err(_) => Err("thread panicked".into()),
                        };
                    let cvc5_result: Result<UnboundedFairLivenessResult, String> =
                        match handle_cvc5.join() {
                            Ok(res) => res,
                            Err(_) => Err("thread panicked".into()),
                        };
                    let (result, details) =
                        merge_portfolio_prove_fair_results(z3_result, cvc5_result);
                    println!("{result}");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                            .into_diagnostic()?
                    );

                    if let Some(out) = cegar_report_out.clone() {
                        let artifact = json!({
                            "schema_version": 1,
                            "file": filename,
                            "mode": "prove",
                            "prove_target": "fair_liveness",
                            "result": unbounded_fair_result_kind(&result),
                            "details": unbounded_fair_result_details(&result),
                            "output": format!("{result}"),
                            "cegar_controls": {
                                "max_refinements": cegar_iters,
                                "timeout_secs": timeout,
                                "solver": "portfolio",
                                "proof_engine": proof_engine_name(options.proof_engine),
                                "fairness": fairness_name(fairness),
                            },
                            "portfolio": details,
                        });
                        write_json_artifact(&out, &artifact)?;
                        println!("CEGAR proof report written to {}", out.display());
                    }

                    if cert_out.is_some() {
                        eprintln!(
                            "Skipping certificate generation in portfolio mode. Use `certify-fair-liveness` with an explicit solver."
                        );
                    }
                } else {
                    let result = if let Some(report_path) = cegar_report_out.clone() {
                        match tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
                            &source,
                            &filename,
                            &options,
                            fairness,
                            cegar_iters,
                        ) {
                            Ok(report) => {
                                let diagnostics = take_run_diagnostics();
                                let result = report.final_result.clone();
                                let artifact = json!({
                                    "schema_version": 1,
                                    "file": filename,
                                    "mode": "prove",
                                    "prove_target": "fair_liveness",
                                    "result": unbounded_fair_result_kind(&result),
                                    "details": unbounded_fair_result_details(&result),
                                    "output": format!("{result}"),
                                    "cegar": unbounded_fair_cegar_report_details(&report),
                                    "abstractions": run_diagnostics_details(&diagnostics),
                                });
                                write_json_artifact(&report_path, &artifact)?;
                                println!("CEGAR proof report written to {}", report_path.display());
                                result
                            }
                            Err(e) => {
                                eprintln!("Error: {e}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        let run = if cegar_iters > 0 {
                            tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                                &source,
                                &filename,
                                &options,
                                fairness,
                                cegar_iters,
                            )
                        } else {
                            tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                                &source, &filename, &options, fairness,
                            )
                        };
                        match run {
                            Ok(result) => result,
                            Err(e) => {
                                eprintln!("Error: {e}");
                                std::process::exit(1);
                            }
                        }
                    };
                    println!("{result}");
                    if let Some(out) = cert_out {
                        match result {
                            UnboundedFairLivenessResult::LiveProved { .. } => {
                                let cert = match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                                    &source,
                                    &filename,
                                    &options,
                                    fairness,
                                ) {
                                    Ok(cert) => cert,
                                    Err(e) => {
                                        eprintln!("Error generating fair-liveness certificate: {e}");
                                        std::process::exit(1);
                                    }
                                };
                                let bundle = certificate_bundle_from_fair_liveness(&cert);
                                write_certificate_bundle(&out, &bundle)?;
                            }
                            _ => {
                                eprintln!(
                                    "Skipping certificate generation: fair-liveness proof did not conclude LIVE."
                                );
                            }
                        }
                    }
                }
            } else if portfolio {
                let mut z3_options = options.clone();
                z3_options.solver = SolverChoice::Z3;
                let mut cvc5_options = options.clone();
                cvc5_options.solver = SolverChoice::Cvc5;

                let src_z3 = source.clone();
                let file_z3 = filename.clone();
                let handle_z3 = std::thread::spawn(move || {
                    if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_safety_with_cegar(
                            &src_z3,
                            &file_z3,
                            &z3_options,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_safety(&src_z3, &file_z3, &z3_options)
                    }
                    .map_err(|e| e.to_string())
                });

                let src_cvc5 = source.clone();
                let file_cvc5 = filename.clone();
                let handle_cvc5 = std::thread::spawn(move || {
                    if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_safety_with_cegar(
                            &src_cvc5,
                            &file_cvc5,
                            &cvc5_options,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_safety(&src_cvc5, &file_cvc5, &cvc5_options)
                    }
                    .map_err(|e| e.to_string())
                });

                let z3_result: Result<UnboundedSafetyResult, String> = match handle_z3.join() {
                    Ok(res) => res,
                    Err(_) => Err("thread panicked".into()),
                };
                let cvc5_result: Result<UnboundedSafetyResult, String> = match handle_cvc5.join() {
                    Ok(res) => res,
                    Err(_) => Err("thread panicked".into()),
                };
                let (result, details) = merge_portfolio_prove_results(z3_result, cvc5_result);
                println!("{result}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                        .into_diagnostic()?
                );

                if let Some(out) = cegar_report_out.clone() {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "mode": "prove",
                        "prove_target": "safety",
                        "result": unbounded_safety_result_kind(&result),
                        "details": unbounded_safety_result_details(&result),
                        "output": format!("{result}"),
                        "cegar_controls": {
                            "max_refinements": cegar_iters,
                            "timeout_secs": timeout,
                            "solver": "portfolio",
                            "proof_engine": proof_engine_name(options.proof_engine),
                            "fairness": fairness_name(fairness),
                        },
                        "portfolio": details,
                    });
                    write_json_artifact(&out, &artifact)?;
                    println!("CEGAR proof report written to {}", out.display());
                }

                if cert_out.is_some() {
                    eprintln!(
                        "Skipping certificate generation in portfolio mode. Use `certify-safety` with an explicit solver."
                    );
                }
            } else {
                let result = if let Some(report_path) = cegar_report_out.clone() {
                    match tarsier_engine::pipeline::prove_safety_with_cegar_report(
                        &source,
                        &filename,
                        &options,
                        cegar_iters,
                    ) {
                        Ok(report) => {
                            let diagnostics = take_run_diagnostics();
                            let result = report.final_result.clone();
                            let artifact = json!({
                                "schema_version": 1,
                                "file": filename,
                                "mode": "prove",
                                "prove_target": "safety",
                                "result": unbounded_safety_result_kind(&result),
                                "details": unbounded_safety_result_details(&result),
                                "output": format!("{result}"),
                                "cegar": unbounded_safety_cegar_report_details(&report),
                                "abstractions": run_diagnostics_details(&diagnostics),
                            });
                            write_json_artifact(&report_path, &artifact)?;
                            println!("CEGAR proof report written to {}", report_path.display());
                            result
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    let run = if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_safety_with_cegar(
                            &source,
                            &filename,
                            &options,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_safety(&source, &filename, &options)
                    };
                    match run {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                };
                println!("{result}");
                if let Some(out) = cert_out {
                    match result {
                        UnboundedSafetyResult::Safe { .. }
                        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                            let cert = match tarsier_engine::pipeline::generate_safety_certificate(
                                &source, &filename, &options,
                            ) {
                                Ok(cert) => cert,
                                Err(e) => {
                                    eprintln!("Error generating certificate: {e}");
                                    std::process::exit(1);
                                }
                            };
                            let bundle = certificate_bundle_from_safety(&cert);
                            write_certificate_bundle(&out, &bundle)?;
                        }
                        _ => {
                            eprintln!(
                                "Skipping certificate generation: proof did not conclude SAFE."
                            );
                        }
                    }
                }
            }
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
            if round_vars.is_empty() {
                miette::bail!("Provide at least one round variable name with --round-vars.");
            }

            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: parse_proof_engine(&engine),
            };

            let proved = tarsier_engine::pipeline::prove_safety_with_round_abstraction(
                &source,
                &filename,
                &options,
                &round_vars,
            )
            .into_diagnostic()?;

            match parse_output_format(&format) {
                OutputFormat::Text => {
                    println!(
                        "{}",
                        render_prove_round_text(&filename, &proved.summary, &proved.result)
                    );
                }
                OutputFormat::Json => {
                    let value = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": unbounded_safety_result_kind(&proved.result),
                        "summary": {
                            "erased_vars": proved.summary.erased_vars,
                            "original_locations": proved.summary.original_locations,
                            "abstract_locations": proved.summary.abstract_locations,
                            "original_shared_vars": proved.summary.original_shared_vars,
                            "abstract_shared_vars": proved.summary.abstract_shared_vars,
                            "original_message_counters": proved.summary.original_message_counters,
                            "abstract_message_counters": proved.summary.abstract_message_counters,
                        },
                        "details": unbounded_safety_result_details(&proved.result),
                        "output": format!("{}", proved.result),
                        "soundness_note": match proved.result {
                            UnboundedSafetyResult::Safe { .. }
                            | UnboundedSafetyResult::ProbabilisticallySafe { .. } =>
                                "SAFE is sound for concrete unbounded-round behavior under this over-approximation.",
                            UnboundedSafetyResult::Unsafe { .. } =>
                                "UNSAFE may be spurious under over-approximation; confirm on concrete model.",
                            _ =>
                                "Inconclusive result; try larger k or different engine.",
                        },
                    });
                    if let Some(path) = out {
                        write_json_artifact(&path, &value)?;
                        println!("Round abstraction report written to {}", path.display());
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).into_diagnostic()?
                        );
                    }
                }
            }
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
            if round_vars.is_empty() {
                miette::bail!("Provide at least one round variable name with --round-vars.");
            }
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let fairness = parse_fairness_mode(&fairness);
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: ProofEngine::Pdr,
            };

            let proved = tarsier_engine::pipeline::prove_fair_liveness_with_round_abstraction(
                &source,
                &filename,
                &options,
                fairness,
                &round_vars,
            )
            .into_diagnostic()?;

            match parse_output_format(&format) {
                OutputFormat::Text => {
                    println!(
                        "{}",
                        render_prove_fair_round_text(&filename, &proved.summary, &proved.result)
                    );
                }
                OutputFormat::Json => {
                    let value = json!({
                        "schema_version": 1,
                        "file": filename,
                        "result": unbounded_fair_result_kind(&proved.result),
                        "summary": {
                            "erased_vars": proved.summary.erased_vars,
                            "original_locations": proved.summary.original_locations,
                            "abstract_locations": proved.summary.abstract_locations,
                            "original_shared_vars": proved.summary.original_shared_vars,
                            "abstract_shared_vars": proved.summary.abstract_shared_vars,
                            "original_message_counters": proved.summary.original_message_counters,
                            "abstract_message_counters": proved.summary.abstract_message_counters,
                        },
                        "details": unbounded_fair_result_details(&proved.result),
                        "output": format!("{}", proved.result),
                        "soundness_note": match proved.result {
                            UnboundedFairLivenessResult::LiveProved { .. } =>
                                "LIVE_PROVED is sound for concrete unbounded-round behavior under this over-approximation.",
                            UnboundedFairLivenessResult::FairCycleFound { .. } =>
                                "FAIR_CYCLE_FOUND may be spurious under over-approximation; confirm on concrete model.",
                            _ =>
                                "Inconclusive result; try larger k or different fairness settings.",
                        },
                    });
                    if let Some(path) = out {
                        write_json_artifact(&path, &value)?;
                        println!(
                            "Round abstraction fair-liveness report written to {}",
                            path.display()
                        );
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).into_diagnostic()?
                        );
                    }
                }
            }
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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;

            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: ProofEngine::Pdr,
            };
            let fairness = parse_fairness_mode(&fairness);

            if portfolio {
                let mut z3_options = options.clone();
                z3_options.solver = SolverChoice::Z3;
                let mut cvc5_options = options.clone();
                cvc5_options.solver = SolverChoice::Cvc5;

                let src_z3 = source.clone();
                let file_z3 = filename.clone();
                let handle_z3 = std::thread::spawn(move || {
                    if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                            &src_z3,
                            &file_z3,
                            &z3_options,
                            fairness,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                            &src_z3,
                            &file_z3,
                            &z3_options,
                            fairness,
                        )
                    }
                    .map_err(|e| e.to_string())
                });

                let src_cvc5 = source.clone();
                let file_cvc5 = filename.clone();
                let handle_cvc5 = std::thread::spawn(move || {
                    if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                            &src_cvc5,
                            &file_cvc5,
                            &cvc5_options,
                            fairness,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                            &src_cvc5,
                            &file_cvc5,
                            &cvc5_options,
                            fairness,
                        )
                    }
                    .map_err(|e| e.to_string())
                });

                let z3_result: Result<UnboundedFairLivenessResult, String> = match handle_z3.join()
                {
                    Ok(res) => res,
                    Err(_) => Err("thread panicked".into()),
                };
                let cvc5_result: Result<UnboundedFairLivenessResult, String> =
                    match handle_cvc5.join() {
                        Ok(res) => res,
                        Err(_) => Err("thread panicked".into()),
                    };
                let (result, details) = merge_portfolio_prove_fair_results(z3_result, cvc5_result);
                println!("{result}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"portfolio": details.clone()}))
                        .into_diagnostic()?
                );

                if let Some(out) = cegar_report_out.clone() {
                    let artifact = json!({
                        "schema_version": 1,
                        "file": filename,
                        "mode": "prove-fair",
                        "result": unbounded_fair_result_kind(&result),
                        "details": unbounded_fair_result_details(&result),
                        "output": format!("{result}"),
                        "cegar_controls": {
                            "max_refinements": cegar_iters,
                            "timeout_secs": timeout,
                            "solver": "portfolio",
                            "proof_engine": "pdr",
                            "fairness": fairness_name(fairness),
                        },
                        "portfolio": details,
                    });
                    write_json_artifact(&out, &artifact)?;
                    println!("CEGAR proof report written to {}", out.display());
                }

                if cert_out.is_some() {
                    eprintln!(
                        "Skipping certificate generation in portfolio mode. Use `certify-fair-liveness` with an explicit solver."
                    );
                }
            } else {
                let result = if let Some(report_path) = cegar_report_out.clone() {
                    match tarsier_engine::pipeline::prove_fair_liveness_with_cegar_report(
                        &source,
                        &filename,
                        &options,
                        fairness,
                        cegar_iters,
                    ) {
                        Ok(report) => {
                            let diagnostics = take_run_diagnostics();
                            let result = report.final_result.clone();
                            let artifact = json!({
                                "schema_version": 1,
                                "file": filename,
                                "mode": "prove-fair",
                                "result": unbounded_fair_result_kind(&result),
                                "details": unbounded_fair_result_details(&result),
                                "output": format!("{result}"),
                                "cegar": unbounded_fair_cegar_report_details(&report),
                                "abstractions": run_diagnostics_details(&diagnostics),
                            });
                            write_json_artifact(&report_path, &artifact)?;
                            println!("CEGAR proof report written to {}", report_path.display());
                            result
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    let run = if cegar_iters > 0 {
                        tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                            &source,
                            &filename,
                            &options,
                            fairness,
                            cegar_iters,
                        )
                    } else {
                        tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                            &source, &filename, &options, fairness,
                        )
                    };
                    match run {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                };
                println!("{result}");
                if let Some(out) = cert_out {
                    match result {
                        UnboundedFairLivenessResult::LiveProved { .. } => {
                            let cert = match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                                &source,
                                &filename,
                                &options,
                                fairness,
                            ) {
                                Ok(cert) => cert,
                                Err(e) => {
                                    eprintln!("Error generating fair-liveness certificate: {e}");
                                    std::process::exit(1);
                                }
                            };
                            let bundle = certificate_bundle_from_fair_liveness(&cert);
                            write_certificate_bundle(&out, &bundle)?;
                        }
                        _ => {
                            eprintln!(
                                "Skipping certificate generation: fair-liveness proof did not conclude LIVE."
                            );
                        }
                    }
                }
            }
        }
        Commands::ShowTa { file } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                SoundnessMode::Strict,
                cli_network_mode,
            )?;

            match tarsier_engine::pipeline::show_ta(&source, &filename) {
                Ok(output) => {
                    print!("{output}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Committee {
            population,
            byzantine,
            size,
            epsilon,
        } => {
            let spec = tarsier_prob::CommitteeSpec {
                name: "committee".into(),
                population,
                byzantine,
                committee_size: size,
                epsilon,
            };

            match tarsier_prob::analyze_committee(&spec) {
                Ok(analysis) => {
                    println!("Committee Analysis:");
                    println!("  Population: {} ({} Byzantine)", population, byzantine);
                    println!("  Committee size: {}", size);
                    println!("  Expected Byzantine: {:.1}", analysis.expected_byzantine);
                    println!(
                        "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
                        analysis.b_max, epsilon
                    );
                    println!(
                        "  Honest majority: {} of {}",
                        analysis.honest_majority, size
                    );
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Liveness {
            file,
            solver,
            depth,
            timeout,
            soundness,
            dump_smt,
        } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;

            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: depth,
                timeout_secs: timeout,
                dump_smt,
                soundness: soundness_mode,
                proof_engine: ProofEngine::KInduction,
            };

            match tarsier_engine::pipeline::check_liveness(&source, &filename, &options) {
                Ok(result) => {
                    println!("{result}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;

            let options =
                make_options(parse_solver_choice(&solver), depth, timeout, soundness_mode);
            let fairness = parse_fairness_mode(&fairness);
            if portfolio {
                let mut z3_options = options.clone();
                z3_options.solver = SolverChoice::Z3;
                let mut cvc5_options = options.clone();
                cvc5_options.solver = SolverChoice::Cvc5;

                let src_z3 = source.clone();
                let file_z3 = filename.clone();
                let handle_z3 = std::thread::spawn(move || {
                    tarsier_engine::pipeline::check_fair_liveness_with_mode(
                        &src_z3,
                        &file_z3,
                        &z3_options,
                        fairness,
                    )
                    .map_err(|e| e.to_string())
                });

                let src_cvc5 = source.clone();
                let file_cvc5 = filename.clone();
                let handle_cvc5 = std::thread::spawn(move || {
                    tarsier_engine::pipeline::check_fair_liveness_with_mode(
                        &src_cvc5,
                        &file_cvc5,
                        &cvc5_options,
                        fairness,
                    )
                    .map_err(|e| e.to_string())
                });

                let z3_result: Result<FairLivenessResult, String> = match handle_z3.join() {
                    Ok(res) => res,
                    Err(_) => Err("thread panicked".into()),
                };
                let cvc5_result: Result<FairLivenessResult, String> = match handle_cvc5.join() {
                    Ok(res) => res,
                    Err(_) => Err("thread panicked".into()),
                };
                let (result, details) =
                    merge_portfolio_fair_liveness_results(z3_result, cvc5_result);
                println!("{result}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"portfolio": details}))
                        .into_diagnostic()?
                );
            } else {
                match tarsier_engine::pipeline::check_fair_liveness_with_mode(
                    &source, &filename, &options, fairness,
                ) {
                    Ok(result) => {
                        println!("{result}");
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();

            let check = parse_visualize_check(&check);
            let format = parse_visualize_format(&format);
            let fairness = parse_fairness_mode(&fairness);
            let soundness = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
            let solver = parse_solver_choice(&solver);
            let engine = parse_proof_engine(&engine);

            let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
            let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

            let mut options = PipelineOptions {
                solver,
                max_depth: depth,
                timeout_secs: timeout,
                dump_smt: None,
                soundness,
                proof_engine: engine,
            };
            if matches!(check, VisualizeCheck::Prove | VisualizeCheck::ProveFair) {
                options.max_depth = k;
            }

            let cex = find_counterexample_for_visualization(
                &source, &filename, check, &options, fairness,
            )?;

            let timeline = render_trace_timeline(&cex.trace, &ta, cex.loop_start);
            let mermaid = render_trace_mermaid(&cex.trace, &ta, cex.loop_start);
            let title = format!(
                "Counterexample Visualization ({})",
                visualize_check_name(cex.check)
            );

            // Bundle export: write all formats into a directory
            if let Some(ref bundle_dir) = bundle {
                fs::create_dir_all(bundle_dir).into_diagnostic()?;
                fs::write(bundle_dir.join("timeline.txt"), &timeline).into_diagnostic()?;
                fs::write(bundle_dir.join("msc.mermaid"), &mermaid).into_diagnostic()?;
                let markdown = render_trace_markdown(&title, &cex.trace, &ta, cex.loop_start);
                fs::write(bundle_dir.join("report.md"), &markdown).into_diagnostic()?;
                let json_output = serde_json::to_string_pretty(&json!({
                    "schema_version": 1,
                    "kind": visualize_check_name(cex.check),
                    "loop_start": cex.loop_start,
                    "result": cex.result_output,
                    "trace": trace_details(&cex.trace),
                }))
                .into_diagnostic()?;
                fs::write(bundle_dir.join("trace.json"), &json_output).into_diagnostic()?;
                let metadata = serde_json::to_string_pretty(&json!({
                    "protocol_file": filename,
                    "check": visualize_check_name(cex.check),
                    "result": cex.result_output,
                    "loop_start": cex.loop_start,
                }))
                .into_diagnostic()?;
                fs::write(bundle_dir.join("metadata.json"), &metadata).into_diagnostic()?;
                println!(
                    "Bundle written to {} (timeline.txt, msc.mermaid, report.md, trace.json, metadata.json)",
                    bundle_dir.display()
                );
            }

            let output = match format {
                VisualizeFormat::Timeline => timeline,
                VisualizeFormat::Mermaid => mermaid,
                VisualizeFormat::Markdown => {
                    render_trace_markdown(&title, &cex.trace, &ta, cex.loop_start)
                }
                VisualizeFormat::Json => serde_json::to_string_pretty(&json!({
                    "schema_version": 1,
                    "kind": visualize_check_name(cex.check),
                    "format": visualize_format_name(format),
                    "loop_start": cex.loop_start,
                    "result": cex.result_output,
                    "timeline": timeline,
                    "mermaid": mermaid,
                    "trace": trace_details(&cex.trace),
                }))
                .into_diagnostic()?,
            };

            write_visualization_output(&output, out.as_ref())?;
        }
        Commands::Comm {
            file,
            depth,
            format,
        } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                SoundnessMode::Strict,
                cli_network_mode,
            )?;
            let output_format = parse_output_format(&format);

            match tarsier_engine::pipeline::comm_complexity(&source, &filename, depth) {
                Ok(report) => match output_format {
                    OutputFormat::Text => {
                        println!("{report}");
                    }
                    OutputFormat::Json => {
                        let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
                        println!("{json}");
                    }
                },
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
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
            let solver = parse_solver_choice(&solver);
            let engine = parse_proof_engine(&engine);
            let soundness = parse_soundness_mode(&soundness);
            if cli_network_mode == CliNetworkSemanticsMode::Faithful
                && soundness != SoundnessMode::Strict
            {
                miette::bail!("`--network-semantics faithful` requires `--soundness strict`.");
            }
            let fairness = parse_fairness_mode(&fairness);
            let output_format = parse_output_format(&format);
            let defaults = CertSuiteDefaults {
                solver,
                depth,
                k,
                timeout_secs: timeout,
                soundness,
                fairness,
                proof_engine: engine,
            };

            let report = run_cert_suite(
                &manifest,
                &defaults,
                cli_network_mode,
                artifacts_dir.as_deref(),
            )?;
            let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
            let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

            if let Some(path) = out {
                write_json_artifact(&path, &report_json_value)?;
                println!("Certification suite report written to {}", path.display());
            }

            match output_format {
                OutputFormat::Text => println!("{}", render_suite_text(&report)),
                OutputFormat::Json => println!("{report_json}"),
            }

            if report.overall != "pass" {
                std::process::exit(2);
            }
        }
        Commands::Lint {
            file,
            soundness,
            format,
            out,
        } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
            let output_format = parse_output_format(&format);
            let report = lint_protocol_file(&source, &filename, soundness);
            let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
            let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

            if let Some(path) = out {
                write_json_artifact(&path, &report_json_value)?;
                println!("Lint report written to {}", path.display());
            }

            match output_format {
                OutputFormat::Text => println!("{}", render_lint_text(&report)),
                OutputFormat::Json => println!("{report_json}"),
            }

            if report.issues.iter().any(|i| i.severity == "error") {
                std::process::exit(2);
            }
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
        } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let check = parse_visualize_check(&check);
            let fairness = parse_fairness_mode(&fairness);
            let soundness = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
            let solver = parse_solver_choice(&solver);
            let engine = parse_proof_engine(&engine);

            let mut options = PipelineOptions {
                solver,
                max_depth: depth,
                timeout_secs: timeout,
                dump_smt: None,
                soundness,
                proof_engine: engine,
            };
            if matches!(check, VisualizeCheck::Prove | VisualizeCheck::ProveFair) {
                options.max_depth = k;
            }

            let ta = tarsier_engine::pipeline::parse(&source, &filename)
                .ok()
                .and_then(|prog| tarsier_engine::pipeline::lower(&prog).ok());

            let cex = find_counterexample_for_visualization(
                &source, &filename, check, &options, fairness,
            )?;
            println!("{}", cex.result_output);
            run_trace_debugger(&cex.trace, cex.loop_start, ta.as_ref())?;
        }
        Commands::Assist { kind, out } => {
            let normalized = kind.trim().to_lowercase();
            let template = assistant_template(&normalized).ok_or_else(|| {
                miette::miette!(
                    "Unknown scaffold kind '{}'. Use pbft | hotstuff | raft | tendermint | streamlet | casper.",
                    kind
                )
            })?;

            if let Some(path) = out {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).into_diagnostic()?;
                }
                fs::write(&path, template).into_diagnostic()?;
                println!("Scaffold written to {}", path.display());
            } else {
                println!("{template}");
            }
        }
        Commands::Codegen {
            file,
            target,
            output,
        } => {
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let program = tarsier_dsl::parse(&source, &filename)
                .map_err(|e| miette::miette!("Parse error: {e}"))?;

            let codegen_target = match target.to_lowercase().as_str() {
                "rust" | "rs" => tarsier_codegen::CodegenTarget::Rust,
                "go" | "golang" => tarsier_codegen::CodegenTarget::Go,
                other => {
                    return Err(miette::miette!(
                        "Unknown codegen target '{}'. Use rust | go.",
                        other
                    ));
                }
            };

            let code = tarsier_codegen::generate(&program, codegen_target)
                .map_err(|e| miette::miette!("Codegen error: {e}"))?;

            let protocol_name = program.protocol.node.name.clone();
            let ext = match codegen_target {
                tarsier_codegen::CodegenTarget::Rust => "rs",
                tarsier_codegen::CodegenTarget::Go => "go",
            };
            let out_file = output.join(format!(
                "{}.{ext}",
                protocol_name.to_lowercase().replace(' ', "_")
            ));

            if let Some(parent) = out_file.parent() {
                fs::create_dir_all(parent).into_diagnostic()?;
            }
            fs::write(&out_file, &code).into_diagnostic()?;
            println!(
                "Generated {} code written to {}",
                target,
                out_file.display()
            );
        }
        Commands::Analyze {
            file,
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
            let source = std::fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();

            let mode = parse_analysis_mode(&mode);
            let solver = parse_solver_choice(&solver);
            let soundness = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
            let fairness = parse_fairness_mode(&fairness);
            let output_format = parse_output_format(&format);
            let cfg = LayerRunCfg {
                solver,
                depth,
                k,
                timeout,
                soundness,
                fairness,
                cegar_iters: 0,
                portfolio,
            };

            let report = run_analysis(&source, &filename, mode, cfg, cli_network_mode);

            let json_report = serde_json::to_string_pretty(&report).into_diagnostic()?;
            if let Some(path) = report_out {
                std::fs::write(path, &json_report).into_diagnostic()?;
            }

            match output_format {
                OutputFormat::Text => println!("{}", render_analysis_text(&report)),
                OutputFormat::Json => println!("{json_report}"),
            }

            if report.overall != "pass" {
                std::process::exit(2);
            }
        }
        Commands::CertifySafety {
            file,
            solver,
            k,
            engine,
            timeout,
            soundness,
            out,
        } => {
            let source = fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: parse_proof_engine(&engine),
            };

            let cert = match tarsier_engine::pipeline::generate_safety_certificate(
                &source, &filename, &options,
            ) {
                Ok(cert) => cert,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };

            let bundle = certificate_bundle_from_safety(&cert);
            write_certificate_bundle(&out, &bundle)?;
        }
        Commands::CertifyFairLiveness {
            file,
            solver,
            k,
            timeout,
            soundness,
            fairness,
            out,
        } => {
            let source = fs::read_to_string(&file).into_diagnostic()?;
            let filename = file.display().to_string();
            let fairness = parse_fairness_mode(&fairness);
            let soundness_mode = parse_soundness_mode(&soundness);
            validate_cli_network_semantics_mode(
                &source,
                &filename,
                soundness_mode,
                cli_network_mode,
            )?;
            let options = PipelineOptions {
                solver: parse_solver_choice(&solver),
                max_depth: k,
                timeout_secs: timeout,
                dump_smt: None,
                soundness: soundness_mode,
                proof_engine: ProofEngine::Pdr,
            };

            let cert = match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
                &source, &filename, &options, fairness,
            ) {
                Ok(cert) => cert,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };

            let bundle = certificate_bundle_from_fair_liveness(&cert);
            write_certificate_bundle(&out, &bundle)?;
        }
        Commands::CheckCertificate {
            bundle,
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
            let integrity = check_bundle_integrity(&bundle).into_diagnostic()?;
            let metadata = integrity.metadata;

            if metadata.kind != CertificateKind::SafetyProof.as_str()
                && metadata.kind != CertificateKind::FairLivenessProof.as_str()
            {
                miette::bail!("Unsupported certificate kind: {}", metadata.kind);
            }

            let mut solver_cmds = parse_solver_list(&solvers);
            solver_cmds.sort();
            solver_cmds.dedup();
            if solver_cmds.is_empty() {
                miette::bail!("No solver commands provided (use --solvers z3,cvc5).");
            }
            validate_trusted_check_requirements(
                trusted_check,
                min_solvers,
                &solver_cmds,
                &metadata,
                rederive,
                proof_checker.as_ref(),
                allow_unchecked_proofs,
            )?;

            let mut had_error = false;
            for issue in integrity.issues {
                had_error = true;
                println!("[FAIL] integrity [{}]: {}", issue.code, issue.message);
            }

            if had_error {
                std::process::exit(2);
            }

            if trusted_check && proof_checker.is_none() && allow_unchecked_proofs {
                println!(
                    "[WARN] trusted-check: --allow-unchecked-proofs enabled; relying on solver UNSAT + proof-shape checks only"
                );
            }

            if rederive {
                match rederive_certificate_bundle_input(&metadata, rederive_timeout) {
                    Ok(rederived_bundle) => {
                        let expected = obligation_triplets_from_metadata(&metadata);
                        let actual = obligation_triplets_from_bundle(&rederived_bundle);
                        if expected != actual {
                            had_error = true;
                            println!(
                                "[FAIL] rederive: certificate obligations differ from freshly generated obligations"
                            );
                            println!(
                                "        (metadata obligations: {}, regenerated obligations: {})",
                                expected.len(),
                                actual.len()
                            );
                        } else {
                            println!(
                                "[PASS] rederive: regenerated obligations match certificate metadata hashes"
                            );
                        }
                    }
                    Err(e) => {
                        had_error = true;
                        println!("[ERROR] rederive: {e}");
                    }
                }
            }

            if had_error {
                std::process::exit(2);
            }

            let emit_proofs_dir = emit_proofs.clone();
            if let Some(dir) = &emit_proofs_dir {
                fs::create_dir_all(dir).into_diagnostic()?;
            }

            let require_proofs = require_proofs || trusted_check;
            let mut obligation_pass_counts = vec![0usize; metadata.obligations.len()];
            let mut obligation_solver_errors = vec![0usize; metadata.obligations.len()];

            for solver_cmd in solver_cmds {
                let mut solver_pass = true;
                let solver_proof_dir = emit_proofs_dir.as_ref().map(|d| d.join(&solver_cmd));
                if let Some(dir) = &solver_proof_dir {
                    fs::create_dir_all(dir).into_diagnostic()?;
                }
                for (obligation_idx, obligation) in metadata.obligations.iter().enumerate() {
                    let obligation_path = bundle.join(&obligation.file);
                    let need_proofs = emit_proofs_dir.is_some() || require_proofs;
                    if need_proofs {
                        match run_external_solver_with_proof(&solver_cmd, &obligation_path) {
                            Ok((result, proof_text)) => {
                                let mut passed = result == obligation.expected;
                                if !passed {
                                    solver_pass = false;
                                    if !trusted_check {
                                        had_error = true;
                                    }
                                    println!(
                                        "[FAIL] {}: {} expected {}, got {}",
                                        solver_cmd, obligation.name, obligation.expected, result
                                    );
                                } else if require_proofs
                                    && obligation.expected == "unsat"
                                    && !proof_object_looks_nontrivial(&proof_text)
                                {
                                    solver_pass = false;
                                    passed = false;
                                    if !trusted_check {
                                        had_error = true;
                                    }
                                    println!(
                                        "[FAIL] {}: {} UNSAT but emitted proof object is empty/malformed",
                                        solver_cmd, obligation.name
                                    );
                                }
                                let mut proof_file_for_check: Option<PathBuf> = None;
                                let mut temp_proof_file: Option<PathBuf> = None;
                                if let Some(dir) = &solver_proof_dir {
                                    let proof_file = dir.join(format!("{}.proof", obligation.name));
                                    if let Err(e) = fs::write(&proof_file, &proof_text) {
                                        solver_pass = false;
                                        obligation_solver_errors[obligation_idx] += 1;
                                        if !trusted_check {
                                            had_error = true;
                                        }
                                        println!(
                                            "[ERROR] {}: failed writing proof file {}: {}",
                                            solver_cmd,
                                            proof_file.display(),
                                            e
                                        );
                                        passed = false;
                                    } else {
                                        proof_file_for_check = Some(proof_file);
                                    }
                                } else if proof_checker.is_some() && obligation.expected == "unsat"
                                {
                                    let temp_path = std::env::temp_dir().join(format!(
                                        "tarsier-proof-{}-{}-{}-{}.proof",
                                        std::process::id(),
                                        solver_cmd,
                                        obligation_idx,
                                        obligation.name
                                    ));
                                    if let Err(e) = fs::write(&temp_path, &proof_text) {
                                        solver_pass = false;
                                        obligation_solver_errors[obligation_idx] += 1;
                                        if !trusted_check {
                                            had_error = true;
                                        }
                                        println!(
                                            "[ERROR] {}: failed writing temporary proof file {}: {}",
                                            solver_cmd,
                                            temp_path.display(),
                                            e
                                        );
                                        passed = false;
                                    } else {
                                        proof_file_for_check = Some(temp_path.clone());
                                        temp_proof_file = Some(temp_path);
                                    }
                                }

                                if passed && obligation.expected == "unsat" && result == "unsat" {
                                    if let Some(checker) = proof_checker.as_ref() {
                                        if let Some(proof_file) = &proof_file_for_check {
                                            if let Err(e) = run_external_proof_checker(
                                                checker,
                                                &solver_cmd,
                                                &obligation_path,
                                                proof_file,
                                            ) {
                                                solver_pass = false;
                                                obligation_solver_errors[obligation_idx] += 1;
                                                if !trusted_check {
                                                    had_error = true;
                                                }
                                                passed = false;
                                                println!(
                                                    "[FAIL] {}: {} ({e})",
                                                    solver_cmd, obligation.name
                                                );
                                            }
                                        } else {
                                            solver_pass = false;
                                            obligation_solver_errors[obligation_idx] += 1;
                                            if !trusted_check {
                                                had_error = true;
                                            }
                                            passed = false;
                                            println!(
                                                "[FAIL] {}: {} no proof file available for --proof-checker",
                                                solver_cmd, obligation.name
                                            );
                                        }
                                    }
                                }

                                if passed {
                                    obligation_pass_counts[obligation_idx] += 1;
                                }

                                if let Some(temp_path) = temp_proof_file {
                                    let _ = fs::remove_file(temp_path);
                                }
                            }
                            Err(e) => {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!("[ERROR] {}: {}", solver_cmd, e);
                            }
                        }
                    } else {
                        match run_external_solver_on_file(&solver_cmd, &obligation_path) {
                            Ok(result) if result == obligation.expected => {
                                obligation_pass_counts[obligation_idx] += 1;
                            }
                            Ok(result) => {
                                solver_pass = false;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!(
                                    "[FAIL] {}: {} expected {}, got {}",
                                    solver_cmd, obligation.name, obligation.expected, result
                                );
                            }
                            Err(e) => {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!("[ERROR] {}: {}", solver_cmd, e);
                            }
                        }
                    }
                }
                if solver_pass {
                    println!(
                        "[PASS] {}: all {} obligations satisfied",
                        solver_cmd,
                        metadata.obligations.len()
                    );
                    if let Some(dir) = &solver_proof_dir {
                        println!(
                            "[PASS] {}: proof objects written to {}",
                            solver_cmd,
                            dir.display()
                        );
                    }
                } else {
                    println!("[FAIL] {}: one or more obligations failed", solver_cmd);
                }
            }

            if trusted_check {
                let mut consensus_failures = 0usize;
                for (idx, obligation) in metadata.obligations.iter().enumerate() {
                    let confirmations = obligation_pass_counts[idx];
                    if confirmations < min_solvers {
                        consensus_failures += 1;
                        println!(
                            "[FAIL] trusted-check: obligation '{}' has {} confirmation(s), requires {}.",
                            obligation.name, confirmations, min_solvers
                        );
                    } else {
                        println!(
                            "[PASS] trusted-check: obligation '{}' confirmed by {} solver(s).",
                            obligation.name, confirmations
                        );
                    }
                    if obligation_solver_errors[idx] > 0 {
                        println!(
                            "[WARN] trusted-check: obligation '{}' had {} solver execution/proof I/O error(s).",
                            obligation.name, obligation_solver_errors[idx]
                        );
                    }
                }
                if consensus_failures > 0 {
                    had_error = true;
                }
            }

            if had_error {
                std::process::exit(2);
            } else {
                println!(
                    "Certificate verified for kind '{}' with engine '{}' (k/frame: {}).",
                    metadata.kind,
                    metadata.proof_engine,
                    metadata
                        .induction_k
                        .map(|k| k.to_string())
                        .unwrap_or_else(|| "n/a".to_string())
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        assistant_template, augment_query_for_proof, canonicalize_obligation_smt2,
        classify_cert_suite_check_triage, compute_bundle_sha256, detect_prove_auto_target,
        expected_matches, has_independent_solver, lint_protocol_file, obligations_all_unsat,
        parse_cli_network_semantics_mode, parse_manifest_fairness_mode,
        parse_manifest_proof_engine, parse_visualize_check, parse_visualize_format,
        proof_object_looks_nontrivial, sha256_hex_bytes, validate_manifest_entry_contract,
        validate_manifest_expected_result, validate_manifest_library_coverage,
        validate_manifest_top_level_contract, validate_trusted_check_requirements,
        write_certificate_bundle, CertSuiteEntry, CertSuiteManifest, CertificateBundleInput,
        CertificateBundleObligation, CertificateKind, CertificateMetadata,
        CertificateObligationMeta, Cli, CliNetworkSemanticsMode, Commands, DebugFilter,
        FairnessMode, ProofEngine, ProveAutoTarget, SoundnessMode, VisualizeCheck, VisualizeFormat,
        CERTIFICATE_SCHEMA_VERSION, CERT_SUITE_SCHEMA_VERSION,
    };
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tarsier_ir::counter_system::{
        MessageAuthMetadata, MessageDeliveryEvent, MessageEventKind, MessageIdentity,
        MessagePayloadVariant, SignatureProvenance,
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

        write_certificate_bundle(&out_a, &input_a).expect("bundle a should be written");
        write_certificate_bundle(&out_b, &input_b).expect("bundle b should be written");

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
    fn proof_object_nontrivial_heuristic_rejects_empty_or_malformed() {
        assert!(!proof_object_looks_nontrivial("unsat\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(error \"oops\")\n"));
        assert!(!proof_object_looks_nontrivial("unsat\n(abc\n"));
    }

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

        let mut variant_filter = DebugFilter::default();
        variant_filter.payload_variant = Some("view=2".into());
        assert!(variant_filter.matches(&event));
        variant_filter.payload_variant = Some("view=3".into());
        assert!(!variant_filter.matches(&event));

        let mut field_filter = DebugFilter::default();
        field_filter.payload_field = Some(("value".into(), "true".into()));
        assert!(field_filter.matches(&event));
        field_filter.payload_field = Some(("value".into(), "false".into()));
        assert!(!field_filter.matches(&event));
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
    fn expected_match_is_case_insensitive() {
        assert!(expected_matches("SAFE", "safe"));
        assert!(!expected_matches("unsafe", "safe"));
    }

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

    fn sample_cert_suite_manifest() -> CertSuiteManifest {
        CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
            library_dir: None,
            entries: vec![sample_cert_suite_entry()],
        }
    }

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

    #[test]
    fn manifest_expected_outcomes_reject_invalid_values() {
        let err = validate_manifest_expected_result("verify", "live")
            .expect_err("verify should reject liveness outcomes");
        assert!(err.contains("Invalid expected outcome"));
    }

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

    #[test]
    fn cert_suite_schema_v2_requires_family_and_valid_class() {
        let mut entry = sample_cert_suite_entry();
        entry.family = None;
        entry.class = Some("other".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
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

    #[test]
    fn cert_suite_schema_v2_requires_known_bug_regression_sentinel_presence() {
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
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

    #[test]
    fn cert_suite_known_bug_entries_require_bug_sentinel_outcome() {
        let mut entry = sample_cert_suite_entry();
        entry.class = Some("known_bug".into());
        entry.verify = Some("safe".into());
        let manifest = CertSuiteManifest {
            schema_version: CERT_SUITE_SCHEMA_VERSION,
            enforce_library_coverage: false,
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

    #[test]
    fn trusted_check_requires_proof_checker_by_default() {
        let metadata = sample_metadata();
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        let err =
            validate_trusted_check_requirements(true, 2, &solvers, &metadata, true, None, false)
                .expect_err("trusted-check should fail without proof checker");
        assert!(err.to_string().contains("--proof-checker"));
    }

    #[test]
    fn trusted_check_allows_unchecked_proofs_only_with_explicit_override() {
        let metadata = sample_metadata();
        let solvers = vec!["z3".to_string(), "cvc5".to_string()];
        validate_trusted_check_requirements(true, 2, &solvers, &metadata, true, None, true)
            .expect("explicit override should allow weaker trusted-check mode");
    }
}
