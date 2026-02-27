//! CLI argument definitions: top-level `Cli` struct and `Commands` enum.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(not(feature = "governance"))]
pub(crate) const CLI_LONG_ABOUT: &str =
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
pub(crate) const CLI_LONG_ABOUT: &str =
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
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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

    /// Watch a .trs file and re-run verification on changes
    #[command(display_order = 5)]
    Watch {
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

        /// Run Z3 and cvc5 in parallel and combine proof outcomes conservatively
        #[arg(long, default_value_t = false)]
        portfolio: bool,

        /// Output format: text | json
        #[arg(long, default_value = "text")]
        format: String,
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
