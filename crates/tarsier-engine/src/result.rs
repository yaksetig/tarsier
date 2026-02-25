use serde::Serialize;
use std::fmt;
use tarsier_ir::counter_system::Trace;

/// JSON schema version for communication/quantitative outputs.
pub const QUANTITATIVE_SCHEMA_VERSION: u32 = 2;
/// Human-readable schema contract document.
pub const QUANTITATIVE_SCHEMA_DOC_PATH: &str = "docs/QUANTITATIVE_SCHEMA.md";
/// Machine-readable JSON schema for quantitative outputs.
pub const QUANTITATIVE_SCHEMA_JSON_PATH: &str = "docs/quantitative-schema-v2.json";

/// Classification of a quantitative bound.
#[derive(Debug, Clone, Serialize)]
pub enum BoundKind {
    #[serde(rename = "upper_bound")]
    UpperBound,
    #[serde(rename = "lower_bound")]
    LowerBound,
    #[serde(rename = "estimate")]
    Estimate,
    #[serde(rename = "exact")]
    Exact,
}

/// Evidence class for a bound annotation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum BoundEvidenceClass {
    #[serde(rename = "theorem_backed")]
    TheoremBacked,
    #[serde(rename = "heuristic_estimate")]
    HeuristicEstimate,
}

/// Documents the kind and meaning of a metric field.
#[derive(Debug, Clone, Serialize)]
pub struct BoundAnnotation {
    pub field: String,
    pub kind: BoundKind,
    pub evidence_class: BoundEvidenceClass,
    pub description: String,
    /// Explicit assumptions that justify this metric interpretation.
    pub assumptions: Vec<String>,
}

/// Model assumptions under which the quantitative results hold.
#[derive(Debug, Clone, Serialize)]
pub struct ModelAssumptions {
    pub fault_model: String,
    pub timing_model: String,
    pub authentication_mode: String,
    pub equivocation_mode: String,
    pub network_semantics: String,
    pub gst_param: Option<String>,
}

/// Ties quantitative results to the exact verified model revision and options.
#[derive(Debug, Clone, Serialize)]
pub struct ModelMetadata {
    pub source_hash: String,
    pub filename: String,
    pub analysis_depth: usize,
    pub engine_version: String,
    pub analysis_options: QuantitativeAnalysisOptions,
    pub analysis_environment: QuantitativeAnalysisEnvironment,
    /// Fingerprint over source hash + options + environment + engine version.
    pub reproducibility_fingerprint: String,
}

/// Explicit options used to produce a quantitative report.
#[derive(Debug, Clone, Serialize)]
pub struct QuantitativeAnalysisOptions {
    pub command: String,
    pub depth: usize,
}

/// Execution environment metadata for report reproducibility.
#[derive(Debug, Clone, Serialize)]
pub struct QuantitativeAnalysisEnvironment {
    pub target_os: String,
    pub target_arch: String,
    pub target_family: String,
    pub build_profile: String,
}

/// A single point in a sensitivity analysis sweep.
#[derive(Debug, Clone, Serialize)]
pub struct SensitivityPoint {
    pub parameter: String,
    pub base_value: f64,
    pub varied_value: f64,
    pub metric: String,
    pub base_result: f64,
    pub varied_result: f64,
}

/// Confidence interval metadata for probabilistic quantitative metrics.
#[derive(Debug, Clone, Serialize)]
pub struct ProbabilisticConfidenceInterval {
    /// Metric field name.
    pub metric: String,
    /// Central confidence level (for example 0.95).
    pub level: f64,
    /// Lower endpoint of the interval.
    pub lower: f64,
    /// Upper endpoint of the interval.
    pub upper: f64,
    /// Number of sensitivity samples used to derive the interval.
    pub sample_size: usize,
    /// Derivation method label.
    pub method: String,
    /// Assumptions needed for this interval interpretation.
    pub assumptions: Vec<String>,
}

/// Assumption validation notes: warnings or notes about applicability.
#[derive(Debug, Clone, Serialize)]
pub struct AssumptionNote {
    pub level: String,
    pub message: String,
}

/// Summary of a committee analysis for inclusion in verification results.
#[derive(Debug, Clone)]
pub struct CommitteeAnalysisSummary {
    /// Committee name.
    pub name: String,
    /// Committee size.
    pub committee_size: u64,
    /// Population size.
    pub population: u64,
    /// Number of Byzantine in population.
    pub byzantine: u64,
    /// Derived maximum Byzantine in committee.
    pub b_max: u64,
    /// Target epsilon.
    pub epsilon: f64,
    /// Actual tail probability P(X > b_max).
    pub tail_probability: f64,
    /// Honest nodes in committee.
    pub honest_majority: u64,
    /// Expected Byzantine in committee.
    pub expected_byzantine: f64,
}

/// The result of a verification run.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// The property holds up to the checked depth.
    Safe { depth_checked: usize },
    /// The property holds probabilistically (with committee selection).
    ProbabilisticallySafe {
        depth_checked: usize,
        failure_probability: f64,
        committee_analyses: Vec<CommitteeAnalysisSummary>,
    },
    /// The property is violated — counterexample found.
    Unsafe { trace: Trace },
    /// Verification was inconclusive.
    Unknown { reason: String },
}

impl VerificationResult {
    /// Machine-readable verdict class for reproducibility checks.
    ///
    /// Returns a stable string that depends only on the variant, not on
    /// internal details like depth or trace content. Two runs with the
    /// same input/options that produce the same `verdict_class()` are
    /// considered reproducible.
    pub fn verdict_class(&self) -> &'static str {
        match self {
            VerificationResult::Safe { .. } => "safe",
            VerificationResult::ProbabilisticallySafe { .. } => "probabilistically_safe",
            VerificationResult::Unsafe { .. } => "unsafe",
            VerificationResult::Unknown { .. } => "unknown",
        }
    }
}

/// Verdict for a single named property.
#[derive(Debug, Clone)]
pub struct PropertyVerdict {
    /// The property name from the DSL declaration.
    pub name: String,
    /// The quantified fragment this property was classified into.
    pub fragment: String,
    /// The verification result for this property.
    pub result: VerificationResult,
}

/// Combined result of verifying multiple named properties independently.
#[derive(Debug, Clone)]
pub struct MultiPropertyResult {
    /// Per-property verdicts in declaration order.
    pub verdicts: Vec<PropertyVerdict>,
}

impl MultiPropertyResult {
    /// True if all properties were verified as Safe (or ProbabilisticallySafe).
    pub fn all_safe(&self) -> bool {
        self.verdicts.iter().all(|v| {
            matches!(
                v.result,
                VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
            )
        })
    }

    /// True if any property was found Unsafe.
    pub fn any_unsafe(&self) -> bool {
        self.verdicts
            .iter()
            .any(|v| matches!(v.result, VerificationResult::Unsafe { .. }))
    }

    /// Overall summary: "safe", "unsafe", or "inconclusive".
    pub fn overall_verdict(&self) -> &'static str {
        if self.any_unsafe() {
            "unsafe"
        } else if self.all_safe() {
            "safe"
        } else {
            "inconclusive"
        }
    }
}

/// Outcome of a single CEGAR stage.
#[derive(Debug, Clone)]
pub enum CegarStageOutcome {
    Safe {
        depth_checked: usize,
    },
    ProbabilisticallySafe {
        depth_checked: usize,
        failure_probability: f64,
        committee_count: usize,
    },
    Unsafe {
        trace: Trace,
    },
    Unknown {
        reason: String,
    },
}

/// Counterexample quality assessment emitted by CEGAR analysis.
///
/// Classification values:
/// - `concrete`: witness persists under stricter refinements.
/// - `potentially_spurious`: witness is eliminated by stricter refinements.
/// - `inconclusive`: witness could not be confirmed/eliminated decisively.
#[derive(Debug, Clone)]
pub struct CegarCounterexampleAnalysis {
    pub classification: String,
    pub rationale: String,
}

/// One explicit model change applied at a CEGAR stage.
#[derive(Debug, Clone)]
pub struct CegarModelChange {
    /// Change category: `adversary` / `channel` / `equivocation`.
    pub category: String,
    /// Changed key or message identifier.
    pub target: String,
    /// Effective value before this stage refinement.
    pub before: String,
    /// Effective value after this stage refinement.
    pub after: String,
    /// Predicate label associated with this change.
    pub predicate: String,
}

/// A trace eliminated by stage refinements.
#[derive(Debug, Clone)]
pub struct CegarEliminatedTrace {
    /// Stable kind identifier.
    pub kind: String,
    /// Stage index that originally produced this trace.
    pub source_stage: usize,
    /// Refinements that eliminated this trace at current stage.
    pub eliminated_by: Vec<String>,
    /// Why this trace is considered eliminated.
    pub rationale: String,
    /// The eliminated trace witness.
    pub trace: Trace,
}

/// Scored predicate with evidence tags and impact estimate for machine-readable output.
#[derive(Debug, Clone)]
pub struct CegarPredicateScore {
    /// Predicate label (e.g., `equivocation_none`, `values_exact`).
    pub predicate: String,
    /// Raw heuristic score (higher = more likely to eliminate spurious witness).
    pub score: i32,
    /// Evidence tags from trace signal analysis that support this predicate.
    pub evidence_tags: Vec<String>,
    /// Number of trace steps this refinement would affect (impact estimate).
    pub affected_steps: usize,
    /// Whether this predicate was selected by the UNSAT-core minimization phase.
    pub unsat_core_selected: bool,
}

/// Audit entry for one CEGAR stage.
#[derive(Debug, Clone)]
pub struct CegarStageReport {
    /// Stage index in execution order (0 = baseline).
    pub stage: usize,
    /// Human-readable label for this stage.
    pub label: String,
    /// Refinements applied relative to baseline.
    pub refinements: Vec<String>,
    /// Result of this stage.
    pub outcome: CegarStageOutcome,
    /// Optional explanatory note.
    pub note: Option<String>,
    /// Explicit stage model changes.
    pub model_changes: Vec<CegarModelChange>,
    /// Traces eliminated at this stage.
    pub eliminated_traces: Vec<CegarEliminatedTrace>,
    /// Predicates discovered/effective at this stage.
    pub discovered_predicates: Vec<String>,
    /// Optional witness-quality analysis for this stage.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Scored predicates with evidence and impact estimates.
    pub scored_predicates: Vec<CegarPredicateScore>,
}

/// Machine-readable CEGAR execution report.
#[derive(Debug, Clone)]
pub struct CegarAuditReport {
    /// User-configured refinement budget.
    pub max_refinements: usize,
    /// Full stage-by-stage outcomes.
    pub stages: Vec<CegarStageReport>,
    /// Refinement predicates that eliminated at least one baseline counterexample.
    pub discovered_predicates: Vec<String>,
    /// Coarse CEGAR classification:
    /// - safe
    /// - unsafe_unrefined
    /// - unsafe_confirmed
    /// - timeout
    /// - inconclusive
    pub classification: String,
    /// Counterexample quality analysis for the overall run.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Deterministic termination metadata (budget use and stop reason).
    pub termination: CegarTermination,
    /// Final verification result reported to users.
    pub final_result: VerificationResult,
}

/// How a CEGAR refinement run terminated.
#[derive(Debug, Clone)]
pub struct CegarTermination {
    /// Stable reason code (machine-readable).
    pub reason: String,
    /// Configured maximum number of refinement stages.
    pub iteration_budget: usize,
    /// Number of refinement stages that actually executed (excludes baseline stage 0).
    pub iterations_used: usize,
    /// Time budget inherited from pipeline options.
    pub timeout_secs: u64,
    /// End-to-end elapsed runtime for this CEGAR report generation.
    pub elapsed_ms: u128,
    /// Whether we stopped due to hitting iteration budget.
    pub reached_iteration_budget: bool,
    /// Whether we stopped due to timeout budget exhaustion.
    pub reached_timeout_budget: bool,
}

/// Machine-readable controls used for CEGAR-enabled proof runs.
#[derive(Debug, Clone)]
pub struct CegarRunControls {
    /// User-configured refinement budget.
    pub max_refinements: usize,
    /// Time budget inherited from pipeline options.
    pub timeout_secs: u64,
    /// Solver backend label (`z3`/`cvc5`).
    pub solver: String,
    /// Proof engine label (`kinduction`/`pdr`), when applicable.
    pub proof_engine: Option<String>,
    /// Fairness mode label (`weak`/`strong`), for fair-liveness runs.
    pub fairness: Option<String>,
}

/// Machine-readable CEGAR report for unbounded safety proof runs.
#[derive(Debug, Clone)]
pub struct UnboundedSafetyCegarAuditReport {
    /// Controls used for this run.
    pub controls: CegarRunControls,
    /// Full stage-by-stage outcomes (stage 0 = baseline).
    pub stages: Vec<UnboundedSafetyCegarStageReport>,
    /// Refinement predicates that eliminated at least one baseline witness.
    pub discovered_predicates: Vec<String>,
    /// Baseline unrefined run result.
    pub baseline_result: UnboundedSafetyResult,
    /// Final CEGAR-refined run result.
    pub final_result: UnboundedSafetyResult,
    /// Coarse CEGAR classification.
    pub classification: String,
    /// Counterexample quality analysis for the overall run.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Deterministic termination metadata (budget use and stop reason).
    pub termination: CegarTermination,
}

/// Machine-readable CEGAR report for unbounded fair-liveness proof runs.
#[derive(Debug, Clone)]
pub struct UnboundedFairLivenessCegarAuditReport {
    /// Controls used for this run.
    pub controls: CegarRunControls,
    /// Full stage-by-stage outcomes (stage 0 = baseline).
    pub stages: Vec<UnboundedFairLivenessCegarStageReport>,
    /// Refinement predicates that eliminated at least one baseline witness.
    pub discovered_predicates: Vec<String>,
    /// Baseline unrefined run result.
    pub baseline_result: UnboundedFairLivenessResult,
    /// Final CEGAR-refined run result.
    pub final_result: UnboundedFairLivenessResult,
    /// Coarse CEGAR classification.
    pub classification: String,
    /// Counterexample quality analysis for the overall run.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Deterministic termination metadata (budget use and stop reason).
    pub termination: CegarTermination,
}

/// Outcome of a single CEGAR stage for unbounded safety proofs.
#[derive(Debug, Clone)]
pub enum UnboundedSafetyCegarStageOutcome {
    Safe {
        induction_k: usize,
    },
    ProbabilisticallySafe {
        induction_k: usize,
        failure_probability: f64,
        committee_count: usize,
    },
    Unsafe {
        trace: Trace,
    },
    NotProved {
        max_k: usize,
        cti: Option<InductionCtiSummary>,
    },
    Unknown {
        reason: String,
    },
}

/// Stage report entry for unbounded safety CEGAR runs.
#[derive(Debug, Clone)]
pub struct UnboundedSafetyCegarStageReport {
    /// Stage index in execution order (0 = baseline).
    pub stage: usize,
    /// Human-readable label for this stage.
    pub label: String,
    /// Refinements applied relative to baseline.
    pub refinements: Vec<String>,
    /// Result of this stage.
    pub outcome: UnboundedSafetyCegarStageOutcome,
    /// Optional explanatory note.
    pub note: Option<String>,
    /// Explicit stage model changes.
    pub model_changes: Vec<CegarModelChange>,
    /// Traces eliminated at this stage.
    pub eliminated_traces: Vec<CegarEliminatedTrace>,
    /// Predicates discovered/effective at this stage.
    pub discovered_predicates: Vec<String>,
    /// Optional witness-quality analysis for this stage.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Scored predicates with evidence and impact estimates.
    pub scored_predicates: Vec<CegarPredicateScore>,
}

/// Outcome of a single CEGAR stage for unbounded fair-liveness proofs.
#[derive(Debug, Clone)]
pub enum UnboundedFairLivenessCegarStageOutcome {
    LiveProved {
        frame: usize,
    },
    FairCycleFound {
        depth: usize,
        loop_start: usize,
        trace: Trace,
    },
    NotProved {
        max_k: usize,
    },
    Unknown {
        reason: String,
    },
}

/// Stage report entry for unbounded fair-liveness CEGAR runs.
#[derive(Debug, Clone)]
pub struct UnboundedFairLivenessCegarStageReport {
    /// Stage index in execution order (0 = baseline).
    pub stage: usize,
    /// Human-readable label for this stage.
    pub label: String,
    /// Refinements applied relative to baseline.
    pub refinements: Vec<String>,
    /// Result of this stage.
    pub outcome: UnboundedFairLivenessCegarStageOutcome,
    /// Optional explanatory note.
    pub note: Option<String>,
    /// Explicit stage model changes.
    pub model_changes: Vec<CegarModelChange>,
    /// Traces eliminated at this stage.
    pub eliminated_traces: Vec<CegarEliminatedTrace>,
    /// Predicates discovered/effective at this stage.
    pub discovered_predicates: Vec<String>,
    /// Optional witness-quality analysis for this stage.
    pub counterexample_analysis: Option<CegarCounterexampleAnalysis>,
    /// Scored predicates with evidence and impact estimates.
    pub scored_predicates: Vec<CegarPredicateScore>,
}

/// The result of a bounded liveness check.
#[derive(Debug)]
pub enum LivenessResult {
    /// All processes satisfy the configured liveness target by the checked depth.
    Live { depth_checked: usize },
    /// A counterexample where some processes do not satisfy the liveness target by the bound.
    NotLive { trace: Trace },
    /// Check was inconclusive.
    Unknown { reason: String },
}

// ---------------------------------------------------------------------------
// Fairness semantics documentation (first-class in reports)
// ---------------------------------------------------------------------------

/// Formal semantics of the fairness assumption used in a liveness proof.
///
/// This struct is designed to be included in machine-readable reports so that
/// consumers know exactly what fairness guarantee the verdict relies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessSemantics {
    /// Fairness mode label: `"weak"` or `"strong"`.
    pub mode: String,
    /// Formal name in the literature.
    pub formal_name: String,
    /// Precise semantic definition.
    pub definition: String,
    /// What the verdict means under this fairness assumption.
    pub verdict_interpretation: String,
}

impl FairnessSemantics {
    /// Construct the semantics descriptor for weak fairness (justice).
    pub fn weak() -> Self {
        Self {
            mode: "weak".into(),
            formal_name: "Justice (weak fairness)".into(),
            definition: "For every transition rule r, if r is continuously enabled \
                         from some point onward in an execution, then r must \
                         eventually fire. Formally: GF(enabled(r)) ∧ FG(enabled(r)) \
                         → GF(fired(r))."
                .into(),
            verdict_interpretation: "LiveProved means no fair execution (under weak \
                                     fairness) violates the liveness property. An \
                                     unfair execution — where a perpetually enabled \
                                     rule never fires — is excluded from \
                                     consideration."
                .into(),
        }
    }

    /// Construct the semantics descriptor for strong fairness (compassion).
    pub fn strong() -> Self {
        Self {
            mode: "strong".into(),
            formal_name: "Compassion (strong fairness)".into(),
            definition: "For every transition rule r, if r is enabled infinitely \
                         often in an execution, then r must fire infinitely often. \
                         Formally: GF(enabled(r)) → GF(fired(r))."
                .into(),
            verdict_interpretation: "LiveProved means no fair execution (under strong \
                                     fairness) violates the liveness property. Strong \
                                     fairness is strictly stronger than weak: every \
                                     strongly-fair execution is also weakly-fair, but \
                                     not vice versa."
                .into(),
        }
    }
}

impl std::fmt::Display for FairnessSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.formal_name, self.mode)
    }
}

// ---------------------------------------------------------------------------
// Machine-readable unknown reason taxonomy
// ---------------------------------------------------------------------------

/// Structured reason code for inconclusive liveness proof outcomes.
///
/// Instead of ad-hoc reason strings, this taxonomy provides machine-readable
/// codes that tools and CI systems can match on deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivenessUnknownReason {
    /// Overall wall-clock timeout exceeded during proof search.
    Timeout {
        /// The frontier frame reached before timeout.
        frontier_frame: usize,
        /// Which phase timed out.
        phase: String,
    },
    /// Configured memory budget exceeded during proof search.
    MemoryBudgetExceeded {
        /// RSS observed when budget enforcement fired.
        rss_bytes: u64,
        /// Configured RSS cap.
        limit_bytes: u64,
        /// The frontier frame reached before stopping (if known).
        frontier_frame: usize,
        /// Which phase exceeded the budget.
        phase: String,
    },
    /// Adaptive cube budget exhausted — state space too large for the
    /// current abstraction level.
    CubeBudgetExhausted {
        /// Number of bad cubes blocked before budget was hit.
        cubes_blocked: usize,
        /// The frontier frame at which the budget was exhausted.
        frontier_frame: usize,
    },
    /// The SMT solver returned "unknown" for a key query.
    SolverUnknown {
        /// The solver's own reason string.
        solver_reason: String,
    },
    /// Fair PDR found a reachable accepting state but bounded lasso
    /// recovery failed to materialize a concrete trace.
    LassoRecoveryFailed,
    /// CEGAR refinements eliminated the baseline witness but no
    /// confirmed cycle or proof was produced.
    CegarRefinementInconclusive {
        /// Predicates discovered during refinement.
        discovered_predicates: Vec<String>,
    },
    /// CEGAR refinement ladder exhausted without resolution.
    CegarLadderExhausted,
}

impl LivenessUnknownReason {
    /// Machine-readable short code for this reason.
    pub fn code(&self) -> &'static str {
        match self {
            LivenessUnknownReason::Timeout { .. } => "timeout",
            LivenessUnknownReason::MemoryBudgetExceeded { .. } => "memory_budget_exceeded",
            LivenessUnknownReason::CubeBudgetExhausted { .. } => "cube_budget_exhausted",
            LivenessUnknownReason::SolverUnknown { .. } => "solver_unknown",
            LivenessUnknownReason::LassoRecoveryFailed => "lasso_recovery_failed",
            LivenessUnknownReason::CegarRefinementInconclusive { .. } => {
                "cegar_refinement_inconclusive"
            }
            LivenessUnknownReason::CegarLadderExhausted => "cegar_ladder_exhausted",
        }
    }
}

impl std::fmt::Display for LivenessUnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LivenessUnknownReason::Timeout {
                frontier_frame,
                phase,
            } => {
                write!(
                    f,
                    "Timeout exceeded at frontier frame {frontier_frame} during {phase}."
                )
            }
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes,
                limit_bytes,
                frontier_frame,
                phase,
            } => {
                write!(
                    f,
                    "Memory budget exceeded at frontier frame {frontier_frame} \
                     during {phase}: rss_bytes={rss_bytes}, limit_bytes={limit_bytes}."
                )
            }
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked,
                frontier_frame,
            } => {
                write!(
                    f,
                    "Blocked {cubes_blocked} bad cubes at frame {frontier_frame} \
                     (adaptive budget exhausted); state space appears too large \
                     for current abstraction."
                )
            }
            LivenessUnknownReason::SolverUnknown { solver_reason } => {
                write!(f, "SMT solver returned unknown: {solver_reason}")
            }
            LivenessUnknownReason::LassoRecoveryFailed => {
                write!(
                    f,
                    "Fair PDR found a reachable accepting state, but bounded \
                     lasso recovery did not return a concrete trace."
                )
            }
            LivenessUnknownReason::CegarRefinementInconclusive {
                discovered_predicates,
            } => {
                write!(
                    f,
                    "CEGAR refinements eliminated the baseline fair-cycle witness \
                     but no confirmed cycle or proof was produced"
                )?;
                if !discovered_predicates.is_empty() {
                    write!(f, " (predicates: {})", discovered_predicates.join(", "))?;
                }
                write!(f, ".")
            }
            LivenessUnknownReason::CegarLadderExhausted => {
                write!(
                    f,
                    "CEGAR refinement ladder exhausted without a confirmed \
                     fair cycle or elimination witness."
                )
            }
        }
    }
}

/// Sentinel substrings used to classify unstructured reason strings.
///
/// These constants are the canonical patterns matched by
/// [`LivenessUnknownReason::classify`].  Pipeline code that constructs
/// reason strings should include the relevant sentinel so that
/// classification remains in sync.
pub mod reason_sentinels {
    pub const TIMEOUT_EXCEEDED: &str = "timeout exceeded";
    pub const TIMED_OUT: &str = "timed out";
    pub const MEMORY_BUDGET: &str = "memory budget exceeded";
    pub const BAD_CUBES: &str = "bad cubes";
    pub const ADAPTIVE_BUDGET: &str = "adaptive budget";
    pub const LASSO_RECOVERY: &str = "lasso recovery";
    pub const BOUNDED_LASSO: &str = "bounded lasso";
    pub const REFINEMENTS_ELIMINATED: &str = "refinements eliminated";
    pub const REFINEMENTS_INCONCLUSIVE: &str = "refinements were inconclusive";
    pub const LADDER_EXHAUSTED: &str = "refinement ladder exhausted";
    pub const CEGAR_PHASE: &str = "CEGAR";
}

impl LivenessUnknownReason {
    /// Classify an unstructured reason string into a machine-readable code.
    ///
    /// This parses ad-hoc reason strings produced by the pipeline into
    /// structured [`LivenessUnknownReason`] variants.  The sentinel
    /// substrings are defined in [`reason_sentinels`].
    pub fn classify(reason: &str) -> Self {
        use reason_sentinels::*;
        if reason.contains(TIMEOUT_EXCEEDED) || reason.contains(TIMED_OUT) {
            // Extract frontier frame number if present.
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| s.trim_end_matches('.').parse::<usize>().ok())
                .unwrap_or(0);
            let phase = if reason.contains(CEGAR_PHASE) {
                "cegar".to_string()
            } else {
                "fair_pdr".to_string()
            };
            LivenessUnknownReason::Timeout {
                frontier_frame,
                phase,
            }
        } else if reason.contains(MEMORY_BUDGET) {
            let rss_bytes = reason
                .split("rss_bytes=")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let limit_bytes = reason
                .split("limit_bytes=")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| {
                    s.trim_end_matches('.')
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let phase = if reason.contains("lasso search") {
                "fair_lasso".to_string()
            } else if reason.contains(CEGAR_PHASE) {
                "cegar".to_string()
            } else {
                "fair_pdr".to_string()
            };
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes,
                limit_bytes,
                frontier_frame,
                phase,
            }
        } else if reason.contains(BAD_CUBES) || reason.contains(ADAPTIVE_BUDGET) {
            let cubes_blocked = reason
                .split("over ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| {
                    s.trim_end_matches('.')
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or(0);
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked,
                frontier_frame,
            }
        } else if reason.contains(LASSO_RECOVERY) || reason.contains(BOUNDED_LASSO) {
            LivenessUnknownReason::LassoRecoveryFailed
        } else if reason.contains(REFINEMENTS_ELIMINATED)
            || reason.contains(REFINEMENTS_INCONCLUSIVE)
        {
            LivenessUnknownReason::CegarRefinementInconclusive {
                discovered_predicates: Vec::new(),
            }
        } else if reason.contains(LADDER_EXHAUSTED) {
            LivenessUnknownReason::CegarLadderExhausted
        } else {
            LivenessUnknownReason::SolverUnknown {
                solver_reason: reason.to_string(),
            }
        }
    }
}

/// Result of bounded fair-liveness search via lasso detection.
#[derive(Debug, Clone)]
pub enum FairLivenessResult {
    /// No fair non-terminating lasso was found up to the checked depth.
    NoFairCycleUpTo { depth_checked: usize },
    /// Found a fair non-terminating lasso counterexample.
    FairCycleFound {
        depth: usize,
        loop_start: usize,
        trace: Trace,
    },
    /// Search was inconclusive.
    Unknown { reason: String },
}

/// Result of unbounded fair-liveness proof attempts.
#[derive(Debug, Clone)]
pub enum UnboundedFairLivenessResult {
    /// Proven live under the selected fairness semantics.
    LiveProved { frame: usize },
    /// Found a fair non-terminating lasso counterexample.
    FairCycleFound {
        depth: usize,
        loop_start: usize,
        trace: Trace,
    },
    /// Proof did not converge up to the requested frame bound.
    NotProved { max_k: usize },
    /// Attempt was inconclusive.
    Unknown { reason: String },
}

impl UnboundedFairLivenessResult {
    /// Machine-readable verdict class for reproducibility checks.
    pub fn verdict_class(&self) -> &'static str {
        match self {
            UnboundedFairLivenessResult::LiveProved { .. } => "live_proved",
            UnboundedFairLivenessResult::FairCycleFound { .. } => "fair_cycle_found",
            UnboundedFairLivenessResult::NotProved { .. } => "not_proved",
            UnboundedFairLivenessResult::Unknown { .. } => "unknown",
        }
    }
}

/// Classification of a counterexample-to-induction (CTI) witness.
///
/// Indicates whether the CTI represents a concrete reachable violation
/// or is likely an artifact of weak induction (spurious).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CtiClassification {
    /// The CTI hypothesis state is reachable from initial states,
    /// indicating a genuine safety violation.
    Concrete,
    /// BMC base case verified safety through the CTI depth, so
    /// the hypothesis state is not reachable within the checked
    /// depth. The induction failure is likely due to a weak
    /// inductive invariant rather than a real protocol bug.
    LikelySpurious,
}

impl fmt::Display for CtiClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CtiClassification::Concrete => write!(f, "concrete"),
            CtiClassification::LikelySpurious => write!(f, "likely-spurious"),
        }
    }
}

/// Human-readable summary of a counterexample-to-induction witness.
#[derive(Debug, Clone)]
pub struct InductionCtiSummary {
    /// Depth k of the failed inductive-step query.
    pub k: usize,
    /// Concrete parameter valuation used in the SAT witness.
    pub params: Vec<(String, i64)>,
    /// Non-zero location counters at step k-1.
    pub hypothesis_locations: Vec<(String, i64)>,
    /// Non-zero shared counters at step k-1.
    pub hypothesis_shared: Vec<(String, i64)>,
    /// Non-zero location counters at violating step k.
    pub violating_locations: Vec<(String, i64)>,
    /// Non-zero shared counters at violating step k.
    pub violating_shared: Vec<(String, i64)>,
    /// Rules fired from step k-1 to k.
    pub final_step_rules: Vec<(String, i64)>,
    /// Human-readable description of which property predicate was violated.
    pub violated_condition: String,
    /// Classification: concrete (reachable) vs likely-spurious (weak induction).
    pub classification: CtiClassification,
    /// Machine-readable evidence supporting the classification.
    pub classification_evidence: Vec<String>,
    /// Human-readable rationale explaining why induction failed and what
    /// the CTI means for the user.
    pub rationale: String,
}

/// The result of an unbounded safety proof attempt.
#[derive(Debug, Clone)]
pub enum UnboundedSafetyResult {
    /// Proven safe for all depths via induction.
    Safe { induction_k: usize },
    /// Proven safe probabilistically with committee bounds.
    ProbabilisticallySafe {
        induction_k: usize,
        failure_probability: f64,
        committee_analyses: Vec<CommitteeAnalysisSummary>,
    },
    /// A concrete finite-depth counterexample was found.
    Unsafe { trace: Trace },
    /// Proof did not close up to the requested k.
    NotProved {
        max_k: usize,
        cti: Option<InductionCtiSummary>,
    },
    /// Attempt was inconclusive (e.g., solver unknown).
    Unknown { reason: String },
}

/// Communication complexity report (sound upper bounds).
#[derive(Debug, Clone, Serialize)]
pub struct CommComplexityReport {
    /// Schema version for machine-readable consumers.
    pub schema_version: u32,
    /// Ties results to exact model revision and analysis options.
    pub model_metadata: ModelMetadata,
    /// Assumptions under which the quantitative results hold.
    pub model_assumptions: ModelAssumptions,
    /// Notes about assumption applicability.
    pub assumption_notes: Vec<AssumptionNote>,
    /// Documents the bound kind (upper/lower/estimate) for each metric.
    pub bound_annotations: Vec<BoundAnnotation>,
    pub depth: usize,
    pub n_param: Option<String>,
    pub adv_param: Option<String>,
    pub min_decision_steps: Option<usize>,
    pub finality_failure_probability_upper: Option<f64>,
    pub finality_success_probability_lower: Option<f64>,
    pub expected_rounds_to_finality: Option<f64>,
    pub rounds_for_90pct_finality: Option<usize>,
    pub rounds_for_95pct_finality: Option<usize>,
    pub rounds_for_99pct_finality: Option<usize>,
    pub expected_total_messages_upper: Option<String>,
    pub messages_for_90pct_finality_upper: Option<String>,
    pub messages_for_99pct_finality_upper: Option<String>,
    pub expected_total_messages_with_adv_upper: Option<String>,
    pub messages_for_90pct_finality_with_adv_upper: Option<String>,
    pub messages_for_99pct_finality_with_adv_upper: Option<String>,
    pub max_sends_per_rule: usize,
    pub max_sends_per_rule_by_type: Vec<(String, usize)>,
    pub adversary_per_step_bound: Option<String>,
    pub adversary_per_depth_bound: Option<String>,
    pub per_step_bound: String,
    pub per_depth_bound: String,
    pub per_step_bound_with_adv: Option<String>,
    pub per_depth_bound_with_adv: Option<String>,
    pub per_step_bound_big_o: String,
    pub per_depth_bound_big_o: String,
    pub per_step_type_bounds: Vec<(String, String)>,
    pub per_depth_type_bounds: Vec<(String, String)>,
    pub adversary_per_step_type_bounds: Vec<(String, String)>,
    pub adversary_per_depth_type_bounds: Vec<(String, String)>,
    pub per_step_type_bounds_with_adv: Vec<(String, String)>,
    pub per_depth_type_bounds_with_adv: Vec<(String, String)>,
    pub per_step_type_big_o: Vec<(String, String)>,
    pub per_depth_type_big_o: Vec<(String, String)>,
    /// Per-role message bounds (item 1).
    pub per_role_step_bounds: Vec<(String, String)>,
    pub per_role_depth_bounds: Vec<(String, String)>,
    /// Per-phase message bounds (item 1).
    pub per_phase_step_bounds: Vec<(String, String)>,
    pub per_phase_depth_bounds: Vec<(String, String)>,
    /// Sensitivity analysis points for committee parameters (item 3).
    pub sensitivity: Vec<SensitivityPoint>,
    /// Confidence intervals for probabilistic metrics derived from sensitivity samples.
    pub probabilistic_confidence_intervals: Vec<ProbabilisticConfidenceInterval>,
}

impl fmt::Display for CommComplexityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "COMMUNICATION COMPLEXITY (sound upper bounds)")?;
        writeln!(f, "Schema version: {}", self.schema_version)?;
        writeln!(
            f,
            "Model: {} (hash: {})",
            self.model_metadata.filename, self.model_metadata.source_hash
        )?;
        writeln!(
            f,
            "Reproducibility: fp={}, cmd={}, depth={}, env={}/{}/{} ({}, engine={})",
            self.model_metadata.reproducibility_fingerprint,
            self.model_metadata.analysis_options.command,
            self.model_metadata.analysis_options.depth,
            self.model_metadata.analysis_environment.target_os,
            self.model_metadata.analysis_environment.target_arch,
            self.model_metadata.analysis_environment.target_family,
            self.model_metadata.analysis_environment.build_profile,
            self.model_metadata.engine_version,
        )?;
        writeln!(
            f,
            "Assumptions: fault={}, timing={}, auth={}, equiv={}, network={}",
            self.model_assumptions.fault_model,
            self.model_assumptions.timing_model,
            self.model_assumptions.authentication_mode,
            self.model_assumptions.equivocation_mode,
            self.model_assumptions.network_semantics,
        )?;
        for note in &self.assumption_notes {
            writeln!(f, "  [{}] {}", note.level, note.message)?;
        }
        let heuristic_fields: Vec<&str> = self
            .bound_annotations
            .iter()
            .filter(|ann| ann.evidence_class == BoundEvidenceClass::HeuristicEstimate)
            .map(|ann| ann.field.as_str())
            .collect();
        let theorem_backed_count = self
            .bound_annotations
            .iter()
            .filter(|ann| ann.evidence_class == BoundEvidenceClass::TheoremBacked)
            .count();
        if !self.bound_annotations.is_empty() {
            writeln!(
                f,
                "Bound evidence classes: theorem_backed={}, heuristic_estimate={}",
                theorem_backed_count,
                heuristic_fields.len()
            )?;
            if !heuristic_fields.is_empty() {
                writeln!(f, "  Heuristic estimates: {}", heuristic_fields.join(", "))?;
            }
        }
        writeln!(f, "Depth: {}", self.depth)?;
        if let Some(ref n) = self.n_param {
            writeln!(f, "Population parameter: {n}")?;
        } else {
            writeln!(f, "Population parameter: (missing `n`, bounds assume `n`)")?;
        }
        if let Some(ref adv) = self.adv_param {
            writeln!(f, "Adversary bound parameter: {adv}")?;
        }
        if let Some(steps) = self.min_decision_steps {
            writeln!(f, "Latency lower bound (steps to decision): {steps}")?;
        } else {
            writeln!(
                f,
                "Latency lower bound (steps to decision): unknown (no reachable `decided=true` location found)"
            )?;
        }
        if let Some(p_fail) = self.finality_failure_probability_upper {
            writeln!(
                f,
                "Finality failure probability upper bound: {:.3e}",
                p_fail
            )?;
        }
        if let Some(p_succ) = self.finality_success_probability_lower {
            writeln!(f, "Finality success probability lower bound: {:.6}", p_succ)?;
        }
        if let Some(rounds) = self.expected_rounds_to_finality {
            writeln!(
                f,
                "Expected rounds to finality (geometric approx): {rounds:.3}"
            )?;
        }
        if let Some(r90) = self.rounds_for_90pct_finality {
            writeln!(
                f,
                "Rounds for >= 90% finality confidence (geometric approx): {r90}"
            )?;
        }
        if let Some(r99) = self.rounds_for_99pct_finality {
            writeln!(
                f,
                "Rounds for >= 99% finality confidence (geometric approx): {r99}"
            )?;
        }
        if let Some(ref bound) = self.expected_total_messages_upper {
            writeln!(
                f,
                "Expected total messages to finality upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_90pct_finality_upper {
            writeln!(
                f,
                "Messages for >= 90% finality confidence upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_99pct_finality_upper {
            writeln!(
                f,
                "Messages for >= 99% finality confidence upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.expected_total_messages_with_adv_upper {
            writeln!(
                f,
                "Expected total messages to finality upper bound (including adversary): {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_90pct_finality_with_adv_upper {
            writeln!(
                f,
                "Messages for >= 90% finality confidence upper bound (including adversary): {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_99pct_finality_with_adv_upper {
            writeln!(
                f,
                "Messages for >= 99% finality confidence upper bound (including adversary): {bound}"
            )?;
        }

        writeln!(f, "Max sends per rule: {}", self.max_sends_per_rule)?;
        if !self.max_sends_per_rule_by_type.is_empty() {
            writeln!(f, "Max sends per rule by message type:")?;
            for (msg, count) in &self.max_sends_per_rule_by_type {
                writeln!(f, "  {msg}: {count}")?;
            }
        }
        writeln!(
            f,
            "Asymptotic per-step bound (protocol only): {}",
            self.per_step_bound_big_o
        )?;
        writeln!(
            f,
            "Asymptotic per-depth bound (protocol only): {}",
            self.per_depth_bound_big_o
        )?;

        writeln!(
            f,
            "Per-step total bound (protocol only): {}",
            self.per_step_bound
        )?;
        writeln!(
            f,
            "Per-depth total bound (protocol only): {}",
            self.per_depth_bound
        )?;
        if let Some(ref per_step_adv) = self.adversary_per_step_bound {
            writeln!(
                f,
                "Per-step adversary message-injection bound: {per_step_adv}"
            )?;
        }
        if let Some(ref per_depth_adv) = self.adversary_per_depth_bound {
            writeln!(
                f,
                "Per-depth adversary message-injection bound: {per_depth_adv}"
            )?;
        }
        if let Some(ref per_step) = self.per_step_bound_with_adv {
            writeln!(f, "Per-step total bound (including adversary): {per_step}")?;
        }
        if let Some(ref per_depth) = self.per_depth_bound_with_adv {
            writeln!(
                f,
                "Per-depth total bound (including adversary): {per_depth}"
            )?;
        }

        if !self.per_step_type_bounds.is_empty() {
            writeln!(f, "Per-step bounds by message type (protocol only):")?;
            for (msg, bound) in &self.per_step_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by message type (protocol only):")?;
            for (msg, bound) in &self.per_depth_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.adversary_per_step_type_bounds.is_empty() {
            writeln!(f, "Per-step adversary bounds by message type:")?;
            for (msg, bound) in &self.adversary_per_step_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.adversary_per_depth_type_bounds.is_empty() {
            writeln!(f, "Per-depth adversary bounds by message type:")?;
            for (msg, bound) in &self.adversary_per_depth_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_step_type_bounds_with_adv.is_empty() {
            writeln!(f, "Per-step bounds by message type (including adversary):")?;
            for (msg, bound) in &self.per_step_type_bounds_with_adv {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_bounds_with_adv.is_empty() {
            writeln!(f, "Per-depth bounds by message type (including adversary):")?;
            for (msg, bound) in &self.per_depth_type_bounds_with_adv {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_step_type_big_o.is_empty() {
            writeln!(f, "Asymptotic per-step bounds by message type:")?;
            for (msg, bound) in &self.per_step_type_big_o {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_big_o.is_empty() {
            writeln!(f, "Asymptotic per-depth bounds by message type:")?;
            for (msg, bound) in &self.per_depth_type_big_o {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_role_step_bounds.is_empty() {
            writeln!(f, "Per-step bounds by role (upper bound):")?;
            for (role, bound) in &self.per_role_step_bounds {
                writeln!(f, "  {role}: {bound}")?;
            }
        }
        if !self.per_role_depth_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by role (upper bound):")?;
            for (role, bound) in &self.per_role_depth_bounds {
                writeln!(f, "  {role}: {bound}")?;
            }
        }
        if !self.per_phase_step_bounds.is_empty() {
            writeln!(f, "Per-step bounds by phase (upper bound):")?;
            for (phase, bound) in &self.per_phase_step_bounds {
                writeln!(f, "  {phase}: {bound}")?;
            }
        }
        if !self.per_phase_depth_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by phase (upper bound):")?;
            for (phase, bound) in &self.per_phase_depth_bounds {
                writeln!(f, "  {phase}: {bound}")?;
            }
        }
        if let Some(r95) = self.rounds_for_95pct_finality {
            writeln!(
                f,
                "Rounds for >= 95% finality confidence (geometric approx): {r95}"
            )?;
        }
        if !self.sensitivity.is_empty() {
            writeln!(f, "Sensitivity analysis:")?;
            for pt in &self.sensitivity {
                writeln!(
                    f,
                    "  {}: {} {} -> {} => {} -> {}",
                    pt.metric,
                    pt.parameter,
                    pt.base_value,
                    pt.varied_value,
                    pt.base_result,
                    pt.varied_result,
                )?;
            }
        }
        if !self.probabilistic_confidence_intervals.is_empty() {
            writeln!(
                f,
                "Probabilistic confidence intervals (sensitivity-derived):"
            )?;
            for ci in &self.probabilistic_confidence_intervals {
                writeln!(
                    f,
                    "  {} @ {:.0}%: [{:.6}, {:.6}] (n={}, method={})",
                    ci.metric,
                    ci.level * 100.0,
                    ci.lower,
                    ci.upper,
                    ci.sample_size,
                    ci.method
                )?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for LivenessResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LivenessResult::Live { depth_checked } => {
                writeln!(f, "RESULT: LIVE (bounded)")?;
                write!(
                    f,
                    "All processes satisfy the liveness target by depth {depth_checked}."
                )
            }
            LivenessResult::NotLive { trace } => {
                writeln!(f, "RESULT: NOT LIVE (bounded)")?;
                write!(f, "{trace}")
            }
            LivenessResult::Unknown { reason } => {
                writeln!(f, "RESULT: UNKNOWN")?;
                write!(f, "Reason: {reason}")
            }
        }
    }
}

impl fmt::Display for FairLivenessResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FairLivenessResult::NoFairCycleUpTo { depth_checked } => {
                writeln!(f, "RESULT: NO FAIR LIVENESS COUNTEREXAMPLE (bounded)")?;
                write!(
                    f,
                    "No fair non-terminating lasso found up to depth {depth_checked}."
                )
            }
            FairLivenessResult::FairCycleFound {
                depth,
                loop_start,
                trace,
            } => {
                writeln!(f, "RESULT: FAIR LIVENESS COUNTEREXAMPLE FOUND")?;
                writeln!(f, "Lasso loop: step {loop_start} -> step {depth}")?;
                write!(f, "{trace}")
            }
            FairLivenessResult::Unknown { reason } => {
                writeln!(f, "RESULT: UNKNOWN")?;
                write!(f, "Reason: {reason}")
            }
        }
    }
}

impl fmt::Display for UnboundedFairLivenessResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnboundedFairLivenessResult::LiveProved { frame } => {
                writeln!(f, "RESULT: LIVE (unbounded, fair)")?;
                write!(f, "Proved by fair-cycle exclusion at frame {frame}.")
            }
            UnboundedFairLivenessResult::FairCycleFound {
                depth,
                loop_start,
                trace,
            } => {
                writeln!(f, "RESULT: NOT LIVE (unbounded, fair)")?;
                writeln!(f, "Fair lasso loop: step {loop_start} -> step {depth}")?;
                write!(f, "{trace}")
            }
            UnboundedFairLivenessResult::NotProved { max_k } => {
                writeln!(f, "RESULT: NOT PROVED")?;
                write!(
                    f,
                    "Unbounded fair-liveness proof did not converge up to frame {max_k}."
                )
            }
            UnboundedFairLivenessResult::Unknown { reason } => {
                writeln!(f, "RESULT: UNKNOWN")?;
                write!(f, "Reason: {reason}")
            }
        }
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationResult::Safe { depth_checked } => {
                writeln!(f, "RESULT: SAFE")?;
                write!(f, "Verified up to depth {depth_checked}.")
            }
            VerificationResult::ProbabilisticallySafe {
                depth_checked,
                failure_probability,
                committee_analyses,
            } => {
                writeln!(f, "RESULT: SAFE (probabilistic)")?;
                writeln!(f, "Verified up to depth {depth_checked}.")?;
                for ca in committee_analyses {
                    writeln!(
                        f,
                        "Committee \"{}\": {} from {} ({} Byzantine)",
                        ca.name, ca.committee_size, ca.population, ca.byzantine
                    )?;
                    writeln!(f, "  Expected Byzantine: {:.1}", ca.expected_byzantine)?;
                    writeln!(
                        f,
                        "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
                        ca.b_max, ca.epsilon
                    )?;
                    writeln!(
                        f,
                        "  Honest majority: {} of {}",
                        ca.honest_majority, ca.committee_size
                    )?;
                }
                write!(
                    f,
                    "Overall: safe with probability >= 1 - {:.0e}",
                    failure_probability
                )
            }
            VerificationResult::Unsafe { trace } => {
                writeln!(f, "RESULT: UNSAFE")?;
                write!(f, "{trace}")
            }
            VerificationResult::Unknown { reason } => {
                writeln!(f, "RESULT: UNKNOWN")?;
                write!(f, "Reason: {reason}")
            }
        }
    }
}

impl fmt::Display for UnboundedSafetyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnboundedSafetyResult::Safe { induction_k } => {
                writeln!(f, "RESULT: SAFE (unbounded)")?;
                write!(
                    f,
                    "Unbounded proof closed with induction depth k = {induction_k}."
                )
            }
            UnboundedSafetyResult::ProbabilisticallySafe {
                induction_k,
                failure_probability,
                committee_analyses,
            } => {
                writeln!(f, "RESULT: SAFE (unbounded, probabilistic)")?;
                writeln!(
                    f,
                    "Unbounded proof closed with induction depth k = {induction_k}."
                )?;
                for ca in committee_analyses {
                    writeln!(
                        f,
                        "Committee \"{}\": {} from {} ({} Byzantine)",
                        ca.name, ca.committee_size, ca.population, ca.byzantine
                    )?;
                    writeln!(f, "  Expected Byzantine: {:.1}", ca.expected_byzantine)?;
                    writeln!(
                        f,
                        "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
                        ca.b_max, ca.epsilon
                    )?;
                    writeln!(
                        f,
                        "  Honest majority: {} of {}",
                        ca.honest_majority, ca.committee_size
                    )?;
                }
                write!(
                    f,
                    "Overall: safe with probability >= 1 - {:.0e}",
                    failure_probability
                )
            }
            UnboundedSafetyResult::Unsafe { trace } => {
                writeln!(f, "RESULT: UNSAFE")?;
                write!(f, "{trace}")
            }
            UnboundedSafetyResult::NotProved { max_k, cti } => {
                writeln!(f, "RESULT: NOT PROVED")?;
                write!(f, "Unbounded proof did not close up to k = {max_k}.")?;
                if let Some(cti) = cti {
                    writeln!(f)?;
                    writeln!(f)?;
                    writeln!(
                        f,
                        "Counterexample to induction (CTI) at k = {} [{}]:",
                        cti.k, cti.classification
                    )?;
                    writeln!(f, "  Classification: {}", cti.classification)?;
                    for evidence in &cti.classification_evidence {
                        writeln!(f, "    - {evidence}")?;
                    }
                    writeln!(f, "  Rationale: {}", cti.rationale)?;
                    writeln!(f)?;
                    if !cti.params.is_empty() {
                        writeln!(f, "  Parameters:")?;
                        for (name, value) in &cti.params {
                            writeln!(f, "    {name} = {value}")?;
                        }
                    }
                    writeln!(f, "  State at step k-1 (induction hypothesis holds):")?;
                    if cti.hypothesis_locations.is_empty() && cti.hypothesis_shared.is_empty() {
                        writeln!(f, "    (all tracked counters are 0)")?;
                    } else {
                        for (name, value) in &cti.hypothesis_locations {
                            writeln!(f, "    {name}: {value}")?;
                        }
                        for (name, value) in &cti.hypothesis_shared {
                            writeln!(f, "    {name} = {value}")?;
                        }
                    }
                    writeln!(f, "  State at step k (property violated):")?;
                    if cti.violating_locations.is_empty() && cti.violating_shared.is_empty() {
                        writeln!(f, "    (all tracked counters are 0)")?;
                    } else {
                        for (name, value) in &cti.violating_locations {
                            writeln!(f, "    {name}: {value}")?;
                        }
                        for (name, value) in &cti.violating_shared {
                            writeln!(f, "    {name} = {value}")?;
                        }
                    }
                    if !cti.final_step_rules.is_empty() {
                        writeln!(f, "  Final transition k-1 -> k:")?;
                        for (rule, delta) in &cti.final_step_rules {
                            writeln!(f, "    {rule}: delta = {delta}")?;
                        }
                    }
                    write!(f, "  Violated condition: {}", cti.violated_condition)?;
                }
                Ok(())
            }
            UnboundedSafetyResult::Unknown { reason } => {
                writeln!(f, "RESULT: UNKNOWN")?;
                write!(f, "Reason: {reason}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::counter_system::Configuration;

    // --- Fairness semantics tests ---

    #[test]
    fn fairness_semantics_weak_fields() {
        let sem = FairnessSemantics::weak();
        assert_eq!(sem.mode, "weak");
        assert!(sem.formal_name.contains("Justice"));
        assert!(sem.definition.contains("continuously enabled"));
        assert!(sem.verdict_interpretation.contains("LiveProved"));
    }

    #[test]
    fn fairness_semantics_strong_fields() {
        let sem = FairnessSemantics::strong();
        assert_eq!(sem.mode, "strong");
        assert!(sem.formal_name.contains("Compassion"));
        assert!(sem.definition.contains("infinitely often"));
        assert!(
            sem.verdict_interpretation.contains("strictly stronger"),
            "should document relation to weak fairness"
        );
    }

    #[test]
    fn fairness_semantics_display() {
        assert_eq!(
            FairnessSemantics::weak().to_string(),
            "Justice (weak fairness) (weak)"
        );
        assert_eq!(
            FairnessSemantics::strong().to_string(),
            "Compassion (strong fairness) (strong)"
        );
    }

    // --- Unknown reason taxonomy tests ---

    #[test]
    fn unknown_reason_classify_timeout() {
        let reason = "Fair PDR: overall timeout exceeded at frontier frame 5.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "timeout");
        match classified {
            LivenessUnknownReason::Timeout {
                frontier_frame,
                phase,
            } => {
                assert_eq!(frontier_frame, 5);
                assert_eq!(phase, "fair_pdr");
            }
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn unknown_reason_classify_cegar_timeout() {
        let reason = "CEGAR fair-liveness proof timed out.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "timeout");
        match classified {
            LivenessUnknownReason::Timeout { phase, .. } => {
                assert_eq!(phase, "cegar");
            }
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn unknown_reason_classify_cube_budget() {
        let reason = "Fair PDR: blocked over 5000 bad cubes \
                      at frame 3 (adaptive budget); state space appears too large \
                      for current abstraction.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "cube_budget_exhausted");
        match classified {
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked,
                frontier_frame,
            } => {
                assert_eq!(cubes_blocked, 5000);
                assert_eq!(frontier_frame, 3);
            }
            _ => panic!("expected CubeBudgetExhausted"),
        }
    }

    #[test]
    fn unknown_reason_classify_memory_budget() {
        let reason = "Fair PDR: memory budget exceeded at frontier frame 4 \
                      (rss_bytes=8388608, limit_bytes=4194304).";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "memory_budget_exceeded");
        match classified {
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes,
                limit_bytes,
                frontier_frame,
                phase,
            } => {
                assert_eq!(rss_bytes, 8_388_608);
                assert_eq!(limit_bytes, 4_194_304);
                assert_eq!(frontier_frame, 4);
                assert_eq!(phase, "fair_pdr");
            }
            _ => panic!("expected MemoryBudgetExceeded"),
        }
    }

    #[test]
    fn unknown_reason_classify_lasso_recovery() {
        let reason = "Fair PDR found a reachable accepting state, \
                      but bounded lasso recovery did not return a trace.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "lasso_recovery_failed");
    }

    #[test]
    fn unknown_reason_classify_cegar_inconclusive() {
        let reason = "CEGAR refinements eliminated the baseline fair-cycle witness, \
                      but no refined fair cycle was found.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "cegar_refinement_inconclusive");
    }

    #[test]
    fn unknown_reason_classify_cegar_ladder() {
        let reason = "CEGAR refinement ladder exhausted without a confirmed fair cycle.";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "cegar_ladder_exhausted");
    }

    #[test]
    fn unknown_reason_classify_solver() {
        let reason = "Z3 returned unknown: resourceout";
        let classified = LivenessUnknownReason::classify(reason);
        assert_eq!(classified.code(), "solver_unknown");
        match classified {
            LivenessUnknownReason::SolverUnknown { solver_reason } => {
                assert_eq!(solver_reason, reason);
            }
            _ => panic!("expected SolverUnknown"),
        }
    }

    #[test]
    fn unknown_reason_code_exhaustive() {
        // Verify all codes are distinct strings.
        let codes: Vec<&str> = vec![
            LivenessUnknownReason::Timeout {
                frontier_frame: 0,
                phase: "test".into(),
            }
            .code(),
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes: 0,
                limit_bytes: 0,
                frontier_frame: 0,
                phase: "test".into(),
            }
            .code(),
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked: 0,
                frontier_frame: 0,
            }
            .code(),
            LivenessUnknownReason::SolverUnknown {
                solver_reason: String::new(),
            }
            .code(),
            LivenessUnknownReason::LassoRecoveryFailed.code(),
            LivenessUnknownReason::CegarRefinementInconclusive {
                discovered_predicates: vec![],
            }
            .code(),
            LivenessUnknownReason::CegarLadderExhausted.code(),
        ];
        let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all codes must be distinct");
    }

    #[test]
    fn unknown_reason_display_roundtrip() {
        // Display should produce a human-readable string that classifies back correctly.
        let reason = LivenessUnknownReason::Timeout {
            frontier_frame: 7,
            phase: "fair_pdr".into(),
        };
        let display = reason.to_string();
        assert!(display.contains("7"));
        assert!(display.contains("fair_pdr"));
    }

    // --- Verdict class tests ---

    #[test]
    fn verification_result_verdict_class_safe() {
        let r = VerificationResult::Safe { depth_checked: 5 };
        assert_eq!(r.verdict_class(), "safe");
    }

    #[test]
    fn verification_result_verdict_class_unsafe() {
        let r = VerificationResult::Unsafe {
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        };
        assert_eq!(r.verdict_class(), "unsafe");
    }

    #[test]
    fn verification_result_verdict_class_unknown() {
        let r = VerificationResult::Unknown {
            reason: "test".into(),
        };
        assert_eq!(r.verdict_class(), "unknown");
    }

    #[test]
    fn verification_result_verdict_class_prob_safe() {
        let r = VerificationResult::ProbabilisticallySafe {
            depth_checked: 3,
            failure_probability: 1e-9,
            committee_analyses: vec![],
        };
        assert_eq!(r.verdict_class(), "probabilistically_safe");
    }

    #[test]
    fn unbounded_fair_liveness_verdict_class_all_variants() {
        assert_eq!(
            UnboundedFairLivenessResult::LiveProved { frame: 1 }.verdict_class(),
            "live_proved"
        );
        assert_eq!(
            UnboundedFairLivenessResult::FairCycleFound {
                depth: 2,
                loop_start: 0,
                trace: Trace {
                    param_values: vec![],
                    initial_config: Configuration::new(0, 0, 0),
                    steps: vec![],
                },
            }
            .verdict_class(),
            "fair_cycle_found"
        );
        assert_eq!(
            UnboundedFairLivenessResult::NotProved { max_k: 5 }.verdict_class(),
            "not_proved"
        );
        assert_eq!(
            UnboundedFairLivenessResult::Unknown { reason: "x".into() }.verdict_class(),
            "unknown"
        );
    }

    // --- Multi-property result tests (from previous session, verified here too) ---

    #[test]
    fn multi_property_result_empty_is_safe() {
        let result = MultiPropertyResult { verdicts: vec![] };
        assert!(result.all_safe());
        assert!(!result.any_unsafe());
        assert_eq!(result.overall_verdict(), "safe");
    }

    // --- CTI classification tests ---

    #[test]
    fn cti_classification_display() {
        assert_eq!(format!("{}", CtiClassification::Concrete), "concrete");
        assert_eq!(
            format!("{}", CtiClassification::LikelySpurious),
            "likely-spurious"
        );
    }

    #[test]
    fn cti_classification_serializes_snake_case() {
        let concrete = serde_json::to_value(&CtiClassification::Concrete).unwrap();
        assert_eq!(concrete, serde_json::Value::String("concrete".into()));
        let spurious = serde_json::to_value(&CtiClassification::LikelySpurious).unwrap();
        assert_eq!(
            spurious,
            serde_json::Value::String("likely_spurious".into())
        );
    }

    #[test]
    fn cti_summary_has_classification_fields() {
        let cti = InductionCtiSummary {
            k: 3,
            params: vec![("n".into(), 4)],
            hypothesis_locations: vec![("Init".into(), 4)],
            hypothesis_shared: vec![],
            violating_locations: vec![("Decided_v0".into(), 2), ("Decided_v1".into(), 2)],
            violating_shared: vec![],
            final_step_rules: vec![("r0 (Propose -> Decided_v0)".into(), 2)],
            violated_condition: "agreement violated: Decided_v0 and Decided_v1 both occupied"
                .into(),
            classification: CtiClassification::LikelySpurious,
            classification_evidence: vec![
                "BMC base case verified no reachable violation through depth 3; \
                 CTI hypothesis state at step 2 is outside the reachable state space."
                    .into(),
            ],
            rationale: "The inductive step failed at k = 3".into(),
        };
        assert_eq!(cti.classification, CtiClassification::LikelySpurious);
        assert!(!cti.classification_evidence.is_empty());
        assert!(cti.rationale.contains("inductive step failed"));
    }

    #[test]
    fn cti_summary_display_includes_classification() {
        let cti = InductionCtiSummary {
            k: 2,
            params: vec![],
            hypothesis_locations: vec![("Loc_A".into(), 3)],
            hypothesis_shared: vec![],
            violating_locations: vec![("Bad".into(), 1)],
            violating_shared: vec![],
            final_step_rules: vec![],
            violated_condition: "invariant violated".into(),
            classification: CtiClassification::LikelySpurious,
            classification_evidence: vec!["BMC passed at depth 2.".into()],
            rationale: "Likely unreachable from init.".into(),
        };
        let result = UnboundedSafetyResult::NotProved {
            max_k: 4,
            cti: Some(cti),
        };
        let display = format!("{result}");
        assert!(
            display.contains("likely-spurious"),
            "Display should contain classification: {display}"
        );
        assert!(
            display.contains("BMC passed at depth 2"),
            "Display should contain evidence: {display}"
        );
        assert!(
            display.contains("Likely unreachable from init"),
            "Display should contain rationale: {display}"
        );
        assert!(
            display.contains("NOT PROVED"),
            "Display should contain NOT PROVED: {display}"
        );
    }

    // --- VerificationResult Display tests ---

    #[test]
    fn display_verification_result_safe() {
        let r = VerificationResult::Safe { depth_checked: 10 };
        let s = format!("{r}");
        assert!(s.contains("RESULT: SAFE"));
        assert!(s.contains("depth 10"));
    }

    #[test]
    fn display_verification_result_unsafe() {
        let r = VerificationResult::Unsafe {
            trace: Trace {
                param_values: vec![("n".into(), 4)],
                initial_config: Configuration::new(2, 1, 1),
                steps: vec![],
            },
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNSAFE"));
        assert!(s.contains("Counterexample trace"));
    }

    #[test]
    fn display_verification_result_unknown() {
        let r = VerificationResult::Unknown {
            reason: "solver timeout".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNKNOWN"));
        assert!(s.contains("solver timeout"));
    }

    #[test]
    fn display_verification_result_probabilistically_safe() {
        let r = VerificationResult::ProbabilisticallySafe {
            depth_checked: 5,
            failure_probability: 1e-9,
            committee_analyses: vec![CommitteeAnalysisSummary {
                name: "validators".into(),
                committee_size: 100,
                population: 1000,
                byzantine: 333,
                b_max: 61,
                epsilon: 1e-9,
                tail_probability: 5e-10,
                honest_majority: 39,
                expected_byzantine: 33.3,
            }],
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: SAFE (probabilistic)"));
        assert!(s.contains("depth 5"));
        assert!(s.contains("validators"));
        assert!(s.contains("100 from 1000"));
        assert!(s.contains("1 - 1e-9") || s.contains("1e-9"));
    }

    // --- UnboundedSafetyResult Display tests ---

    #[test]
    fn display_unbounded_safety_safe() {
        let r = UnboundedSafetyResult::Safe { induction_k: 3 };
        let s = format!("{r}");
        assert!(s.contains("RESULT: SAFE (unbounded)"));
        assert!(s.contains("k = 3"));
    }

    #[test]
    fn display_unbounded_safety_prob_safe() {
        let r = UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k: 2,
            failure_probability: 1e-6,
            committee_analyses: vec![],
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: SAFE (unbounded, probabilistic)"));
        assert!(s.contains("k = 2"));
    }

    #[test]
    fn display_unbounded_safety_unsafe() {
        let r = UnboundedSafetyResult::Unsafe {
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNSAFE"));
    }

    #[test]
    fn display_unbounded_safety_not_proved_no_cti() {
        let r = UnboundedSafetyResult::NotProved {
            max_k: 10,
            cti: None,
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: NOT PROVED"));
        assert!(s.contains("k = 10"));
        // No CTI section should appear
        assert!(!s.contains("Counterexample to induction"));
    }

    #[test]
    fn display_unbounded_safety_unknown() {
        let r = UnboundedSafetyResult::Unknown {
            reason: "solver gave up".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNKNOWN"));
        assert!(s.contains("solver gave up"));
    }

    // --- LivenessResult Display tests ---

    #[test]
    fn display_liveness_live() {
        let r = LivenessResult::Live { depth_checked: 7 };
        let s = format!("{r}");
        assert!(s.contains("RESULT: LIVE (bounded)"));
        assert!(s.contains("depth 7"));
    }

    #[test]
    fn display_liveness_not_live() {
        let r = LivenessResult::NotLive {
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: NOT LIVE (bounded)"));
    }

    #[test]
    fn display_liveness_unknown() {
        let r = LivenessResult::Unknown {
            reason: "incomplete".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNKNOWN"));
        assert!(s.contains("incomplete"));
    }

    // --- FairLivenessResult Display tests ---

    #[test]
    fn display_fair_liveness_no_fair_cycle() {
        let r = FairLivenessResult::NoFairCycleUpTo { depth_checked: 12 };
        let s = format!("{r}");
        assert!(s.contains("NO FAIR LIVENESS COUNTEREXAMPLE"));
        assert!(s.contains("depth 12"));
    }

    #[test]
    fn display_fair_liveness_fair_cycle_found() {
        let r = FairLivenessResult::FairCycleFound {
            depth: 5,
            loop_start: 2,
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        };
        let s = format!("{r}");
        assert!(s.contains("FAIR LIVENESS COUNTEREXAMPLE FOUND"));
        assert!(s.contains("step 2 -> step 5"));
    }

    #[test]
    fn display_fair_liveness_unknown() {
        let r = FairLivenessResult::Unknown {
            reason: "resource limit".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNKNOWN"));
        assert!(s.contains("resource limit"));
    }

    // --- UnboundedFairLivenessResult Display tests ---

    #[test]
    fn display_unbounded_fair_liveness_live_proved() {
        let r = UnboundedFairLivenessResult::LiveProved { frame: 4 };
        let s = format!("{r}");
        assert!(s.contains("RESULT: LIVE (unbounded, fair)"));
        assert!(s.contains("frame 4"));
    }

    #[test]
    fn display_unbounded_fair_liveness_fair_cycle() {
        let r = UnboundedFairLivenessResult::FairCycleFound {
            depth: 8,
            loop_start: 3,
            trace: Trace {
                param_values: vec![],
                initial_config: Configuration::new(0, 0, 0),
                steps: vec![],
            },
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: NOT LIVE (unbounded, fair)"));
        assert!(s.contains("step 3 -> step 8"));
    }

    #[test]
    fn display_unbounded_fair_liveness_not_proved() {
        let r = UnboundedFairLivenessResult::NotProved { max_k: 15 };
        let s = format!("{r}");
        assert!(s.contains("RESULT: NOT PROVED"));
        assert!(s.contains("frame 15"));
    }

    #[test]
    fn display_unbounded_fair_liveness_unknown() {
        let r = UnboundedFairLivenessResult::Unknown {
            reason: "z3 unknown".into(),
        };
        let s = format!("{r}");
        assert!(s.contains("RESULT: UNKNOWN"));
        assert!(s.contains("z3 unknown"));
    }

    // --- MultiPropertyResult tests ---

    #[test]
    fn multi_property_all_safe_with_mixed_safe_variants() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agreement".into(),
                    fragment: "safety".into(),
                    result: VerificationResult::Safe { depth_checked: 5 },
                },
                PropertyVerdict {
                    name: "validity".into(),
                    fragment: "safety".into(),
                    result: VerificationResult::ProbabilisticallySafe {
                        depth_checked: 5,
                        failure_probability: 1e-9,
                        committee_analyses: vec![],
                    },
                },
            ],
        };
        assert!(result.all_safe());
        assert!(!result.any_unsafe());
        assert_eq!(result.overall_verdict(), "safe");
    }

    #[test]
    fn multi_property_unsafe_overrides_safe() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agreement".into(),
                    fragment: "safety".into(),
                    result: VerificationResult::Safe { depth_checked: 5 },
                },
                PropertyVerdict {
                    name: "validity".into(),
                    fragment: "safety".into(),
                    result: VerificationResult::Unsafe {
                        trace: Trace {
                            param_values: vec![],
                            initial_config: Configuration::new(0, 0, 0),
                            steps: vec![],
                        },
                    },
                },
            ],
        };
        assert!(!result.all_safe());
        assert!(result.any_unsafe());
        assert_eq!(result.overall_verdict(), "unsafe");
    }

    #[test]
    fn multi_property_unknown_yields_inconclusive() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agreement".into(),
                    fragment: "safety".into(),
                    result: VerificationResult::Safe { depth_checked: 5 },
                },
                PropertyVerdict {
                    name: "termination".into(),
                    fragment: "liveness".into(),
                    result: VerificationResult::Unknown {
                        reason: "timeout".into(),
                    },
                },
            ],
        };
        assert!(!result.all_safe());
        assert!(!result.any_unsafe());
        assert_eq!(result.overall_verdict(), "inconclusive");
    }

    // --- Serde serialization tests ---

    #[test]
    fn bound_kind_serializes_correctly() {
        let upper = serde_json::to_value(&BoundKind::UpperBound).unwrap();
        assert_eq!(upper, serde_json::json!("upper_bound"));
        let lower = serde_json::to_value(&BoundKind::LowerBound).unwrap();
        assert_eq!(lower, serde_json::json!("lower_bound"));
        let est = serde_json::to_value(&BoundKind::Estimate).unwrap();
        assert_eq!(est, serde_json::json!("estimate"));
        let exact = serde_json::to_value(&BoundKind::Exact).unwrap();
        assert_eq!(exact, serde_json::json!("exact"));
    }

    #[test]
    fn bound_evidence_class_serializes_correctly() {
        let tb = serde_json::to_value(&BoundEvidenceClass::TheoremBacked).unwrap();
        assert_eq!(tb, serde_json::json!("theorem_backed"));
        let he = serde_json::to_value(&BoundEvidenceClass::HeuristicEstimate).unwrap();
        assert_eq!(he, serde_json::json!("heuristic_estimate"));
    }

    #[test]
    fn bound_annotation_serializes_all_fields() {
        let ann = BoundAnnotation {
            field: "per_step_bound".into(),
            kind: BoundKind::UpperBound,
            evidence_class: BoundEvidenceClass::TheoremBacked,
            description: "Sound upper bound on messages per step".into(),
            assumptions: vec!["authenticated channels".into()],
        };
        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["field"], "per_step_bound");
        assert_eq!(json["kind"], "upper_bound");
        assert_eq!(json["evidence_class"], "theorem_backed");
        assert!(json["assumptions"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn model_assumptions_serializes_with_optional_gst() {
        let assumptions = ModelAssumptions {
            fault_model: "byzantine".into(),
            timing_model: "asynchronous".into(),
            authentication_mode: "signed".into(),
            equivocation_mode: "allowed".into(),
            network_semantics: "point_to_point".into(),
            gst_param: Some("GST".into()),
        };
        let json = serde_json::to_value(&assumptions).unwrap();
        assert_eq!(json["fault_model"], "byzantine");
        assert_eq!(json["gst_param"], "GST");

        let no_gst = ModelAssumptions {
            gst_param: None,
            ..assumptions.clone()
        };
        let json2 = serde_json::to_value(&no_gst).unwrap();
        assert!(json2["gst_param"].is_null());
    }

    #[test]
    fn assumption_note_serializes_level_and_message() {
        let note = AssumptionNote {
            level: "warning".into(),
            message: "Equivocation is not modeled".into(),
        };
        let json = serde_json::to_value(&note).unwrap();
        assert_eq!(json["level"], "warning");
        assert_eq!(json["message"], "Equivocation is not modeled");
    }

    // --- LivenessUnknownReason Display tests ---

    #[test]
    fn display_unknown_reason_memory_budget() {
        let reason = LivenessUnknownReason::MemoryBudgetExceeded {
            rss_bytes: 8_000_000,
            limit_bytes: 4_000_000,
            frontier_frame: 3,
            phase: "fair_pdr".into(),
        };
        let s = reason.to_string();
        assert!(s.contains("Memory budget exceeded"));
        assert!(s.contains("frame 3"));
        assert!(s.contains("rss_bytes=8000000"));
        assert!(s.contains("limit_bytes=4000000"));
    }

    #[test]
    fn display_unknown_reason_cube_budget() {
        let reason = LivenessUnknownReason::CubeBudgetExhausted {
            cubes_blocked: 5000,
            frontier_frame: 2,
        };
        let s = reason.to_string();
        assert!(s.contains("5000"));
        assert!(s.contains("frame 2"));
        assert!(s.contains("adaptive budget"));
    }

    #[test]
    fn display_unknown_reason_cegar_inconclusive_with_predicates() {
        let reason = LivenessUnknownReason::CegarRefinementInconclusive {
            discovered_predicates: vec!["no_equivocation".into(), "exact_values".into()],
        };
        let s = reason.to_string();
        assert!(s.contains("no_equivocation, exact_values"));
        assert!(s.contains("predicates:"));
    }

    #[test]
    fn display_unknown_reason_cegar_inconclusive_no_predicates() {
        let reason = LivenessUnknownReason::CegarRefinementInconclusive {
            discovered_predicates: vec![],
        };
        let s = reason.to_string();
        assert!(!s.contains("predicates:"));
    }

    #[test]
    fn display_unknown_reason_lasso_recovery_failed() {
        let reason = LivenessUnknownReason::LassoRecoveryFailed;
        let s = reason.to_string();
        assert!(s.contains("bounded lasso recovery"));
    }

    #[test]
    fn display_unknown_reason_cegar_ladder_exhausted() {
        let reason = LivenessUnknownReason::CegarLadderExhausted;
        let s = reason.to_string();
        assert!(s.contains("refinement ladder exhausted"));
    }

    // --- CommitteeAnalysisSummary construction ---

    #[test]
    fn committee_analysis_summary_field_access() {
        let ca = CommitteeAnalysisSummary {
            name: "validators".into(),
            committee_size: 100,
            population: 1000,
            byzantine: 333,
            b_max: 61,
            epsilon: 1e-9,
            tail_probability: 5e-10,
            honest_majority: 39,
            expected_byzantine: 33.3,
        };
        assert_eq!(ca.name, "validators");
        assert_eq!(ca.committee_size, 100);
        assert_eq!(ca.population, 1000);
        assert_eq!(ca.byzantine, 333);
        assert_eq!(ca.b_max, 61);
        assert!(ca.tail_probability < ca.epsilon);
        assert_eq!(ca.honest_majority, 39);
    }

    // --- CEGAR types construction ---

    #[test]
    fn cegar_stage_outcome_variants_are_constructible() {
        let safe = CegarStageOutcome::Safe { depth_checked: 5 };
        assert!(matches!(safe, CegarStageOutcome::Safe { depth_checked: 5 }));

        let prob = CegarStageOutcome::ProbabilisticallySafe {
            depth_checked: 5,
            failure_probability: 1e-9,
            committee_count: 2,
        };
        assert!(matches!(
            prob,
            CegarStageOutcome::ProbabilisticallySafe { .. }
        ));

        let unknown = CegarStageOutcome::Unknown {
            reason: "test".into(),
        };
        assert!(matches!(unknown, CegarStageOutcome::Unknown { .. }));
    }

    #[test]
    fn cegar_termination_fields() {
        let term = CegarTermination {
            reason: "proof_found".into(),
            iteration_budget: 10,
            iterations_used: 3,
            timeout_secs: 60,
            elapsed_ms: 1234,
            reached_iteration_budget: false,
            reached_timeout_budget: false,
        };
        assert_eq!(term.reason, "proof_found");
        assert_eq!(term.iterations_used, 3);
        assert!(!term.reached_iteration_budget);
        assert!(!term.reached_timeout_budget);
        assert!(term.elapsed_ms < term.timeout_secs as u128 * 1000);
    }

    #[test]
    fn cegar_model_change_construction() {
        let change = CegarModelChange {
            category: "adversary".into(),
            target: "Vote".into(),
            before: "unbounded".into(),
            after: "bounded(3)".into(),
            predicate: "adversary_bound".into(),
        };
        assert_eq!(change.category, "adversary");
        assert_eq!(change.predicate, "adversary_bound");
    }

    #[test]
    fn cegar_predicate_score_construction() {
        let score = CegarPredicateScore {
            predicate: "equivocation_none".into(),
            score: 42,
            evidence_tags: vec!["single_variant".into()],
            affected_steps: 3,
            unsat_core_selected: true,
        };
        assert_eq!(score.score, 42);
        assert!(score.unsat_core_selected);
        assert_eq!(score.affected_steps, 3);
    }

    // --- Quantitative schema constants ---

    #[test]
    fn quantitative_schema_paths_are_non_empty() {
        assert!(!QUANTITATIVE_SCHEMA_DOC_PATH.is_empty());
        assert!(!QUANTITATIVE_SCHEMA_JSON_PATH.is_empty());
        assert!(QUANTITATIVE_SCHEMA_JSON_PATH.ends_with(".json"));
    }
}
