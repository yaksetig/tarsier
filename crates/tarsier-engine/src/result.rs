use serde::Serialize;
use std::fmt;
use tarsier_ir::counter_system::Trace;

mod comm_complexity;
pub use comm_complexity::CommComplexityReport;

mod liveness_unknown;
pub use liveness_unknown::{reason_sentinels, LivenessUnknownReason};

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

/// One transition in an extracted lasso witness loop segment.
#[derive(Debug, Clone)]
pub struct CegarLassoStep {
    /// SMT step index of this transition.
    pub smt_step: usize,
    /// Fired rule identifier.
    pub rule_id: usize,
    /// Delta value for the fired rule.
    pub delta: i64,
}

/// First-class lasso witness extracted from a fair-cycle result.
///
/// This captures the loop segment as a concrete counterexample candidate that
/// downstream CEGAR stages can analyze and replay.
#[derive(Debug, Clone)]
pub struct CegarLassoWitness {
    /// Depth reported by fair-cycle search/PDR.
    pub depth: usize,
    /// Loop entry index.
    pub loop_start: usize,
    /// Length of loop segment (`depth - loop_start`).
    pub loop_len: usize,
    /// Length of prefix segment (`loop_start`).
    pub prefix_len: usize,
    /// Number of transitions in the full witness trace.
    pub trace_steps: usize,
    /// Ordered loop transitions extracted from the trace.
    pub loop_steps: Vec<CegarLassoStep>,
    /// Distinct rule ids observed in the loop segment (first-seen order).
    pub loop_rule_ids: Vec<usize>,
    /// Parameter valuation carried by the witness.
    pub param_values: Vec<(String, i64)>,
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
    /// Extracted lasso witness for this stage when a fair cycle is found.
    pub lasso_witness: Option<CegarLassoWitness>,
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
mod tests;
