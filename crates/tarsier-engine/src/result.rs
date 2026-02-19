use serde::Serialize;
use std::fmt;
use tarsier_ir::counter_system::Trace;

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

/// Documents the kind and meaning of a metric field.
#[derive(Debug, Clone, Serialize)]
pub struct BoundAnnotation {
    pub field: String,
    pub kind: BoundKind,
    pub description: String,
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
                        "Counterexample to induction (CTI) at k = {} (may be unreachable from init):",
                        cti.k
                    )?;
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
