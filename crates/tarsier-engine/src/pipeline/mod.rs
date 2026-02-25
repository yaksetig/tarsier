#![allow(clippy::result_large_err)]
#![allow(unused_imports)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::info;

use tarsier_dsl::ast;
use tarsier_dsl::errors::ParseError;
use tarsier_ir::abstraction::abstract_to_counter_system;
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::lowering::{self, LoweringError, SpannedLoweringError};
use tarsier_ir::properties::{extract_agreement_property, SafetyProperty};
use tarsier_ir::threshold_automaton::{
    AuthenticationMode, CmpOp, EquivocationMode, FaultModel, GuardAtom, LinearCombination,
    LocalValue, NetworkSemantics, ParamOrConst, PorMode, SharedVarKind, ThresholdAutomaton,
};
use tarsier_prob::committee::{CommitteeError, CommitteeSpec};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{
    reset_smt_run_profile, run_bmc_at_depth, run_bmc_with_deadline,
    run_bmc_with_extra_assertions_at_depth, run_bmc_with_extra_assertions_with_deadline,
    run_k_induction_with_deadline, run_pdr_with_certificate_with_deadline, run_pdr_with_deadline,
    take_smt_run_profile, BmcResult, KInductionCti, KInductionResult, PdrInvariantCertificate,
    SmtRunProfile,
};
use tarsier_smt::encoder::{encode_bmc, encode_k_induction_step, BmcEncoding};
use tarsier_smt::solver::{Model, SatResult, SmtSolver};
use tarsier_smt::sorts::SmtSort;
use tarsier_smt::terms::SmtTerm;

use crate::counterexample::extract_trace;
use crate::result::{
    AssumptionNote, BoundAnnotation, BoundEvidenceClass, BoundKind, CegarAuditReport,
    CegarCounterexampleAnalysis, CegarEliminatedTrace, CegarModelChange, CegarPredicateScore,
    CegarRunControls, CegarStageOutcome, CegarStageReport, CegarTermination, CommComplexityReport,
    CommitteeAnalysisSummary, CtiClassification, FairLivenessResult, FairnessSemantics,
    InductionCtiSummary, LivenessResult, ModelAssumptions, ModelMetadata, MultiPropertyResult,
    ProbabilisticConfidenceInterval, PropertyVerdict, QuantitativeAnalysisEnvironment,
    QuantitativeAnalysisOptions, SensitivityPoint, UnboundedFairLivenessCegarAuditReport,
    UnboundedFairLivenessCegarStageOutcome, UnboundedFairLivenessCegarStageReport,
    UnboundedFairLivenessResult, UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome,
    UnboundedSafetyCegarStageReport, UnboundedSafetyResult, VerificationResult,
    QUANTITATIVE_SCHEMA_VERSION,
};

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Lowering error: {0}")]
    Lowering(#[from] LoweringError),
    #[error("Committee analysis error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("Solver error: {0}")]
    Solver(String),
    #[error("Property error: {0}")]
    Property(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Sandbox limit exceeded: {0}")]
    Sandbox(#[from] crate::sandbox::SandboxError),
}

/// Which solver backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolverChoice {
    Z3,
    Cvc5,
}

/// Soundness profile for protocol analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SoundnessMode {
    /// Reject underspecified or approximation-prone models.
    #[default]
    Strict,
    /// Allow permissive fallbacks for prototyping.
    Permissive,
}

/// Backend used by `prove` (unbounded safety).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofEngine {
    /// Classic k-induction.
    #[default]
    KInduction,
    /// IC3/PDR with clause blocking, generalization, and frame propagation.
    Pdr,
}

/// Fairness semantics for liveness checks/proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FairnessMode {
    /// Weak fairness (justice): continuously-enabled rules must eventually fire.
    #[default]
    Weak,
    /// Strong fairness (compassion): infinitely-often-enabled rules must eventually fire.
    Strong,
}

impl FairnessMode {
    /// Return the formal semantics descriptor for this fairness mode.
    pub fn semantics(&self) -> FairnessSemantics {
        match self {
            FairnessMode::Weak => FairnessSemantics::weak(),
            FairnessMode::Strong => FairnessSemantics::strong(),
        }
    }
}

/// Options for the verification pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    pub solver: SolverChoice,
    pub max_depth: usize,
    pub timeout_secs: u64,
    pub dump_smt: Option<String>,
    pub soundness: SoundnessMode,
    pub proof_engine: ProofEngine,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            solver: SolverChoice::Z3,
            max_depth: 10,
            timeout_secs: 300,
            dump_smt: None,
            soundness: SoundnessMode::Strict,
            proof_engine: ProofEngine::KInduction,
        }
    }
}

/// Lower-bound for automatic faithful-network fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaithfulFallbackFloor {
    /// Never fall back to legacy `network: classic`.
    #[default]
    IdentitySelective,
    /// Allow fallback down to legacy `network: classic`.
    Classic,
}

/// Optional model-size budget for automatic network fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaithfulFallbackConfig {
    pub max_locations: usize,
    pub max_shared_vars: usize,
    pub max_message_counters: usize,
    pub floor: FaithfulFallbackFloor,
}

/// Optional execution controls for size/soundness tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PipelineExecutionControls {
    /// If set, faithful network modes can be automatically coarsened when the
    /// model exceeds this budget.
    pub faithful_fallback: Option<FaithfulFallbackConfig>,
    /// Optional RSS memory budget (MiB) for unbounded fair-liveness proof
    /// search. Exceeding the budget yields an inconclusive result instead of
    /// continuing an unbounded search that may destabilize CI/runtime.
    pub liveness_memory_budget_mb: Option<u64>,
    /// CLI override for partial-order reduction mode. `None` means use DSL value.
    pub por_mode_override: Option<PorMode>,
}

/// Coarse size summary of a lowered automaton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AutomatonFootprint {
    pub locations: usize,
    pub rules: usize,
    pub shared_vars: usize,
    pub message_counters: usize,
}

/// One applied abstraction/reduction step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedReductionDiagnostic {
    pub context: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub before: AutomatonFootprint,
    pub after: AutomatonFootprint,
}

/// Per-phase runtime/memory profiling entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseProfileDiagnostic {
    pub context: String,
    pub phase: String,
    pub elapsed_ms: u128,
    pub rss_bytes: Option<u64>,
}

/// SMT encoding/solve profile summary for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtProfileDiagnostic {
    pub context: String,
    pub encode_calls: u64,
    pub encode_elapsed_ms: u128,
    pub solve_calls: u64,
    pub solve_elapsed_ms: u128,
    pub assertion_candidates: u64,
    pub assertion_unique: u64,
    pub assertion_dedup_hits: u64,
    pub incremental_depth_reuse_steps: u64,
    pub incremental_decl_reuse_hits: u64,
    pub incremental_assertion_reuse_hits: u64,
    pub symmetry_candidates: u64,
    pub symmetry_pruned: u64,
    pub stutter_signature_normalizations: u64,
    pub por_pending_obligation_dedup_hits: u64,
    pub por_dynamic_ample_queries: u64,
    pub por_dynamic_ample_fast_sat: u64,
    pub por_dynamic_ample_unsat_rechecks: u64,
    pub por_dynamic_ample_unsat_recheck_sat: u64,
}

/// Network abstraction diagnostics for one lowering pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringDiagnostic {
    pub context: String,
    pub requested_network: String,
    pub effective_network: String,
    pub fault_model: String,
    pub authentication: String,
    pub equivocation: String,
    pub delivery_control: String,
    pub fault_budget_scope: String,
    pub identity_roles: usize,
    pub process_identity_roles: usize,
    pub requested_footprint: AutomatonFootprint,
    pub effective_footprint: AutomatonFootprint,
    pub fallback_budget: Option<AutomatonFootprint>,
    pub budget_satisfied: bool,
    pub fallback_applied: bool,
    pub fallback_steps: usize,
    pub fallback_exhausted: bool,
    pub independent_rule_pairs: usize,
    pub por_stutter_rules_pruned: usize,
    pub por_commutative_duplicate_rules_pruned: usize,
    pub por_guard_dominated_rules_pruned: usize,
    pub por_effective_rule_count: usize,
}

/// Deterministic property-compilation trace entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyCompilationDiagnostic {
    pub context: String,
    pub property_name: String,
    pub property_kind: String,
    pub fragment: String,
    pub source_formula: String,
    pub source_formula_sha256: String,
    pub compilation_target: String,
    pub compiled_summary: String,
    pub compiled_sha256: String,
}

/// Assumptions attached to a per-property machine-readable verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PropertyAssumptionsDiagnostic {
    pub solver: String,
    pub soundness: String,
    pub max_depth: usize,
    pub network_semantics: String,
    pub committee_bounds: Vec<(String, u64)>,
    pub failure_probability_bound: Option<f64>,
}

/// Temporal monitor snapshot attached to a counterexample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropertyTemporalMonitorStepDiagnostic {
    pub step: usize,
    pub active_states: Vec<usize>,
    pub true_atoms: Vec<usize>,
    pub acceptance_sets_hit: Vec<usize>,
}

/// Witness metadata attached to a per-property machine-readable verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropertyWitnessMetadataDiagnostic {
    pub witness_kind: String,
    pub trace_steps: usize,
    pub violation_step: Option<usize>,
    pub temporal_monitor: Option<Vec<PropertyTemporalMonitorStepDiagnostic>>,
}

/// Machine-readable per-property verdict diagnostic.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PropertyResultDiagnostic {
    pub property_id: String,
    pub property_name: String,
    pub property_kind: String,
    pub fragment: String,
    pub verdict: String,
    pub assumptions: PropertyAssumptionsDiagnostic,
    pub witness: Option<PropertyWitnessMetadataDiagnostic>,
}

/// Reduction/abstraction diagnostics for one pipeline run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PipelineRunDiagnostics {
    pub lowerings: Vec<LoweringDiagnostic>,
    pub applied_reductions: Vec<AppliedReductionDiagnostic>,
    pub reduction_notes: Vec<String>,
    pub property_compilations: Vec<PropertyCompilationDiagnostic>,
    pub property_results: Vec<PropertyResultDiagnostic>,
    pub phase_profiles: Vec<PhaseProfileDiagnostic>,
    pub smt_profiles: Vec<SmtProfileDiagnostic>,
}

fn execution_controls_lock() -> &'static Mutex<PipelineExecutionControls> {
    static CONTROLS: OnceLock<Mutex<PipelineExecutionControls>> = OnceLock::new();
    CONTROLS.get_or_init(|| Mutex::new(PipelineExecutionControls::default()))
}

thread_local! {
    static RUN_DIAGNOSTICS: RefCell<PipelineRunDiagnostics> = RefCell::new(PipelineRunDiagnostics::default());
    static EXECUTION_CONTROLS_OVERRIDE: RefCell<Option<PipelineExecutionControls>> = const { RefCell::new(None) };
}

/// Set execution controls for subsequent pipeline runs on the current thread.
///
/// This override is thread-local so parallel test/worker execution cannot
/// cross-contaminate POR/fallback settings. For process-wide defaults (used by
/// CLI entrypoints before spawning worker threads), call
/// [`set_global_execution_controls`].
pub fn set_execution_controls(controls: PipelineExecutionControls) {
    EXECUTION_CONTROLS_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = Some(controls);
    });
}

/// Clear the current thread's execution-controls override.
pub fn clear_execution_controls_override() {
    EXECUTION_CONTROLS_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Set process-wide execution controls used when no thread-local override exists.
pub fn set_global_execution_controls(controls: PipelineExecutionControls) {
    match execution_controls_lock().lock() {
        Ok(mut guard) => *guard = controls,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = controls;
        }
    }
}

fn global_execution_controls() -> PipelineExecutionControls {
    match execution_controls_lock().lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

fn current_execution_controls() -> PipelineExecutionControls {
    let local = EXECUTION_CONTROLS_OVERRIDE.with(|cell| *cell.borrow());
    local.unwrap_or_else(global_execution_controls)
}

/// Reset per-run diagnostics for the current thread.
pub fn reset_run_diagnostics() {
    RUN_DIAGNOSTICS.with(|cell| {
        *cell.borrow_mut() = PipelineRunDiagnostics::default();
    });
}

/// Return a snapshot of current per-run diagnostics.
pub fn current_run_diagnostics() -> PipelineRunDiagnostics {
    RUN_DIAGNOSTICS.with(|cell| cell.borrow().clone())
}

/// Return diagnostics and clear the per-run buffer.
pub fn take_run_diagnostics() -> PipelineRunDiagnostics {
    RUN_DIAGNOSTICS.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// An independently checkable proof obligation.
#[derive(Debug, Clone)]
pub struct SafetyProofObligation {
    pub name: String,
    pub expected: String,
    pub smt2: String,
}

/// A safety proof certificate bundle.
///
/// All obligations must evaluate to `expected` (currently `unsat`) under an
/// external SMT solver to validate the certificate independently.
#[derive(Debug, Clone)]
pub struct SafetyProofCertificate {
    pub protocol_file: String,
    pub proof_engine: ProofEngine,
    pub induction_k: Option<usize>,
    pub solver_used: SolverChoice,
    pub soundness: SoundnessMode,
    pub committee_bounds: Vec<(String, u64)>,
    pub obligations: Vec<SafetyProofObligation>,
}

/// A fair-liveness proof certificate bundle.
///
/// All obligations must evaluate to `expected` (currently `unsat`) under an
/// external SMT solver to validate the certificate independently.
#[derive(Debug, Clone)]
pub struct FairLivenessProofCertificate {
    pub protocol_file: String,
    pub fairness: FairnessMode,
    pub proof_engine: ProofEngine,
    pub frame: usize,
    pub solver_used: SolverChoice,
    pub soundness: SoundnessMode,
    pub committee_bounds: Vec<(String, u64)>,
    pub obligations: Vec<SafetyProofObligation>,
}

/// Statistics for round/view erasure abstraction.
#[derive(Debug, Clone)]
pub struct RoundAbstractionSummary {
    pub erased_vars: Vec<String>,
    pub original_locations: usize,
    pub abstract_locations: usize,
    pub original_shared_vars: usize,
    pub abstract_shared_vars: usize,
    pub original_message_counters: usize,
    pub abstract_message_counters: usize,
}

/// Result of proving safety on a round-erased abstraction.
#[derive(Debug, Clone)]
pub struct RoundAbstractionProofResult {
    pub summary: RoundAbstractionSummary,
    pub result: UnboundedSafetyResult,
}

/// Result of proving fair-liveness on a round-erased abstraction.
#[derive(Debug, Clone)]
pub struct RoundAbstractionFairProofResult {
    pub summary: RoundAbstractionSummary,
    pub result: UnboundedFairLivenessResult,
}

/// Parse a .trs source file into an AST.
///
/// If the filename refers to a real file path, any `import` declarations in
/// the parsed program are automatically resolved by loading and merging the
/// referenced files.
pub fn parse(source: &str, filename: &str) -> Result<ast::Program, PipelineError> {
    let started = Instant::now();
    let mut program = tarsier_dsl::parse(source, filename).map_err(PipelineError::from)?;
    push_phase_profile(filename, "parse", started.elapsed().as_millis());

    // Resolve imports if the filename is a real file path with a parent directory.
    if !program.protocol.node.imports.is_empty() {
        let path = std::path::Path::new(filename);
        if let Some(base_dir) = path.parent() {
            resolve_imports(&mut program, base_dir)?;
        }
    }
    Ok(program)
}

/// Resolve import declarations in a parsed program.
///
/// For each `import Name from "path";` declaration, the referenced file is
/// loaded (relative to `base_dir`), parsed, and its declarations are merged
/// into the program. This is a no-op when no imports are present.
pub fn resolve_imports(
    program: &mut ast::Program,
    base_dir: &std::path::Path,
) -> Result<(), PipelineError> {
    if program.protocol.node.imports.is_empty() {
        return Ok(());
    }
    tarsier_dsl::resolve_imports(program, base_dir).map_err(PipelineError::from)
}

/// Lower an AST into a threshold automaton.
pub fn lower(program: &ast::Program) -> Result<ThresholdAutomaton, PipelineError> {
    let started = Instant::now();
    let ta = lowering::lower(program).map_err(PipelineError::from)?;
    push_phase_profile("lower", "lower", started.elapsed().as_millis());
    ta.validate()
        .map_err(|e| PipelineError::Validation(e.to_string()))?;
    Ok(ta)
}

/// Lower an AST into a threshold automaton with rich source-span diagnostics.
///
/// When source text and filename are available, this provides miette-rendered
/// error messages pointing to the exact source location.
pub fn lower_with_source(
    program: &ast::Program,
    source: &str,
    filename: &str,
) -> Result<ThresholdAutomaton, SpannedLoweringError> {
    let ta = lowering::lower_with_source(program, source, filename)?;
    ta.validate().map_err(|e| SpannedLoweringError {
        src: miette::NamedSource::new(filename, source.to_owned()),
        inner: LoweringError::Validation(e.to_string()),
        span: None,
    })?;
    Ok(ta)
}

/// Abstract a threshold automaton into a counter system.
pub fn abstract_to_cs(ta: ThresholdAutomaton) -> CounterSystem {
    abstract_to_counter_system(ta)
}

// ---------------------------------------------------------------------------
// Submodules
// ---------------------------------------------------------------------------

pub(crate) mod analysis;
pub(crate) mod certification;
pub(crate) mod diagnostics;
pub(crate) mod property;
pub(crate) mod verification;

use diagnostics::push_phase_profile;

// ---------------------------------------------------------------------------
// Re-exports: maintain the same public API surface
// ---------------------------------------------------------------------------

// From property
pub use property::{
    classify_property_fragment, extract_property, select_property_for_ta_export,
    validate_property_fragments, FragmentDiagnostic, QuantifiedFragment,
};

// From analysis
pub use analysis::{comm_complexity, show_ta};

// From verification
pub use verification::{
    check_fair_liveness, check_fair_liveness_with_mode, check_liveness, completeness_preflight,
    prove_fair_liveness, prove_fair_liveness_with_cegar, prove_fair_liveness_with_cegar_report,
    prove_fair_liveness_with_mode, prove_fair_liveness_with_round_abstraction, prove_safety,
    prove_safety_with_cegar, prove_safety_with_cegar_report, prove_safety_with_round_abstraction,
    verify, verify_all_properties, verify_program_ast, verify_with_cegar, verify_with_cegar_report,
    CompletenessWarning,
};

// From certification
pub use certification::{
    generate_fair_liveness_certificate, generate_fair_liveness_certificate_with_mode,
    generate_kinduction_safety_certificate, generate_pdr_safety_certificate,
    generate_safety_certificate,
};

// Re-export the execution controls and diagnostics functions
// (already pub in this module)

fn current_rss_bytes() -> Option<u64> {
    crate::sandbox::current_rss_bytes()
}

#[cfg(test)]
mod tests {
    use super::analysis::*;
    use super::certification::*;
    use super::diagnostics::*;
    use super::property::*;
    use super::verification::*;
    use super::*;

    #[test]
    fn remaining_timeout_rounds_up_to_one_second() {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(50))
            .expect("deadline should be constructible");
        let remaining = remaining_timeout_secs(Some(deadline)).expect("remaining timeout present");
        assert!(remaining >= 1);
    }

    #[test]
    fn options_with_remaining_timeout_reports_expired_deadline() {
        let deadline = Instant::now() - Duration::from_millis(1);
        let options = PipelineOptions::default();
        let err = options_with_remaining_timeout(&options, Some(deadline), "cegar")
            .expect_err("expired deadline should fail");
        match err {
            PipelineError::Solver(reason) => assert!(reason.contains("timed out")),
            other => panic!("unexpected error kind: {other}"),
        }
    }

    #[test]
    fn execution_controls_use_thread_local_override_before_global_default() {
        set_global_execution_controls(PipelineExecutionControls {
            por_mode_override: Some(PorMode::Full),
            ..Default::default()
        });
        clear_execution_controls_override();

        assert_eq!(
            current_execution_controls().por_mode_override,
            Some(PorMode::Full),
            "global controls should apply when no thread-local override is present"
        );

        set_execution_controls(PipelineExecutionControls {
            por_mode_override: Some(PorMode::Off),
            ..Default::default()
        });
        assert_eq!(
            current_execution_controls().por_mode_override,
            Some(PorMode::Off),
            "thread-local controls should override global defaults"
        );

        clear_execution_controls_override();
        set_global_execution_controls(PipelineExecutionControls::default());
    }

    #[test]
    fn execution_controls_thread_local_overrides_are_isolated_across_threads() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        set_global_execution_controls(PipelineExecutionControls::default());
        clear_execution_controls_override();

        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            set_execution_controls(PipelineExecutionControls {
                por_mode_override: Some(PorMode::Full),
                ..Default::default()
            });
            worker_barrier.wait();
            let mode = current_execution_controls().por_mode_override;
            clear_execution_controls_override();
            mode
        });

        set_execution_controls(PipelineExecutionControls {
            por_mode_override: Some(PorMode::Off),
            ..Default::default()
        });
        barrier.wait();
        let main_mode = current_execution_controls().por_mode_override;
        clear_execution_controls_override();

        let worker_mode = handle.join().expect("worker thread should complete");
        assert_eq!(main_mode, Some(PorMode::Off));
        assert_eq!(worker_mode, Some(PorMode::Full));

        set_global_execution_controls(PipelineExecutionControls::default());
    }

    #[test]
    fn adaptive_cegar_seeds_plan_with_unsat_core_minimized_refinement_cover() {
        let src = r#"
protocol AdaptiveOrder {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        equivocation: full;
        auth: none;
        values: sign;
        network: classic;
    }
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
        let program = parse(src, "adaptive_order.trs").expect("program should parse");
        let signals = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: true,
            sign_abstract_values: true,
            identity_scoped_channels: false,
            conflicting_variant_families: BTreeSet::new(),
            cross_recipient_families: BTreeSet::new(),
        };
        let plan =
            cegar_refinement_plan_with_signals(&program, Some(&signals), SolverChoice::Z3, 5);
        assert!(
            !plan.is_empty(),
            "adaptive plan should produce at least one refinement stage"
        );
        assert!(
            plan[0]
                .rationale
                .contains("unsat-core minimized evidence cover"),
            "first stage should be selected from solver-backed UNSAT-core minimization"
        );
        assert!(
            plan[0].refinement.label().contains("values:exact"),
            "minimal evidence cover must retain values:exact when sign abstraction evidence is present"
        );
    }

    #[test]
    fn adaptive_cegar_plan_carries_evidence_rationale() {
        let src = r#"
protocol AdaptivePlan {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        equivocation: full;
        auth: none;
        values: sign;
        network: classic;
    }
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
        let program = parse(src, "adaptive_plan.trs").expect("program should parse");
        let signals = CegarTraceSignals {
            conflicting_variants: false,
            cross_recipient_delivery: false,
            sign_abstract_values: true,
            identity_scoped_channels: false,
            conflicting_variant_families: BTreeSet::new(),
            cross_recipient_families: BTreeSet::new(),
        };
        let plan =
            cegar_refinement_plan_with_signals(&program, Some(&signals), SolverChoice::Z3, 5);
        assert!(!plan.is_empty(), "plan should not be empty");
        assert_eq!(
            plan[0].refinement.label(),
            "values:exact",
            "value abstraction evidence should drive first refinement"
        );
        assert!(
            plan[0].rationale.contains("sign_abstract_values"),
            "first stage should record extracted evidence in rationale"
        );
    }

    #[test]
    fn adaptive_cegar_plan_is_deterministic_for_same_signals() {
        let src = r#"
protocol AdaptiveDeterministic {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        equivocation: full;
        auth: none;
        values: sign;
        network: classic;
    }
    message Vote(v: bool);
    message Ping(v: bool);
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
        let program = parse(src, "adaptive_deterministic.trs").expect("program should parse");
        let signals = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: true,
            sign_abstract_values: true,
            identity_scoped_channels: false,
            conflicting_variant_families: ["Vote".to_string()].into_iter().collect(),
            cross_recipient_families: ["Ping".to_string()].into_iter().collect(),
        };

        let plan_a =
            cegar_refinement_plan_with_signals(&program, Some(&signals), SolverChoice::Z3, 5);
        let plan_b =
            cegar_refinement_plan_with_signals(&program, Some(&signals), SolverChoice::Z3, 5);

        let labels_a: Vec<String> = plan_a
            .iter()
            .map(|entry| entry.refinement.label())
            .collect();
        let labels_b: Vec<String> = plan_b
            .iter()
            .map(|entry| entry.refinement.label())
            .collect();
        assert_eq!(labels_a, labels_b, "plan ordering should be deterministic");
        let refinements_a: Vec<Vec<String>> = plan_a
            .iter()
            .map(|entry| sorted_unique_strings(entry.refinement.refinements()))
            .collect();
        let refinements_b: Vec<Vec<String>> = plan_b
            .iter()
            .map(|entry| sorted_unique_strings(entry.refinement.refinements()))
            .collect();
        assert_eq!(
            refinements_a, refinements_b,
            "stage refinement payloads should be deterministic"
        );
    }

    #[test]
    fn adaptive_cegar_generates_message_scoped_refinements_from_trace_signals() {
        let src = r#"
protocol AdaptiveGenerated {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        equivocation: full;
        auth: none;
        values: exact;
        network: classic;
    }
    message Vote(v: bool);
    message Ping(v: bool);
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
        let program = parse(src, "adaptive_generated.trs").expect("program should parse");
        let signals = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: true,
            sign_abstract_values: false,
            identity_scoped_channels: false,
            conflicting_variant_families: ["Vote".to_string()].into_iter().collect(),
            cross_recipient_families: ["Ping".to_string()].into_iter().collect(),
        };
        let plan =
            cegar_refinement_plan_with_signals(&program, Some(&signals), SolverChoice::Z3, 5);
        let labels: HashSet<String> = plan.iter().map(|entry| entry.refinement.label()).collect();
        assert!(
            labels.contains("equivocation:Vote=none"),
            "trace-derived conflicting variants should synthesize message-scoped equivocation refinements"
        );
        assert!(
            labels.contains("channel:Ping=authenticated"),
            "trace-derived cross-recipient delivery should synthesize message-scoped auth refinements"
        );
    }

    #[test]
    fn cegar_core_compound_predicate_is_generated_for_multi_atom_cores() {
        let preds = vec![
            "adversary.equivocation=none".to_string(),
            "channel(Vote)=authenticated".to_string(),
        ];
        let combined = cegar_core_compound_predicate(&preds)
            .expect("multi-atom cores should produce a derived predicate");
        assert_eq!(
            combined,
            "cegar.core.min(adversary.equivocation=none && channel(Vote)=authenticated)"
        );
        assert!(
            cegar_core_compound_predicate(&["adversary.values=exact".to_string()]).is_none(),
            "single-atom cores should not emit derived conjunction predicates"
        );
    }

    #[test]
    fn cegar_core_shrinker_finds_minimal_elimination_subset() {
        let refinement = CegarRefinement {
            atoms: vec![
                CegarAtomicRefinement::global(
                    CegarRefinementKind::GlobalEquivocationNone,
                    "equivocation:none",
                    "adversary.equivocation=none",
                ),
                CegarAtomicRefinement::global(
                    CegarRefinementKind::GlobalAuthSigned,
                    "auth:signed",
                    "adversary.auth=signed",
                ),
                CegarAtomicRefinement::global(
                    CegarRefinementKind::GlobalNetworkProcessSelective,
                    "network:process_selective",
                    "adversary.network=process_selective",
                ),
            ],
        };

        let core = cegar_shrink_refinement_core(&refinement, |candidate| {
            // Simulate elimination iff process_selective is enabled.
            Ok(Some(
                candidate
                    .atoms
                    .iter()
                    .any(|atom| atom.label == "network:process_selective"),
            ))
        })
        .expect("core shrink should succeed")
        .expect("core should be reduced");

        assert_eq!(core.atoms.len(), 1);
        assert_eq!(core.atoms[0].label, "network:process_selective");
    }

    #[test]
    fn faithful_network_fallback_coarsens_when_budget_exceeded() {
        reset_run_diagnostics();
        let src = r#"
protocol FallbackBudget {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        network: process_selective;
    }
    identity R: process(pid) key r_key;
    message Vote(v: bool);
    role R {
        var pid: nat in 0..2;
        var decided: bool = false;
        init start;
        phase start {
            when received >= 0 Vote(v=true) => {
                goto phase start;
            }
        }
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let program = parse(src, "fallback_budget.trs").expect("program should parse");
        let controls = PipelineExecutionControls {
            faithful_fallback: Some(FaithfulFallbackConfig {
                max_locations: usize::MAX,
                max_shared_vars: usize::MAX,
                max_message_counters: 0,
                floor: FaithfulFallbackFloor::IdentitySelective,
            }),
            liveness_memory_budget_mb: None,
            por_mode_override: None,
        };
        let ta = lower_with_controls(&program, "test.fallback", controls)
            .expect("lowering with fallback should succeed");
        assert_eq!(ta.network_semantics, NetworkSemantics::IdentitySelective);

        let diag = take_run_diagnostics();
        assert!(
            diag.applied_reductions
                .iter()
                .any(|r| r.kind == "network_fallback"),
            "expected at least one fallback reduction entry"
        );
        let lowering = diag
            .lowerings
            .iter()
            .find(|entry| entry.context == "test.fallback")
            .expect("lowering diagnostic should be recorded");
        assert_eq!(lowering.requested_network, "process_selective");
        assert_eq!(lowering.effective_network, "identity_selective");
    }

    #[test]
    fn faithful_network_fallback_disabled_keeps_requested_mode() {
        reset_run_diagnostics();
        let src = r#"
protocol NoFallback {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        network: process_selective;
    }
    identity R: process(pid) key r_key;
    message Vote(v: bool);
    role R {
        var pid: nat in 0..1;
        var decided: bool = false;
        init start;
        phase start {
            when received >= 0 Vote(v=true) => {
                goto phase start;
            }
        }
    }
    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let program = parse(src, "no_fallback.trs").expect("program should parse");
        let ta = lower_with_controls(
            &program,
            "test.no_fallback",
            PipelineExecutionControls::default(),
        )
        .expect("lowering should succeed");
        assert_eq!(ta.network_semantics, NetworkSemantics::ProcessSelective);
        let diag = take_run_diagnostics();
        let lowering = diag
            .lowerings
            .iter()
            .find(|entry| entry.context == "test.no_fallback")
            .expect("lowering diagnostic should be recorded");
        assert_eq!(lowering.requested_network, "process_selective");
        assert_eq!(lowering.effective_network, "process_selective");
        assert!(diag.applied_reductions.is_empty());
    }

    #[test]
    fn lowering_records_independent_rule_pairs_for_por_visibility() {
        reset_run_diagnostics();
        let src = r#"
protocol IndependentRules {
    params n, t, f;
    resilience: n > 3*t;

    role A {
        var x: nat in 0..1;
        init start;
        phase start {
            when x == 0 => {
                x = 1;
                goto phase done;
            }
        }
        phase done {}
    }

    role B {
        var y: nat in 0..1;
        init start;
        phase start {
            when y == 0 => {
                y = 1;
                goto phase done;
            }
        }
        phase done {}
    }

    property inv: safety {
        forall p: A. p.x <= 1
    }
}
"#;
        let program = parse(src, "independent_rules.trs").expect("program should parse");
        let _ = lower_with_controls(
            &program,
            "test.independent_rules",
            PipelineExecutionControls::default(),
        )
        .expect("lowering should succeed");

        let diag = take_run_diagnostics();
        let lowering = diag
            .lowerings
            .iter()
            .find(|entry| entry.context == "test.independent_rules")
            .expect("lowering diagnostic should be recorded");
        assert!(
            lowering.independent_rule_pairs > 0,
            "expected at least one independent rule pair"
        );
        assert!(
            diag.reduction_notes
                .iter()
                .any(|note| note.starts_with("por.independent_rule_pairs=")),
            "expected POR independent-pair reduction note"
        );
        assert!(
            diag.reduction_notes
                .iter()
                .any(|note| note == "por.transition_multiset_semantics=on"),
            "expected POR semantics reduction note"
        );
    }

    #[test]
    fn lowering_reports_por_stutter_and_duplicate_pruning_counts() {
        reset_run_diagnostics();
        let src = r#"
protocol PorPruning {
    params n, t, f;
    resilience: n > 3*t;
    message Vote;

    role R {
        var x: nat in 0..1;
        init start;

        phase start {
            when x == 0 => {
                goto phase start;
            }

            when x == 0 => {
                send Vote;
                goto phase done;
            }

            when x == 0 => {
                send Vote;
                goto phase done;
            }
        }

        phase done {}
    }

    property inv: safety {
        forall p: R. p.x <= 1
    }
}
"#;
        let program = parse(src, "por_pruning.trs").expect("program should parse");
        let _ = lower_with_controls(
            &program,
            "test.por_pruning",
            PipelineExecutionControls::default(),
        )
        .expect("lowering should succeed");

        let diag = take_run_diagnostics();
        let lowering = diag
            .lowerings
            .iter()
            .find(|entry| entry.context == "test.por_pruning")
            .expect("lowering diagnostic should be recorded");
        assert!(
            lowering.por_stutter_rules_pruned >= 1,
            "expected stutter-rule pruning count to be reported"
        );
        assert!(
            lowering.por_commutative_duplicate_rules_pruned >= 1,
            "expected commutative-duplicate pruning count to be reported"
        );
        assert!(
            lowering.por_effective_rule_count < lowering.effective_footprint.rules,
            "effective rule count should be reduced by POR pruning"
        );
        assert!(
            diag.reduction_notes
                .iter()
                .any(|note| note.starts_with("por.stutter_rules_pruned=")),
            "expected stutter-pruning reduction note"
        );
        assert!(
            diag.reduction_notes
                .iter()
                .any(|note| note.starts_with("por.commutative_duplicate_rules_pruned=")),
            "expected duplicate-pruning reduction note"
        );
    }

    #[test]
    fn lowering_reports_por_guard_dominance_pruning_counts() {
        reset_run_diagnostics();
        let src = r#"
protocol PorDominance {
    params n, t, f;
    resilience: n > 3*t;
    message Vote;

    role R {
        var decided: bool = false;
        init start;

        phase start {
            when received >= 2 Vote => {
                send Vote;
                goto phase done;
            }

            when received >= 1 Vote => {
                send Vote;
                goto phase done;
            }
        }

        phase done {}
    }

    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#;
        let program = parse(src, "por_dominance.trs").expect("program should parse");
        let _ = lower_with_controls(
            &program,
            "test.por_dominance",
            PipelineExecutionControls::default(),
        )
        .expect("lowering should succeed");

        let diag = take_run_diagnostics();
        let lowering = diag
            .lowerings
            .iter()
            .find(|entry| entry.context == "test.por_dominance")
            .expect("lowering diagnostic should be recorded");
        assert!(
            lowering.por_guard_dominated_rules_pruned >= 1,
            "expected guard-dominance pruning count to be reported"
        );
        assert!(
            lowering.por_effective_rule_count < lowering.effective_footprint.rules,
            "effective rule count should be reduced by POR guard-dominance pruning"
        );
        assert!(
            diag.reduction_notes
                .iter()
                .any(|note| note.starts_with("por.guard_dominated_rules_pruned=")),
            "expected guard-dominance reduction note"
        );
    }

    #[test]
    fn fair_pdr_frame_insert_uses_cube_subsumption() {
        let specific = FairPdrCube {
            lits: vec![
                FairPdrCubeLit {
                    state_var_idx: 0,
                    value: 1,
                },
                FairPdrCubeLit {
                    state_var_idx: 1,
                    value: 2,
                },
            ],
        };
        let general = FairPdrCube {
            lits: vec![FairPdrCubeLit {
                state_var_idx: 0,
                value: 1,
            }],
        };
        let unrelated = FairPdrCube {
            lits: vec![FairPdrCubeLit {
                state_var_idx: 2,
                value: 0,
            }],
        };

        let mut frame = FairPdrFrame::default();
        frame.insert(specific.clone());
        frame.insert(general.clone());
        frame.insert(unrelated.clone());

        assert!(
            frame.contains(&general),
            "more general cube should be retained"
        );
        assert!(
            !frame.contains(&specific),
            "subsumed specific cube should be removed"
        );
        assert!(
            frame.contains(&unrelated),
            "non-subsumed cube should remain"
        );
    }

    // --- Quantified fragment contract tests ---

    fn make_property_decl(
        name: &str,
        kind: ast::PropertyKind,
        quantifiers: Vec<ast::QuantifierBinding>,
        body: ast::FormulaExpr,
    ) -> ast::PropertyDecl {
        ast::PropertyDecl {
            name: name.to_string(),
            kind,
            formula: ast::QuantifiedFormula { quantifiers, body },
        }
    }

    fn forall_binding(var: &str, domain: &str) -> ast::QuantifierBinding {
        ast::QuantifierBinding {
            quantifier: ast::Quantifier::ForAll,
            var: var.to_string(),
            domain: domain.to_string(),
        }
    }

    fn exists_binding(var: &str, domain: &str) -> ast::QuantifierBinding {
        ast::QuantifierBinding {
            quantifier: ast::Quantifier::Exists,
            var: var.to_string(),
            domain: domain.to_string(),
        }
    }

    fn eq_comparison(obj: &str, field: &str, val: bool) -> ast::FormulaExpr {
        ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::QualifiedVar {
                object: obj.to_string(),
                field: field.to_string(),
            },
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::BoolLit(val),
        }
    }

    fn agreement_eq(var_l: &str, var_r: &str, field: &str) -> ast::FormulaExpr {
        ast::FormulaExpr::Comparison {
            lhs: ast::FormulaAtom::QualifiedVar {
                object: var_l.to_string(),
                field: field.to_string(),
            },
            op: ast::CmpOp::Eq,
            rhs: ast::FormulaAtom::QualifiedVar {
                object: var_r.to_string(),
                field: field.to_string(),
            },
        }
    }

    #[test]
    fn fragment_classifies_agreement() {
        let prop = make_property_decl(
            "agr",
            ast::PropertyKind::Agreement,
            vec![forall_binding("p", "R"), forall_binding("q", "R")],
            agreement_eq("p", "q", "vote"),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalAgreement);
        assert!(frag
            .soundness_statement()
            .contains("conflicting decision values"));
    }

    #[test]
    fn fragment_classifies_invariant() {
        let prop = make_property_decl(
            "inv",
            ast::PropertyKind::Invariant,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "x", true),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalInvariant);
        assert!(frag.soundness_statement().contains("invariant predicate"));
    }

    #[test]
    fn fragment_classifies_safety() {
        let prop = make_property_decl(
            "safe",
            ast::PropertyKind::Safety,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "x", false),
        );
        assert_eq!(
            classify_property_fragment(&prop).unwrap(),
            QuantifiedFragment::UniversalInvariant
        );
    }

    #[test]
    fn fragment_classifies_validity() {
        let prop = make_property_decl(
            "val",
            ast::PropertyKind::Validity,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "x", true),
        );
        assert_eq!(
            classify_property_fragment(&prop).unwrap(),
            QuantifiedFragment::UniversalInvariant
        );
    }

    #[test]
    fn fragment_classifies_termination_liveness() {
        let prop = make_property_decl(
            "term",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "decided", true),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTermination);
        assert!(frag.soundness_statement().contains("fair execution"));
    }

    #[test]
    fn fragment_classifies_temporal_liveness() {
        let prop = make_property_decl(
            "live",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "decided", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
        assert!(frag.soundness_statement().contains("Büchi automaton"));
    }

    #[test]
    fn fragment_classifies_existential_in_safety_as_existential_temporal() {
        let prop = make_property_decl(
            "exists_safe",
            ast::PropertyKind::Safety,
            vec![exists_binding("p", "R")],
            eq_comparison("p", "x", true),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::ExistentialTemporal);
    }

    #[test]
    fn fragment_rejects_existential_in_agreement() {
        let prop = make_property_decl(
            "bad_exists_agr",
            ast::PropertyKind::Agreement,
            vec![exists_binding("p", "R"), forall_binding("q", "R")],
            agreement_eq("p", "q", "vote"),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("supports only universal quantifiers"));
    }

    #[test]
    fn fragment_rejects_agreement_wrong_quantifier_count() {
        let prop = make_property_decl(
            "bad_agr",
            ast::PropertyKind::Agreement,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "x", true),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("exactly 2 universal quantifiers"));
    }

    #[test]
    fn fragment_rejects_agreement_different_roles() {
        let prop = make_property_decl(
            "bad_agr_roles",
            ast::PropertyKind::Agreement,
            vec![
                forall_binding("p", "Sender"),
                forall_binding("q", "Receiver"),
            ],
            agreement_eq("p", "q", "vote"),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("same role"));
    }

    #[test]
    fn fragment_classifies_temporal_in_safety_kind_as_temporal() {
        let prop = make_property_decl(
            "bad_temporal_safety",
            ast::PropertyKind::Invariant,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Always(Box::new(eq_comparison("p", "x", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn fragment_classifies_temporal_in_agreement_as_temporal() {
        let prop = make_property_decl(
            "bad_temporal_agr",
            ast::PropertyKind::Agreement,
            vec![forall_binding("p", "R"), forall_binding("q", "R")],
            ast::FormulaExpr::Always(Box::new(agreement_eq("p", "q", "vote"))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn fragment_rejects_liveness_wrong_quantifier_count() {
        let prop = make_property_decl(
            "bad_live_q",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R"), forall_binding("q", "R")],
            ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "decided", true))),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("exactly 1 quantifier"));
    }

    #[test]
    fn fragment_display_roundtrip() {
        let fragments = vec![
            (
                QuantifiedFragment::UniversalAgreement,
                "universal-agreement",
            ),
            (
                QuantifiedFragment::UniversalInvariant,
                "universal-invariant",
            ),
            (
                QuantifiedFragment::UniversalTermination,
                "universal-termination",
            ),
            (QuantifiedFragment::UniversalTemporal, "universal-temporal"),
            (
                QuantifiedFragment::ExistentialTemporal,
                "existential-temporal",
            ),
        ];
        for (frag, expected) in fragments {
            assert_eq!(frag.to_string(), expected);
        }
    }

    #[test]
    fn validate_property_fragments_all_valid() {
        let src = r#"
protocol Frag {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = false;
        init start;
        phase start {}
    }

    property agr: agreement {
        forall p: R. forall q: R.
            p.decided == q.decided
    }
}
        "#;
        let program = tarsier_dsl::parse(src, "test.trs").expect("parse");
        let result = validate_property_fragments(&program);
        let frags = result.expect("all valid");
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, "agr");
        assert_eq!(frags[0].1, QuantifiedFragment::UniversalAgreement);
    }

    #[test]
    fn validate_property_fragments_rejects_bad_shape() {
        let src = r#"
protocol Frag {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = false;
        init start;
        phase start {}
    }

    property bad: agreement {
        forall p: R.
            p.decided == true
    }
}
        "#;
        let program = tarsier_dsl::parse(src, "test.trs").expect("parse");
        let result = validate_property_fragments(&program);
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .message
            .contains("exactly 2 universal quantifiers"));
    }

    // --- LTL Conformance Suite ---
    //
    // Tests canonical LTL pattern classes from the Manna-Pnueli hierarchy:
    //   Safety:      []p          (invariance)
    //   Guarantee:   <>p          (reachability)
    //   Obligation:  []p || <>q   (safety ∪ guarantee)
    //   Response:    p ~> <>q     (leads-to)
    //   Persistence: <>[]p        (stability)
    //   Reactivity:  []<>p ==> []<>q

    #[test]
    fn ltl_conformance_safety_always_p() {
        // []p is a safety property — should be classified as temporal liveness
        // when used with liveness kind (or as invariant when no temporal ops).
        // As a liveness formula with temporal ops, it becomes UniversalTemporal.
        let prop = make_property_decl(
            "safety_always",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Always(Box::new(eq_comparison("p", "x", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_guarantee_eventually_p() {
        // <>p — reachability / guarantee
        let prop = make_property_decl(
            "guarantee_eventually",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "decided", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_obligation_always_or_eventually() {
        // []p || <>q — obligation class
        let prop = make_property_decl(
            "obligation",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::Always(Box::new(eq_comparison(
                    "p", "x", true,
                )))),
                Box::new(ast::FormulaExpr::Eventually(Box::new(eq_comparison(
                    "p", "y", true,
                )))),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_response_leads_to() {
        // p ~> <>q — response class (leads-to is syntactic sugar for [](p ==> <>q))
        let prop = make_property_decl(
            "response",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::LeadsTo(
                Box::new(eq_comparison("p", "ready", true)),
                Box::new(ast::FormulaExpr::Eventually(Box::new(eq_comparison(
                    "p", "done", true,
                )))),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_persistence_eventually_always() {
        // <>[]p — persistence / stability
        let prop = make_property_decl(
            "persistence",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Eventually(Box::new(ast::FormulaExpr::Always(Box::new(
                eq_comparison("p", "stable", true),
            )))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_reactivity_gf_implies_gf() {
        // []<>p ==> []<>q — reactivity class
        let prop = make_property_decl(
            "reactivity",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Implies(
                Box::new(ast::FormulaExpr::Always(Box::new(
                    ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "req", true))),
                ))),
                Box::new(ast::FormulaExpr::Always(Box::new(
                    ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "ack", true))),
                ))),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_until() {
        // p U q — until (fundamental LTL operator)
        let prop = make_property_decl(
            "until",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Until(
                Box::new(eq_comparison("p", "waiting", true)),
                Box::new(eq_comparison("p", "done", true)),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_weak_until() {
        // p W q — weak until (either p holds until q, or p holds forever)
        let prop = make_property_decl(
            "weak_until",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::WeakUntil(
                Box::new(eq_comparison("p", "waiting", true)),
                Box::new(eq_comparison("p", "done", true)),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_release() {
        // p R q — release (dual of until)
        let prop = make_property_decl(
            "release",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Release(
                Box::new(eq_comparison("p", "reset", true)),
                Box::new(eq_comparison("p", "hold", true)),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_conformance_next() {
        // X p — next-step operator
        let prop = make_property_decl(
            "next_step",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Next(Box::new(eq_comparison("p", "ready", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    // Fail-fast diagnostic tests for still-unsupported LTL shapes

    #[test]
    fn ltl_conformance_temporal_in_invariant_kind_is_temporal_fragment() {
        // []p under kind `invariant` is now classified into the temporal fragment.
        let prop = make_property_decl(
            "bad_inv_temporal",
            ast::PropertyKind::Invariant,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::Always(Box::new(eq_comparison("p", "x", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    #[test]
    fn ltl_classifies_existential_in_liveness_as_existential_temporal() {
        let prop = make_property_decl(
            "exists_live",
            ast::PropertyKind::Liveness,
            vec![exists_binding("p", "R")],
            ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "x", true))),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::ExistentialTemporal);
    }

    #[test]
    fn ltl_failfast_multiple_quantifiers_in_liveness() {
        let prop = make_property_decl(
            "bad_multi_q_live",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R"), forall_binding("q", "R")],
            ast::FormulaExpr::Eventually(Box::new(eq_comparison("p", "x", true))),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("exactly 1 quantifier"));
    }

    #[test]
    fn ltl_failfast_zero_quantifiers_in_safety() {
        let prop = make_property_decl(
            "bad_no_q",
            ast::PropertyKind::Safety,
            vec![],
            eq_comparison("p", "x", true),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert!(err.message.contains("exactly 1 quantifier"));
    }

    #[test]
    fn ltl_failfast_diagnostic_has_property_name() {
        let prop = make_property_decl(
            "my_broken_prop",
            ast::PropertyKind::Agreement,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "x", true),
        );
        let err = classify_property_fragment(&prop).unwrap_err();
        assert_eq!(err.property_name, "my_broken_prop");
        // Display should include the property name
        let display = format!("{err}");
        assert!(display.contains("my_broken_prop"));
    }

    #[test]
    fn ltl_conformance_propositional_termination() {
        // p.decided == true (no temporal ops) under liveness kind →
        // UniversalTermination (propositional goal-location check)
        let prop = make_property_decl(
            "prop_term",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            eq_comparison("p", "decided", true),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTermination);
    }

    #[test]
    fn ltl_conformance_nested_leads_to() {
        // Nested leads-to: (p.x == true) ~> ((p.y == true) ~> (p.z == true))
        let prop = make_property_decl(
            "nested_leads_to",
            ast::PropertyKind::Liveness,
            vec![forall_binding("p", "R")],
            ast::FormulaExpr::LeadsTo(
                Box::new(eq_comparison("p", "x", true)),
                Box::new(ast::FormulaExpr::LeadsTo(
                    Box::new(eq_comparison("p", "y", true)),
                    Box::new(eq_comparison("p", "z", true)),
                )),
            ),
        );
        let frag = classify_property_fragment(&prop).unwrap();
        assert_eq!(frag, QuantifiedFragment::UniversalTemporal);
    }

    // --- Multi-property result tests ---

    #[test]
    fn multi_property_result_all_safe() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agr".into(),
                    fragment: "universal-agreement".into(),
                    result: VerificationResult::Safe { depth_checked: 4 },
                },
                PropertyVerdict {
                    name: "inv".into(),
                    fragment: "universal-invariant".into(),
                    result: VerificationResult::Safe { depth_checked: 4 },
                },
            ],
        };
        assert!(result.all_safe());
        assert!(!result.any_unsafe());
        assert_eq!(result.overall_verdict(), "safe");
    }

    #[test]
    fn multi_property_result_one_unsafe() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agr".into(),
                    fragment: "universal-agreement".into(),
                    result: VerificationResult::Safe { depth_checked: 4 },
                },
                PropertyVerdict {
                    name: "inv".into(),
                    fragment: "universal-invariant".into(),
                    result: VerificationResult::Unsafe {
                        trace: tarsier_ir::counter_system::Trace {
                            initial_config: tarsier_ir::counter_system::Configuration::new(0, 0, 0),
                            param_values: vec![],
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
    fn multi_property_result_inconclusive() {
        let result = MultiPropertyResult {
            verdicts: vec![
                PropertyVerdict {
                    name: "agr".into(),
                    fragment: "universal-agreement".into(),
                    result: VerificationResult::Safe { depth_checked: 4 },
                },
                PropertyVerdict {
                    name: "inv".into(),
                    fragment: "universal-invariant".into(),
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

    #[test]
    fn verify_all_properties_checks_safety_and_liveness_independently() {
        let src = r#"
protocol MultiProps {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property inv_ok: safety {
        forall p: R. p.decided == true
    }

    property inv_bad: safety {
        forall p: R. p.decided == false
    }

    property live_ok: liveness {
        forall p: R. p.decided == true
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Permissive,
            max_depth: 2,
            ..Default::default()
        };

        let result =
            verify_all_properties(src, "multi_props.trs", &options).expect("multi-property run");
        let names: Vec<String> = result.verdicts.iter().map(|v| v.name.clone()).collect();
        assert_eq!(names, vec!["inv_ok", "inv_bad", "live_ok"]);

        let inv_ok = result
            .verdicts
            .iter()
            .find(|v| v.name == "inv_ok")
            .expect("inv_ok verdict");
        assert!(matches!(
            inv_ok.result,
            VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
        ));

        let inv_bad = result
            .verdicts
            .iter()
            .find(|v| v.name == "inv_bad")
            .expect("inv_bad verdict");
        assert!(matches!(inv_bad.result, VerificationResult::Unsafe { .. }));

        let live_ok = result
            .verdicts
            .iter()
            .find(|v| v.name == "live_ok")
            .expect("live_ok verdict");
        assert!(matches!(live_ok.result, VerificationResult::Safe { .. }));

        let diag = take_run_diagnostics();
        assert_eq!(
            diag.property_results.len(),
            3,
            "per-property machine-readable diagnostics should include all declarations"
        );
        let live_entry = diag
            .property_results
            .iter()
            .find(|r| r.property_name == "live_ok")
            .expect("live_ok machine-readable result");
        assert_eq!(live_entry.property_id, "live_ok");
        assert_eq!(live_entry.verdict, "safe");
        assert_eq!(live_entry.assumptions.solver, "z3");
        assert_eq!(live_entry.assumptions.max_depth, 2);
        assert!(live_entry.witness.is_none());
    }

    #[test]
    fn verify_all_properties_routes_temporal_safety_kind_to_temporal_backend() {
        let src = r#"
protocol TemporalSafetyKind {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property inv_temporal: safety {
        forall p: R. [] (p.decided == true)
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Permissive,
            max_depth: 2,
            ..Default::default()
        };

        let result = verify_all_properties(src, "temporal_safety_kind.trs", &options)
            .expect("multi-property temporal safety run");
        assert_eq!(result.verdicts.len(), 1);
        assert_eq!(result.verdicts[0].name, "inv_temporal");
        assert_eq!(result.verdicts[0].fragment, "universal-temporal");
        assert!(matches!(
            result.verdicts[0].result,
            VerificationResult::Safe { .. }
        ));
    }

    #[test]
    fn verify_routes_temporal_safety_kind_to_temporal_backend() {
        let src = r#"
protocol TemporalSafetyKindSingle {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property inv_temporal: safety {
        forall p: R. [] (p.decided == true)
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Strict,
            max_depth: 2,
            ..Default::default()
        };

        let result = verify(src, "temporal_safety_kind_single.trs", &options)
            .expect("single-property temporal safety run");
        assert!(matches!(result, VerificationResult::Safe { .. }));
    }

    #[test]
    fn verify_all_properties_routes_exists_safety_kind_to_temporal_backend() {
        let src = r#"
protocol ExistsSafetyKind {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property some_decided_always: safety {
        exists p: R. p.decided == true
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Permissive,
            max_depth: 2,
            ..Default::default()
        };

        let result = verify_all_properties(src, "exists_safety_kind.trs", &options)
            .expect("multi-property exists safety run");
        assert_eq!(result.verdicts.len(), 1);
        assert_eq!(result.verdicts[0].name, "some_decided_always");
        assert_eq!(result.verdicts[0].fragment, "existential-temporal");
        assert!(matches!(
            result.verdicts[0].result,
            VerificationResult::Safe { .. }
        ));
    }

    #[test]
    fn verify_routes_exists_safety_kind_to_temporal_backend() {
        let src = r#"
protocol ExistsSafetyKindSingle {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property some_decided_always: safety {
        exists p: R. p.decided == true
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Strict,
            max_depth: 2,
            ..Default::default()
        };

        let result = verify(src, "exists_safety_kind_single.trs", &options)
            .expect("single-property exists safety run");
        assert!(matches!(result, VerificationResult::Safe { .. }));
    }

    #[test]
    fn verify_all_properties_emits_deterministic_property_compilation_trace() {
        let src = r#"
protocol MultiPropsTemporal {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property inv_ok: safety {
        forall p: R. p.decided == true
    }

    property live_temporal: liveness {
        forall p: R. [] (p.decided == true)
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Permissive,
            max_depth: 2,
            ..Default::default()
        };

        let first = verify_all_properties(src, "multi_props_temporal.trs", &options)
            .expect("first multi-property run");
        assert_eq!(first.verdicts.len(), 2);
        let diag_a = take_run_diagnostics();
        assert!(
            !diag_a.property_compilations.is_empty(),
            "property compilation diagnostics should be populated"
        );
        assert!(
            diag_a
                .property_compilations
                .iter()
                .any(|d| d.compilation_target == "temporal_buchi_monitor"),
            "temporal monitor compilation trace should be present"
        );
        assert!(
            diag_a
                .property_compilations
                .iter()
                .any(|d| d.compilation_target == "liveness_temporal_constraints"),
            "temporal constraint compilation trace should be present"
        );

        let second = verify_all_properties(src, "multi_props_temporal.trs", &options)
            .expect("second multi-property run");
        assert_eq!(second.verdicts.len(), 2);
        let diag_b = take_run_diagnostics();
        assert_eq!(
            diag_a.property_compilations, diag_b.property_compilations,
            "property compilation traces should be deterministic across identical runs"
        );
        assert_eq!(
            diag_a.property_results, diag_b.property_results,
            "machine-readable per-property results should be deterministic across identical runs"
        );
    }

    #[test]
    fn temporal_counterexample_includes_monitor_state_metadata() {
        let src = r#"
protocol TemporalFailing {
    params n, t;
    resilience: n > 3*t;

    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }

    property live_eventually: liveness {
        forall p: R. <> (p.decided == true)
    }
}
"#;
        let options = PipelineOptions {
            soundness: SoundnessMode::Permissive,
            max_depth: 3,
            ..Default::default()
        };

        let result =
            verify_all_properties(src, "temporal_failing.trs", &options).expect("verify all");
        let live = result
            .verdicts
            .iter()
            .find(|v| v.name == "live_eventually")
            .expect("live_eventually verdict");
        assert!(matches!(live.result, VerificationResult::Unsafe { .. }));

        let diag = take_run_diagnostics();
        let entry = diag
            .property_results
            .iter()
            .find(|r| r.property_name == "live_eventually")
            .expect("live_eventually property result");
        assert_eq!(entry.verdict, "unsafe");
        let witness = entry.witness.as_ref().expect("witness metadata");
        assert_eq!(witness.witness_kind, "temporal_monitor_counterexample");
        let monitor = witness
            .temporal_monitor
            .as_ref()
            .expect("temporal monitor replay");
        assert!(
            !monitor.is_empty(),
            "temporal monitor replay should provide step-by-step monitor state"
        );
        assert_eq!(
            monitor[0].step, 0,
            "monitor trace must include initial monitor state"
        );
    }

    // --- Multi-signal correlation scoring tests ---

    #[test]
    fn multi_signal_correlation_bonus_applied() {
        // An atom matching two independent signals should score higher
        // than the same atom matching only one.
        let atom = CegarAtomicRefinement {
            kind: CegarRefinementKind::GlobalAuthSigned,
            label: "auth:signed".into(),
            predicate: "adversary.auth=signed".into(),
        };

        let single_signal = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: false,
            ..Default::default()
        };
        let double_signal = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: true,
            ..Default::default()
        };

        let score_single = cegar_refinement_score(&atom, &single_signal);
        let score_double = cegar_refinement_score(&atom, &double_signal);

        assert!(
            score_double > score_single,
            "double evidence ({score_double}) should score higher than single ({score_single})"
        );
        // The multi-signal bonus should be at least 25 (the 2-signal correlation bonus)
        assert!(
            score_double - score_single >= 25,
            "multi-signal bonus should be >= 25, got {}",
            score_double - score_single
        );
    }

    #[test]
    fn evidence_tag_count_matches_signal_analysis() {
        let atom_auth = CegarAtomicRefinement {
            kind: CegarRefinementKind::GlobalAuthSigned,
            label: "auth:signed".into(),
            predicate: "adversary.auth=signed".into(),
        };
        let signals = CegarTraceSignals {
            conflicting_variants: true,
            cross_recipient_delivery: true,
            sign_abstract_values: false,
            identity_scoped_channels: false,
            ..Default::default()
        };
        assert_eq!(
            cegar_atom_evidence_tag_count(&atom_auth, &signals),
            2,
            "GlobalAuthSigned with conflicting_variants + cross_recipient should count 2"
        );

        let atom_network = CegarAtomicRefinement {
            kind: CegarRefinementKind::GlobalNetworkProcessSelective,
            label: "network:process_selective".into(),
            predicate: "adversary.network=process_selective".into(),
        };
        let signals_triple = CegarTraceSignals {
            cross_recipient_delivery: true,
            identity_scoped_channels: true,
            ..Default::default()
        };
        assert_eq!(
            cegar_atom_evidence_tag_count(&atom_network, &signals_triple),
            2,
            "ProcessSelective with cross_recipient + identity_scoped should count 2"
        );
    }

    #[test]
    fn step_impact_estimate_counts_relevant_changes() {
        use tarsier_ir::counter_system::{Configuration, Trace, TraceStep};
        use tarsier_ir::threshold_automaton::SharedVar;

        // Build a minimal TA with 2 shared vars: one message counter, one shared var.
        let mut ta = ThresholdAutomaton::default();
        ta.shared_vars.push(SharedVar {
            name: "cnt_Vote@R".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.shared_vars.push(SharedVar {
            name: "decided".into(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });

        let atom = CegarAtomicRefinement {
            kind: CegarRefinementKind::GlobalEquivocationNone,
            label: "equivocation:none".into(),
            predicate: "equivocation:none".into(),
        };

        let trace = Trace {
            param_values: vec![],
            initial_config: Configuration {
                kappa: vec![1],
                gamma: vec![0, 0],
                params: vec![],
            },
            steps: vec![
                TraceStep {
                    smt_step: 0,
                    rule_id: 0,
                    delta: 1,
                    deliveries: vec![],
                    config: Configuration {
                        kappa: vec![1],
                        gamma: vec![1, 0],
                        params: vec![],
                    },
                    por_status: None,
                },
                TraceStep {
                    smt_step: 1,
                    rule_id: 0,
                    delta: 1,
                    deliveries: vec![],
                    config: Configuration {
                        kappa: vec![0],
                        gamma: vec![1, 1],
                        params: vec![],
                    },
                    por_status: None,
                },
            ],
        };

        let impact = cegar_step_impact_estimate(&atom, &ta, &trace);
        assert_eq!(
            impact, 1,
            "only step 0 changed cnt_Vote (message counter), step 1 only changed decided (shared)"
        );
    }

    #[test]
    fn classify_cti_can_report_concrete_when_hypothesis_is_reachable() {
        use std::collections::HashMap;
        use tarsier_smt::solver::ModelValue;

        let src = r#"
protocol CtiConcreteClassification {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
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
        let program = parse(src, "cti_concrete_classification.trs").expect("parse");
        let ta =
            lower_with_active_controls(&program, "cti_concrete_classification").expect("lower");
        let cs = abstract_to_cs(ta.clone());
        let property =
            extract_property(&ta, &program, SoundnessMode::Strict).expect("extract property");

        let mut model_values: HashMap<String, ModelValue> = HashMap::new();
        for (pid, param) in ta.parameters.iter().enumerate() {
            let value = match param.name.as_str() {
                "n" => 1,
                "t" | "f" => 0,
                _ => 0,
            };
            model_values.insert(format!("p_{pid}"), ModelValue::Int(value));
        }
        for loc_id in 0..ta.locations.len() {
            let value = if ta.initial_locations.contains(&loc_id) {
                1
            } else {
                0
            };
            model_values.insert(format!("kappa_0_{loc_id}"), ModelValue::Int(value));
        }
        for var_id in 0..ta.shared_vars.len() {
            model_values.insert(format!("g_0_{var_id}"), ModelValue::Int(0));
        }

        let witness = KInductionCti {
            k: 1,
            model: Model {
                values: model_values,
            },
        };
        let params: Vec<(String, i64)> = ta
            .parameters
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    p.name.clone(),
                    witness.model.get_int(&format!("p_{i}")).unwrap_or(0),
                )
            })
            .collect();
        let hypothesis_locations = collect_named_location_values(&ta, &witness.model, 0);

        let options = PipelineOptions {
            solver: SolverChoice::Z3,
            max_depth: 1,
            timeout_secs: 5,
            dump_smt: None,
            soundness: SoundnessMode::Strict,
            proof_engine: ProofEngine::KInduction,
        };
        let (classification, evidence) = classify_cti(
            &cs,
            &witness,
            witness.k,
            0,
            &hypothesis_locations,
            &params,
            &ta,
            &[],
            &options,
        );
        assert_eq!(
            classification,
            CtiClassification::Concrete,
            "reachable hypothesis should classify as concrete"
        );
        assert!(
            evidence
                .iter()
                .any(|entry| entry.contains("reachability replay is SAT")),
            "classification evidence should include SAT reachability replay details: {evidence:?}"
        );

        // Keep this assertion to ensure the witness and extracted property are
        // at least internally coherent for the CTI summary surface.
        let summary = build_induction_cti_summary(&cs, &property, &witness, 0, &[], &options);
        assert_eq!(summary.classification, CtiClassification::Concrete);
    }

    // ---- certification tests ----

    #[test]
    fn query_to_smt2_script_produces_valid_smtlib2() {
        use tarsier_smt::sorts::SmtSort;
        use tarsier_smt::terms::SmtTerm;

        let decls = vec![
            ("x".to_string(), SmtSort::Int),
            ("b".to_string(), SmtSort::Bool),
        ];
        let assertions = vec![SmtTerm::var("x").ge(SmtTerm::int(0)), SmtTerm::var("b")];
        let smt2 = query_to_smt2_script(&decls, &assertions);

        assert!(smt2.starts_with("(set-logic QF_LIA)\n"));
        assert!(smt2.contains("(declare-const x Int)"));
        assert!(smt2.contains("(declare-const b Bool)"));
        assert!(smt2.contains("(assert"));
        assert!(smt2.ends_with("(check-sat)\n(exit)\n"));
    }

    #[test]
    fn query_to_smt2_script_empty_inputs() {
        let smt2 = query_to_smt2_script(&[], &[]);
        assert_eq!(smt2, "(set-logic QF_LIA)\n(check-sat)\n(exit)\n");
    }

    #[test]
    fn pdr_certificate_produces_three_obligations() {
        use tarsier_smt::bmc::PdrInvariantCertificate;
        use tarsier_smt::sorts::SmtSort;
        use tarsier_smt::terms::SmtTerm;

        let cert = PdrInvariantCertificate {
            frame: 3,
            declarations: vec![
                ("x".to_string(), SmtSort::Int),
                ("x_prime".to_string(), SmtSort::Int),
            ],
            init_assertions: vec![SmtTerm::var("x").eq(SmtTerm::int(0))],
            transition_assertions: vec![
                SmtTerm::var("x_prime").eq(SmtTerm::var("x").add(SmtTerm::int(1)))
            ],
            bad_pre: SmtTerm::var("x").ge(SmtTerm::int(10)),
            invariant_pre: vec![SmtTerm::var("x").le(SmtTerm::int(9))],
            invariant_post: vec![SmtTerm::var("x_prime").le(SmtTerm::int(9))],
        };

        let obligations = pdr_certificate_to_obligations(&cert, &[]);
        assert_eq!(obligations.len(), 3);
        assert_eq!(obligations[0].name, "init_implies_inv");
        assert_eq!(obligations[1].name, "inv_and_transition_implies_inv_prime");
        assert_eq!(obligations[2].name, "inv_implies_safe");
        for ob in &obligations {
            assert_eq!(ob.expected, "unsat");
            assert!(ob.smt2.contains("(set-logic QF_LIA)"));
            assert!(ob.smt2.contains("(check-sat)"));
        }
    }

    #[test]
    fn pdr_certificate_includes_extra_assertions() {
        use tarsier_smt::bmc::PdrInvariantCertificate;
        use tarsier_smt::sorts::SmtSort;
        use tarsier_smt::terms::SmtTerm;

        let cert = PdrInvariantCertificate {
            frame: 1,
            declarations: vec![("n".to_string(), SmtSort::Int)],
            init_assertions: vec![SmtTerm::bool(true)],
            transition_assertions: vec![SmtTerm::bool(true)],
            bad_pre: SmtTerm::bool(false),
            invariant_pre: vec![SmtTerm::bool(true)],
            invariant_post: vec![SmtTerm::bool(true)],
        };
        let extra = vec![SmtTerm::var("n").ge(SmtTerm::int(4))];

        let obligations = pdr_certificate_to_obligations(&cert, &extra);
        // Extra assertions should appear in all three obligations
        for ob in &obligations {
            assert!(
                ob.smt2.contains("n"),
                "obligation '{}' should reference extra assertion variable",
                ob.name
            );
        }
    }

    #[test]
    fn fair_pdr_certificate_produces_three_obligations() {
        use tarsier_smt::sorts::SmtSort;
        use tarsier_smt::terms::SmtTerm;

        let cert = FairPdrInvariantCertificate {
            frame: 2,
            declarations: vec![("x".to_string(), SmtSort::Int)],
            init_assertions: vec![SmtTerm::var("x").eq(SmtTerm::int(0))],
            transition_assertions: vec![SmtTerm::bool(true)],
            bad_pre: SmtTerm::bool(false),
            invariant_pre: vec![SmtTerm::var("x").ge(SmtTerm::int(0))],
            invariant_post: vec![SmtTerm::var("x").ge(SmtTerm::int(0))],
        };

        let obligations = fair_pdr_certificate_to_obligations(&cert, &[]);
        assert_eq!(obligations.len(), 3);
        assert_eq!(obligations[0].name, "init_implies_inv");
        assert_eq!(obligations[1].name, "inv_and_transition_implies_inv_prime");
        assert_eq!(obligations[2].name, "inv_implies_no_fair_bad");
        for ob in &obligations {
            assert_eq!(ob.expected, "unsat");
        }
    }

    #[test]
    fn pdr_certificate_empty_invariant_uses_true() {
        use tarsier_smt::bmc::PdrInvariantCertificate;
        use tarsier_smt::sorts::SmtSort;
        use tarsier_smt::terms::SmtTerm;

        let cert = PdrInvariantCertificate {
            frame: 1,
            declarations: vec![("x".to_string(), SmtSort::Int)],
            init_assertions: vec![],
            transition_assertions: vec![],
            bad_pre: SmtTerm::bool(false),
            invariant_pre: vec![],  // empty => should become `true`
            invariant_post: vec![], // empty => should become `true`
        };

        let obligations = pdr_certificate_to_obligations(&cert, &[]);
        assert_eq!(obligations.len(), 3);
        // With empty invariant (true), init_implies_inv should have (not true) = false,
        // making it trivially UNSAT
        assert!(obligations[0].smt2.contains("true"));
    }
}
