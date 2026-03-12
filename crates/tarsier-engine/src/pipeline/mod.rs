// PipelineError carries diagnostic payloads (traces, footprints) that would lose
// ergonomics if boxed; callers pattern-match directly on error variants.
#![allow(clippy::result_large_err)]
// Submodules use `use super::*` to access these imports; the unused_imports lint
// fires because the items are not referenced directly in this file.

use serde::Serialize;
use sha2::Sha256;
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
    CegarCounterexampleAnalysis, CegarEliminatedTrace, CegarLassoWitness, CegarModelChange,
    CegarPredicateScore, CegarRunControls, CegarStageOutcome, CegarStageReport, CegarTermination,
    CommComplexityReport, CommitteeAnalysisSummary, CtiClassification, FairLivenessResult,
    FairnessSemantics, InductionCtiSummary, LivenessResult, ModelAssumptions, ModelMetadata,
    MultiPropertyResult, ProbabilisticConfidenceInterval, PropertyVerdict,
    QuantitativeAnalysisEnvironment, QuantitativeAnalysisOptions, SensitivityPoint,
    UnboundedFairLivenessCegarAuditReport, UnboundedFairLivenessCegarStageOutcome,
    UnboundedFairLivenessCegarStageReport, UnboundedFairLivenessResult,
    UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome,
    UnboundedSafetyCegarStageReport, UnboundedSafetyResult, VerificationResult,
    QUANTITATIVE_SCHEMA_VERSION,
};

/// Errors that can occur during the verification pipeline.
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
    /// Ranking-function synthesis for liveness proofs.
    Ranking,
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
pub(crate) mod proof_export;
pub(crate) mod property;
pub mod stages;
pub mod verification;

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
    prove_safety_program_ast, prove_safety_with_cegar, prove_safety_with_cegar_report,
    prove_safety_with_round_abstraction, verify, verify_all_properties, verify_program_ast,
    verify_with_cegar, verify_with_cegar_report, CompletenessWarning,
};

// From certification
pub use certification::{
    generate_fair_liveness_certificate, generate_fair_liveness_certificate_with_mode,
    generate_kinduction_safety_certificate, generate_pdr_safety_certificate,
    generate_safety_certificate,
};

// From proof_export
pub use proof_export::{
    attach_certificate_evidence_by_name, export_ir_from_fair_liveness_certificate,
    export_ir_from_safety_certificate, ProofExportCertificateObligationEvidence, ProofExportIr,
    ProofExportKind, ProofExportObligation,
};

pub use stages::{
    parse_lower_abstract, AbstractStage, ComposedStage, LowerStage, ParseInput, ParseStage,
    PipelineStage, PipelineStageExt,
};

// Re-export the execution controls and diagnostics functions
// (already pub in this module)

fn current_rss_bytes() -> Option<u64> {
    crate::sandbox::current_rss_bytes()
}

#[cfg(test)]
mod tests;
