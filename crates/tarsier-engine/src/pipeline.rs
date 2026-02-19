#![allow(clippy::result_large_err)]

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
    LocalValue, NetworkSemantics, ParamOrConst, SharedVarKind, ThresholdAutomaton,
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
    AssumptionNote, BoundAnnotation, BoundKind, CegarAuditReport, CegarCounterexampleAnalysis,
    CegarEliminatedTrace, CegarModelChange, CegarRunControls, CegarStageOutcome, CegarStageReport,
    CegarTermination, CommComplexityReport, CommitteeAnalysisSummary, FairLivenessResult,
    InductionCtiSummary, LivenessResult, ModelAssumptions, ModelMetadata, SensitivityPoint,
    UnboundedFairLivenessCegarAuditReport, UnboundedFairLivenessCegarStageOutcome,
    UnboundedFairLivenessCegarStageReport, UnboundedFairLivenessResult,
    UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome,
    UnboundedSafetyCegarStageReport, UnboundedSafetyResult, VerificationResult,
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
    pub por_effective_rule_count: usize,
}

/// Reduction/abstraction diagnostics for one pipeline run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineRunDiagnostics {
    pub lowerings: Vec<LoweringDiagnostic>,
    pub applied_reductions: Vec<AppliedReductionDiagnostic>,
    pub reduction_notes: Vec<String>,
    pub phase_profiles: Vec<PhaseProfileDiagnostic>,
    pub smt_profiles: Vec<SmtProfileDiagnostic>,
}

fn execution_controls_lock() -> &'static Mutex<PipelineExecutionControls> {
    static CONTROLS: OnceLock<Mutex<PipelineExecutionControls>> = OnceLock::new();
    CONTROLS.get_or_init(|| Mutex::new(PipelineExecutionControls::default()))
}

thread_local! {
    static RUN_DIAGNOSTICS: RefCell<PipelineRunDiagnostics> = RefCell::new(PipelineRunDiagnostics::default());
}

/// Set execution controls for subsequent pipeline runs.
pub fn set_execution_controls(controls: PipelineExecutionControls) {
    match execution_controls_lock().lock() {
        Ok(mut guard) => *guard = controls,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = controls;
        }
    }
}

fn current_execution_controls() -> PipelineExecutionControls {
    match execution_controls_lock().lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
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
pub fn parse(source: &str, filename: &str) -> Result<ast::Program, PipelineError> {
    let started = Instant::now();
    let result = tarsier_dsl::parse(source, filename).map_err(PipelineError::from);
    push_phase_profile(filename, "parse", started.elapsed().as_millis());
    result
}

/// Lower an AST into a threshold automaton.
pub fn lower(program: &ast::Program) -> Result<ThresholdAutomaton, PipelineError> {
    let started = Instant::now();
    let result = lowering::lower(program).map_err(PipelineError::from);
    push_phase_profile("lower", "lower", started.elapsed().as_millis());
    result
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
    lowering::lower_with_source(program, source, filename)
}

/// Abstract a threshold automaton into a counter system.
pub fn abstract_to_cs(ta: ThresholdAutomaton) -> CounterSystem {
    abstract_to_counter_system(ta)
}

/// Extract the safety property from the protocol.
///
/// Supported (sound) fragments:
/// - Agreement: `forall p: R. forall q: R. p.x == q.x` where `x` is a boolean or enum local var.
/// - Invariant/Safety/Validity: `forall p: R. p.x == true/false` where `x` is boolean.
///
/// Any other property shape returns an error rather than silently falling back.
pub fn extract_property(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
    soundness: SoundnessMode,
) -> Result<SafetyProperty, PipelineError> {
    let safety_props: Vec<&ast::Spanned<ast::PropertyDecl>> = program
        .protocol
        .node
        .properties
        .iter()
        .filter(|p| is_safety_property_kind(p.node.kind))
        .collect();
    if safety_props.is_empty() {
        if soundness == SoundnessMode::Strict {
            return Err(PipelineError::Validation(
                "Strict mode requires an explicit property declaration.".into(),
            ));
        }
        // Default to agreement on `decided` if no property provided.
        tracing::warn!("No property declared; defaulting to structural agreement on `decided`.");
        return Ok(extract_agreement_property(ta));
    }
    if safety_props.len() > 1 {
        return Err(PipelineError::Validation(
            "Multiple safety properties are not yet supported; please specify exactly one safety property."
                .into(),
        ));
    }

    let prop = &safety_props[0].node;
    extract_property_from_decl(ta, prop)
}

fn extract_property_from_decl(
    ta: &ThresholdAutomaton,
    prop: &ast::PropertyDecl,
) -> Result<SafetyProperty, PipelineError> {
    use ast::{PropertyKind, Quantifier};
    let reachable = graph_reachable_locations(ta);

    let q = &prop.formula.quantifiers;
    let body = &prop.formula.body;

    match prop.kind {
        PropertyKind::Agreement => {
            // Expect either:
            // 1) forall p:R. forall q:R. p.x == q.x
            // 2) forall p:R. forall q:R. (p.d == true && q.d == true) ==> (p.x == q.x)
            if q.len() != 2 || q.iter().any(|b| b.quantifier != Quantifier::ForAll) {
                return Err(PipelineError::Property(
                    "Agreement property must use two universal quantifiers.".into(),
                ));
            }
            let role = &q[0].domain;
            if q[1].domain != *role {
                return Err(PipelineError::Property(
                    "Agreement quantifiers must be over the same role.".into(),
                ));
            }
            if let Some((guard_field, decision_field, var_l, var_r)) = parse_guarded_agreement(body)
            {
                if !((var_l == q[0].var && var_r == q[1].var)
                    || (var_l == q[1].var && var_r == q[0].var))
                {
                    return Err(PipelineError::Property(
                        "Agreement formula must reference the quantified variables in order."
                            .into(),
                    ));
                }
                let groups = locs_by_local_var_with_guard(
                    ta,
                    role,
                    &decision_field,
                    &guard_field,
                    &reachable,
                )?;
                let mut conflicting_pairs = Vec::new();
                build_conflicts_from_groups(&groups, &mut conflicting_pairs);
                return Ok(SafetyProperty::Agreement { conflicting_pairs });
            }

            let (var_l, var_r, field) = parse_qualified_eq(body).ok_or_else(|| {
                PipelineError::Property(
                    "Agreement formula must be of the form `p.x == q.x` or a guarded agreement."
                        .into(),
                )
            })?;
            if !((var_l == q[0].var && var_r == q[1].var)
                || (var_l == q[1].var && var_r == q[0].var))
            {
                return Err(PipelineError::Property(
                    "Agreement formula must reference the quantified variables in order.".into(),
                ));
            }
            let groups = locs_by_local_var(ta, role, &field, &reachable)?;
            let mut conflicting_pairs = Vec::new();
            build_conflicts_from_groups(&groups, &mut conflicting_pairs);
            Ok(SafetyProperty::Agreement { conflicting_pairs })
        }
        PropertyKind::Invariant | PropertyKind::Safety | PropertyKind::Validity => {
            // Expect forall p:R. p.x == true/false
            if q.len() != 1 || q[0].quantifier != Quantifier::ForAll {
                return Err(PipelineError::Property(
                    "Invariant/safety property must use one universal quantifier.".into(),
                ));
            }
            let role = &q[0].domain;
            let (var, field, value) = parse_qualified_eq_bool(body).ok_or_else(|| {
                PipelineError::Property(
                    "Invariant/safety formula must be of the form `p.x == true/false`.".into(),
                )
            })?;
            if var != q[0].var {
                return Err(PipelineError::Property(
                    "Invariant/safety formula must reference the quantified variable.".into(),
                ));
            }
            let (true_locs, false_locs) = locs_by_bool_var(ta, role, &field, &reachable)?;
            let bad_locs = if value { false_locs } else { true_locs };
            let bad_sets = bad_locs.into_iter().map(|l| vec![l]).collect();
            Ok(SafetyProperty::Invariant { bad_sets })
        }
        PropertyKind::Liveness => Err(PipelineError::Property(
            "Liveness properties are not safety properties; use `liveness`, `fair-liveness`, or `prove-fair`."
                .into(),
        )),
    }
}

fn graph_reachable_locations(ta: &ThresholdAutomaton) -> HashSet<usize> {
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = ta.initial_locations.clone();
    while let Some(lid) = stack.pop() {
        if !reachable.insert(lid) {
            continue;
        }
        for rule in &ta.rules {
            if rule.from == lid && !reachable.contains(&rule.to) {
                stack.push(rule.to);
            }
        }
    }
    reachable
}

fn parse_qualified_eq(body: &ast::FormulaExpr) -> Option<(String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (
                ast::FormulaAtom::QualifiedVar {
                    object: lobj,
                    field,
                },
                ast::FormulaAtom::QualifiedVar {
                    object: robj,
                    field: rfield,
                },
            ) if field == rfield => Some((lobj.clone(), robj.clone(), field.clone())),
            _ => None,
        }
    } else {
        None
    }
}

fn parse_qualified_eq_bool(body: &ast::FormulaExpr) -> Option<(String, String, bool)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Comparison { lhs, op, rhs } = body {
        if *op != ast::CmpOp::Eq {
            return None;
        }
        match (lhs, rhs) {
            (ast::FormulaAtom::QualifiedVar { object, field }, ast::FormulaAtom::BoolLit(b)) => {
                Some((object.clone(), field.clone(), *b))
            }
            (ast::FormulaAtom::BoolLit(b), ast::FormulaAtom::QualifiedVar { object, field }) => {
                Some((object.clone(), field.clone(), *b))
            }
            _ => None,
        }
    } else {
        None
    }
}

fn parse_guarded_agreement(body: &ast::FormulaExpr) -> Option<(String, String, String, String)> {
    let body = strip_outer_always(body);
    if let ast::FormulaExpr::Implies(lhs, rhs) = body {
        let (var_l, var_r, decision_field) = parse_qualified_eq(rhs)?;
        let mut guards = Vec::new();
        if !collect_guard_comparisons(lhs, &mut guards) {
            return None;
        }
        if guards.len() != 2 {
            return None;
        }
        let (g1_var, g1_field, g1_val) = &guards[0];
        let (g2_var, g2_field, g2_val) = &guards[1];
        if g1_field != g2_field || !*g1_val || !*g2_val {
            return None;
        }
        if (g1_var == &var_l && g2_var == &var_r) || (g1_var == &var_r && g2_var == &var_l) {
            Some((g1_field.clone(), decision_field, var_l, var_r))
        } else {
            None
        }
    } else {
        None
    }
}

fn strip_outer_always(body: &ast::FormulaExpr) -> &ast::FormulaExpr {
    if let ast::FormulaExpr::Always(inner) = body {
        strip_outer_always(inner)
    } else {
        body
    }
}

fn collect_guard_comparisons(
    expr: &ast::FormulaExpr,
    out: &mut Vec<(String, String, bool)>,
) -> bool {
    match expr {
        ast::FormulaExpr::And(lhs, rhs) => {
            collect_guard_comparisons(lhs, out) && collect_guard_comparisons(rhs, out)
        }
        ast::FormulaExpr::Comparison { .. } => {
            if let Some((var, field, val)) = parse_qualified_eq_bool(expr) {
                out.push((var, field, val));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn locs_by_bool_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<(Vec<usize>, Vec<usize>), PipelineError> {
    let mut true_locs = Vec::new();
    let mut false_locs = Vec::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            match val {
                LocalValue::Bool(b) => {
                    if *b {
                        true_locs.push(id);
                    } else {
                        false_locs.push(id);
                    }
                }
                _ => {
                    return Err(PipelineError::Property(format!(
                        "Local variable '{field}' in role '{role}' is not boolean."
                    )));
                }
            }
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown boolean local variable '{field}' in role '{role}'."
        )));
    }
    Ok((true_locs, false_locs))
}

fn locs_by_local_var(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

fn locs_by_local_var_with_guard(
    ta: &ThresholdAutomaton,
    role: &str,
    field: &str,
    guard_field: &str,
    reachable: &HashSet<usize>,
) -> Result<std::collections::HashMap<LocalValue, Vec<usize>>, PipelineError> {
    let mut groups: std::collections::HashMap<LocalValue, Vec<usize>> =
        std::collections::HashMap::new();
    let mut found_field = false;
    let mut found_guard = false;
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != role {
            continue;
        }
        let guard_val = match loc.local_vars.get(guard_field) {
            Some(LocalValue::Bool(b)) => {
                found_guard = true;
                *b
            }
            Some(_) => {
                return Err(PipelineError::Property(format!(
                    "Guard variable '{guard_field}' in role '{role}' is not boolean."
                )))
            }
            None => false,
        };
        if !guard_val {
            continue;
        }
        if let Some(val) = loc.local_vars.get(field) {
            found_field = true;
            groups.entry(val.clone()).or_default().push(id);
        }
    }
    if !found_field || !found_guard {
        return Err(PipelineError::Property(format!(
            "Unknown local variable '{field}' or guard '{guard_field}' in role '{role}'."
        )));
    }
    Ok(groups)
}

fn build_conflicts_from_groups(
    groups: &std::collections::HashMap<LocalValue, Vec<usize>>,
    out: &mut Vec<(usize, usize)>,
) {
    let group_vec: Vec<&Vec<usize>> = groups.values().collect();
    for i in 0..group_vec.len() {
        for j in (i + 1)..group_vec.len() {
            for &li in group_vec[i] {
                for &lj in group_vec[j] {
                    out.push((li, lj));
                }
            }
        }
    }
}

fn base_message_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix("cnt_")?;
    let without_recipient = stripped.split_once('@').map(|(b, _)| b).unwrap_or(stripped);
    let base = without_recipient
        .split_once('[')
        .map(|(b, _)| b)
        .unwrap_or(without_recipient);
    Some(base.to_string())
}

fn message_family_and_recipient_from_counter_name(name: &str) -> Option<(String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, recipient) = match stripped.split_once('@') {
        Some((family, tail)) => {
            let channel = tail.split_once('[').map(|(r, _)| r).unwrap_or(tail);
            let recipient = channel
                .split_once("<-")
                .map(|(r, _)| r)
                .unwrap_or(channel)
                .to_string();
            (family, Some(recipient))
        }
        None => (stripped, None),
    };
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    Some((family, recipient))
}

fn normalize_erased_var_names(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

fn is_erased_var_name(name: &str, erased: &HashSet<String>) -> bool {
    erased.contains(&name.to_ascii_lowercase())
}

fn erase_round_fields_from_message_counter_name(name: &str, erased: &HashSet<String>) -> String {
    if !name.starts_with("cnt_") {
        return name.to_string();
    }
    let Some((prefix, suffix)) = name.split_once('[') else {
        return name.to_string();
    };
    let inner = suffix.strip_suffix(']').unwrap_or(suffix);
    let kept_parts = inner
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            let (field, value) = part.split_once('=')?;
            if is_erased_var_name(field.trim(), erased) {
                None
            } else {
                Some(format!("{}={}", field.trim(), value.trim()))
            }
        })
        .collect::<Vec<_>>();
    if kept_parts.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}[{}]", kept_parts.join(","))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum SharedMergeKey {
    MessageCounter(String),
    Unique(usize),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct LocationMergeKey {
    role: String,
    phase: String,
    locals: Vec<(String, LocalValue)>,
}

fn build_location_merge_key(
    loc: &tarsier_ir::threshold_automaton::Location,
    erased: &HashSet<String>,
) -> LocationMergeKey {
    let mut locals = loc
        .local_vars
        .iter()
        .filter(|(name, _)| !is_erased_var_name(name, erased))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    locals.sort_by(|a, b| a.0.cmp(&b.0));
    LocationMergeKey {
        role: loc.role.clone(),
        phase: loc.phase.clone(),
        locals,
    }
}

fn apply_round_erasure_abstraction(
    ta: &ThresholdAutomaton,
    erased_var_names: &[String],
) -> (ThresholdAutomaton, RoundAbstractionSummary) {
    let erased = normalize_erased_var_names(erased_var_names);
    let original_message_counters = ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();

    let mut abstract_ta = ThresholdAutomaton {
        locations: Vec::new(),
        initial_locations: Vec::new(),
        shared_vars: Vec::new(),
        rules: Vec::new(),
        parameters: ta.parameters.clone(),
        resilience_condition: ta.resilience_condition.clone(),
        adversary_bound_param: ta.adversary_bound_param,
        fault_model: ta.fault_model,
        timing_model: ta.timing_model,
        gst_param: ta.gst_param,
        value_abstraction: ta.value_abstraction,
        equivocation_mode: ta.equivocation_mode,
        authentication_mode: ta.authentication_mode,
        network_semantics: ta.network_semantics,
        delivery_control: ta.delivery_control,
        fault_budget_scope: ta.fault_budget_scope,
        role_identities: ta.role_identities.clone(),
        key_ownership: ta.key_ownership.clone(),
        compromised_keys: ta.compromised_keys.clone(),
        message_policies: ta.message_policies.clone(),
        crypto_objects: ta.crypto_objects.clone(),
        committees: ta.committees.clone(),
    };

    let mut shared_map: Vec<usize> = vec![0; ta.shared_vars.len()];
    let mut shared_key_to_new: HashMap<SharedMergeKey, usize> = HashMap::new();
    for (old_id, shared) in ta.shared_vars.iter().enumerate() {
        let key = if shared.kind == SharedVarKind::MessageCounter {
            let erased_name = erase_round_fields_from_message_counter_name(&shared.name, &erased);
            SharedMergeKey::MessageCounter(erased_name)
        } else {
            SharedMergeKey::Unique(old_id)
        };

        if let Some(&new_id) = shared_key_to_new.get(&key) {
            shared_map[old_id] = new_id;
            if shared.kind == SharedVarKind::MessageCounter {
                let existing = &mut abstract_ta.shared_vars[new_id];
                existing.distinct &= shared.distinct;
                if existing.distinct {
                    if existing.distinct_role != shared.distinct_role {
                        existing.distinct = false;
                        existing.distinct_role = None;
                    }
                } else {
                    existing.distinct_role = None;
                }
            }
            continue;
        }

        let new_name = match &key {
            SharedMergeKey::MessageCounter(name) => name.clone(),
            SharedMergeKey::Unique(_) => shared.name.clone(),
        };
        let new_id = abstract_ta.shared_vars.len();
        abstract_ta
            .shared_vars
            .push(tarsier_ir::threshold_automaton::SharedVar {
                name: new_name,
                kind: shared.kind,
                distinct: shared.distinct,
                distinct_role: shared.distinct_role.clone(),
            });
        shared_key_to_new.insert(key, new_id);
        shared_map[old_id] = new_id;
    }

    let mut loc_map: Vec<usize> = vec![0; ta.locations.len()];
    let mut loc_key_to_new: HashMap<LocationMergeKey, usize> = HashMap::new();
    for (old_id, loc) in ta.locations.iter().enumerate() {
        let key = build_location_merge_key(loc, &erased);
        if let Some(&new_id) = loc_key_to_new.get(&key) {
            loc_map[old_id] = new_id;
            continue;
        }

        let mut local_vars = loc.local_vars.clone();
        local_vars.retain(|name, _| !is_erased_var_name(name, &erased));
        let new_id = abstract_ta.locations.len();
        abstract_ta
            .locations
            .push(tarsier_ir::threshold_automaton::Location {
                name: format!("{}::{}::abs{new_id}", key.role, key.phase),
                role: key.role.clone(),
                phase: key.phase.clone(),
                local_vars,
            });
        loc_key_to_new.insert(key, new_id);
        loc_map[old_id] = new_id;
    }

    let mut initial_set: HashSet<usize> = HashSet::new();
    for old_init in &ta.initial_locations {
        if let Some(&mapped) = loc_map.get(*old_init) {
            initial_set.insert(mapped);
        }
    }
    let mut initial_locations: Vec<usize> = initial_set.into_iter().collect();
    initial_locations.sort_unstable();
    abstract_ta.initial_locations = initial_locations;

    abstract_ta.rules = ta
        .rules
        .iter()
        .map(|rule| tarsier_ir::threshold_automaton::Rule {
            from: loc_map[rule.from],
            to: loc_map[rule.to],
            guard: tarsier_ir::threshold_automaton::Guard {
                atoms: rule
                    .guard
                    .atoms
                    .iter()
                    .map(|atom| match atom {
                        GuardAtom::Threshold {
                            vars,
                            op,
                            bound,
                            distinct,
                        } => GuardAtom::Threshold {
                            vars: vars.iter().map(|v| shared_map[*v]).collect(),
                            op: *op,
                            bound: bound.clone(),
                            distinct: *distinct,
                        },
                    })
                    .collect(),
            },
            updates: rule
                .updates
                .iter()
                .map(|update| tarsier_ir::threshold_automaton::Update {
                    var: shared_map[update.var],
                    kind: update.kind.clone(),
                })
                .collect(),
        })
        .collect();

    let abstract_message_counters = abstract_ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();
    let abstract_locations = abstract_ta.locations.len();
    let abstract_shared_vars = abstract_ta.shared_vars.len();

    let mut erased_vars: Vec<String> = erased.into_iter().collect();
    erased_vars.sort();

    (
        abstract_ta,
        RoundAbstractionSummary {
            erased_vars,
            original_locations: ta.locations.len(),
            abstract_locations,
            original_shared_vars: ta.shared_vars.len(),
            abstract_shared_vars,
            original_message_counters,
            abstract_message_counters,
        },
    )
}

fn format_bound(parts: &[String]) -> String {
    if parts.is_empty() {
        return "0".into();
    }
    parts.join(" * ")
}

fn format_scaled_term(symbol: &str, multiplier: usize) -> String {
    match multiplier {
        0 => "0".into(),
        1 => symbol.to_string(),
        _ => format_bound(&[symbol.to_string(), multiplier.to_string()]),
    }
}

fn format_sum_bounds(parts: &[String]) -> String {
    let kept: Vec<&String> = parts.iter().filter(|p| p.as_str() != "0").collect();
    if kept.is_empty() {
        "0".into()
    } else {
        kept.iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

fn scale_bound_by_depth(depth: usize, bound: &str) -> String {
    if bound == "0" {
        "0".into()
    } else if depth == 1 {
        bound.to_string()
    } else if bound.contains(" + ") {
        format!("{depth} * ({bound})")
    } else {
        format!("{depth} * {bound}")
    }
}

fn add_bounds(lhs: &str, rhs: &str) -> String {
    if lhs == "0" {
        return rhs.to_string();
    }
    if rhs == "0" {
        return lhs.to_string();
    }
    format!("{lhs} + {rhs}")
}

fn geometric_rounds_for_confidence(p_fail: f64, confidence: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&p_fail) {
        return None;
    }
    if !(0.0..1.0).contains(&confidence) {
        return None;
    }
    if p_fail <= 0.0 {
        return Some(1);
    }
    if p_fail >= 1.0 {
        return None;
    }
    let rounds = ((1.0 - confidence).ln() / p_fail.ln()).ceil();
    if rounds.is_finite() && rounds >= 1.0 {
        Some(rounds as usize)
    } else {
        None
    }
}
/// Analyze committee selections and derive concrete adversary bounds.
///
/// For each committee spec, compute the worst-case Byzantine count b_max
/// such that P(Byzantine > b_max) <= epsilon. Returns summaries for reporting
/// and optionally injects concrete bounds into the threshold automaton.
fn analyze_and_constrain_committees(
    ta: &mut ThresholdAutomaton,
) -> Result<Vec<CommitteeAnalysisSummary>, PipelineError> {
    let mut summaries = Vec::new();

    for committee in &ta.committees.clone() {
        let epsilon = committee.epsilon.unwrap_or(1e-9);

        // Resolve population, byzantine, committee_size to concrete values
        let population = resolve_param_or_const(&committee.population, ta)?;
        let byzantine = resolve_param_or_const(&committee.byzantine, ta)?;
        let committee_size = resolve_param_or_const(&committee.committee_size, ta)?;

        let spec = CommitteeSpec {
            name: committee.name.clone(),
            population: population as u64,
            byzantine: byzantine as u64,
            committee_size: committee_size as u64,
            epsilon,
        };

        info!(
            name = %spec.name,
            population = spec.population,
            byzantine = spec.byzantine,
            committee_size = spec.committee_size,
            epsilon = %spec.epsilon,
            "Analyzing committee selection..."
        );

        let analysis = tarsier_prob::analyze_committee(&spec)?;

        info!(
            b_max = analysis.b_max,
            expected = %format!("{:.1}", analysis.expected_byzantine),
            "Committee analysis complete"
        );

        summaries.push(CommitteeAnalysisSummary {
            name: spec.name.clone(),
            committee_size: spec.committee_size,
            population: spec.population,
            byzantine: spec.byzantine,
            b_max: analysis.b_max,
            epsilon,
            tail_probability: analysis.tail_probability,
            honest_majority: analysis.honest_majority,
            expected_byzantine: analysis.expected_byzantine,
        });
    }

    // If no explicit adversary bound was set, allow a single committee-bound
    // parameter to drive adversary injections. Multiple committee bound params
    // are ambiguous and must be disambiguated explicitly by the model.
    if ta.adversary_bound_param.is_none() {
        let mut candidate_params: HashSet<usize> = HashSet::new();
        for c in &ta.committees {
            if let Some(pid) = c.bound_param {
                candidate_params.insert(pid);
            }
        }
        if candidate_params.len() == 1 {
            let pid = *candidate_params.iter().next().expect("len() checked");
            ta.adversary_bound_param = Some(pid);
            info!(
                param = %ta.parameters[pid].name,
                "Using committee-derived adversary bound parameter"
            );
        } else if candidate_params.len() > 1 {
            return Err(PipelineError::Property(
                "Multiple committee bound parameters found but adversary.bound is not set. \
                 Set `adversary { bound: ...; }` explicitly."
                    .into(),
            ));
        }
    }

    Ok(summaries)
}

fn ensure_n_parameter(ta: &ThresholdAutomaton) -> Result<(), PipelineError> {
    if ta.find_param_by_name("n").is_none() {
        return Err(PipelineError::Property(
            "Protocol must declare parameter `n` (process population size).".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PipelineCommand {
    Verify,
    Liveness,
}

fn guard_uses_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(_) => true,
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_uses_threshold(lhs) || guard_uses_threshold(rhs)
        }
        _ => false,
    }
}

fn guard_uses_distinct_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(tg) => tg.distinct,
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_uses_distinct_threshold(lhs) || guard_uses_distinct_threshold(rhs)
        }
        _ => false,
    }
}

fn collect_distinct_roles_from_guard(guard: &ast::GuardExpr, out: &mut HashSet<String>) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            if tg.distinct {
                if let Some(role) = &tg.distinct_role {
                    out.insert(role.clone());
                }
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_distinct_roles_from_guard(lhs, out);
            collect_distinct_roles_from_guard(rhs, out);
        }
        _ => {}
    }
}

fn collect_distinct_messages_from_guard(guard: &ast::GuardExpr, out: &mut HashSet<String>) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            if tg.distinct {
                out.insert(tg.message_type.clone());
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_distinct_messages_from_guard(lhs, out);
            collect_distinct_messages_from_guard(rhs, out);
        }
        _ => {}
    }
}

fn guard_has_non_monotone_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(tg) => !matches!(tg.op, ast::CmpOp::Ge | ast::CmpOp::Gt),
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_has_non_monotone_threshold(lhs) || guard_has_non_monotone_threshold(rhs)
        }
        _ => false,
    }
}

fn protocol_uses_thresholds(program: &ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_threshold(&tr.node.guard))
        })
    })
}

fn protocol_uses_distinct_thresholds(program: &ast::Program) -> bool {
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

fn protocol_distinct_roles(program: &ast::Program) -> HashSet<String> {
    let mut roles = HashSet::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_roles_from_guard(&tr.node.guard, &mut roles);
            }
        }
    }
    roles
}

fn protocol_distinct_messages(program: &ast::Program) -> HashSet<String> {
    let mut messages = HashSet::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_messages_from_guard(&tr.node.guard, &mut messages);
            }
        }
    }
    messages
}

fn effective_message_authenticated(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_auth: &str,
) -> bool {
    if let Some(ch) = proto.channels.iter().find(|c| c.message == msg) {
        return matches!(ch.auth, ast::ChannelAuthMode::Authenticated);
    }
    global_auth == "signed"
}

fn effective_message_non_equivocating(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_equivocation: &str,
) -> bool {
    if let Some(eq) = proto
        .equivocation_policies
        .iter()
        .find(|e| e.message == msg)
    {
        return matches!(eq.mode, ast::EquivocationPolicyMode::None);
    }
    global_equivocation == "none"
}

fn protocol_has_non_monotone_thresholds(program: &ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_has_non_monotone_threshold(&tr.node.guard))
        })
    })
}

fn strict_preflight_validate(
    program: &ast::Program,
    command: PipelineCommand,
) -> Result<(), PipelineError> {
    let proto = &program.protocol.node;
    let mut issues: Vec<String> = Vec::new();

    let has_n = proto.parameters.iter().any(|p| p.name == "n");
    let has_t = proto.parameters.iter().any(|p| p.name == "t");
    if !has_n {
        issues.push("Missing required parameter `n`.".into());
    }
    if !has_t {
        issues.push("Missing required parameter `t`.".into());
    }
    if proto.resilience.is_none() {
        issues.push("Missing resilience declaration.".into());
    }

    for role in &proto.roles {
        for v in &role.node.vars {
            if matches!(v.ty, ast::VarType::Nat | ast::VarType::Int) && v.range.is_none() {
                issues.push(format!(
                    "Unbounded local variable '{}.{}' is not allowed in strict mode; add `in a..b`.",
                    role.node.name, v.name
                ));
            }
        }
    }

    let uses_thresholds = protocol_uses_thresholds(program);
    let uses_distinct_thresholds = protocol_uses_distinct_thresholds(program);
    let mut has_adv_model = false;
    let mut has_adv_bound = false;
    let mut timing_partial = false;
    let mut has_gst = false;
    let mut auth_mode = "none";
    let mut has_auth_field = false;
    let mut adv_model: Option<String> = None;
    let mut equivocation_mode: Option<String> = None;
    let mut network_mode = "classic";
    for item in &proto.adversary {
        if item.key == "model"
            && (item.value == "byzantine" || item.value == "crash" || item.value == "omission")
        {
            has_adv_model = true;
            adv_model = Some(item.value.clone());
        }
        if item.key == "bound" {
            has_adv_bound = true;
        }
        if item.key == "timing"
            && (item.value == "partial_synchrony" || item.value == "partial_sync")
        {
            timing_partial = true;
        }
        if item.key == "gst" {
            has_gst = true;
        }
        if item.key == "equivocation" {
            equivocation_mode = Some(item.value.clone());
        }
        if item.key == "auth" || item.key == "authentication" {
            auth_mode = item.value.as_str();
            has_auth_field = true;
        }
        if item.key == "network" || item.key == "network_semantics" {
            network_mode = item.value.as_str();
        }
    }

    if uses_thresholds && !has_adv_model {
        issues.push(
            "Threshold protocols in strict mode require `adversary { model: byzantine|crash|omission; ... }`."
                .into(),
        );
    }
    if (uses_thresholds || has_adv_model) && !has_adv_bound {
        issues.push(
            "Strict mode requires `adversary { bound: <param>; }` when faults are modeled.".into(),
        );
    }

    let faithful_network = matches!(
        network_mode,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if faithful_network {
        let role_names: HashSet<String> = proto.roles.iter().map(|r| r.node.name.clone()).collect();
        let identity_roles: HashSet<String> =
            proto.identities.iter().map(|id| id.role.clone()).collect();
        let mut missing_identity_roles: Vec<String> =
            role_names.difference(&identity_roles).cloned().collect();
        missing_identity_roles.sort();
        if !missing_identity_roles.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit `identity` declarations \
                 for every role. Missing: {}.",
                missing_identity_roles.join(", ")
            ));
        }
        let mut missing_identity_key_roles: Vec<String> = proto
            .identities
            .iter()
            .filter(|id| id.key.is_none())
            .map(|id| id.role.clone())
            .collect();
        missing_identity_key_roles.sort();
        missing_identity_key_roles.dedup();
        if !missing_identity_key_roles.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit identity keys. \
                 Add `key <name>` for roles: {}.",
                missing_identity_key_roles.join(", ")
            ));
        }
        if network_mode == "process_selective" {
            let mut non_process_roles: Vec<String> = proto
                .identities
                .iter()
                .filter(|id| id.scope != ast::IdentityScope::Process)
                .map(|id| id.role.clone())
                .collect();
            non_process_roles.sort();
            non_process_roles.dedup();
            if !non_process_roles.is_empty() {
                issues.push(format!(
                    "`network: process_selective` in strict mode requires \
                     `identity <Role>: process(<id-var>)` for every role. Non-process identities: {}.",
                    non_process_roles.join(", ")
                ));
            }
        }
        let channel_covered: HashSet<String> =
            proto.channels.iter().map(|c| c.message.clone()).collect();
        let mut missing_channel_auth: Vec<String> = proto
            .messages
            .iter()
            .map(|m| m.name.clone())
            .filter(|m| !channel_covered.contains(m))
            .collect();
        missing_channel_auth.sort();
        if !has_auth_field && !missing_channel_auth.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit authentication semantics. \
                 Add global `adversary {{ auth: signed|none; }}` or message channels for: {}.",
                missing_channel_auth.join(", ")
            ));
        }
    }

    if uses_thresholds {
        if timing_partial && !has_gst {
            issues.push(
                "Partial synchrony in strict mode requires `adversary { gst: <param>; }`.".into(),
            );
        }
        if uses_distinct_thresholds {
            let unauthenticated_msgs: Vec<String> = protocol_distinct_messages(program)
                .into_iter()
                .filter(|msg| !effective_message_authenticated(proto, msg, auth_mode))
                .collect();
            if !unauthenticated_msgs.is_empty() {
                issues.push(format!(
                    "Distinct-sender thresholds require authenticated sender identities in strict mode. \
                     Add `adversary {{ auth: signed; }}` or per-message `channel <Msg>: authenticated;` for: {}.",
                    unauthenticated_msgs.join(", ")
                ));
            }
        }
        if uses_distinct_thresholds {
            let role_count = proto.roles.len();
            for role_name in protocol_distinct_roles(program) {
                let param_name = format!("n_{}", role_name.to_lowercase());
                let has_role_population = proto.parameters.iter().any(|p| p.name == param_name);
                if !has_role_population && role_count > 1 {
                    issues.push(format!(
                        "Distinct sender domain role `{role_name}` needs population parameter `{param_name}` in strict mode."
                    ));
                }
            }
        }
        if adv_model.as_deref() == Some("byzantine")
            && equivocation_mode.as_deref().unwrap_or("full") != "none"
            && protocol_has_non_monotone_thresholds(program)
        {
            issues.push(
                "Byzantine full-equivocation in strict mode requires monotone threshold guards (`received ... >=` or `>`). Use monotone guards or set `adversary { equivocation: none; }`."
                    .into(),
            );
        }
    }

    if command == PipelineCommand::Verify {
        let safety_count = proto
            .properties
            .iter()
            .filter(|p| is_safety_property_kind(p.node.kind))
            .count();
        if safety_count != 1 {
            issues.push(
                "Strict mode requires exactly one safety property declaration for `verify`.".into(),
            );
        }
    }

    if !issues.is_empty() {
        return Err(PipelineError::Validation(issues.join(" ")));
    }
    Ok(())
}

fn preflight_validate(
    program: &ast::Program,
    options: &PipelineOptions,
    command: PipelineCommand,
) -> Result<(), PipelineError> {
    if options.soundness == SoundnessMode::Strict {
        strict_preflight_validate(program, command)
    } else {
        Ok(())
    }
}

fn is_safety_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(
        kind,
        ast::PropertyKind::Agreement
            | ast::PropertyKind::Validity
            | ast::PropertyKind::Safety
            | ast::PropertyKind::Invariant
    )
}

fn is_liveness_property_kind(kind: ast::PropertyKind) -> bool {
    matches!(kind, ast::PropertyKind::Liveness)
}

fn has_safety_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_safety_property_kind(p.node.kind))
}

fn has_liveness_properties(program: &ast::Program) -> bool {
    program
        .protocol
        .node
        .properties
        .iter()
        .any(|p| is_liveness_property_kind(p.node.kind))
}

fn collect_decided_goal_locs(ta: &ThresholdAutomaton) -> Vec<usize> {
    ta.locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.local_vars.get("decided") == Some(&LocalValue::Bool(true)))
        .map(|(id, _)| id)
        .collect()
}

fn collect_non_goal_reachable_locs(ta: &ThresholdAutomaton, goal_locs: &[usize]) -> Vec<usize> {
    let reachable = graph_reachable_locations(ta);
    let goals: HashSet<usize> = goal_locs.iter().copied().collect();
    ta.locations
        .iter()
        .enumerate()
        .filter(|(id, _)| reachable.contains(id) && !goals.contains(id))
        .map(|(id, _)| id)
        .collect()
}

#[derive(Debug, Clone)]
enum LivenessSpec {
    TerminationGoalLocs(Vec<usize>),
    Temporal {
        quantified_var: String,
        role: String,
        formula: ast::FormulaExpr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum TemporalFormula {
    True,
    False,
    Atom(usize),
    NotAtom(usize),
    Next(Box<TemporalFormula>),
    And(Box<TemporalFormula>, Box<TemporalFormula>),
    Or(Box<TemporalFormula>, Box<TemporalFormula>),
    Until(Box<TemporalFormula>, Box<TemporalFormula>),
    Release(Box<TemporalFormula>, Box<TemporalFormula>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum TemporalAtomLit {
    Pos(usize),
    Neg(usize),
}

#[derive(Debug, Clone)]
struct TemporalBuchiState {
    old: BTreeSet<TemporalFormula>,
    label_lits: Vec<TemporalAtomLit>,
    transitions: Vec<usize>,
}

#[derive(Debug, Clone)]
struct TemporalBuchiAutomaton {
    quantified_var: String,
    role: String,
    atoms: Vec<ast::FormulaExpr>,
    states: Vec<TemporalBuchiState>,
    initial_states: Vec<usize>,
    acceptance_sets: Vec<Vec<usize>>,
}

#[derive(Debug, Clone)]
enum FairLivenessTarget {
    NonGoalLocs(Vec<usize>),
    Temporal(TemporalBuchiAutomaton),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FormulaValue {
    Bool(bool),
    Int(i64),
    Enum(String),
}

fn formula_value_from_local(value: &LocalValue) -> FormulaValue {
    match value {
        LocalValue::Bool(b) => FormulaValue::Bool(*b),
        LocalValue::Int(i) => FormulaValue::Int(*i),
        LocalValue::Enum(v) => FormulaValue::Enum(v.clone()),
    }
}

fn eval_formula_atom_on_location(
    atom: &ast::FormulaAtom,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<FormulaValue, PipelineError> {
    match atom {
        ast::FormulaAtom::IntLit(i) => Ok(FormulaValue::Int(*i)),
        ast::FormulaAtom::BoolLit(b) => Ok(FormulaValue::Bool(*b)),
        ast::FormulaAtom::Var(name) => {
            if let Some(v) = loc.local_vars.get(name) {
                Ok(formula_value_from_local(v))
            } else {
                // Unresolved identifiers are treated as enum literals.
                Ok(FormulaValue::Enum(name.clone()))
            }
        }
        ast::FormulaAtom::QualifiedVar { object, field } => {
            if object != quantified_var {
                return Err(PipelineError::Property(format!(
                    "Liveness formula references unsupported quantified variable '{object}'."
                )));
            }
            let value = loc.local_vars.get(field).ok_or_else(|| {
                PipelineError::Property(format!(
                    "Unknown local variable '{field}' in liveness formula."
                ))
            })?;
            Ok(formula_value_from_local(value))
        }
    }
}

fn eval_formula_comparison(
    op: ast::CmpOp,
    lhs: FormulaValue,
    rhs: FormulaValue,
) -> Result<bool, PipelineError> {
    use ast::CmpOp;
    match (lhs, rhs) {
        (FormulaValue::Bool(l), FormulaValue::Bool(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err(PipelineError::Property(
                "Boolean liveness comparisons only support == and !=.".into(),
            )),
        },
        (FormulaValue::Int(l), FormulaValue::Int(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            CmpOp::Ge => Ok(l >= r),
            CmpOp::Gt => Ok(l > r),
            CmpOp::Le => Ok(l <= r),
            CmpOp::Lt => Ok(l < r),
        },
        (FormulaValue::Enum(l), FormulaValue::Enum(r)) => match op {
            CmpOp::Eq => Ok(l == r),
            CmpOp::Ne => Ok(l != r),
            _ => Err(PipelineError::Property(
                "Enum liveness comparisons only support == and !=.".into(),
            )),
        },
        _ => Err(PipelineError::Property(
            "Type mismatch in liveness formula comparison.".into(),
        )),
    }
}

fn eval_formula_expr_on_location(
    expr: &ast::FormulaExpr,
    quantified_var: &str,
    loc: &tarsier_ir::threshold_automaton::Location,
) -> Result<bool, PipelineError> {
    match expr {
        ast::FormulaExpr::Comparison { lhs, op, rhs } => {
            let l = eval_formula_atom_on_location(lhs, quantified_var, loc)?;
            let r = eval_formula_atom_on_location(rhs, quantified_var, loc)?;
            eval_formula_comparison(*op, l, r)
        }
        ast::FormulaExpr::Not(inner) => {
            Ok(!eval_formula_expr_on_location(inner, quantified_var, loc)?)
        }
        ast::FormulaExpr::And(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                && eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            Ok(eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            Ok(!eval_formula_expr_on_location(lhs, quantified_var, loc)?
                || eval_formula_expr_on_location(rhs, quantified_var, loc)?)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let lv = eval_formula_expr_on_location(lhs, quantified_var, loc)?;
            let rv = eval_formula_expr_on_location(rhs, quantified_var, loc)?;
            Ok(lv == rv)
        }
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_)
        | ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => Err(PipelineError::Property(
            "Temporal operators are not valid inside a single-state predicate context.".into(),
        )),
    }
}

fn formula_contains_temporal(expr: &ast::FormulaExpr) -> bool {
    match expr {
        ast::FormulaExpr::Comparison { .. } => false,
        ast::FormulaExpr::Not(inner) => formula_contains_temporal(inner),
        ast::FormulaExpr::Next(_)
        | ast::FormulaExpr::Always(_)
        | ast::FormulaExpr::Eventually(_) => true,
        ast::FormulaExpr::Until(_, _)
        | ast::FormulaExpr::WeakUntil(_, _)
        | ast::FormulaExpr::Release(_, _)
        | ast::FormulaExpr::LeadsTo(_, _) => true,
        ast::FormulaExpr::And(lhs, rhs)
        | ast::FormulaExpr::Or(lhs, rhs)
        | ast::FormulaExpr::Implies(lhs, rhs)
        | ast::FormulaExpr::Iff(lhs, rhs) => {
            formula_contains_temporal(lhs) || formula_contains_temporal(rhs)
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TemporalAtomTable {
    atoms: Vec<ast::FormulaExpr>,
}

impl TemporalAtomTable {
    fn intern(&mut self, expr: &ast::FormulaExpr) -> usize {
        if let Some(idx) = self.atoms.iter().position(|existing| existing == expr) {
            idx
        } else {
            let idx = self.atoms.len();
            self.atoms.push(expr.clone());
            idx
        }
    }
}

fn temporal_and(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::False, _) | (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) | (other, TemporalFormula::True) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::And(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::And(Box::new(right), Box::new(left))
            }
        }
    }
}

fn temporal_or(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::True, _) | (_, TemporalFormula::True) => TemporalFormula::True,
        (TemporalFormula::False, other) | (other, TemporalFormula::False) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::Or(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::Or(Box::new(right), Box::new(left))
            }
        }
    }
}

fn temporal_until(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::False, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Until(Box::new(left), Box::new(right)),
    }
}

fn temporal_release(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Release(Box::new(left), Box::new(right)),
    }
}

fn formula_to_temporal_nnf(
    expr: &ast::FormulaExpr,
    atoms: &mut TemporalAtomTable,
    negated: bool,
) -> Result<TemporalFormula, PipelineError> {
    if !formula_contains_temporal(expr) {
        let atom = atoms.intern(expr);
        return Ok(if negated {
            TemporalFormula::NotAtom(atom)
        } else {
            TemporalFormula::Atom(atom)
        });
    }

    match expr {
        ast::FormulaExpr::Comparison { .. } => {
            let atom = atoms.intern(expr);
            Ok(if negated {
                TemporalFormula::NotAtom(atom)
            } else {
                TemporalFormula::Atom(atom)
            })
        }
        ast::FormulaExpr::Not(inner) => formula_to_temporal_nnf(inner, atoms, !negated),
        ast::FormulaExpr::And(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_or(l, r)
            } else {
                temporal_and(l, r)
            })
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_and(l, r)
            } else {
                temporal_or(l, r)
            })
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let desugared =
                ast::FormulaExpr::Or(Box::new(ast::FormulaExpr::Not(lhs.clone())), rhs.clone());
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::And(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::And(
                    Box::new(ast::FormulaExpr::Not(lhs.clone())),
                    Box::new(ast::FormulaExpr::Not(rhs.clone())),
                )),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Next(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(TemporalFormula::Next(Box::new(inner_nnf)))
        }
        ast::FormulaExpr::Always(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_until(TemporalFormula::True, inner_nnf)
            } else {
                temporal_release(TemporalFormula::False, inner_nnf)
            })
        }
        ast::FormulaExpr::Eventually(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_release(TemporalFormula::False, inner_nnf)
            } else {
                temporal_until(TemporalFormula::True, inner_nnf)
            })
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_release(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_until(l, r))
            }
        }
        ast::FormulaExpr::Release(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_until(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_release(l, r))
            }
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::Until(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::Always(lhs.clone())),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Implies(
                lhs.clone(),
                Box::new(ast::FormulaExpr::Eventually(rhs.clone())),
            )));
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
    }
}

fn collect_until_formulas(formula: &TemporalFormula, out: &mut BTreeSet<TemporalFormula>) {
    match formula {
        TemporalFormula::Until(lhs, rhs) => {
            out.insert(formula.clone());
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::And(lhs, rhs)
        | TemporalFormula::Or(lhs, rhs)
        | TemporalFormula::Release(lhs, rhs) => {
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::Next(inner) => {
            collect_until_formulas(inner, out);
        }
        TemporalFormula::True
        | TemporalFormula::False
        | TemporalFormula::Atom(_)
        | TemporalFormula::NotAtom(_) => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemporalExpansionOutcome {
    old: BTreeSet<TemporalFormula>,
    next: BTreeSet<TemporalFormula>,
    literals: BTreeMap<usize, bool>,
}

fn temporal_push_todo(
    todo: &mut Vec<TemporalFormula>,
    old: &BTreeSet<TemporalFormula>,
    formula: TemporalFormula,
) {
    if old.contains(&formula) || todo.iter().any(|f| f == &formula) {
        return;
    }
    todo.push(formula);
}

fn expand_temporal_seed(seed: &BTreeSet<TemporalFormula>) -> Vec<TemporalExpansionOutcome> {
    fn recurse(
        mut todo: Vec<TemporalFormula>,
        old: BTreeSet<TemporalFormula>,
        next: BTreeSet<TemporalFormula>,
        literals: BTreeMap<usize, bool>,
        outcomes: &mut Vec<TemporalExpansionOutcome>,
    ) {
        let Some(formula) = todo.pop() else {
            outcomes.push(TemporalExpansionOutcome {
                old,
                next,
                literals,
            });
            return;
        };

        if old.contains(&formula) {
            recurse(todo, old, next, literals, outcomes);
            return;
        }

        match formula {
            TemporalFormula::True => {
                let mut old2 = old;
                old2.insert(TemporalFormula::True);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::False => {}
            TemporalFormula::Atom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(false)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::Atom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, true);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::NotAtom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(true)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::NotAtom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, false);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::Next(inner) => {
                let mut old2 = old;
                let next_formula = TemporalFormula::Next(inner.clone());
                old2.insert(next_formula);
                let mut next2 = next;
                next2.insert(*inner);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::And(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::And(lhs.clone(), rhs.clone()));
                temporal_push_todo(&mut todo, &old2, *lhs);
                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Or(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::Or(lhs.clone(), rhs.clone()));

                let mut left_todo = todo.clone();
                temporal_push_todo(&mut left_todo, &old2, *lhs.clone());
                recurse(
                    left_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Until(lhs, rhs) => {
                let mut old2 = old;
                let until_formula = TemporalFormula::Until(lhs.clone(), rhs.clone());
                old2.insert(until_formula.clone());

                let mut rhs_todo = todo.clone();
                temporal_push_todo(&mut rhs_todo, &old2, *rhs.clone());
                recurse(
                    rhs_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *lhs);
                let mut next2 = next;
                next2.insert(until_formula);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::Release(lhs, rhs) => {
                let mut old2 = old;
                let rel_formula = TemporalFormula::Release(lhs.clone(), rhs.clone());
                old2.insert(rel_formula.clone());

                let mut keep_todo = todo.clone();
                temporal_push_todo(&mut keep_todo, &old2, *lhs.clone());
                temporal_push_todo(&mut keep_todo, &old2, *rhs.clone());
                let mut keep_next = next.clone();
                keep_next.insert(rel_formula.clone());
                recurse(
                    keep_todo,
                    old2.clone(),
                    keep_next,
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
        }
    }

    let mut outcomes = Vec::new();
    recurse(
        seed.iter().cloned().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        &mut outcomes,
    );

    let mut unique = Vec::new();
    for outcome in outcomes {
        if !unique.iter().any(|existing| existing == &outcome) {
            unique.push(outcome);
        }
    }
    unique
}

fn compile_temporal_buchi_automaton(
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
) -> Result<TemporalBuchiAutomaton, PipelineError> {
    let mut atoms = TemporalAtomTable::default();
    let negated = formula_to_temporal_nnf(formula, &mut atoms, true)?;

    let mut initial_seed = BTreeSet::new();
    initial_seed.insert(negated.clone());

    let mut seed_to_state_ids: BTreeMap<BTreeSet<TemporalFormula>, Vec<usize>> = BTreeMap::new();
    let mut pending_seeds = VecDeque::new();
    pending_seeds.push_back(initial_seed.clone());

    let mut state_by_old: BTreeMap<BTreeSet<TemporalFormula>, usize> = BTreeMap::new();
    let mut states = Vec::<TemporalBuchiState>::new();
    let mut pending_next_per_state = Vec::<Vec<BTreeSet<TemporalFormula>>>::new();

    while let Some(seed) = pending_seeds.pop_front() {
        if seed_to_state_ids.contains_key(&seed) {
            continue;
        }

        let expansions = expand_temporal_seed(&seed);
        let mut state_ids = Vec::new();

        for expansion in expansions {
            let label_lits: Vec<TemporalAtomLit> = expansion
                .literals
                .iter()
                .map(|(atom_id, value)| {
                    if *value {
                        TemporalAtomLit::Pos(*atom_id)
                    } else {
                        TemporalAtomLit::Neg(*atom_id)
                    }
                })
                .collect();

            let state_id = if let Some(existing) = state_by_old.get(&expansion.old) {
                let id = *existing;
                if states[id].label_lits != label_lits {
                    return Err(PipelineError::Property(
                        "Temporal automaton construction conflict: same logical state produced incompatible labels."
                            .into(),
                    ));
                }
                id
            } else {
                let id = states.len();
                state_by_old.insert(expansion.old.clone(), id);
                states.push(TemporalBuchiState {
                    old: expansion.old.clone(),
                    label_lits,
                    transitions: Vec::new(),
                });
                pending_next_per_state.push(Vec::new());
                id
            };

            if !pending_next_per_state[state_id]
                .iter()
                .any(|existing| existing == &expansion.next)
            {
                pending_next_per_state[state_id].push(expansion.next.clone());
            }
            if !seed_to_state_ids.contains_key(&expansion.next) {
                pending_seeds.push_back(expansion.next.clone());
            }
            state_ids.push(state_id);
        }

        state_ids.sort_unstable();
        state_ids.dedup();
        seed_to_state_ids.insert(seed, state_ids);
    }

    for (state_id, next_seeds) in pending_next_per_state.iter().enumerate() {
        let mut transitions = Vec::new();
        for next_seed in next_seeds {
            if let Some(ids) = seed_to_state_ids.get(next_seed) {
                transitions.extend(ids.iter().copied());
            }
        }
        transitions.sort_unstable();
        transitions.dedup();
        states[state_id].transitions = transitions;
    }

    let mut initial_states = seed_to_state_ids
        .get(&initial_seed)
        .cloned()
        .unwrap_or_default();
    initial_states.sort_unstable();
    initial_states.dedup();

    let mut until_formulas = BTreeSet::new();
    collect_until_formulas(&negated, &mut until_formulas);
    let mut acceptance_sets = Vec::new();
    for until_formula in until_formulas {
        let TemporalFormula::Until(_, rhs) = &until_formula else {
            continue;
        };
        let mut acc = Vec::new();
        for (sid, st) in states.iter().enumerate() {
            if !st.old.contains(&until_formula) || st.old.contains(rhs.as_ref()) {
                acc.push(sid);
            }
        }
        acceptance_sets.push(acc);
    }

    Ok(TemporalBuchiAutomaton {
        quantified_var: quantified_var.to_string(),
        role: role.to_string(),
        atoms: atoms.atoms,
        states,
        initial_states,
        acceptance_sets,
    })
}

fn build_universal_state_predicate_term(
    ta: &ThresholdAutomaton,
    quantified_var: &str,
    role: &str,
    state_expr: &ast::FormulaExpr,
    step: usize,
) -> Result<SmtTerm, PipelineError> {
    let mut disallowed_locs = Vec::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        if loc.role != role {
            continue;
        }
        let holds = eval_formula_expr_on_location(state_expr, quantified_var, loc)?;
        if !holds {
            disallowed_locs.push(id);
        }
    }
    if disallowed_locs.is_empty() {
        return Ok(SmtTerm::bool(true));
    }
    let clauses = disallowed_locs
        .into_iter()
        .map(|id| SmtTerm::var(pdr_kappa_var(step, id)).eq(SmtTerm::int(0)))
        .collect::<Vec<_>>();
    Ok(SmtTerm::and(clauses))
}

fn encode_temporal_formula_term(
    ta: &ThresholdAutomaton,
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
) -> Result<SmtTerm, PipelineError> {
    if step > depth {
        return Ok(SmtTerm::bool(false));
    }
    if !formula_contains_temporal(formula) {
        return build_universal_state_predicate_term(ta, quantified_var, role, formula, step);
    }
    match formula {
        ast::FormulaExpr::Comparison { .. } => {
            build_universal_state_predicate_term(ta, quantified_var, role, formula, step)
        }
        ast::FormulaExpr::Not(inner) => Ok(SmtTerm::not(encode_temporal_formula_term(
            ta,
            quantified_var,
            role,
            inner,
            step,
            depth,
        )?)),
        ast::FormulaExpr::And(lhs, rhs) => Ok(SmtTerm::and(vec![
            encode_temporal_formula_term(ta, quantified_var, role, lhs, step, depth)?,
            encode_temporal_formula_term(ta, quantified_var, role, rhs, step, depth)?,
        ])),
        ast::FormulaExpr::Or(lhs, rhs) => Ok(SmtTerm::or(vec![
            encode_temporal_formula_term(ta, quantified_var, role, lhs, step, depth)?,
            encode_temporal_formula_term(ta, quantified_var, role, rhs, step, depth)?,
        ])),
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let l = encode_temporal_formula_term(ta, quantified_var, role, lhs, step, depth)?;
            let r = encode_temporal_formula_term(ta, quantified_var, role, rhs, step, depth)?;
            Ok(SmtTerm::or(vec![SmtTerm::not(l), r]))
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let l = encode_temporal_formula_term(ta, quantified_var, role, lhs, step, depth)?;
            let r = encode_temporal_formula_term(ta, quantified_var, role, rhs, step, depth)?;
            Ok(SmtTerm::or(vec![
                SmtTerm::and(vec![l.clone(), r.clone()]),
                SmtTerm::and(vec![SmtTerm::not(l), SmtTerm::not(r)]),
            ]))
        }
        ast::FormulaExpr::Next(inner) => {
            if step == depth {
                Ok(SmtTerm::bool(false))
            } else {
                encode_temporal_formula_term(ta, quantified_var, role, inner, step + 1, depth)
            }
        }
        ast::FormulaExpr::Always(inner) => {
            let terms = (step..=depth)
                .map(|i| encode_temporal_formula_term(ta, quantified_var, role, inner, i, depth))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SmtTerm::and(terms))
        }
        ast::FormulaExpr::Eventually(inner) => {
            let terms = (step..=depth)
                .map(|i| encode_temporal_formula_term(ta, quantified_var, role, inner, i, depth))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SmtTerm::or(terms))
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            let mut disjuncts = Vec::new();
            for j in step..=depth {
                let rhs_at_j =
                    encode_temporal_formula_term(ta, quantified_var, role, rhs, j, depth)?;
                let mut conjuncts = vec![rhs_at_j];
                for i in step..j {
                    conjuncts.push(encode_temporal_formula_term(
                        ta,
                        quantified_var,
                        role,
                        lhs,
                        i,
                        depth,
                    )?);
                }
                disjuncts.push(SmtTerm::and(conjuncts));
            }
            Ok(SmtTerm::or(disjuncts))
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => {
            let until_expr = ast::FormulaExpr::Until(lhs.clone(), rhs.clone());
            let always_expr = ast::FormulaExpr::Always(lhs.clone());
            Ok(SmtTerm::or(vec![
                encode_temporal_formula_term(ta, quantified_var, role, &until_expr, step, depth)?,
                encode_temporal_formula_term(ta, quantified_var, role, &always_expr, step, depth)?,
            ]))
        }
        ast::FormulaExpr::Release(lhs, rhs) => {
            // Release dual: (lhs R rhs) == !((!lhs) U (!rhs))
            let dual_until = ast::FormulaExpr::Until(
                Box::new(ast::FormulaExpr::Not(lhs.clone())),
                Box::new(ast::FormulaExpr::Not(rhs.clone())),
            );
            Ok(SmtTerm::not(encode_temporal_formula_term(
                ta,
                quantified_var,
                role,
                &dual_until,
                step,
                depth,
            )?))
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let mut conjuncts = Vec::new();
            for i in step..=depth {
                let lhs_i = encode_temporal_formula_term(ta, quantified_var, role, lhs, i, depth)?;
                let future_rhs = (i..=depth)
                    .map(|j| encode_temporal_formula_term(ta, quantified_var, role, rhs, j, depth))
                    .collect::<Result<Vec<_>, _>>()?;
                conjuncts.push(SmtTerm::or(vec![
                    SmtTerm::not(lhs_i),
                    SmtTerm::or(future_rhs),
                ]));
            }
            Ok(SmtTerm::and(conjuncts))
        }
    }
}

fn extract_liveness_spec(
    ta: &ThresholdAutomaton,
    program: &ast::Program,
) -> Result<LivenessSpec, PipelineError> {
    let reachable = graph_reachable_locations(ta);
    let liveness_props: Vec<&ast::Spanned<ast::PropertyDecl>> = program
        .protocol
        .node
        .properties
        .iter()
        .filter(|p| is_liveness_property_kind(p.node.kind))
        .collect();

    if liveness_props.len() > 1 {
        return Err(PipelineError::Validation(
            "Multiple liveness properties are not yet supported; please specify exactly one."
                .into(),
        ));
    }

    if liveness_props.is_empty() {
        return Ok(LivenessSpec::TerminationGoalLocs(
            collect_decided_goal_locs(ta),
        ));
    }

    let prop = &liveness_props[0].node;
    let q = &prop.formula.quantifiers;
    if q.len() != 1 || q[0].quantifier != ast::Quantifier::ForAll {
        return Err(PipelineError::Property(
            "Liveness property must use one universal quantifier: `forall p: Role. ...`.".into(),
        ));
    }
    let quantified_var = &q[0].var;
    let role = &q[0].domain;
    let role_exists = ta.locations.iter().any(|loc| loc.role == *role);
    if !role_exists {
        return Err(PipelineError::Property(format!(
            "Liveness property references unknown role '{role}'."
        )));
    }

    if formula_contains_temporal(&prop.formula.body) {
        return Ok(LivenessSpec::Temporal {
            quantified_var: quantified_var.clone(),
            role: role.clone(),
            formula: prop.formula.body.clone(),
        });
    }

    let mut goal_locs = Vec::new();
    for (id, loc) in ta.locations.iter().enumerate() {
        if !reachable.contains(&id) {
            continue;
        }
        if loc.role != *role {
            // Liveness predicate scopes one role; other roles are unconstrained.
            goal_locs.push(id);
            continue;
        }
        if eval_formula_expr_on_location(&prop.formula.body, quantified_var, loc)? {
            goal_locs.push(id);
        }
    }
    Ok(LivenessSpec::TerminationGoalLocs(goal_locs))
}

fn fair_liveness_target_from_spec(
    ta: &ThresholdAutomaton,
    spec: LivenessSpec,
) -> Result<FairLivenessTarget, PipelineError> {
    match spec {
        LivenessSpec::TerminationGoalLocs(goal_locs) => Ok(FairLivenessTarget::NonGoalLocs(
            collect_non_goal_reachable_locs(ta, &goal_locs),
        )),
        LivenessSpec::Temporal {
            quantified_var,
            role,
            formula,
        } => Ok(FairLivenessTarget::Temporal(
            compile_temporal_buchi_automaton(&quantified_var, &role, &formula)?,
        )),
    }
}

/// Resolve a ParamOrConst to a concrete i64 value.
/// For Const, returns the value directly.
/// For Param, this is only valid for concrete committee specs (not parametric).
fn resolve_param_or_const(
    poc: &ParamOrConst,
    _ta: &ThresholdAutomaton,
) -> Result<i64, PipelineError> {
    match poc {
        ParamOrConst::Const(c) => Ok(*c),
        ParamOrConst::Param(_pid) => {
            // For now, committee specs must use concrete values
            Err(PipelineError::Solver(
                "Committee parameters must be concrete values, not protocol parameters".into(),
            ))
        }
    }
}

fn with_smt_profile<T, F>(context: &str, run: F) -> Result<T, PipelineError>
where
    F: FnOnce() -> Result<T, PipelineError>,
{
    reset_smt_run_profile();
    let check_started = Instant::now();
    let result = run();
    push_phase_profile(context, "check", check_started.elapsed().as_millis());
    let profile = take_smt_run_profile();
    let has_activity = profile.encode_calls > 0
        || profile.solve_calls > 0
        || profile.assertion_candidates > 0
        || profile.assertion_unique > 0
        || profile.assertion_dedup_hits > 0;
    if has_activity {
        push_phase_profile(context, "encode", profile.encode_elapsed_ms);
        push_phase_profile(context, "solve", profile.solve_elapsed_ms);
        push_smt_profile(context, profile);
    }
    result
}

/// Run the full verification pipeline.
pub fn verify(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    verify_with_cegar(source, filename, options, 0)
}

/// Run verification on an already-parsed program.
///
/// This is useful for workflows that synthesize or mutate protocol ASTs
/// (for example, round-bound sweeps) without re-rendering to source.
pub fn verify_program_ast(
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    preflight_validate(program, options, PipelineCommand::Verify)?;
    verify_program(program, options, options.dump_smt.as_deref())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CegarRefinementKind {
    GlobalEquivocationNone,
    GlobalAuthSigned,
    GlobalValuesExact,
    GlobalNetworkIdentitySelective,
    GlobalNetworkProcessSelective,
    MessageEquivocationNone { message: String },
    MessageAuthAuthenticated { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CegarAtomicRefinement {
    kind: CegarRefinementKind,
    label: String,
    predicate: String,
}

#[derive(Debug, Clone)]
struct CegarRefinement {
    atoms: Vec<CegarAtomicRefinement>,
}

#[derive(Debug, Clone)]
struct CegarRefinementPlanEntry {
    refinement: CegarRefinement,
    rationale: String,
}

impl CegarRefinement {
    fn label(&self) -> String {
        self.atoms
            .iter()
            .map(|atom| atom.label.clone())
            .collect::<Vec<_>>()
            .join("+")
    }

    fn refinements(&self) -> Vec<String> {
        self.atoms
            .iter()
            .map(|atom| atom.predicate.clone())
            .collect()
    }

    fn apply(&self, program: &mut ast::Program) {
        let proto = &mut program.protocol.node;
        for atom in &self.atoms {
            atom.apply(proto);
        }
        let network = adversary_value(proto, "network")
            .or_else(|| adversary_value(proto, "network_semantics"))
            .unwrap_or("classic")
            .to_string();
        ensure_identity_and_auth_for_faithful_mode(proto, &network);
    }
}

impl CegarAtomicRefinement {
    fn global(kind: CegarRefinementKind, label: &'static str, predicate: &'static str) -> Self {
        Self {
            kind,
            label: label.to_string(),
            predicate: predicate.to_string(),
        }
    }

    fn message_equivocation_none(message: &str) -> Self {
        Self {
            kind: CegarRefinementKind::MessageEquivocationNone {
                message: message.to_string(),
            },
            label: format!("equivocation:{message}=none"),
            predicate: format!("equivocation({message})=none"),
        }
    }

    fn message_auth_authenticated(message: &str) -> Self {
        Self {
            kind: CegarRefinementKind::MessageAuthAuthenticated {
                message: message.to_string(),
            },
            label: format!("channel:{message}=authenticated"),
            predicate: format!("channel({message})=authenticated"),
        }
    }

    fn apply(&self, proto: &mut ast::ProtocolDecl) {
        match &self.kind {
            CegarRefinementKind::GlobalEquivocationNone => {
                upsert_adversary_item(proto, "equivocation", "none");
            }
            CegarRefinementKind::GlobalAuthSigned => {
                upsert_adversary_item(proto, "auth", "signed");
            }
            CegarRefinementKind::GlobalValuesExact => {
                upsert_adversary_item(proto, "values", "exact");
            }
            CegarRefinementKind::GlobalNetworkIdentitySelective => {
                upsert_adversary_item(proto, "network", "identity_selective");
            }
            CegarRefinementKind::GlobalNetworkProcessSelective => {
                upsert_adversary_item(proto, "network", "process_selective");
            }
            CegarRefinementKind::MessageEquivocationNone { message } => {
                upsert_message_equivocation_policy(
                    proto,
                    message,
                    ast::EquivocationPolicyMode::None,
                );
            }
            CegarRefinementKind::MessageAuthAuthenticated { message } => {
                upsert_message_channel_policy(proto, message, ast::ChannelAuthMode::Authenticated);
            }
        }
    }
}

fn adversary_value<'a>(proto: &'a ast::ProtocolDecl, key: &str) -> Option<&'a str> {
    proto
        .adversary
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
}

fn upsert_adversary_item(proto: &mut ast::ProtocolDecl, key: &str, value: &str) {
    if let Some(existing) = proto.adversary.iter_mut().find(|item| item.key == key) {
        existing.value = value.to_string();
        return;
    }

    let span = proto
        .adversary
        .first()
        .map(|item| item.span)
        .unwrap_or(ast::Span::new(0, 0));
    proto.adversary.push(ast::AdversaryItem {
        key: key.to_string(),
        value: value.to_string(),
        span,
    });
}

fn upsert_message_channel_policy(
    proto: &mut ast::ProtocolDecl,
    message: &str,
    auth: ast::ChannelAuthMode,
) {
    if let Some(existing) = proto
        .channels
        .iter_mut()
        .find(|decl| decl.message == message)
    {
        existing.auth = auth;
        return;
    }

    let span = proto
        .channels
        .first()
        .map(|decl| decl.span)
        .or_else(|| {
            proto
                .messages
                .iter()
                .find(|decl| decl.name == message)
                .map(|decl| decl.span)
        })
        .or_else(|| proto.adversary.first().map(|decl| decl.span))
        .unwrap_or(ast::Span::new(0, 0));
    proto.channels.push(ast::ChannelDecl {
        message: message.to_string(),
        auth,
        span,
    });
}

fn upsert_message_equivocation_policy(
    proto: &mut ast::ProtocolDecl,
    message: &str,
    mode: ast::EquivocationPolicyMode,
) {
    if let Some(existing) = proto
        .equivocation_policies
        .iter_mut()
        .find(|decl| decl.message == message)
    {
        existing.mode = mode;
        return;
    }

    let span = proto
        .equivocation_policies
        .first()
        .map(|decl| decl.span)
        .or_else(|| {
            proto
                .messages
                .iter()
                .find(|decl| decl.name == message)
                .map(|decl| decl.span)
        })
        .or_else(|| proto.adversary.first().map(|decl| decl.span))
        .unwrap_or(ast::Span::new(0, 0));
    proto.equivocation_policies.push(ast::EquivocationDecl {
        message: message.to_string(),
        mode,
        span,
    });
}

fn ensure_identity_and_auth_for_faithful_mode(proto: &mut ast::ProtocolDecl, network: &str) {
    let faithful = matches!(
        network,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if !faithful {
        return;
    }
    let span = proto
        .identities
        .first()
        .map(|id| id.span)
        .or_else(|| proto.adversary.first().map(|a| a.span))
        .unwrap_or(ast::Span::new(0, 0));
    for role in &proto.roles {
        let role_name = role.node.name.clone();
        if let Some(existing) = proto.identities.iter_mut().find(|id| id.role == role_name) {
            if network == "process_selective" {
                existing.scope = ast::IdentityScope::Process;
                if existing.process_var.is_none() {
                    existing.process_var = Some("pid".into());
                }
            }
            if existing.key.is_none() {
                existing.key = Some(format!("{}_key", role_name.to_lowercase()));
            }
            continue;
        }
        proto.identities.push(ast::IdentityDecl {
            role: role_name.clone(),
            scope: if network == "process_selective" {
                ast::IdentityScope::Process
            } else {
                ast::IdentityScope::Role
            },
            process_var: if network == "process_selective" {
                Some("pid".into())
            } else {
                None
            },
            key: Some(format!("{}_key", role_name.to_lowercase())),
            span,
        });
    }

    let has_auth_field = proto
        .adversary
        .iter()
        .any(|i| i.key == "auth" || i.key == "authentication");
    if !has_auth_field {
        upsert_adversary_item(proto, "auth", "none");
    }
}

fn network_semantics_name(mode: NetworkSemantics) -> &'static str {
    match mode {
        NetworkSemantics::Classic => "classic",
        NetworkSemantics::IdentitySelective => "identity_selective",
        NetworkSemantics::CohortSelective => "cohort_selective",
        NetworkSemantics::ProcessSelective => "process_selective",
    }
}

fn fault_model_name(mode: FaultModel) -> &'static str {
    match mode {
        FaultModel::Byzantine => "byzantine",
        FaultModel::Crash => "crash",
        FaultModel::Omission => "omission",
    }
}

fn authentication_mode_name(mode: AuthenticationMode) -> &'static str {
    match mode {
        AuthenticationMode::None => "none",
        AuthenticationMode::Signed => "signed",
    }
}

fn equivocation_mode_name(mode: EquivocationMode) -> &'static str {
    match mode {
        EquivocationMode::Full => "full",
        EquivocationMode::None => "none",
    }
}

fn delivery_control_mode_name(
    mode: tarsier_ir::threshold_automaton::DeliveryControlMode,
) -> &'static str {
    match mode {
        tarsier_ir::threshold_automaton::DeliveryControlMode::LegacyCounter => "legacy_counter",
        tarsier_ir::threshold_automaton::DeliveryControlMode::PerRecipient => "per_recipient",
        tarsier_ir::threshold_automaton::DeliveryControlMode::Global => "global",
    }
}

fn fault_budget_scope_name(
    mode: tarsier_ir::threshold_automaton::FaultBudgetScope,
) -> &'static str {
    match mode {
        tarsier_ir::threshold_automaton::FaultBudgetScope::LegacyCounter => "legacy_counter",
        tarsier_ir::threshold_automaton::FaultBudgetScope::PerRecipient => "per_recipient",
        tarsier_ir::threshold_automaton::FaultBudgetScope::Global => "global",
    }
}

fn parse_declared_network_semantics(raw: &str) -> NetworkSemantics {
    match raw {
        "identity_selective" | "faithful" | "selective" | "selective_delivery" => {
            NetworkSemantics::IdentitySelective
        }
        "cohort_selective" | "lane_selective" => NetworkSemantics::CohortSelective,
        "process_selective" | "per_process" | "process_scoped" => {
            NetworkSemantics::ProcessSelective
        }
        _ => NetworkSemantics::Classic,
    }
}

fn declared_network_semantics(program: &ast::Program) -> NetworkSemantics {
    let proto = &program.protocol.node;
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");
    parse_declared_network_semantics(network)
}

fn is_faithful_network(mode: NetworkSemantics) -> bool {
    matches!(
        mode,
        NetworkSemantics::IdentitySelective
            | NetworkSemantics::CohortSelective
            | NetworkSemantics::ProcessSelective
    )
}

fn next_coarser_network_mode(
    current: NetworkSemantics,
    floor: FaithfulFallbackFloor,
) -> Option<NetworkSemantics> {
    match current {
        NetworkSemantics::ProcessSelective => Some(NetworkSemantics::CohortSelective),
        NetworkSemantics::CohortSelective => Some(NetworkSemantics::IdentitySelective),
        NetworkSemantics::IdentitySelective => match floor {
            FaithfulFallbackFloor::IdentitySelective => None,
            FaithfulFallbackFloor::Classic => Some(NetworkSemantics::Classic),
        },
        NetworkSemantics::Classic => None,
    }
}

fn automaton_footprint(ta: &ThresholdAutomaton) -> AutomatonFootprint {
    let message_counters = ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();
    AutomatonFootprint {
        locations: ta.locations.len(),
        rules: ta.rules.len(),
        shared_vars: ta.shared_vars.len(),
        message_counters,
    }
}

fn guard_read_vars(guard: &tarsier_ir::threshold_automaton::Guard) -> HashSet<usize> {
    let mut out = HashSet::new();
    for atom in &guard.atoms {
        let GuardAtom::Threshold { vars, .. } = atom;
        out.extend(vars.iter().copied());
    }
    out
}

fn update_write_vars(updates: &[tarsier_ir::threshold_automaton::Update]) -> HashSet<usize> {
    updates.iter().map(|u| u.var).collect()
}

fn por_linear_combination_signature(lc: &LinearCombination) -> String {
    let mut terms = lc.terms.clone();
    terms.sort_by_key(|(_, pid)| *pid);
    let mut out = format!("c={}", lc.constant);
    for (coeff, pid) in terms {
        out.push('|');
        out.push_str(&format!("{coeff}*p{pid}"));
    }
    out
}

fn por_guard_atom_signature(atom: &GuardAtom) -> String {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            let lhs = vars
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let op = match op {
                CmpOp::Ge => ">=",
                CmpOp::Le => "<=",
                CmpOp::Gt => ">",
                CmpOp::Lt => "<",
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
            };
            format!(
                "thr(distinct={distinct};lhs={lhs};op={op};rhs={})",
                por_linear_combination_signature(bound)
            )
        }
    }
}

fn por_update_signature(update: &tarsier_ir::threshold_automaton::Update) -> String {
    match &update.kind {
        tarsier_ir::threshold_automaton::UpdateKind::Increment => format!("inc@{}", update.var),
        tarsier_ir::threshold_automaton::UpdateKind::Set(lc) => {
            format!(
                "set@{}={}",
                update.var,
                por_linear_combination_signature(lc)
            )
        }
    }
}

fn por_rule_signature(rule: &tarsier_ir::threshold_automaton::Rule) -> String {
    let mut guards = rule
        .guard
        .atoms
        .iter()
        .map(por_guard_atom_signature)
        .collect::<Vec<_>>();
    guards.sort();
    let updates = rule
        .updates
        .iter()
        .map(por_update_signature)
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "from={};to={};guards=[{}];updates=[{}]",
        rule.from,
        rule.to,
        guards.join(";"),
        updates
    )
}

fn is_pure_stutter_rule(rule: &tarsier_ir::threshold_automaton::Rule) -> bool {
    rule.from == rule.to && rule.updates.is_empty()
}

fn por_rule_pruning_summary(ta: &ThresholdAutomaton) -> (usize, usize, usize) {
    let mut stutter_pruned = 0usize;
    let mut duplicate_pruned = 0usize;
    let mut seen_signatures: HashSet<String> = HashSet::new();

    for rule in &ta.rules {
        if is_pure_stutter_rule(rule) {
            stutter_pruned = stutter_pruned.saturating_add(1);
            continue;
        }
        let signature = por_rule_signature(rule);
        if !seen_signatures.insert(signature) {
            duplicate_pruned = duplicate_pruned.saturating_add(1);
        }
    }

    let effective_rules = ta
        .rules
        .len()
        .saturating_sub(stutter_pruned)
        .saturating_sub(duplicate_pruned);
    (stutter_pruned, duplicate_pruned, effective_rules)
}

fn rules_independent(
    ta: &ThresholdAutomaton,
    lhs: &tarsier_ir::threshold_automaton::Rule,
    rhs: &tarsier_ir::threshold_automaton::Rule,
) -> bool {
    // Conservative independence: no shared source/target locations and no
    // read/write conflicts over shared variables.
    if lhs.from == rhs.from || lhs.from == rhs.to || lhs.to == rhs.from || lhs.to == rhs.to {
        return false;
    }
    if ta.locations[lhs.from].role == ta.locations[rhs.from].role {
        return false;
    }
    let lhs_reads = guard_read_vars(&lhs.guard);
    let rhs_reads = guard_read_vars(&rhs.guard);
    let lhs_writes = update_write_vars(&lhs.updates);
    let rhs_writes = update_write_vars(&rhs.updates);

    lhs_writes.is_disjoint(&rhs_writes)
        && lhs_writes.is_disjoint(&rhs_reads)
        && rhs_writes.is_disjoint(&lhs_reads)
}

fn independent_rule_pair_count(ta: &ThresholdAutomaton) -> usize {
    let mut count = 0usize;
    for i in 0..ta.rules.len() {
        for j in (i + 1)..ta.rules.len() {
            if rules_independent(ta, &ta.rules[i], &ta.rules[j]) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn footprint_exceeds_budget(footprint: &AutomatonFootprint, cfg: &FaithfulFallbackConfig) -> bool {
    footprint.locations > cfg.max_locations
        || footprint.shared_vars > cfg.max_shared_vars
        || footprint.message_counters > cfg.max_message_counters
}

fn apply_network_semantics_override(program: &mut ast::Program, mode: NetworkSemantics) {
    let proto = &mut program.protocol.node;
    let mode_name = network_semantics_name(mode);
    upsert_adversary_item(proto, "network", mode_name);
    if is_faithful_network(mode) {
        ensure_identity_and_auth_for_faithful_mode(proto, mode_name);
    }
}

fn push_lowering_diagnostic(diag: LoweringDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().lowerings.push(diag);
    });
}

fn push_applied_reduction(diag: AppliedReductionDiagnostic) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().applied_reductions.push(diag);
    });
}

fn push_reduction_note(note: &str) {
    RUN_DIAGNOSTICS.with(|cell| {
        let mut guard = cell.borrow_mut();
        if !guard.reduction_notes.iter().any(|n| n == note) {
            guard.reduction_notes.push(note.to_string());
        }
    });
}

fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = raw.split_whitespace().nth(1)?.parse().ok()?;
        let page_size = 4096_u64;
        return Some(pages.saturating_mul(page_size));
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn push_phase_profile(context: &str, phase: &str, elapsed_ms: u128) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut()
            .phase_profiles
            .push(PhaseProfileDiagnostic {
                context: context.to_string(),
                phase: phase.to_string(),
                elapsed_ms,
                rss_bytes: current_rss_bytes(),
            });
    });
}

fn push_smt_profile(context: &str, profile: SmtRunProfile) {
    RUN_DIAGNOSTICS.with(|cell| {
        cell.borrow_mut().smt_profiles.push(SmtProfileDiagnostic {
            context: context.to_string(),
            encode_calls: profile.encode_calls,
            encode_elapsed_ms: profile.encode_elapsed_ms,
            solve_calls: profile.solve_calls,
            solve_elapsed_ms: profile.solve_elapsed_ms,
            assertion_candidates: profile.assertion_candidates,
            assertion_unique: profile.assertion_unique,
            assertion_dedup_hits: profile.assertion_dedup_hits,
            incremental_depth_reuse_steps: profile.incremental_depth_reuse_steps,
            incremental_decl_reuse_hits: profile.incremental_decl_reuse_hits,
            incremental_assertion_reuse_hits: profile.incremental_assertion_reuse_hits,
            symmetry_candidates: profile.symmetry_candidates,
            symmetry_pruned: profile.symmetry_pruned,
            stutter_signature_normalizations: profile.stutter_signature_normalizations,
        });
    });
}

fn lower_with_controls(
    program: &ast::Program,
    context: &str,
    controls: PipelineExecutionControls,
) -> Result<ThresholdAutomaton, PipelineError> {
    let requested_network = declared_network_semantics(program);
    let mut current_mode = requested_network;
    let initial_lower_started = Instant::now();
    let mut current_ta = lower(program)?;
    push_phase_profile(
        context,
        "lower",
        initial_lower_started.elapsed().as_millis(),
    );
    let requested_footprint = automaton_footprint(&current_ta);
    let mut effective_footprint = requested_footprint;
    let mut budget = None;
    let mut budget_satisfied = true;
    let mut fallback_steps = 0usize;
    let mut fallback_exhausted = false;

    if let Some(cfg) = controls.faithful_fallback {
        budget = Some(AutomatonFootprint {
            locations: cfg.max_locations,
            rules: 0,
            shared_vars: cfg.max_shared_vars,
            message_counters: cfg.max_message_counters,
        });

        if is_faithful_network(current_mode) && footprint_exceeds_budget(&effective_footprint, &cfg)
        {
            loop {
                let Some(next_mode) = next_coarser_network_mode(current_mode, cfg.floor) else {
                    fallback_exhausted = true;
                    break;
                };
                let mut rewritten = program.clone();
                apply_network_semantics_override(&mut rewritten, next_mode);
                let fallback_lower_started = Instant::now();
                let next_ta = lower(&rewritten)?;
                push_phase_profile(
                    context,
                    "lower",
                    fallback_lower_started.elapsed().as_millis(),
                );
                let next_footprint = automaton_footprint(&next_ta);

                push_applied_reduction(AppliedReductionDiagnostic {
                    context: context.to_string(),
                    kind: "network_fallback".into(),
                    from: network_semantics_name(current_mode).into(),
                    to: network_semantics_name(next_mode).into(),
                    trigger: format!(
                        "model footprint exceeded budget: loc={} (<= {}), shared={} (<= {}), msg={} (<= {})",
                        effective_footprint.locations,
                        cfg.max_locations,
                        effective_footprint.shared_vars,
                        cfg.max_shared_vars,
                        effective_footprint.message_counters,
                        cfg.max_message_counters,
                    ),
                    before: effective_footprint,
                    after: next_footprint,
                });
                fallback_steps = fallback_steps.saturating_add(1);

                current_mode = next_mode;
                current_ta = next_ta;
                effective_footprint = next_footprint;

                if !footprint_exceeds_budget(&effective_footprint, &cfg) {
                    break;
                }
            }
            budget_satisfied = !footprint_exceeds_budget(&effective_footprint, &cfg);
            if !budget_satisfied {
                push_reduction_note(
                    "faithful fallback exhausted before reaching size budget; running with coarsest allowed network semantics",
                );
                push_reduction_note("fast_fail.network_size_guard=triggered");
            }
        }
    }
    let independent_pairs = independent_rule_pair_count(&current_ta);
    let (
        por_stutter_rules_pruned,
        por_commutative_duplicate_rules_pruned,
        por_effective_rule_count,
    ) = por_rule_pruning_summary(&current_ta);
    if independent_pairs > 0 {
        push_reduction_note(&format!("por.independent_rule_pairs={independent_pairs}"));
        push_reduction_note("por.transition_multiset_semantics=on");
    }
    if por_stutter_rules_pruned > 0 {
        push_reduction_note(&format!(
            "por.stutter_rules_pruned={por_stutter_rules_pruned}"
        ));
    }
    if por_commutative_duplicate_rules_pruned > 0 {
        push_reduction_note(&format!(
            "por.commutative_duplicate_rules_pruned={por_commutative_duplicate_rules_pruned}"
        ));
    }
    if por_stutter_rules_pruned > 0 || por_commutative_duplicate_rules_pruned > 0 {
        push_reduction_note(&format!("por.effective_rules={por_effective_rule_count}"));
    }

    push_lowering_diagnostic(LoweringDiagnostic {
        context: context.to_string(),
        requested_network: network_semantics_name(requested_network).into(),
        effective_network: network_semantics_name(current_mode).into(),
        fault_model: fault_model_name(current_ta.fault_model).into(),
        authentication: authentication_mode_name(current_ta.authentication_mode).into(),
        equivocation: equivocation_mode_name(current_ta.equivocation_mode).into(),
        delivery_control: delivery_control_mode_name(current_ta.delivery_control).into(),
        fault_budget_scope: fault_budget_scope_name(current_ta.fault_budget_scope).into(),
        identity_roles: current_ta.role_identities.len(),
        process_identity_roles: current_ta
            .role_identities
            .values()
            .filter(|cfg| cfg.scope == tarsier_ir::threshold_automaton::RoleIdentityScope::Process)
            .count(),
        requested_footprint,
        effective_footprint,
        fallback_budget: budget,
        budget_satisfied,
        fallback_applied: fallback_steps > 0,
        fallback_steps,
        fallback_exhausted,
        independent_rule_pairs: independent_pairs,
        por_stutter_rules_pruned,
        por_commutative_duplicate_rules_pruned,
        por_effective_rule_count,
    });

    Ok(current_ta)
}

fn lower_with_active_controls(
    program: &ast::Program,
    context: &str,
) -> Result<ThresholdAutomaton, PipelineError> {
    lower_with_controls(program, context, current_execution_controls())
}

fn cegar_atomic_refinements(program: &ast::Program) -> Vec<CegarAtomicRefinement> {
    let proto = &program.protocol.node;
    let model = adversary_value(proto, "model").unwrap_or("byzantine");
    let equivocation = adversary_value(proto, "equivocation").unwrap_or("full");
    let auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let values = adversary_value(proto, "values")
        .or_else(|| adversary_value(proto, "value_abstraction"))
        .unwrap_or("exact");
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");

    let mut atomics: Vec<CegarAtomicRefinement> = Vec::new();
    if model == "byzantine" && equivocation != "none" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalEquivocationNone,
            "equivocation:none",
            "adversary.equivocation=none",
        ));
    }
    if auth != "signed" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalAuthSigned,
            "auth:signed",
            "adversary.auth=signed",
        ));
    }
    if values != "exact" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalValuesExact,
            "values:exact",
            "adversary.values=exact",
        ));
    }
    if model == "byzantine"
        && network != "identity_selective"
        && network != "cohort_selective"
        && network != "process_selective"
    {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalNetworkIdentitySelective,
            "network:identity_selective",
            "adversary.network=identity_selective",
        ));
    }
    if model == "byzantine" && network != "process_selective" {
        atomics.push(CegarAtomicRefinement::global(
            CegarRefinementKind::GlobalNetworkProcessSelective,
            "network:process_selective",
            "adversary.network=process_selective",
        ));
    }

    atomics
}

#[derive(Debug, Clone, Default)]
struct CegarTraceSignals {
    conflicting_variants: bool,
    cross_recipient_delivery: bool,
    sign_abstract_values: bool,
    identity_scoped_channels: bool,
    conflicting_variant_families: BTreeSet<String>,
    cross_recipient_families: BTreeSet<String>,
}

fn parse_counter_signature(name: &str) -> Option<(String, String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped.split_once('@')?;
    let channel = recipient_part
        .split_once('[')
        .map(|(r, _)| r)
        .unwrap_or(recipient_part);
    let recipient = channel
        .split_once("<-")
        .map(|(r, _)| r)
        .unwrap_or(channel)
        .to_string();
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    let variant_suffix = stripped
        .split_once('[')
        .map(|(_, fields)| format!("[{fields}"))
        .unwrap_or_default();
    let variant = format!("{family}{variant_suffix}");
    Some((family, variant, Some(recipient)))
}

fn cegar_trace_signals_from_trace(
    ta: &ThresholdAutomaton,
    trace: &tarsier_ir::counter_system::Trace,
) -> CegarTraceSignals {
    let mut active_vars: HashSet<usize> = trace
        .initial_config
        .gamma
        .iter()
        .enumerate()
        .filter(|(_, value)| **value > 0)
        .map(|(idx, _)| idx)
        .collect();
    for step in &trace.steps {
        for (idx, value) in step.config.gamma.iter().enumerate() {
            if *value > 0 {
                active_vars.insert(idx);
            }
        }
    }

    let mut variants_by_family: HashMap<String, HashSet<String>> = HashMap::new();
    let mut recipients_by_variant: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut sign_abstract_values = false;
    let mut identity_scoped_channels = false;

    for var_id in active_vars {
        let Some(shared) = ta.shared_vars.get(var_id) else {
            continue;
        };
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        if let Some((family, variant, recipient)) = parse_counter_signature(&shared.name) {
            variants_by_family
                .entry(family.clone())
                .or_default()
                .insert(variant.clone());
            if let Some(recipient) = recipient {
                if recipient.contains('#') {
                    identity_scoped_channels = true;
                }
                recipients_by_variant
                    .entry((family, variant))
                    .or_default()
                    .insert(recipient);
            }
        }
        if shared.name.contains("=neg")
            || shared.name.contains("=pos")
            || shared.name.contains("=zero")
        {
            sign_abstract_values = true;
        }
    }

    let conflicting_variants = variants_by_family
        .values()
        .any(|variants| variants.len() > 1);
    let cross_recipient_delivery = recipients_by_variant
        .values()
        .any(|recipients| recipients.len() > 1);
    let conflicting_variant_families: BTreeSet<String> = variants_by_family
        .iter()
        .filter_map(|(family, variants)| {
            if variants.len() > 1 {
                Some(family.clone())
            } else {
                None
            }
        })
        .collect();
    let cross_recipient_families: BTreeSet<String> = recipients_by_variant
        .iter()
        .filter_map(|((family, _variant), recipients)| {
            if recipients.len() > 1 {
                Some(family.clone())
            } else {
                None
            }
        })
        .collect();

    CegarTraceSignals {
        conflicting_variants,
        cross_recipient_delivery,
        sign_abstract_values,
        identity_scoped_channels,
        conflicting_variant_families,
        cross_recipient_families,
    }
}

fn cegar_trace_generated_refinements(
    program: &ast::Program,
    signals: &CegarTraceSignals,
) -> Vec<CegarAtomicRefinement> {
    let proto = &program.protocol.node;
    let declared_messages: HashSet<&str> = proto.messages.iter().map(|m| m.name.as_str()).collect();
    let global_auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let global_equivocation = adversary_value(proto, "equivocation").unwrap_or("full");

    let mut generated = Vec::new();
    for message in &signals.conflicting_variant_families {
        if !declared_messages.contains(message.as_str()) {
            continue;
        }
        if !effective_message_non_equivocating(proto, message, global_equivocation) {
            generated.push(CegarAtomicRefinement::message_equivocation_none(message));
        }
    }
    for message in &signals.cross_recipient_families {
        if !declared_messages.contains(message.as_str()) {
            continue;
        }
        if !effective_message_authenticated(proto, message, global_auth) {
            generated.push(CegarAtomicRefinement::message_auth_authenticated(message));
        }
    }
    generated
}

fn cegar_core_compound_predicate(predicates: &[String]) -> Option<String> {
    if predicates.len() <= 1 {
        return None;
    }
    Some(format!("cegar.core.min({})", predicates.join(" && ")))
}

fn cegar_refinement_score(atom: &CegarAtomicRefinement, signals: &CegarTraceSignals) -> i32 {
    let mut score = match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => 40,
        CegarRefinementKind::GlobalAuthSigned => 30,
        CegarRefinementKind::GlobalValuesExact => 80,
        CegarRefinementKind::GlobalNetworkIdentitySelective => 30,
        CegarRefinementKind::GlobalNetworkProcessSelective => 20,
        CegarRefinementKind::MessageEquivocationNone { .. } => 50,
        CegarRefinementKind::MessageAuthAuthenticated { .. } => 35,
    };
    match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => {
            if signals.conflicting_variants {
                score += 220;
            }
        }
        CegarRefinementKind::GlobalAuthSigned => {
            if signals.conflicting_variants || signals.cross_recipient_delivery {
                score += 60;
            }
        }
        CegarRefinementKind::GlobalValuesExact => {
            if signals.sign_abstract_values {
                // Recover exact value semantics before network refinements when
                // the trace clearly exercised sign abstraction.
                score += 120;
            }
        }
        CegarRefinementKind::GlobalNetworkIdentitySelective => {
            if signals.cross_recipient_delivery {
                score += 70;
            }
        }
        CegarRefinementKind::GlobalNetworkProcessSelective => {
            if signals.cross_recipient_delivery {
                score += 95;
            }
            if signals.identity_scoped_channels {
                score += 10;
            }
        }
        CegarRefinementKind::MessageEquivocationNone { message } => {
            if signals.conflicting_variant_families.contains(message) {
                score += 205;
            }
            if signals.cross_recipient_families.contains(message) {
                score += 30;
            }
        }
        CegarRefinementKind::MessageAuthAuthenticated { message } => {
            if signals.cross_recipient_families.contains(message) {
                score += 145;
            }
            if signals.conflicting_variant_families.contains(message) {
                score += 55;
            }
        }
    }
    score
}

fn cegar_atom_evidence_tags(
    atom: &CegarAtomicRefinement,
    signals: &CegarTraceSignals,
) -> Vec<String> {
    let mut tags = Vec::new();
    match &atom.kind {
        CegarRefinementKind::GlobalEquivocationNone => {
            if signals.conflicting_variants {
                tags.push("conflicting_variants".to_string());
            }
        }
        CegarRefinementKind::GlobalAuthSigned => {
            if signals.conflicting_variants {
                tags.push("conflicting_variants".to_string());
            }
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
        }
        CegarRefinementKind::GlobalValuesExact => {
            if signals.sign_abstract_values {
                tags.push("sign_abstract_values".to_string());
            }
        }
        CegarRefinementKind::GlobalNetworkIdentitySelective => {
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
        }
        CegarRefinementKind::GlobalNetworkProcessSelective => {
            if signals.cross_recipient_delivery {
                tags.push("cross_recipient_delivery".to_string());
            }
            if signals.identity_scoped_channels {
                tags.push("identity_scoped_channels".to_string());
            }
        }
        CegarRefinementKind::MessageEquivocationNone { message } => {
            if signals.conflicting_variant_families.contains(message) {
                tags.push("conflicting_variants".to_string());
                tags.push(format!("conflicting_variants:{message}"));
            }
            if signals.cross_recipient_families.contains(message) {
                tags.push(format!("cross_recipient_delivery:{message}"));
            }
        }
        CegarRefinementKind::MessageAuthAuthenticated { message } => {
            if signals.cross_recipient_families.contains(message) {
                tags.push("cross_recipient_delivery".to_string());
                tags.push(format!("cross_recipient_delivery:{message}"));
            }
            if signals.conflicting_variant_families.contains(message) {
                tags.push(format!("conflicting_variants:{message}"));
            }
        }
    }
    tags
}

#[derive(Debug, Clone)]
struct CegarEvidenceRequirement {
    tag: String,
    supporters: Vec<usize>,
}

#[derive(Debug, Clone)]
struct CegarUnsatCoreSelection {
    selected_indices: Vec<usize>,
    cores_considered: usize,
}

#[derive(Debug, Clone)]
enum CegarOracleOutcome {
    Sat,
    Unsat { core_indices: Vec<usize> },
    Unknown,
}

fn cegar_selection_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, 15)
}

fn cegar_evidence_requirements(
    atomics: &[CegarAtomicRefinement],
    signals: &CegarTraceSignals,
) -> Vec<CegarEvidenceRequirement> {
    let mut supporters_by_tag: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for (idx, atom) in atomics.iter().enumerate() {
        for tag in cegar_atom_evidence_tags(atom, signals) {
            supporters_by_tag.entry(tag).or_default().insert(idx);
        }
    }

    supporters_by_tag
        .into_iter()
        .filter_map(|(tag, supporters)| {
            if supporters.is_empty() {
                None
            } else {
                Some(CegarEvidenceRequirement {
                    tag,
                    supporters: supporters.into_iter().collect(),
                })
            }
        })
        .collect()
}

fn combinations_of_size(indices_len: usize, pick: usize) -> Vec<Vec<usize>> {
    if pick == 0 {
        return vec![Vec::new()];
    }
    if pick > indices_len {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(pick);
    fn rec(
        start: usize,
        remaining: usize,
        total: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            out.push(current.clone());
            return;
        }
        let last_start = total.saturating_sub(remaining);
        for idx in start..=last_start {
            current.push(idx);
            rec(idx + 1, remaining - 1, total, current, out);
            current.pop();
        }
    }
    rec(0, pick, indices_len, &mut current, &mut out);
    out
}

fn at_most_k_bool_terms(vars: &[String], k: usize) -> Vec<SmtTerm> {
    if k >= vars.len() {
        return Vec::new();
    }
    if k == 0 {
        return vars
            .iter()
            .map(|name| SmtTerm::var(name.clone()).not())
            .collect();
    }
    let mut terms = Vec::new();
    for combo in combinations_of_size(vars.len(), k + 1) {
        let clause = combo
            .into_iter()
            .map(|idx| SmtTerm::var(vars[idx].clone()).not())
            .collect();
        terms.push(SmtTerm::or(clause));
    }
    terms
}

fn cegar_oracle_outcome_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
    enabled_indices: &BTreeSet<usize>,
) -> Result<CegarOracleOutcome, S::Error> {
    if !solver.supports_assumption_unsat_core() {
        return Ok(CegarOracleOutcome::Unknown);
    }

    let select_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_select_{idx}"))
        .collect();
    for name in &select_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }

    for req in requirements {
        let disjuncts: Vec<SmtTerm> = req
            .supporters
            .iter()
            .map(|idx| SmtTerm::var(select_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disjuncts))?;
    }

    let mut disable_by_index: HashMap<usize, String> = HashMap::with_capacity(atomics_len);
    for (idx, selected_name) in select_vars.iter().enumerate() {
        let disable_name = format!("__cegar_disable_{idx}");
        solver.declare_var(&disable_name, &SmtSort::Bool)?;
        solver.assert(
            &SmtTerm::var(disable_name.clone()).implies(SmtTerm::var(selected_name.clone()).not()),
        )?;
        disable_by_index.insert(idx, disable_name);
    }

    let assumptions: Vec<String> = (0..atomics_len)
        .filter(|idx| !enabled_indices.contains(idx))
        .filter_map(|idx| disable_by_index.get(&idx).cloned())
        .collect();
    match solver.check_sat_assuming(&assumptions)? {
        SatResult::Sat => Ok(CegarOracleOutcome::Sat),
        SatResult::Unsat => {
            let core_names = solver.get_unsat_core_assumptions()?;
            let mut index_by_disable: HashMap<String, usize> =
                HashMap::with_capacity(disable_by_index.len());
            for (idx, name) in disable_by_index {
                index_by_disable.insert(name, idx);
            }
            let mut core_indices: Vec<usize> = core_names
                .into_iter()
                .filter_map(|name| index_by_disable.get(&name).copied())
                .collect();
            core_indices.sort_unstable();
            core_indices.dedup();
            if core_indices.is_empty() {
                Ok(CegarOracleOutcome::Unknown)
            } else {
                Ok(CegarOracleOutcome::Unsat { core_indices })
            }
        }
        SatResult::Unknown(_) => Ok(CegarOracleOutcome::Unknown),
    }
}

fn cegar_min_hitting_set_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    discovered_cores: &[Vec<usize>],
) -> Result<Option<BTreeSet<usize>>, S::Error> {
    if atomics_len == 0 {
        return Ok(Some(BTreeSet::new()));
    }
    let choice_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_pick_{idx}"))
        .collect();
    for name in &choice_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }
    for core in discovered_cores {
        let disj = core
            .iter()
            .map(|idx| SmtTerm::var(choice_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disj))?;
    }

    for k in 0..=atomics_len {
        solver.push()?;
        for term in at_most_k_bool_terms(&choice_vars, k) {
            solver.assert(&term)?;
        }
        let sat = solver.check_sat()?;
        match sat {
            SatResult::Sat => {
                let mut selected = BTreeSet::new();
                // Deterministic tie-break: lexicographically minimize the
                // selected-index bitvector by trying to force each variable to
                // false in index order, and only forcing true when UNSAT.
                for (idx, name) in choice_vars.iter().enumerate() {
                    solver.push()?;
                    solver.assert(&SmtTerm::var(name.clone()).not())?;
                    match solver.check_sat()? {
                        SatResult::Sat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()).not())?;
                        }
                        SatResult::Unsat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()))?;
                            selected.insert(idx);
                        }
                        SatResult::Unknown(_) => {
                            solver.pop()?;
                            solver.pop()?;
                            return Ok(None);
                        }
                    }
                }
                solver.pop()?;
                return Ok(Some(selected));
            }
            SatResult::Unsat => {
                solver.pop()?;
            }
            SatResult::Unknown(_) => {
                solver.pop()?;
                return Ok(None);
            }
        }
    }

    Ok(None)
}

fn cegar_unsat_core_seed_with_factory<S, E, F>(
    mut solver_factory: F,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
) -> Result<Option<CegarUnsatCoreSelection>, PipelineError>
where
    S: SmtSolver<Error = E>,
    E: std::error::Error,
    F: FnMut() -> Result<S, E>,
{
    if atomics_len == 0 || requirements.is_empty() {
        return Ok(None);
    }

    {
        let solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
        if !solver.supports_assumption_unsat_core() {
            return Ok(None);
        }
    }

    let mut discovered_cores: Vec<Vec<usize>> = Vec::new();
    let mut seen_cores: HashSet<Vec<usize>> = HashSet::new();
    let max_iters = atomics_len.saturating_mul(8).max(8);

    for _ in 0..max_iters {
        let candidate = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_min_hitting_set_with_solver(&mut solver, atomics_len, &discovered_cores)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        let Some(candidate) = candidate else {
            return Ok(None);
        };

        let outcome = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_oracle_outcome_with_solver(&mut solver, atomics_len, requirements, &candidate)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        match outcome {
            CegarOracleOutcome::Sat => {
                return Ok(Some(CegarUnsatCoreSelection {
                    selected_indices: candidate.into_iter().collect(),
                    cores_considered: discovered_cores.len(),
                }));
            }
            CegarOracleOutcome::Unsat { core_indices } => {
                if seen_cores.insert(core_indices.clone()) {
                    discovered_cores.push(core_indices);
                } else {
                    return Ok(None);
                }
            }
            CegarOracleOutcome::Unknown => {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

fn cegar_unsat_core_seed(
    atomics: &[CegarAtomicRefinement],
    requirements: &[CegarEvidenceRequirement],
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Option<CegarUnsatCoreSelection> {
    let timeout_secs = cegar_selection_timeout_secs(timeout_secs);
    let result = match solver_choice {
        SolverChoice::Z3 => cegar_unsat_core_seed_with_factory(
            || {
                Ok::<_, tarsier_smt::backends::z3_backend::Z3Error>(Z3Solver::with_timeout_secs(
                    timeout_secs,
                ))
            },
            atomics.len(),
            requirements,
        ),
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            cegar_unsat_core_seed_with_factory(
                || Cvc5Solver::with_timeout_secs(timeout_secs),
                atomics.len(),
                requirements,
            )
        }
    };

    match result {
        Ok(seed) => seed,
        Err(err) => {
            info!("CEGAR UNSAT-core refinement selection fallback: {err}");
            None
        }
    }
}

fn cegar_refinement_plan_with_signals(
    program: &ast::Program,
    signals: Option<&CegarTraceSignals>,
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Vec<CegarRefinementPlanEntry> {
    let mut atomics = cegar_atomic_refinements(program);
    if let Some(signals) = signals {
        atomics.extend(cegar_trace_generated_refinements(program, signals));
    }
    if atomics.is_empty() {
        return Vec::new();
    }
    let mut seen_labels = HashSet::new();
    atomics.retain(|atom| seen_labels.insert(atom.label.clone()));

    let mut plan = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();
    let mut push_plan = |atoms: Vec<CegarAtomicRefinement>, rationale: String| {
        let refinement = CegarRefinement { atoms };
        let label = refinement.label();
        if emitted.insert(label) {
            plan.push(CegarRefinementPlanEntry {
                refinement,
                rationale,
            });
        }
    };

    if let Some(signals) = signals {
        let requirements = cegar_evidence_requirements(&atomics, signals);
        if let Some(seed) =
            cegar_unsat_core_seed(&atomics, &requirements, solver_choice, timeout_secs)
        {
            if !seed.selected_indices.is_empty() {
                let atoms: Vec<CegarAtomicRefinement> = seed
                    .selected_indices
                    .iter()
                    .filter_map(|idx| atomics.get(*idx).cloned())
                    .collect();
                if !atoms.is_empty() {
                    let requirement_tags: Vec<String> =
                        requirements.iter().map(|req| req.tag.clone()).collect();
                    push_plan(
                        atoms,
                        format!(
                            "unsat-core minimized evidence cover: solver-backed seed over [{}] (cores={}, selected={})",
                            requirement_tags.join(", "),
                            seed.cores_considered,
                            seed.selected_indices.len()
                        ),
                    );
                }
            }
        }

        atomics.sort_by(|a, b| {
            let sa = cegar_refinement_score(a, signals);
            let sb = cegar_refinement_score(b, signals);
            sb.cmp(&sa).then_with(|| a.label.cmp(&b.label))
        });

        let mut evidence_backed: Vec<(CegarAtomicRefinement, Vec<String>, i32)> = atomics
            .iter()
            .cloned()
            .filter_map(|atom| {
                let tags = cegar_atom_evidence_tags(&atom, signals);
                if tags.is_empty() {
                    None
                } else {
                    let score = cegar_refinement_score(&atom, signals);
                    Some((atom, tags, score))
                }
            })
            .collect();
        evidence_backed.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.label.cmp(&b.0.label)));

        for (atom, tags, score) in &evidence_backed {
            push_plan(
                vec![atom.clone()],
                format!(
                    "evidence-driven: selected by trace signals [{}] (score={score})",
                    tags.join(", ")
                ),
            );
        }

        if evidence_backed.len() > 1 {
            let atoms: Vec<CegarAtomicRefinement> = evidence_backed
                .iter()
                .map(|(atom, _, _)| atom.clone())
                .collect();
            push_plan(
                atoms,
                "evidence-driven: combined evidence-backed refinements to eliminate correlated artifacts".into(),
            );
        }

        for atom in &atomics {
            let tags = cegar_atom_evidence_tags(atom, signals);
            if tags.is_empty() {
                let score = cegar_refinement_score(atom, signals);
                push_plan(
                    vec![atom.clone()],
                    format!(
                        "fallback: no direct trace signal matched; trying next best ranked refinement (score={score})"
                    ),
                );
            }
        }
    } else {
        for atom in &atomics {
            push_plan(
                vec![atom.clone()],
                "baseline: no counterexample evidence available; using default refinement ordering"
                    .into(),
            );
        }
    }

    // Final cumulative fallback to avoid being locked into single-atom refinements only.
    let mut prefix = Vec::new();
    for atom in atomics {
        prefix.push(atom);
        if prefix.len() > 1 {
            push_plan(
                prefix.clone(),
                "fallback: cumulative strengthening after single-refinement attempts".into(),
            );
        }
    }

    plan
}

fn cegar_refinement_ladder_with_signals(
    program: &ast::Program,
    signals: Option<&CegarTraceSignals>,
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Vec<CegarRefinement> {
    cegar_refinement_plan_with_signals(program, signals, solver_choice, timeout_secs)
        .into_iter()
        .map(|entry| entry.refinement)
        .collect()
}

#[derive(Debug)]
struct CegarStageEvalCache<T> {
    entries: HashMap<String, T>,
    hits: usize,
    misses: usize,
}

impl<T> Default for CegarStageEvalCache<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            hits: 0,
            misses: 0,
        }
    }
}

impl<T: Clone> CegarStageEvalCache<T> {
    fn key(refinement: &CegarRefinement) -> String {
        let mut predicates = sorted_unique_strings(refinement.refinements());
        if predicates.is_empty() {
            "<baseline>".into()
        } else {
            predicates.sort();
            predicates.join(" && ")
        }
    }

    fn eval<F>(&mut self, refinement: &CegarRefinement, compute: F) -> Result<T, PipelineError>
    where
        F: FnOnce() -> Result<T, PipelineError>,
    {
        let key = Self::key(refinement);
        if let Some(existing) = self.entries.get(&key) {
            self.hits = self.hits.saturating_add(1);
            return Ok(existing.clone());
        }
        self.misses = self.misses.saturating_add(1);
        let value = compute()?;
        self.entries.insert(key, value.clone());
        Ok(value)
    }

    fn emit_notes(&self) {
        if self.hits == 0 && self.misses == 0 {
            return;
        }
        push_reduction_note("cegar.incremental_stage_cache=on");
        push_reduction_note(&format!("cegar.incremental_stage_cache_hits={}", self.hits));
        push_reduction_note(&format!(
            "cegar.incremental_stage_cache_misses={}",
            self.misses
        ));
    }
}

fn cegar_shrink_refinement_core<Eval>(
    refinement: &CegarRefinement,
    mut eval: Eval,
) -> Result<Option<CegarRefinement>, PipelineError>
where
    Eval: FnMut(&CegarRefinement) -> Result<Option<bool>, PipelineError>,
{
    if refinement.atoms.len() <= 1 {
        return Ok(None);
    }
    let mut core = refinement.atoms.clone();
    let mut changed = true;
    let mut attempted = false;
    while changed && core.len() > 1 {
        changed = false;
        let mut idx = 0;
        while idx < core.len() {
            let mut candidate = core.clone();
            candidate.remove(idx);
            if candidate.is_empty() {
                idx += 1;
                continue;
            }
            attempted = true;
            match eval(&CegarRefinement {
                atoms: candidate.clone(),
            })? {
                Some(true) => {
                    core = candidate;
                    changed = true;
                    break;
                }
                Some(false) => {
                    idx += 1;
                }
                None => return Ok(None),
            }
        }
    }
    if attempted && core.len() < refinement.atoms.len() {
        Ok(Some(CegarRefinement { atoms: core }))
    } else {
        Ok(None)
    }
}

fn cegar_signals_note(signals: &CegarTraceSignals) -> Option<String> {
    let tags = cegar_signal_tags(signals);
    if tags.is_empty() {
        None
    } else {
        Some(format!("Adaptive CEGAR trace signals: {}", tags.join(", ")))
    }
}

fn cegar_signal_tags(signals: &CegarTraceSignals) -> Vec<&'static str> {
    let mut tags = Vec::new();
    if signals.conflicting_variants {
        tags.push("conflicting_variants");
    }
    if signals.cross_recipient_delivery {
        tags.push("cross_recipient_delivery");
    }
    if signals.sign_abstract_values {
        tags.push("sign_abstract_values");
    }
    if signals.identity_scoped_channels {
        tags.push("identity_scoped_channels");
    }
    tags
}

fn cegar_stage_counterexample_analysis(
    stage: usize,
    refinements: &[String],
    result: &VerificationResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        VerificationResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        VerificationResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

fn stage_outcome_from_verification(result: &VerificationResult) -> CegarStageOutcome {
    match result {
        VerificationResult::Safe { depth_checked } => CegarStageOutcome::Safe {
            depth_checked: *depth_checked,
        },
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => CegarStageOutcome::ProbabilisticallySafe {
            depth_checked: *depth_checked,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        VerificationResult::Unsafe { trace } => CegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        VerificationResult::Unknown { reason } => CegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

fn stage_outcome_from_unbounded_safety(
    result: &UnboundedSafetyResult,
) -> UnboundedSafetyCegarStageOutcome {
    match result {
        UnboundedSafetyResult::Safe { induction_k } => UnboundedSafetyCegarStageOutcome::Safe {
            induction_k: *induction_k,
        },
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => UnboundedSafetyCegarStageOutcome::ProbabilisticallySafe {
            induction_k: *induction_k,
            failure_probability: *failure_probability,
            committee_count: committee_analyses.len(),
        },
        UnboundedSafetyResult::Unsafe { trace } => UnboundedSafetyCegarStageOutcome::Unsafe {
            trace: trace.clone(),
        },
        UnboundedSafetyResult::NotProved { max_k, cti } => {
            UnboundedSafetyCegarStageOutcome::NotProved {
                max_k: *max_k,
                cti: cti.clone(),
            }
        }
        UnboundedSafetyResult::Unknown { reason } => UnboundedSafetyCegarStageOutcome::Unknown {
            reason: reason.clone(),
        },
    }
}

fn stage_outcome_from_unbounded_fair_liveness(
    result: &UnboundedFairLivenessResult,
) -> UnboundedFairLivenessCegarStageOutcome {
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => {
            UnboundedFairLivenessCegarStageOutcome::LiveProved { frame: *frame }
        }
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => UnboundedFairLivenessCegarStageOutcome::FairCycleFound {
            depth: *depth,
            loop_start: *loop_start,
            trace: trace.clone(),
        },
        UnboundedFairLivenessResult::NotProved { max_k } => {
            UnboundedFairLivenessCegarStageOutcome::NotProved { max_k: *max_k }
        }
        UnboundedFairLivenessResult::Unknown { reason } => {
            UnboundedFairLivenessCegarStageOutcome::Unknown {
                reason: reason.clone(),
            }
        }
    }
}

fn cegar_stage_counterexample_analysis_unbounded_safety(
    stage: usize,
    refinements: &[String],
    result: &UnboundedSafetyResult,
    baseline_is_unsafe: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_is_unsafe {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedSafetyResult::Unsafe { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported UNSAFE before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this UNSAFE is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                    stage, refinements_text
                ),
            })
        }
        UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
            let reason = match result {
                UnboundedSafetyResult::NotProved { max_k, .. } => {
                    format!("proof did not close up to k={max_k}")
                }
                UnboundedSafetyResult::Unknown { reason } => reason.clone(),
                _ => unreachable!(),
            };
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: format!(
                    "Stage {} could not decisively confirm or eliminate the baseline UNSAFE witness under refinements [{}]: {}",
                    stage, refinements_text, reason
                ),
            })
        }
    }
}

fn cegar_stage_counterexample_analysis_unbounded_fair(
    stage: usize,
    refinements: &[String],
    result: &UnboundedFairLivenessResult,
    baseline_has_cycle: bool,
    baseline_signals: Option<&CegarTraceSignals>,
) -> Option<CegarCounterexampleAnalysis> {
    if !baseline_has_cycle {
        return None;
    }
    let refinements_text = if refinements.is_empty() {
        "(none)".to_string()
    } else {
        refinements.join(", ")
    };
    let signal_text = baseline_signals
        .map(cegar_signal_tags)
        .filter(|tags| !tags.is_empty())
        .map(|tags| tags.join(", "));
    match result {
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            let mut rationale = if stage == 0 {
                "Baseline stage reported a fair-cycle witness before refinement replay; witness starts as potentially spurious until checked under stricter assumptions.".to_string()
            } else {
                format!(
                    "Fair-cycle witness persists at stage {} under refinements [{}]. Because refinements only restrict behaviors, this witness is treated as concrete.",
                    stage, refinements_text
                )
            };
            if let Some(signals) = signal_text {
                rationale.push_str(&format!(" Baseline trace signals: {signals}."));
            }
            Some(CegarCounterexampleAnalysis {
                classification: if stage == 0 {
                    "potentially_spurious".into()
                } else {
                    "concrete".into()
                },
                rationale,
            })
        }
        UnboundedFairLivenessResult::LiveProved { .. } => Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline fair-cycle witness is eliminated at stage {} under refinements [{}], so it may be spurious under the baseline abstraction.",
                stage, refinements_text
            ),
        }),
        UnboundedFairLivenessResult::NotProved { max_k } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: proof did not converge up to frame {}.",
                stage, refinements_text, max_k
            ),
        }),
        UnboundedFairLivenessResult::Unknown { reason } => Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: format!(
                "Stage {} could not decisively confirm or eliminate the baseline fair-cycle witness under refinements [{}]: {}",
                stage, refinements_text, reason
            ),
        }),
    }
}

fn sorted_unique_strings(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

fn effective_message_equivocation_mode(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_equivocation: &str,
) -> String {
    if effective_message_non_equivocating(proto, msg, global_equivocation) {
        "none".to_string()
    } else {
        "full".to_string()
    }
}

fn effective_message_auth_mode(proto: &ast::ProtocolDecl, msg: &str, global_auth: &str) -> String {
    if effective_message_authenticated(proto, msg, global_auth) {
        "authenticated".to_string()
    } else {
        "unauthenticated".to_string()
    }
}

fn cegar_stage_model_changes(
    program: &ast::Program,
    refinement: &CegarRefinement,
) -> Vec<CegarModelChange> {
    let proto = &program.protocol.node;
    let global_auth = adversary_value(proto, "auth")
        .or_else(|| adversary_value(proto, "authentication"))
        .unwrap_or("none");
    let global_equivocation = adversary_value(proto, "equivocation").unwrap_or("full");
    let network = adversary_value(proto, "network")
        .or_else(|| adversary_value(proto, "network_semantics"))
        .unwrap_or("classic");
    let values = adversary_value(proto, "values")
        .or_else(|| adversary_value(proto, "value_abstraction"))
        .unwrap_or("exact");

    let mut changes = Vec::new();
    for atom in &refinement.atoms {
        match &atom.kind {
            CegarRefinementKind::GlobalEquivocationNone => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "equivocation".into(),
                before: global_equivocation.to_string(),
                after: "none".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalAuthSigned => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "auth".into(),
                before: global_auth.to_string(),
                after: "signed".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalValuesExact => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "values".into(),
                before: values.to_string(),
                after: "exact".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkIdentitySelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "identity_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::GlobalNetworkProcessSelective => changes.push(CegarModelChange {
                category: "adversary".into(),
                target: "network".into(),
                before: network.to_string(),
                after: "process_selective".into(),
                predicate: atom.predicate.clone(),
            }),
            CegarRefinementKind::MessageEquivocationNone { message } => {
                changes.push(CegarModelChange {
                    category: "equivocation".into(),
                    target: message.clone(),
                    before: effective_message_equivocation_mode(
                        proto,
                        message,
                        global_equivocation,
                    ),
                    after: "none".into(),
                    predicate: atom.predicate.clone(),
                })
            }
            CegarRefinementKind::MessageAuthAuthenticated { message } => {
                changes.push(CegarModelChange {
                    category: "channel".into(),
                    target: message.clone(),
                    before: effective_message_auth_mode(proto, message, global_auth),
                    after: "authenticated".into(),
                    predicate: atom.predicate.clone(),
                })
            }
        }
    }

    changes.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.predicate.cmp(&b.predicate))
    });
    changes.dedup_by(|a, b| {
        a.category == b.category
            && a.target == b.target
            && a.before == b.before
            && a.after == b.after
            && a.predicate == b.predicate
    });
    changes
}

fn cegar_stage_eliminated_traces(
    stage: usize,
    result: &VerificationResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe trace is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

fn cegar_stage_eliminated_traces_unbounded_safety(
    stage: usize,
    result: &UnboundedSafetyResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(
        result,
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. }
    ) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_unsafe_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline unsafe proof witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

fn cegar_stage_eliminated_traces_unbounded_fair(
    stage: usize,
    result: &UnboundedFairLivenessResult,
    baseline_trace: Option<&tarsier_ir::counter_system::Trace>,
    effective_preds: &[String],
) -> Vec<CegarEliminatedTrace> {
    let Some(trace) = baseline_trace else {
        return Vec::new();
    };
    if !matches!(result, UnboundedFairLivenessResult::LiveProved { .. }) {
        return Vec::new();
    }
    vec![CegarEliminatedTrace {
        kind: "baseline_fair_cycle_witness".into(),
        source_stage: 0,
        eliminated_by: sorted_unique_strings(effective_preds.to_vec()),
        rationale: format!(
            "Baseline fair-cycle witness is eliminated at stage {stage} under monotone refinement replay."
        ),
        trace: trace.clone(),
    }]
}

fn cegar_build_termination(
    reason: &str,
    max_refinements: usize,
    stages: &[CegarStageReport],
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let iterations_used = stages.iter().filter(|stage| stage.stage > 0).count();
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}

fn cegar_build_termination_from_iterations(
    reason: &str,
    max_refinements: usize,
    iterations_used: usize,
    timeout_secs: u64,
    started_at: Instant,
    reached_timeout_budget: bool,
) -> CegarTermination {
    let reached_iteration_budget = max_refinements > 0 && iterations_used >= max_refinements;
    CegarTermination {
        reason: reason.to_string(),
        iteration_budget: max_refinements,
        iterations_used,
        timeout_secs,
        elapsed_ms: started_at.elapsed().as_millis(),
        reached_iteration_budget,
        reached_timeout_budget,
    }
}

fn verify_program(
    program: &ast::Program,
    options: &PipelineOptions,
    dump_smt: Option<&str>,
) -> Result<VerificationResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(program, "verify")?;
    info!(
        locations = ta.locations.len(),
        rules = ta.rules.len(),
        "Threshold automaton constructed"
    );
    ensure_n_parameter(&ta)?;

    // Analyze committees (if any) and derive adversary bounds.
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();

    // Collect per-committee (param_id, b_max) bounds for SMT injection.
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Ok(VerificationResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    let property = extract_property(&ta, program, options.soundness)?;

    info!(
        solver = ?options.solver,
        max_depth = options.max_depth,
        "Starting BMC verification..."
    );

    let (bmc_result, cs) = run_bmc_for_ta(&ta, &property, options, &committee_bounds, dump_smt)?;

    if has_committees {
        // Union bound for overall failure probability.
        let total_epsilon: f64 = committee_summaries.iter().map(|c| c.epsilon).sum();

        match bmc_result {
            BmcResult::Safe { depth_checked } => Ok(VerificationResult::ProbabilisticallySafe {
                depth_checked,
                failure_probability: total_epsilon,
                committee_analyses: committee_summaries,
            }),
            BmcResult::Unsafe { depth, model } => {
                let trace = extract_trace(&cs, &model, depth);
                Ok(VerificationResult::Unsafe { trace })
            }
            BmcResult::Unknown { reason, .. } => Ok(VerificationResult::Unknown { reason }),
        }
    } else {
        Ok(bmc_result_to_verification(bmc_result, &cs))
    }
}

/// Run verification with adaptive CEGAR and return a stage report.
///
/// Refinements are monotone (only restrict behaviors) and are prioritized from
/// baseline counterexample signals. The schedule evaluates single refinements
/// first, then cumulative combinations; elimination cores are greedily shrunk.
pub fn verify_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<CegarAuditReport, PipelineError> {
    with_smt_profile("verify_cegar", || {
        let started_at = Instant::now();
        reset_run_diagnostics();
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR verification") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    let baseline_result = VerificationResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR verification"),
                    };
                    return Ok(CegarAuditReport {
                        max_refinements,
                        stages: vec![CegarStageReport {
                            stage: 0,
                            label: "baseline".into(),
                            refinements: Vec::new(),
                            outcome: stage_outcome_from_verification(&baseline_result),
                            note: Some("Global timeout exhausted before baseline stage.".into()),
                            model_changes: Vec::new(),
                            eliminated_traces: Vec::new(),
                            discovered_predicates: Vec::new(),
                            counterexample_analysis: None,
                        }],
                        discovered_predicates: Vec::new(),
                        classification: "timeout".into(),
                        counterexample_analysis: None,
                        termination: cegar_build_termination(
                            "baseline_timeout",
                            max_refinements,
                            &[],
                            options.timeout_secs,
                            started_at,
                            true,
                        ),
                        final_result: baseline_result,
                    });
                }
            };

        let baseline_result = verify_program(
            &program,
            &baseline_options,
            baseline_options.dump_smt.as_deref(),
        )?;
        let trace_signals = match &baseline_result {
            VerificationResult::Unsafe { trace } => {
                let ta_for_signals = lower_with_active_controls(&program, "verify_cegar.signals")?;
                Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
            }
            _ => None,
        };
        let baseline_is_unsafe = matches!(baseline_result, VerificationResult::Unsafe { .. });
        let mut stages = vec![CegarStageReport {
            stage: 0,
            label: "baseline".into(),
            refinements: Vec::new(),
            outcome: stage_outcome_from_verification(&baseline_result),
            note: trace_signals.as_ref().and_then(cegar_signals_note),
            model_changes: Vec::new(),
            eliminated_traces: Vec::new(),
            discovered_predicates: Vec::new(),
            counterexample_analysis: cegar_stage_counterexample_analysis(
                0,
                &[],
                &baseline_result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            ),
        }];
        let mut discovered_predicates: Vec<String> = Vec::new();
        let mut saw_timeout = false;

        if !baseline_is_unsafe || max_refinements == 0 {
            let classification = if baseline_is_unsafe {
                "unsafe_unrefined"
            } else if matches!(
                baseline_result,
                VerificationResult::Safe { .. } | VerificationResult::ProbabilisticallySafe { .. }
            ) {
                "safe"
            } else {
                "inconclusive"
            };
            let termination = cegar_build_termination(
                if baseline_is_unsafe {
                    "iteration_budget_zero"
                } else {
                    "baseline_non_unsafe"
                },
                max_refinements,
                &stages,
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(CegarAuditReport {
                max_refinements,
                stages,
                discovered_predicates,
                classification: classification.into(),
                counterexample_analysis: if baseline_is_unsafe {
                    Some(CegarCounterexampleAnalysis {
                    classification: "potentially_spurious".into(),
                    rationale: "No refinement replay was performed, so the baseline UNSAFE witness is not yet confirmed under stricter assumptions.".into(),
                })
                } else {
                    None
                },
                termination,
                final_result: baseline_result,
            });
        }

        let mut final_result = baseline_result.clone();
        let mut saw_eliminated = false;
        let mut saw_inconclusive = false;
        let mut confirmed_unsafe = false;
        let mut eval_cache = CegarStageEvalCache::<VerificationResult>::default();
        let refinement_plan = cegar_refinement_plan_with_signals(
            &program,
            trace_signals.as_ref(),
            options.solver,
            options.timeout_secs,
        );

        for (idx, plan_entry) in refinement_plan
            .into_iter()
            .take(max_refinements)
            .enumerate()
        {
            let refinement = plan_entry.refinement;
            let refined_options =
                match options_with_remaining_timeout(options, deadline, "CEGAR verification") {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        saw_timeout = true;
                        final_result = VerificationResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR verification"),
                        };
                        break;
                    }
                };
            let result = eval_cache.eval(&refinement, || {
                let mut refined_program = program.clone();
                refinement.apply(&mut refined_program);
                verify_program(&refined_program, &refined_options, None)
            })?;
            let refinement_preds = sorted_unique_strings(refinement.refinements());
            let mut effective_preds = refinement_preds.clone();
            let model_changes = cegar_stage_model_changes(&program, &refinement);

            let mut note = match &result {
                VerificationResult::Unsafe { .. } => Some(
                    "Counterexample persists under this refinement; treated as concrete.".into(),
                ),
                VerificationResult::Safe { .. }
                | VerificationResult::ProbabilisticallySafe { .. } => {
                    Some("Baseline counterexample is eliminated under this refinement.".into())
                }
                VerificationResult::Unknown { .. } => {
                    Some("Refinement did not produce a decisive verdict for this stage.".into())
                }
            };
            let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
            note = Some(match note {
                Some(existing) => format!("{selection_note} {existing}"),
                None => selection_note,
            });

            if !matches!(result, VerificationResult::Unsafe { .. }) && refinement.atoms.len() > 1 {
                let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                    let refined_options = match options_with_remaining_timeout(
                        options,
                        deadline,
                        "CEGAR refinement-core extraction",
                    ) {
                        Ok(adjusted) => adjusted,
                        Err(_) => return Ok(None),
                    };
                    let candidate_result = eval_cache.eval(candidate, || {
                        let mut candidate_program = program.clone();
                        candidate.apply(&mut candidate_program);
                        verify_program(&candidate_program, &refined_options, None)
                    })?;
                    Ok(Some(!matches!(
                        candidate_result,
                        VerificationResult::Unsafe { .. }
                    )))
                })?;
                if let Some(core) = maybe_core {
                    let core_preds = core.refinements();
                    effective_preds = core_preds.clone();
                    let core_note = format!("Refinement-elimination core: {}", core.label());
                    note = Some(match note {
                        Some(existing) => format!("{existing} {core_note}"),
                        None => core_note,
                    });
                }
            }
            if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                let core_note = format!("Generated core predicate: {core_predicate}");
                note = Some(match note {
                    Some(existing) => format!("{existing} {core_note}"),
                    None => core_note,
                });
            }
            let stage_counterexample_analysis = cegar_stage_counterexample_analysis(
                idx + 1,
                &effective_preds,
                &result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            );
            let baseline_trace = match &stages[0].outcome {
                CegarStageOutcome::Unsafe { trace } => Some(trace),
                _ => None,
            };
            let eliminated_traces =
                cegar_stage_eliminated_traces(idx + 1, &result, baseline_trace, &effective_preds);
            let stage_discovered_predicates = if eliminated_traces.is_empty() {
                Vec::new()
            } else {
                let mut preds = effective_preds.clone();
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    preds.push(core_predicate);
                }
                sorted_unique_strings(preds)
            };

            stages.push(CegarStageReport {
                stage: idx + 1,
                label: refinement.label(),
                refinements: sorted_unique_strings(refinement_preds.clone()),
                outcome: stage_outcome_from_verification(&result),
                note,
                model_changes,
                eliminated_traces,
                discovered_predicates: stage_discovered_predicates,
                counterexample_analysis: stage_counterexample_analysis,
            });

            match result {
                VerificationResult::Unsafe { .. } => {
                    final_result = result;
                    confirmed_unsafe = true;
                    break;
                }
                VerificationResult::Safe { .. }
                | VerificationResult::ProbabilisticallySafe { .. } => {
                    saw_eliminated = true;
                    for pred in &effective_preds {
                        if !discovered_predicates.contains(&pred) {
                            discovered_predicates.push(pred.clone());
                        }
                    }
                    if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                        if !discovered_predicates.contains(&core_predicate) {
                            discovered_predicates.push(core_predicate);
                        }
                    }
                }
                VerificationResult::Unknown { .. } => {
                    saw_inconclusive = true;
                }
            }
        }
        eval_cache.emit_notes();
        discovered_predicates = sorted_unique_strings(discovered_predicates);

        if !confirmed_unsafe && saw_eliminated {
            final_result = VerificationResult::Unknown {
                reason: "CEGAR refinements eliminated the baseline counterexample, but no refined \
                     unsafe witness was found. Treat as inconclusive and inspect the CEGAR report."
                    .into(),
            };
        } else if !confirmed_unsafe && saw_timeout {
            final_result = VerificationResult::Unknown {
                reason: timeout_unknown_reason("CEGAR verification"),
            };
        } else if !confirmed_unsafe && saw_inconclusive {
            final_result = VerificationResult::Unknown {
                reason: "CEGAR refinements were inconclusive; baseline counterexample is not \
                     confirmed under refined assumptions."
                    .into(),
            };
        }

        let classification = if confirmed_unsafe {
            "unsafe_confirmed"
        } else if saw_eliminated {
            "inconclusive"
        } else if saw_timeout {
            "timeout"
        } else {
            "inconclusive"
        };
        let counterexample_analysis = if !baseline_is_unsafe {
            None
        } else if confirmed_unsafe {
            let confirmation = stages
                .iter()
                .find(|stage| {
                    stage.stage > 0 && matches!(&stage.outcome, CegarStageOutcome::Unsafe { .. })
                })
                .map(|stage| stage.stage)
                .unwrap_or(0);
            Some(CegarCounterexampleAnalysis {
                classification: "concrete".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is confirmed concrete by refined replay at stage {}.",
                    confirmation
                ),
            })
        } else if saw_eliminated {
            Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline UNSAFE witness was eliminated by refinement predicates [{}], so the overall result is inconclusive until a concrete refined UNSAFE witness is found.",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        })
        } else if saw_timeout {
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: timeout_unknown_reason("CEGAR verification"),
            })
        } else {
            Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: "Unable to confirm or eliminate the baseline UNSAFE witness within refinement budget.".into(),
        })
        };
        let termination_reason = if confirmed_unsafe {
            "confirmed_unsafe"
        } else if saw_eliminated {
            "counterexample_eliminated_no_confirmation"
        } else if saw_timeout {
            "timeout"
        } else if stages.iter().filter(|stage| stage.stage > 0).count() >= max_refinements {
            "max_refinements_reached"
        } else {
            "inconclusive"
        };
        let termination = cegar_build_termination(
            termination_reason,
            max_refinements,
            &stages,
            options.timeout_secs,
            started_at,
            saw_timeout,
        );

        Ok(CegarAuditReport {
            max_refinements,
            stages,
            discovered_predicates,
            classification: classification.into(),
            counterexample_analysis,
            termination,
            final_result,
        })
    })
}

/// Run verification with CEGAR refinement and return the final verdict.
pub fn verify_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<VerificationResult, PipelineError> {
    reset_run_diagnostics();
    let report = verify_with_cegar_report(source, filename, options, max_refinements)?;
    Ok(report.final_result)
}

fn prove_safety_for_ta(
    mut ta: ThresholdAutomaton,
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Ok(UnboundedSafetyResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    let property = extract_property(&ta, program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());

    info!(
        solver = ?options.solver,
        proof_engine = ?options.proof_engine,
        max_k = options.max_depth,
        "Starting unbounded safety proof..."
    );

    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_with_engine(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &committee_bounds,
                options.proof_engine,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_with_engine(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &committee_bounds,
                options.proof_engine,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };

    Ok(kind_result_to_unbounded_safety(
        kind_result,
        &cs,
        &property,
        &committee_summaries,
    ))
}

fn prove_safety_program(
    program: &ast::Program,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(program, "prove_safety")?;
    ensure_n_parameter(&ta)?;
    prove_safety_for_ta(ta, program, options)
}

/// Run an unbounded safety proof attempt via k-induction.
///
/// Uses `options.max_depth` as the maximum induction depth `k`.
pub fn prove_safety(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety", || {
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;
        prove_safety_program(&program, options)
    })
}

/// Run unbounded safety proof with adaptive CEGAR refinements.
///
/// Refinements are monotone restrictions over adversary assumptions and value
/// abstraction. If a baseline `UNSAFE` trace is eliminated by refinements and
/// no refined stage remains `UNSAFE`, the result is reported as `UNKNOWN`
/// (potentially spurious baseline trace).
pub fn prove_safety_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety_cegar", || {
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    });
                }
            };

        let baseline_result = prove_safety_program(&program, &baseline_options)?;
        let baseline_is_unsafe = matches!(baseline_result, UnboundedSafetyResult::Unsafe { .. });
        if baseline_is_unsafe {
            if max_refinements == 0 {
                return Ok(baseline_result);
            }

            let trace_signals = match &baseline_result {
                UnboundedSafetyResult::Unsafe { trace } => {
                    let ta_for_signals =
                        lower_with_active_controls(&program, "prove_safety_cegar.signals")?;
                    Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
                }
                _ => None,
            };
            let mut saw_eliminated = false;
            let mut saw_inconclusive = false;
            let refinement_ladder = cegar_refinement_ladder_with_signals(
                &program,
                trace_signals.as_ref(),
                options.solver,
                options.timeout_secs,
            );
            let mut discovered_predicates: Vec<String> = Vec::new();
            let mut eval_cache = CegarStageEvalCache::<UnboundedSafetyResult>::default();

            for refinement in refinement_ladder.into_iter().take(max_refinements) {
                let refined_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR unbounded safety",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        eval_cache.emit_notes();
                        return Ok(UnboundedSafetyResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR unbounded safety"),
                        });
                    }
                };
                let result = eval_cache.eval(&refinement, || {
                    let mut refined_program = program.clone();
                    refinement.apply(&mut refined_program);
                    prove_safety_program(&refined_program, &refined_options)
                })?;
                let refinement_preds = refinement.refinements();
                let mut effective_preds = refinement_preds.clone();
                match result {
                    UnboundedSafetyResult::Unsafe { .. } => {
                        eval_cache.emit_notes();
                        return Ok(result);
                    }
                    UnboundedSafetyResult::Safe { .. }
                    | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                        if refinement.atoms.len() > 1 {
                            let maybe_core =
                                cegar_shrink_refinement_core(&refinement, |candidate| {
                                    let refined_options = match options_with_remaining_timeout(
                                        options,
                                        deadline,
                                        "CEGAR unbounded safety core extraction",
                                    ) {
                                        Ok(adjusted) => adjusted,
                                        Err(_) => return Ok(None),
                                    };
                                    let candidate_result = eval_cache.eval(candidate, || {
                                        let mut candidate_program = program.clone();
                                        candidate.apply(&mut candidate_program);
                                        prove_safety_program(&candidate_program, &refined_options)
                                    })?;
                                    Ok(Some(!matches!(
                                        candidate_result,
                                        UnboundedSafetyResult::Unsafe { .. }
                                    )))
                                })?;
                            if let Some(core) = maybe_core {
                                effective_preds = core.refinements();
                            }
                        }
                        saw_eliminated = true;
                        for pred in &effective_preds {
                            if !discovered_predicates.contains(&pred) {
                                discovered_predicates.push(pred.clone());
                            }
                        }
                        if let Some(core_predicate) =
                            cegar_core_compound_predicate(&effective_preds)
                        {
                            if !discovered_predicates.contains(&core_predicate) {
                                discovered_predicates.push(core_predicate);
                            }
                        }
                    }
                    UnboundedSafetyResult::NotProved { .. }
                    | UnboundedSafetyResult::Unknown { .. } => {
                        saw_inconclusive = true;
                    }
                }
            }
            eval_cache.emit_notes();

            if saw_eliminated {
                discovered_predicates = sorted_unique_strings(discovered_predicates);
                return Ok(UnboundedSafetyResult::Unknown {
                    reason: format!(
                        "CEGAR refinements eliminated the baseline unsafe proof witness, \
                         but no refined unsafe witness was found. Potentially spurious \
                         under refinements: {}",
                        if discovered_predicates.is_empty() {
                            "<none>".into()
                        } else {
                            discovered_predicates.join(", ")
                        }
                    ),
                });
            }
            if saw_inconclusive {
                return Ok(UnboundedSafetyResult::Unknown {
                    reason: "CEGAR refinements were inconclusive; baseline unsafe witness is not \
                             confirmed under refined assumptions."
                        .into(),
                });
            }
            return Ok(UnboundedSafetyResult::Unknown {
                reason: "CEGAR refinement ladder exhausted without a confirmed unsafe or \
                         elimination witness."
                    .into(),
            });
        }

        if max_refinements == 0 {
            return Ok(baseline_result);
        }

        let Some(cti_summary) = (match &baseline_result {
            UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => Some(cti.clone()),
            _ => None,
        }) else {
            return Ok(baseline_result);
        };

        info!("Attempting automatic invariant synthesis from induction CTI...");
        let mut ta = lower_with_active_controls(&program, "prove_safety_cegar.synthesis")?;
        ensure_n_parameter(&ta)?;
        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();
        let committee_bounds: Vec<(usize, u64)> = ta
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(baseline_result);
        }

        let property = extract_property(&ta, &program, options.soundness)?;
        let cs = abstract_to_cs(ta.clone());
        let candidate_budget = (max_refinements.max(1)) * 2;
        let candidates =
            cti_zero_location_candidates(&ta, &property, &cti_summary, candidate_budget);
        if candidates.is_empty() {
            return Ok(baseline_result);
        }

        let mut synthesized_locs = Vec::new();
        for loc in candidates {
            let synthesis_options = match options_with_remaining_timeout(
                options,
                deadline,
                "CTI predicate synthesis",
            ) {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CTI predicate synthesis"),
                    });
                }
            };
            if prove_location_unreachable_for_synthesis(
                &cs,
                &synthesis_options,
                &committee_bounds,
                loc,
            )? {
                synthesized_locs.push(loc);
            }
            if synthesized_locs.len() >= max_refinements.max(1) {
                break;
            }
        }
        if synthesized_locs.is_empty() {
            return Ok(baseline_result);
        }

        let mut labels: Vec<String> = synthesized_locs
            .iter()
            .map(|loc| format!("loc_unreachable:{}", ta.locations[*loc].name))
            .collect();
        labels.sort();
        labels.dedup();

        let run_with_engine = |engine: ProofEngine,
                               stage_options: &PipelineOptions|
         -> Result<KInductionResult, PipelineError> {
            match stage_options.solver {
                SolverChoice::Z3 => {
                    let mut solver = Z3Solver::with_timeout_secs(stage_options.timeout_secs);
                    run_unbounded_with_engine_and_location_invariants(
                        &mut solver,
                        &cs,
                        &property,
                        stage_options.max_depth,
                        &committee_bounds,
                        engine,
                        &synthesized_locs,
                        overall_timeout_duration(stage_options.timeout_secs),
                    )
                }
                SolverChoice::Cvc5 => {
                    use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                    let mut solver = Cvc5Solver::with_timeout_secs(stage_options.timeout_secs)
                        .map_err(|e| PipelineError::Solver(e.to_string()))?;
                    run_unbounded_with_engine_and_location_invariants(
                        &mut solver,
                        &cs,
                        &property,
                        stage_options.max_depth,
                        &committee_bounds,
                        engine,
                        &synthesized_locs,
                        overall_timeout_duration(stage_options.timeout_secs),
                    )
                }
            }
        };

        let final_stage_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Ok(UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    });
                }
            };

        let kind_result = run_with_engine(options.proof_engine, &final_stage_options)?;

        let mut refined =
            kind_result_to_unbounded_safety(kind_result, &cs, &property, &committee_summaries);
        match &mut refined {
            UnboundedSafetyResult::Unknown { reason } => {
                *reason = format!(
                    "{reason} Auto-synthesized predicates: {}",
                    labels.join(", ")
                );
            }
            UnboundedSafetyResult::NotProved { cti: Some(cti), .. } => {
                cti.violated_condition = format!(
                    "{} | auto-synthesized predicates: {}",
                    cti.violated_condition,
                    labels.join(", ")
                );
            }
            _ => {}
        }

        Ok(refined)
    })
}

fn solver_choice_label(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn proof_engine_label(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

fn fairness_mode_label(fairness: FairnessMode) -> &'static str {
    match fairness {
        FairnessMode::Weak => "weak",
        FairnessMode::Strong => "strong",
    }
}

/// Run unbounded safety proof with CEGAR and return a machine-readable report.
///
/// This API is intended for CI/governance integrations that need explicit
/// refinement controls and baseline/final outcome tracking.
pub fn prove_safety_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    max_refinements: usize,
) -> Result<UnboundedSafetyCegarAuditReport, PipelineError> {
    with_smt_profile("prove_safety_cegar_report", || {
        let started_at = Instant::now();
        reset_run_diagnostics();
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Unbounded safety proof (`prove`) is safety-only, but this protocol declares only \
                 liveness properties. Use `prove-fair` / `prove_fair_liveness` for unbounded \
                 temporal liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        let deadline = deadline_from_timeout_secs(options.timeout_secs);
        let baseline_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    let baseline_result = UnboundedSafetyResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR unbounded safety"),
                    };
                    let stages = vec![UnboundedSafetyCegarStageReport {
                        stage: 0,
                        label: "baseline".into(),
                        refinements: Vec::new(),
                        outcome: stage_outcome_from_unbounded_safety(&baseline_result),
                        note: Some("Global timeout exhausted before baseline stage.".into()),
                        model_changes: Vec::new(),
                        eliminated_traces: Vec::new(),
                        discovered_predicates: Vec::new(),
                        counterexample_analysis: None,
                    }];
                    let termination = cegar_build_termination_from_iterations(
                        "baseline_timeout",
                        max_refinements,
                        0,
                        options.timeout_secs,
                        started_at,
                        true,
                    );
                    return Ok(UnboundedSafetyCegarAuditReport {
                        controls: CegarRunControls {
                            max_refinements,
                            timeout_secs: options.timeout_secs,
                            solver: solver_choice_label(options.solver).into(),
                            proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                            fairness: None,
                        },
                        stages,
                        discovered_predicates: Vec::new(),
                        baseline_result: baseline_result.clone(),
                        final_result: baseline_result,
                        classification: "timeout".into(),
                        counterexample_analysis: None,
                        termination,
                    });
                }
            };
        let baseline_result = prove_safety_program(&program, &baseline_options)?;
        let trace_signals = match &baseline_result {
            UnboundedSafetyResult::Unsafe { trace } => {
                let ta_for_signals =
                    lower_with_active_controls(&program, "prove_safety_cegar.signals")?;
                Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
            }
            _ => None,
        };
        let baseline_is_unsafe = matches!(baseline_result, UnboundedSafetyResult::Unsafe { .. });
        let mut stages = vec![UnboundedSafetyCegarStageReport {
            stage: 0,
            label: "baseline".into(),
            refinements: Vec::new(),
            outcome: stage_outcome_from_unbounded_safety(&baseline_result),
            note: trace_signals.as_ref().and_then(cegar_signals_note),
            model_changes: Vec::new(),
            eliminated_traces: Vec::new(),
            discovered_predicates: Vec::new(),
            counterexample_analysis: cegar_stage_counterexample_analysis_unbounded_safety(
                0,
                &[],
                &baseline_result,
                baseline_is_unsafe,
                trace_signals.as_ref(),
            ),
        }];

        let mut final_result = baseline_result.clone();
        let mut discovered_predicates: Vec<String> = Vec::new();
        let mut saw_timeout = false;
        let mut saw_eliminated = false;
        let mut saw_inconclusive = false;
        let mut confirmed_unsafe = false;
        let mut eval_cache = CegarStageEvalCache::<UnboundedSafetyResult>::default();

        if !baseline_is_unsafe {
            if max_refinements > 0
                && matches!(baseline_result, UnboundedSafetyResult::NotProved { .. })
                && options.proof_engine == ProofEngine::KInduction
            {
                let synthesized =
                    prove_safety_with_cegar(source, filename, options, max_refinements)?;
                final_result = synthesized.clone();
                let note =
                    "Applied CTI-driven invariant synthesis for NOT_PROVED baseline.".to_string();
                stages.push(UnboundedSafetyCegarStageReport {
                    stage: 1,
                    label: "cti-synthesis".into(),
                    refinements: Vec::new(),
                    outcome: stage_outcome_from_unbounded_safety(&synthesized),
                    note: Some(note),
                    model_changes: Vec::new(),
                    eliminated_traces: Vec::new(),
                    discovered_predicates: Vec::new(),
                    counterexample_analysis: None,
                });
            }

            let classification = if matches!(
                final_result,
                UnboundedSafetyResult::Safe { .. }
                    | UnboundedSafetyResult::ProbabilisticallySafe { .. }
            ) {
                "safe"
            } else {
                "inconclusive"
            };
            let termination = cegar_build_termination_from_iterations(
                "baseline_non_unsafe",
                max_refinements,
                stages.len().saturating_sub(1),
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(UnboundedSafetyCegarAuditReport {
                controls: CegarRunControls {
                    max_refinements,
                    timeout_secs: options.timeout_secs,
                    solver: solver_choice_label(options.solver).into(),
                    proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                    fairness: None,
                },
                stages,
                discovered_predicates,
                baseline_result,
                final_result,
                classification: classification.into(),
                counterexample_analysis: None,
                termination,
            });
        }

        if max_refinements == 0 {
            let termination = cegar_build_termination_from_iterations(
                "iteration_budget_zero",
                max_refinements,
                0,
                options.timeout_secs,
                started_at,
                false,
            );
            return Ok(UnboundedSafetyCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: None,
            },
            stages,
            discovered_predicates,
            baseline_result: baseline_result.clone(),
            final_result: baseline_result,
            classification: "unsafe_unrefined".into(),
            counterexample_analysis: Some(CegarCounterexampleAnalysis {
                classification: "potentially_spurious".into(),
                rationale: "No refinement replay was performed, so the baseline UNSAFE witness is not yet confirmed under stricter assumptions.".into(),
            }),
            termination,
            });
        }

        let refinement_plan = cegar_refinement_plan_with_signals(
            &program,
            trace_signals.as_ref(),
            options.solver,
            options.timeout_secs,
        );

        for (idx, plan_entry) in refinement_plan
            .into_iter()
            .take(max_refinements)
            .enumerate()
        {
            let refinement = plan_entry.refinement;
            let refined_options =
                match options_with_remaining_timeout(options, deadline, "CEGAR unbounded safety") {
                    Ok(adjusted) => adjusted,
                    Err(_) => {
                        saw_timeout = true;
                        final_result = UnboundedSafetyResult::Unknown {
                            reason: timeout_unknown_reason("CEGAR unbounded safety"),
                        };
                        break;
                    }
                };
            let result = eval_cache.eval(&refinement, || {
                let mut refined_program = program.clone();
                refinement.apply(&mut refined_program);
                prove_safety_program(&refined_program, &refined_options)
            })?;
            let refinement_preds = sorted_unique_strings(refinement.refinements());
            let mut effective_preds = refinement_preds.clone();
            let model_changes = cegar_stage_model_changes(&program, &refinement);

            let mut note = match &result {
                UnboundedSafetyResult::Unsafe { .. } => Some(
                    "Counterexample persists under this refinement; treated as concrete.".into(),
                ),
                UnboundedSafetyResult::Safe { .. }
                | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                    Some("Baseline counterexample is eliminated under this refinement.".into())
                }
                UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
                    Some("Refinement did not produce a decisive verdict for this stage.".into())
                }
            };
            let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
            note = Some(match note {
                Some(existing) => format!("{selection_note} {existing}"),
                None => selection_note,
            });

            if !matches!(result, UnboundedSafetyResult::Unsafe { .. }) && refinement.atoms.len() > 1
            {
                let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                    let refined_options = match options_with_remaining_timeout(
                        options,
                        deadline,
                        "CEGAR unbounded safety core extraction",
                    ) {
                        Ok(adjusted) => adjusted,
                        Err(_) => return Ok(None),
                    };
                    let candidate_result = eval_cache.eval(candidate, || {
                        let mut candidate_program = program.clone();
                        candidate.apply(&mut candidate_program);
                        prove_safety_program(&candidate_program, &refined_options)
                    })?;
                    Ok(Some(!matches!(
                        candidate_result,
                        UnboundedSafetyResult::Unsafe { .. }
                    )))
                })?;
                if let Some(core) = maybe_core {
                    let core_preds = core.refinements();
                    effective_preds = core_preds.clone();
                    let core_note = format!("Refinement-elimination core: {}", core.label());
                    note = Some(match note {
                        Some(existing) => format!("{existing} {core_note}"),
                        None => core_note,
                    });
                }
            }
            if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                let core_note = format!("Generated core predicate: {core_predicate}");
                note = Some(match note {
                    Some(existing) => format!("{existing} {core_note}"),
                    None => core_note,
                });
            }
            let stage_counterexample_analysis =
                cegar_stage_counterexample_analysis_unbounded_safety(
                    idx + 1,
                    &effective_preds,
                    &result,
                    baseline_is_unsafe,
                    trace_signals.as_ref(),
                );
            let baseline_trace = match &stages[0].outcome {
                UnboundedSafetyCegarStageOutcome::Unsafe { trace } => Some(trace),
                _ => None,
            };
            let eliminated_traces = cegar_stage_eliminated_traces_unbounded_safety(
                idx + 1,
                &result,
                baseline_trace,
                &effective_preds,
            );
            let stage_discovered_predicates = if eliminated_traces.is_empty() {
                Vec::new()
            } else {
                let mut preds = effective_preds.clone();
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    preds.push(core_predicate);
                }
                sorted_unique_strings(preds)
            };

            stages.push(UnboundedSafetyCegarStageReport {
                stage: idx + 1,
                label: refinement.label(),
                refinements: sorted_unique_strings(refinement_preds.clone()),
                outcome: stage_outcome_from_unbounded_safety(&result),
                note,
                model_changes,
                eliminated_traces,
                discovered_predicates: stage_discovered_predicates,
                counterexample_analysis: stage_counterexample_analysis,
            });

            match result {
                UnboundedSafetyResult::Unsafe { .. } => {
                    final_result = result;
                    confirmed_unsafe = true;
                    break;
                }
                UnboundedSafetyResult::Safe { .. }
                | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
                    saw_eliminated = true;
                    for pred in &effective_preds {
                        if !discovered_predicates.contains(pred) {
                            discovered_predicates.push(pred.clone());
                        }
                    }
                    if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                        if !discovered_predicates.contains(&core_predicate) {
                            discovered_predicates.push(core_predicate);
                        }
                    }
                }
                UnboundedSafetyResult::NotProved { .. } | UnboundedSafetyResult::Unknown { .. } => {
                    saw_inconclusive = true;
                }
            }
        }
        eval_cache.emit_notes();
        discovered_predicates = sorted_unique_strings(discovered_predicates);

        if !confirmed_unsafe && saw_eliminated {
            final_result = UnboundedSafetyResult::Unknown {
            reason: "CEGAR refinements eliminated the baseline unsafe proof witness, but no refined unsafe witness was found. Treat as inconclusive and inspect the CEGAR report.".into(),
        };
        } else if !confirmed_unsafe && saw_timeout {
            final_result = UnboundedSafetyResult::Unknown {
                reason: timeout_unknown_reason("CEGAR unbounded safety"),
            };
        } else if !confirmed_unsafe && saw_inconclusive {
            final_result = UnboundedSafetyResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline unsafe witness is not confirmed under refined assumptions."
                .into(),
        };
        }

        let classification = if confirmed_unsafe {
            "unsafe_confirmed"
        } else if saw_eliminated {
            "inconclusive"
        } else if saw_timeout {
            "timeout"
        } else {
            "inconclusive"
        };
        let counterexample_analysis = if confirmed_unsafe {
            let confirmation = stages
                .iter()
                .find(|stage| {
                    stage.stage > 0
                        && matches!(
                            stage.outcome,
                            UnboundedSafetyCegarStageOutcome::Unsafe { .. }
                        )
                })
                .map(|stage| stage.stage)
                .unwrap_or(0);
            Some(CegarCounterexampleAnalysis {
                classification: "concrete".into(),
                rationale: format!(
                    "Baseline UNSAFE witness is confirmed concrete by refined replay at stage {}.",
                    confirmation
                ),
            })
        } else if saw_eliminated {
            Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline UNSAFE witness was eliminated by refinement predicates [{}], so the overall result is inconclusive until a concrete refined UNSAFE witness is found.",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        })
        } else if saw_timeout {
            Some(CegarCounterexampleAnalysis {
                classification: "inconclusive".into(),
                rationale: timeout_unknown_reason("CEGAR unbounded safety"),
            })
        } else {
            Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: "Unable to confirm or eliminate the baseline UNSAFE witness within refinement budget.".into(),
        })
        };
        let termination_reason = if confirmed_unsafe {
            "confirmed_unsafe"
        } else if saw_eliminated {
            "counterexample_eliminated_no_confirmation"
        } else if saw_timeout {
            "timeout"
        } else if stages.iter().filter(|stage| stage.stage > 0).count() >= max_refinements {
            "max_refinements_reached"
        } else {
            "inconclusive"
        };
        let termination = cegar_build_termination_from_iterations(
            termination_reason,
            max_refinements,
            stages.iter().filter(|stage| stage.stage > 0).count(),
            options.timeout_secs,
            started_at,
            saw_timeout,
        );

        Ok(UnboundedSafetyCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: None,
            },
            stages,
            discovered_predicates,
            baseline_result,
            final_result,
            classification: classification.into(),
            counterexample_analysis,
            termination,
        })
    })
}

/// Prove unbounded safety on an over-approximating round/view-erased abstraction.
///
/// The abstraction merges locations that differ only in erased round variables and
/// merges message counters across erased round fields. SAFE outcomes are sound for
/// the concrete model; UNSAFE outcomes may be spurious due to over-approximation.
pub fn prove_safety_with_round_abstraction(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    erased_round_vars: &[String],
) -> Result<RoundAbstractionProofResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    if normalize_erased_var_names(erased_round_vars).is_empty() {
        return Err(PipelineError::Validation(
            "Round abstraction requires at least one erased variable name.".into(),
        ));
    }

    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(&program, "prove_round")?;
    ensure_n_parameter(&ta)?;

    let (abstract_ta, summary) = apply_round_erasure_abstraction(&ta, erased_round_vars);
    let result = prove_safety_for_ta(abstract_ta, &program, options)?;
    Ok(RoundAbstractionProofResult { summary, result })
}

/// Generate an independently checkable k-induction certificate for safety.
///
/// The certificate contains two SMT-LIB queries whose UNSAT results prove
/// unbounded safety under the model assumptions encoded from the protocol.
pub fn generate_kinduction_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_safety_kinduction")?;
    ensure_n_parameter(&ta)?;

    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Err(PipelineError::Validation(
            "Cannot certify safety: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let property = extract_property(&ta, &program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());
    let extra_assertions = committee_bound_assertions(&committee_bounds);

    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_k_induction_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_k_induction_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
    };

    let induction_k = match kind_result {
        KInductionResult::Proved { k } => k,
        KInductionResult::Unsafe { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify safety: protocol is unsafe (counterexample found).".into(),
            ));
        }
        KInductionResult::NotProved { max_k, .. } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify safety: k-induction did not close up to k = {max_k}."
            )));
        }
        KInductionResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify safety: k-induction returned unknown ({reason})."
            )));
        }
    };

    let base_case = encode_bmc(&cs, &property, induction_k);
    let step_case = encode_k_induction_step(&cs, &property, induction_k);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    Ok(SafetyProofCertificate {
        protocol_file: filename.to_string(),
        proof_engine: ProofEngine::KInduction,
        induction_k: Some(induction_k),
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: vec![
            SafetyProofObligation {
                name: "base_case".into(),
                expected: "unsat".into(),
                smt2: encoding_to_smt2_script(&base_case, &extra_assertions),
            },
            SafetyProofObligation {
                name: "inductive_step".into(),
                expected: "unsat".into(),
                smt2: encoding_to_smt2_script(&step_case, &extra_assertions),
            },
        ],
    })
}

/// Generate an independently checkable IC3/PDR invariant certificate for safety.
pub fn generate_pdr_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Verify)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_safety_pdr")?;
    ensure_n_parameter(&ta)?;

    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Err(PipelineError::Validation(
            "Cannot certify safety: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let property = extract_property(&ta, &program, options.soundness)?;
    let cs = abstract_to_cs(ta.clone());
    let extra_assertions = committee_bound_assertions(&committee_bounds);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    let (result, cert) = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_pdr_with_certificate_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_pdr_with_certificate_with_deadline(
                &mut solver,
                &cs,
                &property,
                options.max_depth,
                &extra_assertions,
                deadline_from_timeout_secs(options.timeout_secs),
            )
            .map_err(|e| PipelineError::Solver(e.to_string()))?
        }
    };

    let frame = match result {
        KInductionResult::Proved { k } => k,
        KInductionResult::Unsafe { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify safety: protocol is unsafe (counterexample found).".into(),
            ));
        }
        KInductionResult::NotProved { max_k, .. } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify safety: PDR did not converge up to k = {max_k}."
            )));
        }
        KInductionResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify safety: PDR returned unknown ({reason})."
            )));
        }
    };

    let cert = cert.ok_or_else(|| {
        PipelineError::Solver(
            "Cannot certify safety: PDR proved safety but did not return an invariant certificate."
                .into(),
        )
    })?;

    Ok(SafetyProofCertificate {
        protocol_file: filename.to_string(),
        proof_engine: ProofEngine::Pdr,
        induction_k: Some(frame),
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: pdr_certificate_to_obligations(&cert, &extra_assertions),
    })
}

/// Generate a safety certificate using the selected proof engine in options.
pub fn generate_safety_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<SafetyProofCertificate, PipelineError> {
    reset_run_diagnostics();
    match options.proof_engine {
        ProofEngine::KInduction => {
            generate_kinduction_safety_certificate(source, filename, options)
        }
        ProofEngine::Pdr => generate_pdr_safety_certificate(source, filename, options),
    }
}

/// Generate an independently checkable fair-liveness proof certificate.
pub fn generate_fair_liveness_certificate_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<FairLivenessProofCertificate, PipelineError> {
    reset_run_diagnostics();
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    info!("Lowering to threshold automaton...");
    let mut ta = lower_with_active_controls(&program, "certify_fair_liveness")?;
    ensure_n_parameter(&ta)?;

    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Err(PipelineError::Validation(
            "Cannot certify fair-liveness: committee analysis present, but no bound_param is specified."
                .into(),
        ));
    }

    let liveness_spec = extract_liveness_spec(&ta, &program)?;
    if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
    {
        return Err(PipelineError::Property(
            "Fair-liveness certificate requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                .into(),
        ));
    }
    let target = fair_liveness_target_from_spec(&ta, liveness_spec)?;

    let cs = abstract_to_cs(ta.clone());
    let overall_timeout = if options.timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(options.timeout_secs))
    };
    let extra_assertions = committee_bound_assertions(&committee_bounds);
    let committee_bound_names: Vec<(String, u64)> = committee_bounds
        .iter()
        .map(|(pid, b)| (ta.parameters[*pid].name.clone(), *b))
        .collect();

    let (result, cert) = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_fair_pdr_with_certificate(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_fair_pdr_with_certificate(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )?
        }
    };

    let frame = match result {
        UnboundedFairLivenessResult::LiveProved { frame } => frame,
        UnboundedFairLivenessResult::FairCycleFound { .. } => {
            return Err(PipelineError::Validation(
                "Cannot certify fair-liveness: protocol has a fair non-terminating counterexample."
                    .into(),
            ));
        }
        UnboundedFairLivenessResult::NotProved { max_k } => {
            return Err(PipelineError::Validation(format!(
                "Cannot certify fair-liveness: proof did not converge up to frame {max_k}."
            )));
        }
        UnboundedFairLivenessResult::Unknown { reason } => {
            return Err(PipelineError::Solver(format!(
                "Cannot certify fair-liveness: solver returned unknown ({reason})."
            )));
        }
    };

    let cert = cert.ok_or_else(|| {
        PipelineError::Solver(
            "Cannot certify fair-liveness: proof converged but invariant certificate was not produced."
                .into(),
        )
    })?;
    if cert.frame != frame {
        return Err(PipelineError::Solver(
            "Cannot certify fair-liveness: internal proof frame mismatch.".into(),
        ));
    }

    Ok(FairLivenessProofCertificate {
        protocol_file: filename.to_string(),
        fairness,
        proof_engine: ProofEngine::Pdr,
        frame,
        solver_used: options.solver,
        soundness: options.soundness,
        committee_bounds: committee_bound_names,
        obligations: fair_pdr_certificate_to_obligations(&cert, &extra_assertions),
    })
}

/// Generate an independently checkable fair-liveness certificate under weak fairness.
pub fn generate_fair_liveness_certificate(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<FairLivenessProofCertificate, PipelineError> {
    reset_run_diagnostics();
    generate_fair_liveness_certificate_with_mode(source, filename, options, FairnessMode::Weak)
}

/// Run a bounded liveness check: all processes satisfy the liveness target by `max_depth`.
pub fn check_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<LivenessResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("check_liveness", || {
        push_reduction_note("encoder.structural_hashing=on");
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Liveness)?;

        info!("Lowering to threshold automaton...");
        let mut ta = lower_with_active_controls(&program, "check_liveness")?;
        ensure_n_parameter(&ta)?;

        // Analyze committees (if any) and derive adversary bounds
        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();

        // Collect per-committee (param_id, b_max) bounds for SMT injection
        let committee_bounds: Vec<(usize, u64)> = ta
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(LivenessResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                    .into(),
            });
        }

        let cs = abstract_to_cs(ta.clone());
        let liveness_spec = extract_liveness_spec(&ta, &program)?;
        match liveness_spec {
            LivenessSpec::TerminationGoalLocs(goal_locs) => {
                if goal_locs.is_empty() {
                    return Err(PipelineError::Property(
                    "Liveness check requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                        .into(),
                ));
                }

                let property = SafetyProperty::Termination { goal_locs };
                if let Some(ref path) = options.dump_smt {
                    let extra = committee_bound_assertions(&committee_bounds);
                    dump_smt_to_file(&cs, &property, options.max_depth, path, &extra);
                }
                let bmc_result = match options.solver {
                    SolverChoice::Z3 => {
                        let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                        run_bmc_with_committee_bounds_at_depth(
                            &mut solver,
                            &cs,
                            &property,
                            options.max_depth,
                            &committee_bounds,
                        )?
                    }
                    SolverChoice::Cvc5 => {
                        use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                        let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?;
                        run_bmc_with_committee_bounds_at_depth(
                            &mut solver,
                            &cs,
                            &property,
                            options.max_depth,
                            &committee_bounds,
                        )?
                    }
                };
                match bmc_result {
                    BmcResult::Safe { depth_checked } => Ok(LivenessResult::Live { depth_checked }),
                    BmcResult::Unsafe { depth, model } => {
                        let trace = extract_trace(&cs, &model, depth);
                        Ok(LivenessResult::NotLive { trace })
                    }
                    BmcResult::Unknown { reason, .. } => Ok(LivenessResult::Unknown { reason }),
                }
            }
            LivenessSpec::Temporal {
                quantified_var,
                role,
                formula,
            } => {
                let dummy_property = SafetyProperty::Agreement {
                    conflicting_pairs: Vec::new(),
                };
                let mut encoding = encode_bmc(&cs, &dummy_property, options.max_depth);
                if !encoding.assertions.is_empty() {
                    encoding.assertions.pop();
                }
                let extra = committee_bound_assertions(&committee_bounds);
                encoding.assertions.extend(extra.iter().cloned());
                let satisfied = encode_temporal_formula_term(
                    &ta,
                    &quantified_var,
                    &role,
                    &formula,
                    0,
                    options.max_depth,
                )?;
                encoding.assertions.push(SmtTerm::not(satisfied));
                if let Some(ref path) = options.dump_smt {
                    let smt = query_to_smt2_script(&encoding.declarations, &encoding.assertions);
                    if let Err(e) = std::fs::write(path, smt) {
                        eprintln!("Warning: could not write SMT dump to {path}: {e}");
                    } else {
                        info!("SMT dump written to {path}");
                    }
                }
                let bmc_result = match options.solver {
                    SolverChoice::Z3 => {
                        let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                        run_single_depth_bmc_encoding(&mut solver, &encoding, options.max_depth)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                    }
                    SolverChoice::Cvc5 => {
                        use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                        let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?;
                        run_single_depth_bmc_encoding(&mut solver, &encoding, options.max_depth)
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                    }
                };
                match bmc_result {
                    BmcResult::Safe { depth_checked } => Ok(LivenessResult::Live { depth_checked }),
                    BmcResult::Unsafe { depth, model } => {
                        let trace = extract_trace(&cs, &model, depth);
                        Ok(LivenessResult::NotLive { trace })
                    }
                    BmcResult::Unknown { reason, .. } => Ok(LivenessResult::Unknown { reason }),
                }
            }
        }
    })
}

fn run_single_depth_bmc_encoding<S: SmtSolver>(
    solver: &mut S,
    encoding: &BmcEncoding,
    depth: usize,
) -> Result<BmcResult, S::Error> {
    solver.reset()?;
    for (name, sort) in &encoding.declarations {
        solver.declare_var(name, sort)?;
    }
    for assertion in &encoding.assertions {
        solver.assert(assertion)?;
    }
    let var_refs: Vec<(&str, &SmtSort)> = encoding
        .model_vars
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();
    let (result, model) = solver.check_sat_with_model(&var_refs)?;
    Ok(match result {
        SatResult::Sat => BmcResult::Unsafe {
            depth,
            model: model.expect("SAT should include model"),
        },
        SatResult::Unsat => BmcResult::Safe {
            depth_checked: depth,
        },
        SatResult::Unknown(reason) => BmcResult::Unknown { depth, reason },
    })
}

fn pdr_param_var(i: usize) -> String {
    format!("p_{i}")
}

fn pdr_kappa_var(step: usize, loc: usize) -> String {
    format!("kappa_{step}_{loc}")
}

fn pdr_gamma_var(step: usize, var: usize) -> String {
    format!("g_{step}_{var}")
}

fn pdr_time_var(step: usize) -> String {
    format!("time_{step}")
}

fn pdr_delta_var(step: usize, rule: usize) -> String {
    format!("delta_{step}_{rule}")
}

fn temporal_state_var(step: usize, state: usize) -> String {
    format!("ltl_q_{step}_{state}")
}

fn mon_snap_temporal_state(step: usize, state: usize) -> String {
    format!("m_snap_q_{step}_{state}")
}

fn mon_acc(step: usize, acceptance_set: usize) -> String {
    format!("m_acc_{step}_{acceptance_set}")
}

fn one_hot_assertion(vars: &[String]) -> SmtTerm {
    if vars.is_empty() {
        return SmtTerm::bool(false);
    }
    let mut sum = SmtTerm::int(0);
    for var in vars {
        sum = sum.add(SmtTerm::var(var.clone()));
    }
    sum.eq(SmtTerm::int(1))
}

fn encode_lc_term(lc: &LinearCombination) -> SmtTerm {
    let mut result = SmtTerm::int(lc.constant);
    for &(coeff, pid) in &lc.terms {
        let pv = SmtTerm::var(pdr_param_var(pid));
        let scaled = if coeff == 1 {
            pv
        } else {
            SmtTerm::int(coeff).mul(pv)
        };
        result = result.add(scaled);
    }
    result
}

fn encode_guard_atom_enabled_at_step(atom: &GuardAtom, step: usize) -> SmtTerm {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            let lhs = if *distinct {
                let mut terms: Vec<SmtTerm> = Vec::with_capacity(vars.len());
                for var in vars {
                    let gv = SmtTerm::var(pdr_gamma_var(step, *var));
                    terms.push(SmtTerm::Ite(
                        Box::new(gv.gt(SmtTerm::int(0))),
                        Box::new(SmtTerm::int(1)),
                        Box::new(SmtTerm::int(0)),
                    ));
                }
                if terms.is_empty() {
                    SmtTerm::int(0)
                } else {
                    let mut sum = SmtTerm::int(0);
                    for term in terms {
                        sum = sum.add(term);
                    }
                    sum
                }
            } else {
                let mut sum = SmtTerm::int(0);
                for var in vars {
                    sum = sum.add(SmtTerm::var(pdr_gamma_var(step, *var)));
                }
                sum
            };
            let rhs = encode_lc_term(bound);
            match op {
                CmpOp::Ge => lhs.ge(rhs),
                CmpOp::Gt => lhs.gt(rhs),
                CmpOp::Le => lhs.le(rhs),
                CmpOp::Lt => lhs.lt(rhs),
                CmpOp::Eq => lhs.eq(rhs),
                CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
            }
        }
    }
}

fn add_temporal_automaton_to_fair_lasso_encoding(
    encoding: &mut BmcEncoding,
    ta: &ThresholdAutomaton,
    automaton: &TemporalBuchiAutomaton,
    depth: usize,
    loop_start: usize,
) -> Result<(), PipelineError> {
    if automaton.states.is_empty() || automaton.initial_states.is_empty() {
        encoding.assertions.push(SmtTerm::bool(false));
        return Ok(());
    }

    let mut atom_terms_by_step = Vec::with_capacity(depth + 1);
    for step in 0..=depth {
        let mut terms = Vec::with_capacity(automaton.atoms.len());
        for atom in &automaton.atoms {
            terms.push(build_universal_state_predicate_term(
                ta,
                &automaton.quantified_var,
                &automaton.role,
                atom,
                step,
            )?);
        }
        atom_terms_by_step.push(terms);
    }

    for step in 0..=depth {
        let step_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(step, sid))
            .collect();
        for var in &step_vars {
            encoding.declarations.push((var.clone(), SmtSort::Int));
            encoding.assertions.extend(bit_domain(var.clone()));
        }
        encoding.assertions.push(one_hot_assertion(&step_vars));
    }

    let init_states: Vec<SmtTerm> = automaton
        .initial_states
        .iter()
        .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
        .collect();
    if init_states.is_empty() {
        encoding.assertions.push(SmtTerm::bool(false));
    } else {
        encoding.assertions.push(SmtTerm::or(init_states));
    }

    for (step, atom_terms_at_step) in atom_terms_by_step.iter().enumerate().take(depth) {
        for (sid, state) in automaton.states.iter().enumerate() {
            let current = bit_is_true(temporal_state_var(step, sid));
            let mut conjuncts = Vec::new();
            for lit in &state.label_lits {
                match lit {
                    TemporalAtomLit::Pos(atom_id) => {
                        conjuncts.push(atom_terms_at_step[*atom_id].clone());
                    }
                    TemporalAtomLit::Neg(atom_id) => {
                        conjuncts.push(SmtTerm::not(atom_terms_at_step[*atom_id].clone()));
                    }
                }
            }
            let succ_terms: Vec<SmtTerm> = state
                .transitions
                .iter()
                .map(|next_sid| bit_is_true(temporal_state_var(step + 1, *next_sid)))
                .collect();
            let succ = if succ_terms.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(succ_terms)
            };
            conjuncts.push(succ);
            let body = if conjuncts.len() == 1 {
                conjuncts[0].clone()
            } else {
                SmtTerm::and(conjuncts)
            };
            encoding.assertions.push(current.implies(body));
        }
    }

    for sid in 0..automaton.states.len() {
        encoding.assertions.push(
            SmtTerm::var(temporal_state_var(loop_start, sid))
                .eq(SmtTerm::var(temporal_state_var(depth, sid))),
        );
    }

    for acc_set in &automaton.acceptance_sets {
        if acc_set.is_empty() {
            encoding.assertions.push(SmtTerm::bool(false));
            continue;
        }
        let mut seen_terms = Vec::new();
        for step in loop_start..depth {
            for sid in acc_set {
                seen_terms.push(bit_is_true(temporal_state_var(step, *sid)));
            }
        }
        if seen_terms.is_empty() {
            encoding.assertions.push(SmtTerm::bool(false));
        } else {
            encoding.assertions.push(SmtTerm::or(seen_terms));
        }
    }

    Ok(())
}

fn build_fair_lasso_encoding(
    cs: &CounterSystem,
    depth: usize,
    loop_start: usize,
    target: &FairLivenessTarget,
    fairness: FairnessMode,
) -> Result<tarsier_smt::encoder::BmcEncoding, PipelineError> {
    let ta = &cs.automaton;
    let dummy_property = SafetyProperty::Agreement {
        conflicting_pairs: Vec::new(),
    };

    let mut step_encoding = encode_k_induction_step(cs, &dummy_property, depth);
    if !step_encoding.assertions.is_empty() {
        // Drop the final `false` assertion injected by the dummy property.
        step_encoding.assertions.pop();
    }

    // Add true initial-state constraints from depth-0 BMC.
    let init_encoding = encode_bmc(cs, &dummy_property, 0);
    if !init_encoding.assertions.is_empty() {
        let init_assertions = &init_encoding.assertions[..init_encoding.assertions.len() - 1];
        step_encoding
            .assertions
            .extend(init_assertions.iter().cloned());
    }

    // Lasso closure: state(loop_start) == state(depth)
    for loc in 0..cs.num_locations() {
        step_encoding.assertions.push(
            SmtTerm::var(pdr_kappa_var(loop_start, loc))
                .eq(SmtTerm::var(pdr_kappa_var(depth, loc))),
        );
    }
    for var in 0..cs.num_shared_vars() {
        step_encoding.assertions.push(
            SmtTerm::var(pdr_gamma_var(loop_start, var))
                .eq(SmtTerm::var(pdr_gamma_var(depth, var))),
        );
    }

    match target {
        FairLivenessTarget::NonGoalLocs(non_goal_locs) => {
            let undecided = non_goal_locs
                .iter()
                .map(|l| SmtTerm::var(pdr_kappa_var(depth, *l)).gt(SmtTerm::int(0)))
                .collect::<Vec<_>>();
            if undecided.is_empty() {
                step_encoding.assertions.push(SmtTerm::bool(false));
            } else {
                step_encoding.assertions.push(SmtTerm::or(undecided));
            }
        }
        FairLivenessTarget::Temporal(automaton) => {
            add_temporal_automaton_to_fair_lasso_encoding(
                &mut step_encoding,
                ta,
                automaton,
                depth,
                loop_start,
            )?;
        }
    }

    if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony {
        if let Some(gst_pid) = ta.gst_param {
            // Fair lasso must be fully post-GST to represent steady-state behavior.
            step_encoding.assertions.push(
                SmtTerm::var(pdr_param_var(gst_pid)).le(SmtTerm::var(pdr_time_var(loop_start))),
            );
        }
    }

    // Fairness on the loop:
    // - weak:   enabled on every loop state  => fires on loop
    // - strong: enabled on some loop state   => fires on loop
    for (rule_id, rule) in ta.rules.iter().enumerate() {
        let enabled_terms = (loop_start..depth)
            .map(|step| {
                let mut atoms = rule
                    .guard
                    .atoms
                    .iter()
                    .map(|a| encode_guard_atom_enabled_at_step(a, step))
                    .collect::<Vec<_>>();
                if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
                {
                    if let Some(gst_pid) = ta.gst_param {
                        atoms.push(
                            SmtTerm::var(pdr_param_var(gst_pid))
                                .le(SmtTerm::var(pdr_time_var(step))),
                        );
                    }
                }
                if atoms.is_empty() {
                    SmtTerm::bool(true)
                } else {
                    SmtTerm::and(atoms)
                }
            })
            .collect::<Vec<_>>();

        let fired_some_step = (loop_start..depth)
            .map(|step| SmtTerm::var(pdr_delta_var(step, rule_id)).gt(SmtTerm::int(0)))
            .collect::<Vec<_>>();

        let antecedent = if enabled_terms.is_empty() {
            SmtTerm::bool(false)
        } else {
            match fairness {
                FairnessMode::Weak => SmtTerm::and(enabled_terms),
                FairnessMode::Strong => SmtTerm::or(enabled_terms),
            }
        };
        let consequent = if fired_some_step.is_empty() {
            SmtTerm::bool(false)
        } else {
            SmtTerm::or(fired_some_step)
        };
        step_encoding
            .assertions
            .push(antecedent.implies(consequent));
    }

    Ok(step_encoding)
}

fn run_fair_lasso_search<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_depth: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    deadline: Option<Instant>,
) -> Result<FairLivenessResult, PipelineError> {
    let extra_assertions = committee_bound_assertions(committee_bounds);

    for depth in 1..=max_depth {
        if deadline_exceeded(deadline) {
            return Ok(FairLivenessResult::Unknown {
                reason: timeout_unknown_reason("Fair-liveness lasso search"),
            });
        }
        for loop_start in 0..depth {
            if deadline_exceeded(deadline) {
                return Ok(FairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("Fair-liveness lasso search"),
                });
            }
            let encoding = build_fair_lasso_encoding(cs, depth, loop_start, target, fairness)?;

            solver
                .reset()
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            for (name, sort) in &encoding.declarations {
                solver
                    .declare_var(name, sort)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }
            for assertion in &encoding.assertions {
                solver
                    .assert(assertion)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }
            for extra in &extra_assertions {
                solver
                    .assert(extra)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }

            let var_refs: Vec<(&str, &SmtSort)> = encoding
                .model_vars
                .iter()
                .map(|(n, s)| (n.as_str(), s))
                .collect();
            let (sat, model) = solver
                .check_sat_with_model(&var_refs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            match sat {
                SatResult::Sat => {
                    if let Some(model) = model {
                        let trace = extract_trace(cs, &model, depth);
                        return Ok(FairLivenessResult::FairCycleFound {
                            depth,
                            loop_start,
                            trace,
                        });
                    }
                    return Ok(FairLivenessResult::Unknown {
                        reason: "SAT result without model during fair-liveness search.".into(),
                    });
                }
                SatResult::Unsat => {}
                SatResult::Unknown(reason) => return Ok(FairLivenessResult::Unknown { reason }),
            }
        }
    }

    Ok(FairLivenessResult::NoFairCycleUpTo {
        depth_checked: max_depth,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FairPdrCubeLit {
    state_var_idx: usize,
    value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FairPdrCube {
    lits: Vec<FairPdrCubeLit>,
}

impl FairPdrCube {
    fn from_model(
        model: &tarsier_smt::solver::Model,
        state_vars: &[(String, SmtSort)],
    ) -> Option<Self> {
        let mut lits = Vec::with_capacity(state_vars.len());
        for (idx, (name, sort)) in state_vars.iter().enumerate() {
            if *sort != SmtSort::Int {
                return None;
            }
            let value = model.get_int(name)?;
            lits.push(FairPdrCubeLit {
                state_var_idx: idx,
                value,
            });
        }
        Some(Self { lits })
    }

    fn to_conjunction(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        if self.lits.is_empty() {
            return SmtTerm::bool(true);
        }
        let mut parts = Vec::with_capacity(self.lits.len());
        for lit in &self.lits {
            let (name, sort) = &state_vars[lit.state_var_idx];
            if *sort != SmtSort::Int {
                return SmtTerm::bool(false);
            }
            parts.push(SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)));
        }
        SmtTerm::and(parts)
    }

    fn to_block_clause(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        self.to_conjunction(state_vars).not()
    }

    /// Returns true iff `self` is at least as general as `other`.
    ///
    /// For blocking clauses, this means `self` blocks a superset of states:
    /// every literal in `self` appears in `other`.
    fn subsumes(&self, other: &FairPdrCube) -> bool {
        if self.lits.len() > other.lits.len() {
            return false;
        }
        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.lits.len() && j < other.lits.len() {
            let a = &self.lits[i];
            let b = &other.lits[j];
            if a == b {
                i += 1;
                j += 1;
                continue;
            }
            if a.state_var_idx > b.state_var_idx {
                j += 1;
                continue;
            }
            return false;
        }
        i == self.lits.len()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FairPdrFrame {
    cubes: HashSet<FairPdrCube>,
}

impl FairPdrFrame {
    fn insert(&mut self, cube: FairPdrCube) {
        if self.cubes.iter().any(|existing| existing.subsumes(&cube)) {
            return;
        }
        let to_remove: Vec<FairPdrCube> = self
            .cubes
            .iter()
            .filter(|existing| cube.subsumes(existing))
            .cloned()
            .collect();
        for existing in to_remove {
            self.cubes.remove(&existing);
        }
        self.cubes.insert(cube);
    }

    fn contains(&self, cube: &FairPdrCube) -> bool {
        self.cubes.contains(cube)
    }
}

#[derive(Debug, Clone)]
struct FairPdrArtifacts {
    declarations: Vec<(String, SmtSort)>,
    state_vars_pre: Vec<(String, SmtSort)>,
    state_vars_post: Vec<(String, SmtSort)>,
    state_assertions_pre: Vec<SmtTerm>,
    init_assertions: Vec<SmtTerm>,
    transition_assertions: Vec<SmtTerm>,
    bad_pre: SmtTerm,
}

#[derive(Debug, Clone)]
struct FairPdrInvariantCertificate {
    frame: usize,
    declarations: Vec<(String, SmtSort)>,
    init_assertions: Vec<SmtTerm>,
    transition_assertions: Vec<SmtTerm>,
    bad_pre: SmtTerm,
    invariant_pre: Vec<SmtTerm>,
    invariant_post: Vec<SmtTerm>,
}

fn mon_armed(step: usize) -> String {
    format!("m_armed_{step}")
}

fn mon_choose(step: usize) -> String {
    format!("m_choose_{step}")
}

fn mon_snap_kappa(step: usize, loc: usize) -> String {
    format!("m_snap_kappa_{step}_{loc}")
}

fn mon_snap_gamma(step: usize, var: usize) -> String {
    format!("m_snap_g_{step}_{var}")
}

fn mon_ce(step: usize, rule: usize) -> String {
    format!("m_ce_{step}_{rule}")
}

fn mon_fired(step: usize, rule: usize) -> String {
    format!("m_fired_{step}_{rule}")
}

fn bit_is_true(name: String) -> SmtTerm {
    SmtTerm::var(name).eq(SmtTerm::int(1))
}

fn bit_is_false(name: String) -> SmtTerm {
    SmtTerm::var(name).eq(SmtTerm::int(0))
}

fn bit_domain(name: String) -> Vec<SmtTerm> {
    vec![
        SmtTerm::var(name.clone()).ge(SmtTerm::int(0)),
        SmtTerm::var(name).le(SmtTerm::int(1)),
    ]
}

fn bool_to_bit(cond: SmtTerm) -> SmtTerm {
    SmtTerm::Ite(
        Box::new(cond),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::int(0)),
    )
}

fn push_decl_unique(decls: &mut Vec<(String, SmtSort)>, name: String, sort: SmtSort) {
    if !decls.iter().any(|(n, _)| *n == name) {
        decls.push((name, sort));
    }
}

fn build_unbounded_fair_pdr_artifacts(
    cs: &CounterSystem,
    target: &FairLivenessTarget,
    fairness: FairnessMode,
) -> Result<FairPdrArtifacts, PipelineError> {
    let ta = &cs.automaton;
    let dummy_property = SafetyProperty::Agreement {
        conflicting_pairs: Vec::new(),
    };

    // Step-0 constraints (state constraints + dummy bad)
    let step0 = encode_k_induction_step(cs, &dummy_property, 0);
    if step0.assertions.is_empty() {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (empty k=0 encoding).".into(),
        ));
    }
    let state_assertions_pre = step0.assertions[..step0.assertions.len() - 1].to_vec();

    // Step-1 constraints (transition + !bad(s0) + bad(s1))
    let step1 = encode_k_induction_step(cs, &dummy_property, 1);
    if step1.assertions.len() < 2 {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (incomplete k=1 encoding).".into(),
        ));
    }
    let mut transition_assertions = step1.assertions[..step1.assertions.len() - 2].to_vec();

    // Init constraints from BMC depth 0 (init + dummy bad)
    let init = encode_bmc(cs, &dummy_property, 0);
    if init.assertions.is_empty() {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (empty init encoding).".into(),
        ));
    }
    let mut init_assertions = init.assertions[..init.assertions.len() - 1].to_vec();

    let mut declarations = step1.declarations.clone();
    let mut state_vars_pre = Vec::new();
    let mut state_vars_post = Vec::new();
    let mut state_assertions_pre_extra = Vec::new();

    for loc in 0..cs.num_locations() {
        state_vars_pre.push((pdr_kappa_var(0, loc), SmtSort::Int));
        state_vars_post.push((pdr_kappa_var(1, loc), SmtSort::Int));
    }
    for var in 0..cs.num_shared_vars() {
        state_vars_pre.push((pdr_gamma_var(0, var), SmtSort::Int));
        state_vars_post.push((pdr_gamma_var(1, var), SmtSort::Int));
    }
    state_vars_pre.push((pdr_time_var(0), SmtSort::Int));
    state_vars_post.push((pdr_time_var(1), SmtSort::Int));

    let temporal_automaton = match target {
        FairLivenessTarget::Temporal(automaton) => Some(automaton),
        FairLivenessTarget::NonGoalLocs(_) => None,
    };
    let temporal_atom_terms_step0 = if let Some(automaton) = temporal_automaton {
        let mut terms = Vec::with_capacity(automaton.atoms.len());
        for atom in &automaton.atoms {
            terms.push(build_universal_state_predicate_term(
                ta,
                &automaton.quantified_var,
                &automaton.role,
                atom,
                0,
            )?);
        }
        Some(terms)
    } else {
        None
    };

    // Monitor state declarations for step 0 and 1.
    for step in 0..=1 {
        push_decl_unique(&mut declarations, mon_armed(step), SmtSort::Int);
        for loc in 0..cs.num_locations() {
            push_decl_unique(&mut declarations, mon_snap_kappa(step, loc), SmtSort::Int);
        }
        for var in 0..cs.num_shared_vars() {
            push_decl_unique(&mut declarations, mon_snap_gamma(step, var), SmtSort::Int);
        }
        for rule in 0..cs.num_rules() {
            push_decl_unique(&mut declarations, mon_ce(step, rule), SmtSort::Int);
            push_decl_unique(&mut declarations, mon_fired(step, rule), SmtSort::Int);
        }
    }
    if let Some(automaton) = temporal_automaton {
        for step in 0..=1 {
            for sid in 0..automaton.states.len() {
                push_decl_unique(
                    &mut declarations,
                    temporal_state_var(step, sid),
                    SmtSort::Int,
                );
                push_decl_unique(
                    &mut declarations,
                    mon_snap_temporal_state(step, sid),
                    SmtSort::Int,
                );
            }
            for acc_id in 0..automaton.acceptance_sets.len() {
                push_decl_unique(&mut declarations, mon_acc(step, acc_id), SmtSort::Int);
            }
        }
    }
    push_decl_unique(&mut declarations, mon_choose(0), SmtSort::Int);

    state_vars_pre.push((mon_armed(0), SmtSort::Int));
    state_vars_post.push((mon_armed(1), SmtSort::Int));
    for loc in 0..cs.num_locations() {
        state_vars_pre.push((mon_snap_kappa(0, loc), SmtSort::Int));
        state_vars_post.push((mon_snap_kappa(1, loc), SmtSort::Int));
    }
    for var in 0..cs.num_shared_vars() {
        state_vars_pre.push((mon_snap_gamma(0, var), SmtSort::Int));
        state_vars_post.push((mon_snap_gamma(1, var), SmtSort::Int));
    }
    for rule in 0..cs.num_rules() {
        state_vars_pre.push((mon_ce(0, rule), SmtSort::Int));
        state_vars_post.push((mon_ce(1, rule), SmtSort::Int));
        state_vars_pre.push((mon_fired(0, rule), SmtSort::Int));
        state_vars_post.push((mon_fired(1, rule), SmtSort::Int));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            state_vars_pre.push((temporal_state_var(0, sid), SmtSort::Int));
            state_vars_post.push((temporal_state_var(1, sid), SmtSort::Int));
            state_vars_pre.push((mon_snap_temporal_state(0, sid), SmtSort::Int));
            state_vars_post.push((mon_snap_temporal_state(1, sid), SmtSort::Int));
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            state_vars_pre.push((mon_acc(0, acc_id), SmtSort::Int));
            state_vars_post.push((mon_acc(1, acc_id), SmtSort::Int));
        }
    }

    // Domains on monitor bits.
    state_assertions_pre_extra.extend(bit_domain(mon_armed(0)));
    for rule in 0..cs.num_rules() {
        state_assertions_pre_extra.extend(bit_domain(mon_ce(0, rule)));
        state_assertions_pre_extra.extend(bit_domain(mon_fired(0, rule)));
    }
    transition_assertions.extend(bit_domain(mon_choose(0)));
    if let Some(automaton) = temporal_automaton {
        let atom_terms = temporal_atom_terms_step0
            .as_ref()
            .expect("temporal atom terms must exist when temporal automaton is active");

        let step0_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(0, sid))
            .collect();
        for var in &step0_vars {
            state_assertions_pre_extra.extend(bit_domain(var.clone()));
        }
        state_assertions_pre_extra.push(one_hot_assertion(&step0_vars));

        let step1_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(1, sid))
            .collect();
        for var in &step1_vars {
            transition_assertions.extend(bit_domain(var.clone()));
        }
        transition_assertions.push(one_hot_assertion(&step1_vars));

        for sid in 0..automaton.states.len() {
            state_assertions_pre_extra.extend(bit_domain(mon_snap_temporal_state(0, sid)));
            transition_assertions.extend(bit_domain(mon_snap_temporal_state(1, sid)));
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            state_assertions_pre_extra.extend(bit_domain(mon_acc(0, acc_id)));
            transition_assertions.extend(bit_domain(mon_acc(1, acc_id)));
        }

        for (sid, state) in automaton.states.iter().enumerate() {
            let current = bit_is_true(temporal_state_var(0, sid));
            let mut label_terms = Vec::new();
            for lit in &state.label_lits {
                match lit {
                    TemporalAtomLit::Pos(atom_id) => label_terms.push(atom_terms[*atom_id].clone()),
                    TemporalAtomLit::Neg(atom_id) => {
                        label_terms.push(SmtTerm::not(atom_terms[*atom_id].clone()))
                    }
                }
            }
            let label = if label_terms.is_empty() {
                SmtTerm::bool(true)
            } else {
                SmtTerm::and(label_terms)
            };
            state_assertions_pre_extra.push(current.clone().implies(label.clone()));

            let succ_terms: Vec<SmtTerm> = state
                .transitions
                .iter()
                .map(|next_sid| bit_is_true(temporal_state_var(1, *next_sid)))
                .collect();
            let succ = if succ_terms.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(succ_terms)
            };
            transition_assertions.push(current.implies(SmtTerm::and(vec![label, succ])));
        }
    }

    // Init monitor values.
    init_assertions.push(bit_is_false(mon_armed(0)));
    for loc in 0..cs.num_locations() {
        init_assertions
            .push(SmtTerm::var(mon_snap_kappa(0, loc)).eq(SmtTerm::var(pdr_kappa_var(0, loc))));
    }
    for var in 0..cs.num_shared_vars() {
        init_assertions
            .push(SmtTerm::var(mon_snap_gamma(0, var)).eq(SmtTerm::var(pdr_gamma_var(0, var))));
    }
    for rule in 0..cs.num_rules() {
        init_assertions.push(bit_is_false(mon_ce(0, rule)));
        init_assertions.push(bit_is_false(mon_fired(0, rule)));
    }
    if let Some(automaton) = temporal_automaton {
        let init_states: Vec<SmtTerm> = automaton
            .initial_states
            .iter()
            .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
            .collect();
        if init_states.is_empty() {
            init_assertions.push(SmtTerm::bool(false));
        } else {
            init_assertions.push(SmtTerm::or(init_states));
        }
        for sid in 0..automaton.states.len() {
            init_assertions.push(
                SmtTerm::var(mon_snap_temporal_state(0, sid))
                    .eq(SmtTerm::var(temporal_state_var(0, sid))),
            );
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            init_assertions.push(bit_is_false(mon_acc(0, acc_id)));
        }
    }

    // Monitor transition updates.
    let armed0_true = bit_is_true(mon_armed(0));
    let choose0_true = bit_is_true(mon_choose(0));
    let post_gst_now = if ta.timing_model
        == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
    {
        ta.gst_param
            .map(|gst_pid| SmtTerm::var(pdr_param_var(gst_pid)).le(SmtTerm::var(pdr_time_var(0))))
    } else {
        None
    };
    if let Some(post_gst_now) = post_gst_now.clone() {
        // Arm point for fair-cycle monitor must be in the post-GST region.
        transition_assertions.push(choose0_true.clone().implies(post_gst_now));
    }
    let choose0_effective = if let Some(post_gst_now) = post_gst_now.clone() {
        SmtTerm::and(vec![choose0_true.clone(), post_gst_now])
    } else {
        choose0_true.clone()
    };
    let arm_now = SmtTerm::and(vec![choose0_effective.clone(), armed0_true.clone().not()]);
    let armed1_next = bool_to_bit(SmtTerm::or(vec![
        armed0_true.clone(),
        choose0_effective.clone(),
    ]));
    transition_assertions.push(SmtTerm::var(mon_armed(1)).eq(armed1_next));
    transition_assertions.extend(bit_domain(mon_armed(1)));

    for loc in 0..cs.num_locations() {
        let snap_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(SmtTerm::var(pdr_kappa_var(0, loc))),
            Box::new(SmtTerm::var(mon_snap_kappa(0, loc))),
        );
        transition_assertions.push(SmtTerm::var(mon_snap_kappa(1, loc)).eq(snap_next));
    }
    for var in 0..cs.num_shared_vars() {
        let snap_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(SmtTerm::var(pdr_gamma_var(0, var))),
            Box::new(SmtTerm::var(mon_snap_gamma(0, var))),
        );
        transition_assertions.push(SmtTerm::var(mon_snap_gamma(1, var)).eq(snap_next));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            let snap_next = SmtTerm::Ite(
                Box::new(arm_now.clone()),
                Box::new(SmtTerm::var(temporal_state_var(0, sid))),
                Box::new(SmtTerm::var(mon_snap_temporal_state(0, sid))),
            );
            transition_assertions.push(SmtTerm::var(mon_snap_temporal_state(1, sid)).eq(snap_next));
        }
    }

    for (rule_id, rule) in ta.rules.iter().enumerate() {
        let mut enabled_now = if rule.guard.atoms.is_empty() {
            SmtTerm::bool(true)
        } else {
            SmtTerm::and(
                rule.guard
                    .atoms
                    .iter()
                    .map(|a| encode_guard_atom_enabled_at_step(a, 0))
                    .collect(),
            )
        };
        if let Some(post_gst_now) = post_gst_now.clone() {
            enabled_now = SmtTerm::and(vec![enabled_now, post_gst_now]);
        }
        let fired_now = SmtTerm::var(pdr_delta_var(0, rule_id)).gt(SmtTerm::int(0));
        let ce0_true = bit_is_true(mon_ce(0, rule_id));
        let fired0_true = bit_is_true(mon_fired(0, rule_id));

        let ce_arm = bool_to_bit(enabled_now.clone());
        let ce_cont = match fairness {
            // Track continuously-enabled on the monitored segment.
            FairnessMode::Weak => bool_to_bit(SmtTerm::and(vec![ce0_true.clone(), enabled_now])),
            // Track seen-enabled (enabled at least once on the monitored segment).
            FairnessMode::Strong => bool_to_bit(SmtTerm::or(vec![ce0_true.clone(), enabled_now])),
        };
        let ce_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(ce_arm),
            Box::new(SmtTerm::Ite(
                Box::new(armed0_true.clone()),
                Box::new(ce_cont),
                Box::new(SmtTerm::int(0)),
            )),
        );
        transition_assertions.push(SmtTerm::var(mon_ce(1, rule_id)).eq(ce_next));

        let fired_arm = bool_to_bit(fired_now.clone());
        let fired_cont = bool_to_bit(SmtTerm::or(vec![fired0_true, fired_now]));
        let fired_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(fired_arm),
            Box::new(SmtTerm::Ite(
                Box::new(armed0_true.clone()),
                Box::new(fired_cont),
                Box::new(SmtTerm::int(0)),
            )),
        );
        transition_assertions.push(SmtTerm::var(mon_fired(1, rule_id)).eq(fired_next));
        transition_assertions.extend(bit_domain(mon_ce(1, rule_id)));
        transition_assertions.extend(bit_domain(mon_fired(1, rule_id)));
    }
    if let Some(automaton) = temporal_automaton {
        for acc_id in 0..automaton.acceptance_sets.len() {
            let visited_now = if automaton.acceptance_sets[acc_id].is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(
                    automaton.acceptance_sets[acc_id]
                        .iter()
                        .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
                        .collect(),
                )
            };
            let acc0_true = bit_is_true(mon_acc(0, acc_id));
            let acc_arm = bool_to_bit(visited_now.clone());
            let acc_cont = bool_to_bit(SmtTerm::or(vec![acc0_true, visited_now]));
            let acc_next = SmtTerm::Ite(
                Box::new(arm_now.clone()),
                Box::new(acc_arm),
                Box::new(SmtTerm::Ite(
                    Box::new(armed0_true.clone()),
                    Box::new(acc_cont),
                    Box::new(SmtTerm::int(0)),
                )),
            );
            transition_assertions.push(SmtTerm::var(mon_acc(1, acc_id)).eq(acc_next));
        }
    }

    // Bad state: armed, loop closed, target obligations met, fairness obligations met.
    let mut closure_terms = vec![bit_is_true(mon_armed(0))];
    for loc in 0..cs.num_locations() {
        closure_terms
            .push(SmtTerm::var(pdr_kappa_var(0, loc)).eq(SmtTerm::var(mon_snap_kappa(0, loc))));
    }
    for var in 0..cs.num_shared_vars() {
        closure_terms
            .push(SmtTerm::var(pdr_gamma_var(0, var)).eq(SmtTerm::var(mon_snap_gamma(0, var))));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            closure_terms.push(
                SmtTerm::var(temporal_state_var(0, sid))
                    .eq(SmtTerm::var(mon_snap_temporal_state(0, sid))),
            );
        }
    }
    match target {
        FairLivenessTarget::NonGoalLocs(non_goal_locs) => {
            if non_goal_locs.is_empty() {
                closure_terms.push(SmtTerm::bool(false));
            } else {
                closure_terms.push(SmtTerm::or(
                    non_goal_locs
                        .iter()
                        .map(|l| SmtTerm::var(pdr_kappa_var(0, *l)).gt(SmtTerm::int(0)))
                        .collect(),
                ));
            }
        }
        FairLivenessTarget::Temporal(automaton) => {
            for acc_id in 0..automaton.acceptance_sets.len() {
                closure_terms.push(bit_is_true(mon_acc(0, acc_id)));
            }
        }
    }
    for rule in 0..cs.num_rules() {
        closure_terms.push(SmtTerm::or(vec![
            bit_is_true(mon_ce(0, rule)).not(),
            bit_is_true(mon_fired(0, rule)),
        ]));
    }
    let bad_pre = SmtTerm::and(closure_terms);

    let mut full_state_assertions_pre = state_assertions_pre;
    full_state_assertions_pre.extend(state_assertions_pre_extra);

    Ok(FairPdrArtifacts {
        declarations,
        state_vars_pre,
        state_vars_post,
        state_assertions_pre: full_state_assertions_pre,
        init_assertions,
        transition_assertions,
        bad_pre,
    })
}

fn rename_state_vars_in_term(
    term: &SmtTerm,
    map: &std::collections::HashMap<String, String>,
) -> SmtTerm {
    match term {
        SmtTerm::Var(name) => {
            if let Some(mapped) = map.get(name) {
                SmtTerm::Var(mapped.clone())
            } else {
                SmtTerm::Var(name.clone())
            }
        }
        SmtTerm::IntLit(n) => SmtTerm::IntLit(*n),
        SmtTerm::BoolLit(b) => SmtTerm::BoolLit(*b),
        SmtTerm::Add(lhs, rhs) => SmtTerm::Add(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Sub(lhs, rhs) => SmtTerm::Sub(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Mul(lhs, rhs) => SmtTerm::Mul(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Eq(lhs, rhs) => SmtTerm::Eq(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Lt(lhs, rhs) => SmtTerm::Lt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Le(lhs, rhs) => SmtTerm::Le(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Gt(lhs, rhs) => SmtTerm::Gt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Ge(lhs, rhs) => SmtTerm::Ge(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::And(terms) => SmtTerm::And(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Or(terms) => SmtTerm::Or(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Not(inner) => SmtTerm::Not(Box::new(rename_state_vars_in_term(inner, map))),
        SmtTerm::Implies(lhs, rhs) => SmtTerm::Implies(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::ForAll(vars, body) => {
            SmtTerm::ForAll(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Exists(vars, body) => {
            SmtTerm::Exists(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Ite(cond, then_term, else_term) => SmtTerm::Ite(
            Box::new(rename_state_vars_in_term(cond, map)),
            Box::new(rename_state_vars_in_term(then_term, map)),
            Box::new(rename_state_vars_in_term(else_term, map)),
        ),
    }
}

fn build_fair_pdr_invariant_certificate(
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    frame_id: usize,
) -> FairPdrInvariantCertificate {
    let mut invariant_pre = artifacts.state_assertions_pre.clone();
    let mut cubes: Vec<FairPdrCube> = frame.cubes.iter().cloned().collect();
    cubes.sort();
    for cube in &cubes {
        invariant_pre.push(cube.to_block_clause(&artifacts.state_vars_pre));
    }

    let rename_map: std::collections::HashMap<String, String> = artifacts
        .state_vars_pre
        .iter()
        .zip(artifacts.state_vars_post.iter())
        .map(|((pre, _), (post, _))| (pre.clone(), post.clone()))
        .collect();
    let invariant_post: Vec<SmtTerm> = invariant_pre
        .iter()
        .map(|t| rename_state_vars_in_term(t, &rename_map))
        .collect();

    FairPdrInvariantCertificate {
        frame: frame_id,
        declarations: artifacts.declarations.clone(),
        init_assertions: artifacts.init_assertions.clone(),
        transition_assertions: artifacts.transition_assertions.clone(),
        bad_pre: artifacts.bad_pre.clone(),
        invariant_pre,
        invariant_post,
    }
}

fn fair_declare_all<S: SmtSolver>(
    solver: &mut S,
    declarations: &[(String, SmtSort)],
) -> Result<(), PipelineError> {
    for (name, sort) in declarations {
        solver
            .declare_var(name, sort)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

fn fair_assert_all<S: SmtSolver>(solver: &mut S, terms: &[SmtTerm]) -> Result<(), PipelineError> {
    for t in terms {
        solver
            .assert(t)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

fn fair_assert_frame<S: SmtSolver>(
    solver: &mut S,
    frame: &FairPdrFrame,
    state_vars: &[(String, SmtSort)],
) -> Result<(), PipelineError> {
    for cube in &frame.cubes {
        solver
            .assert(&cube.to_block_clause(state_vars))
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

enum FairCubeQueryResult {
    Sat(FairPdrCube),
    Unsat,
    Unknown(String),
}

enum FairSatQueryResult {
    Sat,
    Unsat,
    Unknown(String),
}

fn fair_query_bad_in_frame<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    extra_assertions: &[SmtTerm],
) -> Result<FairCubeQueryResult, PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, extra_assertions)?;
    fair_assert_frame(solver, frame, &artifacts.state_vars_pre)?;
    solver
        .assert(&artifacts.bad_pre)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    let var_refs: Vec<(&str, &SmtSort)> = artifacts
        .state_vars_pre
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();
    let (sat, model) = solver
        .check_sat_with_model(&var_refs)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    match sat {
        SatResult::Unsat => Ok(FairCubeQueryResult::Unsat),
        SatResult::Unknown(reason) => Ok(FairCubeQueryResult::Unknown(reason)),
        SatResult::Sat => {
            let Some(model) = model else {
                return Ok(FairCubeQueryResult::Unknown(
                    "Fair PDR: SAT without model".into(),
                ));
            };
            let Some(cube) = FairPdrCube::from_model(&model, &artifacts.state_vars_pre) else {
                return Ok(FairCubeQueryResult::Unknown(
                    "Fair PDR: failed to extract bad-state cube".into(),
                ));
            };
            Ok(FairCubeQueryResult::Sat(cube))
        }
    }
}

fn fair_predecessor_query<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    with_model: bool,
) -> Result<(FairSatQueryResult, Option<FairPdrCube>), PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;

    if level == 1 {
        fair_assert_all(solver, &artifacts.init_assertions)?;
    } else {
        fair_assert_frame(solver, &frames[level - 1], &artifacts.state_vars_pre)?;
    }

    solver
        .assert(&cube.to_conjunction(&artifacts.state_vars_post))
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    if with_model {
        let var_refs: Vec<(&str, &SmtSort)> = artifacts
            .state_vars_pre
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let (sat, model) = solver
            .check_sat_with_model(&var_refs)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        return match sat {
            SatResult::Unsat => Ok((FairSatQueryResult::Unsat, None)),
            SatResult::Unknown(reason) => Ok((FairSatQueryResult::Unknown(reason), None)),
            SatResult::Sat => {
                let Some(model) = model else {
                    return Ok((
                        FairSatQueryResult::Unknown(
                            "Fair PDR: SAT predecessor without model".into(),
                        ),
                        None,
                    ));
                };
                let Some(pred) = FairPdrCube::from_model(&model, &artifacts.state_vars_pre) else {
                    return Ok((
                        FairSatQueryResult::Unknown(
                            "Fair PDR: failed to extract predecessor cube".into(),
                        ),
                        None,
                    ));
                };
                Ok((FairSatQueryResult::Sat, Some(pred)))
            }
        };
    }

    match solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Sat => Ok((FairSatQueryResult::Sat, None)),
        SatResult::Unsat => Ok((FairSatQueryResult::Unsat, None)),
        SatResult::Unknown(reason) => Ok((FairSatQueryResult::Unknown(reason), None)),
    }
}

fn fair_cube_literal_to_term(
    lit: &FairPdrCubeLit,
    state_vars: &[(String, SmtSort)],
) -> Option<SmtTerm> {
    let (name, sort) = state_vars.get(lit.state_var_idx)?;
    Some(match sort {
        SmtSort::Int => SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)),
        SmtSort::Bool => SmtTerm::var(name.clone()).eq(SmtTerm::bool(lit.value != 0)),
    })
}

fn fair_try_generalize_cube_with_unsat_core<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    if !solver.supports_assumption_unsat_core() || cube.lits.is_empty() {
        return Ok((None, None));
    }

    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;

    if level == 1 {
        fair_assert_all(solver, &artifacts.init_assertions)?;
    } else {
        fair_assert_frame(solver, &frames[level - 1], &artifacts.state_vars_pre)?;
    }

    let mut assumptions = Vec::with_capacity(cube.lits.len());
    let mut lit_by_assumption = HashMap::with_capacity(cube.lits.len());
    for (idx, lit) in cube.lits.iter().enumerate() {
        let Some(lit_term) = fair_cube_literal_to_term(lit, &artifacts.state_vars_post) else {
            return Ok((None, None));
        };
        let assumption_name = format!("__fair_pdr_assume_{level}_{idx}");
        solver
            .declare_var(&assumption_name, &SmtSort::Bool)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        solver
            .assert(&SmtTerm::var(assumption_name.clone()).implies(lit_term))
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        assumptions.push(assumption_name.clone());
        lit_by_assumption.insert(assumption_name, lit.clone());
    }

    match solver
        .check_sat_assuming(&assumptions)
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Unsat => {
            let core_names = solver
                .get_unsat_core_assumptions()
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            if core_names.is_empty() {
                return Ok((None, None));
            }
            let mut core_lits: Vec<FairPdrCubeLit> = core_names
                .iter()
                .filter_map(|name| lit_by_assumption.get(name).cloned())
                .collect();
            if core_lits.is_empty() {
                return Ok((None, None));
            }
            core_lits.sort();
            core_lits.dedup();
            Ok((Some(FairPdrCube { lits: core_lits }), None))
        }
        SatResult::Sat => Ok((None, None)),
        SatResult::Unknown(reason) => Ok((None, Some(reason))),
    }
}

fn fair_pdr_bad_cube_budget(state_var_count: usize, frontier: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(120)
        .saturating_add(frontier.saturating_mul(800));
    5_000usize.saturating_add(scaled).clamp(5_000, 200_000)
}

fn fair_pdr_obligation_budget(state_var_count: usize, level: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(220)
        .saturating_add(level.saturating_mul(1_500));
    10_000usize.saturating_add(scaled).clamp(10_000, 300_000)
}

fn fair_pdr_single_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(32)
        .saturating_add(128)
        .clamp(128, 16_384)
}

fn fair_pdr_pair_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(lit_count.saturating_sub(1))
        .saturating_div(2)
        .clamp(0, 2_048)
}

fn fair_pdr_literal_priority(
    lit: &FairPdrCubeLit,
    state_vars: &[(String, SmtSort)],
) -> (u8, usize) {
    let name = state_vars
        .get(lit.state_var_idx)
        .map(|(n, _)| n.as_str())
        .unwrap_or_default();
    // Domain-guided ordering for consensus models and fairness monitors.
    let class = if name.starts_with("m_") || name.starts_with("time_") {
        0
    } else if name.starts_with("g_") && lit.value == 0 {
        1
    } else if name.starts_with("g_") {
        2
    } else if name.starts_with("kappa_") && lit.value == 0 {
        3
    } else if name.starts_with("kappa_") {
        4
    } else if lit.value == 0 {
        5
    } else {
        6
    };
    (class, lit.state_var_idx)
}

fn fair_pdr_literal_drop_order(cube: &FairPdrCube, state_vars: &[(String, SmtSort)]) -> Vec<usize> {
    let mut entries: Vec<(usize, (u8, usize))> = cube
        .lits
        .iter()
        .enumerate()
        .map(|(idx, lit)| (idx, fair_pdr_literal_priority(lit, state_vars)))
        .collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    entries.into_iter().map(|(idx, _)| idx).collect()
}

fn fair_try_drop_single_literal<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
    query_budget: &mut usize,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    for idx in fair_pdr_literal_drop_order(cube, &artifacts.state_vars_post) {
        if deadline_exceeded(deadline) {
            return Ok((None, Some("Fair PDR: overall timeout exceeded.".into())));
        }
        if *query_budget == 0 {
            return Ok((None, None));
        }
        *query_budget -= 1;
        let mut candidate = cube.clone();
        candidate.lits.remove(idx);
        let (sat, _) = fair_predecessor_query(
            solver,
            artifacts,
            frames,
            level,
            &candidate,
            extra_assertions,
            false,
        )?;
        match sat {
            FairSatQueryResult::Unsat => return Ok((Some(candidate), None)),
            FairSatQueryResult::Sat => {}
            FairSatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
        }
    }
    Ok((None, None))
}

fn fair_try_drop_literal_pair<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
    pair_budget: &mut usize,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    let order = fair_pdr_literal_drop_order(cube, &artifacts.state_vars_post);
    for i in 0..order.len() {
        for j in (i + 1)..order.len() {
            if deadline_exceeded(deadline) {
                return Ok((None, Some("Fair PDR: overall timeout exceeded.".into())));
            }
            if *pair_budget == 0 {
                return Ok((None, None));
            }
            *pair_budget -= 1;
            let idx_a = order[i];
            let idx_b = order[j];
            let mut candidate = cube.clone();
            if idx_a > idx_b {
                candidate.lits.remove(idx_a);
                candidate.lits.remove(idx_b);
            } else {
                candidate.lits.remove(idx_b);
                candidate.lits.remove(idx_a);
            }
            let (sat, _) = fair_predecessor_query(
                solver,
                artifacts,
                frames,
                level,
                &candidate,
                extra_assertions,
                false,
            )?;
            match sat {
                FairSatQueryResult::Unsat => return Ok((Some(candidate), None)),
                FairSatQueryResult::Sat => {}
                FairSatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
            }
        }
    }
    Ok((None, None))
}

fn fair_try_generalize_cube<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    let (core_cube, core_reason) = fair_try_generalize_cube_with_unsat_core(
        solver,
        artifacts,
        frames,
        level,
        cube,
        extra_assertions,
    )?;
    if let Some(reason) = core_reason {
        return Ok((None, Some(reason)));
    }
    if core_cube.is_some() {
        return Ok((core_cube, None));
    }

    let mut current = cube.clone();
    if current.lits.len() <= 1 {
        return Ok((Some(current), None));
    }

    let mut single_budget = fair_pdr_single_literal_query_budget(current.lits.len());
    let mut pair_budget = fair_pdr_pair_literal_query_budget(current.lits.len());

    loop {
        let (candidate, reason) = fair_try_drop_single_literal(
            solver,
            artifacts,
            frames,
            level,
            &current,
            extra_assertions,
            deadline,
            &mut single_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(candidate) = candidate else {
            break;
        };
        current = candidate;
        if current.lits.len() <= 1 {
            return Ok((Some(current), None));
        }
    }

    while current.lits.len() > 2 {
        let (pair_candidate, reason) = fair_try_drop_literal_pair(
            solver,
            artifacts,
            frames,
            level,
            &current,
            extra_assertions,
            deadline,
            &mut pair_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(pair_candidate) = pair_candidate else {
            break;
        };
        current = pair_candidate;
        loop {
            let (single_candidate, reason) = fair_try_drop_single_literal(
                solver,
                artifacts,
                frames,
                level,
                &current,
                extra_assertions,
                deadline,
                &mut single_budget,
            )?;
            if let Some(reason) = reason {
                return Ok((None, Some(reason)));
            }
            let Some(single_candidate) = single_candidate else {
                break;
            };
            current = single_candidate;
            if current.lits.len() <= 1 {
                return Ok((Some(current), None));
            }
        }
    }

    Ok((Some(current), None))
}

fn fair_add_cube_up_to(frames: &mut [FairPdrFrame], level: usize, cube: FairPdrCube) {
    for frame in frames.iter_mut().take(level + 1).skip(1) {
        frame.insert(cube.clone());
    }
}

enum FairBlockingOutcome {
    Blocked,
    Counterexample,
    Unknown(String),
}

fn fair_block_cube<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &mut [FairPdrFrame],
    level: usize,
    initial_cube: FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<FairBlockingOutcome, PipelineError> {
    let max_obligations = fair_pdr_obligation_budget(artifacts.state_vars_pre.len(), level);
    let mut obligations = vec![(initial_cube, level)];
    let mut processed = 0usize;

    while let Some((cube, lvl)) = obligations.pop() {
        processed += 1;
        if processed > max_obligations {
            return Ok(FairBlockingOutcome::Unknown(
                format!(
                    "Fair PDR: obligation budget exceeded while blocking a bad cube (budget={max_obligations})."
                ),
            ));
        }
        if deadline_exceeded(deadline) {
            return Ok(FairBlockingOutcome::Unknown(
                "Fair PDR: overall timeout exceeded.".into(),
            ));
        }

        if lvl == 0 {
            return Ok(FairBlockingOutcome::Counterexample);
        }

        let (sat, pred) = fair_predecessor_query(
            solver,
            artifacts,
            frames,
            lvl,
            &cube,
            extra_assertions,
            true,
        )?;
        match sat {
            FairSatQueryResult::Unsat => {
                let (generalized, unknown_reason) = fair_try_generalize_cube(
                    solver,
                    artifacts,
                    frames,
                    lvl,
                    &cube,
                    extra_assertions,
                    deadline,
                )?;
                if let Some(reason) = unknown_reason {
                    return Ok(FairBlockingOutcome::Unknown(reason));
                }
                let Some(gen_cube) = generalized else {
                    return Ok(FairBlockingOutcome::Unknown(
                        "Fair PDR: failed to generalize blocked cube.".into(),
                    ));
                };
                fair_add_cube_up_to(frames, lvl, gen_cube);
            }
            FairSatQueryResult::Sat => {
                let Some(pred_cube) = pred else {
                    return Ok(FairBlockingOutcome::Unknown(
                        "Fair PDR: predecessor SAT without model".into(),
                    ));
                };
                obligations.push((cube, lvl));
                obligations.push((pred_cube, lvl - 1));
            }
            FairSatQueryResult::Unknown(reason) => return Ok(FairBlockingOutcome::Unknown(reason)),
        }
    }

    Ok(FairBlockingOutcome::Blocked)
}

fn fair_can_push<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
) -> Result<FairSatQueryResult, PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;
    fair_assert_frame(solver, frame, &artifacts.state_vars_pre)?;
    solver
        .assert(&cube.to_conjunction(&artifacts.state_vars_post))
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    match solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Unsat => Ok(FairSatQueryResult::Unsat),
        SatResult::Sat => Ok(FairSatQueryResult::Sat),
        SatResult::Unknown(reason) => Ok(FairSatQueryResult::Unknown(reason)),
    }
}

fn run_unbounded_fair_pdr_internal<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<
    (
        UnboundedFairLivenessResult,
        Option<FairPdrInvariantCertificate>,
    ),
    PipelineError,
> {
    let frame_limit = if max_k == 0 { None } else { Some(max_k) };
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));

    let artifacts = build_unbounded_fair_pdr_artifacts(cs, target, fairness)?;
    let extra_assertions = committee_bound_assertions(committee_bounds);

    let mut frames = vec![FairPdrFrame::default(), FairPdrFrame::default()];
    let mut frontier = 1usize;

    loop {
        if deadline_exceeded(deadline) {
            return Ok((
                UnboundedFairLivenessResult::Unknown {
                    reason: format!(
                        "Fair PDR: overall timeout exceeded at frontier frame {}.",
                        frontier
                    ),
                },
                None,
            ));
        }

        let mut blocked_bad_cubes = 0usize;
        let max_bad_cubes = fair_pdr_bad_cube_budget(artifacts.state_vars_pre.len(), frontier);
        loop {
            if deadline_exceeded(deadline) {
                return Ok((
                    UnboundedFairLivenessResult::Unknown {
                        reason: format!(
                            "Fair PDR: overall timeout exceeded at frontier frame {}.",
                            frontier
                        ),
                    },
                    None,
                ));
            }
            match fair_query_bad_in_frame(solver, &artifacts, &frames[frontier], &extra_assertions)?
            {
                FairCubeQueryResult::Unsat => break,
                FairCubeQueryResult::Unknown(reason) => {
                    return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                }
                FairCubeQueryResult::Sat(cube) => {
                    blocked_bad_cubes += 1;
                    if blocked_bad_cubes > max_bad_cubes {
                        return Ok((
                            UnboundedFairLivenessResult::Unknown {
                                reason: format!(
                                    "Fair PDR: blocked over {max_bad_cubes} bad cubes \
                                     at frame {frontier} (adaptive budget); state space appears too large \
                                     for current abstraction."
                                ),
                            },
                            None,
                        ));
                    }
                    match fair_block_cube(
                        solver,
                        &artifacts,
                        &mut frames,
                        frontier,
                        cube,
                        &extra_assertions,
                        deadline,
                    )? {
                        FairBlockingOutcome::Blocked => {}
                        FairBlockingOutcome::Unknown(reason) => {
                            return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                        }
                        FairBlockingOutcome::Counterexample => {
                            // Recover a concrete lasso trace using bounded fair-lasso search.
                            match run_fair_lasso_search(
                                solver,
                                cs,
                                frontier + 1,
                                target,
                                committee_bounds,
                                fairness,
                                deadline,
                            )? {
                                FairLivenessResult::FairCycleFound {
                                    depth,
                                    loop_start,
                                    trace,
                                } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::FairCycleFound {
                                            depth,
                                            loop_start,
                                            trace,
                                        },
                                        None,
                                    ));
                                }
                                FairLivenessResult::Unknown { reason } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::Unknown { reason },
                                        None,
                                    ));
                                }
                                FairLivenessResult::NoFairCycleUpTo { .. } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::Unknown {
                                            reason:
                                                "Fair PDR found a reachable accepting state, \
                                                 but bounded lasso recovery did not return a trace."
                                                    .into(),
                                        },
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        for level in 1..frontier {
            if deadline_exceeded(deadline) {
                return Ok((
                    UnboundedFairLivenessResult::Unknown {
                        reason: format!(
                            "Fair PDR: overall timeout exceeded at frontier frame {}.",
                            frontier
                        ),
                    },
                    None,
                ));
            }
            let cubes: Vec<FairPdrCube> = frames[level].cubes.iter().cloned().collect();
            for cube in cubes {
                if frames[level + 1].contains(&cube) {
                    continue;
                }
                match fair_can_push(solver, &artifacts, &frames[level], &cube, &extra_assertions)? {
                    FairSatQueryResult::Unsat => {
                        frames[level + 1].insert(cube);
                    }
                    FairSatQueryResult::Sat => {}
                    FairSatQueryResult::Unknown(reason) => {
                        return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                    }
                }
            }
        }

        for i in 1..frontier {
            if frames[i] == frames[i + 1] {
                let cert = build_fair_pdr_invariant_certificate(&artifacts, &frames[i], i);
                return Ok((
                    UnboundedFairLivenessResult::LiveProved { frame: i },
                    Some(cert),
                ));
            }
        }

        if let Some(limit) = frame_limit {
            if frontier >= limit {
                return Ok((
                    UnboundedFairLivenessResult::NotProved { max_k: limit },
                    None,
                ));
            }
        }

        frames.push(FairPdrFrame::default());
        frontier += 1;
    }
}

fn run_unbounded_fair_pdr<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    Ok(run_unbounded_fair_pdr_internal(
        solver,
        cs,
        max_k,
        target,
        committee_bounds,
        fairness,
        overall_timeout,
    )?
    .0)
}

fn run_unbounded_fair_pdr_with_certificate<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<
    (
        UnboundedFairLivenessResult,
        Option<FairPdrInvariantCertificate>,
    ),
    PipelineError,
> {
    run_unbounded_fair_pdr_internal(
        solver,
        cs,
        max_k,
        target,
        committee_bounds,
        fairness,
        overall_timeout,
    )
}

fn deadline_exceeded(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() >= deadline,
        None => false,
    }
}

fn overall_timeout_duration(timeout_secs: u64) -> Option<Duration> {
    if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    }
}

fn deadline_from_timeout_secs(timeout_secs: u64) -> Option<Instant> {
    overall_timeout_duration(timeout_secs).and_then(|t| Instant::now().checked_add(t))
}

fn remaining_timeout_secs(deadline: Option<Instant>) -> Option<u64> {
    let deadline = deadline?;
    if Instant::now() >= deadline {
        return Some(0);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let secs = remaining.as_secs();
    let nanos = remaining.subsec_nanos();
    let rounded_up = if nanos > 0 {
        secs.saturating_add(1)
    } else {
        secs
    };
    Some(rounded_up.max(1))
}

fn timeout_unknown_reason(context: &str) -> String {
    format!("{context} timed out before completion.")
}

fn options_with_remaining_timeout(
    options: &PipelineOptions,
    deadline: Option<Instant>,
    context: &str,
) -> Result<PipelineOptions, PipelineError> {
    match remaining_timeout_secs(deadline) {
        Some(0) => Err(PipelineError::Solver(timeout_unknown_reason(context))),
        Some(remaining) => {
            let mut adjusted = options.clone();
            adjusted.timeout_secs = remaining;
            Ok(adjusted)
        }
        None => Ok(options.clone()),
    }
}

/// Attempt unbounded fair-liveness proof under a selected fairness semantics.
///
/// This checks fair non-termination via a monitor transformation and IC3/PDR.
/// On convergence, liveness is proven for all depths under the chosen fairness mode.
fn prove_fair_liveness_program_with_mode(
    program: &ast::Program,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(program, "prove_fair_liveness")?;
    ensure_n_parameter(&ta)?;
    prove_fair_liveness_for_ta(ta, program, options, fairness)
}

pub fn prove_fair_liveness_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;
    prove_fair_liveness_program_with_mode(&program, options, fairness)
}

/// Run unbounded fair-liveness proof with adaptive CEGAR refinements.
///
/// Refinements are monotone restrictions over adversary assumptions and value
/// abstraction. If a baseline fair cycle is eliminated by refinements and no
/// refined stage still finds a fair cycle, the result is reported as `UNKNOWN`
/// (potentially spurious baseline cycle).
pub fn prove_fair_liveness_with_cegar(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    max_refinements: usize,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    let deadline = deadline_from_timeout_secs(options.timeout_secs);
    let baseline_options =
        match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
            Ok(adjusted) => adjusted,
            Err(_) => {
                return Ok(UnboundedFairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                });
            }
        };
    let baseline_result =
        prove_fair_liveness_program_with_mode(&program, &baseline_options, fairness)?;
    let baseline_is_cycle = matches!(
        baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    );
    if !baseline_is_cycle || max_refinements == 0 {
        return Ok(baseline_result);
    }

    let trace_signals = match &baseline_result {
        UnboundedFairLivenessResult::FairCycleFound { trace, .. } => {
            let ta_for_signals =
                lower_with_active_controls(&program, "prove_fair_liveness_cegar.signals")?;
            Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
        }
        _ => None,
    };
    let mut saw_eliminated = false;
    let mut saw_inconclusive = false;
    let refinement_ladder = cegar_refinement_ladder_with_signals(
        &program,
        trace_signals.as_ref(),
        options.solver,
        options.timeout_secs,
    );
    let mut discovered_predicates: Vec<String> = Vec::new();
    let mut eval_cache = CegarStageEvalCache::<UnboundedFairLivenessResult>::default();

    for refinement in refinement_ladder.into_iter().take(max_refinements) {
        let refined_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    eval_cache.emit_notes();
                    return Ok(UnboundedFairLivenessResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                    });
                }
            };
        let result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = refinement.refinements();
        let mut effective_preds = refinement_preds.clone();
        match result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                eval_cache.emit_notes();
                return Ok(result);
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                if refinement.atoms.len() > 1 {
                    let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                        let refined_options = match options_with_remaining_timeout(
                            options,
                            deadline,
                            "CEGAR fair-liveness core extraction",
                        ) {
                            Ok(adjusted) => adjusted,
                            Err(_) => return Ok(None),
                        };
                        let candidate_result = eval_cache.eval(candidate, || {
                            let mut candidate_program = program.clone();
                            candidate.apply(&mut candidate_program);
                            prove_fair_liveness_program_with_mode(
                                &candidate_program,
                                &refined_options,
                                fairness,
                            )
                        })?;
                        Ok(Some(!matches!(
                            candidate_result,
                            UnboundedFairLivenessResult::FairCycleFound { .. }
                        )))
                    })?;
                    if let Some(core) = maybe_core {
                        effective_preds = core.refinements();
                    }
                }
                saw_eliminated = true;
                for pred in &effective_preds {
                    if !discovered_predicates.contains(&pred) {
                        discovered_predicates.push(pred.clone());
                    }
                }
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    if !discovered_predicates.contains(&core_predicate) {
                        discovered_predicates.push(core_predicate);
                    }
                }
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                saw_inconclusive = true;
            }
        }
    }
    eval_cache.emit_notes();

    if saw_eliminated {
        discovered_predicates = sorted_unique_strings(discovered_predicates);
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: format!(
                "CEGAR refinements eliminated the baseline fair-cycle witness, \
                 but no refined fair cycle was found. Potentially spurious under \
                 refinements: {}",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        });
    }
    if saw_inconclusive {
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline fair-cycle witness \
                     is not confirmed under refined assumptions."
                .into(),
        });
    }
    Ok(UnboundedFairLivenessResult::Unknown {
        reason: "CEGAR refinement ladder exhausted without a confirmed fair cycle or \
                 elimination witness."
            .into(),
    })
}

/// Run unbounded fair-liveness proof with CEGAR and return a machine-readable report.
///
/// This API is intended for CI/governance integrations that need explicit
/// refinement controls and baseline/final outcome tracking.
pub fn prove_fair_liveness_with_cegar_report(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    max_refinements: usize,
) -> Result<UnboundedFairLivenessCegarAuditReport, PipelineError> {
    let started_at = Instant::now();
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    let deadline = deadline_from_timeout_secs(options.timeout_secs);
    let baseline_options =
        match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
            Ok(adjusted) => adjusted,
            Err(_) => {
                let baseline_result = UnboundedFairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                };
                let stages = vec![UnboundedFairLivenessCegarStageReport {
                    stage: 0,
                    label: "baseline".into(),
                    refinements: Vec::new(),
                    outcome: stage_outcome_from_unbounded_fair_liveness(&baseline_result),
                    note: Some("Global timeout exhausted before baseline stage.".into()),
                    model_changes: Vec::new(),
                    eliminated_traces: Vec::new(),
                    discovered_predicates: Vec::new(),
                    counterexample_analysis: None,
                }];
                let termination = cegar_build_termination_from_iterations(
                    "baseline_timeout",
                    max_refinements,
                    0,
                    options.timeout_secs,
                    started_at,
                    true,
                );
                return Ok(UnboundedFairLivenessCegarAuditReport {
                    controls: CegarRunControls {
                        max_refinements,
                        timeout_secs: options.timeout_secs,
                        solver: solver_choice_label(options.solver).into(),
                        proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                        fairness: Some(fairness_mode_label(fairness).into()),
                    },
                    stages,
                    discovered_predicates: Vec::new(),
                    baseline_result: baseline_result.clone(),
                    final_result: baseline_result,
                    classification: "timeout".into(),
                    counterexample_analysis: None,
                    termination,
                });
            }
        };

    let baseline_result =
        prove_fair_liveness_program_with_mode(&program, &baseline_options, fairness)?;
    let trace_signals = match &baseline_result {
        UnboundedFairLivenessResult::FairCycleFound { trace, .. } => {
            let ta_for_signals =
                lower_with_active_controls(&program, "prove_fair_liveness_cegar.signals")?;
            Some(cegar_trace_signals_from_trace(&ta_for_signals, trace))
        }
        _ => None,
    };
    let baseline_has_cycle = matches!(
        baseline_result,
        UnboundedFairLivenessResult::FairCycleFound { .. }
    );
    let mut stages = vec![UnboundedFairLivenessCegarStageReport {
        stage: 0,
        label: "baseline".into(),
        refinements: Vec::new(),
        outcome: stage_outcome_from_unbounded_fair_liveness(&baseline_result),
        note: trace_signals.as_ref().and_then(cegar_signals_note),
        model_changes: Vec::new(),
        eliminated_traces: Vec::new(),
        discovered_predicates: Vec::new(),
        counterexample_analysis: cegar_stage_counterexample_analysis_unbounded_fair(
            0,
            &[],
            &baseline_result,
            baseline_has_cycle,
            trace_signals.as_ref(),
        ),
    }];
    let mut final_result = baseline_result.clone();
    let mut discovered_predicates: Vec<String> = Vec::new();
    let mut saw_timeout = false;
    let mut saw_eliminated = false;
    let mut saw_inconclusive = false;
    let mut confirmed_cycle = false;
    let mut eval_cache = CegarStageEvalCache::<UnboundedFairLivenessResult>::default();

    if !baseline_has_cycle || max_refinements == 0 {
        let classification = if baseline_has_cycle {
            "fair_cycle_unrefined"
        } else if matches!(
            baseline_result,
            UnboundedFairLivenessResult::LiveProved { .. }
        ) {
            "live_proved"
        } else {
            "inconclusive"
        };
        let termination = cegar_build_termination_from_iterations(
            if baseline_has_cycle {
                "iteration_budget_zero"
            } else {
                "baseline_non_counterexample"
            },
            max_refinements,
            0,
            options.timeout_secs,
            started_at,
            false,
        );
        return Ok(UnboundedFairLivenessCegarAuditReport {
            controls: CegarRunControls {
                max_refinements,
                timeout_secs: options.timeout_secs,
                solver: solver_choice_label(options.solver).into(),
                proof_engine: Some(proof_engine_label(options.proof_engine).into()),
                fairness: Some(fairness_mode_label(fairness).into()),
            },
            stages,
            discovered_predicates,
            baseline_result: baseline_result.clone(),
            final_result: baseline_result,
            classification: classification.into(),
            counterexample_analysis: if baseline_has_cycle {
                Some(CegarCounterexampleAnalysis {
                    classification: "potentially_spurious".into(),
                    rationale: "No refinement replay was performed, so the baseline fair-cycle witness is not yet confirmed under stricter assumptions.".into(),
                })
            } else {
                None
            },
            termination,
        });
    }

    let refinement_plan = cegar_refinement_plan_with_signals(
        &program,
        trace_signals.as_ref(),
        options.solver,
        options.timeout_secs,
    );

    for (idx, plan_entry) in refinement_plan
        .into_iter()
        .take(max_refinements)
        .enumerate()
    {
        let refinement = plan_entry.refinement;
        let refined_options =
            match options_with_remaining_timeout(options, deadline, "CEGAR fair-liveness proof") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    saw_timeout = true;
                    final_result = UnboundedFairLivenessResult::Unknown {
                        reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
                    };
                    break;
                }
            };
        let result = eval_cache.eval(&refinement, || {
            let mut refined_program = program.clone();
            refinement.apply(&mut refined_program);
            prove_fair_liveness_program_with_mode(&refined_program, &refined_options, fairness)
        })?;
        let refinement_preds = sorted_unique_strings(refinement.refinements());
        let mut effective_preds = refinement_preds.clone();
        let model_changes = cegar_stage_model_changes(&program, &refinement);

        let mut note = match &result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => Some(
                "Fair-cycle witness persists under this refinement; treated as concrete.".into(),
            ),
            UnboundedFairLivenessResult::LiveProved { .. } => {
                Some("Baseline fair-cycle witness is eliminated under this refinement.".into())
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                Some("Refinement did not produce a decisive verdict for this stage.".into())
            }
        };
        let selection_note = format!("Selection rationale: {}", plan_entry.rationale);
        note = Some(match note {
            Some(existing) => format!("{selection_note} {existing}"),
            None => selection_note,
        });

        if !matches!(result, UnboundedFairLivenessResult::FairCycleFound { .. })
            && refinement.atoms.len() > 1
        {
            let maybe_core = cegar_shrink_refinement_core(&refinement, |candidate| {
                let refined_options = match options_with_remaining_timeout(
                    options,
                    deadline,
                    "CEGAR fair-liveness core extraction",
                ) {
                    Ok(adjusted) => adjusted,
                    Err(_) => return Ok(None),
                };
                let candidate_result = eval_cache.eval(candidate, || {
                    let mut candidate_program = program.clone();
                    candidate.apply(&mut candidate_program);
                    prove_fair_liveness_program_with_mode(
                        &candidate_program,
                        &refined_options,
                        fairness,
                    )
                })?;
                Ok(Some(!matches!(
                    candidate_result,
                    UnboundedFairLivenessResult::FairCycleFound { .. }
                )))
            })?;
            if let Some(core) = maybe_core {
                let core_preds = core.refinements();
                effective_preds = core_preds.clone();
                let core_note = format!("Refinement-elimination core: {}", core.label());
                note = Some(match note {
                    Some(existing) => format!("{existing} {core_note}"),
                    None => core_note,
                });
            }
        }
        if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
            let core_note = format!("Generated core predicate: {core_predicate}");
            note = Some(match note {
                Some(existing) => format!("{existing} {core_note}"),
                None => core_note,
            });
        }
        let stage_counterexample_analysis = cegar_stage_counterexample_analysis_unbounded_fair(
            idx + 1,
            &effective_preds,
            &result,
            baseline_has_cycle,
            trace_signals.as_ref(),
        );
        let baseline_trace = match &stages[0].outcome {
            UnboundedFairLivenessCegarStageOutcome::FairCycleFound { trace, .. } => Some(trace),
            _ => None,
        };
        let eliminated_traces = cegar_stage_eliminated_traces_unbounded_fair(
            idx + 1,
            &result,
            baseline_trace,
            &effective_preds,
        );
        let stage_discovered_predicates = if eliminated_traces.is_empty() {
            Vec::new()
        } else {
            let mut preds = effective_preds.clone();
            if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                preds.push(core_predicate);
            }
            sorted_unique_strings(preds)
        };

        stages.push(UnboundedFairLivenessCegarStageReport {
            stage: idx + 1,
            label: refinement.label(),
            refinements: sorted_unique_strings(refinement_preds.clone()),
            outcome: stage_outcome_from_unbounded_fair_liveness(&result),
            note,
            model_changes,
            eliminated_traces,
            discovered_predicates: stage_discovered_predicates,
            counterexample_analysis: stage_counterexample_analysis,
        });

        match result {
            UnboundedFairLivenessResult::FairCycleFound { .. } => {
                final_result = result;
                confirmed_cycle = true;
                break;
            }
            UnboundedFairLivenessResult::LiveProved { .. } => {
                saw_eliminated = true;
                for pred in &effective_preds {
                    if !discovered_predicates.contains(pred) {
                        discovered_predicates.push(pred.clone());
                    }
                }
                if let Some(core_predicate) = cegar_core_compound_predicate(&effective_preds) {
                    if !discovered_predicates.contains(&core_predicate) {
                        discovered_predicates.push(core_predicate);
                    }
                }
            }
            UnboundedFairLivenessResult::NotProved { .. }
            | UnboundedFairLivenessResult::Unknown { .. } => {
                saw_inconclusive = true;
            }
        }
    }
    eval_cache.emit_notes();
    discovered_predicates = sorted_unique_strings(discovered_predicates);

    if !confirmed_cycle && saw_eliminated {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements eliminated the baseline fair-cycle witness, but no refined fair cycle was found. Treat as inconclusive and inspect the CEGAR report.".into(),
        };
    } else if !confirmed_cycle && saw_timeout {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: timeout_unknown_reason("CEGAR fair-liveness proof"),
        };
    } else if !confirmed_cycle && saw_inconclusive {
        final_result = UnboundedFairLivenessResult::Unknown {
            reason: "CEGAR refinements were inconclusive; baseline fair-cycle witness is not confirmed under refined assumptions.".into(),
        };
    }

    let classification = if confirmed_cycle {
        "fair_cycle_confirmed"
    } else if saw_eliminated {
        "inconclusive"
    } else if saw_timeout {
        "timeout"
    } else {
        "inconclusive"
    };
    let counterexample_analysis = if confirmed_cycle {
        let confirmation = stages
            .iter()
            .find(|stage| {
                stage.stage > 0
                    && matches!(
                        stage.outcome,
                        UnboundedFairLivenessCegarStageOutcome::FairCycleFound { .. }
                    )
            })
            .map(|stage| stage.stage)
            .unwrap_or(0);
        Some(CegarCounterexampleAnalysis {
            classification: "concrete".into(),
            rationale: format!(
                "Baseline fair-cycle witness is confirmed concrete by refined replay at stage {}.",
                confirmation
            ),
        })
    } else if saw_eliminated {
        Some(CegarCounterexampleAnalysis {
            classification: "potentially_spurious".into(),
            rationale: format!(
                "Baseline fair-cycle witness was eliminated by refinement predicates [{}], so the overall result is inconclusive until a concrete refined fair-cycle witness is found.",
                if discovered_predicates.is_empty() {
                    "<none>".into()
                } else {
                    discovered_predicates.join(", ")
                }
            ),
        })
    } else if saw_timeout {
        Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: timeout_unknown_reason("CEGAR fair-liveness proof"),
        })
    } else {
        Some(CegarCounterexampleAnalysis {
            classification: "inconclusive".into(),
            rationale: "Unable to confirm or eliminate the baseline fair-cycle witness within refinement budget.".into(),
        })
    };
    let termination_reason = if confirmed_cycle {
        "confirmed_fair_cycle"
    } else if saw_eliminated {
        "counterexample_eliminated_no_confirmation"
    } else if saw_timeout {
        "timeout"
    } else if stages.iter().filter(|stage| stage.stage > 0).count() >= max_refinements {
        "max_refinements_reached"
    } else {
        "inconclusive"
    };
    let termination = cegar_build_termination_from_iterations(
        termination_reason,
        max_refinements,
        stages.iter().filter(|stage| stage.stage > 0).count(),
        options.timeout_secs,
        started_at,
        saw_timeout,
    );

    Ok(UnboundedFairLivenessCegarAuditReport {
        controls: CegarRunControls {
            max_refinements,
            timeout_secs: options.timeout_secs,
            solver: solver_choice_label(options.solver).into(),
            proof_engine: Some(proof_engine_label(options.proof_engine).into()),
            fairness: Some(fairness_mode_label(fairness).into()),
        },
        stages,
        discovered_predicates,
        baseline_result,
        final_result,
        classification: classification.into(),
        counterexample_analysis,
        termination,
    })
}

fn prove_fair_liveness_for_ta(
    mut ta: ThresholdAutomaton,
    program: &ast::Program,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("pdr.symmetry_generalization=on");
    push_reduction_note("pdr.incremental_query_reuse=on");
    push_reduction_note("por.stutter_time_signature_collapse=on");
    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let has_committees = !committee_summaries.is_empty();
    let committee_bounds: Vec<(usize, u64)> = ta
        .committees
        .iter()
        .zip(committee_summaries.iter())
        .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
        .collect();

    if has_committees && committee_bounds.is_empty() {
        return Ok(UnboundedFairLivenessResult::Unknown {
            reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                .into(),
        });
    }

    let liveness_spec = extract_liveness_spec(&ta, program)?;
    if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
    {
        return Err(PipelineError::Property(
            "Unbounded fair-liveness proof requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                .into(),
        ));
    }
    let target = fair_liveness_target_from_spec(&ta, liveness_spec)?;

    let cs = abstract_to_cs(ta.clone());
    let overall_timeout = if options.timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(options.timeout_secs))
    };
    match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_fair_pdr(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_fair_pdr(
                &mut solver,
                &cs,
                options.max_depth,
                &target,
                &committee_bounds,
                fairness,
                overall_timeout,
            )
        }
    }
}

/// Attempt unbounded fair-liveness proof on a round/view-erased over-approximation.
///
/// LIVE_PROVED is sound for the concrete model. FAIR_CYCLE_FOUND may be
/// spurious due to abstraction.
pub fn prove_fair_liveness_with_round_abstraction(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
    erased_round_vars: &[String],
) -> Result<RoundAbstractionFairProofResult, PipelineError> {
    reset_run_diagnostics();
    info!("Parsing {filename}...");
    let program = parse(source, filename)?;
    preflight_validate(&program, options, PipelineCommand::Liveness)?;

    if normalize_erased_var_names(erased_round_vars).is_empty() {
        return Err(PipelineError::Validation(
            "Round abstraction requires at least one erased variable name.".into(),
        ));
    }

    info!("Lowering to threshold automaton...");
    let ta = lower_with_active_controls(&program, "prove_fair_round")?;
    ensure_n_parameter(&ta)?;

    let (abstract_ta, summary) = apply_round_erasure_abstraction(&ta, erased_round_vars);
    let result = prove_fair_liveness_for_ta(abstract_ta, &program, options, fairness)?;
    Ok(RoundAbstractionFairProofResult { summary, result })
}

/// Attempt unbounded fair-liveness proof under weak fairness.
pub fn prove_fair_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    prove_fair_liveness_with_mode(source, filename, options, FairnessMode::Weak)
}

/// Search for bounded fair non-terminating lassos.
///
/// If a fair lasso is found, liveness is violated. If no lasso is found up to
/// `max_depth`, the result is "no fair counterexample up to bound" (not a full
/// unbounded proof).
pub fn check_fair_liveness_with_mode(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> Result<FairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("check_fair_liveness", || {
        push_reduction_note("encoder.structural_hashing=on");
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        preflight_validate(&program, options, PipelineCommand::Liveness)?;

        info!("Lowering to threshold automaton...");
        let mut ta = lower_with_active_controls(&program, "check_fair_liveness")?;
        ensure_n_parameter(&ta)?;

        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();
        let committee_bounds: Vec<(usize, u64)> = ta
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| spec.bound_param.map(|pid| (pid, summary.b_max)))
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(FairLivenessResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified; \
                     probabilistic bounds are not enforced."
                    .into(),
            });
        }

        let liveness_spec = extract_liveness_spec(&ta, &program)?;
        if matches!(&liveness_spec, LivenessSpec::TerminationGoalLocs(goal_locs) if goal_locs.is_empty())
        {
            return Err(PipelineError::Property(
            "Fair liveness check requires either a `property ...: liveness { ... }` declaration or a boolean local variable named `decided`."
                .into(),
        ));
        }
        let target = fair_liveness_target_from_spec(&ta, liveness_spec)?;
        if matches!(&target, FairLivenessTarget::NonGoalLocs(non_goal_locs) if non_goal_locs.is_empty())
        {
            return Ok(FairLivenessResult::NoFairCycleUpTo {
                depth_checked: options.max_depth,
            });
        }

        let cs = abstract_to_cs(ta.clone());
        match options.solver {
            SolverChoice::Z3 => {
                let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                run_fair_lasso_search(
                    &mut solver,
                    &cs,
                    options.max_depth,
                    &target,
                    &committee_bounds,
                    fairness,
                    deadline_from_timeout_secs(options.timeout_secs),
                )
            }
            SolverChoice::Cvc5 => {
                use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
                run_fair_lasso_search(
                    &mut solver,
                    &cs,
                    options.max_depth,
                    &target,
                    &committee_bounds,
                    fairness,
                    deadline_from_timeout_secs(options.timeout_secs),
                )
            }
        }
    })
}

/// Search for bounded weak-fair non-terminating lassos.
pub fn check_fair_liveness(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<FairLivenessResult, PipelineError> {
    reset_run_diagnostics();
    check_fair_liveness_with_mode(source, filename, options, FairnessMode::Weak)
}

fn run_bmc_for_ta(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    dump_smt_path: Option<&str>,
) -> Result<(BmcResult, CounterSystem), PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    push_reduction_note("bmc.incremental_depth_reuse=on");
    let cs = abstract_to_cs(ta.clone());
    if let Some(path) = dump_smt_path {
        let extra = committee_bound_assertions(committee_bounds);
        dump_smt_to_file(&cs, property, options.max_depth, path, &extra);
    }

    let result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_bmc_with_committee_bounds(
                &mut solver,
                &cs,
                property,
                options.max_depth,
                committee_bounds,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_bmc_with_committee_bounds(
                &mut solver,
                &cs,
                property,
                options.max_depth,
                committee_bounds,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };

    Ok((result, cs))
}

/// Run BMC with per-committee concrete bounds on adversary parameters.
fn run_bmc_with_committee_bounds<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    committee_bounds: &[(usize, u64)],
    overall_timeout: Option<Duration>,
) -> Result<BmcResult, PipelineError> {
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    if !committee_bounds.is_empty() {
        let extra_assertions = committee_bound_assertions(committee_bounds);
        run_bmc_with_extra_assertions_with_deadline(
            solver,
            cs,
            property,
            max_depth,
            &extra_assertions,
            deadline,
        )
        .map_err(|e| PipelineError::Solver(e.to_string()))
    } else {
        run_bmc_with_deadline(solver, cs, property, max_depth, deadline)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    }
}

/// Run BMC at a single depth with per-committee concrete bounds.
fn run_bmc_with_committee_bounds_at_depth<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    depth: usize,
    committee_bounds: &[(usize, u64)],
) -> Result<BmcResult, PipelineError> {
    if !committee_bounds.is_empty() {
        let extra_assertions = committee_bound_assertions(committee_bounds);
        run_bmc_with_extra_assertions_at_depth(solver, cs, property, depth, &extra_assertions)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    } else {
        run_bmc_at_depth(solver, cs, property, depth)
            .map_err(|e| PipelineError::Solver(e.to_string()))
    }
}

/// Run unbounded safety backend with optional committee-derived parameter bounds.
fn run_unbounded_with_engine<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    committee_bounds: &[(usize, u64)],
    engine: ProofEngine,
    overall_timeout: Option<Duration>,
) -> Result<KInductionResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    if engine == ProofEngine::Pdr {
        push_reduction_note("pdr.symmetry_generalization=on");
        push_reduction_note("pdr.incremental_query_reuse=on");
        push_reduction_note("por.stutter_time_signature_collapse=on");
    }
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    let extra_assertions = committee_bound_assertions(committee_bounds);
    match engine {
        ProofEngine::KInduction => {
            run_k_induction_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
        ProofEngine::Pdr => {
            run_pdr_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
    }
}

fn location_zero_assertions_for_depth(locs: &[usize], depth: usize) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(locs.len() * (depth + 1));
    for step in 0..=depth {
        for loc in locs {
            assertions.push(SmtTerm::var(pdr_kappa_var(step, *loc)).eq(SmtTerm::int(0)));
        }
    }
    assertions
}

fn location_zero_assertions_for_step_relation(locs: &[usize]) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(locs.len() * 2);
    for loc in locs {
        assertions.push(SmtTerm::var(pdr_kappa_var(0, *loc)).eq(SmtTerm::int(0)));
        assertions.push(SmtTerm::var(pdr_kappa_var(1, *loc)).eq(SmtTerm::int(0)));
    }
    assertions
}

fn run_k_induction_with_location_invariants<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    base_extra_assertions: &[SmtTerm],
    invariant_zero_locs: &[usize],
    deadline: Option<Instant>,
) -> Result<KInductionResult, S::Error> {
    if max_k == 0 {
        return Ok(KInductionResult::NotProved { max_k, cti: None });
    }

    let mut first_cti: Option<KInductionCti> = None;

    for k in 1..=max_k {
        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: timeout_unknown_reason("k-induction"),
            });
        }
        for depth in 0..=k {
            if deadline_exceeded(deadline) {
                return Ok(KInductionResult::Unknown {
                    reason: timeout_unknown_reason("k-induction"),
                });
            }
            solver.reset()?;
            let encoding = encode_bmc(cs, property, depth);
            for (name, sort) in &encoding.declarations {
                solver.declare_var(name, sort)?;
            }
            for assertion in &encoding.assertions {
                solver.assert(assertion)?;
            }
            for extra in base_extra_assertions {
                solver.assert(extra)?;
            }
            for inv in location_zero_assertions_for_depth(invariant_zero_locs, depth) {
                solver.assert(&inv)?;
            }
            let var_refs: Vec<(&str, &SmtSort)> = encoding
                .model_vars
                .iter()
                .map(|(n, s)| (n.as_str(), s))
                .collect();
            let (sat, model) = solver.check_sat_with_model(&var_refs)?;
            match sat {
                SatResult::Sat => {
                    let Some(model) = model else {
                        return Ok(KInductionResult::Unknown {
                            reason: format!(
                                "k-induction base at depth {depth} returned SAT without a model."
                            ),
                        });
                    };
                    return Ok(KInductionResult::Unsafe { depth, model });
                }
                SatResult::Unsat => {}
                SatResult::Unknown(reason) => {
                    return Ok(KInductionResult::Unknown { reason });
                }
            }
        }

        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: timeout_unknown_reason("k-induction"),
            });
        }
        solver.reset()?;
        let encoding = encode_k_induction_step(cs, property, k);
        for (name, sort) in &encoding.declarations {
            solver.declare_var(name, sort)?;
        }
        for assertion in &encoding.assertions {
            solver.assert(assertion)?;
        }
        for extra in base_extra_assertions {
            solver.assert(extra)?;
        }
        for inv in location_zero_assertions_for_depth(invariant_zero_locs, k) {
            solver.assert(&inv)?;
        }
        let var_refs: Vec<(&str, &SmtSort)> = encoding
            .model_vars
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let (sat, model) = solver.check_sat_with_model(&var_refs)?;
        match sat {
            SatResult::Unsat => {
                return Ok(KInductionResult::Proved { k });
            }
            SatResult::Sat => {
                if first_cti.is_none() {
                    let Some(model) = model else {
                        return Ok(KInductionResult::Unknown {
                            reason: format!(
                                "k-induction step at k={k} returned SAT without a model."
                            ),
                        });
                    };
                    first_cti = Some(KInductionCti { k, model });
                }
            }
            SatResult::Unknown(reason) => {
                return Ok(KInductionResult::Unknown { reason });
            }
        }
    }

    Ok(KInductionResult::NotProved {
        max_k,
        cti: first_cti,
    })
}

fn run_unbounded_with_engine_and_location_invariants<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    committee_bounds: &[(usize, u64)],
    engine: ProofEngine,
    invariant_zero_locs: &[usize],
    overall_timeout: Option<Duration>,
) -> Result<KInductionResult, PipelineError> {
    push_reduction_note("encoder.structural_hashing=on");
    if engine == ProofEngine::Pdr {
        push_reduction_note("pdr.symmetry_generalization=on");
        push_reduction_note("pdr.incremental_query_reuse=on");
        push_reduction_note("por.stutter_time_signature_collapse=on");
    }
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));
    let mut extra_assertions = committee_bound_assertions(committee_bounds);
    match engine {
        ProofEngine::KInduction => run_k_induction_with_location_invariants(
            solver,
            cs,
            property,
            max_k,
            &extra_assertions,
            invariant_zero_locs,
            deadline,
        )
        .map_err(|e| PipelineError::Solver(e.to_string())),
        ProofEngine::Pdr => {
            extra_assertions.extend(location_zero_assertions_for_step_relation(
                invariant_zero_locs,
            ));
            run_pdr_with_deadline(solver, cs, property, max_k, &extra_assertions, deadline)
                .map_err(|e| PipelineError::Solver(e.to_string()))
        }
    }
}

fn property_relevant_location_set(property: &SafetyProperty) -> HashSet<usize> {
    let mut locs = HashSet::new();
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            for (a, b) in conflicting_pairs {
                locs.insert(*a);
                locs.insert(*b);
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            for bad in bad_sets {
                for loc in bad {
                    locs.insert(*loc);
                }
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            for loc in goal_locs {
                locs.insert(*loc);
            }
        }
    }
    locs
}

fn cti_zero_location_candidates(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    max_candidates: usize,
) -> Vec<usize> {
    if max_candidates == 0 {
        return Vec::new();
    }

    let occupied_names: HashSet<&str> = cti
        .hypothesis_locations
        .iter()
        .chain(cti.violating_locations.iter())
        .map(|(name, _)| name.as_str())
        .collect();
    let relevant = property_relevant_location_set(property);

    let mut candidates: Vec<usize> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| !occupied_names.contains(loc.name.as_str()))
        .map(|(id, _)| id)
        .collect();
    candidates.sort_by(|a, b| {
        let ra = relevant.contains(a);
        let rb = relevant.contains(b);
        rb.cmp(&ra)
            .then_with(|| ta.locations[*a].name.cmp(&ta.locations[*b].name))
    });
    candidates.truncate(max_candidates);
    candidates
}

fn prove_location_unreachable_for_synthesis(
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    loc_id: usize,
) -> Result<bool, PipelineError> {
    let candidate = SafetyProperty::Invariant {
        bad_sets: vec![vec![loc_id]],
    };
    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };
    Ok(matches!(kind_result, KInductionResult::Proved { .. }))
}

fn kind_result_to_unbounded_safety(
    kind_result: KInductionResult,
    cs: &CounterSystem,
    property: &SafetyProperty,
    committee_summaries: &[CommitteeAnalysisSummary],
) -> UnboundedSafetyResult {
    let has_committees = !committee_summaries.is_empty();
    match kind_result {
        KInductionResult::Proved { k } => {
            if has_committees {
                let total_epsilon: f64 = committee_summaries.iter().map(|c| c.epsilon).sum();
                UnboundedSafetyResult::ProbabilisticallySafe {
                    induction_k: k,
                    failure_probability: total_epsilon,
                    committee_analyses: committee_summaries.to_vec(),
                }
            } else {
                UnboundedSafetyResult::Safe { induction_k: k }
            }
        }
        KInductionResult::Unsafe { depth, model } => {
            let trace = extract_trace(cs, &model, depth);
            UnboundedSafetyResult::Unsafe { trace }
        }
        KInductionResult::Unknown { reason } => UnboundedSafetyResult::Unknown { reason },
        KInductionResult::NotProved { max_k, cti } => UnboundedSafetyResult::NotProved {
            max_k,
            cti: cti
                .as_ref()
                .map(|witness| build_induction_cti_summary(cs, property, witness)),
        },
    }
}

fn committee_bound_assertions(
    committee_bounds: &[(usize, u64)],
) -> Vec<tarsier_smt::terms::SmtTerm> {
    use tarsier_smt::terms::SmtTerm;
    let mut extra = Vec::new();
    for &(param_id, b_max) in committee_bounds {
        // param <= b_max (concrete upper bound from committee analysis)
        extra.push(SmtTerm::var(format!("p_{param_id}")).le(SmtTerm::int(b_max as i64)));
        // param >= 0
        extra.push(SmtTerm::var(format!("p_{param_id}")).ge(SmtTerm::int(0)));
    }
    extra
}

fn bmc_result_to_verification(result: BmcResult, cs: &CounterSystem) -> VerificationResult {
    match result {
        BmcResult::Safe { depth_checked } => VerificationResult::Safe { depth_checked },
        BmcResult::Unsafe { depth, model } => {
            let trace = extract_trace(cs, &model, depth);
            VerificationResult::Unsafe { trace }
        }
        BmcResult::Unknown { reason, .. } => VerificationResult::Unknown { reason },
    }
}

fn build_induction_cti_summary(
    cs: &CounterSystem,
    property: &SafetyProperty,
    witness: &KInductionCti,
) -> InductionCtiSummary {
    let ta = &cs.automaton;
    let k = witness.k;
    let model = &witness.model;

    let params: Vec<(String, i64)> = ta
        .parameters
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                p.name.clone(),
                model.get_int(&format!("p_{i}")).unwrap_or(0),
            )
        })
        .collect();

    let pre_step = k.saturating_sub(1);
    let hypothesis_locations = collect_named_location_values(ta, model, pre_step);
    let hypothesis_shared = collect_named_shared_values(ta, model, pre_step);
    let violating_locations = collect_named_location_values(ta, model, k);
    let violating_shared = collect_named_shared_values(ta, model, k);

    let final_step_rules = if k == 0 {
        Vec::new()
    } else {
        ta.rules
            .iter()
            .enumerate()
            .filter_map(|(rule_id, rule)| {
                let delta = model
                    .get_int(&format!("delta_{}_{}", k - 1, rule_id))
                    .unwrap_or(0);
                if delta <= 0 {
                    return None;
                }
                let from = &ta.locations[rule.from].name;
                let to = &ta.locations[rule.to].name;
                Some((format!("r{rule_id} ({from} -> {to})"), delta))
            })
            .collect()
    };

    let violated_condition = summarize_property_violation(ta, property, model, k);

    InductionCtiSummary {
        k,
        params,
        hypothesis_locations,
        hypothesis_shared,
        violating_locations,
        violating_shared,
        final_step_rules,
        violated_condition,
    }
}

fn collect_named_location_values(
    ta: &ThresholdAutomaton,
    model: &Model,
    step: usize,
) -> Vec<(String, i64)> {
    ta.locations
        .iter()
        .enumerate()
        .filter_map(|(loc_id, loc)| {
            let value = model
                .get_int(&format!("kappa_{step}_{loc_id}"))
                .unwrap_or(0);
            (value > 0).then(|| (loc.name.clone(), value))
        })
        .collect()
}

fn collect_named_shared_values(
    ta: &ThresholdAutomaton,
    model: &Model,
    step: usize,
) -> Vec<(String, i64)> {
    ta.shared_vars
        .iter()
        .enumerate()
        .filter_map(|(var_id, var)| {
            let value = model.get_int(&format!("g_{step}_{var_id}")).unwrap_or(0);
            (value > 0).then(|| (var.name.clone(), value))
        })
        .collect()
}

fn summarize_property_violation(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    model: &Model,
    step: usize,
) -> String {
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            let mut violated_pairs = Vec::new();
            for &(a, b) in conflicting_pairs {
                let ka = model.get_int(&format!("kappa_{step}_{a}")).unwrap_or(0);
                let kb = model.get_int(&format!("kappa_{step}_{b}")).unwrap_or(0);
                if ka > 0 && kb > 0 {
                    violated_pairs.push(format!(
                        "{} and {} both occupied",
                        ta.locations[a].name, ta.locations[b].name
                    ));
                }
            }
            if violated_pairs.is_empty() {
                "step state satisfies induction hypotheses on 0..k-1 but violates agreement at k"
                    .into()
            } else {
                format!("agreement violated: {}", violated_pairs.join("; "))
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            let mut witnesses = Vec::new();
            for bad_set in bad_sets {
                let occupied: Vec<usize> = bad_set
                    .iter()
                    .copied()
                    .filter(|loc| model.get_int(&format!("kappa_{step}_{loc}")).unwrap_or(0) > 0)
                    .collect();
                if occupied.len() == bad_set.len() {
                    let names = occupied
                        .iter()
                        .map(|loc| ta.locations[*loc].name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    witnesses.push(format!("all of {{{names}}} occupied"));
                }
            }
            if witnesses.is_empty() {
                "step state satisfies induction hypotheses on 0..k-1 but violates invariant at k"
                    .into()
            } else {
                format!("invariant violated: {}", witnesses.join("; "))
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            let goal_set: HashSet<usize> = goal_locs.iter().copied().collect();
            let still_active = ta
                .locations
                .iter()
                .enumerate()
                .filter_map(|(loc_id, loc)| {
                    if goal_set.contains(&loc_id) {
                        return None;
                    }
                    let value = model
                        .get_int(&format!("kappa_{step}_{loc_id}"))
                        .unwrap_or(0);
                    (value > 0).then(|| format!("{}={}", loc.name, value))
                })
                .collect::<Vec<_>>();
            if still_active.is_empty() {
                "termination violated at step k".into()
            } else {
                format!(
                    "termination violated: non-goal locations still populated ({})",
                    still_active.join(", ")
                )
            }
        }
    }
}

fn dump_smt_to_file(
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    path: &str,
    extra_assertions: &[tarsier_smt::terms::SmtTerm],
) {
    use tarsier_smt::encoder::encode_bmc;

    let encoding = encode_bmc(cs, property, max_depth);
    let smt = encoding_to_smt2_script(&encoding, extra_assertions);

    if let Err(e) = std::fs::write(path, smt) {
        eprintln!("Warning: could not write SMT dump to {path}: {e}");
    } else {
        info!("SMT dump written to {path}");
    }
}

fn encoding_to_smt2_script(
    encoding: &tarsier_smt::encoder::BmcEncoding,
    extra_assertions: &[tarsier_smt::terms::SmtTerm],
) -> String {
    let mut assertions = encoding.assertions.clone();
    assertions.extend(extra_assertions.iter().cloned());
    query_to_smt2_script(&encoding.declarations, &assertions)
}

fn query_to_smt2_script(declarations: &[(String, SmtSort)], assertions: &[SmtTerm]) -> String {
    use tarsier_smt::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};

    let mut smt = String::new();
    smt.push_str("(set-logic QF_LIA)\n");
    for (name, sort) in declarations {
        smt.push_str(&format!(
            "(declare-const {} {})\n",
            name,
            sort_to_smtlib(sort)
        ));
    }
    for assertion in assertions {
        smt.push_str(&format!("(assert {})\n", to_smtlib(assertion)));
    }
    smt.push_str("(check-sat)\n");
    smt.push_str("(exit)\n");
    smt
}

fn pdr_certificate_to_obligations(
    cert: &PdrInvariantCertificate,
    extra_assertions: &[SmtTerm],
) -> Vec<SafetyProofObligation> {
    let inv_pre = if cert.invariant_pre.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_pre.clone())
    };
    let inv_post = if cert.invariant_post.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_post.clone())
    };

    let mut init_to_inv = cert.init_assertions.clone();
    init_to_inv.extend(extra_assertions.iter().cloned());
    init_to_inv.push(inv_pre.clone().not());

    let mut consecution = cert.invariant_pre.clone();
    consecution.extend(cert.transition_assertions.iter().cloned());
    consecution.extend(extra_assertions.iter().cloned());
    consecution.push(inv_post.not());

    let mut inv_to_safe = cert.invariant_pre.clone();
    inv_to_safe.extend(extra_assertions.iter().cloned());
    inv_to_safe.push(cert.bad_pre.clone());

    vec![
        SafetyProofObligation {
            name: "init_implies_inv".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &init_to_inv),
        },
        SafetyProofObligation {
            name: "inv_and_transition_implies_inv_prime".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &consecution),
        },
        SafetyProofObligation {
            name: "inv_implies_safe".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &inv_to_safe),
        },
    ]
}

fn fair_pdr_certificate_to_obligations(
    cert: &FairPdrInvariantCertificate,
    extra_assertions: &[SmtTerm],
) -> Vec<SafetyProofObligation> {
    let inv_pre = if cert.invariant_pre.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_pre.clone())
    };
    let inv_post = if cert.invariant_post.is_empty() {
        SmtTerm::bool(true)
    } else {
        SmtTerm::and(cert.invariant_post.clone())
    };

    let mut init_to_inv = cert.init_assertions.clone();
    init_to_inv.extend(extra_assertions.iter().cloned());
    init_to_inv.push(inv_pre.clone().not());

    let mut consecution = cert.invariant_pre.clone();
    consecution.extend(cert.transition_assertions.iter().cloned());
    consecution.extend(extra_assertions.iter().cloned());
    consecution.push(inv_post.not());

    let mut inv_to_no_fair_bad = cert.invariant_pre.clone();
    inv_to_no_fair_bad.extend(extra_assertions.iter().cloned());
    inv_to_no_fair_bad.push(cert.bad_pre.clone());

    vec![
        SafetyProofObligation {
            name: "init_implies_inv".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &init_to_inv),
        },
        SafetyProofObligation {
            name: "inv_and_transition_implies_inv_prime".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &consecution),
        },
        SafetyProofObligation {
            name: "inv_implies_no_fair_bad".into(),
            expected: "unsat".into(),
            smt2: query_to_smt2_script(&cert.declarations, &inv_to_no_fair_bad),
        },
    ]
}

/// Show the threshold automaton for a protocol.
pub fn show_ta(source: &str, filename: &str) -> Result<String, PipelineError> {
    reset_run_diagnostics();
    let program = parse(source, filename)?;
    let ta = lower_with_active_controls(&program, "show_ta")?;
    Ok(format!("{ta}"))
}

/// Analyze communication complexity (coarse upper bounds).
pub fn comm_complexity(
    source: &str,
    filename: &str,
    depth: usize,
) -> Result<CommComplexityReport, PipelineError> {
    reset_run_diagnostics();
    let program = parse(source, filename)?;
    let mut ta = lower_with_active_controls(&program, "comm_complexity")?;
    ensure_n_parameter(&ta)?;

    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let total_finality_failure: Option<f64> = if committee_summaries.is_empty() {
        None
    } else {
        Some(committee_summaries.iter().map(|c| c.epsilon).sum())
    };
    let finality_success_probability_lower =
        total_finality_failure.map(|p_fail| (1.0 - p_fail).clamp(0.0, 1.0));
    let expected_rounds_to_finality = total_finality_failure.and_then(|p_fail| {
        if p_fail < 1.0 {
            Some(1.0 / (1.0 - p_fail))
        } else {
            None
        }
    });
    let rounds_for_90pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.90));
    let rounds_for_95pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.95));
    let rounds_for_99pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.99));

    let n_param = ta
        .find_param_by_name("n")
        .map(|id| ta.parameters[id].name.clone());
    let n_label = n_param.clone().unwrap_or_else(|| "n".into());
    let adv_param = ta
        .adversary_bound_param
        .map(|id| ta.parameters[id].name.clone());
    let min_decision_steps = {
        let decision_locs: Vec<usize> = ta
            .locations
            .iter()
            .enumerate()
            .filter_map(|(loc_id, loc)| match loc.local_vars.get("decided") {
                Some(LocalValue::Bool(true)) => Some(loc_id),
                _ => None,
            })
            .collect();
        if decision_locs.is_empty() || ta.initial_locations.is_empty() {
            None
        } else {
            let mut dist = vec![usize::MAX; ta.locations.len()];
            let mut queue = VecDeque::new();
            for &start in &ta.initial_locations {
                if start < dist.len() && dist[start] == usize::MAX {
                    dist[start] = 0;
                    queue.push_back(start);
                }
            }

            while let Some(current) = queue.pop_front() {
                let next_dist = dist[current].saturating_add(1);
                for rule in &ta.rules {
                    if rule.from != current {
                        continue;
                    }
                    if dist[rule.to] == usize::MAX {
                        dist[rule.to] = next_dist;
                        queue.push_back(rule.to);
                    }
                }
            }

            decision_locs
                .into_iter()
                .filter_map(|id| {
                    let d = dist[id];
                    (d != usize::MAX).then_some(d)
                })
                .min()
        }
    };

    let mut max_sends_per_rule = 0usize;
    let mut max_by_type: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut max_by_role: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut max_by_role_and_type: std::collections::HashMap<
        String,
        std::collections::HashMap<String, usize>,
    > = std::collections::HashMap::new();

    for rule in &ta.rules {
        let mut total = 0usize;
        let mut per_type: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for upd in &rule.updates {
            if ta.shared_vars[upd.var].kind != SharedVarKind::MessageCounter {
                continue;
            }
            if !matches!(
                upd.kind,
                tarsier_ir::threshold_automaton::UpdateKind::Increment
            ) {
                continue;
            }
            total += 1;
            if let Some(base) = base_message_name(&ta.shared_vars[upd.var].name) {
                *per_type.entry(base).or_insert(0) += 1;
            }
        }
        if total > max_sends_per_rule {
            max_sends_per_rule = total;
        }
        for (msg, count) in &per_type {
            let entry = max_by_type.entry(msg.clone()).or_insert(0);
            if *count > *entry {
                *entry = *count;
            }
        }

        let sender_role = ta.locations[rule.from].role.clone();
        let role_entry = max_by_role.entry(sender_role.clone()).or_insert(0);
        if total > *role_entry {
            *role_entry = total;
        }
        let role_types = max_by_role_and_type.entry(sender_role).or_default();
        for (msg, count) in per_type {
            let entry = role_types.entry(msg).or_insert(0);
            if count > *entry {
                *entry = count;
            }
        }
    }

    let mut sender_roles: Vec<String> = max_by_role.keys().cloned().collect();
    sender_roles.sort();
    let single_role_model = ta
        .locations
        .iter()
        .map(|loc| loc.role.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
        == 1;
    let mut role_population_labels: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for role in &sender_roles {
        let role_param = format!("n_{}", role.to_lowercase());
        if let Some(pid) = ta.find_param_by_name(&role_param) {
            role_population_labels.insert(role.clone(), ta.parameters[pid].name.clone());
        } else if single_role_model {
            role_population_labels.insert(role.clone(), n_label.clone());
        }
    }
    let use_role_population_bounds = !sender_roles.is_empty()
        && sender_roles
            .iter()
            .all(|role| role_population_labels.contains_key(role));

    let per_step_bound = if use_role_population_bounds {
        let mut terms = Vec::new();
        for role in &sender_roles {
            let Some(pop) = role_population_labels.get(role) else {
                continue;
            };
            let max_count = *max_by_role.get(role).unwrap_or(&0);
            terms.push(format_scaled_term(pop, max_count));
        }
        format_sum_bounds(&terms)
    } else if max_sends_per_rule == 0 {
        "0".into()
    } else {
        format_bound(&[n_label.clone(), max_sends_per_rule.to_string()])
    };
    let per_depth_bound = scale_bound_by_depth(depth, &per_step_bound);

    let mut max_sends_per_rule_by_type: Vec<(String, usize)> = max_by_type.into_iter().collect();
    max_sends_per_rule_by_type.sort_by(|a, b| a.0.cmp(&b.0));

    let mut per_step_type_bounds = Vec::new();
    let mut per_depth_type_bounds = Vec::new();
    let mut per_step_type_big_o = Vec::new();
    let mut per_depth_type_big_o = Vec::new();
    for (msg, count) in &max_sends_per_rule_by_type {
        let step_bound = if use_role_population_bounds {
            let mut terms = Vec::new();
            for role in &sender_roles {
                let Some(pop) = role_population_labels.get(role) else {
                    continue;
                };
                let role_count = max_by_role_and_type
                    .get(role)
                    .and_then(|m| m.get(msg))
                    .copied()
                    .unwrap_or(0);
                terms.push(format_scaled_term(pop, role_count));
            }
            format_sum_bounds(&terms)
        } else if *count == 0 {
            "0".into()
        } else {
            format_bound(&[n_label.clone(), count.to_string()])
        };
        let depth_bound = scale_bound_by_depth(depth, &step_bound);
        per_step_type_bounds.push((msg.clone(), step_bound));
        per_depth_type_bounds.push((msg.clone(), depth_bound));
        let step_big_o = if *count == 0 {
            "O(1)".into()
        } else if n_param.is_some() {
            "O(n)".into()
        } else {
            "O(1)".into()
        };
        let depth_big_o = if *count == 0 {
            "O(1)".into()
        } else if n_param.is_some() {
            "O(k * n)".into()
        } else {
            "O(k)".into()
        };
        per_step_type_big_o.push((msg.clone(), step_big_o));
        per_depth_type_big_o.push((msg.clone(), depth_big_o));
    }

    let mut family_counter_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut family_recipients: std::collections::HashMap<
        String,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for shared in &ta.shared_vars {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient)) =
            message_family_and_recipient_from_counter_name(&shared.name)
        else {
            continue;
        };
        *family_counter_counts.entry(family.clone()).or_insert(0) += 1;
        family_recipients
            .entry(family)
            .or_default()
            .insert(recipient.unwrap_or_else(|| "*".into()));
    }
    let mut family_recipient_group_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (family, recipients) in &family_recipients {
        family_recipient_group_counts.insert(family.clone(), recipients.len());
    }
    let total_message_counters = family_counter_counts.values().sum::<usize>();
    let total_family_recipient_groups = family_recipient_group_counts.values().sum::<usize>();

    let byzantine_faults = ta.fault_model == FaultModel::Byzantine;
    let signed_or_no_equiv = ta.authentication_mode == AuthenticationMode::Signed
        || ta.equivocation_mode == EquivocationMode::None;

    let adversary_multiplier_total = if byzantine_faults {
        if signed_or_no_equiv {
            total_family_recipient_groups
        } else {
            total_message_counters
        }
    } else {
        0
    };

    let adversary_per_step_bound = adv_param
        .as_ref()
        .map(|adv| format_scaled_term(adv, adversary_multiplier_total));
    let adversary_per_depth_bound = adversary_per_step_bound
        .as_ref()
        .map(|step| scale_bound_by_depth(depth, step));

    let mut family_names: Vec<String> = family_counter_counts.keys().cloned().collect();
    family_names.sort();
    let mut adversary_per_step_type_bounds = Vec::new();
    let mut adversary_per_depth_type_bounds = Vec::new();
    if let Some(adv) = adv_param.as_ref() {
        for family in &family_names {
            let multiplier = if byzantine_faults {
                if signed_or_no_equiv {
                    *family_recipient_group_counts.get(family).unwrap_or(&0)
                } else {
                    *family_counter_counts.get(family).unwrap_or(&0)
                }
            } else {
                0
            };
            let step = format_scaled_term(adv, multiplier);
            let depth_bound = scale_bound_by_depth(depth, &step);
            adversary_per_step_type_bounds.push((family.clone(), step));
            adversary_per_depth_type_bounds.push((family.clone(), depth_bound));
        }
    }

    let per_step_bound_with_adv = adv_param.as_ref().map(|_| {
        let adv_step = adversary_per_step_bound.as_deref().unwrap_or("0");
        add_bounds(&per_step_bound, adv_step)
    });
    let per_depth_bound_with_adv = per_step_bound_with_adv
        .as_ref()
        .map(|step| scale_bound_by_depth(depth, step));

    let mut protocol_step_by_type: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (msg, bound) in &per_step_type_bounds {
        protocol_step_by_type.insert(msg.clone(), bound.clone());
    }
    let mut adv_step_by_type: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (msg, bound) in &adversary_per_step_type_bounds {
        adv_step_by_type.insert(msg.clone(), bound.clone());
    }
    let mut all_type_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    all_type_names.extend(protocol_step_by_type.keys().cloned());
    all_type_names.extend(adv_step_by_type.keys().cloned());

    let mut per_step_type_bounds_with_adv = Vec::new();
    let mut per_depth_type_bounds_with_adv = Vec::new();
    for msg in all_type_names {
        let protocol = protocol_step_by_type
            .get(&msg)
            .map(String::as_str)
            .unwrap_or("0");
        let adv = adv_step_by_type
            .get(&msg)
            .map(String::as_str)
            .unwrap_or("0");
        let combined = add_bounds(protocol, adv);
        let depth_combined = scale_bound_by_depth(depth, &combined);
        per_step_type_bounds_with_adv.push((msg.clone(), combined));
        per_depth_type_bounds_with_adv.push((msg, depth_combined));
    }

    let per_step_bound_big_o = if max_sends_per_rule == 0 {
        "O(1)".into()
    } else if n_param.is_some() {
        "O(n)".into()
    } else {
        "O(1)".into()
    };
    let per_depth_bound_big_o = if max_sends_per_rule == 0 {
        "O(1)".into()
    } else if n_param.is_some() {
        "O(k * n)".into()
    } else {
        "O(k)".into()
    };

    let expected_total_messages_upper =
        expected_rounds_to_finality.map(|rounds| format!("{rounds:.3} * ({per_step_bound})"));
    let messages_for_90pct_finality_upper =
        rounds_for_90pct_finality.map(|rounds| format!("{rounds} * ({per_step_bound})"));
    let messages_for_99pct_finality_upper =
        rounds_for_99pct_finality.map(|rounds| format!("{rounds} * ({per_step_bound})"));
    let expected_total_messages_with_adv_upper = expected_rounds_to_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds:.3} * ({bound})"))
    });
    let messages_for_90pct_finality_with_adv_upper = rounds_for_90pct_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds} * ({bound})"))
    });
    let messages_for_99pct_finality_with_adv_upper = rounds_for_99pct_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds} * ({bound})"))
    });

    // --- Per-role bounds (item 1) ---
    let mut per_role_step_bounds = Vec::new();
    let mut per_role_depth_bounds = Vec::new();
    for role in &sender_roles {
        let max_count = *max_by_role.get(role).unwrap_or(&0);
        let pop = role_population_labels
            .get(role)
            .cloned()
            .unwrap_or_else(|| n_label.clone());
        let step = format_scaled_term(&pop, max_count);
        let depth_bound = scale_bound_by_depth(depth, &step);
        per_role_step_bounds.push((role.clone(), step));
        per_role_depth_bounds.push((role.clone(), depth_bound));
    }

    // --- Per-phase bounds (item 1) ---
    let mut max_by_phase: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for rule in &ta.rules {
        let phase = ta.locations[rule.from].phase.clone();
        let mut total = 0usize;
        for upd in &rule.updates {
            if ta.shared_vars[upd.var].kind != SharedVarKind::MessageCounter {
                continue;
            }
            if !matches!(
                upd.kind,
                tarsier_ir::threshold_automaton::UpdateKind::Increment
            ) {
                continue;
            }
            total += 1;
        }
        let entry = max_by_phase.entry(phase).or_insert(0);
        if total > *entry {
            *entry = total;
        }
    }
    let mut phase_names: Vec<String> = max_by_phase.keys().cloned().collect();
    phase_names.sort();
    let mut per_phase_step_bounds = Vec::new();
    let mut per_phase_depth_bounds = Vec::new();
    for phase in &phase_names {
        let max_count = *max_by_phase.get(phase).unwrap_or(&0);
        let step = format_scaled_term(&n_label, max_count);
        let depth_bound = scale_bound_by_depth(depth, &step);
        per_phase_step_bounds.push((phase.clone(), step));
        per_phase_depth_bounds.push((phase.clone(), depth_bound));
    }

    // --- Model assumptions (item 2) ---
    let model_assumptions = ModelAssumptions {
        fault_model: format!("{:?}", ta.fault_model),
        timing_model: format!("{:?}", ta.timing_model),
        authentication_mode: format!("{:?}", ta.authentication_mode),
        equivocation_mode: format!("{:?}", ta.equivocation_mode),
        network_semantics: format!("{:?}", ta.network_semantics),
        gst_param: ta.gst_param.map(|id| ta.parameters[id].name.clone()),
    };

    // --- Model metadata (item 7) ---
    let source_hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        source.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };
    let model_metadata = ModelMetadata {
        source_hash,
        filename: filename.to_string(),
        analysis_depth: depth,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // --- Assumption notes (item 8) ---
    let mut assumption_notes = Vec::new();
    if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::Asynchronous
        && ta.gst_param.is_none()
    {
        assumption_notes.push(AssumptionNote {
            level: "warning".into(),
            message: "Finality metrics assume eventual delivery; under pure asynchrony \
                      without GST, no finality guarantee is possible."
                .into(),
        });
    }
    if total_finality_failure.is_none() && min_decision_steps.is_some() {
        assumption_notes.push(AssumptionNote {
            level: "note".into(),
            message: "No committee selection found; finality round estimates are unavailable. \
                      Latency lower bound is based on BFS graph distance only."
                .into(),
        });
    }
    if ta.fault_model == FaultModel::Crash {
        assumption_notes.push(AssumptionNote {
            level: "note".into(),
            message: "Crash fault model: adversary injection bounds are zero \
                      (crash faults cannot inject messages)."
                .into(),
        });
    }

    // --- Sensitivity analysis (item 3) ---
    let mut sensitivity = Vec::new();
    for cs in &committee_summaries {
        let base_epsilon = cs.epsilon;
        let base_b_max = cs.b_max;
        // Vary epsilon by factors of 10
        for factor in [10.0_f64, 100.0, 0.1, 0.01] {
            let varied_epsilon = base_epsilon * factor;
            if varied_epsilon <= 0.0 || varied_epsilon >= 1.0 {
                continue;
            }
            let spec = CommitteeSpec {
                name: cs.name.clone(),
                population: cs.population,
                byzantine: cs.byzantine,
                committee_size: cs.committee_size,
                epsilon: varied_epsilon,
            };
            if let Ok(analysis) = tarsier_prob::committee::analyze_committee(&spec) {
                sensitivity.push(SensitivityPoint {
                    parameter: "epsilon".into(),
                    base_value: base_epsilon,
                    varied_value: varied_epsilon,
                    metric: format!("b_max({})", cs.name),
                    base_result: base_b_max as f64,
                    varied_result: analysis.b_max as f64,
                });
            }
        }
    }

    // --- Bound annotations (item 4) ---
    let bound_annotations = vec![
        BoundAnnotation {
            field: "min_decision_steps".into(),
            kind: BoundKind::LowerBound,
            description: "BFS shortest path from initial to decided location".into(),
        },
        BoundAnnotation {
            field: "finality_failure_probability_upper".into(),
            kind: BoundKind::UpperBound,
            description: "Union bound over committee tail probabilities".into(),
        },
        BoundAnnotation {
            field: "finality_success_probability_lower".into(),
            kind: BoundKind::LowerBound,
            description: "1 - finality_failure_probability_upper".into(),
        },
        BoundAnnotation {
            field: "expected_rounds_to_finality".into(),
            kind: BoundKind::Estimate,
            description: "Geometric distribution mean (1/p_success); assumes IID rounds".into(),
        },
        BoundAnnotation {
            field: "per_step_bound".into(),
            kind: BoundKind::UpperBound,
            description: "Maximum honest protocol messages per step".into(),
        },
        BoundAnnotation {
            field: "per_depth_bound".into(),
            kind: BoundKind::UpperBound,
            description: "Maximum honest protocol messages over all steps".into(),
        },
        BoundAnnotation {
            field: "per_step_bound_with_adv".into(),
            kind: BoundKind::UpperBound,
            description: "Maximum messages per step including adversary injection".into(),
        },
        BoundAnnotation {
            field: "per_depth_bound_with_adv".into(),
            kind: BoundKind::UpperBound,
            description: "Maximum messages over all steps including adversary injection".into(),
        },
        BoundAnnotation {
            field: "per_step_bound_big_o".into(),
            kind: BoundKind::UpperBound,
            description: "Asymptotic per-step message complexity class".into(),
        },
        BoundAnnotation {
            field: "per_depth_bound_big_o".into(),
            kind: BoundKind::UpperBound,
            description: "Asymptotic per-depth message complexity class".into(),
        },
        BoundAnnotation {
            field: "rounds_for_90pct_finality".into(),
            kind: BoundKind::UpperBound,
            description: "Geometric distribution quantile for 90% confidence".into(),
        },
        BoundAnnotation {
            field: "rounds_for_95pct_finality".into(),
            kind: BoundKind::UpperBound,
            description: "Geometric distribution quantile for 95% confidence".into(),
        },
        BoundAnnotation {
            field: "rounds_for_99pct_finality".into(),
            kind: BoundKind::UpperBound,
            description: "Geometric distribution quantile for 99% confidence".into(),
        },
    ];

    Ok(CommComplexityReport {
        schema_version: 1,
        model_metadata,
        model_assumptions,
        assumption_notes,
        bound_annotations,
        depth,
        n_param,
        adv_param,
        min_decision_steps,
        finality_failure_probability_upper: total_finality_failure,
        finality_success_probability_lower,
        expected_rounds_to_finality,
        rounds_for_90pct_finality,
        rounds_for_95pct_finality,
        rounds_for_99pct_finality,
        expected_total_messages_upper,
        messages_for_90pct_finality_upper,
        messages_for_99pct_finality_upper,
        expected_total_messages_with_adv_upper,
        messages_for_90pct_finality_with_adv_upper,
        messages_for_99pct_finality_with_adv_upper,
        max_sends_per_rule,
        max_sends_per_rule_by_type,
        adversary_per_step_bound,
        adversary_per_depth_bound,
        per_step_bound,
        per_depth_bound,
        per_step_bound_with_adv,
        per_depth_bound_with_adv,
        per_step_bound_big_o,
        per_depth_bound_big_o,
        per_step_type_bounds,
        per_depth_type_bounds,
        adversary_per_step_type_bounds,
        adversary_per_depth_type_bounds,
        per_step_type_bounds_with_adv,
        per_depth_type_bounds_with_adv,
        per_step_type_big_o,
        per_depth_type_big_o,
        per_role_step_bounds,
        per_role_depth_bounds,
        per_phase_step_bounds,
        per_phase_depth_bounds,
        sensitivity,
    })
}

#[cfg(test)]
mod tests {
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
}
