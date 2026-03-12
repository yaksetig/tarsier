//! CTI-driven invariant inference helpers.
//!
//! This module isolates reusable invariant-synthesis logic from orchestration
//! and provides candidate predicate generation for automatic strengthening.

use crate::pipeline::verification::*;
use crate::pipeline::*;
use std::collections::HashSet;
use tarsier_ir::counter_system::Configuration;

use tarsier_smt::encoder::{encode_bmc, encode_k_induction_step};

// ---------------------------------------------------------------------------
// Candidate predicate types (INV-02)
// ---------------------------------------------------------------------------

/// A term in a linear predicate over kappa, gamma, and parameter variables.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinearTerm {
    /// Location counter: `kappa[loc_id]`.
    Kappa(usize),
    /// Shared variable: `gamma[var_id]`.
    Gamma(usize),
    /// Protocol parameter: `params[param_id]`.
    Param(usize),
    /// Integer constant.
    Const(i64),
}

/// Comparison operator for a linear predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateOp {
    Eq,
    Le,
    Ge,
}

/// An atomic linear predicate candidate: `sum(coeffs[i] * terms[i]) PredicateOp 0`.
///
/// For example, `kappa[2] = 0` is represented as `[(1, Kappa(2)), (-1, Const(0))]` with `Eq`,
/// or equivalently `[(1, Kappa(2))]` with `op = Eq` against zero on the RHS.
///
/// We use a simplified form: `lhs op rhs` where both sides are sums of terms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CandidatePredicate {
    /// Human-readable label for reporting.
    pub label: String,
    /// Left-hand side terms with coefficients.
    pub lhs: Vec<(i64, LinearTerm)>,
    /// Comparison operator.
    pub op: PredicateOp,
    /// Right-hand side terms with coefficients.
    pub rhs: Vec<(i64, LinearTerm)>,
}

impl CandidatePredicate {
    fn zero_location(loc_id: usize, loc_name: &str) -> Self {
        Self {
            label: format!("kappa_{loc_name} = 0"),
            lhs: vec![(1, LinearTerm::Kappa(loc_id))],
            op: PredicateOp::Eq,
            rhs: vec![(1, LinearTerm::Const(0))],
        }
    }

    fn kappa_le_param(loc_id: usize, loc_name: &str, param_id: usize, param_name: &str) -> Self {
        Self {
            label: format!("kappa_{loc_name} <= {param_name}"),
            lhs: vec![(1, LinearTerm::Kappa(loc_id))],
            op: PredicateOp::Le,
            rhs: vec![(1, LinearTerm::Param(param_id))],
        }
    }

    fn kappa_sum_le_param(locs: &[(usize, &str)], param_id: usize, param_name: &str) -> Self {
        let label_parts: Vec<String> = locs.iter().map(|(_, n)| format!("kappa_{n}")).collect();
        Self {
            label: format!("{} <= {param_name}", label_parts.join(" + ")),
            lhs: locs
                .iter()
                .map(|(id, _)| (1, LinearTerm::Kappa(*id)))
                .collect(),
            op: PredicateOp::Le,
            rhs: vec![(1, LinearTerm::Param(param_id))],
        }
    }

    fn gamma_le_param(var_id: usize, var_name: &str, param_id: usize, param_name: &str) -> Self {
        Self {
            label: format!("gamma_{var_name} <= {param_name}"),
            lhs: vec![(1, LinearTerm::Gamma(var_id))],
            op: PredicateOp::Le,
            rhs: vec![(1, LinearTerm::Param(param_id))],
        }
    }

    fn gamma_ge_zero(var_id: usize, var_name: &str) -> Self {
        Self {
            label: format!("gamma_{var_name} >= 0"),
            lhs: vec![(1, LinearTerm::Gamma(var_id))],
            op: PredicateOp::Ge,
            rhs: vec![(1, LinearTerm::Const(0))],
        }
    }

    /// Evaluate this predicate on a concrete configuration.
    pub fn evaluate(&self, config: &Configuration) -> bool {
        let eval_side = |terms: &[(i64, LinearTerm)]| -> i64 {
            terms
                .iter()
                .map(|(coeff, term)| {
                    coeff
                        * match term {
                            LinearTerm::Kappa(id) => config.kappa.get(*id).copied().unwrap_or(0),
                            LinearTerm::Gamma(id) => config.gamma.get(*id).copied().unwrap_or(0),
                            LinearTerm::Param(id) => config.params.get(*id).copied().unwrap_or(0),
                            LinearTerm::Const(v) => *v,
                        }
                })
                .sum()
        };
        let l = eval_side(&self.lhs);
        let r = eval_side(&self.rhs);
        match self.op {
            PredicateOp::Eq => l == r,
            PredicateOp::Le => l <= r,
            PredicateOp::Ge => l >= r,
        }
    }
}

impl std::fmt::Display for CandidatePredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

/// Generate atomic linear predicate candidates from the threshold automaton structure.
///
/// Produces candidates in priority order (most likely to be inductive first):
/// 1. Zero-location predicates for non-initial, non-CTI-occupied locations
/// 2. Per-location upper bounds (`kappa_l <= n`)
/// 3. Pairwise location sum bounds (`kappa_l1 + kappa_l2 <= n`)
/// 4. Shared variable bounds (`0 <= gamma_v <= n`)
///
/// If a CTI is provided, candidates are filtered to exclude those trivially
/// satisfied by the CTI (which cannot help strengthen the induction hypothesis).
pub fn generate_linear_predicate_candidates(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: Option<&InductionCtiSummary>,
) -> Vec<CandidatePredicate> {
    let mut candidates = Vec::new();

    let initial_set: HashSet<usize> = ta.initial_locations.iter().map(|l| l.as_usize()).collect();

    // Locations occupied in CTI (both hypothesis and violating states).
    let cti_occupied: HashSet<&str> = cti
        .map(|c| {
            c.hypothesis_locations
                .iter()
                .chain(c.violating_locations.iter())
                .map(|(name, _)| name.as_str())
                .collect()
        })
        .unwrap_or_default();

    // Find the population parameter "n" (first param, or by name).
    let n_param = ta
        .parameters
        .iter()
        .enumerate()
        .find(|(_, p)| p.name == "n")
        .map(|(id, _)| id);

    let relevant_locs = property_relevant_location_set(property);

    // --- Category 1: Zero-location candidates ---
    // For each non-initial location not occupied in CTI.
    for (id, loc) in ta.locations.iter().enumerate() {
        if initial_set.contains(&id) {
            continue;
        }
        if cti_occupied.contains(loc.name.as_str()) {
            continue;
        }
        let pred = CandidatePredicate::zero_location(id, &loc.name);
        // Boost property-relevant locations to front (by inserting earlier).
        if relevant_locs.contains(&id) {
            candidates.insert(0, pred);
        } else {
            candidates.push(pred);
        }
    }

    // --- Category 2: Per-location upper bounds (kappa_l <= n) ---
    if let Some(n_id) = n_param {
        let n_name = &ta.parameters[n_id].name;
        for (id, loc) in ta.locations.iter().enumerate() {
            candidates.push(CandidatePredicate::kappa_le_param(
                id, &loc.name, n_id, n_name,
            ));
        }
    }

    // --- Category 3: Pairwise location sum bounds ---
    // Only for non-initial location pairs where both are property-relevant
    // or appear in different roles/phases.
    if let Some(n_id) = n_param {
        let n_name = &ta.parameters[n_id].name;
        let non_initial: Vec<(usize, &str)> = ta
            .locations
            .iter()
            .enumerate()
            .filter(|(id, _)| !initial_set.contains(id))
            .map(|(id, loc)| (id, loc.name.as_str()))
            .collect();
        for i in 0..non_initial.len() {
            for j in (i + 1)..non_initial.len() {
                let (id_a, name_a) = non_initial[i];
                let (id_b, name_b) = non_initial[j];
                // Prioritize pairs where at least one is property-relevant.
                if relevant_locs.contains(&id_a) || relevant_locs.contains(&id_b) {
                    candidates.push(CandidatePredicate::kappa_sum_le_param(
                        &[(id_a, name_a), (id_b, name_b)],
                        n_id,
                        n_name,
                    ));
                }
            }
        }
    }

    // --- Category 4: Shared variable bounds ---
    for (id, var) in ta.shared_vars.iter().enumerate() {
        candidates.push(CandidatePredicate::gamma_ge_zero(id, &var.name));
        if let Some(n_id) = n_param {
            let n_name = &ta.parameters[n_id].name;
            candidates.push(CandidatePredicate::gamma_le_param(
                id, &var.name, n_id, n_name,
            ));
        }
    }

    candidates
}

// ---------------------------------------------------------------------------
// Inductiveness checks and candidate scoring (INV-03)
// ---------------------------------------------------------------------------

impl CandidatePredicate {
    /// Convert this predicate to an SMT term at a given step.
    ///
    /// Maps `Kappa(id)` → `kappa_{step}_{id}`, `Gamma(id)` → `g_{step}_{id}`,
    /// `Param(id)` → `p_{id}`, `Const(v)` → integer literal.
    pub(crate) fn to_smt_term(&self, step: usize) -> SmtTerm {
        let build_side = |terms: &[(i64, LinearTerm)]| -> SmtTerm {
            if terms.is_empty() {
                return SmtTerm::int(0);
            }
            let mut parts: Vec<SmtTerm> = terms
                .iter()
                .map(|(coeff, term)| {
                    let base = match term {
                        LinearTerm::Kappa(id) => SmtTerm::var(pdr_kappa_var(step, *id)),
                        LinearTerm::Gamma(id) => SmtTerm::var(pdr_gamma_var(step, *id)),
                        LinearTerm::Param(id) => SmtTerm::var(pdr_param_var(*id)),
                        LinearTerm::Const(v) => SmtTerm::int(*v),
                    };
                    if *coeff == 1 {
                        base
                    } else {
                        SmtTerm::int(*coeff).mul(base)
                    }
                })
                .collect();
            let mut result = parts.remove(0);
            for p in parts {
                result = result.add(p);
            }
            result
        };
        let lhs = build_side(&self.lhs);
        let rhs = build_side(&self.rhs);
        match self.op {
            PredicateOp::Eq => lhs.eq(rhs),
            PredicateOp::Le => lhs.le(rhs),
            PredicateOp::Ge => lhs.ge(rhs),
        }
    }
}

/// Result of checking a single candidate predicate for inductiveness.
#[derive(Debug, Clone)]
pub struct InductivenessResult {
    pub candidate: CandidatePredicate,
    /// True if the predicate holds at all initial states.
    pub holds_at_init: bool,
    /// True if the predicate is preserved by all transitions (consecution).
    pub is_inductive: bool,
    /// Combined score: 2 if fully inductive (init + consecution), 1 if init only, 0 otherwise.
    pub score: u32,
}

/// Check whether a candidate predicate holds at all initial states.
///
/// Encodes the system at depth 0 (just initial state) without property
/// violation, asserts ¬P, and checks satisfiability.
/// UNSAT means P holds at all initial states.
pub(crate) fn check_predicate_init<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    candidate: &CandidatePredicate,
    committee_bounds: &[(usize, u64)],
) -> Result<bool, PipelineError> {
    // Use a dummy agreement property with no conflicting pairs.
    // This produces a violation term `Or([])` = false, which we skip.
    // We need any SafetyProperty to generate the state encoding.
    let dummy_prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_bmc(cs, &dummy_prop, 0);
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    for (name, sort) in &encoding.declarations {
        solver
            .declare_var(name, sort)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    // Assert all state constraints but skip `false` literals (which arise
    // from empty property violation encodings).
    for assertion in &encoding.assertions {
        if matches!(assertion, SmtTerm::BoolLit(false)) {
            continue;
        }
        solver
            .assert(assertion)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    // Add committee bounds if any.
    for assertion in &committee_bound_assertions(committee_bounds) {
        solver
            .assert(assertion)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    // Assert ¬P at step 0.
    let negated = candidate.to_smt_term(0).not();
    solver
        .assert(&negated)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    let result = solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    Ok(matches!(result, SatResult::Unsat))
}

/// Check whether a candidate predicate is preserved by all transitions (consecution).
///
/// Encodes a single transition step (using k-induction step encoding at k=1),
/// asserts P at step 0 and ¬P at step 1, and checks satisfiability.
/// UNSAT means P is inductive (preserved by transitions).
pub(crate) fn check_predicate_consecution<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    candidate: &CandidatePredicate,
    committee_bounds: &[(usize, u64)],
) -> Result<bool, PipelineError> {
    let dummy_prop = SafetyProperty::Agreement {
        conflicting_pairs: vec![],
    };
    let encoding = encode_k_induction_step(cs, &dummy_prop, 1);
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    for (name, sort) in &encoding.declarations {
        solver
            .declare_var(name, sort)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    for assertion in &encoding.assertions {
        if matches!(assertion, SmtTerm::BoolLit(false) | SmtTerm::BoolLit(true)) {
            continue;
        }
        solver
            .assert(assertion)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    for assertion in &committee_bound_assertions(committee_bounds) {
        solver
            .assert(assertion)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    // Assert P holds at step 0.
    let p_at_0 = candidate.to_smt_term(0);
    solver
        .assert(&p_at_0)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    // Assert ¬P at step 1.
    let not_p_at_1 = candidate.to_smt_term(1).not();
    solver
        .assert(&not_p_at_1)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    let result = solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    Ok(matches!(result, SatResult::Unsat))
}

/// Score candidate predicates by checking init and consecution, returning results
/// sorted by score (highest first).
pub fn score_candidates<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    candidates: &[CandidatePredicate],
    committee_bounds: &[(usize, u64)],
) -> Result<Vec<InductivenessResult>, PipelineError> {
    let mut results = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let holds_at_init = check_predicate_init(solver, cs, candidate, committee_bounds)?;
        let is_inductive = if holds_at_init {
            check_predicate_consecution(solver, cs, candidate, committee_bounds)?
        } else {
            false
        };
        let score = if holds_at_init && is_inductive {
            2
        } else if holds_at_init {
            1
        } else {
            0
        };
        results.push(InductivenessResult {
            candidate: candidate.clone(),
            holds_at_init,
            is_inductive,
            score,
        });
    }
    results.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(results)
}

pub(crate) fn property_relevant_location_set(property: &SafetyProperty) -> HashSet<usize> {
    let mut locs = HashSet::new();
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            for (a, b) in conflicting_pairs {
                locs.insert(a.as_usize());
                locs.insert(b.as_usize());
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            for bad in bad_sets {
                for loc in bad {
                    locs.insert(loc.as_usize());
                }
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            for loc in goal_locs {
                locs.insert(loc.as_usize());
            }
        }
    }
    locs
}

pub(crate) fn cti_zero_location_candidates(
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

pub(crate) fn prove_location_unreachable_for_synthesis(
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    loc_id: usize,
) -> Result<bool, PipelineError> {
    let candidate = SafetyProperty::Invariant {
        bad_sets: vec![vec![loc_id.into()]],
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

pub(crate) struct CtiSynthesisContext<'a> {
    pub(crate) cs: &'a CounterSystem,
    pub(crate) options: &'a PipelineOptions,
    pub(crate) committee_bounds: &'a [(usize, u64)],
    pub(crate) max_refinements: usize,
    pub(crate) deadline: Option<Instant>,
}

pub(crate) fn synthesize_cti_zero_location_invariants(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    ctx: CtiSynthesisContext<'_>,
) -> Result<Vec<usize>, PipelineError> {
    let CtiSynthesisContext {
        cs,
        options,
        committee_bounds,
        max_refinements,
        deadline,
    } = ctx;
    let candidate_budget = (max_refinements.max(1)) * 2;
    let candidates = cti_zero_location_candidates(ta, property, cti, candidate_budget);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut synthesized_locs = Vec::new();
    for loc in candidates {
        let synthesis_options =
            match options_with_remaining_timeout(options, deadline, "CTI predicate synthesis") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Err(PipelineError::Solver(timeout_unknown_reason(
                        "CTI predicate synthesis",
                    )));
                }
            };

        if prove_location_unreachable_for_synthesis(cs, &synthesis_options, committee_bounds, loc)?
        {
            synthesized_locs.push(loc);
        }
        if synthesized_locs.len() >= max_refinements.max(1) {
            break;
        }
    }
    Ok(synthesized_locs)
}

// ---------------------------------------------------------------------------
// Prove pre-pass: infer-then-strengthen (INV-05)
// ---------------------------------------------------------------------------

/// Convert inductive predicates into per-step SMT assertions suitable for
/// injection into k-induction or PDR.
///
/// For a predicate `P`, this generates `P` instantiated at each step in
/// `0..=depth` (for base case / inductive step use).
pub fn predicate_assertions_for_depth(
    predicates: &[CandidatePredicate],
    depth: usize,
) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(predicates.len() * (depth + 1));
    for step in 0..=depth {
        for pred in predicates {
            assertions.push(pred.to_smt_term(step));
        }
    }
    assertions
}

/// Convert inductive predicates into step-relation assertions (steps 0 and 1)
/// for PDR-style encoding.
pub fn predicate_assertions_for_step_relation(predicates: &[CandidatePredicate]) -> Vec<SmtTerm> {
    let mut assertions = Vec::with_capacity(predicates.len() * 2);
    for pred in predicates {
        assertions.push(pred.to_smt_term(0));
        assertions.push(pred.to_smt_term(1));
    }
    assertions
}

/// Run invariant inference pre-pass: generate candidates, score them, and
/// return the fully inductive predicates (score == 2).
///
/// Returns an empty vec if no inductive invariants are found.
pub fn infer_inductive_predicates(
    ta: &ThresholdAutomaton,
    cs: &CounterSystem,
    property: &SafetyProperty,
    committee_bounds: &[(usize, u64)],
    options: &PipelineOptions,
) -> Result<Vec<CandidatePredicate>, PipelineError> {
    let candidates = generate_linear_predicate_candidates(ta, property, None);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let scored = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            score_candidates(&mut solver, cs, &candidates, committee_bounds)?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            score_candidates(&mut solver, cs, &candidates, committee_bounds)?
        }
    };

    let inductive: Vec<CandidatePredicate> = scored
        .into_iter()
        .filter(|r| r.score == 2)
        .map(|r| r.candidate)
        .collect();

    Ok(inductive)
}

/// Run an unbounded safety proof with an automatic invariant-inference
/// pre-pass that strengthens the induction hypothesis.
///
/// This is the main entry point for `prove --auto-strengthen`. It:
/// 1. Lowers the protocol and extracts the property.
/// 2. Runs invariant inference to discover inductive predicates.
/// 3. Injects those predicates as extra assertions into k-induction/PDR.
pub fn prove_safety_with_auto_strengthen(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
) -> Result<UnboundedSafetyResult, PipelineError> {
    reset_run_diagnostics();
    with_smt_profile("prove_safety_auto_strengthen", || {
        info!("Parsing {filename}...");
        let program = parse(source, filename)?;
        if !has_safety_properties(&program) && has_liveness_properties(&program) {
            return Err(PipelineError::Validation(
                "Auto-strengthened safety proof is safety-only, but this protocol declares \
                 only liveness properties. Use `prove-fair` for liveness proofs."
                    .into(),
            ));
        }
        preflight_validate(&program, options, PipelineCommand::Verify)?;

        info!("Lowering to threshold automaton...");
        let mut ta = lower_with_active_controls(&program, "prove_safety_auto_strengthen")?;
        ensure_n_parameter(&ta)?;

        let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
        let has_committees = !committee_summaries.is_empty();
        let committee_bounds: Vec<(usize, u64)> = ta
            .constraints
            .committees
            .iter()
            .zip(committee_summaries.iter())
            .filter_map(|(spec, summary)| {
                spec.bound_param.map(|pid| (pid.as_usize(), summary.b_max))
            })
            .collect();

        if has_committees && committee_bounds.is_empty() {
            return Ok(UnboundedSafetyResult::Unknown {
                reason: "Committee analysis present, but no bound_param specified.".into(),
            });
        }

        let property = extract_property(&ta, &program, options.soundness)?;
        let cs = abstract_to_cs(ta.clone());

        // --- Invariant inference pre-pass ---
        info!("Running invariant inference pre-pass...");
        let inductive_preds =
            infer_inductive_predicates(&ta, &cs, &property, &committee_bounds, options)?;

        let num_inductive = inductive_preds.len();
        if num_inductive > 0 {
            info!(
                count = num_inductive,
                "Discovered inductive strengthening predicates."
            );
            for pred in &inductive_preds {
                push_reduction_note(&format!("auto_strengthen.invariant={}", pred.label));
            }
        } else {
            info!("No inductive predicates discovered; proceeding without strengthening.");
        }

        // --- Run proof with injected invariants ---
        info!(
            solver = ?options.solver,
            proof_engine = ?options.proof_engine,
            max_k = options.max_depth,
            "Starting auto-strengthened unbounded safety proof..."
        );

        let kind_result = if inductive_preds.is_empty() {
            // No invariants found — fall back to standard proof.
            match options.solver {
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
            }
        } else {
            // Inject invariant assertions.
            let deadline = overall_timeout_duration(options.timeout_secs)
                .and_then(|t| Instant::now().checked_add(t));
            let mut extra = committee_bound_assertions(&committee_bounds);

            match options.proof_engine {
                ProofEngine::KInduction => {
                    // For k-induction, we inject per-step invariant assertions
                    // via a custom loop that adds them at each depth.
                    match options.solver {
                        SolverChoice::Z3 => {
                            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                            run_k_induction_with_predicate_invariants(
                                &mut solver,
                                &cs,
                                &property,
                                options.max_depth,
                                &extra,
                                &inductive_preds,
                                deadline,
                            )
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                        }
                        SolverChoice::Cvc5 => {
                            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                                .map_err(|e| PipelineError::Solver(e.to_string()))?;
                            run_k_induction_with_predicate_invariants(
                                &mut solver,
                                &cs,
                                &property,
                                options.max_depth,
                                &extra,
                                &inductive_preds,
                                deadline,
                            )
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                        }
                    }
                }
                ProofEngine::Pdr | ProofEngine::Ranking => {
                    // For PDR, add step-relation invariant assertions as extra.
                    extra.extend(predicate_assertions_for_step_relation(&inductive_preds));
                    match options.solver {
                        SolverChoice::Z3 => {
                            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
                            run_pdr_with_deadline(
                                &mut solver,
                                &cs,
                                &property,
                                options.max_depth,
                                &extra,
                                deadline,
                            )
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                        }
                        SolverChoice::Cvc5 => {
                            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
                            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                                .map_err(|e| PipelineError::Solver(e.to_string()))?;
                            run_pdr_with_deadline(
                                &mut solver,
                                &cs,
                                &property,
                                options.max_depth,
                                &extra,
                                deadline,
                            )
                            .map_err(|e| PipelineError::Solver(e.to_string()))?
                        }
                    }
                }
            }
        };

        Ok(kind_result_to_unbounded_safety(
            kind_result,
            &cs,
            &property,
            &committee_bounds,
            &committee_summaries,
            options,
        ))
    })
}

/// K-induction loop with predicate invariant strengthening.
///
/// Like `run_k_induction_with_location_invariants` but for arbitrary predicates
/// instead of just zero-location assertions.
fn run_k_induction_with_predicate_invariants<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    base_extra_assertions: &[SmtTerm],
    invariant_predicates: &[CandidatePredicate],
    deadline: Option<Instant>,
) -> Result<KInductionResult, S::Error> {
    if max_k == 0 {
        return Ok(KInductionResult::NotProved { max_k, cti: None });
    }

    let mut first_cti: Option<KInductionCti> = None;

    for k in 1..=max_k {
        if crate::sandbox::enforce_active_limits().is_err() {
            return Ok(KInductionResult::Unknown {
                reason: "Sandbox resource limit exceeded during k-induction.".into(),
            });
        }
        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: timeout_unknown_reason("k-induction"),
            });
        }

        // --- Base case: check steps 0..=k ---
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
            // Inject invariant predicates at each step.
            for inv in predicate_assertions_for_depth(invariant_predicates, depth) {
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

        // --- Inductive step: assume P holds at steps 0..k, check step k ---
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
        // Inject invariant predicates at each step of the induction window.
        for inv in predicate_assertions_for_depth(invariant_predicates, k) {
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

#[cfg(test)]
mod tests;
