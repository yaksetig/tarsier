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

pub(crate) fn synthesize_cti_zero_location_invariants(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    max_refinements: usize,
    deadline: Option<Instant>,
) -> Result<Vec<usize>, PipelineError> {
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
mod tests {
    use super::*;
    use tarsier_ir::counter_system::Configuration;
    use tarsier_ir::threshold_automaton::{Location, SharedVar, SharedVarKind};

    fn make_test_ta() -> ThresholdAutomaton {
        ThresholdAutomaton {
            locations: vec![
                Location {
                    name: "Init".into(),
                    role: "R".into(),
                    phase: "p0".into(),
                    local_vars: Default::default(),
                },
                Location {
                    name: "Sent".into(),
                    role: "R".into(),
                    phase: "p1".into(),
                    local_vars: Default::default(),
                },
                Location {
                    name: "Decided".into(),
                    role: "R".into(),
                    phase: "p2".into(),
                    local_vars: Default::default(),
                },
            ],
            initial_locations: vec![0.into()],
            shared_vars: vec![SharedVar {
                name: "msgs".into(),
                kind: SharedVarKind::MessageCounter,
                distinct: false,
                distinct_role: None,
            }],
            parameters: vec![
                tarsier_ir::threshold_automaton::Parameter {
                    name: "n".into(),
                    time_varying: false,
                },
                tarsier_ir::threshold_automaton::Parameter {
                    name: "t".into(),
                    time_varying: false,
                },
                tarsier_ir::threshold_automaton::Parameter {
                    name: "f".into(),
                    time_varying: false,
                },
            ],
            ..ThresholdAutomaton::default()
        }
    }

    #[test]
    fn generate_candidates_produces_zero_location_for_non_initial() {
        let ta = make_test_ta();
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(1.into(), 2.into())],
        };
        let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
        // Should have zero-location candidates for Sent and Decided (not Init).
        let zero_labels: Vec<&str> = candidates
            .iter()
            .filter(|c| {
                c.op == PredicateOp::Eq && matches!(c.rhs.as_slice(), [(1, LinearTerm::Const(0))])
            })
            .map(|c| c.label.as_str())
            .collect();
        assert!(zero_labels.contains(&"kappa_Sent = 0"));
        assert!(zero_labels.contains(&"kappa_Decided = 0"));
        assert!(!zero_labels.iter().any(|l| l.contains("Init")));
    }

    #[test]
    fn generate_candidates_includes_upper_bounds() {
        let ta = make_test_ta();
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![2.into()]],
        };
        let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
        let has_kappa_le_n = candidates.iter().any(|c| c.label == "kappa_Init <= n");
        assert!(has_kappa_le_n);
    }

    #[test]
    fn generate_candidates_includes_shared_var_bounds() {
        let ta = make_test_ta();
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![2.into()]],
        };
        let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
        assert!(candidates.iter().any(|c| c.label == "gamma_msgs >= 0"));
        assert!(candidates.iter().any(|c| c.label == "gamma_msgs <= n"));
    }

    #[test]
    fn generate_candidates_includes_pairwise_sums() {
        let ta = make_test_ta();
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(1.into(), 2.into())],
        };
        let candidates = generate_linear_predicate_candidates(&ta, &prop, None);
        assert!(candidates
            .iter()
            .any(|c| c.label == "kappa_Sent + kappa_Decided <= n"));
    }

    #[test]
    fn generate_candidates_cti_filters_occupied_locations() {
        let ta = make_test_ta();
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(1.into(), 2.into())],
        };
        let cti = InductionCtiSummary {
            k: 1,
            params: vec![("n".into(), 4), ("t".into(), 1), ("f".into(), 1)],
            hypothesis_locations: vec![("Sent".into(), 2)],
            hypothesis_shared: vec![],
            violating_locations: vec![("Decided".into(), 1)],
            violating_shared: vec![],
            final_step_rules: vec![],
            violated_condition: String::new(),
            classification: CtiClassification::LikelySpurious,
            classification_evidence: vec![],
            rationale: String::new(),
        };
        let candidates = generate_linear_predicate_candidates(&ta, &prop, Some(&cti));
        // Zero-location candidates for Sent and Decided should be excluded (CTI-occupied).
        let zero_labels: Vec<&str> = candidates
            .iter()
            .filter(|c| {
                c.op == PredicateOp::Eq && matches!(c.rhs.as_slice(), [(1, LinearTerm::Const(0))])
            })
            .map(|c| c.label.as_str())
            .collect();
        assert!(!zero_labels.contains(&"kappa_Sent = 0"));
        assert!(!zero_labels.contains(&"kappa_Decided = 0"));
    }

    #[test]
    fn candidate_predicate_evaluate_zero_location() {
        let pred = CandidatePredicate::zero_location(1, "Sent");
        let config_zero = Configuration {
            kappa: vec![3, 0, 1],
            gamma: vec![],
            params: vec![4],
        };
        assert!(pred.evaluate(&config_zero));
        let config_nonzero = Configuration {
            kappa: vec![3, 2, 1],
            gamma: vec![],
            params: vec![4],
        };
        assert!(!pred.evaluate(&config_nonzero));
    }

    #[test]
    fn candidate_predicate_evaluate_le_param() {
        let pred = CandidatePredicate::kappa_le_param(0, "Init", 0, "n");
        let config_ok = Configuration {
            kappa: vec![3],
            gamma: vec![],
            params: vec![4],
        };
        assert!(pred.evaluate(&config_ok));
        let config_bad = Configuration {
            kappa: vec![5],
            gamma: vec![],
            params: vec![4],
        };
        assert!(!pred.evaluate(&config_bad));
    }

    #[test]
    fn to_smt_term_zero_location() {
        let pred = CandidatePredicate::zero_location(2, "Decided");
        let term = pred.to_smt_term(0);
        // Should be: kappa_0_2 = 0
        let expected = SmtTerm::var("kappa_0_2").eq(SmtTerm::int(0));
        assert_eq!(term, expected);
    }

    #[test]
    fn to_smt_term_le_param() {
        let pred = CandidatePredicate::kappa_le_param(1, "Sent", 0, "n");
        let term = pred.to_smt_term(3);
        // Should be: kappa_3_1 <= p_0
        let expected = SmtTerm::var("kappa_3_1").le(SmtTerm::var("p_0"));
        assert_eq!(term, expected);
    }

    #[test]
    fn to_smt_term_pairwise_sum() {
        let pred = CandidatePredicate::kappa_sum_le_param(&[(1, "Sent"), (2, "Decided")], 0, "n");
        let term = pred.to_smt_term(0);
        // Should be: (kappa_0_1 + kappa_0_2) <= p_0
        let expected = SmtTerm::var("kappa_0_1")
            .add(SmtTerm::var("kappa_0_2"))
            .le(SmtTerm::var("p_0"));
        assert_eq!(term, expected);
    }

    #[test]
    fn to_smt_term_gamma_ge_zero() {
        let pred = CandidatePredicate::gamma_ge_zero(0, "msgs");
        let term = pred.to_smt_term(1);
        // Should be: g_1_0 >= 0
        let expected = SmtTerm::var("g_1_0").ge(SmtTerm::int(0));
        assert_eq!(term, expected);
    }

    /// Build a minimal ThresholdAutomaton suitable for solver-based tests.
    /// Two locations (Init, Done), one shared var, one rule Init→Done.
    fn make_solver_test_ta() -> ThresholdAutomaton {
        use tarsier_ir::threshold_automaton::*;
        ThresholdAutomaton {
            locations: vec![
                Location {
                    name: "Init".into(),
                    role: "R".into(),
                    phase: "p0".into(),
                    local_vars: Default::default(),
                },
                Location {
                    name: "Done".into(),
                    role: "R".into(),
                    phase: "p1".into(),
                    local_vars: Default::default(),
                },
            ],
            initial_locations: vec![0.into()],
            shared_vars: vec![],
            rules: vec![Rule {
                from: 0.into(),
                to: 1.into(),
                guard: Guard { atoms: vec![] },
                updates: vec![],
                collection_updates: vec![],
                clock_guards: vec![],
                clock_updates: vec![],
                param_updates: vec![],
            }],
            parameters: vec![Parameter {
                name: "n".into(),
                time_varying: false,
            }],
            constraints: ThresholdAutomatonConstraints {
                resilience_condition: None,
                adversary_bound_param: None,
                committees: vec![],
            },
            ..ThresholdAutomaton::default()
        }
    }

    #[test]
    fn check_init_zero_non_initial_location_holds() {
        // kappa_Done = 0 should hold at init (all processes start at Init).
        let ta = make_solver_test_ta();
        let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
        let pred = CandidatePredicate::zero_location(1, "Done");
        let mut solver = Z3Solver::with_timeout_secs(10);
        let result = check_predicate_init(&mut solver, &cs, &pred, &[]).unwrap();
        assert!(result, "kappa_Done = 0 should hold at init");
    }

    #[test]
    fn check_init_zero_initial_location_fails_with_resilience() {
        // kappa_Init = 0 should NOT hold at init when n >= 1
        // (processes start at Init, so kappa_Init = n >= 1).
        use tarsier_ir::threshold_automaton::{
            CmpOp as IrCmpOp, LinearCombination, LinearConstraint, ParamId,
        };
        let mut ta = make_solver_test_ta();
        // Add resilience condition: n >= 1 (so there's at least one process).
        ta.constraints.resilience_condition = Some(LinearConstraint {
            lhs: LinearCombination {
                terms: vec![(1, ParamId::new(0))],
                constant: 0,
            },
            op: IrCmpOp::Ge,
            rhs: LinearCombination {
                terms: vec![],
                constant: 1,
            },
        });
        let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
        let pred = CandidatePredicate::zero_location(0, "Init");
        let mut solver = Z3Solver::with_timeout_secs(10);
        let result = check_predicate_init(&mut solver, &cs, &pred, &[]).unwrap();
        assert!(
            !result,
            "kappa_Init = 0 should NOT hold at init when n >= 1"
        );
    }

    #[test]
    fn score_candidates_ranks_by_inductiveness() {
        let ta = make_solver_test_ta();
        let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
        let candidates = vec![
            CandidatePredicate::zero_location(0, "Init"), // fails init
            CandidatePredicate::kappa_le_param(0, "Init", 0, "n"), // kappa_Init <= n: should be inductive
        ];
        let mut solver = Z3Solver::with_timeout_secs(10);
        let results = score_candidates(&mut solver, &cs, &candidates, &[]).unwrap();
        // The inductive candidate (kappa_Init <= n) should score higher.
        assert!(results[0].score >= results[1].score);
        assert!(results[0].holds_at_init);
    }

    #[test]
    fn property_relevant_location_set_agreement() {
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0.into(), 1.into()), (2.into(), 3.into())],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 4);
        assert!(locs.contains(&0));
        assert!(locs.contains(&1));
        assert!(locs.contains(&2));
        assert!(locs.contains(&3));
    }

    #[test]
    fn property_relevant_location_set_invariant() {
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![5.into(), 6.into()], vec![7.into()]],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 3);
        assert!(locs.contains(&5));
        assert!(locs.contains(&6));
        assert!(locs.contains(&7));
    }

    #[test]
    fn property_relevant_location_set_termination() {
        let prop = SafetyProperty::Termination {
            goal_locs: vec![10.into(), 20.into()],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 2);
        assert!(locs.contains(&10));
        assert!(locs.contains(&20));
    }

    // --- INV-05 tests: pre-pass integration ---

    #[test]
    fn predicate_assertions_for_depth_generates_correct_count() {
        let preds = vec![
            CandidatePredicate::zero_location(1, "Sent"),
            CandidatePredicate::gamma_ge_zero(0, "msgs"),
        ];
        let assertions = predicate_assertions_for_depth(&preds, 3);
        // 2 predicates × 4 steps (0..=3) = 8
        assert_eq!(assertions.len(), 8);
    }

    #[test]
    fn predicate_assertions_for_step_relation_generates_pairs() {
        let preds = vec![CandidatePredicate::zero_location(1, "Sent")];
        let assertions = predicate_assertions_for_step_relation(&preds);
        // 1 predicate × 2 steps (0, 1)
        assert_eq!(assertions.len(), 2);
    }

    #[test]
    fn infer_inductive_predicates_returns_only_fully_inductive() {
        let ta = make_solver_test_ta();
        let cs = abstract_to_cs(ta.clone());
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        let options = PipelineOptions::default();
        let result = infer_inductive_predicates(&ta, &cs, &prop, &[], &options).unwrap();
        // All returned predicates should be fully inductive (score == 2).
        // The exact count depends on the TA, but we should get at least some.
        // kappa_Init <= n should hold at init (all processes start there)
        // and be inductive (no rule can create more processes than n).
        for pred in &result {
            // Verify each returned predicate is actually inductive by re-checking.
            let mut solver = Z3Solver::with_timeout_secs(10);
            assert!(
                check_predicate_init(&mut solver, &cs, pred, &[]).unwrap(),
                "predicate {} should hold at init",
                pred.label
            );
            assert!(
                check_predicate_consecution(&mut solver, &cs, pred, &[]).unwrap(),
                "predicate {} should be inductive",
                pred.label
            );
        }
    }

    #[test]
    fn k_induction_with_predicate_invariants_proves_with_strengthening() {
        // Build a simple system (Init=0, Done=1) and verify that injecting
        // a known-inductive predicate allows k-induction to succeed.
        let ta = make_solver_test_ta();
        let cs = abstract_to_cs(ta.clone());
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![],
        };
        // kappa_Done <= n is inductive for this system.
        let invariants = vec![CandidatePredicate::kappa_le_param(1, "Done", 0, "n")];
        let mut solver = Z3Solver::with_timeout_secs(10);
        let result = run_k_induction_with_predicate_invariants(
            &mut solver,
            &cs,
            &prop,
            5,
            &[],
            &invariants,
            None,
        )
        .unwrap();
        // With empty conflicting_pairs and a valid invariant,
        // the property should be trivially provable.
        assert!(
            matches!(result, KInductionResult::Proved { .. }),
            "expected Proved, got {:?}",
            result
        );
    }
}
