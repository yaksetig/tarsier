//! SMT encoding for bounded simulation-preservation checking.
//!
//! Given a [`ProductAutomaton`] from the product construction (REF-03),
//! this module encodes the simulation check as a bounded reachability
//! problem in QF_LIA: can any mismatch state in the product be reached
//! within `k` steps? If SAT, the simulation relation is violated and the
//! solver model provides a concrete counterexample trace.

use tarsier_ir::product::{ProductAutomaton, ProductLocationId};
use tarsier_ir::threshold_automaton::{
    CmpOp, GuardAtom, LinearCombination, SharedVarId, UpdateKind,
};

use tracing::info;

use crate::solver::{SatResult, SmtSolver};
use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

/// Variable declarations and assertions for the refinement BMC encoding.
#[derive(Debug)]
pub struct RefinementEncoding {
    /// Variable declarations: (name, sort).
    pub declarations: Vec<(String, SmtSort)>,
    /// Assertions (constraints).
    pub assertions: Vec<SmtTerm>,
}

impl RefinementEncoding {
    fn new() -> Self {
        Self {
            declarations: Vec::new(),
            assertions: Vec::new(),
        }
    }

    fn declare(&mut self, name: String, sort: SmtSort) {
        self.declarations.push((name, sort));
    }

    fn assert_term(&mut self, term: SmtTerm) {
        self.assertions.push(term);
    }
}

// --- Variable naming for refinement encoding ---

/// Product location counter at step `step` for product location index `idx`.
fn prod_kappa(step: usize, idx: usize) -> String {
    format!("pk_{step}_{idx}")
}

/// Product shared variable at step `step` for variable `var`.
fn prod_gamma(step: usize, var: usize) -> String {
    format!("pg_{step}_{var}")
}

/// Product parameter variable for parameter `p`.
fn prod_param(p: usize) -> String {
    format!("pp_{p}")
}

/// Product rule firing count at step `step` for rule `r`.
fn prod_delta(step: usize, r: usize) -> String {
    format!("pd_{step}_{r}")
}

/// Encode the product automaton as a bounded reachability problem.
///
/// Returns a `RefinementEncoding` that is SAT iff a mismatch state in the
/// product automaton is reachable within `depth` steps, meaning the
/// simulation relation is violated.
pub fn encode_refinement_check(product: &ProductAutomaton, depth: usize) -> RefinementEncoding {
    let mut enc = RefinementEncoding::new();

    // --- 1. Declare parameters ---
    for (i, _param) in product.parameters.iter().enumerate() {
        enc.declare(prod_param(i), SmtSort::Int);
        // Parameters are positive.
        enc.assert_term(SmtTerm::Ge(
            Box::new(SmtTerm::var(prod_param(i))),
            Box::new(SmtTerm::int(1)),
        ));
    }

    // --- 2. Encode initial state (step 0) ---
    encode_initial_state(&mut enc, product);

    // --- 3. Encode transition relation for each step ---
    for k in 0..depth {
        encode_step_transition(&mut enc, product, k);
    }

    // --- 4. Encode mismatch reachability target ---
    encode_mismatch_target(&mut enc, product, depth);

    enc
}

/// Encode the initial state: product counters match the initial product locations.
fn encode_initial_state(enc: &mut RefinementEncoding, product: &ProductAutomaton) {
    // Declare product location counters at step 0.
    for (idx, _loc) in product.locations.iter().enumerate() {
        let var_name = prod_kappa(0, idx);
        enc.declare(var_name.clone(), SmtSort::Int);
        // Non-negative.
        enc.assert_term(SmtTerm::Ge(
            Box::new(SmtTerm::var(var_name)),
            Box::new(SmtTerm::int(0)),
        ));
    }

    // Declare shared variables at step 0.
    for (v, _sv) in product.shared_vars.iter().enumerate() {
        let var_name = prod_gamma(0, v);
        enc.declare(var_name.clone(), SmtSort::Int);
        // Shared vars start at 0.
        enc.assert_term(SmtTerm::Eq(
            Box::new(SmtTerm::var(var_name)),
            Box::new(SmtTerm::int(0)),
        ));
    }

    // Initial product locations have all processes; non-initial have zero.
    for (idx, loc) in product.locations.iter().enumerate() {
        let is_initial = product.initial_locations.contains(loc);
        if !is_initial {
            enc.assert_term(SmtTerm::Eq(
                Box::new(SmtTerm::var(prod_kappa(0, idx))),
                Box::new(SmtTerm::int(0)),
            ));
        }
    }

    // Total processes across initial locations must be positive.
    if !product.initial_locations.is_empty() {
        let init_sum = sum_of_vars(
            product
                .initial_locations
                .iter()
                .filter_map(|loc| product.location_idx(loc))
                .map(|idx| prod_kappa(0, idx)),
        );
        enc.assert_term(SmtTerm::Ge(Box::new(init_sum), Box::new(SmtTerm::int(1))));
    }
}

/// Encode a single step transition from step `k` to step `k+1`.
fn encode_step_transition(enc: &mut RefinementEncoding, product: &ProductAutomaton, k: usize) {
    let k_next = k + 1;

    // Declare counters at step k+1.
    for (idx, _loc) in product.locations.iter().enumerate() {
        let var_name = prod_kappa(k_next, idx);
        enc.declare(var_name.clone(), SmtSort::Int);
        enc.assert_term(SmtTerm::Ge(
            Box::new(SmtTerm::var(var_name)),
            Box::new(SmtTerm::int(0)),
        ));
    }

    // Declare shared variables at step k+1.
    for (v, _sv) in product.shared_vars.iter().enumerate() {
        let var_name = prod_gamma(k_next, v);
        enc.declare(var_name.clone(), SmtSort::Int);
    }

    // Declare rule firing counts at step k.
    for (r, _rule) in product.rules.iter().enumerate() {
        let var_name = prod_delta(k, r);
        enc.declare(var_name.clone(), SmtSort::Int);
        enc.assert_term(SmtTerm::Ge(
            Box::new(SmtTerm::var(var_name)),
            Box::new(SmtTerm::int(0)),
        ));
    }

    // Counter update: kappa[k+1][loc] = kappa[k][loc] + sum(delta for rules into loc) - sum(delta for rules out of loc)
    for (idx, loc) in product.locations.iter().enumerate() {
        let mut incoming = Vec::new();
        let mut outgoing = Vec::new();

        for (r, rule) in product.rules.iter().enumerate() {
            if rule.to == *loc {
                incoming.push(SmtTerm::var(prod_delta(k, r)));
            }
            if rule.from == *loc {
                outgoing.push(SmtTerm::var(prod_delta(k, r)));
            }
        }

        // kappa[k+1] = kappa[k] + sum(incoming) - sum(outgoing)
        let mut rhs: SmtTerm = SmtTerm::var(prod_kappa(k, idx));
        for inc in incoming {
            rhs = SmtTerm::Add(Box::new(rhs), Box::new(inc));
        }
        for out in outgoing {
            rhs = SmtTerm::Sub(Box::new(rhs), Box::new(out));
        }

        enc.assert_term(SmtTerm::Eq(
            Box::new(SmtTerm::var(prod_kappa(k_next, idx))),
            Box::new(rhs),
        ));
    }

    // Guard constraints: firing delta > 0 implies guard must hold.
    for (r, rule) in product.rules.iter().enumerate() {
        // Safety: rule.from must exist in product.locations by construction.
        let from_idx = product
            .location_idx(&rule.from)
            .expect("product rule references a location not in the product (invariant violation)");
        let delta = SmtTerm::var(prod_delta(k, r));

        // delta <= kappa[k][from] (can't fire more than available processes)
        enc.assert_term(SmtTerm::Le(
            Box::new(delta.clone()),
            Box::new(SmtTerm::var(prod_kappa(k, from_idx))),
        ));

        // Guard encoding: for each guard atom, delta > 0 implies atom holds.
        for atom in &rule.guard.atoms {
            let guard_term = encode_guard_atom(atom, k, &product.parameters);
            // delta > 0 => guard
            enc.assert_term(SmtTerm::Implies(
                Box::new(SmtTerm::Gt(
                    Box::new(SmtTerm::var(prod_delta(k, r))),
                    Box::new(SmtTerm::int(0)),
                )),
                Box::new(guard_term),
            ));
        }
    }

    // Shared variable updates: combine all rule updates.
    for (v, _sv) in product.shared_vars.iter().enumerate() {
        let var_id = SharedVarId::from(v);
        let mut delta_sum = SmtTerm::var(prod_gamma(k, v));

        for (r, rule) in product.rules.iter().enumerate() {
            // Check concrete updates.
            for upd in &rule.concrete_updates {
                if upd.var == var_id {
                    match &upd.kind {
                        UpdateKind::Increment => {
                            delta_sum = SmtTerm::Add(
                                Box::new(delta_sum),
                                Box::new(SmtTerm::var(prod_delta(k, r))),
                            );
                        }
                        UpdateKind::Set(_lc) => {
                            // Set semantics: if delta > 0, var = lc. Encoded as implication.
                            let lc_term = encode_lc(_lc, &product.parameters);
                            enc.assert_term(SmtTerm::Implies(
                                Box::new(SmtTerm::Gt(
                                    Box::new(SmtTerm::var(prod_delta(k, r))),
                                    Box::new(SmtTerm::int(0)),
                                )),
                                Box::new(SmtTerm::Eq(
                                    Box::new(SmtTerm::var(prod_gamma(k_next, v))),
                                    Box::new(lc_term),
                                )),
                            ));
                        }
                    }
                }
            }
            // Check abstract updates.
            for upd in &rule.abstract_updates {
                if upd.var == var_id {
                    match &upd.kind {
                        UpdateKind::Increment => {
                            delta_sum = SmtTerm::Add(
                                Box::new(delta_sum),
                                Box::new(SmtTerm::var(prod_delta(k, r))),
                            );
                        }
                        UpdateKind::Set(_lc) => {
                            let lc_term = encode_lc(_lc, &product.parameters);
                            enc.assert_term(SmtTerm::Implies(
                                Box::new(SmtTerm::Gt(
                                    Box::new(SmtTerm::var(prod_delta(k, r))),
                                    Box::new(SmtTerm::int(0)),
                                )),
                                Box::new(SmtTerm::Eq(
                                    Box::new(SmtTerm::var(prod_gamma(k_next, v))),
                                    Box::new(lc_term),
                                )),
                            ));
                        }
                    }
                }
            }
        }

        // For increment-only variables, the cumulative sum is the next value.
        // This is a simplified encoding; Set-updates override via implication above.
        let has_set_update = product.rules.iter().any(|rule| {
            rule.concrete_updates
                .iter()
                .chain(rule.abstract_updates.iter())
                .any(|upd| upd.var == var_id && matches!(upd.kind, UpdateKind::Set(_)))
        });

        if !has_set_update {
            enc.assert_term(SmtTerm::Eq(
                Box::new(SmtTerm::var(prod_gamma(k_next, v))),
                Box::new(delta_sum),
            ));
        }
    }
}

/// Encode mismatch reachability: at some step, a mismatch location has processes.
fn encode_mismatch_target(enc: &mut RefinementEncoding, product: &ProductAutomaton, depth: usize) {
    if product.mismatch_locations.is_empty() {
        // No mismatches possible — simulation trivially holds.
        // Assert false to make the formula UNSAT.
        enc.assert_term(SmtTerm::BoolLit(false));
        return;
    }

    // At least one mismatch location has > 0 processes at some step.
    let mut mismatch_disjuncts = Vec::new();
    for step in 0..=depth {
        for mismatch in &product.mismatch_locations {
            if let Some(idx) = product.location_idx(mismatch) {
                mismatch_disjuncts.push(SmtTerm::Gt(
                    Box::new(SmtTerm::var(prod_kappa(step, idx))),
                    Box::new(SmtTerm::int(0)),
                ));
            }
        }
    }

    enc.assert_term(SmtTerm::Or(mismatch_disjuncts));
}

/// Encode a guard atom into an SMT term.
fn encode_guard_atom(
    atom: &GuardAtom,
    step: usize,
    params: &[tarsier_ir::threshold_automaton::Parameter],
) -> SmtTerm {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct: _,
        } => {
            // Sum of shared variables.
            let lhs = if vars.is_empty() {
                SmtTerm::int(0)
            } else {
                sum_of_vars(vars.iter().map(|v| prod_gamma(step, v.as_usize())))
            };

            let rhs = encode_lc(bound, params);

            match op {
                CmpOp::Ge => SmtTerm::Ge(Box::new(lhs), Box::new(rhs)),
                CmpOp::Le => SmtTerm::Le(Box::new(lhs), Box::new(rhs)),
                CmpOp::Gt => SmtTerm::Gt(Box::new(lhs), Box::new(rhs)),
                CmpOp::Lt => SmtTerm::Lt(Box::new(lhs), Box::new(rhs)),
                CmpOp::Eq => SmtTerm::Eq(Box::new(lhs), Box::new(rhs)),
                CmpOp::Ne => SmtTerm::Not(Box::new(SmtTerm::Eq(Box::new(lhs), Box::new(rhs)))),
            }
        }
    }
}

/// Encode a linear combination as an SMT term.
fn encode_lc(
    lc: &LinearCombination,
    _params: &[tarsier_ir::threshold_automaton::Parameter],
) -> SmtTerm {
    let mut result = SmtTerm::int(lc.constant);
    for &(coeff, param_id) in &lc.terms {
        let param_term = SmtTerm::var(prod_param(param_id.as_usize()));
        let scaled = if coeff == 1 {
            param_term
        } else {
            SmtTerm::Mul(Box::new(SmtTerm::int(coeff)), Box::new(param_term))
        };
        result = SmtTerm::Add(Box::new(result), Box::new(scaled));
    }
    result
}

/// Helper: build a sum of variable references.
fn sum_of_vars(names: impl Iterator<Item = String>) -> SmtTerm {
    let mut terms: Vec<SmtTerm> = names.map(SmtTerm::var).collect();
    if terms.is_empty() {
        return SmtTerm::int(0);
    }
    let mut acc = terms.remove(0);
    for t in terms {
        acc = SmtTerm::Add(Box::new(acc), Box::new(t));
    }
    acc
}

/// A snapshot of the product automaton state at a single step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessStep {
    /// Step index (0 = initial state).
    pub step: usize,
    /// Counter value for each product location at this step.
    /// Index corresponds to the product's location list.
    pub location_counters: Vec<(ProductLocationId, i64)>,
    /// Shared variable values at this step.
    /// Entries are `(var_index, value)`.
    pub shared_var_values: Vec<(usize, i64)>,
    /// Rule firing counts from this step to the next (empty for the last step).
    /// Entries are `(rule_index, firing_count)`.
    pub rule_firings: Vec<(usize, i64)>,
}

/// A full counterexample/witness trace for a violated simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinementWitness {
    /// The depth at which the violation was found.
    pub depth: usize,
    /// The step at which the mismatch was first reached.
    pub violation_step: usize,
    /// The mismatch product location that was reached.
    pub mismatch_location: ProductLocationId,
    /// Parameter values in the witness.
    pub parameter_values: Vec<(usize, i64)>,
    /// Step-by-step trace from initial state to the violation.
    pub trace: Vec<WitnessStep>,
}

/// Result of a refinement simulation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationCheckResult {
    /// No mismatch reachable within the bound — simulation holds up to depth `k`.
    SimulationHolds { depth: usize },
    /// A mismatch state is reachable — simulation is violated.
    SimulationViolated {
        depth: usize,
        /// Step at which the violation was found.
        violation_step: usize,
        /// The mismatch product location that was reached.
        mismatch_location: ProductLocationId,
        /// Full witness trace (if model extraction succeeded).
        witness: Option<RefinementWitness>,
    },
    /// Solver returned unknown (e.g., timeout).
    Unknown { depth: usize, reason: String },
}

/// Run the refinement simulation check against an SMT solver.
///
/// Encodes the product automaton at the given `depth`, feeds the encoding to
/// the solver, and interprets the result:
/// - **UNSAT** → simulation holds up to `depth`
/// - **SAT** → simulation violated; extracts violation step and mismatch location
/// - **Unknown** → solver could not decide (e.g., timeout)
pub fn run_refinement_solver<S: SmtSolver>(
    solver: &mut S,
    product: &ProductAutomaton,
    depth: usize,
) -> Result<SimulationCheckResult, S::Error> {
    // Trivial case: no mismatches → simulation holds without calling solver.
    if product.mismatch_locations.is_empty() {
        return Ok(SimulationCheckResult::SimulationHolds { depth });
    }

    info!(depth, mismatches = product.mismatch_locations.len(), "refinement: encoding product");

    let encoding = encode_refinement_check(product, depth);

    solver.reset()?;

    // Declare all variables.
    for (name, sort) in &encoding.declarations {
        solver.declare_var(name, sort)?;
    }

    // Assert all constraints.
    for assertion in &encoding.assertions {
        solver.assert(assertion)?;
    }

    // Build variable list for model extraction.
    let var_refs: Vec<(&str, &SmtSort)> = encoding
        .declarations
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();

    let (result, model) = solver.check_sat_with_model(&var_refs)?;

    match result {
        SatResult::Sat => {
            info!(depth, "refinement: VIOLATED - mismatch reachable");
            let (violation_step, mismatch_loc) = extract_violation(product, depth, &model);
            let witness = model
                .as_ref()
                .map(|m| extract_witness(product, depth, violation_step, &mismatch_loc, m));
            Ok(SimulationCheckResult::SimulationViolated {
                depth,
                violation_step,
                mismatch_location: mismatch_loc,
                witness,
            })
        }
        SatResult::Unsat => {
            info!(depth, "refinement: HOLDS up to depth");
            Ok(SimulationCheckResult::SimulationHolds { depth })
        }
        SatResult::Unknown(reason) => {
            info!(depth, %reason, "refinement: solver returned unknown");
            Ok(SimulationCheckResult::Unknown { depth, reason })
        }
    }
}

/// Extract the violation step and mismatch location from a SAT model.
fn extract_violation(
    product: &ProductAutomaton,
    depth: usize,
    model: &Option<crate::solver::Model>,
) -> (usize, ProductLocationId) {
    let default_mismatch = product
        .mismatch_locations
        .first()
        .cloned()
        .unwrap_or(ProductLocationId {
            concrete: tarsier_ir::threshold_automaton::LocationId::from(0),
            abstract_loc: tarsier_ir::threshold_automaton::LocationId::from(0),
        });

    let Some(model) = model else {
        return (0, default_mismatch);
    };

    // Find the earliest step where a mismatch location counter > 0.
    for step in 0..=depth {
        for mismatch in &product.mismatch_locations {
            if let Some(idx) = product.location_idx(mismatch) {
                let var_name = prod_kappa(step, idx);
                if let Some(val) = model.get_int(&var_name) {
                    if val > 0 {
                        return (step, mismatch.clone());
                    }
                }
            }
        }
    }

    // Fallback: SAT but couldn't identify exact step (shouldn't happen).
    (0, default_mismatch)
}

/// Extract a full witness trace from a SAT model.
fn extract_witness(
    product: &ProductAutomaton,
    depth: usize,
    violation_step: usize,
    mismatch_location: &ProductLocationId,
    model: &crate::solver::Model,
) -> RefinementWitness {
    // Extract parameter values.
    let parameter_values: Vec<(usize, i64)> = (0..product.parameters.len())
        .filter_map(|p| {
            let val = model.get_int(&prod_param(p))?;
            Some((p, val))
        })
        .collect();

    // Extract step-by-step trace up to and including the violation step.
    let trace_depth = violation_step.min(depth);
    let mut trace = Vec::with_capacity(trace_depth + 1);

    for step in 0..=trace_depth {
        // Location counters at this step.
        let location_counters: Vec<(ProductLocationId, i64)> = product
            .locations
            .iter()
            .enumerate()
            .filter_map(|(idx, loc)| {
                let val = model.get_int(&prod_kappa(step, idx)).unwrap_or(0);
                if val != 0 {
                    Some((*loc, val))
                } else {
                    None
                }
            })
            .collect();

        // Shared variable values at this step.
        let shared_var_values: Vec<(usize, i64)> = (0..product.shared_vars.len())
            .filter_map(|v| {
                let val = model.get_int(&prod_gamma(step, v))?;
                Some((v, val))
            })
            .collect();

        // Rule firings from this step (not applicable for the last step).
        let rule_firings: Vec<(usize, i64)> = if step < trace_depth {
            (0..product.rules.len())
                .filter_map(|r| {
                    let val = model.get_int(&prod_delta(step, r)).unwrap_or(0);
                    if val > 0 {
                        Some((r, val))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        trace.push(WitnessStep {
            step,
            location_counters,
            shared_var_values,
            rule_firings,
        });
    }

    RefinementWitness {
        depth,
        violation_step,
        mismatch_location: mismatch_location.clone(),
        parameter_values,
        trace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::product::build_product;
    use tarsier_ir::refinement::{RefinementMapping, RefinementRelation};
    use tarsier_ir::threshold_automaton::*;

    fn minimal_ta(
        num_locations: usize,
        initial: &[usize],
        rules: Vec<(usize, usize)>,
    ) -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        for i in 0..num_locations {
            ta.add_location(Location {
                name: format!("L{i}"),
                role: "R".into(),
                phase: format!("P{i}"),
                local_vars: Default::default(),
            });
        }
        for &init in initial {
            ta.initial_locations.push(LocationId::from(init));
        }
        for (from, to) in rules {
            ta.add_rule(Rule {
                from: LocationId::from(from),
                to: LocationId::from(to),
                guard: Guard::trivial(),
                updates: vec![],
                collection_updates: vec![],
                clock_guards: vec![],
                clock_updates: vec![],
                param_updates: vec![],
            });
        }
        ta
    }

    #[test]
    fn encoding_produces_declarations_and_assertions() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        let enc = encode_refinement_check(&product, 2);

        assert!(!enc.declarations.is_empty());
        assert!(!enc.assertions.is_empty());
    }

    #[test]
    fn encoding_has_initial_state_constraints() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        let enc = encode_refinement_check(&product, 1);

        // Should declare pk_0_* variables for step 0.
        let step0_vars: Vec<_> = enc
            .declarations
            .iter()
            .filter(|(name, _)| name.starts_with("pk_0_"))
            .collect();
        assert_eq!(step0_vars.len(), product.num_locations());
    }

    #[test]
    fn encoding_has_mismatch_disjunction() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        assert!(product.has_mismatches());

        let enc = encode_refinement_check(&product, 1);

        // Should have an Or(...) assertion for mismatch reachability.
        let has_or = enc.assertions.iter().any(|t| matches!(t, SmtTerm::Or(_)));
        assert!(has_or, "encoding should contain a mismatch disjunction");
    }

    #[test]
    fn encoding_no_mismatches_asserts_false() {
        // Identity mapping on 1 location → no mismatches.
        let concrete = minimal_ta(1, &[0], vec![]);
        let abstract_ta = minimal_ta(1, &[0], vec![]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        assert!(!product.has_mismatches());

        let enc = encode_refinement_check(&product, 1);

        // Should assert false (trivially UNSAT → simulation holds).
        let has_false = enc
            .assertions
            .iter()
            .any(|t| matches!(t, SmtTerm::BoolLit(false)));
        assert!(has_false, "no-mismatch encoding should assert false");
    }

    #[test]
    fn encoding_declares_step_variables() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        let depth = 3;
        let enc = encode_refinement_check(&product, depth);

        // Should have delta variables for each step.
        for k in 0..depth {
            let deltas: Vec<_> = enc
                .declarations
                .iter()
                .filter(|(name, _)| name.starts_with(&format!("pd_{k}_")))
                .collect();
            assert_eq!(
                deltas.len(),
                product.num_rules(),
                "step {k} should have delta vars for each rule"
            );
        }
    }

    #[test]
    fn simulation_check_result_variants() {
        let holds = SimulationCheckResult::SimulationHolds { depth: 5 };
        assert_eq!(holds, SimulationCheckResult::SimulationHolds { depth: 5 });

        let violated = SimulationCheckResult::SimulationViolated {
            depth: 3,
            violation_step: 2,
            mismatch_location: ProductLocationId {
                concrete: LocationId::from(1),
                abstract_loc: LocationId::from(0),
            },
            witness: None,
        };
        assert!(matches!(
            violated,
            SimulationCheckResult::SimulationViolated { .. }
        ));
    }

    #[test]
    fn witness_step_construction() {
        let step = WitnessStep {
            step: 0,
            location_counters: vec![(
                ProductLocationId {
                    concrete: LocationId::from(0),
                    abstract_loc: LocationId::from(0),
                },
                3,
            )],
            shared_var_values: vec![(0, 5)],
            rule_firings: vec![(1, 2)],
        };
        assert_eq!(step.step, 0);
        assert_eq!(step.location_counters.len(), 1);
        assert_eq!(step.shared_var_values[0], (0, 5));
        assert_eq!(step.rule_firings[0], (1, 2));
    }

    #[test]
    fn refinement_witness_construction() {
        let witness = RefinementWitness {
            depth: 3,
            violation_step: 2,
            mismatch_location: ProductLocationId {
                concrete: LocationId::from(1),
                abstract_loc: LocationId::from(0),
            },
            parameter_values: vec![(0, 4)],
            trace: vec![
                WitnessStep {
                    step: 0,
                    location_counters: vec![(
                        ProductLocationId {
                            concrete: LocationId::from(0),
                            abstract_loc: LocationId::from(0),
                        },
                        4,
                    )],
                    shared_var_values: vec![],
                    rule_firings: vec![(0, 2)],
                },
                WitnessStep {
                    step: 1,
                    location_counters: vec![(
                        ProductLocationId {
                            concrete: LocationId::from(1),
                            abstract_loc: LocationId::from(0),
                        },
                        2,
                    )],
                    shared_var_values: vec![],
                    rule_firings: vec![],
                },
            ],
        };
        assert_eq!(witness.depth, 3);
        assert_eq!(witness.violation_step, 2);
        assert_eq!(witness.trace.len(), 2);
        assert_eq!(witness.parameter_values[0], (0, 4));
    }

    #[test]
    fn violated_result_includes_witness() {
        let result = SimulationCheckResult::SimulationViolated {
            depth: 1,
            violation_step: 1,
            mismatch_location: ProductLocationId {
                concrete: LocationId::from(0),
                abstract_loc: LocationId::from(1),
            },
            witness: Some(RefinementWitness {
                depth: 1,
                violation_step: 1,
                mismatch_location: ProductLocationId {
                    concrete: LocationId::from(0),
                    abstract_loc: LocationId::from(1),
                },
                parameter_values: vec![],
                trace: vec![],
            }),
        };
        match result {
            SimulationCheckResult::SimulationViolated { witness, .. } => {
                assert!(witness.is_some());
            }
            _ => panic!("expected SimulationViolated"),
        }
    }
}
