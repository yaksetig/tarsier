//! SMT encoding for bounded simulation-preservation checking.
//!
//! Given a [`ProductAutomaton`] from the product construction (REF-03),
//! this module encodes the simulation check as a bounded reachability
//! problem in QF_LIA: can any mismatch state in the product be reached
//! within `k` steps? If SAT, the simulation relation is violated and the
//! solver model provides a concrete counterexample trace.

use tarsier_ir::product::{ProductAutomaton, ProductLocationId};
use tarsier_ir::threshold_automaton::{
    CmpOp, GuardAtom, LinearCombination, ParamId, SharedVarId, UpdateKind,
};

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
pub fn encode_refinement_check(
    product: &ProductAutomaton,
    depth: usize,
) -> RefinementEncoding {
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
fn encode_step_transition(
    enc: &mut RefinementEncoding,
    product: &ProductAutomaton,
    k: usize,
) {
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
        let from_idx = product.location_idx(&rule.from).unwrap();
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
fn encode_mismatch_target(
    enc: &mut RefinementEncoding,
    product: &ProductAutomaton,
    depth: usize,
) {
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
                CmpOp::Ne => SmtTerm::Not(Box::new(SmtTerm::Eq(
                    Box::new(lhs),
                    Box::new(rhs),
                ))),
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
    },
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
        assert_eq!(
            holds,
            SimulationCheckResult::SimulationHolds { depth: 5 }
        );

        let violated = SimulationCheckResult::SimulationViolated {
            depth: 3,
            violation_step: 2,
            mismatch_location: ProductLocationId {
                concrete: LocationId::from(1),
                abstract_loc: LocationId::from(0),
            },
        };
        assert!(matches!(
            violated,
            SimulationCheckResult::SimulationViolated { .. }
        ));
    }
}
