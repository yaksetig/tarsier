//! SMT encoding for bounded behavioral equivalence checking.
//!
//! Encodes both directions of the bisimulation check (A refines B, B refines A)
//! as bounded reachability problems. If either direction's encoding is SAT,
//! equivalence is violated.

use tarsier_ir::equivalence::EquivalenceProducts;

use crate::refinement_encoder::{
    encode_refinement_check, run_refinement_solver, RefinementEncoding, RefinementWitness,
    SimulationCheckResult,
};
use crate::solver::SmtSolver;

/// Bidirectional equivalence encoding: one per simulation direction.
#[derive(Debug)]
pub struct EquivalenceEncoding {
    /// Encoding for forward direction (A → B): SAT means A has behavior B cannot match.
    pub forward: RefinementEncoding,
    /// Encoding for backward direction (B → A): SAT means B has behavior A cannot match.
    pub backward: RefinementEncoding,
}

/// Result of a bounded equivalence check.
#[derive(Debug, Clone)]
pub enum EquivalenceCheckResult {
    /// Both directions hold up to the given depth.
    EquivalentUpTo { depth: usize },
    /// Forward simulation fails: A has behavior that B cannot match.
    ForwardDivergence {
        depth: usize,
        witness: Option<RefinementWitness>,
    },
    /// Backward simulation fails: B has behavior that A cannot match.
    BackwardDivergence {
        depth: usize,
        witness: Option<RefinementWitness>,
    },
    /// Both directions fail.
    BidirectionalDivergence {
        depth: usize,
        forward_witness: Option<RefinementWitness>,
        backward_witness: Option<RefinementWitness>,
    },
    /// Trivially equivalent — no mismatch locations in either product.
    TriviallyEquivalent,
    /// Solver returned unknown for at least one direction.
    Unknown { depth: usize, reason: String },
}

/// Encode the bounded equivalence check for both simulation directions.
///
/// Returns `None` if both products have no mismatches (trivially equivalent).
pub fn encode_equivalence_check(
    products: &EquivalenceProducts,
    depth: usize,
) -> EquivalenceEncoding {
    let forward = encode_refinement_check(&products.forward, depth);
    let backward = encode_refinement_check(&products.backward, depth);
    EquivalenceEncoding { forward, backward }
}

/// Run the equivalence solver on both directions and merge results.
///
/// Checks forward (A→B) and backward (B→A) simulation independently,
/// then combines the verdicts into a single `EquivalenceCheckResult`.
pub fn run_equivalence_solver<S: SmtSolver>(
    forward_solver: &mut S,
    backward_solver: &mut S,
    products: &EquivalenceProducts,
    depth: usize,
) -> Result<EquivalenceCheckResult, S::Error> {
    // Trivial case: no mismatches in either direction.
    if products.is_trivially_equivalent() {
        return Ok(EquivalenceCheckResult::TriviallyEquivalent);
    }

    let fwd_result = run_refinement_solver(forward_solver, &products.forward, depth)?;
    let bwd_result = run_refinement_solver(backward_solver, &products.backward, depth)?;

    Ok(merge_results(fwd_result, bwd_result, depth))
}

/// Merge forward and backward simulation results into an equivalence verdict.
fn merge_results(
    fwd: SimulationCheckResult,
    bwd: SimulationCheckResult,
    depth: usize,
) -> EquivalenceCheckResult {
    match (&fwd, &bwd) {
        (
            SimulationCheckResult::SimulationHolds { .. },
            SimulationCheckResult::SimulationHolds { .. },
        ) => EquivalenceCheckResult::EquivalentUpTo { depth },
        (
            SimulationCheckResult::SimulationViolated { witness, .. },
            SimulationCheckResult::SimulationHolds { .. },
        ) => EquivalenceCheckResult::ForwardDivergence {
            depth,
            witness: witness.clone(),
        },
        (
            SimulationCheckResult::SimulationHolds { .. },
            SimulationCheckResult::SimulationViolated { witness, .. },
        ) => EquivalenceCheckResult::BackwardDivergence {
            depth,
            witness: witness.clone(),
        },
        (
            SimulationCheckResult::SimulationViolated { witness: fw, .. },
            SimulationCheckResult::SimulationViolated { witness: bw, .. },
        ) => EquivalenceCheckResult::BidirectionalDivergence {
            depth,
            forward_witness: fw.clone(),
            backward_witness: bw.clone(),
        },
        (SimulationCheckResult::Unknown { reason, .. }, _)
        | (_, SimulationCheckResult::Unknown { reason, .. }) => EquivalenceCheckResult::Unknown {
            depth,
            reason: reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::equivalence::build_equivalence_products;
    use tarsier_ir::threshold_automaton::*;

    fn make_ta(
        loc_names: &[&str],
        initial: &[usize],
        rules: &[(usize, usize)],
    ) -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        for name in loc_names {
            ta.add_location(Location {
                name: name.to_string(),
                role: "R".into(),
                phase: name.to_string(),
                local_vars: Default::default(),
            });
        }
        for &i in initial {
            ta.initial_locations.push(LocationId::from(i));
        }
        for &(from, to) in rules {
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
    fn trivially_equivalent_encodes_false() {
        let a = make_ta(&["Init"], &[0], &[]);
        let b = make_ta(&["Init"], &[0], &[]);

        let products = build_equivalence_products(&a, &b).unwrap();
        assert!(products.is_trivially_equivalent());

        let enc = encode_equivalence_check(&products, 3);
        // Both should assert false (UNSAT → equivalent).
        let fwd_has_false = enc
            .forward
            .assertions
            .iter()
            .any(|t| matches!(t, crate::terms::SmtTerm::BoolLit(false)));
        let bwd_has_false = enc
            .backward
            .assertions
            .iter()
            .any(|t| matches!(t, crate::terms::SmtTerm::BoolLit(false)));
        assert!(fwd_has_false);
        assert!(bwd_has_false);
    }

    #[test]
    fn non_trivial_produces_disjunctions() {
        let a = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);
        let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);

        let products = build_equivalence_products(&a, &b).unwrap();
        assert!(!products.is_trivially_equivalent());

        let enc = encode_equivalence_check(&products, 2);
        // Both should have Or(...) mismatch disjunctions.
        let fwd_has_or = enc
            .forward
            .assertions
            .iter()
            .any(|t| matches!(t, crate::terms::SmtTerm::Or(_)));
        let bwd_has_or = enc
            .backward
            .assertions
            .iter()
            .any(|t| matches!(t, crate::terms::SmtTerm::Or(_)));
        assert!(fwd_has_or);
        assert!(bwd_has_or);
    }

    #[test]
    fn encoding_scales_with_depth() {
        let a = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);
        let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);

        let products = build_equivalence_products(&a, &b).unwrap();
        let enc1 = encode_equivalence_check(&products, 1);
        let enc3 = encode_equivalence_check(&products, 3);

        assert!(enc3.forward.declarations.len() > enc1.forward.declarations.len());
        assert!(enc3.backward.declarations.len() > enc1.backward.declarations.len());
    }

    #[test]
    fn equivalence_check_result_variants() {
        let r1 = EquivalenceCheckResult::EquivalentUpTo { depth: 5 };
        assert!(matches!(
            r1,
            EquivalenceCheckResult::EquivalentUpTo { depth: 5 }
        ));

        let r2 = EquivalenceCheckResult::ForwardDivergence {
            depth: 3,
            witness: None,
        };
        assert!(matches!(
            r2,
            EquivalenceCheckResult::ForwardDivergence { .. }
        ));

        let r3 = EquivalenceCheckResult::TriviallyEquivalent;
        assert!(matches!(r3, EquivalenceCheckResult::TriviallyEquivalent));

        let r4 = EquivalenceCheckResult::Unknown {
            depth: 1,
            reason: "timeout".into(),
        };
        assert!(matches!(r4, EquivalenceCheckResult::Unknown { .. }));
    }

    #[test]
    fn merge_both_hold_yields_equivalent() {
        let fwd = SimulationCheckResult::SimulationHolds { depth: 5 };
        let bwd = SimulationCheckResult::SimulationHolds { depth: 5 };
        let result = merge_results(fwd, bwd, 5);
        assert!(matches!(
            result,
            EquivalenceCheckResult::EquivalentUpTo { depth: 5 }
        ));
    }

    #[test]
    fn merge_forward_violated_yields_forward_divergence() {
        use tarsier_ir::product::ProductLocationId;
        use tarsier_ir::threshold_automaton::LocationId;
        let fwd = SimulationCheckResult::SimulationViolated {
            depth: 3,
            violation_step: 1,
            mismatch_location: ProductLocationId {
                concrete: LocationId::from(0),
                abstract_loc: LocationId::from(1),
            },
            witness: None,
        };
        let bwd = SimulationCheckResult::SimulationHolds { depth: 3 };
        let result = merge_results(fwd, bwd, 3);
        assert!(matches!(
            result,
            EquivalenceCheckResult::ForwardDivergence { .. }
        ));
    }
}
