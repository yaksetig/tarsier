//! SMT encoding for bounded behavioral equivalence checking.
//!
//! Encodes both directions of the bisimulation check (A refines B, B refines A)
//! as bounded reachability problems. If either direction's encoding is SAT,
//! equivalence is violated.

use tarsier_ir::equivalence::EquivalenceProducts;

use crate::refinement_encoder::{encode_refinement_check, RefinementEncoding};

/// Bidirectional equivalence encoding: one per simulation direction.
#[derive(Debug)]
pub struct EquivalenceEncoding {
    /// Encoding for forward direction (A → B): SAT means A has behavior B cannot match.
    pub forward: RefinementEncoding,
    /// Encoding for backward direction (B → A): SAT means B has behavior A cannot match.
    pub backward: RefinementEncoding,
}

/// Result of a bounded equivalence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivalenceCheckResult {
    /// Both directions hold up to the given depth — protocols are equivalent
    /// within the bound.
    EquivalentUpTo { depth: usize },
    /// Forward simulation fails: A has behavior that B cannot match.
    ForwardDivergence { depth: usize },
    /// Backward simulation fails: B has behavior that A cannot match.
    BackwardDivergence { depth: usize },
    /// Both directions fail.
    BidirectionalDivergence { depth: usize },
    /// Trivially equivalent — no mismatch locations in either product.
    TriviallyEquivalent,
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
        assert_eq!(r1, EquivalenceCheckResult::EquivalentUpTo { depth: 5 });

        let r2 = EquivalenceCheckResult::ForwardDivergence { depth: 3 };
        assert!(matches!(r2, EquivalenceCheckResult::ForwardDivergence { .. }));

        let r3 = EquivalenceCheckResult::TriviallyEquivalent;
        assert_eq!(r3, EquivalenceCheckResult::TriviallyEquivalent);
    }
}
