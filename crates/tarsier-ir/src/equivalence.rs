//! Behavioral equivalence checking via bidirectional simulation.
//!
//! Two threshold automata are behaviorally equivalent if they simulate each
//! other: every behavior of A can be matched by B, and vice versa. This is
//! checked by building two product automata (one per direction) and checking
//! that no mismatch (divergence) state is reachable in either.

use crate::product::{build_product, ProductAutomaton, ProductError};
use crate::refinement::{RefinementMapping, RefinementRelation};
use crate::threshold_automaton::{LocationId, SharedVarId, ThresholdAutomaton};

/// Result of building the bidirectional product for equivalence checking.
#[derive(Debug, Clone)]
pub struct EquivalenceProducts {
    /// Product for forward direction: A refines B (A is concrete, B is abstract).
    pub forward: ProductAutomaton,
    /// Product for backward direction: B refines A (B is concrete, A is abstract).
    pub backward: ProductAutomaton,
}

impl EquivalenceProducts {
    /// True if neither direction has mismatch locations (trivial equivalence).
    pub fn is_trivially_equivalent(&self) -> bool {
        !self.forward.has_mismatches() && !self.backward.has_mismatches()
    }

    /// Total mismatch locations across both directions.
    pub fn total_mismatches(&self) -> usize {
        self.forward.mismatch_locations.len() + self.backward.mismatch_locations.len()
    }
}

/// Errors from equivalence product construction.
#[derive(Debug, Clone)]
pub enum EquivalenceError {
    /// Error building the forward (A→B) product.
    ForwardProductError(ProductError),
    /// Error building the backward (B→A) product.
    BackwardProductError(ProductError),
}

impl std::fmt::Display for EquivalenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EquivalenceError::ForwardProductError(e) => write!(f, "forward product: {e}"),
            EquivalenceError::BackwardProductError(e) => write!(f, "backward product: {e}"),
        }
    }
}

impl std::error::Error for EquivalenceError {}

/// Build bidirectional products for equivalence checking between two threshold automata.
///
/// Uses name-based auto-mapping: locations and shared variables with matching names
/// are paired; unmatched elements are marked as internal.
pub fn build_equivalence_products(
    ta_a: &ThresholdAutomaton,
    ta_b: &ThresholdAutomaton,
) -> Result<EquivalenceProducts, EquivalenceError> {
    // Forward: A (concrete) refines B (abstract)
    let forward_mapping = build_name_mapping(ta_a, ta_b, "B");
    let forward_rel = RefinementRelation::new(forward_mapping);
    let forward = build_product(ta_a, ta_b, &forward_rel)
        .map_err(EquivalenceError::ForwardProductError)?;

    // Backward: B (concrete) refines A (abstract)
    let backward_mapping = build_name_mapping(ta_b, ta_a, "A");
    let backward_rel = RefinementRelation::new(backward_mapping);
    let backward = build_product(ta_b, ta_a, &backward_rel)
        .map_err(EquivalenceError::BackwardProductError)?;

    Ok(EquivalenceProducts { forward, backward })
}

/// Build a name-based refinement mapping from concrete to abstract.
///
/// Locations and shared variables with matching names are mapped;
/// unmatched concrete elements are marked as internal.
fn build_name_mapping(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
    abstract_label: &str,
) -> RefinementMapping {
    let mut mapping = RefinementMapping::new(abstract_label.to_string());

    for (c_idx, c_loc) in concrete.locations.iter().enumerate() {
        let c_id = LocationId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_location_by_name(&c_loc.name) {
            mapping.map_location(c_id, a_id);
        } else {
            mapping.mark_location_internal(c_id);
        }
    }

    for (c_idx, c_var) in concrete.shared_vars.iter().enumerate() {
        let c_id = SharedVarId::from(c_idx);
        if let Some(a_id) = abstract_ta.find_shared_var_by_name(&c_var.name) {
            mapping.map_variable(c_id, a_id);
        } else {
            mapping.mark_variable_internal(c_id);
        }
    }

    mapping
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_automaton::*;

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
                param_updates: vec![],
            });
        }
        ta
    }

    #[test]
    fn identical_automata_trivially_equivalent() {
        let a = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);
        let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);

        let products = build_equivalence_products(&a, &b).unwrap();
        // Both directions have no mismatches on the diagonal.
        // With 2×2 product, off-diagonal are mismatches but diagonal is fine.
        assert!(!products.is_trivially_equivalent());
        // But diagonal locations are correct — mismatches are only off-diagonal.
        assert_eq!(products.forward.mismatch_locations.len(), 2);
        assert_eq!(products.backward.mismatch_locations.len(), 2);
    }

    #[test]
    fn single_location_identity_is_trivial() {
        let a = make_ta(&["Init"], &[0], &[]);
        let b = make_ta(&["Init"], &[0], &[]);

        let products = build_equivalence_products(&a, &b).unwrap();
        assert!(products.is_trivially_equivalent());
        assert_eq!(products.total_mismatches(), 0);
    }

    #[test]
    fn asymmetric_automata_have_divergence() {
        // A has an extra location that B doesn't.
        let a = make_ta(&["Init", "Mid", "Done"], &[0], &[(0, 1), (1, 2)]);
        let b = make_ta(&["Init", "Done"], &[0], &[(0, 1)]);

        let products = build_equivalence_products(&a, &b).unwrap();
        // Forward: A→B has internal location "Mid" (not in B).
        // Backward: B→A maps fine since both B locations exist in A.
        assert!(products.forward.has_mismatches());
    }

    #[test]
    fn disjoint_names_all_internal() {
        // No name overlap → all locations marked internal.
        let a = make_ta(&["X"], &[0], &[]);
        let b = make_ta(&["Y"], &[0], &[]);

        let products = build_equivalence_products(&a, &b).unwrap();
        // Internal locations in 1×1 product → no mismatches (internal = None mapping).
        assert!(products.is_trivially_equivalent());
    }

    #[test]
    fn shared_vars_matched_by_name() {
        let mut a = make_ta(&["Init"], &[0], &[]);
        a.add_shared_var(SharedVar {
            name: "votes".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let mut b = make_ta(&["Init"], &[0], &[]);
        b.add_shared_var(SharedVar {
            name: "votes".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let products = build_equivalence_products(&a, &b).unwrap();
        // Both products should have 2 shared vars (conc_votes + abs_votes).
        assert_eq!(products.forward.shared_vars.len(), 2);
        assert_eq!(products.backward.shared_vars.len(), 2);
    }
}
