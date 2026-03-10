//! IR model for refinement checking between abstract and concrete protocols.
//!
//! A refinement relation maps concrete protocol states to abstract protocol
//! states and establishes that every concrete behavior is a valid abstract
//! behavior (simulation preservation).

use std::collections::HashMap;

use crate::threshold_automaton::{LocationId, SharedVarId};

/// Mapping from concrete locations/variables to abstract locations/variables.
#[derive(Debug, Clone)]
pub struct RefinementMapping {
    /// Path to the abstract protocol that this protocol refines.
    pub abstract_protocol_path: String,

    /// Maps concrete location IDs to abstract location IDs.
    /// A concrete location may map to `None` if it has no abstract counterpart
    /// (e.g., internal implementation detail locations).
    pub location_map: HashMap<LocationId, Option<LocationId>>,

    /// Maps concrete shared variable IDs to abstract shared variable IDs.
    /// A concrete variable may map to `None` if it is an implementation detail.
    pub variable_map: HashMap<SharedVarId, Option<SharedVarId>>,
}

impl RefinementMapping {
    /// Create a new empty refinement mapping for the given abstract protocol path.
    pub fn new(abstract_protocol_path: String) -> Self {
        Self {
            abstract_protocol_path,
            location_map: HashMap::new(),
            variable_map: HashMap::new(),
        }
    }

    /// Map a concrete location to an abstract location.
    pub fn map_location(&mut self, concrete: LocationId, abstract_loc: LocationId) {
        self.location_map.insert(concrete, Some(abstract_loc));
    }

    /// Mark a concrete location as having no abstract counterpart.
    pub fn mark_location_internal(&mut self, concrete: LocationId) {
        self.location_map.insert(concrete, None);
    }

    /// Map a concrete shared variable to an abstract shared variable.
    pub fn map_variable(&mut self, concrete: SharedVarId, abstract_var: SharedVarId) {
        self.variable_map.insert(concrete, Some(abstract_var));
    }

    /// Mark a concrete shared variable as having no abstract counterpart.
    pub fn mark_variable_internal(&mut self, concrete: SharedVarId) {
        self.variable_map.insert(concrete, None);
    }

    /// Look up the abstract location for a concrete location.
    pub fn abstract_location(&self, concrete: LocationId) -> Option<Option<LocationId>> {
        self.location_map.get(&concrete).copied()
    }

    /// Look up the abstract variable for a concrete variable.
    pub fn abstract_variable(&self, concrete: SharedVarId) -> Option<Option<SharedVarId>> {
        self.variable_map.get(&concrete).copied()
    }
}

/// Simulation relation kind — determines how the product automaton is constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SimulationKind {
    /// Forward simulation: every concrete step can be matched by an abstract step.
    #[default]
    Forward,
    /// Backward simulation: every abstract step can be matched by a concrete step.
    Backward,
}

/// Stub for a refinement relation between two threshold automata.
///
/// This is populated during product automaton construction (REF-03)
/// and used in the SMT encoding for simulation preservation (REF-04).
#[derive(Debug, Clone)]
pub struct RefinementRelation {
    /// The mapping from concrete to abstract protocol elements.
    pub mapping: RefinementMapping,

    /// The kind of simulation to check.
    pub simulation_kind: SimulationKind,
}

impl RefinementRelation {
    /// Create a new forward-simulation refinement relation.
    pub fn new(mapping: RefinementMapping) -> Self {
        Self {
            mapping,
            simulation_kind: SimulationKind::Forward,
        }
    }

    /// Create a new refinement relation with the specified simulation kind.
    pub fn with_simulation_kind(mapping: RefinementMapping, kind: SimulationKind) -> Self {
        Self {
            mapping,
            simulation_kind: kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refinement_mapping_location_roundtrip() {
        let mut mapping = RefinementMapping::new("abstract.trs".into());
        let concrete = LocationId::from(0);
        let abstract_loc = LocationId::from(5);
        mapping.map_location(concrete, abstract_loc);

        assert_eq!(
            mapping.abstract_location(concrete),
            Some(Some(abstract_loc))
        );
    }

    #[test]
    fn refinement_mapping_internal_location() {
        let mut mapping = RefinementMapping::new("abstract.trs".into());
        let concrete = LocationId::from(3);
        mapping.mark_location_internal(concrete);

        assert_eq!(mapping.abstract_location(concrete), Some(None));
    }

    #[test]
    fn refinement_mapping_unmapped_returns_none() {
        let mapping = RefinementMapping::new("abstract.trs".into());
        assert_eq!(mapping.abstract_location(LocationId::from(99)), None);
    }

    #[test]
    fn refinement_mapping_variable_roundtrip() {
        let mut mapping = RefinementMapping::new("abstract.trs".into());
        let concrete = SharedVarId::from(0);
        let abstract_var = SharedVarId::from(2);
        mapping.map_variable(concrete, abstract_var);

        assert_eq!(
            mapping.abstract_variable(concrete),
            Some(Some(abstract_var))
        );
    }

    #[test]
    fn refinement_relation_defaults_to_forward() {
        let mapping = RefinementMapping::new("base.trs".into());
        let rel = RefinementRelation::new(mapping);
        assert_eq!(rel.simulation_kind, SimulationKind::Forward);
    }

    #[test]
    fn refinement_relation_with_backward_simulation() {
        let mapping = RefinementMapping::new("base.trs".into());
        let rel = RefinementRelation::with_simulation_kind(mapping, SimulationKind::Backward);
        assert_eq!(rel.simulation_kind, SimulationKind::Backward);
    }
}
