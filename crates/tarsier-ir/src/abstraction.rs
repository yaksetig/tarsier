use crate::counter_system::CounterSystem;
use crate::threshold_automaton::ThresholdAutomaton;

/// Convert a threshold automaton into a counter system.
///
/// Counter semantics are represented directly on the threshold automaton model,
/// so this conversion is an identity mapping.
pub fn abstract_to_counter_system(ta: ThresholdAutomaton) -> CounterSystem {
    ta
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_automaton::{Location, LocationId, ThresholdAutomaton};
    use indexmap::IndexMap;

    #[test]
    fn abstraction_preserves_original_automaton() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_location(Location {
            name: "Init".into(),
            role: "Replica".into(),
            phase: "init".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations.push(LocationId::from(0));

        let cs = abstract_to_counter_system(ta.clone());
        assert_eq!(cs.locations.len(), 1);
        assert_eq!(cs.locations[0].name, "Init");
        assert_eq!(cs.initial_locations, vec![LocationId::from(0)]);
        assert_eq!(cs.locations[0].phase, ta.locations[0].phase);
    }
}
