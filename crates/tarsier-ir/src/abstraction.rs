use crate::counter_system::CounterSystem;
use crate::threshold_automaton::ThresholdAutomaton;

/// Convert a threshold automaton into a counter system.
///
/// The counter system is the abstracted form: instead of tracking individual
/// processes, we track counters for each location.
pub fn abstract_to_counter_system(ta: ThresholdAutomaton) -> CounterSystem {
    CounterSystem::new(ta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_automaton::{Location, ThresholdAutomaton};
    use indexmap::IndexMap;

    #[test]
    fn abstraction_wraps_original_automaton() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_location(Location {
            name: "Init".into(),
            role: "Replica".into(),
            phase: "init".into(),
            local_vars: IndexMap::new(),
        });
        ta.initial_locations.push(0);

        let cs = abstract_to_counter_system(ta.clone());
        assert_eq!(cs.automaton.locations.len(), 1);
        assert_eq!(cs.automaton.locations[0].name, "Init");
        assert_eq!(cs.automaton.initial_locations, vec![0]);
        assert_eq!(cs.automaton.locations[0].phase, ta.locations[0].phase);
    }
}
