use crate::counter_system::CounterSystem;
use crate::threshold_automaton::ThresholdAutomaton;

/// Convert a threshold automaton into a counter system.
///
/// The counter system is the abstracted form: instead of tracking individual
/// processes, we track counters for each location.
pub fn abstract_to_counter_system(ta: ThresholdAutomaton) -> CounterSystem {
    CounterSystem::new(ta)
}
