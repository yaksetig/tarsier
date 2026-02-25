use crate::threshold_automaton::{LocalValue, LocationId, ThresholdAutomaton};

/// A safety property to be verified.
#[derive(Debug, Clone)]
pub enum SafetyProperty {
    /// Agreement: no two decision locations with different decision values
    /// are simultaneously occupied.
    Agreement {
        /// Pairs of location IDs that must not be simultaneously occupied.
        conflicting_pairs: Vec<(LocationId, LocationId)>,
    },
    /// General safety invariant: a set of "bad" location sets.
    /// The property is violated if all locations in any bad set are occupied.
    Invariant {
        /// Each inner Vec is a set of locations that must not all be occupied simultaneously.
        bad_sets: Vec<Vec<LocationId>>,
    },
    /// Bounded liveness: by the final step, all processes are in goal locations.
    Termination {
        /// Locations that satisfy the configured liveness target predicate.
        goal_locs: Vec<LocationId>,
    },
}

/// Extract safety properties from the AST property declarations and the threshold automaton.
///
/// For agreement: no two locations with `decided=true` but in different
/// decision phases should be simultaneously occupied. In practice this means
/// two groups of processes cannot reach conflicting decisions.
///
/// If all decided locations share the same phase (single decision value),
/// the agreement property is trivially satisfied. For protocols with
/// multiple decision values, we create conflicting pairs between decided
/// locations in different phases.
///
/// If no such structural conflicts exist (single decision value), we fall
/// back to checking a reachability-based safety property: no decided location
/// should be occupied while a process is stuck in a non-initial, non-decided
/// location AND cannot make further progress (i.e., there is no rule out of
/// that location whose guard can be satisfied). Since detecting guard
/// satisfiability statically is hard, we use a simpler heuristic for the
/// prototype: we only generate conflicting pairs between decided locations
/// in genuinely different decision groups.
pub fn extract_agreement_property(ta: &ThresholdAutomaton) -> SafetyProperty {
    let decided_locs: Vec<LocationId> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| loc.local_vars.get("decided") == Some(&LocalValue::Bool(true)))
        .map(|(id, _)| id)
        .collect();

    let mut conflicting_pairs = Vec::new();

    // Group decided locations by phase. Locations in different phases
    // represent different decision values — these form conflicting pairs.
    let mut phase_groups: std::collections::HashMap<String, Vec<LocationId>> =
        std::collections::HashMap::new();
    for &d in &decided_locs {
        let phase = ta.locations[d].phase.clone();
        phase_groups.entry(phase).or_default().push(d);
    }

    let groups: Vec<Vec<LocationId>> = phase_groups.into_values().collect();
    for i in 0..groups.len() {
        for j in (i + 1)..groups.len() {
            for &loc_i in &groups[i] {
                for &loc_j in &groups[j] {
                    conflicting_pairs.push((loc_i, loc_j));
                }
            }
        }
    }

    SafetyProperty::Agreement { conflicting_pairs }
}

/// Extract a simple reachability-based safety property.
///
/// The property is: the given set of "bad" locations should never all
/// be simultaneously occupied.
pub fn extract_invariant_property(
    _ta: &ThresholdAutomaton,
    bad_locations: Vec<Vec<LocationId>>,
) -> SafetyProperty {
    SafetyProperty::Invariant {
        bad_sets: bad_locations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_automaton::Location;
    use indexmap::IndexMap;

    fn location(name: &str, phase: &str, decided: bool) -> Location {
        let mut local_vars = IndexMap::new();
        local_vars.insert("decided".to_string(), LocalValue::Bool(decided));
        Location {
            name: name.to_string(),
            role: "Replica".to_string(),
            phase: phase.to_string(),
            local_vars,
        }
    }

    #[test]
    fn agreement_property_builds_cross_phase_pairs_for_decided_locations() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_location(location("init", "init", false)); // 0
        ta.add_location(location("decide_0_a", "v0", true)); // 1
        ta.add_location(location("decide_0_b", "v0", true)); // 2
        ta.add_location(location("decide_1", "v1", true)); // 3

        let prop = extract_agreement_property(&ta);
        match prop {
            SafetyProperty::Agreement { conflicting_pairs } => {
                // Two locations in v0 and one in v1 => 2 x 1 pairs.
                assert_eq!(conflicting_pairs.len(), 2);
                assert!(conflicting_pairs.contains(&(1, 3)) || conflicting_pairs.contains(&(3, 1)));
                assert!(conflicting_pairs.contains(&(2, 3)) || conflicting_pairs.contains(&(3, 2)));
            }
            other => panic!("unexpected property variant: {other:?}"),
        }
    }

    #[test]
    fn agreement_property_is_empty_when_all_decided_locations_share_phase() {
        let mut ta = ThresholdAutomaton::new();
        ta.add_location(location("decide_a", "final", true));
        ta.add_location(location("decide_b", "final", true));

        let prop = extract_agreement_property(&ta);
        match prop {
            SafetyProperty::Agreement { conflicting_pairs } => {
                assert!(conflicting_pairs.is_empty())
            }
            other => panic!("unexpected property variant: {other:?}"),
        }
    }

    #[test]
    fn agreement_property_ignores_non_bool_decided_values() {
        let mut ta = ThresholdAutomaton::new();
        let mut enum_loc_vars = IndexMap::new();
        enum_loc_vars.insert("decided".to_string(), LocalValue::Enum("true".to_string()));
        ta.add_location(Location {
            name: "enum_decided".to_string(),
            role: "Replica".to_string(),
            phase: "v0".to_string(),
            local_vars: enum_loc_vars,
        });
        ta.add_location(location("bool_decided", "v1", true));

        let prop = extract_agreement_property(&ta);
        match prop {
            SafetyProperty::Agreement { conflicting_pairs } => {
                assert!(conflicting_pairs.is_empty());
            }
            other => panic!("unexpected property variant: {other:?}"),
        }
    }

    #[test]
    fn invariant_property_preserves_bad_location_sets() {
        let ta = ThresholdAutomaton::new();
        let bad_sets = vec![vec![1, 2], vec![3]];
        let prop = extract_invariant_property(&ta, bad_sets.clone());

        match prop {
            SafetyProperty::Invariant {
                bad_sets: extracted,
            } => assert_eq!(extracted, bad_sets),
            other => panic!("unexpected property variant: {other:?}"),
        }
    }
}
