use serde::{Deserialize, Serialize};
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;

/// A machine-readable mapping from verified properties to runtime monitoring obligations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationMap {
    /// Schema version (currently 1).
    pub schema_version: u32,
    /// Protocol name.
    pub protocol_name: String,
    /// List of runtime obligations derived from verified properties.
    pub obligations: Vec<RuntimeObligation>,
}

/// A single runtime obligation derived from a verified safety property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeObligation {
    /// Name of the property this obligation derives from.
    pub property_name: String,
    /// Kind of property: "agreement", "invariant", or "termination".
    pub property_kind: String,
    /// Human-readable description of the obligation.
    pub description: String,
    /// The monitor specification.
    pub monitor: ObligationMonitor,
}

/// A runtime monitor derived from a verified property.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ObligationMonitor {
    /// No two processes should simultaneously be in conflicting decision locations.
    AgreementMonitor {
        conflicting_location_pairs: Vec<(String, String)>,
    },
    /// The given location sets should never all be simultaneously occupied.
    InvariantMonitor { bad_location_sets: Vec<Vec<String>> },
    /// Eventually all processes reach goal locations.
    TerminationMonitor { goal_locations: Vec<String> },
}

/// Generate an obligation map from a threshold automaton and its verified properties.
pub fn generate_obligation_map(
    ta: &ThresholdAutomaton,
    protocol_name: &str,
    properties: &[(String, SafetyProperty)],
) -> ObligationMap {
    let obligations = properties
        .iter()
        .map(|(name, prop)| match prop {
            SafetyProperty::Agreement { conflicting_pairs } => {
                let pairs: Vec<(String, String)> = conflicting_pairs
                    .iter()
                    .map(|&(a, b)| (ta.locations[a].name.clone(), ta.locations[b].name.clone()))
                    .collect();
                RuntimeObligation {
                    property_name: name.clone(),
                    property_kind: "agreement".into(),
                    description: format!(
                        "No two processes should simultaneously occupy conflicting \
                         decision locations ({} conflicting pairs)",
                        pairs.len()
                    ),
                    monitor: ObligationMonitor::AgreementMonitor {
                        conflicting_location_pairs: pairs,
                    },
                }
            }
            SafetyProperty::Invariant { bad_sets } => {
                let named_sets: Vec<Vec<String>> = bad_sets
                    .iter()
                    .map(|set| {
                        set.iter()
                            .map(|&lid| ta.locations[lid].name.clone())
                            .collect()
                    })
                    .collect();
                RuntimeObligation {
                    property_name: name.clone(),
                    property_kind: "invariant".into(),
                    description: format!(
                        "The following location sets must never all be simultaneously \
                         occupied ({} bad sets)",
                        named_sets.len()
                    ),
                    monitor: ObligationMonitor::InvariantMonitor {
                        bad_location_sets: named_sets,
                    },
                }
            }
            SafetyProperty::Termination { goal_locs } => {
                let goals: Vec<String> = goal_locs
                    .iter()
                    .map(|&lid| ta.locations[lid].name.clone())
                    .collect();
                RuntimeObligation {
                    property_name: name.clone(),
                    property_kind: "termination".into(),
                    description: format!(
                        "All processes must eventually reach one of the goal locations: {}",
                        goals.join(", ")
                    ),
                    monitor: ObligationMonitor::TerminationMonitor {
                        goal_locations: goals,
                    },
                }
            }
        })
        .collect();

    ObligationMap {
        schema_version: 1,
        protocol_name: protocol_name.to_string(),
        obligations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::{
        Guard, Location, Parameter, Rule, SharedVar, SharedVarKind,
    };

    fn make_test_automaton() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.add_parameter(Parameter { name: "n".into() });
        ta.add_parameter(Parameter { name: "t".into() });
        // L0: Init
        ta.add_location(Location {
            name: "Process_Init".into(),
            role: "Process".into(),
            phase: "Init".into(),
            local_vars: Default::default(),
        });
        // L1: Decided_Commit (decided=true, phase=Commit)
        let mut local_vars_commit = indexmap::IndexMap::new();
        local_vars_commit.insert(
            "decided".into(),
            tarsier_ir::threshold_automaton::LocalValue::Bool(true),
        );
        ta.add_location(Location {
            name: "Process_Commit_decided".into(),
            role: "Process".into(),
            phase: "Commit".into(),
            local_vars: local_vars_commit,
        });
        // L2: Decided_Abort (decided=true, phase=Abort)
        let mut local_vars_abort = indexmap::IndexMap::new();
        local_vars_abort.insert(
            "decided".into(),
            tarsier_ir::threshold_automaton::LocalValue::Bool(true),
        );
        ta.add_location(Location {
            name: "Process_Abort_decided".into(),
            role: "Process".into(),
            phase: "Abort".into(),
            local_vars: local_vars_abort,
        });
        ta.initial_locations = vec![0];
        ta.add_shared_var(SharedVar {
            name: "cnt_Vote".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });
        ta.add_rule(Rule {
            from: 0,
            to: 1,
            guard: Guard::trivial(),
            updates: vec![],
        });
        ta.add_rule(Rule {
            from: 0,
            to: 2,
            guard: Guard::trivial(),
            updates: vec![],
        });
        ta
    }

    #[test]
    fn test_agreement_obligation_map() {
        let ta = make_test_automaton();
        let props = vec![(
            "agreement".into(),
            SafetyProperty::Agreement {
                conflicting_pairs: vec![(1, 2)],
            },
        )];

        let map = generate_obligation_map(&ta, "TestProtocol", &props);
        assert_eq!(map.schema_version, 1);
        assert_eq!(map.protocol_name, "TestProtocol");
        assert_eq!(map.obligations.len(), 1);

        let ob = &map.obligations[0];
        assert_eq!(ob.property_kind, "agreement");
        match &ob.monitor {
            ObligationMonitor::AgreementMonitor {
                conflicting_location_pairs,
            } => {
                assert_eq!(conflicting_location_pairs.len(), 1);
                assert_eq!(
                    conflicting_location_pairs[0],
                    (
                        "Process_Commit_decided".to_string(),
                        "Process_Abort_decided".to_string()
                    )
                );
            }
            _ => panic!("expected AgreementMonitor"),
        }
    }

    #[test]
    fn test_invariant_obligation_map() {
        let ta = make_test_automaton();
        let props = vec![(
            "safety_inv".into(),
            SafetyProperty::Invariant {
                bad_sets: vec![vec![1, 2]],
            },
        )];

        let map = generate_obligation_map(&ta, "TestProtocol", &props);
        assert_eq!(map.obligations.len(), 1);

        let ob = &map.obligations[0];
        assert_eq!(ob.property_kind, "invariant");
        match &ob.monitor {
            ObligationMonitor::InvariantMonitor { bad_location_sets } => {
                assert_eq!(bad_location_sets.len(), 1);
                assert_eq!(bad_location_sets[0].len(), 2);
            }
            _ => panic!("expected InvariantMonitor"),
        }
    }

    #[test]
    fn test_termination_obligation_map() {
        let ta = make_test_automaton();
        let props = vec![(
            "liveness".into(),
            SafetyProperty::Termination {
                goal_locs: vec![1, 2],
            },
        )];

        let map = generate_obligation_map(&ta, "TestProtocol", &props);
        assert_eq!(map.obligations.len(), 1);

        let ob = &map.obligations[0];
        assert_eq!(ob.property_kind, "termination");
        match &ob.monitor {
            ObligationMonitor::TerminationMonitor { goal_locations } => {
                assert_eq!(goal_locations.len(), 2);
                assert_eq!(goal_locations[0], "Process_Commit_decided");
                assert_eq!(goal_locations[1], "Process_Abort_decided");
            }
            _ => panic!("expected TerminationMonitor"),
        }
    }

    #[test]
    fn test_obligation_map_serialization() {
        let ta = make_test_automaton();
        let props = vec![
            (
                "agreement".into(),
                SafetyProperty::Agreement {
                    conflicting_pairs: vec![(1, 2)],
                },
            ),
            (
                "liveness".into(),
                SafetyProperty::Termination { goal_locs: vec![1] },
            ),
        ];

        let map = generate_obligation_map(&ta, "TestProtocol", &props);
        let json = serde_json::to_string_pretty(&map).expect("serialize");
        let roundtrip: ObligationMap = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(roundtrip.schema_version, 1);
        assert_eq!(roundtrip.protocol_name, "TestProtocol");
        assert_eq!(roundtrip.obligations.len(), 2);
        assert_eq!(roundtrip.obligations[0].property_kind, "agreement");
        assert_eq!(roundtrip.obligations[1].property_kind, "termination");
    }
}
