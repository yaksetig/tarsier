use crate::threshold_automaton::{LinearCombination, ThresholdAutomaton};
use std::collections::HashMap;

/// A module for compositional verification.
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub automaton: ThresholdAutomaton,
    pub interface: ModuleContract,
}

/// Assume-guarantee contract for a module.
#[derive(Debug, Clone)]
pub struct ModuleContract {
    pub assumptions: Vec<Assumption>,
    pub guarantees: Vec<Guarantee>,
}

/// Assumptions a module makes about its environment.
#[derive(Debug, Clone)]
pub enum Assumption {
    /// Assume a minimum number of messages of a given type will be available.
    MessageAvailability {
        message_type: String,
        min_count: LinearCombination,
    },
    /// Assume a parameter constraint holds.
    ParameterConstraint {
        lhs: LinearCombination,
        op: crate::threshold_automaton::CmpOp,
        rhs: LinearCombination,
    },
}

/// Guarantees a module provides to other modules.
#[derive(Debug, Clone)]
pub enum Guarantee {
    /// This module guarantees a safety property.
    Safety(String),
    /// This module guarantees producing at least `min_count` messages of a type.
    MessageProduction {
        message_type: String,
        min_count: LinearCombination,
    },
}

/// Result of composition checking.
#[derive(Debug)]
pub enum CompositionResult {
    /// All assumptions are covered by guarantees and modules form a DAG.
    Valid,
    /// One or more assumptions are not covered.
    UncoveredAssumptions(Vec<UncoveredAssumption>),
    /// Modules have circular dependencies.
    CircularDependency(Vec<String>),
}

/// An assumption that is not covered by any module's guarantee.
#[derive(Debug)]
pub struct UncoveredAssumption {
    pub module: String,
    pub assumption: String,
}

/// Check that module composition is valid: every assumption is covered
/// by some other module's guarantee, and the dependency graph is a DAG.
pub fn check_composition(modules: &[Module]) -> CompositionResult {
    // Build guarantee index: message_type -> list of providing modules
    let mut message_guarantees: HashMap<String, Vec<String>> = HashMap::new();
    let mut safety_guarantees: HashMap<String, Vec<String>> = HashMap::new();

    for module in modules {
        for guarantee in &module.interface.guarantees {
            match guarantee {
                Guarantee::Safety(prop_name) => {
                    safety_guarantees
                        .entry(prop_name.clone())
                        .or_default()
                        .push(module.name.clone());
                }
                Guarantee::MessageProduction { message_type, .. } => {
                    message_guarantees
                        .entry(message_type.clone())
                        .or_default()
                        .push(module.name.clone());
                }
            }
        }
    }

    // Check all assumptions are covered
    let mut uncovered = Vec::new();
    let mut depends_on: HashMap<String, Vec<String>> = HashMap::new();

    for module in modules {
        for assumption in &module.interface.assumptions {
            match assumption {
                Assumption::MessageAvailability { message_type, .. } => {
                    if let Some(providers) = message_guarantees.get(message_type) {
                        depends_on
                            .entry(module.name.clone())
                            .or_default()
                            .extend(providers.iter().cloned());
                    } else {
                        uncovered.push(UncoveredAssumption {
                            module: module.name.clone(),
                            assumption: format!("message availability: {message_type}"),
                        });
                    }
                }
                Assumption::ParameterConstraint { .. } => {
                    // Parameter constraints are checked against resilience conditions,
                    // not other modules' guarantees.
                }
            }
        }
    }

    if !uncovered.is_empty() {
        return CompositionResult::UncoveredAssumptions(uncovered);
    }

    // Check for circular dependencies (simple DFS cycle detection)
    let module_names: Vec<String> = modules.iter().map(|m| m.name.clone()).collect();
    if has_cycle(&module_names, &depends_on) {
        let cycle_modules = module_names
            .into_iter()
            .filter(|name| depends_on.contains_key(name))
            .collect();
        return CompositionResult::CircularDependency(cycle_modules);
    }

    CompositionResult::Valid
}

fn has_cycle(nodes: &[String], edges: &HashMap<String, Vec<String>>) -> bool {
    let mut visited: HashMap<String, u8> = HashMap::new(); // 0=unvisited, 1=in-progress, 2=done

    fn dfs(
        node: &str,
        edges: &HashMap<String, Vec<String>>,
        visited: &mut HashMap<String, u8>,
    ) -> bool {
        match visited.get(node).copied().unwrap_or(0) {
            1 => return true,  // cycle found
            2 => return false, // already fully explored
            _ => {}
        }
        visited.insert(node.to_string(), 1);
        if let Some(neighbors) = edges.get(node) {
            for neighbor in neighbors {
                if dfs(neighbor, edges, visited) {
                    return true;
                }
            }
        }
        visited.insert(node.to_string(), 2);
        false
    }

    for node in nodes {
        if dfs(node, edges, &mut visited) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_automaton::ThresholdAutomaton;

    fn make_module(name: &str, assumptions: Vec<Assumption>, guarantees: Vec<Guarantee>) -> Module {
        Module {
            name: name.to_string(),
            automaton: ThresholdAutomaton::new(),
            interface: ModuleContract {
                assumptions,
                guarantees,
            },
        }
    }

    #[test]
    fn empty_modules_are_valid() {
        let result = check_composition(&[]);
        assert!(matches!(result, CompositionResult::Valid));
    }

    #[test]
    fn single_module_no_assumptions_valid() {
        let m = make_module("A", vec![], vec![Guarantee::Safety("agreement".into())]);
        let result = check_composition(&[m]);
        assert!(matches!(result, CompositionResult::Valid));
    }

    #[test]
    fn assumption_covered_by_guarantee() {
        let a = make_module(
            "Sender",
            vec![],
            vec![Guarantee::MessageProduction {
                message_type: "Vote".into(),
                min_count: LinearCombination::constant(1),
            }],
        );
        let b = make_module(
            "Receiver",
            vec![Assumption::MessageAvailability {
                message_type: "Vote".into(),
                min_count: LinearCombination::constant(1),
            }],
            vec![Guarantee::Safety("agreement".into())],
        );
        let result = check_composition(&[a, b]);
        assert!(matches!(result, CompositionResult::Valid));
    }

    #[test]
    fn uncovered_assumption() {
        let m = make_module(
            "Receiver",
            vec![Assumption::MessageAvailability {
                message_type: "Vote".into(),
                min_count: LinearCombination::constant(1),
            }],
            vec![],
        );
        let result = check_composition(&[m]);
        assert!(matches!(result, CompositionResult::UncoveredAssumptions(_)));
    }
}
