use tarsier_ir::composition::{
    check_composition, CompositionResult, Guarantee, Module, UncoveredAssumption,
};

/// Result of compositional contract validation.
///
/// **Note:** This checks structural validity of assume-guarantee contracts
/// (DAG acyclicity and assumption coverage) but does **not** perform
/// per-module SMT verification. Use the standard pipeline on each module's
/// automaton separately to verify individual guarantees.
#[derive(Debug)]
pub enum CompositionalResult {
    /// All assume-guarantee contracts are structurally valid (no uncovered
    /// assumptions, no circular dependencies).
    ContractsValid {
        module_results: Vec<(String, String)>,
    },
    /// Contract validation failed (uncovered assumptions or cycles).
    CompositionError(String),
}

/// Validate module composition contracts without running SMT verification.
///
/// Returns [`ContractsValid`](CompositionalResult::ContractsValid) when the
/// assume-guarantee graph forms a valid DAG with all assumptions covered by
/// some other module's guarantee.  This is a necessary precondition for
/// compositional safety but does **not** discharge individual module proofs.
pub fn check_module_composition(modules: &[Module]) -> CompositionalResult {
    match check_composition(modules) {
        CompositionResult::Valid => {
            let mut module_results = Vec::new();
            for module in modules {
                for guarantee in &module.interface.guarantees {
                    match guarantee {
                        Guarantee::Safety(prop_name) => {
                            module_results.push((
                                module.name.clone(),
                                format!("safety guarantee: {prop_name}"),
                            ));
                        }
                        Guarantee::MessageProduction { message_type, .. } => {
                            module_results.push((
                                module.name.clone(),
                                format!("message production: {message_type}"),
                            ));
                        }
                    }
                }
            }
            CompositionalResult::ContractsValid { module_results }
        }
        CompositionResult::UncoveredAssumptions(uncovered) => {
            CompositionalResult::CompositionError(format_uncovered_assumptions(&uncovered))
        }
        CompositionResult::CircularDependency(cycle) => {
            CompositionalResult::CompositionError(format!(
                "Circular dependency detected among modules: {}",
                cycle.join(", ")
            ))
        }
    }
}

fn format_uncovered_assumptions(uncovered: &[UncoveredAssumption]) -> String {
    let mut msg = String::from("Uncovered assumptions:\n");
    for ua in uncovered {
        msg.push_str(&format!("  - Module '{}': {}\n", ua.module, ua.assumption));
    }
    msg
}

#[cfg(test)]
mod tests;
