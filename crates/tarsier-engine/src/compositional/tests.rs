use super::*;
use tarsier_ir::composition::{Assumption, ModuleContract};
use tarsier_ir::threshold_automaton::{CmpOp, LinearCombination};

fn module(name: &str, assumptions: Vec<Assumption>, guarantees: Vec<Guarantee>) -> Module {
    Module {
        name: name.to_string(),
        automaton: tarsier_ir::threshold_automaton::ThresholdAutomaton::new(),
        interface: ModuleContract {
            assumptions,
            guarantees,
        },
    }
}

#[test]
fn valid_contracts_report_all_guarantees() {
    let sender = module(
        "Sender",
        vec![],
        vec![
            Guarantee::MessageProduction {
                message_type: "Vote".to_string(),
                min_count: LinearCombination::constant(1),
            },
            Guarantee::Safety("agreement".to_string()),
        ],
    );
    let receiver = module(
        "Receiver",
        vec![Assumption::MessageAvailability {
            message_type: "Vote".to_string(),
            min_count: LinearCombination::constant(1),
        }],
        vec![],
    );

    match check_module_composition(&[sender, receiver]) {
        CompositionalResult::ContractsValid { module_results } => {
            assert_eq!(module_results.len(), 2);
            assert!(module_results
                .iter()
                .any(|(m, g)| { m == "Sender" && g == "message production: Vote" }));
            assert!(module_results
                .iter()
                .any(|(m, g)| m == "Sender" && g == "safety guarantee: agreement"));
        }
        other => panic!("expected ContractsValid, got {other:?}"),
    }
}

#[test]
fn uncovered_assumptions_are_formatted_with_module_name() {
    let receiver = module(
        "Receiver",
        vec![Assumption::MessageAvailability {
            message_type: "Prepare".to_string(),
            min_count: LinearCombination::constant(2),
        }],
        vec![],
    );

    match check_module_composition(&[receiver]) {
        CompositionalResult::CompositionError(msg) => {
            assert!(msg.contains("Uncovered assumptions"));
            assert!(msg.contains("Module 'Receiver'"));
            assert!(msg.contains("message availability: Prepare"));
        }
        other => panic!("expected CompositionError, got {other:?}"),
    }
}

#[test]
fn cycle_detection_surfaces_clear_error_message() {
    let a = module(
        "A",
        vec![Assumption::MessageAvailability {
            message_type: "mb".to_string(),
            min_count: LinearCombination::constant(1),
        }],
        vec![Guarantee::MessageProduction {
            message_type: "ma".to_string(),
            min_count: LinearCombination::constant(1),
        }],
    );
    let b = module(
        "B",
        vec![Assumption::MessageAvailability {
            message_type: "ma".to_string(),
            min_count: LinearCombination::constant(1),
        }],
        vec![Guarantee::MessageProduction {
            message_type: "mb".to_string(),
            min_count: LinearCombination::constant(1),
        }],
    );

    match check_module_composition(&[a, b]) {
        CompositionalResult::CompositionError(msg) => {
            assert!(msg.contains("Circular dependency detected"));
            assert!(msg.contains("A"));
            assert!(msg.contains("B"));
        }
        other => panic!("expected CompositionError, got {other:?}"),
    }
}

#[test]
fn parameter_constraint_assumptions_do_not_require_external_providers() {
    let constrained = module(
        "Constrained",
        vec![Assumption::ParameterConstraint {
            lhs: LinearCombination::param(0.into()),
            op: CmpOp::Ge,
            rhs: LinearCombination::constant(1),
        }],
        vec![],
    );

    match check_module_composition(&[constrained]) {
        CompositionalResult::ContractsValid { module_results } => {
            assert!(module_results.is_empty());
        }
        other => panic!("expected ContractsValid, got {other:?}"),
    }
}
