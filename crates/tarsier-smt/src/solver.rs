use std::collections::HashMap;

use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

/// Result of a satisfiability check.
#[derive(Debug, Clone, PartialEq)]
pub enum SatResult {
    Sat,
    Unsat,
    Unknown(String),
}

/// A model (variable assignments) extracted from a SAT result.
#[derive(Debug, Clone)]
pub struct Model {
    pub values: HashMap<String, ModelValue>,
}

#[derive(Debug, Clone)]
pub enum ModelValue {
    Int(i64),
    Bool(bool),
}

impl Model {
    pub fn get_int(&self, name: &str) -> Option<i64> {
        match self.values.get(name) {
            Some(ModelValue::Int(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn get_bool(&self, name: &str) -> Option<bool> {
        match self.values.get(name) {
            Some(ModelValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// Abstract SMT solver interface.
pub trait SmtSolver {
    type Error: std::error::Error;

    /// Declare a new variable.
    fn declare_var(&mut self, name: &str, sort: &SmtSort) -> Result<(), Self::Error>;

    /// Assert a constraint.
    fn assert(&mut self, term: &SmtTerm) -> Result<(), Self::Error>;

    /// Push a new scope.
    fn push(&mut self) -> Result<(), Self::Error>;

    /// Pop a scope.
    fn pop(&mut self) -> Result<(), Self::Error>;

    /// Check satisfiability.
    fn check_sat(&mut self) -> Result<SatResult, Self::Error>;

    /// Check satisfiability and extract a model if SAT.
    fn check_sat_with_model(
        &mut self,
        var_names: &[(&str, &SmtSort)],
    ) -> Result<(SatResult, Option<Model>), Self::Error>;

    /// Returns true when the backend supports `check-sat-assuming` with
    /// retrievable UNSAT cores over the provided assumptions.
    fn supports_assumption_unsat_core(&self) -> bool {
        false
    }

    /// Check satisfiability under a set of Boolean assumption variables.
    ///
    /// Assumptions are backend variable names that must be declared as `Bool`.
    fn check_sat_assuming(&mut self, _assumptions: &[String]) -> Result<SatResult, Self::Error> {
        self.check_sat()
    }

    /// Return UNSAT-core assumptions for the previous `check_sat_assuming`.
    fn get_unsat_core_assumptions(&mut self) -> Result<Vec<String>, Self::Error> {
        Ok(Vec::new())
    }

    /// Reset the solver state.
    fn reset(&mut self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io;

    struct MockSolver {
        sat_result: SatResult,
        check_sat_calls: usize,
        reset_calls: usize,
    }

    impl MockSolver {
        fn new(sat_result: SatResult) -> Self {
            Self {
                sat_result,
                check_sat_calls: 0,
                reset_calls: 0,
            }
        }
    }

    impl SmtSolver for MockSolver {
        type Error = io::Error;

        fn declare_var(&mut self, _name: &str, _sort: &SmtSort) -> Result<(), Self::Error> {
            Ok(())
        }

        fn assert(&mut self, _term: &SmtTerm) -> Result<(), Self::Error> {
            Ok(())
        }

        fn push(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn pop(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn check_sat(&mut self) -> Result<SatResult, Self::Error> {
            self.check_sat_calls += 1;
            Ok(self.sat_result.clone())
        }

        fn check_sat_with_model(
            &mut self,
            _var_names: &[(&str, &SmtSort)],
        ) -> Result<(SatResult, Option<Model>), Self::Error> {
            Ok((self.sat_result.clone(), None))
        }

        fn reset(&mut self) -> Result<(), Self::Error> {
            self.reset_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn model_getters_return_typed_values_only() {
        let mut values = HashMap::new();
        values.insert("x".to_string(), ModelValue::Int(42));
        values.insert("flag".to_string(), ModelValue::Bool(true));
        let model = Model { values };

        assert_eq!(model.get_int("x"), Some(42));
        assert_eq!(model.get_bool("flag"), Some(true));
        assert_eq!(model.get_int("flag"), None);
        assert_eq!(model.get_bool("x"), None);
        assert_eq!(model.get_int("missing"), None);
        assert_eq!(model.get_bool("missing"), None);
    }

    #[test]
    fn default_assumption_core_support_is_disabled() {
        let solver = MockSolver::new(SatResult::Sat);
        assert!(!solver.supports_assumption_unsat_core());
    }

    #[test]
    fn default_check_sat_assuming_delegates_to_check_sat() {
        let mut solver = MockSolver::new(SatResult::Unsat);
        let result = solver
            .check_sat_assuming(&["a0".to_string(), "a1".to_string()])
            .expect("check_sat_assuming should succeed");

        assert_eq!(result, SatResult::Unsat);
        assert_eq!(solver.check_sat_calls, 1);
    }

    #[test]
    fn default_unsat_core_returns_empty_and_reset_is_callable() {
        let mut solver = MockSolver::new(SatResult::Unknown("timeout".to_string()));
        let core = solver
            .get_unsat_core_assumptions()
            .expect("default unsat core query should succeed");
        assert!(core.is_empty());

        solver.reset().expect("reset should succeed");
        assert_eq!(solver.reset_calls, 1);
    }
}
