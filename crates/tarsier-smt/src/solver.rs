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
