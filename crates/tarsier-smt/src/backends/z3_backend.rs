use std::collections::HashMap;

use thiserror::Error;
use z3::SatResult as Z3SatResult;

use crate::solver::{Model, ModelValue, SatResult, SmtSolver};
use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

#[derive(Debug, Error)]
pub enum Z3Error {
    #[error("Z3 error: {0}")]
    Internal(String),
    #[error("Unknown variable: {0}")]
    UnknownVariable(String),
    #[error("Sort mismatch for variable {0}")]
    SortMismatch(String),
}

pub struct Z3Solver {
    solver: z3::Solver,
    int_vars: HashMap<String, z3::ast::Int>,
    bool_vars: HashMap<String, z3::ast::Bool>,
    last_assumption_names: Vec<String>,
    last_assumption_terms: Vec<z3::ast::Bool>,
    _params: Option<z3::Params>,
}

impl Z3Solver {
    pub fn new() -> Self {
        let solver = z3::Solver::new();
        Self {
            solver,
            int_vars: HashMap::new(),
            bool_vars: HashMap::new(),
            last_assumption_names: Vec::new(),
            last_assumption_terms: Vec::new(),
            _params: None,
        }
    }

    pub fn with_timeout_secs(timeout_secs: u64) -> Self {
        if timeout_secs == 0 {
            return Self::new();
        }
        let solver = z3::Solver::new();
        let mut params = z3::Params::new();
        let timeout_ms = timeout_secs.saturating_mul(1000);
        params.set_u32("timeout", timeout_ms as u32);
        params.set_u32("solver2_timeout", timeout_ms as u32);
        solver.set_params(&params);
        Self {
            solver,
            int_vars: HashMap::new(),
            bool_vars: HashMap::new(),
            last_assumption_names: Vec::new(),
            last_assumption_terms: Vec::new(),
            _params: Some(params),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new()
    }

    fn translate_term(&self, term: &SmtTerm) -> Result<Z3Term, Z3Error> {
        match term {
            SmtTerm::Var(name) => {
                if let Some(v) = self.int_vars.get(name) {
                    Ok(Z3Term::Int(v.clone()))
                } else if let Some(v) = self.bool_vars.get(name) {
                    Ok(Z3Term::Bool(v.clone()))
                } else {
                    Err(Z3Error::UnknownVariable(name.clone()))
                }
            }
            SmtTerm::IntLit(n) => Ok(Z3Term::Int(z3::ast::Int::from_i64(*n))),
            SmtTerm::BoolLit(b) => Ok(Z3Term::Bool(z3::ast::Bool::from_bool(*b))),
            SmtTerm::Add(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Int(&l + &r))
            }
            SmtTerm::Sub(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Int(&l - &r))
            }
            SmtTerm::Mul(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Int(&l * &r))
            }
            SmtTerm::Eq(lhs, rhs) => {
                let l = self.translate_term(lhs)?;
                let r = self.translate_term(rhs)?;
                match (l, r) {
                    (Z3Term::Int(li), Z3Term::Int(ri)) => Ok(Z3Term::Bool(li.eq(&ri))),
                    (Z3Term::Bool(lb), Z3Term::Bool(rb)) => Ok(Z3Term::Bool(lb.eq(&rb))),
                    _ => Err(Z3Error::Internal("Sort mismatch in Eq".into())),
                }
            }
            SmtTerm::Lt(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Bool(l.lt(&r)))
            }
            SmtTerm::Le(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Bool(l.le(&r)))
            }
            SmtTerm::Gt(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Bool(l.gt(&r)))
            }
            SmtTerm::Ge(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_int()?;
                let r = self.translate_term(rhs)?.into_int()?;
                Ok(Z3Term::Bool(l.ge(&r)))
            }
            SmtTerm::And(terms) => {
                let bools: Result<Vec<_>, _> = terms
                    .iter()
                    .map(|t| self.translate_term(t).and_then(|z| z.into_bool()))
                    .collect();
                let bools = bools?;
                let refs: Vec<&z3::ast::Bool> = bools.iter().collect();
                Ok(Z3Term::Bool(z3::ast::Bool::and(&refs)))
            }
            SmtTerm::Or(terms) => {
                let bools: Result<Vec<_>, _> = terms
                    .iter()
                    .map(|t| self.translate_term(t).and_then(|z| z.into_bool()))
                    .collect();
                let bools = bools?;
                let refs: Vec<&z3::ast::Bool> = bools.iter().collect();
                Ok(Z3Term::Bool(z3::ast::Bool::or(&refs)))
            }
            SmtTerm::Not(inner) => {
                let b = self.translate_term(inner)?.into_bool()?;
                Ok(Z3Term::Bool(b.not()))
            }
            SmtTerm::Implies(lhs, rhs) => {
                let l = self.translate_term(lhs)?.into_bool()?;
                let r = self.translate_term(rhs)?.into_bool()?;
                Ok(Z3Term::Bool(l.implies(&r)))
            }
            SmtTerm::Ite(cond, then, els) => {
                let c = self.translate_term(cond)?.into_bool()?;
                let t = self.translate_term(then)?;
                let e = self.translate_term(els)?;
                match (t, e) {
                    (Z3Term::Int(ti), Z3Term::Int(ei)) => Ok(Z3Term::Int(c.ite(&ti, &ei))),
                    (Z3Term::Bool(tb), Z3Term::Bool(eb)) => Ok(Z3Term::Bool(c.ite(&tb, &eb))),
                    _ => Err(Z3Error::Internal("Sort mismatch in ITE".into())),
                }
            }
            SmtTerm::ForAll(_, _) | SmtTerm::Exists(_, _) => Err(Z3Error::Internal(
                "Quantifiers not supported in BMC encoding".into(),
            )),
        }
    }
}

enum Z3Term {
    Int(z3::ast::Int),
    Bool(z3::ast::Bool),
}

impl Z3Term {
    fn into_int(self) -> Result<z3::ast::Int, Z3Error> {
        match self {
            Z3Term::Int(i) => Ok(i),
            Z3Term::Bool(_) => Err(Z3Error::Internal("Expected Int, got Bool".into())),
        }
    }

    fn into_bool(self) -> Result<z3::ast::Bool, Z3Error> {
        match self {
            Z3Term::Bool(b) => Ok(b),
            Z3Term::Int(_) => Err(Z3Error::Internal("Expected Bool, got Int".into())),
        }
    }
}

impl Default for Z3Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtSolver for Z3Solver {
    type Error = Z3Error;

    fn declare_var(&mut self, name: &str, sort: &SmtSort) -> Result<(), Z3Error> {
        match sort {
            SmtSort::Int => {
                let v = z3::ast::Int::new_const(name);
                self.int_vars.insert(name.to_string(), v);
            }
            SmtSort::Bool => {
                let v = z3::ast::Bool::new_const(name);
                self.bool_vars.insert(name.to_string(), v);
            }
        }
        Ok(())
    }

    fn assert(&mut self, term: &SmtTerm) -> Result<(), Z3Error> {
        let z3_term = self.translate_term(term)?.into_bool()?;
        self.solver.assert(&z3_term);
        Ok(())
    }

    fn push(&mut self) -> Result<(), Z3Error> {
        self.solver.push();
        Ok(())
    }

    fn pop(&mut self) -> Result<(), Z3Error> {
        self.solver.pop(1);
        Ok(())
    }

    fn check_sat(&mut self) -> Result<SatResult, Z3Error> {
        match self.solver.check() {
            Z3SatResult::Sat => Ok(SatResult::Sat),
            Z3SatResult::Unsat => Ok(SatResult::Unsat),
            Z3SatResult::Unknown => Ok(SatResult::Unknown("Z3 returned unknown".into())),
        }
    }

    fn check_sat_with_model(
        &mut self,
        var_names: &[(&str, &SmtSort)],
    ) -> Result<(SatResult, Option<Model>), Z3Error> {
        match self.solver.check() {
            Z3SatResult::Sat => {
                let z3_model = self
                    .solver
                    .get_model()
                    .ok_or_else(|| Z3Error::Internal("SAT but no model available".into()))?;
                let mut values = HashMap::new();

                for &(name, sort) in var_names {
                    match sort {
                        SmtSort::Int => {
                            if let Some(v) = self.int_vars.get(name) {
                                if let Some(val) = z3_model.eval::<z3::ast::Int>(v, true) {
                                    if let Some(n) = val.as_i64() {
                                        values.insert(name.to_string(), ModelValue::Int(n));
                                    }
                                }
                            }
                        }
                        SmtSort::Bool => {
                            if let Some(v) = self.bool_vars.get(name) {
                                if let Some(val) = z3_model.eval::<z3::ast::Bool>(v, true) {
                                    if let Some(b) = val.as_bool() {
                                        values.insert(name.to_string(), ModelValue::Bool(b));
                                    }
                                }
                            }
                        }
                    }
                }

                Ok((SatResult::Sat, Some(Model { values })))
            }
            Z3SatResult::Unsat => Ok((SatResult::Unsat, None)),
            Z3SatResult::Unknown => Ok((SatResult::Unknown("Z3 returned unknown".into()), None)),
        }
    }

    fn supports_assumption_unsat_core(&self) -> bool {
        true
    }

    fn check_sat_assuming(&mut self, assumptions: &[String]) -> Result<SatResult, Z3Error> {
        let mut asts = Vec::with_capacity(assumptions.len());
        for name in assumptions {
            let Some(var) = self.bool_vars.get(name) else {
                return Err(Z3Error::UnknownVariable(name.clone()));
            };
            asts.push(var.clone());
        }
        self.last_assumption_names = assumptions.to_vec();
        self.last_assumption_terms = asts.clone();
        match self.solver.check_assumptions(&asts) {
            Z3SatResult::Sat => Ok(SatResult::Sat),
            Z3SatResult::Unsat => Ok(SatResult::Unsat),
            Z3SatResult::Unknown => Ok(SatResult::Unknown("Z3 returned unknown".into())),
        }
    }

    fn get_unsat_core_assumptions(&mut self) -> Result<Vec<String>, Z3Error> {
        let core = self.solver.get_unsat_core();
        let mut out = Vec::new();
        for core_lit in core {
            if let Some((idx, _)) = self
                .last_assumption_terms
                .iter()
                .enumerate()
                .find(|(_, lit)| **lit == core_lit)
            {
                out.push(self.last_assumption_names[idx].clone());
            }
        }
        Ok(out)
    }

    fn reset(&mut self) -> Result<(), Z3Error> {
        self.solver.reset();
        // Z3 may drop per-solver parameters on reset; reapply timeout if configured.
        if let Some(params) = &self._params {
            self.solver.set_params(params);
        }
        self.int_vars.clear();
        self.bool_vars.clear();
        self.last_assumption_names.clear();
        self.last_assumption_terms.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn z3_basic_sat() -> TestResult {
        let mut solver = Z3Solver::with_default_config();

        solver.declare_var("x", &SmtSort::Int)?;
        solver.declare_var("y", &SmtSort::Int)?;

        // x > 0 && y > 0 && x + y == 10
        let term = SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("y").gt(SmtTerm::int(0)),
            SmtTerm::var("x")
                .add(SmtTerm::var("y"))
                .eq(SmtTerm::int(10)),
        ]);
        solver.assert(&term)?;
        let result = solver.check_sat()?;
        assert_eq!(result, SatResult::Sat);
        Ok(())
    }

    #[test]
    fn z3_basic_unsat() -> TestResult {
        let mut solver = Z3Solver::with_default_config();

        solver.declare_var("x", &SmtSort::Int)?;

        // x > 0 && x < 0
        let term = SmtTerm::and(vec![
            SmtTerm::var("x").gt(SmtTerm::int(0)),
            SmtTerm::var("x").lt(SmtTerm::int(0)),
        ]);
        solver.assert(&term)?;
        let result = solver.check_sat()?;
        assert_eq!(result, SatResult::Unsat);
        Ok(())
    }

    #[test]
    fn z3_model_extraction() -> TestResult {
        let mut solver = Z3Solver::with_default_config();

        solver.declare_var("x", &SmtSort::Int)?;
        solver.assert(&SmtTerm::var("x").eq(SmtTerm::int(42)))?;

        let vars = vec![("x", &SmtSort::Int)];
        let (result, model) = solver.check_sat_with_model(&vars)?;
        assert_eq!(result, SatResult::Sat);
        let model = model.ok_or_else(|| {
            std::io::Error::other("expected model for SAT result in z3_model_extraction")
        })?;
        assert_eq!(model.get_int("x"), Some(42));
        Ok(())
    }

    #[test]
    fn z3_assumption_unsat_core_roundtrip() -> TestResult {
        let mut solver = Z3Solver::with_default_config();
        solver.declare_var("x", &SmtSort::Int)?;
        solver.declare_var("a", &SmtSort::Bool)?;
        solver.declare_var("b", &SmtSort::Bool)?;

        // a => x > 0, b => x < 0
        solver.assert(&SmtTerm::var("a").implies(SmtTerm::var("x").gt(SmtTerm::int(0))))?;
        solver.assert(&SmtTerm::var("b").implies(SmtTerm::var("x").lt(SmtTerm::int(0))))?;

        let sat = solver.check_sat_assuming(&["a".to_string(), "b".to_string()])?;
        assert_eq!(sat, SatResult::Unsat);

        let core = solver.get_unsat_core_assumptions()?;
        assert!(core.contains(&"a".to_string()));
        assert!(core.contains(&"b".to_string()));
        Ok(())
    }

    #[test]
    fn z3_timeout_configuration_survives_reset() -> TestResult {
        let mut solver = Z3Solver::with_timeout_secs(2);
        assert!(
            solver._params.is_some(),
            "timeout-backed solver should persist params for reset()"
        );

        solver.declare_var("x", &SmtSort::Int)?;
        solver.assert(&SmtTerm::var("x").eq(SmtTerm::int(1)))?;
        assert_eq!(solver.check_sat()?, SatResult::Sat);

        solver.reset()?;
        solver.declare_var("x", &SmtSort::Int)?;
        solver.assert(&SmtTerm::var("x").eq(SmtTerm::int(2)))?;
        assert_eq!(solver.check_sat()?, SatResult::Sat);
        assert!(
            solver._params.is_some(),
            "timeout parameters should still be available after reset()"
        );
        Ok(())
    }

    #[test]
    fn z3_declare_var_redeclaration_overwrites() -> TestResult {
        let mut solver = Z3Solver::with_default_config();
        solver.declare_var("x", &SmtSort::Int)?;
        // Redeclare with same sort — should overwrite cleanly
        solver.declare_var("x", &SmtSort::Int)?;
        solver.assert(&SmtTerm::var("x").eq(SmtTerm::int(5)))?;
        assert_eq!(solver.check_sat()?, SatResult::Sat);
        Ok(())
    }

    #[test]
    fn z3_translate_nested_ite() -> TestResult {
        let mut solver = Z3Solver::with_default_config();
        solver.declare_var("a", &SmtSort::Bool)?;
        solver.declare_var("b", &SmtSort::Bool)?;
        solver.declare_var("x", &SmtSort::Int)?;

        // x == ite(a, ite(b, 1, 2), 3)
        let inner_ite = SmtTerm::Ite(
            Box::new(SmtTerm::var("b")),
            Box::new(SmtTerm::int(1)),
            Box::new(SmtTerm::int(2)),
        );
        let outer_ite = SmtTerm::Ite(
            Box::new(SmtTerm::var("a")),
            Box::new(inner_ite),
            Box::new(SmtTerm::int(3)),
        );
        let constraint = SmtTerm::var("x").eq(outer_ite);
        solver.assert(&constraint)?;

        // a = true, b = true => x = 1
        solver.assert(&SmtTerm::var("a").eq(SmtTerm::bool(true)))?;
        solver.assert(&SmtTerm::var("b").eq(SmtTerm::bool(true)))?;

        let vars = vec![("x", &SmtSort::Int)];
        let (result, model) = solver.check_sat_with_model(&vars)?;
        assert_eq!(result, SatResult::Sat);
        let model = model.ok_or_else(|| {
            std::io::Error::other("expected model for SAT result in z3_translate_nested_ite")
        })?;
        assert_eq!(model.get_int("x"), Some(1));
        Ok(())
    }

    #[test]
    fn z3_quantifier_rejection() -> TestResult {
        let mut solver = Z3Solver::with_default_config();
        solver.declare_var("x", &SmtSort::Int)?;

        let forall = SmtTerm::ForAll(
            vec![("y".to_string(), SmtSort::Int)],
            Box::new(SmtTerm::var("x").gt(SmtTerm::var("y"))),
        );
        let result = solver.assert(&forall);
        assert!(result.is_err(), "ForAll should be rejected by z3 backend");

        let exists = SmtTerm::Exists(
            vec![("y".to_string(), SmtSort::Int)],
            Box::new(SmtTerm::var("x").gt(SmtTerm::var("y"))),
        );
        let result = solver.assert(&exists);
        assert!(result.is_err(), "Exists should be rejected by z3 backend");
        Ok(())
    }
}
