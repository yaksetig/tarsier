use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use thiserror::Error;

use crate::backends::smtlib_printer::{sort_to_smtlib, to_smtlib};
use crate::solver::{Model, ModelValue, SatResult, SmtSolver};
use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

#[derive(Debug, Error)]
pub enum Cvc5Error {
    #[error("cvc5 I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cvc5 not found: {0}")]
    NotFound(String),
    #[error("cvc5 error: {0}")]
    SolverError(String),
    #[error("Failed to parse cvc5 output: {0}")]
    ParseError(String),
}

pub struct Cvc5Solver {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: BufReader<ChildStderr>,
    vars: HashMap<String, SmtSort>,
    last_assumptions: Vec<String>,
}

impl Cvc5Solver {
    pub fn new() -> Result<Self, Cvc5Error> {
        Self::with_command_and_timeout("cvc5", None)
    }

    pub fn with_timeout_secs(timeout_secs: u64) -> Result<Self, Cvc5Error> {
        if timeout_secs == 0 {
            return Self::with_command_and_timeout("cvc5", None);
        }
        let timeout_ms = timeout_secs.saturating_mul(1000);
        Self::with_command_and_timeout("cvc5", Some(timeout_ms))
    }

    pub fn with_command(cmd: &str) -> Result<Self, Cvc5Error> {
        Self::with_command_and_timeout(cmd, None)
    }

    pub fn with_command_and_timeout(cmd: &str, timeout_ms: Option<u64>) -> Result<Self, Cvc5Error> {
        let mut args = vec![
            "--lang".to_string(),
            "smt2".to_string(),
            "--incremental".to_string(),
            "--produce-models".to_string(),
            "--produce-unsat-assumptions".to_string(),
        ];
        if let Some(ms) = timeout_ms {
            args.push(format!("--tlimit={ms}"));
        }

        let mut child = Command::new(cmd)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Cvc5Error::NotFound(format!("{cmd}: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Cvc5Error::SolverError("failed to capture cvc5 stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Cvc5Error::SolverError("failed to capture cvc5 stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Cvc5Error::SolverError("failed to capture cvc5 stderr".into()))?;

        let mut solver = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr: BufReader::new(stderr),
            vars: HashMap::new(),
            last_assumptions: Vec::new(),
        };

        solver.send_command("(set-logic QF_LIA)")?;
        Ok(solver)
    }

    fn send_command(&mut self, cmd: &str) -> Result<String, Cvc5Error> {
        writeln!(self.stdin, "{cmd}")?;
        self.stdin.flush()?;

        // Read one line of response
        let mut response = String::new();
        self.stdout.read_line(&mut response)?;
        if response.is_empty() {
            let mut stderr = String::new();
            let _ = self.stderr.read_line(&mut stderr);
            return Err(Cvc5Error::SolverError(format!(
                "No response from cvc5 for command `{cmd}`. stderr: {}",
                stderr.trim()
            )));
        }
        Ok(response.trim_end().to_string())
    }

    fn send_command_no_response(&mut self, cmd: &str) -> Result<(), Cvc5Error> {
        writeln!(self.stdin, "{cmd}")?;
        self.stdin.flush()?;
        Ok(())
    }
}

impl Drop for Cvc5Solver {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "(exit)");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

impl SmtSolver for Cvc5Solver {
    type Error = Cvc5Error;

    fn declare_var(&mut self, name: &str, sort: &SmtSort) -> Result<(), Cvc5Error> {
        let sort_str = sort_to_smtlib(sort);
        self.send_command_no_response(&format!("(declare-const {name} {sort_str})"))?;
        self.vars.insert(name.to_string(), sort.clone());
        Ok(())
    }

    fn assert(&mut self, term: &SmtTerm) -> Result<(), Cvc5Error> {
        let smt_str = to_smtlib(term);
        self.send_command_no_response(&format!("(assert {smt_str})"))?;
        Ok(())
    }

    fn push(&mut self) -> Result<(), Cvc5Error> {
        self.send_command_no_response("(push 1)")?;
        Ok(())
    }

    fn pop(&mut self) -> Result<(), Cvc5Error> {
        self.send_command_no_response("(pop 1)")?;
        Ok(())
    }

    fn check_sat(&mut self) -> Result<SatResult, Cvc5Error> {
        let response = self.send_command("(check-sat)")?;
        match response.as_str() {
            "sat" => Ok(SatResult::Sat),
            "unsat" => Ok(SatResult::Unsat),
            "unknown" => Ok(SatResult::Unknown("cvc5 returned unknown".into())),
            other => Err(Cvc5Error::SolverError(other.to_string())),
        }
    }

    fn check_sat_with_model(
        &mut self,
        var_names: &[(&str, &SmtSort)],
    ) -> Result<(SatResult, Option<Model>), Cvc5Error> {
        let result = self.check_sat()?;
        if result != SatResult::Sat {
            return Ok((result, None));
        }

        let mut values = HashMap::new();
        for &(name, sort) in var_names {
            let response = self.send_command(&format!("(get-value ({name}))"))?;
            // Response format: ((name value))
            if let Some(val) = parse_cvc5_value(&response, name, sort) {
                values.insert(name.to_string(), val);
            }
        }

        Ok((SatResult::Sat, Some(Model { values })))
    }

    fn supports_assumption_unsat_core(&self) -> bool {
        true
    }

    fn check_sat_assuming(&mut self, assumptions: &[String]) -> Result<SatResult, Cvc5Error> {
        for name in assumptions {
            match self.vars.get(name) {
                Some(SmtSort::Bool) => {}
                Some(_) => {
                    return Err(Cvc5Error::SolverError(format!(
                        "assumption `{name}` is not declared as Bool"
                    )));
                }
                None => {
                    return Err(Cvc5Error::SolverError(format!(
                        "assumption `{name}` is not declared"
                    )));
                }
            }
        }
        self.last_assumptions = assumptions.to_vec();
        let payload = assumptions.join(" ");
        let response = self.send_command(&format!("(check-sat-assuming ({payload}))"))?;
        match response.as_str() {
            "sat" => Ok(SatResult::Sat),
            "unsat" => Ok(SatResult::Unsat),
            "unknown" => Ok(SatResult::Unknown("cvc5 returned unknown".into())),
            other => Err(Cvc5Error::SolverError(other.to_string())),
        }
    }

    fn get_unsat_core_assumptions(&mut self) -> Result<Vec<String>, Cvc5Error> {
        let response = self.send_command("(get-unsat-assumptions)")?;
        Ok(parse_cvc5_unsat_assumptions(&response)
            .into_iter()
            .filter(|name| self.last_assumptions.iter().any(|a| a == name))
            .collect())
    }

    fn reset(&mut self) -> Result<(), Cvc5Error> {
        self.send_command_no_response("(reset)")?;
        self.send_command_no_response("(set-logic QF_LIA)")?;
        self.vars.clear();
        self.last_assumptions.clear();
        Ok(())
    }
}

fn parse_cvc5_value(response: &str, _name: &str, sort: &SmtSort) -> Option<ModelValue> {
    // Strip outer parens: ((name value)) → name value
    let inner = response
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    let parts: Vec<&str> = inner.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let val_str = parts[1].trim().trim_end_matches(')').trim();

    match sort {
        SmtSort::Int => {
            // Handle (- N) format
            if val_str.starts_with("(- ") {
                let num_str = val_str.trim_start_matches("(- ").trim_end_matches(')');
                num_str.parse::<i64>().ok().map(|n| ModelValue::Int(-n))
            } else {
                val_str.parse::<i64>().ok().map(ModelValue::Int)
            }
        }
        SmtSort::Bool => match val_str {
            "true" => Some(ModelValue::Bool(true)),
            "false" => Some(ModelValue::Bool(false)),
            _ => None,
        },
    }
}

fn parse_cvc5_unsat_assumptions(response: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quoted_symbol = false;
    for ch in response.trim().chars() {
        match ch {
            '(' | ')' if !in_quoted_symbol => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            '|' => {
                in_quoted_symbol = !in_quoted_symbol;
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            c if c.is_whitespace() && !in_quoted_symbol => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            other => buf.push(other),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cvc5_int_value() {
        let v = parse_cvc5_value("((x 42))", "x", &SmtSort::Int);
        match v {
            Some(ModelValue::Int(n)) => assert_eq!(n, 42),
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn parse_cvc5_negative_int_value() {
        let v = parse_cvc5_value("((x (- 7)))", "x", &SmtSort::Int);
        match v {
            Some(ModelValue::Int(n)) => assert_eq!(n, -7),
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn parse_cvc5_bool_value() {
        let t = parse_cvc5_value("((b true))", "b", &SmtSort::Bool);
        let f = parse_cvc5_value("((b false))", "b", &SmtSort::Bool);
        assert!(matches!(t, Some(ModelValue::Bool(true))));
        assert!(matches!(f, Some(ModelValue::Bool(false))));
    }

    #[test]
    fn parse_cvc5_unsat_assumption_list() {
        assert_eq!(
            parse_cvc5_unsat_assumptions("(a b c)"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(
            parse_cvc5_unsat_assumptions("(|a b| c)"),
            vec!["a b".to_string(), "c".to_string()]
        );
    }
}
