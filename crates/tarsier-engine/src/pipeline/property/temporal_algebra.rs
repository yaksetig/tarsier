//! `TemporalAtomTable`, NNF conversion, operators.

use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct TemporalAtomTable {
    pub(crate) atoms: Vec<ast::FormulaExpr>,
}

impl TemporalAtomTable {
    pub(crate) fn intern(&mut self, expr: &ast::FormulaExpr) -> usize {
        if let Some(idx) = self.atoms.iter().position(|existing| existing == expr) {
            idx
        } else {
            let idx = self.atoms.len();
            self.atoms.push(expr.clone());
            idx
        }
    }
}

pub(crate) fn temporal_and(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::False, _) | (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) | (other, TemporalFormula::True) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::And(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::And(Box::new(right), Box::new(left))
            }
        }
    }
}

pub(crate) fn temporal_or(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (TemporalFormula::True, _) | (_, TemporalFormula::True) => TemporalFormula::True,
        (TemporalFormula::False, other) | (other, TemporalFormula::False) => other,
        (left, right) if left == right => left,
        (left, right) => {
            if left <= right {
                TemporalFormula::Or(Box::new(left), Box::new(right))
            } else {
                TemporalFormula::Or(Box::new(right), Box::new(left))
            }
        }
    }
}

pub(crate) fn temporal_until(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::False, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Until(Box::new(left), Box::new(right)),
    }
}

pub(crate) fn temporal_release(lhs: TemporalFormula, rhs: TemporalFormula) -> TemporalFormula {
    match (lhs, rhs) {
        (_, TemporalFormula::True) => TemporalFormula::True,
        (_, TemporalFormula::False) => TemporalFormula::False,
        (TemporalFormula::True, other) => other,
        (left, right) if left == right => left,
        (left, right) => TemporalFormula::Release(Box::new(left), Box::new(right)),
    }
}

pub(crate) fn formula_to_temporal_nnf(
    expr: &ast::FormulaExpr,
    atoms: &mut TemporalAtomTable,
    negated: bool,
) -> Result<TemporalFormula, PipelineError> {
    if !formula_contains_temporal(expr) {
        let atom = atoms.intern(expr);
        return Ok(if negated {
            TemporalFormula::NotAtom(atom)
        } else {
            TemporalFormula::Atom(atom)
        });
    }

    match expr {
        ast::FormulaExpr::Comparison { .. } => {
            let atom = atoms.intern(expr);
            Ok(if negated {
                TemporalFormula::NotAtom(atom)
            } else {
                TemporalFormula::Atom(atom)
            })
        }
        ast::FormulaExpr::Not(inner) => formula_to_temporal_nnf(inner, atoms, !negated),
        ast::FormulaExpr::And(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_or(l, r)
            } else {
                temporal_and(l, r)
            })
        }
        ast::FormulaExpr::Or(lhs, rhs) => {
            let l = formula_to_temporal_nnf(lhs, atoms, negated)?;
            let r = formula_to_temporal_nnf(rhs, atoms, negated)?;
            Ok(if negated {
                temporal_and(l, r)
            } else {
                temporal_or(l, r)
            })
        }
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let desugared =
                ast::FormulaExpr::Or(Box::new(ast::FormulaExpr::Not(lhs.clone())), rhs.clone());
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::And(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::And(
                    Box::new(ast::FormulaExpr::Not(lhs.clone())),
                    Box::new(ast::FormulaExpr::Not(rhs.clone())),
                )),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::Next(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(TemporalFormula::Next(Box::new(inner_nnf)))
        }
        ast::FormulaExpr::Always(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_until(TemporalFormula::True, inner_nnf)
            } else {
                temporal_release(TemporalFormula::False, inner_nnf)
            })
        }
        ast::FormulaExpr::Eventually(inner) => {
            let inner_nnf = formula_to_temporal_nnf(inner, atoms, negated)?;
            Ok(if negated {
                temporal_release(TemporalFormula::False, inner_nnf)
            } else {
                temporal_until(TemporalFormula::True, inner_nnf)
            })
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_release(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_until(l, r))
            }
        }
        ast::FormulaExpr::Release(lhs, rhs) => {
            if negated {
                let n_rhs = formula_to_temporal_nnf(rhs, atoms, true)?;
                let n_lhs = formula_to_temporal_nnf(lhs, atoms, true)?;
                Ok(temporal_until(n_rhs.clone(), temporal_and(n_lhs, n_rhs)))
            } else {
                let l = formula_to_temporal_nnf(lhs, atoms, false)?;
                let r = formula_to_temporal_nnf(rhs, atoms, false)?;
                Ok(temporal_release(l, r))
            }
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Or(
                Box::new(ast::FormulaExpr::Until(lhs.clone(), rhs.clone())),
                Box::new(ast::FormulaExpr::Always(lhs.clone())),
            );
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let desugared = ast::FormulaExpr::Always(Box::new(ast::FormulaExpr::Implies(
                lhs.clone(),
                Box::new(ast::FormulaExpr::Eventually(rhs.clone())),
            )));
            formula_to_temporal_nnf(&desugared, atoms, negated)
        }
    }
}

pub(crate) fn collect_until_formulas(
    formula: &TemporalFormula,
    out: &mut BTreeSet<TemporalFormula>,
) {
    match formula {
        TemporalFormula::Until(lhs, rhs) => {
            out.insert(formula.clone());
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::And(lhs, rhs)
        | TemporalFormula::Or(lhs, rhs)
        | TemporalFormula::Release(lhs, rhs) => {
            collect_until_formulas(lhs, out);
            collect_until_formulas(rhs, out);
        }
        TemporalFormula::Next(inner) => {
            collect_until_formulas(inner, out);
        }
        TemporalFormula::True
        | TemporalFormula::False
        | TemporalFormula::Atom(_)
        | TemporalFormula::NotAtom(_) => {}
    }
}

pub(crate) fn temporal_formula_canonical(formula: &TemporalFormula) -> String {
    match formula {
        TemporalFormula::True => "true".to_string(),
        TemporalFormula::False => "false".to_string(),
        TemporalFormula::Atom(id) => format!("atom({id})"),
        TemporalFormula::NotAtom(id) => format!("not_atom({id})"),
        TemporalFormula::Next(inner) => format!("X({})", temporal_formula_canonical(inner)),
        TemporalFormula::And(lhs, rhs) => format!(
            "and({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Or(lhs, rhs) => format!(
            "or({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Until(lhs, rhs) => format!(
            "until({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
        TemporalFormula::Release(lhs, rhs) => format!(
            "release({}, {})",
            temporal_formula_canonical(lhs),
            temporal_formula_canonical(rhs)
        ),
    }
}

pub(crate) fn temporal_buchi_monitor_canonical(automaton: &TemporalBuchiAutomaton) -> String {
    let mut chunks = Vec::new();
    chunks.push(format!(
        "quantifier={};quantified_var={};role={}",
        automaton.quantifier, automaton.quantified_var, automaton.role
    ));
    let quantifiers = automaton
        .quantifiers
        .iter()
        .map(|binding| format!("{}:{}:{}", binding.quantifier, binding.var, binding.domain))
        .collect::<Vec<_>>()
        .join(",");
    chunks.push(format!("quantifiers=[{quantifiers}]"));
    for (idx, atom) in automaton.atoms.iter().enumerate() {
        chunks.push(format!("atom[{idx}]={atom}"));
    }
    chunks.push(format!("initial={:?}", automaton.initial_states));
    for (acc_id, acc) in automaton.acceptance_sets.iter().enumerate() {
        chunks.push(format!("acceptance[{acc_id}]={acc:?}"));
    }
    for (sid, state) in automaton.states.iter().enumerate() {
        let old = state
            .old
            .iter()
            .map(temporal_formula_canonical)
            .collect::<Vec<_>>()
            .join(",");
        let labels = state
            .label_lits
            .iter()
            .map(|lit| match lit {
                TemporalAtomLit::Pos(id) => format!("+{id}"),
                TemporalAtomLit::Neg(id) => format!("-{id}"),
            })
            .collect::<Vec<_>>()
            .join(",");
        chunks.push(format!(
            "state[{sid}]:old=[{old}] labels=[{labels}] trans={:?}",
            state.transitions
        ));
    }
    chunks.join("\n")
}
