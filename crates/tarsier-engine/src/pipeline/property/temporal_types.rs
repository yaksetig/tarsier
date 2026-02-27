//! `LivenessSpec`, `TemporalFormula`, `TemporalBuchiAutomaton`, etc.

use super::*;

#[derive(Debug, Clone)]
pub(crate) enum LivenessSpec {
    TerminationGoalLocs(Vec<usize>),
    Temporal {
        quantifiers: Vec<ast::QuantifierBinding>,
        formula: ast::FormulaExpr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum TemporalFormula {
    True,
    False,
    Atom(usize),
    NotAtom(usize),
    Next(Box<TemporalFormula>),
    And(Box<TemporalFormula>, Box<TemporalFormula>),
    Or(Box<TemporalFormula>, Box<TemporalFormula>),
    Until(Box<TemporalFormula>, Box<TemporalFormula>),
    Release(Box<TemporalFormula>, Box<TemporalFormula>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum TemporalAtomLit {
    Pos(usize),
    Neg(usize),
}

#[derive(Debug, Clone)]
pub(crate) struct TemporalBuchiState {
    pub(crate) old: BTreeSet<TemporalFormula>,
    pub(crate) label_lits: Vec<TemporalAtomLit>,
    pub(crate) transitions: Vec<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct TemporalBuchiAutomaton {
    pub(crate) quantifier: ast::Quantifier,
    pub(crate) quantified_var: String,
    pub(crate) role: String,
    pub(crate) quantifiers: Vec<ast::QuantifierBinding>,
    pub(crate) atoms: Vec<ast::FormulaExpr>,
    pub(crate) states: Vec<TemporalBuchiState>,
    pub(crate) initial_states: Vec<usize>,
    pub(crate) acceptance_sets: Vec<Vec<usize>>,
}

#[derive(Debug, Clone)]
pub(crate) enum FairLivenessTarget {
    NonGoalLocs(Vec<usize>),
    Temporal(TemporalBuchiAutomaton),
}
