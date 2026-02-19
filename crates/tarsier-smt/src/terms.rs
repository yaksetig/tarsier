use crate::sorts::SmtSort;

/// Abstract SMT term representation, solver-agnostic.
#[derive(Debug, Clone, PartialEq)]
pub enum SmtTerm {
    /// Variable reference by name.
    Var(String),
    /// Integer literal.
    IntLit(i64),
    /// Boolean literal.
    BoolLit(bool),

    // Arithmetic
    Add(Box<SmtTerm>, Box<SmtTerm>),
    Sub(Box<SmtTerm>, Box<SmtTerm>),
    Mul(Box<SmtTerm>, Box<SmtTerm>),

    // Comparison
    Eq(Box<SmtTerm>, Box<SmtTerm>),
    Lt(Box<SmtTerm>, Box<SmtTerm>),
    Le(Box<SmtTerm>, Box<SmtTerm>),
    Gt(Box<SmtTerm>, Box<SmtTerm>),
    Ge(Box<SmtTerm>, Box<SmtTerm>),

    // Boolean logic
    And(Vec<SmtTerm>),
    Or(Vec<SmtTerm>),
    Not(Box<SmtTerm>),
    Implies(Box<SmtTerm>, Box<SmtTerm>),

    // Quantifiers (for completeness)
    ForAll(Vec<(String, SmtSort)>, Box<SmtTerm>),
    Exists(Vec<(String, SmtSort)>, Box<SmtTerm>),

    // If-then-else
    Ite(Box<SmtTerm>, Box<SmtTerm>, Box<SmtTerm>),
}

#[allow(clippy::should_implement_trait)]
impl SmtTerm {
    pub fn var(name: impl Into<String>) -> Self {
        SmtTerm::Var(name.into())
    }

    pub fn int(n: i64) -> Self {
        SmtTerm::IntLit(n)
    }

    pub fn bool(b: bool) -> Self {
        SmtTerm::BoolLit(b)
    }

    pub fn add(self, other: SmtTerm) -> Self {
        SmtTerm::Add(Box::new(self), Box::new(other))
    }

    pub fn sub(self, other: SmtTerm) -> Self {
        SmtTerm::Sub(Box::new(self), Box::new(other))
    }

    pub fn mul(self, other: SmtTerm) -> Self {
        SmtTerm::Mul(Box::new(self), Box::new(other))
    }

    pub fn eq(self, other: SmtTerm) -> Self {
        SmtTerm::Eq(Box::new(self), Box::new(other))
    }

    pub fn lt(self, other: SmtTerm) -> Self {
        SmtTerm::Lt(Box::new(self), Box::new(other))
    }

    pub fn le(self, other: SmtTerm) -> Self {
        SmtTerm::Le(Box::new(self), Box::new(other))
    }

    pub fn gt(self, other: SmtTerm) -> Self {
        SmtTerm::Gt(Box::new(self), Box::new(other))
    }

    pub fn ge(self, other: SmtTerm) -> Self {
        SmtTerm::Ge(Box::new(self), Box::new(other))
    }

    pub fn and(terms: Vec<SmtTerm>) -> Self {
        SmtTerm::And(terms)
    }

    pub fn or(terms: Vec<SmtTerm>) -> Self {
        SmtTerm::Or(terms)
    }

    pub fn not(self) -> Self {
        SmtTerm::Not(Box::new(self))
    }

    pub fn implies(self, other: SmtTerm) -> Self {
        SmtTerm::Implies(Box::new(self), Box::new(other))
    }
}
