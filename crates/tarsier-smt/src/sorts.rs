/// SMT sorts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SmtSort {
    Bool,
    Int,
}

impl std::fmt::Display for SmtSort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtSort::Bool => write!(f, "Bool"),
            SmtSort::Int => write!(f, "Int"),
        }
    }
}
