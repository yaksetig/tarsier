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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn display_renders_standard_smt_sort_names() {
        assert_eq!(SmtSort::Bool.to_string(), "Bool");
        assert_eq!(SmtSort::Int.to_string(), "Int");
    }

    #[test]
    fn sorts_are_hashable_and_distinct() {
        let mut seen = HashSet::new();
        seen.insert(SmtSort::Bool);
        seen.insert(SmtSort::Int);
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&SmtSort::Bool));
        assert!(seen.contains(&SmtSort::Int));
    }
}
