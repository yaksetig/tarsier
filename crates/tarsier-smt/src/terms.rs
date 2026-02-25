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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_literal_and_variable_builders_create_expected_nodes() {
        assert_eq!(SmtTerm::var("x"), SmtTerm::Var("x".to_string()));
        assert_eq!(SmtTerm::int(7), SmtTerm::IntLit(7));
        assert_eq!(SmtTerm::bool(true), SmtTerm::BoolLit(true));
    }

    #[test]
    fn arithmetic_and_comparison_builders_preserve_operand_order() {
        let x = SmtTerm::var("x");
        let y = SmtTerm::var("y");
        let expr = x.clone().add(y.clone()).mul(SmtTerm::int(3));
        let cmp = expr.clone().ge(SmtTerm::int(0));
        let eq = x.clone().sub(y.clone()).eq(SmtTerm::int(1));

        assert!(matches!(expr, SmtTerm::Mul(_, _)));
        assert!(matches!(cmp, SmtTerm::Ge(_, _)));
        assert!(matches!(eq, SmtTerm::Eq(_, _)));
    }

    #[test]
    fn boolean_connective_builders_create_expected_shapes() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        let c = SmtTerm::var("c");

        let and_term = SmtTerm::and(vec![a.clone(), b.clone()]);
        let or_term = SmtTerm::or(vec![b.clone(), c.clone()]);
        let not_term = a.clone().not();
        let impl_term = a.clone().implies(c.clone());

        assert_eq!(and_term, SmtTerm::And(vec![a.clone(), b.clone()]));
        assert_eq!(or_term, SmtTerm::Or(vec![b.clone(), c.clone()]));
        assert_eq!(not_term, SmtTerm::Not(Box::new(a.clone())));
        assert_eq!(impl_term, SmtTerm::Implies(Box::new(a), Box::new(c)));
    }

    #[test]
    fn quantifier_and_ite_nodes_are_constructible() {
        let body = SmtTerm::var("x").ge(SmtTerm::int(0));
        let forall = SmtTerm::ForAll(
            vec![("x".to_string(), SmtSort::Int)],
            Box::new(body.clone()),
        );
        let exists = SmtTerm::Exists(
            vec![("b".to_string(), SmtSort::Bool)],
            Box::new(body.clone()),
        );
        let ite = SmtTerm::Ite(
            Box::new(SmtTerm::bool(true)),
            Box::new(SmtTerm::int(1)),
            Box::new(SmtTerm::int(0)),
        );

        assert!(matches!(forall, SmtTerm::ForAll(_, _)));
        assert!(matches!(exists, SmtTerm::Exists(_, _)));
        assert!(matches!(ite, SmtTerm::Ite(_, _, _)));
    }

    #[test]
    fn sub_preserves_operand_order() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        let sub = a.sub(b);
        assert_eq!(
            sub,
            SmtTerm::Sub(Box::new(SmtTerm::var("a")), Box::new(SmtTerm::var("b")))
        );
    }

    #[test]
    fn implies_preserves_direction() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        let imp = a.implies(b);
        assert_eq!(
            imp,
            SmtTerm::Implies(Box::new(SmtTerm::var("a")), Box::new(SmtTerm::var("b")))
        );
    }

    #[test]
    fn and_empty_vec() {
        let and = SmtTerm::and(vec![]);
        assert_eq!(and, SmtTerm::And(vec![]));
    }

    #[test]
    fn or_empty_vec() {
        let or = SmtTerm::or(vec![]);
        assert_eq!(or, SmtTerm::Or(vec![]));
    }

    #[test]
    fn and_single_element() {
        let a = SmtTerm::var("a");
        let and = SmtTerm::and(vec![a.clone()]);
        assert_eq!(and, SmtTerm::And(vec![SmtTerm::var("a")]));
    }

    #[test]
    fn double_negation_structure() {
        let a = SmtTerm::var("a");
        let double_neg = a.not().not();
        assert_eq!(
            double_neg,
            SmtTerm::Not(Box::new(SmtTerm::Not(Box::new(SmtTerm::var("a")))))
        );
    }

    #[test]
    fn nested_arithmetic_left_associativity() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        let c = SmtTerm::var("c");
        let expr = a.add(b).add(c);
        // (a + b) + c
        assert_eq!(
            expr,
            SmtTerm::Add(
                Box::new(SmtTerm::Add(
                    Box::new(SmtTerm::var("a")),
                    Box::new(SmtTerm::var("b")),
                )),
                Box::new(SmtTerm::var("c")),
            )
        );
    }

    #[test]
    fn lt_le_gt_ge_all_distinct_variants() {
        let x = SmtTerm::var("x");
        let y = SmtTerm::var("y");
        let lt = x.clone().lt(y.clone());
        let le = x.clone().le(y.clone());
        let gt = x.clone().gt(y.clone());
        let ge = x.clone().ge(y.clone());
        assert!(matches!(lt, SmtTerm::Lt(_, _)));
        assert!(matches!(le, SmtTerm::Le(_, _)));
        assert!(matches!(gt, SmtTerm::Gt(_, _)));
        assert!(matches!(ge, SmtTerm::Ge(_, _)));
        // All four are structurally distinct
        assert_ne!(x.clone().lt(y.clone()), x.clone().le(y.clone()));
        assert_ne!(x.clone().gt(y.clone()), x.clone().ge(y.clone()));
        assert_ne!(x.clone().lt(y.clone()), x.clone().gt(y.clone()));
    }

    #[test]
    fn ite_preserves_all_three_branches() {
        let cond = SmtTerm::var("c");
        let then_t = SmtTerm::int(1);
        let else_t = SmtTerm::int(2);
        let ite = SmtTerm::Ite(
            Box::new(cond.clone()),
            Box::new(then_t.clone()),
            Box::new(else_t.clone()),
        );
        match ite {
            SmtTerm::Ite(c, t, e) => {
                assert_eq!(*c, cond);
                assert_eq!(*t, then_t);
                assert_eq!(*e, else_t);
            }
            _ => panic!("expected Ite"),
        }
    }

    #[test]
    fn eq_is_not_commutative_at_term_level() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        assert_ne!(a.clone().eq(b.clone()), b.eq(a));
    }

    #[test]
    fn large_and_or_vectors() {
        let terms: Vec<SmtTerm> = (0..100).map(|i| SmtTerm::var(format!("x_{i}"))).collect();
        let and = SmtTerm::and(terms.clone());
        let or = SmtTerm::or(terms.clone());
        match and {
            SmtTerm::And(v) => assert_eq!(v.len(), 100),
            _ => panic!("expected And"),
        }
        match or {
            SmtTerm::Or(v) => assert_eq!(v.len(), 100),
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn var_accepts_string_and_str() {
        let from_str = SmtTerm::var("x");
        let from_string = SmtTerm::var(String::from("x"));
        assert_eq!(from_str, from_string);
    }
}
