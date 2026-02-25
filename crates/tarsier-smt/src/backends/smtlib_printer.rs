use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

/// Print an SmtTerm as SMT-LIB2 format.
pub fn to_smtlib(term: &SmtTerm) -> String {
    match term {
        SmtTerm::Var(name) => name.clone(),
        SmtTerm::IntLit(n) => {
            if *n < 0 {
                format!("(- {})", -n)
            } else {
                n.to_string()
            }
        }
        SmtTerm::BoolLit(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        SmtTerm::Add(lhs, rhs) => format!("(+ {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Sub(lhs, rhs) => format!("(- {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Mul(lhs, rhs) => format!("(* {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Eq(lhs, rhs) => format!("(= {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Lt(lhs, rhs) => format!("(< {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Le(lhs, rhs) => format!("(<= {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Gt(lhs, rhs) => format!("(> {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::Ge(lhs, rhs) => format!("(>= {} {})", to_smtlib(lhs), to_smtlib(rhs)),
        SmtTerm::And(terms) => {
            if terms.is_empty() {
                "true".to_string()
            } else if terms.len() == 1 {
                to_smtlib(&terms[0])
            } else {
                let inner: Vec<String> = terms.iter().map(to_smtlib).collect();
                format!("(and {})", inner.join(" "))
            }
        }
        SmtTerm::Or(terms) => {
            if terms.is_empty() {
                "false".to_string()
            } else if terms.len() == 1 {
                to_smtlib(&terms[0])
            } else {
                let inner: Vec<String> = terms.iter().map(to_smtlib).collect();
                format!("(or {})", inner.join(" "))
            }
        }
        SmtTerm::Not(inner) => format!("(not {})", to_smtlib(inner)),
        SmtTerm::Implies(lhs, rhs) => {
            format!("(=> {} {})", to_smtlib(lhs), to_smtlib(rhs))
        }
        SmtTerm::ForAll(bindings, body) => {
            let vars: Vec<String> = bindings.iter().map(|(n, s)| format!("({n} {s})")).collect();
            format!("(forall ({}) {})", vars.join(" "), to_smtlib(body))
        }
        SmtTerm::Exists(bindings, body) => {
            let vars: Vec<String> = bindings.iter().map(|(n, s)| format!("({n} {s})")).collect();
            format!("(exists ({}) {})", vars.join(" "), to_smtlib(body))
        }
        SmtTerm::Ite(cond, then, els) => {
            format!(
                "(ite {} {} {})",
                to_smtlib(cond),
                to_smtlib(then),
                to_smtlib(els)
            )
        }
    }
}

/// Print a sort as SMT-LIB2 format.
pub fn sort_to_smtlib(sort: &SmtSort) -> &'static str {
    match sort {
        SmtSort::Bool => "Bool",
        SmtSort::Int => "Int",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_simple_term() {
        let term = SmtTerm::var("x").add(SmtTerm::int(1)).ge(SmtTerm::int(0));
        assert_eq!(to_smtlib(&term), "(>= (+ x 1) 0)");
    }

    #[test]
    fn print_and_term() {
        let term = SmtTerm::and(vec![
            SmtTerm::var("a").gt(SmtTerm::int(0)),
            SmtTerm::var("b").lt(SmtTerm::int(10)),
        ]);
        assert_eq!(to_smtlib(&term), "(and (> a 0) (< b 10))");
    }

    #[test]
    fn print_negative_integer() {
        assert_eq!(to_smtlib(&SmtTerm::int(-5)), "(- 5)");
        assert_eq!(to_smtlib(&SmtTerm::int(-1)), "(- 1)");
    }

    #[test]
    fn print_boolean_literals() {
        assert_eq!(to_smtlib(&SmtTerm::bool(true)), "true");
        assert_eq!(to_smtlib(&SmtTerm::bool(false)), "false");
    }

    #[test]
    fn print_sub_term() {
        let term = SmtTerm::var("a").sub(SmtTerm::var("b"));
        assert_eq!(to_smtlib(&term), "(- a b)");
    }

    #[test]
    fn print_mul_term() {
        let term = SmtTerm::var("a").mul(SmtTerm::var("b"));
        assert_eq!(to_smtlib(&term), "(* a b)");
    }

    #[test]
    fn print_eq_term() {
        let term = SmtTerm::var("a").eq(SmtTerm::var("b"));
        assert_eq!(to_smtlib(&term), "(= a b)");
    }

    #[test]
    fn print_le_lt_gt_terms() {
        assert_eq!(
            to_smtlib(&SmtTerm::var("x").le(SmtTerm::int(5))),
            "(<= x 5)"
        );
        assert_eq!(to_smtlib(&SmtTerm::var("x").lt(SmtTerm::int(5))), "(< x 5)");
        assert_eq!(to_smtlib(&SmtTerm::var("x").gt(SmtTerm::int(5))), "(> x 5)");
    }

    #[test]
    fn print_not_term() {
        assert_eq!(to_smtlib(&SmtTerm::var("x").not()), "(not x)");
    }

    #[test]
    fn print_implies_term() {
        let term = SmtTerm::var("a").implies(SmtTerm::var("b"));
        assert_eq!(to_smtlib(&term), "(=> a b)");
    }

    #[test]
    fn print_ite_term() {
        let term = SmtTerm::Ite(
            Box::new(SmtTerm::var("c")),
            Box::new(SmtTerm::int(1)),
            Box::new(SmtTerm::int(0)),
        );
        assert_eq!(to_smtlib(&term), "(ite c 1 0)");
    }

    #[test]
    fn print_and_or_empty_and_single() {
        // Empty And is identity: true
        assert_eq!(to_smtlib(&SmtTerm::and(vec![])), "true");
        // Empty Or is identity: false
        assert_eq!(to_smtlib(&SmtTerm::or(vec![])), "false");
        // Single element: unwrapped
        assert_eq!(to_smtlib(&SmtTerm::and(vec![SmtTerm::var("x")])), "x");
        assert_eq!(to_smtlib(&SmtTerm::or(vec![SmtTerm::var("y")])), "y");
    }

    #[test]
    fn print_forall_exists() {
        let forall = SmtTerm::ForAll(
            vec![("x".to_string(), SmtSort::Int)],
            Box::new(SmtTerm::var("x").ge(SmtTerm::int(0))),
        );
        assert_eq!(to_smtlib(&forall), "(forall ((x Int)) (>= x 0))");

        let exists = SmtTerm::Exists(
            vec![("b".to_string(), SmtSort::Bool)],
            Box::new(SmtTerm::var("b")),
        );
        assert_eq!(to_smtlib(&exists), "(exists ((b Bool)) b)");
    }

    #[test]
    fn sort_to_smtlib_values() {
        assert_eq!(sort_to_smtlib(&SmtSort::Bool), "Bool");
        assert_eq!(sort_to_smtlib(&SmtSort::Int), "Int");
    }

    // --- Deeply nested expression tests ---

    #[test]
    fn print_nested_and_inside_or() {
        let inner_and = SmtTerm::and(vec![SmtTerm::var("a"), SmtTerm::var("b")]);
        let inner_and2 = SmtTerm::and(vec![SmtTerm::var("c"), SmtTerm::var("d")]);
        let outer_or = SmtTerm::or(vec![inner_and, inner_and2]);
        assert_eq!(to_smtlib(&outer_or), "(or (and a b) (and c d))");
    }

    #[test]
    fn print_nested_or_inside_and() {
        let inner_or = SmtTerm::or(vec![SmtTerm::var("x"), SmtTerm::var("y")]);
        let outer = SmtTerm::and(vec![inner_or, SmtTerm::var("z")]);
        assert_eq!(to_smtlib(&outer), "(and (or x y) z)");
    }

    #[test]
    fn print_not_of_and() {
        let and_term = SmtTerm::and(vec![SmtTerm::var("p"), SmtTerm::var("q")]);
        let negated = SmtTerm::Not(Box::new(and_term));
        assert_eq!(to_smtlib(&negated), "(not (and p q))");
    }

    #[test]
    fn print_implies_with_compound_antecedent_and_consequent() {
        let antecedent = SmtTerm::and(vec![SmtTerm::var("a"), SmtTerm::var("b")]);
        let consequent = SmtTerm::or(vec![SmtTerm::var("c"), SmtTerm::var("d")]);
        let imp = antecedent.implies(consequent);
        assert_eq!(to_smtlib(&imp), "(=> (and a b) (or c d))");
    }

    #[test]
    fn print_nested_ite() {
        // (ite p (ite q 1 2) 3)
        let inner_ite = SmtTerm::Ite(
            Box::new(SmtTerm::var("q")),
            Box::new(SmtTerm::int(1)),
            Box::new(SmtTerm::int(2)),
        );
        let outer_ite = SmtTerm::Ite(
            Box::new(SmtTerm::var("p")),
            Box::new(inner_ite),
            Box::new(SmtTerm::int(3)),
        );
        assert_eq!(to_smtlib(&outer_ite), "(ite p (ite q 1 2) 3)");
    }

    #[test]
    fn print_or_with_three_terms() {
        let term = SmtTerm::or(vec![
            SmtTerm::var("a"),
            SmtTerm::var("b"),
            SmtTerm::var("c"),
        ]);
        assert_eq!(to_smtlib(&term), "(or a b c)");
    }

    #[test]
    fn print_and_with_many_terms() {
        let terms: Vec<SmtTerm> = (0..5).map(|i| SmtTerm::var(format!("x{i}"))).collect();
        let and = SmtTerm::and(terms);
        assert_eq!(to_smtlib(&and), "(and x0 x1 x2 x3 x4)");
    }

    #[test]
    fn print_negative_int_in_arithmetic_expression() {
        let term = SmtTerm::var("x").add(SmtTerm::int(-3));
        assert_eq!(to_smtlib(&term), "(+ x (- 3))");
    }

    #[test]
    fn print_zero_integer() {
        assert_eq!(to_smtlib(&SmtTerm::int(0)), "0");
    }

    #[test]
    fn print_large_positive_integer() {
        assert_eq!(to_smtlib(&SmtTerm::int(999999)), "999999");
    }

    // --- Multiple-binding quantifier tests ---

    #[test]
    fn print_forall_with_multiple_bindings() {
        let forall = SmtTerm::ForAll(
            vec![
                ("x".to_string(), SmtSort::Int),
                ("y".to_string(), SmtSort::Int),
                ("b".to_string(), SmtSort::Bool),
            ],
            Box::new(SmtTerm::var("x").add(SmtTerm::var("y")).ge(SmtTerm::int(0))),
        );
        assert_eq!(
            to_smtlib(&forall),
            "(forall ((x Int) (y Int) (b Bool)) (>= (+ x y) 0))"
        );
    }

    #[test]
    fn print_exists_with_multiple_bindings() {
        let exists = SmtTerm::Exists(
            vec![
                ("a".to_string(), SmtSort::Int),
                ("b".to_string(), SmtSort::Bool),
            ],
            Box::new(SmtTerm::and(vec![
                SmtTerm::var("b"),
                SmtTerm::var("a").gt(SmtTerm::int(0)),
            ])),
        );
        assert_eq!(
            to_smtlib(&exists),
            "(exists ((a Int) (b Bool)) (and b (> a 0)))"
        );
    }

    // --- Deeply nested arithmetic/comparison tests ---

    #[test]
    fn print_deeply_nested_arithmetic() {
        // ((x + y) * (a - b)) >= 0
        let lhs = SmtTerm::var("x").add(SmtTerm::var("y"));
        let rhs = SmtTerm::var("a").sub(SmtTerm::var("b"));
        let product = lhs.mul(rhs);
        let comparison = product.ge(SmtTerm::int(0));
        assert_eq!(to_smtlib(&comparison), "(>= (* (+ x y) (- a b)) 0)");
    }

    #[test]
    fn print_eq_of_complex_subterms() {
        let lhs = SmtTerm::var("x").add(SmtTerm::int(1));
        let rhs = SmtTerm::var("y").mul(SmtTerm::int(2));
        let eq = lhs.eq(rhs);
        assert_eq!(to_smtlib(&eq), "(= (+ x 1) (* y 2))");
    }

    #[test]
    fn print_chained_implies() {
        // a => (b => c)
        let inner = SmtTerm::var("b").implies(SmtTerm::var("c"));
        let outer = SmtTerm::var("a").implies(inner);
        assert_eq!(to_smtlib(&outer), "(=> a (=> b c))");
    }

    #[test]
    fn print_double_negation() {
        let term = SmtTerm::var("x").not().not();
        assert_eq!(to_smtlib(&term), "(not (not x))");
    }

    #[test]
    fn print_ite_with_boolean_conditions_and_arithmetic_branches() {
        let term = SmtTerm::Ite(
            Box::new(SmtTerm::var("flag").not()),
            Box::new(SmtTerm::var("x").add(SmtTerm::int(1))),
            Box::new(SmtTerm::var("x").sub(SmtTerm::int(1))),
        );
        assert_eq!(to_smtlib(&term), "(ite (not flag) (+ x 1) (- x 1))");
    }

    #[test]
    fn print_variable_name_with_special_chars() {
        // SMT-LIB allows pipe-quoted names; our printer just emits the stored name.
        let term = SmtTerm::var("kappa_0_3");
        assert_eq!(to_smtlib(&term), "kappa_0_3");
    }

    #[test]
    fn print_nested_quantifier() {
        // (forall ((x Int)) (exists ((y Int)) (= x y)))
        let inner = SmtTerm::Exists(
            vec![("y".to_string(), SmtSort::Int)],
            Box::new(SmtTerm::var("x").eq(SmtTerm::var("y"))),
        );
        let outer = SmtTerm::ForAll(vec![("x".to_string(), SmtSort::Int)], Box::new(inner));
        assert_eq!(
            to_smtlib(&outer),
            "(forall ((x Int)) (exists ((y Int)) (= x y)))"
        );
    }
}
