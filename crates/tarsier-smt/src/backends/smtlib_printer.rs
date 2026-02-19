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
}
