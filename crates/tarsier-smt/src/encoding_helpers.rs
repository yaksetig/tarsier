//! Shared SMT encoding helper functions for guard atoms, linear combinations,
//! and arithmetic sum trees.
//!
//! These helpers are parameterised by variable-naming closures so that both
//! the main BMC encoder and the refinement encoder can reuse the same logic
//! with their own naming conventions (`g_k_v` vs `pg_k_v`, `p_i` vs `pp_i`,
//! etc.).

use tarsier_ir::threshold_automaton::{CmpOp, LinearCombination};

use crate::terms::SmtTerm;

// ── Balanced sum tree ────────────────────────────────────────────────

/// Build a balanced arithmetic sum tree from a vector of SMT terms.
///
/// Returns `SmtTerm::int(0)` for an empty input.  Using a balanced tree
/// rather than a left-fold keeps the term depth logarithmic, which helps
/// the solver.
pub fn sum_terms(mut terms: Vec<SmtTerm>) -> SmtTerm {
    if terms.is_empty() {
        return SmtTerm::int(0);
    }
    while terms.len() > 1 {
        let mut next = Vec::with_capacity(terms.len().div_ceil(2));
        let mut iter = terms.into_iter();
        while let Some(lhs) = iter.next() {
            if let Some(rhs) = iter.next() {
                next.push(lhs.add(rhs));
            } else {
                next.push(lhs);
            }
        }
        terms = next;
    }
    terms.pop().unwrap_or_else(|| SmtTerm::int(0))
}

// ── Linear combination encoding ──────────────────────────────────────

/// Encode a [`LinearCombination`] as an SMT term.
///
/// `param_var_fn` maps a parameter id (the raw `usize` from
/// `ParameterId::as_usize()`) to the SMT variable name to use.
pub fn encode_linear_combination(
    lc: &LinearCombination,
    param_var_fn: impl Fn(usize) -> String,
) -> SmtTerm {
    let mut terms = Vec::with_capacity(lc.terms.len() + usize::from(lc.constant != 0));
    if lc.constant != 0 {
        terms.push(SmtTerm::int(lc.constant));
    }
    for &(coeff, pid) in &lc.terms {
        let param_term = SmtTerm::var(param_var_fn(pid.as_usize()));
        let scaled = if coeff == 1 {
            param_term
        } else {
            SmtTerm::int(coeff).mul(param_term)
        };
        terms.push(scaled);
    }
    sum_terms(terms)
}

// ── Threshold guard encoding ─────────────────────────────────────────

/// Encode a threshold guard atom as an SMT comparison.
///
/// `var_terms` is a pre-built list of SMT terms for the shared variables on
/// the LHS of the guard.  `param_var_fn` is forwarded to
/// [`encode_linear_combination`] for encoding the bound.
///
/// When `distinct` is true the LHS counts *distinct* non-zero variables
/// (each clamped to 0/1 via an ITE).
pub fn encode_threshold_guard(
    var_terms: Vec<SmtTerm>,
    op: CmpOp,
    bound: &LinearCombination,
    distinct: bool,
    param_var_fn: impl Fn(usize) -> String,
) -> SmtTerm {
    let lhs = if distinct {
        let terms: Vec<SmtTerm> = var_terms
            .into_iter()
            .map(|gv| {
                SmtTerm::Ite(
                    Box::new(gv.gt(SmtTerm::int(0))),
                    Box::new(SmtTerm::int(1)),
                    Box::new(SmtTerm::int(0)),
                )
            })
            .collect();
        sum_terms(terms)
    } else {
        sum_terms(var_terms)
    };
    let rhs = encode_linear_combination(bound, param_var_fn);
    match op {
        CmpOp::Ge => lhs.ge(rhs),
        CmpOp::Gt => lhs.gt(rhs),
        CmpOp::Le => lhs.le(rhs),
        CmpOp::Lt => lhs.lt(rhs),
        CmpOp::Eq => lhs.eq(rhs),
        CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_ir::threshold_automaton::ParamId;

    fn make_lc(constant: i64, terms: Vec<(i64, usize)>) -> LinearCombination {
        LinearCombination {
            constant,
            terms: terms
                .into_iter()
                .map(|(c, p)| (c, ParamId::from(p)))
                .collect(),
        }
    }

    // ── sum_terms ────────────────────────────────────────────────────

    #[test]
    fn sum_terms_empty() {
        assert_eq!(sum_terms(vec![]), SmtTerm::int(0));
    }

    #[test]
    fn sum_terms_single() {
        let t = SmtTerm::var("x");
        assert_eq!(sum_terms(vec![t.clone()]), t);
    }

    #[test]
    fn sum_terms_two() {
        let a = SmtTerm::var("a");
        let b = SmtTerm::var("b");
        assert_eq!(sum_terms(vec![a.clone(), b.clone()]), a.add(b));
    }

    // ── encode_linear_combination ────────────────────────────────────

    #[test]
    fn encode_lc_constant_only() {
        let lc = make_lc(42, vec![]);
        assert_eq!(
            encode_linear_combination(&lc, |i| format!("p_{i}")),
            SmtTerm::int(42),
        );
    }

    #[test]
    fn encode_lc_single_unit_coeff() {
        let lc = make_lc(0, vec![(1, 0)]);
        assert_eq!(
            encode_linear_combination(&lc, |i| format!("p_{i}")),
            SmtTerm::var("p_0"),
        );
    }

    #[test]
    fn encode_lc_with_scaling() {
        let lc = make_lc(5, vec![(3, 1)]);
        assert_eq!(
            encode_linear_combination(&lc, |i| format!("p_{i}")),
            SmtTerm::int(5).add(SmtTerm::int(3).mul(SmtTerm::var("p_1"))),
        );
    }

    // ── encode_threshold_guard ───────────────────────────────────────

    #[test]
    fn guard_ge() {
        let bound = make_lc(1, vec![]);
        let var_terms = vec![SmtTerm::var("g_0"), SmtTerm::var("g_1")];
        let term =
            encode_threshold_guard(var_terms, CmpOp::Ge, &bound, false, |i| format!("p_{i}"));
        let expected_lhs = SmtTerm::var("g_0").add(SmtTerm::var("g_1"));
        assert_eq!(term, expected_lhs.ge(SmtTerm::int(1)));
    }

    #[test]
    fn guard_ne() {
        let bound = make_lc(0, vec![(1, 0)]);
        let var_terms = vec![SmtTerm::var("g_2")];
        let term =
            encode_threshold_guard(var_terms, CmpOp::Ne, &bound, false, |i| format!("p_{i}"));
        assert_eq!(
            term,
            SmtTerm::not(SmtTerm::var("g_2").eq(SmtTerm::var("p_0"))),
        );
    }
}
