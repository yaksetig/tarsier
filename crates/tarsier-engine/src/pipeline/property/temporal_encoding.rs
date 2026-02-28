//! Memoized temporal encoding.

use crate::pipeline::*;
use crate::pipeline::property::*;

/// Encode a (possibly temporal) quantified formula on a bounded trace suffix.
#[cfg(test)]
pub(crate) fn encode_quantified_temporal_formula_term(
    ta: &ThresholdAutomaton,
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
) -> Result<SmtTerm, PipelineError> {
    let quantifiers = vec![ast::QuantifierBinding {
        quantifier,
        var: quantified_var.to_string(),
        domain: role.to_string(),
    }];
    encode_quantified_temporal_formula_term_with_bindings(ta, &quantifiers, formula, step, depth)
}

/// Encode a (possibly temporal) quantified formula on a bounded trace suffix.
pub(crate) fn encode_quantified_temporal_formula_term_with_bindings(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
) -> Result<SmtTerm, PipelineError> {
    let mut memo = HashMap::new();
    encode_quantified_temporal_formula_term_with_bindings_cached(
        ta,
        quantifiers,
        formula,
        step,
        depth,
        &mut memo,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TemporalEncodingMemoKey {
    formula_ptr: usize,
    step: usize,
}

fn temporal_encoding_memo_key(formula: &ast::FormulaExpr, step: usize) -> TemporalEncodingMemoKey {
    TemporalEncodingMemoKey {
        formula_ptr: formula as *const ast::FormulaExpr as usize,
        step,
    }
}

fn encode_quantified_temporal_always_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    inner: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let terms = (step..=depth)
        .map(|i| {
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                i,
                depth,
                memo,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SmtTerm::and(terms))
}

fn encode_quantified_temporal_eventually_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    inner: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let terms = (step..=depth)
        .map(|i| {
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                i,
                depth,
                memo,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SmtTerm::or(terms))
}

fn encode_quantified_temporal_until_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    lhs: &ast::FormulaExpr,
    rhs: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    let mut disjuncts = Vec::new();
    for j in step..=depth {
        let rhs_at_j = encode_quantified_temporal_formula_term_with_bindings_cached(
            ta,
            quantifiers,
            rhs,
            j,
            depth,
            memo,
        )?;
        let mut conjuncts = vec![rhs_at_j];
        for i in step..j {
            conjuncts.push(
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?,
            );
        }
        disjuncts.push(SmtTerm::and(conjuncts));
    }
    Ok(SmtTerm::or(disjuncts))
}

fn encode_quantified_temporal_release_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    lhs: &ast::FormulaExpr,
    rhs: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    // Finite-trace expansion equivalent to dual translation:
    //   lhs R rhs == !((!lhs) U (!rhs))
    // and expanded as:
    //   /\_{j=step..depth} ( rhs@j \/ \/_{i=step..j-1} lhs@i )
    let mut conjuncts = Vec::new();
    for j in step..=depth {
        let rhs_at_j = encode_quantified_temporal_formula_term_with_bindings_cached(
            ta,
            quantifiers,
            rhs,
            j,
            depth,
            memo,
        )?;
        let mut disjuncts = vec![rhs_at_j];
        for i in step..j {
            disjuncts.push(
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?,
            );
        }
        conjuncts.push(SmtTerm::or(disjuncts));
    }
    Ok(SmtTerm::and(conjuncts))
}

fn encode_quantified_temporal_formula_term_with_bindings_cached(
    ta: &ThresholdAutomaton,
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
    step: usize,
    depth: usize,
    memo: &mut HashMap<TemporalEncodingMemoKey, SmtTerm>,
) -> Result<SmtTerm, PipelineError> {
    if step > depth {
        return Ok(SmtTerm::bool(false));
    }
    let memo_key = temporal_encoding_memo_key(formula, step);
    if let Some(cached) = memo.get(&memo_key) {
        return Ok(cached.clone());
    }

    if !formula_contains_temporal(formula) {
        let term =
            build_quantified_state_predicate_term_with_bindings(ta, quantifiers, formula, step)?;
        memo.insert(memo_key, term.clone());
        return Ok(term);
    }
    let encoded = match formula {
        ast::FormulaExpr::Comparison { .. } => {
            build_quantified_state_predicate_term_with_bindings(ta, quantifiers, formula, step)
        }
        ast::FormulaExpr::Not(inner) => Ok(SmtTerm::not(
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )?,
        )),
        ast::FormulaExpr::And(lhs, rhs) => Ok(SmtTerm::and(vec![
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Or(lhs, rhs) => Ok(SmtTerm::or(vec![
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Implies(lhs, rhs) => {
            let l = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?;
            let r = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?;
            Ok(SmtTerm::or(vec![SmtTerm::not(l), r]))
        }
        ast::FormulaExpr::Iff(lhs, rhs) => {
            let l = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?;
            let r = encode_quantified_temporal_formula_term_with_bindings_cached(
                ta,
                quantifiers,
                rhs,
                step,
                depth,
                memo,
            )?;
            Ok(SmtTerm::or(vec![
                SmtTerm::and(vec![l.clone(), r.clone()]),
                SmtTerm::and(vec![SmtTerm::not(l), SmtTerm::not(r)]),
            ]))
        }
        ast::FormulaExpr::Next(inner) => {
            if step == depth {
                Ok(SmtTerm::bool(false))
            } else {
                encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    inner,
                    step + 1,
                    depth,
                    memo,
                )
            }
        }
        ast::FormulaExpr::Always(inner) => {
            encode_quantified_temporal_always_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::Eventually(inner) => {
            encode_quantified_temporal_eventually_term_with_bindings_cached(
                ta,
                quantifiers,
                inner,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::Until(lhs, rhs) => {
            encode_quantified_temporal_until_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::WeakUntil(lhs, rhs) => Ok(SmtTerm::or(vec![
            encode_quantified_temporal_until_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )?,
            encode_quantified_temporal_always_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                step,
                depth,
                memo,
            )?,
        ])),
        ast::FormulaExpr::Release(lhs, rhs) => {
            encode_quantified_temporal_release_term_with_bindings_cached(
                ta,
                quantifiers,
                lhs,
                rhs,
                step,
                depth,
                memo,
            )
        }
        ast::FormulaExpr::LeadsTo(lhs, rhs) => {
            let mut conjuncts = Vec::new();
            for i in step..=depth {
                let lhs_i = encode_quantified_temporal_formula_term_with_bindings_cached(
                    ta,
                    quantifiers,
                    lhs,
                    i,
                    depth,
                    memo,
                )?;
                let future_rhs = (i..=depth)
                    .map(|j| {
                        encode_quantified_temporal_formula_term_with_bindings_cached(
                            ta,
                            quantifiers,
                            rhs,
                            j,
                            depth,
                            memo,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                conjuncts.push(SmtTerm::or(vec![
                    SmtTerm::not(lhs_i),
                    SmtTerm::or(future_rhs),
                ]));
            }
            Ok(SmtTerm::and(conjuncts))
        }
    }?;

    memo.insert(memo_key, encoded.clone());
    Ok(encoded)
}
