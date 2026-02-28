//! Büchi monitor compilation.

use crate::pipeline::*;
use crate::pipeline::property::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemporalExpansionOutcome {
    old: BTreeSet<TemporalFormula>,
    next: BTreeSet<TemporalFormula>,
    literals: BTreeMap<usize, bool>,
}

pub(crate) fn temporal_push_todo(
    todo: &mut Vec<TemporalFormula>,
    old: &BTreeSet<TemporalFormula>,
    formula: TemporalFormula,
) {
    if old.contains(&formula) || todo.iter().any(|f| f == &formula) {
        return;
    }
    todo.push(formula);
}

pub(crate) fn expand_temporal_seed(
    seed: &BTreeSet<TemporalFormula>,
) -> Vec<TemporalExpansionOutcome> {
    fn recurse(
        mut todo: Vec<TemporalFormula>,
        old: BTreeSet<TemporalFormula>,
        next: BTreeSet<TemporalFormula>,
        literals: BTreeMap<usize, bool>,
        outcomes: &mut Vec<TemporalExpansionOutcome>,
    ) {
        let Some(formula) = todo.pop() else {
            outcomes.push(TemporalExpansionOutcome {
                old,
                next,
                literals,
            });
            return;
        };

        if old.contains(&formula) {
            recurse(todo, old, next, literals, outcomes);
            return;
        }

        match formula {
            TemporalFormula::True => {
                let mut old2 = old;
                old2.insert(TemporalFormula::True);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::False => {}
            TemporalFormula::Atom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(false)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::Atom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, true);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::NotAtom(atom_id) => {
                if matches!(literals.get(&atom_id), Some(true)) {
                    return;
                }
                let mut old2 = old;
                old2.insert(TemporalFormula::NotAtom(atom_id));
                let mut literals2 = literals;
                literals2.insert(atom_id, false);
                recurse(todo, old2, next, literals2, outcomes);
            }
            TemporalFormula::Next(inner) => {
                let mut old2 = old;
                let next_formula = TemporalFormula::Next(inner.clone());
                old2.insert(next_formula);
                let mut next2 = next;
                next2.insert(*inner);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::And(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::And(lhs.clone(), rhs.clone()));
                temporal_push_todo(&mut todo, &old2, *lhs);
                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Or(lhs, rhs) => {
                let mut old2 = old;
                old2.insert(TemporalFormula::Or(lhs.clone(), rhs.clone()));

                let mut left_todo = todo.clone();
                temporal_push_todo(&mut left_todo, &old2, *lhs.clone());
                recurse(
                    left_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
            TemporalFormula::Until(lhs, rhs) => {
                let mut old2 = old;
                let until_formula = TemporalFormula::Until(lhs.clone(), rhs.clone());
                old2.insert(until_formula.clone());

                let mut rhs_todo = todo.clone();
                temporal_push_todo(&mut rhs_todo, &old2, *rhs.clone());
                recurse(
                    rhs_todo,
                    old2.clone(),
                    next.clone(),
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *lhs);
                let mut next2 = next;
                next2.insert(until_formula);
                recurse(todo, old2, next2, literals, outcomes);
            }
            TemporalFormula::Release(lhs, rhs) => {
                let mut old2 = old;
                let rel_formula = TemporalFormula::Release(lhs.clone(), rhs.clone());
                old2.insert(rel_formula.clone());

                let mut keep_todo = todo.clone();
                temporal_push_todo(&mut keep_todo, &old2, *lhs.clone());
                temporal_push_todo(&mut keep_todo, &old2, *rhs.clone());
                let mut keep_next = next.clone();
                keep_next.insert(rel_formula.clone());
                recurse(
                    keep_todo,
                    old2.clone(),
                    keep_next,
                    literals.clone(),
                    outcomes,
                );

                temporal_push_todo(&mut todo, &old2, *rhs);
                recurse(todo, old2, next, literals, outcomes);
            }
        }
    }

    let mut outcomes = Vec::new();
    recurse(
        seed.iter().cloned().collect(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeMap::new(),
        &mut outcomes,
    );

    let mut unique = Vec::new();
    for outcome in outcomes {
        if !unique.iter().any(|existing| existing == &outcome) {
            unique.push(outcome);
        }
    }
    unique
}

/// Compile a temporal property into an explicit Büchi monitor.
#[cfg(test)]
pub(crate) fn compile_temporal_buchi_automaton(
    quantifier: ast::Quantifier,
    quantified_var: &str,
    role: &str,
    formula: &ast::FormulaExpr,
) -> Result<TemporalBuchiAutomaton, PipelineError> {
    let quantifiers = vec![ast::QuantifierBinding {
        quantifier,
        var: quantified_var.to_string(),
        domain: role.to_string(),
    }];
    compile_temporal_buchi_automaton_with_bindings(&quantifiers, formula)
}

/// Compile a temporal property into an explicit Büchi monitor.
pub(crate) fn compile_temporal_buchi_automaton_with_bindings(
    quantifiers: &[ast::QuantifierBinding],
    formula: &ast::FormulaExpr,
) -> Result<TemporalBuchiAutomaton, PipelineError> {
    let representative_binding = quantifiers.first().ok_or_else(|| {
        PipelineError::Property("Temporal monitor requires at least one quantifier binding.".into())
    })?;
    let quantifier = representative_binding.quantifier;
    let quantified_var = representative_binding.var.as_str();
    let role = representative_binding.domain.as_str();

    let mut atoms = TemporalAtomTable::default();
    let negated = formula_to_temporal_nnf(formula, &mut atoms, true)?;

    let mut initial_seed = BTreeSet::new();
    initial_seed.insert(negated.clone());

    let mut seed_to_state_ids: BTreeMap<BTreeSet<TemporalFormula>, Vec<usize>> = BTreeMap::new();
    let mut pending_seeds = VecDeque::new();
    pending_seeds.push_back(initial_seed.clone());

    let mut state_by_old: BTreeMap<BTreeSet<TemporalFormula>, usize> = BTreeMap::new();
    let mut states = Vec::<TemporalBuchiState>::new();
    let mut pending_next_per_state = Vec::<Vec<BTreeSet<TemporalFormula>>>::new();

    while let Some(seed) = pending_seeds.pop_front() {
        if seed_to_state_ids.contains_key(&seed) {
            continue;
        }

        let expansions = expand_temporal_seed(&seed);
        let mut state_ids = Vec::new();

        for expansion in expansions {
            let label_lits: Vec<TemporalAtomLit> = expansion
                .literals
                .iter()
                .map(|(atom_id, value)| {
                    if *value {
                        TemporalAtomLit::Pos(*atom_id)
                    } else {
                        TemporalAtomLit::Neg(*atom_id)
                    }
                })
                .collect();

            let state_id = if let Some(existing) = state_by_old.get(&expansion.old) {
                let id = *existing;
                if states[id].label_lits != label_lits {
                    return Err(PipelineError::Property(
                        "Temporal automaton construction conflict: same logical state produced incompatible labels."
                            .into(),
                    ));
                }
                id
            } else {
                let id = states.len();
                state_by_old.insert(expansion.old.clone(), id);
                states.push(TemporalBuchiState {
                    old: expansion.old.clone(),
                    label_lits,
                    transitions: Vec::new(),
                });
                pending_next_per_state.push(Vec::new());
                id
            };

            if !pending_next_per_state[state_id]
                .iter()
                .any(|existing| existing == &expansion.next)
            {
                pending_next_per_state[state_id].push(expansion.next.clone());
            }
            if !seed_to_state_ids.contains_key(&expansion.next) {
                pending_seeds.push_back(expansion.next.clone());
            }
            state_ids.push(state_id);
        }

        state_ids.sort_unstable();
        state_ids.dedup();
        seed_to_state_ids.insert(seed, state_ids);
    }

    for (state_id, next_seeds) in pending_next_per_state.iter().enumerate() {
        let mut transitions = Vec::new();
        for next_seed in next_seeds {
            if let Some(ids) = seed_to_state_ids.get(next_seed) {
                transitions.extend(ids.iter().copied());
            }
        }
        transitions.sort_unstable();
        transitions.dedup();
        states[state_id].transitions = transitions;
    }

    let mut initial_states = seed_to_state_ids
        .get(&initial_seed)
        .cloned()
        .unwrap_or_default();
    initial_states.sort_unstable();
    initial_states.dedup();

    let mut until_formulas = BTreeSet::new();
    collect_until_formulas(&negated, &mut until_formulas);
    let mut acceptance_sets = Vec::new();
    for until_formula in until_formulas {
        let TemporalFormula::Until(_, rhs) = &until_formula else {
            continue;
        };
        let mut acc = Vec::new();
        for (sid, st) in states.iter().enumerate() {
            if !st.old.contains(&until_formula) || st.old.contains(rhs.as_ref()) {
                acc.push(sid);
            }
        }
        acceptance_sets.push(acc);
    }

    Ok(TemporalBuchiAutomaton {
        quantifier,
        quantified_var: quantified_var.to_string(),
        role: role.to_string(),
        quantifiers: quantifiers.to_vec(),
        atoms: atoms.atoms,
        states,
        initial_states,
        acceptance_sets,
    })
}
