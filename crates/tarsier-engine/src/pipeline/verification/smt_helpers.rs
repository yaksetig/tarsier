//! SMT variable naming, term construction, and fair-lasso encoding helpers.

use super::*;

pub(crate) fn run_single_depth_bmc_encoding<S: SmtSolver>(
    solver: &mut S,
    encoding: &BmcEncoding,
    depth: usize,
) -> Result<BmcResult, S::Error> {
    solver.reset()?;
    for (name, sort) in &encoding.declarations {
        solver.declare_var(name, sort)?;
    }
    for assertion in &encoding.assertions {
        solver.assert(assertion)?;
    }
    let var_refs: Vec<(&str, &SmtSort)> = encoding
        .model_vars
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();
    let (result, model) = solver.check_sat_with_model(&var_refs)?;
    Ok(match result {
        SatResult::Sat => BmcResult::Unsafe {
            depth,
            model: model.expect("SAT should include model"),
        },
        SatResult::Unsat => BmcResult::Safe {
            depth_checked: depth,
        },
        SatResult::Unknown(reason) => BmcResult::Unknown { depth, reason },
    })
}

pub(crate) fn pdr_param_var(i: usize) -> String {
    format!("p_{i}")
}

pub(crate) fn pdr_kappa_var(step: usize, loc: usize) -> String {
    format!("kappa_{step}_{loc}")
}

pub(crate) fn pdr_gamma_var(step: usize, var: usize) -> String {
    format!("g_{step}_{var}")
}

pub(crate) fn pdr_time_var(step: usize) -> String {
    format!("time_{step}")
}

pub(crate) fn pdr_delta_var(step: usize, rule: usize) -> String {
    format!("delta_{step}_{rule}")
}

pub(crate) fn temporal_state_var(step: usize, state: usize) -> String {
    format!("ltl_q_{step}_{state}")
}

pub(crate) fn mon_snap_temporal_state(step: usize, state: usize) -> String {
    format!("m_snap_q_{step}_{state}")
}

pub(crate) fn mon_acc(step: usize, acceptance_set: usize) -> String {
    format!("m_acc_{step}_{acceptance_set}")
}

pub(crate) fn one_hot_assertion(vars: &[String]) -> SmtTerm {
    if vars.is_empty() {
        return SmtTerm::bool(false);
    }
    let mut sum = SmtTerm::int(0);
    for var in vars {
        sum = sum.add(SmtTerm::var(var.clone()));
    }
    sum.eq(SmtTerm::int(1))
}

pub(crate) fn encode_lc_term(lc: &LinearCombination) -> SmtTerm {
    let mut result = SmtTerm::int(lc.constant);
    for &(coeff, pid) in &lc.terms {
        let pv = SmtTerm::var(pdr_param_var(pid));
        let scaled = if coeff == 1 {
            pv
        } else {
            SmtTerm::int(coeff).mul(pv)
        };
        result = result.add(scaled);
    }
    result
}

pub(crate) fn encode_guard_atom_enabled_at_step(atom: &GuardAtom, step: usize) -> SmtTerm {
    match atom {
        GuardAtom::Threshold {
            vars,
            op,
            bound,
            distinct,
        } => {
            let lhs = if *distinct {
                let mut terms: Vec<SmtTerm> = Vec::with_capacity(vars.len());
                for var in vars {
                    let gv = SmtTerm::var(pdr_gamma_var(step, *var));
                    terms.push(SmtTerm::Ite(
                        Box::new(gv.gt(SmtTerm::int(0))),
                        Box::new(SmtTerm::int(1)),
                        Box::new(SmtTerm::int(0)),
                    ));
                }
                if terms.is_empty() {
                    SmtTerm::int(0)
                } else {
                    let mut sum = SmtTerm::int(0);
                    for term in terms {
                        sum = sum.add(term);
                    }
                    sum
                }
            } else {
                let mut sum = SmtTerm::int(0);
                for var in vars {
                    sum = sum.add(SmtTerm::var(pdr_gamma_var(step, *var)));
                }
                sum
            };
            let rhs = encode_lc_term(bound);
            match op {
                CmpOp::Ge => lhs.ge(rhs),
                CmpOp::Gt => lhs.gt(rhs),
                CmpOp::Le => lhs.le(rhs),
                CmpOp::Lt => lhs.lt(rhs),
                CmpOp::Eq => lhs.eq(rhs),
                CmpOp::Ne => SmtTerm::not(lhs.eq(rhs)),
            }
        }
    }
}

pub(crate) fn add_temporal_automaton_to_fair_lasso_encoding(
    encoding: &mut BmcEncoding,
    ta: &ThresholdAutomaton,
    automaton: &TemporalBuchiAutomaton,
    depth: usize,
    loop_start: usize,
) -> Result<(), PipelineError> {
    if automaton.states.is_empty() || automaton.initial_states.is_empty() {
        encoding.assertions.push(SmtTerm::bool(false));
        return Ok(());
    }

    let mut atom_terms_by_step = Vec::with_capacity(depth + 1);
    for step in 0..=depth {
        let mut terms = Vec::with_capacity(automaton.atoms.len());
        for atom in &automaton.atoms {
            terms.push(build_universal_state_predicate_term(
                ta,
                &automaton.quantified_var,
                &automaton.role,
                atom,
                step,
            )?);
        }
        atom_terms_by_step.push(terms);
    }

    for step in 0..=depth {
        let step_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(step, sid))
            .collect();
        for var in &step_vars {
            encoding.declarations.push((var.clone(), SmtSort::Int));
            encoding.assertions.extend(bit_domain(var.clone()));
        }
        encoding.assertions.push(one_hot_assertion(&step_vars));
    }

    let init_states: Vec<SmtTerm> = automaton
        .initial_states
        .iter()
        .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
        .collect();
    if init_states.is_empty() {
        encoding.assertions.push(SmtTerm::bool(false));
    } else {
        encoding.assertions.push(SmtTerm::or(init_states));
    }

    for (step, atom_terms_at_step) in atom_terms_by_step.iter().enumerate().take(depth) {
        for (sid, state) in automaton.states.iter().enumerate() {
            let current = bit_is_true(temporal_state_var(step, sid));
            let mut conjuncts = Vec::new();
            for lit in &state.label_lits {
                match lit {
                    TemporalAtomLit::Pos(atom_id) => {
                        conjuncts.push(atom_terms_at_step[*atom_id].clone());
                    }
                    TemporalAtomLit::Neg(atom_id) => {
                        conjuncts.push(SmtTerm::not(atom_terms_at_step[*atom_id].clone()));
                    }
                }
            }
            let succ_terms: Vec<SmtTerm> = state
                .transitions
                .iter()
                .map(|next_sid| bit_is_true(temporal_state_var(step + 1, *next_sid)))
                .collect();
            let succ = if succ_terms.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(succ_terms)
            };
            conjuncts.push(succ);
            let body = if conjuncts.len() == 1 {
                conjuncts[0].clone()
            } else {
                SmtTerm::and(conjuncts)
            };
            encoding.assertions.push(current.implies(body));
        }
    }

    for sid in 0..automaton.states.len() {
        encoding.assertions.push(
            SmtTerm::var(temporal_state_var(loop_start, sid))
                .eq(SmtTerm::var(temporal_state_var(depth, sid))),
        );
    }

    for acc_set in &automaton.acceptance_sets {
        if acc_set.is_empty() {
            encoding.assertions.push(SmtTerm::bool(false));
            continue;
        }
        let mut seen_terms = Vec::new();
        for step in loop_start..depth {
            for sid in acc_set {
                seen_terms.push(bit_is_true(temporal_state_var(step, *sid)));
            }
        }
        if seen_terms.is_empty() {
            encoding.assertions.push(SmtTerm::bool(false));
        } else {
            encoding.assertions.push(SmtTerm::or(seen_terms));
        }
    }

    Ok(())
}

pub(crate) fn build_fair_lasso_encoding(
    cs: &CounterSystem,
    depth: usize,
    loop_start: usize,
    target: &FairLivenessTarget,
    fairness: FairnessMode,
) -> Result<tarsier_smt::encoder::BmcEncoding, PipelineError> {
    let ta = &cs.automaton;
    let dummy_property = SafetyProperty::Agreement {
        conflicting_pairs: Vec::new(),
    };

    let mut step_encoding = encode_k_induction_step(cs, &dummy_property, depth);
    if !step_encoding.assertions.is_empty() {
        // Drop the final `false` assertion injected by the dummy property.
        step_encoding.assertions.pop();
    }

    // Add true initial-state constraints from depth-0 BMC.
    let init_encoding = encode_bmc(cs, &dummy_property, 0);
    if !init_encoding.assertions.is_empty() {
        let init_assertions = &init_encoding.assertions[..init_encoding.assertions.len() - 1];
        step_encoding
            .assertions
            .extend(init_assertions.iter().cloned());
    }

    // Lasso closure: state(loop_start) == state(depth)
    for loc in 0..cs.num_locations() {
        step_encoding.assertions.push(
            SmtTerm::var(pdr_kappa_var(loop_start, loc))
                .eq(SmtTerm::var(pdr_kappa_var(depth, loc))),
        );
    }
    for var in 0..cs.num_shared_vars() {
        step_encoding.assertions.push(
            SmtTerm::var(pdr_gamma_var(loop_start, var))
                .eq(SmtTerm::var(pdr_gamma_var(depth, var))),
        );
    }

    match target {
        FairLivenessTarget::NonGoalLocs(non_goal_locs) => {
            let undecided = non_goal_locs
                .iter()
                .map(|l| SmtTerm::var(pdr_kappa_var(depth, *l)).gt(SmtTerm::int(0)))
                .collect::<Vec<_>>();
            if undecided.is_empty() {
                step_encoding.assertions.push(SmtTerm::bool(false));
            } else {
                step_encoding.assertions.push(SmtTerm::or(undecided));
            }
        }
        FairLivenessTarget::Temporal(automaton) => {
            add_temporal_automaton_to_fair_lasso_encoding(
                &mut step_encoding,
                ta,
                automaton,
                depth,
                loop_start,
            )?;
        }
    }

    if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony {
        if let Some(gst_pid) = ta.gst_param {
            // Fair lasso must be fully post-GST to represent steady-state behavior.
            step_encoding.assertions.push(
                SmtTerm::var(pdr_param_var(gst_pid)).le(SmtTerm::var(pdr_time_var(loop_start))),
            );
        }
    }

    // Fairness on the loop:
    // - weak:   enabled on every loop state  => fires on loop
    // - strong: enabled on some loop state   => fires on loop
    for (rule_id, rule) in ta.rules.iter().enumerate() {
        let enabled_terms = (loop_start..depth)
            .map(|step| {
                let mut atoms = rule
                    .guard
                    .atoms
                    .iter()
                    .map(|a| encode_guard_atom_enabled_at_step(a, step))
                    .collect::<Vec<_>>();
                if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
                {
                    if let Some(gst_pid) = ta.gst_param {
                        atoms.push(
                            SmtTerm::var(pdr_param_var(gst_pid))
                                .le(SmtTerm::var(pdr_time_var(step))),
                        );
                    }
                }
                if atoms.is_empty() {
                    SmtTerm::bool(true)
                } else {
                    SmtTerm::and(atoms)
                }
            })
            .collect::<Vec<_>>();

        let fired_some_step = (loop_start..depth)
            .map(|step| SmtTerm::var(pdr_delta_var(step, rule_id)).gt(SmtTerm::int(0)))
            .collect::<Vec<_>>();

        let antecedent = if enabled_terms.is_empty() {
            SmtTerm::bool(false)
        } else {
            match fairness {
                FairnessMode::Weak => SmtTerm::and(enabled_terms),
                FairnessMode::Strong => SmtTerm::or(enabled_terms),
            }
        };
        let consequent = if fired_some_step.is_empty() {
            SmtTerm::bool(false)
        } else {
            SmtTerm::or(fired_some_step)
        };
        step_encoding
            .assertions
            .push(antecedent.implies(consequent));
    }

    Ok(step_encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdr_param_var_format() {
        assert_eq!(pdr_param_var(0), "p_0");
        assert_eq!(pdr_param_var(5), "p_5");
        assert_eq!(pdr_param_var(42), "p_42");
    }

    #[test]
    fn pdr_kappa_var_format() {
        assert_eq!(pdr_kappa_var(0, 0), "kappa_0_0");
        assert_eq!(pdr_kappa_var(3, 7), "kappa_3_7");
    }

    #[test]
    fn pdr_gamma_var_format() {
        assert_eq!(pdr_gamma_var(0, 0), "g_0_0");
        assert_eq!(pdr_gamma_var(2, 5), "g_2_5");
    }

    #[test]
    fn pdr_time_var_format() {
        assert_eq!(pdr_time_var(0), "time_0");
        assert_eq!(pdr_time_var(10), "time_10");
    }

    #[test]
    fn pdr_delta_var_format() {
        assert_eq!(pdr_delta_var(0, 0), "delta_0_0");
        assert_eq!(pdr_delta_var(1, 3), "delta_1_3");
    }

    #[test]
    fn temporal_state_var_format() {
        assert_eq!(temporal_state_var(0, 0), "ltl_q_0_0");
        assert_eq!(temporal_state_var(5, 2), "ltl_q_5_2");
    }

    #[test]
    fn mon_snap_temporal_state_format() {
        assert_eq!(mon_snap_temporal_state(0, 0), "m_snap_q_0_0");
        assert_eq!(mon_snap_temporal_state(3, 1), "m_snap_q_3_1");
    }

    #[test]
    fn mon_acc_format() {
        assert_eq!(mon_acc(0, 0), "m_acc_0_0");
        assert_eq!(mon_acc(2, 4), "m_acc_2_4");
    }

    #[test]
    fn one_hot_assertion_empty_is_false() {
        let result = one_hot_assertion(&[]);
        assert_eq!(result, SmtTerm::bool(false));
    }

    #[test]
    fn one_hot_assertion_single_var() {
        let vars = vec!["x".to_string()];
        let result = one_hot_assertion(&vars);
        // Should be: (= (+ 0 x) 1)
        let expected = SmtTerm::int(0)
            .add(SmtTerm::var("x".to_string()))
            .eq(SmtTerm::int(1));
        assert_eq!(result, expected);
    }

    #[test]
    fn one_hot_assertion_two_vars() {
        let vars = vec!["a".to_string(), "b".to_string()];
        let result = one_hot_assertion(&vars);
        // Should be: (= (+ (+ 0 a) b) 1)
        let expected = SmtTerm::int(0)
            .add(SmtTerm::var("a".to_string()))
            .add(SmtTerm::var("b".to_string()))
            .eq(SmtTerm::int(1));
        assert_eq!(result, expected);
    }

    #[test]
    fn encode_lc_term_constant_only() {
        let lc = LinearCombination {
            constant: 42,
            terms: vec![],
        };
        let result = encode_lc_term(&lc);
        assert_eq!(result, SmtTerm::int(42));
    }

    #[test]
    fn encode_lc_term_single_term_coeff_1() {
        let lc = LinearCombination {
            constant: 0,
            terms: vec![(1, 0)],
        };
        let result = encode_lc_term(&lc);
        // (+ 0 p_0) since coeff is 1, no multiplication
        let expected = SmtTerm::int(0).add(SmtTerm::var("p_0".to_string()));
        assert_eq!(result, expected);
    }

    #[test]
    fn encode_lc_term_with_coefficient() {
        let lc = LinearCombination {
            constant: 1,
            terms: vec![(2, 0)],
        };
        let result = encode_lc_term(&lc);
        // (+ 1 (* 2 p_0))
        let expected = SmtTerm::int(1).add(SmtTerm::int(2).mul(SmtTerm::var("p_0".to_string())));
        assert_eq!(result, expected);
    }

    #[test]
    fn encode_lc_term_multiple_terms() {
        let lc = LinearCombination {
            constant: 5,
            terms: vec![(1, 0), (3, 1)],
        };
        let result = encode_lc_term(&lc);
        // (+ (+ 5 p_0) (* 3 p_1))
        let expected = SmtTerm::int(5)
            .add(SmtTerm::var("p_0".to_string()))
            .add(SmtTerm::int(3).mul(SmtTerm::var("p_1".to_string())));
        assert_eq!(result, expected);
    }

    #[test]
    fn encode_guard_atom_ge_non_distinct() {
        let atom = GuardAtom::Threshold {
            vars: vec![0, 1],
            op: CmpOp::Ge,
            bound: LinearCombination {
                constant: 1,
                terms: vec![],
            },
            distinct: false,
        };
        let term = encode_guard_atom_enabled_at_step(&atom, 0);
        // Non-distinct: sum of gamma vars >= bound
        // (>= (+ (+ 0 g_0_0) g_0_1) 1)
        let expected = SmtTerm::int(0)
            .add(SmtTerm::var("g_0_0".to_string()))
            .add(SmtTerm::var("g_0_1".to_string()))
            .ge(SmtTerm::int(1));
        assert_eq!(term, expected);
    }

    #[test]
    fn encode_guard_atom_ne_operator() {
        let atom = GuardAtom::Threshold {
            vars: vec![0],
            op: CmpOp::Ne,
            bound: LinearCombination {
                constant: 0,
                terms: vec![],
            },
            distinct: false,
        };
        let term = encode_guard_atom_enabled_at_step(&atom, 2);
        // Ne means: not(sum == bound)
        let inner = SmtTerm::int(0)
            .add(SmtTerm::var("g_2_0".to_string()))
            .eq(SmtTerm::int(0));
        let expected = SmtTerm::not(inner);
        assert_eq!(term, expected);
    }
}
