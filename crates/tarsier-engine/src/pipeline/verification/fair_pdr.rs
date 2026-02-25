//! Unbounded fair PDR engine (IC3-style).

use super::*;

pub(crate) fn run_fair_lasso_search<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_depth: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    deadline: Option<Instant>,
) -> Result<FairLivenessResult, PipelineError> {
    let extra_assertions = committee_bound_assertions(committee_bounds);

    for depth in 1..=max_depth {
        crate::sandbox::enforce_active_limits()?;
        if let Some(reason) = liveness_memory_budget_reason("Fair-liveness lasso search", None) {
            return Ok(FairLivenessResult::Unknown { reason });
        }
        if deadline_exceeded(deadline) {
            return Ok(FairLivenessResult::Unknown {
                reason: timeout_unknown_reason("Fair-liveness lasso search"),
            });
        }
        for loop_start in 0..depth {
            if let Some(reason) =
                liveness_memory_budget_reason("Fair-liveness lasso search", Some(depth))
            {
                return Ok(FairLivenessResult::Unknown { reason });
            }
            if deadline_exceeded(deadline) {
                return Ok(FairLivenessResult::Unknown {
                    reason: timeout_unknown_reason("Fair-liveness lasso search"),
                });
            }
            let encoding = build_fair_lasso_encoding(cs, depth, loop_start, target, fairness)?;

            solver
                .reset()
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            for (name, sort) in &encoding.declarations {
                solver
                    .declare_var(name, sort)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }
            for assertion in &encoding.assertions {
                solver
                    .assert(assertion)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }
            for extra in &extra_assertions {
                solver
                    .assert(extra)
                    .map_err(|e| PipelineError::Solver(e.to_string()))?;
            }

            let var_refs: Vec<(&str, &SmtSort)> = encoding
                .model_vars
                .iter()
                .map(|(n, s)| (n.as_str(), s))
                .collect();
            let (sat, model) = solver
                .check_sat_with_model(&var_refs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            match sat {
                SatResult::Sat => {
                    if let Some(model) = model {
                        let trace = extract_trace(cs, &model, depth);
                        return Ok(FairLivenessResult::FairCycleFound {
                            depth,
                            loop_start,
                            trace,
                        });
                    }
                    return Ok(FairLivenessResult::Unknown {
                        reason: "SAT result without model during fair-liveness search.".into(),
                    });
                }
                SatResult::Unsat => {}
                SatResult::Unknown(reason) => return Ok(FairLivenessResult::Unknown { reason }),
            }
        }
    }

    Ok(FairLivenessResult::NoFairCycleUpTo {
        depth_checked: max_depth,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct FairPdrCubeLit {
    pub(crate) state_var_idx: usize,
    pub(crate) value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct FairPdrCube {
    pub(crate) lits: Vec<FairPdrCubeLit>,
}

impl FairPdrCube {
    pub(crate) fn from_model(
        model: &tarsier_smt::solver::Model,
        state_vars: &[(String, SmtSort)],
    ) -> Option<Self> {
        let mut lits = Vec::with_capacity(state_vars.len());
        for (idx, (name, sort)) in state_vars.iter().enumerate() {
            if *sort != SmtSort::Int {
                return None;
            }
            let value = model.get_int(name)?;
            lits.push(FairPdrCubeLit {
                state_var_idx: idx,
                value,
            });
        }
        Some(Self { lits })
    }

    pub(crate) fn to_conjunction(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        if self.lits.is_empty() {
            return SmtTerm::bool(true);
        }
        let mut parts = Vec::with_capacity(self.lits.len());
        for lit in &self.lits {
            let (name, sort) = &state_vars[lit.state_var_idx];
            if *sort != SmtSort::Int {
                return SmtTerm::bool(false);
            }
            parts.push(SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)));
        }
        SmtTerm::and(parts)
    }

    pub(crate) fn to_block_clause(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        self.to_conjunction(state_vars).not()
    }

    /// Returns true iff `self` is at least as general as `other`.
    ///
    /// For blocking clauses, this means `self` blocks a superset of states:
    /// every literal in `self` appears in `other`.
    pub(crate) fn subsumes(&self, other: &FairPdrCube) -> bool {
        if self.lits.len() > other.lits.len() {
            return false;
        }
        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.lits.len() && j < other.lits.len() {
            let a = &self.lits[i];
            let b = &other.lits[j];
            if a == b {
                i += 1;
                j += 1;
                continue;
            }
            if a.state_var_idx > b.state_var_idx {
                j += 1;
                continue;
            }
            return false;
        }
        i == self.lits.len()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FairPdrFrame {
    pub(crate) cubes: HashSet<FairPdrCube>,
}

impl FairPdrFrame {
    pub(crate) fn insert(&mut self, cube: FairPdrCube) {
        if self.cubes.iter().any(|existing| existing.subsumes(&cube)) {
            return;
        }
        let to_remove: Vec<FairPdrCube> = self
            .cubes
            .iter()
            .filter(|existing| cube.subsumes(existing))
            .cloned()
            .collect();
        for existing in to_remove {
            self.cubes.remove(&existing);
        }
        self.cubes.insert(cube);
    }

    pub(crate) fn contains(&self, cube: &FairPdrCube) -> bool {
        self.cubes.contains(cube)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FairPdrArtifacts {
    declarations: Vec<(String, SmtSort)>,
    state_vars_pre: Vec<(String, SmtSort)>,
    state_vars_post: Vec<(String, SmtSort)>,
    state_assertions_pre: Vec<SmtTerm>,
    init_assertions: Vec<SmtTerm>,
    transition_assertions: Vec<SmtTerm>,
    bad_pre: SmtTerm,
}

#[derive(Debug, Clone)]
pub(crate) struct FairPdrInvariantCertificate {
    pub(crate) frame: usize,
    pub(crate) declarations: Vec<(String, SmtSort)>,
    pub(crate) init_assertions: Vec<SmtTerm>,
    pub(crate) transition_assertions: Vec<SmtTerm>,
    pub(crate) bad_pre: SmtTerm,
    pub(crate) invariant_pre: Vec<SmtTerm>,
    pub(crate) invariant_post: Vec<SmtTerm>,
}

pub(crate) fn mon_armed(step: usize) -> String {
    format!("m_armed_{step}")
}

pub(crate) fn mon_choose(step: usize) -> String {
    format!("m_choose_{step}")
}

pub(crate) fn mon_snap_kappa(step: usize, loc: usize) -> String {
    format!("m_snap_kappa_{step}_{loc}")
}

pub(crate) fn mon_snap_gamma(step: usize, var: usize) -> String {
    format!("m_snap_g_{step}_{var}")
}

pub(crate) fn mon_ce(step: usize, rule: usize) -> String {
    format!("m_ce_{step}_{rule}")
}

pub(crate) fn mon_fired(step: usize, rule: usize) -> String {
    format!("m_fired_{step}_{rule}")
}

pub(crate) fn bit_is_true(name: String) -> SmtTerm {
    SmtTerm::var(name).eq(SmtTerm::int(1))
}

pub(crate) fn bit_is_false(name: String) -> SmtTerm {
    SmtTerm::var(name).eq(SmtTerm::int(0))
}

pub(crate) fn bit_domain(name: String) -> Vec<SmtTerm> {
    vec![
        SmtTerm::var(name.clone()).ge(SmtTerm::int(0)),
        SmtTerm::var(name).le(SmtTerm::int(1)),
    ]
}

pub(crate) fn bool_to_bit(cond: SmtTerm) -> SmtTerm {
    SmtTerm::Ite(
        Box::new(cond),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::int(0)),
    )
}

pub(crate) fn push_decl_unique(decls: &mut Vec<(String, SmtSort)>, name: String, sort: SmtSort) {
    if !decls.iter().any(|(n, _)| *n == name) {
        decls.push((name, sort));
    }
}

pub(crate) fn build_unbounded_fair_pdr_artifacts(
    cs: &CounterSystem,
    target: &FairLivenessTarget,
    fairness: FairnessMode,
) -> Result<FairPdrArtifacts, PipelineError> {
    let ta = &cs.automaton;
    let dummy_property = SafetyProperty::Agreement {
        conflicting_pairs: Vec::new(),
    };

    // Step-0 constraints (state constraints + dummy bad)
    let step0 = encode_k_induction_step(cs, &dummy_property, 0);
    if step0.assertions.is_empty() {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (empty k=0 encoding).".into(),
        ));
    }
    let state_assertions_pre = step0.assertions[..step0.assertions.len() - 1].to_vec();

    // Step-1 constraints (transition + !bad(s0) + bad(s1))
    let step1 = encode_k_induction_step(cs, &dummy_property, 1);
    if step1.assertions.len() < 2 {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (incomplete k=1 encoding).".into(),
        ));
    }
    let mut transition_assertions = step1.assertions[..step1.assertions.len() - 2].to_vec();

    // Init constraints from BMC depth 0 (init + dummy bad)
    let init = encode_bmc(cs, &dummy_property, 0);
    if init.assertions.is_empty() {
        return Err(PipelineError::Solver(
            "Unable to build fair-liveness monitor (empty init encoding).".into(),
        ));
    }
    let mut init_assertions = init.assertions[..init.assertions.len() - 1].to_vec();

    let mut declarations = step1.declarations.clone();
    let mut state_vars_pre = Vec::new();
    let mut state_vars_post = Vec::new();
    let mut state_assertions_pre_extra = Vec::new();

    for loc in 0..cs.num_locations() {
        state_vars_pre.push((pdr_kappa_var(0, loc), SmtSort::Int));
        state_vars_post.push((pdr_kappa_var(1, loc), SmtSort::Int));
    }
    for var in 0..cs.num_shared_vars() {
        state_vars_pre.push((pdr_gamma_var(0, var), SmtSort::Int));
        state_vars_post.push((pdr_gamma_var(1, var), SmtSort::Int));
    }
    state_vars_pre.push((pdr_time_var(0), SmtSort::Int));
    state_vars_post.push((pdr_time_var(1), SmtSort::Int));

    let temporal_automaton = match target {
        FairLivenessTarget::Temporal(automaton) => Some(automaton),
        FairLivenessTarget::NonGoalLocs(_) => None,
    };
    let temporal_atom_terms_step0 = if let Some(automaton) = temporal_automaton {
        let mut terms = Vec::with_capacity(automaton.atoms.len());
        for atom in &automaton.atoms {
            terms.push(build_quantified_state_predicate_term(
                ta,
                automaton.quantifier,
                &automaton.quantified_var,
                &automaton.role,
                atom,
                0,
            )?);
        }
        Some(terms)
    } else {
        None
    };

    // Monitor state declarations for step 0 and 1.
    for step in 0..=1 {
        push_decl_unique(&mut declarations, mon_armed(step), SmtSort::Int);
        for loc in 0..cs.num_locations() {
            push_decl_unique(&mut declarations, mon_snap_kappa(step, loc), SmtSort::Int);
        }
        for var in 0..cs.num_shared_vars() {
            push_decl_unique(&mut declarations, mon_snap_gamma(step, var), SmtSort::Int);
        }
        for rule in 0..cs.num_rules() {
            push_decl_unique(&mut declarations, mon_ce(step, rule), SmtSort::Int);
            push_decl_unique(&mut declarations, mon_fired(step, rule), SmtSort::Int);
        }
    }
    if let Some(automaton) = temporal_automaton {
        for step in 0..=1 {
            for sid in 0..automaton.states.len() {
                push_decl_unique(
                    &mut declarations,
                    temporal_state_var(step, sid),
                    SmtSort::Int,
                );
                push_decl_unique(
                    &mut declarations,
                    mon_snap_temporal_state(step, sid),
                    SmtSort::Int,
                );
            }
            for acc_id in 0..automaton.acceptance_sets.len() {
                push_decl_unique(&mut declarations, mon_acc(step, acc_id), SmtSort::Int);
            }
        }
    }
    push_decl_unique(&mut declarations, mon_choose(0), SmtSort::Int);

    state_vars_pre.push((mon_armed(0), SmtSort::Int));
    state_vars_post.push((mon_armed(1), SmtSort::Int));
    for loc in 0..cs.num_locations() {
        state_vars_pre.push((mon_snap_kappa(0, loc), SmtSort::Int));
        state_vars_post.push((mon_snap_kappa(1, loc), SmtSort::Int));
    }
    for var in 0..cs.num_shared_vars() {
        state_vars_pre.push((mon_snap_gamma(0, var), SmtSort::Int));
        state_vars_post.push((mon_snap_gamma(1, var), SmtSort::Int));
    }
    for rule in 0..cs.num_rules() {
        state_vars_pre.push((mon_ce(0, rule), SmtSort::Int));
        state_vars_post.push((mon_ce(1, rule), SmtSort::Int));
        state_vars_pre.push((mon_fired(0, rule), SmtSort::Int));
        state_vars_post.push((mon_fired(1, rule), SmtSort::Int));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            state_vars_pre.push((temporal_state_var(0, sid), SmtSort::Int));
            state_vars_post.push((temporal_state_var(1, sid), SmtSort::Int));
            state_vars_pre.push((mon_snap_temporal_state(0, sid), SmtSort::Int));
            state_vars_post.push((mon_snap_temporal_state(1, sid), SmtSort::Int));
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            state_vars_pre.push((mon_acc(0, acc_id), SmtSort::Int));
            state_vars_post.push((mon_acc(1, acc_id), SmtSort::Int));
        }
    }

    // Domains on monitor bits.
    state_assertions_pre_extra.extend(bit_domain(mon_armed(0)));
    for rule in 0..cs.num_rules() {
        state_assertions_pre_extra.extend(bit_domain(mon_ce(0, rule)));
        state_assertions_pre_extra.extend(bit_domain(mon_fired(0, rule)));
    }
    transition_assertions.extend(bit_domain(mon_choose(0)));
    if let Some(automaton) = temporal_automaton {
        let atom_terms = temporal_atom_terms_step0
            .as_ref()
            .expect("temporal atom terms must exist when temporal automaton is active");

        let step0_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(0, sid))
            .collect();
        for var in &step0_vars {
            state_assertions_pre_extra.extend(bit_domain(var.clone()));
        }
        state_assertions_pre_extra.push(one_hot_assertion(&step0_vars));

        let step1_vars: Vec<String> = (0..automaton.states.len())
            .map(|sid| temporal_state_var(1, sid))
            .collect();
        for var in &step1_vars {
            transition_assertions.extend(bit_domain(var.clone()));
        }
        transition_assertions.push(one_hot_assertion(&step1_vars));

        for sid in 0..automaton.states.len() {
            state_assertions_pre_extra.extend(bit_domain(mon_snap_temporal_state(0, sid)));
            transition_assertions.extend(bit_domain(mon_snap_temporal_state(1, sid)));
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            state_assertions_pre_extra.extend(bit_domain(mon_acc(0, acc_id)));
            transition_assertions.extend(bit_domain(mon_acc(1, acc_id)));
        }

        for (sid, state) in automaton.states.iter().enumerate() {
            let current = bit_is_true(temporal_state_var(0, sid));
            let mut label_terms = Vec::new();
            for lit in &state.label_lits {
                match lit {
                    TemporalAtomLit::Pos(atom_id) => label_terms.push(atom_terms[*atom_id].clone()),
                    TemporalAtomLit::Neg(atom_id) => {
                        label_terms.push(SmtTerm::not(atom_terms[*atom_id].clone()))
                    }
                }
            }
            let label = if label_terms.is_empty() {
                SmtTerm::bool(true)
            } else {
                SmtTerm::and(label_terms)
            };
            state_assertions_pre_extra.push(current.clone().implies(label.clone()));

            let succ_terms: Vec<SmtTerm> = state
                .transitions
                .iter()
                .map(|next_sid| bit_is_true(temporal_state_var(1, *next_sid)))
                .collect();
            let succ = if succ_terms.is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(succ_terms)
            };
            transition_assertions.push(current.implies(SmtTerm::and(vec![label, succ])));
        }
    }

    // Init monitor values.
    init_assertions.push(bit_is_false(mon_armed(0)));
    for loc in 0..cs.num_locations() {
        init_assertions
            .push(SmtTerm::var(mon_snap_kappa(0, loc)).eq(SmtTerm::var(pdr_kappa_var(0, loc))));
    }
    for var in 0..cs.num_shared_vars() {
        init_assertions
            .push(SmtTerm::var(mon_snap_gamma(0, var)).eq(SmtTerm::var(pdr_gamma_var(0, var))));
    }
    for rule in 0..cs.num_rules() {
        init_assertions.push(bit_is_false(mon_ce(0, rule)));
        init_assertions.push(bit_is_false(mon_fired(0, rule)));
    }
    if let Some(automaton) = temporal_automaton {
        let init_states: Vec<SmtTerm> = automaton
            .initial_states
            .iter()
            .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
            .collect();
        if init_states.is_empty() {
            init_assertions.push(SmtTerm::bool(false));
        } else {
            init_assertions.push(SmtTerm::or(init_states));
        }
        for sid in 0..automaton.states.len() {
            init_assertions.push(
                SmtTerm::var(mon_snap_temporal_state(0, sid))
                    .eq(SmtTerm::var(temporal_state_var(0, sid))),
            );
        }
        for acc_id in 0..automaton.acceptance_sets.len() {
            init_assertions.push(bit_is_false(mon_acc(0, acc_id)));
        }
    }

    // Monitor transition updates.
    let armed0_true = bit_is_true(mon_armed(0));
    let choose0_true = bit_is_true(mon_choose(0));
    let post_gst_now = if ta.timing_model
        == tarsier_ir::threshold_automaton::TimingModel::PartialSynchrony
    {
        ta.gst_param
            .map(|gst_pid| SmtTerm::var(pdr_param_var(gst_pid)).le(SmtTerm::var(pdr_time_var(0))))
    } else {
        None
    };
    if let Some(post_gst_now) = post_gst_now.clone() {
        // Arm point for fair-cycle monitor must be in the post-GST region.
        transition_assertions.push(choose0_true.clone().implies(post_gst_now));
    }
    let choose0_effective = if let Some(post_gst_now) = post_gst_now.clone() {
        SmtTerm::and(vec![choose0_true.clone(), post_gst_now])
    } else {
        choose0_true.clone()
    };
    let arm_now = SmtTerm::and(vec![choose0_effective.clone(), armed0_true.clone().not()]);
    let armed1_next = bool_to_bit(SmtTerm::or(vec![
        armed0_true.clone(),
        choose0_effective.clone(),
    ]));
    transition_assertions.push(SmtTerm::var(mon_armed(1)).eq(armed1_next));
    transition_assertions.extend(bit_domain(mon_armed(1)));

    for loc in 0..cs.num_locations() {
        let snap_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(SmtTerm::var(pdr_kappa_var(0, loc))),
            Box::new(SmtTerm::var(mon_snap_kappa(0, loc))),
        );
        transition_assertions.push(SmtTerm::var(mon_snap_kappa(1, loc)).eq(snap_next));
    }
    for var in 0..cs.num_shared_vars() {
        let snap_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(SmtTerm::var(pdr_gamma_var(0, var))),
            Box::new(SmtTerm::var(mon_snap_gamma(0, var))),
        );
        transition_assertions.push(SmtTerm::var(mon_snap_gamma(1, var)).eq(snap_next));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            let snap_next = SmtTerm::Ite(
                Box::new(arm_now.clone()),
                Box::new(SmtTerm::var(temporal_state_var(0, sid))),
                Box::new(SmtTerm::var(mon_snap_temporal_state(0, sid))),
            );
            transition_assertions.push(SmtTerm::var(mon_snap_temporal_state(1, sid)).eq(snap_next));
        }
    }

    for (rule_id, rule) in ta.rules.iter().enumerate() {
        let mut enabled_now = if rule.guard.atoms.is_empty() {
            SmtTerm::bool(true)
        } else {
            SmtTerm::and(
                rule.guard
                    .atoms
                    .iter()
                    .map(|a| encode_guard_atom_enabled_at_step(a, 0))
                    .collect(),
            )
        };
        if let Some(post_gst_now) = post_gst_now.clone() {
            enabled_now = SmtTerm::and(vec![enabled_now, post_gst_now]);
        }
        let fired_now = SmtTerm::var(pdr_delta_var(0, rule_id)).gt(SmtTerm::int(0));
        let ce0_true = bit_is_true(mon_ce(0, rule_id));
        let fired0_true = bit_is_true(mon_fired(0, rule_id));

        let ce_arm = bool_to_bit(enabled_now.clone());
        let ce_cont = match fairness {
            // Track continuously-enabled on the monitored segment.
            FairnessMode::Weak => bool_to_bit(SmtTerm::and(vec![ce0_true.clone(), enabled_now])),
            // Track seen-enabled (enabled at least once on the monitored segment).
            FairnessMode::Strong => bool_to_bit(SmtTerm::or(vec![ce0_true.clone(), enabled_now])),
        };
        let ce_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(ce_arm),
            Box::new(SmtTerm::Ite(
                Box::new(armed0_true.clone()),
                Box::new(ce_cont),
                Box::new(SmtTerm::int(0)),
            )),
        );
        transition_assertions.push(SmtTerm::var(mon_ce(1, rule_id)).eq(ce_next));

        let fired_arm = bool_to_bit(fired_now.clone());
        let fired_cont = bool_to_bit(SmtTerm::or(vec![fired0_true, fired_now]));
        let fired_next = SmtTerm::Ite(
            Box::new(arm_now.clone()),
            Box::new(fired_arm),
            Box::new(SmtTerm::Ite(
                Box::new(armed0_true.clone()),
                Box::new(fired_cont),
                Box::new(SmtTerm::int(0)),
            )),
        );
        transition_assertions.push(SmtTerm::var(mon_fired(1, rule_id)).eq(fired_next));
        transition_assertions.extend(bit_domain(mon_ce(1, rule_id)));
        transition_assertions.extend(bit_domain(mon_fired(1, rule_id)));
    }
    if let Some(automaton) = temporal_automaton {
        for acc_id in 0..automaton.acceptance_sets.len() {
            let visited_now = if automaton.acceptance_sets[acc_id].is_empty() {
                SmtTerm::bool(false)
            } else {
                SmtTerm::or(
                    automaton.acceptance_sets[acc_id]
                        .iter()
                        .map(|sid| bit_is_true(temporal_state_var(0, *sid)))
                        .collect(),
                )
            };
            let acc0_true = bit_is_true(mon_acc(0, acc_id));
            let acc_arm = bool_to_bit(visited_now.clone());
            let acc_cont = bool_to_bit(SmtTerm::or(vec![acc0_true, visited_now]));
            let acc_next = SmtTerm::Ite(
                Box::new(arm_now.clone()),
                Box::new(acc_arm),
                Box::new(SmtTerm::Ite(
                    Box::new(armed0_true.clone()),
                    Box::new(acc_cont),
                    Box::new(SmtTerm::int(0)),
                )),
            );
            transition_assertions.push(SmtTerm::var(mon_acc(1, acc_id)).eq(acc_next));
        }
    }

    // Bad state: armed, loop closed, target obligations met, fairness obligations met.
    let mut closure_terms = vec![bit_is_true(mon_armed(0))];
    for loc in 0..cs.num_locations() {
        closure_terms
            .push(SmtTerm::var(pdr_kappa_var(0, loc)).eq(SmtTerm::var(mon_snap_kappa(0, loc))));
    }
    for var in 0..cs.num_shared_vars() {
        closure_terms
            .push(SmtTerm::var(pdr_gamma_var(0, var)).eq(SmtTerm::var(mon_snap_gamma(0, var))));
    }
    if let Some(automaton) = temporal_automaton {
        for sid in 0..automaton.states.len() {
            closure_terms.push(
                SmtTerm::var(temporal_state_var(0, sid))
                    .eq(SmtTerm::var(mon_snap_temporal_state(0, sid))),
            );
        }
    }
    match target {
        FairLivenessTarget::NonGoalLocs(non_goal_locs) => {
            if non_goal_locs.is_empty() {
                closure_terms.push(SmtTerm::bool(false));
            } else {
                closure_terms.push(SmtTerm::or(
                    non_goal_locs
                        .iter()
                        .map(|l| SmtTerm::var(pdr_kappa_var(0, *l)).gt(SmtTerm::int(0)))
                        .collect(),
                ));
            }
        }
        FairLivenessTarget::Temporal(automaton) => {
            for acc_id in 0..automaton.acceptance_sets.len() {
                closure_terms.push(bit_is_true(mon_acc(0, acc_id)));
            }
        }
    }
    for rule in 0..cs.num_rules() {
        closure_terms.push(SmtTerm::or(vec![
            bit_is_true(mon_ce(0, rule)).not(),
            bit_is_true(mon_fired(0, rule)),
        ]));
    }
    let bad_pre = SmtTerm::and(closure_terms);

    let mut full_state_assertions_pre = state_assertions_pre;
    full_state_assertions_pre.extend(state_assertions_pre_extra);

    Ok(FairPdrArtifacts {
        declarations,
        state_vars_pre,
        state_vars_post,
        state_assertions_pre: full_state_assertions_pre,
        init_assertions,
        transition_assertions,
        bad_pre,
    })
}

pub(crate) fn rename_state_vars_in_term(
    term: &SmtTerm,
    map: &std::collections::HashMap<String, String>,
) -> SmtTerm {
    match term {
        SmtTerm::Var(name) => {
            if let Some(mapped) = map.get(name) {
                SmtTerm::Var(mapped.clone())
            } else {
                SmtTerm::Var(name.clone())
            }
        }
        SmtTerm::IntLit(n) => SmtTerm::IntLit(*n),
        SmtTerm::BoolLit(b) => SmtTerm::BoolLit(*b),
        SmtTerm::Add(lhs, rhs) => SmtTerm::Add(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Sub(lhs, rhs) => SmtTerm::Sub(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Mul(lhs, rhs) => SmtTerm::Mul(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Eq(lhs, rhs) => SmtTerm::Eq(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Lt(lhs, rhs) => SmtTerm::Lt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Le(lhs, rhs) => SmtTerm::Le(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Gt(lhs, rhs) => SmtTerm::Gt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Ge(lhs, rhs) => SmtTerm::Ge(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::And(terms) => SmtTerm::And(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Or(terms) => SmtTerm::Or(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Not(inner) => SmtTerm::Not(Box::new(rename_state_vars_in_term(inner, map))),
        SmtTerm::Implies(lhs, rhs) => SmtTerm::Implies(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::ForAll(vars, body) => {
            SmtTerm::ForAll(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Exists(vars, body) => {
            SmtTerm::Exists(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Ite(cond, then_term, else_term) => SmtTerm::Ite(
            Box::new(rename_state_vars_in_term(cond, map)),
            Box::new(rename_state_vars_in_term(then_term, map)),
            Box::new(rename_state_vars_in_term(else_term, map)),
        ),
    }
}

pub(crate) fn build_fair_pdr_invariant_certificate(
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    frame_id: usize,
) -> FairPdrInvariantCertificate {
    let mut invariant_pre = artifacts.state_assertions_pre.clone();
    let mut cubes: Vec<FairPdrCube> = frame.cubes.iter().cloned().collect();
    cubes.sort();
    for cube in &cubes {
        invariant_pre.push(cube.to_block_clause(&artifacts.state_vars_pre));
    }

    let rename_map: std::collections::HashMap<String, String> = artifacts
        .state_vars_pre
        .iter()
        .zip(artifacts.state_vars_post.iter())
        .map(|((pre, _), (post, _))| (pre.clone(), post.clone()))
        .collect();
    let invariant_post: Vec<SmtTerm> = invariant_pre
        .iter()
        .map(|t| rename_state_vars_in_term(t, &rename_map))
        .collect();

    FairPdrInvariantCertificate {
        frame: frame_id,
        declarations: artifacts.declarations.clone(),
        init_assertions: artifacts.init_assertions.clone(),
        transition_assertions: artifacts.transition_assertions.clone(),
        bad_pre: artifacts.bad_pre.clone(),
        invariant_pre,
        invariant_post,
    }
}

pub(crate) fn fair_declare_all<S: SmtSolver>(
    solver: &mut S,
    declarations: &[(String, SmtSort)],
) -> Result<(), PipelineError> {
    for (name, sort) in declarations {
        solver
            .declare_var(name, sort)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

pub(crate) fn fair_assert_all<S: SmtSolver>(
    solver: &mut S,
    terms: &[SmtTerm],
) -> Result<(), PipelineError> {
    for t in terms {
        solver
            .assert(t)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

pub(crate) fn fair_assert_frame<S: SmtSolver>(
    solver: &mut S,
    frame: &FairPdrFrame,
    state_vars: &[(String, SmtSort)],
) -> Result<(), PipelineError> {
    for cube in &frame.cubes {
        solver
            .assert(&cube.to_block_clause(state_vars))
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
    }
    Ok(())
}

pub(crate) enum FairCubeQueryResult {
    Sat(FairPdrCube),
    Unsat,
    Unknown(String),
}

pub(crate) enum FairSatQueryResult {
    Sat,
    Unsat,
    Unknown(String),
}

pub(crate) fn fair_query_bad_in_frame<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    extra_assertions: &[SmtTerm],
) -> Result<FairCubeQueryResult, PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, extra_assertions)?;
    fair_assert_frame(solver, frame, &artifacts.state_vars_pre)?;
    solver
        .assert(&artifacts.bad_pre)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    let var_refs: Vec<(&str, &SmtSort)> = artifacts
        .state_vars_pre
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();
    let (sat, model) = solver
        .check_sat_with_model(&var_refs)
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    match sat {
        SatResult::Unsat => Ok(FairCubeQueryResult::Unsat),
        SatResult::Unknown(reason) => Ok(FairCubeQueryResult::Unknown(reason)),
        SatResult::Sat => {
            let Some(model) = model else {
                return Ok(FairCubeQueryResult::Unknown(
                    "Fair PDR: SAT without model".into(),
                ));
            };
            let Some(cube) = FairPdrCube::from_model(&model, &artifacts.state_vars_pre) else {
                return Ok(FairCubeQueryResult::Unknown(
                    "Fair PDR: failed to extract bad-state cube".into(),
                ));
            };
            Ok(FairCubeQueryResult::Sat(cube))
        }
    }
}

pub(crate) fn fair_predecessor_query<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    with_model: bool,
) -> Result<(FairSatQueryResult, Option<FairPdrCube>), PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;

    if level == 1 {
        fair_assert_all(solver, &artifacts.init_assertions)?;
    } else {
        fair_assert_frame(solver, &frames[level - 1], &artifacts.state_vars_pre)?;
    }

    solver
        .assert(&cube.to_conjunction(&artifacts.state_vars_post))
        .map_err(|e| PipelineError::Solver(e.to_string()))?;

    if with_model {
        let var_refs: Vec<(&str, &SmtSort)> = artifacts
            .state_vars_pre
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let (sat, model) = solver
            .check_sat_with_model(&var_refs)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        return match sat {
            SatResult::Unsat => Ok((FairSatQueryResult::Unsat, None)),
            SatResult::Unknown(reason) => Ok((FairSatQueryResult::Unknown(reason), None)),
            SatResult::Sat => {
                let Some(model) = model else {
                    return Ok((
                        FairSatQueryResult::Unknown(
                            "Fair PDR: SAT predecessor without model".into(),
                        ),
                        None,
                    ));
                };
                let Some(pred) = FairPdrCube::from_model(&model, &artifacts.state_vars_pre) else {
                    return Ok((
                        FairSatQueryResult::Unknown(
                            "Fair PDR: failed to extract predecessor cube".into(),
                        ),
                        None,
                    ));
                };
                Ok((FairSatQueryResult::Sat, Some(pred)))
            }
        };
    }

    match solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Sat => Ok((FairSatQueryResult::Sat, None)),
        SatResult::Unsat => Ok((FairSatQueryResult::Unsat, None)),
        SatResult::Unknown(reason) => Ok((FairSatQueryResult::Unknown(reason), None)),
    }
}

pub(crate) fn fair_cube_literal_to_term(
    lit: &FairPdrCubeLit,
    state_vars: &[(String, SmtSort)],
) -> Option<SmtTerm> {
    let (name, sort) = state_vars.get(lit.state_var_idx)?;
    Some(match sort {
        SmtSort::Int => SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)),
        SmtSort::Bool => SmtTerm::var(name.clone()).eq(SmtTerm::bool(lit.value != 0)),
    })
}

pub(crate) fn fair_try_generalize_cube_with_unsat_core<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    if !solver.supports_assumption_unsat_core() || cube.lits.is_empty() {
        return Ok((None, None));
    }

    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;

    if level == 1 {
        fair_assert_all(solver, &artifacts.init_assertions)?;
    } else {
        fair_assert_frame(solver, &frames[level - 1], &artifacts.state_vars_pre)?;
    }

    let mut assumptions = Vec::with_capacity(cube.lits.len());
    let mut lit_by_assumption = HashMap::with_capacity(cube.lits.len());
    for (idx, lit) in cube.lits.iter().enumerate() {
        let Some(lit_term) = fair_cube_literal_to_term(lit, &artifacts.state_vars_post) else {
            return Ok((None, None));
        };
        let assumption_name = format!("__fair_pdr_assume_{level}_{idx}");
        solver
            .declare_var(&assumption_name, &SmtSort::Bool)
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        solver
            .assert(&SmtTerm::var(assumption_name.clone()).implies(lit_term))
            .map_err(|e| PipelineError::Solver(e.to_string()))?;
        assumptions.push(assumption_name.clone());
        lit_by_assumption.insert(assumption_name, lit.clone());
    }

    match solver
        .check_sat_assuming(&assumptions)
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Unsat => {
            let core_names = solver
                .get_unsat_core_assumptions()
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            if core_names.is_empty() {
                return Ok((None, None));
            }
            let mut core_lits: Vec<FairPdrCubeLit> = core_names
                .iter()
                .filter_map(|name| lit_by_assumption.get(name).cloned())
                .collect();
            if core_lits.is_empty() {
                return Ok((None, None));
            }
            core_lits.sort();
            core_lits.dedup();
            Ok((Some(FairPdrCube { lits: core_lits }), None))
        }
        SatResult::Sat => Ok((None, None)),
        SatResult::Unknown(reason) => Ok((None, Some(reason))),
    }
}

pub(crate) fn fair_pdr_bad_cube_budget(state_var_count: usize, frontier: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(120)
        .saturating_add(frontier.saturating_mul(800));
    5_000usize.saturating_add(scaled).clamp(5_000, 200_000)
}

pub(crate) fn fair_pdr_obligation_budget(state_var_count: usize, level: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(220)
        .saturating_add(level.saturating_mul(1_500));
    10_000usize.saturating_add(scaled).clamp(10_000, 300_000)
}

pub(crate) fn fair_pdr_single_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(32)
        .saturating_add(128)
        .clamp(128, 16_384)
}

pub(crate) fn fair_pdr_pair_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(lit_count.saturating_sub(1))
        .saturating_div(2)
        .clamp(0, 2_048)
}

pub(crate) fn fair_pdr_literal_priority(
    lit: &FairPdrCubeLit,
    state_vars: &[(String, SmtSort)],
) -> (u8, usize) {
    let name = state_vars
        .get(lit.state_var_idx)
        .map(|(n, _)| n.as_str())
        .unwrap_or_default();
    // Domain-guided ordering for consensus models and fairness monitors.
    let class = if name.starts_with("m_") || name.starts_with("time_") {
        0
    } else if name.starts_with("g_") && lit.value == 0 {
        1
    } else if name.starts_with("g_") {
        2
    } else if name.starts_with("kappa_") && lit.value == 0 {
        3
    } else if name.starts_with("kappa_") {
        4
    } else if lit.value == 0 {
        5
    } else {
        6
    };
    (class, lit.state_var_idx)
}

pub(crate) fn fair_pdr_literal_drop_order(
    cube: &FairPdrCube,
    state_vars: &[(String, SmtSort)],
) -> Vec<usize> {
    let mut entries: Vec<(usize, (u8, usize))> = cube
        .lits
        .iter()
        .enumerate()
        .map(|(idx, lit)| (idx, fair_pdr_literal_priority(lit, state_vars)))
        .collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    entries.into_iter().map(|(idx, _)| idx).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fair_try_drop_single_literal<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
    query_budget: &mut usize,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    for idx in fair_pdr_literal_drop_order(cube, &artifacts.state_vars_post) {
        if deadline_exceeded(deadline) {
            return Ok((None, Some("Fair PDR: overall timeout exceeded.".into())));
        }
        if *query_budget == 0 {
            return Ok((None, None));
        }
        *query_budget -= 1;
        let mut candidate = cube.clone();
        candidate.lits.remove(idx);
        let (sat, _) = fair_predecessor_query(
            solver,
            artifacts,
            frames,
            level,
            &candidate,
            extra_assertions,
            false,
        )?;
        match sat {
            FairSatQueryResult::Unsat => return Ok((Some(candidate), None)),
            FairSatQueryResult::Sat => {}
            FairSatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
        }
    }
    Ok((None, None))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fair_try_drop_literal_pair<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
    pair_budget: &mut usize,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    let order = fair_pdr_literal_drop_order(cube, &artifacts.state_vars_post);
    for i in 0..order.len() {
        for j in (i + 1)..order.len() {
            if deadline_exceeded(deadline) {
                return Ok((None, Some("Fair PDR: overall timeout exceeded.".into())));
            }
            if *pair_budget == 0 {
                return Ok((None, None));
            }
            *pair_budget -= 1;
            let idx_a = order[i];
            let idx_b = order[j];
            let mut candidate = cube.clone();
            if idx_a > idx_b {
                candidate.lits.remove(idx_a);
                candidate.lits.remove(idx_b);
            } else {
                candidate.lits.remove(idx_b);
                candidate.lits.remove(idx_a);
            }
            let (sat, _) = fair_predecessor_query(
                solver,
                artifacts,
                frames,
                level,
                &candidate,
                extra_assertions,
                false,
            )?;
            match sat {
                FairSatQueryResult::Unsat => return Ok((Some(candidate), None)),
                FairSatQueryResult::Sat => {}
                FairSatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
            }
        }
    }
    Ok((None, None))
}

pub(crate) fn fair_try_generalize_cube<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &[FairPdrFrame],
    level: usize,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<(Option<FairPdrCube>, Option<String>), PipelineError> {
    let (core_cube, core_reason) = fair_try_generalize_cube_with_unsat_core(
        solver,
        artifacts,
        frames,
        level,
        cube,
        extra_assertions,
    )?;
    if let Some(reason) = core_reason {
        return Ok((None, Some(reason)));
    }
    if core_cube.is_some() {
        return Ok((core_cube, None));
    }

    let mut current = cube.clone();
    if current.lits.len() <= 1 {
        return Ok((Some(current), None));
    }

    let mut single_budget = fair_pdr_single_literal_query_budget(current.lits.len());
    let mut pair_budget = fair_pdr_pair_literal_query_budget(current.lits.len());

    loop {
        let (candidate, reason) = fair_try_drop_single_literal(
            solver,
            artifacts,
            frames,
            level,
            &current,
            extra_assertions,
            deadline,
            &mut single_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(candidate) = candidate else {
            break;
        };
        current = candidate;
        if current.lits.len() <= 1 {
            return Ok((Some(current), None));
        }
    }

    while current.lits.len() > 2 {
        let (pair_candidate, reason) = fair_try_drop_literal_pair(
            solver,
            artifacts,
            frames,
            level,
            &current,
            extra_assertions,
            deadline,
            &mut pair_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(pair_candidate) = pair_candidate else {
            break;
        };
        current = pair_candidate;
        loop {
            let (single_candidate, reason) = fair_try_drop_single_literal(
                solver,
                artifacts,
                frames,
                level,
                &current,
                extra_assertions,
                deadline,
                &mut single_budget,
            )?;
            if let Some(reason) = reason {
                return Ok((None, Some(reason)));
            }
            let Some(single_candidate) = single_candidate else {
                break;
            };
            current = single_candidate;
            if current.lits.len() <= 1 {
                return Ok((Some(current), None));
            }
        }
    }

    Ok((Some(current), None))
}

pub(crate) fn fair_add_cube_up_to(frames: &mut [FairPdrFrame], level: usize, cube: FairPdrCube) {
    for frame in frames.iter_mut().take(level + 1).skip(1) {
        frame.insert(cube.clone());
    }
}

pub(crate) enum FairBlockingOutcome {
    Blocked,
    Counterexample,
    Unknown(String),
}

pub(crate) fn fair_block_cube<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frames: &mut [FairPdrFrame],
    level: usize,
    initial_cube: FairPdrCube,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<FairBlockingOutcome, PipelineError> {
    let max_obligations = fair_pdr_obligation_budget(artifacts.state_vars_pre.len(), level);
    let mut obligations = vec![(initial_cube, level)];
    let mut processed = 0usize;

    while let Some((cube, lvl)) = obligations.pop() {
        processed += 1;
        if processed > max_obligations {
            return Ok(FairBlockingOutcome::Unknown(
                format!(
                    "Fair PDR: obligation budget exceeded while blocking a bad cube (budget={max_obligations})."
                ),
            ));
        }
        if deadline_exceeded(deadline) {
            return Ok(FairBlockingOutcome::Unknown(
                "Fair PDR: overall timeout exceeded.".into(),
            ));
        }

        if lvl == 0 {
            return Ok(FairBlockingOutcome::Counterexample);
        }

        let (sat, pred) = fair_predecessor_query(
            solver,
            artifacts,
            frames,
            lvl,
            &cube,
            extra_assertions,
            true,
        )?;
        match sat {
            FairSatQueryResult::Unsat => {
                let (generalized, unknown_reason) = fair_try_generalize_cube(
                    solver,
                    artifacts,
                    frames,
                    lvl,
                    &cube,
                    extra_assertions,
                    deadline,
                )?;
                if let Some(reason) = unknown_reason {
                    return Ok(FairBlockingOutcome::Unknown(reason));
                }
                let Some(gen_cube) = generalized else {
                    return Ok(FairBlockingOutcome::Unknown(
                        "Fair PDR: failed to generalize blocked cube.".into(),
                    ));
                };
                fair_add_cube_up_to(frames, lvl, gen_cube);
            }
            FairSatQueryResult::Sat => {
                let Some(pred_cube) = pred else {
                    return Ok(FairBlockingOutcome::Unknown(
                        "Fair PDR: predecessor SAT without model".into(),
                    ));
                };
                obligations.push((cube, lvl));
                obligations.push((pred_cube, lvl - 1));
            }
            FairSatQueryResult::Unknown(reason) => return Ok(FairBlockingOutcome::Unknown(reason)),
        }
    }

    Ok(FairBlockingOutcome::Blocked)
}

pub(crate) fn fair_can_push<S: SmtSolver>(
    solver: &mut S,
    artifacts: &FairPdrArtifacts,
    frame: &FairPdrFrame,
    cube: &FairPdrCube,
    extra_assertions: &[SmtTerm],
) -> Result<FairSatQueryResult, PipelineError> {
    solver
        .reset()
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    fair_declare_all(solver, &artifacts.declarations)?;
    fair_assert_all(solver, &artifacts.state_assertions_pre)?;
    fair_assert_all(solver, &artifacts.transition_assertions)?;
    fair_assert_all(solver, extra_assertions)?;
    fair_assert_frame(solver, frame, &artifacts.state_vars_pre)?;
    solver
        .assert(&cube.to_conjunction(&artifacts.state_vars_post))
        .map_err(|e| PipelineError::Solver(e.to_string()))?;
    match solver
        .check_sat()
        .map_err(|e| PipelineError::Solver(e.to_string()))?
    {
        SatResult::Unsat => Ok(FairSatQueryResult::Unsat),
        SatResult::Sat => Ok(FairSatQueryResult::Sat),
        SatResult::Unknown(reason) => Ok(FairSatQueryResult::Unknown(reason)),
    }
}

pub(crate) fn run_unbounded_fair_pdr_internal<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<
    (
        UnboundedFairLivenessResult,
        Option<FairPdrInvariantCertificate>,
    ),
    PipelineError,
> {
    let frame_limit = if max_k == 0 { None } else { Some(max_k) };
    let deadline = overall_timeout.and_then(|t| Instant::now().checked_add(t));

    let artifacts = build_unbounded_fair_pdr_artifacts(cs, target, fairness)?;
    let extra_assertions = committee_bound_assertions(committee_bounds);

    let mut frames = vec![FairPdrFrame::default(), FairPdrFrame::default()];
    let mut frontier = 1usize;

    loop {
        crate::sandbox::enforce_active_limits()?;
        if let Some(reason) = liveness_memory_budget_reason("Fair PDR", Some(frontier)) {
            return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
        }
        if deadline_exceeded(deadline) {
            return Ok((
                UnboundedFairLivenessResult::Unknown {
                    reason: format!(
                        "Fair PDR: overall timeout exceeded at frontier frame {}.",
                        frontier
                    ),
                },
                None,
            ));
        }

        let mut blocked_bad_cubes = 0usize;
        let max_bad_cubes = fair_pdr_bad_cube_budget(artifacts.state_vars_pre.len(), frontier);
        loop {
            crate::sandbox::enforce_active_limits()?;
            if let Some(reason) = liveness_memory_budget_reason("Fair PDR", Some(frontier)) {
                return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
            }
            if deadline_exceeded(deadline) {
                return Ok((
                    UnboundedFairLivenessResult::Unknown {
                        reason: format!(
                            "Fair PDR: overall timeout exceeded at frontier frame {}.",
                            frontier
                        ),
                    },
                    None,
                ));
            }
            match fair_query_bad_in_frame(solver, &artifacts, &frames[frontier], &extra_assertions)?
            {
                FairCubeQueryResult::Unsat => break,
                FairCubeQueryResult::Unknown(reason) => {
                    return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                }
                FairCubeQueryResult::Sat(cube) => {
                    blocked_bad_cubes += 1;
                    if blocked_bad_cubes > max_bad_cubes {
                        return Ok((
                            UnboundedFairLivenessResult::Unknown {
                                reason: format!(
                                    "Fair PDR: blocked over {max_bad_cubes} bad cubes \
                                     at frame {frontier} (adaptive budget); state space appears too large \
                                     for current abstraction."
                                ),
                            },
                            None,
                        ));
                    }
                    match fair_block_cube(
                        solver,
                        &artifacts,
                        &mut frames,
                        frontier,
                        cube,
                        &extra_assertions,
                        deadline,
                    )? {
                        FairBlockingOutcome::Blocked => {}
                        FairBlockingOutcome::Unknown(reason) => {
                            return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                        }
                        FairBlockingOutcome::Counterexample => {
                            // Recover a concrete lasso trace using bounded fair-lasso search.
                            match run_fair_lasso_search(
                                solver,
                                cs,
                                frontier + 1,
                                target,
                                committee_bounds,
                                fairness,
                                deadline,
                            )? {
                                FairLivenessResult::FairCycleFound {
                                    depth,
                                    loop_start,
                                    trace,
                                } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::FairCycleFound {
                                            depth,
                                            loop_start,
                                            trace,
                                        },
                                        None,
                                    ));
                                }
                                FairLivenessResult::Unknown { reason } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::Unknown { reason },
                                        None,
                                    ));
                                }
                                FairLivenessResult::NoFairCycleUpTo { .. } => {
                                    return Ok((
                                        UnboundedFairLivenessResult::Unknown {
                                            reason:
                                                "Fair PDR found a reachable accepting state, \
                                                 but bounded lasso recovery did not return a trace."
                                                    .into(),
                                        },
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        for level in 1..frontier {
            if let Some(reason) = liveness_memory_budget_reason("Fair PDR", Some(frontier)) {
                return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
            }
            if deadline_exceeded(deadline) {
                return Ok((
                    UnboundedFairLivenessResult::Unknown {
                        reason: format!(
                            "Fair PDR: overall timeout exceeded at frontier frame {}.",
                            frontier
                        ),
                    },
                    None,
                ));
            }
            let cubes: Vec<FairPdrCube> = frames[level].cubes.iter().cloned().collect();
            for cube in cubes {
                if frames[level + 1].contains(&cube) {
                    continue;
                }
                match fair_can_push(solver, &artifacts, &frames[level], &cube, &extra_assertions)? {
                    FairSatQueryResult::Unsat => {
                        frames[level + 1].insert(cube);
                    }
                    FairSatQueryResult::Sat => {}
                    FairSatQueryResult::Unknown(reason) => {
                        return Ok((UnboundedFairLivenessResult::Unknown { reason }, None));
                    }
                }
            }
        }

        for i in 1..frontier {
            if frames[i] == frames[i + 1] {
                let cert = build_fair_pdr_invariant_certificate(&artifacts, &frames[i], i);
                return Ok((
                    UnboundedFairLivenessResult::LiveProved { frame: i },
                    Some(cert),
                ));
            }
        }

        if let Some(limit) = frame_limit {
            if frontier >= limit {
                return Ok((
                    UnboundedFairLivenessResult::NotProved { max_k: limit },
                    None,
                ));
            }
        }

        frames.push(FairPdrFrame::default());
        frontier += 1;
    }
}

pub(crate) fn run_unbounded_fair_pdr<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<UnboundedFairLivenessResult, PipelineError> {
    Ok(run_unbounded_fair_pdr_internal(
        solver,
        cs,
        max_k,
        target,
        committee_bounds,
        fairness,
        overall_timeout,
    )?
    .0)
}

pub(crate) fn run_unbounded_fair_pdr_with_certificate<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    max_k: usize,
    target: &FairLivenessTarget,
    committee_bounds: &[(usize, u64)],
    fairness: FairnessMode,
    overall_timeout: Option<Duration>,
) -> Result<
    (
        UnboundedFairLivenessResult,
        Option<FairPdrInvariantCertificate>,
    ),
    PipelineError,
> {
    run_unbounded_fair_pdr_internal(
        solver,
        cs,
        max_k,
        target,
        committee_bounds,
        fairness,
        overall_timeout,
    )
}
