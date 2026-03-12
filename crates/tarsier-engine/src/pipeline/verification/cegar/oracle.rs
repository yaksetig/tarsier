//! CEGAR refinement-selection oracle and UNSAT-core helper routines.

use super::*;

pub(crate) struct CegarEvidenceRequirement {
    pub(crate) tag: String,
    pub(crate) supporters: Vec<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct CegarUnsatCoreSelection {
    pub(crate) selected_indices: Vec<usize>,
    pub(crate) cores_considered: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum CegarOracleOutcome {
    Sat,
    Unsat { core_indices: Vec<usize> },
    Unknown,
}

pub(crate) fn cegar_selection_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, 15)
}

pub(crate) fn cegar_evidence_requirements(
    atomics: &[CegarAtomicRefinement],
    signals: &CegarTraceSignals,
) -> Vec<CegarEvidenceRequirement> {
    let mut supporters_by_tag: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for (idx, atom) in atomics.iter().enumerate() {
        for tag in cegar_atom_evidence_tags(atom, signals) {
            supporters_by_tag.entry(tag).or_default().insert(idx);
        }
    }

    supporters_by_tag
        .into_iter()
        .filter_map(|(tag, supporters)| {
            if supporters.is_empty() {
                None
            } else {
                Some(CegarEvidenceRequirement {
                    tag,
                    supporters: supporters.into_iter().collect(),
                })
            }
        })
        .collect()
}

pub(crate) fn combinations_of_size(indices_len: usize, pick: usize) -> Vec<Vec<usize>> {
    if pick == 0 {
        return vec![Vec::new()];
    }
    if pick > indices_len {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(pick);
    fn rec(
        start: usize,
        remaining: usize,
        total: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            out.push(current.clone());
            return;
        }
        let last_start = total.saturating_sub(remaining);
        for idx in start..=last_start {
            current.push(idx);
            rec(idx + 1, remaining - 1, total, current, out);
            current.pop();
        }
    }
    rec(0, pick, indices_len, &mut current, &mut out);
    out
}

pub(crate) fn at_most_k_bool_terms(vars: &[String], k: usize) -> Vec<SmtTerm> {
    if k >= vars.len() {
        return Vec::new();
    }
    if k == 0 {
        return vars
            .iter()
            .map(|name| SmtTerm::var(name.clone()).not())
            .collect();
    }
    let mut terms = Vec::new();
    for combo in combinations_of_size(vars.len(), k + 1) {
        let clause = combo
            .into_iter()
            .map(|idx| SmtTerm::var(vars[idx].clone()).not())
            .collect();
        terms.push(SmtTerm::or(clause));
    }
    terms
}

pub(crate) fn cegar_oracle_outcome_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
    enabled_indices: &BTreeSet<usize>,
) -> Result<CegarOracleOutcome, S::Error> {
    if !solver.supports_assumption_unsat_core() {
        return Ok(CegarOracleOutcome::Unknown);
    }

    let select_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_select_{idx}"))
        .collect();
    for name in &select_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }

    for req in requirements {
        let disjuncts: Vec<SmtTerm> = req
            .supporters
            .iter()
            .map(|idx| SmtTerm::var(select_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disjuncts))?;
    }

    let mut disable_by_index: HashMap<usize, String> = HashMap::with_capacity(atomics_len);
    for (idx, selected_name) in select_vars.iter().enumerate() {
        let disable_name = format!("__cegar_disable_{idx}");
        solver.declare_var(&disable_name, &SmtSort::Bool)?;
        solver.assert(
            &SmtTerm::var(disable_name.clone()).implies(SmtTerm::var(selected_name.clone()).not()),
        )?;
        disable_by_index.insert(idx, disable_name);
    }

    let assumptions: Vec<String> = (0..atomics_len)
        .filter(|idx| !enabled_indices.contains(idx))
        .filter_map(|idx| disable_by_index.get(&idx).cloned())
        .collect();
    match solver.check_sat_assuming(&assumptions)? {
        SatResult::Sat => Ok(CegarOracleOutcome::Sat),
        SatResult::Unsat => {
            let core_names = solver.get_unsat_core_assumptions()?;
            let mut index_by_disable: HashMap<String, usize> =
                HashMap::with_capacity(disable_by_index.len());
            for (idx, name) in disable_by_index {
                index_by_disable.insert(name, idx);
            }
            let mut core_indices: Vec<usize> = core_names
                .into_iter()
                .filter_map(|name| index_by_disable.get(&name).copied())
                .collect();
            core_indices.sort_unstable();
            core_indices.dedup();
            if core_indices.is_empty() {
                Ok(CegarOracleOutcome::Unknown)
            } else {
                Ok(CegarOracleOutcome::Unsat { core_indices })
            }
        }
        SatResult::Unknown(_) => Ok(CegarOracleOutcome::Unknown),
    }
}

pub(crate) fn cegar_min_hitting_set_with_solver<S: SmtSolver>(
    solver: &mut S,
    atomics_len: usize,
    discovered_cores: &[Vec<usize>],
) -> Result<Option<BTreeSet<usize>>, S::Error> {
    if atomics_len == 0 {
        return Ok(Some(BTreeSet::new()));
    }
    let choice_vars: Vec<String> = (0..atomics_len)
        .map(|idx| format!("__cegar_pick_{idx}"))
        .collect();
    for name in &choice_vars {
        solver.declare_var(name, &SmtSort::Bool)?;
    }
    for core in discovered_cores {
        let disj = core
            .iter()
            .map(|idx| SmtTerm::var(choice_vars[*idx].clone()))
            .collect();
        solver.assert(&SmtTerm::or(disj))?;
    }

    for k in 0..=atomics_len {
        solver.push()?;
        for term in at_most_k_bool_terms(&choice_vars, k) {
            solver.assert(&term)?;
        }
        let sat = solver.check_sat()?;
        match sat {
            SatResult::Sat => {
                let mut selected = BTreeSet::new();
                // Deterministic tie-break: lexicographically minimize the
                // selected-index bitvector by trying to force each variable to
                // false in index order, and only forcing true when UNSAT.
                for (idx, name) in choice_vars.iter().enumerate() {
                    solver.push()?;
                    solver.assert(&SmtTerm::var(name.clone()).not())?;
                    match solver.check_sat()? {
                        SatResult::Sat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()).not())?;
                        }
                        SatResult::Unsat => {
                            solver.pop()?;
                            solver.assert(&SmtTerm::var(name.clone()))?;
                            selected.insert(idx);
                        }
                        SatResult::Unknown(_) => {
                            solver.pop()?;
                            solver.pop()?;
                            return Ok(None);
                        }
                    }
                }
                solver.pop()?;
                return Ok(Some(selected));
            }
            SatResult::Unsat => {
                solver.pop()?;
            }
            SatResult::Unknown(_) => {
                solver.pop()?;
                return Ok(None);
            }
        }
    }

    Ok(None)
}

pub(crate) fn cegar_unsat_core_seed_with_factory<S, E, F>(
    mut solver_factory: F,
    atomics_len: usize,
    requirements: &[CegarEvidenceRequirement],
) -> Result<Option<CegarUnsatCoreSelection>, PipelineError>
where
    S: SmtSolver<Error = E>,
    E: std::error::Error,
    F: FnMut() -> Result<S, E>,
{
    if atomics_len == 0 || requirements.is_empty() {
        return Ok(None);
    }

    {
        let solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
        if !solver.supports_assumption_unsat_core() {
            return Ok(None);
        }
    }

    let mut discovered_cores: Vec<Vec<usize>> = Vec::new();
    let mut seen_cores: HashSet<Vec<usize>> = HashSet::new();
    let max_iters = atomics_len.saturating_mul(8).max(8);

    for _ in 0..max_iters {
        let candidate = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_min_hitting_set_with_solver(&mut solver, atomics_len, &discovered_cores)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        let Some(candidate) = candidate else {
            return Ok(None);
        };

        let outcome = {
            let mut solver = solver_factory().map_err(|e| PipelineError::Solver(e.to_string()))?;
            cegar_oracle_outcome_with_solver(&mut solver, atomics_len, requirements, &candidate)
                .map_err(|e| PipelineError::Solver(e.to_string()))?
        };
        match outcome {
            CegarOracleOutcome::Sat => {
                return Ok(Some(CegarUnsatCoreSelection {
                    selected_indices: candidate.into_iter().collect(),
                    cores_considered: discovered_cores.len(),
                }));
            }
            CegarOracleOutcome::Unsat { core_indices } => {
                if seen_cores.insert(core_indices.clone()) {
                    discovered_cores.push(core_indices);
                } else {
                    return Ok(None);
                }
            }
            CegarOracleOutcome::Unknown => {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

pub(crate) fn cegar_unsat_core_seed(
    atomics: &[CegarAtomicRefinement],
    requirements: &[CegarEvidenceRequirement],
    solver_choice: SolverChoice,
    timeout_secs: u64,
) -> Option<CegarUnsatCoreSelection> {
    let timeout_secs = cegar_selection_timeout_secs(timeout_secs);
    let result = match solver_choice {
        SolverChoice::Z3 => cegar_unsat_core_seed_with_factory(
            || {
                Ok::<_, tarsier_smt::backends::z3_backend::Z3Error>(Z3Solver::with_timeout_secs(
                    timeout_secs,
                ))
            },
            atomics.len(),
            requirements,
        ),
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            cegar_unsat_core_seed_with_factory(
                || Cvc5Solver::with_timeout_secs(timeout_secs),
                atomics.len(),
                requirements,
            )
        }
    };

    match result {
        Ok(seed) => seed,
        Err(err) => {
            info!("CEGAR UNSAT-core refinement selection fallback: {err}");
            None
        }
    }
}
