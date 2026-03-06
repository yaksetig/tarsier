//! CTI-driven invariant inference helpers.
//!
//! This module isolates reusable invariant-synthesis logic from orchestration.

use crate::pipeline::verification::*;
use crate::pipeline::*;
use std::collections::HashSet;

pub(crate) fn property_relevant_location_set(property: &SafetyProperty) -> HashSet<usize> {
    let mut locs = HashSet::new();
    match property {
        SafetyProperty::Agreement { conflicting_pairs } => {
            for (a, b) in conflicting_pairs {
                locs.insert(a.as_usize());
                locs.insert(b.as_usize());
            }
        }
        SafetyProperty::Invariant { bad_sets } => {
            for bad in bad_sets {
                for loc in bad {
                    locs.insert(loc.as_usize());
                }
            }
        }
        SafetyProperty::Termination { goal_locs } => {
            for loc in goal_locs {
                locs.insert(loc.as_usize());
            }
        }
    }
    locs
}

pub(crate) fn cti_zero_location_candidates(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    max_candidates: usize,
) -> Vec<usize> {
    if max_candidates == 0 {
        return Vec::new();
    }

    let occupied_names: HashSet<&str> = cti
        .hypothesis_locations
        .iter()
        .chain(cti.violating_locations.iter())
        .map(|(name, _)| name.as_str())
        .collect();
    let relevant = property_relevant_location_set(property);

    let mut candidates: Vec<usize> = ta
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| !occupied_names.contains(loc.name.as_str()))
        .map(|(id, _)| id)
        .collect();
    candidates.sort_by(|a, b| {
        let ra = relevant.contains(a);
        let rb = relevant.contains(b);
        rb.cmp(&ra)
            .then_with(|| ta.locations[*a].name.cmp(&ta.locations[*b].name))
    });
    candidates.truncate(max_candidates);
    candidates
}

pub(crate) fn prove_location_unreachable_for_synthesis(
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    loc_id: usize,
) -> Result<bool, PipelineError> {
    let candidate = SafetyProperty::Invariant {
        bad_sets: vec![vec![loc_id.into()]],
    };
    let kind_result = match options.solver {
        SolverChoice::Z3 => {
            let mut solver = Z3Solver::with_timeout_secs(options.timeout_secs);
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
        SolverChoice::Cvc5 => {
            use tarsier_smt::backends::cvc5_backend::Cvc5Solver;
            let mut solver = Cvc5Solver::with_timeout_secs(options.timeout_secs)
                .map_err(|e| PipelineError::Solver(e.to_string()))?;
            run_unbounded_with_engine(
                &mut solver,
                cs,
                &candidate,
                options.max_depth,
                committee_bounds,
                ProofEngine::KInduction,
                overall_timeout_duration(options.timeout_secs),
            )?
        }
    };
    Ok(matches!(kind_result, KInductionResult::Proved { .. }))
}

pub(crate) fn synthesize_cti_zero_location_invariants(
    ta: &ThresholdAutomaton,
    property: &SafetyProperty,
    cti: &InductionCtiSummary,
    cs: &CounterSystem,
    options: &PipelineOptions,
    committee_bounds: &[(usize, u64)],
    max_refinements: usize,
    deadline: Option<Instant>,
) -> Result<Vec<usize>, PipelineError> {
    let candidate_budget = (max_refinements.max(1)) * 2;
    let candidates = cti_zero_location_candidates(ta, property, cti, candidate_budget);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut synthesized_locs = Vec::new();
    for loc in candidates {
        let synthesis_options =
            match options_with_remaining_timeout(options, deadline, "CTI predicate synthesis") {
                Ok(adjusted) => adjusted,
                Err(_) => {
                    return Err(PipelineError::Solver(timeout_unknown_reason(
                        "CTI predicate synthesis",
                    )));
                }
            };

        if prove_location_unreachable_for_synthesis(cs, &synthesis_options, committee_bounds, loc)?
        {
            synthesized_locs.push(loc);
        }
        if synthesized_locs.len() >= max_refinements.max(1) {
            break;
        }
    }
    Ok(synthesized_locs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_relevant_location_set_agreement() {
        let prop = SafetyProperty::Agreement {
            conflicting_pairs: vec![(0.into(), 1.into()), (2.into(), 3.into())],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 4);
        assert!(locs.contains(&0));
        assert!(locs.contains(&1));
        assert!(locs.contains(&2));
        assert!(locs.contains(&3));
    }

    #[test]
    fn property_relevant_location_set_invariant() {
        let prop = SafetyProperty::Invariant {
            bad_sets: vec![vec![5.into(), 6.into()], vec![7.into()]],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 3);
        assert!(locs.contains(&5));
        assert!(locs.contains(&6));
        assert!(locs.contains(&7));
    }

    #[test]
    fn property_relevant_location_set_termination() {
        let prop = SafetyProperty::Termination {
            goal_locs: vec![10.into(), 20.into()],
        };
        let locs = property_relevant_location_set(&prop);
        assert_eq!(locs.len(), 2);
        assert!(locs.contains(&10));
        assert!(locs.contains(&20));
    }
}
