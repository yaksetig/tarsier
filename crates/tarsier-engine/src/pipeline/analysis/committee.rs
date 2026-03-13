// Committee-derived adversary bound helpers.

use super::*;

/// Analyze committee selections and derive concrete adversary bounds.
///
/// For each committee spec, compute the worst-case Byzantine count b_max
/// such that P(Byzantine > b_max) <= epsilon. Returns summaries for reporting
/// and optionally injects concrete bounds into the threshold automaton.
pub(in super::super) fn analyze_and_constrain_committees(
    ta: &mut ThresholdAutomaton,
) -> Result<Vec<CommitteeAnalysisSummary>, PipelineError> {
    let mut summaries = Vec::new();

    for committee in &ta.constraints.committees.clone() {
        let epsilon = committee.epsilon.unwrap_or(1e-9);

        // Resolve population, byzantine, committee_size to concrete values
        let population = resolve_param_or_const(&committee.population, ta)?;
        let byzantine = resolve_param_or_const(&committee.byzantine, ta)?;
        let committee_size = resolve_param_or_const(&committee.committee_size, ta)?;

        let spec = CommitteeSpec {
            name: committee.name.clone(),
            population: population as u64,
            byzantine: byzantine as u64,
            committee_size: committee_size as u64,
            epsilon,
        };

        info!(
            name = %spec.name,
            population = spec.population,
            byzantine = spec.byzantine,
            committee_size = spec.committee_size,
            epsilon = %spec.epsilon,
            "Analyzing committee selection..."
        );

        let analysis = tarsier_prob::analyze_committee(&spec)?;

        info!(
            b_max = analysis.b_max,
            expected = %format!("{:.1}", analysis.expected_byzantine),
            "Committee analysis complete"
        );

        summaries.push(CommitteeAnalysisSummary {
            name: spec.name.clone(),
            committee_size: spec.committee_size,
            population: spec.population,
            byzantine: spec.byzantine,
            b_max: analysis.b_max,
            epsilon,
            tail_probability: analysis.tail_probability,
            honest_majority: analysis.honest_majority,
            expected_byzantine: analysis.expected_byzantine,
        });
    }

    // If no explicit adversary bound was set, allow a single committee-bound
    // parameter to drive adversary injections. Multiple committee bound params
    // are ambiguous and must be disambiguated explicitly by the model.
    if ta.constraints.adversary_bound_param.is_none() {
        let mut candidate_params: HashSet<ParamId> = HashSet::new();
        for c in &ta.constraints.committees {
            if let Some(pid) = c.bound_param {
                candidate_params.insert(pid);
            }
        }
        if candidate_params.len() == 1 {
            if let Some(&pid) = candidate_params.iter().next() {
                ta.constraints.adversary_bound_param = Some(pid);
                info!(
                    param = %ta.parameters[pid.as_usize()].name,
                    "Using committee-derived adversary bound parameter"
                );
            }
        } else if candidate_params.len() > 1 {
            return Err(PipelineError::Property(
                "Multiple committee bound parameters found but adversary.bound is not set. \
                 Set `adversary { bound: ...; }` explicitly."
                    .into(),
            ));
        }
    }

    Ok(summaries)
}

pub(in super::super) fn ensure_n_parameter(ta: &ThresholdAutomaton) -> Result<(), PipelineError> {
    if ta.find_param_by_name("n").is_none() {
        return Err(PipelineError::Property(
            "Protocol must declare parameter `n` (process population size).".into(),
        ));
    }
    Ok(())
}
