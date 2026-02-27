//! Committee analysis, quantitative analysis functions, round erasure abstraction.

use sha2::Digest; // trait needed for Sha256::new()/update()/finalize()

use super::property::resolve_param_or_const;
use super::verification::lower_with_active_controls;
use super::*;

pub(super) fn base_message_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix("cnt_")?;
    let without_recipient = stripped.split_once('@').map(|(b, _)| b).unwrap_or(stripped);
    let base = without_recipient
        .split_once('[')
        .map(|(b, _)| b)
        .unwrap_or(without_recipient);
    Some(base.to_string())
}

/// Parse `cnt_<family>@<recipient>[...]` style names into family and recipient.
pub(super) fn message_family_and_recipient_from_counter_name(
    name: &str,
) -> Option<(String, Option<String>)> {
    let stripped = name.strip_prefix("cnt_")?;
    let (family_part, recipient) = match stripped.split_once('@') {
        Some((family, tail)) => {
            let channel = tail.split_once('[').map(|(r, _)| r).unwrap_or(tail);
            let recipient = channel
                .split_once("<-")
                .map(|(r, _)| r)
                .unwrap_or(channel)
                .to_string();
            (family, Some(recipient))
        }
        None => (stripped, None),
    };
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    Some((family, recipient))
}

/// Canonicalize erased-variable names for case-insensitive matching.
pub(super) fn normalize_erased_var_names(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Return whether `name` is in the erased-variable set (case-insensitive).
pub(super) fn is_erased_var_name(name: &str, erased: &HashSet<String>) -> bool {
    erased.contains(&name.to_ascii_lowercase())
}

/// Remove erased field assignments from counter payloads (`cnt_*[k=v,...]`).
pub(super) fn erase_round_fields_from_message_counter_name(
    name: &str,
    erased: &HashSet<String>,
) -> String {
    if !name.starts_with("cnt_") {
        return name.to_string();
    }
    let Some((prefix, suffix)) = name.split_once('[') else {
        return name.to_string();
    };
    let inner = suffix.strip_suffix(']').unwrap_or(suffix);
    let kept_parts = inner
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            let (field, value) = part.split_once('=')?;
            if is_erased_var_name(field.trim(), erased) {
                None
            } else {
                Some(format!("{}={}", field.trim(), value.trim()))
            }
        })
        .collect::<Vec<_>>();
    if kept_parts.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}[{}]", kept_parts.join(","))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) enum SharedMergeKey {
    MessageCounter(String),
    Unique(usize),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct LocationMergeKey {
    role: String,
    phase: String,
    locals: Vec<(String, LocalValue)>,
}

pub(super) fn build_location_merge_key(
    loc: &tarsier_ir::threshold_automaton::Location,
    erased: &HashSet<String>,
) -> LocationMergeKey {
    let mut locals = loc
        .local_vars
        .iter()
        .filter(|(name, _)| !is_erased_var_name(name, erased))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    locals.sort_by(|a, b| a.0.cmp(&b.0));
    LocationMergeKey {
        role: loc.role.clone(),
        phase: loc.phase.clone(),
        locals,
    }
}

pub(super) fn apply_round_erasure_abstraction(
    ta: &ThresholdAutomaton,
    erased_var_names: &[String],
) -> (ThresholdAutomaton, RoundAbstractionSummary) {
    let erased = normalize_erased_var_names(erased_var_names);
    let original_message_counters = ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();

    let mut abstract_ta = ThresholdAutomaton {
        locations: Vec::new(),
        initial_locations: Vec::new(),
        shared_vars: Vec::new(),
        rules: Vec::new(),
        parameters: ta.parameters.clone(),
        resilience_condition: ta.resilience_condition.clone(),
        adversary_bound_param: ta.adversary_bound_param,
        fault_model: ta.fault_model,
        timing_model: ta.timing_model,
        gst_param: ta.gst_param,
        value_abstraction: ta.value_abstraction,
        equivocation_mode: ta.equivocation_mode,
        authentication_mode: ta.authentication_mode,
        network_semantics: ta.network_semantics,
        delivery_control: ta.delivery_control,
        fault_budget_scope: ta.fault_budget_scope,
        role_identities: ta.role_identities.clone(),
        key_ownership: ta.key_ownership.clone(),
        compromised_keys: ta.compromised_keys.clone(),
        message_policies: ta.message_policies.clone(),
        crypto_objects: ta.crypto_objects.clone(),
        committees: ta.committees.clone(),
        por_mode: ta.por_mode,
    };

    let mut shared_map: Vec<usize> = vec![0; ta.shared_vars.len()];
    let mut shared_key_to_new: HashMap<SharedMergeKey, usize> = HashMap::new();
    for (old_id, shared) in ta.shared_vars.iter().enumerate() {
        let key = if shared.kind == SharedVarKind::MessageCounter {
            let erased_name = erase_round_fields_from_message_counter_name(&shared.name, &erased);
            SharedMergeKey::MessageCounter(erased_name)
        } else {
            SharedMergeKey::Unique(old_id)
        };

        if let Some(&new_id) = shared_key_to_new.get(&key) {
            shared_map[old_id] = new_id;
            if shared.kind == SharedVarKind::MessageCounter {
                let existing = &mut abstract_ta.shared_vars[new_id];
                existing.distinct &= shared.distinct;
                if existing.distinct {
                    if existing.distinct_role != shared.distinct_role {
                        existing.distinct = false;
                        existing.distinct_role = None;
                    }
                } else {
                    existing.distinct_role = None;
                }
            }
            continue;
        }

        let new_name = match &key {
            SharedMergeKey::MessageCounter(name) => name.clone(),
            SharedMergeKey::Unique(_) => shared.name.clone(),
        };
        let new_id = abstract_ta.shared_vars.len();
        abstract_ta
            .shared_vars
            .push(tarsier_ir::threshold_automaton::SharedVar {
                name: new_name,
                kind: shared.kind,
                distinct: shared.distinct,
                distinct_role: shared.distinct_role.clone(),
            });
        shared_key_to_new.insert(key, new_id);
        shared_map[old_id] = new_id;
    }

    let mut loc_map: Vec<usize> = vec![0; ta.locations.len()];
    let mut loc_key_to_new: HashMap<LocationMergeKey, usize> = HashMap::new();
    for (old_id, loc) in ta.locations.iter().enumerate() {
        let key = build_location_merge_key(loc, &erased);
        if let Some(&new_id) = loc_key_to_new.get(&key) {
            loc_map[old_id] = new_id;
            continue;
        }

        let mut local_vars = loc.local_vars.clone();
        local_vars.retain(|name, _| !is_erased_var_name(name, &erased));
        let new_id = abstract_ta.locations.len();
        abstract_ta
            .locations
            .push(tarsier_ir::threshold_automaton::Location {
                name: format!("{}::{}::abs{new_id}", key.role, key.phase),
                role: key.role.clone(),
                phase: key.phase.clone(),
                local_vars,
            });
        loc_key_to_new.insert(key, new_id);
        loc_map[old_id] = new_id;
    }

    let mut initial_set: HashSet<usize> = HashSet::new();
    for old_init in &ta.initial_locations {
        if let Some(&mapped) = loc_map.get(*old_init) {
            initial_set.insert(mapped);
        }
    }
    let mut initial_locations: Vec<usize> = initial_set.into_iter().collect();
    initial_locations.sort_unstable();
    abstract_ta.initial_locations = initial_locations;

    abstract_ta.rules = ta
        .rules
        .iter()
        .map(|rule| tarsier_ir::threshold_automaton::Rule {
            from: loc_map[rule.from],
            to: loc_map[rule.to],
            guard: tarsier_ir::threshold_automaton::Guard {
                atoms: rule
                    .guard
                    .atoms
                    .iter()
                    .map(|atom| match atom {
                        GuardAtom::Threshold {
                            vars,
                            op,
                            bound,
                            distinct,
                        } => GuardAtom::Threshold {
                            vars: vars.iter().map(|v| shared_map[*v]).collect(),
                            op: *op,
                            bound: bound.clone(),
                            distinct: *distinct,
                        },
                    })
                    .collect(),
            },
            updates: rule
                .updates
                .iter()
                .map(|update| tarsier_ir::threshold_automaton::Update {
                    var: shared_map[update.var],
                    kind: update.kind.clone(),
                })
                .collect(),
        })
        .collect();

    let abstract_message_counters = abstract_ta
        .shared_vars
        .iter()
        .filter(|v| v.kind == SharedVarKind::MessageCounter)
        .count();
    let abstract_locations = abstract_ta.locations.len();
    let abstract_shared_vars = abstract_ta.shared_vars.len();

    let mut erased_vars: Vec<String> = erased.into_iter().collect();
    erased_vars.sort();

    (
        abstract_ta,
        RoundAbstractionSummary {
            erased_vars,
            original_locations: ta.locations.len(),
            abstract_locations,
            original_shared_vars: ta.shared_vars.len(),
            abstract_shared_vars,
            original_message_counters,
            abstract_message_counters,
        },
    )
}

/// Render a multiplicative symbolic bound from ordered factors.
pub(super) fn format_bound(parts: &[String]) -> String {
    if parts.is_empty() {
        return "0".into();
    }
    parts.join(" * ")
}

/// Render `multiplier * symbol` with simplifications for 0 and 1.
pub(super) fn format_scaled_term(symbol: &str, multiplier: usize) -> String {
    match multiplier {
        0 => "0".into(),
        1 => symbol.to_string(),
        _ => format_bound(&[symbol.to_string(), multiplier.to_string()]),
    }
}

/// Render an additive symbolic bound while dropping additive zero terms.
pub(super) fn format_sum_bounds(parts: &[String]) -> String {
    let kept: Vec<&String> = parts.iter().filter(|p| p.as_str() != "0").collect();
    if kept.is_empty() {
        "0".into()
    } else {
        kept.iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

/// Scale a per-step symbolic bound to a per-depth symbolic bound.
pub(super) fn scale_bound_by_depth(depth: usize, bound: &str) -> String {
    if bound == "0" {
        "0".into()
    } else if depth == 1 {
        bound.to_string()
    } else if bound.contains(" + ") {
        format!("{depth} * ({bound})")
    } else {
        format!("{depth} * {bound}")
    }
}

/// Add two symbolic bounds with zero-elision.
pub(super) fn add_bounds(lhs: &str, rhs: &str) -> String {
    if lhs == "0" {
        return rhs.to_string();
    }
    if rhs == "0" {
        return lhs.to_string();
    }
    format!("{lhs} + {rhs}")
}

/// Return minimal rounds `r` such that `1 - p_fail^r >= confidence`.
pub(super) fn geometric_rounds_for_confidence(p_fail: f64, confidence: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&p_fail) {
        return None;
    }
    if !(0.0..1.0).contains(&confidence) {
        return None;
    }
    if p_fail <= 0.0 {
        return Some(1);
    }
    if p_fail >= 1.0 {
        return None;
    }
    let rounds = ((1.0 - confidence).ln() / p_fail.ln()).ceil();
    if rounds.is_finite() && rounds >= 1.0 {
        Some(rounds as usize)
    } else {
        None
    }
}

/// Compute lowercase hex SHA-256 digest for arbitrary bytes.
pub(super) fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    format!("{:x}", hasher.finalize())
}

/// Build a deterministic fingerprint over source hash, options, environment, and engine version.
pub(super) fn quantitative_reproducibility_fingerprint(
    source_hash: &str,
    engine_version: &str,
    options: &QuantitativeAnalysisOptions,
    environment: &QuantitativeAnalysisEnvironment,
) -> Result<String, PipelineError> {
    let payload = serde_json::json!({
        "source_hash": source_hash,
        "engine_version": engine_version,
        "options": options,
        "environment": environment,
    });
    let serialized = serde_json::to_vec(&payload).map_err(|e| {
        PipelineError::Validation(format!(
            "failed to serialize reproducibility payload for quantitative report: {e}"
        ))
    })?;
    Ok(sha256_hex(serialized))
}

/// Linear-interpolated quantile over finite values.
pub(super) fn quantile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() || !(0.0..=1.0).contains(&q) {
        return None;
    }
    if values.len() == 1 {
        return Some(values[0]);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let pos = q * ((sorted.len() - 1) as f64);
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return Some(sorted[lo]);
    }
    let frac = pos - (lo as f64);
    Some(sorted[lo] * (1.0 - frac) + sorted[hi] * frac)
}

pub(super) fn push_prob_sample(
    probabilistic_metric_samples: &mut BTreeMap<String, Vec<f64>>,
    metric: &str,
    value: Option<f64>,
) {
    if let Some(v) = value.filter(|v| v.is_finite()) {
        probabilistic_metric_samples
            .entry(metric.to_string())
            .or_default()
            .push(v);
    }
}

pub(super) fn push_prob_sensitivity_point(
    sensitivity: &mut Vec<SensitivityPoint>,
    probabilistic_metric_samples: &mut BTreeMap<String, Vec<f64>>,
    metric: &str,
    base: Option<f64>,
    varied: Option<f64>,
    base_epsilon: f64,
    varied_epsilon: f64,
) {
    if let (Some(base_result), Some(varied_result)) = (base, varied) {
        sensitivity.push(SensitivityPoint {
            parameter: "epsilon".into(),
            base_value: base_epsilon,
            varied_value: varied_epsilon,
            metric: metric.into(),
            base_result,
            varied_result,
        });
        push_prob_sample(probabilistic_metric_samples, metric, Some(varied_result));
    }
}
/// Analyze committee selections and derive concrete adversary bounds.
///
/// For each committee spec, compute the worst-case Byzantine count b_max
/// such that P(Byzantine > b_max) <= epsilon. Returns summaries for reporting
/// and optionally injects concrete bounds into the threshold automaton.
pub(super) fn analyze_and_constrain_committees(
    ta: &mut ThresholdAutomaton,
) -> Result<Vec<CommitteeAnalysisSummary>, PipelineError> {
    let mut summaries = Vec::new();

    for committee in &ta.committees.clone() {
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
    if ta.adversary_bound_param.is_none() {
        let mut candidate_params: HashSet<usize> = HashSet::new();
        for c in &ta.committees {
            if let Some(pid) = c.bound_param {
                candidate_params.insert(pid);
            }
        }
        if candidate_params.len() == 1 {
            let pid = *candidate_params.iter().next().expect("len() checked");
            ta.adversary_bound_param = Some(pid);
            info!(
                param = %ta.parameters[pid].name,
                "Using committee-derived adversary bound parameter"
            );
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

pub(super) fn ensure_n_parameter(ta: &ThresholdAutomaton) -> Result<(), PipelineError> {
    if ta.find_param_by_name("n").is_none() {
        return Err(PipelineError::Property(
            "Protocol must declare parameter `n` (process population size).".into(),
        ));
    }
    Ok(())
}

pub fn show_ta(source: &str, filename: &str) -> Result<String, PipelineError> {
    reset_run_diagnostics();
    let program = parse(source, filename)?;
    let ta = lower_with_active_controls(&program, "show_ta")?;
    Ok(format!("{ta}"))
}

/// Analyze communication complexity (coarse upper bounds).
pub fn comm_complexity(
    source: &str,
    filename: &str,
    depth: usize,
) -> Result<CommComplexityReport, PipelineError> {
    reset_run_diagnostics();
    let program = parse(source, filename)?;
    let mut ta = lower_with_active_controls(&program, "comm_complexity")?;
    ensure_n_parameter(&ta)?;

    let committee_summaries = analyze_and_constrain_committees(&mut ta)?;
    let raw_total_finality_failure: Option<f64> = if committee_summaries.is_empty() {
        None
    } else {
        Some(committee_summaries.iter().map(|c| c.epsilon).sum())
    };
    let reject_probabilistic_extrapolation_async_no_gst = raw_total_finality_failure.is_some()
        && ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::Asynchronous
        && ta.gst_param.is_none();
    let total_finality_failure = if reject_probabilistic_extrapolation_async_no_gst {
        None
    } else {
        raw_total_finality_failure.map(|p| p.clamp(0.0, 1.0))
    };
    let finality_success_probability_lower =
        total_finality_failure.map(|p_fail| (1.0 - p_fail).clamp(0.0, 1.0));
    let expected_rounds_to_finality = total_finality_failure.and_then(|p_fail| {
        if p_fail < 1.0 {
            Some(1.0 / (1.0 - p_fail))
        } else {
            None
        }
    });
    let rounds_for_90pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.90));
    let rounds_for_95pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.95));
    let rounds_for_99pct_finality =
        total_finality_failure.and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.99));

    let n_param = ta
        .find_param_by_name("n")
        .map(|id| ta.parameters[id].name.clone());
    let n_label = n_param.clone().unwrap_or_else(|| "n".into());
    let adv_param = ta
        .adversary_bound_param
        .map(|id| ta.parameters[id].name.clone());
    let min_decision_steps = {
        let decision_locs: Vec<usize> = ta
            .locations
            .iter()
            .enumerate()
            .filter_map(|(loc_id, loc)| match loc.local_vars.get("decided") {
                Some(LocalValue::Bool(true)) => Some(loc_id),
                _ => None,
            })
            .collect();
        if decision_locs.is_empty() || ta.initial_locations.is_empty() {
            None
        } else {
            let mut dist = vec![usize::MAX; ta.locations.len()];
            let mut queue = VecDeque::new();
            for &start in &ta.initial_locations {
                if start < dist.len() && dist[start] == usize::MAX {
                    dist[start] = 0;
                    queue.push_back(start);
                }
            }

            while let Some(current) = queue.pop_front() {
                let next_dist = dist[current].saturating_add(1);
                for rule in &ta.rules {
                    if rule.from != current {
                        continue;
                    }
                    if dist[rule.to] == usize::MAX {
                        dist[rule.to] = next_dist;
                        queue.push_back(rule.to);
                    }
                }
            }

            decision_locs
                .into_iter()
                .filter_map(|id| {
                    let d = dist[id];
                    (d != usize::MAX).then_some(d)
                })
                .min()
        }
    };

    let mut max_sends_per_rule = 0usize;
    let mut max_by_type: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut max_by_role: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut max_by_role_and_type: std::collections::HashMap<
        String,
        std::collections::HashMap<String, usize>,
    > = std::collections::HashMap::new();

    for rule in &ta.rules {
        let mut total = 0usize;
        let mut per_type: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for upd in &rule.updates {
            if ta.shared_vars[upd.var].kind != SharedVarKind::MessageCounter {
                continue;
            }
            if !matches!(
                upd.kind,
                tarsier_ir::threshold_automaton::UpdateKind::Increment
            ) {
                continue;
            }
            total += 1;
            if let Some(base) = base_message_name(&ta.shared_vars[upd.var].name) {
                *per_type.entry(base).or_insert(0) += 1;
            }
        }
        if total > max_sends_per_rule {
            max_sends_per_rule = total;
        }
        for (msg, count) in &per_type {
            let entry = max_by_type.entry(msg.clone()).or_insert(0);
            if *count > *entry {
                *entry = *count;
            }
        }

        let sender_role = ta.locations[rule.from].role.clone();
        let role_entry = max_by_role.entry(sender_role.clone()).or_insert(0);
        if total > *role_entry {
            *role_entry = total;
        }
        let role_types = max_by_role_and_type.entry(sender_role).or_default();
        for (msg, count) in per_type {
            let entry = role_types.entry(msg).or_insert(0);
            if count > *entry {
                *entry = count;
            }
        }
    }

    let mut sender_roles: Vec<String> = max_by_role.keys().cloned().collect();
    sender_roles.sort();
    let single_role_model = ta
        .locations
        .iter()
        .map(|loc| loc.role.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
        == 1;
    let mut role_population_labels: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for role in &sender_roles {
        let role_param = format!("n_{}", role.to_lowercase());
        if let Some(pid) = ta.find_param_by_name(&role_param) {
            role_population_labels.insert(role.clone(), ta.parameters[pid].name.clone());
        } else if single_role_model {
            role_population_labels.insert(role.clone(), n_label.clone());
        }
    }
    let use_role_population_bounds = !sender_roles.is_empty()
        && sender_roles
            .iter()
            .all(|role| role_population_labels.contains_key(role));

    let per_step_bound = if use_role_population_bounds {
        let mut terms = Vec::new();
        for role in &sender_roles {
            let Some(pop) = role_population_labels.get(role) else {
                continue;
            };
            let max_count = *max_by_role.get(role).unwrap_or(&0);
            terms.push(format_scaled_term(pop, max_count));
        }
        format_sum_bounds(&terms)
    } else if max_sends_per_rule == 0 {
        "0".into()
    } else {
        format_bound(&[n_label.clone(), max_sends_per_rule.to_string()])
    };
    let per_depth_bound = scale_bound_by_depth(depth, &per_step_bound);

    let mut max_sends_per_rule_by_type: Vec<(String, usize)> = max_by_type.into_iter().collect();
    max_sends_per_rule_by_type.sort_by(|a, b| a.0.cmp(&b.0));

    let mut per_step_type_bounds = Vec::new();
    let mut per_depth_type_bounds = Vec::new();
    let mut per_step_type_big_o = Vec::new();
    let mut per_depth_type_big_o = Vec::new();
    for (msg, count) in &max_sends_per_rule_by_type {
        let step_bound = if use_role_population_bounds {
            let mut terms = Vec::new();
            for role in &sender_roles {
                let Some(pop) = role_population_labels.get(role) else {
                    continue;
                };
                let role_count = max_by_role_and_type
                    .get(role)
                    .and_then(|m| m.get(msg))
                    .copied()
                    .unwrap_or(0);
                terms.push(format_scaled_term(pop, role_count));
            }
            format_sum_bounds(&terms)
        } else if *count == 0 {
            "0".into()
        } else {
            format_bound(&[n_label.clone(), count.to_string()])
        };
        let depth_bound = scale_bound_by_depth(depth, &step_bound);
        per_step_type_bounds.push((msg.clone(), step_bound));
        per_depth_type_bounds.push((msg.clone(), depth_bound));
        let step_big_o = if *count == 0 {
            "O(1)".into()
        } else if n_param.is_some() {
            "O(n)".into()
        } else {
            "O(1)".into()
        };
        let depth_big_o = if *count == 0 {
            "O(1)".into()
        } else if n_param.is_some() {
            "O(k * n)".into()
        } else {
            "O(k)".into()
        };
        per_step_type_big_o.push((msg.clone(), step_big_o));
        per_depth_type_big_o.push((msg.clone(), depth_big_o));
    }

    let mut family_counter_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut family_recipients: std::collections::HashMap<
        String,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for shared in &ta.shared_vars {
        if shared.kind != SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient)) =
            message_family_and_recipient_from_counter_name(&shared.name)
        else {
            continue;
        };
        *family_counter_counts.entry(family.clone()).or_insert(0) += 1;
        family_recipients
            .entry(family)
            .or_default()
            .insert(recipient.unwrap_or_else(|| "*".into()));
    }
    let mut family_recipient_group_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (family, recipients) in &family_recipients {
        family_recipient_group_counts.insert(family.clone(), recipients.len());
    }
    let total_message_counters = family_counter_counts.values().sum::<usize>();
    let total_family_recipient_groups = family_recipient_group_counts.values().sum::<usize>();

    let byzantine_faults = ta.fault_model == FaultModel::Byzantine;
    let signed_or_no_equiv = ta.authentication_mode == AuthenticationMode::Signed
        || ta.equivocation_mode == EquivocationMode::None;

    let adversary_multiplier_total = if byzantine_faults {
        if signed_or_no_equiv {
            total_family_recipient_groups
        } else {
            total_message_counters
        }
    } else {
        0
    };

    let adversary_per_step_bound = adv_param
        .as_ref()
        .map(|adv| format_scaled_term(adv, adversary_multiplier_total));
    let adversary_per_depth_bound = adversary_per_step_bound
        .as_ref()
        .map(|step| scale_bound_by_depth(depth, step));

    let mut family_names: Vec<String> = family_counter_counts.keys().cloned().collect();
    family_names.sort();
    let mut adversary_per_step_type_bounds = Vec::new();
    let mut adversary_per_depth_type_bounds = Vec::new();
    if let Some(adv) = adv_param.as_ref() {
        for family in &family_names {
            let multiplier = if byzantine_faults {
                if signed_or_no_equiv {
                    *family_recipient_group_counts.get(family).unwrap_or(&0)
                } else {
                    *family_counter_counts.get(family).unwrap_or(&0)
                }
            } else {
                0
            };
            let step = format_scaled_term(adv, multiplier);
            let depth_bound = scale_bound_by_depth(depth, &step);
            adversary_per_step_type_bounds.push((family.clone(), step));
            adversary_per_depth_type_bounds.push((family.clone(), depth_bound));
        }
    }

    let per_step_bound_with_adv = adv_param.as_ref().map(|_| {
        let adv_step = adversary_per_step_bound.as_deref().unwrap_or("0");
        add_bounds(&per_step_bound, adv_step)
    });
    let per_depth_bound_with_adv = per_step_bound_with_adv
        .as_ref()
        .map(|step| scale_bound_by_depth(depth, step));

    let mut protocol_step_by_type: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (msg, bound) in &per_step_type_bounds {
        protocol_step_by_type.insert(msg.clone(), bound.clone());
    }
    let mut adv_step_by_type: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (msg, bound) in &adversary_per_step_type_bounds {
        adv_step_by_type.insert(msg.clone(), bound.clone());
    }
    let mut all_type_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    all_type_names.extend(protocol_step_by_type.keys().cloned());
    all_type_names.extend(adv_step_by_type.keys().cloned());

    let mut per_step_type_bounds_with_adv = Vec::new();
    let mut per_depth_type_bounds_with_adv = Vec::new();
    for msg in all_type_names {
        let protocol = protocol_step_by_type
            .get(&msg)
            .map(String::as_str)
            .unwrap_or("0");
        let adv = adv_step_by_type
            .get(&msg)
            .map(String::as_str)
            .unwrap_or("0");
        let combined = add_bounds(protocol, adv);
        let depth_combined = scale_bound_by_depth(depth, &combined);
        per_step_type_bounds_with_adv.push((msg.clone(), combined));
        per_depth_type_bounds_with_adv.push((msg, depth_combined));
    }

    let per_step_bound_big_o = if max_sends_per_rule == 0 {
        "O(1)".into()
    } else if n_param.is_some() {
        "O(n)".into()
    } else {
        "O(1)".into()
    };
    let per_depth_bound_big_o = if max_sends_per_rule == 0 {
        "O(1)".into()
    } else if n_param.is_some() {
        "O(k * n)".into()
    } else {
        "O(k)".into()
    };

    let expected_total_messages_upper =
        expected_rounds_to_finality.map(|rounds| format!("{rounds:.3} * ({per_step_bound})"));
    let messages_for_90pct_finality_upper =
        rounds_for_90pct_finality.map(|rounds| format!("{rounds} * ({per_step_bound})"));
    let messages_for_99pct_finality_upper =
        rounds_for_99pct_finality.map(|rounds| format!("{rounds} * ({per_step_bound})"));
    let expected_total_messages_with_adv_upper = expected_rounds_to_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds:.3} * ({bound})"))
    });
    let messages_for_90pct_finality_with_adv_upper = rounds_for_90pct_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds} * ({bound})"))
    });
    let messages_for_99pct_finality_with_adv_upper = rounds_for_99pct_finality.and_then(|rounds| {
        per_step_bound_with_adv
            .as_ref()
            .map(|bound| format!("{rounds} * ({bound})"))
    });

    // --- Per-role bounds (item 1) ---
    let mut per_role_step_bounds = Vec::new();
    let mut per_role_depth_bounds = Vec::new();
    for role in &sender_roles {
        let max_count = *max_by_role.get(role).unwrap_or(&0);
        let pop = role_population_labels
            .get(role)
            .cloned()
            .unwrap_or_else(|| n_label.clone());
        let step = format_scaled_term(&pop, max_count);
        let depth_bound = scale_bound_by_depth(depth, &step);
        per_role_step_bounds.push((role.clone(), step));
        per_role_depth_bounds.push((role.clone(), depth_bound));
    }

    // --- Per-phase bounds (item 1) ---
    let mut max_by_phase: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for rule in &ta.rules {
        let phase = ta.locations[rule.from].phase.clone();
        let mut total = 0usize;
        for upd in &rule.updates {
            if ta.shared_vars[upd.var].kind != SharedVarKind::MessageCounter {
                continue;
            }
            if !matches!(
                upd.kind,
                tarsier_ir::threshold_automaton::UpdateKind::Increment
            ) {
                continue;
            }
            total += 1;
        }
        let entry = max_by_phase.entry(phase).or_insert(0);
        if total > *entry {
            *entry = total;
        }
    }
    let mut phase_names: Vec<String> = max_by_phase.keys().cloned().collect();
    phase_names.sort();
    let mut per_phase_step_bounds = Vec::new();
    let mut per_phase_depth_bounds = Vec::new();
    for phase in &phase_names {
        let max_count = *max_by_phase.get(phase).unwrap_or(&0);
        let step = format_scaled_term(&n_label, max_count);
        let depth_bound = scale_bound_by_depth(depth, &step);
        per_phase_step_bounds.push((phase.clone(), step));
        per_phase_depth_bounds.push((phase.clone(), depth_bound));
    }

    // --- Model assumptions (item 2) ---
    let model_assumptions = ModelAssumptions {
        fault_model: format!("{:?}", ta.fault_model),
        timing_model: format!("{:?}", ta.timing_model),
        authentication_mode: format!("{:?}", ta.authentication_mode),
        equivocation_mode: format!("{:?}", ta.equivocation_mode),
        network_semantics: format!("{:?}", ta.network_semantics),
        gst_param: ta.gst_param.map(|id| ta.parameters[id].name.clone()),
    };

    // --- Model metadata (item 7) ---
    let source_hash = sha256_hex(source.as_bytes());
    let engine_version = env!("CARGO_PKG_VERSION").to_string();
    let analysis_options = QuantitativeAnalysisOptions {
        command: "comm".to_string(),
        depth,
    };
    let analysis_environment = QuantitativeAnalysisEnvironment {
        target_os: std::env::consts::OS.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_family: std::env::consts::FAMILY.to_string(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
    };
    let reproducibility_fingerprint = quantitative_reproducibility_fingerprint(
        &source_hash,
        &engine_version,
        &analysis_options,
        &analysis_environment,
    )?;
    let model_metadata = ModelMetadata {
        source_hash,
        filename: filename.to_string(),
        analysis_depth: depth,
        engine_version,
        analysis_options,
        analysis_environment,
        reproducibility_fingerprint,
    };

    // --- Assumption notes (item 8) ---
    let mut assumption_notes = Vec::new();
    if ta.timing_model == tarsier_ir::threshold_automaton::TimingModel::Asynchronous
        && ta.gst_param.is_none()
    {
        if reject_probabilistic_extrapolation_async_no_gst {
            assumption_notes.push(AssumptionNote {
                level: "error".into(),
                message: "Rejected unsupported probabilistic/finality extrapolation: \
                          committee-derived finality metrics require eventual delivery \
                          (partial synchrony + GST). Metrics set to null."
                    .into(),
            });
        } else {
            assumption_notes.push(AssumptionNote {
                level: "warning".into(),
                message: "Finality metrics assume eventual delivery; under pure asynchrony \
                          without GST, no finality guarantee is possible."
                    .into(),
            });
        }
    }
    if let Some(raw_failure) = raw_total_finality_failure {
        if raw_failure > 1.0 {
            assumption_notes.push(AssumptionNote {
                level: "note".into(),
                message: format!(
                    "Finality failure union-bound sum ({raw_failure:.3}) exceeded 1.0; \
                     capped to 1.0 for probability semantics."
                ),
            });
        }
    }
    if total_finality_failure.is_none() && min_decision_steps.is_some() {
        assumption_notes.push(AssumptionNote {
            level: "note".into(),
            message: "No committee selection found; finality round estimates are unavailable. \
                      Latency lower bound is based on BFS graph distance only."
                .into(),
        });
    }
    if ta.fault_model == FaultModel::Crash {
        assumption_notes.push(AssumptionNote {
            level: "note".into(),
            message: "Crash fault model: adversary injection bounds are zero \
                      (crash faults cannot inject messages)."
                .into(),
        });
    }

    // --- Sensitivity analysis (item 3) ---
    let mut sensitivity = Vec::new();
    let mut probabilistic_metric_samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();

    let base_fail = total_finality_failure;
    let base_success = finality_success_probability_lower;
    let base_expected_rounds = expected_rounds_to_finality;
    let base_rounds_90 = rounds_for_90pct_finality.map(|v| v as f64);
    let base_rounds_95 = rounds_for_95pct_finality.map(|v| v as f64);
    let base_rounds_99 = rounds_for_99pct_finality.map(|v| v as f64);
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "finality_failure_probability_upper",
        base_fail,
    );
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "finality_success_probability_lower",
        base_success,
    );
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "expected_rounds_to_finality",
        base_expected_rounds,
    );
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "rounds_for_90pct_finality",
        base_rounds_90,
    );
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "rounds_for_95pct_finality",
        base_rounds_95,
    );
    push_prob_sample(
        &mut probabilistic_metric_samples,
        "rounds_for_99pct_finality",
        base_rounds_99,
    );

    for cs in &committee_summaries {
        let base_epsilon = cs.epsilon;
        let base_b_max = cs.b_max;
        // Vary epsilon by factors of 10
        for factor in [10.0_f64, 100.0, 0.1, 0.01] {
            let varied_epsilon = base_epsilon * factor;
            if varied_epsilon <= 0.0 || varied_epsilon >= 1.0 {
                continue;
            }
            let spec = CommitteeSpec {
                name: cs.name.clone(),
                population: cs.population,
                byzantine: cs.byzantine,
                committee_size: cs.committee_size,
                epsilon: varied_epsilon,
            };
            if let Ok(analysis) = tarsier_prob::committee::analyze_committee(&spec) {
                sensitivity.push(SensitivityPoint {
                    parameter: "epsilon".into(),
                    base_value: base_epsilon,
                    varied_value: varied_epsilon,
                    metric: format!("b_max({})", cs.name),
                    base_result: base_b_max as f64,
                    varied_result: analysis.b_max as f64,
                });

                let varied_fail = total_finality_failure
                    .map(|base| (base - base_epsilon + varied_epsilon).clamp(0.0, 1.0));
                let varied_success = varied_fail.map(|p_fail| (1.0 - p_fail).clamp(0.0, 1.0));
                let varied_expected_rounds = varied_success.and_then(|p_success| {
                    if p_success > 0.0 {
                        Some(1.0 / p_success)
                    } else {
                        None
                    }
                });
                let varied_rounds_90 = varied_fail
                    .and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.90))
                    .map(|v| v as f64);
                let varied_rounds_95 = varied_fail
                    .and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.95))
                    .map(|v| v as f64);
                let varied_rounds_99 = varied_fail
                    .and_then(|p_fail| geometric_rounds_for_confidence(p_fail, 0.99))
                    .map(|v| v as f64);

                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "finality_failure_probability_upper",
                    base_fail,
                    varied_fail,
                    base_epsilon,
                    varied_epsilon,
                );
                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "finality_success_probability_lower",
                    base_success,
                    varied_success,
                    base_epsilon,
                    varied_epsilon,
                );
                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "expected_rounds_to_finality",
                    base_expected_rounds,
                    varied_expected_rounds,
                    base_epsilon,
                    varied_epsilon,
                );
                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "rounds_for_90pct_finality",
                    base_rounds_90,
                    varied_rounds_90,
                    base_epsilon,
                    varied_epsilon,
                );
                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "rounds_for_95pct_finality",
                    base_rounds_95,
                    varied_rounds_95,
                    base_epsilon,
                    varied_epsilon,
                );
                push_prob_sensitivity_point(
                    &mut sensitivity,
                    &mut probabilistic_metric_samples,
                    "rounds_for_99pct_finality",
                    base_rounds_99,
                    varied_rounds_99,
                    base_epsilon,
                    varied_epsilon,
                );
            }
        }
    }

    let mut probabilistic_confidence_intervals = Vec::new();
    let interval_method = "epsilon_sensitivity_quantile_band";
    for (metric, samples) in &probabilistic_metric_samples {
        if samples.len() < 2 {
            continue;
        }
        for level in [0.90_f64, 0.95_f64] {
            let alpha = 1.0 - level;
            let lower_q = alpha / 2.0;
            let upper_q = 1.0 - alpha / 2.0;
            let (Some(lower), Some(upper)) =
                (quantile(samples, lower_q), quantile(samples, upper_q))
            else {
                continue;
            };
            probabilistic_confidence_intervals.push(ProbabilisticConfidenceInterval {
                metric: metric.clone(),
                level,
                lower,
                upper,
                sample_size: samples.len(),
                method: interval_method.into(),
                assumptions: vec![
                    "derived from deterministic epsilon perturbation sweep per committee".into(),
                    "perturbation factors: [0.01, 0.1, 1, 10, 100] around declared epsilon".into(),
                    "intervals represent model-parameter sensitivity bands, not statistical sampling error".into(),
                    "probabilistic metrics rely on geometric IID approximation across rounds".into(),
                ],
            });
        }
    }

    // --- Bound annotations (item 4) ---
    let mut base_metric_assumptions = vec![
        format!("fault_model={}", model_assumptions.fault_model),
        format!("timing_model={}", model_assumptions.timing_model),
        format!(
            "authentication_mode={}",
            model_assumptions.authentication_mode
        ),
        format!("equivocation_mode={}", model_assumptions.equivocation_mode),
        format!("network_semantics={}", model_assumptions.network_semantics),
        format!("analysis_depth={depth}"),
        "message accounting uses lowered message-counter increments".into(),
    ];
    if let Some(gst) = model_assumptions.gst_param.as_deref() {
        base_metric_assumptions.push(format!("gst_param={gst}"));
    } else {
        base_metric_assumptions.push("gst_param=none".into());
    }

    let annotate =
        |field: &str, kind: BoundKind, description: &str, extra: &[&str]| -> BoundAnnotation {
            let mut assumptions = base_metric_assumptions.clone();
            assumptions.extend(extra.iter().map(|s| (*s).to_string()));
            let evidence_class = match kind {
                BoundKind::Estimate => BoundEvidenceClass::HeuristicEstimate,
                BoundKind::UpperBound | BoundKind::LowerBound | BoundKind::Exact => {
                    BoundEvidenceClass::TheoremBacked
                }
            };
            BoundAnnotation {
                field: field.into(),
                kind,
                evidence_class,
                description: description.into(),
                assumptions,
            }
        };

    let bound_annotations = vec![
        annotate(
            "min_decision_steps",
            BoundKind::LowerBound,
            "BFS shortest path from initial to decided location",
            &[
                "latency metric is structural and does not include scheduling delays",
                "requires a reachable decided=true location in the lowered automaton",
            ],
        ),
        annotate(
            "finality_failure_probability_upper",
            BoundKind::UpperBound,
            "Union bound over committee tail probabilities",
            &[
                "committee declarations are present and interpreted via hypergeometric tails",
                "assumes independent per-committee failure aggregation via union bound",
            ],
        ),
        annotate(
            "finality_success_probability_lower",
            BoundKind::LowerBound,
            "1 - finality_failure_probability_upper",
            &[
                "derived directly from finality_failure_probability_upper",
                "committee declarations are required for non-null values",
            ],
        ),
        annotate(
            "expected_rounds_to_finality",
            BoundKind::Estimate,
            "Geometric distribution mean (1/p_success); assumes IID rounds",
            &[
                "uses geometric approximation over per-round success probability",
                "committee selection and success probability assumed stationary across rounds",
            ],
        ),
        annotate(
            "rounds_for_90pct_finality",
            BoundKind::UpperBound,
            "Geometric distribution quantile for 90% confidence",
            &[
                "uses lower-bounded success probability under geometric IID approximation",
                "interpreted as confidence-round upper bound under the model assumptions",
            ],
        ),
        annotate(
            "rounds_for_95pct_finality",
            BoundKind::UpperBound,
            "Geometric distribution quantile for 95% confidence",
            &[
                "uses lower-bounded success probability under geometric IID approximation",
                "interpreted as confidence-round upper bound under the model assumptions",
            ],
        ),
        annotate(
            "rounds_for_99pct_finality",
            BoundKind::UpperBound,
            "Geometric distribution quantile for 99% confidence",
            &[
                "uses lower-bounded success probability under geometric IID approximation",
                "interpreted as confidence-round upper bound under the model assumptions",
            ],
        ),
        annotate(
            "max_sends_per_rule",
            BoundKind::Exact,
            "Exact maximum number of protocol send increments in any single rule",
            &["computed syntactically from lowered rule updates"],
        ),
        annotate(
            "max_sends_per_rule_by_type",
            BoundKind::Exact,
            "Exact maximum protocol send increments per message type in any single rule",
            &["computed syntactically from lowered rule updates grouped by message family"],
        ),
        annotate(
            "per_step_bound",
            BoundKind::UpperBound,
            "Maximum honest protocol messages per step",
            &["population parameters represent active sender populations"],
        ),
        annotate(
            "per_depth_bound",
            BoundKind::UpperBound,
            "Maximum honest protocol messages over all analyzed steps",
            &["computed as depth-scaled per_step_bound"],
        ),
        annotate(
            "adversary_per_step_bound",
            BoundKind::UpperBound,
            "Maximum adversary message injection per step",
            &[
                "depends on adversary bound parameter and authentication/equivocation mode",
                "zero for non-Byzantine models",
            ],
        ),
        annotate(
            "adversary_per_depth_bound",
            BoundKind::UpperBound,
            "Maximum adversary message injection over analyzed depth",
            &["computed as depth-scaled adversary_per_step_bound"],
        ),
        annotate(
            "per_step_bound_with_adv",
            BoundKind::UpperBound,
            "Maximum total messages per step including adversary injection",
            &["sum of protocol per_step_bound and adversary_per_step_bound"],
        ),
        annotate(
            "per_depth_bound_with_adv",
            BoundKind::UpperBound,
            "Maximum total messages over analyzed depth including adversary injection",
            &["depth-scaled per_step_bound_with_adv"],
        ),
        annotate(
            "per_step_bound_big_o",
            BoundKind::UpperBound,
            "Asymptotic per-step message complexity class",
            &["derived from symbolic upper-bound shape over population parameters"],
        ),
        annotate(
            "per_depth_bound_big_o",
            BoundKind::UpperBound,
            "Asymptotic per-depth message complexity class",
            &["derived from symbolic upper-bound shape over depth and population parameters"],
        ),
        annotate(
            "per_step_type_bounds",
            BoundKind::UpperBound,
            "Per-step protocol message upper bounds by message type",
            &["computed from per-type max send increments"],
        ),
        annotate(
            "per_depth_type_bounds",
            BoundKind::UpperBound,
            "Per-depth protocol message upper bounds by message type",
            &["depth-scaled per_step_type_bounds"],
        ),
        annotate(
            "adversary_per_step_type_bounds",
            BoundKind::UpperBound,
            "Per-step adversary injection upper bounds by message type",
            &["depends on fault model and authentication/equivocation restrictions"],
        ),
        annotate(
            "adversary_per_depth_type_bounds",
            BoundKind::UpperBound,
            "Per-depth adversary injection upper bounds by message type",
            &["depth-scaled adversary_per_step_type_bounds"],
        ),
        annotate(
            "per_step_type_bounds_with_adv",
            BoundKind::UpperBound,
            "Per-step total message upper bounds by type including adversary injection",
            &["sum of per_step_type_bounds and adversary_per_step_type_bounds"],
        ),
        annotate(
            "per_depth_type_bounds_with_adv",
            BoundKind::UpperBound,
            "Per-depth total message upper bounds by type including adversary injection",
            &["depth-scaled per_step_type_bounds_with_adv"],
        ),
        annotate(
            "per_step_type_big_o",
            BoundKind::UpperBound,
            "Asymptotic per-step message complexity class by type",
            &["derived from per-type symbolic upper-bound shape"],
        ),
        annotate(
            "per_depth_type_big_o",
            BoundKind::UpperBound,
            "Asymptotic per-depth message complexity class by type",
            &["derived from per-type symbolic upper-bound shape over depth"],
        ),
        annotate(
            "per_role_step_bounds",
            BoundKind::UpperBound,
            "Per-step protocol message upper bounds by sender role",
            &["role population parameters are used when available (n_<role>)"],
        ),
        annotate(
            "per_role_depth_bounds",
            BoundKind::UpperBound,
            "Per-depth protocol message upper bounds by sender role",
            &["depth-scaled per_role_step_bounds"],
        ),
        annotate(
            "per_phase_step_bounds",
            BoundKind::UpperBound,
            "Per-step protocol message upper bounds by phase",
            &["phase grouping uses source phase of lowered transition rules"],
        ),
        annotate(
            "per_phase_depth_bounds",
            BoundKind::UpperBound,
            "Per-depth protocol message upper bounds by phase",
            &["depth-scaled per_phase_step_bounds"],
        ),
        annotate(
            "expected_total_messages_upper",
            BoundKind::Estimate,
            "Estimated expected total messages to finality upper expression",
            &[
                "combines expected_rounds_to_finality estimate with per_step_bound upper bound",
                "requires committee-derived success probability estimate",
            ],
        ),
        annotate(
            "messages_for_90pct_finality_upper",
            BoundKind::UpperBound,
            "Upper expression for messages needed to reach >=90% finality confidence",
            &["combines rounds_for_90pct_finality upper bound with per_step_bound upper bound"],
        ),
        annotate(
            "messages_for_99pct_finality_upper",
            BoundKind::UpperBound,
            "Upper expression for messages needed to reach >=99% finality confidence",
            &["combines rounds_for_99pct_finality upper bound with per_step_bound upper bound"],
        ),
        annotate(
            "expected_total_messages_with_adv_upper",
            BoundKind::Estimate,
            "Estimated expected total messages to finality upper expression including adversary",
            &[
                "combines expected_rounds_to_finality estimate with per_step_bound_with_adv upper bound",
                "requires adversary model with bounded injection parameter",
            ],
        ),
        annotate(
            "messages_for_90pct_finality_with_adv_upper",
            BoundKind::UpperBound,
            "Upper expression for >=90% finality-confidence messages including adversary",
            &[
                "combines rounds_for_90pct_finality with per_step_bound_with_adv upper bound",
            ],
        ),
        annotate(
            "messages_for_99pct_finality_with_adv_upper",
            BoundKind::UpperBound,
            "Upper expression for >=99% finality-confidence messages including adversary",
            &[
                "combines rounds_for_99pct_finality with per_step_bound_with_adv upper bound",
            ],
        ),
    ];

    Ok(CommComplexityReport {
        schema_version: QUANTITATIVE_SCHEMA_VERSION,
        model_metadata,
        model_assumptions,
        assumption_notes,
        bound_annotations,
        depth,
        n_param,
        adv_param,
        min_decision_steps,
        finality_failure_probability_upper: total_finality_failure,
        finality_success_probability_lower,
        expected_rounds_to_finality,
        rounds_for_90pct_finality,
        rounds_for_95pct_finality,
        rounds_for_99pct_finality,
        expected_total_messages_upper,
        messages_for_90pct_finality_upper,
        messages_for_99pct_finality_upper,
        expected_total_messages_with_adv_upper,
        messages_for_90pct_finality_with_adv_upper,
        messages_for_99pct_finality_with_adv_upper,
        max_sends_per_rule,
        max_sends_per_rule_by_type,
        adversary_per_step_bound,
        adversary_per_depth_bound,
        per_step_bound,
        per_depth_bound,
        per_step_bound_with_adv,
        per_depth_bound_with_adv,
        per_step_bound_big_o,
        per_depth_bound_big_o,
        per_step_type_bounds,
        per_depth_type_bounds,
        adversary_per_step_type_bounds,
        adversary_per_depth_type_bounds,
        per_step_type_bounds_with_adv,
        per_depth_type_bounds_with_adv,
        per_step_type_big_o,
        per_depth_type_big_o,
        per_role_step_bounds,
        per_role_depth_bounds,
        per_phase_step_bounds,
        per_phase_depth_bounds,
        sensitivity,
        probabilistic_confidence_intervals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tarsier_ir::threshold_automaton::{
        CmpOp, Guard, IrCommitteeSpec, LinearCombination, Location, Parameter, Rule, SharedVar,
        Update, UpdateKind,
    };

    fn mk_location(name: &str, round: i64, flag: bool) -> Location {
        let mut loc = Location {
            name: name.to_string(),
            role: "R".to_string(),
            phase: "p".to_string(),
            local_vars: Default::default(),
        };
        loc.local_vars
            .insert("round".to_string(), LocalValue::Int(round));
        loc.local_vars
            .insert("flag".to_string(), LocalValue::Bool(flag));
        loc
    }

    fn mk_erasure_ta() -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        ta.parameters.push(Parameter {
            name: "n".to_string(),
        });
        ta.locations.push(mk_location("l0", 1, false));
        ta.locations.push(mk_location("l1", 2, false));
        ta.locations.push(mk_location("l2", 2, true));
        ta.initial_locations = vec![0, 1];
        ta.shared_vars.push(SharedVar {
            name: "cnt_Vote@R[round=1,value=true]".to_string(),
            kind: SharedVarKind::MessageCounter,
            distinct: true,
            distinct_role: Some("R".to_string()),
        });
        ta.shared_vars.push(SharedVar {
            name: "cnt_Vote@R[round=2,value=true]".to_string(),
            kind: SharedVarKind::MessageCounter,
            distinct: true,
            distinct_role: Some("S".to_string()),
        });
        ta.shared_vars.push(SharedVar {
            name: "decided".to_string(),
            kind: SharedVarKind::Shared,
            distinct: false,
            distinct_role: None,
        });
        ta.rules.push(Rule {
            from: 0,
            to: 2,
            guard: Guard {
                atoms: vec![GuardAtom::Threshold {
                    vars: vec![0, 1],
                    op: CmpOp::Ge,
                    bound: LinearCombination::constant(1),
                    distinct: false,
                }],
            },
            updates: vec![
                Update {
                    var: 0,
                    kind: UpdateKind::Increment,
                },
                Update {
                    var: 1,
                    kind: UpdateKind::Increment,
                },
                Update {
                    var: 2,
                    kind: UpdateKind::Increment,
                },
            ],
        });
        ta
    }

    #[test]
    fn base_message_name_parses_counter_family_and_rejects_non_counters() {
        assert_eq!(
            base_message_name("cnt_Vote@Replica#1<-Replica#0[view=2,value=true]"),
            Some("Vote".to_string())
        );
        assert_eq!(
            base_message_name("cnt_Prepare[round=3]"),
            Some("Prepare".to_string())
        );
        assert_eq!(base_message_name("decided"), None);
    }

    #[test]
    fn message_family_and_recipient_parser_handles_sender_suffix_and_missing_recipient() {
        assert_eq!(
            message_family_and_recipient_from_counter_name(
                "cnt_Vote@Replica#1<-Replica#0[view=2,value=true]"
            ),
            Some(("Vote".to_string(), Some("Replica#1".to_string())))
        );
        assert_eq!(
            message_family_and_recipient_from_counter_name("cnt_Vote@Replica#1[view=2]"),
            Some(("Vote".to_string(), Some("Replica#1".to_string())))
        );
        assert_eq!(
            message_family_and_recipient_from_counter_name("cnt_Vote[view=2]"),
            Some(("Vote".to_string(), None))
        );
    }

    #[test]
    fn erased_name_normalization_and_lookup_are_case_insensitive() {
        let normalized =
            normalize_erased_var_names(&[" round ".to_string(), "View".to_string(), "".into()]);
        assert!(normalized.contains("round"));
        assert!(normalized.contains("view"));
        assert!(is_erased_var_name("ROUND", &normalized));
        assert!(is_erased_var_name("view", &normalized));
        assert!(!is_erased_var_name("height", &normalized));
    }

    #[test]
    fn erasing_counter_fields_drops_selected_assignments_and_collapses_empty_payload() {
        let erased = normalize_erased_var_names(&["round".to_string(), "view".to_string()]);
        assert_eq!(
            erase_round_fields_from_message_counter_name(
                "cnt_Vote@R[round=1,value=true,view=2]",
                &erased
            ),
            "cnt_Vote@R[value=true]"
        );
        assert_eq!(
            erase_round_fields_from_message_counter_name("cnt_Vote@R[round=1,view=2]", &erased),
            "cnt_Vote@R"
        );
        assert_eq!(
            erase_round_fields_from_message_counter_name("decided", &erased),
            "decided"
        );
    }

    #[test]
    fn location_merge_key_sorts_locals_and_drops_erased_fields() {
        let mut loc = Location {
            name: "L".to_string(),
            role: "Replica".to_string(),
            phase: "prepare".to_string(),
            local_vars: Default::default(),
        };
        loc.local_vars
            .insert("z".to_string(), LocalValue::Bool(true));
        loc.local_vars.insert("a".to_string(), LocalValue::Int(1));
        loc.local_vars
            .insert("view".to_string(), LocalValue::Int(9));
        let erased = normalize_erased_var_names(&["view".to_string()]);
        let key = build_location_merge_key(&loc, &erased);
        assert_eq!(key.role, "Replica");
        assert_eq!(key.phase, "prepare");
        assert_eq!(
            key.locals,
            vec![
                ("a".to_string(), LocalValue::Int(1)),
                ("z".to_string(), LocalValue::Bool(true))
            ]
        );
    }

    #[test]
    fn round_erasure_abstraction_merges_locations_and_message_counters() {
        let ta = mk_erasure_ta();
        let (abs, summary) = apply_round_erasure_abstraction(&ta, &["round".to_string()]);

        assert_eq!(summary.original_locations, 3);
        assert_eq!(summary.abstract_locations, 2);
        assert_eq!(summary.original_shared_vars, 3);
        assert_eq!(summary.abstract_shared_vars, 2);
        assert_eq!(summary.original_message_counters, 2);
        assert_eq!(summary.abstract_message_counters, 1);
        assert_eq!(abs.initial_locations, vec![0]);

        let merged_counter = abs
            .shared_vars
            .iter()
            .find(|v| v.kind == SharedVarKind::MessageCounter)
            .expect("message counter must remain after abstraction");
        assert_eq!(merged_counter.name, "cnt_Vote@R[value=true]");
        assert!(!merged_counter.distinct);
        assert_eq!(merged_counter.distinct_role, None);

        let mapped_guard_vars = match &abs.rules[0].guard.atoms[0] {
            GuardAtom::Threshold { vars, .. } => vars.clone(),
        };
        assert_eq!(mapped_guard_vars.len(), 2);
        assert_eq!(mapped_guard_vars[0], mapped_guard_vars[1]);
        assert_eq!(abs.rules[0].updates[0].var, abs.rules[0].updates[1].var);
    }

    #[test]
    fn symbolic_bound_helpers_render_expected_forms() {
        assert_eq!(format_bound(&[]), "0");
        assert_eq!(format_bound(&["n".to_string(), "2".to_string()]), "n * 2");

        assert_eq!(format_scaled_term("n", 0), "0");
        assert_eq!(format_scaled_term("n", 1), "n");
        assert_eq!(format_scaled_term("n", 3), "n * 3");

        assert_eq!(
            format_sum_bounds(&["0".to_string(), "n".to_string(), "f".to_string()]),
            "n + f"
        );
        assert_eq!(format_sum_bounds(&["0".to_string(), "0".to_string()]), "0");

        assert_eq!(scale_bound_by_depth(3, "0"), "0");
        assert_eq!(scale_bound_by_depth(1, "n + f"), "n + f");
        assert_eq!(scale_bound_by_depth(2, "n + f"), "2 * (n + f)");
        assert_eq!(scale_bound_by_depth(2, "n"), "2 * n");

        assert_eq!(add_bounds("0", "n"), "n");
        assert_eq!(add_bounds("f", "0"), "f");
        assert_eq!(add_bounds("n", "f"), "n + f");
    }

    #[test]
    fn geometric_round_estimator_handles_edges_and_finite_cases() {
        assert_eq!(geometric_rounds_for_confidence(-0.1, 0.9), None);
        assert_eq!(geometric_rounds_for_confidence(0.1, 1.0), None);
        assert_eq!(geometric_rounds_for_confidence(0.0, 0.95), Some(1));
        assert_eq!(geometric_rounds_for_confidence(1.0, 0.95), None);
        assert_eq!(geometric_rounds_for_confidence(0.5, 0.75), Some(2));
    }

    #[test]
    fn hashing_fingerprint_and_quantile_helpers_are_deterministic() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let opts_a = QuantitativeAnalysisOptions {
            command: "comm".to_string(),
            depth: 4,
        };
        let opts_b = QuantitativeAnalysisOptions {
            command: "comm".to_string(),
            depth: 5,
        };
        let env = QuantitativeAnalysisEnvironment {
            target_os: "macos".to_string(),
            target_arch: "aarch64".to_string(),
            target_family: "unix".to_string(),
            build_profile: "debug".to_string(),
        };

        let fp_a1 = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_a, &env)
            .expect("fingerprint should serialize");
        let fp_a2 = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_a, &env)
            .expect("fingerprint should serialize");
        let fp_b = quantitative_reproducibility_fingerprint("src_hash", "0.1.0", &opts_b, &env)
            .expect("fingerprint should serialize");
        assert_eq!(fp_a1, fp_a2);
        assert_ne!(fp_a1, fp_b);

        assert_eq!(quantile(&[3.0, 1.0, 2.0], 0.0), Some(1.0));
        assert_eq!(quantile(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
        assert_eq!(quantile(&[3.0, 1.0, 2.0], 1.0), Some(3.0));
        assert_eq!(quantile(&[0.0, 10.0], 0.25), Some(2.5));
        assert_eq!(quantile(&[], 0.5), None);
        assert_eq!(quantile(&[1.0], 1.1), None);
    }

    #[test]
    fn probabilistic_sample_and_sensitivity_helpers_filter_invalid_inputs() {
        let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        let mut sensitivity = Vec::new();

        push_prob_sample(&mut samples, "p", None);
        push_prob_sample(&mut samples, "p", Some(f64::NAN));
        push_prob_sample(&mut samples, "p", Some(f64::INFINITY));
        assert!(samples.is_empty());

        push_prob_sensitivity_point(
            &mut sensitivity,
            &mut samples,
            "metric",
            Some(0.2),
            Some(0.1),
            1e-6,
            1e-4,
        );
        assert_eq!(sensitivity.len(), 1);
        assert_eq!(samples.get("metric"), Some(&vec![0.1]));

        push_prob_sensitivity_point(
            &mut sensitivity,
            &mut samples,
            "metric",
            None,
            Some(0.05),
            1e-6,
            1e-3,
        );
        assert_eq!(sensitivity.len(), 1);
        assert_eq!(samples.get("metric"), Some(&vec![0.1]));
    }

    #[test]
    fn committee_analysis_sets_single_bound_param_or_rejects_ambiguous_bounds() {
        let mut ta = ThresholdAutomaton::new();
        ta.parameters.push(Parameter {
            name: "n".to_string(),
        });
        ta.parameters.push(Parameter {
            name: "f".to_string(),
        });
        ta.committees.push(IrCommitteeSpec {
            name: "c1".to_string(),
            population: ParamOrConst::Const(100),
            byzantine: ParamOrConst::Const(33),
            committee_size: ParamOrConst::Const(25),
            epsilon: Some(1e-6),
            bound_param: Some(1),
        });

        let summaries =
            analyze_and_constrain_committees(&mut ta).expect("single bound param should succeed");
        assert_eq!(summaries.len(), 1);
        assert_eq!(ta.adversary_bound_param, Some(1));

        let mut ambiguous = ThresholdAutomaton::new();
        ambiguous.parameters.push(Parameter {
            name: "f1".to_string(),
        });
        ambiguous.parameters.push(Parameter {
            name: "f2".to_string(),
        });
        ambiguous.committees.push(IrCommitteeSpec {
            name: "c1".to_string(),
            population: ParamOrConst::Const(100),
            byzantine: ParamOrConst::Const(33),
            committee_size: ParamOrConst::Const(25),
            epsilon: Some(1e-6),
            bound_param: Some(0),
        });
        ambiguous.committees.push(IrCommitteeSpec {
            name: "c2".to_string(),
            population: ParamOrConst::Const(100),
            byzantine: ParamOrConst::Const(33),
            committee_size: ParamOrConst::Const(25),
            epsilon: Some(1e-6),
            bound_param: Some(1),
        });

        let err = analyze_and_constrain_committees(&mut ambiguous)
            .expect_err("ambiguous bound params should require explicit adversary bound");
        match err {
            PipelineError::Property(msg) => {
                assert!(msg.contains("Multiple committee bound parameters"))
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn ensure_n_parameter_requires_population_parameter() {
        let mut ta = ThresholdAutomaton::new();
        let err = ensure_n_parameter(&ta).expect_err("missing n must fail");
        match err {
            PipelineError::Property(msg) => assert!(msg.contains("parameter `n`")),
            other => panic!("unexpected error kind: {other}"),
        }

        ta.parameters.push(Parameter {
            name: "n".to_string(),
        });
        ensure_n_parameter(&ta).expect("n parameter should pass");
    }
}
