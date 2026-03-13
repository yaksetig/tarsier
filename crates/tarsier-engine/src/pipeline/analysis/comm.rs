// Threshold-automaton display and communication-complexity entrypoints.

use super::*;

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
        && ta.semantics.timing_model == tarsier_ir::threshold_automaton::TimingModel::Asynchronous
        && ta.semantics.gst_param.is_none();
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
        .map(|id| ta.parameters[id.as_usize()].name.clone());
    let n_label = n_param.clone().unwrap_or_else(|| "n".into());
    let adv_param = ta
        .constraints
        .adversary_bound_param
        .map(|id| ta.parameters[id.as_usize()].name.clone());
    let min_decision_steps = {
        let decision_locs: Vec<LocationId> = ta
            .locations
            .iter()
            .enumerate()
            .filter_map(|(loc_id, loc)| match loc.local_vars.get("decided") {
                Some(LocalValue::Bool(true)) => Some(loc_id.into()),
                _ => None,
            })
            .collect();
        if decision_locs.is_empty() || ta.initial_locations.is_empty() {
            None
        } else {
            let mut dist = vec![usize::MAX; ta.locations.len()];
            let mut queue: VecDeque<LocationId> = VecDeque::new();
            for &start in &ta.initial_locations {
                let start_idx = start.as_usize();
                if start_idx < dist.len() && dist[start_idx] == usize::MAX {
                    dist[start_idx] = 0;
                    queue.push_back(start);
                }
            }

            while let Some(current) = queue.pop_front() {
                let next_dist = dist[current.as_usize()].saturating_add(1);
                for rule in &ta.rules {
                    if rule.from != current {
                        continue;
                    }
                    if dist[rule.to.as_usize()] == usize::MAX {
                        dist[rule.to.as_usize()] = next_dist;
                        queue.push_back(rule.to);
                    }
                }
            }

            decision_locs
                .into_iter()
                .filter_map(|id| {
                    let d = dist[id.as_usize()];
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
            if ta.shared_vars[upd.var.as_usize()].kind != SharedVarKind::MessageCounter {
                continue;
            }
            if !matches!(
                upd.kind,
                tarsier_ir::threshold_automaton::UpdateKind::Increment
            ) {
                continue;
            }
            total += 1;
            if let Some(base) = base_message_name(&ta.shared_vars[upd.var.as_usize()].name) {
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

        let sender_role = ta.locations[rule.from.as_usize()].role.clone();
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
            role_population_labels.insert(role.clone(), ta.parameters[pid.as_usize()].name.clone());
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

    let byzantine_faults = ta.semantics.fault_model == FaultModel::Byzantine;
    let signed_or_no_equiv = ta.semantics.authentication_mode == AuthenticationMode::Signed
        || ta.semantics.equivocation_mode == EquivocationMode::None;

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
        let phase = ta.locations[rule.from.as_usize()].phase.clone();
        let mut total = 0usize;
        for upd in &rule.updates {
            if ta.shared_vars[upd.var.as_usize()].kind != SharedVarKind::MessageCounter {
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
        fault_model: format!("{:?}", ta.semantics.fault_model),
        timing_model: format!("{:?}", ta.semantics.timing_model),
        authentication_mode: format!("{:?}", ta.semantics.authentication_mode),
        equivocation_mode: format!("{:?}", ta.semantics.equivocation_mode),
        network_semantics: format!("{:?}", ta.semantics.network_semantics),
        gst_param: ta
            .semantics
            .gst_param
            .map(|id| ta.parameters[id.as_usize()].name.clone()),
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
    if ta.semantics.timing_model == tarsier_ir::threshold_automaton::TimingModel::Asynchronous
        && ta.semantics.gst_param.is_none()
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
    if ta.semantics.fault_model == FaultModel::Crash {
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
