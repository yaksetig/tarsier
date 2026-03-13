// Round-erasure abstraction helpers.

use super::*;

pub(in super::super) fn base_message_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix("cnt_")?;
    let without_recipient = stripped.split_once('@').map(|(b, _)| b).unwrap_or(stripped);
    let base = without_recipient
        .split_once('[')
        .map(|(b, _)| b)
        .unwrap_or(without_recipient);
    Some(base.to_string())
}

/// Parse `cnt_<family>@<recipient>[...]` style names into family and recipient.
pub(in super::super) fn message_family_and_recipient_from_counter_name(
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
pub(in super::super) fn normalize_erased_var_names(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Return whether `name` is in the erased-variable set (case-insensitive).
pub(in super::super) fn is_erased_var_name(name: &str, erased: &HashSet<String>) -> bool {
    erased.contains(&name.to_ascii_lowercase())
}

/// Remove erased field assignments from counter payloads (`cnt_*[k=v,...]`).
pub(in super::super) fn erase_round_fields_from_message_counter_name(
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
pub(in super::super) struct LocationMergeKey {
    pub(in super::super) role: String,
    pub(in super::super) phase: String,
    pub(in super::super) locals: Vec<(String, LocalValue)>,
}

pub(in super::super) fn build_location_merge_key(
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

pub(in super::super) fn apply_round_erasure_abstraction(
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
        constraints: ta.constraints.clone(),
        semantics: ta.semantics.clone(),
        security: ta.security.clone(),
        reconfiguration: ta.reconfiguration.clone(),
        clocks: ta.clocks.clone(),
        leader_roles: ta.leader_roles.clone(),
        collections: ta.collections.clone(),
        dag_rounds: ta.dag_rounds.clone(),
    };

    let mut shared_map: Vec<SharedVarId> = vec![SharedVarId::default(); ta.shared_vars.len()];
    let mut shared_key_to_new: HashMap<SharedMergeKey, SharedVarId> = HashMap::new();
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
                let existing = &mut abstract_ta.shared_vars[new_id.as_usize()];
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
        let new_id = SharedVarId::from(abstract_ta.shared_vars.len());
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

    let mut loc_map: Vec<LocationId> = vec![LocationId::default(); ta.locations.len()];
    let mut loc_key_to_new: HashMap<LocationMergeKey, LocationId> = HashMap::new();
    for (old_id, loc) in ta.locations.iter().enumerate() {
        let key = build_location_merge_key(loc, &erased);
        if let Some(&new_id) = loc_key_to_new.get(&key) {
            loc_map[old_id] = new_id;
            continue;
        }

        let mut local_vars = loc.local_vars.clone();
        local_vars.retain(|name, _| !is_erased_var_name(name, &erased));
        let new_id = LocationId::from(abstract_ta.locations.len());
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

    let mut initial_set: HashSet<LocationId> = HashSet::new();
    for old_init in &ta.initial_locations {
        if let Some(&mapped) = loc_map.get(old_init.as_usize()) {
            initial_set.insert(mapped);
        }
    }
    let mut initial_locations: Vec<LocationId> = initial_set.into_iter().collect();
    initial_locations.sort_by_key(|id| id.as_usize());
    abstract_ta.initial_locations = initial_locations;

    abstract_ta.rules = ta
        .rules
        .iter()
        .map(|rule| tarsier_ir::threshold_automaton::Rule {
            from: loc_map[rule.from.as_usize()],
            to: loc_map[rule.to.as_usize()],
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
                            vars: vars.iter().map(|v| shared_map[v.as_usize()]).collect(),
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
                    var: shared_map[update.var.as_usize()],
                    kind: update.kind.clone(),
                })
                .collect(),
            clock_guards: rule.clock_guards.clone(),
            clock_updates: rule.clock_updates.clone(),
            collection_updates: rule.collection_updates.clone(),
            param_updates: rule.param_updates.clone(),
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
