//! Proptest strategies for generating well-formed `ThresholdAutomaton` instances.

use proptest::prelude::*;

use crate::threshold_automaton::*;
use indexmap::IndexMap;

/// Strategy for a well-formed `ThresholdAutomaton` suitable for property testing.
///
/// Generated automata have:
/// - 3 parameters (n, t, f) — always present
/// - 2–6 locations with unique names
/// - 1–3 shared variables (message counters)
/// - 1–8 rules connecting valid locations with valid guards
/// - At least one initial location
/// - A resilience condition (n > 3*t)
pub fn arb_threshold_automaton() -> impl Strategy<Value = ThresholdAutomaton> {
    // Generate structure sizes first
    (2..=6usize, 1..=3usize, 1..=8usize)
        .prop_flat_map(|(nlocs, nvars, nrules)| {
            let nrules = nrules.min(nlocs * nlocs); // cap at possible transitions

            // Generate rule source/dest pairs (valid location ids)
            let rules_strategy = proptest::collection::vec((0..nlocs, 0..nlocs), nrules..=nrules);

            // Generate guard thresholds (which shared vars to reference)
            let guards_strategy = proptest::collection::vec(
                (
                    0..nvars,
                    prop_oneof![Just(CmpOp::Ge), Just(CmpOp::Gt), Just(CmpOp::Le)],
                ),
                nrules..=nrules,
            );

            // Generate update info for rules (which var to increment, if any)
            let updates_strategy =
                proptest::collection::vec(proptest::option::of(0..nvars), nrules..=nrules);

            (
                Just(nlocs),
                Just(nvars),
                rules_strategy,
                guards_strategy,
                updates_strategy,
            )
        })
        .prop_map(|(nlocs, nvars, rule_pairs, guard_info, update_info)| {
            let mut ta = ThresholdAutomaton::new();

            // Add standard parameters: n, t, f
            let _n_id = ta.add_parameter(Parameter { name: "n".into() });
            let t_id = ta.add_parameter(Parameter { name: "t".into() });
            let f_id = ta.add_parameter(Parameter { name: "f".into() });

            // Resilience condition: n > 3*t
            ta.resilience_condition = Some(LinearConstraint {
                lhs: LinearCombination::param(0), // n
                op: CmpOp::Gt,
                rhs: LinearCombination::param(t_id).scale(3),
            });

            // Adversary bound is f
            ta.adversary_bound_param = Some(f_id);

            // Add locations
            for i in 0..nlocs {
                ta.add_location(Location {
                    name: format!("Role_phase{i}[decided=false]"),
                    role: "Role".into(),
                    phase: format!("phase{i}"),
                    local_vars: IndexMap::new(),
                });
            }

            // First location is always initial
            ta.initial_locations.push(0);

            // Add shared vars (message counters)
            for i in 0..nvars {
                ta.add_shared_var(SharedVar {
                    name: format!("cnt_Msg{i}@Role"),
                    kind: SharedVarKind::MessageCounter,
                    distinct: false,
                    distinct_role: None,
                });
            }

            // Add rules
            for (idx, &(from, to)) in rule_pairs.iter().enumerate() {
                let (guard_var, guard_op) = &guard_info[idx];

                // Build guard: shared_var >= 1 + 2*t (or similar)
                let guard = Guard::single(GuardAtom::Threshold {
                    vars: vec![*guard_var],
                    op: *guard_op,
                    bound: LinearCombination {
                        constant: 1,
                        terms: vec![(2, t_id)],
                    },
                    distinct: false,
                });

                // Build updates
                let mut updates = Vec::new();
                if let Some(var_id) = update_info[idx] {
                    updates.push(Update {
                        var: var_id,
                        kind: UpdateKind::Increment,
                    });
                }

                ta.add_rule(Rule {
                    from,
                    to,
                    guard,
                    updates,
                });
            }

            ta
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn generated_automata_are_well_formed(ta in arb_threshold_automaton()) {
            // At least 2 locations
            prop_assert!(ta.locations.len() >= 2);
            // At least 1 rule
            prop_assert!(!ta.rules.is_empty());
            // Has parameters n, t, f
            prop_assert_eq!(ta.parameters.len(), 3);
            prop_assert_eq!(&ta.parameters[0].name, "n");
            prop_assert_eq!(&ta.parameters[1].name, "t");
            prop_assert_eq!(&ta.parameters[2].name, "f");
            // Has initial location
            prop_assert!(!ta.initial_locations.is_empty());
            // Has resilience condition
            prop_assert!(ta.resilience_condition.is_some());
            // All rule references are valid
            for rule in &ta.rules {
                prop_assert!(rule.from < ta.locations.len());
                prop_assert!(rule.to < ta.locations.len());
                for atom in &rule.guard.atoms {
                    match atom {
                        GuardAtom::Threshold { vars, .. } => {
                            for &v in vars {
                                prop_assert!(v < ta.shared_vars.len());
                            }
                        }
                    }
                }
                for upd in &rule.updates {
                    prop_assert!(upd.var < ta.shared_vars.len());
                }
            }
        }
    }
}
