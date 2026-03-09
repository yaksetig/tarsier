//! Product automaton construction for refinement checking.
//!
//! Given a concrete threshold automaton and an abstract threshold automaton,
//! this module constructs a product automaton whose state space is the
//! Cartesian product of the two. Product transitions synchronize concrete
//! steps with their abstract counterparts via the refinement mapping.
//!
//! The product automaton is then fed to the SMT encoder (REF-04) to check
//! simulation preservation.

use std::collections::HashMap;

use crate::refinement::{RefinementMapping, RefinementRelation, SimulationKind};
use crate::threshold_automaton::{
    Guard, GuardAtom, LinearCombination, LocationId, ParamId, Parameter, RuleId,
    SharedVar, SharedVarId, ThresholdAutomaton, Update, UpdateKind,
};

/// A location in the product automaton, pairing a concrete and abstract location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductLocationId {
    pub concrete: LocationId,
    pub abstract_loc: LocationId,
}

/// A rule in the product automaton, pairing concrete and abstract rule origins.
#[derive(Debug, Clone)]
pub struct ProductRule {
    pub from: ProductLocationId,
    pub to: ProductLocationId,
    /// Guard combining both concrete and abstract guards.
    pub guard: Guard,
    /// Updates to concrete shared variables (using product-space variable IDs).
    pub concrete_updates: Vec<Update>,
    /// Updates to abstract shared variables (using product-space variable IDs).
    pub abstract_updates: Vec<Update>,
    /// Original concrete rule index (for diagnostics).
    pub concrete_rule: RuleId,
    /// Original abstract rule index (for diagnostics). `None` for stutter steps.
    pub abstract_rule: Option<RuleId>,
}

/// The product automaton for refinement checking.
///
/// Contains:
/// - Product locations (concrete × abstract)
/// - Synchronized product rules
/// - Merged parameter and shared variable spaces
/// - Mismatch states that witness simulation failures
#[derive(Debug, Clone)]
pub struct ProductAutomaton {
    /// All product locations, indexed by `ProductLocationId`.
    pub locations: Vec<ProductLocationId>,
    /// Map from product location to its index in `locations`.
    pub location_index: HashMap<ProductLocationId, usize>,
    /// Initial product locations.
    pub initial_locations: Vec<ProductLocationId>,
    /// Product rules (synchronized transitions).
    pub rules: Vec<ProductRule>,

    /// Shared variables from the concrete automaton (remapped into product space).
    /// Maps concrete `SharedVarId` → product-space `SharedVarId`.
    pub concrete_var_map: HashMap<SharedVarId, SharedVarId>,
    /// Shared variables from the abstract automaton (remapped into product space).
    /// Maps abstract `SharedVarId` → product-space `SharedVarId`.
    pub abstract_var_map: HashMap<SharedVarId, SharedVarId>,
    /// All shared variables in the product space.
    pub shared_vars: Vec<SharedVar>,

    /// Parameters from the concrete automaton (remapped).
    /// Maps concrete `ParamId` → product-space `ParamId`.
    pub concrete_param_map: HashMap<ParamId, ParamId>,
    /// Parameters from the abstract automaton (remapped).
    /// Maps abstract `ParamId` → product-space `ParamId`.
    pub abstract_param_map: HashMap<ParamId, ParamId>,
    /// All parameters in the product space.
    pub parameters: Vec<Parameter>,

    /// Mismatch locations — product locations where the concrete location
    /// maps to a different abstract location than the one in the pair.
    /// Non-empty mismatch set after reachability = simulation violation.
    pub mismatch_locations: Vec<ProductLocationId>,

    /// The simulation kind used for construction.
    pub simulation_kind: SimulationKind,
}

/// Errors from product automaton construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductError {
    /// A concrete location has no mapping in the refinement.
    UnmappedConcreteLocation(LocationId),
    /// A concrete variable has no mapping in the refinement.
    UnmappedConcreteVariable(SharedVarId),
}

impl std::fmt::Display for ProductError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProductError::UnmappedConcreteLocation(id) => {
                write!(f, "concrete location {id} has no refinement mapping")
            }
            ProductError::UnmappedConcreteVariable(id) => {
                write!(f, "concrete variable {id} has no refinement mapping")
            }
        }
    }
}

impl std::error::Error for ProductError {}

/// Build a product automaton from concrete and abstract threshold automata
/// using the given refinement relation.
pub fn build_product(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
    relation: &RefinementRelation,
) -> Result<ProductAutomaton, ProductError> {
    let mapping = &relation.mapping;

    // --- 1. Merge parameters ---
    let (parameters, concrete_param_map, abstract_param_map) =
        merge_parameters(concrete, abstract_ta);

    // --- 2. Merge shared variables ---
    let (shared_vars, concrete_var_map, abstract_var_map) =
        merge_shared_vars(concrete, abstract_ta);

    // --- 3. Build product location space ---
    let mut locations = Vec::new();
    let mut location_index = HashMap::new();
    let mut initial_locations = Vec::new();
    let mut mismatch_locations = Vec::new();

    // For each concrete location, determine the set of abstract locations it can pair with.
    for c_loc_id in 0..concrete.locations.len() {
        let c_loc = LocationId::from(c_loc_id);
        let mapped_abstract = mapping
            .abstract_location(c_loc)
            .ok_or(ProductError::UnmappedConcreteLocation(c_loc))?;

        for a_loc_id in 0..abstract_ta.locations.len() {
            let a_loc = LocationId::from(a_loc_id);
            let prod_loc = ProductLocationId {
                concrete: c_loc,
                abstract_loc: a_loc,
            };
            let idx = locations.len();
            locations.push(prod_loc);
            location_index.insert(prod_loc, idx);

            // A product location is a mismatch if the concrete location maps
            // to Some(abstract_loc) but the paired abstract location differs.
            if let Some(expected_abstract) = mapped_abstract {
                if expected_abstract != a_loc {
                    mismatch_locations.push(prod_loc);
                }
            }
        }
    }

    // Initial product locations: pair each concrete initial with its mapped abstract initial.
    for &c_init in &concrete.initial_locations {
        let mapped = mapping
            .abstract_location(c_init)
            .ok_or(ProductError::UnmappedConcreteLocation(c_init))?;

        match mapped {
            Some(a_init) => {
                // Concrete initial maps to a specific abstract location.
                let prod_loc = ProductLocationId {
                    concrete: c_init,
                    abstract_loc: a_init,
                };
                if !initial_locations.contains(&prod_loc) {
                    initial_locations.push(prod_loc);
                }
            }
            None => {
                // Internal concrete location — pair with all abstract initials.
                for &a_init in &abstract_ta.initial_locations {
                    let prod_loc = ProductLocationId {
                        concrete: c_init,
                        abstract_loc: a_init,
                    };
                    if !initial_locations.contains(&prod_loc) {
                        initial_locations.push(prod_loc);
                    }
                }
            }
        }
    }

    // --- 4. Build product rules ---
    let rules = build_product_rules(
        concrete,
        abstract_ta,
        mapping,
        relation.simulation_kind,
        &concrete_var_map,
        &abstract_var_map,
        &concrete_param_map,
        &abstract_param_map,
    );

    Ok(ProductAutomaton {
        locations,
        location_index,
        initial_locations,
        rules,
        concrete_var_map,
        abstract_var_map,
        shared_vars,
        concrete_param_map,
        abstract_param_map,
        parameters,
        mismatch_locations,
        simulation_kind: relation.simulation_kind,
    })
}

/// Merge parameters from both automata into a single parameter space.
/// Concrete parameters come first, then abstract parameters (with "abs_" prefix to avoid collisions).
fn merge_parameters(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
) -> (Vec<Parameter>, HashMap<ParamId, ParamId>, HashMap<ParamId, ParamId>) {
    let mut parameters = Vec::new();
    let mut concrete_map = HashMap::new();
    let mut abstract_map = HashMap::new();

    for (i, p) in concrete.parameters.iter().enumerate() {
        let new_id = ParamId::from(parameters.len());
        parameters.push(Parameter {
            name: format!("conc_{}", p.name),
            time_varying: p.time_varying,
        });
        concrete_map.insert(ParamId::from(i), new_id);
    }

    for (i, p) in abstract_ta.parameters.iter().enumerate() {
        let new_id = ParamId::from(parameters.len());
        parameters.push(Parameter {
            name: format!("abs_{}", p.name),
            time_varying: p.time_varying,
        });
        abstract_map.insert(ParamId::from(i), new_id);
    }

    (parameters, concrete_map, abstract_map)
}

/// Merge shared variables from both automata.
/// Concrete vars come first, then abstract vars (prefixed).
fn merge_shared_vars(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
) -> (
    Vec<SharedVar>,
    HashMap<SharedVarId, SharedVarId>,
    HashMap<SharedVarId, SharedVarId>,
) {
    let mut vars = Vec::new();
    let mut concrete_map = HashMap::new();
    let mut abstract_map = HashMap::new();

    for (i, v) in concrete.shared_vars.iter().enumerate() {
        let new_id = SharedVarId::from(vars.len());
        vars.push(SharedVar {
            name: format!("conc_{}", v.name),
            kind: v.kind,
            distinct: v.distinct,
            distinct_role: v.distinct_role.clone(),
        });
        concrete_map.insert(SharedVarId::from(i), new_id);
    }

    for (i, v) in abstract_ta.shared_vars.iter().enumerate() {
        let new_id = SharedVarId::from(vars.len());
        vars.push(SharedVar {
            name: format!("abs_{}", v.name),
            kind: v.kind,
            distinct: v.distinct,
            distinct_role: v.distinct_role.clone(),
        });
        abstract_map.insert(SharedVarId::from(i), new_id);
    }

    (vars, concrete_map, abstract_map)
}

/// Remap a `LinearCombination` from one parameter space to another.
fn remap_lc(lc: &LinearCombination, param_map: &HashMap<ParamId, ParamId>) -> LinearCombination {
    LinearCombination {
        constant: lc.constant,
        terms: lc
            .terms
            .iter()
            .map(|&(coeff, pid)| (coeff, *param_map.get(&pid).unwrap_or(&pid)))
            .collect(),
    }
}

/// Remap a guard's atoms into the product space.
fn remap_guard(
    guard: &Guard,
    var_map: &HashMap<SharedVarId, SharedVarId>,
    param_map: &HashMap<ParamId, ParamId>,
) -> Guard {
    Guard {
        atoms: guard
            .atoms
            .iter()
            .map(|atom| match atom {
                GuardAtom::Threshold {
                    vars,
                    op,
                    bound,
                    distinct,
                } => GuardAtom::Threshold {
                    vars: vars
                        .iter()
                        .map(|v| *var_map.get(v).unwrap_or(v))
                        .collect(),
                    op: *op,
                    bound: remap_lc(bound, param_map),
                    distinct: *distinct,
                },
            })
            .collect(),
    }
}

/// Remap updates into the product space.
fn remap_updates(
    updates: &[Update],
    var_map: &HashMap<SharedVarId, SharedVarId>,
    param_map: &HashMap<ParamId, ParamId>,
) -> Vec<Update> {
    updates
        .iter()
        .map(|upd| Update {
            var: *var_map.get(&upd.var).unwrap_or(&upd.var),
            kind: match &upd.kind {
                UpdateKind::Increment => UpdateKind::Increment,
                UpdateKind::Set(lc) => UpdateKind::Set(remap_lc(lc, param_map)),
            },
        })
        .collect()
}

/// Build synchronized product rules for forward simulation.
///
/// For each concrete rule `c: (c_from → c_to)`, and for each abstract rule
/// `a: (a_from → a_to)` where `mapping(c_from) = a_from` and
/// `mapping(c_to) = a_to`, create a synchronized product rule.
///
/// Additionally, for concrete rules where the source maps to an internal
/// location (None), create stutter rules where the abstract side doesn't move.
fn build_product_rules(
    concrete: &ThresholdAutomaton,
    abstract_ta: &ThresholdAutomaton,
    mapping: &RefinementMapping,
    _simulation_kind: SimulationKind,
    concrete_var_map: &HashMap<SharedVarId, SharedVarId>,
    abstract_var_map: &HashMap<SharedVarId, SharedVarId>,
    concrete_param_map: &HashMap<ParamId, ParamId>,
    abstract_param_map: &HashMap<ParamId, ParamId>,
) -> Vec<ProductRule> {
    let mut rules = Vec::new();

    for (c_idx, c_rule) in concrete.rules.iter().enumerate() {
        let c_from_mapped = mapping.abstract_location(c_rule.from);
        let c_to_mapped = mapping.abstract_location(c_rule.to);

        // Skip rules from completely unmapped locations (will be caught by validation).
        let (c_from_abs, c_to_abs) = match (c_from_mapped, c_to_mapped) {
            (Some(from), Some(to)) => (from, to),
            _ => continue,
        };

        let remapped_c_guard = remap_guard(&c_rule.guard, concrete_var_map, concrete_param_map);
        let remapped_c_updates = remap_updates(&c_rule.updates, concrete_var_map, concrete_param_map);

        match (c_from_abs, c_to_abs) {
            // Both mapped to specific abstract locations — synchronized step.
            (Some(a_from), Some(a_to)) => {
                // Find matching abstract rules.
                for (a_idx, a_rule) in abstract_ta.rules.iter().enumerate() {
                    if a_rule.from == a_from && a_rule.to == a_to {
                        let remapped_a_guard =
                            remap_guard(&a_rule.guard, abstract_var_map, abstract_param_map);
                        let remapped_a_updates =
                            remap_updates(&a_rule.updates, abstract_var_map, abstract_param_map);

                        // Combine guards.
                        let mut combined_atoms = remapped_c_guard.atoms.clone();
                        combined_atoms.extend(remapped_a_guard.atoms);

                        rules.push(ProductRule {
                            from: ProductLocationId {
                                concrete: c_rule.from,
                                abstract_loc: a_from,
                            },
                            to: ProductLocationId {
                                concrete: c_rule.to,
                                abstract_loc: a_to,
                            },
                            guard: Guard {
                                atoms: combined_atoms,
                            },
                            concrete_updates: remapped_c_updates.clone(),
                            abstract_updates: remapped_a_updates,
                            concrete_rule: RuleId::from(c_idx),
                            abstract_rule: Some(RuleId::from(a_idx)),
                        });
                    }
                }

                // Also add a stutter rule: concrete moves but abstract stays,
                // if source and target map to the same abstract location.
                if a_from == a_to {
                    rules.push(ProductRule {
                        from: ProductLocationId {
                            concrete: c_rule.from,
                            abstract_loc: a_from,
                        },
                        to: ProductLocationId {
                            concrete: c_rule.to,
                            abstract_loc: a_to,
                        },
                        guard: Guard {
                            atoms: remapped_c_guard.atoms.clone(),
                        },
                        concrete_updates: remapped_c_updates.clone(),
                        abstract_updates: vec![],
                        concrete_rule: RuleId::from(c_idx),
                        abstract_rule: None,
                    });
                }
            }
            // Source or target is internal — abstract side stutters.
            _ => {
                // For internal transitions, the abstract side doesn't move.
                // We create stutter rules for all abstract locations.
                let a_from_loc = c_from_abs.unwrap_or(LocationId::from(0));
                let a_to_loc = c_to_abs.unwrap_or(a_from_loc);

                // If from is internal, pair with every abstract location.
                if c_from_abs.is_none() {
                    for a_loc_id in 0..abstract_ta.locations.len() {
                        let a_loc = LocationId::from(a_loc_id);
                        rules.push(ProductRule {
                            from: ProductLocationId {
                                concrete: c_rule.from,
                                abstract_loc: a_loc,
                            },
                            to: ProductLocationId {
                                concrete: c_rule.to,
                                abstract_loc: c_to_abs.unwrap_or(a_loc),
                            },
                            guard: Guard {
                                atoms: remapped_c_guard.atoms.clone(),
                            },
                            concrete_updates: remapped_c_updates.clone(),
                            abstract_updates: vec![],
                            concrete_rule: RuleId::from(c_idx),
                            abstract_rule: None,
                        });
                    }
                } else {
                    // From is mapped, to is internal — abstract stays at a_from.
                    rules.push(ProductRule {
                        from: ProductLocationId {
                            concrete: c_rule.from,
                            abstract_loc: a_from_loc,
                        },
                        to: ProductLocationId {
                            concrete: c_rule.to,
                            abstract_loc: a_to_loc,
                        },
                        guard: Guard {
                            atoms: remapped_c_guard.atoms.clone(),
                        },
                        concrete_updates: remapped_c_updates.clone(),
                        abstract_updates: vec![],
                        concrete_rule: RuleId::from(c_idx),
                        abstract_rule: None,
                    });
                }
            }
        }
    }

    rules
}

impl ProductAutomaton {
    /// Returns true if the product has any mismatch locations.
    pub fn has_mismatches(&self) -> bool {
        !self.mismatch_locations.is_empty()
    }

    /// Number of product locations.
    pub fn num_locations(&self) -> usize {
        self.locations.len()
    }

    /// Number of product rules.
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    /// Look up the index of a product location.
    pub fn location_idx(&self, loc: &ProductLocationId) -> Option<usize> {
        self.location_index.get(loc).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refinement::RefinementMapping;
    use crate::threshold_automaton::*;

    /// Helper: build a minimal threshold automaton with given number of locations, rules, etc.
    fn minimal_ta(
        num_locations: usize,
        initial: &[usize],
        rules: Vec<(usize, usize)>,
    ) -> ThresholdAutomaton {
        let mut ta = ThresholdAutomaton::new();
        for i in 0..num_locations {
            ta.add_location(Location {
                name: format!("L{i}"),
                role: "R".into(),
                phase: format!("P{i}"),
                local_vars: Default::default(),
            });
        }
        for &init in initial {
            ta.initial_locations.push(LocationId::from(init));
        }
        for (from, to) in rules {
            ta.add_rule(Rule {
                from: LocationId::from(from),
                to: LocationId::from(to),
                guard: Guard::trivial(),
                updates: vec![],
                collection_updates: vec![],
                clock_guards: vec![],
                clock_updates: vec![],
                param_updates: vec![],
            });
        }
        ta
    }

    #[test]
    fn product_location_count() {
        // Concrete: 3 locations, Abstract: 2 locations → 6 product locations
        let concrete = minimal_ta(3, &[0], vec![(0, 1), (1, 2)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(0));
        mapping.map_location(LocationId::from(2), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        assert_eq!(product.num_locations(), 6); // 3 × 2
    }

    #[test]
    fn product_initial_locations() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        assert_eq!(product.initial_locations.len(), 1);
        assert_eq!(product.initial_locations[0].concrete, LocationId::from(0));
        assert_eq!(
            product.initial_locations[0].abstract_loc,
            LocationId::from(0)
        );
    }

    #[test]
    fn product_synchronized_rules() {
        // Concrete: L0→L1, Abstract: L0→L1, mapping: 0→0, 1→1
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        // Should have at least one synchronized rule (0,0)→(1,1)
        let synced: Vec<_> = product
            .rules
            .iter()
            .filter(|r| r.abstract_rule.is_some())
            .collect();
        assert!(!synced.is_empty());
        assert_eq!(synced[0].from.concrete, LocationId::from(0));
        assert_eq!(synced[0].from.abstract_loc, LocationId::from(0));
        assert_eq!(synced[0].to.concrete, LocationId::from(1));
        assert_eq!(synced[0].to.abstract_loc, LocationId::from(1));
    }

    #[test]
    fn product_mismatch_detection() {
        // Concrete: L0→L1, mapping: 0→0, 1→1
        // Mismatch: product location (1, 0) has concrete mapped to abstract 1, but paired with 0.
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        // (0,1) and (1,0) should be mismatches
        assert!(product.has_mismatches());
        assert_eq!(product.mismatch_locations.len(), 2);
    }

    #[test]
    fn product_internal_location_stutter() {
        // Concrete has an internal location (no abstract mapping).
        let concrete = minimal_ta(3, &[0], vec![(0, 1), (1, 2)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.mark_location_internal(LocationId::from(1)); // internal
        mapping.map_location(LocationId::from(2), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        // Rule 0→1 should produce stutter rules (abstract doesn't move)
        let stutter: Vec<_> = product
            .rules
            .iter()
            .filter(|r| r.abstract_rule.is_none() && r.from.concrete == LocationId::from(0))
            .collect();
        assert!(!stutter.is_empty());
    }

    #[test]
    fn product_unmapped_location_error() {
        let concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        let abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);

        // Only map location 0, leave 1 unmapped.
        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));

        let relation = RefinementRelation::new(mapping);
        let result = build_product(&concrete, &abstract_ta, &relation);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProductError::UnmappedConcreteLocation(LocationId::from(1))
        );
    }

    #[test]
    fn product_merged_parameters() {
        let mut concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        concrete.add_parameter(Parameter { name: "n".into(), time_varying: false });
        concrete.add_parameter(Parameter { name: "t".into(), time_varying: false });

        let mut abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);
        abstract_ta.add_parameter(Parameter { name: "n".into(), time_varying: false });

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        // 2 concrete + 1 abstract = 3 parameters
        assert_eq!(product.parameters.len(), 3);
        assert_eq!(product.parameters[0].name, "conc_n");
        assert_eq!(product.parameters[1].name, "conc_t");
        assert_eq!(product.parameters[2].name, "abs_n");
    }

    #[test]
    fn product_merged_shared_vars() {
        let mut concrete = minimal_ta(2, &[0], vec![(0, 1)]);
        concrete.add_shared_var(SharedVar {
            name: "vote_count".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let mut abstract_ta = minimal_ta(2, &[0], vec![(0, 1)]);
        abstract_ta.add_shared_var(SharedVar {
            name: "vote_count".into(),
            kind: SharedVarKind::MessageCounter,
            distinct: false,
            distinct_role: None,
        });

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        mapping.map_location(LocationId::from(0), LocationId::from(0));
        mapping.map_location(LocationId::from(1), LocationId::from(1));

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        assert_eq!(product.shared_vars.len(), 2);
        assert_eq!(product.shared_vars[0].name, "conc_vote_count");
        assert_eq!(product.shared_vars[1].name, "abs_vote_count");
    }

    #[test]
    fn product_identity_mapping_no_mismatches_on_diagonal() {
        // When mapping is identity, diagonal product locations should not be mismatches.
        let concrete = minimal_ta(3, &[0], vec![(0, 1), (1, 2)]);
        let abstract_ta = minimal_ta(3, &[0], vec![(0, 1), (1, 2)]);

        let mut mapping = RefinementMapping::new("abstract.trs".into());
        for i in 0..3 {
            mapping.map_location(LocationId::from(i), LocationId::from(i));
        }

        let relation = RefinementRelation::new(mapping);
        let product = build_product(&concrete, &abstract_ta, &relation).unwrap();

        // Diagonal locations (0,0), (1,1), (2,2) should NOT be mismatches.
        for i in 0..3 {
            let diag = ProductLocationId {
                concrete: LocationId::from(i),
                abstract_loc: LocationId::from(i),
            };
            assert!(
                !product.mismatch_locations.contains(&diag),
                "diagonal ({i},{i}) should not be a mismatch"
            );
        }
        // Off-diagonal should be mismatches: 6 total (3×3 - 3 = 6)
        assert_eq!(product.mismatch_locations.len(), 6);
    }
}
