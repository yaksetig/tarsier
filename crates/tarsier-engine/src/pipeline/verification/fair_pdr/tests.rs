use super::*;
use std::collections::{HashMap, VecDeque};
use std::io;
use tarsier_smt::solver::{Model, ModelValue};

// ========================================================================
// Helpers
// ========================================================================

fn make_cube(lits: &[(usize, i64)]) -> FairPdrCube {
    FairPdrCube {
        lits: lits
            .iter()
            .map(|&(idx, val)| FairPdrCubeLit {
                state_var_idx: idx,
                value: val,
            })
            .collect(),
    }
}

fn int_state_vars(names: &[&str]) -> Vec<(String, SmtSort)> {
    names
        .iter()
        .map(|n| (n.to_string(), SmtSort::Int))
        .collect()
}

fn int_model(values: &[(&str, i64)]) -> Model {
    let mut out = HashMap::new();
    for (name, value) in values {
        out.insert((*name).to_string(), ModelValue::Int(*value));
    }
    Model { values: out }
}

// ========================================================================
// 1. FairPdrCubeLit construction and ordering
// ========================================================================

#[test]
fn cube_lit_construction_and_field_access() {
    let lit = FairPdrCubeLit {
        state_var_idx: 3,
        value: -7,
    };
    assert_eq!(lit.state_var_idx, 3);
    assert_eq!(lit.value, -7);
}

#[test]
fn cube_lit_ord_orders_by_idx_then_value() {
    let a = FairPdrCubeLit {
        state_var_idx: 1,
        value: 10,
    };
    let b = FairPdrCubeLit {
        state_var_idx: 2,
        value: 5,
    };
    let c = FairPdrCubeLit {
        state_var_idx: 1,
        value: 20,
    };
    assert!(a < b);
    assert!(a < c);
}

#[test]
fn cube_lit_equality() {
    let a = FairPdrCubeLit {
        state_var_idx: 0,
        value: 42,
    };
    let b = FairPdrCubeLit {
        state_var_idx: 0,
        value: 42,
    };
    let c = FairPdrCubeLit {
        state_var_idx: 0,
        value: 43,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ========================================================================
// 2. FairPdrCube
// ========================================================================

#[test]
fn cube_from_model_all_int_vars() {
    let state_vars = int_state_vars(&["x", "y", "z"]);
    let model = int_model(&[("x", 1), ("y", 2), ("z", 3)]);
    let cube = FairPdrCube::from_model(&model, &state_vars).unwrap();
    assert_eq!(cube.lits.len(), 3);
    assert_eq!(cube.lits[0].state_var_idx, 0);
    assert_eq!(cube.lits[0].value, 1);
    assert_eq!(cube.lits[1].value, 2);
    assert_eq!(cube.lits[2].value, 3);
}

#[test]
fn cube_from_model_returns_none_for_bool_sort() {
    let state_vars = vec![("x".to_string(), SmtSort::Bool)];
    let model = int_model(&[("x", 1)]);
    assert!(FairPdrCube::from_model(&model, &state_vars).is_none());
}

#[test]
fn cube_from_model_returns_none_for_missing_var() {
    let state_vars = int_state_vars(&["x", "y"]);
    let model = int_model(&[("x", 1)]); // missing "y"
    assert!(FairPdrCube::from_model(&model, &state_vars).is_none());
}

#[test]
fn cube_to_conjunction_single_lit() {
    let cube = make_cube(&[(0, 42)]);
    let vars = int_state_vars(&["alpha"]);
    let conj = cube.to_conjunction(&vars);
    let expected = SmtTerm::and(vec![SmtTerm::var("alpha").eq(SmtTerm::int(42))]);
    assert_eq!(conj, expected);
}

#[test]
fn cube_to_conjunction_empty_returns_true() {
    let cube = make_cube(&[]);
    let vars = int_state_vars(&["x"]);
    assert_eq!(cube.to_conjunction(&vars), SmtTerm::bool(true));
}

#[test]
fn cube_to_conjunction_non_int_sort_returns_false() {
    let cube = FairPdrCube {
        lits: vec![FairPdrCubeLit {
            state_var_idx: 0,
            value: 1,
        }],
    };
    let vars = vec![("x".to_string(), SmtSort::Bool)];
    assert_eq!(cube.to_conjunction(&vars), SmtTerm::bool(false));
}

#[test]
fn cube_to_block_clause_is_negation_of_conjunction() {
    let cube = make_cube(&[(0, 5)]);
    let vars = int_state_vars(&["v"]);
    let block = cube.to_block_clause(&vars);
    let expected = cube.to_conjunction(&vars).not();
    assert_eq!(block, expected);
}

#[test]
fn cube_subsumes_empty_subsumes_everything() {
    let empty = make_cube(&[]);
    let non_empty = make_cube(&[(0, 1), (1, 2)]);
    assert!(empty.subsumes(&non_empty));
    assert!(empty.subsumes(&empty));
}

#[test]
fn cube_subsumes_reflexive() {
    let cube = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    assert!(cube.subsumes(&cube));
}

#[test]
fn cube_subsumes_proper_subset() {
    let small = make_cube(&[(0, 1), (2, 3)]);
    let big = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    assert!(small.subsumes(&big));
    assert!(!big.subsumes(&small));
}

#[test]
fn cube_subsumes_different_values_no_subsumption() {
    let a = make_cube(&[(0, 1)]);
    let b = make_cube(&[(0, 2)]);
    assert!(!a.subsumes(&b));
    assert!(!b.subsumes(&a));
}

#[test]
fn cube_subsumes_disjoint_indices_no_subsumption() {
    let a = make_cube(&[(0, 1)]);
    let b = make_cube(&[(1, 1)]);
    assert!(!a.subsumes(&b));
}

// ========================================================================
// 3. FairPdrFrame
// ========================================================================

#[test]
fn frame_default_is_empty() {
    let frame = FairPdrFrame::default();
    assert!(frame.cubes.is_empty());
}

#[test]
fn frame_insert_and_contains() {
    let mut frame = FairPdrFrame::default();
    let cube = make_cube(&[(0, 1), (1, 2)]);
    frame.insert(cube.clone());
    assert!(frame.contains(&cube));
    assert_eq!(frame.cubes.len(), 1);
}

#[test]
fn frame_insert_removes_subsumed_cubes() {
    let mut frame = FairPdrFrame::default();
    let specific = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    frame.insert(specific.clone());
    assert!(frame.contains(&specific));

    let general = make_cube(&[(0, 1), (2, 3)]);
    frame.insert(general.clone());
    assert!(frame.contains(&general));
    assert!(!frame.contains(&specific));
    assert_eq!(frame.cubes.len(), 1);
}

#[test]
fn frame_insert_skips_when_existing_is_more_general() {
    let mut frame = FairPdrFrame::default();
    let general = make_cube(&[(0, 1)]);
    frame.insert(general.clone());

    let specific = make_cube(&[(0, 1), (1, 2)]);
    frame.insert(specific.clone());
    assert!(!frame.contains(&specific));
    assert_eq!(frame.cubes.len(), 1);
}

#[test]
fn frame_insert_multiple_independent_cubes() {
    let mut frame = FairPdrFrame::default();
    let c1 = make_cube(&[(0, 1)]);
    let c2 = make_cube(&[(1, 2)]);
    let c3 = make_cube(&[(2, 3)]);
    frame.insert(c1.clone());
    frame.insert(c2.clone());
    frame.insert(c3.clone());
    assert_eq!(frame.cubes.len(), 3);
    assert!(frame.contains(&c1));
    assert!(frame.contains(&c2));
    assert!(frame.contains(&c3));
}

#[test]
fn frame_equality() {
    let mut f1 = FairPdrFrame::default();
    let mut f2 = FairPdrFrame::default();
    assert_eq!(f1, f2);

    let cube = make_cube(&[(0, 1)]);
    f1.insert(cube.clone());
    assert_ne!(f1, f2);

    f2.insert(cube);
    assert_eq!(f1, f2);
}

// ========================================================================
// 4. Monitor naming functions
// ========================================================================

#[test]
fn mon_armed_format() {
    assert_eq!(mon_armed(0), "m_armed_0");
    assert_eq!(mon_armed(5), "m_armed_5");
}

#[test]
fn mon_choose_format() {
    assert_eq!(mon_choose(0), "m_choose_0");
    assert_eq!(mon_choose(3), "m_choose_3");
}

#[test]
fn mon_snap_kappa_format() {
    assert_eq!(mon_snap_kappa(1, 2), "m_snap_kappa_1_2");
    assert_eq!(mon_snap_kappa(0, 0), "m_snap_kappa_0_0");
}

#[test]
fn mon_snap_gamma_format() {
    assert_eq!(mon_snap_gamma(0, 3), "m_snap_g_0_3");
    assert_eq!(mon_snap_gamma(2, 1), "m_snap_g_2_1");
}

#[test]
fn mon_snap_clock_format() {
    assert_eq!(mon_snap_clock(0, 0), "m_snap_clk_0_0");
    assert_eq!(mon_snap_clock(1, 2), "m_snap_clk_1_2");
}

#[test]
fn mon_ce_format() {
    assert_eq!(mon_ce(0, 0), "m_ce_0_0");
    assert_eq!(mon_ce(3, 7), "m_ce_3_7");
}

#[test]
fn mon_fired_format() {
    assert_eq!(mon_fired(0, 0), "m_fired_0_0");
    assert_eq!(mon_fired(2, 4), "m_fired_2_4");
}

// ========================================================================
// 5. Bit helpers
// ========================================================================

#[test]
fn bit_is_true_constructs_eq_one() {
    let t = bit_is_true("flag".to_string());
    assert_eq!(t, SmtTerm::var("flag").eq(SmtTerm::int(1)));
}

#[test]
fn bit_is_false_constructs_eq_zero() {
    let t = bit_is_false("flag".to_string());
    assert_eq!(t, SmtTerm::var("flag").eq(SmtTerm::int(0)));
}

#[test]
fn bit_domain_ge_zero_le_one() {
    let d = bit_domain("v".to_string());
    assert_eq!(d.len(), 2);
    assert_eq!(d[0], SmtTerm::var("v").ge(SmtTerm::int(0)));
    assert_eq!(d[1], SmtTerm::var("v").le(SmtTerm::int(1)));
}

#[test]
fn bool_to_bit_ite_structure() {
    let cond = SmtTerm::var("c");
    let result = bool_to_bit(cond.clone());
    match result {
        SmtTerm::Ite(c, t, e) => {
            assert_eq!(*c, cond);
            assert_eq!(*t, SmtTerm::int(1));
            assert_eq!(*e, SmtTerm::int(0));
        }
        _ => panic!("expected Ite"),
    }
}

// ========================================================================
// 6. push_decl_unique
// ========================================================================

#[test]
fn push_decl_unique_adds_new_entry() {
    let mut decls = Vec::new();
    push_decl_unique(&mut decls, "x".to_string(), SmtSort::Int);
    assert_eq!(decls.len(), 1);
    assert_eq!(decls[0], ("x".to_string(), SmtSort::Int));
}

#[test]
fn push_decl_unique_skips_duplicate() {
    let mut decls = vec![("x".to_string(), SmtSort::Int)];
    push_decl_unique(&mut decls, "x".to_string(), SmtSort::Int);
    assert_eq!(decls.len(), 1);
}

#[test]
fn push_decl_unique_allows_different_names() {
    let mut decls = vec![("x".to_string(), SmtSort::Int)];
    push_decl_unique(&mut decls, "y".to_string(), SmtSort::Bool);
    assert_eq!(decls.len(), 2);
}

// ========================================================================
// 7. Budget functions
// ========================================================================

#[test]
fn bad_cube_budget_zero_inputs() {
    assert_eq!(fair_pdr_bad_cube_budget(0, 0), 5_000);
}

#[test]
fn bad_cube_budget_scales_with_state_and_frontier() {
    assert_eq!(fair_pdr_bad_cube_budget(10, 0), 5_000 + 10 * 120);
    assert_eq!(fair_pdr_bad_cube_budget(10, 5), 5_000 + 10 * 120 + 5 * 800);
}

#[test]
fn bad_cube_budget_clamped_to_max() {
    let result = fair_pdr_bad_cube_budget(100_000, 100_000);
    assert_eq!(result, 200_000);
}

#[test]
fn obligation_budget_zero_inputs() {
    assert_eq!(fair_pdr_obligation_budget(0, 0), 10_000);
}

#[test]
fn obligation_budget_scales_with_state_and_level() {
    assert_eq!(fair_pdr_obligation_budget(10, 0), 10_000 + 10 * 220);
    assert_eq!(
        fair_pdr_obligation_budget(10, 5),
        10_000 + 10 * 220 + 5 * 1500
    );
}

#[test]
fn obligation_budget_clamped_to_max() {
    let result = fair_pdr_obligation_budget(100_000, 100_000);
    assert_eq!(result, 300_000);
}

#[test]
fn single_literal_query_budget_scaling() {
    assert_eq!(fair_pdr_single_literal_query_budget(0), 128);
    assert_eq!(fair_pdr_single_literal_query_budget(4), 128 + 4 * 32);
    assert_eq!(fair_pdr_single_literal_query_budget(100_000), 16_384);
}

#[test]
fn pair_literal_query_budget_scaling() {
    assert_eq!(fair_pdr_pair_literal_query_budget(0), 0);
    assert_eq!(fair_pdr_pair_literal_query_budget(1), 0);
    assert_eq!(fair_pdr_pair_literal_query_budget(5), 10);
    assert_eq!(fair_pdr_pair_literal_query_budget(100_000), 2_048);
}

// ========================================================================
// 8. Literal priority and drop order
// ========================================================================

#[test]
fn literal_priority_monitor_class_zero() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 1,
    };
    let vars = int_state_vars(&["m_armed_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 0);
}

#[test]
fn literal_priority_time_class_zero() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 5,
    };
    let vars = int_state_vars(&["time_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 0);
}

#[test]
fn literal_priority_gamma_zero_class_one() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 0,
    };
    let vars = int_state_vars(&["g_0_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 1);
}

#[test]
fn literal_priority_gamma_nonzero_class_two() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 5,
    };
    let vars = int_state_vars(&["g_0_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 2);
}

#[test]
fn literal_priority_kappa_zero_class_three() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 0,
    };
    let vars = int_state_vars(&["kappa_0_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 3);
}

#[test]
fn literal_priority_kappa_nonzero_class_four() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 3,
    };
    let vars = int_state_vars(&["kappa_0_0"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 4);
}

#[test]
fn literal_priority_unknown_zero_class_five() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 0,
    };
    let vars = int_state_vars(&["foo"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 5);
}

#[test]
fn literal_priority_unknown_nonzero_class_six() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 9,
    };
    let vars = int_state_vars(&["foo"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 6);
}

#[test]
fn literal_priority_out_of_bounds_idx_defaults_class_five() {
    let lit = FairPdrCubeLit {
        state_var_idx: 99,
        value: 0,
    };
    let vars = int_state_vars(&["x"]);
    let (class, _) = fair_pdr_literal_priority(&lit, &vars);
    assert_eq!(class, 5);
}

#[test]
fn literal_drop_order_sorts_by_priority() {
    let vars = int_state_vars(&["kappa_0_0", "m_armed_0", "g_0_0", "time_0"]);
    let cube = FairPdrCube {
        lits: vec![
            FairPdrCubeLit {
                state_var_idx: 0,
                value: 5,
            },
            FairPdrCubeLit {
                state_var_idx: 1,
                value: 1,
            },
            FairPdrCubeLit {
                state_var_idx: 2,
                value: 3,
            },
            FairPdrCubeLit {
                state_var_idx: 3,
                value: 7,
            },
        ],
    };
    let order = fair_pdr_literal_drop_order(&cube, &vars);
    assert_eq!(order, vec![1, 3, 2, 0]);
}

#[test]
fn literal_drop_order_empty_cube() {
    let vars = int_state_vars(&["x"]);
    let cube = make_cube(&[]);
    let order = fair_pdr_literal_drop_order(&cube, &vars);
    assert!(order.is_empty());
}

// ========================================================================
// 9. rename_state_vars_in_term
// ========================================================================

#[test]
fn rename_var_present_in_map() {
    let mut map = HashMap::new();
    map.insert("x".to_string(), "y".to_string());
    let term = SmtTerm::var("x");
    let result = rename_state_vars_in_term(&term, &map);
    assert_eq!(result, SmtTerm::var("y"));
}

#[test]
fn rename_var_not_in_map_unchanged() {
    let map = HashMap::new();
    let term = SmtTerm::var("x");
    let result = rename_state_vars_in_term(&term, &map);
    assert_eq!(result, SmtTerm::var("x"));
}

#[test]
fn rename_literals_unchanged() {
    let map = HashMap::new();
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::int(42), &map),
        SmtTerm::int(42)
    );
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::bool(true), &map),
        SmtTerm::bool(true)
    );
}

#[test]
fn rename_nested_and_term() {
    let mut map = HashMap::new();
    map.insert("a".to_string(), "b".to_string());
    let term = SmtTerm::and(vec![
        SmtTerm::var("a").eq(SmtTerm::int(1)),
        SmtTerm::var("c").gt(SmtTerm::int(0)),
    ]);
    let result = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::and(vec![
        SmtTerm::var("b").eq(SmtTerm::int(1)),
        SmtTerm::var("c").gt(SmtTerm::int(0)),
    ]);
    assert_eq!(result, expected);
}

#[test]
fn rename_or_term() {
    let mut map = HashMap::new();
    map.insert("x".to_string(), "y".to_string());
    let term = SmtTerm::or(vec![SmtTerm::var("x"), SmtTerm::var("z")]);
    let result = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::or(vec![SmtTerm::var("y"), SmtTerm::var("z")]);
    assert_eq!(result, expected);
}

#[test]
fn rename_ite_term() {
    let mut map = HashMap::new();
    map.insert("x".to_string(), "y".to_string());
    let term = SmtTerm::Ite(
        Box::new(SmtTerm::var("x")),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::var("x")),
    );
    let result = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::Ite(
        Box::new(SmtTerm::var("y")),
        Box::new(SmtTerm::int(1)),
        Box::new(SmtTerm::var("y")),
    );
    assert_eq!(result, expected);
}

#[test]
fn rename_implies_term() {
    let mut map = HashMap::new();
    map.insert("p".to_string(), "q".to_string());
    let term = SmtTerm::var("p").implies(SmtTerm::var("r"));
    let result = rename_state_vars_in_term(&term, &map);
    let expected = SmtTerm::var("q").implies(SmtTerm::var("r"));
    assert_eq!(result, expected);
}

#[test]
fn rename_arithmetic_terms() {
    let mut map = HashMap::new();
    map.insert("a".to_string(), "b".to_string());

    let add = SmtTerm::var("a").add(SmtTerm::int(1));
    assert_eq!(
        rename_state_vars_in_term(&add, &map),
        SmtTerm::var("b").add(SmtTerm::int(1))
    );

    let sub = SmtTerm::var("a").sub(SmtTerm::int(1));
    assert_eq!(
        rename_state_vars_in_term(&sub, &map),
        SmtTerm::var("b").sub(SmtTerm::int(1))
    );

    let mul = SmtTerm::var("a").mul(SmtTerm::int(2));
    assert_eq!(
        rename_state_vars_in_term(&mul, &map),
        SmtTerm::var("b").mul(SmtTerm::int(2))
    );
}

#[test]
fn rename_comparison_terms() {
    let mut map = HashMap::new();
    map.insert("v".to_string(), "w".to_string());

    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::var("v").lt(SmtTerm::int(5)), &map),
        SmtTerm::var("w").lt(SmtTerm::int(5))
    );
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::var("v").le(SmtTerm::int(5)), &map),
        SmtTerm::var("w").le(SmtTerm::int(5))
    );
    assert_eq!(
        rename_state_vars_in_term(&SmtTerm::var("v").ge(SmtTerm::int(5)), &map),
        SmtTerm::var("w").ge(SmtTerm::int(5))
    );
}

#[test]
fn rename_not_term() {
    let mut map = HashMap::new();
    map.insert("x".to_string(), "y".to_string());
    let term = SmtTerm::not(SmtTerm::var("x"));
    let result = rename_state_vars_in_term(&term, &map);
    assert_eq!(result, SmtTerm::not(SmtTerm::var("y")));
}

// ========================================================================
// 10. fair_add_cube_up_to
// ========================================================================

#[test]
fn add_cube_up_to_adds_to_all_frames_in_range() {
    let mut frames = vec![
        FairPdrFrame::default(),
        FairPdrFrame::default(),
        FairPdrFrame::default(),
        FairPdrFrame::default(),
    ];
    let cube = make_cube(&[(0, 1)]);
    fair_add_cube_up_to(&mut frames, 2, cube.clone());
    assert!(!frames[0].contains(&cube));
    assert!(frames[1].contains(&cube));
    assert!(frames[2].contains(&cube));
    assert!(!frames[3].contains(&cube));
}

#[test]
fn add_cube_up_to_level_one() {
    let mut frames = vec![FairPdrFrame::default(), FairPdrFrame::default()];
    let cube = make_cube(&[(0, 5)]);
    fair_add_cube_up_to(&mut frames, 1, cube.clone());
    assert!(!frames[0].contains(&cube));
    assert!(frames[1].contains(&cube));
}

// ========================================================================
// 11. fair_cube_literal_to_term
// ========================================================================

#[test]
fn cube_literal_to_term_int_sort() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 42,
    };
    let vars = int_state_vars(&["x"]);
    let term = fair_cube_literal_to_term(&lit, &vars).unwrap();
    assert_eq!(term, SmtTerm::var("x").eq(SmtTerm::int(42)));
}

#[test]
fn cube_literal_to_term_bool_sort() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 1,
    };
    let vars = vec![("flag".to_string(), SmtSort::Bool)];
    let term = fair_cube_literal_to_term(&lit, &vars).unwrap();
    assert_eq!(term, SmtTerm::var("flag").eq(SmtTerm::bool(true)));
}

#[test]
fn cube_literal_to_term_bool_zero_is_false() {
    let lit = FairPdrCubeLit {
        state_var_idx: 0,
        value: 0,
    };
    let vars = vec![("flag".to_string(), SmtSort::Bool)];
    let term = fair_cube_literal_to_term(&lit, &vars).unwrap();
    assert_eq!(term, SmtTerm::var("flag").eq(SmtTerm::bool(false)));
}

#[test]
fn cube_literal_to_term_out_of_bounds_returns_none() {
    let lit = FairPdrCubeLit {
        state_var_idx: 5,
        value: 1,
    };
    let vars = int_state_vars(&["x"]);
    assert!(fair_cube_literal_to_term(&lit, &vars).is_none());
}

// ========================================================================
// 12. Enum variant constructibility
// ========================================================================

#[test]
fn fair_cube_query_result_variants_constructible() {
    let cube = make_cube(&[(0, 1)]);
    let _sat = FairCubeQueryResult::Sat(cube);
    let _unsat = FairCubeQueryResult::Unsat;
    let _unk = FairCubeQueryResult::Unknown("reason".into());
}

#[test]
fn fair_sat_query_result_variants_constructible() {
    let _sat = FairSatQueryResult::Sat;
    let _unsat = FairSatQueryResult::Unsat;
    let _unk = FairSatQueryResult::Unknown("reason".into());
}

#[test]
fn fair_blocking_outcome_variants_constructible() {
    let _blocked = FairBlockingOutcome::Blocked;
    let _cex = FairBlockingOutcome::Counterexample;
    let _unk = FairBlockingOutcome::Unknown("reason".into());
}

// ========================================================================
// 13. FairPdrInvariantCertificate fields
// ========================================================================

#[test]
fn fair_pdr_invariant_certificate_fields() {
    let cert = FairPdrInvariantCertificate {
        frame: 3,
        declarations: vec![("x".to_string(), SmtSort::Int)],
        init_assertions: vec![SmtTerm::bool(true)],
        transition_assertions: vec![SmtTerm::bool(true)],
        bad_pre: SmtTerm::bool(false),
        invariant_pre: vec![SmtTerm::bool(true)],
        invariant_post: vec![SmtTerm::bool(true)],
    };
    assert_eq!(cert.frame, 3);
    assert_eq!(cert.declarations.len(), 1);
    assert_eq!(cert.init_assertions.len(), 1);
    assert_eq!(cert.transition_assertions.len(), 1);
    assert_eq!(cert.invariant_pre.len(), 1);
    assert_eq!(cert.invariant_post.len(), 1);
}

// ========================================================================
// 14. build_fair_pdr_invariant_certificate
// ========================================================================

#[test]
fn build_certificate_empty_frame_has_only_state_assertions() {
    let artifacts = FairPdrArtifacts {
        declarations: vec![("x".to_string(), SmtSort::Int)],
        state_vars_pre: vec![("x_0".to_string(), SmtSort::Int)],
        state_vars_post: vec![("x_1".to_string(), SmtSort::Int)],
        state_assertions_pre: vec![SmtTerm::var("x_0").ge(SmtTerm::int(0))],
        init_assertions: vec![SmtTerm::var("x_0").eq(SmtTerm::int(0))],
        transition_assertions: vec![SmtTerm::bool(true)],
        bad_pre: SmtTerm::bool(false),
    };
    let frame = FairPdrFrame::default();
    let cert = build_fair_pdr_invariant_certificate(&artifacts, &frame, 2);
    assert_eq!(cert.frame, 2);
    assert_eq!(cert.invariant_pre.len(), 1);
    assert_eq!(cert.invariant_post.len(), 1);
    assert_eq!(
        cert.invariant_post[0],
        SmtTerm::var("x_1").ge(SmtTerm::int(0))
    );
}

#[test]
fn build_certificate_with_cube_adds_block_clause() {
    let artifacts = FairPdrArtifacts {
        declarations: vec![],
        state_vars_pre: vec![("a_0".to_string(), SmtSort::Int)],
        state_vars_post: vec![("a_1".to_string(), SmtSort::Int)],
        state_assertions_pre: vec![],
        init_assertions: vec![],
        transition_assertions: vec![],
        bad_pre: SmtTerm::bool(false),
    };
    let mut frame = FairPdrFrame::default();
    let cube = make_cube(&[(0, 5)]);
    frame.insert(cube.clone());
    let cert = build_fair_pdr_invariant_certificate(&artifacts, &frame, 1);
    assert_eq!(cert.invariant_pre.len(), 1);
    let expected_block = cube.to_block_clause(&artifacts.state_vars_pre);
    assert_eq!(cert.invariant_pre[0], expected_block);
}

// ========================================================================
// 15. PDR-04 generalization behavior
// ========================================================================

struct ScriptedSolver {
    supports_unsat_core: bool,
    check_sat_queue: VecDeque<SatResult>,
    check_sat_assuming_result: SatResult,
    check_sat_calls: usize,
    check_sat_assuming_calls: usize,
    last_assumptions: Vec<String>,
    core_take_first_only: bool,
}

impl Default for ScriptedSolver {
    fn default() -> Self {
        Self {
            supports_unsat_core: false,
            check_sat_queue: VecDeque::new(),
            check_sat_assuming_result: SatResult::Sat,
            check_sat_calls: 0,
            check_sat_assuming_calls: 0,
            last_assumptions: Vec::new(),
            core_take_first_only: false,
        }
    }
}

impl ScriptedSolver {
    fn with_unsat_core(result: SatResult, core_take_first_only: bool) -> Self {
        Self {
            supports_unsat_core: true,
            check_sat_assuming_result: result,
            core_take_first_only,
            ..Self::default()
        }
    }

    fn with_check_sat_queue(results: &[SatResult]) -> Self {
        Self {
            check_sat_queue: results.iter().cloned().collect(),
            ..Self::default()
        }
    }

    fn next_check_sat(&mut self) -> SatResult {
        self.check_sat_queue.pop_front().unwrap_or(SatResult::Sat)
    }
}

impl SmtSolver for ScriptedSolver {
    type Error = io::Error;

    fn declare_var(&mut self, _name: &str, _sort: &SmtSort) -> Result<(), Self::Error> {
        Ok(())
    }

    fn assert(&mut self, _term: &SmtTerm) -> Result<(), Self::Error> {
        Ok(())
    }

    fn push(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn pop(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn check_sat(&mut self) -> Result<SatResult, Self::Error> {
        self.check_sat_calls += 1;
        Ok(self.next_check_sat())
    }

    fn check_sat_with_model(
        &mut self,
        _var_names: &[(&str, &SmtSort)],
    ) -> Result<(SatResult, Option<Model>), Self::Error> {
        Ok((self.check_sat()?, None))
    }

    fn supports_assumption_unsat_core(&self) -> bool {
        self.supports_unsat_core
    }

    fn check_sat_assuming(&mut self, assumptions: &[String]) -> Result<SatResult, Self::Error> {
        self.check_sat_assuming_calls += 1;
        self.last_assumptions = assumptions.to_vec();
        Ok(self.check_sat_assuming_result.clone())
    }

    fn get_unsat_core_assumptions(&mut self) -> Result<Vec<String>, Self::Error> {
        if !self.supports_unsat_core || self.last_assumptions.is_empty() {
            return Ok(Vec::new());
        }
        if self.core_take_first_only {
            return Ok(vec![self.last_assumptions[0].clone()]);
        }
        Ok(self.last_assumptions.clone())
    }

    fn reset(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn generalization_artifacts() -> FairPdrArtifacts {
    FairPdrArtifacts {
        declarations: vec![
            ("m_armed_0".to_string(), SmtSort::Int),
            ("g_0_0".to_string(), SmtSort::Int),
            ("kappa_0_0".to_string(), SmtSort::Int),
            ("m_armed_1".to_string(), SmtSort::Int),
            ("g_1_0".to_string(), SmtSort::Int),
            ("kappa_1_0".to_string(), SmtSort::Int),
        ],
        state_vars_pre: vec![
            ("m_armed_0".to_string(), SmtSort::Int),
            ("g_0_0".to_string(), SmtSort::Int),
            ("kappa_0_0".to_string(), SmtSort::Int),
        ],
        state_vars_post: vec![
            ("m_armed_1".to_string(), SmtSort::Int),
            ("g_1_0".to_string(), SmtSort::Int),
            ("kappa_1_0".to_string(), SmtSort::Int),
        ],
        state_assertions_pre: Vec::new(),
        init_assertions: Vec::new(),
        transition_assertions: Vec::new(),
        bad_pre: SmtTerm::bool(false),
    }
}

#[test]
fn generalization_prefers_unsat_core_before_literal_dropping() {
    let artifacts = generalization_artifacts();
    let frames = vec![FairPdrFrame::default(), FairPdrFrame::default()];
    let cube = make_cube(&[(0, 1), (1, 2), (2, 3)]);
    let mut solver = ScriptedSolver::with_unsat_core(SatResult::Unsat, true);

    let (generalized, reason) =
        fair_try_generalize_cube(&mut solver, &artifacts, &frames, 1, &cube, &[], None)
            .expect("generalization should succeed");

    assert!(reason.is_none());
    let generalized = generalized.expect("core-based cube expected");
    assert_eq!(generalized.lits.len(), 1);
    assert_eq!(solver.check_sat_assuming_calls, 1);
    assert_eq!(
        solver.check_sat_calls, 0,
        "single/pair literal dropping should not run when core generalization succeeds"
    );
}

#[test]
fn generalization_fallback_uses_priority_guided_literal_dropping() {
    let artifacts = generalization_artifacts();
    let frames = vec![FairPdrFrame::default(), FairPdrFrame::default()];
    let cube = make_cube(&[(0, 1), (1, 7), (2, 3)]);
    let mut solver = ScriptedSolver::with_check_sat_queue(&[
        SatResult::Sat,   // dropping monitor literal (idx=0) fails
        SatResult::Unsat, // dropping gamma literal (idx=1) succeeds
        SatResult::Sat,   // no further single literal drop from reduced cube
        SatResult::Sat,
    ]);

    let (generalized, reason) =
        fair_try_generalize_cube(&mut solver, &artifacts, &frames, 1, &cube, &[], None)
            .expect("generalization should succeed");

    assert!(reason.is_none());
    let generalized = generalized.expect("literal-drop generalized cube expected");
    assert_eq!(generalized.lits.len(), 2);
    assert!(
        generalized.lits.iter().all(|lit| lit.state_var_idx != 1),
        "gamma literal should be dropped in fallback generalization"
    );
    assert!(
        solver.check_sat_calls >= 2,
        "fallback path should exercise predecessor SAT checks"
    );
}
