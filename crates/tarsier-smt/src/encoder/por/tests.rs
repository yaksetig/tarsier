use super::*;

fn make_lc(constant: i64, terms: Vec<(i64, usize)>) -> LinearCombination {
    LinearCombination {
        constant,
        terms: terms.into_iter().map(|(c, p)| (c, p.into())).collect(),
    }
}

fn make_guard_atom_t(
    vars: Vec<usize>,
    op: CmpOp,
    constant: i64,
    terms: Vec<(i64, usize)>,
    distinct: bool,
) -> GuardAtom {
    GuardAtom::Threshold {
        vars: vars.into_iter().map(Into::into).collect(),
        op,
        bound: make_lc(constant, terms),
        distinct,
    }
}

fn make_guard_t(atoms: Vec<GuardAtom>) -> Guard {
    Guard { atoms }
}

fn make_rule_t(from: usize, to: usize, guard: Guard, updates: Vec<Update>) -> Rule {
    Rule {
        from: from.into(),
        to: to.into(),
        guard,
        updates,
        collection_updates: vec![],
        clock_guards: vec![],
        clock_updates: vec![],
        param_updates: vec![],
    }
}

#[test]
fn lc_signature_constant_only() {
    let lc = make_lc(42, vec![]);
    assert_eq!(linear_combination_signature(&lc), "c=42");
}

#[test]
fn lc_signature_with_terms_sorted() {
    let lc = make_lc(1, vec![(3, 2), (1, 0)]);
    let sig = linear_combination_signature(&lc);
    assert_eq!(sig, "c=1|1*p0|3*p2");
}

#[test]
fn normalized_vars_dedup_and_sort() {
    assert_eq!(normalized_vars(&[3usize, 1, 2, 1, 3]), vec![1, 2, 3]);
}

#[test]
fn normalized_vars_empty() {
    let empty: &[usize] = &[];
    assert_eq!(normalized_vars(empty), Vec::<usize>::new());
}

#[test]
fn normalized_lc_terms_merges_and_drops_zeros() {
    let lc = make_lc(0, vec![(2, 0), (3, 1), (-2, 0)]);
    assert_eq!(normalized_lc_terms(&lc), vec![(3, 1)]);
}

#[test]
fn normalized_lc_terms_skips_zero_coefficients() {
    let lc = make_lc(5, vec![(0, 0), (1, 1)]);
    assert_eq!(normalized_lc_terms(&lc), vec![(1, 1)]);
}

#[test]
fn comparable_lc_constants_same_terms() {
    let lhs = make_lc(10, vec![(1, 0)]);
    let rhs = make_lc(20, vec![(1, 0)]);
    assert_eq!(comparable_lc_constants(&lhs, &rhs), Some((10, 20)));
}

#[test]
fn comparable_lc_constants_different_terms() {
    let lhs = make_lc(10, vec![(1, 0)]);
    let rhs = make_lc(20, vec![(2, 0)]);
    assert_eq!(comparable_lc_constants(&lhs, &rhs), None);
}

#[test]
fn threshold_op_entails_eq_cases() {
    assert!(threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 5));
    assert!(!threshold_op_entails(CmpOp::Eq, 5, CmpOp::Eq, 6));
    assert!(threshold_op_entails(CmpOp::Eq, 5, CmpOp::Ge, 3));
    assert!(threshold_op_entails(CmpOp::Eq, 5, CmpOp::Gt, 4));
    assert!(!threshold_op_entails(CmpOp::Eq, 5, CmpOp::Gt, 5));
    assert!(threshold_op_entails(CmpOp::Eq, 5, CmpOp::Ne, 6));
    assert!(!threshold_op_entails(CmpOp::Eq, 5, CmpOp::Ne, 5));
}

#[test]
fn threshold_op_entails_ge_gt_cases() {
    assert!(threshold_op_entails(CmpOp::Ge, 5, CmpOp::Ge, 3));
    assert!(!threshold_op_entails(CmpOp::Ge, 3, CmpOp::Ge, 5));
    assert!(threshold_op_entails(CmpOp::Gt, 5, CmpOp::Gt, 3));
    assert!(threshold_op_entails(CmpOp::Gt, 5, CmpOp::Ge, 5));
}

#[test]
fn threshold_op_entails_incompatible_directions() {
    assert!(!threshold_op_entails(CmpOp::Ge, 5, CmpOp::Lt, 10));
    assert!(!threshold_op_entails(CmpOp::Lt, 5, CmpOp::Ge, 0));
    assert!(!threshold_op_entails(CmpOp::Ne, 5, CmpOp::Eq, 5));
}

#[test]
fn guard_atom_implies_stronger_bound() {
    let lhs = make_guard_atom_t(vec![0], CmpOp::Ge, 5, vec![], false);
    let rhs = make_guard_atom_t(vec![0], CmpOp::Ge, 3, vec![], false);
    assert!(guard_atom_implies(&lhs, &rhs));
    assert!(!guard_atom_implies(&rhs, &lhs));
}

#[test]
fn guard_atom_implies_different_vars() {
    let lhs = make_guard_atom_t(vec![0], CmpOp::Ge, 5, vec![], false);
    let rhs = make_guard_atom_t(vec![1], CmpOp::Ge, 3, vec![], false);
    assert!(!guard_atom_implies(&lhs, &rhs));
}

#[test]
fn guard_atom_implies_different_distinct() {
    let lhs = make_guard_atom_t(vec![0], CmpOp::Ge, 5, vec![], false);
    let rhs = make_guard_atom_t(vec![0], CmpOp::Ge, 3, vec![], true);
    assert!(!guard_atom_implies(&lhs, &rhs));
}

#[test]
fn guard_implies_empty_rhs_always_true() {
    let lhs = make_guard_t(vec![make_guard_atom_t(
        vec![0],
        CmpOp::Ge,
        5,
        vec![],
        false,
    )]);
    let rhs = make_guard_t(vec![]);
    assert!(guard_implies(&lhs, &rhs));
}

#[test]
fn guard_implies_subset() {
    let a1 = make_guard_atom_t(vec![0], CmpOp::Ge, 5, vec![], false);
    let a2 = make_guard_atom_t(vec![1], CmpOp::Le, 3, vec![], false);
    let lhs = make_guard_t(vec![a1, a2]);
    let rhs = make_guard_t(vec![make_guard_atom_t(
        vec![0],
        CmpOp::Ge,
        3,
        vec![],
        false,
    )]);
    assert!(guard_implies(&lhs, &rhs));
}

#[test]
fn stutter_rule_detected() {
    let rule = make_rule_t(0, 0, make_guard_t(vec![]), vec![]);
    assert!(is_pure_stutter_rule(&rule));
}

#[test]
fn non_stutter_rule_move() {
    let rule = make_rule_t(0, 1, make_guard_t(vec![]), vec![]);
    assert!(!is_pure_stutter_rule(&rule));
}

#[test]
fn non_stutter_rule_update() {
    let rule = make_rule_t(
        0,
        0,
        make_guard_t(vec![]),
        vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
    );
    assert!(!is_pure_stutter_rule(&rule));
}

#[test]
fn parse_counter_with_recipient() {
    let result = message_family_and_recipient_from_counter_name("cnt_vote@Alice");
    assert_eq!(
        result,
        Some(("vote".to_string(), Some("Alice".to_string())))
    );
}

#[test]
fn parse_counter_with_sender_arrow() {
    let result = message_family_and_recipient_from_counter_name("cnt_vote@Alice<-Bob");
    assert_eq!(
        result,
        Some(("vote".to_string(), Some("Alice".to_string())))
    );
}

#[test]
fn parse_counter_no_at() {
    let result = message_family_and_recipient_from_counter_name("cnt_echo");
    assert_eq!(result, Some(("echo".to_string(), None)));
}

#[test]
fn parse_counter_invalid_prefix() {
    assert_eq!(
        message_family_and_recipient_from_counter_name("vote@Alice"),
        None
    );
}

#[test]
fn parse_sender_with_arrow() {
    let result = message_family_and_sender_from_counter_name("cnt_vote@Alice<-Bob");
    assert_eq!(result, Some(("vote".to_string(), Some("Bob".to_string()))));
}

#[test]
fn parse_sender_no_arrow() {
    let result = message_family_and_sender_from_counter_name("cnt_vote@Alice");
    assert_eq!(result, Some(("vote".to_string(), None)));
}

#[test]
fn sender_channel_role_with_hash() {
    assert_eq!(sender_channel_role("Replica#3"), "Replica");
}

#[test]
fn sender_channel_role_no_hash() {
    assert_eq!(sender_channel_role("Leader"), "Leader");
}

#[test]
fn variant_and_family_with_at() {
    let result = message_variant_and_family_from_counter_name("cnt_vote@Alice[v=1]");
    assert_eq!(result, Some(("vote[v=1]".to_string(), "vote".to_string())));
}

#[test]
fn variant_and_family_no_at() {
    let result = message_variant_and_family_from_counter_name("cnt_echo");
    assert_eq!(result, Some(("echo".to_string(), "echo".to_string())));
}

#[test]
fn sum_balanced_empty_is_zero() {
    assert_eq!(sum_terms_balanced(vec![]), SmtTerm::int(0));
}

#[test]
fn sum_balanced_single() {
    let term = SmtTerm::int(42);
    assert_eq!(sum_terms_balanced(vec![term.clone()]), term);
}

#[test]
fn sum_balanced_two() {
    let a = SmtTerm::int(1);
    let b = SmtTerm::int(2);
    assert_eq!(sum_terms_balanced(vec![a.clone(), b.clone()]), a.add(b));
}

#[test]
fn update_signature_increment() {
    let u = Update {
        var: 3.into(),
        kind: UpdateKind::Increment,
    };
    assert_eq!(update_signature(&u), "inc@3");
}

#[test]
fn update_signature_set() {
    let u = Update {
        var: 1.into(),
        kind: UpdateKind::Set(make_lc(5, vec![])),
    };
    assert_eq!(update_signature(&u), "set@1=c=5");
}

#[test]
fn rule_effect_signature_basic() {
    let rule = make_rule_t(
        0,
        1,
        make_guard_t(vec![]),
        vec![Update {
            var: 0.into(),
            kind: UpdateKind::Increment,
        }],
    );
    assert_eq!(rule_effect_signature(&rule), "from=0;to=1;updates=[inc@0]");
}

#[test]
fn por_off_mode_disables_nothing() {
    let mut ta = ThresholdAutomaton::new();
    ta.semantics.por_mode = PorMode::Off;
    ta.rules
        .push(make_rule_t(0, 0, make_guard_t(vec![]), vec![]));
    let pruning = compute_por_rule_pruning(&ta);
    assert!(!pruning.is_disabled(0));
    assert_eq!(pruning.stutter_pruned, 0);
}

#[test]
fn por_static_prunes_stutter() {
    let mut ta = ThresholdAutomaton::new();
    ta.semantics.por_mode = PorMode::Static;
    ta.rules
        .push(make_rule_t(0, 0, make_guard_t(vec![]), vec![]));
    ta.rules
        .push(make_rule_t(0, 1, make_guard_t(vec![]), vec![]));
    let pruning = compute_por_rule_pruning(&ta);
    assert!(pruning.is_disabled(0));
    assert!(!pruning.is_disabled(1));
    assert_eq!(pruning.stutter_pruned, 1);
    assert_eq!(pruning.active_rule_ids(), vec![1]);
}
