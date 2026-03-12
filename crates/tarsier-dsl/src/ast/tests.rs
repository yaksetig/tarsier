use super::*;

// ---------------------------------------------------------------
// Span & Spanned
// ---------------------------------------------------------------

#[test]
fn span_construction_and_fields() {
    let s = Span::new(10, 20);
    assert_eq!(s.start, 10);
    assert_eq!(s.end, 20);
}

#[test]
fn span_equality() {
    assert_eq!(Span::new(0, 5), Span::new(0, 5));
    assert_ne!(Span::new(0, 5), Span::new(0, 6));
}

#[test]
fn spanned_construction_and_fields() {
    let span = Span::new(1, 2);
    let spanned = Spanned::new(42_i32, span);
    assert_eq!(spanned.node, 42);
    assert_eq!(spanned.span, Span::new(1, 2));
}

// ---------------------------------------------------------------
// CmpOp Display
// ---------------------------------------------------------------

#[test]
fn display_cmp_op_all_variants() {
    assert_eq!(CmpOp::Ge.to_string(), ">=");
    assert_eq!(CmpOp::Le.to_string(), "<=");
    assert_eq!(CmpOp::Gt.to_string(), ">");
    assert_eq!(CmpOp::Lt.to_string(), "<");
    assert_eq!(CmpOp::Eq.to_string(), "==");
    assert_eq!(CmpOp::Ne.to_string(), "!=");
}

// ---------------------------------------------------------------
// LinearExpr Display
// ---------------------------------------------------------------

#[test]
fn display_linear_expr_const() {
    assert_eq!(LinearExpr::Const(42).to_string(), "42");
    assert_eq!(LinearExpr::Const(-1).to_string(), "-1");
    assert_eq!(LinearExpr::Const(0).to_string(), "0");
}

#[test]
fn display_linear_expr_var() {
    assert_eq!(LinearExpr::Var("n".into()).to_string(), "n");
}

#[test]
fn display_linear_expr_add() {
    let expr = LinearExpr::Add(
        Box::new(LinearExpr::Var("n".into())),
        Box::new(LinearExpr::Const(1)),
    );
    assert_eq!(expr.to_string(), "(n + 1)");
}

#[test]
fn display_linear_expr_sub() {
    let expr = LinearExpr::Sub(
        Box::new(LinearExpr::Var("n".into())),
        Box::new(LinearExpr::Var("t".into())),
    );
    assert_eq!(expr.to_string(), "(n - t)");
}

#[test]
fn display_linear_expr_mul() {
    let expr = LinearExpr::Mul(3, Box::new(LinearExpr::Var("t".into())));
    assert_eq!(expr.to_string(), "3*t");
}

#[test]
fn display_linear_expr_nested() {
    // 2*t + 1
    let expr = LinearExpr::Add(
        Box::new(LinearExpr::Mul(2, Box::new(LinearExpr::Var("t".into())))),
        Box::new(LinearExpr::Const(1)),
    );
    assert_eq!(expr.to_string(), "(2*t + 1)");
}

// ---------------------------------------------------------------
// Expr Display
// ---------------------------------------------------------------

#[test]
fn display_expr_literals_and_var() {
    assert_eq!(Expr::IntLit(7).to_string(), "7");
    assert_eq!(Expr::BoolLit(true).to_string(), "true");
    assert_eq!(Expr::BoolLit(false).to_string(), "false");
    assert_eq!(Expr::Var("x".into()).to_string(), "x");
}

#[test]
fn display_expr_arithmetic() {
    let add = Expr::Add(Box::new(Expr::Var("x".into())), Box::new(Expr::IntLit(1)));
    assert_eq!(add.to_string(), "(x + 1)");

    let sub = Expr::Sub(
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    assert_eq!(sub.to_string(), "(a - b)");

    let mul = Expr::Mul(Box::new(Expr::IntLit(2)), Box::new(Expr::Var("y".into())));
    assert_eq!(mul.to_string(), "(2 * y)");

    let div = Expr::Div(Box::new(Expr::Var("z".into())), Box::new(Expr::IntLit(3)));
    assert_eq!(div.to_string(), "(z / 3)");
}

#[test]
fn display_expr_not_and_neg() {
    let not = Expr::Not(Box::new(Expr::BoolLit(true)));
    assert_eq!(not.to_string(), "!true");

    let neg = Expr::Neg(Box::new(Expr::IntLit(5)));
    assert_eq!(neg.to_string(), "-5");
}

// ---------------------------------------------------------------
// FormulaAtom Display
// ---------------------------------------------------------------

#[test]
fn display_formula_atom_all_variants() {
    assert_eq!(FormulaAtom::IntLit(99).to_string(), "99");
    assert_eq!(FormulaAtom::BoolLit(true).to_string(), "true");
    assert_eq!(FormulaAtom::Var("decided".into()).to_string(), "decided");
    assert_eq!(
        FormulaAtom::QualifiedVar {
            object: "p".into(),
            field: "phase".into(),
        }
        .to_string(),
        "p.phase"
    );
}

// ---------------------------------------------------------------
// FormulaExpr::is_binary
// ---------------------------------------------------------------

fn atom_cmp() -> FormulaExpr {
    FormulaExpr::Comparison {
        lhs: FormulaAtom::Var("x".into()),
        op: CmpOp::Eq,
        rhs: FormulaAtom::IntLit(1),
    }
}

#[test]
fn is_binary_returns_true_for_binary_ops() {
    let a = Box::new(atom_cmp());
    let b = Box::new(atom_cmp());
    assert!(FormulaExpr::And(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::Or(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::Implies(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::Iff(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::Until(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::WeakUntil(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::Release(a.clone(), b.clone()).is_binary());
    assert!(FormulaExpr::LeadsTo(a.clone(), b.clone()).is_binary());
}

#[test]
fn is_binary_returns_false_for_non_binary_variants() {
    assert!(!atom_cmp().is_binary());
    assert!(!FormulaExpr::Not(Box::new(atom_cmp())).is_binary());
    assert!(!FormulaExpr::Next(Box::new(atom_cmp())).is_binary());
    assert!(!FormulaExpr::Always(Box::new(atom_cmp())).is_binary());
    assert!(!FormulaExpr::Eventually(Box::new(atom_cmp())).is_binary());
}

// ---------------------------------------------------------------
// FormulaExpr Display (unary operators)
// ---------------------------------------------------------------

#[test]
fn display_formula_comparison() {
    let f = FormulaExpr::Comparison {
        lhs: FormulaAtom::Var("x".into()),
        op: CmpOp::Ge,
        rhs: FormulaAtom::IntLit(5),
    };
    assert_eq!(f.to_string(), "x >= 5");
}

#[test]
fn display_formula_not_with_atom() {
    let f = FormulaExpr::Not(Box::new(atom_cmp()));
    assert_eq!(f.to_string(), "!x == 1");
}

#[test]
fn display_formula_not_with_binary_adds_parens() {
    let inner = FormulaExpr::And(Box::new(atom_cmp()), Box::new(atom_cmp()));
    let f = FormulaExpr::Not(Box::new(inner));
    assert_eq!(f.to_string(), "!(x == 1 && x == 1)");
}

#[test]
fn display_formula_temporal_unary() {
    let next = FormulaExpr::Next(Box::new(atom_cmp()));
    assert_eq!(next.to_string(), "X x == 1");

    let always = FormulaExpr::Always(Box::new(atom_cmp()));
    assert_eq!(always.to_string(), "[] x == 1");

    let eventually = FormulaExpr::Eventually(Box::new(atom_cmp()));
    assert_eq!(eventually.to_string(), "<> x == 1");
}

#[test]
fn display_formula_temporal_unary_with_binary_inner() {
    let binary = FormulaExpr::Or(Box::new(atom_cmp()), Box::new(atom_cmp()));
    let next = FormulaExpr::Next(Box::new(binary.clone()));
    assert_eq!(next.to_string(), "X (x == 1 || x == 1)");

    let always = FormulaExpr::Always(Box::new(binary.clone()));
    assert_eq!(always.to_string(), "[] (x == 1 || x == 1)");

    let eventually = FormulaExpr::Eventually(Box::new(binary));
    assert_eq!(eventually.to_string(), "<> (x == 1 || x == 1)");
}

// ---------------------------------------------------------------
// FormulaExpr Display (binary operators & parenthesization)
// ---------------------------------------------------------------

#[test]
fn display_formula_binary_operators() {
    let a = Box::new(atom_cmp());
    let b = Box::new(atom_cmp());

    assert_eq!(
        FormulaExpr::And(a.clone(), b.clone()).to_string(),
        "x == 1 && x == 1"
    );
    assert_eq!(
        FormulaExpr::Or(a.clone(), b.clone()).to_string(),
        "x == 1 || x == 1"
    );
    assert_eq!(
        FormulaExpr::Implies(a.clone(), b.clone()).to_string(),
        "x == 1 ==> x == 1"
    );
    assert_eq!(
        FormulaExpr::Iff(a.clone(), b.clone()).to_string(),
        "x == 1 <=> x == 1"
    );
    assert_eq!(
        FormulaExpr::Until(a.clone(), b.clone()).to_string(),
        "x == 1 U x == 1"
    );
    assert_eq!(
        FormulaExpr::WeakUntil(a.clone(), b.clone()).to_string(),
        "x == 1 W x == 1"
    );
    assert_eq!(
        FormulaExpr::Release(a.clone(), b.clone()).to_string(),
        "x == 1 R x == 1"
    );
    assert_eq!(
        FormulaExpr::LeadsTo(a.clone(), b.clone()).to_string(),
        "x == 1 ~> x == 1"
    );
}

#[test]
fn display_formula_right_child_binary_gets_parens() {
    // Right child is a binary op => should be parenthesized
    let inner_and = FormulaExpr::And(Box::new(atom_cmp()), Box::new(atom_cmp()));
    let outer = FormulaExpr::Or(Box::new(atom_cmp()), Box::new(inner_and));
    assert_eq!(outer.to_string(), "x == 1 || (x == 1 && x == 1)");
}

#[test]
fn display_formula_left_child_binary_no_parens() {
    // Left child is a binary op => should NOT be parenthesized (left-associative)
    let inner_and = FormulaExpr::And(Box::new(atom_cmp()), Box::new(atom_cmp()));
    let outer = FormulaExpr::Or(Box::new(inner_and), Box::new(atom_cmp()));
    assert_eq!(outer.to_string(), "x == 1 && x == 1 || x == 1");
}

// ---------------------------------------------------------------
// Quantifier Display
// ---------------------------------------------------------------

#[test]
fn display_quantifier() {
    assert_eq!(Quantifier::ForAll.to_string(), "forall");
    assert_eq!(Quantifier::Exists.to_string(), "exists");
}

// ---------------------------------------------------------------
// PropertyKind Display
// ---------------------------------------------------------------

#[test]
fn display_property_kind_all_variants() {
    assert_eq!(PropertyKind::Agreement.to_string(), "agreement");
    assert_eq!(PropertyKind::Validity.to_string(), "validity");
    assert_eq!(PropertyKind::Safety.to_string(), "safety");
    assert_eq!(PropertyKind::Invariant.to_string(), "invariant");
    assert_eq!(PropertyKind::Liveness.to_string(), "liveness");
}

// ---------------------------------------------------------------
// QuantifiedFormula Display
// ---------------------------------------------------------------

#[test]
fn display_quantified_formula_no_quantifiers() {
    let qf = QuantifiedFormula {
        quantifiers: vec![],
        body: atom_cmp(),
    };
    assert_eq!(qf.to_string(), "x == 1");
}

#[test]
fn display_quantified_formula_single_quantifier() {
    let qf = QuantifiedFormula {
        quantifiers: vec![QuantifierBinding {
            quantifier: Quantifier::ForAll,
            var: "p".into(),
            domain: "Replica".into(),
        }],
        body: atom_cmp(),
    };
    assert_eq!(qf.to_string(), "forall p: Replica. x == 1");
}

#[test]
fn display_quantified_formula_multiple_quantifiers() {
    let qf = QuantifiedFormula {
        quantifiers: vec![
            QuantifierBinding {
                quantifier: Quantifier::ForAll,
                var: "p".into(),
                domain: "Replica".into(),
            },
            QuantifierBinding {
                quantifier: Quantifier::Exists,
                var: "q".into(),
                domain: "Replica".into(),
            },
        ],
        body: atom_cmp(),
    };
    assert_eq!(
        qf.to_string(),
        "forall p: Replica. exists q: Replica. x == 1"
    );
}

// ---------------------------------------------------------------
// PropertyDecl Display
// ---------------------------------------------------------------

#[test]
fn display_property_decl() {
    let decl = PropertyDecl {
        name: "agreement_prop".into(),
        kind: PropertyKind::Agreement,
        formula: QuantifiedFormula {
            quantifiers: vec![QuantifierBinding {
                quantifier: Quantifier::ForAll,
                var: "p".into(),
                domain: "Replica".into(),
            }],
            body: atom_cmp(),
        },
    };
    let expected = "property agreement_prop: agreement {\n    forall p: Replica. x == 1\n}";
    assert_eq!(decl.to_string(), expected);
}
