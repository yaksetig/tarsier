/// Source span for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// A spanned AST node.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }
}

/// Top-level program = a single protocol declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct Program {
    pub protocol: Spanned<ProtocolDecl>,
}

/// Protocol declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ProtocolDecl {
    pub name: String,
    pub imports: Vec<ImportDecl>,
    pub modules: Vec<ModuleDecl>,
    pub enums: Vec<EnumDecl>,
    pub parameters: Vec<ParamDef>,
    pub resilience: Option<ResilienceDecl>,
    pub pacemaker: Option<PacemakerDecl>,
    pub adversary: Vec<AdversaryItem>,
    pub identities: Vec<IdentityDecl>,
    pub channels: Vec<ChannelDecl>,
    pub equivocation_policies: Vec<EquivocationDecl>,
    pub committees: Vec<CommitteeDecl>,
    pub messages: Vec<MessageDecl>,
    pub crypto_objects: Vec<CryptoObjectDecl>,
    pub roles: Vec<Spanned<RoleDecl>>,
    pub properties: Vec<Spanned<PropertyDecl>>,
}

/// Import declaration: `import ModuleName from "path";`
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ImportDecl {
    pub name: String,
    pub path: String,
    pub span: Span,
}

/// Module declaration with optional interface contract.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ModuleDecl {
    pub name: String,
    pub interface: Option<ModuleInterface>,
    pub items: ModuleItems,
    pub span: Span,
}

/// Module interface with assume/guarantee clauses.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ModuleInterface {
    pub assumptions: Vec<InterfaceAssumption>,
    pub guarantees: Vec<InterfaceGuarantee>,
}

/// An assumption in a module interface.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct InterfaceAssumption {
    pub lhs: LinearExpr,
    pub op: CmpOp,
    pub rhs: LinearExpr,
    pub span: Span,
}

/// A guarantee in a module interface.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct InterfaceGuarantee {
    pub kind: PropertyKind,
    pub property_name: String,
    pub span: Span,
}

/// Items that can appear inside a module (subset of protocol items).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ModuleItems {
    pub parameters: Vec<ParamDef>,
    pub resilience: Option<ResilienceDecl>,
    pub adversary: Vec<AdversaryItem>,
    pub messages: Vec<MessageDecl>,
    pub roles: Vec<Spanned<RoleDecl>>,
    pub properties: Vec<Spanned<PropertyDecl>>,
}

/// Pacemaker configuration (automatic view changes).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct PacemakerDecl {
    pub view_var: String,
    pub start_phase: String,
    pub reset_vars: Vec<String>,
}

/// Enum declaration (finite domain).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct EnumDecl {
    pub name: String,
    pub variants: Vec<String>,
    pub span: Span,
}

/// Parameter definition (e.g., `n: nat;`)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ParamDef {
    pub name: String,
    pub ty: ParamType,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum ParamType {
    Nat,
    Int,
}

/// Resilience condition (e.g., `n > 3*t`)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ResilienceDecl {
    pub condition: ResilienceExpr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ResilienceExpr {
    pub lhs: LinearExpr,
    pub op: CmpOp,
    pub rhs: LinearExpr,
}

/// Adversary model items (e.g., `model: byzantine;`)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct AdversaryItem {
    pub key: String,
    pub value: String,
    pub span: Span,
}

/// Identity declaration for a role.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct IdentityDecl {
    pub role: String,
    pub scope: IdentityScope,
    /// Process identity variable (required when `scope=process`).
    pub process_var: Option<String>,
    /// Optional key namespace/label for this role identity.
    pub key: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum IdentityScope {
    Role,
    Process,
}

/// Per-message channel authentication declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ChannelDecl {
    pub message: String,
    pub auth: ChannelAuthMode,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum ChannelAuthMode {
    Authenticated,
    Unauthenticated,
}

/// Per-message equivocation policy declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct EquivocationDecl {
    pub message: String,
    pub mode: EquivocationPolicyMode,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum EquivocationPolicyMode {
    Full,
    None,
}

/// Committee selection declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct CommitteeDecl {
    pub name: String,
    pub items: Vec<CommitteeItem>,
    pub span: Span,
}

/// A key-value item in a committee declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct CommitteeItem {
    pub key: String,
    pub value: CommitteeValue,
    pub span: Span,
}

/// Value in a committee declaration item.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum CommitteeValue {
    /// A parameter reference.
    Param(String),
    /// An integer constant.
    Int(i64),
    /// A floating-point constant (e.g., for epsilon).
    Float(f64),
}

/// First-class cryptographic object declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct CryptoObjectDecl {
    pub name: String,
    pub kind: CryptoObjectKind,
    pub source_message: String,
    pub threshold: LinearExpr,
    pub signer_role: Option<String>,
    pub conflict_policy: CryptoConflictPolicy,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum CryptoObjectKind {
    QuorumCertificate,
    ThresholdSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum CryptoConflictPolicy {
    /// No extra admissibility constraints on conflicting variants.
    Allow,
    /// Conflicting variants are disallowed at a recipient.
    Exclusive,
}

/// Message type declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct MessageDecl {
    pub name: String,
    pub fields: Vec<FieldDef>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct FieldDef {
    pub name: String,
    pub ty: String,
    pub range: Option<VarRange>,
}

/// Role declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct RoleDecl {
    pub name: String,
    pub vars: Vec<VarDecl>,
    pub init_phase: Option<String>,
    pub phases: Vec<Spanned<PhaseDecl>>,
}

/// Local variable declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct VarDecl {
    pub name: String,
    pub ty: VarType,
    pub range: Option<VarRange>,
    pub init: Option<Expr>,
    pub span: Span,
}

/// Optional range for integer/nat local variables.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct VarRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum VarType {
    Bool,
    Nat,
    Int,
    Enum(String),
}

/// Phase (local state in the automaton).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct PhaseDecl {
    pub name: String,
    pub transitions: Vec<Spanned<TransitionRule>>,
}

/// Transition rule: `when guard => { actions }`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct TransitionRule {
    pub guard: GuardExpr,
    pub actions: Vec<Action>,
}

/// Guard expression.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum GuardExpr {
    Threshold(ThresholdGuard),
    HasCryptoObject {
        object_name: String,
        object_args: Vec<(String, Expr)>,
    },
    Comparison {
        lhs: Expr,
        op: CmpOp,
        rhs: Expr,
    },
    BoolVar(String),
    And(Box<GuardExpr>, Box<GuardExpr>),
    Or(Box<GuardExpr>, Box<GuardExpr>),
}

/// Threshold guard: `received >= 2*t+1 MsgType`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct ThresholdGuard {
    pub op: CmpOp,
    pub threshold: LinearExpr,
    pub message_type: String,
    /// Optional message field constraints (name = expr).
    pub message_args: Vec<(String, Expr)>,
    /// Whether the message count should be interpreted as distinct senders.
    pub distinct: bool,
    /// Optional distinct sender domain (by role).
    pub distinct_role: Option<String>,
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum CmpOp {
    Ge,
    Le,
    Gt,
    Lt,
    Eq,
    Ne,
}

impl std::fmt::Display for CmpOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmpOp::Ge => write!(f, ">="),
            CmpOp::Le => write!(f, "<="),
            CmpOp::Gt => write!(f, ">"),
            CmpOp::Lt => write!(f, "<"),
            CmpOp::Eq => write!(f, "=="),
            CmpOp::Ne => write!(f, "!="),
        }
    }
}

/// Linear expression (for thresholds and resilience conditions).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum LinearExpr {
    Const(i64),
    Var(String),
    Add(Box<LinearExpr>, Box<LinearExpr>),
    Sub(Box<LinearExpr>, Box<LinearExpr>),
    Mul(i64, Box<LinearExpr>),
}

impl std::fmt::Display for LinearExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinearExpr::Const(c) => write!(f, "{c}"),
            LinearExpr::Var(v) => write!(f, "{v}"),
            LinearExpr::Add(l, r) => write!(f, "({l} + {r})"),
            LinearExpr::Sub(l, r) => write!(f, "({l} - {r})"),
            LinearExpr::Mul(c, e) => write!(f, "{c}*{e}"),
        }
    }
}

/// General expression (for actions and comparisons).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Expr {
    IntLit(i64),
    BoolLit(bool),
    Var(String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::IntLit(n) => write!(f, "{n}"),
            Expr::BoolLit(b) => write!(f, "{b}"),
            Expr::Var(v) => write!(f, "{v}"),
            Expr::Add(l, r) => write!(f, "({l} + {r})"),
            Expr::Sub(l, r) => write!(f, "({l} - {r})"),
            Expr::Mul(l, r) => write!(f, "({l} * {r})"),
            Expr::Div(l, r) => write!(f, "({l} / {r})"),
            Expr::Not(e) => write!(f, "!{e}"),
            Expr::Neg(e) => write!(f, "-{e}"),
        }
    }
}

/// Action in a transition rule.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Action {
    Send {
        message_type: String,
        args: Vec<SendArg>,
        recipient_role: Option<String>,
    },
    FormCryptoObject {
        object_name: String,
        args: Vec<SendArg>,
        recipient_role: Option<String>,
    },
    LockCryptoObject {
        object_name: String,
        args: Vec<SendArg>,
    },
    JustifyCryptoObject {
        object_name: String,
        args: Vec<SendArg>,
    },
    Assign {
        var: String,
        value: Expr,
    },
    GotoPhase {
        phase: String,
    },
    Decide {
        value: Expr,
    },
}

/// Argument to a send action.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum SendArg {
    Positional(Expr),
    Named { name: String, value: Expr },
}

/// Property declaration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct PropertyDecl {
    pub name: String,
    pub kind: PropertyKind,
    pub formula: QuantifiedFormula,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum PropertyKind {
    Agreement,
    Validity,
    Safety,
    Invariant,
    Liveness,
}

/// Quantified formula for property specifications.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct QuantifiedFormula {
    pub quantifiers: Vec<QuantifierBinding>,
    pub body: FormulaExpr,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct QuantifierBinding {
    pub quantifier: Quantifier,
    pub var: String,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Quantifier {
    ForAll,
    Exists,
}

/// Formula expression (propositional logic over comparisons).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum FormulaExpr {
    Comparison {
        lhs: FormulaAtom,
        op: CmpOp,
        rhs: FormulaAtom,
    },
    Not(Box<FormulaExpr>),
    Next(Box<FormulaExpr>),
    Always(Box<FormulaExpr>),
    Eventually(Box<FormulaExpr>),
    Until(Box<FormulaExpr>, Box<FormulaExpr>),
    WeakUntil(Box<FormulaExpr>, Box<FormulaExpr>),
    Release(Box<FormulaExpr>, Box<FormulaExpr>),
    LeadsTo(Box<FormulaExpr>, Box<FormulaExpr>),
    And(Box<FormulaExpr>, Box<FormulaExpr>),
    Or(Box<FormulaExpr>, Box<FormulaExpr>),
    Implies(Box<FormulaExpr>, Box<FormulaExpr>),
    Iff(Box<FormulaExpr>, Box<FormulaExpr>),
}

/// Atomic term in a formula.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum FormulaAtom {
    IntLit(i64),
    BoolLit(bool),
    Var(String),
    QualifiedVar { object: String, field: String },
}

impl std::fmt::Display for FormulaAtom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormulaAtom::IntLit(n) => write!(f, "{n}"),
            FormulaAtom::BoolLit(b) => write!(f, "{b}"),
            FormulaAtom::Var(v) => write!(f, "{v}"),
            FormulaAtom::QualifiedVar { object, field } => write!(f, "{object}.{field}"),
        }
    }
}

impl FormulaExpr {
    /// Whether this is a binary infix operator.
    /// The parser treats all binary ops at the same precedence with left-associativity.
    fn is_binary(&self) -> bool {
        matches!(
            self,
            FormulaExpr::And(_, _)
                | FormulaExpr::Or(_, _)
                | FormulaExpr::Implies(_, _)
                | FormulaExpr::Iff(_, _)
                | FormulaExpr::Until(_, _)
                | FormulaExpr::WeakUntil(_, _)
                | FormulaExpr::Release(_, _)
                | FormulaExpr::LeadsTo(_, _)
        )
    }

    /// Format the left child of a binary operator.
    /// Left children never need parens (left-associative parser, same precedence).
    fn fmt_left(&self, child: &FormulaExpr, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{child}")
    }

    /// Format the right child of a binary operator.
    /// Right children need parens if they are also binary ops (to preserve grouping
    /// against the left-associative parser).
    fn fmt_right(&self, child: &FormulaExpr, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if child.is_binary() {
            write!(f, "({child})")
        } else {
            write!(f, "{child}")
        }
    }
}

impl std::fmt::Display for FormulaExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormulaExpr::Comparison { lhs, op, rhs } => write!(f, "{lhs} {op} {rhs}"),
            FormulaExpr::Not(inner) => {
                if inner.is_binary() {
                    write!(f, "!({inner})")
                } else {
                    write!(f, "!{inner}")
                }
            }
            FormulaExpr::Next(inner) => {
                if inner.is_binary() {
                    write!(f, "X ({inner})")
                } else {
                    write!(f, "X {inner}")
                }
            }
            FormulaExpr::Always(inner) => {
                if inner.is_binary() {
                    write!(f, "[] ({inner})")
                } else {
                    write!(f, "[] {inner}")
                }
            }
            FormulaExpr::Eventually(inner) => {
                if inner.is_binary() {
                    write!(f, "<> ({inner})")
                } else {
                    write!(f, "<> {inner}")
                }
            }
            FormulaExpr::Until(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " U ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::WeakUntil(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " W ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::Release(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " R ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::LeadsTo(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " ~> ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::And(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " && ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::Or(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " || ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::Implies(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " ==> ")?;
                self.fmt_right(rhs, f)
            }
            FormulaExpr::Iff(lhs, rhs) => {
                self.fmt_left(lhs, f)?;
                write!(f, " <=> ")?;
                self.fmt_right(rhs, f)
            }
        }
    }
}

impl std::fmt::Display for Quantifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Quantifier::ForAll => write!(f, "forall"),
            Quantifier::Exists => write!(f, "exists"),
        }
    }
}

impl std::fmt::Display for PropertyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyKind::Agreement => write!(f, "agreement"),
            PropertyKind::Validity => write!(f, "validity"),
            PropertyKind::Safety => write!(f, "safety"),
            PropertyKind::Invariant => write!(f, "invariant"),
            PropertyKind::Liveness => write!(f, "liveness"),
        }
    }
}

impl std::fmt::Display for QuantifiedFormula {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for qb in &self.quantifiers {
            write!(f, "{} {}: {}. ", qb.quantifier, qb.var, qb.domain)?;
        }
        write!(f, "{}", self.body)
    }
}

impl std::fmt::Display for PropertyDecl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "property {}: {} {{\n    {}\n}}",
            self.name, self.kind, self.formula
        )
    }
}

#[cfg(test)]
mod tests {
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
        let add = Expr::Add(
            Box::new(Expr::Var("x".into())),
            Box::new(Expr::IntLit(1)),
        );
        assert_eq!(add.to_string(), "(x + 1)");

        let sub = Expr::Sub(
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        );
        assert_eq!(sub.to_string(), "(a - b)");

        let mul = Expr::Mul(
            Box::new(Expr::IntLit(2)),
            Box::new(Expr::Var("y".into())),
        );
        assert_eq!(mul.to_string(), "(2 * y)");

        let div = Expr::Div(
            Box::new(Expr::Var("z".into())),
            Box::new(Expr::IntLit(3)),
        );
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
}
