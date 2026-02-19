/// Source span for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct Program {
    pub protocol: Spanned<ProtocolDecl>,
}

/// Protocol declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolDecl {
    pub name: String,
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

/// Pacemaker configuration (automatic view changes).
#[derive(Debug, Clone, PartialEq)]
pub struct PacemakerDecl {
    pub view_var: String,
    pub start_phase: String,
    pub reset_vars: Vec<String>,
}

/// Enum declaration (finite domain).
#[derive(Debug, Clone, PartialEq)]
pub struct EnumDecl {
    pub name: String,
    pub variants: Vec<String>,
}

/// Parameter definition (e.g., `n: nat;`)
#[derive(Debug, Clone, PartialEq)]
pub struct ParamDef {
    pub name: String,
    pub ty: ParamType,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    Nat,
    Int,
}

/// Resilience condition (e.g., `n > 3*t`)
#[derive(Debug, Clone, PartialEq)]
pub struct ResilienceDecl {
    pub condition: ResilienceExpr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResilienceExpr {
    pub lhs: LinearExpr,
    pub op: CmpOp,
    pub rhs: LinearExpr,
}

/// Adversary model items (e.g., `model: byzantine;`)
#[derive(Debug, Clone, PartialEq)]
pub struct AdversaryItem {
    pub key: String,
    pub value: String,
    pub span: Span,
}

/// Identity declaration for a role.
#[derive(Debug, Clone, PartialEq)]
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
pub enum IdentityScope {
    Role,
    Process,
}

/// Per-message channel authentication declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelDecl {
    pub message: String,
    pub auth: ChannelAuthMode,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAuthMode {
    Authenticated,
    Unauthenticated,
}

/// Per-message equivocation policy declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct EquivocationDecl {
    pub message: String,
    pub mode: EquivocationPolicyMode,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationPolicyMode {
    Full,
    None,
}

/// Committee selection declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitteeDecl {
    pub name: String,
    pub items: Vec<CommitteeItem>,
    pub span: Span,
}

/// A key-value item in a committee declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitteeItem {
    pub key: String,
    pub value: CommitteeValue,
    pub span: Span,
}

/// Value in a committee declaration item.
#[derive(Debug, Clone, PartialEq)]
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
pub enum CryptoObjectKind {
    QuorumCertificate,
    ThresholdSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoConflictPolicy {
    /// No extra admissibility constraints on conflicting variants.
    Allow,
    /// Conflicting variants are disallowed at a recipient.
    Exclusive,
}

/// Message type declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDecl {
    pub name: String,
    pub fields: Vec<FieldDef>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldDef {
    pub name: String,
    pub ty: String,
    pub range: Option<VarRange>,
}

/// Role declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleDecl {
    pub name: String,
    pub vars: Vec<VarDecl>,
    pub init_phase: Option<String>,
    pub phases: Vec<Spanned<PhaseDecl>>,
}

/// Local variable declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct VarDecl {
    pub name: String,
    pub ty: VarType,
    pub range: Option<VarRange>,
    pub init: Option<Expr>,
    pub span: Span,
}

/// Optional range for integer/nat local variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    Bool,
    Nat,
    Int,
    Enum(String),
}

/// Phase (local state in the automaton).
#[derive(Debug, Clone, PartialEq)]
pub struct PhaseDecl {
    pub name: String,
    pub transitions: Vec<Spanned<TransitionRule>>,
}

/// Transition rule: `when guard => { actions }`.
#[derive(Debug, Clone, PartialEq)]
pub struct TransitionRule {
    pub guard: GuardExpr,
    pub actions: Vec<Action>,
}

/// Guard expression.
#[derive(Debug, Clone, PartialEq)]
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
pub enum SendArg {
    Positional(Expr),
    Named { name: String, value: Expr },
}

/// Property declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyDecl {
    pub name: String,
    pub kind: PropertyKind,
    pub formula: QuantifiedFormula,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyKind {
    Agreement,
    Validity,
    Safety,
    Invariant,
    Liveness,
}

/// Quantified formula for property specifications.
#[derive(Debug, Clone, PartialEq)]
pub struct QuantifiedFormula {
    pub quantifiers: Vec<QuantifierBinding>,
    pub body: FormulaExpr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuantifierBinding {
    pub quantifier: Quantifier,
    pub var: String,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    ForAll,
    Exists,
}

/// Formula expression (propositional logic over comparisons).
#[derive(Debug, Clone, PartialEq)]
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
