//! Hover documentation for keywords and user-defined symbols.

use tarsier_dsl::ast::{Program, VarType};

pub(crate) fn keyword_docs(word: &str) -> Option<&'static str> {
    match word {
        "protocol" => Some("Top-level protocol declaration. Contains parameters, messages, roles, and properties."),
        "parameters" => Some("Parameter block declaring symbolic integer constants (e.g., `n: nat; t: nat;`)."),
        "resilience" => Some("Resilience condition constraining the relationship between total processes (n) and faulty processes (t). Example: `n > 3*t`"),
        "adversary" => Some("Adversary model configuration. Keys: `model` (byzantine/crash/omission), `bound` (fault bound parameter)."),
        "message" => Some("Message type declaration. Can include fields: `message Vote(value: nat, round: nat);`"),
        "role" => Some("Role declaration defining a process type with variables, an init phase, and phases with transitions."),
        "var" => Some("Local variable declaration inside a role. Syntax: `var name: type = init_value;`"),
        "init" => Some("Specifies the initial phase for a role. Syntax: `init <phase_name>;`"),
        "phase" => Some("Phase (location) in the role's state machine. Contains transition rules (`when ... => { ... }`)."),
        "when" => Some("Transition guard in a phase. Syntax: `when <guard> => { <actions> }`"),
        "send" => Some("Action: broadcast a message to all processes. Syntax: `send MessageType(args);`"),
        "goto" => Some("Action: transition to another phase. Syntax: `goto phase <name>;`"),
        "decide" => Some("Action: make a decision (for agreement properties). Syntax: `decide <value>;`"),
        "received" => Some("Threshold guard: checks if enough messages of a type have been received. Syntax: `received [distinct] >= THRESHOLD MessageType`"),
        "property" => Some("Property declaration for verification. Syntax: `property name: kind { formula }`"),
        "agreement" => Some("Agreement property: all correct processes that decide must decide the same value."),
        "validity" => Some("Validity property: if all correct processes start with the same value, they must decide that value."),
        "safety" => Some("Generic safety property (something bad never happens)."),
        "invariant" => Some("Invariant property: a condition that must hold in every reachable state."),
        "liveness" => Some("Liveness property: something good eventually happens."),
        "committee" => Some("Committee selection declaration for probabilistic verification. Specifies population, byzantine count, committee size, and error bound."),
        "identity" => Some("Identity declaration specifying authentication scope for a role (role-level or process-level)."),
        "channel" => Some("Channel authentication declaration for a message type (`authenticated` or `unauthenticated`)."),
        "equivocation" => Some("Equivocation policy for a message type (`full` or `none`)."),
        "forall" => Some("Universal quantifier in property formulas. Syntax: `forall p: RoleName. <formula>`"),
        "exists" => Some("Existential quantifier in property formulas. Syntax: `exists p: RoleName. <formula>`"),
        "enum" => Some("Finite domain enumeration type. Syntax: `enum Color { Red, Green, Blue }`"),
        "certificate" | "threshold_signature" => Some("Cryptographic object declaration for quorum certificates or threshold signatures."),
        "pacemaker" => Some("Pacemaker configuration for automatic view/round changes."),
        "module" => Some("Module declaration for compositional protocol specification."),
        "import" => Some("Import declaration to include external protocol modules."),
        "refines" => Some("Refinement declaration linking this protocol to an abstract/base protocol file. Syntax: `refines \"base_protocol.trs\";`"),
        "dag_round" => Some("DAG round declaration. Syntax: `dag_round r2 extends r0, r1;`"),
        "extends" => Some("DAG edge declaration keyword used in `dag_round` declarations to list parent rounds."),
        "log" => Some("Bounded log collection declaration. Syntax: `log Name: Type[BOUND];`"),
        "sequence" => Some("Bounded sequence collection declaration. Syntax: `sequence Name: Type[BOUND];`"),
        "fifo_channel" => Some("Bounded FIFO channel declaration with ordered delivery. Syntax: `fifo_channel Name: Type[BOUND];`"),
        "true" => Some("Boolean literal `true`."),
        "false" => Some("Boolean literal `false`."),
        "bool" => Some("Boolean type for local variables."),
        "nat" => Some("Natural number type (non-negative integer) for parameters and variables."),
        "int" => Some("Integer type for parameters and variables."),
        "distinct" => Some("Modifier for threshold guards: count distinct senders. Syntax: `received distinct >= N MsgType`"),
        "append" => Some("Action: append an element to a bounded collection. Syntax: `append coll value;`"),
        "enqueue" => Some("Action: enqueue an element into a FIFO collection. Syntax: `enqueue ch value;`"),
        "dequeue" => Some("Action: dequeue an element from a FIFO collection. Syntax: `dequeue ch;`"),
        "reconfigure" => Some("Action: update protocol parameters at a transition boundary. Syntax: `reconfigure { n = n + 1; t = t; }`"),
        _ => None,
    }
}

pub(crate) fn hover_for_user_defined(word: &str, program: &Program) -> Option<String> {
    let proto = &program.protocol.node;

    // Messages
    for msg in &proto.messages {
        if msg.name == word {
            if msg.fields.is_empty() {
                return Some(format!("**Message** `{}`", msg.name));
            } else {
                let fields: Vec<String> = msg
                    .fields
                    .iter()
                    .map(|f| format!("{}: {}", f.name, f.ty))
                    .collect();
                return Some(format!("**Message** `{}({})`", msg.name, fields.join(", ")));
            }
        }
    }

    // Roles
    for role in &proto.roles {
        if role.node.name == word {
            let n_vars = role.node.vars.len();
            let n_phases = role.node.phases.len();
            let phase_names: Vec<&str> = role
                .node
                .phases
                .iter()
                .map(|p| p.node.name.as_str())
                .collect();
            return Some(format!(
                "**Role** `{}` — {} variable(s), {} phase(s) ({})",
                role.node.name,
                n_vars,
                n_phases,
                phase_names.join(", ")
            ));
        }
    }

    // Phases
    for role in &proto.roles {
        for phase in &role.node.phases {
            if phase.node.name == word {
                let n_transitions = phase.node.transitions.len();
                return Some(format!(
                    "**Phase** `{}` in role `{}` — {} transition(s)",
                    phase.node.name, role.node.name, n_transitions
                ));
            }
        }
    }

    // Parameters
    for param in &proto.parameters {
        if param.name == word {
            return Some(format!("**Parameter** `{}: {:?}`", param.name, param.ty));
        }
    }

    // Variables
    for role in &proto.roles {
        for var in &role.node.vars {
            if var.name == word {
                let ty_str = match &var.ty {
                    VarType::Bool => "bool".to_string(),
                    VarType::Nat => "nat".to_string(),
                    VarType::Int => "int".to_string(),
                    VarType::Enum(e) => e.clone(),
                };
                let init_str = var
                    .init
                    .as_ref()
                    .map(|e| format!(" = {e}"))
                    .unwrap_or_default();
                return Some(format!(
                    "**Variable** `{}: {}{init_str}` in role `{}`",
                    var.name, ty_str, role.node.name
                ));
            }
        }
    }

    // Properties
    for prop in &proto.properties {
        if prop.node.name == word {
            return Some(format!(
                "**Property** `{}`: {}",
                prop.node.name, prop.node.kind
            ));
        }
    }

    // Enums
    for e in &proto.enums {
        if e.name == word {
            return Some(format!(
                "**Enum** `{}` {{ {} }}",
                e.name,
                e.variants.join(", ")
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_dsl::ast::*;

    fn empty_program() -> Program {
        Program {
            protocol: Spanned::new(
                ProtocolDecl {
                    name: "Test".to_string(),
                    imports: vec![],
                    refines: None,
                    modules: vec![],
                    enums: vec![],
                    parameters: vec![],
                    resilience: None,
                    pacemaker: None,
                    adversary: vec![],
                    identities: vec![],
                    channels: vec![],
                    equivocation_policies: vec![],
                    committees: vec![],
                    dag_rounds: vec![],
                    collections: vec![],
                    clocks: vec![],
                    messages: vec![],
                    crypto_objects: vec![],
                    roles: vec![],
                    properties: vec![],
                },
                Span { start: 0, end: 0 },
            ),
        }
    }

    // ── keyword_docs tests ──

    #[test]
    fn keyword_docs_protocol() {
        let doc = keyword_docs("protocol");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("protocol"));
    }

    #[test]
    fn keyword_docs_all_known_keywords_return_some() {
        let keywords = [
            "protocol", "parameters", "resilience", "adversary", "message",
            "role", "var", "init", "phase", "when", "send", "goto", "decide",
            "received", "property", "agreement", "validity", "safety",
            "invariant", "liveness", "committee", "identity", "channel",
            "equivocation", "forall", "exists", "enum", "certificate",
            "threshold_signature", "pacemaker", "module", "import", "refines",
            "dag_round", "extends", "log", "sequence", "fifo_channel",
            "true", "false", "bool", "nat", "int", "distinct", "append",
            "enqueue", "dequeue", "reconfigure",
        ];
        for kw in keywords {
            assert!(keyword_docs(kw).is_some(), "keyword '{}' should have docs", kw);
        }
    }

    #[test]
    fn keyword_docs_unknown_returns_none() {
        assert!(keyword_docs("foobar").is_none());
        assert!(keyword_docs("").is_none());
        assert!(keyword_docs("Protocol").is_none()); // case-sensitive
    }

    #[test]
    fn keyword_docs_certificate_and_threshold_signature_same() {
        let doc1 = keyword_docs("certificate").unwrap();
        let doc2 = keyword_docs("threshold_signature").unwrap();
        assert_eq!(doc1, doc2);
    }

    // ── hover_for_user_defined tests ──

    #[test]
    fn hover_message_no_fields() {
        let mut prog = empty_program();
        prog.protocol.node.messages.push(MessageDecl {
            name: "Ping".to_string(),
            fields: vec![],
            span: Span { start: 0, end: 0 },
        });
        let result = hover_for_user_defined("Ping", &prog);
        assert_eq!(result, Some("**Message** `Ping`".to_string()));
    }

    #[test]
    fn hover_message_with_fields() {
        let mut prog = empty_program();
        prog.protocol.node.messages.push(MessageDecl {
            name: "Vote".to_string(),
            fields: vec![
                FieldDef { name: "value".into(), ty: "nat".into(), range: None },
                FieldDef { name: "round".into(), ty: "nat".into(), range: None },
            ],
            span: Span { start: 0, end: 0 },
        });
        let result = hover_for_user_defined("Vote", &prog).unwrap();
        assert!(result.contains("Vote(value: nat, round: nat)"));
    }

    #[test]
    fn hover_role() {
        let mut prog = empty_program();
        prog.protocol.node.roles.push(Spanned::new(
            RoleDecl {
                name: "Voter".to_string(),
                is_leader: false,
                vars: vec![VarDecl {
                    name: "x".into(),
                    ty: VarType::Bool,
                    range: None,
                    init: None,
                    span: Span { start: 0, end: 0 },
                }],
                init_phase: Some("start".into()),
                phases: vec![
                    Spanned::new(
                        PhaseDecl { name: "start".into(), transitions: vec![] },
                        Span { start: 0, end: 0 },
                    ),
                    Spanned::new(
                        PhaseDecl { name: "done".into(), transitions: vec![] },
                        Span { start: 0, end: 0 },
                    ),
                ],
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("Voter", &prog).unwrap();
        assert!(result.contains("**Role** `Voter`"));
        assert!(result.contains("1 variable(s)"));
        assert!(result.contains("2 phase(s)"));
        assert!(result.contains("start, done"));
    }

    #[test]
    fn hover_phase() {
        let mut prog = empty_program();
        prog.protocol.node.roles.push(Spanned::new(
            RoleDecl {
                name: "R".to_string(),
                is_leader: false,
                vars: vec![],
                init_phase: Some("idle".into()),
                phases: vec![Spanned::new(
                    PhaseDecl { name: "idle".into(), transitions: vec![] },
                    Span { start: 0, end: 0 },
                )],
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("idle", &prog).unwrap();
        assert!(result.contains("**Phase** `idle`"));
        assert!(result.contains("role `R`"));
        assert!(result.contains("0 transition(s)"));
    }

    #[test]
    fn hover_parameter() {
        let mut prog = empty_program();
        prog.protocol.node.parameters.push(ParamDef {
            name: "n".to_string(),
            ty: ParamType::Nat,
            span: Span { start: 0, end: 0 },
        });
        let result = hover_for_user_defined("n", &prog).unwrap();
        assert!(result.contains("**Parameter** `n:"));
    }

    #[test]
    fn hover_variable_bool() {
        let mut prog = empty_program();
        prog.protocol.node.roles.push(Spanned::new(
            RoleDecl {
                name: "R".to_string(),
                is_leader: false,
                vars: vec![VarDecl {
                    name: "decided".into(),
                    ty: VarType::Bool,
                    range: None,
                    init: Some(Expr::BoolLit(false)),
                    span: Span { start: 0, end: 0 },
                }],
                init_phase: None,
                phases: vec![],
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("decided", &prog).unwrap();
        assert!(result.contains("**Variable** `decided: bool"));
        assert!(result.contains("role `R`"));
    }

    #[test]
    fn hover_variable_enum_type() {
        let mut prog = empty_program();
        prog.protocol.node.roles.push(Spanned::new(
            RoleDecl {
                name: "R".to_string(),
                is_leader: false,
                vars: vec![VarDecl {
                    name: "color".into(),
                    ty: VarType::Enum("Color".into()),
                    range: None,
                    init: None,
                    span: Span { start: 0, end: 0 },
                }],
                init_phase: None,
                phases: vec![],
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("color", &prog).unwrap();
        assert!(result.contains("Color"));
    }

    #[test]
    fn hover_property() {
        let mut prog = empty_program();
        prog.protocol.node.properties.push(Spanned::new(
            PropertyDecl {
                name: "agree".to_string(),
                kind: PropertyKind::Agreement,
                formula: QuantifiedFormula {
                    quantifiers: vec![],
                    body: FormulaExpr::Comparison {
                        lhs: FormulaAtom::BoolLit(true),
                        op: CmpOp::Eq,
                        rhs: FormulaAtom::BoolLit(true),
                    },
                },
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("agree", &prog).unwrap();
        assert!(result.contains("**Property** `agree`"));
        assert!(result.contains("agreement"));
    }

    #[test]
    fn hover_enum() {
        let mut prog = empty_program();
        prog.protocol.node.enums.push(EnumDecl {
            name: "Color".to_string(),
            variants: vec!["Red".into(), "Green".into(), "Blue".into()],
            span: Span { start: 0, end: 0 },
        });
        let result = hover_for_user_defined("Color", &prog).unwrap();
        assert!(result.contains("**Enum** `Color`"));
        assert!(result.contains("Red, Green, Blue"));
    }

    #[test]
    fn hover_unknown_returns_none() {
        let prog = empty_program();
        assert!(hover_for_user_defined("nonexistent", &prog).is_none());
    }

    #[test]
    fn hover_priority_message_over_role() {
        // If a message and role share the same name, message wins (checked first)
        let mut prog = empty_program();
        prog.protocol.node.messages.push(MessageDecl {
            name: "X".to_string(),
            fields: vec![],
            span: Span { start: 0, end: 0 },
        });
        prog.protocol.node.roles.push(Spanned::new(
            RoleDecl {
                name: "X".to_string(),
                is_leader: false,
                vars: vec![],
                init_phase: None,
                phases: vec![],
            },
            Span { start: 0, end: 0 },
        ));
        let result = hover_for_user_defined("X", &prog).unwrap();
        assert!(result.starts_with("**Message**"));
    }
}
