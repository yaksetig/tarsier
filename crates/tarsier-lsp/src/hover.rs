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
        "true" => Some("Boolean literal `true`."),
        "false" => Some("Boolean literal `false`."),
        "bool" => Some("Boolean type for local variables."),
        "nat" => Some("Natural number type (non-negative integer) for parameters and variables."),
        "int" => Some("Integer type for parameters and variables."),
        "distinct" => Some("Modifier for threshold guards: count distinct senders. Syntax: `received distinct >= N MsgType`"),
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
