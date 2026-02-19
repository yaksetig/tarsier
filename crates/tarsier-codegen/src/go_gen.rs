use std::collections::HashSet;
use std::fmt::Write;

use tarsier_dsl::ast::*;

use crate::common::*;
use crate::{CodegenError, CodegenTarget};

/// Generate a complete Go source file from a protocol declaration.
pub fn generate_go(protocol: &ProtocolDecl) -> Result<String, CodegenError> {
    let params = collect_param_names(&protocol.parameters);
    let mut out = String::new();

    let pkg_name = protocol.name.to_lowercase().replace('_', "");
    write_header(&mut out, protocol, &pkg_name);
    write_config(&mut out, protocol);
    write_enums(&mut out, protocol);
    write_messages(&mut out, protocol);
    write_envelope(&mut out);
    write_network_interface(&mut out);

    for role in &protocol.roles {
        write_role(&mut out, &role.node, protocol, &params)?;
    }

    // Emit helper functions when distinct-sender guards are used
    if uses_distinct_guards(protocol) {
        write_distinct_helpers(&mut out);
    }

    Ok(out)
}

fn write_header(out: &mut String, protocol: &ProtocolDecl, pkg_name: &str) {
    writeln!(out, "// Generated from protocol: {}", protocol.name).unwrap();
    writeln!(
        out,
        "// This is a skeleton implementation. Fill in networking and serialization."
    )
    .unwrap();
    writeln!(out, "//").unwrap();
    writeln!(
        out,
        "// Protocol logic is verified-by-construction from the .trs model."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "package {pkg_name}").unwrap();
    writeln!(out).unwrap();
}

fn write_config(out: &mut String, protocol: &ProtocolDecl) {
    if protocol.parameters.is_empty() {
        return;
    }
    writeln!(out, "// Config holds protocol parameters.").unwrap();
    writeln!(out, "type Config struct {{").unwrap();
    for p in &protocol.parameters {
        let ty = match p.ty {
            ParamType::Nat => "uint64",
            ParamType::Int => "int64",
        };
        writeln!(out, "\t{} {ty}", to_pascal_case(&p.name)).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_enums(out: &mut String, protocol: &ProtocolDecl) {
    for e in &protocol.enums {
        let type_name = to_pascal_case(&e.name);
        writeln!(out, "type {type_name} uint64").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "const (").unwrap();
        for (i, v) in e.variants.iter().enumerate() {
            let variant_name = format!("{type_name}{}", to_pascal_case(v));
            if i == 0 {
                writeln!(out, "\t{variant_name} {type_name} = iota").unwrap();
            } else {
                writeln!(out, "\t{variant_name}").unwrap();
            }
        }
        writeln!(out, ")").unwrap();
        writeln!(out).unwrap();
    }
}

fn write_messages(out: &mut String, protocol: &ProtocolDecl) {
    for msg in &protocol.messages {
        let name = format!("{}Msg", to_pascal_case(&msg.name));
        writeln!(out, "// {name} represents a {} message.", msg.name).unwrap();
        writeln!(out, "type {name} struct {{").unwrap();
        for f in &msg.fields {
            let ty = field_type_to_go(&f.ty);
            writeln!(out, "\t{} {ty}", to_pascal_case(&f.name)).unwrap();
        }
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }

    // Message is represented as interface{} in Go (no sum types).
    writeln!(out, "// Message is a union type for all protocol messages.").unwrap();
    if !protocol.messages.is_empty() {
        writeln!(
            out,
            "// Use type switches to match: switch m := msg.(type) {{ case *EchoMsg: ... }}"
        )
        .unwrap();
    }
    writeln!(out, "type Message interface{{}}").unwrap();
    writeln!(out).unwrap();
}

fn write_envelope(out: &mut String) {
    writeln!(out, "// Envelope wraps a message with sender information.").unwrap();
    writeln!(out, "type Envelope struct {{").unwrap();
    writeln!(out, "\tSender  uint64").unwrap();
    writeln!(out, "\tMessage Message").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_network_interface(out: &mut String) {
    writeln!(
        out,
        "// Network is the interface for sending protocol messages."
    )
    .unwrap();
    writeln!(out, "type Network interface {{").unwrap();
    writeln!(out, "\tBroadcast(msg Message)").unwrap();
    writeln!(out, "\tSend(msg Message, to uint64)").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_role(
    out: &mut String,
    role: &RoleDecl,
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
) -> Result<(), CodegenError> {
    let role_name = to_pascal_case(&role.name);

    // Phase type and constants
    let phase_type = format!("{role_name}Phase");
    writeln!(out, "type {phase_type} int").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "const (").unwrap();
    for (i, phase) in role.phases.iter().enumerate() {
        let const_name = format!("{phase_type}{}", to_pascal_case(&phase.node.name));
        if i == 0 {
            writeln!(out, "\t{const_name} {phase_type} = iota").unwrap();
        } else {
            writeln!(out, "\t{const_name}").unwrap();
        }
    }
    writeln!(out, ")").unwrap();
    writeln!(out).unwrap();

    // Decision struct
    writeln!(
        out,
        "// {role_name}Decision represents a protocol decision."
    )
    .unwrap();
    writeln!(out, "type {role_name}Decision struct {{").unwrap();
    writeln!(out, "\tValue uint64").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // State struct
    let state_name = format!("{role_name}State");
    writeln!(
        out,
        "// {state_name} holds the state for a {role_name} node."
    )
    .unwrap();
    writeln!(out, "type {state_name} struct {{").unwrap();
    writeln!(out, "\tPhase {phase_type}").unwrap();
    for var in &role.vars {
        let ty = go_type(&var.ty);
        writeln!(out, "\t{} {ty}", to_pascal_case(&var.name)).unwrap();
    }
    for msg in &protocol.messages {
        let buf_name = format!("{}Buffer", to_pascal_case(&msg.name));
        writeln!(out, "\t{buf_name} []Envelope").unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // New function
    let init_phase = role.init_phase.as_deref().unwrap_or_else(|| {
        role.phases
            .first()
            .map(|p| p.node.name.as_str())
            .unwrap_or("unknown")
    });
    writeln!(
        out,
        "// New{state_name} creates a new {state_name} with initial values."
    )
    .unwrap();
    writeln!(out, "func New{state_name}() *{state_name} {{").unwrap();
    writeln!(out, "\treturn &{state_name}{{").unwrap();
    writeln!(
        out,
        "\t\tPhase: {phase_type}{},",
        to_pascal_case(init_phase)
    )
    .unwrap();
    for var in &role.vars {
        let default_val = match &var.init {
            Some(expr) => render_expr_literal_go(expr),
            None => match var.ty {
                VarType::Bool => "false".to_string(),
                VarType::Nat | VarType::Int => "0".to_string(),
                VarType::Enum(_) => "0".to_string(),
            },
        };
        writeln!(out, "\t\t{}: {default_val},", to_pascal_case(&var.name)).unwrap();
    }
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // HandleMessage method
    writeln!(
        out,
        "// HandleMessage processes an incoming message and returns outgoing messages and an optional decision."
    )
    .unwrap();
    writeln!(
        out,
        "func (s *{state_name}) HandleMessage(envelope Envelope, config *Config) ([]Message, *{role_name}Decision) {{"
    )
    .unwrap();
    writeln!(out, "\tvar outgoing []Message").unwrap();
    writeln!(out, "\tvar decision *{role_name}Decision").unwrap();
    writeln!(out).unwrap();

    // Buffer incoming
    writeln!(out, "\t// Buffer incoming message").unwrap();
    writeln!(out, "\tswitch envelope.Message.(type) {{").unwrap();
    for msg in &protocol.messages {
        let struct_name = format!("*{}Msg", to_pascal_case(&msg.name));
        let buf_name = format!("{}Buffer", to_pascal_case(&msg.name));
        writeln!(out, "\tcase {struct_name}:").unwrap();
        writeln!(out, "\t\ts.{buf_name} = append(s.{buf_name}, envelope)").unwrap();
    }
    writeln!(out, "\t}}").unwrap();
    writeln!(out).unwrap();

    // Phase switch
    writeln!(out, "\t// Evaluate transitions for current phase").unwrap();
    writeln!(out, "\tswitch s.Phase {{").unwrap();
    for phase in &role.phases {
        let phase_const = format!("{phase_type}{}", to_pascal_case(&phase.node.name));
        writeln!(out, "\tcase {phase_const}:").unwrap();
        write_phase_transitions_go(out, &phase.node, protocol, params, &role_name, &phase_type)?;
    }
    writeln!(out, "\t}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "\treturn outgoing, decision").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    Ok(())
}

fn write_phase_transitions_go(
    out: &mut String,
    phase: &PhaseDecl,
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
    role_name: &str,
    phase_type: &str,
) -> Result<(), CodegenError> {
    let indent = "\t\t";
    for (i, transition) in phase.transitions.iter().enumerate() {
        let t = &transition.node;
        let keyword = if i == 0 { "if" } else { "} else if" };
        let guard_str = render_guard_go(&t.guard, protocol, params);
        writeln!(out, "{indent}{keyword} {guard_str} {{").unwrap();
        write_actions_go(
            out,
            &t.actions,
            protocol,
            params,
            role_name,
            phase_type,
            &format!("{indent}\t"),
        )?;
    }
    if !phase.transitions.is_empty() {
        writeln!(out, "{indent}}}").unwrap();
    }
    Ok(())
}

fn render_guard_go(guard: &GuardExpr, protocol: &ProtocolDecl, params: &HashSet<String>) -> String {
    match guard {
        GuardExpr::Threshold(tg) => {
            let buf_name = format!("{}Buffer", to_pascal_case(&tg.message_type));
            let threshold = render_linear_expr(&tg.threshold, params, CodegenTarget::Go);
            let op = render_cmp_op(&tg.op);

            if tg.message_args.is_empty() && !tg.distinct {
                format!("uint64(len(s.{buf_name})) {op} {threshold}")
            } else if tg.distinct && tg.message_args.is_empty() {
                format!("countDistinctSenders(s.{buf_name}) {op} {threshold}")
            } else {
                let variant = to_pascal_case(&tg.message_type);
                let struct_type = format!("{}Msg", variant);
                let filter_conditions: Vec<String> = tg
                    .message_args
                    .iter()
                    .map(|(field, expr)| {
                        let val = render_expr(expr, params, CodegenTarget::Go);
                        format!("m.{} == {val}", to_pascal_case(field))
                    })
                    .collect();
                let filter_body = filter_conditions.join(" && ");

                if tg.distinct {
                    format!(
                        "countDistinctFiltered(s.{buf_name}, func(m *{struct_type}) bool {{ return {filter_body} }}) {op} {threshold}"
                    )
                } else {
                    format!(
                        "countFiltered(s.{buf_name}, func(m *{struct_type}) bool {{ return {filter_body} }}) {op} {threshold}"
                    )
                }
            }
        }
        GuardExpr::Comparison { lhs, op, rhs } => {
            let l = render_expr(lhs, params, CodegenTarget::Go);
            let r = render_expr(rhs, params, CodegenTarget::Go);
            let op_str = render_cmp_op(op);
            format!("{l} {op_str} {r}")
        }
        GuardExpr::BoolVar(name) => {
            format!("s.{}", to_pascal_case(name))
        }
        GuardExpr::And(a, b) => {
            let left = render_guard_go(a, protocol, params);
            let right = render_guard_go(b, protocol, params);
            format!("({left}) && ({right})")
        }
        GuardExpr::Or(a, b) => {
            let left = render_guard_go(a, protocol, params);
            let right = render_guard_go(b, protocol, params);
            format!("({left}) || ({right})")
        }
        GuardExpr::HasCryptoObject { object_name, .. } => {
            format!("/* TODO: hasCryptoObject({object_name}) */ true")
        }
    }
}

fn write_actions_go(
    out: &mut String,
    actions: &[Action],
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
    role_name: &str,
    phase_type: &str,
    indent: &str,
) -> Result<(), CodegenError> {
    for action in actions {
        match action {
            Action::Send {
                message_type, args, ..
            } => {
                let variant = to_pascal_case(message_type);
                let struct_name = format!("{variant}Msg");

                let msg_decl = protocol.messages.iter().find(|m| m.name == *message_type);

                if let Some(decl) = msg_decl {
                    if decl.fields.is_empty() {
                        writeln!(
                            out,
                            "{indent}outgoing = append(outgoing, &{struct_name}{{}})"
                        )
                        .unwrap();
                    } else {
                        writeln!(out, "{indent}outgoing = append(outgoing, &{struct_name}{{")
                            .unwrap();
                        for (i, arg) in args.iter().enumerate() {
                            match arg {
                                SendArg::Named { name, value } => {
                                    let val = render_expr(value, params, CodegenTarget::Go);
                                    writeln!(out, "{indent}\t{}: {val},", to_pascal_case(name))
                                        .unwrap();
                                }
                                SendArg::Positional(expr) => {
                                    if let Some(field) = decl.fields.get(i) {
                                        let val = render_expr(expr, params, CodegenTarget::Go);
                                        writeln!(
                                            out,
                                            "{indent}\t{}: {val},",
                                            to_pascal_case(&field.name)
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                        writeln!(out, "{indent}}})").unwrap();
                    }
                } else {
                    writeln!(
                        out,
                        "{indent}outgoing = append(outgoing, &{struct_name}{{}})"
                    )
                    .unwrap();
                }
            }
            Action::Assign { var, value } => {
                let val = render_expr(value, params, CodegenTarget::Go);
                writeln!(out, "{indent}s.{} = {val}", to_pascal_case(var)).unwrap();
            }
            Action::GotoPhase { phase } => {
                writeln!(
                    out,
                    "{indent}s.Phase = {phase_type}{}",
                    to_pascal_case(phase)
                )
                .unwrap();
            }
            Action::Decide { value } => {
                // Go cannot cast bool to uint64, so map BoolLit to 1/0
                let val = match value {
                    Expr::BoolLit(true) => "1".to_string(),
                    Expr::BoolLit(false) => "0".to_string(),
                    _ => render_expr(value, params, CodegenTarget::Go),
                };
                writeln!(
                    out,
                    "{indent}decision = &{role_name}Decision{{Value: uint64({val})}}"
                )
                .unwrap();
            }
            Action::FormCryptoObject { object_name, .. } => {
                writeln!(out, "{indent}// TODO: form crypto object '{object_name}'").unwrap();
            }
            Action::LockCryptoObject { object_name, .. } => {
                writeln!(out, "{indent}// TODO: lock crypto object '{object_name}'").unwrap();
            }
            Action::JustifyCryptoObject { object_name, .. } => {
                writeln!(
                    out,
                    "{indent}// TODO: justify crypto object '{object_name}'"
                )
                .unwrap();
            }
        }
    }
    Ok(())
}

/// Render a literal expression for Go default values.
fn render_expr_literal_go(expr: &Expr) -> String {
    match expr {
        Expr::IntLit(n) => n.to_string(),
        Expr::BoolLit(b) => b.to_string(),
        Expr::Var(v) => v.clone(),
        _ => "0".to_string(),
    }
}

/// Map a DSL field type name to a Go type string.
fn field_type_to_go(ty: &str) -> &str {
    match ty {
        "bool" => "bool",
        "nat" => "uint64",
        "int" => "int64",
        _ => "uint64",
    }
}

/// Emit Go helper functions for distinct-sender counting.
fn write_distinct_helpers(out: &mut String) {
    writeln!(
        out,
        "// countDistinctSenders counts the number of unique senders in a buffer."
    )
    .unwrap();
    writeln!(out, "func countDistinctSenders(buf []Envelope) uint64 {{").unwrap();
    writeln!(out, "\tseen := make(map[uint64]bool)").unwrap();
    writeln!(out, "\tfor _, e := range buf {{").unwrap();
    writeln!(out, "\t\tseen[e.Sender] = true").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "\treturn uint64(len(seen))").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}
