use std::collections::HashSet;
use std::fmt::Write;

use tarsier_dsl::ast::*;

use crate::common::*;
use crate::{CodegenError, CodegenTarget};

/// Generate a complete Rust source file from a protocol declaration.
pub fn generate_rust(protocol: &ProtocolDecl) -> Result<String, CodegenError> {
    let params = collect_param_names(&protocol.parameters);
    let mut out = String::new();

    write_header(&mut out, protocol);
    write_config(&mut out, protocol);
    write_enums(&mut out, protocol);
    write_messages(&mut out, protocol);
    write_envelope(&mut out);
    write_network_trait(&mut out);

    for role in &protocol.roles {
        write_role(&mut out, &role.node, protocol, &params)?;
    }

    Ok(out)
}

fn write_header(out: &mut String, protocol: &ProtocolDecl) {
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
    writeln!(out, "#![allow(unused, unused_comparisons)]").unwrap();
    writeln!(out).unwrap();

    // Only import HashSet if any guard uses distinct senders
    if uses_distinct_guards(protocol) {
        writeln!(out, "use std::collections::HashSet;").unwrap();
        writeln!(out).unwrap();
    }
}

fn write_config(out: &mut String, protocol: &ProtocolDecl) {
    if protocol.parameters.is_empty() {
        return;
    }
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct Config {{").unwrap();
    for p in &protocol.parameters {
        let ty = match p.ty {
            ParamType::Nat => "u64",
            ParamType::Int => "i64",
        };
        writeln!(out, "    pub {}: {ty},", p.name).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_enums(out: &mut String, protocol: &ProtocolDecl) {
    for e in &protocol.enums {
        writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
        writeln!(out, "pub enum {} {{", to_pascal_case(&e.name)).unwrap();
        for v in &e.variants {
            writeln!(out, "    {},", to_pascal_case(v)).unwrap();
        }
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }
}

fn write_messages(out: &mut String, protocol: &ProtocolDecl) {
    // Individual message structs
    for msg in &protocol.messages {
        let name = format!("{}Msg", to_pascal_case(&msg.name));
        if msg.fields.is_empty() {
            writeln!(out, "#[derive(Debug, Clone)]").unwrap();
            writeln!(out, "pub struct {name};").unwrap();
        } else {
            writeln!(out, "#[derive(Debug, Clone)]").unwrap();
            writeln!(out, "pub struct {name} {{").unwrap();
            for f in &msg.fields {
                let ty = field_type_to_rust(&f.ty);
                writeln!(out, "    pub {}: {ty},", f.name).unwrap();
            }
            writeln!(out, "}}").unwrap();
        }
        writeln!(out).unwrap();
    }

    // Wrapper enum (always emitted; empty enum is uninhabited but type-valid)
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub enum Message {{").unwrap();
    for msg in &protocol.messages {
        let variant = to_pascal_case(&msg.name);
        let struct_name = format!("{variant}Msg");
        writeln!(out, "    {variant}({struct_name}),").unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_envelope(out: &mut String) {
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct Envelope {{").unwrap();
    writeln!(out, "    pub sender: u64,").unwrap();
    writeln!(out, "    pub message: Message,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_network_trait(out: &mut String) {
    writeln!(out, "pub trait Network {{").unwrap();
    writeln!(out, "    fn broadcast(&mut self, msg: Message);").unwrap();
    writeln!(out, "    fn send(&mut self, msg: Message, to: u64);").unwrap();
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

    // Phase enum
    let phase_enum_name = format!("{role_name}Phase");
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
    writeln!(out, "pub enum {phase_enum_name} {{").unwrap();
    for phase in &role.phases {
        writeln!(out, "    {},", to_pascal_case(&phase.node.name)).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Decision struct
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct {role_name}Decision {{").unwrap();
    writeln!(out, "    pub value: u64,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // State struct
    let state_name = format!("{role_name}State");
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct {state_name} {{").unwrap();
    writeln!(out, "    pub phase: {phase_enum_name},").unwrap();
    for var in &role.vars {
        let ty = rust_type(&var.ty);
        writeln!(out, "    pub {}: {ty},", var.name).unwrap();
    }
    // Per-message-type receive buffers
    for msg in &protocol.messages {
        let buf_name = format!("{}_buffer", to_snake_case(&msg.name));
        writeln!(out, "    pub {buf_name}: Vec<Envelope>,").unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // impl block
    writeln!(out, "impl {state_name} {{").unwrap();

    // new()
    let init_phase = role.init_phase.as_deref().unwrap_or_else(|| {
        role.phases
            .first()
            .map(|p| p.node.name.as_str())
            .unwrap_or("unknown")
    });
    writeln!(out, "    pub fn new() -> Self {{").unwrap();
    writeln!(out, "        Self {{").unwrap();
    writeln!(
        out,
        "            phase: {phase_enum_name}::{},",
        to_pascal_case(init_phase)
    )
    .unwrap();
    for var in &role.vars {
        let default_val = match &var.init {
            Some(expr) => render_expr_literal(expr),
            None => match var.ty {
                VarType::Bool => "false".to_string(),
                VarType::Nat | VarType::Int => "0".to_string(),
                VarType::Enum(_) => "0".to_string(),
            },
        };
        writeln!(out, "            {}: {default_val},", var.name).unwrap();
    }
    for msg in &protocol.messages {
        let buf_name = format!("{}_buffer", to_snake_case(&msg.name));
        writeln!(out, "            {buf_name}: Vec::new(),").unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // handle_message()
    writeln!(out, "    pub fn handle_message(").unwrap();
    writeln!(out, "        &mut self,").unwrap();
    writeln!(out, "        envelope: Envelope,").unwrap();
    writeln!(out, "        config: &Config,").unwrap();
    writeln!(
        out,
        "    ) -> (Vec<Message>, Option<{role_name}Decision>) {{"
    )
    .unwrap();
    writeln!(out, "        let mut outgoing: Vec<Message> = Vec::new();").unwrap();
    writeln!(
        out,
        "        let mut decision: Option<{role_name}Decision> = None;"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Buffer the incoming message
    if !protocol.messages.is_empty() {
        writeln!(out, "        // Buffer incoming message").unwrap();
        writeln!(out, "        match &envelope.message {{").unwrap();
        for msg in &protocol.messages {
            let variant = to_pascal_case(&msg.name);
            let buf_name = format!("{}_buffer", to_snake_case(&msg.name));
            writeln!(
                out,
                "            Message::{variant}(_) => self.{buf_name}.push(envelope.clone()),"
            )
            .unwrap();
        }
        writeln!(out, "        }}").unwrap();
        writeln!(out).unwrap();
    }

    // Evaluate transitions based on current phase
    writeln!(out, "        // Evaluate transitions for current phase").unwrap();
    writeln!(out, "        match self.phase {{").unwrap();
    for phase in &role.phases {
        let phase_variant = to_pascal_case(&phase.node.name);
        writeln!(out, "            {phase_enum_name}::{phase_variant} => {{").unwrap();
        write_phase_transitions(out, &phase.node, protocol, params, &role_name)?;
        writeln!(out, "            }}").unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "        (outgoing, decision)").unwrap();
    writeln!(out, "    }}").unwrap();

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    Ok(())
}

fn write_phase_transitions(
    out: &mut String,
    phase: &PhaseDecl,
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
    role_name: &str,
) -> Result<(), CodegenError> {
    let indent = "                ";
    for (i, transition) in phase.transitions.iter().enumerate() {
        let t = &transition.node;
        let keyword = if i == 0 { "if" } else { "} else if" };
        let guard_str = render_guard(&t.guard, protocol, params);
        writeln!(out, "{indent}{keyword} {guard_str} {{").unwrap();
        write_actions(
            out,
            &t.actions,
            protocol,
            params,
            role_name,
            &format!("{indent}    "),
        )?;
    }
    if !phase.transitions.is_empty() {
        writeln!(out, "{indent}}}").unwrap();
    }
    Ok(())
}

fn render_guard(guard: &GuardExpr, protocol: &ProtocolDecl, params: &HashSet<String>) -> String {
    match guard {
        GuardExpr::Threshold(tg) => {
            let buf_name = format!("{}_buffer", to_snake_case(&tg.message_type));
            let threshold = render_linear_expr(&tg.threshold, params, CodegenTarget::Rust);
            let op = render_cmp_op(&tg.op);

            if tg.message_args.is_empty() && !tg.distinct {
                // Simple count
                format!("self.{buf_name}.len() as u64 {op} {threshold}")
            } else if tg.distinct && tg.message_args.is_empty() {
                // Distinct senders, no field filter
                format!(
                    "self.{buf_name}.iter().map(|e| e.sender).collect::<HashSet<_>>().len() as u64 {op} {threshold}"
                )
            } else {
                // Filtered count (possibly distinct)
                let variant = to_pascal_case(&tg.message_type);
                let filter_conditions: Vec<String> = tg
                    .message_args
                    .iter()
                    .map(|(field, expr)| {
                        let val = render_expr(expr, params, CodegenTarget::Rust);
                        format!("m.{field} == {val}")
                    })
                    .collect();
                let filter_body = filter_conditions.join(" && ");

                if tg.distinct {
                    format!(
                        "self.{buf_name}.iter().filter(|e| match &e.message {{ Message::{variant}(m) => {filter_body}, _ => false }}).map(|e| e.sender).collect::<HashSet<_>>().len() as u64 {op} {threshold}"
                    )
                } else {
                    format!(
                        "self.{buf_name}.iter().filter(|e| match &e.message {{ Message::{variant}(m) => {filter_body}, _ => false }}).count() as u64 {op} {threshold}"
                    )
                }
            }
        }
        GuardExpr::Comparison { lhs, op, rhs } => {
            let l = render_expr(lhs, params, CodegenTarget::Rust);
            let r = render_expr(rhs, params, CodegenTarget::Rust);
            let op_str = render_cmp_op(op);
            format!("{l} {op_str} {r}")
        }
        GuardExpr::BoolVar(name) => {
            format!("self.{name}")
        }
        GuardExpr::And(a, b) => {
            let left = render_guard(a, protocol, params);
            let right = render_guard(b, protocol, params);
            format!("({left}) && ({right})")
        }
        GuardExpr::Or(a, b) => {
            let left = render_guard(a, protocol, params);
            let right = render_guard(b, protocol, params);
            format!("({left}) || ({right})")
        }
        GuardExpr::HasCryptoObject { object_name, .. } => {
            format!("/* TODO: has_crypto_object({object_name}) */ true")
        }
    }
}

fn write_actions(
    out: &mut String,
    actions: &[Action],
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
    role_name: &str,
    indent: &str,
) -> Result<(), CodegenError> {
    let phase_enum_name = format!("{role_name}Phase");

    for action in actions {
        match action {
            Action::Send {
                message_type, args, ..
            } => {
                let variant = to_pascal_case(message_type);
                let struct_name = format!("{variant}Msg");

                // Find message decl to get field names
                let msg_decl = protocol.messages.iter().find(|m| m.name == *message_type);

                if let Some(decl) = msg_decl {
                    if decl.fields.is_empty() {
                        writeln!(
                            out,
                            "{indent}outgoing.push(Message::{variant}({struct_name}));"
                        )
                        .unwrap();
                    } else {
                        writeln!(
                            out,
                            "{indent}outgoing.push(Message::{variant}({struct_name} {{"
                        )
                        .unwrap();
                        for (i, arg) in args.iter().enumerate() {
                            match arg {
                                SendArg::Named { name, value } => {
                                    let val = render_expr(value, params, CodegenTarget::Rust);
                                    writeln!(out, "{indent}    {name}: {val},").unwrap();
                                }
                                SendArg::Positional(expr) => {
                                    if let Some(field) = decl.fields.get(i) {
                                        let val = render_expr(expr, params, CodegenTarget::Rust);
                                        writeln!(out, "{indent}    {}: {val},", field.name)
                                            .unwrap();
                                    }
                                }
                            }
                        }
                        writeln!(out, "{indent}}}));").unwrap();
                    }
                } else {
                    // Fallback if message not found
                    writeln!(
                        out,
                        "{indent}outgoing.push(Message::{variant}({struct_name}));"
                    )
                    .unwrap();
                }
            }
            Action::Assign { var, value } => {
                let val = render_expr(value, params, CodegenTarget::Rust);
                writeln!(out, "{indent}self.{var} = {val};").unwrap();
            }
            Action::GotoPhase { phase } => {
                writeln!(
                    out,
                    "{indent}self.phase = {phase_enum_name}::{};",
                    to_pascal_case(phase)
                )
                .unwrap();
            }
            Action::Decide { value } => {
                let val = render_expr(value, params, CodegenTarget::Rust);
                writeln!(
                    out,
                    "{indent}decision = Some({role_name}Decision {{ value: {val} as u64 }});"
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

/// Render a literal expression (for default values in struct initialization).
fn render_expr_literal(expr: &Expr) -> String {
    match expr {
        Expr::IntLit(n) => n.to_string(),
        Expr::BoolLit(b) => b.to_string(),
        Expr::Var(v) => v.clone(),
        _ => "Default::default()".to_string(),
    }
}

/// Map a DSL field type name to a Rust type string.
fn field_type_to_rust(ty: &str) -> &str {
    match ty {
        "bool" => "bool",
        "nat" => "u64",
        "int" => "i64",
        _ => "u64", // default for enum types or unknown
    }
}
