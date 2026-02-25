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
    write_semantics_surface(&mut out, protocol);
    write_outbound_message(&mut out);
    write_network_trait(&mut out);

    for role in &protocol.roles {
        write_role(&mut out, &role.node, protocol, &params)?;
    }

    // Emit TraceRecorder trait and NoopRecorder for conformance trace recording
    writeln!(out, "// --- Conformance Trace Recording ---").unwrap();
    writeln!(out).unwrap();
    out.push_str(&crate::trace_hooks::generate_trace_recorder_trait());

    Ok(out)
}

fn write_header(out: &mut String, protocol: &ProtocolDecl) {
    writeln!(out, "// Generated from protocol: {}", protocol.name).unwrap();
    writeln!(
        out,
        "// Verified implementation scaffold. Protocol logic is derived from the verified .trs model."
    )
    .unwrap();
    writeln!(out, "//").unwrap();
    writeln!(
        out,
        "// Integrate networking, serialization, and deployment infrastructure to complete."
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

fn write_semantics_surface(out: &mut String, protocol: &ProtocolDecl) {
    let default_auth = default_channel_auth_variant(protocol);
    let default_equivocation = default_equivocation_variant(protocol);

    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum IdentityScopeSpec {{\n\
         \x20\x20\x20\x20Role,\n\
         \x20\x20\x20\x20Process,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct IdentityDeclSpec {{\n\
         \x20\x20\x20\x20pub role: &'static str,\n\
         \x20\x20\x20\x20pub scope: IdentityScopeSpec,\n\
         \x20\x20\x20\x20pub process_var: Option<&'static str>,\n\
         \x20\x20\x20\x20pub key: Option<&'static str>,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum ChannelAuthModeSpec {{\n\
         \x20\x20\x20\x20Authenticated,\n\
         \x20\x20\x20\x20Unauthenticated,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct ChannelPolicySpec {{\n\
         \x20\x20\x20\x20pub message: &'static str,\n\
         \x20\x20\x20\x20pub auth: ChannelAuthModeSpec,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum EquivocationModeSpec {{\n\
         \x20\x20\x20\x20Full,\n\
         \x20\x20\x20\x20None,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct EquivocationPolicySpec {{\n\
         \x20\x20\x20\x20pub message: &'static str,\n\
         \x20\x20\x20\x20pub mode: EquivocationModeSpec,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub enum CommitteeValueSpec {{\n\
         \x20\x20\x20\x20Param(&'static str),\n\
         \x20\x20\x20\x20Int(i64),\n\
         \x20\x20\x20\x20Float(f64),\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct CommitteeItemSpec {{\n\
         \x20\x20\x20\x20pub key: &'static str,\n\
         \x20\x20\x20\x20pub value: CommitteeValueSpec,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct CommitteeSpec {{\n\
         \x20\x20\x20\x20pub name: &'static str,\n\
         \x20\x20\x20\x20pub items: Vec<CommitteeItemSpec>,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "#[derive(Debug, Clone)]\n\
         pub struct ProtocolSemanticsSpec {{\n\
         \x20\x20\x20\x20pub identities: Vec<IdentityDeclSpec>,\n\
         \x20\x20\x20\x20pub channels: Vec<ChannelPolicySpec>,\n\
         \x20\x20\x20\x20pub equivocation: Vec<EquivocationPolicySpec>,\n\
         \x20\x20\x20\x20pub committees: Vec<CommitteeSpec>,\n\
         \x20\x20\x20\x20pub default_channel_auth: ChannelAuthModeSpec,\n\
         \x20\x20\x20\x20pub default_equivocation: EquivocationModeSpec,\n\
         }}\n"
    )
    .unwrap();

    writeln!(
        out,
        "pub fn protocol_semantics_spec() -> ProtocolSemanticsSpec {{"
    )
    .unwrap();
    writeln!(out, "    ProtocolSemanticsSpec {{").unwrap();
    writeln!(out, "        identities: vec![").unwrap();
    for identity in &protocol.identities {
        let scope = match identity.scope {
            IdentityScope::Role => "IdentityScopeSpec::Role",
            IdentityScope::Process => "IdentityScopeSpec::Process",
        };
        let process_var = identity
            .process_var
            .as_ref()
            .map(|v| format!("Some(\"{v}\")"))
            .unwrap_or_else(|| "None".to_string());
        let key = identity
            .key
            .as_ref()
            .map(|v| format!("Some(\"{v}\")"))
            .unwrap_or_else(|| "None".to_string());
        writeln!(
            out,
            "            IdentityDeclSpec {{ role: \"{}\", scope: {scope}, process_var: {process_var}, key: {key} }},",
            identity.role
        )
        .unwrap();
    }
    writeln!(out, "        ],").unwrap();

    writeln!(out, "        channels: vec![").unwrap();
    for channel in &protocol.channels {
        writeln!(
            out,
            "            ChannelPolicySpec {{ message: \"{}\", auth: {} }},",
            channel.message,
            channel_auth_variant(channel.auth)
        )
        .unwrap();
    }
    writeln!(out, "        ],").unwrap();

    writeln!(out, "        equivocation: vec![").unwrap();
    for policy in &protocol.equivocation_policies {
        writeln!(
            out,
            "            EquivocationPolicySpec {{ message: \"{}\", mode: {} }},",
            policy.message,
            equivocation_variant(policy.mode)
        )
        .unwrap();
    }
    writeln!(out, "        ],").unwrap();

    writeln!(out, "        committees: vec![").unwrap();
    for committee in &protocol.committees {
        writeln!(out, "            CommitteeSpec {{").unwrap();
        writeln!(out, "                name: \"{}\",", committee.name).unwrap();
        writeln!(out, "                items: vec![").unwrap();
        for item in &committee.items {
            writeln!(
                out,
                "                    CommitteeItemSpec {{ key: \"{}\", value: {} }},",
                item.key,
                render_committee_value(&item.value)
            )
            .unwrap();
        }
        writeln!(out, "                ],").unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "        ],").unwrap();
    writeln!(out, "        default_channel_auth: {default_auth},").unwrap();
    writeln!(out, "        default_equivocation: {default_equivocation},").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "pub fn channel_auth_for_message_family(message_family: &str) -> ChannelAuthModeSpec {{"
    )
    .unwrap();
    writeln!(out, "    match message_family {{").unwrap();
    for channel in &protocol.channels {
        writeln!(
            out,
            "        \"{}\" => {},",
            channel.message,
            channel_auth_variant(channel.auth)
        )
        .unwrap();
    }
    writeln!(out, "        _ => {default_auth},").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "pub fn equivocation_mode_for_message_family(message_family: &str) -> EquivocationModeSpec {{"
    )
    .unwrap();
    writeln!(out, "    match message_family {{").unwrap();
    for policy in &protocol.equivocation_policies {
        writeln!(
            out,
            "        \"{}\" => {},",
            policy.message,
            equivocation_variant(policy.mode)
        )
        .unwrap();
    }
    writeln!(out, "        _ => {default_equivocation},").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_outbound_message(out: &mut String) {
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct OutboundMessage {{").unwrap();
    writeln!(out, "    pub message: Message,").unwrap();
    writeln!(out, "    pub recipient_role: Option<&'static str>,").unwrap();
    writeln!(out, "    pub channel_auth: ChannelAuthModeSpec,").unwrap();
    writeln!(out, "    pub equivocation: EquivocationModeSpec,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_network_trait(out: &mut String) {
    writeln!(out, "pub trait Network {{").unwrap();
    writeln!(
        out,
        "    fn broadcast(&mut self, outbound: OutboundMessage);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn send(&mut self, outbound: OutboundMessage, to: u64);"
    )
    .unwrap();
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
    // Per-crypto-object tracking fields
    for co in &protocol.crypto_objects {
        let snake = to_snake_case(&co.name);
        writeln!(out, "    pub {snake}_count: u64,").unwrap();
        writeln!(out, "    pub lock_{snake}: bool,").unwrap();
        writeln!(out, "    pub justify_{snake}: bool,").unwrap();
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
    for co in &protocol.crypto_objects {
        let snake = to_snake_case(&co.name);
        writeln!(out, "            {snake}_count: 0,").unwrap();
        writeln!(out, "            lock_{snake}: false,").unwrap();
        writeln!(out, "            justify_{snake}: false,").unwrap();
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
        "    ) -> (Vec<OutboundMessage>, Option<{role_name}Decision>) {{"
    )
    .unwrap();
    writeln!(
        out,
        "        let mut outgoing: Vec<OutboundMessage> = Vec::new();"
    )
    .unwrap();
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
        let guard_str = render_guard(&t.guard, params);
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

fn render_guard(guard: &GuardExpr, params: &HashSet<String>) -> String {
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
            let left = render_guard(a, params);
            let right = render_guard(b, params);
            format!("({left}) && ({right})")
        }
        GuardExpr::Or(a, b) => {
            let left = render_guard(a, params);
            let right = render_guard(b, params);
            format!("({left}) || ({right})")
        }
        GuardExpr::HasCryptoObject { object_name, .. } => {
            let count_field = format!("{}_count", to_snake_case(object_name));
            format!("self.{count_field} >= 1")
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
                message_type,
                args,
                recipient_role,
            } => {
                let recipient = recipient_role
                    .as_ref()
                    .map(|r| format!("Some(\"{r}\")"))
                    .unwrap_or_else(|| "None".to_string());
                let ctor = render_message_ctor(message_type, args, protocol, params);
                writeln!(out, "{indent}outgoing.push(OutboundMessage {{").unwrap();
                writeln!(out, "{indent}    message: {ctor},").unwrap();
                writeln!(out, "{indent}    recipient_role: {recipient},").unwrap();
                writeln!(
                    out,
                    "{indent}    channel_auth: channel_auth_for_message_family(\"{message_type}\"),"
                )
                .unwrap();
                writeln!(
                    out,
                    "{indent}    equivocation: equivocation_mode_for_message_family(\"{message_type}\"),"
                )
                .unwrap();
                writeln!(out, "{indent}}});").unwrap();
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
                let snake = to_snake_case(object_name);
                writeln!(out, "{indent}self.{snake}_count += 1;").unwrap();
            }
            Action::LockCryptoObject { object_name, .. } => {
                let snake = to_snake_case(object_name);
                writeln!(out, "{indent}self.lock_{snake} = true;").unwrap();
            }
            Action::JustifyCryptoObject { object_name, .. } => {
                let snake = to_snake_case(object_name);
                writeln!(out, "{indent}self.justify_{snake} = true;").unwrap();
            }
        }
    }
    Ok(())
}

fn render_message_ctor(
    message_type: &str,
    args: &[SendArg],
    protocol: &ProtocolDecl,
    params: &HashSet<String>,
) -> String {
    let variant = to_pascal_case(message_type);
    let struct_name = format!("{variant}Msg");
    let Some(decl) = protocol.messages.iter().find(|m| m.name == message_type) else {
        return format!("Message::{variant}({struct_name})");
    };

    if decl.fields.is_empty() {
        return format!("Message::{variant}({struct_name})");
    }

    let mut assignments: Vec<String> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        match arg {
            SendArg::Named { name, value } => {
                let val = render_expr(value, params, CodegenTarget::Rust);
                assignments.push(format!("{name}: {val}"));
            }
            SendArg::Positional(expr) => {
                if let Some(field) = decl.fields.get(i) {
                    let val = render_expr(expr, params, CodegenTarget::Rust);
                    assignments.push(format!("{}: {val}", field.name));
                }
            }
        }
    }
    format!(
        "Message::{variant}({struct_name} {{ {} }})",
        assignments.join(", ")
    )
}

fn channel_auth_variant(mode: ChannelAuthMode) -> &'static str {
    match mode {
        ChannelAuthMode::Authenticated => "ChannelAuthModeSpec::Authenticated",
        ChannelAuthMode::Unauthenticated => "ChannelAuthModeSpec::Unauthenticated",
    }
}

fn equivocation_variant(mode: EquivocationPolicyMode) -> &'static str {
    match mode {
        EquivocationPolicyMode::Full => "EquivocationModeSpec::Full",
        EquivocationPolicyMode::None => "EquivocationModeSpec::None",
    }
}

/// Compute the protocol-wide default channel auth when no per-message
/// `channel` override is present.
fn default_channel_auth_variant(protocol: &ProtocolDecl) -> &'static str {
    let Some(item) = protocol.adversary.iter().find(|item| item.key == "auth") else {
        return "ChannelAuthModeSpec::Unauthenticated";
    };
    if item.value == "signed" || item.value == "authenticated" {
        "ChannelAuthModeSpec::Authenticated"
    } else {
        "ChannelAuthModeSpec::Unauthenticated"
    }
}

/// Compute the protocol-wide default equivocation mode when no per-message
/// `equivocation` override is present.
fn default_equivocation_variant(protocol: &ProtocolDecl) -> &'static str {
    if let Some(item) = protocol
        .adversary
        .iter()
        .find(|item| item.key == "equivocation")
    {
        if item.value == "none" {
            return "EquivocationModeSpec::None";
        }
        return "EquivocationModeSpec::Full";
    }
    if protocol
        .adversary
        .iter()
        .any(|item| item.key == "model" && item.value == "byzantine")
    {
        "EquivocationModeSpec::Full"
    } else {
        "EquivocationModeSpec::None"
    }
}

fn render_committee_value(value: &CommitteeValue) -> String {
    match value {
        CommitteeValue::Param(name) => format!("CommitteeValueSpec::Param(\"{name}\")"),
        CommitteeValue::Int(value) => format!("CommitteeValueSpec::Int({value})"),
        CommitteeValue::Float(value) => format!("CommitteeValueSpec::Float({value})"),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn span() -> Span {
        Span::new(0, 0)
    }

    fn empty_protocol() -> ProtocolDecl {
        ProtocolDecl {
            name: "TestProtocol".to_string(),
            imports: vec![],
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
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        }
    }

    fn protocol_with_vote_message() -> ProtocolDecl {
        let mut protocol = empty_protocol();
        protocol.messages.push(MessageDecl {
            name: "Vote".to_string(),
            fields: vec![
                FieldDef {
                    name: "view".to_string(),
                    ty: "nat".to_string(),
                    range: None,
                },
                FieldDef {
                    name: "value".to_string(),
                    ty: "bool".to_string(),
                    range: None,
                },
            ],
            span: span(),
        });
        protocol
    }

    #[test]
    fn default_channel_auth_variant_follows_adversary_auth_entry() {
        let mut protocol = empty_protocol();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Unauthenticated"
        );

        protocol.adversary.push(AdversaryItem {
            key: "auth".to_string(),
            value: "signed".to_string(),
            span: span(),
        });
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Authenticated"
        );

        protocol.adversary[0].value = "none".to_string();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthModeSpec::Unauthenticated"
        );
    }

    #[test]
    fn default_equivocation_variant_follows_explicit_or_model_defaults() {
        let mut protocol = empty_protocol();
        protocol.adversary.push(AdversaryItem {
            key: "model".to_string(),
            value: "byzantine".to_string(),
            span: span(),
        });
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::Full"
        );

        protocol.adversary.push(AdversaryItem {
            key: "equivocation".to_string(),
            value: "none".to_string(),
            span: span(),
        });
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::None"
        );

        protocol.adversary[1].value = "full".to_string();
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::Full"
        );

        protocol.adversary = vec![AdversaryItem {
            key: "model".to_string(),
            value: "crash".to_string(),
            span: span(),
        }];
        assert_eq!(
            default_equivocation_variant(&protocol),
            "EquivocationModeSpec::None"
        );
    }

    #[test]
    fn render_message_ctor_supports_named_and_positional_arguments() {
        let protocol = protocol_with_vote_message();
        let params = collect_param_names(&[ParamDef {
            name: "n".to_string(),
            ty: ParamType::Nat,
            span: span(),
        }]);

        let named = render_message_ctor(
            "Vote",
            &[
                SendArg::Named {
                    name: "view".to_string(),
                    value: Expr::IntLit(3),
                },
                SendArg::Named {
                    name: "value".to_string(),
                    value: Expr::BoolLit(true),
                },
            ],
            &protocol,
            &params,
        );
        assert_eq!(named, "Message::Vote(VoteMsg { view: 3, value: true })");

        let positional = render_message_ctor(
            "Vote",
            &[
                SendArg::Positional(Expr::Var("n".to_string())),
                SendArg::Positional(Expr::BoolLit(false)),
            ],
            &protocol,
            &params,
        );
        assert_eq!(
            positional,
            "Message::Vote(VoteMsg { view: config.n, value: false })"
        );
    }

    #[test]
    fn render_message_ctor_uses_unit_struct_for_unknown_or_fieldless_message() {
        let protocol = protocol_with_vote_message();
        let params = HashSet::new();
        assert_eq!(
            render_message_ctor("Unknown", &[], &protocol, &params),
            "Message::Unknown(UnknownMsg)"
        );

        let mut fieldless = empty_protocol();
        fieldless.messages.push(MessageDecl {
            name: "Ping".to_string(),
            fields: vec![],
            span: span(),
        });
        assert_eq!(
            render_message_ctor("Ping", &[], &fieldless, &params),
            "Message::Ping(PingMsg)"
        );
    }

    #[test]
    fn literal_and_type_helpers_have_stable_fallbacks() {
        assert_eq!(render_expr_literal(&Expr::IntLit(9)), "9");
        assert_eq!(render_expr_literal(&Expr::BoolLit(false)), "false");
        assert_eq!(render_expr_literal(&Expr::Var("x".to_string())), "x");
        assert_eq!(
            render_expr_literal(&Expr::Add(
                Box::new(Expr::IntLit(1)),
                Box::new(Expr::IntLit(2))
            )),
            "Default::default()"
        );
        assert_eq!(field_type_to_rust("bool"), "bool");
        assert_eq!(field_type_to_rust("nat"), "u64");
        assert_eq!(field_type_to_rust("int"), "i64");
        assert_eq!(field_type_to_rust("enum"), "u64");
    }

    #[test]
    fn rust_codegen_imports_hashset_only_when_distinct_guards_are_used() {
        let with_distinct_src = include_str!("../../tarsier-dsl/../../examples/crypto_objects.trs");
        let with_distinct_program =
            tarsier_dsl::parse(with_distinct_src, "crypto_objects.trs").unwrap();
        let with_distinct = generate_rust(&with_distinct_program.protocol.node).unwrap();
        assert!(with_distinct.contains("use std::collections::HashSet;"));

        let no_distinct_src = include_str!("../../tarsier-dsl/../../examples/trivial_live.trs");
        let no_distinct_program = tarsier_dsl::parse(no_distinct_src, "trivial_live.trs").unwrap();
        let no_distinct = generate_rust(&no_distinct_program.protocol.node).unwrap();
        assert!(!no_distinct.contains("use std::collections::HashSet;"));
    }
}
