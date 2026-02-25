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
    write_semantics_surface(&mut out, protocol);
    write_outbound_message(&mut out);
    write_network_interface(&mut out);

    for role in &protocol.roles {
        write_role(&mut out, &role.node, protocol, &params)?;
    }

    // Emit helper functions when distinct-sender guards are used
    if uses_distinct_guards(protocol) {
        write_distinct_helpers(&mut out);
    }

    // Emit filtered-guard helper functions when field-filtered threshold guards are used
    if uses_filtered_guards(protocol) {
        write_filtered_helpers(&mut out);
    }

    Ok(out)
}

fn write_header(out: &mut String, protocol: &ProtocolDecl, pkg_name: &str) {
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

fn write_semantics_surface(out: &mut String, protocol: &ProtocolDecl) {
    let default_auth = default_channel_auth_variant(protocol);
    let default_equivocation = default_equivocation_variant(protocol);

    writeln!(out, "type IdentityScopeSpec string").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "const (").unwrap();
    writeln!(out, "\tIdentityScopeRole IdentityScopeSpec = \"role\"").unwrap();
    writeln!(
        out,
        "\tIdentityScopeProcess IdentityScopeSpec = \"process\""
    )
    .unwrap();
    writeln!(out, ")").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type IdentityDeclSpec struct {{").unwrap();
    writeln!(out, "\tRole string").unwrap();
    writeln!(out, "\tScope IdentityScopeSpec").unwrap();
    writeln!(out, "\tProcessVar string").unwrap();
    writeln!(out, "\tHasProcessVar bool").unwrap();
    writeln!(out, "\tKey string").unwrap();
    writeln!(out, "\tHasKey bool").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type ChannelAuthModeSpec string").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "const (").unwrap();
    writeln!(
        out,
        "\tChannelAuthAuthenticated ChannelAuthModeSpec = \"authenticated\""
    )
    .unwrap();
    writeln!(
        out,
        "\tChannelAuthUnauthenticated ChannelAuthModeSpec = \"unauthenticated\""
    )
    .unwrap();
    writeln!(out, ")").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type ChannelPolicySpec struct {{").unwrap();
    writeln!(out, "\tMessage string").unwrap();
    writeln!(out, "\tAuth ChannelAuthModeSpec").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type EquivocationModeSpec string").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "const (").unwrap();
    writeln!(out, "\tEquivocationFull EquivocationModeSpec = \"full\"").unwrap();
    writeln!(out, "\tEquivocationNone EquivocationModeSpec = \"none\"").unwrap();
    writeln!(out, ")").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type EquivocationPolicySpec struct {{").unwrap();
    writeln!(out, "\tMessage string").unwrap();
    writeln!(out, "\tMode EquivocationModeSpec").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type CommitteeValueKind string").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "const (").unwrap();
    writeln!(out, "\tCommitteeValueParam CommitteeValueKind = \"param\"").unwrap();
    writeln!(out, "\tCommitteeValueInt CommitteeValueKind = \"int\"").unwrap();
    writeln!(out, "\tCommitteeValueFloat CommitteeValueKind = \"float\"").unwrap();
    writeln!(out, ")").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type CommitteeValueSpec struct {{").unwrap();
    writeln!(out, "\tKind CommitteeValueKind").unwrap();
    writeln!(out, "\tParam string").unwrap();
    writeln!(out, "\tInt int64").unwrap();
    writeln!(out, "\tFloat float64").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type CommitteeItemSpec struct {{").unwrap();
    writeln!(out, "\tKey string").unwrap();
    writeln!(out, "\tValue CommitteeValueSpec").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type CommitteeSpec struct {{").unwrap();
    writeln!(out, "\tName string").unwrap();
    writeln!(out, "\tItems []CommitteeItemSpec").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "type ProtocolSemanticsSpec struct {{").unwrap();
    writeln!(out, "\tIdentities []IdentityDeclSpec").unwrap();
    writeln!(out, "\tChannels []ChannelPolicySpec").unwrap();
    writeln!(out, "\tEquivocation []EquivocationPolicySpec").unwrap();
    writeln!(out, "\tCommittees []CommitteeSpec").unwrap();
    writeln!(out, "\tDefaultChannelAuth ChannelAuthModeSpec").unwrap();
    writeln!(out, "\tDefaultEquivocation EquivocationModeSpec").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "func ProtocolSemanticsSpecData() ProtocolSemanticsSpec {{"
    )
    .unwrap();
    writeln!(out, "\treturn ProtocolSemanticsSpec{{").unwrap();
    writeln!(out, "\t\tIdentities: []IdentityDeclSpec{{").unwrap();
    for identity in &protocol.identities {
        let scope = match identity.scope {
            IdentityScope::Role => "IdentityScopeRole",
            IdentityScope::Process => "IdentityScopeProcess",
        };
        let process_var = identity.process_var.clone().unwrap_or_default();
        let has_process_var = if identity.process_var.is_some() {
            "true"
        } else {
            "false"
        };
        let key = identity.key.clone().unwrap_or_default();
        let has_key = if identity.key.is_some() {
            "true"
        } else {
            "false"
        };
        writeln!(
            out,
            "\t\t\t{{Role: \"{}\", Scope: {scope}, ProcessVar: \"{process_var}\", HasProcessVar: {has_process_var}, Key: \"{key}\", HasKey: {has_key}}},",
            identity.role
        )
        .unwrap();
    }
    writeln!(out, "\t\t}},").unwrap();

    writeln!(out, "\t\tChannels: []ChannelPolicySpec{{").unwrap();
    for channel in &protocol.channels {
        writeln!(
            out,
            "\t\t\t{{Message: \"{}\", Auth: {}}},",
            channel.message,
            channel_auth_variant(channel.auth)
        )
        .unwrap();
    }
    writeln!(out, "\t\t}},").unwrap();

    writeln!(out, "\t\tEquivocation: []EquivocationPolicySpec{{").unwrap();
    for policy in &protocol.equivocation_policies {
        writeln!(
            out,
            "\t\t\t{{Message: \"{}\", Mode: {}}},",
            policy.message,
            equivocation_variant(policy.mode)
        )
        .unwrap();
    }
    writeln!(out, "\t\t}},").unwrap();

    writeln!(out, "\t\tCommittees: []CommitteeSpec{{").unwrap();
    for committee in &protocol.committees {
        writeln!(out, "\t\t\t{{").unwrap();
        writeln!(out, "\t\t\t\tName: \"{}\",", committee.name).unwrap();
        writeln!(out, "\t\t\t\tItems: []CommitteeItemSpec{{").unwrap();
        for item in &committee.items {
            writeln!(
                out,
                "\t\t\t\t\t{{Key: \"{}\", Value: {}}},",
                item.key,
                render_committee_value(&item.value)
            )
            .unwrap();
        }
        writeln!(out, "\t\t\t\t}},").unwrap();
        writeln!(out, "\t\t\t}},").unwrap();
    }
    writeln!(out, "\t\t}},").unwrap();
    writeln!(out, "\t\tDefaultChannelAuth: {default_auth},").unwrap();
    writeln!(out, "\t\tDefaultEquivocation: {default_equivocation},").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "func channelAuthForMessageFamily(messageFamily string) ChannelAuthModeSpec {{"
    )
    .unwrap();
    writeln!(out, "\tswitch messageFamily {{").unwrap();
    for channel in &protocol.channels {
        writeln!(out, "\tcase \"{}\":", channel.message).unwrap();
        writeln!(out, "\t\treturn {}", channel_auth_variant(channel.auth)).unwrap();
    }
    writeln!(out, "\tdefault:").unwrap();
    writeln!(out, "\t\treturn {default_auth}").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "func equivocationModeForMessageFamily(messageFamily string) EquivocationModeSpec {{"
    )
    .unwrap();
    writeln!(out, "\tswitch messageFamily {{").unwrap();
    for policy in &protocol.equivocation_policies {
        writeln!(out, "\tcase \"{}\":", policy.message).unwrap();
        writeln!(out, "\t\treturn {}", equivocation_variant(policy.mode)).unwrap();
    }
    writeln!(out, "\tdefault:").unwrap();
    writeln!(out, "\t\treturn {default_equivocation}").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_outbound_message(out: &mut String) {
    writeln!(out, "type OutboundMessage struct {{").unwrap();
    writeln!(out, "\tMessage Message").unwrap();
    writeln!(out, "\tRecipientRole string").unwrap();
    writeln!(out, "\tChannelAuth ChannelAuthModeSpec").unwrap();
    writeln!(out, "\tEquivocation EquivocationModeSpec").unwrap();
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
    writeln!(out, "\tBroadcast(outbound OutboundMessage)").unwrap();
    writeln!(out, "\tSend(outbound OutboundMessage, to uint64)").unwrap();
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
    // Per-crypto-object tracking fields
    for co in &protocol.crypto_objects {
        let pascal = to_pascal_case(&co.name);
        writeln!(out, "\t{pascal}Count uint64").unwrap();
        writeln!(out, "\tLock{pascal} bool").unwrap();
        writeln!(out, "\tJustify{pascal} bool").unwrap();
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
        "func (s *{state_name}) HandleMessage(envelope Envelope, config *Config) ([]OutboundMessage, *{role_name}Decision) {{"
    )
    .unwrap();
    writeln!(out, "\tvar outgoing []OutboundMessage").unwrap();
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
        let guard_str = render_guard_go(&t.guard, params);
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

fn render_guard_go(guard: &GuardExpr, params: &HashSet<String>) -> String {
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

                let closure = format!(
                    "func(msg interface{{}}) bool {{ m, ok := msg.(*{struct_type}); return ok && {filter_body} }}"
                );

                if tg.distinct {
                    format!("countDistinctFiltered(s.{buf_name}, {closure}) {op} {threshold}")
                } else {
                    format!("countFiltered(s.{buf_name}, {closure}) {op} {threshold}")
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
            let left = render_guard_go(a, params);
            let right = render_guard_go(b, params);
            format!("({left}) && ({right})")
        }
        GuardExpr::Or(a, b) => {
            let left = render_guard_go(a, params);
            let right = render_guard_go(b, params);
            format!("({left}) || ({right})")
        }
        GuardExpr::HasCryptoObject { object_name, .. } => {
            let pascal = to_pascal_case(object_name);
            format!("s.{pascal}Count >= 1")
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
                message_type,
                args,
                recipient_role,
            } => {
                let recipient_role = recipient_role.as_deref().unwrap_or("");
                let ctor = render_message_ctor(message_type, args, protocol, params);
                writeln!(out, "{indent}outgoing = append(outgoing, OutboundMessage{{").unwrap();
                writeln!(out, "{indent}\tMessage: {ctor},").unwrap();
                writeln!(out, "{indent}\tRecipientRole: \"{recipient_role}\",").unwrap();
                writeln!(
                    out,
                    "{indent}\tChannelAuth: channelAuthForMessageFamily(\"{message_type}\"),"
                )
                .unwrap();
                writeln!(
                    out,
                    "{indent}\tEquivocation: equivocationModeForMessageFamily(\"{message_type}\"),"
                )
                .unwrap();
                writeln!(out, "{indent}}})").unwrap();
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
                let pascal = to_pascal_case(object_name);
                writeln!(out, "{indent}s.{pascal}Count++").unwrap();
            }
            Action::LockCryptoObject { object_name, .. } => {
                let pascal = to_pascal_case(object_name);
                writeln!(out, "{indent}s.Lock{pascal} = true").unwrap();
            }
            Action::JustifyCryptoObject { object_name, .. } => {
                let pascal = to_pascal_case(object_name);
                writeln!(out, "{indent}s.Justify{pascal} = true").unwrap();
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
        return format!("&{struct_name}{{}}");
    };

    if decl.fields.is_empty() {
        return format!("&{struct_name}{{}}");
    }

    let mut assignments: Vec<String> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        match arg {
            SendArg::Named { name, value } => {
                let val = render_expr(value, params, CodegenTarget::Go);
                assignments.push(format!("{}: {val}", to_pascal_case(name)));
            }
            SendArg::Positional(expr) => {
                if let Some(field) = decl.fields.get(i) {
                    let val = render_expr(expr, params, CodegenTarget::Go);
                    assignments.push(format!("{}: {val}", to_pascal_case(&field.name)));
                }
            }
        }
    }
    format!("&{struct_name}{{ {} }}", assignments.join(", "))
}

fn channel_auth_variant(mode: ChannelAuthMode) -> &'static str {
    match mode {
        ChannelAuthMode::Authenticated => "ChannelAuthAuthenticated",
        ChannelAuthMode::Unauthenticated => "ChannelAuthUnauthenticated",
    }
}

fn equivocation_variant(mode: EquivocationPolicyMode) -> &'static str {
    match mode {
        EquivocationPolicyMode::Full => "EquivocationFull",
        EquivocationPolicyMode::None => "EquivocationNone",
    }
}

/// Compute the protocol-wide default channel auth when no per-message
/// `channel` override is present.
fn default_channel_auth_variant(protocol: &ProtocolDecl) -> &'static str {
    let Some(item) = protocol.adversary.iter().find(|item| item.key == "auth") else {
        return "ChannelAuthUnauthenticated";
    };
    if item.value == "signed" || item.value == "authenticated" {
        "ChannelAuthAuthenticated"
    } else {
        "ChannelAuthUnauthenticated"
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
            return "EquivocationNone";
        }
        return "EquivocationFull";
    }
    if protocol
        .adversary
        .iter()
        .any(|item| item.key == "model" && item.value == "byzantine")
    {
        "EquivocationFull"
    } else {
        "EquivocationNone"
    }
}

fn render_committee_value(value: &CommitteeValue) -> String {
    match value {
        CommitteeValue::Param(name) => {
            format!("CommitteeValueSpec{{Kind: CommitteeValueParam, Param: \"{name}\"}}")
        }
        CommitteeValue::Int(value) => {
            format!("CommitteeValueSpec{{Kind: CommitteeValueInt, Int: {value}}}")
        }
        CommitteeValue::Float(value) => {
            format!("CommitteeValueSpec{{Kind: CommitteeValueFloat, Float: {value}}}")
        }
    }
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

/// Emit Go helper functions for filtered-guard counting.
fn write_filtered_helpers(out: &mut String) {
    writeln!(
        out,
        "// countFiltered counts envelopes whose message satisfies the predicate."
    )
    .unwrap();
    writeln!(
        out,
        "func countFiltered(buf []Envelope, match func(interface{{}}) bool) uint64 {{"
    )
    .unwrap();
    writeln!(out, "\tvar count uint64").unwrap();
    writeln!(out, "\tfor _, e := range buf {{").unwrap();
    writeln!(out, "\t\tif match(e.Message) {{").unwrap();
    writeln!(out, "\t\t\tcount++").unwrap();
    writeln!(out, "\t\t}}").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "\treturn count").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "// countDistinctFiltered counts distinct senders of envelopes satisfying the predicate."
    )
    .unwrap();
    writeln!(
        out,
        "func countDistinctFiltered(buf []Envelope, match func(interface{{}}) bool) uint64 {{"
    )
    .unwrap();
    writeln!(out, "\tseen := make(map[uint64]bool)").unwrap();
    writeln!(out, "\tfor _, e := range buf {{").unwrap();
    writeln!(out, "\t\tif match(e.Message) {{").unwrap();
    writeln!(out, "\t\t\tseen[e.Sender] = true").unwrap();
    writeln!(out, "\t\t}}").unwrap();
    writeln!(out, "\t}}").unwrap();
    writeln!(out, "\treturn uint64(len(seen))").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
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
            "ChannelAuthUnauthenticated"
        );

        protocol.adversary.push(AdversaryItem {
            key: "auth".to_string(),
            value: "signed".to_string(),
            span: span(),
        });
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthAuthenticated"
        );

        protocol.adversary[0].value = "none".to_string();
        assert_eq!(
            default_channel_auth_variant(&protocol),
            "ChannelAuthUnauthenticated"
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
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationFull");

        protocol.adversary.push(AdversaryItem {
            key: "equivocation".to_string(),
            value: "none".to_string(),
            span: span(),
        });
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationNone");

        protocol.adversary[1].value = "full".to_string();
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationFull");

        protocol.adversary = vec![AdversaryItem {
            key: "model".to_string(),
            value: "crash".to_string(),
            span: span(),
        }];
        assert_eq!(default_equivocation_variant(&protocol), "EquivocationNone");
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
        assert_eq!(named, "&VoteMsg{ View: 3, Value: true }");

        let positional = render_message_ctor(
            "Vote",
            &[
                SendArg::Positional(Expr::Var("n".to_string())),
                SendArg::Positional(Expr::BoolLit(false)),
            ],
            &protocol,
            &params,
        );
        assert_eq!(positional, "&VoteMsg{ View: config.N, Value: false }");
    }

    #[test]
    fn render_message_ctor_uses_empty_struct_for_unknown_or_fieldless_message() {
        let protocol = protocol_with_vote_message();
        let params = HashSet::new();
        assert_eq!(
            render_message_ctor("Unknown", &[], &protocol, &params),
            "&UnknownMsg{}"
        );

        let mut fieldless = empty_protocol();
        fieldless.messages.push(MessageDecl {
            name: "Ping".to_string(),
            fields: vec![],
            span: span(),
        });
        assert_eq!(
            render_message_ctor("Ping", &[], &fieldless, &params),
            "&PingMsg{}"
        );
    }

    #[test]
    fn literal_and_type_helpers_have_stable_fallbacks() {
        assert_eq!(render_expr_literal_go(&Expr::IntLit(9)), "9");
        assert_eq!(render_expr_literal_go(&Expr::BoolLit(false)), "false");
        assert_eq!(
            render_expr_literal_go(&Expr::Add(
                Box::new(Expr::IntLit(1)),
                Box::new(Expr::IntLit(2))
            )),
            "0"
        );
        assert_eq!(field_type_to_go("bool"), "bool");
        assert_eq!(field_type_to_go("nat"), "uint64");
        assert_eq!(field_type_to_go("int"), "int64");
        assert_eq!(field_type_to_go("enum"), "uint64");
    }

    #[test]
    fn go_codegen_emits_distinct_and_filtered_helpers_only_when_needed() {
        let filtered_src = include_str!("../../tarsier-dsl/../../examples/crypto_objects.trs");
        let filtered_program = tarsier_dsl::parse(filtered_src, "crypto_objects.trs").unwrap();
        let filtered = generate_go(&filtered_program.protocol.node).unwrap();
        assert!(filtered.contains("func countDistinctSenders"));
        assert!(filtered.contains("func countFiltered"));
        assert!(filtered.contains("func countDistinctFiltered"));

        let plain_src = include_str!("../../tarsier-dsl/../../examples/trivial_live.trs");
        let plain_program = tarsier_dsl::parse(plain_src, "trivial_live.trs").unwrap();
        let plain = generate_go(&plain_program.protocol.node).unwrap();
        assert!(!plain.contains("func countDistinctSenders"));
        assert!(!plain.contains("func countFiltered"));
        assert!(!plain.contains("func countDistinctFiltered"));
    }
}
