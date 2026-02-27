//! Diagnostic helpers for parse errors and lowering errors.

use tarsier_dsl::ast::{self, Program, VarType};
use tower_lsp::lsp_types::*;

use crate::code_actions::{collect_phase_names, find_closest};
use crate::utils::offset_to_range;

pub(crate) fn lowering_error_code(err: &tarsier_ir::lowering::LoweringError) -> String {
    use tarsier_ir::lowering::LoweringError::*;
    match err {
        UnknownParameter(_) => "tarsier::lower::unknown_param".into(),
        UnknownMessageType(_) => "tarsier::lower::unknown_message".into(),
        UnknownPhase(_) => "tarsier::lower::unknown_phase".into(),
        NoInitPhase(_) => "tarsier::lower::no_init_phase".into(),
        UnknownEnum(_) => "tarsier::lower::unknown_enum".into(),
        UnknownEnumVariant(..) => "tarsier::lower::unknown_enum_variant".into(),
        MissingEnumInit(_) => "tarsier::lower::missing_enum_init".into(),
        OutOfRange { .. } => "tarsier::lower::out_of_range".into(),
        InvalidRange(..) => "tarsier::lower::invalid_range".into(),
        Unsupported(_) => "tarsier::lower::unsupported".into(),
        Validation(_) => "tarsier::lower::validation".into(),
    }
}

pub(crate) fn lowering_error_message(
    err: &tarsier_ir::lowering::LoweringError,
    program: &Program,
) -> String {
    use tarsier_ir::lowering::LoweringError::*;
    match err {
        UnknownPhase(name) => {
            let known = collect_phase_names(program);
            if let Some(suggestion) = find_closest(name, &known) {
                format!("Unknown phase '{name}' in goto. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown phase '{name}' in goto")
            }
        }
        UnknownMessageType(name) => {
            let known: Vec<String> = program
                .protocol
                .node
                .messages
                .iter()
                .map(|m| m.name.clone())
                .collect();
            if let Some(suggestion) = find_closest(name, &known) {
                format!("Unknown message type '{name}'. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown message type '{name}'")
            }
        }
        NoInitPhase(role) => {
            format!("Role '{role}' has no init phase. Add `init <phase_name>;` inside the role.")
        }
        UnknownEnumVariant(variant, enum_name) => {
            let known_variants: Vec<String> = program
                .protocol
                .node
                .enums
                .iter()
                .find(|e| e.name == *enum_name)
                .map(|e| e.variants.clone())
                .unwrap_or_default();
            if let Some(suggestion) = find_closest(variant, &known_variants) {
                format!("Unknown enum variant '{variant}' for enum '{enum_name}'. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown enum variant '{variant}' for enum '{enum_name}'")
            }
        }
        UnknownParameter(param) => {
            let known_params: Vec<String> = program
                .protocol
                .node
                .parameters
                .iter()
                .map(|p| p.name.clone())
                .collect();
            if let Some(suggestion) = find_closest(param, &known_params) {
                format!("Unknown parameter '{param}' in expression. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown parameter '{param}' in expression")
            }
        }
        _ => format!("{err}"),
    }
}

pub(crate) fn parse_error_span_and_code(
    err: &tarsier_dsl::errors::ParseError,
    text: &str,
) -> (Range, String) {
    use tarsier_dsl::errors::ParseError::*;
    match err {
        Syntax { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::syntax".into())
        }
        UnexpectedToken { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::unexpected".into())
        }
        Duplicate { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::duplicate".into())
        }
        MissingSection { .. } => {
            let range = Range::new(Position::new(0, 0), Position::new(0, 1));
            (range, "tarsier::parse::missing_section".into())
        }
        InvalidField { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::invalid_field".into())
        }
        UnsupportedInModule { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::unsupported_in_module".into())
        }
        ImportResolution { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::import_resolution".into())
        }
        MultipleErrors(errs) => {
            // Use the span/code from the first error, if any
            if let Some(first) = errs.errors.first() {
                parse_error_span_and_code(first, text)
            } else {
                let range = Range::new(Position::new(0, 0), Position::new(0, 1));
                (range, "tarsier::parse::multiple_errors".into())
            }
        }
    }
}

pub(crate) fn parse_error_diagnostics(
    err: &tarsier_dsl::errors::ParseError,
    text: &str,
) -> Vec<Diagnostic> {
    use tarsier_dsl::errors::ParseError::MultipleErrors;

    match err {
        MultipleErrors(errs) if !errs.errors.is_empty() => {
            let mut diagnostics = Vec::new();
            for nested in &errs.errors {
                for diag in parse_error_diagnostics(nested, text) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }
            }
            diagnostics
        }
        _ => {
            let (range, code_str) = parse_error_span_and_code(err, text);
            vec![Diagnostic {
                range,
                severity: Some(DiagnosticSeverity::ERROR),
                source: Some("tarsier".into()),
                code: Some(NumberOrString::String(code_str)),
                message: format!("{err}"),
                ..Default::default()
            }]
        }
    }
}

pub(crate) fn range_from_span_or_default(text: &str, span: ast::Span) -> Range {
    offset_to_range(text, span.start, span.end)
        .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)))
}

pub(crate) fn push_unique_diagnostic(diagnostics: &mut Vec<Diagnostic>, candidate: Diagnostic) {
    let exists = diagnostics.iter().any(|d| {
        d.range == candidate.range && d.code == candidate.code && d.message == candidate.message
    });
    if !exists {
        diagnostics.push(candidate);
    }
}

pub(crate) fn lowering_error_diag(code: &str, message: String, range: Range) -> Diagnostic {
    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some("tarsier".into()),
        code: Some(NumberOrString::String(code.to_string())),
        message,
        ..Default::default()
    }
}

fn collect_linear_expr_vars(expr: &ast::LinearExpr, out: &mut Vec<String>) {
    match expr {
        ast::LinearExpr::Var(name) => out.push(name.clone()),
        ast::LinearExpr::Add(l, r) | ast::LinearExpr::Sub(l, r) => {
            collect_linear_expr_vars(l, out);
            collect_linear_expr_vars(r, out);
        }
        ast::LinearExpr::Mul(_, e) => collect_linear_expr_vars(e, out),
        ast::LinearExpr::Const(_) => {}
    }
}

fn push_guard_unknown_param_diagnostics(
    guard: &ast::GuardExpr,
    transition_span: ast::Span,
    known_params: &[String],
    text: &str,
    out: &mut Vec<Diagnostic>,
) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            let mut vars = Vec::new();
            collect_linear_expr_vars(&tg.threshold, &mut vars);
            for var_name in vars {
                if !known_params.iter().any(|p| p == &var_name) {
                    let mut msg = format!("Unknown parameter '{var_name}' in expression");
                    if let Some(suggestion) = find_closest(&var_name, known_params) {
                        msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                    }
                    push_unique_diagnostic(
                        out,
                        lowering_error_diag(
                            "tarsier::lower::unknown_param",
                            msg,
                            range_from_span_or_default(text, transition_span),
                        ),
                    );
                }
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            push_guard_unknown_param_diagnostics(lhs, transition_span, known_params, text, out);
            push_guard_unknown_param_diagnostics(rhs, transition_span, known_params, text, out);
        }
        _ => {}
    }
}

fn push_guard_unknown_message_diagnostics(
    guard: &ast::GuardExpr,
    transition_span: ast::Span,
    known_messages: &[String],
    known_crypto_objects: &[String],
    text: &str,
    out: &mut Vec<Diagnostic>,
) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            let known = known_messages
                .iter()
                .chain(known_crypto_objects.iter())
                .any(|name| name == &tg.message_type);
            if !known {
                let mut msg = format!("Unknown message type '{}'", tg.message_type);
                let mut candidates = known_messages.to_vec();
                candidates.extend_from_slice(known_crypto_objects);
                if let Some(suggestion) = find_closest(&tg.message_type, &candidates) {
                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                }
                push_unique_diagnostic(
                    out,
                    lowering_error_diag(
                        "tarsier::lower::unknown_message",
                        msg,
                        range_from_span_or_default(text, transition_span),
                    ),
                );
            }
        }
        ast::GuardExpr::HasCryptoObject { object_name, .. } => {
            if !known_crypto_objects.iter().any(|name| name == object_name) {
                let mut msg = format!("Unknown cryptographic object '{object_name}'");
                if let Some(suggestion) = find_closest(object_name, known_crypto_objects) {
                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                }
                push_unique_diagnostic(
                    out,
                    lowering_error_diag(
                        "tarsier::lower::unknown_message",
                        msg,
                        range_from_span_or_default(text, transition_span),
                    ),
                );
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            push_guard_unknown_message_diagnostics(
                lhs,
                transition_span,
                known_messages,
                known_crypto_objects,
                text,
                out,
            );
            push_guard_unknown_message_diagnostics(
                rhs,
                transition_span,
                known_messages,
                known_crypto_objects,
                text,
                out,
            );
        }
        _ => {}
    }
}

pub(crate) fn collect_structural_lowering_diagnostics(
    program: &Program,
    text: &str,
) -> Vec<Diagnostic> {
    let proto = &program.protocol.node;
    let known_messages: Vec<String> = proto.messages.iter().map(|m| m.name.clone()).collect();
    let known_crypto_objects: Vec<String> = proto
        .crypto_objects
        .iter()
        .map(|o| o.name.clone())
        .collect();
    let known_enums: Vec<String> = proto.enums.iter().map(|e| e.name.clone()).collect();
    let known_params: Vec<String> = proto.parameters.iter().map(|p| p.name.clone()).collect();
    // Build a map from enum name -> variants for quick lookup.
    let enum_variants: std::collections::HashMap<&str, &[String]> = proto
        .enums
        .iter()
        .map(|e| (e.name.as_str(), e.variants.as_slice()))
        .collect();
    let mut diagnostics = Vec::new();

    for role in &proto.roles {
        if role.node.init_phase.is_none() {
            push_unique_diagnostic(
                &mut diagnostics,
                lowering_error_diag(
                    "tarsier::lower::no_init_phase",
                    format!(
                        "Role '{}' has no init phase. Add `init <phase_name>;` inside the role.",
                        role.node.name
                    ),
                    range_from_span_or_default(text, role.span),
                ),
            );
        }

        let role_phase_names: Vec<String> = role
            .node
            .phases
            .iter()
            .map(|p| p.node.name.clone())
            .collect();
        for var in &role.node.vars {
            if let VarType::Enum(enum_name) = &var.ty {
                if !known_enums.iter().any(|e| e == enum_name) {
                    let mut msg = format!("Unknown enum type '{enum_name}'");
                    if let Some(suggestion) = find_closest(enum_name, &known_enums) {
                        msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                    }
                    push_unique_diagnostic(
                        &mut diagnostics,
                        lowering_error_diag(
                            "tarsier::lower::unknown_enum",
                            msg,
                            range_from_span_or_default(text, var.span),
                        ),
                    );
                } else if var.init.is_none() {
                    push_unique_diagnostic(
                        &mut diagnostics,
                        lowering_error_diag(
                            "tarsier::lower::missing_enum_init",
                            format!("Missing init value for enum variable '{}'", var.name),
                            range_from_span_or_default(text, var.span),
                        ),
                    );
                } else if let Some(ast::Expr::Var(init_name)) = &var.init {
                    // Check if the init value is a valid variant of the enum.
                    if let Some(variants) = enum_variants.get(enum_name.as_str()) {
                        if !variants.iter().any(|v| v == init_name) {
                            let known_v: Vec<String> = variants.to_vec();
                            let mut msg = format!(
                                "Unknown enum variant '{init_name}' for enum '{enum_name}'"
                            );
                            if let Some(suggestion) = find_closest(init_name, &known_v) {
                                msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                            }
                            push_unique_diagnostic(
                                &mut diagnostics,
                                lowering_error_diag(
                                    "tarsier::lower::unknown_enum_variant",
                                    msg,
                                    range_from_span_or_default(text, var.span),
                                ),
                            );
                        }
                    }
                }
            }
        }

        for phase in &role.node.phases {
            for transition in &phase.node.transitions {
                push_guard_unknown_message_diagnostics(
                    &transition.node.guard,
                    transition.span,
                    &known_messages,
                    &known_crypto_objects,
                    text,
                    &mut diagnostics,
                );

                push_guard_unknown_param_diagnostics(
                    &transition.node.guard,
                    transition.span,
                    &known_params,
                    text,
                    &mut diagnostics,
                );

                for action in &transition.node.actions {
                    match action {
                        ast::Action::GotoPhase { phase } => {
                            if !role_phase_names.iter().any(|p| p == phase) {
                                let mut msg = format!("Unknown phase '{phase}' in goto");
                                if let Some(suggestion) = find_closest(phase, &role_phase_names) {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_phase",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        ast::Action::Send { message_type, .. } => {
                            let known = known_messages
                                .iter()
                                .chain(known_crypto_objects.iter())
                                .any(|name| name == message_type);
                            if !known {
                                let mut candidates = known_messages.clone();
                                candidates.extend_from_slice(&known_crypto_objects);
                                let mut msg = format!("Unknown message type '{message_type}'");
                                if let Some(suggestion) = find_closest(message_type, &candidates) {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_message",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        ast::Action::FormCryptoObject { object_name, .. }
                        | ast::Action::LockCryptoObject { object_name, .. }
                        | ast::Action::JustifyCryptoObject { object_name, .. } => {
                            if !known_crypto_objects.iter().any(|name| name == object_name) {
                                let mut msg =
                                    format!("Unknown cryptographic object '{object_name}'");
                                if let Some(suggestion) =
                                    find_closest(object_name, &known_crypto_objects)
                                {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_message",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        ast::Action::Assign {
                            var: var_name,
                            value: ast::Expr::Var(assigned_name),
                        } => {
                            // Check if this assignment targets an enum variable
                            // with an unknown variant value.
                            if let Some(var_decl) =
                                role.node.vars.iter().find(|v| v.name == *var_name)
                            {
                                if let VarType::Enum(enum_name) = &var_decl.ty {
                                    if let Some(variants) = enum_variants.get(enum_name.as_str()) {
                                        if !variants.iter().any(|v| v == assigned_name) {
                                            let known_v: Vec<String> = variants.to_vec();
                                            let mut msg = format!(
                                                "Unknown enum variant '{assigned_name}' for enum '{enum_name}'"
                                            );
                                            if let Some(suggestion) =
                                                find_closest(assigned_name, &known_v)
                                            {
                                                msg.push_str(&format!(
                                                    ". Did you mean '{suggestion}'?"
                                                ));
                                            }
                                            push_unique_diagnostic(
                                                &mut diagnostics,
                                                lowering_error_diag(
                                                    "tarsier::lower::unknown_enum_variant",
                                                    msg,
                                                    range_from_span_or_default(
                                                        text,
                                                        transition.span,
                                                    ),
                                                ),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    diagnostics
}

pub(crate) fn diagnostic_has_code(diag: &Diagnostic, code: &str) -> bool {
    matches!(diag.code.as_ref(), Some(NumberOrString::String(s)) if s == code)
}

pub(crate) fn has_diagnostic_code(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics
        .iter()
        .any(|diag| diagnostic_has_code(diag, code))
}

pub(crate) fn is_structural_lowering_code(code: &str) -> bool {
    matches!(
        code,
        "tarsier::lower::no_init_phase"
            | "tarsier::lower::unknown_enum"
            | "tarsier::lower::missing_enum_init"
            | "tarsier::lower::unknown_phase"
            | "tarsier::lower::unknown_message"
            | "tarsier::lower::unknown_enum_variant"
            | "tarsier::lower::unknown_param"
    )
}

pub(crate) fn collect_lowering_diagnostics(
    program: &Program,
    text: &str,
    filename: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = collect_structural_lowering_diagnostics(program, text);

    // Use the multi-error lowering function to collect as many errors as
    // possible instead of stopping at the first one.
    let (_ta, lowering_errors) =
        tarsier_ir::lowering::lower_with_source_multi(program, text, filename);

    for e in &lowering_errors {
        let range = e
            .span
            .map(|s| {
                let start = s.offset();
                let end = start + s.len();
                offset_to_range(text, start, end)
                    .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)))
            })
            .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));

        let code_str = lowering_error_code(&e.inner);
        let message = lowering_error_message(&e.inner, program);
        let fallback_diag = lowering_error_diag(&code_str, message, range);

        if !is_structural_lowering_code(&code_str) || !has_diagnostic_code(&diagnostics, &code_str)
        {
            push_unique_diagnostic(&mut diagnostics, fallback_diag);
        }
    }

    diagnostics
}
