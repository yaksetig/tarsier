//! Span lookup and validation helpers for lowering diagnostics.

use tarsier_dsl::ast;

use super::LoweringError;

/// Best-effort span lookup for a lowering error by examining the AST.
pub(super) fn find_span_for_error(
    err: &LoweringError,
    program: &ast::Program,
) -> Option<ast::Span> {
    let proto = &program.protocol.node;
    match err {
        LoweringError::UnknownPhase(name) => {
            // Search transition actions for GotoPhase with the unknown phase name
            for role in &proto.roles {
                for phase in &role.node.phases {
                    for tr in &phase.node.transitions {
                        for action in &tr.node.actions {
                            if let ast::Action::GotoPhase { phase } = action {
                                if phase == name {
                                    return Some(tr.span);
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        LoweringError::NoInitPhase(role_name) => {
            for role in &proto.roles {
                if role.node.name == *role_name {
                    return Some(role.span);
                }
            }
            None
        }
        LoweringError::UnknownMessageType(msg_name) => {
            // Search transition actions for Send with the unknown message
            for role in &proto.roles {
                for phase in &role.node.phases {
                    for tr in &phase.node.transitions {
                        for action in &tr.node.actions {
                            if let ast::Action::Send { message_type, .. } = action {
                                if message_type == msg_name {
                                    return Some(tr.span);
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        LoweringError::UnknownParameter(param_name) => {
            for p in &proto.parameters {
                if p.name == *param_name {
                    return Some(p.span);
                }
            }
            None
        }
        LoweringError::OutOfRange { var, .. } | LoweringError::InvalidRange(var, ..) => {
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.name == *var {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::UnknownEnum(enum_name) => {
            // Search enum declarations for the unknown type name.
            for e in &proto.enums {
                if e.name == *enum_name {
                    return Some(e.span);
                }
            }
            // Fall back to searching variables whose type matches.
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.ty == ast::VarType::Enum(enum_name.clone()) {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::MissingEnumInit(var_name) => {
            // MissingEnumInit carries the variable name.
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.name == *var_name {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::UnknownEnumVariant(_, enum_name) => {
            // Search enum declarations first.
            for e in &proto.enums {
                if e.name == *enum_name {
                    return Some(e.span);
                }
            }
            // Fall back to variables of this enum type.
            for role in &proto.roles {
                for v in &role.node.vars {
                    if v.ty == ast::VarType::Enum(enum_name.clone()) {
                        return Some(v.span);
                    }
                }
            }
            None
        }
        LoweringError::Unsupported(_) | LoweringError::Validation(_) => Some(program.protocol.span),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tarsier_dsl::parse;

    fn fixture_program() -> ast::Program {
        let src = r#"
protocol SpanLookup {
    params n, t;
    resilience: n > 3*t;
    enum Known { a, b };
    message Ping;
    role WithInit {
        var status: Known = a;
        var x: int in 0..3 = 1;
        var missing: MissingType = foo;
        init ready;
        phase ready {
            when received >= 1 Ping => {
                send MissingMsg;
                goto phase ghost;
            }
        }
    }
    role NoInit {
        phase wait {}
    }
}
"#;
        parse(src, "span_lookup.trs").expect("fixture should parse")
    }

    fn role<'a>(program: &'a ast::Program, name: &str) -> &'a ast::Spanned<ast::RoleDecl> {
        program
            .protocol
            .node
            .roles
            .iter()
            .find(|r| r.node.name == name)
            .expect("role should exist")
    }

    fn role_var_span(program: &ast::Program, role_name: &str, var_name: &str) -> ast::Span {
        role(program, role_name)
            .node
            .vars
            .iter()
            .find(|v| v.name == var_name)
            .expect("var should exist")
            .span
    }

    fn enum_span(program: &ast::Program, enum_name: &str) -> ast::Span {
        program
            .protocol
            .node
            .enums
            .iter()
            .find(|e| e.name == enum_name)
            .expect("enum should exist")
            .span
    }

    fn first_transition_span(program: &ast::Program, role_name: &str) -> ast::Span {
        role(program, role_name).node.phases[0].node.transitions[0].span
    }

    #[test]
    fn maps_unknown_phase_to_transition_span() {
        let program = fixture_program();
        let span = find_span_for_error(&LoweringError::UnknownPhase("ghost".into()), &program);
        assert_eq!(span, Some(first_transition_span(&program, "WithInit")));
    }

    #[test]
    fn maps_no_init_phase_to_role_span() {
        let program = fixture_program();
        let span = find_span_for_error(&LoweringError::NoInitPhase("NoInit".into()), &program);
        assert_eq!(span, Some(role(&program, "NoInit").span));
    }

    #[test]
    fn maps_unknown_message_type_to_transition_span() {
        let program = fixture_program();
        let span = find_span_for_error(
            &LoweringError::UnknownMessageType("MissingMsg".into()),
            &program,
        );
        assert_eq!(span, Some(first_transition_span(&program, "WithInit")));
    }

    #[test]
    fn maps_unknown_parameter_to_parameter_span() {
        let program = fixture_program();
        let expected = program.protocol.node.parameters[0].span;
        let span = find_span_for_error(&LoweringError::UnknownParameter("n".into()), &program);
        assert_eq!(span, Some(expected));
    }

    #[test]
    fn maps_range_errors_to_variable_span() {
        let program = fixture_program();
        let expected = role_var_span(&program, "WithInit", "x");

        let out_of_range = find_span_for_error(
            &LoweringError::OutOfRange {
                var: "x".into(),
                value: 5,
                min: 0,
                max: 3,
            },
            &program,
        );
        assert_eq!(out_of_range, Some(expected));

        let invalid_range =
            find_span_for_error(&LoweringError::InvalidRange("x".into(), 3, 1), &program);
        assert_eq!(invalid_range, Some(expected));
    }

    #[test]
    fn maps_unknown_enum_to_enum_declaration_span_when_available() {
        let program = fixture_program();
        let span = find_span_for_error(&LoweringError::UnknownEnum("Known".into()), &program);
        assert_eq!(span, Some(enum_span(&program, "Known")));
    }

    #[test]
    fn maps_unknown_enum_to_variable_type_span_when_declaration_missing() {
        let program = fixture_program();
        let expected = role_var_span(&program, "WithInit", "missing");
        let span = find_span_for_error(&LoweringError::UnknownEnum("MissingType".into()), &program);
        assert_eq!(span, Some(expected));
    }

    #[test]
    fn maps_missing_enum_init_to_variable_span() {
        let program = fixture_program();
        let expected = role_var_span(&program, "WithInit", "status");
        let span = find_span_for_error(&LoweringError::MissingEnumInit("status".into()), &program);
        assert_eq!(span, Some(expected));
    }

    #[test]
    fn maps_unknown_enum_variant_to_enum_declaration_span_when_available() {
        let program = fixture_program();
        let span = find_span_for_error(
            &LoweringError::UnknownEnumVariant("zzz".into(), "Known".into()),
            &program,
        );
        assert_eq!(span, Some(enum_span(&program, "Known")));
    }

    #[test]
    fn maps_unknown_enum_variant_to_variable_type_span_when_declaration_missing() {
        let program = fixture_program();
        let expected = role_var_span(&program, "WithInit", "missing");
        let span = find_span_for_error(
            &LoweringError::UnknownEnumVariant("zzz".into(), "MissingType".into()),
            &program,
        );
        assert_eq!(span, Some(expected));
    }

    #[test]
    fn maps_unsupported_and_validation_errors_to_protocol_span() {
        let program = fixture_program();
        let protocol_span = Some(program.protocol.span);

        let unsupported = find_span_for_error(
            &LoweringError::Unsupported("not implemented".into()),
            &program,
        );
        assert_eq!(unsupported, protocol_span);

        let validation = find_span_for_error(
            &LoweringError::Validation("broken invariant".into()),
            &program,
        );
        assert_eq!(validation, protocol_span);
    }

    #[test]
    fn returns_none_when_error_payload_cannot_be_matched() {
        let program = fixture_program();

        assert_eq!(
            find_span_for_error(
                &LoweringError::UnknownPhase("absent_phase".into()),
                &program
            ),
            None
        );
        assert_eq!(
            find_span_for_error(
                &LoweringError::UnknownMessageType("absent_message".into()),
                &program
            ),
            None
        );
        assert_eq!(
            find_span_for_error(&LoweringError::NoInitPhase("absent_role".into()), &program),
            None
        );
        assert_eq!(
            find_span_for_error(
                &LoweringError::UnknownParameter("absent_param".into()),
                &program
            ),
            None
        );
        assert_eq!(
            find_span_for_error(
                &LoweringError::InvalidRange("absent_var".into(), 1, 0),
                &program
            ),
            None
        );
    }
}
