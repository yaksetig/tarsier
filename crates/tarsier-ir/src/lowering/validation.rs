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
