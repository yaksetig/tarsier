// Threshold and distinct-sender analysis helpers.

pub(crate) fn guard_has_non_monotone_threshold(guard: &tarsier_dsl::ast::GuardExpr) -> bool {
    use tarsier_dsl::ast::{CmpOp, GuardExpr};
    match guard {
        GuardExpr::Threshold(t) => !matches!(t.op, CmpOp::Ge | CmpOp::Gt),
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            guard_has_non_monotone_threshold(l) || guard_has_non_monotone_threshold(r)
        }
        _ => false,
    }
}

pub(crate) fn guard_uses_distinct_threshold(guard: &tarsier_dsl::ast::GuardExpr) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    match guard {
        GuardExpr::Threshold(t) => t.distinct,
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            guard_uses_distinct_threshold(l) || guard_uses_distinct_threshold(r)
        }
        _ => false,
    }
}

pub(crate) fn collect_distinct_roles_from_guard(
    guard: &tarsier_dsl::ast::GuardExpr,
    out: &mut Vec<String>,
) {
    use tarsier_dsl::ast::GuardExpr;
    match guard {
        GuardExpr::Threshold(t) => {
            if t.distinct {
                if let Some(role) = &t.distinct_role {
                    if !out.contains(role) {
                        out.push(role.clone());
                    }
                }
            }
        }
        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
            collect_distinct_roles_from_guard(l, out);
            collect_distinct_roles_from_guard(r, out);
        }
        _ => {}
    }
}

pub(crate) fn protocol_uses_thresholds(program: &tarsier_dsl::ast::Program) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase.node.transitions.iter().any(|tr| {
                fn has_threshold(guard: &GuardExpr) -> bool {
                    match guard {
                        GuardExpr::Threshold(_) => true,
                        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
                            has_threshold(l) || has_threshold(r)
                        }
                        _ => false,
                    }
                }
                has_threshold(&tr.node.guard)
            })
        })
    })
}

pub(crate) fn protocol_uses_distinct_thresholds(program: &tarsier_dsl::ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_distinct_threshold(&tr.node.guard))
        })
    })
}

pub(crate) fn protocol_distinct_roles(program: &tarsier_dsl::ast::Program) -> Vec<String> {
    let mut roles = Vec::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_roles_from_guard(&tr.node.guard, &mut roles);
            }
        }
    }
    roles
}
