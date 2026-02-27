//! Inlay hint generation for the Tarsier DSL.
//!
//! Provides inline hints for:
//! - Variable type annotations (range bounds for int/nat, enum type name)
//! - Threshold guard parameter hints (contextual info about thresholds)
//! - Committee bound hints (computed bound parameter info)

use tower_lsp::lsp_types::*;

use tarsier_dsl::ast::{
    CommitteeDecl, CommitteeValue, GuardExpr, LinearExpr, Program, ThresholdGuard, VarDecl, VarType,
};

use crate::utils::offset_to_position;

/// Build inlay hints for an entire program.
pub(crate) fn build_inlay_hints(source: &str, program: &Program) -> Vec<InlayHint> {
    let mut hints = Vec::new();
    let proto = &program.protocol.node;

    // Variable type hints for each role
    for role in &proto.roles {
        for var in &role.node.vars {
            if let Some(hint) = var_type_hint(source, var) {
                hints.push(hint);
            }
        }

        // Threshold guard hints in transitions
        for phase in &role.node.phases {
            for transition in &phase.node.transitions {
                collect_guard_hints(source, &transition.node.guard, proto, &mut hints);
            }
        }
    }

    // Committee bound hints
    for committee in &proto.committees {
        if let Some(hint) = committee_bound_hint(source, committee) {
            hints.push(hint);
        }
    }

    hints
}

/// Generate an inlay hint for a variable declaration showing type/range info.
fn var_type_hint(source: &str, var: &VarDecl) -> Option<InlayHint> {
    let label = match (&var.ty, &var.range) {
        (VarType::Int, Some(range)) => format!(" [{}, {}]", range.min, range.max),
        (VarType::Nat, Some(range)) => format!(" [{}, {}]", range.min, range.max),
        (VarType::Enum(enum_name), _) => format!(": {enum_name}"),
        (VarType::Bool, _) => return None, // bool is self-evident
        (VarType::Int, None) => return None,
        (VarType::Nat, None) => return None,
    };

    // Place the hint after the variable name.
    // We need to find the end of the variable name in the span.
    // The var span covers the whole declaration; we want to place the hint
    // right after the type annotation or the variable name.
    let var_end = var.span.end;
    let position = offset_to_position(source, var_end);

    Some(InlayHint {
        position,
        label: InlayHintLabel::String(label),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: Some(InlayHintTooltip::String(match &var.ty {
            VarType::Int => "Integer variable range bounds".to_string(),
            VarType::Nat => "Natural number variable range bounds".to_string(),
            VarType::Enum(name) => format!("Enum type: {name}"),
            VarType::Bool => "Boolean variable".to_string(),
        })),
        padding_left: Some(false),
        padding_right: Some(true),
        data: None,
    })
}

/// Describe a linear expression in human-readable form for threshold hints.
fn describe_threshold(threshold: &LinearExpr) -> String {
    // Try to detect common patterns like 2*t+1 (quorum), t+1 (weak quorum), n-t, etc.
    match threshold {
        LinearExpr::Add(lhs, rhs) => {
            if let (LinearExpr::Mul(coeff, inner), LinearExpr::Const(1)) =
                (lhs.as_ref(), rhs.as_ref())
            {
                if *coeff == 2 {
                    return format!("quorum (2*{}+1)", inner);
                }
            }
            if let (LinearExpr::Var(_), LinearExpr::Const(1)) = (lhs.as_ref(), rhs.as_ref()) {
                return format!("weak quorum ({threshold})");
            }
            format!("{threshold}")
        }
        LinearExpr::Const(1) => "single message".to_string(),
        LinearExpr::Const(c) => format!("{c} messages"),
        LinearExpr::Var(v) => v.clone(),
        LinearExpr::Sub(lhs, _rhs) => {
            if let LinearExpr::Var(v) = lhs.as_ref() {
                return format!("all-minus ({v} - ...)");
            }
            format!("{threshold}")
        }
        LinearExpr::Mul(coeff, inner) => {
            if *coeff == 2 {
                format!("2*{inner}")
            } else {
                format!("{threshold}")
            }
        }
    }
}

/// Collect inlay hints for guard expressions (threshold guards).
fn collect_guard_hints(
    source: &str,
    guard: &GuardExpr,
    _proto: &tarsier_dsl::ast::ProtocolDecl,
    hints: &mut Vec<InlayHint>,
) {
    match guard {
        GuardExpr::Threshold(tg) => {
            if let Some(hint) = threshold_guard_hint(source, tg) {
                hints.push(hint);
            }
        }
        GuardExpr::And(lhs, rhs) | GuardExpr::Or(lhs, rhs) => {
            collect_guard_hints(source, lhs, _proto, hints);
            collect_guard_hints(source, rhs, _proto, hints);
        }
        _ => {}
    }
}

/// Generate an inlay hint for a threshold guard showing the threshold description.
fn threshold_guard_hint(source: &str, tg: &ThresholdGuard) -> Option<InlayHint> {
    let description = describe_threshold(&tg.threshold);

    // We want to place the hint after the message type name in the guard.
    // The threshold guard doesn't have its own span, so we search the source
    // for the message type pattern near the threshold expression.
    // Since we don't have span info on the guard itself, we search for the
    // pattern "received ... <MessageType>" in source and use the end of the
    // message type as the position.
    let msg_type = &tg.message_type;
    // Find occurrences of the message type in the source that follow "received"
    let mut search_start = 0;
    while let Some(pos) = source[search_start..].find(msg_type) {
        let abs_pos = search_start + pos;
        let end_pos = abs_pos + msg_type.len();

        // Check that this is preceded by "received" somewhere earlier on the same
        // line-ish context (within ~80 chars)
        let lookback_start = abs_pos.saturating_sub(80);
        let before = &source[lookback_start..abs_pos];
        if before.contains("received") {
            let position = offset_to_position(source, end_pos);
            return Some(InlayHint {
                position,
                label: InlayHintLabel::String(format!(" // {description}")),
                kind: Some(InlayHintKind::PARAMETER),
                text_edits: None,
                tooltip: Some(InlayHintTooltip::String(format!(
                    "Threshold: {} {} {}",
                    tg.op, tg.threshold, msg_type
                ))),
                padding_left: Some(true),
                padding_right: Some(false),
                data: None,
            });
        }

        search_start = abs_pos + 1;
    }

    None
}

/// Generate an inlay hint for a committee declaration showing bound info.
fn committee_bound_hint(source: &str, committee: &CommitteeDecl) -> Option<InlayHint> {
    let mut population = None;
    let mut byzantine = None;
    let mut size = None;
    let mut epsilon = None;
    let mut bound_param = None;

    for item in &committee.items {
        match item.key.as_str() {
            "population" => {
                if let CommitteeValue::Int(v) = &item.value {
                    population = Some(*v);
                }
            }
            "byzantine" => {
                if let CommitteeValue::Int(v) = &item.value {
                    byzantine = Some(*v);
                }
            }
            "size" => {
                if let CommitteeValue::Int(v) = &item.value {
                    size = Some(*v);
                }
            }
            "epsilon" => {
                if let CommitteeValue::Float(v) = &item.value {
                    epsilon = Some(*v);
                }
            }
            "bound_param" => {
                if let CommitteeValue::Param(p) = &item.value {
                    bound_param = Some(p.clone());
                }
            }
            _ => {}
        }
    }

    let label = match (population, byzantine, size, epsilon, bound_param) {
        (Some(pop), Some(byz), Some(sz), Some(eps), Some(bp)) => {
            format!(" // N={pop}, K={byz}, S={sz}, eps={eps:.0e} -> {bp}",)
        }
        (Some(pop), Some(byz), Some(sz), _, Some(bp)) => {
            format!(" // N={pop}, K={byz}, S={sz} -> {bp}")
        }
        _ => return None,
    };

    let position = offset_to_position(source, committee.span.end);

    Some(InlayHint {
        position,
        label: InlayHintLabel::String(label),
        kind: Some(InlayHintKind::PARAMETER),
        text_edits: None,
        tooltip: Some(InlayHintTooltip::String(format!(
            "Committee '{}': hypergeometric analysis for committee selection",
            committee.name
        ))),
        padding_left: Some(true),
        padding_right: Some(false),
        data: None,
    })
}
