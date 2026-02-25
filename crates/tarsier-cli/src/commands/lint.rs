// Command handler for: Lint
//
// Extracts lint-related types, helpers, and the main lint pipeline from main.rs
// into a self-contained module.

use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde::Serialize;

use tarsier_dsl::ast::Span as DslSpan;
use tarsier_engine::pipeline::SoundnessMode;

use super::helpers::{parse_output_format, parse_soundness_mode, sandbox_read_source};
use crate::{CliNetworkSemanticsMode, OutputFormat};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct LintFix {
    pub(crate) label: String,
    pub(crate) snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) insert_offset: Option<usize>,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub(crate) struct LintSourceSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) end_line: usize,
    pub(crate) end_column: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct LintIssue {
    pub(crate) severity: String,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) soundness_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fix: Option<LintFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_span: Option<LintSourceSpan>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LintReport {
    pub(crate) schema_version: u32,
    pub(crate) file: String,
    pub(crate) soundness: String,
    pub(crate) issues: Vec<LintIssue>,
}

// ---------------------------------------------------------------------------
// Guard / threshold helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Faithful-proof suggestion helpers
// ---------------------------------------------------------------------------

pub(crate) fn faithful_identity_decl_snippet(
    role: &str,
    scope: tarsier_dsl::ast::IdentityScope,
    process_var: Option<&str>,
    key: &str,
) -> String {
    match scope {
        tarsier_dsl::ast::IdentityScope::Role => {
            format!("identity {role}: role key {key};")
        }
        tarsier_dsl::ast::IdentityScope::Process => format!(
            "identity {role}: process({}) key {key};",
            process_var.unwrap_or("pid")
        ),
    }
}

pub(crate) fn suggested_identity_scope_for_network(
    network_mode: &str,
) -> (tarsier_dsl::ast::IdentityScope, Option<&'static str>) {
    if network_mode == "process_selective" {
        (tarsier_dsl::ast::IdentityScope::Process, Some("pid"))
    } else {
        (tarsier_dsl::ast::IdentityScope::Role, None)
    }
}

pub(crate) fn faithful_missing_identity_suggestion(
    missing_roles: &[String],
    network_mode: &str,
) -> Option<String> {
    if missing_roles.is_empty() {
        return None;
    }
    let (scope, process_var) = suggested_identity_scope_for_network(network_mode);
    let mut lines = Vec::new();
    lines.push("Add these identity declarations:".to_string());
    for role in missing_roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_identity_key_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    roles_without_key: &[String],
    network_mode: &str,
) -> Option<String> {
    if roles_without_key.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Add explicit keys to these identity declarations:".to_string());
    for role in roles_without_key {
        let scope = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .map(|id| id.scope)
            .unwrap_or_else(|| suggested_identity_scope_for_network(network_mode).0);
        let process_var = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .and_then(|id| id.process_var.as_deref())
            .or_else(|| suggested_identity_scope_for_network(network_mode).1);
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_process_identity_suggestion(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Use process-scoped identities for these roles:".to_string());
    for role in roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!("  identity {role}: process(pid) key {key};"));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_auth_suggestion(messages: &[String]) -> Option<String> {
    if messages.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Choose one auth strategy for faithful proofs:".to_string());
    lines.push("  Option A: adversary { auth: signed; }".to_string());
    lines.push("  Option B: add per-message channels:".to_string());
    for msg in messages {
        lines.push(format!("    channel {msg}: authenticated;"));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_equivocation_suggestion() -> Option<String> {
    Some(
        "Declare an explicit policy: `adversary { equivocation: full; }` (over-approx) \
or `adversary { equivocation: none; }` (non-equivocating)."
            .to_string(),
    )
}

pub(crate) fn faithful_proof_scaffold_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    network_mode: &str,
) -> String {
    let role_names: std::collections::HashSet<String> =
        proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let identity_roles: std::collections::HashSet<String> =
        proto.identities.iter().map(|id| id.role.clone()).collect();
    let mut missing_identity_roles: Vec<String> =
        role_names.difference(&identity_roles).cloned().collect();
    missing_identity_roles.sort();
    let channel_covered: std::collections::HashSet<String> =
        proto.channels.iter().map(|c| c.message.clone()).collect();
    let mut missing_auth_messages: Vec<String> = proto
        .messages
        .iter()
        .map(|m| m.name.clone())
        .filter(|m| !channel_covered.contains(m))
        .collect();
    missing_auth_messages.sort();
    let mut lines = Vec::new();
    lines.push("Use faithful-proof baseline:".to_string());
    lines.push("  adversary { network: process_selective; auth: signed; }".to_string());
    if let Some(s) =
        faithful_missing_identity_suggestion(&missing_identity_roles, "process_selective")
    {
        lines.push(s);
    }
    if let Some(s) = faithful_missing_auth_suggestion(&missing_auth_messages) {
        lines.push(s);
    }
    if lines.len() == 1 {
        lines.push(format!(
            "  (network currently `{network_mode}`; add the adversary line above to switch to faithful semantics)"
        ));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Source-span helpers
// ---------------------------------------------------------------------------

pub(crate) fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let clamped = offset.min(source.len());
    for (idx, ch) in source.char_indices() {
        if idx >= clamped {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

pub(crate) fn lint_source_span(source: &str, span: DslSpan) -> LintSourceSpan {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len()).max(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let (end_line, end_column) = byte_offset_to_line_col(source, end);
    LintSourceSpan {
        start,
        end,
        line,
        column,
        end_line,
        end_column,
    }
}

pub(crate) fn line_col_to_byte_offset(source: &str, line: usize, column: usize) -> usize {
    if line <= 1 && column <= 1 {
        return 0;
    }
    let mut cur_line = 1usize;
    let mut cur_col = 1usize;
    for (idx, ch) in source.char_indices() {
        if cur_line == line && cur_col == column {
            return idx;
        }
        if ch == '\n' {
            cur_line += 1;
            cur_col = 1;
        } else {
            cur_col += 1;
        }
    }
    source.len()
}

pub(crate) fn advance_one_char(source: &str, start: usize) -> usize {
    if start >= source.len() {
        return start;
    }
    let tail = &source[start..];
    let char_len = tail.chars().next().map(char::len_utf8).unwrap_or(1);
    (start + char_len).min(source.len())
}

pub(crate) fn infer_parse_error_span(source: &str, message: &str) -> Option<DslSpan> {
    let marker = "-->";
    if let Some(idx) = message.find(marker) {
        let tail = &message[idx + marker.len()..];
        let mut digits = String::new();
        let mut chars = tail.trim_start().chars().peekable();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(chars.next().unwrap_or_default());
        }
        if !digits.is_empty() && chars.peek() == Some(&':') {
            let _ = chars.next();
            let mut col_digits = String::new();
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                col_digits.push(chars.next().unwrap_or_default());
            }
            if let (Ok(line), Ok(column)) = (digits.parse::<usize>(), col_digits.parse::<usize>()) {
                let start = line_col_to_byte_offset(source, line.max(1), column.max(1));
                let end = advance_one_char(source, start);
                return Some(DslSpan { start, end });
            }
        }
    }
    if source.is_empty() {
        None
    } else {
        Some(DslSpan {
            start: 0,
            end: advance_one_char(source, 0),
        })
    }
}

// ---------------------------------------------------------------------------
// Soundness-impact & issue constructors
// ---------------------------------------------------------------------------

pub(crate) fn lint_soundness_impact(code: &str, severity: &str) -> Option<String> {
    let impact = match code {
        "parse_error" | "lowering_error" => {
            "Model could not be analyzed; no soundness claim can be established."
        }
        "missing_resilience" => {
            "Fault assumptions are under-specified; safety/liveness claims may be vacuous."
        }
        "missing_safety_property" => {
            "No explicit safety objective is checked; security claims may omit core invariants."
        }
        "missing_adversary_bound" | "missing_fault_bound" => {
            "Adversary power is under-constrained; verification may be unsound or misleading."
        }
        "missing_gst" => {
            "Partial-synchrony liveness assumptions are incomplete; liveness conclusions are unsound."
        }
        "unbounded_local_int" | "unbounded_message_field" => {
            "State space is not finitely bounded in the model abstraction; results may not be reliable."
        }
        "distinct_requires_signed_auth" => {
            "Distinct-sender thresholds need authenticated identities; otherwise sender-counting is unsound."
        }
        "non_monotone_threshold_full_equivocation" => {
            "Full-equivocation with non-monotone thresholds can produce unsound safety conclusions."
        }
        "faithful_mode_missing_identity_declarations"
        | "faithful_mode_missing_identity_keys"
        | "faithful_mode_missing_auth_semantics"
        | "faithful_mode_missing_equivocation_policy"
        | "process_selective_requires_process_identity"
        | "byzantine_network_not_identity_selective" => {
            "Network/auth assumptions are incomplete or weak; protocol-faithful soundness is not guaranteed."
        }
        "distinct_role_missing_population_param" => {
            "Role population is missing for distinct counting; threshold semantics may be unsound."
        }
        _ => {
            if severity == "error" {
                "Blocking modeling issue; verification soundness claim is not currently defensible."
            } else if severity == "warn" {
                "Modeling assumption weakens confidence in soundness/fidelity."
            } else {
                ""
            }
        }
    };
    if impact.is_empty() {
        None
    } else {
        Some(impact.to_string())
    }
}

pub(crate) fn lint_issue(
    source: &str,
    severity: &str,
    code: impl Into<String>,
    message: impl Into<String>,
    suggestion: Option<String>,
    fix: Option<LintFix>,
    span: Option<DslSpan>,
) -> LintIssue {
    let code = code.into();
    let severity_owned = severity.to_string();
    LintIssue {
        severity: severity_owned.clone(),
        code: code.clone(),
        message: message.into(),
        suggestion,
        soundness_impact: lint_soundness_impact(&code, &severity_owned),
        fix,
        source_span: span.map(|s| lint_source_span(source, s)),
    }
}

// ---------------------------------------------------------------------------
// Main lint pipeline
// ---------------------------------------------------------------------------

pub(crate) fn lint_protocol_file(
    source: &str,
    filename: &str,
    soundness: SoundnessMode,
) -> LintReport {
    let mut issues: Vec<LintIssue> = Vec::new();
    let (program, parse_diags) = match tarsier_dsl::parse_with_diagnostics(source, filename) {
        Ok(p) => p,
        Err(e) => {
            let parse_error = e.to_string();
            issues.push(lint_issue(
                source,
                "error",
                "parse_error",
                parse_error.clone(),
                None,
                None,
                infer_parse_error_span(source, &parse_error),
            ));
            return LintReport {
                schema_version: 1,
                file: filename.to_string(),
                soundness: soundness_name(soundness).to_string(),
                issues,
            };
        }
    };
    for diag in parse_diags {
        issues.push(lint_issue(
            source,
            "warn",
            diag.code,
            diag.message,
            diag.suggestion,
            None,
            diag.span,
        ));
    }

    let proto = &program.protocol.node;
    let protocol_span = Some(program.protocol.span);
    let has_n = proto.parameters.iter().any(|p| p.name == "n");
    let has_t = proto.parameters.iter().any(|p| p.name == "t");
    let adversary_item_span = |key: &str| -> Option<DslSpan> {
        proto
            .adversary
            .iter()
            .find(|i| i.key == key)
            .map(|i| i.span)
    };
    if !has_n {
        issues.push(lint_issue(
            source,
            "error",
            "missing_n_param",
            "Missing required parameter `n`.",
            Some("Add `params n, ...;`.".into()),
            None,
            protocol_span,
        ));
    }
    if !has_t {
        issues.push(lint_issue(
            source,
            "warn",
            "missing_t_param",
            "Parameter `t` is missing; many BFT resilience checks assume it.",
            Some("Add `t` or explain resilience with explicit bounds.".into()),
            None,
            protocol_span,
        ));
    }
    if proto.resilience.is_none() {
        let insert_offset = proto.parameters.last().map(|p| p.span.end);
        issues.push(lint_issue(
            source,
            "error",
            "missing_resilience",
            "Missing resilience declaration.",
            Some("Add `resilience: n = 3*f+1;` (or protocol-specific bound).".into()),
            Some(LintFix {
                label: "insert resilience".into(),
                snippet: "\n    resilience: n = 3*f + 1;".into(),
                insert_offset,
            }),
            protocol_span,
        ));
    }

    let safety_props = proto
        .properties
        .iter()
        .filter(|p| {
            matches!(
                p.node.kind,
                tarsier_dsl::ast::PropertyKind::Agreement
                    | tarsier_dsl::ast::PropertyKind::Safety
                    | tarsier_dsl::ast::PropertyKind::Invariant
                    | tarsier_dsl::ast::PropertyKind::Validity
            )
        })
        .count();
    if safety_props == 0 {
        // Insert before the closing } of the protocol
        let insert_offset = Some(program.protocol.span.end.saturating_sub(1));
        issues.push(lint_issue(
            source,
            "error",
            "missing_safety_property",
            "No safety property found.",
            Some("Declare one `property ...: safety|agreement|invariant|validity { ... }`.".into()),
            Some(LintFix {
                label: "insert safety property".into(),
                snippet:
                    "\n    property safety_inv: safety { forall p: Role. p.decided == false }\n"
                        .into(),
                insert_offset,
            }),
            protocol_span,
        ));
    } else if safety_props > 1 {
        issues.push(lint_issue(
            source,
            "warn",
            "multiple_safety_properties",
            "Multiple safety properties found; current verify path expects one primary safety objective.",
            Some("Split checks or keep one canonical safety property for CI.".into()),
            None,
            proto.properties.first().map(|p| p.span).or(protocol_span),
        ));
    }

    for role in &proto.roles {
        for var in &role.node.vars {
            if matches!(
                var.ty,
                tarsier_dsl::ast::VarType::Nat | tarsier_dsl::ast::VarType::Int
            ) && var.range.is_none()
            {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "unbounded_local_int",
                    format!(
                        "Unbounded local numeric variable '{}.{}'.",
                        role.node.name, var.name
                    ),
                    Some("Add `in a..b` bounds to keep abstraction finite.".into()),
                    Some(LintFix {
                        label: "append range bound".into(),
                        snippet: " in 0..N".into(),
                        insert_offset: Some(var.span.end),
                    }),
                    Some(var.span),
                ));
            }
        }
    }

    for msg in &proto.messages {
        for field in &msg.fields {
            if (field.ty == "nat" || field.ty == "int") && field.range.is_none() {
                issues.push(lint_issue(
                    source,
                    "warn",
                    "unbounded_message_field",
                    format!(
                        "Unbounded numeric message field '{}.{}'.",
                        msg.name, field.name
                    ),
                    Some("Add `in a..b` or use `adversary { values: sign; }` abstraction.".into()),
                    None,
                    Some(msg.span),
                ));
            }
        }
    }

    let uses_thresholds = protocol_uses_thresholds(&program);
    let uses_distinct_thresholds = protocol_uses_distinct_thresholds(&program);
    let mut adv_model: Option<&str> = None;
    let mut adv_bound = false;
    let mut timing_partial = false;
    let mut gst = false;
    let mut equivocation: &str = "full";
    let mut has_equivocation_field = false;
    let mut auth_mode: &str = "none";
    let mut has_auth_field = false;
    let mut network_mode: &str = "classic";
    for item in &proto.adversary {
        match item.key.as_str() {
            "model" => adv_model = Some(item.value.as_str()),
            "bound" => adv_bound = true,
            "timing" if item.value == "partial_synchrony" || item.value == "partial_sync" => {
                timing_partial = true
            }
            "gst" => gst = true,
            "equivocation" => {
                equivocation = item.value.as_str();
                has_equivocation_field = true;
            }
            "auth" | "authentication" => {
                auth_mode = item.value.as_str();
                has_auth_field = true;
            }
            "network" => network_mode = item.value.as_str(),
            _ => {}
        }
    }

    if uses_thresholds && !adv_bound {
        issues.push(lint_issue(
            source,
            "error",
            "missing_adversary_bound",
            "Threshold guards present but adversary bound is missing.",
            Some("Add `adversary { bound: f; }`.".into()),
            None,
            adversary_item_span("model").or(protocol_span),
        ));
    }
    if timing_partial && !gst {
        issues.push(lint_issue(
            source,
            "error",
            "missing_gst",
            "Partial synchrony configured without GST parameter.",
            Some("Add `adversary { gst: gst; }` and declare `gst` parameter.".into()),
            None,
            adversary_item_span("timing")
                .or(adversary_item_span("gst"))
                .or(protocol_span),
        ));
    }
    if adv_model == Some("byzantine")
        && equivocation != "none"
        && proto.roles.iter().any(|role| {
            role.node.phases.iter().any(|phase| {
                phase
                    .node
                    .transitions
                    .iter()
                    .any(|tr| guard_has_non_monotone_threshold(&tr.node.guard))
            })
        })
    {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "non_monotone_threshold_full_equivocation",
            "Non-monotone threshold guard with Byzantine full equivocation can introduce unsoundness.",
            Some("Use monotone `>=`/`>` threshold guards or set `equivocation: none`.".into()),
            None,
            adversary_item_span("equivocation")
                .or(adversary_item_span("model"))
                .or(protocol_span),
        ));
    }
    if uses_distinct_thresholds && auth_mode != "signed" {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "distinct_requires_signed_auth",
            "Distinct-sender thresholds are modeled soundly only with authenticated sender identities.",
            Some("Add `adversary { auth: signed; }`.".into()),
            None,
            adversary_item_span("auth")
                .or(adversary_item_span("authentication"))
                .or(protocol_span),
        ));
    }
    let faithful_network = matches!(
        network_mode,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if faithful_network {
        let role_names: std::collections::HashSet<String> =
            proto.roles.iter().map(|r| r.node.name.clone()).collect();
        let identity_roles: std::collections::HashSet<String> =
            proto.identities.iter().map(|id| id.role.clone()).collect();
        let mut missing_identity_roles: Vec<String> =
            role_names.difference(&identity_roles).cloned().collect();
        missing_identity_roles.sort();
        if !missing_identity_roles.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_identity_declarations",
                format!(
                    "Faithful network mode is missing explicit `identity` declarations for roles: {}.",
                    missing_identity_roles.join(", ")
                ),
                faithful_missing_identity_suggestion(&missing_identity_roles, network_mode),
                None,
                adversary_item_span("network").or(protocol_span),
            ));
        }
        let mut identities_without_key: Vec<String> = proto
            .identities
            .iter()
            .filter(|id| id.key.is_none())
            .map(|id| id.role.clone())
            .collect();
        identities_without_key.sort();
        identities_without_key.dedup();
        if !identities_without_key.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_identity_keys",
                format!(
                    "Faithful network mode should pin explicit key namespaces for roles: {}.",
                    identities_without_key.join(", ")
                ),
                faithful_missing_identity_key_suggestion(
                    proto,
                    &identities_without_key,
                    network_mode,
                ),
                None,
                proto.identities.first().map(|id| id.span).or(protocol_span),
            ));
        }
        if network_mode == "process_selective" {
            let mut non_process_roles: Vec<String> = proto
                .identities
                .iter()
                .filter(|id| id.scope != tarsier_dsl::ast::IdentityScope::Process)
                .map(|id| id.role.clone())
                .collect();
            non_process_roles.sort();
            non_process_roles.dedup();
            if !non_process_roles.is_empty() {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "process_selective_requires_process_identity",
                    format!(
                        "`network: process_selective` requires process-scoped identities; found non-process identities for: {}.",
                        non_process_roles.join(", ")
                    ),
                    faithful_missing_process_identity_suggestion(&non_process_roles),
                    None,
                    adversary_item_span("network").or(protocol_span),
                ));
            }
        }
        let channel_covered: std::collections::HashSet<String> =
            proto.channels.iter().map(|c| c.message.clone()).collect();
        let mut missing_auth_messages: Vec<String> = proto
            .messages
            .iter()
            .map(|m| m.name.clone())
            .filter(|m| !channel_covered.contains(m))
            .collect();
        missing_auth_messages.sort();
        if !has_auth_field && !missing_auth_messages.is_empty() {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_auth_semantics",
                format!(
                    "Faithful network mode has no explicit global auth and missing per-message channel auth for: {}.",
                    missing_auth_messages.join(", ")
                ),
                faithful_missing_auth_suggestion(&missing_auth_messages),
                None,
                adversary_item_span("auth")
                    .or(adversary_item_span("authentication"))
                    .or(adversary_item_span("network"))
                    .or(protocol_span),
            ));
        }
        if adv_model == Some("byzantine") && !has_equivocation_field {
            issues.push(lint_issue(
                source,
                if soundness == SoundnessMode::Strict {
                    "error"
                } else {
                    "warn"
                },
                "faithful_mode_missing_equivocation_policy",
                "Byzantine faithful network mode requires explicit equivocation policy (`equivocation: full|none`).",
                faithful_missing_equivocation_suggestion(),
                None,
                adversary_item_span("equivocation")
                    .or(adversary_item_span("model"))
                    .or(adversary_item_span("network"))
                    .or(protocol_span),
            ));
        }
    }
    if adv_model == Some("byzantine")
        && network_mode != "identity_selective"
        && network_mode != "cohort_selective"
        && network_mode != "process_selective"
    {
        issues.push(lint_issue(
            source,
            if soundness == SoundnessMode::Strict {
                "error"
            } else {
                "warn"
            },
            "byzantine_network_not_identity_selective",
            "Byzantine model is using legacy `network: classic`; recipient channels remain weakly coupled and may introduce spuriousness.",
            Some(faithful_proof_scaffold_suggestion(proto, network_mode)),
            None,
            adversary_item_span("network")
                .or(adversary_item_span("model"))
                .or(protocol_span),
        ));
    }
    if uses_distinct_thresholds && proto.roles.len() > 1 {
        for role_name in protocol_distinct_roles(&program) {
            let param_name = format!("n_{}", role_name.to_lowercase());
            if !proto.parameters.iter().any(|p| p.name == param_name) {
                issues.push(lint_issue(
                    source,
                    if soundness == SoundnessMode::Strict {
                        "error"
                    } else {
                        "warn"
                    },
                    "distinct_role_missing_population_param",
                    format!(
                        "Distinct sender domain role `{role_name}` is missing population parameter `{param_name}`."
                    ),
                    Some(format!(
                        "Add `params {param_name};` (or avoid role-scoped distinct counting)."
                    )),
                    None,
                    protocol_span,
                ));
            }
        }
    }

    if !proto.committees.is_empty() {
        let has_bound_param = proto.committees.iter().any(|c| {
            c.items
                .iter()
                .any(|i| i.key == "bound_param" || i.key == "bound")
        });
        if !has_bound_param {
            issues.push(lint_issue(
                source,
                "warn",
                "committee_missing_bound_param",
                "Committee analysis exists but no `bound_param` is configured.",
                Some("Set `committee ... { bound_param: f; }` to enforce SMT bounds.".into()),
                None,
                proto.committees.first().map(|c| c.span),
            ));
        }
    }

    if !proto
        .properties
        .iter()
        .any(|p| p.node.kind == tarsier_dsl::ast::PropertyKind::Liveness)
    {
        issues.push(lint_issue(
            source,
            "info",
            "missing_liveness_property",
            "No explicit liveness property; tool will fall back to `decided == true` target.",
            Some("Add `property live: liveness { forall p: Role. ... }`.".into()),
            None,
            protocol_span,
        ));
    }

    if proto.pacemaker.is_none() {
        issues.push(lint_issue(
            source,
            "info",
            "missing_pacemaker",
            "No pacemaker/view-change helper declared.",
            Some("Consider `pacemaker { ... }` for protocols with explicit views.".into()),
            None,
            protocol_span,
        ));
    }

    LintReport {
        schema_version: 1,
        file: filename.to_string(),
        soundness: soundness_name(soundness).to_string(),
        issues,
    }
}

// ---------------------------------------------------------------------------
// Text rendering
// ---------------------------------------------------------------------------

pub(crate) fn render_lint_text(report: &LintReport) -> String {
    let mut out = String::new();
    let errors = report
        .issues
        .iter()
        .filter(|i| i.severity == "error")
        .count();
    let warns = report
        .issues
        .iter()
        .filter(|i| i.severity == "warn")
        .count();
    let infos = report
        .issues
        .iter()
        .filter(|i| i.severity == "info")
        .count();
    out.push_str("LINT REPORT\n");
    out.push_str(&format!("File: {}\n", report.file));
    out.push_str(&format!(
        "Summary: {} error(s), {} warning(s), {} info\n",
        errors, warns, infos
    ));
    for issue in &report.issues {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            issue.severity.to_uppercase(),
            issue.code,
            issue.message
        ));
        if let Some(span) = issue.source_span {
            out.push_str(&format!(
                "    span: {}:{} -> {}:{} (bytes {}..{})\n",
                span.line, span.column, span.end_line, span.end_column, span.start, span.end
            ));
        }
        if let Some(suggestion) = &issue.suggestion {
            out.push_str(&format!("    suggestion: {suggestion}\n"));
        }
        if let Some(soundness_impact) = &issue.soundness_impact {
            out.push_str(&format!("    soundness impact: {soundness_impact}\n"));
        }
        if let Some(fix) = &issue.fix {
            out.push_str(&format!(
                "    fix ({}): {}\n",
                fix.label,
                fix.snippet.replace('\n', "\n      ")
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Local soundness-name helper (mirrors crate::soundness_name)
// ---------------------------------------------------------------------------

fn soundness_name(mode: SoundnessMode) -> &'static str {
    match mode {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

// ---------------------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------------------

pub(crate) fn run_lint_command(
    file: PathBuf,
    soundness: String,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness = parse_soundness_mode(&soundness);
    crate::validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
    let output_format = parse_output_format(&format);
    let report = lint_protocol_file(&source, &filename, soundness);
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        crate::write_json_artifact(&path, &report_json_value)?;
        println!("Lint report written to {}", path.display());
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_lint_text(&report)),
        OutputFormat::Json => println!("{report_json}"),
    }

    if report.issues.iter().any(|i| i.severity == "error") {
        std::process::exit(2);
    }

    Ok(())
}
