// Main lint pipeline.

use tarsier_dsl::ast::Span as DslSpan;
use tarsier_engine::pipeline::SoundnessMode;

use super::faithful::{
    faithful_missing_auth_suggestion, faithful_missing_equivocation_suggestion,
    faithful_missing_identity_key_suggestion, faithful_missing_identity_suggestion,
    faithful_missing_process_identity_suggestion, faithful_proof_scaffold_suggestion,
};
use super::issues::{lint_issue, soundness_name};
use super::spans::infer_parse_error_span;
use super::thresholds::{
    guard_has_non_monotone_threshold, protocol_distinct_roles, protocol_uses_distinct_thresholds,
    protocol_uses_thresholds,
};
use super::types::{LintFix, LintIssue, LintReport};

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
