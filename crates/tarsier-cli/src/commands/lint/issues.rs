// Lint issue construction and soundness impact helpers.

use tarsier_dsl::ast::Span as DslSpan;
use tarsier_engine::pipeline::SoundnessMode;

use super::spans::lint_source_span;
use super::types::{LintFix, LintIssue};

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

pub(crate) fn soundness_name(mode: SoundnessMode) -> &'static str {
    match mode {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}
