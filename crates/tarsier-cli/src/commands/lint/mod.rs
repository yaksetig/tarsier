//! Lint command module facade.

mod command;
mod faithful;
mod issues;
mod pipeline;
mod render;
mod spans;
mod thresholds;
mod types;

#[cfg(test)]
mod tests;

pub(crate) use command::run_lint_command;
#[cfg(test)]
pub(crate) use faithful::{
    faithful_identity_decl_snippet, faithful_missing_auth_suggestion,
    faithful_missing_equivocation_suggestion, faithful_missing_identity_suggestion,
    faithful_missing_process_identity_suggestion, suggested_identity_scope_for_network,
};
#[cfg(test)]
pub(crate) use issues::{lint_issue, lint_soundness_impact, soundness_name};
pub(crate) use pipeline::lint_protocol_file;
#[cfg(test)]
pub(crate) use render::render_lint_text;
#[cfg(test)]
pub(crate) use spans::{
    advance_one_char, byte_offset_to_line_col, infer_parse_error_span, line_col_to_byte_offset,
    lint_source_span,
};
#[cfg(test)]
pub(crate) use thresholds::{
    collect_distinct_roles_from_guard, guard_has_non_monotone_threshold,
    guard_uses_distinct_threshold,
};
#[cfg(test)]
pub(crate) use types::{LintFix, LintIssue, LintReport, LintSourceSpan};
