// Lint report rendering helpers.

use super::types::LintReport;

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
