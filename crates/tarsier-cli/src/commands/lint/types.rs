use serde::Serialize;

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
