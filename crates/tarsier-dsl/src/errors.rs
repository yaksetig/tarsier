#![allow(unused_assignments)]

use miette::Diagnostic;
use thiserror::Error;

use crate::ast::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseDiagnosticSeverity {
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostic {
    pub code: String,
    pub severity: ParseDiagnosticSeverity,
    pub message: String,
    pub suggestion: Option<String>,
    pub span: Option<Span>,
}

#[derive(Debug, Error, Diagnostic)]
pub enum ParseError {
    #[error("Syntax error: {message}")]
    #[diagnostic(code(tarsier::parse::syntax))]
    Syntax {
        message: String,
        #[label("here")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("Unexpected token: expected {expected}, found {found}")]
    #[diagnostic(code(tarsier::parse::unexpected))]
    UnexpectedToken {
        expected: String,
        found: String,
        #[label("unexpected token")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("Missing required section: {section}")]
    #[diagnostic(code(tarsier::parse::missing_section))]
    MissingSection { section: String },

    #[error("Duplicate definition: {name}")]
    #[diagnostic(code(tarsier::parse::duplicate))]
    Duplicate {
        name: String,
        #[label("duplicate")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("Unknown {context} key '{field}'")]
    #[diagnostic(
        code(tarsier::parse::invalid_field),
        help("valid keys are: model, bound, timing, values, auth, network, equivocation, delivery, faults, por, compromise, compromised_key, gst")
    )]
    InvalidField {
        field: String,
        context: String,
        #[label("unknown key")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("{item_kind} declarations are not supported inside module blocks")]
    #[diagnostic(
        code(tarsier::parse::unsupported_in_module),
        help("move this declaration to the top-level protocol block")
    )]
    UnsupportedInModule {
        item_kind: String,
        #[label("not allowed in module")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("Import resolution error: {message}")]
    #[diagnostic(code(tarsier::parse::import_resolution))]
    ImportResolution {
        message: String,
        #[label("import")]
        span: miette::SourceSpan,
        #[source_code]
        src: miette::NamedSource<String>,
    },

    #[error("{0}")]
    #[diagnostic(code(tarsier::parse::multiple))]
    MultipleErrors(#[from] ParseErrors),
}

/// Wrapper for collecting multiple semantic parse errors.
///
/// After pest produces a valid parse tree, the AST-building phase can encounter
/// multiple recoverable semantic errors (e.g., invalid adversary keys, unsupported
/// module items). This type collects them all instead of failing on the first.
#[derive(Debug, Error)]
#[error("{}", format_parse_errors(.errors))]
pub struct ParseErrors {
    pub errors: Vec<ParseError>,
}

fn format_parse_errors(errors: &[ParseError]) -> String {
    if errors.len() == 1 {
        return errors[0].to_string();
    }
    let mut s = format!("{} parse errors:\n", errors.len());
    for (i, e) in errors.iter().enumerate() {
        s.push_str(&format!("  {}. {}\n", i + 1, e));
    }
    s
}

impl ParseErrors {
    /// Enrich all contained errors with source context.
    pub fn with_source_context(mut self, source: &str, filename: &str) -> Self {
        self.errors = self
            .errors
            .into_iter()
            .map(|e| e.with_source_context(source, filename))
            .collect();
        self
    }
}

impl ParseError {
    pub fn syntax(message: impl Into<String>, span: Span, source: &str, filename: &str) -> Self {
        ParseError::Syntax {
            message: message.into(),
            span: (span.start, span.end - span.start).into(),
            src: miette::NamedSource::new(filename, source.to_owned()),
        }
    }

    /// Enrich span-only error variants with source context for CLI rendering.
    ///
    /// Variants constructed during parsing carry raw byte offsets. This method
    /// attaches the source text and filename so miette can render highlighted
    /// code snippets.
    pub fn with_source_context(self, source: &str, filename: &str) -> Self {
        match self {
            ParseError::InvalidField {
                field,
                context,
                span,
                ..
            } => ParseError::InvalidField {
                field,
                context,
                span,
                src: miette::NamedSource::new(filename, source.to_owned()),
            },
            ParseError::UnsupportedInModule {
                item_kind, span, ..
            } => ParseError::UnsupportedInModule {
                item_kind,
                span,
                src: miette::NamedSource::new(filename, source.to_owned()),
            },
            ParseError::ImportResolution { message, span, .. } => ParseError::ImportResolution {
                message,
                span,
                src: miette::NamedSource::new(filename, source.to_owned()),
            },
            ParseError::MultipleErrors(errs) => {
                ParseError::MultipleErrors(errs.with_source_context(source, filename))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // ParseDiagnosticSeverity
    // ---------------------------------------------------------------

    #[test]
    fn parse_diagnostic_severity_warning_variant() {
        let sev = ParseDiagnosticSeverity::Warning;
        assert_eq!(sev, ParseDiagnosticSeverity::Warning);
    }

    // ---------------------------------------------------------------
    // ParseDiagnostic construction and fields
    // ---------------------------------------------------------------

    #[test]
    fn parse_diagnostic_construction_all_fields() {
        let diag = ParseDiagnostic {
            code: "W001".into(),
            severity: ParseDiagnosticSeverity::Warning,
            message: "unused variable".into(),
            suggestion: Some("remove it".into()),
            span: Some(Span::new(10, 20)),
        };
        assert_eq!(diag.code, "W001");
        assert_eq!(diag.severity, ParseDiagnosticSeverity::Warning);
        assert_eq!(diag.message, "unused variable");
        assert_eq!(diag.suggestion, Some("remove it".into()));
        assert_eq!(diag.span, Some(Span::new(10, 20)));
    }

    #[test]
    fn parse_diagnostic_optional_fields_none() {
        let diag = ParseDiagnostic {
            code: "W002".into(),
            severity: ParseDiagnosticSeverity::Warning,
            message: "something".into(),
            suggestion: None,
            span: None,
        };
        assert!(diag.suggestion.is_none());
        assert!(diag.span.is_none());
    }

    // ---------------------------------------------------------------
    // ParseError Display messages
    // ---------------------------------------------------------------

    #[test]
    fn display_syntax_error() {
        let err = ParseError::Syntax {
            message: "unexpected EOF".into(),
            span: (0, 5).into(),
            src: miette::NamedSource::new("test.trs", "hello".to_owned()),
        };
        assert_eq!(err.to_string(), "Syntax error: unexpected EOF");
    }

    #[test]
    fn display_unexpected_token_error() {
        let err = ParseError::UnexpectedToken {
            expected: "identifier".into(),
            found: "number".into(),
            span: (0, 3).into(),
            src: miette::NamedSource::new("test.trs", "123".to_owned()),
        };
        assert_eq!(
            err.to_string(),
            "Unexpected token: expected identifier, found number"
        );
    }

    #[test]
    fn display_missing_section_error() {
        let err = ParseError::MissingSection {
            section: "roles".into(),
        };
        assert_eq!(err.to_string(), "Missing required section: roles");
    }

    #[test]
    fn display_duplicate_error() {
        let err = ParseError::Duplicate {
            name: "Replica".into(),
            span: (0, 7).into(),
            src: miette::NamedSource::new("test.trs", "Replica".to_owned()),
        };
        assert_eq!(err.to_string(), "Duplicate definition: Replica");
    }

    #[test]
    fn display_invalid_field_error() {
        let err = ParseError::InvalidField {
            field: "foo".into(),
            context: "adversary".into(),
            span: (0, 3).into(),
            src: miette::NamedSource::new("test.trs", "foo".to_owned()),
        };
        assert_eq!(err.to_string(), "Unknown adversary key 'foo'");
    }

    #[test]
    fn display_unsupported_in_module_error() {
        let err = ParseError::UnsupportedInModule {
            item_kind: "committee".into(),
            span: (0, 9).into(),
            src: miette::NamedSource::new("test.trs", "committee".to_owned()),
        };
        assert_eq!(
            err.to_string(),
            "committee declarations are not supported inside module blocks"
        );
    }

    // ---------------------------------------------------------------
    // ParseError::syntax() convenience constructor
    // ---------------------------------------------------------------

    #[test]
    fn syntax_convenience_constructor() {
        let span = Span::new(5, 10);
        let err = ParseError::syntax("bad token", span, "some source code", "file.trs");
        assert_eq!(err.to_string(), "Syntax error: bad token");
        // Verify it is the Syntax variant
        match &err {
            ParseError::Syntax {
                message,
                span: s,
                ..
            } => {
                assert_eq!(message, "bad token");
                // miette::SourceSpan offset = 5, length = 5
                assert_eq!(s.offset(), 5);
                assert_eq!(s.len(), 5);
            }
            _ => panic!("expected Syntax variant"),
        }
    }

    // ---------------------------------------------------------------
    // ParseErrors (multiple errors) formatting
    // ---------------------------------------------------------------

    #[test]
    fn parse_errors_single_formats_without_numbering() {
        let errs = ParseErrors {
            errors: vec![ParseError::MissingSection {
                section: "roles".into(),
            }],
        };
        let msg = errs.to_string();
        assert_eq!(msg, "Missing required section: roles");
    }

    #[test]
    fn parse_errors_multiple_formats_with_count_and_numbering() {
        let errs = ParseErrors {
            errors: vec![
                ParseError::MissingSection {
                    section: "roles".into(),
                },
                ParseError::MissingSection {
                    section: "parameters".into(),
                },
            ],
        };
        let msg = errs.to_string();
        assert!(msg.starts_with("2 parse errors:\n"));
        assert!(msg.contains("1. Missing required section: roles"));
        assert!(msg.contains("2. Missing required section: parameters"));
    }

    // ---------------------------------------------------------------
    // with_source_context
    // ---------------------------------------------------------------

    #[test]
    fn with_source_context_enriches_invalid_field() {
        let err = ParseError::InvalidField {
            field: "foo".into(),
            context: "adversary".into(),
            span: (0, 3).into(),
            src: miette::NamedSource::new("old.trs", "old".to_owned()),
        };
        let enriched = err.with_source_context("new source", "new.trs");
        match enriched {
            ParseError::InvalidField { src, .. } => {
                assert_eq!(src.name(), "new.trs");
            }
            _ => panic!("expected InvalidField variant"),
        }
    }
}
