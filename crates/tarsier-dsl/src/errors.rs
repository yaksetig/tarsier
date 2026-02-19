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
}

impl ParseError {
    pub fn syntax(message: impl Into<String>, span: Span, source: &str, filename: &str) -> Self {
        ParseError::Syntax {
            message: message.into(),
            span: (span.start, span.end - span.start).into(),
            src: miette::NamedSource::new(filename, source.to_owned()),
        }
    }
}
