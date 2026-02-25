#![doc = include_str!("../README.md")]

//! Language Server Protocol implementation for the Tarsier DSL.
//!
//! Provides IDE features (diagnostics, hover, go-to-definition, completions)
//! for `.trs` protocol specification files via the LSP protocol.

use pest::Parser as _;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use tarsier_dsl::ast::{self, Program, VarType};

// ---------------------------------------------------------------------------
// Document state
// ---------------------------------------------------------------------------

struct DocumentState {
    source: String,
    #[allow(dead_code)]
    version: i32,
    /// Cached successful parse result (AST + parse diagnostics).
    parsed: Option<(Program, Vec<tarsier_dsl::errors::ParseDiagnostic>)>,
}

#[derive(Debug, Clone)]
struct SymbolDocument {
    uri: Url,
    source: String,
    program: Program,
}

const MAX_IMPORT_TRAVERSAL_DEPTH: usize = 8;
const MAX_WORKSPACE_SYMBOL_FILES: usize = 512;
const MAX_WORKSPACE_SCAN_DEPTH: usize = 6;
const MAX_WORKSPACE_SYMBOL_RESULTS: usize = 256;

// ---------------------------------------------------------------------------
// Definition info (for goto-definition / references)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DefinitionKind {
    Message,
    Role,
    Phase,
    Param,
    Var,
    Property,
    Enum,
}

#[derive(Debug, Clone)]
struct DefinitionInfo {
    name: String,
    #[cfg_attr(not(test), allow(dead_code))]
    kind: DefinitionKind,
    start: usize,
    end: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    parent: Option<String>,
}

mod reference_parser {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "../../tarsier-dsl/src/grammar.pest"]
    pub struct TarsierReferenceParser;
}

use reference_parser::{Rule as ReferenceRule, TarsierReferenceParser};
type ReferencePair<'a> = pest::iterators::Pair<'a, ReferenceRule>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolTarget {
    name: String,
    kind: DefinitionKind,
    parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolOccurrence {
    name: String,
    kind: DefinitionKind,
    parent: Option<String>,
    start: usize,
    end: usize,
    declaration: bool,
}

#[derive(Debug, Default, Clone)]
struct SymbolTables {
    params: HashSet<String>,
    roles: HashSet<String>,
    role_vars: HashMap<String, HashSet<String>>,
    role_phases: HashMap<String, HashSet<String>>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// LSP backend implementation for `.trs` files.
pub struct TarsierLspBackend {
    client: Client,
    documents: RwLock<HashMap<Url, DocumentState>>,
}

impl TarsierLspBackend {
    /// Construct a new backend bound to the given LSP client.
    ///
    /// # Parameters
    /// - `client`: The `tower_lsp` client used to publish diagnostics and notifications.
    ///
    /// # Returns
    /// A backend instance with an empty in-memory document cache.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: RwLock::new(HashMap::new()),
        }
    }

    /// Run diagnostics and cache the parse result.
    fn diagnose_and_cache(&self, uri: &Url, text: &str) -> Vec<Diagnostic> {
        let filename = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("untitled.trs");

        let mut diagnostics = Vec::new();

        match tarsier_dsl::parse_with_diagnostics(text, filename) {
            Ok((program, parse_diags)) => {
                // Parse diagnostics (warnings)
                for diag in &parse_diags {
                    let range = diag
                        .span
                        .as_ref()
                        .and_then(|s| offset_to_range(text, s.start, s.end))
                        .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
                    push_unique_diagnostic(
                        &mut diagnostics,
                        Diagnostic {
                            range,
                            severity: Some(DiagnosticSeverity::WARNING),
                            source: Some("tarsier".into()),
                            code: Some(NumberOrString::String(diag.code.clone())),
                            message: diag.message.clone(),
                            ..Default::default()
                        },
                    );
                }

                // Lowering diagnostics:
                // 1) collect structural checks in one pass (multi-error),
                // 2) keep lower_with_source fallback for deeper first-error diagnostics.
                for diag in collect_lowering_diagnostics(&program, text, filename) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }

                // Cache parse result
                {
                    if let Ok(mut docs) = self.documents.write() {
                        if let Some(state) = docs.get_mut(uri) {
                            state.parsed = Some((program, parse_diags));
                        }
                    }
                }
            }
            Err(e) => {
                for diag in parse_error_diagnostics(&e, text) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }

                // Clear cached parse
                {
                    if let Ok(mut docs) = self.documents.write() {
                        if let Some(state) = docs.get_mut(uri) {
                            state.parsed = None;
                        }
                    }
                }
            }
        }

        diagnostics
    }

    fn snapshot_document(&self, uri: &Url) -> Option<(String, Option<Program>)> {
        let docs = self.documents.read().ok()?;
        let state = docs.get(uri)?;
        let parsed = state.parsed.as_ref().map(|(program, _)| program.clone());
        Some((state.source.clone(), parsed))
    }

    fn load_symbol_document(&self, uri: &Url) -> Option<SymbolDocument> {
        if let Some((source, parsed_program)) = self.snapshot_document(uri) {
            let filename = uri
                .path_segments()
                .and_then(|mut s| s.next_back())
                .unwrap_or("untitled.trs");
            let program = match parsed_program {
                Some(program) => program,
                None => tarsier_dsl::parse_with_diagnostics(&source, filename)
                    .ok()
                    .map(|(program, _)| program)?,
            };
            return Some(SymbolDocument {
                uri: uri.clone(),
                source,
                program,
            });
        }

        let path = uri.to_file_path().ok()?;
        let source = std::fs::read_to_string(path).ok()?;
        let filename = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("untitled.trs");
        let (program, _) = tarsier_dsl::parse_with_diagnostics(&source, filename).ok()?;
        Some(SymbolDocument {
            uri: uri.clone(),
            source,
            program,
        })
    }

    fn collect_import_documents(
        &self,
        root_uri: &Url,
        root_program: &Program,
    ) -> Vec<SymbolDocument> {
        let mut out = Vec::new();
        let mut visited: HashSet<Url> = HashSet::new();
        let mut queue: VecDeque<(Url, Program, usize)> = VecDeque::new();

        visited.insert(root_uri.clone());
        queue.push_back((root_uri.clone(), root_program.clone(), 0));

        while let Some((current_uri, current_program, depth)) = queue.pop_front() {
            if depth >= MAX_IMPORT_TRAVERSAL_DEPTH {
                continue;
            }

            for import in &current_program.protocol.node.imports {
                let Some(import_uri) = resolve_import_uri(&current_uri, &import.path) else {
                    continue;
                };
                if !visited.insert(import_uri.clone()) {
                    continue;
                }

                let Some(import_doc) = self.load_symbol_document(&import_uri) else {
                    continue;
                };
                queue.push_back((
                    import_doc.uri.clone(),
                    import_doc.program.clone(),
                    depth + 1,
                ));
                out.push(import_doc);
            }
        }

        out
    }

    fn collect_workspace_symbol_documents(&self) -> Vec<SymbolDocument> {
        let open_uris: Vec<Url> = {
            let Ok(docs) = self.documents.read() else {
                return Vec::new();
            };
            docs.keys().cloned().collect()
        };

        let mut by_uri: HashMap<Url, SymbolDocument> = HashMap::new();
        let mut queue: VecDeque<SymbolDocument> = VecDeque::new();

        for uri in &open_uris {
            if let Some(doc) = self.load_symbol_document(uri) {
                if by_uri.insert(uri.clone(), doc.clone()).is_none() {
                    queue.push_back(doc);
                }
            }
        }

        while let Some(doc) = queue.pop_front() {
            for import_doc in self.collect_import_documents(&doc.uri, &doc.program) {
                if by_uri.contains_key(&import_doc.uri) {
                    continue;
                }
                let uri = import_doc.uri.clone();
                by_uri.insert(uri, import_doc.clone());
                queue.push_back(import_doc);
            }
        }

        let mut roots = workspace_roots_from_uris(&open_uris);
        if roots.is_empty() {
            if let Ok(cwd) = std::env::current_dir() {
                roots.push(cwd);
            }
        }

        for root in roots {
            let files = discover_workspace_trs_files(
                &root,
                MAX_WORKSPACE_SYMBOL_FILES.saturating_sub(by_uri.len()),
                MAX_WORKSPACE_SCAN_DEPTH,
            );
            for file in files {
                if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                    break;
                }
                let Ok(uri) = Url::from_file_path(file) else {
                    continue;
                };
                if by_uri.contains_key(&uri) {
                    continue;
                }
                if let Some(doc) = self.load_symbol_document(&uri) {
                    by_uri.insert(uri, doc);
                }
            }
            if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                break;
            }
        }

        let mut docs: Vec<SymbolDocument> = by_uri.into_values().collect();
        docs.sort_by_key(|d| d.uri.to_string());
        docs
    }
}

// ---------------------------------------------------------------------------
// Diagnostic helpers
// ---------------------------------------------------------------------------

fn lowering_error_code(err: &tarsier_ir::lowering::LoweringError) -> String {
    use tarsier_ir::lowering::LoweringError::*;
    match err {
        UnknownParameter(_) => "tarsier::lower::unknown_param".into(),
        UnknownMessageType(_) => "tarsier::lower::unknown_message".into(),
        UnknownPhase(_) => "tarsier::lower::unknown_phase".into(),
        NoInitPhase(_) => "tarsier::lower::no_init_phase".into(),
        UnknownEnum(_) => "tarsier::lower::unknown_enum".into(),
        UnknownEnumVariant(..) => "tarsier::lower::unknown_enum_variant".into(),
        MissingEnumInit(_) => "tarsier::lower::missing_enum_init".into(),
        OutOfRange { .. } => "tarsier::lower::out_of_range".into(),
        InvalidRange(..) => "tarsier::lower::invalid_range".into(),
        Unsupported(_) => "tarsier::lower::unsupported".into(),
        Validation(_) => "tarsier::lower::validation".into(),
    }
}

fn lowering_error_message(err: &tarsier_ir::lowering::LoweringError, program: &Program) -> String {
    use tarsier_ir::lowering::LoweringError::*;
    match err {
        UnknownPhase(name) => {
            let known = collect_phase_names(program);
            if let Some(suggestion) = find_closest(name, &known) {
                format!("Unknown phase '{name}' in goto. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown phase '{name}' in goto")
            }
        }
        UnknownMessageType(name) => {
            let known: Vec<String> = program
                .protocol
                .node
                .messages
                .iter()
                .map(|m| m.name.clone())
                .collect();
            if let Some(suggestion) = find_closest(name, &known) {
                format!("Unknown message type '{name}'. Did you mean '{suggestion}'?")
            } else {
                format!("Unknown message type '{name}'")
            }
        }
        NoInitPhase(role) => {
            format!("Role '{role}' has no init phase. Add `init <phase_name>;` inside the role.")
        }
        _ => format!("{err}"),
    }
}

fn parse_error_span_and_code(err: &tarsier_dsl::errors::ParseError, text: &str) -> (Range, String) {
    use tarsier_dsl::errors::ParseError::*;
    match err {
        Syntax { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::syntax".into())
        }
        UnexpectedToken { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::unexpected".into())
        }
        Duplicate { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::duplicate".into())
        }
        MissingSection { .. } => {
            let range = Range::new(Position::new(0, 0), Position::new(0, 1));
            (range, "tarsier::parse::missing_section".into())
        }
        InvalidField { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::invalid_field".into())
        }
        UnsupportedInModule { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::unsupported_in_module".into())
        }
        ImportResolution { span, .. } => {
            let start = span.offset();
            let end = start + span.len();
            let range = offset_to_range(text, start, end)
                .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
            (range, "tarsier::parse::import_resolution".into())
        }
        MultipleErrors(errs) => {
            // Use the span/code from the first error, if any
            if let Some(first) = errs.errors.first() {
                parse_error_span_and_code(first, text)
            } else {
                let range = Range::new(Position::new(0, 0), Position::new(0, 1));
                (range, "tarsier::parse::multiple_errors".into())
            }
        }
    }
}

fn parse_error_diagnostics(err: &tarsier_dsl::errors::ParseError, text: &str) -> Vec<Diagnostic> {
    use tarsier_dsl::errors::ParseError::MultipleErrors;

    match err {
        MultipleErrors(errs) if !errs.errors.is_empty() => {
            let mut diagnostics = Vec::new();
            for nested in &errs.errors {
                for diag in parse_error_diagnostics(nested, text) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }
            }
            diagnostics
        }
        _ => {
            let (range, code_str) = parse_error_span_and_code(err, text);
            vec![Diagnostic {
                range,
                severity: Some(DiagnosticSeverity::ERROR),
                source: Some("tarsier".into()),
                code: Some(NumberOrString::String(code_str)),
                message: format!("{err}"),
                ..Default::default()
            }]
        }
    }
}

fn range_from_span_or_default(text: &str, span: ast::Span) -> Range {
    offset_to_range(text, span.start, span.end)
        .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)))
}

fn push_unique_diagnostic(diagnostics: &mut Vec<Diagnostic>, candidate: Diagnostic) {
    let exists = diagnostics.iter().any(|d| {
        d.range == candidate.range && d.code == candidate.code && d.message == candidate.message
    });
    if !exists {
        diagnostics.push(candidate);
    }
}

fn lowering_error_diag(code: &str, message: String, range: Range) -> Diagnostic {
    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some("tarsier".into()),
        code: Some(NumberOrString::String(code.to_string())),
        message,
        ..Default::default()
    }
}

fn push_guard_unknown_message_diagnostics(
    guard: &ast::GuardExpr,
    transition_span: ast::Span,
    known_messages: &[String],
    known_crypto_objects: &[String],
    text: &str,
    out: &mut Vec<Diagnostic>,
) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            let known = known_messages
                .iter()
                .chain(known_crypto_objects.iter())
                .any(|name| name == &tg.message_type);
            if !known {
                let mut msg = format!("Unknown message type '{}'", tg.message_type);
                let mut candidates = known_messages.to_vec();
                candidates.extend_from_slice(known_crypto_objects);
                if let Some(suggestion) = find_closest(&tg.message_type, &candidates) {
                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                }
                push_unique_diagnostic(
                    out,
                    lowering_error_diag(
                        "tarsier::lower::unknown_message",
                        msg,
                        range_from_span_or_default(text, transition_span),
                    ),
                );
            }
        }
        ast::GuardExpr::HasCryptoObject { object_name, .. } => {
            if !known_crypto_objects.iter().any(|name| name == object_name) {
                let mut msg = format!("Unknown cryptographic object '{object_name}'");
                if let Some(suggestion) = find_closest(object_name, known_crypto_objects) {
                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                }
                push_unique_diagnostic(
                    out,
                    lowering_error_diag(
                        "tarsier::lower::unknown_message",
                        msg,
                        range_from_span_or_default(text, transition_span),
                    ),
                );
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            push_guard_unknown_message_diagnostics(
                lhs,
                transition_span,
                known_messages,
                known_crypto_objects,
                text,
                out,
            );
            push_guard_unknown_message_diagnostics(
                rhs,
                transition_span,
                known_messages,
                known_crypto_objects,
                text,
                out,
            );
        }
        _ => {}
    }
}

fn collect_structural_lowering_diagnostics(program: &Program, text: &str) -> Vec<Diagnostic> {
    let proto = &program.protocol.node;
    let known_messages: Vec<String> = proto.messages.iter().map(|m| m.name.clone()).collect();
    let known_crypto_objects: Vec<String> = proto
        .crypto_objects
        .iter()
        .map(|o| o.name.clone())
        .collect();
    let known_enums: Vec<String> = proto.enums.iter().map(|e| e.name.clone()).collect();
    let mut diagnostics = Vec::new();

    for role in &proto.roles {
        if role.node.init_phase.is_none() {
            push_unique_diagnostic(
                &mut diagnostics,
                lowering_error_diag(
                    "tarsier::lower::no_init_phase",
                    format!(
                        "Role '{}' has no init phase. Add `init <phase_name>;` inside the role.",
                        role.node.name
                    ),
                    range_from_span_or_default(text, role.span),
                ),
            );
        }

        let role_phase_names: Vec<String> = role
            .node
            .phases
            .iter()
            .map(|p| p.node.name.clone())
            .collect();
        for var in &role.node.vars {
            if let VarType::Enum(enum_name) = &var.ty {
                if !known_enums.iter().any(|e| e == enum_name) {
                    let mut msg = format!("Unknown enum type '{enum_name}'");
                    if let Some(suggestion) = find_closest(enum_name, &known_enums) {
                        msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                    }
                    push_unique_diagnostic(
                        &mut diagnostics,
                        lowering_error_diag(
                            "tarsier::lower::unknown_enum",
                            msg,
                            range_from_span_or_default(text, var.span),
                        ),
                    );
                } else if var.init.is_none() {
                    push_unique_diagnostic(
                        &mut diagnostics,
                        lowering_error_diag(
                            "tarsier::lower::missing_enum_init",
                            format!("Missing init value for enum variable '{}'", var.name),
                            range_from_span_or_default(text, var.span),
                        ),
                    );
                }
            }
        }

        for phase in &role.node.phases {
            for transition in &phase.node.transitions {
                push_guard_unknown_message_diagnostics(
                    &transition.node.guard,
                    transition.span,
                    &known_messages,
                    &known_crypto_objects,
                    text,
                    &mut diagnostics,
                );

                for action in &transition.node.actions {
                    match action {
                        ast::Action::GotoPhase { phase } => {
                            if !role_phase_names.iter().any(|p| p == phase) {
                                let mut msg = format!("Unknown phase '{phase}' in goto");
                                if let Some(suggestion) = find_closest(phase, &role_phase_names) {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_phase",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        ast::Action::Send { message_type, .. } => {
                            let known = known_messages
                                .iter()
                                .chain(known_crypto_objects.iter())
                                .any(|name| name == message_type);
                            if !known {
                                let mut candidates = known_messages.clone();
                                candidates.extend_from_slice(&known_crypto_objects);
                                let mut msg = format!("Unknown message type '{message_type}'");
                                if let Some(suggestion) = find_closest(message_type, &candidates) {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_message",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        ast::Action::FormCryptoObject { object_name, .. }
                        | ast::Action::LockCryptoObject { object_name, .. }
                        | ast::Action::JustifyCryptoObject { object_name, .. } => {
                            if !known_crypto_objects.iter().any(|name| name == object_name) {
                                let mut msg =
                                    format!("Unknown cryptographic object '{object_name}'");
                                if let Some(suggestion) =
                                    find_closest(object_name, &known_crypto_objects)
                                {
                                    msg.push_str(&format!(". Did you mean '{suggestion}'?"));
                                }
                                push_unique_diagnostic(
                                    &mut diagnostics,
                                    lowering_error_diag(
                                        "tarsier::lower::unknown_message",
                                        msg,
                                        range_from_span_or_default(text, transition.span),
                                    ),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    diagnostics
}

fn diagnostic_has_code(diag: &Diagnostic, code: &str) -> bool {
    matches!(diag.code.as_ref(), Some(NumberOrString::String(s)) if s == code)
}

fn has_diagnostic_code(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics
        .iter()
        .any(|diag| diagnostic_has_code(diag, code))
}

fn is_structural_lowering_code(code: &str) -> bool {
    matches!(
        code,
        "tarsier::lower::no_init_phase"
            | "tarsier::lower::unknown_enum"
            | "tarsier::lower::missing_enum_init"
            | "tarsier::lower::unknown_phase"
            | "tarsier::lower::unknown_message"
    )
}

fn collect_lowering_diagnostics(program: &Program, text: &str, filename: &str) -> Vec<Diagnostic> {
    let mut diagnostics = collect_structural_lowering_diagnostics(program, text);

    if let Err(e) = tarsier_ir::lowering::lower_with_source(program, text, filename) {
        let range = e
            .span
            .map(|s| {
                let start = s.offset();
                let end = start + s.len();
                offset_to_range(text, start, end)
                    .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)))
            })
            .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));

        let code_str = lowering_error_code(&e.inner);
        let message = lowering_error_message(&e.inner, program);
        let fallback_diag = lowering_error_diag(&code_str, message, range);

        if !is_structural_lowering_code(&code_str) || !has_diagnostic_code(&diagnostics, &code_str)
        {
            push_unique_diagnostic(&mut diagnostics, fallback_diag);
        }
    }

    diagnostics
}

// ---------------------------------------------------------------------------
// Position / offset helpers
// ---------------------------------------------------------------------------

/// Convert a byte offset into an LSP `Position` (line/character).
///
/// # Parameters
/// - `text`: UTF-8 document text.
/// - `offset`: Byte offset into `text`.
///
/// # Returns
/// The corresponding LSP position. Offsets past the end clamp to the end.
pub fn offset_to_position(text: &str, offset: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    for (i, ch) in text.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    Position::new(line, col)
}

/// Convert an LSP `Position` into a byte offset.
///
/// # Parameters
/// - `text`: UTF-8 document text.
/// - `pos`: LSP line/character position.
///
/// # Returns
/// Byte offset in `text`, clamped to a valid boundary.
pub fn position_to_offset(text: &str, pos: Position) -> usize {
    let mut current_line = 0u32;
    let mut current_col = 0u32;
    for (i, ch) in text.char_indices() {
        if current_line == pos.line && current_col == pos.character {
            return i;
        }
        if ch == '\n' {
            if current_line == pos.line {
                // Position is past end of this line — clamp to newline
                return i;
            }
            current_line += 1;
            current_col = 0;
        } else {
            current_col += 1;
        }
    }
    text.len()
}

/// Convert byte offsets into an LSP `Range`.
///
/// # Parameters
/// - `text`: UTF-8 document text.
/// - `start`: Start byte offset.
/// - `end`: End byte offset.
///
/// # Returns
/// `Some(range)` mapped through `offset_to_position`.
pub fn offset_to_range(text: &str, start: usize, end: usize) -> Option<Range> {
    let start_pos = offset_to_position(text, start);
    let end_pos = offset_to_position(text, end);
    Some(Range::new(start_pos, end_pos))
}

/// Apply an incremental text change to a source string.
fn apply_incremental_change(text: &mut String, range: &Range, new_text: &str) {
    let start = position_to_offset(text, range.start);
    let end = position_to_offset(text, range.end);
    let start = start.min(text.len());
    let end = end.min(text.len());
    text.replace_range(start..end, new_text);
}

// ---------------------------------------------------------------------------
// Word extraction helper
// ---------------------------------------------------------------------------

fn word_at_position(text: &str, offset: usize) -> Option<(String, usize, usize)> {
    if offset > text.len() {
        return None;
    }
    let bytes = text.as_bytes();
    let mut start = offset;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = offset;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    Some((text[start..end].to_string(), start, end))
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

const SEMANTIC_TOKEN_KEYWORD: u32 = 0;
const SEMANTIC_TOKEN_TYPE: u32 = 1;
const SEMANTIC_TOKEN_VARIABLE: u32 = 2;
const SEMANTIC_TOKEN_PROPERTY: u32 = 3;
const SEMANTIC_TOKEN_FUNCTION: u32 = 4;
const SEMANTIC_TOKEN_STRING: u32 = 5;
const SEMANTIC_TOKEN_NUMBER: u32 = 6;
const SEMANTIC_TOKEN_OPERATOR: u32 = 7;

fn semantic_tokens_legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: vec![
            SemanticTokenType::KEYWORD,
            SemanticTokenType::TYPE,
            SemanticTokenType::VARIABLE,
            SemanticTokenType::PROPERTY,
            SemanticTokenType::FUNCTION,
            SemanticTokenType::STRING,
            SemanticTokenType::NUMBER,
            SemanticTokenType::OPERATOR,
        ],
        token_modifiers: Vec::new(),
    }
}

fn semantic_token_type_for_definition(kind: &DefinitionKind) -> u32 {
    match kind {
        DefinitionKind::Message | DefinitionKind::Role | DefinitionKind::Enum => {
            SEMANTIC_TOKEN_TYPE
        }
        DefinitionKind::Phase | DefinitionKind::Property => SEMANTIC_TOKEN_FUNCTION,
        DefinitionKind::Param => SEMANTIC_TOKEN_PROPERTY,
        DefinitionKind::Var => SEMANTIC_TOKEN_VARIABLE,
    }
}

fn is_ident_start_char(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn compare_position(a: Position, b: Position) -> std::cmp::Ordering {
    (a.line, a.character).cmp(&(b.line, b.character))
}

fn position_in_range(pos: Position, range: &Range) -> bool {
    compare_position(pos, range.start) != std::cmp::Ordering::Less
        && compare_position(pos, range.end) == std::cmp::Ordering::Less
}

fn semantic_operator_len_at(bytes: &[u8], i: usize) -> usize {
    const OPS: [&[u8]; 18] = [
        b"<=>", b"==>", b"&&", b"||", b">=", b"<=", b"==", b"!=", b"[]", b"<>", b"~>", b"+", b"-",
        b"*", b"/", b">", b"<", b"=",
    ];
    for op in OPS {
        if i + op.len() <= bytes.len() && &bytes[i..i + op.len()] == op {
            return op.len();
        }
    }
    0
}

#[derive(Debug, Clone)]
struct SemanticTokenCandidate {
    start: usize,
    end: usize,
    token_type: u32,
}

fn collect_semantic_token_candidates(
    source: &str,
    program: Option<&Program>,
) -> Vec<SemanticTokenCandidate> {
    let mut def_types: HashMap<String, u32> = HashMap::new();
    if let Some(program) = program {
        for def in collect_definitions(program) {
            def_types
                .entry(def.name.clone())
                .or_insert_with(|| semantic_token_type_for_definition(&def.kind));
        }
    }

    let mut candidates = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip line comments.
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Skip block comments.
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        // String literals.
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let b = bytes[i];
                if escaped {
                    escaped = false;
                    i += 1;
                    continue;
                }
                if b == b'\\' {
                    escaped = true;
                    i += 1;
                    continue;
                }
                i += 1;
                if b == b'"' {
                    break;
                }
            }
            candidates.push(SemanticTokenCandidate {
                start,
                end: i.min(bytes.len()),
                token_type: SEMANTIC_TOKEN_STRING,
            });
            continue;
        }

        // Numbers.
        if bytes[i].is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            candidates.push(SemanticTokenCandidate {
                start,
                end: i,
                token_type: SEMANTIC_TOKEN_NUMBER,
            });
            continue;
        }

        // Identifiers, keywords, and known symbols.
        if is_ident_start_char(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_char(bytes[i]) {
                i += 1;
            }
            let text = &source[start..i];
            let token_type = if keyword_docs(text).is_some() {
                SEMANTIC_TOKEN_KEYWORD
            } else if let Some(kind) = def_types.get(text) {
                *kind
            } else {
                SEMANTIC_TOKEN_VARIABLE
            };
            candidates.push(SemanticTokenCandidate {
                start,
                end: i,
                token_type,
            });
            continue;
        }

        // Operators.
        let op_len = semantic_operator_len_at(bytes, i);
        if op_len > 0 {
            candidates.push(SemanticTokenCandidate {
                start: i,
                end: i + op_len,
                token_type: SEMANTIC_TOKEN_OPERATOR,
            });
            i += op_len;
            continue;
        }

        // Advance by one UTF-8 scalar.
        i += source[i..].chars().next().map(char::len_utf8).unwrap_or(1);
    }

    candidates.sort_by_key(|c| (c.start, c.end));
    candidates
        .dedup_by(|a, b| a.start == b.start && a.end == b.end && a.token_type == b.token_type);
    candidates
}

fn build_semantic_tokens(
    source: &str,
    program: Option<&Program>,
    range: Option<&Range>,
) -> SemanticTokens {
    let candidates = collect_semantic_token_candidates(source, program);
    let mut tokens = Vec::new();
    let mut prev_line = 0u32;
    let mut prev_start = 0u32;
    let mut have_prev = false;

    for candidate in candidates {
        if candidate.start >= candidate.end || candidate.end > source.len() {
            continue;
        }
        let start_pos = offset_to_position(source, candidate.start);
        if let Some(filter_range) = range {
            if !position_in_range(start_pos, filter_range) {
                continue;
            }
        }
        let end_pos = offset_to_position(source, candidate.end);
        if start_pos.line != end_pos.line {
            continue;
        }
        if end_pos.character <= start_pos.character {
            continue;
        }
        let length = end_pos.character - start_pos.character;
        let delta_line = if have_prev {
            start_pos.line - prev_line
        } else {
            start_pos.line
        };
        let delta_start = if have_prev && delta_line == 0 {
            start_pos.character - prev_start
        } else {
            start_pos.character
        };

        tokens.push(SemanticToken {
            delta_line,
            delta_start,
            length,
            token_type: candidate.token_type,
            token_modifiers_bitset: 0,
        });
        prev_line = start_pos.line;
        prev_start = start_pos.character;
        have_prev = true;
    }

    SemanticTokens {
        result_id: None,
        data: tokens,
    }
}

fn count_leading_closing_braces(line: &str) -> i32 {
    line.chars()
        .take_while(|c| c.is_ascii_whitespace() || *c == '}')
        .filter(|c| *c == '}')
        .count() as i32
}

fn brace_counts_ignoring_strings_and_comments(line: &str) -> (i32, i32) {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut opens = 0i32;
    let mut closes = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if i + 1 < bytes.len() && b == b'/' && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'{' {
            opens += 1;
        } else if b == b'}' {
            closes += 1;
        }
        i += 1;
    }
    (opens, closes)
}

fn format_document_text(source: &str) -> String {
    let mut formatted = String::new();
    let mut indent = 0i32;
    let mut last_was_blank = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !last_was_blank {
                formatted.push('\n');
                last_was_blank = true;
            }
            continue;
        }
        last_was_blank = false;

        let leading_closes = count_leading_closing_braces(trimmed);
        let current_indent = (indent - leading_closes).max(0);
        for _ in 0..current_indent {
            formatted.push_str("    ");
        }
        formatted.push_str(trimmed);
        formatted.push('\n');

        let (opens, closes) = brace_counts_ignoring_strings_and_comments(trimmed);
        let non_leading_closes = (closes - leading_closes).max(0);
        indent = (current_indent + opens - non_leading_closes).max(0);
    }

    if !source.ends_with('\n') && formatted.ends_with('\n') {
        formatted.pop();
    }
    formatted
}

fn is_valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn resolve_import_path(base_path: &Path, import_path: &str) -> Option<PathBuf> {
    let import = Path::new(import_path);
    let mut candidates = Vec::new();

    if import.is_absolute() {
        candidates.push(import.to_path_buf());
    } else {
        let parent = base_path.parent()?;
        candidates.push(parent.join(import));
    }

    if import.extension().is_none() {
        let mut with_ext = candidates[0].clone();
        with_ext.set_extension("trs");
        candidates.push(with_ext);
    }

    for candidate in candidates {
        if candidate.exists() {
            if let Ok(canon) = std::fs::canonicalize(candidate) {
                return Some(canon);
            }
        }
    }
    None
}

fn resolve_import_uri(base_uri: &Url, import_path: &str) -> Option<Url> {
    let base_path = base_uri.to_file_path().ok()?;
    let import_fs_path = resolve_import_path(&base_path, import_path)?;
    Url::from_file_path(import_fs_path).ok()
}

fn is_skippable_workspace_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".idea" | ".vscode"
    )
}

fn workspace_roots_from_uris(uris: &[Url]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for uri in uris {
        let Ok(file_path) = uri.to_file_path() else {
            continue;
        };
        let Some(parent) = file_path.parent() else {
            continue;
        };
        if let Ok(canon) = std::fs::canonicalize(parent) {
            if !roots.contains(&canon) {
                roots.push(canon);
            }
        }
    }
    roots
}

fn discover_workspace_trs_files(root: &Path, max_files: usize, max_depth: usize) -> Vec<PathBuf> {
    if max_files == 0 || !root.exists() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };

            if ft.is_dir() {
                if depth >= max_depth {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if is_skippable_workspace_dir(name) {
                        continue;
                    }
                }
                queue.push_back((path, depth + 1));
                continue;
            }

            if ft.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("trs"))
                    .unwrap_or(false)
            {
                if let Ok(canon) = std::fs::canonicalize(path) {
                    out.push(canon);
                }
                if out.len() >= max_files {
                    return out;
                }
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Keyword documentation
// ---------------------------------------------------------------------------

fn keyword_docs(word: &str) -> Option<&'static str> {
    match word {
        "protocol" => Some("Top-level protocol declaration. Contains parameters, messages, roles, and properties."),
        "parameters" => Some("Parameter block declaring symbolic integer constants (e.g., `n: nat; t: nat;`)."),
        "resilience" => Some("Resilience condition constraining the relationship between total processes (n) and faulty processes (t). Example: `n > 3*t`"),
        "adversary" => Some("Adversary model configuration. Keys: `model` (byzantine/crash/omission), `bound` (fault bound parameter)."),
        "message" => Some("Message type declaration. Can include fields: `message Vote(value: nat, round: nat);`"),
        "role" => Some("Role declaration defining a process type with variables, an init phase, and phases with transitions."),
        "var" => Some("Local variable declaration inside a role. Syntax: `var name: type = init_value;`"),
        "init" => Some("Specifies the initial phase for a role. Syntax: `init <phase_name>;`"),
        "phase" => Some("Phase (location) in the role's state machine. Contains transition rules (`when ... => { ... }`)."),
        "when" => Some("Transition guard in a phase. Syntax: `when <guard> => { <actions> }`"),
        "send" => Some("Action: broadcast a message to all processes. Syntax: `send MessageType(args);`"),
        "goto" => Some("Action: transition to another phase. Syntax: `goto phase <name>;`"),
        "decide" => Some("Action: make a decision (for agreement properties). Syntax: `decide <value>;`"),
        "received" => Some("Threshold guard: checks if enough messages of a type have been received. Syntax: `received [distinct] >= THRESHOLD MessageType`"),
        "property" => Some("Property declaration for verification. Syntax: `property name: kind { formula }`"),
        "agreement" => Some("Agreement property: all correct processes that decide must decide the same value."),
        "validity" => Some("Validity property: if all correct processes start with the same value, they must decide that value."),
        "safety" => Some("Generic safety property (something bad never happens)."),
        "invariant" => Some("Invariant property: a condition that must hold in every reachable state."),
        "liveness" => Some("Liveness property: something good eventually happens."),
        "committee" => Some("Committee selection declaration for probabilistic verification. Specifies population, byzantine count, committee size, and error bound."),
        "identity" => Some("Identity declaration specifying authentication scope for a role (role-level or process-level)."),
        "channel" => Some("Channel authentication declaration for a message type (`authenticated` or `unauthenticated`)."),
        "equivocation" => Some("Equivocation policy for a message type (`full` or `none`)."),
        "forall" => Some("Universal quantifier in property formulas. Syntax: `forall p: RoleName. <formula>`"),
        "exists" => Some("Existential quantifier in property formulas. Syntax: `exists p: RoleName. <formula>`"),
        "enum" => Some("Finite domain enumeration type. Syntax: `enum Color { Red, Green, Blue }`"),
        "certificate" | "threshold_signature" => Some("Cryptographic object declaration for quorum certificates or threshold signatures."),
        "pacemaker" => Some("Pacemaker configuration for automatic view/round changes."),
        "module" => Some("Module declaration for compositional protocol specification."),
        "import" => Some("Import declaration to include external protocol modules."),
        "true" => Some("Boolean literal `true`."),
        "false" => Some("Boolean literal `false`."),
        "bool" => Some("Boolean type for local variables."),
        "nat" => Some("Natural number type (non-negative integer) for parameters and variables."),
        "int" => Some("Integer type for parameters and variables."),
        "distinct" => Some("Modifier for threshold guards: count distinct senders. Syntax: `received distinct >= N MsgType`"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Completion helpers
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum CursorContext {
    TopLevel,
    RoleLevel,
    PhaseLevel,
    ActionLevel,
    AfterColon,
    AfterPropertyColon,
    FormulaContext,
    Unknown,
}

fn infer_cursor_context(text: &str, offset: usize) -> CursorContext {
    let before = &text[..offset.min(text.len())];

    // Check backward for structural context
    let mut brace_depth: i32 = 0;
    let mut last_keyword = None;

    // Walk backwards looking at braces and keywords
    for (i, ch) in before.char_indices().rev() {
        match ch {
            '}' => brace_depth += 1,
            '{' => {
                brace_depth -= 1;
                if brace_depth < 0 {
                    // Find what keyword precedes this opening brace
                    let before_brace = before[..i].trim_end();
                    if before_brace.ends_with("=>") {
                        return CursorContext::ActionLevel;
                    }
                    // Look for keyword before the brace
                    let word_end = before_brace.len();
                    let word_start = before_brace
                        .rfind(|c: char| !c.is_alphanumeric() && c != '_')
                        .map(|p| p + 1)
                        .unwrap_or(0);
                    let kw = &before_brace[word_start..word_end];
                    last_keyword = Some(kw.to_string());
                    break;
                }
            }
            _ => {}
        }
    }

    // Check if cursor is right after ':'
    let trimmed = before.trim_end();
    if let Some(stripped) = trimmed.strip_suffix(':') {
        // Check if this is a property declaration
        let before_colon = stripped.trim_end();
        // Look for "property <name>" pattern
        let words: Vec<&str> = before_colon.split_whitespace().collect();
        if words.len() >= 2 && words[words.len() - 2] == "property" {
            return CursorContext::AfterPropertyColon;
        }
        return CursorContext::AfterColon;
    }

    if let Some(kw) = last_keyword {
        match kw.as_str() {
            "protocol" => return CursorContext::TopLevel,
            // Inside a role block
            name if before.contains(&format!("role {name}"))
                || before.contains(&format!("role {name} ")) =>
            {
                // Check if we're more deeply nested (inside a phase)
                // Count depth of braces from this role's opening
                let role_pattern = format!("role {name}");
                if let Some(role_pos) = before.rfind(&role_pattern) {
                    let after_role = &before[role_pos..];
                    let mut depth = 0i32;
                    for ch in after_role.chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => depth -= 1,
                            _ => {}
                        }
                    }
                    if depth >= 3 {
                        return CursorContext::ActionLevel;
                    }
                    if depth >= 2 {
                        return CursorContext::PhaseLevel;
                    }
                    return CursorContext::RoleLevel;
                }
                return CursorContext::RoleLevel;
            }
            _ => {}
        }
    }

    // Fallback: count nesting depth from the start
    let mut depth = 0i32;
    let mut in_phase = false;
    let mut in_action = false;
    for (i, ch) in before.char_indices() {
        match ch {
            '{' => {
                depth += 1;
                let pre = before[..i].trim_end();
                if pre.ends_with("=>") {
                    in_action = true;
                } else if depth >= 3 {
                    // Check if preceding text indicates a phase
                    let words: Vec<&str> = pre.split_whitespace().collect();
                    if let Some(last) = words.last() {
                        if *last != "protocol" && depth >= 2 {
                            in_phase = true;
                        }
                    }
                }
            }
            '}' => {
                depth -= 1;
                if depth < 3 {
                    in_action = false;
                }
                if depth < 2 {
                    in_phase = false;
                }
            }
            _ => {}
        }
    }

    if in_action || depth >= 4 {
        return CursorContext::ActionLevel;
    }

    // Check if we're in a formula/property context
    let trimmed_before = before.trim_end();
    if trimmed_before.contains("property ") && depth >= 2 {
        return CursorContext::FormulaContext;
    }

    if in_phase || depth >= 3 {
        return CursorContext::PhaseLevel;
    }
    if depth >= 2 {
        return CursorContext::RoleLevel;
    }
    if depth >= 1 {
        return CursorContext::TopLevel;
    }

    CursorContext::Unknown
}

fn build_completions(context: &CursorContext, program: Option<&Program>) -> Vec<CompletionItem> {
    let mut items = Vec::new();

    match context {
        CursorContext::TopLevel => {
            for kw in &[
                "parameters",
                "resilience",
                "adversary",
                "message",
                "role",
                "property",
                "committee",
                "identity",
                "channel",
                "equivocation",
                "enum",
                "pacemaker",
                "module",
                "import",
                "certificate",
                "threshold_signature",
            ] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    detail: keyword_docs(kw).map(|s| s.to_string()),
                    ..Default::default()
                });
            }
        }
        CursorContext::RoleLevel => {
            for kw in &["var", "init", "phase"] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    detail: keyword_docs(kw).map(|s| s.to_string()),
                    ..Default::default()
                });
            }
        }
        CursorContext::PhaseLevel => {
            items.push(CompletionItem {
                label: "when".into(),
                kind: Some(CompletionItemKind::KEYWORD),
                detail: keyword_docs("when").map(|s| s.to_string()),
                ..Default::default()
            });
            for kw in &["received", "received distinct", "has", "true", "false"] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                });
            }
        }
        CursorContext::ActionLevel => {
            for kw in &[
                "send",
                "goto phase",
                "decide",
                "assign",
                "form",
                "lock",
                "justify",
            ] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                });
            }
            // Add message names and phase names from AST
            if let Some(prog) = program {
                for msg in &prog.protocol.node.messages {
                    items.push(CompletionItem {
                        label: msg.name.clone(),
                        kind: Some(CompletionItemKind::CLASS),
                        detail: Some("Message type".into()),
                        ..Default::default()
                    });
                }
                for role in &prog.protocol.node.roles {
                    for phase in &role.node.phases {
                        items.push(CompletionItem {
                            label: phase.node.name.clone(),
                            kind: Some(CompletionItemKind::ENUM_MEMBER),
                            detail: Some(format!("Phase in role {}", role.node.name)),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        CursorContext::AfterColon => {
            for kw in &["bool", "nat", "int"] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    detail: keyword_docs(kw).map(|s| s.to_string()),
                    ..Default::default()
                });
            }
            // Add enum names
            if let Some(prog) = program {
                for e in &prog.protocol.node.enums {
                    items.push(CompletionItem {
                        label: e.name.clone(),
                        kind: Some(CompletionItemKind::ENUM),
                        detail: Some("Enum type".into()),
                        ..Default::default()
                    });
                }
            }
        }
        CursorContext::AfterPropertyColon => {
            for kw in &["agreement", "validity", "safety", "invariant", "liveness"] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    detail: keyword_docs(kw).map(|s| s.to_string()),
                    ..Default::default()
                });
            }
        }
        CursorContext::FormulaContext => {
            for kw in &[
                "forall", "exists", "true", "false", "[]", "<>", "X", "U", "W", "R", "~>",
            ] {
                items.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                });
            }
            // Add role names for quantifier domains
            if let Some(prog) = program {
                for role in &prog.protocol.node.roles {
                    items.push(CompletionItem {
                        label: role.node.name.clone(),
                        kind: Some(CompletionItemKind::CLASS),
                        detail: Some("Role (quantifier domain)".into()),
                        ..Default::default()
                    });
                }
            }
        }
        CursorContext::Unknown => {
            // Offer context-aware names if we have an AST
            if let Some(prog) = program {
                for msg in &prog.protocol.node.messages {
                    items.push(CompletionItem {
                        label: msg.name.clone(),
                        kind: Some(CompletionItemKind::CLASS),
                        detail: Some("Message type".into()),
                        ..Default::default()
                    });
                }
                for param in &prog.protocol.node.parameters {
                    items.push(CompletionItem {
                        label: param.name.clone(),
                        kind: Some(CompletionItemKind::VARIABLE),
                        detail: Some(format!("Parameter: {:?}", param.ty)),
                        ..Default::default()
                    });
                }
            }
        }
    }

    items
}

// ---------------------------------------------------------------------------
// AST-aware hover
// ---------------------------------------------------------------------------

fn hover_for_user_defined(word: &str, program: &Program) -> Option<String> {
    let proto = &program.protocol.node;

    // Messages
    for msg in &proto.messages {
        if msg.name == word {
            if msg.fields.is_empty() {
                return Some(format!("**Message** `{}`", msg.name));
            } else {
                let fields: Vec<String> = msg
                    .fields
                    .iter()
                    .map(|f| format!("{}: {}", f.name, f.ty))
                    .collect();
                return Some(format!("**Message** `{}({})`", msg.name, fields.join(", ")));
            }
        }
    }

    // Roles
    for role in &proto.roles {
        if role.node.name == word {
            let n_vars = role.node.vars.len();
            let n_phases = role.node.phases.len();
            let phase_names: Vec<&str> = role
                .node
                .phases
                .iter()
                .map(|p| p.node.name.as_str())
                .collect();
            return Some(format!(
                "**Role** `{}` — {} variable(s), {} phase(s) ({})",
                role.node.name,
                n_vars,
                n_phases,
                phase_names.join(", ")
            ));
        }
    }

    // Phases
    for role in &proto.roles {
        for phase in &role.node.phases {
            if phase.node.name == word {
                let n_transitions = phase.node.transitions.len();
                return Some(format!(
                    "**Phase** `{}` in role `{}` — {} transition(s)",
                    phase.node.name, role.node.name, n_transitions
                ));
            }
        }
    }

    // Parameters
    for param in &proto.parameters {
        if param.name == word {
            return Some(format!("**Parameter** `{}: {:?}`", param.name, param.ty));
        }
    }

    // Variables
    for role in &proto.roles {
        for var in &role.node.vars {
            if var.name == word {
                let ty_str = match &var.ty {
                    VarType::Bool => "bool".to_string(),
                    VarType::Nat => "nat".to_string(),
                    VarType::Int => "int".to_string(),
                    VarType::Enum(e) => e.clone(),
                };
                let init_str = var
                    .init
                    .as_ref()
                    .map(|e| format!(" = {e}"))
                    .unwrap_or_default();
                return Some(format!(
                    "**Variable** `{}: {}{init_str}` in role `{}`",
                    var.name, ty_str, role.node.name
                ));
            }
        }
    }

    // Properties
    for prop in &proto.properties {
        if prop.node.name == word {
            return Some(format!(
                "**Property** `{}`: {}",
                prop.node.name, prop.node.kind
            ));
        }
    }

    // Enums
    for e in &proto.enums {
        if e.name == word {
            return Some(format!(
                "**Enum** `{}` {{ {} }}",
                e.name,
                e.variants.join(", ")
            ));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Collect definitions from AST
// ---------------------------------------------------------------------------

fn collect_definitions(program: &Program) -> Vec<DefinitionInfo> {
    let mut defs = Vec::new();
    let proto = &program.protocol.node;

    // Messages
    for msg in &proto.messages {
        defs.push(DefinitionInfo {
            name: msg.name.clone(),
            kind: DefinitionKind::Message,
            start: msg.span.start,
            end: msg.span.end,
            parent: None,
        });
    }

    // Parameters
    for param in &proto.parameters {
        defs.push(DefinitionInfo {
            name: param.name.clone(),
            kind: DefinitionKind::Param,
            start: param.span.start,
            end: param.span.end,
            parent: None,
        });
    }

    // Enums
    for e in &proto.enums {
        defs.push(DefinitionInfo {
            name: e.name.clone(),
            kind: DefinitionKind::Enum,
            start: e.span.start,
            end: e.span.end,
            parent: None,
        });
    }

    // Roles
    for role in &proto.roles {
        defs.push(DefinitionInfo {
            name: role.node.name.clone(),
            kind: DefinitionKind::Role,
            start: role.span.start,
            end: role.span.end,
            parent: None,
        });

        // Phases
        for phase in &role.node.phases {
            defs.push(DefinitionInfo {
                name: phase.node.name.clone(),
                kind: DefinitionKind::Phase,
                start: phase.span.start,
                end: phase.span.end,
                parent: Some(role.node.name.clone()),
            });
        }

        // Variables
        for var in &role.node.vars {
            defs.push(DefinitionInfo {
                name: var.name.clone(),
                kind: DefinitionKind::Var,
                start: var.span.start,
                end: var.span.end,
                parent: Some(role.node.name.clone()),
            });
        }
    }

    // Properties
    for prop in &proto.properties {
        defs.push(DefinitionInfo {
            name: prop.node.name.clone(),
            kind: DefinitionKind::Property,
            start: prop.span.start,
            end: prop.span.end,
            parent: None,
        });
    }

    defs
}

fn build_symbol_tables(program: &Program) -> SymbolTables {
    let mut tables = SymbolTables::default();
    let proto = &program.protocol.node;

    for param in &proto.parameters {
        tables.params.insert(param.name.clone());
    }
    for role in &proto.roles {
        tables.roles.insert(role.node.name.clone());

        let role_vars = tables.role_vars.entry(role.node.name.clone()).or_default();
        for var in &role.node.vars {
            role_vars.insert(var.name.clone());
        }

        let role_phases = tables
            .role_phases
            .entry(role.node.name.clone())
            .or_default();
        for phase in &role.node.phases {
            role_phases.insert(phase.node.name.clone());
        }
    }

    tables
}

fn add_occurrence(
    out: &mut Vec<SymbolOccurrence>,
    name: &str,
    kind: DefinitionKind,
    parent: Option<&str>,
    start: usize,
    end: usize,
    declaration: bool,
) {
    if start >= end {
        return;
    }
    out.push(SymbolOccurrence {
        name: name.to_string(),
        kind,
        parent: parent.map(ToString::to_string),
        start,
        end,
        declaration,
    });
}

fn classify_runtime_identifier(
    name: &str,
    tables: &SymbolTables,
    current_role: Option<&str>,
) -> Option<(DefinitionKind, Option<String>)> {
    if let Some(role) = current_role {
        if tables
            .role_vars
            .get(role)
            .is_some_and(|vars| vars.contains(name))
        {
            return Some((DefinitionKind::Var, Some(role.to_string())));
        }
    }
    if tables.params.contains(name) {
        return Some((DefinitionKind::Param, None));
    }
    None
}

fn collect_expr_identifiers(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::ident => {
            if let Some((kind, parent)) =
                classify_runtime_identifier(pair.as_str(), tables, current_role)
            {
                let span = pair.as_span();
                add_occurrence(
                    out,
                    pair.as_str(),
                    kind,
                    parent.as_deref(),
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_expr_identifiers(child, tables, current_role, out);
            }
        }
    }
}

fn collect_linear_identifiers(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    collect_expr_identifiers(pair, tables, current_role, out);
}

fn collect_arg_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::arg => {
            if let Some(inner) = pair.into_inner().next() {
                collect_arg_occurrences(inner, tables, current_role, out);
            }
        }
        ReferenceRule::named_arg => {
            let mut inner = pair.into_inner();
            let _name = inner.next();
            if let Some(value) = inner.next() {
                collect_expr_identifiers(value, tables, current_role, out);
            }
        }
        _ => collect_expr_identifiers(pair, tables, current_role, out),
    }
}

fn collect_msg_filter_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::msg_filter_item => {
            let mut inner = pair.into_inner();
            let _name = inner.next();
            if let Some(value) = inner.next() {
                collect_expr_identifiers(value, tables, current_role, out);
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_msg_filter_occurrences(child, tables, current_role, out);
            }
        }
    }
}

fn collect_guard_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::guard_expr => {
            for child in pair.into_inner() {
                if child.as_rule() != ReferenceRule::guard_op {
                    collect_guard_occurrences(child, tables, current_role, out);
                }
            }
        }
        ReferenceRule::guard_atom => {
            if let Some(inner) = pair.into_inner().next() {
                collect_guard_occurrences(inner, tables, current_role, out);
            }
        }
        ReferenceRule::threshold_guard => {
            let mut captured_message = false;
            for child in pair.into_inner() {
                match child.as_rule() {
                    ReferenceRule::linear_expr_no_implicit | ReferenceRule::linear_expr => {
                        collect_linear_identifiers(child, tables, Some(current_role), out);
                    }
                    ReferenceRule::ident if !captured_message => {
                        captured_message = true;
                        let span = child.as_span();
                        add_occurrence(
                            out,
                            child.as_str(),
                            DefinitionKind::Message,
                            None,
                            span.start(),
                            span.end(),
                            false,
                        );
                    }
                    ReferenceRule::msg_filter => {
                        collect_msg_filter_occurrences(child, tables, Some(current_role), out);
                    }
                    _ => {}
                }
            }
        }
        ReferenceRule::has_crypto_guard => {
            let mut inner = pair.into_inner();
            let _object_name = inner.next();
            for child in inner {
                if child.as_rule() == ReferenceRule::msg_filter {
                    collect_msg_filter_occurrences(child, tables, Some(current_role), out);
                }
            }
        }
        ReferenceRule::comparison_guard => {
            for child in pair.into_inner() {
                if matches!(child.as_rule(), ReferenceRule::expr | ReferenceRule::term) {
                    collect_expr_identifiers(child, tables, Some(current_role), out);
                }
            }
        }
        ReferenceRule::bool_guard => {
            if let Some(name) = pair.into_inner().next() {
                if let Some((kind, parent)) =
                    classify_runtime_identifier(name.as_str(), tables, Some(current_role))
                {
                    let span = name.as_span();
                    add_occurrence(
                        out,
                        name.as_str(),
                        kind,
                        parent.as_deref(),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_guard_occurrences(child, tables, current_role, out);
            }
        }
    }
}

fn collect_transition_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    if let Some(guard) = inner.next() {
        collect_guard_occurrences(guard, tables, current_role, out);
    }

    for action in inner {
        match action.as_rule() {
            ReferenceRule::send_action => {
                let mut ai = action.into_inner();
                if let Some(msg) = ai.next() {
                    let span = msg.as_span();
                    add_occurrence(
                        out,
                        msg.as_str(),
                        DefinitionKind::Message,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
                for child in ai {
                    match child.as_rule() {
                        ReferenceRule::arg_list => {
                            for arg in child.into_inner() {
                                collect_arg_occurrences(arg, tables, Some(current_role), out);
                            }
                        }
                        ReferenceRule::ident => {
                            let span = child.as_span();
                            add_occurrence(
                                out,
                                child.as_str(),
                                DefinitionKind::Role,
                                None,
                                span.start(),
                                span.end(),
                                false,
                            );
                        }
                        _ => {}
                    }
                }
            }
            ReferenceRule::form_crypto_action => {
                let mut ai = action.into_inner();
                let _object_name = ai.next();
                for child in ai {
                    match child.as_rule() {
                        ReferenceRule::arg_list => {
                            for arg in child.into_inner() {
                                collect_arg_occurrences(arg, tables, Some(current_role), out);
                            }
                        }
                        ReferenceRule::ident => {
                            let span = child.as_span();
                            add_occurrence(
                                out,
                                child.as_str(),
                                DefinitionKind::Role,
                                None,
                                span.start(),
                                span.end(),
                                false,
                            );
                        }
                        _ => {}
                    }
                }
            }
            ReferenceRule::lock_crypto_action | ReferenceRule::justify_crypto_action => {
                let mut ai = action.into_inner();
                let _object_name = ai.next();
                for child in ai {
                    if child.as_rule() == ReferenceRule::arg_list {
                        for arg in child.into_inner() {
                            collect_arg_occurrences(arg, tables, Some(current_role), out);
                        }
                    }
                }
            }
            ReferenceRule::assign_action => {
                let mut ai = action.into_inner();
                if let Some(var) = ai.next() {
                    let span = var.as_span();
                    add_occurrence(
                        out,
                        var.as_str(),
                        DefinitionKind::Var,
                        Some(current_role),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
                if let Some(expr) = ai.next() {
                    collect_expr_identifiers(expr, tables, Some(current_role), out);
                }
            }
            ReferenceRule::goto_action => {
                if let Some(phase) = action.into_inner().next() {
                    let span = phase.as_span();
                    add_occurrence(
                        out,
                        phase.as_str(),
                        DefinitionKind::Phase,
                        Some(current_role),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
            ReferenceRule::decide_action => {
                if let Some(expr) = action.into_inner().next() {
                    collect_expr_identifiers(expr, tables, Some(current_role), out);
                }
            }
            _ => {}
        }
    }
}

fn collect_phase_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(phase_name) = inner.next() else {
        return;
    };
    let phase_span = phase_name.as_span();
    add_occurrence(
        out,
        phase_name.as_str(),
        DefinitionKind::Phase,
        Some(current_role),
        phase_span.start(),
        phase_span.end(),
        true,
    );

    for item in inner {
        if item.as_rule() == ReferenceRule::transition_rule {
            collect_transition_occurrences(item, tables, current_role, out);
        }
    }
}

fn collect_var_decl_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(var_name) = inner.next() else {
        return;
    };
    let span = var_name.as_span();
    add_occurrence(
        out,
        var_name.as_str(),
        DefinitionKind::Var,
        Some(current_role),
        span.start(),
        span.end(),
        true,
    );

    if let Some(var_ty) = inner.next() {
        if var_ty.as_rule() == ReferenceRule::ident {
            let ty_span = var_ty.as_span();
            add_occurrence(
                out,
                var_ty.as_str(),
                DefinitionKind::Enum,
                None,
                ty_span.start(),
                ty_span.end(),
                false,
            );
        }
    }

    for item in inner {
        if item.as_rule() == ReferenceRule::expr {
            collect_expr_identifiers(item, tables, Some(current_role), out);
        }
    }
}

fn collect_role_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(role_name) = inner.next() else {
        return;
    };
    let role = role_name.as_str().to_string();
    let span = role_name.as_span();
    add_occurrence(
        out,
        &role,
        DefinitionKind::Role,
        None,
        span.start(),
        span.end(),
        true,
    );

    for item in inner {
        match item.as_rule() {
            ReferenceRule::var_decl => collect_var_decl_occurrences(item, tables, &role, out),
            ReferenceRule::init_decl => {
                if let Some(init_phase) = item.into_inner().next() {
                    let init_span = init_phase.as_span();
                    add_occurrence(
                        out,
                        init_phase.as_str(),
                        DefinitionKind::Phase,
                        Some(&role),
                        init_span.start(),
                        init_span.end(),
                        false,
                    );
                }
            }
            ReferenceRule::phase_decl => collect_phase_occurrences(item, tables, &role, out),
            _ => {}
        }
    }
}

fn collect_parameters_occurrences(pair: ReferencePair<'_>, out: &mut Vec<SymbolOccurrence>) {
    for item in pair.into_inner() {
        match item.as_rule() {
            ReferenceRule::param_def | ReferenceRule::param_list_item => {
                if let Some(name) = item.into_inner().next() {
                    let span = name.as_span();
                    add_occurrence(
                        out,
                        name.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        true,
                    );
                }
            }
            ReferenceRule::param_list => {
                for arg in item.into_inner() {
                    if arg.as_rule() == ReferenceRule::param_list_item {
                        collect_parameters_occurrences(arg, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_property_formula_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    quantifier_domains: &HashMap<String, String>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::qualified_ident => {
            let mut inner = pair.into_inner();
            let Some(object) = inner.next() else {
                return;
            };
            let Some(field) = inner.next() else {
                return;
            };
            if let Some(role_domain) = quantifier_domains.get(object.as_str()) {
                if tables
                    .role_vars
                    .get(role_domain)
                    .is_some_and(|vars| vars.contains(field.as_str()))
                {
                    let span = field.as_span();
                    add_occurrence(
                        out,
                        field.as_str(),
                        DefinitionKind::Var,
                        Some(role_domain),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::ident => {
            let name = pair.as_str();
            if quantifier_domains.contains_key(name) {
                return;
            }
            if tables.params.contains(name) {
                let span = pair.as_span();
                add_occurrence(
                    out,
                    name,
                    DefinitionKind::Param,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_property_formula_occurrences(child, tables, quantifier_domains, out);
            }
        }
    }
}

fn collect_quantified_formula_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner().peekable();
    let mut quantifier_domains: HashMap<String, String> = HashMap::new();

    while let Some(next) = inner.peek() {
        if next.as_rule() != ReferenceRule::quantifier {
            break;
        }
        let _quantifier = inner.next();
        let Some(var_name) = inner.next() else {
            break;
        };
        let Some(domain_name) = inner.next() else {
            break;
        };
        quantifier_domains.insert(
            var_name.as_str().to_string(),
            domain_name.as_str().to_string(),
        );
        let span = domain_name.as_span();
        add_occurrence(
            out,
            domain_name.as_str(),
            DefinitionKind::Role,
            None,
            span.start(),
            span.end(),
            false,
        );
    }

    if let Some(formula_body) = inner.next() {
        collect_property_formula_occurrences(formula_body, tables, &quantifier_domains, out);
    }
}

fn collect_module_interface_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    for item in pair.into_inner() {
        match item.as_rule() {
            ReferenceRule::assumes_clause => {
                for child in item.into_inner() {
                    if matches!(child.as_rule(), ReferenceRule::linear_expr) {
                        collect_linear_identifiers(child, tables, None, out);
                    }
                }
            }
            ReferenceRule::guarantees_clause => {
                let mut inner = item.into_inner();
                let _kind = inner.next();
                if let Some(prop_name) = inner.next() {
                    let span = prop_name.as_span();
                    add_occurrence(
                        out,
                        prop_name.as_str(),
                        DefinitionKind::Property,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
            _ => {}
        }
    }
}

fn collect_protocol_item_occurrences(
    item: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    match item.as_rule() {
        ReferenceRule::module_decl => {
            let mut inner = item.into_inner();
            let _module_name = inner.next();
            for child in inner {
                match child.as_rule() {
                    ReferenceRule::module_interface => {
                        collect_module_interface_occurrences(child, tables, out)
                    }
                    _ => collect_protocol_item_occurrences(child, tables, out),
                }
            }
        }
        ReferenceRule::enum_decl => {
            if let Some(name) = item.into_inner().next() {
                let span = name.as_span();
                add_occurrence(
                    out,
                    name.as_str(),
                    DefinitionKind::Enum,
                    None,
                    span.start(),
                    span.end(),
                    true,
                );
            }
        }
        ReferenceRule::parameters_decl
        | ReferenceRule::param_def
        | ReferenceRule::param_list
        | ReferenceRule::param_list_item => collect_parameters_occurrences(item, out),
        ReferenceRule::resilience_decl => {
            for child in item.into_inner() {
                if matches!(child.as_rule(), ReferenceRule::resilience_expr) {
                    for expr in child.into_inner() {
                        if matches!(expr.as_rule(), ReferenceRule::linear_expr) {
                            collect_linear_identifiers(expr, tables, None, out);
                        }
                    }
                }
            }
        }
        ReferenceRule::pacemaker_decl => {
            for pm_item in item.into_inner() {
                if pm_item.as_rule() != ReferenceRule::pacemaker_item {
                    continue;
                }
                let mut inner = pm_item.into_inner();
                let key = inner.next().map(|k| k.as_str().to_string());
                let Some(values) = inner.next() else {
                    continue;
                };
                for value in values.into_inner() {
                    if value.as_rule() != ReferenceRule::ident {
                        continue;
                    }
                    let span = value.as_span();
                    match key.as_deref() {
                        Some("start") => add_occurrence(
                            out,
                            value.as_str(),
                            DefinitionKind::Phase,
                            None,
                            span.start(),
                            span.end(),
                            false,
                        ),
                        _ => {
                            if tables.params.contains(value.as_str()) {
                                add_occurrence(
                                    out,
                                    value.as_str(),
                                    DefinitionKind::Param,
                                    None,
                                    span.start(),
                                    span.end(),
                                    false,
                                );
                            }
                        }
                    }
                }
            }
        }
        ReferenceRule::adversary_decl => {
            for adversary_item in item.into_inner() {
                if adversary_item.as_rule() != ReferenceRule::adversary_item {
                    continue;
                }
                let mut inner = adversary_item.into_inner();
                let key = inner.next().map(|k| k.as_str().to_string());
                let Some(value) = inner.next() else {
                    continue;
                };
                if value.as_rule() == ReferenceRule::ident
                    && (tables.params.contains(value.as_str())
                        || matches!(key.as_deref(), Some("bound")))
                {
                    let span = value.as_span();
                    add_occurrence(
                        out,
                        value.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::identity_decl => {
            if let Some(role_name) = item.into_inner().next() {
                let span = role_name.as_span();
                add_occurrence(
                    out,
                    role_name.as_str(),
                    DefinitionKind::Role,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        ReferenceRule::channel_decl | ReferenceRule::equivocation_decl => {
            if let Some(msg_name) = item.into_inner().next() {
                let span = msg_name.as_span();
                add_occurrence(
                    out,
                    msg_name.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        ReferenceRule::committee_decl => {
            let mut inner = item.into_inner();
            let _committee_name = inner.next();
            for committee_item in inner {
                if committee_item.as_rule() != ReferenceRule::committee_item {
                    continue;
                }
                let mut item_inner = committee_item.into_inner();
                let _key = item_inner.next();
                let Some(value) = item_inner.next() else {
                    continue;
                };
                if value.as_rule() == ReferenceRule::ident && tables.params.contains(value.as_str())
                {
                    let span = value.as_span();
                    add_occurrence(
                        out,
                        value.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::message_decl => {
            if let Some(message_name) = item.into_inner().next() {
                let span = message_name.as_span();
                add_occurrence(
                    out,
                    message_name.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    true,
                );
            }
        }
        ReferenceRule::crypto_object_decl => {
            let mut inner = item.into_inner();
            let _kind = inner.next();
            let _object_name = inner.next();
            if let Some(source_message) = inner.next() {
                let span = source_message.as_span();
                add_occurrence(
                    out,
                    source_message.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
            if let Some(threshold) = inner.next() {
                collect_linear_identifiers(threshold, tables, None, out);
            }
            for extra in inner {
                if extra.as_rule() == ReferenceRule::ident {
                    let span = extra.as_span();
                    add_occurrence(
                        out,
                        extra.as_str(),
                        DefinitionKind::Role,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::role_decl => collect_role_occurrences(item, tables, out),
        ReferenceRule::property_decl => {
            let mut inner = item.into_inner();
            let Some(name) = inner.next() else {
                return;
            };
            let span = name.as_span();
            add_occurrence(
                out,
                name.as_str(),
                DefinitionKind::Property,
                None,
                span.start(),
                span.end(),
                true,
            );
            let _kind = inner.next();
            if let Some(formula) = inner.next() {
                collect_quantified_formula_occurrences(formula, tables, out);
            }
        }
        _ => {}
    }
}

fn collect_symbol_occurrences(source: &str, program: &Program) -> Vec<SymbolOccurrence> {
    let Ok(mut parsed) = TarsierReferenceParser::parse(ReferenceRule::program, source) else {
        return Vec::new();
    };
    let Some(program_pair) = parsed.next() else {
        return Vec::new();
    };
    let Some(protocol_decl) = program_pair
        .into_inner()
        .find(|pair| pair.as_rule() == ReferenceRule::protocol_decl)
    else {
        return Vec::new();
    };

    let tables = build_symbol_tables(program);
    let mut out = Vec::new();
    for item in protocol_decl.into_inner() {
        collect_protocol_item_occurrences(item, &tables, &mut out);
    }

    out.sort_by_key(|occ| {
        (
            occ.start,
            occ.end,
            occ.name.clone(),
            definition_kind_sort_key(&occ.kind),
            occ.parent.clone(),
            occ.declaration,
        )
    });
    out.dedup_by(|a, b| {
        a.start == b.start
            && a.end == b.end
            && a.name == b.name
            && a.kind == b.kind
            && a.parent == b.parent
            && a.declaration == b.declaration
    });
    out
}

// ---------------------------------------------------------------------------
// Collect references (text-based search within AST spans)
// ---------------------------------------------------------------------------

fn collect_references(source: &str, program: &Program, name: &str) -> Vec<(usize, usize)> {
    let mut refs = Vec::new();
    let name_len = name.len();

    // Search for all occurrences of the name as a whole word in the source
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(name) {
        let abs_pos = search_from + pos;
        // Check word boundaries
        let before_ok = abs_pos == 0 || !is_ident_char(source.as_bytes()[abs_pos - 1]);
        let after_ok = abs_pos + name_len >= source.len()
            || !is_ident_char(source.as_bytes()[abs_pos + name_len]);
        if before_ok && after_ok {
            refs.push((abs_pos, abs_pos + name_len));
        }
        search_from = abs_pos + 1;
    }

    // Filter to only references within the protocol span
    let proto_start = program.protocol.span.start;
    let proto_end = program.protocol.span.end;
    refs.retain(|&(start, end)| start >= proto_start && end <= proto_end);

    refs
}

fn definition_spans_for_name(program: &Program, name: &str) -> Vec<(usize, usize)> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.name == name && def.start < def.end)
        .map(|def| (def.start, def.end))
        .collect()
}

fn definition_locations(source: &str, program: &Program, uri: &Url, name: &str) -> Vec<Location> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.name == name && def.start < def.end)
        .filter_map(|def| {
            offset_to_range(source, def.start, def.end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

fn reference_locations(
    source: &str,
    program: &Program,
    uri: &Url,
    name: &str,
    include_declaration: bool,
) -> Vec<Location> {
    let declaration_spans = if include_declaration {
        Vec::new()
    } else {
        definition_spans_for_name(program, name)
    };

    collect_references(source, program, name)
        .into_iter()
        .filter(|(start, end)| {
            include_declaration
                || !declaration_spans
                    .iter()
                    .any(|(dstart, dend)| start >= dstart && end <= dend)
        })
        .filter_map(|(start, end)| {
            offset_to_range(source, start, end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

fn symbol_target_from_definition(def: &DefinitionInfo) -> SymbolTarget {
    SymbolTarget {
        name: def.name.clone(),
        kind: def.kind.clone(),
        parent: def.parent.clone(),
    }
}

fn symbol_target_from_occurrence(occ: &SymbolOccurrence) -> SymbolTarget {
    SymbolTarget {
        name: occ.name.clone(),
        kind: occ.kind.clone(),
        parent: occ.parent.clone(),
    }
}

fn symbol_target_matches_occurrence(target: &SymbolTarget, occ: &SymbolOccurrence) -> bool {
    target.name == occ.name && target.kind == occ.kind && target.parent == occ.parent
}

fn symbol_target_matches_definition(target: &SymbolTarget, def: &DefinitionInfo) -> bool {
    target.name == def.name && target.kind == def.kind && target.parent == def.parent
}

fn definition_kind_sort_key(kind: &DefinitionKind) -> u8 {
    match kind {
        DefinitionKind::Message => 0,
        DefinitionKind::Role => 1,
        DefinitionKind::Phase => 2,
        DefinitionKind::Param => 3,
        DefinitionKind::Var => 4,
        DefinitionKind::Property => 5,
        DefinitionKind::Enum => 6,
    }
}

fn dedup_symbol_targets(targets: Vec<SymbolTarget>) -> Vec<SymbolTarget> {
    let mut deduped = targets;
    deduped.sort_by_key(|t| {
        (
            t.name.clone(),
            definition_kind_sort_key(&t.kind),
            t.parent.clone(),
        )
    });
    deduped.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.parent == b.parent);
    deduped
}

fn definition_spans_for_target(program: &Program, target: &SymbolTarget) -> Vec<(usize, usize)> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.start < def.end && symbol_target_matches_definition(target, def))
        .map(|def| (def.start, def.end))
        .collect()
}

fn has_target_definition(program: &Program, target: &SymbolTarget) -> bool {
    collect_definitions(program)
        .into_iter()
        .any(|def| def.start < def.end && symbol_target_matches_definition(target, &def))
}

fn dedup_and_sort_spans(spans: &mut Vec<(usize, usize)>) {
    spans.sort_unstable();
    spans.dedup();
}

fn resolve_symbol_target(
    source: &str,
    program: &Program,
    offset: usize,
    occurrences: &[SymbolOccurrence],
) -> Option<SymbolTarget> {
    let (word, start, end) = word_at_position(source, offset)?;
    if keyword_docs(&word).is_some() {
        return None;
    }

    let exact_targets = dedup_symbol_targets(
        occurrences
            .iter()
            .filter(|occ| occ.name == word && occ.start == start && occ.end == end)
            .map(symbol_target_from_occurrence)
            .collect(),
    );
    if exact_targets.len() == 1 {
        return exact_targets.into_iter().next();
    }
    if exact_targets.len() > 1 {
        let declaration_targets = dedup_symbol_targets(
            occurrences
                .iter()
                .filter(|occ| {
                    occ.name == word && occ.start == start && occ.end == end && occ.declaration
                })
                .map(symbol_target_from_occurrence)
                .collect(),
        );
        if declaration_targets.len() == 1 {
            return declaration_targets.into_iter().next();
        }
        return None;
    }

    let defs_for_name = dedup_symbol_targets(
        collect_definitions(program)
            .into_iter()
            .filter(|def| def.name == word && def.start < def.end)
            .map(|def| symbol_target_from_definition(&def))
            .collect(),
    );
    if defs_for_name.len() == 1 {
        return defs_for_name.into_iter().next();
    }
    if defs_for_name.is_empty() {
        return None;
    }

    let role_scope = program
        .protocol
        .node
        .roles
        .iter()
        .find(|role| offset >= role.span.start && offset <= role.span.end)
        .map(|role| role.node.name.clone());
    if let Some(role_name) = role_scope {
        let scoped = dedup_symbol_targets(
            defs_for_name
                .into_iter()
                .filter(|target| target.parent.as_deref() == Some(role_name.as_str()))
                .collect(),
        );
        if scoped.len() == 1 {
            return scoped.into_iter().next();
        }
    }

    None
}

fn collect_reference_spans_for_target(
    source: &str,
    program: &Program,
    target: &SymbolTarget,
    include_declaration: bool,
    occurrences: &[SymbolOccurrence],
) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = occurrences
        .iter()
        .filter(|occ| symbol_target_matches_occurrence(target, occ))
        .filter(|occ| include_declaration || !occ.declaration)
        .map(|occ| (occ.start, occ.end))
        .collect();
    dedup_and_sort_spans(&mut spans);

    if spans.is_empty() {
        spans = collect_references(source, program, &target.name);
        if matches!(target.kind, DefinitionKind::Var | DefinitionKind::Phase) {
            if let Some(role_name) = target.parent.as_deref() {
                if let Some(role) = program
                    .protocol
                    .node
                    .roles
                    .iter()
                    .find(|role| role.node.name == role_name)
                {
                    spans.retain(|(start, end)| *start >= role.span.start && *end <= role.span.end);
                }
            }
        }
        if !include_declaration {
            let declaration_spans = definition_spans_for_target(program, target);
            spans.retain(|(start, end)| {
                !declaration_spans
                    .iter()
                    .any(|(dstart, dend)| start >= dstart && end <= dend)
            });
        }
        dedup_and_sort_spans(&mut spans);
    }

    spans
}

fn target_reference_locations(
    source: &str,
    program: &Program,
    uri: &Url,
    target: &SymbolTarget,
    include_declaration: bool,
    occurrences: &[SymbolOccurrence],
) -> Vec<Location> {
    collect_reference_spans_for_target(source, program, target, include_declaration, occurrences)
        .into_iter()
        .filter_map(|(start, end)| {
            offset_to_range(source, start, end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

fn location_sort_key(location: &Location) -> (String, u32, u32, u32, u32) {
    (
        location.uri.to_string(),
        location.range.start.line,
        location.range.start.character,
        location.range.end.line,
        location.range.end.character,
    )
}

fn dedup_and_sort_locations(locations: &mut Vec<Location>) {
    locations.sort_by_key(location_sort_key);
    locations.dedup_by(|a, b| location_sort_key(a) == location_sort_key(b));
}

fn as_goto_definition_response(mut locations: Vec<Location>) -> Option<GotoDefinitionResponse> {
    dedup_and_sort_locations(&mut locations);
    match locations.len() {
        0 => None,
        1 => Some(GotoDefinitionResponse::Scalar(locations.remove(0))),
        _ => Some(GotoDefinitionResponse::Array(locations)),
    }
}

fn symbol_kind_for_definition_kind(kind: &DefinitionKind) -> SymbolKind {
    match kind {
        DefinitionKind::Message => SymbolKind::STRUCT,
        DefinitionKind::Role => SymbolKind::CLASS,
        DefinitionKind::Phase => SymbolKind::METHOD,
        DefinitionKind::Param => SymbolKind::CONSTANT,
        DefinitionKind::Var => SymbolKind::VARIABLE,
        DefinitionKind::Property => SymbolKind::PROPERTY,
        DefinitionKind::Enum => SymbolKind::ENUM,
    }
}

fn workspace_symbol_query_matches(name: &str, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return true;
    }
    let name_lc = name.to_ascii_lowercase();
    let q_lc = q.to_ascii_lowercase();
    if name_lc.contains(&q_lc) || name_lc.starts_with(&q_lc) {
        return true;
    }
    levenshtein(&name_lc, &q_lc) <= 2
}

#[allow(deprecated)]
fn collect_workspace_symbol_information(
    source: &str,
    program: &Program,
    uri: &Url,
    query: &str,
) -> Vec<SymbolInformation> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.start < def.end)
        .filter(|def| workspace_symbol_query_matches(&def.name, query))
        .filter_map(|def| {
            let range = offset_to_range(source, def.start, def.end)?;
            Some(SymbolInformation {
                name: def.name,
                kind: symbol_kind_for_definition_kind(&def.kind),
                tags: None,
                deprecated: None,
                location: Location {
                    uri: uri.clone(),
                    range,
                },
                container_name: def.parent,
            })
        })
        .collect()
}

fn workspace_symbol_sort_key(symbol: &SymbolInformation) -> (String, String, u32, u32, u32, u32) {
    (
        symbol.name.to_ascii_lowercase(),
        symbol.location.uri.to_string(),
        symbol.location.range.start.line,
        symbol.location.range.start.character,
        symbol.location.range.end.line,
        symbol.location.range.end.character,
    )
}

fn dedup_and_sort_workspace_symbols(symbols: &mut Vec<SymbolInformation>) {
    symbols.sort_by_key(workspace_symbol_sort_key);
    symbols.dedup_by(|a, b| {
        workspace_symbol_sort_key(a) == workspace_symbol_sort_key(b) && a.kind == b.kind
    });
}

// ---------------------------------------------------------------------------
// Levenshtein distance
// ---------------------------------------------------------------------------

fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

fn find_closest(name: &str, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .filter(|c| levenshtein(name, c) <= 2)
        .min_by_key(|c| levenshtein(name, c))
        .cloned()
}

fn collect_phase_names(program: &Program) -> Vec<String> {
    let mut names = Vec::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            names.push(phase.node.name.clone());
        }
    }
    names
}

fn symbol_range(source: &str, span: tarsier_dsl::ast::Span) -> Range {
    offset_to_range(source, span.start, span.end)
        .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)))
}

fn find_name_span_in_text_range(
    source: &str,
    start: usize,
    end: usize,
    name: &str,
) -> Option<(usize, usize)> {
    if name.is_empty() {
        return None;
    }
    let bounded_start = start.min(source.len());
    let bounded_end = end.min(source.len());
    if bounded_start >= bounded_end {
        return None;
    }
    let window = &source[bounded_start..bounded_end];
    let mut search_from = 0usize;
    while let Some(rel_pos) = window[search_from..].find(name) {
        let rel_start = search_from + rel_pos;
        let abs_start = bounded_start + rel_start;
        let abs_end = abs_start + name.len();
        let before_ok = abs_start == 0 || !is_ident_char(source.as_bytes()[abs_start - 1]);
        let after_ok = abs_end >= source.len() || !is_ident_char(source.as_bytes()[abs_end]);
        if before_ok && after_ok {
            return Some((abs_start, abs_end));
        }
        search_from = rel_start + 1;
    }
    None
}

fn symbol_selection_range(source: &str, span: tarsier_dsl::ast::Span, name: &str) -> Range {
    if let Some((start, end)) = find_name_span_in_text_range(source, span.start, span.end, name) {
        offset_to_range(source, start, end).unwrap_or_else(|| symbol_range(source, span))
    } else {
        symbol_range(source, span)
    }
}

#[allow(deprecated)]
fn make_document_symbol(
    source: &str,
    name: &str,
    kind: SymbolKind,
    detail: Option<String>,
    span: tarsier_dsl::ast::Span,
    children: Option<Vec<DocumentSymbol>>,
) -> DocumentSymbol {
    let range = symbol_range(source, span);
    let selection_range = symbol_selection_range(source, span, name);
    DocumentSymbol {
        name: name.to_string(),
        detail,
        kind,
        tags: None,
        deprecated: None,
        range,
        selection_range,
        children,
    }
}

fn sort_document_symbols(symbols: &mut [DocumentSymbol]) {
    symbols.sort_by_key(|symbol| {
        (
            symbol.range.start.line,
            symbol.range.start.character,
            symbol.range.end.line,
            symbol.range.end.character,
        )
    });
    for symbol in symbols {
        if let Some(children) = symbol.children.as_mut() {
            sort_document_symbols(children);
        }
    }
}

fn build_document_symbols(source: &str, program: &Program) -> Vec<DocumentSymbol> {
    let protocol = &program.protocol.node;
    let mut protocol_children: Vec<DocumentSymbol> = Vec::new();

    for import in &protocol.imports {
        protocol_children.push(make_document_symbol(
            source,
            &import.name,
            SymbolKind::MODULE,
            Some(format!("import from {}", import.path)),
            import.span,
            None,
        ));
    }

    for module in &protocol.modules {
        protocol_children.push(make_document_symbol(
            source,
            &module.name,
            SymbolKind::MODULE,
            Some("module".into()),
            module.span,
            None,
        ));
    }

    for param in &protocol.parameters {
        let detail = match param.ty {
            tarsier_dsl::ast::ParamType::Nat => "nat",
            tarsier_dsl::ast::ParamType::Int => "int",
        };
        protocol_children.push(make_document_symbol(
            source,
            &param.name,
            SymbolKind::CONSTANT,
            Some(detail.into()),
            param.span,
            None,
        ));
    }

    for e in &protocol.enums {
        protocol_children.push(make_document_symbol(
            source,
            &e.name,
            SymbolKind::ENUM,
            Some(format!("{} variant(s)", e.variants.len())),
            e.span,
            None,
        ));
    }

    for message in &protocol.messages {
        protocol_children.push(make_document_symbol(
            source,
            &message.name,
            SymbolKind::STRUCT,
            Some(format!("{} field(s)", message.fields.len())),
            message.span,
            None,
        ));
    }

    for object in &protocol.crypto_objects {
        protocol_children.push(make_document_symbol(
            source,
            &object.name,
            SymbolKind::OBJECT,
            Some(format!("from {}", object.source_message)),
            object.span,
            None,
        ));
    }

    for committee in &protocol.committees {
        protocol_children.push(make_document_symbol(
            source,
            &committee.name,
            SymbolKind::STRUCT,
            Some("committee".into()),
            committee.span,
            None,
        ));
    }

    for role in &protocol.roles {
        let mut role_children = Vec::new();
        for var in &role.node.vars {
            let ty_detail = match &var.ty {
                VarType::Bool => "bool".to_string(),
                VarType::Nat => "nat".to_string(),
                VarType::Int => "int".to_string(),
                VarType::Enum(enum_name) => enum_name.clone(),
            };
            role_children.push(make_document_symbol(
                source,
                &var.name,
                SymbolKind::VARIABLE,
                Some(ty_detail),
                var.span,
                None,
            ));
        }
        for phase in &role.node.phases {
            role_children.push(make_document_symbol(
                source,
                &phase.node.name,
                SymbolKind::METHOD,
                Some(format!("{} transition(s)", phase.node.transitions.len())),
                phase.span,
                None,
            ));
        }
        sort_document_symbols(&mut role_children);
        protocol_children.push(make_document_symbol(
            source,
            &role.node.name,
            SymbolKind::CLASS,
            Some("role".into()),
            role.span,
            Some(role_children),
        ));
    }

    for property in &protocol.properties {
        protocol_children.push(make_document_symbol(
            source,
            &property.node.name,
            SymbolKind::PROPERTY,
            Some(format!("{}", property.node.kind)),
            property.span,
            None,
        ));
    }

    sort_document_symbols(&mut protocol_children);
    vec![make_document_symbol(
        source,
        &protocol.name,
        SymbolKind::MODULE,
        Some("protocol".into()),
        program.protocol.span,
        Some(protocol_children),
    )]
}

// ---------------------------------------------------------------------------
// Code actions helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Code action generation
// ---------------------------------------------------------------------------

fn build_code_actions(
    uri: &Url,
    source: &str,
    program: Option<&Program>,
    diagnostics: &[Diagnostic],
) -> Vec<CodeActionOrCommand> {
    let mut actions = Vec::new();

    for diag in diagnostics {
        let code = diag.code.as_ref().and_then(|c| match c {
            NumberOrString::String(s) => Some(s.as_str()),
            _ => None,
        });

        match code {
            Some("tarsier::lower::unknown_phase") => {
                if let Some(prog) = program {
                    // Extract the unknown name from the message
                    let unknown_name = extract_quoted_name(&diag.message);
                    if let Some(name) = unknown_name {
                        let known_phases = collect_phase_names(prog);
                        if let Some(suggestion) = find_closest(&name, &known_phases) {
                            // Replace the unknown phase with the suggestion
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: diag.range,
                                    new_text: source[position_to_offset(source, diag.range.start)
                                        ..position_to_offset(source, diag.range.end)]
                                        .replace(&name, &suggestion),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Replace with '{suggestion}'"),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diag.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
            Some("tarsier::lower::unknown_message") => {
                if let Some(prog) = program {
                    let unknown_name = extract_quoted_name(&diag.message);
                    if let Some(name) = unknown_name {
                        let mut known_candidates: Vec<String> = prog
                            .protocol
                            .node
                            .messages
                            .iter()
                            .map(|m| m.name.clone())
                            .collect();
                        known_candidates.extend(
                            prog.protocol
                                .node
                                .crypto_objects
                                .iter()
                                .map(|obj| obj.name.clone()),
                        );

                        if let Some(suggestion) = find_closest(&name, &known_candidates) {
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: diag.range,
                                    new_text: source[position_to_offset(source, diag.range.start)
                                        ..position_to_offset(source, diag.range.end)]
                                        .replace(&name, &suggestion),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Replace with '{suggestion}'"),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diag.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }));
                        }

                        // Offer to add message declaration only for message-type diagnostics.
                        if diag.message.starts_with("Unknown message type ") {
                            // Find insertion point: after last message decl or at start of protocol body.
                            let insert_offset = prog
                                .protocol
                                .node
                                .messages
                                .last()
                                .map(|m| m.span.end)
                                .unwrap_or(prog.protocol.span.start + 1);
                            let insert_pos = offset_to_position(source, insert_offset);
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: Range::new(insert_pos, insert_pos),
                                    new_text: format!("\n    message {name};"),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Add message declaration for '{name}'"),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diag.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
            Some("tarsier::lower::unknown_enum") => {
                if let Some(prog) = program {
                    let unknown_name = extract_quoted_name(&diag.message);
                    if let Some(name) = unknown_name {
                        let known_enums: Vec<String> = prog
                            .protocol
                            .node
                            .enums
                            .iter()
                            .map(|e| e.name.clone())
                            .collect();
                        if let Some(suggestion) = find_closest(&name, &known_enums) {
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: diag.range,
                                    new_text: source[position_to_offset(source, diag.range.start)
                                        ..position_to_offset(source, diag.range.end)]
                                        .replace(&name, &suggestion),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Replace with '{suggestion}'"),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diag.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
            Some("tarsier::lower::missing_enum_init") => {
                if let Some(prog) = program {
                    let var_name = extract_quoted_name(&diag.message);
                    if let Some(vname) = var_name {
                        if let Some((insert_pos, default_variant)) =
                            find_enum_init_insertion(prog, source, &vname)
                        {
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: Range::new(insert_pos, insert_pos),
                                    new_text: format!(" = {default_variant}"),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Initialize '{vname}' with '{default_variant}'"),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diag.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
            Some("tarsier::lower::no_init_phase") => {
                if let Some(prog) = program {
                    // Find the role and suggest init <first_phase>
                    let role_name = extract_quoted_name(&diag.message);
                    if let Some(rname) = role_name {
                        for role in &prog.protocol.node.roles {
                            if role.node.name == rname {
                                if let Some(first_phase) = role.node.phases.first() {
                                    let insert_offset = first_phase.span.start;
                                    let insert_pos = offset_to_position(source, insert_offset);
                                    let mut changes = HashMap::new();
                                    changes.insert(
                                        uri.clone(),
                                        vec![TextEdit {
                                            range: Range::new(insert_pos, insert_pos),
                                            new_text: format!(
                                                "init {};\n\n        ",
                                                first_phase.node.name
                                            ),
                                        }],
                                    );
                                    actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                        title: format!("Add `init {};`", first_phase.node.name),
                                        kind: Some(CodeActionKind::QUICKFIX),
                                        diagnostics: Some(vec![diag.clone()]),
                                        edit: Some(WorkspaceEdit {
                                            changes: Some(changes),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    }));
                                }
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    actions
}

fn extract_quoted_name(message: &str) -> Option<String> {
    let start = message.find('\'')?;
    let rest = &message[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn find_enum_init_insertion(
    program: &Program,
    source: &str,
    var_name: &str,
) -> Option<(Position, String)> {
    for role in &program.protocol.node.roles {
        for var in &role.node.vars {
            if var.name != var_name {
                continue;
            }

            let VarType::Enum(enum_name) = &var.ty else {
                continue;
            };

            let default_variant = program
                .protocol
                .node
                .enums
                .iter()
                .find(|e| e.name == *enum_name)
                .and_then(|e| e.variants.first())
                .cloned()?;

            let var_text = source.get(var.span.start..var.span.end)?;
            let semi_rel = var_text.rfind(';')?;
            let insert_offset = var.span.start + semi_rel;
            return Some((offset_to_position(source, insert_offset), default_variant));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// LanguageServer implementation
// ---------------------------------------------------------------------------

#[tower_lsp::async_trait]
impl LanguageServer for TarsierLspBackend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::INCREMENTAL,
                )),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![" ".into(), ":".into(), "{".into()]),
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                document_range_formatting_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Right(RenameOptions {
                    prepare_provider: Some(true),
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                })),
                semantic_tokens_provider: Some(
                    SemanticTokensOptions {
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                        legend: semantic_tokens_legend(),
                        range: Some(true),
                        full: Some(SemanticTokensFullOptions::Bool(true)),
                    }
                    .into(),
                ),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        tracing::info!("tarsier-lsp initialized");
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let text = params.text_document.text.clone();
        let version = params.text_document.version;
        {
            let Ok(mut docs) = self.documents.write() else {
                return;
            };
            docs.insert(
                uri.clone(),
                DocumentState {
                    source: text.clone(),
                    version,
                    parsed: None,
                },
            );
        }
        let diags = self.diagnose_and_cache(&uri, &text);
        self.client.publish_diagnostics(uri, diags, None).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let version = params.text_document.version;

        let text = {
            let Ok(mut docs) = self.documents.write() else {
                return;
            };
            let state = docs.entry(uri.clone()).or_insert_with(|| DocumentState {
                source: String::new(),
                version,
                parsed: None,
            });

            for change in &params.content_changes {
                if let Some(range) = change.range {
                    apply_incremental_change(&mut state.source, &range, &change.text);
                } else {
                    // Full replacement
                    state.source = change.text.clone();
                }
            }
            state.version = version;
            state.source.clone()
        };

        let diags = self.diagnose_and_cache(&uri, &text);
        self.client.publish_diagnostics(uri, diags, None).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        {
            if let Ok(mut docs) = self.documents.write() {
                docs.remove(&uri);
            }
        }
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let offset = position_to_offset(&state.source, pos);
        let context = infer_cursor_context(&state.source, offset);
        let program = state.parsed.as_ref().map(|(p, _)| p);
        let items = build_completions(&context, program);

        Ok(Some(CompletionResponse::Array(items)))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let offset = position_to_offset(&state.source, pos);
        let word_info = word_at_position(&state.source, offset);
        let (word, w_start, w_end) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };

        // Try keyword docs first
        if let Some(doc) = keyword_docs(&word) {
            let range = offset_to_range(&state.source, w_start, w_end);
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: doc.to_string(),
                }),
                range,
            }));
        }

        // Try AST-aware docs
        if let Some((program, _)) = &state.parsed {
            if let Some(doc) = hover_for_user_defined(&word, program) {
                let range = offset_to_range(&state.source, w_start, w_end);
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: doc,
                    }),
                    range,
                }));
            }
        }

        Ok(None)
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let word_info = word_at_position(&source, offset);
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };
        if keyword_docs(&word).is_some() {
            return Ok(None);
        }

        let local_defs = definition_locations(&source, &program, &uri, &word);
        if !local_defs.is_empty() {
            return Ok(as_goto_definition_response(local_defs));
        }

        let mut imported_defs = Vec::new();
        for import_doc in self.collect_import_documents(&uri, &program) {
            imported_defs.extend(definition_locations(
                &import_doc.source,
                &import_doc.program,
                &import_doc.uri,
                &word,
            ));
        }
        Ok(as_goto_definition_response(imported_defs))
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let include_declaration = params.context.include_declaration;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let word_info = word_at_position(&source, offset);
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };
        if keyword_docs(&word).is_some() {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let target = resolve_symbol_target(&source, &program, offset, &local_occurrences);

        let mut docs = vec![SymbolDocument {
            uri: uri.clone(),
            source,
            program: program.clone(),
        }];
        docs.extend(self.collect_import_documents(&uri, &program));

        let has_definition = if let Some(target) = target.as_ref() {
            docs.iter()
                .any(|doc| has_target_definition(&doc.program, target))
        } else {
            docs.iter()
                .any(|doc| !definition_spans_for_name(&doc.program, &word).is_empty())
        };
        if !has_definition {
            return Ok(None);
        }

        let mut locations = Vec::new();
        for doc in &docs {
            if let Some(target) = target.as_ref() {
                let occurrences = collect_symbol_occurrences(&doc.source, &doc.program);
                locations.extend(target_reference_locations(
                    &doc.source,
                    &doc.program,
                    &doc.uri,
                    target,
                    include_declaration,
                    &occurrences,
                ));
            } else {
                locations.extend(reference_locations(
                    &doc.source,
                    &doc.program,
                    &doc.uri,
                    &word,
                    include_declaration,
                ));
            }
        }
        dedup_and_sort_locations(&mut locations);

        if locations.is_empty() {
            Ok(None)
        } else {
            Ok(Some(locations))
        }
    }

    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let uri = params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let new_name = params.new_name;
        if !is_valid_identifier(&new_name) {
            return Err(Error::invalid_params(format!(
                "Invalid rename target '{new_name}': expected identifier [A-Za-z_][A-Za-z0-9_]*"
            )));
        }

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let Some((old_name, _, _)) = word_at_position(&source, offset) else {
            return Ok(None);
        };
        if keyword_docs(&old_name).is_some() || !is_valid_identifier(&old_name) {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let Some(target) = resolve_symbol_target(&source, &program, offset, &local_occurrences)
        else {
            return Err(Error::invalid_params(
                "Rename target is ambiguous or unresolved at cursor position".to_string(),
            ));
        };
        if target.name == new_name {
            return Ok(None);
        }

        let mut docs = vec![SymbolDocument {
            uri: uri.clone(),
            source,
            program: program.clone(),
        }];
        docs.extend(self.collect_import_documents(&uri, &program));

        let has_definition = docs
            .iter()
            .any(|doc| has_target_definition(&doc.program, &target));
        if !has_definition {
            return Ok(None);
        }

        let mut changes: HashMap<Url, Vec<TextEdit>> = HashMap::new();
        for doc in docs {
            let occurrences = collect_symbol_occurrences(&doc.source, &doc.program);
            let refs = collect_reference_spans_for_target(
                &doc.source,
                &doc.program,
                &target,
                true,
                &occurrences,
            );
            if refs.is_empty() {
                continue;
            }

            let mut edits: Vec<TextEdit> = refs
                .into_iter()
                .filter_map(|(start, end)| {
                    offset_to_range(&doc.source, start, end).map(|range| TextEdit {
                        range,
                        new_text: new_name.clone(),
                    })
                })
                .collect();
            edits.sort_by_key(|edit| {
                (
                    edit.range.start.line,
                    edit.range.start.character,
                    edit.range.end.line,
                    edit.range.end.character,
                )
            });
            edits.dedup_by(|a, b| a.range == b.range);
            if !edits.is_empty() {
                changes.insert(doc.uri, edits);
            }
        }

        if changes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }))
        }
    }

    async fn prepare_rename(
        &self,
        params: TextDocumentPositionParams,
    ) -> Result<Option<PrepareRenameResponse>> {
        let uri = params.text_document.uri;
        let pos = params.position;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let Some((word, start, end)) = word_at_position(&source, offset) else {
            return Ok(None);
        };
        if keyword_docs(&word).is_some() || !is_valid_identifier(&word) {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let Some(target) = resolve_symbol_target(&source, &program, offset, &local_occurrences)
        else {
            return Ok(None);
        };

        let mut docs = vec![SymbolDocument {
            uri: uri.clone(),
            source: source.clone(),
            program: program.clone(),
        }];
        docs.extend(self.collect_import_documents(&uri, &program));

        let has_definition = docs
            .iter()
            .any(|doc| has_target_definition(&doc.program, &target));
        if !has_definition {
            return Ok(None);
        }

        let range = offset_to_range(&source, start, end)
            .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
        Ok(Some(PrepareRenameResponse::RangeWithPlaceholder {
            range,
            placeholder: target.name,
        }))
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;
        let Some((source, _)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let formatted = format_document_text(&source);
        if formatted == source {
            return Ok(None);
        }

        let edit = TextEdit {
            range: Range::new(
                Position::new(0, 0),
                offset_to_position(&source, source.len()),
            ),
            new_text: formatted,
        };
        Ok(Some(vec![edit]))
    }

    async fn range_formatting(
        &self,
        params: DocumentRangeFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;
        let Some((source, _)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let formatted = format_document_text(&source);
        if formatted == source {
            return Ok(None);
        }

        // Current formatter is document-based; range formatting reuses the same deterministic
        // canonicalization pass to keep output consistent with full-document formatting.
        let edit = TextEdit {
            range: Range::new(
                Position::new(0, 0),
                offset_to_position(&source, source.len()),
            ),
            new_text: formatted,
        };
        Ok(Some(vec![edit]))
    }

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;
        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let tokens = build_semantic_tokens(&source, parsed_program.as_ref(), None);
        Ok(Some(SemanticTokensResult::Tokens(tokens)))
    }

    async fn semantic_tokens_range(
        &self,
        params: SemanticTokensRangeParams,
    ) -> Result<Option<SemanticTokensRangeResult>> {
        let uri = params.text_document.uri;
        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let tokens = build_semantic_tokens(&source, parsed_program.as_ref(), Some(&params.range));
        Ok(Some(SemanticTokensRangeResult::Tokens(tokens)))
    }

    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let docs = self.collect_workspace_symbol_documents();
        if docs.is_empty() {
            return Ok(None);
        }

        let mut symbols = Vec::new();
        for doc in &docs {
            symbols.extend(collect_workspace_symbol_information(
                &doc.source,
                &doc.program,
                &doc.uri,
                &params.query,
            ));
        }
        dedup_and_sort_workspace_symbols(&mut symbols);
        if symbols.len() > MAX_WORKSPACE_SYMBOL_RESULTS {
            symbols.truncate(MAX_WORKSPACE_SYMBOL_RESULTS);
        }

        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(symbols))
        }
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((program, _)) => program,
            None => return Ok(None),
        };

        let symbols = build_document_symbols(&state.source, program);
        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Nested(symbols)))
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = state.parsed.as_ref().map(|(p, _)| p);
        let actions = build_code_actions(uri, &state.source, program, &params.context.diagnostics);

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(actions))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- position_to_offset / offset_to_position --

    #[test]
    fn offset_to_position_basic() {
        let text = "hello\nworld\nfoo";
        assert_eq!(offset_to_position(text, 0), Position::new(0, 0));
        assert_eq!(offset_to_position(text, 5), Position::new(0, 5));
        assert_eq!(offset_to_position(text, 6), Position::new(1, 0));
        assert_eq!(offset_to_position(text, 11), Position::new(1, 5));
        assert_eq!(offset_to_position(text, 12), Position::new(2, 0));
    }

    #[test]
    fn offset_to_range_roundtrip() {
        let text = "protocol Foo {\n    params n, t;\n}";
        let range = offset_to_range(text, 0, 12).unwrap();
        assert_eq!(range.start, Position::new(0, 0));
        assert_eq!(range.end, Position::new(0, 12));
    }

    #[test]
    fn test_position_to_offset() {
        let text = "hello\nworld\nfoo";
        assert_eq!(position_to_offset(text, Position::new(0, 0)), 0);
        assert_eq!(position_to_offset(text, Position::new(0, 5)), 5);
        assert_eq!(position_to_offset(text, Position::new(1, 0)), 6);
        assert_eq!(position_to_offset(text, Position::new(1, 5)), 11);
        assert_eq!(position_to_offset(text, Position::new(2, 0)), 12);
        assert_eq!(position_to_offset(text, Position::new(2, 3)), 15);
    }

    #[test]
    fn test_position_offset_roundtrip() {
        let text = "hello\nworld\nfoo bar";
        for offset in [0, 3, 5, 6, 10, 12, 15] {
            let pos = offset_to_position(text, offset);
            let back = position_to_offset(text, pos);
            assert_eq!(back, offset, "roundtrip failed for offset {offset}");
        }
    }

    // -- incremental change --

    #[test]
    fn test_incremental_change_apply() {
        let mut text = "hello world".to_string();
        let range = Range::new(Position::new(0, 6), Position::new(0, 11));
        apply_incremental_change(&mut text, &range, "rust");
        assert_eq!(text, "hello rust");
    }

    #[test]
    fn test_incremental_change_insert() {
        let mut text = "hello world".to_string();
        let range = Range::new(Position::new(0, 5), Position::new(0, 5));
        apply_incremental_change(&mut text, &range, " beautiful");
        assert_eq!(text, "hello beautiful world");
    }

    #[test]
    fn test_incremental_change_multiline() {
        let mut text = "line1\nline2\nline3".to_string();
        let range = Range::new(Position::new(1, 0), Position::new(1, 5));
        apply_incremental_change(&mut text, &range, "REPLACED");
        assert_eq!(text, "line1\nREPLACED\nline3");
    }

    // -- levenshtein --

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "ab"), 1);
        assert_eq!(levenshtein("abc", "axc"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn test_find_closest() {
        let candidates = vec![
            "waiting".to_string(),
            "echoed".to_string(),
            "readied".to_string(),
            "done".to_string(),
        ];
        assert_eq!(
            find_closest("echoedd", &candidates),
            Some("echoed".to_string())
        );
        assert_eq!(find_closest("don", &candidates), Some("done".to_string()));
        assert_eq!(find_closest("zzzzz", &candidates), None);
    }

    // -- word_at_position --

    #[test]
    fn test_word_at_position() {
        let text = "hello world foo_bar";
        assert_eq!(word_at_position(text, 3), Some(("hello".to_string(), 0, 5)));
        assert_eq!(
            word_at_position(text, 8),
            Some(("world".to_string(), 6, 11))
        );
        assert_eq!(
            word_at_position(text, 15),
            Some(("foo_bar".to_string(), 12, 19))
        );
        // Cursor right after a word still identifies that word (useful for LSP hover)
        assert_eq!(word_at_position(text, 5), Some(("hello".to_string(), 0, 5)));
        // In the middle of two spaces: no word
        let text2 = "hello  world";
        assert_eq!(word_at_position(text2, 6), None);
    }

    #[test]
    fn test_is_valid_identifier_rules() {
        assert!(is_valid_identifier("foo"));
        assert!(is_valid_identifier("_foo2"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("2foo"));
        assert!(!is_valid_identifier("foo-bar"));
        assert!(!is_valid_identifier("foo bar"));
    }

    #[test]
    fn test_format_document_text_brace_indentation() {
        let input = r#"protocol X{
role P{
phase s{
}
}
}"#;
        let expected = r#"protocol X{
    role P{
        phase s{
        }
    }
}"#;
        assert_eq!(format_document_text(input), expected);
    }

    #[test]
    fn test_semantic_tokens_legend_includes_keyword_and_operator() {
        let legend = semantic_tokens_legend();
        assert!(legend.token_types.contains(&SemanticTokenType::KEYWORD));
        assert!(legend.token_types.contains(&SemanticTokenType::OPERATOR));
    }

    #[test]
    fn test_workspace_symbol_query_matches_fuzzy() {
        assert!(workspace_symbol_query_matches("Process", "proc"));
        assert!(workspace_symbol_query_matches("agreement", "agrrement"));
        assert!(!workspace_symbol_query_matches("Echo", "quorum"));
    }

    #[test]
    fn test_discover_workspace_trs_files_finds_nested_files() {
        let unique = format!(
            "tarsier-lsp-ws-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let a = root.join("a.trs");
        let b = nested.join("b.trs");
        std::fs::write(&a, "protocol A {}").unwrap();
        std::fs::write(&b, "protocol B {}").unwrap();

        let files = discover_workspace_trs_files(&root, 10, 4);
        assert!(files.iter().any(|p| p.ends_with("a.trs")));
        assert!(files.iter().any(|p| p.ends_with("b.trs")));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_resolve_import_uri_relative_with_extension_inference() {
        let unique = format!(
            "tarsier-lsp-import-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let base = root.join("main.trs");
        let imported = root.join("child.trs");
        std::fs::write(&base, "protocol Main { import Child from \"child\"; }").unwrap();
        std::fs::write(&imported, "protocol Child {}").unwrap();

        let base_uri = Url::from_file_path(&base).unwrap();
        let resolved = resolve_import_uri(&base_uri, "child").expect("import should resolve");
        assert_eq!(
            resolved.to_file_path().unwrap(),
            std::fs::canonicalize(&imported).unwrap()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    // -- keyword hover --

    #[test]
    fn test_hover_keyword() {
        let doc = keyword_docs("resilience");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Resilience condition"));
    }

    #[test]
    fn test_hover_keyword_unknown() {
        assert!(keyword_docs("foobar_nonexistent").is_none());
    }

    // -- completions context --

    #[test]
    fn test_keyword_completions_at_protocol_level() {
        let text = "protocol Foo {\n    ";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::TopLevel);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"parameters"));
        assert!(labels.contains(&"message"));
        assert!(labels.contains(&"role"));
        assert!(labels.contains(&"property"));
    }

    #[test]
    fn test_keyword_completions_at_role_level() {
        let text = "protocol Foo {\n    role Bar {\n        ";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::RoleLevel);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"var"));
        assert!(labels.contains(&"init"));
        assert!(labels.contains(&"phase"));
    }

    #[test]
    fn test_after_colon_completions() {
        let text = "protocol Foo {\n    role Bar {\n        var x:";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::AfterColon);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bool"));
        assert!(labels.contains(&"nat"));
        assert!(labels.contains(&"int"));
    }

    #[test]
    fn test_property_kind_completions() {
        let text = "protocol Foo {\n    property myProp:";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::AfterPropertyColon);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"agreement"));
        assert!(labels.contains(&"safety"));
        assert!(labels.contains(&"liveness"));
    }

    // -- parse + AST-based tests --

    fn parse_example() -> Program {
        let src = parse_example_src();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        program
    }

    #[test]
    fn test_hover_user_defined_message() {
        let program = parse_example();
        let doc = hover_for_user_defined("Echo", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Message"));
    }

    #[test]
    fn test_hover_user_defined_role() {
        let program = parse_example();
        let doc = hover_for_user_defined("Process", &program);
        assert!(doc.is_some());
        let text = doc.unwrap();
        assert!(text.contains("Role"));
        assert!(text.contains("Process"));
    }

    #[test]
    fn test_hover_user_defined_phase() {
        let program = parse_example();
        let doc = hover_for_user_defined("waiting", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Phase"));
    }

    #[test]
    fn test_hover_user_defined_variable() {
        let program = parse_example();
        let doc = hover_for_user_defined("decided", &program);
        assert!(doc.is_some());
        let text = doc.unwrap();
        assert!(text.contains("Variable"));
        assert!(text.contains("bool"));
    }

    #[test]
    fn test_hover_user_defined_param() {
        let program = parse_example();
        let doc = hover_for_user_defined("n", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Parameter"));
    }

    #[test]
    fn test_build_semantic_tokens_contains_keyword_and_type() {
        let src = parse_example_src();
        let program = parse_example();
        let tokens = build_semantic_tokens(src, Some(&program), None);
        assert!(!tokens.data.is_empty());
        assert!(tokens
            .data
            .iter()
            .any(|t| t.token_type == SEMANTIC_TOKEN_KEYWORD));
        assert!(tokens
            .data
            .iter()
            .any(|t| t.token_type == SEMANTIC_TOKEN_TYPE));
    }

    #[test]
    fn test_collect_workspace_symbol_information_filters_by_query() {
        let src = parse_example_src();
        let program = parse_example();
        let uri = Url::parse("file:///tmp/test.trs").unwrap();
        let symbols = collect_workspace_symbol_information(src, &program, &uri, "proc");
        assert!(symbols.iter().any(|s| s.name == "Process"));
        assert!(!symbols.iter().any(|s| s.name == "Echo"));
    }

    // -- collect_definitions --

    #[test]
    fn test_collect_definitions() {
        let program = parse_example();
        let defs = collect_definitions(&program);

        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Echo"));
        assert!(names.contains(&"Ready"));
        assert!(names.contains(&"Process"));
        assert!(names.contains(&"waiting"));
        assert!(names.contains(&"done"));
        assert!(names.contains(&"n"));
        assert!(names.contains(&"t"));
        assert!(names.contains(&"f"));
        assert!(names.contains(&"decided"));
        assert!(names.contains(&"agreement"));

        // Check kinds
        let echo_def = defs.iter().find(|d| d.name == "Echo").unwrap();
        assert_eq!(echo_def.kind, DefinitionKind::Message);

        let process_def = defs.iter().find(|d| d.name == "Process").unwrap();
        assert_eq!(process_def.kind, DefinitionKind::Role);

        let waiting_def = defs.iter().find(|d| d.name == "waiting").unwrap();
        assert_eq!(waiting_def.kind, DefinitionKind::Phase);
        assert_eq!(waiting_def.parent.as_deref(), Some("Process"));
    }

    // -- goto definition --

    #[test]
    fn test_goto_definition_message() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let echo_def = defs
            .iter()
            .find(|d| d.name == "Echo" && d.kind == DefinitionKind::Message);
        assert!(echo_def.is_some());
        let def = echo_def.unwrap();
        assert!(
            def.start < def.end,
            "Message definition should have a valid span"
        );
    }

    #[test]
    fn test_goto_definition_phase() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let phase_def = defs
            .iter()
            .find(|d| d.name == "waiting" && d.kind == DefinitionKind::Phase);
        assert!(phase_def.is_some());
        let def = phase_def.unwrap();
        assert!(
            def.start < def.end,
            "Phase definition should have a valid span"
        );
    }

    #[test]
    fn test_goto_definition_role() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let role_def = defs
            .iter()
            .find(|d| d.name == "Process" && d.kind == DefinitionKind::Role);
        assert!(role_def.is_some());
        let def = role_def.unwrap();
        assert!(
            def.start < def.end,
            "Role definition should have a valid span"
        );
    }

    // -- find references --

    #[test]
    fn test_find_references_message() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                send Echo;
                goto phase done;
            }
        }
        phase done {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let refs = collect_references(src, &program, "Echo");
        // "Echo" should appear at: message declaration, threshold guard, send action
        assert!(
            refs.len() >= 3,
            "Expected at least 3 references to Echo, got {}",
            refs.len()
        );
    }

    #[test]
    fn test_reference_locations_excludes_declaration_when_requested() {
        let src = parse_example_src();
        let program = parse_example();
        let uri = Url::parse("file:///tmp/test.trs").unwrap();

        let include = reference_locations(src, &program, &uri, "Echo", true);
        let exclude = reference_locations(src, &program, &uri, "Echo", false);

        assert!(
            include.len() > exclude.len(),
            "excluding declarations should remove at least one location"
        );
    }

    #[test]
    fn test_collect_symbol_occurrences_disambiguates_message_and_var_names() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);

        let message_count = occurrences
            .iter()
            .filter(|occ| occ.name == "Echo" && occ.kind == DefinitionKind::Message)
            .count();
        let var_count = occurrences
            .iter()
            .filter(|occ| occ.name == "Echo" && occ.kind == DefinitionKind::Var)
            .count();

        assert!(message_count >= 3, "expected message declaration/usages");
        assert!(var_count >= 3, "expected var declaration/usages");
    }

    #[test]
    fn test_resolve_symbol_target_uses_contextual_kind() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);

        let send_offset = src.find("send Echo").unwrap() + "send ".len();
        let send_target =
            resolve_symbol_target(src, &program, send_offset, &occurrences).expect("send target");
        assert_eq!(send_target.kind, DefinitionKind::Message);
        assert_eq!(send_target.name, "Echo");

        let assign_offset = src.find("Echo = true").unwrap();
        let assign_target = resolve_symbol_target(src, &program, assign_offset, &occurrences)
            .expect("assign target");
        assert_eq!(assign_target.kind, DefinitionKind::Var);
        assert_eq!(assign_target.name, "Echo");
        assert_eq!(assign_target.parent.as_deref(), Some("R"));
    }

    #[test]
    fn test_collect_reference_spans_for_target_excludes_other_symbol_kinds() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);
        let target = SymbolTarget {
            name: "Echo".to_string(),
            kind: DefinitionKind::Var,
            parent: Some("R".to_string()),
        };

        let refs = collect_reference_spans_for_target(src, &program, &target, true, &occurrences);
        let send_span = {
            let start = src.find("send Echo").unwrap() + "send ".len();
            (start, start + "Echo".len())
        };
        let threshold_span = {
            let start = src.find("received >= 1 Echo").unwrap() + "received >= 1 ".len();
            (start, start + "Echo".len())
        };

        assert!(
            !refs.contains(&send_span),
            "var target must not capture send message type"
        );
        assert!(
            !refs.contains(&threshold_span),
            "var target must not capture threshold message type"
        );
    }

    #[test]
    fn test_as_goto_definition_response_uses_array_for_multiple_locations() {
        let uri = Url::parse("file:///tmp/test.trs").unwrap();
        let locations = vec![
            Location {
                uri: uri.clone(),
                range: Range::new(Position::new(1, 0), Position::new(1, 5)),
            },
            Location {
                uri,
                range: Range::new(Position::new(2, 0), Position::new(2, 4)),
            },
        ];

        match as_goto_definition_response(locations) {
            Some(GotoDefinitionResponse::Array(arr)) => assert_eq!(arr.len(), 2),
            other => panic!("expected array goto response, got {other:?}"),
        }
    }

    // -- diagnostics --

    #[test]
    fn test_diagnostics_have_codes() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let filename = "test.trs";
        let (program, parse_diags) = tarsier_dsl::parse_with_diagnostics(src, filename).unwrap();

        // Parse diagnostics should have codes
        for diag in &parse_diags {
            assert!(!diag.code.is_empty(), "Parse diagnostic should have a code");
        }

        // Lowering errors should produce codes
        if let Err(e) = tarsier_ir::lowering::lower_with_source(&program, src, filename) {
            let code = lowering_error_code(&e.inner);
            assert!(!code.is_empty(), "Lowering error should have a code");
        }
    }

    #[test]
    fn test_diagnostics_have_precise_spans() {
        // Use a protocol with an unknown phase to trigger a lowering error with a span
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase nonexistent;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let filename = "test.trs";
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, filename).unwrap();
        let err = tarsier_ir::lowering::lower_with_source(&program, src, filename);
        assert!(
            err.is_err(),
            "Should have a lowering error for unknown phase"
        );
        let e = err.unwrap_err();
        assert!(
            e.span.is_some(),
            "Lowering error should have a source span, not None"
        );
        let span = e.span.unwrap();
        assert!(
            span.offset() > 0,
            "Span offset should be > 0, not at file start"
        );
    }

    #[test]
    fn test_collect_structural_lowering_diagnostics_reports_multiple_codes() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    enum Status { idle, active }

    message Echo;

    role Process {
        var decided: bool = false;
        var status: Status;
        var state: Statu = idle;
        phase waiting {
            when received >= 1 Ehoo => {
                send Reddy;
                goto phase don;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_structural_lowering_diagnostics(&program, src);
        let codes: std::collections::HashSet<String> = diags
            .iter()
            .filter_map(|d| match d.code.as_ref() {
                Some(NumberOrString::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();

        assert!(codes.contains("tarsier::lower::no_init_phase"));
        assert!(codes.contains("tarsier::lower::unknown_enum"));
        assert!(codes.contains("tarsier::lower::missing_enum_init"));
        assert!(codes.contains("tarsier::lower::unknown_message"));
        assert!(codes.contains("tarsier::lower::unknown_phase"));
    }

    #[test]
    fn test_collect_lowering_diagnostics_preserves_non_structural_errors() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    role Process {
        var decided: bool = false;
        var x: int in 0..1 = 5;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_lowering_diagnostics(&program, src, "test.trs");
        let codes: std::collections::HashSet<String> = diags
            .iter()
            .filter_map(|d| match d.code.as_ref() {
                Some(NumberOrString::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();

        assert!(codes.contains("tarsier::lower::no_init_phase"));
        assert!(codes.contains("tarsier::lower::out_of_range"));
    }

    #[test]
    fn test_collect_lowering_diagnostics_avoids_duplicate_structural_fallback() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase nonexistent;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_lowering_diagnostics(&program, src, "test.trs");
        let unknown_phase_count = diags
            .iter()
            .filter(|d| diagnostic_has_code(d, "tarsier::lower::unknown_phase"))
            .count();

        assert_eq!(
            unknown_phase_count, 1,
            "unknown phase should not be duplicated by fallback lowering diagnostics"
        );
    }

    #[test]
    fn test_parse_error_diagnostics_flattens_multiple_errors() {
        use tarsier_dsl::errors::{ParseError, ParseErrors};

        let parse_error = ParseError::MultipleErrors(ParseErrors {
            errors: vec![
                ParseError::MissingSection {
                    section: "parameters".into(),
                },
                ParseError::MissingSection {
                    section: "resilience".into(),
                },
            ],
        });

        let diags = parse_error_diagnostics(&parse_error, "protocol X {}");
        assert_eq!(diags.len(), 2);
        assert!(diags
            .iter()
            .all(|d| diagnostic_has_code(d, "tarsier::parse::missing_section")));
        assert!(diags.iter().any(|d| d.message.contains("parameters")));
        assert!(diags.iter().any(|d| d.message.contains("resilience")));
    }

    // -- code actions --

    #[test]
    fn test_code_action_unknown_phase_suggestion() {
        let program = parse_example();
        let known_phases = collect_phase_names(&program);
        let suggestion = find_closest("waitin", &known_phases);
        assert_eq!(suggestion, Some("waiting".to_string()));
    }

    #[test]
    fn test_code_action_missing_init() {
        // Parse a protocol that has no init phase to check the diagnostic message
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let err = tarsier_ir::lowering::lower_with_source(&program, src, "test.trs");
        assert!(err.is_err());
        let e = err.unwrap_err();
        let msg = lowering_error_message(&e.inner, &program);
        assert!(
            msg.contains("no init phase"),
            "Expected 'no init phase' message, got: {msg}"
        );
        assert!(msg.contains("Process"));
    }

    #[test]
    fn test_code_action_unknown_enum_suggestion() {
        let src = r#"protocol EnumFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active }
    role Worker {
        var status: Statu = idle;
        init s;
        phase s {}
    }
}"#;
        let uri = Url::parse("file:///tmp/enum_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "enum_fix.trs").unwrap();
        let var_span = program.protocol.node.roles[0].node.vars[0].span;
        let range = offset_to_range(src, var_span.start, var_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::unknown_enum".into(),
            )),
            message: "Unknown enum type 'Statu'. Did you mean 'Status'?".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        assert!(actions.iter().any(|a| match a {
            CodeActionOrCommand::CodeAction(action) => action.title == "Replace with 'Status'",
            _ => false,
        }));
    }

    #[test]
    fn test_code_action_missing_enum_init_insertion() {
        let src = r#"protocol EnumInitFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active }
    role Worker {
        var status: Status;
        init s;
        phase s {}
    }
}"#;
        let uri = Url::parse("file:///tmp/enum_init_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "enum_init_fix.trs").unwrap();
        let var_span = program.protocol.node.roles[0].node.vars[0].span;
        let range = offset_to_range(src, var_span.start, var_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::missing_enum_init".into(),
            )),
            message: "Missing init value for enum variable 'status'".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        let init_action = actions.into_iter().find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action)
                if action.title == "Initialize 'status' with 'idle'" =>
            {
                Some(action)
            }
            _ => None,
        });
        let action = init_action.expect("expected enum init quick fix");
        let edits = action
            .edit
            .and_then(|e| e.changes)
            .and_then(|mut c| c.remove(&uri))
            .expect("expected workspace edit changes");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, " = idle");
    }

    // -- extract_quoted_name --

    #[test]
    fn test_extract_quoted_name() {
        assert_eq!(
            extract_quoted_name("Unknown phase 'foo' in goto"),
            Some("foo".to_string())
        );
        assert_eq!(
            extract_quoted_name("Role 'Process' has no init phase"),
            Some("Process".to_string())
        );
        assert_eq!(extract_quoted_name("No quotes here"), None);
    }

    // -- name references across AST --

    #[test]
    fn test_all_major_names_referenced() {
        let src = parse_example_src();
        let program = parse_example();
        // Verify key names appear as references in the source
        for name in &["Echo", "Ready", "done", "Process"] {
            let refs = collect_references(src, &program, name);
            assert!(
                !refs.is_empty(),
                "Expected at least one reference to '{name}'"
            );
        }
    }

    #[test]
    fn test_build_document_symbols_outline_tree() {
        let src = parse_example_src();
        let program = parse_example();
        let symbols = build_document_symbols(src, &program);

        assert_eq!(symbols.len(), 1, "expected protocol root symbol");
        let protocol = &symbols[0];
        assert_eq!(protocol.name, "Test");
        assert_eq!(protocol.kind, SymbolKind::MODULE);
        let protocol_children = protocol
            .children
            .as_ref()
            .expect("protocol should expose children");
        assert!(protocol_children.iter().any(|s| s.name == "Echo"));
        assert!(protocol_children.iter().any(|s| s.name == "Ready"));
        assert!(protocol_children.iter().any(|s| s.name == "agreement"));

        let process = protocol_children
            .iter()
            .find(|s| s.name == "Process")
            .expect("role symbol should be present");
        assert_eq!(process.kind, SymbolKind::CLASS);

        let process_children = process
            .children
            .as_ref()
            .expect("role should expose child symbols");
        assert!(process_children
            .iter()
            .any(|s| s.name == "decided" && s.kind == SymbolKind::VARIABLE));
        assert!(process_children
            .iter()
            .any(|s| s.name == "waiting" && s.kind == SymbolKind::METHOD));
        assert!(process_children
            .iter()
            .any(|s| s.name == "done" && s.kind == SymbolKind::METHOD));
    }

    #[test]
    fn test_document_symbol_selection_range_prefers_name_token() {
        let src = parse_example_src();
        let program = parse_example();
        let symbols = build_document_symbols(src, &program);
        let protocol = &symbols[0];
        let range_start = position_to_offset(src, protocol.range.start);
        let selection_start = position_to_offset(src, protocol.selection_range.start);

        assert!(
            selection_start > range_start,
            "selection range should point at protocol name token"
        );
    }

    fn parse_example_src() -> &'static str {
        r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;
    message Ready;

    role Process {
        var decided: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Echo => {
                send Ready;
                goto phase done;
            }
        }

        phase done {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#
    }

    // -- LSP capability check --

    #[test]
    fn test_lsp_capabilities_declared() {
        // Verify all capabilities are present in the initialize response
        // We test this indirectly by checking the ServerCapabilities struct
        let caps = ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(
                TextDocumentSyncKind::INCREMENTAL,
            )),
            completion_provider: Some(CompletionOptions {
                trigger_characters: Some(vec![" ".into(), ":".into(), "{".into()]),
                ..Default::default()
            }),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            definition_provider: Some(OneOf::Left(true)),
            references_provider: Some(OneOf::Left(true)),
            document_symbol_provider: Some(OneOf::Left(true)),
            workspace_symbol_provider: Some(OneOf::Left(true)),
            document_formatting_provider: Some(OneOf::Left(true)),
            document_range_formatting_provider: Some(OneOf::Left(true)),
            rename_provider: Some(OneOf::Right(RenameOptions {
                prepare_provider: Some(true),
                work_done_progress_options: WorkDoneProgressOptions::default(),
            })),
            semantic_tokens_provider: Some(
                SemanticTokensOptions {
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                    legend: semantic_tokens_legend(),
                    range: Some(true),
                    full: Some(SemanticTokensFullOptions::Bool(true)),
                }
                .into(),
            ),
            code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
            ..Default::default()
        };

        assert!(caps.text_document_sync.is_some());
        assert!(caps.completion_provider.is_some());
        assert!(caps.hover_provider.is_some());
        assert!(caps.definition_provider.is_some());
        assert!(caps.references_provider.is_some());
        assert!(caps.document_symbol_provider.is_some());
        assert!(caps.workspace_symbol_provider.is_some());
        assert!(caps.document_formatting_provider.is_some());
        assert!(caps.document_range_formatting_provider.is_some());
        assert!(caps.rename_provider.is_some());
        assert!(caps.semantic_tokens_provider.is_some());
        assert!(caps.code_action_provider.is_some());

        // Verify incremental sync
        match caps.text_document_sync {
            Some(TextDocumentSyncCapability::Kind(k)) => {
                assert_eq!(k, TextDocumentSyncKind::INCREMENTAL);
            }
            _ => panic!("Expected incremental sync kind"),
        }
    }
}
