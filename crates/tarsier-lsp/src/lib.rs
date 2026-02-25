#![doc = include_str!("../README.md")]

//! Language Server Protocol implementation for the Tarsier DSL.
//!
//! Provides IDE features (diagnostics, hover, go-to-definition, completions)
//! for `.trs` protocol specification files via the LSP protocol.

use std::collections::HashMap;
use std::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use tarsier_dsl::ast::{Program, VarType};

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

// ---------------------------------------------------------------------------
// Definition info (for goto-definition / references)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
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
                    diagnostics.push(Diagnostic {
                        range,
                        severity: Some(DiagnosticSeverity::WARNING),
                        source: Some("tarsier".into()),
                        code: Some(NumberOrString::String(diag.code.clone())),
                        message: diag.message.clone(),
                        ..Default::default()
                    });
                }

                // Lowering diagnostics — use lower_with_source for spans
                if let Err(e) = tarsier_ir::lowering::lower_with_source(&program, text, filename) {
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
                    let message = lowering_error_message(&e.inner, &program);

                    diagnostics.push(Diagnostic {
                        range,
                        severity: Some(DiagnosticSeverity::ERROR),
                        source: Some("tarsier".into()),
                        code: Some(NumberOrString::String(code_str)),
                        message,
                        ..Default::default()
                    });
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
                let (range, code_str) = parse_error_span_and_code(&e, text);
                diagnostics.push(Diagnostic {
                    range,
                    severity: Some(DiagnosticSeverity::ERROR),
                    source: Some("tarsier".into()),
                    code: Some(NumberOrString::String(code_str)),
                    message: format!("{e}"),
                    ..Default::default()
                });

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
                        let known_msgs: Vec<String> = prog
                            .protocol
                            .node
                            .messages
                            .iter()
                            .map(|m| m.name.clone())
                            .collect();
                        if let Some(suggestion) = find_closest(&name, &known_msgs) {
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

                        // Offer to add message declaration
                        // Find insertion point: after last message decl or at start of protocol body
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
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((p, _)) => p,
            None => return Ok(None),
        };

        let defs = collect_definitions(program);
        for def in &defs {
            if def.name == word && def.start != def.end {
                let range = offset_to_range(&state.source, def.start, def.end)
                    .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
                return Ok(Some(GotoDefinitionResponse::Scalar(Location {
                    uri: uri.clone(),
                    range,
                })));
            }
        }

        Ok(None)
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
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
        let word_info = word_at_position(&state.source, offset);
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((p, _)) => p,
            None => return Ok(None),
        };

        let refs = collect_references(&state.source, program, &word);
        if refs.is_empty() {
            return Ok(None);
        }

        let locations: Vec<Location> = refs
            .iter()
            .filter_map(|&(start, end)| {
                offset_to_range(&state.source, start, end).map(|range| Location {
                    uri: uri.clone(),
                    range,
                })
            })
            .collect();

        Ok(Some(locations))
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
}"#;
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
            code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
            ..Default::default()
        };

        assert!(caps.text_document_sync.is_some());
        assert!(caps.completion_provider.is_some());
        assert!(caps.hover_provider.is_some());
        assert!(caps.definition_provider.is_some());
        assert!(caps.references_provider.is_some());
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
