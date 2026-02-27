use std::collections::HashMap;
use tower_lsp::lsp_types::*;

use crate::utils::{is_ident_char, offset_to_position, offset_to_range, position_to_offset};

use tarsier_dsl::ast::{Program, VarType};

// ---------------------------------------------------------------------------
// Levenshtein distance
// ---------------------------------------------------------------------------

pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
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

pub(crate) fn find_closest(name: &str, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .filter(|c| levenshtein(name, c) <= 2)
        .min_by_key(|c| levenshtein(name, c))
        .cloned()
}

pub(crate) fn collect_phase_names(program: &Program) -> Vec<String> {
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

pub(crate) fn build_document_symbols(source: &str, program: &Program) -> Vec<DocumentSymbol> {
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

pub(crate) fn build_code_actions(
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
            Some("tarsier::lower::unknown_enum_variant") => {
                if let Some(prog) = program {
                    let variant_name = extract_quoted_name(&diag.message);
                    let enum_name = extract_second_quoted_name(&diag.message);
                    if let (Some(vname), Some(ename)) = (variant_name, enum_name) {
                        // Find the enum and collect its variants
                        let known_variants: Vec<String> = prog
                            .protocol
                            .node
                            .enums
                            .iter()
                            .find(|e| e.name == ename)
                            .map(|e| e.variants.clone())
                            .unwrap_or_default();
                        if let Some(suggestion) = find_closest(&vname, &known_variants) {
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: diag.range,
                                    new_text: source[position_to_offset(source, diag.range.start)
                                        ..position_to_offset(source, diag.range.end)]
                                        .replace(&vname, &suggestion),
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
            Some("tarsier::lower::unknown_param") => {
                if let Some(prog) = program {
                    let unknown_name = extract_quoted_name(&diag.message);
                    if let Some(name) = unknown_name {
                        let known_params: Vec<String> = prog
                            .protocol
                            .node
                            .parameters
                            .iter()
                            .map(|p| p.name.clone())
                            .collect();
                        if let Some(suggestion) = find_closest(&name, &known_params) {
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
            Some("tarsier::lower::out_of_range") => {
                // Message format: "Out of range for variable 'x': 5 not in [0, 3]"
                if let Some((value, min, max)) = parse_out_of_range_message(&diag.message) {
                    let clamped = if value < min { min } else { max };
                    // Find the init value literal in the source within the diagnostic range.
                    let diag_start = position_to_offset(source, diag.range.start);
                    let diag_end = position_to_offset(source, diag.range.end);
                    let diag_text = &source[diag_start..diag_end];
                    let value_str = value.to_string();
                    // Look for `= <value>` pattern and replace the value portion.
                    if let Some(eq_pos) = diag_text.rfind('=') {
                        let after_eq = &diag_text[eq_pos + 1..];
                        if let Some(val_rel) = after_eq.find(&value_str) {
                            let val_abs_start = diag_start + eq_pos + 1 + val_rel;
                            let val_abs_end = val_abs_start + value_str.len();
                            let val_range = Range::new(
                                offset_to_position(source, val_abs_start),
                                offset_to_position(source, val_abs_end),
                            );
                            let mut changes = HashMap::new();
                            changes.insert(
                                uri.clone(),
                                vec![TextEdit {
                                    range: val_range,
                                    new_text: clamped.to_string(),
                                }],
                            );
                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: format!("Clamp value to {clamped}"),
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
            _ => {}
        }
    }

    actions
}

/// Parse the `out_of_range` diagnostic message to extract `(value, min, max)`.
///
/// Expected format: `"Out of range for variable 'x': <value> not in [<min>, <max>]"`
fn parse_out_of_range_message(message: &str) -> Option<(i64, i64, i64)> {
    // Find the colon after the variable name, then parse "<value> not in [<min>, <max>]"
    let colon_idx = message.find(": ")?;
    let rest = &message[colon_idx + 2..]; // "<value> not in [<min>, <max>]"
    let not_idx = rest.find(" not in [")?;
    let value: i64 = rest[..not_idx].trim().parse().ok()?;
    let bracket_start = rest.find('[')?;
    let bracket_end = rest.find(']')?;
    let inner = &rest[bracket_start + 1..bracket_end]; // "<min>, <max>"
    let mut parts = inner.split(',');
    let min: i64 = parts.next()?.trim().parse().ok()?;
    let max: i64 = parts.next()?.trim().parse().ok()?;
    Some((value, min, max))
}

pub(crate) fn extract_quoted_name(message: &str) -> Option<String> {
    let start = message.find('\'')?;
    let rest = &message[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Extract the second single-quoted name from a diagnostic message.
///
/// For example, `"Unknown enum variant 'foo' for enum 'Status'"` returns `Some("Status")`.
pub(crate) fn extract_second_quoted_name(message: &str) -> Option<String> {
    let first_start = message.find('\'')?;
    let after_first = &message[first_start + 1..];
    let first_end = after_first.find('\'')?;
    let rest = &after_first[first_end + 1..];
    let second_start = rest.find('\'')?;
    let after_second = &rest[second_start + 1..];
    let second_end = after_second.find('\'')?;
    Some(after_second[..second_end].to_string())
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
