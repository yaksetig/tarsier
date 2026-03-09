//! Completion context inference and completion item generation.

use tarsier_dsl::ast::Program;
use tower_lsp::lsp_types::*;

use crate::hover::keyword_docs;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CursorContext {
    TopLevel,
    RoleLevel,
    PhaseLevel,
    ActionLevel,
    AfterColon,
    AfterPropertyColon,
    FormulaContext,
    Unknown,
}

pub(crate) fn infer_cursor_context(text: &str, offset: usize) -> CursorContext {
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

pub(crate) fn build_completions(
    context: &CursorContext,
    program: Option<&Program>,
) -> Vec<CompletionItem> {
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
