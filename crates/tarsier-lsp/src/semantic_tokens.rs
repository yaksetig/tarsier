use std::collections::HashMap;
use tower_lsp::lsp_types::*;

use crate::utils::{is_ident_char, offset_to_position};
use crate::{collect_definitions, DefinitionKind};

use tarsier_dsl::ast::Program;

pub(crate) const SEMANTIC_TOKEN_KEYWORD: u32 = 0;
pub(crate) const SEMANTIC_TOKEN_TYPE: u32 = 1;
pub(crate) const SEMANTIC_TOKEN_VARIABLE: u32 = 2;
pub(crate) const SEMANTIC_TOKEN_PROPERTY: u32 = 3;
pub(crate) const SEMANTIC_TOKEN_FUNCTION: u32 = 4;
pub(crate) const SEMANTIC_TOKEN_STRING: u32 = 5;
pub(crate) const SEMANTIC_TOKEN_NUMBER: u32 = 6;
pub(crate) const SEMANTIC_TOKEN_OPERATOR: u32 = 7;

pub(crate) fn semantic_tokens_legend() -> SemanticTokensLegend {
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
                if escaped {
                    escaped = false;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'\\' {
                    escaped = true;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            candidates.push(SemanticTokenCandidate {
                start,
                end: i,
                token_type: SEMANTIC_TOKEN_STRING,
            });
            continue;
        }

        // Numeric literals.
        if bytes[i].is_ascii_digit()
            || (bytes[i] == b'-'
                && i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_digit()
                && (i == 0 || !is_ident_char(bytes[i - 1])))
        {
            let start = i;
            if bytes[i] == b'-' {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // Floating-point: optional decimal part and exponent.
            if i < bytes.len()
                && bytes[i] == b'.'
                && i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_digit()
            {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
                i += 1;
                if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            candidates.push(SemanticTokenCandidate {
                start,
                end: i,
                token_type: SEMANTIC_TOKEN_NUMBER,
            });
            continue;
        }

        // Operators
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

        // Identifiers / keywords.
        if is_ident_start_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_ident_char(bytes[i]) {
                i += 1;
            }
            let word = &source[start..i];
            let token_type = match word {
                "protocol" | "role" | "phase" | "message" | "params" | "param" | "init" | "var"
                | "send" | "goto" | "decide" | "import" | "true" | "false" | "if" | "else"
                | "property" | "safety" | "liveness" | "bool" | "nat" | "int" | "forall"
                | "exists" | "resilience" | "quorum" | "certificate" | "adversary"
                | "pacemaker" | "enum" | "to" | "channel" | "identity" | "equivocation"
                | "module" | "assumes" | "guarantees" | "committee" | "sign" | "lock"
                | "justify" | "form" | "has" => SEMANTIC_TOKEN_KEYWORD,
                _ => {
                    if let Some(&def_type) = def_types.get(word) {
                        def_type
                    } else {
                        i = start + word.len();
                        continue;
                    }
                }
            };
            candidates.push(SemanticTokenCandidate {
                start,
                end: i,
                token_type,
            });
            continue;
        }

        i += 1;
    }

    candidates.sort_by_key(|c| (c.start, c.end));
    candidates
        .dedup_by(|a, b| a.start == b.start && a.end == b.end && a.token_type == b.token_type);
    candidates
}

pub(crate) fn build_semantic_tokens(
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
