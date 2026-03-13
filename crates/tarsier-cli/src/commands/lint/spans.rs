// Source span conversion helpers.

use tarsier_dsl::ast::Span as DslSpan;

use super::types::LintSourceSpan;

pub(crate) fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let clamped = offset.min(source.len());
    for (idx, ch) in source.char_indices() {
        if idx >= clamped {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

pub(crate) fn lint_source_span(source: &str, span: DslSpan) -> LintSourceSpan {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len()).max(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let (end_line, end_column) = byte_offset_to_line_col(source, end);
    LintSourceSpan {
        start,
        end,
        line,
        column,
        end_line,
        end_column,
    }
}

pub(crate) fn line_col_to_byte_offset(source: &str, line: usize, column: usize) -> usize {
    if line <= 1 && column <= 1 {
        return 0;
    }
    let mut cur_line = 1usize;
    let mut cur_col = 1usize;
    for (idx, ch) in source.char_indices() {
        if cur_line == line && cur_col == column {
            return idx;
        }
        if ch == '\n' {
            cur_line += 1;
            cur_col = 1;
        } else {
            cur_col += 1;
        }
    }
    source.len()
}

pub(crate) fn advance_one_char(source: &str, start: usize) -> usize {
    if start >= source.len() {
        return start;
    }
    let tail = &source[start..];
    let char_len = tail.chars().next().map(char::len_utf8).unwrap_or(1);
    (start + char_len).min(source.len())
}

pub(crate) fn infer_parse_error_span(source: &str, message: &str) -> Option<DslSpan> {
    let marker = "-->";
    if let Some(idx) = message.find(marker) {
        let tail = &message[idx + marker.len()..];
        let mut digits = String::new();
        let mut chars = tail.trim_start().chars().peekable();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(chars.next().unwrap_or_default());
        }
        if !digits.is_empty() && chars.peek() == Some(&':') {
            let _ = chars.next();
            let mut col_digits = String::new();
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                col_digits.push(chars.next().unwrap_or_default());
            }
            if let (Ok(line), Ok(column)) = (digits.parse::<usize>(), col_digits.parse::<usize>()) {
                let start = line_col_to_byte_offset(source, line.max(1), column.max(1));
                let end = advance_one_char(source, start);
                return Some(DslSpan { start, end });
            }
        }
    }
    if source.is_empty() {
        None
    } else {
        Some(DslSpan {
            start: 0,
            end: advance_one_char(source, 0),
        })
    }
}
