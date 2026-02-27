//! Document formatting and minimal-edit computation for the Tarsier LSP.

use similar::{Algorithm, TextDiff};
use tower_lsp::lsp_types::*;

pub(crate) fn count_leading_closing_braces(line: &str) -> i32 {
    line.chars()
        .take_while(|c| c.is_ascii_whitespace() || *c == '}')
        .filter(|c| *c == '}')
        .count() as i32
}

pub(crate) fn brace_counts_ignoring_strings_and_comments(line: &str) -> (i32, i32) {
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

pub(crate) fn format_document_text(source: &str) -> String {
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

/// Format only the lines within `[start_line, end_line]` (inclusive, 0-indexed),
/// returning `TextEdit`s for lines that differ from their formatted form.
///
/// The formatter's only inter-line state is the brace depth (indent level) and
/// whether the previous line was blank.  We compute this state by scanning all
/// lines before `start_line`, then format only the requested range.
pub(crate) fn format_range_text(source: &str, start_line: u32, end_line: u32) -> Vec<TextEdit> {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len() as u32;

    // Clamp to valid range.
    let start = start_line.min(total_lines);
    let end = end_line.min(total_lines.saturating_sub(1));
    if start > end {
        return Vec::new();
    }

    // Phase 1: Scan lines 0..start to compute initial formatter state.
    let mut indent = 0i32;
    let mut last_was_blank = false;
    for line in lines.iter().take(start as usize) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            last_was_blank = true;
            continue;
        }
        last_was_blank = false;

        let leading_closes = count_leading_closing_braces(trimmed);
        let current_indent = (indent - leading_closes).max(0);

        let (opens, closes) = brace_counts_ignoring_strings_and_comments(trimmed);
        let non_leading_closes = (closes - leading_closes).max(0);
        indent = (current_indent + opens - non_leading_closes).max(0);
    }

    // Phase 2: Format lines start..=end and collect edits.
    let mut edits = Vec::new();
    for line_idx in start..=end {
        let original = lines[line_idx as usize];
        let trimmed = original.trim();

        if trimmed.is_empty() {
            // Blank-line compression: if previous was already blank, the
            // formatter would suppress this line.  Emit a deletion edit.
            if last_was_blank {
                let line_end = if (line_idx as usize) + 1 < lines.len() || source.ends_with('\n') {
                    Position::new(line_idx + 1, 0)
                } else {
                    Position::new(line_idx, original.len() as u32)
                };
                edits.push(TextEdit {
                    range: Range::new(Position::new(line_idx, 0), line_end),
                    new_text: String::new(),
                });
            } else {
                last_was_blank = true;
            }
            continue;
        }
        last_was_blank = false;

        let leading_closes = count_leading_closing_braces(trimmed);
        let current_indent = (indent - leading_closes).max(0);

        // Build the formatted version of this line.
        let mut formatted_line = String::new();
        for _ in 0..current_indent {
            formatted_line.push_str("    ");
        }
        formatted_line.push_str(trimmed);

        // Emit an edit only if the line changed.
        if formatted_line != original {
            let line_end = if (line_idx as usize) + 1 < lines.len() || source.ends_with('\n') {
                Position::new(line_idx + 1, 0)
            } else {
                Position::new(line_idx, original.len() as u32)
            };
            edits.push(TextEdit {
                range: Range::new(Position::new(line_idx, 0), line_end),
                new_text: format!("{}\n", formatted_line),
            });
            // If this is the very last line and source doesn't end with newline,
            // strip the trailing newline from the replacement.
            if (line_idx as usize) + 1 >= lines.len() && !source.ends_with('\n') {
                if let Some(edit) = edits.last_mut() {
                    edit.new_text = formatted_line;
                }
            }
        }

        // Advance the indent state.
        let (opens, closes) = brace_counts_ignoring_strings_and_comments(trimmed);
        let non_leading_closes = (closes - leading_closes).max(0);
        indent = (current_indent + opens - non_leading_closes).max(0);
    }

    edits
}

/// Check whether two LSP ranges have a non-empty intersection.
#[cfg(test)]
pub(crate) fn ranges_overlap(a: &Range, b: &Range) -> bool {
    // Two ranges overlap iff neither is entirely before the other.
    let a_before_b = a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character <= b.start.character);
    let b_before_a = b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character <= a.start.character);
    !a_before_b && !b_before_a
}

/// Compute minimal line-granularity `TextEdit`s that transform `source` into `formatted`.
pub(crate) fn compute_minimal_edits(source: &str, formatted: &str) -> Vec<TextEdit> {
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Patience)
        .diff_lines(source, formatted);

    let source_lines: Vec<&str> = source.lines().collect();

    let line_start_col = |line_idx: usize| -> Position { Position::new(line_idx as u32, 0) };
    let line_end_col = |line_idx: usize| -> Position {
        if line_idx < source_lines.len() {
            let len = source_lines[line_idx].len() as u32;
            // Include the newline if it exists
            if line_idx + 1 < source_lines.len() || source.ends_with('\n') {
                Position::new(line_idx as u32, len + 1)
            } else {
                Position::new(line_idx as u32, len)
            }
        } else {
            // Past end of file
            Position::new(source_lines.len() as u32, 0)
        }
    };

    let mut edits = Vec::new();
    for op in diff.ops() {
        match *op {
            similar::DiffOp::Equal { .. } => {}
            similar::DiffOp::Delete {
                old_index, old_len, ..
            } => {
                let start = line_start_col(old_index);
                let end = if old_index + old_len < source_lines.len() {
                    line_start_col(old_index + old_len)
                } else {
                    line_end_col(old_index + old_len - 1)
                };
                edits.push(TextEdit {
                    range: Range::new(start, end),
                    new_text: String::new(),
                });
            }
            similar::DiffOp::Insert {
                old_index,
                new_index,
                new_len,
                ..
            } => {
                let pos = line_start_col(old_index);
                let new_text: String = diff.new_slices()[new_index..new_index + new_len]
                    .iter()
                    .map(|s| format!("{}\n", s.trim_end_matches('\n')))
                    .collect();
                // If inserting at very end and source doesn't end with newline, adjust
                let new_text = if old_index >= source_lines.len() && !source.ends_with('\n') {
                    format!("\n{}", new_text.trim_end_matches('\n'))
                } else {
                    new_text
                };
                edits.push(TextEdit {
                    range: Range::new(pos, pos),
                    new_text,
                });
            }
            similar::DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                let start = line_start_col(old_index);
                let end = if old_index + old_len < source_lines.len() {
                    line_start_col(old_index + old_len)
                } else {
                    line_end_col(old_index + old_len - 1)
                };
                let new_text: String = diff.new_slices()[new_index..new_index + new_len]
                    .iter()
                    .map(|s| format!("{}\n", s.trim_end_matches('\n')))
                    .collect();
                // If replacing the last lines and source doesn't end with newline, strip trailing newline
                let new_text =
                    if old_index + old_len >= source_lines.len() && !source.ends_with('\n') {
                        new_text.trim_end_matches('\n').to_string()
                    } else {
                        new_text
                    };
                edits.push(TextEdit {
                    range: Range::new(start, end),
                    new_text,
                });
            }
        }
    }
    edits
}
