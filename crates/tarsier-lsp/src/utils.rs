use tower_lsp::lsp_types::*;

/// Convert a byte offset into an LSP `Position` (line/character).
pub(crate) fn offset_to_position(text: &str, offset: usize) -> Position {
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
pub(crate) fn position_to_offset(text: &str, pos: Position) -> usize {
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
pub(crate) fn offset_to_range(text: &str, start: usize, end: usize) -> Option<Range> {
    let start_pos = offset_to_position(text, start);
    let end_pos = offset_to_position(text, end);
    Some(Range::new(start_pos, end_pos))
}

/// Apply an incremental text change to a source string.
pub(crate) fn apply_incremental_change(text: &mut String, range: &Range, new_text: &str) {
    let start = position_to_offset(text, range.start);
    let end = position_to_offset(text, range.end);
    let start = start.min(text.len());
    let end = end.min(text.len());
    text.replace_range(start..end, new_text);
}

pub(crate) fn word_at_position(text: &str, offset: usize) -> Option<(String, usize, usize)> {
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

pub(crate) fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
