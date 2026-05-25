use crate::ast::Span;
use crate::errors::ParseError;

const MAX_PARSE_BYTES: usize = 256 * 1024;
const MAX_DELIMITER_NESTING: usize = 32;

pub(super) fn validate_source_shape(source: &str, filename: &str) -> Result<(), ParseError> {
    if source.len() > MAX_PARSE_BYTES {
        return Err(ParseError::syntax(
            format!("source exceeds parser size limit of {MAX_PARSE_BYTES} bytes"),
            Span::new(0, source.len()),
            source,
            filename,
        ));
    }

    let mut nesting = 0usize;
    for (idx, ch) in source.char_indices() {
        if ch == '\0' {
            return Err(ParseError::syntax(
                "source contains a NUL byte",
                Span::new(idx, idx + ch.len_utf8()),
                source,
                filename,
            ));
        }
        match ch {
            '(' | '[' | '{' => {
                nesting += 1;
                if nesting > MAX_DELIMITER_NESTING {
                    return Err(ParseError::syntax(
                        format!(
                            "delimiter nesting exceeds parser limit of {MAX_DELIMITER_NESTING}"
                        ),
                        Span::new(idx, idx + ch.len_utf8()),
                        source,
                        filename,
                    ));
                }
            }
            ')' | ']' | '}' => {
                nesting = nesting.saturating_sub(1);
            }
            _ => {}
        }
    }

    Ok(())
}
