use crate::ast::Span;
use crate::errors::ParseError;

pub(super) const MAX_PARSE_BYTES: usize = 256 * 1024;
pub(super) const MAX_PARSE_GROUP_NESTING: usize = 32;

pub(super) fn validate_parse_complexity(source: &str, filename: &str) -> Result<(), ParseError> {
    if source.len() > MAX_PARSE_BYTES {
        return Err(ParseError::syntax(
            format!("Source exceeds the maximum supported size of {MAX_PARSE_BYTES} bytes"),
            Span::new(0, source.len()),
            source,
            filename,
        ));
    }

    let bytes = source.as_bytes();
    let mut idx = 0;
    let mut paren_depth = 0usize;

    while idx < bytes.len() {
        match bytes[idx] {
            0 => {
                return Err(ParseError::syntax(
                    "Source contains a NUL byte",
                    Span::new(idx, idx + 1),
                    source,
                    filename,
                ));
            }
            b'/' if bytes.get(idx + 1) == Some(&b'/') => {
                idx += 2;
                while idx < bytes.len() && bytes[idx] != b'\n' {
                    idx += 1;
                }
            }
            b'/' if bytes.get(idx + 1) == Some(&b'*') => {
                idx += 2;
                while idx + 1 < bytes.len() && !(bytes[idx] == b'*' && bytes[idx + 1] == b'/') {
                    idx += 1;
                }
                idx = (idx + 2).min(bytes.len());
            }
            b'"' => {
                idx += 1;
                while idx < bytes.len() && bytes[idx] != b'"' {
                    idx += 1;
                }
                idx += 1;
            }
            b'(' => {
                paren_depth += 1;
                if paren_depth > MAX_PARSE_GROUP_NESTING {
                    return Err(ParseError::syntax(
                        format!(
                            "Parenthesis nesting exceeds the maximum supported depth of {MAX_PARSE_GROUP_NESTING}"
                        ),
                        Span::new(idx, idx + 1),
                        source,
                        filename,
                    ));
                }
                idx += 1;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    Ok(())
}
