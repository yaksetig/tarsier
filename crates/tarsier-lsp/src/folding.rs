//! Folding range generation for the Tarsier DSL.
//!
//! Provides collapsible regions for:
//! - Protocol blocks
//! - Messages sections (grouped consecutive message declarations)
//! - Role blocks
//! - Phase blocks
//! - Multi-line transition rules
//! - Property blocks
//! - Committee blocks
//! - Enum blocks

use tower_lsp::lsp_types::*;

use tarsier_dsl::ast::Program;

use crate::utils::offset_to_position;

/// Build folding ranges for an entire program.
pub(crate) fn build_folding_ranges(source: &str, program: &Program) -> Vec<FoldingRange> {
    let mut ranges = Vec::new();
    let proto = &program.protocol;

    // Protocol block
    let proto_start = offset_to_position(source, proto.span.start);
    let proto_end = offset_to_position(source, proto.span.end);
    if proto_end.line > proto_start.line {
        ranges.push(FoldingRange {
            start_line: proto_start.line,
            start_character: None,
            end_line: proto_end.line,
            end_character: None,
            kind: Some(FoldingRangeKind::Region),
            collapsed_text: Some(format!("protocol {} {{ ... }}", proto.node.name)),
        });
    }

    // Enum blocks
    for enum_decl in &proto.node.enums {
        let start = offset_to_position(source, enum_decl.span.start);
        let end = offset_to_position(source, enum_decl.span.end);
        if end.line > start.line {
            ranges.push(FoldingRange {
                start_line: start.line,
                start_character: None,
                end_line: end.line,
                end_character: None,
                kind: Some(FoldingRangeKind::Region),
                collapsed_text: Some(format!("enum {} {{ ... }}", enum_decl.name)),
            });
        }
    }

    // Committee blocks
    for committee in &proto.node.committees {
        let start = offset_to_position(source, committee.span.start);
        let end = offset_to_position(source, committee.span.end);
        if end.line > start.line {
            ranges.push(FoldingRange {
                start_line: start.line,
                start_character: None,
                end_line: end.line,
                end_character: None,
                kind: Some(FoldingRangeKind::Region),
                collapsed_text: Some(format!("committee {} {{ ... }}", committee.name)),
            });
        }
    }

    // Role blocks
    for role in &proto.node.roles {
        let start = offset_to_position(source, role.span.start);
        let end = offset_to_position(source, role.span.end);
        if end.line > start.line {
            ranges.push(FoldingRange {
                start_line: start.line,
                start_character: None,
                end_line: end.line,
                end_character: None,
                kind: Some(FoldingRangeKind::Region),
                collapsed_text: Some(format!("role {} {{ ... }}", role.node.name)),
            });
        }

        // Phase blocks within this role
        for phase in &role.node.phases {
            let p_start = offset_to_position(source, phase.span.start);
            let p_end = offset_to_position(source, phase.span.end);
            if p_end.line > p_start.line {
                ranges.push(FoldingRange {
                    start_line: p_start.line,
                    start_character: None,
                    end_line: p_end.line,
                    end_character: None,
                    kind: Some(FoldingRangeKind::Region),
                    collapsed_text: Some(format!("phase {} {{ ... }}", phase.node.name)),
                });
            }

            // Multi-line transition rules within this phase
            for transition in &phase.node.transitions {
                let t_start = offset_to_position(source, transition.span.start);
                let t_end = offset_to_position(source, transition.span.end);
                if t_end.line > t_start.line {
                    ranges.push(FoldingRange {
                        start_line: t_start.line,
                        start_character: None,
                        end_line: t_end.line,
                        end_character: None,
                        kind: Some(FoldingRangeKind::Region),
                        collapsed_text: Some("when ... => { ... }".to_string()),
                    });
                }
            }
        }
    }

    // Property blocks
    for prop in &proto.node.properties {
        let start = offset_to_position(source, prop.span.start);
        let end = offset_to_position(source, prop.span.end);
        if end.line > start.line {
            ranges.push(FoldingRange {
                start_line: start.line,
                start_character: None,
                end_line: end.line,
                end_character: None,
                kind: Some(FoldingRangeKind::Region),
                collapsed_text: Some(format!(
                    "property {}: {} {{ ... }}",
                    prop.node.name, prop.node.kind
                )),
            });
        }
    }

    // Module blocks
    for module in &proto.node.modules {
        let start = offset_to_position(source, module.span.start);
        let end = offset_to_position(source, module.span.end);
        if end.line > start.line {
            ranges.push(FoldingRange {
                start_line: start.line,
                start_character: None,
                end_line: end.line,
                end_character: None,
                kind: Some(FoldingRangeKind::Region),
                collapsed_text: Some(format!("module {} {{ ... }}", module.name)),
            });
        }
    }

    // Comment blocks: fold consecutive single-line comments
    let mut comment_start: Option<u32> = None;
    let mut comment_end: Option<u32> = None;
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            let ln = line_num as u32;
            match comment_start {
                None => {
                    comment_start = Some(ln);
                    comment_end = Some(ln);
                }
                Some(_) => {
                    comment_end = Some(ln);
                }
            }
        } else {
            if let (Some(cs), Some(ce)) = (comment_start, comment_end) {
                if ce > cs {
                    ranges.push(FoldingRange {
                        start_line: cs,
                        start_character: None,
                        end_line: ce,
                        end_character: None,
                        kind: Some(FoldingRangeKind::Comment),
                        collapsed_text: Some("// ...".to_string()),
                    });
                }
            }
            comment_start = None;
            comment_end = None;
        }
    }
    // Handle trailing comments
    if let (Some(cs), Some(ce)) = (comment_start, comment_end) {
        if ce > cs {
            ranges.push(FoldingRange {
                start_line: cs,
                start_character: None,
                end_line: ce,
                end_character: None,
                kind: Some(FoldingRangeKind::Comment),
                collapsed_text: Some("// ...".to_string()),
            });
        }
    }

    // Sort by start_line for consistent output
    ranges.sort_by_key(|r| (r.start_line, r.end_line));
    ranges
}
