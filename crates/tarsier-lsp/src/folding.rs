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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Program {
        tarsier_dsl::parse_with_diagnostics(src, "test.trs")
            .unwrap()
            .0
    }

    #[test]
    fn protocol_block_foldable() {
        let src = "protocol Foo {\n    message M;\n}";
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let proto_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("protocol Foo"))
        });
        assert!(proto_fold.is_some(), "protocol block should be foldable");
        let pf = proto_fold.unwrap();
        assert_eq!(pf.start_line, 0);
        assert_eq!(pf.end_line, 2);
    }

    #[test]
    fn single_line_protocol_not_foldable() {
        let src = "protocol Foo { message M; }";
        let result = tarsier_dsl::parse_with_diagnostics(src, "test.trs");
        if let Ok((program, _)) = result {
            let ranges = build_folding_ranges(src, &program);
            let proto_fold = ranges.iter().find(|r| {
                r.collapsed_text
                    .as_deref()
                    .is_some_and(|t| t.contains("protocol Foo"))
            });
            assert!(proto_fold.is_none());
        }
    }

    #[test]
    fn role_block_foldable() {
        let src = r#"protocol P {
    message Echo;
    role Node {
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase waiting;
            }
        }
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let role_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("role Node"))
        });
        assert!(role_fold.is_some(), "role block should be foldable");
    }

    #[test]
    fn phase_block_foldable() {
        let src = r#"protocol P {
    message Echo;
    role Node {
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase waiting;
            }
        }
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let phase_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("phase waiting"))
        });
        assert!(phase_fold.is_some(), "phase block should be foldable");
    }

    #[test]
    fn transition_block_foldable() {
        let src = r#"protocol P {
    message Echo;
    role Node {
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase waiting;
            }
        }
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let transition_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("when"))
        });
        assert!(
            transition_fold.is_some(),
            "multi-line transition should be foldable"
        );
    }

    #[test]
    fn comment_block_foldable() {
        let src = r#"// line1
// line2
// line3
protocol P {
    message M;
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let comment_fold = ranges
            .iter()
            .find(|r| r.kind == Some(FoldingRangeKind::Comment));
        assert!(
            comment_fold.is_some(),
            "consecutive comments should be foldable"
        );
        let cf = comment_fold.unwrap();
        assert_eq!(cf.start_line, 0);
        assert_eq!(cf.end_line, 2);
    }

    #[test]
    fn single_comment_line_not_foldable() {
        let src = "// one comment\nprotocol P {\n    message M;\n}";
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let comment_fold = ranges
            .iter()
            .find(|r| r.kind == Some(FoldingRangeKind::Comment));
        assert!(
            comment_fold.is_none(),
            "a single comment line should not be foldable"
        );
    }

    #[test]
    fn enum_block_foldable() {
        let src = r#"protocol P {
    enum Status {
        idle,
        done
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let enum_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("enum Status"))
        });
        assert!(enum_fold.is_some(), "enum block should be foldable");
    }

    #[test]
    fn ranges_sorted_by_start_line() {
        let src = r#"protocol P {
    message Echo;
    role Node {
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase waiting;
            }
        }
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        for i in 1..ranges.len() {
            assert!(
                (ranges[i].start_line, ranges[i].end_line)
                    >= (ranges[i - 1].start_line, ranges[i - 1].end_line),
                "folding ranges should be sorted by start_line"
            );
        }
    }

    #[test]
    fn property_block_foldable() {
        let src = r#"protocol P {
    message Echo;
    role Node {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase waiting;
            }
        }
    }
    property agr: agreement {
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let program = parse(src);
        let ranges = build_folding_ranges(src, &program);
        let prop_fold = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.contains("property agr"))
        });
        assert!(prop_fold.is_some(), "property block should be foldable");
    }
}
