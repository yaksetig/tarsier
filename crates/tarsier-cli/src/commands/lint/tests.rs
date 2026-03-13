use super::*;
use tarsier_dsl::ast::{LinearExpr, Span as DslSpan};
use tarsier_engine::pipeline::SoundnessMode;

// -- LintFix serialization --

#[test]
fn lint_fix_serializes_without_insert_offset_when_none() {
    let fix = LintFix {
        label: "test".into(),
        snippet: "code".into(),
        insert_offset: None,
    };
    let json = serde_json::to_value(&fix).unwrap();
    assert!(!json.as_object().unwrap().contains_key("insert_offset"));
}

#[test]
fn lint_fix_serializes_with_insert_offset_when_some() {
    let fix = LintFix {
        label: "test".into(),
        snippet: "code".into(),
        insert_offset: Some(42),
    };
    let json = serde_json::to_value(&fix).unwrap();
    assert_eq!(json["insert_offset"], 42);
}

// -- LintSourceSpan --

#[test]
fn lint_source_span_copy_semantics() {
    let span = LintSourceSpan {
        start: 0,
        end: 5,
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 6,
    };
    let copy = span;
    assert_eq!(copy.start, span.start);
    assert_eq!(copy.end, span.end);
}

// -- LintIssue serialization --

#[test]
fn lint_issue_skips_none_fields() {
    let issue = LintIssue {
        severity: "warn".into(),
        code: "test_code".into(),
        message: "hello".into(),
        suggestion: None,
        soundness_impact: None,
        fix: None,
        source_span: None,
    };
    let json = serde_json::to_value(&issue).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("soundness_impact"));
    assert!(!obj.contains_key("fix"));
    assert!(!obj.contains_key("source_span"));
}

// -- LintReport serialization --

#[test]
fn lint_report_serializes_correctly() {
    let report = LintReport {
        schema_version: 1,
        file: "test.trs".into(),
        soundness: "strict".into(),
        issues: vec![],
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["file"], "test.trs");
    assert_eq!(json["soundness"], "strict");
    assert!(json["issues"].as_array().unwrap().is_empty());
}

// -- guard_has_non_monotone_threshold --

fn make_threshold(
    op: tarsier_dsl::ast::CmpOp,
    distinct: bool,
    distinct_role: Option<&str>,
    msg: &str,
) -> tarsier_dsl::ast::GuardExpr {
    tarsier_dsl::ast::GuardExpr::Threshold(tarsier_dsl::ast::ThresholdGuard {
        op,
        threshold: LinearExpr::Const(1),
        message_type: msg.into(),
        message_args: vec![],
        distinct,
        distinct_role: distinct_role.map(String::from),
    })
}

#[test]
fn guard_has_non_monotone_threshold_false_for_ge() {
    use tarsier_dsl::ast::CmpOp;
    let guard = make_threshold(CmpOp::Ge, false, None, "M");
    assert!(!guard_has_non_monotone_threshold(&guard));
}

#[test]
fn guard_has_non_monotone_threshold_true_for_le() {
    use tarsier_dsl::ast::CmpOp;
    let guard = make_threshold(CmpOp::Le, false, None, "M");
    assert!(guard_has_non_monotone_threshold(&guard));
}

#[test]
fn guard_has_non_monotone_in_and() {
    use tarsier_dsl::ast::{CmpOp, GuardExpr};
    let monotone = make_threshold(CmpOp::Ge, false, None, "M");
    let non_monotone = make_threshold(CmpOp::Eq, false, None, "M");
    let and_guard = GuardExpr::And(Box::new(monotone), Box::new(non_monotone));
    assert!(guard_has_non_monotone_threshold(&and_guard));
}

// -- guard_uses_distinct_threshold --

#[test]
fn guard_uses_distinct_true() {
    use tarsier_dsl::ast::CmpOp;
    let guard = make_threshold(CmpOp::Ge, true, Some("Validator"), "M");
    assert!(guard_uses_distinct_threshold(&guard));
}

#[test]
fn guard_uses_distinct_false() {
    use tarsier_dsl::ast::CmpOp;
    let guard = make_threshold(CmpOp::Ge, false, None, "M");
    assert!(!guard_uses_distinct_threshold(&guard));
}

// -- collect_distinct_roles_from_guard --

#[test]
fn collect_distinct_roles_deduplicates() {
    use tarsier_dsl::ast::{CmpOp, GuardExpr};
    let guard = GuardExpr::And(
        Box::new(make_threshold(CmpOp::Ge, true, Some("R"), "M")),
        Box::new(make_threshold(CmpOp::Ge, true, Some("R"), "N")),
    );
    let mut roles = Vec::new();
    collect_distinct_roles_from_guard(&guard, &mut roles);
    assert_eq!(roles, vec!["R".to_string()]);
}

// -- byte_offset_to_line_col --

#[test]
fn byte_offset_to_line_col_start() {
    assert_eq!(byte_offset_to_line_col("hello", 0), (1, 1));
}

#[test]
fn byte_offset_to_line_col_middle() {
    assert_eq!(byte_offset_to_line_col("hello\nworld", 6), (2, 1));
}

#[test]
fn byte_offset_to_line_col_end() {
    assert_eq!(byte_offset_to_line_col("ab", 2), (1, 3));
}

#[test]
fn byte_offset_to_line_col_clamped() {
    assert_eq!(byte_offset_to_line_col("ab", 100), (1, 3));
}

// -- line_col_to_byte_offset --

#[test]
fn line_col_to_byte_offset_start() {
    assert_eq!(line_col_to_byte_offset("hello", 1, 1), 0);
}

#[test]
fn line_col_to_byte_offset_second_line() {
    assert_eq!(line_col_to_byte_offset("hello\nworld", 2, 1), 6);
}

#[test]
fn line_col_to_byte_offset_past_end() {
    assert_eq!(line_col_to_byte_offset("ab", 99, 1), 2);
}

// -- advance_one_char --

#[test]
fn advance_one_char_ascii() {
    assert_eq!(advance_one_char("abc", 0), 1);
    assert_eq!(advance_one_char("abc", 1), 2);
}

#[test]
fn advance_one_char_at_end() {
    assert_eq!(advance_one_char("ab", 2), 2);
}

#[test]
fn advance_one_char_past_end() {
    assert_eq!(advance_one_char("ab", 99), 99);
}

// -- lint_source_span --

#[test]
fn lint_source_span_basic() {
    let source = "hello\nworld";
    let span = DslSpan { start: 6, end: 11 };
    let ls = lint_source_span(source, span);
    assert_eq!(ls.start, 6);
    assert_eq!(ls.end, 11);
    assert_eq!(ls.line, 2);
    assert_eq!(ls.column, 1);
}

#[test]
fn lint_source_span_clamps() {
    let source = "ab";
    let span = DslSpan {
        start: 100,
        end: 200,
    };
    let ls = lint_source_span(source, span);
    assert_eq!(ls.start, 2);
    assert_eq!(ls.end, 2);
}

// -- infer_parse_error_span --

#[test]
fn infer_parse_error_span_with_arrow() {
    let source = "hello\nworld";
    let msg = "error --> 2:1 something";
    let span = infer_parse_error_span(source, msg).unwrap();
    assert_eq!(span.start, 6);
}

#[test]
fn infer_parse_error_span_no_arrow() {
    let source = "abc";
    let msg = "some error without location";
    let span = infer_parse_error_span(source, msg).unwrap();
    assert_eq!(span.start, 0);
}

#[test]
fn infer_parse_error_span_empty_source() {
    assert!(infer_parse_error_span("", "error").is_none());
}

// -- lint_soundness_impact --

#[test]
fn lint_soundness_impact_known_codes() {
    assert!(lint_soundness_impact("parse_error", "error").is_some());
    assert!(lint_soundness_impact("missing_resilience", "error").is_some());
    assert!(lint_soundness_impact("missing_safety_property", "error").is_some());
    assert!(lint_soundness_impact("missing_adversary_bound", "error").is_some());
    assert!(lint_soundness_impact("missing_gst", "error").is_some());
    assert!(lint_soundness_impact("unbounded_local_int", "warn").is_some());
    assert!(lint_soundness_impact("distinct_requires_signed_auth", "warn").is_some());
}

#[test]
fn lint_soundness_impact_unknown_error() {
    let impact = lint_soundness_impact("unknown_code", "error");
    assert!(impact.is_some());
    assert!(impact.unwrap().contains("Blocking"));
}

#[test]
fn lint_soundness_impact_unknown_warn() {
    let impact = lint_soundness_impact("unknown_code", "warn");
    assert!(impact.is_some());
}

#[test]
fn lint_soundness_impact_unknown_info() {
    let impact = lint_soundness_impact("unknown_code", "info");
    assert!(impact.is_none());
}

// -- lint_issue --

#[test]
fn lint_issue_constructs_correctly() {
    let issue = lint_issue(
        "hello",
        "error",
        "test_code",
        "test message",
        Some("do this".into()),
        None,
        None,
    );
    assert_eq!(issue.severity, "error");
    assert_eq!(issue.code, "test_code");
    assert_eq!(issue.message, "test message");
    assert_eq!(issue.suggestion.as_deref(), Some("do this"));
    assert!(issue.soundness_impact.is_some());
    assert!(issue.fix.is_none());
    assert!(issue.source_span.is_none());
}

// -- soundness_name (local) --

#[test]
fn soundness_name_local() {
    assert_eq!(soundness_name(SoundnessMode::Strict), "strict");
    assert_eq!(soundness_name(SoundnessMode::Permissive), "permissive");
}

// -- render_lint_text --

#[test]
fn render_lint_text_empty_report() {
    let report = LintReport {
        schema_version: 1,
        file: "test.trs".into(),
        soundness: "strict".into(),
        issues: vec![],
    };
    let text = render_lint_text(&report);
    assert!(text.contains("LINT REPORT"));
    assert!(text.contains("File: test.trs"));
    assert!(text.contains("0 error(s), 0 warning(s), 0 info"));
}

#[test]
fn render_lint_text_with_issues() {
    let report = LintReport {
        schema_version: 1,
        file: "proto.trs".into(),
        soundness: "permissive".into(),
        issues: vec![
            LintIssue {
                severity: "error".into(),
                code: "missing_n".into(),
                message: "No n param".into(),
                suggestion: Some("Add n".into()),
                soundness_impact: Some("impact".into()),
                fix: Some(LintFix {
                    label: "fix".into(),
                    snippet: "params n;".into(),
                    insert_offset: Some(0),
                }),
                source_span: Some(LintSourceSpan {
                    start: 0,
                    end: 1,
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 2,
                }),
            },
            LintIssue {
                severity: "warn".into(),
                code: "warn_code".into(),
                message: "warning msg".into(),
                suggestion: None,
                soundness_impact: None,
                fix: None,
                source_span: None,
            },
        ],
    };
    let text = render_lint_text(&report);
    assert!(text.contains("1 error(s), 1 warning(s), 0 info"));
    assert!(text.contains("[ERROR] missing_n: No n param"));
    assert!(text.contains("suggestion: Add n"));
    assert!(text.contains("soundness impact: impact"));
    assert!(text.contains("fix (fix): params n;"));
    assert!(text.contains("span: 1:1 -> 1:2 (bytes 0..1)"));
    assert!(text.contains("[WARN] warn_code: warning msg"));
}

// -- faithful suggestion helpers --

#[test]
fn faithful_identity_decl_snippet_role() {
    let snippet = faithful_identity_decl_snippet(
        "Validator",
        tarsier_dsl::ast::IdentityScope::Role,
        None,
        "vk",
    );
    assert_eq!(snippet, "identity Validator: role key vk;");
}

#[test]
fn faithful_identity_decl_snippet_process() {
    let snippet = faithful_identity_decl_snippet(
        "Validator",
        tarsier_dsl::ast::IdentityScope::Process,
        Some("pid"),
        "vk",
    );
    assert_eq!(snippet, "identity Validator: process(pid) key vk;");
}

#[test]
fn suggested_identity_scope_for_process_selective() {
    let (scope, var) = suggested_identity_scope_for_network("process_selective");
    assert_eq!(scope, tarsier_dsl::ast::IdentityScope::Process);
    assert_eq!(var, Some("pid"));
}

#[test]
fn suggested_identity_scope_for_classic() {
    let (scope, var) = suggested_identity_scope_for_network("classic");
    assert_eq!(scope, tarsier_dsl::ast::IdentityScope::Role);
    assert!(var.is_none());
}

#[test]
fn faithful_missing_identity_suggestion_empty() {
    assert!(faithful_missing_identity_suggestion(&[], "classic").is_none());
}

#[test]
fn faithful_missing_identity_suggestion_nonempty() {
    let suggestion =
        faithful_missing_identity_suggestion(&["Validator".to_string()], "classic").unwrap();
    assert!(suggestion.contains("identity Validator"));
}

#[test]
fn faithful_missing_auth_suggestion_empty() {
    assert!(faithful_missing_auth_suggestion(&[]).is_none());
}

#[test]
fn faithful_missing_auth_suggestion_nonempty() {
    let suggestion = faithful_missing_auth_suggestion(&["Vote".to_string()]).unwrap();
    assert!(suggestion.contains("channel Vote: authenticated;"));
}

#[test]
fn faithful_missing_equivocation_suggestion_is_some() {
    assert!(faithful_missing_equivocation_suggestion().is_some());
}

#[test]
fn faithful_missing_process_identity_suggestion_empty() {
    assert!(faithful_missing_process_identity_suggestion(&[]).is_none());
}

#[test]
fn faithful_missing_process_identity_suggestion_nonempty() {
    let suggestion = faithful_missing_process_identity_suggestion(&["Node".to_string()]).unwrap();
    assert!(suggestion.contains("identity Node: process(pid)"));
}
