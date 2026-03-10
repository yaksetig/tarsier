//! Message info building, field enumeration, and counter naming.

use indexmap::IndexMap;

use crate::threshold_automaton::*;
use tarsier_dsl::ast;

use super::{FieldDomain, LoweringError, MessageFieldInfo, MessageInfo};

pub(super) fn abstract_nat_values_sign(min: i64, max: i64) -> Vec<String> {
    let mut out = Vec::new();
    if min <= 0 && 0 <= max {
        out.push("zero".to_string());
    }
    if max >= 1 {
        out.push("pos".to_string());
    }
    out
}

pub(super) fn abstract_int_values_sign(min: i64, max: i64) -> Vec<String> {
    let mut out = Vec::new();
    if min <= -1 {
        out.push("neg".to_string());
    }
    if min <= 0 && 0 <= max {
        out.push("zero".to_string());
    }
    if max >= 1 {
        out.push("pos".to_string());
    }
    out
}

pub(super) fn build_message_infos(
    messages: &[ast::MessageDecl],
    enum_defs: &IndexMap<String, Vec<String>>,
    value_abstraction: ValueAbstractionMode,
) -> Result<IndexMap<String, MessageInfo>, LoweringError> {
    let mut infos: IndexMap<String, MessageInfo> = IndexMap::new();
    for msg in messages {
        let mut fields = Vec::new();
        for f in &msg.fields {
            let domain = match f.ty.as_str() {
                "bool" => FieldDomain::Bool,
                "nat" => match value_abstraction {
                    ValueAbstractionMode::Exact => {
                        let range = f.range.as_ref().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Message field '{}' in '{}' with type nat must use a finite range \
                                     (e.g., `in 0..4`) unless `adversary {{ values: sign; }}` is enabled",
                                    f.name, msg.name
                                ))
                            })?;
                        if range.min < 0 || range.max < range.min {
                            return Err(LoweringError::Unsupported(format!(
                                "Invalid nat range for message field '{}' in '{}': {}..{}",
                                f.name, msg.name, range.min, range.max
                            )));
                        }
                        FieldDomain::Int {
                            min: range.min,
                            max: range.max,
                        }
                    }
                    ValueAbstractionMode::Sign => {
                        let values = if let Some(range) = &f.range {
                            if range.min < 0 || range.max < range.min {
                                return Err(LoweringError::Unsupported(format!(
                                    "Invalid nat range for message field '{}' in '{}': {}..{}",
                                    f.name, msg.name, range.min, range.max
                                )));
                            }
                            abstract_nat_values_sign(range.min, range.max)
                        } else {
                            vec!["zero".into(), "pos".into()]
                        };
                        FieldDomain::AbstractNatSign(values)
                    }
                },
                "int" => match value_abstraction {
                    ValueAbstractionMode::Exact => {
                        let range = f.range.as_ref().ok_or_else(|| {
                                LoweringError::Unsupported(format!(
                                    "Message field '{}' in '{}' with type int must use a finite range \
                                     (e.g., `in 0..4`) unless `adversary {{ values: sign; }}` is enabled",
                                    f.name, msg.name
                                ))
                            })?;
                        if range.max < range.min {
                            return Err(LoweringError::Unsupported(format!(
                                "Invalid int range for message field '{}' in '{}': {}..{}",
                                f.name, msg.name, range.min, range.max
                            )));
                        }
                        FieldDomain::Int {
                            min: range.min,
                            max: range.max,
                        }
                    }
                    ValueAbstractionMode::Sign => {
                        let values = if let Some(range) = &f.range {
                            if range.max < range.min {
                                return Err(LoweringError::Unsupported(format!(
                                    "Invalid int range for message field '{}' in '{}': {}..{}",
                                    f.name, msg.name, range.min, range.max
                                )));
                            }
                            abstract_int_values_sign(range.min, range.max)
                        } else {
                            vec!["neg".into(), "zero".into(), "pos".into()]
                        };
                        FieldDomain::AbstractIntSign(values)
                    }
                },
                other => {
                    if f.range.is_some() {
                        return Err(LoweringError::Unsupported(format!(
                            "Message field '{}' in '{}' uses range syntax but type '{}' is not int/nat",
                            f.name, msg.name, other
                        )));
                    }
                    let variants = enum_defs
                        .get(other)
                        .ok_or_else(|| LoweringError::UnknownEnum(other.to_string()))?;
                    FieldDomain::Enum(variants.clone())
                }
            };
            fields.push(MessageFieldInfo {
                name: f.name.clone(),
                domain,
            });
        }
        infos.insert(
            msg.name.clone(),
            MessageInfo {
                name: msg.name.clone(),
                fields,
            },
        );
    }
    Ok(infos)
}

pub(super) fn enumerate_field_values(fields: &[MessageFieldInfo]) -> Vec<Vec<String>> {
    let mut results: Vec<Vec<String>> = vec![Vec::new()];
    for field in fields {
        let values: Vec<String> = match &field.domain {
            FieldDomain::Bool => vec!["false".into(), "true".into()],
            FieldDomain::Enum(variants) => variants.clone(),
            FieldDomain::Int { min, max } => {
                let mut vals = Vec::new();
                for v in *min..=*max {
                    vals.push(v.to_string());
                }
                vals
            }
            FieldDomain::AbstractNatSign(values) | FieldDomain::AbstractIntSign(values) => {
                values.clone()
            }
        };
        let mut next = Vec::new();
        for prefix in &results {
            for v in &values {
                let mut new = prefix.clone();
                new.push(v.clone());
                next.push(new);
            }
        }
        results = next;
    }
    results
}

pub(super) fn msg_key(
    name: &str,
    recipient_role: &str,
    sender_channel: Option<&str>,
    values: &[String],
) -> String {
    let sender_part = sender_channel.map(|s| format!("<-{s}")).unwrap_or_default();
    if values.is_empty() {
        format!("{name}@{recipient_role}{sender_part}")
    } else {
        format!("{name}@{recipient_role}{sender_part}|{}", values.join("|"))
    }
}

pub(super) fn format_msg_counter_name(
    name: &str,
    recipient_role: &str,
    sender_channel: Option<&str>,
    fields: &[MessageFieldInfo],
    values: &[String],
) -> String {
    let sender_suffix = sender_channel
        .map(|sender| format!("<-{sender}"))
        .unwrap_or_default();
    if fields.is_empty() {
        format!("cnt_{name}@{recipient_role}{sender_suffix}")
    } else {
        let parts: Vec<String> = fields
            .iter()
            .zip(values.iter())
            .map(|(f, v)| format!("{}={}", f.name, v))
            .collect();
        format!(
            "cnt_{name}@{recipient_role}{sender_suffix}[{}]",
            parts.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_nat_sign_zero_and_positive() {
        assert_eq!(abstract_nat_values_sign(0, 5), vec!["zero", "pos"]);
    }

    #[test]
    fn abstract_nat_sign_positive_only() {
        assert_eq!(abstract_nat_values_sign(1, 5), vec!["pos"]);
    }

    #[test]
    fn abstract_nat_sign_zero_only() {
        assert_eq!(abstract_nat_values_sign(0, 0), vec!["zero"]);
    }

    #[test]
    fn abstract_int_sign_all_three() {
        assert_eq!(abstract_int_values_sign(-3, 3), vec!["neg", "zero", "pos"]);
    }

    #[test]
    fn abstract_int_sign_neg_only() {
        assert_eq!(abstract_int_values_sign(-5, -1), vec!["neg"]);
    }

    #[test]
    fn abstract_int_sign_neg_and_zero() {
        assert_eq!(abstract_int_values_sign(-3, 0), vec!["neg", "zero"]);
    }

    #[test]
    fn abstract_int_sign_pos_only() {
        assert_eq!(abstract_int_values_sign(1, 10), vec!["pos"]);
    }

    #[test]
    fn msg_key_no_sender_no_values() {
        assert_eq!(msg_key("Vote", "Replica", None, &[]), "Vote@Replica");
    }

    #[test]
    fn msg_key_with_sender() {
        assert_eq!(
            msg_key("Vote", "Replica", Some("Leader#0"), &[]),
            "Vote@Replica<-Leader#0"
        );
    }

    #[test]
    fn msg_key_with_values() {
        let values = vec!["v0".to_string(), "true".to_string()];
        assert_eq!(
            msg_key("Vote", "Replica", None, &values),
            "Vote@Replica|v0|true"
        );
    }

    #[test]
    fn msg_key_with_sender_and_values() {
        let values = vec!["42".to_string()];
        assert_eq!(msg_key("Msg", "R", Some("S#1"), &values), "Msg@R<-S#1|42");
    }

    #[test]
    fn format_counter_name_no_fields() {
        let fields: Vec<MessageFieldInfo> = vec![];
        assert_eq!(
            format_msg_counter_name("Vote", "Replica", None, &fields, &[]),
            "cnt_Vote@Replica"
        );
    }

    #[test]
    fn format_counter_name_with_sender() {
        let fields: Vec<MessageFieldInfo> = vec![];
        assert_eq!(
            format_msg_counter_name("Vote", "Replica", Some("Leader"), &fields, &[]),
            "cnt_Vote@Replica<-Leader"
        );
    }

    #[test]
    fn format_counter_name_with_fields() {
        let fields = vec![
            MessageFieldInfo {
                name: "view".into(),
                domain: FieldDomain::Enum(vec!["v0".into(), "v1".into()]),
            },
            MessageFieldInfo {
                name: "flag".into(),
                domain: FieldDomain::Bool,
            },
        ];
        let values = vec!["v0".to_string(), "true".to_string()];
        assert_eq!(
            format_msg_counter_name("Vote", "Replica", None, &fields, &values),
            "cnt_Vote@Replica[view=v0,flag=true]"
        );
    }

    #[test]
    fn enumerate_no_fields() {
        let fields: Vec<MessageFieldInfo> = vec![];
        let results = enumerate_field_values(&fields);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_empty());
    }

    #[test]
    fn enumerate_bool_field() {
        let fields = vec![MessageFieldInfo {
            name: "flag".into(),
            domain: FieldDomain::Bool,
        }];
        let results = enumerate_field_values(&fields);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], vec!["false"]);
        assert_eq!(results[1], vec!["true"]);
    }

    #[test]
    fn enumerate_int_range_field() {
        let fields = vec![MessageFieldInfo {
            name: "x".into(),
            domain: FieldDomain::Int { min: 0, max: 2 },
        }];
        let results = enumerate_field_values(&fields);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], vec!["0"]);
        assert_eq!(results[2], vec!["2"]);
    }

    #[test]
    fn enumerate_cross_product_fields() {
        let fields = vec![
            MessageFieldInfo {
                name: "a".into(),
                domain: FieldDomain::Bool,
            },
            MessageFieldInfo {
                name: "b".into(),
                domain: FieldDomain::Enum(vec!["x".into(), "y".into(), "z".into()]),
            },
        ];
        let results = enumerate_field_values(&fields);
        assert_eq!(results.len(), 6);
    }

    #[test]
    fn build_message_infos_simple_no_fields() {
        let messages = vec![ast::MessageDecl {
            name: "Echo".into(),
            fields: vec![],
            span: ast::Span { start: 0, end: 0 },
        }];
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        let infos =
            build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Exact).unwrap();
        assert_eq!(infos.len(), 1);
        assert!(infos["Echo"].fields.is_empty());
    }

    #[test]
    fn build_message_infos_bool_field() {
        let messages = vec![ast::MessageDecl {
            name: "Vote".into(),
            fields: vec![ast::FieldDef {
                name: "value".into(),
                ty: "bool".into(),
                range: None,
            }],
            span: ast::Span { start: 0, end: 0 },
        }];
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        let infos =
            build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Exact).unwrap();
        assert_eq!(infos["Vote"].fields.len(), 1);
        assert!(matches!(infos["Vote"].fields[0].domain, FieldDomain::Bool));
    }

    #[test]
    fn build_message_infos_nat_exact_requires_range() {
        let messages = vec![ast::MessageDecl {
            name: "Msg".into(),
            fields: vec![ast::FieldDef {
                name: "x".into(),
                ty: "nat".into(),
                range: None,
            }],
            span: ast::Span { start: 0, end: 0 },
        }];
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Exact).is_err());
    }

    #[test]
    fn build_message_infos_nat_sign_no_range_defaults() {
        let messages = vec![ast::MessageDecl {
            name: "Msg".into(),
            fields: vec![ast::FieldDef {
                name: "x".into(),
                ty: "nat".into(),
                range: None,
            }],
            span: ast::Span { start: 0, end: 0 },
        }];
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        let infos = build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Sign).unwrap();
        match &infos["Msg"].fields[0].domain {
            FieldDomain::AbstractNatSign(vals) => {
                assert_eq!(*vals, vec!["zero".to_string(), "pos".to_string()]);
            }
            other => panic!("expected AbstractNatSign, got {:?}", other),
        }
    }

    #[test]
    fn build_message_infos_enum_field() {
        let messages = vec![ast::MessageDecl {
            name: "Msg".into(),
            fields: vec![ast::FieldDef {
                name: "view".into(),
                ty: "View".into(),
                range: None,
            }],
            span: ast::Span { start: 0, end: 0 },
        }];
        let mut enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        enum_defs.insert("View".into(), vec!["v0".into(), "v1".into()]);
        let infos =
            build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Exact).unwrap();
        match &infos["Msg"].fields[0].domain {
            FieldDomain::Enum(variants) => {
                assert_eq!(*variants, vec!["v0".to_string(), "v1".to_string()]);
            }
            other => panic!("expected Enum, got {:?}", other),
        }
    }

    #[test]
    fn build_message_infos_unknown_enum_error() {
        let messages = vec![ast::MessageDecl {
            name: "Msg".into(),
            fields: vec![ast::FieldDef {
                name: "view".into(),
                ty: "UnknownType".into(),
                range: None,
            }],
            span: ast::Span { start: 0, end: 0 },
        }];
        let enum_defs: IndexMap<String, Vec<String>> = IndexMap::new();
        assert!(build_message_infos(&messages, &enum_defs, ValueAbstractionMode::Exact).is_err());
    }
}
