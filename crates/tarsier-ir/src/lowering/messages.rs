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
