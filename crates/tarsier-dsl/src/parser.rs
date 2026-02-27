// ParseError carries diagnostic spans and source fragments; boxing would lose
// the zero-copy benefit and complicate call sites throughout the crate.
#![allow(clippy::result_large_err)]

use pest::Parser;
use pest_derive::Parser;

use crate::ast::*;
use crate::errors::{ParseDiagnostic, ParseDiagnosticSeverity, ParseError};

#[derive(Parser)]
#[grammar = "grammar.pest"]
struct TarsierParser;

type Pair<'a> = pest::iterators::Pair<'a, Rule>;

fn span_from(pair: &Pair<'_>) -> Span {
    let s = pair.as_span();
    Span::new(s.start(), s.end())
}

fn syntax_error_at(pair: &Pair<'_>, message: impl Into<String>) -> ParseError {
    ParseError::syntax(message, span_from(pair), "", "")
}

/// Helper to extract the next child from a pest iterator, returning a descriptive
/// error instead of panicking. Used throughout the post-parse AST-building phase
/// where the grammar guarantees structure but we prefer graceful errors.
fn next_child<'a>(
    iter: &mut pest::iterators::Pairs<'a, Rule>,
    context: &str,
) -> Result<Pair<'a>, ParseError> {
    iter.next().ok_or_else(|| ParseError::MissingSection {
        section: format!("expected child in {context}"),
    })
}

/// Parse a .trs source file into an AST Program.
///
/// # Parameters
/// - `source`: UTF-8 protocol source text.
/// - `filename`: Logical filename used in diagnostics.
///
/// # Returns
/// Parsed [`Program`] or a parser error.
pub fn parse(source: &str, filename: &str) -> Result<Program, ParseError> {
    let (program, _) = parse_with_diagnostics(source, filename)?;
    Ok(program)
}

/// Parse a .trs source file into an AST Program and emit parser diagnostics.
///
/// # Parameters
/// - `source`: UTF-8 protocol source text.
/// - `filename`: Logical filename used in diagnostics.
///
/// # Returns
/// Parsed [`Program`] plus non-fatal diagnostics, or a parser error.
pub fn parse_with_diagnostics(
    source: &str,
    filename: &str,
) -> Result<(Program, Vec<ParseDiagnostic>), ParseError> {
    let pairs = TarsierParser::parse(Rule::program, source).map_err(|e| {
        let (start, end) = match e.location {
            pest::error::InputLocation::Pos(p) => (p, p + 1),
            pest::error::InputLocation::Span((s, e)) => (s, e),
        };
        ParseError::syntax(format!("{e}"), Span::new(start, end), source, filename)
    })?;

    let program_pair = pairs
        .into_iter()
        .next()
        .ok_or_else(|| ParseError::MissingSection {
            section: "program".into(),
        })?;
    let protocol_pair = program_pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::protocol_decl)
        .ok_or_else(|| ParseError::MissingSection {
            section: "protocol".into(),
        })?;

    let protocol = parse_protocol(protocol_pair, source, filename)
        .map_err(|e| e.with_source_context(source, filename))?;
    let program = Program { protocol };
    let diagnostics = collect_parser_diagnostics(&program);
    Ok((program, diagnostics))
}

fn collect_parser_diagnostics(program: &Program) -> Vec<ParseDiagnostic> {
    let proto = &program.protocol.node;
    let model = proto
        .adversary
        .iter()
        .find(|item| item.key == "model")
        .map(|item| item.value.as_str())
        .unwrap_or("byzantine");
    let network = proto
        .adversary
        .iter()
        .find(|item| item.key == "network" || item.key == "network_semantics")
        .map(|item| item.value.as_str())
        .unwrap_or("classic");
    let uses_distinct = proto.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase.node.transitions.iter().any(|tr| {
                fn has_distinct(g: &GuardExpr) -> bool {
                    match g {
                        GuardExpr::Threshold(t) => t.distinct,
                        GuardExpr::And(l, r) | GuardExpr::Or(l, r) => {
                            has_distinct(l) || has_distinct(r)
                        }
                        _ => false,
                    }
                }
                has_distinct(&tr.node.guard)
            })
        })
    });
    let uses_recipient_targeting = proto.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase.node.transitions.iter().any(|tr| {
                tr.node.actions.iter().any(|action| {
                    matches!(
                        action,
                        Action::Send {
                            recipient_role: Some(_),
                            ..
                        } | Action::FormCryptoObject {
                            recipient_role: Some(_),
                            ..
                        }
                    )
                })
            })
        })
    });
    let legacy_network = matches!(network, "classic" | "counter" | "legacy");

    let mut diagnostics = Vec::new();
    if model == "byzantine" && legacy_network && (uses_recipient_targeting || uses_distinct) {
        diagnostics.push(ParseDiagnostic {
            code: "legacy_counter_ambiguous_model".into(),
            severity: ParseDiagnosticSeverity::Warning,
            message: "Model relies on legacy counter semantics (`network: classic`) while using \
                      recipient-scoped messaging or distinct-sender logic. This can hide selective Byzantine behavior."
                .into(),
            suggestion: Some(
                "Set `adversary { network: identity_selective|cohort_selective|process_selective; \
                 auth: signed; }` and add explicit `identity` declarations."
                    .into(),
            ),
            span: Some(program.protocol.span),
        });
    }

    diagnostics
}

fn parse_protocol(
    pair: Pair<'_>,
    source: &str,
    filename: &str,
) -> Result<Spanned<ProtocolDecl>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "protocol name")?
        .as_str()
        .to_string();

    let mut imports = Vec::new();
    let mut modules = Vec::new();
    let mut parameters = Vec::new();
    let mut enums = Vec::new();
    let mut resilience = None;
    let mut pacemaker = None;
    let mut adversary = Vec::new();
    let mut identities = Vec::new();
    let mut channels = Vec::new();
    let mut equivocation_policies = Vec::new();
    let mut committees = Vec::new();
    let mut messages = Vec::new();
    let mut crypto_objects = Vec::new();
    let mut roles = Vec::new();
    let mut properties = Vec::new();
    let mut semantic_errors: Vec<ParseError> = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::import_decl => {
                imports.push(parse_import(item)?);
            }
            Rule::module_decl => match parse_module(item, source, filename) {
                Ok(m) => modules.push(m),
                Err(e @ ParseError::UnsupportedInModule { .. }) => {
                    semantic_errors.push(e);
                }
                Err(e) => return Err(e),
            },
            Rule::parameters_decl => {
                parameters = parse_parameters(item)?;
            }
            Rule::enum_decl => {
                enums.push(parse_enum(item)?);
            }
            Rule::resilience_decl => {
                resilience = Some(parse_resilience(item)?);
            }
            Rule::pacemaker_decl => {
                pacemaker = Some(parse_pacemaker(item, source, filename)?);
            }
            Rule::adversary_decl => {
                adversary = parse_adversary_collecting(item, &mut semantic_errors)?;
            }
            Rule::identity_decl => {
                identities.push(parse_identity(item)?);
            }
            Rule::channel_decl => {
                channels.push(parse_channel(item)?);
            }
            Rule::equivocation_decl => {
                equivocation_policies.push(parse_equivocation(item)?);
            }
            Rule::committee_decl => {
                committees.push(parse_committee(item)?);
            }
            Rule::message_decl => {
                messages.push(parse_message(item)?);
            }
            Rule::crypto_object_decl => {
                crypto_objects.push(parse_crypto_object(item)?);
            }
            Rule::role_decl => {
                roles.push(parse_role(item)?);
            }
            Rule::property_decl => {
                properties.push(parse_property(item)?);
            }
            _ => {}
        }
    }

    if !semantic_errors.is_empty() {
        // If there's only one error, return it directly for backward compatibility.
        if semantic_errors.len() == 1 {
            return Err(semantic_errors.into_iter().next().expect("len checked"));
        }
        return Err(ParseError::MultipleErrors(crate::errors::ParseErrors {
            errors: semantic_errors,
        }));
    }

    Ok(Spanned::new(
        ProtocolDecl {
            name,
            imports,
            modules,
            enums,
            parameters,
            resilience,
            pacemaker,
            adversary,
            identities,
            channels,
            equivocation_policies,
            committees,
            messages,
            crypto_objects,
            roles,
            properties,
        },
        span,
    ))
}

fn parse_import(pair: Pair<'_>) -> Result<ImportDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let path_raw = next_child(&mut inner, "inner")?.as_str();
    // Strip surrounding quotes from string_literal
    let path = path_raw
        .strip_prefix('"')
        .and_then(|s: &str| s.strip_suffix('"'))
        .unwrap_or(path_raw)
        .to_string();
    Ok(ImportDecl { name, path, span })
}

fn parse_module(pair: Pair<'_>, _source: &str, _filename: &str) -> Result<ModuleDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();

    let mut interface = None;
    let mut parameters = Vec::new();
    let mut resilience = None;
    let mut adversary = Vec::new();
    let mut messages = Vec::new();
    let mut roles = Vec::new();
    let mut properties = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::module_interface => {
                interface = Some(parse_module_interface(item)?);
            }
            Rule::parameters_decl => {
                parameters = parse_parameters(item)?;
            }
            Rule::resilience_decl => {
                resilience = Some(parse_resilience(item)?);
            }
            Rule::adversary_decl => {
                adversary = parse_adversary(item)?;
            }
            Rule::message_decl => {
                messages.push(parse_message(item)?);
            }
            Rule::role_decl => {
                roles.push(parse_role(item)?);
            }
            Rule::property_decl => {
                properties.push(parse_property(item)?);
            }
            Rule::import_decl
            | Rule::enum_decl
            | Rule::crypto_object_decl
            | Rule::committee_decl
            | Rule::channel_decl
            | Rule::equivocation_decl
            | Rule::identity_decl
            | Rule::pacemaker_decl => {
                let span = span_from(&item);
                let rule_name = format!("{:?}", item.as_rule());
                return Err(ParseError::UnsupportedInModule {
                    item_kind: rule_name,
                    span: (span.start, span.end - span.start).into(),
                    src: miette::NamedSource::new("", String::new()),
                });
            }
            _ => {}
        }
    }

    Ok(ModuleDecl {
        name,
        interface,
        items: ModuleItems {
            parameters,
            resilience,
            adversary,
            messages,
            roles,
            properties,
        },
        span,
    })
}

fn parse_module_interface(pair: Pair<'_>) -> Result<ModuleInterface, ParseError> {
    let mut assumptions = Vec::new();
    let mut guarantees = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::assumes_clause => {
                let span = span_from(&item);
                let mut inner = item.into_inner();
                let lhs = parse_linear_expr(next_child(&mut inner, "inner")?)?;
                let op = parse_cmp_op(next_child(&mut inner, "inner")?);
                let rhs = parse_linear_expr(next_child(&mut inner, "inner")?)?;
                assumptions.push(InterfaceAssumption { lhs, op, rhs, span });
            }
            Rule::guarantees_clause => {
                let span = span_from(&item);
                let mut inner = item.into_inner();
                let kind_pair = next_child(&mut inner, "inner")?;
                let kind = match kind_pair.as_str() {
                    "agreement" => PropertyKind::Agreement,
                    "validity" => PropertyKind::Validity,
                    "safety" => PropertyKind::Safety,
                    "invariant" => PropertyKind::Invariant,
                    "liveness" => PropertyKind::Liveness,
                    other => unreachable!("grammar produced unknown property kind: {other:?}"),
                };
                let property_name = next_child(&mut inner, "inner")?.as_str().to_string();
                guarantees.push(InterfaceGuarantee {
                    kind,
                    property_name,
                    span,
                });
            }
            _ => {}
        }
    }

    Ok(ModuleInterface {
        assumptions,
        guarantees,
    })
}

fn parse_enum(pair: Pair<'_>) -> Result<EnumDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let mut variants = Vec::new();
    for item in inner {
        if item.as_rule() == Rule::ident {
            variants.push(item.as_str().to_string());
        }
    }
    Ok(EnumDecl {
        name,
        variants,
        span,
    })
}

fn parse_parameters(pair: Pair<'_>) -> Result<Vec<ParamDef>, ParseError> {
    let mut params = Vec::new();
    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::param_def => {
                let span = span_from(&item);
                let mut inner = item.into_inner();
                let name = next_child(&mut inner, "inner")?.as_str().to_string();
                let ty = match next_child(&mut inner, "inner")?.as_str() {
                    "nat" => ParamType::Nat,
                    "int" => ParamType::Int,
                    _ => ParamType::Nat,
                };
                params.push(ParamDef { name, ty, span });
            }
            Rule::param_list => {
                for entry in item.into_inner() {
                    if entry.as_rule() == Rule::param_list_item {
                        let span = span_from(&entry);
                        let mut inner = entry.into_inner();
                        let name = next_child(&mut inner, "inner")?.as_str().to_string();
                        let ty = match inner.next().map(|p| p.as_str()) {
                            Some("int") => ParamType::Int,
                            _ => ParamType::Nat, // default
                        };
                        params.push(ParamDef { name, ty, span });
                    }
                }
            }
            Rule::param_list_item => {
                let span = span_from(&item);
                let mut inner = item.into_inner();
                let name = next_child(&mut inner, "inner")?.as_str().to_string();
                let ty = match inner.next().map(|p| p.as_str()) {
                    Some("int") => ParamType::Int,
                    _ => ParamType::Nat, // default
                };
                params.push(ParamDef { name, ty, span });
            }
            _ => {}
        }
    }
    Ok(params)
}

fn parse_resilience(pair: Pair<'_>) -> Result<ResilienceDecl, ParseError> {
    let span = span_from(&pair);
    let expr_pair = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::resilience_expr)
        .ok_or_else(|| ParseError::MissingSection {
            section: "resilience_expr".into(),
        })?;
    let mut inner = expr_pair.into_inner();
    let lhs = parse_linear_expr(next_child(&mut inner, "inner")?)?;
    let op = parse_cmp_op(next_child(&mut inner, "inner")?);
    let rhs = parse_linear_expr(next_child(&mut inner, "inner")?)?;
    Ok(ResilienceDecl {
        condition: ResilienceExpr { lhs, op, rhs },
        span,
    })
}

fn parse_pacemaker(
    pair: Pair<'_>,
    source: &str,
    filename: &str,
) -> Result<PacemakerDecl, ParseError> {
    let span = span_from(&pair);
    let mut view_var = None;
    let mut start_phase = None;
    let mut reset_vars: Vec<String> = Vec::new();

    for item in pair.into_inner() {
        if item.as_rule() != Rule::pacemaker_item {
            continue;
        }
        let mut inner = item.into_inner();
        let key = next_child(&mut inner, "inner")?.as_str();
        let list = next_child(&mut inner, "inner")?;
        let values: Vec<String> = list
            .into_inner()
            .filter(|p: &Pair<'_>| p.as_rule() == Rule::ident)
            .map(|p: Pair<'_>| p.as_str().to_string())
            .collect();
        match key {
            "view" => {
                if values.len() != 1 {
                    return Err(ParseError::syntax(
                        "pacemaker view expects a single variable",
                        span,
                        source,
                        filename,
                    ));
                }
                view_var = Some(values[0].clone());
            }
            "start" => {
                if values.len() != 1 {
                    return Err(ParseError::syntax(
                        "pacemaker start expects a single phase",
                        span,
                        source,
                        filename,
                    ));
                }
                start_phase = Some(values[0].clone());
            }
            "reset" => {
                reset_vars.extend(values);
            }
            _ => {
                return Err(ParseError::syntax(
                    format!("unknown pacemaker key '{key}'"),
                    span,
                    source,
                    filename,
                ));
            }
        }
    }

    let view_var = view_var.ok_or_else(|| {
        ParseError::syntax("pacemaker missing view variable", span, source, filename)
    })?;
    let start_phase = start_phase.ok_or_else(|| {
        ParseError::syntax("pacemaker missing start phase", span, source, filename)
    })?;

    Ok(PacemakerDecl {
        view_var,
        start_phase,
        reset_vars,
    })
}

const KNOWN_ADVERSARY_KEYS: &[&str] = &[
    "model",
    "bound",
    "timing",
    "values",
    "value_abstraction",
    "auth",
    "authentication",
    "network",
    "equivocation",
    "delivery",
    "delivery_scope",
    "faults",
    "fault_scope",
    "fault_budget",
    "por",
    "por_mode",
    "compromise",
    "compromised",
    "compromised_key",
    "compromised_keys",
    "gst",
];

fn parse_adversary(pair: Pair<'_>) -> Result<Vec<AdversaryItem>, ParseError> {
    let mut errors = Vec::new();
    let items = parse_adversary_collecting(pair, &mut errors)?;
    if let Some(err) = errors.into_iter().next() {
        return Err(err);
    }
    Ok(items)
}

/// Parse adversary items, collecting `InvalidField` errors into `errors` instead
/// of returning on the first one. Irrecoverable errors still short-circuit.
fn parse_adversary_collecting(
    pair: Pair<'_>,
    errors: &mut Vec<ParseError>,
) -> Result<Vec<AdversaryItem>, ParseError> {
    let mut items = Vec::new();
    for item in pair.into_inner() {
        if item.as_rule() == Rule::adversary_item {
            let span = span_from(&item);
            let mut inner = item.into_inner();
            let key = next_child(&mut inner, "adversary key")?
                .as_str()
                .to_string();
            let value = next_child(&mut inner, "adversary value")?
                .as_str()
                .to_string();
            if !KNOWN_ADVERSARY_KEYS.contains(&key.as_str()) {
                errors.push(ParseError::InvalidField {
                    field: key,
                    context: "adversary block".to_string(),
                    span: (span.start, span.end - span.start).into(),
                    src: miette::NamedSource::new("", String::new()),
                });
                continue;
            }
            items.push(AdversaryItem { key, value, span });
        }
    }
    Ok(items)
}

fn parse_identity(pair: Pair<'_>) -> Result<IdentityDecl, ParseError> {
    let span = span_from(&pair);
    let mut role = None;
    let mut scope = IdentityScope::Role;
    let mut process_var = None;
    let mut key = None;

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::ident => {
                if role.is_none() {
                    role = Some(item.as_str().to_string());
                } else if key.is_none() {
                    key = Some(item.as_str().to_string());
                }
            }
            Rule::identity_mode => {
                if item.as_str().trim_start().starts_with("process") {
                    scope = IdentityScope::Process;
                    let pid = item.into_inner().next().ok_or_else(|| {
                        ParseError::syntax(
                            "identity process(...) requires a variable",
                            span,
                            "",
                            "",
                        )
                    })?;
                    process_var = Some(pid.as_str().to_string());
                } else {
                    scope = IdentityScope::Role;
                }
            }
            _ => {}
        }
    }

    let role = role.ok_or_else(|| ParseError::syntax("identity missing role", span, "", ""))?;
    if scope == IdentityScope::Process && process_var.is_none() {
        return Err(ParseError::syntax(
            "identity process(...) requires a process variable",
            span,
            "",
            "",
        ));
    }

    Ok(IdentityDecl {
        role,
        scope,
        process_var,
        key,
        span,
    })
}

fn parse_channel(pair: Pair<'_>) -> Result<ChannelDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let message = inner
        .next()
        .ok_or_else(|| ParseError::syntax("channel missing message", span, "", ""))?
        .as_str()
        .to_string();
    let auth_pair = inner
        .next()
        .ok_or_else(|| ParseError::syntax("channel missing auth mode", span, "", ""))?;
    let auth = match auth_pair.as_str() {
        "authenticated" | "signed" => ChannelAuthMode::Authenticated,
        "unauthenticated" | "unsigned" => ChannelAuthMode::Unauthenticated,
        other => {
            return Err(ParseError::syntax(
                format!("unsupported channel auth mode '{other}'"),
                span_from(&auth_pair),
                "",
                "",
            ));
        }
    };
    Ok(ChannelDecl {
        message,
        auth,
        span,
    })
}

fn parse_equivocation(pair: Pair<'_>) -> Result<EquivocationDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let message = inner
        .next()
        .ok_or_else(|| ParseError::syntax("equivocation missing message", span, "", ""))?
        .as_str()
        .to_string();
    let mode_pair = inner
        .next()
        .ok_or_else(|| ParseError::syntax("equivocation missing mode", span, "", ""))?;
    let mode = match mode_pair.as_str() {
        "full" => EquivocationPolicyMode::Full,
        "none" => EquivocationPolicyMode::None,
        other => {
            return Err(ParseError::syntax(
                format!("unsupported equivocation mode '{other}'"),
                span_from(&mode_pair),
                "",
                "",
            ));
        }
    };
    Ok(EquivocationDecl {
        message,
        mode,
        span,
    })
}

fn parse_committee(pair: Pair<'_>) -> Result<CommitteeDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let mut items = Vec::new();

    for item in inner {
        if item.as_rule() == Rule::committee_item {
            let item_span = span_from(&item);
            let mut ci = item.into_inner();
            let key = next_child(&mut ci, "ci")?.as_str().to_string();
            let value_pair = next_child(&mut ci, "ci")?;
            let value = match value_pair.as_rule() {
                Rule::float_literal => {
                    let f: f64 = value_pair.as_str().parse().map_err(|e| {
                        ParseError::syntax(
                            format!("Invalid float literal: {e}"),
                            span_from(&value_pair),
                            "",
                            "",
                        )
                    })?;
                    CommitteeValue::Float(f)
                }
                Rule::int_literal => {
                    let n: i64 = value_pair.as_str().parse().map_err(|e| {
                        ParseError::syntax(
                            format!("Invalid int literal: {e}"),
                            span_from(&value_pair),
                            "",
                            "",
                        )
                    })?;
                    CommitteeValue::Int(n)
                }
                Rule::ident => CommitteeValue::Param(value_pair.as_str().to_string()),
                other => {
                    return Err(ParseError::syntax(
                        format!("Unexpected committee value rule: {:?}", other),
                        span_from(&value_pair),
                        "",
                        "",
                    ));
                }
            };
            items.push(CommitteeItem {
                key,
                value,
                span: item_span,
            });
        }
    }

    Ok(CommitteeDecl { name, items, span })
}

fn parse_message(pair: Pair<'_>) -> Result<MessageDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let mut fields = Vec::new();
    for item in inner {
        if item.as_rule() == Rule::field_list {
            for field in item.into_inner() {
                if field.as_rule() == Rule::field {
                    let mut fi = field.into_inner();
                    let fname = next_child(&mut fi, "fi")?.as_str().to_string();
                    let ftype = next_child(&mut fi, "fi")?.as_str().to_string();
                    let mut range = None;
                    for extra in fi {
                        if extra.as_rule() == Rule::var_range {
                            let mut r = extra.into_inner();
                            let min: i64 = r
                                .next()
                                .ok_or_else(|| {
                                    ParseError::syntax(
                                        "Missing lower bound in field range",
                                        span,
                                        "",
                                        "",
                                    )
                                })?
                                .as_str()
                                .parse()
                                .map_err(|e| {
                                    ParseError::syntax(
                                        format!("Invalid lower field-range bound: {e}"),
                                        span,
                                        "",
                                        "",
                                    )
                                })?;
                            let max: i64 = r
                                .next()
                                .ok_or_else(|| {
                                    ParseError::syntax(
                                        "Missing upper bound in field range",
                                        span,
                                        "",
                                        "",
                                    )
                                })?
                                .as_str()
                                .parse()
                                .map_err(|e| {
                                    ParseError::syntax(
                                        format!("Invalid upper field-range bound: {e}"),
                                        span,
                                        "",
                                        "",
                                    )
                                })?;
                            range = Some(VarRange { min, max });
                        }
                    }
                    fields.push(FieldDef {
                        name: fname,
                        ty: ftype,
                        range,
                    });
                }
            }
        }
    }
    Ok(MessageDecl { name, fields, span })
}

fn parse_crypto_object(pair: Pair<'_>) -> Result<CryptoObjectDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let kind = match inner.next().map(|p| p.as_str()) {
        Some("threshold_signature") => CryptoObjectKind::ThresholdSignature,
        _ => CryptoObjectKind::QuorumCertificate,
    };
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let source_message = next_child(&mut inner, "inner")?.as_str().to_string();
    let threshold = parse_linear_expr(next_child(&mut inner, "inner")?)?;
    let mut signer_role = None;
    let mut conflict_policy = CryptoConflictPolicy::Allow;
    for item in inner {
        match item.as_rule() {
            Rule::ident => {
                if signer_role.is_some() {
                    return Err(ParseError::syntax(
                        "Duplicate signer role in crypto object declaration",
                        span,
                        "",
                        "",
                    ));
                }
                signer_role = Some(item.as_str().to_string());
            }
            Rule::crypto_conflict_policy => {
                conflict_policy = match item.as_str() {
                    "allow" => CryptoConflictPolicy::Allow,
                    "exclusive" => CryptoConflictPolicy::Exclusive,
                    other => {
                        return Err(ParseError::syntax(
                            format!("Unknown crypto conflict policy '{other}'"),
                            span,
                            "",
                            "",
                        ))
                    }
                };
            }
            _ => {}
        }
    }
    Ok(CryptoObjectDecl {
        name,
        kind,
        source_message,
        threshold,
        signer_role,
        conflict_policy,
        span,
    })
}

fn parse_role(pair: Pair<'_>) -> Result<Spanned<RoleDecl>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let mut vars = Vec::new();
    let mut init_phase = None;
    let mut phases = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::var_decl => vars.push(parse_var_decl(item)?),
            Rule::init_decl => {
                init_phase = Some(
                    next_child(&mut item.into_inner(), "init_decl")?
                        .as_str()
                        .to_string(),
                );
            }
            Rule::phase_decl => phases.push(parse_phase(item)?),
            _ => {}
        }
    }

    Ok(Spanned::new(
        RoleDecl {
            name,
            vars,
            init_phase,
            phases,
        },
        span,
    ))
}

fn parse_var_decl(pair: Pair<'_>) -> Result<VarDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let ty_pair = next_child(&mut inner, "inner")?;
    let ty = match ty_pair.as_str() {
        "bool" => VarType::Bool,
        "nat" => VarType::Nat,
        "int" => VarType::Int,
        other => VarType::Enum(other.to_string()),
    };
    let mut range = None;
    let mut init = None;
    for item in inner {
        match item.as_rule() {
            Rule::var_range => {
                let mut r = item.into_inner();
                let min = r
                    .next()
                    .ok_or_else(|| {
                        ParseError::syntax("Missing lower bound in variable range", span, "", "")
                    })?
                    .as_str()
                    .parse::<i64>()
                    .map_err(|e| {
                        ParseError::syntax(format!("Invalid lower range bound: {e}"), span, "", "")
                    })?;
                let max = r
                    .next()
                    .ok_or_else(|| {
                        ParseError::syntax("Missing upper bound in variable range", span, "", "")
                    })?
                    .as_str()
                    .parse::<i64>()
                    .map_err(|e| {
                        ParseError::syntax(format!("Invalid upper range bound: {e}"), span, "", "")
                    })?;
                range = Some(VarRange { min, max });
            }
            Rule::expr => {
                init = Some(parse_expr(item)?);
            }
            _ => {}
        }
    }
    Ok(VarDecl {
        name,
        ty,
        range,
        init,
        span,
    })
}

fn parse_phase(pair: Pair<'_>) -> Result<Spanned<PhaseDecl>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let mut transitions = Vec::new();
    for item in inner {
        if item.as_rule() == Rule::transition_rule {
            transitions.push(parse_transition(item)?);
        }
    }
    Ok(Spanned::new(PhaseDecl { name, transitions }, span))
}

fn parse_transition(pair: Pair<'_>) -> Result<Spanned<TransitionRule>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let guard_pair = next_child(&mut inner, "inner")?;
    let guard = parse_guard_expr(guard_pair)?;

    let mut actions = Vec::new();
    for item in inner {
        match item.as_rule() {
            Rule::send_action => {
                let mut si = item.into_inner();
                let msg = next_child(&mut si, "si")?.as_str().to_string();
                let mut args = Vec::new();
                let mut recipient_role = None;
                for sub in si {
                    match sub.as_rule() {
                        Rule::arg_list => {
                            for arg in sub.into_inner() {
                                args.push(parse_send_arg(arg)?);
                            }
                        }
                        Rule::ident => {
                            recipient_role = Some(sub.as_str().to_string());
                        }
                        _ => {}
                    }
                }
                actions.push(Action::Send {
                    message_type: msg,
                    args,
                    recipient_role,
                });
            }
            Rule::form_crypto_action => {
                let mut si = item.into_inner();
                let object_name = next_child(&mut si, "si")?.as_str().to_string();
                let mut args = Vec::new();
                let mut recipient_role = None;
                for sub in si {
                    match sub.as_rule() {
                        Rule::arg_list => {
                            for arg in sub.into_inner() {
                                args.push(parse_send_arg(arg)?);
                            }
                        }
                        Rule::ident => {
                            recipient_role = Some(sub.as_str().to_string());
                        }
                        _ => {}
                    }
                }
                actions.push(Action::FormCryptoObject {
                    object_name,
                    args,
                    recipient_role,
                });
            }
            Rule::lock_crypto_action => {
                let mut si = item.into_inner();
                let object_name = next_child(&mut si, "si")?.as_str().to_string();
                let mut args = Vec::new();
                for sub in si {
                    if sub.as_rule() == Rule::arg_list {
                        for arg in sub.into_inner() {
                            args.push(parse_send_arg(arg)?);
                        }
                    }
                }
                actions.push(Action::LockCryptoObject { object_name, args });
            }
            Rule::justify_crypto_action => {
                let mut si = item.into_inner();
                let object_name = next_child(&mut si, "si")?.as_str().to_string();
                let mut args = Vec::new();
                for sub in si {
                    if sub.as_rule() == Rule::arg_list {
                        for arg in sub.into_inner() {
                            args.push(parse_send_arg(arg)?);
                        }
                    }
                }
                actions.push(Action::JustifyCryptoObject { object_name, args });
            }
            Rule::assign_action => {
                let mut si = item.into_inner();
                let var = next_child(&mut si, "si")?.as_str().to_string();
                let value = parse_expr(next_child(&mut si, "si")?)?;
                actions.push(Action::Assign { var, value });
            }
            Rule::goto_action => {
                let phase = next_child(&mut item.into_inner(), "goto_action")?
                    .as_str()
                    .to_string();
                actions.push(Action::GotoPhase { phase });
            }
            Rule::decide_action => {
                let value = parse_expr(next_child(&mut item.into_inner(), "decide_action")?)?;
                actions.push(Action::Decide { value });
            }
            _ => {}
        }
    }

    Ok(Spanned::new(TransitionRule { guard, actions }, span))
}

fn parse_send_arg(pair: Pair<'_>) -> Result<SendArg, ParseError> {
    match pair.as_rule() {
        Rule::arg => {
            let inner = next_child(&mut pair.into_inner(), "arg")?;
            parse_send_arg(inner)
        }
        Rule::named_arg => {
            let mut inner = pair.into_inner();
            let name = next_child(&mut inner, "inner")?.as_str().to_string();
            let value = parse_expr(next_child(&mut inner, "inner")?)?;
            Ok(SendArg::Named { name, value })
        }
        _ => Ok(SendArg::Positional(parse_expr(pair)?)),
    }
}

fn parse_guard_expr(pair: Pair<'_>) -> Result<GuardExpr, ParseError> {
    let mut inner = pair.into_inner();
    let first = next_child(&mut inner, "inner")?;
    let mut result = parse_guard_atom(first)?;

    while let Some(op_pair) = inner.next() {
        let op = op_pair.as_str();
        let next = next_child(&mut inner, "inner")?;
        let rhs = parse_guard_atom(next)?;
        result = match op {
            "&&" => GuardExpr::And(Box::new(result), Box::new(rhs)),
            "||" => GuardExpr::Or(Box::new(result), Box::new(rhs)),
            _ => result,
        };
    }

    Ok(result)
}

fn parse_guard_atom(pair: Pair<'_>) -> Result<GuardExpr, ParseError> {
    match pair.as_rule() {
        Rule::threshold_guard => {
            let span = span_from(&pair);
            let inner = pair.into_inner();
            let mut distinct = false;
            let mut op = None;
            let mut threshold = None;
            let mut message_type = None;
            let mut message_args = Vec::new();
            for item in inner {
                match item.as_rule() {
                    Rule::distinct_kw => {
                        distinct = true;
                    }
                    Rule::cmp_op => {
                        op = Some(parse_cmp_op(item));
                    }
                    Rule::linear_expr_no_implicit | Rule::linear_expr => {
                        threshold = Some(parse_linear_expr(item)?);
                    }
                    Rule::ident => {
                        message_type = Some(item.as_str().to_string());
                    }
                    Rule::msg_filter => {
                        for filter in item.into_inner() {
                            match filter.as_rule() {
                                Rule::msg_filter_list => {
                                    for arg in filter.into_inner() {
                                        if arg.as_rule() == Rule::msg_filter_item {
                                            let mut ai = arg.into_inner();
                                            let name =
                                                next_child(&mut ai, "ai")?.as_str().to_string();
                                            let value = parse_expr(next_child(&mut ai, "ai")?)?;
                                            message_args.push((name, value));
                                        }
                                    }
                                }
                                Rule::msg_filter_item => {
                                    let mut ai = filter.into_inner();
                                    let name = next_child(&mut ai, "ai")?.as_str().to_string();
                                    let value = parse_expr(next_child(&mut ai, "ai")?)?;
                                    message_args.push((name, value));
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            let op = op.ok_or_else(|| {
                ParseError::syntax(
                    "Missing comparison operator in threshold guard",
                    span,
                    "",
                    "",
                )
            })?;
            let threshold = threshold.ok_or_else(|| {
                ParseError::syntax("Missing threshold expression in guard", span, "", "")
            })?;
            let message_type = message_type
                .ok_or_else(|| ParseError::syntax("Missing message type in guard", span, "", ""))?;
            Ok(GuardExpr::Threshold(ThresholdGuard {
                op,
                threshold,
                message_type,
                message_args,
                distinct,
                distinct_role: None,
            }))
        }
        Rule::has_crypto_guard => {
            let span = span_from(&pair);
            let mut inner = pair.into_inner();
            let object_name = inner
                .next()
                .map(|p| p.as_str().to_string())
                .ok_or_else(|| {
                    ParseError::syntax("Missing crypto object in has-guard", span, "", "")
                })?;
            let mut object_args = Vec::new();
            for item in inner {
                if item.as_rule() != Rule::msg_filter {
                    continue;
                }
                for filter in item.into_inner() {
                    match filter.as_rule() {
                        Rule::msg_filter_list => {
                            for arg in filter.into_inner() {
                                if arg.as_rule() == Rule::msg_filter_item {
                                    let mut ai = arg.into_inner();
                                    let name = next_child(&mut ai, "ai")?.as_str().to_string();
                                    let value = parse_expr(next_child(&mut ai, "ai")?)?;
                                    object_args.push((name, value));
                                }
                            }
                        }
                        Rule::msg_filter_item => {
                            let mut ai = filter.into_inner();
                            let name = next_child(&mut ai, "ai")?.as_str().to_string();
                            let value = parse_expr(next_child(&mut ai, "ai")?)?;
                            object_args.push((name, value));
                        }
                        _ => {}
                    }
                }
            }
            Ok(GuardExpr::HasCryptoObject {
                object_name,
                object_args,
            })
        }
        Rule::comparison_guard => {
            let mut inner = pair.into_inner();
            let lhs = parse_expr(next_child(&mut inner, "inner")?)?;
            let op = parse_cmp_op(next_child(&mut inner, "inner")?);
            let rhs = parse_expr(next_child(&mut inner, "inner")?)?;
            Ok(GuardExpr::Comparison { lhs, op, rhs })
        }
        Rule::bool_guard => {
            let name = next_child(&mut pair.into_inner(), "bool_guard")?
                .as_str()
                .to_string();
            Ok(GuardExpr::BoolVar(name))
        }
        Rule::guard_expr => parse_guard_expr(pair),
        _ => {
            // Try to parse as sub-expressions
            let span = span_from(&pair);
            let inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                // SAFETY: inner.len() == 1 checked above
                parse_guard_atom(inner.into_iter().next().expect("len checked"))
            } else {
                Err(ParseError::syntax(
                    format!("Unexpected guard atom shape ({} children)", inner.len()),
                    span,
                    "",
                    "",
                ))
            }
        }
    }
}

fn parse_expr(pair: Pair<'_>) -> Result<Expr, ParseError> {
    match pair.as_rule() {
        Rule::expr => {
            let mut inner = pair.into_inner();
            let first = parse_expr(next_child(&mut inner, "inner")?)?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_expr(next_child(&mut inner, "inner")?)?;
                result = match op_pair.as_str() {
                    "+" => Expr::Add(Box::new(result), Box::new(rhs)),
                    "-" => Expr::Sub(Box::new(result), Box::new(rhs)),
                    _ => result,
                };
            }
            Ok(result)
        }
        Rule::term => {
            let mut inner = pair.into_inner();
            let first = parse_expr(next_child(&mut inner, "inner")?)?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_expr(next_child(&mut inner, "inner")?)?;
                result = match op_pair.as_str() {
                    "*" => Expr::Mul(Box::new(result), Box::new(rhs)),
                    "/" => Expr::Div(Box::new(result), Box::new(rhs)),
                    _ => result,
                };
            }
            Ok(result)
        }
        Rule::unary => {
            let span = span_from(&pair);
            let inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 2 {
                let operand = parse_expr(inner[1].clone())?;
                match inner[0].as_rule() {
                    Rule::neg_op => Ok(Expr::Neg(Box::new(operand))),
                    Rule::not_op => Ok(Expr::Not(Box::new(operand))),
                    _ => Ok(operand),
                }
            } else if inner.len() == 1 {
                // SAFETY: inner.len() == 1 checked above
                parse_expr(inner.into_iter().next().expect("len checked"))
            } else {
                Err(ParseError::syntax(
                    format!(
                        "Unexpected unary expression shape ({} children)",
                        inner.len()
                    ),
                    span,
                    "",
                    "",
                ))
            }
        }
        Rule::int_literal => {
            let n: i64 = pair
                .as_str()
                .parse()
                .map_err(|e| syntax_error_at(&pair, format!("Invalid integer literal: {e}")))?;
            Ok(Expr::IntLit(n))
        }
        Rule::bool_literal => {
            let b = pair.as_str() == "true";
            Ok(Expr::BoolLit(b))
        }
        Rule::ident => Ok(Expr::Var(pair.as_str().to_string())),
        _ => {
            // Fallthrough: descend into children
            let span = span_from(&pair);
            let mut inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                parse_expr(inner.remove(0))
            } else {
                Err(ParseError::syntax(
                    format!("Unexpected expression shape ({} children)", inner.len()),
                    span,
                    "",
                    "",
                ))
            }
        }
    }
}

fn parse_linear_expr(pair: Pair<'_>) -> Result<LinearExpr, ParseError> {
    match pair.as_rule() {
        Rule::linear_expr | Rule::linear_expr_no_implicit => {
            let mut inner = pair.into_inner();
            let first = parse_linear_expr(next_child(&mut inner, "inner")?)?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_linear_expr(next_child(&mut inner, "inner")?)?;
                result = match op_pair.as_str() {
                    "+" => LinearExpr::Add(Box::new(result), Box::new(rhs)),
                    "-" => LinearExpr::Sub(Box::new(result), Box::new(rhs)),
                    _ => result,
                };
            }
            Ok(result)
        }
        Rule::linear_term | Rule::linear_term_no_implicit => {
            let span = span_from(&pair);
            let inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 2 {
                // coefficient * atom
                let coeff: i64 = inner[0].as_str().parse().map_err(|e| {
                    syntax_error_at(&inner[0], format!("Invalid linear coefficient: {e}"))
                })?;
                let atom = parse_linear_expr(inner[1].clone())?;
                Ok(LinearExpr::Mul(coeff, Box::new(atom)))
            } else if inner.len() == 1 {
                // SAFETY: inner.len() == 1 checked above
                parse_linear_expr(inner.into_iter().next().expect("len checked"))
            } else {
                Err(ParseError::syntax(
                    format!("Unexpected linear term shape ({} children)", inner.len()),
                    span,
                    "",
                    "",
                ))
            }
        }
        Rule::int_literal => {
            let n: i64 = pair
                .as_str()
                .parse()
                .map_err(|e| syntax_error_at(&pair, format!("Invalid integer literal: {e}")))?;
            Ok(LinearExpr::Const(n))
        }
        Rule::ident => Ok(LinearExpr::Var(pair.as_str().to_string())),
        _ => {
            let span = span_from(&pair);
            let mut inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                parse_linear_expr(inner.remove(0))
            } else {
                Err(ParseError::syntax(
                    format!(
                        "Unexpected linear expression shape ({} children)",
                        inner.len()
                    ),
                    span,
                    "",
                    "",
                ))
            }
        }
    }
}

fn parse_cmp_op(pair: Pair<'_>) -> CmpOp {
    match pair.as_str() {
        ">=" => CmpOp::Ge,
        "<=" => CmpOp::Le,
        ">" => CmpOp::Gt,
        "<" => CmpOp::Lt,
        "==" | "=" => CmpOp::Eq,
        "!=" => CmpOp::Ne,
        other => unreachable!("grammar produced unknown comparison operator: {other:?}"),
    }
}

fn parse_property(pair: Pair<'_>) -> Result<Spanned<PropertyDecl>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = next_child(&mut inner, "inner")?.as_str().to_string();
    let kind_pair = next_child(&mut inner, "inner")?;
    let kind = match kind_pair.as_str() {
        "agreement" => PropertyKind::Agreement,
        "validity" => PropertyKind::Validity,
        "safety" => PropertyKind::Safety,
        "invariant" => PropertyKind::Invariant,
        "liveness" => PropertyKind::Liveness,
        other => unreachable!("grammar produced unknown property kind: {other:?}"),
    };
    let formula_pair = next_child(&mut inner, "inner")?;
    let formula = parse_quantified_formula(formula_pair)?;
    Ok(Spanned::new(
        PropertyDecl {
            name,
            kind,
            formula,
        },
        span,
    ))
}

fn parse_quantified_formula(pair: Pair<'_>) -> Result<QuantifiedFormula, ParseError> {
    let inner: Vec<_> = pair.into_inner().collect();
    let mut quantifiers = Vec::new();
    let mut formula_pair = None;

    let mut i = 0;
    while i < inner.len() {
        if inner[i].as_rule() == Rule::quantifier {
            let q = match inner[i].as_str() {
                "forall" => Quantifier::ForAll,
                "exists" => Quantifier::Exists,
                other => unreachable!("grammar produced unknown quantifier: {other:?}"),
            };
            let var = inner[i + 1].as_str().to_string();
            let domain = inner[i + 2].as_str().to_string();
            quantifiers.push(QuantifierBinding {
                quantifier: q,
                var,
                domain,
            });
            i += 3;
        } else {
            formula_pair = Some(inner[i].clone());
            break;
        }
    }

    let body = if let Some(fp) = formula_pair {
        parse_formula_expr(fp)?
    } else {
        unreachable!("grammar requires a formula body in quantified formula");
    };

    Ok(QuantifiedFormula { quantifiers, body })
}

fn parse_formula_expr(pair: Pair<'_>) -> Result<FormulaExpr, ParseError> {
    match pair.as_rule() {
        Rule::formula_expr => {
            let mut inner = pair.into_inner();
            let first = parse_formula_expr(next_child(&mut inner, "inner")?)?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_formula_expr(next_child(&mut inner, "inner")?)?;
                result = match op_pair.as_str() {
                    "&&" => FormulaExpr::And(Box::new(result), Box::new(rhs)),
                    "||" => FormulaExpr::Or(Box::new(result), Box::new(rhs)),
                    "==>" => FormulaExpr::Implies(Box::new(result), Box::new(rhs)),
                    "<=>" => FormulaExpr::Iff(Box::new(result), Box::new(rhs)),
                    "U" => FormulaExpr::Until(Box::new(result), Box::new(rhs)),
                    "W" => FormulaExpr::WeakUntil(Box::new(result), Box::new(rhs)),
                    "R" => FormulaExpr::Release(Box::new(result), Box::new(rhs)),
                    "~>" => FormulaExpr::LeadsTo(Box::new(result), Box::new(rhs)),
                    _ => result,
                };
            }
            Ok(result)
        }
        Rule::formula_comparison => {
            let mut inner = pair.into_inner();
            let lhs = parse_formula_term(next_child(&mut inner, "inner")?)?;
            let op = parse_cmp_op(next_child(&mut inner, "inner")?);
            let rhs = parse_formula_term(next_child(&mut inner, "inner")?)?;
            Ok(FormulaExpr::Comparison { lhs, op, rhs })
        }
        Rule::formula_not => {
            let inner = next_child(&mut pair.into_inner(), "formula_not")?;
            let sub = parse_formula_expr(inner)?;
            Ok(FormulaExpr::Not(Box::new(sub)))
        }
        Rule::formula_temporal_prefix => {
            let mut inner = pair.into_inner();
            let op = next_child(&mut inner, "inner")?.as_str().to_string();
            let rhs = parse_formula_expr(next_child(&mut inner, "inner")?)?;
            match op.as_str() {
                "X" | "next" => Ok(FormulaExpr::Next(Box::new(rhs))),
                "[]" | "always" => Ok(FormulaExpr::Always(Box::new(rhs))),
                "<>" | "eventually" => Ok(FormulaExpr::Eventually(Box::new(rhs))),
                _ => Ok(rhs),
            }
        }
        _ => {
            let span = span_from(&pair);
            let mut inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                parse_formula_expr(inner.remove(0))
            } else {
                Err(ParseError::syntax(
                    format!(
                        "Unexpected formula expression shape ({} children)",
                        inner.len()
                    ),
                    span,
                    "",
                    "",
                ))
            }
        }
    }
}

fn parse_formula_term(pair: Pair<'_>) -> Result<FormulaAtom, ParseError> {
    match pair.as_rule() {
        Rule::int_literal => {
            let n: i64 = pair
                .as_str()
                .parse()
                .map_err(|e| syntax_error_at(&pair, format!("Invalid integer literal: {e}")))?;
            Ok(FormulaAtom::IntLit(n))
        }
        Rule::bool_literal => {
            let b = pair.as_str() == "true";
            Ok(FormulaAtom::BoolLit(b))
        }
        Rule::qualified_ident => {
            let mut inner = pair.into_inner();
            let object = next_child(&mut inner, "inner")?.as_str().to_string();
            let field = next_child(&mut inner, "inner")?.as_str().to_string();
            Ok(FormulaAtom::QualifiedVar { object, field })
        }
        Rule::ident => Ok(FormulaAtom::Var(pair.as_str().to_string())),
        _ => {
            let span = span_from(&pair);
            let mut inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                parse_formula_term(inner.remove(0))
            } else {
                Err(ParseError::syntax(
                    format!("Unexpected formula term shape ({} children)", inner.len()),
                    span,
                    "",
                    "",
                ))
            }
        }
    }
}

/// Resolve import declarations by loading and parsing imported files.
///
/// For each `import Name from "path";` in the program, this reads and parses
/// the file at `path` (resolved relative to `base_dir`) and merges its
/// protocol declarations (messages, roles, enums) into the importing program.
///
/// # Parameters
/// - `program`: Parsed program to mutate in place.
/// - `base_dir`: Directory used to resolve relative import paths.
///
/// # Returns
/// `Ok(())` when all imports are resolved and merged, or an import/parse error.
pub fn resolve_imports(
    program: &mut Program,
    base_dir: &std::path::Path,
) -> Result<(), ParseError> {
    let imports: Vec<ImportDecl> = program.protocol.node.imports.drain(..).collect();
    for import in &imports {
        let import_path = base_dir.join(&import.path);
        let source =
            std::fs::read_to_string(&import_path).map_err(|e| ParseError::ImportResolution {
                message: format!("cannot read '{}': {e}", import_path.display()),
                span: (import.span.start, import.span.end - import.span.start).into(),
                src: miette::NamedSource::new("", String::new()),
            })?;
        let filename = import_path.display().to_string();
        let imported = parse(&source, &filename)?;
        let imported_proto = imported.protocol.node;

        // Merge all declaration types from the imported protocol.
        program
            .protocol
            .node
            .messages
            .extend(imported_proto.messages);
        program.protocol.node.roles.extend(imported_proto.roles);
        program.protocol.node.enums.extend(imported_proto.enums);
        program
            .protocol
            .node
            .properties
            .extend(imported_proto.properties);
        program
            .protocol
            .node
            .parameters
            .extend(imported_proto.parameters);
        program
            .protocol
            .node
            .committees
            .extend(imported_proto.committees);
        program
            .protocol
            .node
            .channels
            .extend(imported_proto.channels);
        program
            .protocol
            .node
            .crypto_objects
            .extend(imported_proto.crypto_objects);
        program
            .protocol
            .node
            .identities
            .extend(imported_proto.identities);
        program
            .protocol
            .node
            .equivocation_policies
            .extend(imported_proto.equivocation_policies);
        if program.protocol.node.adversary.is_empty() {
            program.protocol.node.adversary = imported_proto.adversary;
        }
        if program.protocol.node.resilience.is_none() {
            program.protocol.node.resilience = imported_proto.resilience;
        }
        if program.protocol.node.pacemaker.is_none() {
            program.protocol.node.pacemaker = imported_proto.pacemaker;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_protocol() {
        let src = r#"
protocol Minimal {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    message Echo;
    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                decided = true;
                decide true;
            }
        }
    }
    property agreement: agreement {
        forall p: Process. forall q: Process.
            p.decided == q.decided
    }
}
"#;
        let result = parse(src, "test.trs");
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
        let prog = result.unwrap();
        assert_eq!(prog.protocol.node.name, "Minimal");
        assert_eq!(prog.protocol.node.parameters.len(), 2);
        assert_eq!(prog.protocol.node.roles.len(), 1);
        assert_eq!(prog.protocol.node.properties.len(), 1);
    }

    #[test]
    fn parse_threshold_guard() {
        let src = r#"
protocol T {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role P {
        init phase1;
        phase phase1 {
            when received >= 2*t+1 Vote => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let result = parse(src, "test.trs");
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
    }

    #[test]
    fn parse_threshold_guard_distinct() {
        let src = r#"
protocol T {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role P {
        init phase1;
        phase phase1 {
            when received distinct >= 2*t+1 Vote => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "test.trs").unwrap();
        let role = &prog.protocol.node.roles[0].node;
        let phase = &role.phases[0].node;
        let trans = &phase.transitions[0].node;
        match &trans.guard {
            GuardExpr::Threshold(tg) => {
                assert!(tg.distinct, "expected distinct guard");
            }
            other => panic!("Expected threshold guard, got {other:?}"),
        }
    }

    #[test]
    fn parse_send_with_recipient_role() {
        let src = r#"
protocol T {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role Leader {
        init s;
        phase s {
            when received >= 0 Vote => {
                send Vote to Replica;
                goto phase done;
            }
        }
        phase done {}
    }
    role Replica {
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "send_recipient.trs").unwrap();
        let leader = &prog.protocol.node.roles[0].node;
        let trans = &leader.phases[0].node.transitions[0].node;
        match &trans.actions[0] {
            Action::Send { recipient_role, .. } => {
                assert_eq!(recipient_role.as_deref(), Some("Replica"));
            }
            other => panic!("Expected Send action, got: {other:?}"),
        }
    }

    #[test]
    fn parse_crypto_object_declaration_and_actions() {
        let src = r#"
protocol Crypto {
    params n, t, f;
    resilience: n > 3*t;
    message Vote(view: nat in 0..3);
    certificate QC from Vote threshold 2*t+1 signer Replica;
    threshold_signature Sig from Vote threshold 2*t+1 signer Replica;
    role Replica {
        init s;
        phase s {
            when has QC(view=0) && received distinct >= 2*t+1 Vote(view=0) => {
                form QC(view=0);
                lock QC(view=0);
                justify QC(view=0);
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "crypto.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.crypto_objects.len(), 2);
        assert_eq!(
            prog.protocol.node.crypto_objects[0].conflict_policy,
            CryptoConflictPolicy::Allow
        );
        let role = &prog.protocol.node.roles[0].node;
        let trans = &role.phases[0].node.transitions[0].node;
        assert_eq!(trans.actions.len(), 4);
    }

    #[test]
    fn parse_crypto_object_conflict_policy() {
        let src = r#"
protocol CryptoPolicy {
    params n, t;
    resilience: n > 3*t;
    message Vote(value: bool);
    certificate QC from Vote threshold 2*t+1 conflicts exclusive;
    role Replica {
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "crypto_policy.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.crypto_objects.len(), 1);
        let qc = &prog.protocol.node.crypto_objects[0];
        assert_eq!(qc.name, "QC");
        assert_eq!(qc.conflict_policy, CryptoConflictPolicy::Exclusive);
    }

    #[test]
    fn parse_short_params_and_resilience() {
        let src = r#"
protocol P {
    params n, f;
    resilience: n = 3f+1;
    message M;
    role R {
        init start;
        phase start {
            when received >= 1 M => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let result = parse(src, "test.trs");
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
        let prog = result.unwrap();
        assert_eq!(prog.protocol.node.parameters.len(), 2);
        assert_eq!(prog.protocol.node.parameters[0].ty, ParamType::Nat);
        assert_eq!(prog.protocol.node.parameters[1].ty, ParamType::Nat);
    }

    #[test]
    fn parse_message_field_int_range() {
        let src = r#"
protocol MsgRange {
    params n, t;
    resilience: n > 3*t;
    message Vote(view: int in 0..2, round: nat in 0..4);
    role P {
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "msg_range.trs").unwrap();
        let msg = &prog.protocol.node.messages[0];
        assert_eq!(msg.fields.len(), 2);
        assert_eq!(msg.fields[0].name, "view");
        assert_eq!(msg.fields[0].range.as_ref().unwrap().min, 0);
        assert_eq!(msg.fields[0].range.as_ref().unwrap().max, 2);
        assert_eq!(msg.fields[1].name, "round");
        assert_eq!(msg.fields[1].range.as_ref().unwrap().max, 4);
    }

    #[test]
    fn parse_liveness_property_kind() {
        let src = r#"
protocol Live {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property term: liveness {
        forall p: R. p.decided == true
    }
}
"#;
        let prog = parse(src, "test.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.properties.len(), 1);
        assert_eq!(
            prog.protocol.node.properties[0].node.kind,
            PropertyKind::Liveness
        );
    }

    #[test]
    fn parse_temporal_liveness_formula() {
        let src = r#"
protocol Temporal {
    params n, t, f;
    resilience: n > 3*t;
    role Replica {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: Replica. [] (p.decided == true ~> <> (p.decided == true))
    }
}
"#;
        let prog = parse(src, "temporal.trs").expect("parse should succeed");
        let body = &prog.protocol.node.properties[0].node.formula.body;
        match body {
            FormulaExpr::Always(inner) => match inner.as_ref() {
                FormulaExpr::LeadsTo(_, rhs) => {
                    assert!(matches!(rhs.as_ref(), FormulaExpr::Eventually(_)));
                }
                other => panic!("expected leads-to, got {other:?}"),
            },
            other => panic!("expected always, got {other:?}"),
        }
    }

    #[test]
    fn parse_weak_until_and_release_formula() {
        let src = r#"
protocol Temporal2 {
    params n, t, f;
    resilience: n > 3*t;
    role Replica {
        var locked: bool = false;
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: Replica. (p.locked == true W p.decided == true) && (p.decided == true R p.locked == true)
    }
}
"#;
        let prog = parse(src, "temporal2.trs").expect("parse should succeed");
        let body = &prog.protocol.node.properties[0].node.formula.body;
        match body {
            FormulaExpr::And(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), FormulaExpr::WeakUntil(_, _)));
                assert!(matches!(rhs.as_ref(), FormulaExpr::Release(_, _)));
            }
            other => panic!("expected conjunction, got {other:?}"),
        }
    }

    #[test]
    fn parse_next_temporal_formula() {
        let src = r#"
protocol TemporalNext {
    params n, t, f;
    resilience: n > 3*t;
    role Replica {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property live: liveness {
        forall p: Replica. X (p.decided == false)
    }
}
"#;
        let prog = parse(src, "temporal_next.trs").expect("parse should succeed");
        let body = &prog.protocol.node.properties[0].node.formula.body;
        assert!(matches!(body, FormulaExpr::Next(_)));
    }

    #[test]
    fn parse_identity_channel_and_equivocation_declarations() {
        let src = r#"
protocol NetSemantics {
    params n, t, f;
    resilience: n > 3*t;
    identity Replica: process(pid) key replica_key;
    identity Client: role key client_key;
    channel Vote: authenticated;
    channel Request: unauthenticated;
    equivocation Vote: none;
    equivocation Request: full;
    message Vote;
    message Request;
    role Replica {
        var pid: nat in 0..2;
        init s;
        phase s {}
    }
    role Client {
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "net_semantics.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.identities.len(), 2);
        assert_eq!(prog.protocol.node.channels.len(), 2);
        assert_eq!(prog.protocol.node.equivocation_policies.len(), 2);

        let replica_id = &prog.protocol.node.identities[0];
        assert_eq!(replica_id.role, "Replica");
        assert_eq!(replica_id.scope, IdentityScope::Process);
        assert_eq!(replica_id.process_var.as_deref(), Some("pid"));
        assert_eq!(replica_id.key.as_deref(), Some("replica_key"));

        let vote_channel = &prog.protocol.node.channels[0];
        assert_eq!(vote_channel.message, "Vote");
        assert_eq!(vote_channel.auth, ChannelAuthMode::Authenticated);

        let vote_eq = &prog.protocol.node.equivocation_policies[0];
        assert_eq!(vote_eq.message, "Vote");
        assert_eq!(vote_eq.mode, EquivocationPolicyMode::None);
    }

    #[test]
    fn parse_identity_auth_and_equivocation_aliases_with_adversary_controls() {
        let src = r#"
protocol FaithfulNetConfig {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        network: process_selective;
        delivery: per_recipient;
        faults: global;
        compromised_key: replica_key;
        compromised_keys: client_key;
    }
    identity Replica: process(node_id) key replica_key;
    identity Client: role;
    channel Vote: signed;
    channel Request: unsigned;
    equivocation Vote: none;
    equivocation Request: full;
    message Vote;
    message Request;
    role Replica {
        var node_id: nat in 0..1;
        init s;
        phase s {}
    }
    role Client {
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "faithful_net_config.trs").expect("parse should succeed");
        let protocol = &prog.protocol.node;

        let adversary: std::collections::HashMap<_, _> = protocol
            .adversary
            .iter()
            .map(|item| (item.key.as_str(), item.value.as_str()))
            .collect();
        assert_eq!(adversary.get("auth"), Some(&"signed"));
        assert_eq!(adversary.get("equivocation"), Some(&"none"));
        assert_eq!(adversary.get("network"), Some(&"process_selective"));
        assert_eq!(adversary.get("delivery"), Some(&"per_recipient"));
        assert_eq!(adversary.get("faults"), Some(&"global"));
        assert_eq!(adversary.get("compromised_key"), Some(&"replica_key"));
        assert_eq!(adversary.get("compromised_keys"), Some(&"client_key"));

        let replica_id = &protocol.identities[0];
        assert_eq!(replica_id.role, "Replica");
        assert_eq!(replica_id.scope, IdentityScope::Process);
        assert_eq!(replica_id.process_var.as_deref(), Some("node_id"));
        assert_eq!(replica_id.key.as_deref(), Some("replica_key"));

        let client_id = &protocol.identities[1];
        assert_eq!(client_id.role, "Client");
        assert_eq!(client_id.scope, IdentityScope::Role);
        assert_eq!(client_id.process_var, None);
        assert_eq!(client_id.key, None);

        assert_eq!(protocol.channels[0].auth, ChannelAuthMode::Authenticated);
        assert_eq!(protocol.channels[1].auth, ChannelAuthMode::Unauthenticated);
        assert_eq!(
            protocol.equivocation_policies[0].mode,
            EquivocationPolicyMode::None
        );
        assert_eq!(
            protocol.equivocation_policies[1].mode,
            EquivocationPolicyMode::Full
        );
    }

    #[test]
    fn parse_emits_legacy_counter_ambiguity_diagnostic() {
        let src = r#"
protocol LegacyAmbiguous {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; network: classic; }
    message Vote;
    role Leader {
        init s;
        phase s {
            when received >= 0 Vote => {
                send Vote to Replica;
                goto phase s;
            }
        }
    }
    role Replica {
        init s;
        phase s {
            when received distinct >= 1 Vote => { goto phase s; }
        }
    }
}
"#;
        let (_, diags) =
            parse_with_diagnostics(src, "legacy_ambiguous.trs").expect("parse should succeed");
        assert!(
            diags
                .iter()
                .any(|d| d.code == "legacy_counter_ambiguous_model"),
            "expected legacy-counter ambiguity diagnostic"
        );
    }

    #[test]
    fn parse_negation_in_assignment() {
        let src = r#"
protocol T {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Vote;
    role P {
        var decided: bool = false;
        init phase1;
        phase phase1 {
            when received >= 1 Vote => {
                decided = !decided;
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let result = parse(src, "test.trs");
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
        let prog = result.unwrap();
        let role = &prog.protocol.node.roles[0].node;
        let transition = &role.phases[0].node.transitions[0].node;
        // Check that the assignment value is Not(Var("decided")), not just Var("decided")
        match &transition.actions[0] {
            Action::Assign { var, value } => {
                assert_eq!(var, "decided");
                assert!(
                    matches!(value, Expr::Not(inner) if matches!(inner.as_ref(), Expr::Var(v) if v == "decided")),
                    "Expected Not(Var(\"decided\")), got: {:?}",
                    value
                );
            }
            other => panic!("Expected Assign, got: {:?}", other),
        }
    }

    /// Helper: wrap a property body in a minimal parseable protocol.
    fn wrap_property(kind: &str, formula: &str) -> String {
        format!(
            r#"
protocol T {{
    parameters {{ n: nat; t: nat; }}
    resilience {{ n > 3*t; }}
    message M;
    role R {{
        var decided: bool = false;
        var x: bool = false;
        var y: bool = false;
        init a;
        phase a {{}}
    }}
    property test_prop: {kind} {{
        {formula}
    }}
}}
"#
        )
    }

    /// Parse a property formula, pretty-print it, re-parse, and compare ASTs.
    fn roundtrip_property(kind: &str, formula: &str) {
        let src = wrap_property(kind, formula);
        let prog = parse(&src, "roundtrip.trs")
            .unwrap_or_else(|e| panic!("Parse failed for formula `{formula}`: {e:?}"));
        let prop = &prog.protocol.node.properties[0].node;
        let printed = prop.formula.to_string();

        // Re-parse the printed formula.
        let src2 = wrap_property(kind, &printed);
        let prog2 = parse(&src2, "roundtrip2.trs")
            .unwrap_or_else(|e| panic!("Re-parse failed for printed `{printed}`: {e:?}"));
        let prop2 = &prog2.protocol.node.properties[0].node;

        assert_eq!(
            prop.formula, prop2.formula,
            "Round-trip mismatch:\n  original: {formula}\n  printed:  {printed}"
        );
    }

    fn parse_property_body(kind: &str, formula: &str) -> FormulaExpr {
        let src = wrap_property(kind, formula);
        let prog = parse(&src, "parse_property_body.trs")
            .unwrap_or_else(|e| panic!("Parse failed for formula `{formula}`: {e:?}"));
        prog.protocol.node.properties[0].node.formula.body.clone()
    }

    #[test]
    fn roundtrip_simple_comparison() {
        roundtrip_property("safety", "forall p: R. p.decided == true");
    }

    #[test]
    fn roundtrip_agreement() {
        roundtrip_property(
            "agreement",
            "forall p: R. forall q: R. p.decided == q.decided",
        );
    }

    #[test]
    fn roundtrip_guarded_agreement() {
        roundtrip_property(
            "agreement",
            "forall p: R. forall q: R. (p.decided == true && q.decided == true) ==> (p.x == q.x)",
        );
    }

    #[test]
    fn roundtrip_not() {
        roundtrip_property("safety", "forall p: R. !(p.decided == false)");
    }

    #[test]
    fn roundtrip_and_or() {
        roundtrip_property(
            "safety",
            "forall p: R. p.decided == true && p.x == true || p.y == true",
        );
    }

    #[test]
    fn roundtrip_implies_iff() {
        roundtrip_property("safety", "forall p: R. p.decided == true ==> p.x == true");
        roundtrip_property("safety", "forall p: R. p.decided == true <=> p.x == true");
    }

    #[test]
    fn roundtrip_always() {
        roundtrip_property("liveness", "forall p: R. [] (p.decided == true)");
    }

    #[test]
    fn roundtrip_eventually() {
        roundtrip_property("liveness", "forall p: R. <> (p.decided == true)");
    }

    #[test]
    fn roundtrip_next() {
        roundtrip_property("liveness", "forall p: R. X (p.decided == true)");
    }

    #[test]
    fn roundtrip_until() {
        roundtrip_property(
            "liveness",
            "forall p: R. (p.x == false) U (p.decided == true)",
        );
    }

    #[test]
    fn roundtrip_weak_until() {
        roundtrip_property(
            "liveness",
            "forall p: R. (p.x == false) W (p.decided == true)",
        );
    }

    #[test]
    fn roundtrip_release() {
        roundtrip_property(
            "liveness",
            "forall p: R. (p.x == false) R (p.decided == true)",
        );
    }

    #[test]
    fn roundtrip_leads_to() {
        roundtrip_property(
            "liveness",
            "forall p: R. (p.x == true) ~> <> (p.decided == true)",
        );
    }

    #[test]
    fn roundtrip_nested_temporal() {
        roundtrip_property("liveness", "forall p: R. [] <> (p.decided == true)");
    }

    #[test]
    fn roundtrip_complex_temporal() {
        roundtrip_property(
            "liveness",
            "forall p: R. (p.x == true) ~> (<> (p.decided == true) && [] (p.y == false))",
        );
    }

    #[test]
    fn roundtrip_exists_quantifier() {
        roundtrip_property("liveness", "exists p: R. <> (p.decided == true)");
    }

    #[test]
    fn roundtrip_property_kind_display() {
        use crate::ast::PropertyKind;
        assert_eq!(PropertyKind::Agreement.to_string(), "agreement");
        assert_eq!(PropertyKind::Validity.to_string(), "validity");
        assert_eq!(PropertyKind::Safety.to_string(), "safety");
        assert_eq!(PropertyKind::Invariant.to_string(), "invariant");
        assert_eq!(PropertyKind::Liveness.to_string(), "liveness");
    }

    #[test]
    fn roundtrip_property_decl_display() {
        let src = wrap_property("safety", "forall p: R. p.decided == true");
        let prog = parse(&src, "test.trs").unwrap();
        let prop = &prog.protocol.node.properties[0].node;
        let display = prop.to_string();
        assert!(display.contains("property test_prop: safety"));
        assert!(display.contains("forall p: R."));
        assert!(display.contains("p.decided == true"));
    }

    #[test]
    fn temporal_infix_ops_are_left_associative() {
        let body = parse_property_body(
            "liveness",
            "forall p: R. p.x == true U p.y == true R p.decided == true",
        );
        match body {
            FormulaExpr::Release(lhs, rhs) => {
                assert!(
                    matches!(lhs.as_ref(), FormulaExpr::Until(_, _)),
                    "left side should keep left-associative grouping"
                );
                assert!(
                    matches!(rhs.as_ref(), FormulaExpr::Comparison { .. }),
                    "right side should be the final comparison atom"
                );
            }
            other => panic!("expected top-level Release from left fold, got {other:?}"),
        }
    }

    #[test]
    fn temporal_prefix_binds_tighter_than_infix_ops() {
        let body = parse_property_body("liveness", "forall p: R. [] p.x == true && p.y == true");
        match body {
            FormulaExpr::And(lhs, rhs) => {
                assert!(
                    matches!(lhs.as_ref(), FormulaExpr::Always(_)),
                    "left side should be parsed as [] (p.x == true)"
                );
                assert!(
                    matches!(rhs.as_ref(), FormulaExpr::Comparison { .. }),
                    "right side should remain the second comparison atom"
                );
            }
            other => panic!("expected top-level And from prefix precedence, got {other:?}"),
        }
    }

    #[test]
    fn parentheses_override_default_temporal_grouping() {
        let body = parse_property_body(
            "liveness",
            "forall p: R. p.x == true U (p.y == true R p.decided == true)",
        );
        match body {
            FormulaExpr::Until(lhs, rhs) => {
                assert!(
                    matches!(lhs.as_ref(), FormulaExpr::Comparison { .. }),
                    "lhs should remain the first comparison atom"
                );
                assert!(
                    matches!(rhs.as_ref(), FormulaExpr::Release(_, _)),
                    "parenthesized rhs should remain grouped"
                );
            }
            other => panic!("expected top-level Until from parenthesized grouping, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // parse_enum tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_enum_basic() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    enum Vote { yes, no }
    message M;
    role R {
        var v: Vote = yes;
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "enum.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.enums.len(), 1);
        let e = &prog.protocol.node.enums[0];
        assert_eq!(e.name, "Vote");
        assert_eq!(e.variants, vec!["yes", "no"]);
        assert!(e.span.start < e.span.end, "enum span should be non-empty");
    }

    #[test]
    fn parse_enum_multiple_variants() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    enum Phase { idle, prepare, commit, decide }
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "enum.trs").unwrap();
        let e = &prog.protocol.node.enums[0];
        assert_eq!(e.name, "Phase");
        assert_eq!(e.variants, vec!["idle", "prepare", "commit", "decide"]);
    }

    #[test]
    fn parse_enum_multiple_declarations() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    enum Color { red, blue }
    enum Status { pending, done }
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "enums.trs").unwrap();
        assert_eq!(prog.protocol.node.enums.len(), 2);
        assert_eq!(prog.protocol.node.enums[0].name, "Color");
        assert_eq!(prog.protocol.node.enums[1].name, "Status");
    }

    #[test]
    fn parse_enum_with_optional_trailing_semicolon() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    enum Vote { yes, no };
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "enum_semi.trs").expect("trailing semicolon should be accepted");
        assert_eq!(prog.protocol.node.enums[0].name, "Vote");
    }

    // ---------------------------------------------------------------
    // parse_pacemaker tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_pacemaker_basic() {
        let src = r#"
protocol P {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    pacemaker {
        view: v;
        start: active;
    }
    message M;
    role R {
        var v: nat = 0;
        init active;
        phase active {}
    }
}
"#;
        let prog = parse(src, "pacemaker.trs").expect("parse should succeed");
        let pm = prog
            .protocol
            .node
            .pacemaker
            .as_ref()
            .expect("pacemaker should be present");
        assert_eq!(pm.view_var, "v");
        assert_eq!(pm.start_phase, "active");
        assert!(pm.reset_vars.is_empty());
    }

    #[test]
    fn parse_pacemaker_with_reset() {
        let src = r#"
protocol P {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    pacemaker {
        view: round;
        start: waiting;
        reset: decided, locked;
    }
    message M;
    role R {
        var round: nat = 0;
        var decided: bool = false;
        var locked: bool = false;
        init waiting;
        phase waiting {}
    }
}
"#;
        let prog = parse(src, "pacemaker_reset.trs").unwrap();
        let pm = prog.protocol.node.pacemaker.unwrap();
        assert_eq!(pm.view_var, "round");
        assert_eq!(pm.start_phase, "waiting");
        assert_eq!(pm.reset_vars, vec!["decided", "locked"]);
    }

    #[test]
    fn parse_pacemaker_missing_view_is_error() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    pacemaker {
        start: active;
    }
    message M;
    role R { init active; phase active {} }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("missing view"),
            "error should mention missing view: {msg}"
        );
    }

    #[test]
    fn parse_pacemaker_missing_start_is_error() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    pacemaker {
        view: v;
    }
    message M;
    role R { var v: nat = 0; init s; phase s {} }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("missing start"),
            "error should mention missing start: {msg}"
        );
    }

    #[test]
    fn parse_pacemaker_unknown_key_is_error() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    pacemaker {
        view: v;
        start: s;
        bogus: x;
    }
    message M;
    role R { var v: nat = 0; init s; phase s {} }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown pacemaker key"),
            "error should mention unknown key: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // parse_module tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_module_basic() {
        let src = r#"
protocol P {
    module Consensus {
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        message Vote;
        role Replica {
            var decided: bool = false;
            init waiting;
            phase waiting {
                when received >= 2*t+1 Vote => {
                    decided = true;
                    decide true;
                }
            }
        }
        property ag: agreement {
            forall p: Replica. forall q: Replica.
                p.decided == q.decided
        }
    }
}
"#;
        let prog = parse(src, "module.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.modules.len(), 1);
        let m = &prog.protocol.node.modules[0];
        assert_eq!(m.name, "Consensus");
        assert!(m.interface.is_none());
        assert_eq!(m.items.parameters.len(), 2);
        assert_eq!(m.items.messages.len(), 1);
        assert_eq!(m.items.roles.len(), 1);
        assert_eq!(m.items.properties.len(), 1);
    }

    #[test]
    fn parse_module_with_interface() {
        let src = r#"
protocol P {
    module SafeConsensus {
        interface {
            assumes: n >= 4;
            assumes: n > 3*t;
            guarantees: agreement ag;
        }
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        message Vote;
        role Replica {
            var decided: bool = false;
            init waiting;
            phase waiting {}
        }
        property ag: agreement {
            forall p: Replica. forall q: Replica.
                p.decided == q.decided
        }
    }
}
"#;
        let prog = parse(src, "module_if.trs").expect("parse should succeed");
        let m = &prog.protocol.node.modules[0];
        let iface = m.interface.as_ref().expect("interface should be present");
        assert_eq!(iface.assumptions.len(), 2);
        assert_eq!(iface.guarantees.len(), 1);

        // Check first assumption: n >= 4
        let a0 = &iface.assumptions[0];
        assert!(matches!(&a0.lhs, LinearExpr::Var(v) if v == "n"));
        assert_eq!(a0.op, CmpOp::Ge);
        assert!(matches!(&a0.rhs, LinearExpr::Const(4)));

        // Check second assumption: n > 3*t
        let a1 = &iface.assumptions[1];
        assert_eq!(a1.op, CmpOp::Gt);

        // Check guarantee
        let g0 = &iface.guarantees[0];
        assert_eq!(g0.kind, PropertyKind::Agreement);
        assert_eq!(g0.property_name, "ag");
    }

    #[test]
    fn parse_module_with_multiple_guarantees() {
        let src = r#"
protocol P {
    module M {
        interface {
            assumes: n > 3*t;
            guarantees: safety inv;
            guarantees: liveness term;
        }
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        message M;
        role R {
            var decided: bool = false;
            init s;
            phase s {}
        }
        property inv: safety {
            forall p: R. p.decided == true
        }
        property term: liveness {
            forall p: R. p.decided == true
        }
    }
}
"#;
        let prog = parse(src, "module_multi_g.trs").unwrap();
        let iface = prog.protocol.node.modules[0].interface.as_ref().unwrap();
        assert_eq!(iface.guarantees.len(), 2);
        assert_eq!(iface.guarantees[0].kind, PropertyKind::Safety);
        assert_eq!(iface.guarantees[0].property_name, "inv");
        assert_eq!(iface.guarantees[1].kind, PropertyKind::Liveness);
        assert_eq!(iface.guarantees[1].property_name, "term");
    }

    #[test]
    fn parse_module_rejects_enum_inside() {
        let src = r#"
protocol P {
    module M {
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        enum Vote { yes, no }
        message M;
        role R { init s; phase s {} }
    }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        assert!(
            matches!(err, ParseError::UnsupportedInModule { .. }),
            "expected UnsupportedInModule, got: {err:?}"
        );
    }

    #[test]
    fn parse_module_rejects_import_inside() {
        let src = r#"
protocol P {
    module M {
        import Foo from "foo.trs";
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        message M;
        role R { init s; phase s {} }
    }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        assert!(
            matches!(err, ParseError::UnsupportedInModule { .. }),
            "expected UnsupportedInModule for import, got: {err:?}"
        );
    }

    #[test]
    fn parse_module_rejects_pacemaker_inside() {
        let src = r#"
protocol P {
    module M {
        parameters { n: nat; t: nat; }
        resilience { n > 3*t; }
        pacemaker { view: v; start: s; }
        message M;
        role R { var v: nat = 0; init s; phase s {} }
    }
}
"#;
        let err = parse(src, "test.trs").unwrap_err();
        assert!(
            matches!(err, ParseError::UnsupportedInModule { .. }),
            "expected UnsupportedInModule for pacemaker, got: {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // parse_import / resolve_imports tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_import_declaration() {
        let src = r#"
protocol P {
    import Common from "common.trs";
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "test.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.imports.len(), 1);
        let imp = &prog.protocol.node.imports[0];
        assert_eq!(imp.name, "Common");
        assert_eq!(imp.path, "common.trs");
        assert!(imp.span.start < imp.span.end);
    }

    #[test]
    fn parse_import_multiple() {
        let src = r#"
protocol P {
    import Types from "types.trs";
    import Roles from "roles.trs";
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "test.trs").unwrap();
        assert_eq!(prog.protocol.node.imports.len(), 2);
        assert_eq!(prog.protocol.node.imports[0].name, "Types");
        assert_eq!(prog.protocol.node.imports[0].path, "types.trs");
        assert_eq!(prog.protocol.node.imports[1].name, "Roles");
        assert_eq!(prog.protocol.node.imports[1].path, "roles.trs");
    }

    #[test]
    fn resolve_imports_merges_declarations() {
        // Write a temporary imported file
        let tmp = std::env::temp_dir().join("tarsier_test_import");
        std::fs::create_dir_all(&tmp).unwrap();
        let imported_src = r#"
protocol Common {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    enum Vote { yes, no }
    message Echo;
    role Helper {
        init idle;
        phase idle {}
    }
}
"#;
        std::fs::write(tmp.join("common.trs"), imported_src).unwrap();

        let main_src = r#"
protocol Main {
    import Common from "common.trs";
    message Request;
    role Primary {
        init active;
        phase active {}
    }
}
"#;
        let mut prog = parse(main_src, "main.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.imports.len(), 1);

        resolve_imports(&mut prog, &tmp).expect("resolve_imports should succeed");

        // imports should be drained
        assert!(prog.protocol.node.imports.is_empty());
        // messages merged: Request (local) + Echo (imported)
        assert_eq!(prog.protocol.node.messages.len(), 2);
        // roles merged: Primary (local) + Helper (imported)
        assert_eq!(prog.protocol.node.roles.len(), 2);
        // enums from imported
        assert_eq!(prog.protocol.node.enums.len(), 1);
        assert_eq!(prog.protocol.node.enums[0].name, "Vote");
        // parameters from imported
        assert_eq!(prog.protocol.node.parameters.len(), 2);
        // resilience from imported
        assert!(prog.protocol.node.resilience.is_some());

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_imports_does_not_overwrite_existing_adversary() {
        let tmp = std::env::temp_dir().join("tarsier_test_import_adv");
        std::fs::create_dir_all(&tmp).unwrap();
        let imported_src = r#"
protocol Imported {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: crash; bound: f; }
    message Echo;
    role R { init s; phase s {} }
}
"#;
        std::fs::write(tmp.join("imported.trs"), imported_src).unwrap();

        let main_src = r#"
protocol Main {
    import Imp from "imported.trs";
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R { init s; phase s {} }
}
"#;
        let mut prog = parse(main_src, "main.trs").unwrap();
        resolve_imports(&mut prog, &tmp).unwrap();

        // Main's adversary should win (byzantine, not crash)
        let adv = &prog.protocol.node.adversary;
        assert!(!adv.is_empty());
        let model_item = adv.iter().find(|a| a.key == "model").expect("model key");
        assert_eq!(model_item.value, "byzantine");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_imports_nonexistent_file_is_error() {
        let tmp = std::env::temp_dir().join("tarsier_test_import_missing");
        std::fs::create_dir_all(&tmp).unwrap();

        let src = r#"
protocol P {
    import Missing from "does_not_exist.trs";
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
        let mut prog = parse(src, "test.trs").unwrap();
        let err = resolve_imports(&mut prog, &tmp).unwrap_err();
        assert!(
            matches!(err, ParseError::ImportResolution { .. }),
            "expected ImportResolution error, got: {err:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn multi_error_adversary_collects_all_invalid_keys() {
        let src = r#"
protocol MultiErr {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    adversary {
        model: byzantine;
        bogus_key1: foo;
        bound: t;
        bogus_key2: bar;
    }
    role R {
        init voting;
        phase voting {}
    }
}
"#;
        let err = parse(src, "multi_err.trs").unwrap_err();
        match err {
            ParseError::MultipleErrors(errs) => {
                assert_eq!(
                    errs.errors.len(),
                    2,
                    "expected 2 invalid field errors, got: {:?}",
                    errs.errors
                );
                for e in &errs.errors {
                    assert!(
                        matches!(e, ParseError::InvalidField { .. }),
                        "expected InvalidField, got: {e:?}"
                    );
                }
            }
            other => panic!("expected MultipleErrors, got: {other:?}"),
        }
    }

    #[test]
    fn single_adversary_error_returns_direct_error() {
        let src = r#"
protocol SingleErr {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    adversary {
        model: byzantine;
        bogus_only: foo;
    }
    role R {
        init voting;
        phase voting {}
    }
}
"#;
        let err = parse(src, "single_err.trs").unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { .. }),
            "expected InvalidField, got: {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // Committee declaration tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_committee_declaration() {
        let src = r#"
protocol P {
    parameters { n: nat; t: nat; b: nat; }
    resilience { n > 2*b; }
    adversary { model: byzantine; bound: b; }
    committee voters {
        population: 1000;
        byzantine: 333;
        size: 100;
        epsilon: 1.0e-9;
        bound_param: b;
    }
    message Vote;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "committee.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.committees.len(), 1);
        let c = &prog.protocol.node.committees[0];
        assert_eq!(c.name, "voters");
        assert_eq!(c.items.len(), 5);

        // Check specific item types
        let pop = c.items.iter().find(|i| i.key == "population").unwrap();
        assert_eq!(pop.value, CommitteeValue::Int(1000));
        let eps = c.items.iter().find(|i| i.key == "epsilon").unwrap();
        match &eps.value {
            CommitteeValue::Float(f) => assert!((*f - 1.0e-9).abs() < 1e-15),
            other => panic!("expected Float for epsilon, got: {other:?}"),
        }
        let bp = c.items.iter().find(|i| i.key == "bound_param").unwrap();
        assert_eq!(bp.value, CommitteeValue::Param("b".to_string()));
    }

    #[test]
    fn parse_multiple_committees() {
        let src = r#"
protocol P {
    params n, t, b1, b2;
    resilience: n > 3*t;
    committee soft {
        population: 500;
        byzantine: 100;
        size: 50;
        epsilon: 1.0e-6;
        bound_param: b1;
    }
    committee cert {
        population: 500;
        byzantine: 100;
        size: 80;
        epsilon: 1.0e-9;
        bound_param: b2;
    }
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "multi_committee.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.committees.len(), 2);
        assert_eq!(prog.protocol.node.committees[0].name, "soft");
        assert_eq!(prog.protocol.node.committees[1].name, "cert");
    }

    // ---------------------------------------------------------------
    // Message declaration tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_message_without_fields() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Echo;
    message Ready;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "msg_no_fields.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.messages.len(), 2);
        assert_eq!(prog.protocol.node.messages[0].name, "Echo");
        assert!(prog.protocol.node.messages[0].fields.is_empty());
        assert_eq!(prog.protocol.node.messages[1].name, "Ready");
        assert!(prog.protocol.node.messages[1].fields.is_empty());
    }

    #[test]
    fn parse_message_with_fields() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Proposal(value: bool, round: nat);
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "msg_fields.trs").expect("parse should succeed");
        let msg = &prog.protocol.node.messages[0];
        assert_eq!(msg.name, "Proposal");
        assert_eq!(msg.fields.len(), 2);
        assert_eq!(msg.fields[0].name, "value");
        assert_eq!(msg.fields[0].ty, "bool");
        assert!(msg.fields[0].range.is_none());
        assert_eq!(msg.fields[1].name, "round");
        assert_eq!(msg.fields[1].ty, "nat");
    }

    // ---------------------------------------------------------------
    // Multiple phases with goto
    // ---------------------------------------------------------------

    #[test]
    fn parse_three_phase_protocol_with_goto() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Echo;
    message Ready;
    role Replica {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 2*t+1 Echo => {
                send Ready;
                goto phase ready;
            }
        }
        phase ready {
            when received >= 2*t+1 Ready => {
                decided = true;
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "three_phase.trs").expect("parse should succeed");
        let role = &prog.protocol.node.roles[0].node;
        assert_eq!(role.name, "Replica");
        assert_eq!(role.init_phase, Some("waiting".to_string()));
        assert_eq!(role.phases.len(), 3);
        assert_eq!(role.phases[0].node.name, "waiting");
        assert_eq!(role.phases[1].node.name, "ready");
        assert_eq!(role.phases[2].node.name, "done");

        // Check goto in first phase
        let actions = &role.phases[0].node.transitions[0].node.actions;
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::GotoPhase { phase } if phase == "ready")));

        // Check decide in second phase
        let actions2 = &role.phases[1].node.transitions[0].node.actions;
        assert!(actions2.iter().any(|a| matches!(a, Action::Decide { .. })));
        assert!(actions2
            .iter()
            .any(|a| matches!(a, Action::GotoPhase { phase } if phase == "done")));
    }

    // ---------------------------------------------------------------
    // Local variable types
    // ---------------------------------------------------------------

    #[test]
    fn parse_local_variable_types_and_initializers() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    enum Phase { idle, active, done }
    message M;
    role R {
        var flag: bool = false;
        var count: nat in 0..5 = 0;
        var score: int = 0;
        var status: Phase = idle;
        init s;
        phase s {}
    }
}
"#;
        let prog = parse(src, "var_types.trs").expect("parse should succeed");
        let vars = &prog.protocol.node.roles[0].node.vars;
        assert_eq!(vars.len(), 4);

        // bool variable
        assert_eq!(vars[0].name, "flag");
        assert_eq!(vars[0].ty, VarType::Bool);
        assert_eq!(vars[0].init, Some(Expr::BoolLit(false)));

        // nat with range
        assert_eq!(vars[1].name, "count");
        assert_eq!(vars[1].ty, VarType::Nat);
        assert_eq!(vars[1].range, Some(VarRange { min: 0, max: 5 }));
        assert_eq!(vars[1].init, Some(Expr::IntLit(0)));

        // int variable
        assert_eq!(vars[2].name, "score");
        assert_eq!(vars[2].ty, VarType::Int);
        assert_eq!(vars[2].init, Some(Expr::IntLit(0)));

        // enum variable
        assert_eq!(vars[3].name, "status");
        assert_eq!(vars[3].ty, VarType::Enum("Phase".to_string()));
        assert_eq!(vars[3].init, Some(Expr::Var("idle".to_string())));
    }

    // ---------------------------------------------------------------
    // Property kind variants
    // ---------------------------------------------------------------

    #[test]
    fn parse_invariant_property() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        var x: nat in 0..3 = 0;
        init s;
        phase s {}
    }
    property bounded: invariant {
        forall p: R. p.x <= 3
    }
}
"#;
        let prog = parse(src, "invariant.trs").expect("parse should succeed");
        let prop = &prog.protocol.node.properties[0].node;
        assert_eq!(prop.name, "bounded");
        assert_eq!(prop.kind, PropertyKind::Invariant);
    }

    #[test]
    fn parse_validity_property() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property val: validity {
        forall p: R. p.decided == true
    }
}
"#;
        let prog = parse(src, "validity.trs").expect("parse should succeed");
        assert_eq!(
            prog.protocol.node.properties[0].node.kind,
            PropertyKind::Validity
        );
    }

    // ---------------------------------------------------------------
    // Adversary block variations
    // ---------------------------------------------------------------

    #[test]
    fn parse_adversary_all_known_keys() {
        let src = r#"
protocol P {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        network: process_selective;
        timing: partial_synchrony;
        delivery: per_recipient;
        delivery_scope: local;
        faults: global;
        fault_scope: global;
        fault_budget: f;
        por: stubborn;
        por_mode: stubborn;
        compromise: adaptive;
        compromised: replica_key;
        gst: finite;
    }
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "adv_all.trs").expect("parse should succeed");
        let adv = &prog.protocol.node.adversary;
        let keys: Vec<&str> = adv.iter().map(|a| a.key.as_str()).collect();
        assert!(keys.contains(&"model"));
        assert!(keys.contains(&"bound"));
        assert!(keys.contains(&"auth"));
        assert!(keys.contains(&"network"));
        assert!(keys.contains(&"gst"));
    }

    // ---------------------------------------------------------------
    // Send action variations
    // ---------------------------------------------------------------

    #[test]
    fn parse_send_with_named_args() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Vote(value: bool, round: nat in 0..3);
    role R {
        var r: nat in 0..3 = 0;
        init s;
        phase s {
            when received >= 1 Vote => {
                send Vote(value=true, round=r);
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "send_named.trs").expect("parse should succeed");
        let actions = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .actions;
        match &actions[0] {
            Action::Send {
                message_type, args, ..
            } => {
                assert_eq!(message_type, "Vote");
                assert_eq!(args.len(), 2);
                match &args[0] {
                    SendArg::Named { name, value } => {
                        assert_eq!(name, "value");
                        assert_eq!(*value, Expr::BoolLit(true));
                    }
                    other => panic!("Expected Named arg, got: {other:?}"),
                }
                match &args[1] {
                    SendArg::Named { name, value } => {
                        assert_eq!(name, "round");
                        assert_eq!(*value, Expr::Var("r".to_string()));
                    }
                    other => panic!("Expected Named arg, got: {other:?}"),
                }
            }
            other => panic!("Expected Send action, got: {other:?}"),
        }
    }

    #[test]
    fn parse_send_with_positional_args() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Vote(value: bool);
    role R {
        init s;
        phase s {
            when received >= 1 Vote => {
                send Vote(true);
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "send_pos.trs").expect("parse should succeed");
        let actions = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .actions;
        match &actions[0] {
            Action::Send { args, .. } => {
                assert_eq!(args.len(), 1);
                assert!(
                    matches!(&args[0], SendArg::Positional(Expr::BoolLit(true))),
                    "Expected positional true arg, got: {:?}",
                    args[0]
                );
            }
            other => panic!("Expected Send, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Assign action expression forms
    // ---------------------------------------------------------------

    #[test]
    fn parse_assign_arithmetic_expressions() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        var x: nat in 0..10 = 0;
        var y: nat in 0..10 = 5;
        init s;
        phase s {
            when received >= 1 M => {
                x = x + 1;
                y = y - x;
                x = x * 2;
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "assign_arith.trs").expect("parse should succeed");
        let actions = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .actions;

        // x = x + 1
        match &actions[0] {
            Action::Assign { var, value } => {
                assert_eq!(var, "x");
                assert!(matches!(value, Expr::Add(_, _)));
            }
            other => panic!("Expected Assign, got: {other:?}"),
        }
        // y = y - x
        match &actions[1] {
            Action::Assign { var, value } => {
                assert_eq!(var, "y");
                assert!(matches!(value, Expr::Sub(_, _)));
            }
            other => panic!("Expected Assign, got: {other:?}"),
        }
        // x = x * 2
        match &actions[2] {
            Action::Assign { var, value } => {
                assert_eq!(var, "x");
                assert!(matches!(value, Expr::Mul(_, _)));
            }
            other => panic!("Expected Assign, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Error cases
    // ---------------------------------------------------------------

    #[test]
    fn parse_empty_string_is_error() {
        let result = parse("", "empty.trs");
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_protocol_keyword_is_error() {
        let result = parse("not a protocol", "bad.trs");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unclosed_brace_is_error() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {}
"#;
        let result = parse(src, "unclosed.trs");
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_role_is_still_valid() {
        // A protocol without a role should still parse (no mandatory role)
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
}
"#;
        let result = parse(src, "no_role.trs");
        assert!(result.is_ok());
        assert!(result.unwrap().protocol.node.roles.is_empty());
    }

    // ---------------------------------------------------------------
    // Linear expression parsing
    // ---------------------------------------------------------------

    #[test]
    fn parse_linear_expr_n_minus_t() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        init s;
        phase s {
            when received >= n-t M => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "n_minus_t.trs").expect("parse should succeed");
        let guard = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .guard;
        match guard {
            GuardExpr::Threshold(tg) => {
                // n-t should be Sub(Var("n"), Var("t"))
                assert!(
                    matches!(&tg.threshold, LinearExpr::Sub(l, r)
                        if matches!(l.as_ref(), LinearExpr::Var(v) if v == "n")
                        && matches!(r.as_ref(), LinearExpr::Var(v) if v == "t")
                    ),
                    "Expected Sub(Var(n), Var(t)), got: {:?}",
                    tg.threshold
                );
            }
            other => panic!("Expected Threshold guard, got: {other:?}"),
        }
    }

    #[test]
    fn parse_linear_expr_2t_plus_1_structure() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R {
        init s;
        phase s {
            when received >= 2*t+1 M => { goto phase done; }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "2t_plus_1.trs").expect("parse should succeed");
        let guard = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .guard;
        match guard {
            GuardExpr::Threshold(tg) => {
                // 2*t+1 should be Add(Mul(2, Var("t")), Const(1))
                match &tg.threshold {
                    LinearExpr::Add(l, r) => {
                        assert!(
                            matches!(l.as_ref(), LinearExpr::Mul(2, inner) if matches!(inner.as_ref(), LinearExpr::Var(v) if v == "t")),
                            "Expected Mul(2, Var(t)), got: {:?}",
                            l
                        );
                        assert_eq!(**r, LinearExpr::Const(1));
                    }
                    other => panic!("Expected Add, got: {other:?}"),
                }
            }
            other => panic!("Expected Threshold guard, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Resilience condition structure
    // ---------------------------------------------------------------

    #[test]
    fn parse_resilience_n_gt_3t() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "resil.trs").expect("parse should succeed");
        let resil = prog
            .protocol
            .node
            .resilience
            .as_ref()
            .expect("should have resilience");
        let cond = &resil.condition;
        assert!(matches!(&cond.lhs, LinearExpr::Var(v) if v == "n"));
        assert_eq!(cond.op, CmpOp::Gt);
        match &cond.rhs {
            LinearExpr::Mul(3, inner) => {
                assert!(matches!(inner.as_ref(), LinearExpr::Var(v) if v == "t"));
            }
            other => panic!("Expected Mul(3, Var(t)), got: {other:?}"),
        }
    }

    #[test]
    fn parse_resilience_n_gt_2t_plus_1() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 2*t+1;
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "resil2.trs").expect("parse should succeed");
        let cond = &prog.protocol.node.resilience.as_ref().unwrap().condition;
        assert_eq!(cond.op, CmpOp::Gt);
        match &cond.rhs {
            LinearExpr::Add(l, r) => {
                assert!(matches!(l.as_ref(), LinearExpr::Mul(2, _)));
                assert_eq!(**r, LinearExpr::Const(1));
            }
            other => panic!("Expected Add(Mul(2,_), Const(1)), got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Nested boolean/formula expression tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_formula_and_or_implication() {
        let src = wrap_property(
            "safety",
            "forall p: R. (p.decided == true && p.x == true) ==> p.y == false",
        );
        let prog = parse(&src, "formula.trs").expect("parse should succeed");
        let body = &prog.protocol.node.properties[0].node.formula.body;
        match body {
            FormulaExpr::Implies(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), FormulaExpr::And(_, _)));
                assert!(matches!(rhs.as_ref(), FormulaExpr::Comparison { .. }));
            }
            other => panic!("Expected Implies, got: {other:?}"),
        }
    }

    #[test]
    fn parse_formula_not_and_or() {
        let src = wrap_property(
            "safety",
            "forall p: R. !(p.decided == true) || p.x == false",
        );
        let prog = parse(&src, "formula_not.trs").expect("parse should succeed");
        let body = &prog.protocol.node.properties[0].node.formula.body;
        match body {
            FormulaExpr::Or(lhs, _) => {
                assert!(matches!(lhs.as_ref(), FormulaExpr::Not(_)));
            }
            other => panic!("Expected Or(Not(_), _), got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Threshold guard with message filter args
    // ---------------------------------------------------------------

    #[test]
    fn parse_threshold_guard_with_message_args() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Vote(view: nat in 0..3);
    role R {
        init s;
        phase s {
            when received >= 2*t+1 Vote(view=0) => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "msg_args.trs").expect("parse should succeed");
        let guard = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .guard;
        match guard {
            GuardExpr::Threshold(tg) => {
                assert_eq!(tg.message_type, "Vote");
                assert_eq!(tg.message_args.len(), 1);
                assert_eq!(tg.message_args[0].0, "view");
                assert_eq!(tg.message_args[0].1, Expr::IntLit(0));
            }
            other => panic!("Expected Threshold guard, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Compound guards (AND/OR)
    // ---------------------------------------------------------------

    #[test]
    fn parse_compound_guard_and() {
        let src = r#"
protocol P {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role R {
        var flag: bool = true;
        init s;
        phase s {
            when received >= 2*t+1 Vote && flag => {
                goto phase done;
            }
        }
        phase done {}
    }
}
"#;
        let prog = parse(src, "compound_guard.trs").expect("parse should succeed");
        let guard = &prog.protocol.node.roles[0].node.phases[0].node.transitions[0]
            .node
            .guard;
        match guard {
            GuardExpr::And(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), GuardExpr::Threshold(_)));
                assert!(matches!(rhs.as_ref(), GuardExpr::BoolVar(_)));
            }
            other => panic!("Expected And guard, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Parameter type annotation in short form
    // ---------------------------------------------------------------

    #[test]
    fn parse_params_with_type_annotation() {
        let src = r#"
protocol P {
    params n, t: int;
    resilience: n > 3*t;
    message M;
    role R { init s; phase s {} }
}
"#;
        let prog = parse(src, "params_typed.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.parameters.len(), 2);
        // 'n' defaults to Nat (no annotation)
        assert_eq!(prog.protocol.node.parameters[0].name, "n");
        assert_eq!(prog.protocol.node.parameters[0].ty, ParamType::Nat);
        // 't: int' should be Int
        assert_eq!(prog.protocol.node.parameters[1].name, "t");
        assert_eq!(prog.protocol.node.parameters[1].ty, ParamType::Int);
    }

    // ---------------------------------------------------------------
    // Diagnostics test
    // ---------------------------------------------------------------

    #[test]
    fn parse_with_diagnostics_no_warnings_on_clean_protocol() {
        let src = r#"
protocol Clean {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; network: process_selective; auth: signed; }
    message Vote;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 2*t+1 Vote => {
                decided = true;
                decide true;
            }
        }
    }
    property ag: agreement {
        forall p: R. forall q: R.
            (p.decided == true && q.decided == true) ==> p.decided == q.decided
    }
}
"#;
        let (prog, diags) = parse_with_diagnostics(src, "clean.trs").expect("parse should succeed");
        assert_eq!(prog.protocol.node.name, "Clean");
        assert!(
            diags.is_empty(),
            "Expected no diagnostics on clean protocol, got: {:?}",
            diags
        );
    }

    // ---------------------------------------------------------------
    // Proptest: property-based / randomized tests
    // ---------------------------------------------------------------

    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngAlgorithm};

    fn dsl_proptest_config() -> ProptestConfig {
        ProptestConfig {
            cases: 64,
            source_file: Some(file!()),
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            rng_algorithm: RngAlgorithm::ChaCha,
            ..ProptestConfig::default()
        }
    }

    /// Reserved words that must not appear as user identifiers.
    const DSL_KEYWORDS: &[&str] = &[
        "protocol",
        "role",
        "phase",
        "var",
        "init",
        "params",
        "parameters",
        "resilience",
        "adversary",
        "when",
        "goto",
        "decide",
        "send",
        "message",
        "true",
        "false",
        "bool",
        "nat",
        "int",
        "forall",
        "exists",
        "property",
        "agreement",
        "validity",
        "safety",
        "invariant",
        "liveness",
        "received",
        "distinct",
        "enum",
        "certificate",
        "threshold_signature",
        "form",
        "lock",
        "justify",
        "module",
        "import",
        "channel",
        "equivocation",
        "identity",
        "pacemaker",
        "has",
        "next",
        "always",
        "eventually",
        "committee",
        "and",
        "or",
        "not",
        "to",
        "from",
        "interface",
        "assumes",
        "guarantees",
    ];

    /// Strategy: generate a valid DSL identifier that is not a reserved word.
    fn arb_identifier() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_]{0,11}".prop_filter("must not be a keyword", |s| {
            !DSL_KEYWORDS.contains(&s.as_str())
        })
    }

    /// Strategy: generate a valid linear expression string.
    fn arb_linear_expr() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("n".to_string()),
            Just("t".to_string()),
            Just("1".to_string()),
            (1..6i64).prop_map(|c| format!("{c}*t+1")),
            (1..6i64).prop_map(|c| format!("{c}*t")),
            Just("n-t".to_string()),
        ]
    }

    /// Strategy: generate a comparison operator string.
    fn arb_cmp_op_str() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just(">="),
            Just(">"),
            Just("<="),
            Just("<"),
            Just("=="),
            Just("!="),
        ]
    }

    /// Strategy: generate a formula atom for a given quantifier variable.
    fn arb_formula_atom(qvar: &str) -> BoxedStrategy<String> {
        let q = qvar.to_string();
        let q2 = q.clone();
        prop_oneof![
            // qualified var == bool literal
            Just(format!("{q}.decided == true")),
            Just(format!("{q}.decided == false")),
            Just(format!("{q}.x == true")),
            Just(format!("{q}.y == false")),
            // qualified var == qualified var
            Just(format!("{q}.x == {q}.y")),
            // qualified var <cmp> int literal
            (0..4i64, arb_cmp_op_str()).prop_map(move |(n, op)| format!("{}.x {} {}", q2, op, n)),
        ]
        .boxed()
    }

    /// Strategy: generate a property formula body (with bounded depth).
    fn arb_formula_body_inner(depth: u32, qvar: &str) -> BoxedStrategy<String> {
        let leaf = arb_formula_atom(qvar);
        if depth == 0 {
            leaf
        } else {
            let q = qvar.to_string();
            let sub = move || arb_formula_body_inner(depth - 1, &q);
            prop_oneof![
                4 => arb_formula_atom(qvar),
                // Binary connectives
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) && ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) || ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) ==> ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) <=> ({r})")),
                // Unary / temporal prefix
                1 => sub().prop_map(|f| format!("!({f})")),
                1 => sub().prop_map(|f| format!("[] ({f})")),
                1 => sub().prop_map(|f| format!("<> ({f})")),
                1 => sub().prop_map(|f| format!("X ({f})")),
                // Binary temporal
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) U ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) W ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) R ({r})")),
                1 => (sub(), sub()).prop_map(|(l, r)| format!("({l}) ~> ({r})")),
            ]
            .boxed()
        }
    }

    /// Strategy: generate a quantified formula string (quantifier prefix + body).
    /// Randomly chooses among single forall, double forall, or exists.
    fn arb_quantified_formula(role: &str) -> BoxedStrategy<String> {
        let r = role.to_string();
        let r2 = r.clone();
        let r3 = r.clone();
        prop_oneof![
            // Single forall
            3 => arb_formula_body_inner(2, "p")
                .prop_map(move |body| format!("forall p: {}. {}", r, body)),
            // Double forall (agreement-style)
            1 => arb_formula_body_inner(1, "p")
                .prop_map(move |body| format!("forall p: {}. forall q: {}. {}", r2, r2, body)),
            // Exists
            1 => arb_formula_body_inner(2, "p")
                .prop_map(move |body| format!("exists p: {}. {}", r3, body)),
        ]
        .boxed()
    }

    /// Strategy: generate a guard expression string for a transition.
    fn arb_guard(msg: &str, thresh: &str) -> BoxedStrategy<String> {
        let m = msg.to_string();
        let m2 = m.clone();
        let m3 = m.clone();
        let t = thresh.to_string();
        let t2 = t.clone();
        let t3 = t.clone();
        prop_oneof![
            // Threshold guard (standard)
            3 => Just(format!("received >= {} {}", t, m)),
            // Threshold guard with distinct
            1 => Just(format!("received distinct >= {} {}", t2, m2)),
            // Bool guard
            1 => Just("decided".to_string()),
            // Compound AND: threshold && comparison
            1 => Just(format!("received >= {} {} && decided == false", t3, m3)),
        ]
        .boxed()
    }

    /// Strategy: generate a complete valid .trs protocol source string.
    /// Optionally includes: adversary block, enum, distinct guard,
    /// send-with-recipient, second role, and randomized property formulas.
    fn arb_protocol_source() -> BoxedStrategy<String> {
        // Stage 1: core identifiers and feature bitmask (keeps tuple ≤ 8).
        (
            arb_identifier(),  // proto
            arb_identifier(),  // role
            arb_identifier(),  // msg
            arb_identifier(),  // ph1
            arb_identifier(),  // ph2
            arb_linear_expr(), // resil
            arb_linear_expr(), // thresh
            0u8..32,           // feature bitmask (5 bits)
        )
            .prop_flat_map(|(proto, role, msg, ph1, ph2, resil, thresh, feat)| {
                let has_adv = feat & 1 != 0;
                let has_enum = feat & 2 != 0;
                let has_prop = feat & 4 != 0;
                let has_send_recip = feat & 8 != 0;
                let has_role2 = feat & 16 != 0;
                // Stage 2: dependent strategies (tuple ≤ 6).
                (
                    arb_identifier(),              // role2_name
                    arb_identifier(),              // enum_name
                    arb_identifier(),              // enum_v1
                    arb_identifier(),              // enum_v2
                    arb_quantified_formula(&role), // prop_formula
                    arb_guard(&msg, &thresh),      // guard
                )
                    .prop_map(
                        move |(role2_name, enum_name, enum_v1, enum_v2, prop_formula, guard)| {
                            let mut s = format!("protocol {} {{\n", proto);
                            s.push_str("    parameters { n: nat; t: nat; }\n");
                            s.push_str(&format!("    resilience {{ n > {}; }}\n", resil));
                            if has_adv {
                                s.push_str("    adversary { model: byzantine; bound: t; }\n");
                            }
                            if has_enum {
                                s.push_str(&format!(
                                    "    enum {} {{ {}, {} }}\n",
                                    enum_name, enum_v1, enum_v2
                                ));
                            }
                            s.push_str(&format!("    message {};\n", msg));
                            // Primary role
                            s.push_str(&format!("    role {} {{\n", role));
                            s.push_str("        var decided: bool = false;\n");
                            s.push_str("        var x: nat in 0..3 = 0;\n");
                            s.push_str("        var y: bool = false;\n");
                            s.push_str(&format!("        init {};\n", ph1));
                            s.push_str(&format!("        phase {} {{\n", ph1));
                            s.push_str(&format!("            when {} => {{\n", guard));
                            s.push_str("                decided = true;\n");
                            if has_send_recip && has_role2 {
                                s.push_str(&format!(
                                    "                send {} to {};\n",
                                    msg, role2_name
                                ));
                            }
                            s.push_str(&format!("                goto phase {};\n", ph2));
                            s.push_str("            }\n");
                            s.push_str("        }\n");
                            s.push_str(&format!("        phase {} {{}}\n", ph2));
                            s.push_str("    }\n");
                            // Optional second role
                            if has_role2 {
                                s.push_str(&format!(
                                "    role {} {{\n        init {};\n        phase {} {{}}\n    }}\n",
                                role2_name, ph1, ph1
                            ));
                            }
                            // Optional property with randomized formula
                            if has_prop {
                                s.push_str(&format!(
                                    "    property test_prop: safety {{\n        {}\n    }}\n",
                                    prop_formula
                                ));
                            }
                            s.push_str("}\n");
                            s
                        },
                    )
            })
            .boxed()
    }

    proptest! {
        #![proptest_config(dsl_proptest_config())]

        /// Feeding arbitrary strings to the parser must never panic.
        #[test]
        fn parse_never_panics_on_arbitrary_bytes(input in "\\PC{0,256}") {
            let _ = parse(&input, "fuzz.trs");
        }

        /// Truncating a valid protocol at an arbitrary byte must not panic.
        #[test]
        fn parse_never_panics_on_truncated_valid_source(
            src in arb_protocol_source(),
            frac in 0.0f64..1.0,
        ) {
            let cut = (src.len() as f64 * frac) as usize;
            let truncated = &src[..cut];
            let _ = parse(truncated, "truncated.trs");
        }

        /// Generated valid protocols must parse successfully with the
        /// expected structure (2 params, 1-2 roles depending on features).
        #[test]
        fn generated_valid_protocols_parse_successfully(src in arb_protocol_source()) {
            let result = parse(&src, "gen.trs");
            prop_assert!(
                result.is_ok(),
                "Generated protocol failed to parse:\n{}\nError: {:?}",
                src,
                result.err()
            );
            let prog = result.unwrap();
            prop_assert_eq!(prog.protocol.node.parameters.len(), 2);
            let n_roles = prog.protocol.node.roles.len();
            prop_assert!(
                n_roles == 1 || n_roles == 2,
                "Expected 1 or 2 roles, got {}",
                n_roles
            );
        }

        /// Random property formulas round-trip: parse -> display -> re-parse -> same AST.
        /// Uses randomized quantifier structures and formula atoms including
        /// integer literals, qualified vars, and all comparison operators.
        #[test]
        fn property_formula_roundtrip_proptest(
            formula in arb_quantified_formula("R"),
        ) {
            let src = wrap_property("safety", &formula);
            let prog = parse(&src, "rt.trs");
            // If the generated formula happens to be unparseable, skip.
            prop_assume!(prog.is_ok());
            let prog = prog.unwrap();
            let prop1 = &prog.protocol.node.properties[0].node.formula;

            let printed = prop1.to_string();
            let src2 = wrap_property("safety", &printed);
            let prog2 = parse(&src2, "rt2.trs");
            prop_assert!(
                prog2.is_ok(),
                "Re-parse failed for printed formula `{}`:\n{:?}",
                printed,
                prog2.err()
            );
            let prop2 = &prog2.unwrap().protocol.node.properties[0].node.formula;
            prop_assert_eq!(
                prop1, prop2,
                "Round-trip mismatch:\n  original: {}\n  printed:  {}",
                formula, printed
            );
        }

        /// Inserting extra whitespace/comments between tokens must not change
        /// the protocol name, role count, or parameter count.
        #[test]
        fn whitespace_insensitivity(src in arb_protocol_source()) {
            // First, parse the original.
            let prog1 = parse(&src, "ws1.trs");
            prop_assume!(prog1.is_ok());
            let prog1 = prog1.unwrap();

            // Insert random extra whitespace: double all spaces and add a line comment.
            let padded = src.replace(' ', "  ").replace('{', "{ /* comment */ ");
            let prog2 = parse(&padded, "ws2.trs");
            prop_assert!(
                prog2.is_ok(),
                "Padded source failed to parse:\n{}\nError: {:?}",
                padded,
                prog2.err()
            );
            let prog2 = prog2.unwrap();
            prop_assert_eq!(
                prog1.protocol.node.name,
                prog2.protocol.node.name,
                "Protocol name changed with extra whitespace"
            );
            prop_assert_eq!(
                prog1.protocol.node.parameters.len(),
                prog2.protocol.node.parameters.len(),
                "Parameter count changed with extra whitespace"
            );
            prop_assert_eq!(
                prog1.protocol.node.roles.len(),
                prog2.protocol.node.roles.len(),
                "Role count changed with extra whitespace"
            );
        }

        /// Parsing the same source twice must yield equal ASTs.
        #[test]
        fn parse_is_deterministic(src in arb_protocol_source()) {
            let r1 = parse(&src, "det1.trs");
            let r2 = parse(&src, "det2.trs");
            prop_assert!(r1.is_ok());
            prop_assert!(r2.is_ok());
            let p1 = r1.unwrap();
            let p2 = r2.unwrap();
            // Full structural equality (Program derives PartialEq).
            prop_assert_eq!(p1, p2, "AST differs between identical parses");
        }
    }
}
