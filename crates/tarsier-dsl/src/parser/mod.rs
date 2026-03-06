// ParseError carries diagnostic spans and source fragments; boxing would lose
// the zero-copy benefit and complicate call sites throughout the crate.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

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
    let mut refines = None;
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
    let mut collections = Vec::new();
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
            Rule::refines_decl => {
                let decl = parse_refines(item)?;
                if refines.is_some() {
                    semantic_errors.push(ParseError::syntax(
                        "Duplicate refines declaration",
                        decl.span,
                        "",
                        "",
                    ));
                } else {
                    refines = Some(decl);
                }
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
            Rule::collection_decl => {
                collections.push(parse_collection(item)?);
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
            refines,
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
            collections,
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

fn parse_refines(pair: Pair<'_>) -> Result<RefinesDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let path_raw = next_child(&mut inner, "refines path")?.as_str();
    let path = path_raw
        .strip_prefix('"')
        .and_then(|s: &str| s.strip_suffix('"'))
        .unwrap_or(path_raw)
        .to_string();
    Ok(RefinesDecl { path, span })
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
            | Rule::refines_decl
            | Rule::enum_decl
            | Rule::crypto_object_decl
            | Rule::committee_decl
            | Rule::collection_decl
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

fn parse_collection(pair: Pair<'_>) -> Result<CollectionDecl, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let kind_pair = next_child(&mut inner, "collection_kind")?;
    let kind = match kind_pair.as_str() {
        "log" => CollectionKind::Log,
        "sequence" => CollectionKind::Sequence,
        // FIFO channels use collection syntax in this stage; queue semantics
        // are introduced by follow-on IR/lowering tasks.
        "fifo_channel" => CollectionKind::Sequence,
        other => {
            return Err(syntax_error_at(
                &kind_pair,
                format!("Unknown collection kind: {other}"),
            ));
        }
    };
    let name = next_child(&mut inner, "collection name")?
        .as_str()
        .to_string();
    let element_type_pair = next_child(&mut inner, "collection element type")?;
    let element_type = element_type_pair.as_str().to_string();
    let capacity_pair = next_child(&mut inner, "collection capacity")?;
    let capacity = parse_linear_expr(capacity_pair)?;
    Ok(CollectionDecl {
        name,
        kind,
        element_type,
        capacity,
        span,
    })
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

    // Check for optional `leader` keyword before the role name.
    let first = next_child(&mut inner, "role_decl")?;
    let (is_leader, name) = if first.as_rule() == Rule::leader_kw {
        let name_pair = next_child(&mut inner, "role name after leader")?;
        (true, name_pair.as_str().to_string())
    } else {
        (false, first.as_str().to_string())
    };

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
            is_leader,
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
            Rule::reconfigure_action => {
                let action_span = span_from(&item);
                let mut seen_params = BTreeSet::new();
                let mut local_updates = Vec::new();

                for update in item.into_inner() {
                    if update.as_rule() != Rule::reconfigure_item {
                        continue;
                    }
                    let mut ui = update.into_inner();
                    let param = next_child(&mut ui, "reconfigure parameter")?
                        .as_str()
                        .to_string();
                    if !seen_params.insert(param.clone()) {
                        return Err(ParseError::syntax(
                            format!("Duplicate reconfigure parameter '{param}'"),
                            action_span,
                            "",
                            "",
                        ));
                    }
                    let value = parse_expr(next_child(&mut ui, "reconfigure value")?)?;
                    local_updates.push((param, value));
                }

                if local_updates.is_empty() {
                    return Err(ParseError::syntax(
                        "reconfigure action requires at least one parameter assignment",
                        action_span,
                        "",
                        "",
                    ));
                }

                // Stage-1 lowering keeps reconfigure syntax local to DSL by
                // desugaring into ordered assignment actions.
                for (param, value) in local_updates {
                    actions.push(Action::Assign { var: param, value });
                }
            }
            Rule::append_action => {
                let mut si = item.into_inner();
                let collection = next_child(&mut si, "si")?.as_str().to_string();
                let value = parse_expr(next_child(&mut si, "si")?)?;
                actions.push(Action::Append { collection, value });
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
        Rule::index_access => {
            let mut inner = pair.into_inner();
            let coll = next_child(&mut inner, "index_access collection")?
                .as_str()
                .to_string();
            let idx = parse_expr(next_child(&mut inner, "index_access index")?)?;
            Ok(Expr::Index(coll, Box::new(idx)))
        }
        Rule::len_expr => {
            let inner_expr = next_child(&mut pair.into_inner(), "len_expr")?;
            match parse_expr(inner_expr)? {
                Expr::Var(name) => Ok(Expr::Len(name)),
                other => Ok(Expr::Len(other.to_string())),
            }
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
mod tests;
