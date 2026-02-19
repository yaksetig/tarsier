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

/// Parse a .trs source file into an AST Program.
pub fn parse(source: &str, filename: &str) -> Result<Program, ParseError> {
    let (program, _) = parse_with_diagnostics(source, filename)?;
    Ok(program)
}

/// Parse a .trs source file into an AST Program and emit parser diagnostics.
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

    let program_pair = pairs.into_iter().next().unwrap();
    let protocol_pair = program_pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::protocol_decl)
        .unwrap();

    let protocol = parse_protocol(protocol_pair, source, filename)?;
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
    let name = inner.next().unwrap().as_str().to_string();

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

    for item in inner {
        match item.as_rule() {
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
                adversary = parse_adversary(item)?;
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

    Ok(Spanned::new(
        ProtocolDecl {
            name,
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

fn parse_enum(pair: Pair<'_>) -> Result<EnumDecl, ParseError> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut variants = Vec::new();
    for item in inner {
        if item.as_rule() == Rule::ident {
            variants.push(item.as_str().to_string());
        }
    }
    Ok(EnumDecl { name, variants })
}

fn parse_parameters(pair: Pair<'_>) -> Result<Vec<ParamDef>, ParseError> {
    let mut params = Vec::new();
    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::param_def => {
                let span = span_from(&item);
                let mut inner = item.into_inner();
                let name = inner.next().unwrap().as_str().to_string();
                let ty = match inner.next().unwrap().as_str() {
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
                        let name = inner.next().unwrap().as_str().to_string();
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
                let name = inner.next().unwrap().as_str().to_string();
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
        .unwrap();
    let mut inner = expr_pair.into_inner();
    let lhs = parse_linear_expr(inner.next().unwrap())?;
    let op = parse_cmp_op(inner.next().unwrap());
    let rhs = parse_linear_expr(inner.next().unwrap())?;
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
        let key = inner.next().unwrap().as_str();
        let list = inner.next().unwrap();
        let values: Vec<String> = list
            .into_inner()
            .filter(|p| p.as_rule() == Rule::ident)
            .map(|p| p.as_str().to_string())
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

fn parse_adversary(pair: Pair<'_>) -> Result<Vec<AdversaryItem>, ParseError> {
    let mut items = Vec::new();
    for item in pair.into_inner() {
        if item.as_rule() == Rule::adversary_item {
            let span = span_from(&item);
            let mut inner = item.into_inner();
            let key = inner.next().unwrap().as_str().to_string();
            let value = inner.next().unwrap().as_str().to_string();
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
    let name = inner.next().unwrap().as_str().to_string();
    let mut items = Vec::new();

    for item in inner {
        if item.as_rule() == Rule::committee_item {
            let item_span = span_from(&item);
            let mut ci = item.into_inner();
            let key = ci.next().unwrap().as_str().to_string();
            let value_pair = ci.next().unwrap();
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
    let name = inner.next().unwrap().as_str().to_string();
    let mut fields = Vec::new();
    for item in inner {
        if item.as_rule() == Rule::field_list {
            for field in item.into_inner() {
                if field.as_rule() == Rule::field {
                    let mut fi = field.into_inner();
                    let fname = fi.next().unwrap().as_str().to_string();
                    let ftype = fi.next().unwrap().as_str().to_string();
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
    let name = inner.next().unwrap().as_str().to_string();
    let source_message = inner.next().unwrap().as_str().to_string();
    let threshold = parse_linear_expr(inner.next().unwrap())?;
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
    let name = inner.next().unwrap().as_str().to_string();
    let mut vars = Vec::new();
    let mut init_phase = None;
    let mut phases = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::var_decl => vars.push(parse_var_decl(item)?),
            Rule::init_decl => {
                init_phase = Some(item.into_inner().next().unwrap().as_str().to_string());
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
    let name = inner.next().unwrap().as_str().to_string();
    let ty_pair = inner.next().unwrap();
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
    let name = inner.next().unwrap().as_str().to_string();
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
    let guard_pair = inner.next().unwrap();
    let guard = parse_guard_expr(guard_pair)?;

    let mut actions = Vec::new();
    for item in inner {
        match item.as_rule() {
            Rule::send_action => {
                let mut si = item.into_inner();
                let msg = si.next().unwrap().as_str().to_string();
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
                let object_name = si.next().unwrap().as_str().to_string();
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
                let object_name = si.next().unwrap().as_str().to_string();
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
                let object_name = si.next().unwrap().as_str().to_string();
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
                let var = si.next().unwrap().as_str().to_string();
                let value = parse_expr(si.next().unwrap())?;
                actions.push(Action::Assign { var, value });
            }
            Rule::goto_action => {
                let phase = item.into_inner().next().unwrap().as_str().to_string();
                actions.push(Action::GotoPhase { phase });
            }
            Rule::decide_action => {
                let value = parse_expr(item.into_inner().next().unwrap())?;
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
            let inner = pair.into_inner().next().unwrap();
            parse_send_arg(inner)
        }
        Rule::named_arg => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let value = parse_expr(inner.next().unwrap())?;
            Ok(SendArg::Named { name, value })
        }
        _ => Ok(SendArg::Positional(parse_expr(pair)?)),
    }
}

fn parse_guard_expr(pair: Pair<'_>) -> Result<GuardExpr, ParseError> {
    let mut inner = pair.into_inner();
    let first = inner.next().unwrap();
    let mut result = parse_guard_atom(first)?;

    while let Some(op_pair) = inner.next() {
        let op = op_pair.as_str();
        let next = inner.next().unwrap();
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
                                            let name = ai.next().unwrap().as_str().to_string();
                                            let value = parse_expr(ai.next().unwrap())?;
                                            message_args.push((name, value));
                                        }
                                    }
                                }
                                Rule::msg_filter_item => {
                                    let mut ai = filter.into_inner();
                                    let name = ai.next().unwrap().as_str().to_string();
                                    let value = parse_expr(ai.next().unwrap())?;
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
                                    let name = ai.next().unwrap().as_str().to_string();
                                    let value = parse_expr(ai.next().unwrap())?;
                                    object_args.push((name, value));
                                }
                            }
                        }
                        Rule::msg_filter_item => {
                            let mut ai = filter.into_inner();
                            let name = ai.next().unwrap().as_str().to_string();
                            let value = parse_expr(ai.next().unwrap())?;
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
            let lhs = parse_expr(inner.next().unwrap())?;
            let op = parse_cmp_op(inner.next().unwrap());
            let rhs = parse_expr(inner.next().unwrap())?;
            Ok(GuardExpr::Comparison { lhs, op, rhs })
        }
        Rule::bool_guard => {
            let name = pair.into_inner().next().unwrap().as_str().to_string();
            Ok(GuardExpr::BoolVar(name))
        }
        Rule::guard_expr => parse_guard_expr(pair),
        _ => {
            // Try to parse as sub-expressions
            let span = span_from(&pair);
            let inner: Vec<_> = pair.into_inner().collect();
            if inner.len() == 1 {
                parse_guard_atom(inner.into_iter().next().unwrap())
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
            let first = parse_expr(inner.next().unwrap())?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_expr(inner.next().unwrap())?;
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
            let first = parse_expr(inner.next().unwrap())?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_expr(inner.next().unwrap())?;
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
                parse_expr(inner.into_iter().next().unwrap())
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
            let first = parse_linear_expr(inner.next().unwrap())?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_linear_expr(inner.next().unwrap())?;
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
                parse_linear_expr(inner.into_iter().next().unwrap())
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
        _ => CmpOp::Eq,
    }
}

fn parse_property(pair: Pair<'_>) -> Result<Spanned<PropertyDecl>, ParseError> {
    let span = span_from(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let kind_pair = inner.next().unwrap();
    let kind = match kind_pair.as_str() {
        "agreement" => PropertyKind::Agreement,
        "validity" => PropertyKind::Validity,
        "safety" => PropertyKind::Safety,
        "invariant" => PropertyKind::Invariant,
        "liveness" => PropertyKind::Liveness,
        _ => PropertyKind::Safety,
    };
    let formula_pair = inner.next().unwrap();
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
                _ => Quantifier::ForAll,
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
        FormulaExpr::Comparison {
            lhs: FormulaAtom::BoolLit(true),
            op: CmpOp::Eq,
            rhs: FormulaAtom::BoolLit(true),
        }
    };

    Ok(QuantifiedFormula { quantifiers, body })
}

fn parse_formula_expr(pair: Pair<'_>) -> Result<FormulaExpr, ParseError> {
    match pair.as_rule() {
        Rule::formula_expr => {
            let mut inner = pair.into_inner();
            let first = parse_formula_expr(inner.next().unwrap())?;
            let mut result = first;
            while let Some(op_pair) = inner.next() {
                let rhs = parse_formula_expr(inner.next().unwrap())?;
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
            let lhs = parse_formula_term(inner.next().unwrap())?;
            let op = parse_cmp_op(inner.next().unwrap());
            let rhs = parse_formula_term(inner.next().unwrap())?;
            Ok(FormulaExpr::Comparison { lhs, op, rhs })
        }
        Rule::formula_not => {
            let inner = pair.into_inner().next().unwrap();
            let sub = parse_formula_expr(inner)?;
            Ok(FormulaExpr::Not(Box::new(sub)))
        }
        Rule::formula_temporal_prefix => {
            let mut inner = pair.into_inner();
            let op = inner.next().unwrap().as_str().to_string();
            let rhs = parse_formula_expr(inner.next().unwrap())?;
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
            let object = inner.next().unwrap().as_str().to_string();
            let field = inner.next().unwrap().as_str().to_string();
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
}
