use pest::Parser as _;
use std::collections::HashMap;

use crate::navigation::definition_kind_sort_key;
use crate::utils::is_ident_char;
use crate::{
    reference_parser::{Rule as ReferenceRule, TarsierReferenceParser},
    DefinitionKind, ReferencePair, SymbolOccurrence, SymbolTables,
};

use tarsier_dsl::ast::Program;

pub(crate) fn build_symbol_tables(program: &Program) -> SymbolTables {
    let mut tables = SymbolTables::default();
    let proto = &program.protocol.node;

    for param in &proto.parameters {
        tables.params.insert(param.name.clone());
    }
    for role in &proto.roles {
        tables.roles.insert(role.node.name.clone());

        let role_vars = tables.role_vars.entry(role.node.name.clone()).or_default();
        for var in &role.node.vars {
            role_vars.insert(var.name.clone());
        }

        let role_phases = tables
            .role_phases
            .entry(role.node.name.clone())
            .or_default();
        for phase in &role.node.phases {
            role_phases.insert(phase.node.name.clone());
        }
    }

    tables
}

fn add_occurrence(
    out: &mut Vec<SymbolOccurrence>,
    name: &str,
    kind: DefinitionKind,
    parent: Option<&str>,
    start: usize,
    end: usize,
    declaration: bool,
) {
    if start >= end {
        return;
    }
    out.push(SymbolOccurrence {
        name: name.to_string(),
        kind,
        parent: parent.map(ToString::to_string),
        start,
        end,
        declaration,
    });
}

fn classify_runtime_identifier(
    name: &str,
    tables: &SymbolTables,
    current_role: Option<&str>,
) -> Option<(DefinitionKind, Option<String>)> {
    if let Some(role) = current_role {
        if tables
            .role_vars
            .get(role)
            .is_some_and(|vars| vars.contains(name))
        {
            return Some((DefinitionKind::Var, Some(role.to_string())));
        }
    }
    if tables.params.contains(name) {
        return Some((DefinitionKind::Param, None));
    }
    None
}

fn collect_expr_identifiers(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::ident => {
            if let Some((kind, parent)) =
                classify_runtime_identifier(pair.as_str(), tables, current_role)
            {
                let span = pair.as_span();
                add_occurrence(
                    out,
                    pair.as_str(),
                    kind,
                    parent.as_deref(),
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_expr_identifiers(child, tables, current_role, out);
            }
        }
    }
}

fn collect_linear_identifiers(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    collect_expr_identifiers(pair, tables, current_role, out);
}

fn collect_arg_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::arg => {
            if let Some(inner) = pair.into_inner().next() {
                collect_arg_occurrences(inner, tables, current_role, out);
            }
        }
        ReferenceRule::named_arg => {
            let mut inner = pair.into_inner();
            let _name = inner.next();
            if let Some(value) = inner.next() {
                collect_expr_identifiers(value, tables, current_role, out);
            }
        }
        _ => collect_expr_identifiers(pair, tables, current_role, out),
    }
}

fn collect_msg_filter_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: Option<&str>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::msg_filter_item => {
            let mut inner = pair.into_inner();
            let _name = inner.next();
            if let Some(value) = inner.next() {
                collect_expr_identifiers(value, tables, current_role, out);
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_msg_filter_occurrences(child, tables, current_role, out);
            }
        }
    }
}

fn collect_guard_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::guard_expr => {
            for child in pair.into_inner() {
                if child.as_rule() != ReferenceRule::guard_op {
                    collect_guard_occurrences(child, tables, current_role, out);
                }
            }
        }
        ReferenceRule::guard_atom => {
            if let Some(inner) = pair.into_inner().next() {
                collect_guard_occurrences(inner, tables, current_role, out);
            }
        }
        ReferenceRule::threshold_guard => {
            let mut captured_message = false;
            for child in pair.into_inner() {
                match child.as_rule() {
                    ReferenceRule::linear_expr_no_implicit | ReferenceRule::linear_expr => {
                        collect_linear_identifiers(child, tables, Some(current_role), out);
                    }
                    ReferenceRule::ident if !captured_message => {
                        captured_message = true;
                        let span = child.as_span();
                        add_occurrence(
                            out,
                            child.as_str(),
                            DefinitionKind::Message,
                            None,
                            span.start(),
                            span.end(),
                            false,
                        );
                    }
                    ReferenceRule::msg_filter => {
                        collect_msg_filter_occurrences(child, tables, Some(current_role), out);
                    }
                    _ => {}
                }
            }
        }
        ReferenceRule::has_crypto_guard => {
            let mut inner = pair.into_inner();
            let _object_name = inner.next();
            for child in inner {
                if child.as_rule() == ReferenceRule::msg_filter {
                    collect_msg_filter_occurrences(child, tables, Some(current_role), out);
                }
            }
        }
        ReferenceRule::comparison_guard => {
            for child in pair.into_inner() {
                if matches!(child.as_rule(), ReferenceRule::expr | ReferenceRule::term) {
                    collect_expr_identifiers(child, tables, Some(current_role), out);
                }
            }
        }
        ReferenceRule::bool_guard => {
            if let Some(name) = pair.into_inner().next() {
                if let Some((kind, parent)) =
                    classify_runtime_identifier(name.as_str(), tables, Some(current_role))
                {
                    let span = name.as_span();
                    add_occurrence(
                        out,
                        name.as_str(),
                        kind,
                        parent.as_deref(),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_guard_occurrences(child, tables, current_role, out);
            }
        }
    }
}

fn collect_transition_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    if let Some(guard) = inner.next() {
        collect_guard_occurrences(guard, tables, current_role, out);
    }

    for action in inner {
        match action.as_rule() {
            ReferenceRule::send_action => {
                let mut ai = action.into_inner();
                if let Some(msg) = ai.next() {
                    let span = msg.as_span();
                    add_occurrence(
                        out,
                        msg.as_str(),
                        DefinitionKind::Message,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
                for child in ai {
                    match child.as_rule() {
                        ReferenceRule::arg_list => {
                            for arg in child.into_inner() {
                                collect_arg_occurrences(arg, tables, Some(current_role), out);
                            }
                        }
                        ReferenceRule::ident => {
                            let span = child.as_span();
                            add_occurrence(
                                out,
                                child.as_str(),
                                DefinitionKind::Role,
                                None,
                                span.start(),
                                span.end(),
                                false,
                            );
                        }
                        _ => {}
                    }
                }
            }
            ReferenceRule::form_crypto_action => {
                let mut ai = action.into_inner();
                let _object_name = ai.next();
                for child in ai {
                    match child.as_rule() {
                        ReferenceRule::arg_list => {
                            for arg in child.into_inner() {
                                collect_arg_occurrences(arg, tables, Some(current_role), out);
                            }
                        }
                        ReferenceRule::ident => {
                            let span = child.as_span();
                            add_occurrence(
                                out,
                                child.as_str(),
                                DefinitionKind::Role,
                                None,
                                span.start(),
                                span.end(),
                                false,
                            );
                        }
                        _ => {}
                    }
                }
            }
            ReferenceRule::lock_crypto_action | ReferenceRule::justify_crypto_action => {
                let mut ai = action.into_inner();
                let _object_name = ai.next();
                for child in ai {
                    if child.as_rule() == ReferenceRule::arg_list {
                        for arg in child.into_inner() {
                            collect_arg_occurrences(arg, tables, Some(current_role), out);
                        }
                    }
                }
            }
            ReferenceRule::assign_action => {
                let mut ai = action.into_inner();
                if let Some(var) = ai.next() {
                    let span = var.as_span();
                    add_occurrence(
                        out,
                        var.as_str(),
                        DefinitionKind::Var,
                        Some(current_role),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
                if let Some(expr) = ai.next() {
                    collect_expr_identifiers(expr, tables, Some(current_role), out);
                }
            }
            ReferenceRule::goto_action => {
                if let Some(phase) = action.into_inner().next() {
                    let span = phase.as_span();
                    add_occurrence(
                        out,
                        phase.as_str(),
                        DefinitionKind::Phase,
                        Some(current_role),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
            ReferenceRule::decide_action => {
                if let Some(expr) = action.into_inner().next() {
                    collect_expr_identifiers(expr, tables, Some(current_role), out);
                }
            }
            _ => {}
        }
    }
}

fn collect_phase_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(phase_name) = inner.next() else {
        return;
    };
    let phase_span = phase_name.as_span();
    add_occurrence(
        out,
        phase_name.as_str(),
        DefinitionKind::Phase,
        Some(current_role),
        phase_span.start(),
        phase_span.end(),
        true,
    );

    for item in inner {
        if item.as_rule() == ReferenceRule::transition_rule {
            collect_transition_occurrences(item, tables, current_role, out);
        }
    }
}

fn collect_var_decl_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    current_role: &str,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(var_name) = inner.next() else {
        return;
    };
    let span = var_name.as_span();
    add_occurrence(
        out,
        var_name.as_str(),
        DefinitionKind::Var,
        Some(current_role),
        span.start(),
        span.end(),
        true,
    );

    if let Some(var_ty) = inner.next() {
        if var_ty.as_rule() == ReferenceRule::ident {
            let ty_span = var_ty.as_span();
            add_occurrence(
                out,
                var_ty.as_str(),
                DefinitionKind::Enum,
                None,
                ty_span.start(),
                ty_span.end(),
                false,
            );
        }
    }

    for item in inner {
        if item.as_rule() == ReferenceRule::expr {
            collect_expr_identifiers(item, tables, Some(current_role), out);
        }
    }
}

fn collect_role_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner();
    let Some(role_name) = inner.next() else {
        return;
    };
    let role = role_name.as_str().to_string();
    let span = role_name.as_span();
    add_occurrence(
        out,
        &role,
        DefinitionKind::Role,
        None,
        span.start(),
        span.end(),
        true,
    );

    for item in inner {
        match item.as_rule() {
            ReferenceRule::var_decl => collect_var_decl_occurrences(item, tables, &role, out),
            ReferenceRule::init_decl => {
                if let Some(init_phase) = item.into_inner().next() {
                    let init_span = init_phase.as_span();
                    add_occurrence(
                        out,
                        init_phase.as_str(),
                        DefinitionKind::Phase,
                        Some(&role),
                        init_span.start(),
                        init_span.end(),
                        false,
                    );
                }
            }
            ReferenceRule::phase_decl => collect_phase_occurrences(item, tables, &role, out),
            _ => {}
        }
    }
}

fn collect_parameters_occurrences(pair: ReferencePair<'_>, out: &mut Vec<SymbolOccurrence>) {
    for item in pair.into_inner() {
        match item.as_rule() {
            ReferenceRule::param_def | ReferenceRule::param_list_item => {
                if let Some(name) = item.into_inner().next() {
                    let span = name.as_span();
                    add_occurrence(
                        out,
                        name.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        true,
                    );
                }
            }
            ReferenceRule::param_list => {
                for arg in item.into_inner() {
                    if arg.as_rule() == ReferenceRule::param_list_item {
                        collect_parameters_occurrences(arg, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_property_formula_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    quantifier_domains: &HashMap<String, String>,
    out: &mut Vec<SymbolOccurrence>,
) {
    match pair.as_rule() {
        ReferenceRule::qualified_ident => {
            let mut inner = pair.into_inner();
            let Some(object) = inner.next() else {
                return;
            };
            let Some(field) = inner.next() else {
                return;
            };
            if let Some(role_domain) = quantifier_domains.get(object.as_str()) {
                if tables
                    .role_vars
                    .get(role_domain)
                    .is_some_and(|vars| vars.contains(field.as_str()))
                {
                    let span = field.as_span();
                    add_occurrence(
                        out,
                        field.as_str(),
                        DefinitionKind::Var,
                        Some(role_domain),
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::ident => {
            let name = pair.as_str();
            if quantifier_domains.contains_key(name) {
                return;
            }
            if tables.params.contains(name) {
                let span = pair.as_span();
                add_occurrence(
                    out,
                    name,
                    DefinitionKind::Param,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        _ => {
            for child in pair.into_inner() {
                collect_property_formula_occurrences(child, tables, quantifier_domains, out);
            }
        }
    }
}

fn collect_quantified_formula_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    let mut inner = pair.into_inner().peekable();
    let mut quantifier_domains: HashMap<String, String> = HashMap::new();

    while let Some(next) = inner.peek() {
        if next.as_rule() != ReferenceRule::quantifier {
            break;
        }
        let _quantifier = inner.next();
        let Some(var_name) = inner.next() else {
            break;
        };
        let Some(domain_name) = inner.next() else {
            break;
        };
        quantifier_domains.insert(
            var_name.as_str().to_string(),
            domain_name.as_str().to_string(),
        );
        let span = domain_name.as_span();
        add_occurrence(
            out,
            domain_name.as_str(),
            DefinitionKind::Role,
            None,
            span.start(),
            span.end(),
            false,
        );
    }

    if let Some(formula_body) = inner.next() {
        collect_property_formula_occurrences(formula_body, tables, &quantifier_domains, out);
    }
}

fn collect_module_interface_occurrences(
    pair: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    for item in pair.into_inner() {
        match item.as_rule() {
            ReferenceRule::assumes_clause => {
                for child in item.into_inner() {
                    if matches!(child.as_rule(), ReferenceRule::linear_expr) {
                        collect_linear_identifiers(child, tables, None, out);
                    }
                }
            }
            ReferenceRule::guarantees_clause => {
                let mut inner = item.into_inner();
                let _kind = inner.next();
                if let Some(prop_name) = inner.next() {
                    let span = prop_name.as_span();
                    add_occurrence(
                        out,
                        prop_name.as_str(),
                        DefinitionKind::Property,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
            _ => {}
        }
    }
}

fn collect_protocol_item_occurrences(
    item: ReferencePair<'_>,
    tables: &SymbolTables,
    out: &mut Vec<SymbolOccurrence>,
) {
    match item.as_rule() {
        ReferenceRule::module_decl => {
            let mut inner = item.into_inner();
            let _module_name = inner.next();
            for child in inner {
                match child.as_rule() {
                    ReferenceRule::module_interface => {
                        collect_module_interface_occurrences(child, tables, out)
                    }
                    _ => collect_protocol_item_occurrences(child, tables, out),
                }
            }
        }
        ReferenceRule::enum_decl => {
            if let Some(name) = item.into_inner().next() {
                let span = name.as_span();
                add_occurrence(
                    out,
                    name.as_str(),
                    DefinitionKind::Enum,
                    None,
                    span.start(),
                    span.end(),
                    true,
                );
            }
        }
        ReferenceRule::parameters_decl
        | ReferenceRule::param_def
        | ReferenceRule::param_list
        | ReferenceRule::param_list_item => collect_parameters_occurrences(item, out),
        ReferenceRule::resilience_decl => {
            for child in item.into_inner() {
                if matches!(child.as_rule(), ReferenceRule::resilience_expr) {
                    for expr in child.into_inner() {
                        if matches!(expr.as_rule(), ReferenceRule::linear_expr) {
                            collect_linear_identifiers(expr, tables, None, out);
                        }
                    }
                }
            }
        }
        ReferenceRule::pacemaker_decl => {
            for pm_item in item.into_inner() {
                if pm_item.as_rule() != ReferenceRule::pacemaker_item {
                    continue;
                }
                let mut inner = pm_item.into_inner();
                let key = inner.next().map(|k| k.as_str().to_string());
                let Some(values) = inner.next() else {
                    continue;
                };
                for value in values.into_inner() {
                    if value.as_rule() != ReferenceRule::ident {
                        continue;
                    }
                    let span = value.as_span();
                    match key.as_deref() {
                        Some("start") => add_occurrence(
                            out,
                            value.as_str(),
                            DefinitionKind::Phase,
                            None,
                            span.start(),
                            span.end(),
                            false,
                        ),
                        _ => {
                            if tables.params.contains(value.as_str()) {
                                add_occurrence(
                                    out,
                                    value.as_str(),
                                    DefinitionKind::Param,
                                    None,
                                    span.start(),
                                    span.end(),
                                    false,
                                );
                            }
                        }
                    }
                }
            }
        }
        ReferenceRule::adversary_decl => {
            for adversary_item in item.into_inner() {
                if adversary_item.as_rule() != ReferenceRule::adversary_item {
                    continue;
                }
                let mut inner = adversary_item.into_inner();
                let key = inner.next().map(|k| k.as_str().to_string());
                let Some(value) = inner.next() else {
                    continue;
                };
                if value.as_rule() == ReferenceRule::ident
                    && (tables.params.contains(value.as_str())
                        || matches!(key.as_deref(), Some("bound")))
                {
                    let span = value.as_span();
                    add_occurrence(
                        out,
                        value.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::identity_decl => {
            if let Some(role_name) = item.into_inner().next() {
                let span = role_name.as_span();
                add_occurrence(
                    out,
                    role_name.as_str(),
                    DefinitionKind::Role,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        ReferenceRule::channel_decl | ReferenceRule::equivocation_decl => {
            if let Some(msg_name) = item.into_inner().next() {
                let span = msg_name.as_span();
                add_occurrence(
                    out,
                    msg_name.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
        }
        ReferenceRule::committee_decl => {
            let mut inner = item.into_inner();
            let _committee_name = inner.next();
            for committee_item in inner {
                if committee_item.as_rule() != ReferenceRule::committee_item {
                    continue;
                }
                let mut item_inner = committee_item.into_inner();
                let _key = item_inner.next();
                let Some(value) = item_inner.next() else {
                    continue;
                };
                if value.as_rule() == ReferenceRule::ident && tables.params.contains(value.as_str())
                {
                    let span = value.as_span();
                    add_occurrence(
                        out,
                        value.as_str(),
                        DefinitionKind::Param,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::message_decl => {
            if let Some(message_name) = item.into_inner().next() {
                let span = message_name.as_span();
                add_occurrence(
                    out,
                    message_name.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    true,
                );
            }
        }
        ReferenceRule::crypto_object_decl => {
            let mut inner = item.into_inner();
            let _kind = inner.next();
            let _object_name = inner.next();
            if let Some(source_message) = inner.next() {
                let span = source_message.as_span();
                add_occurrence(
                    out,
                    source_message.as_str(),
                    DefinitionKind::Message,
                    None,
                    span.start(),
                    span.end(),
                    false,
                );
            }
            if let Some(threshold) = inner.next() {
                collect_linear_identifiers(threshold, tables, None, out);
            }
            for extra in inner {
                if extra.as_rule() == ReferenceRule::ident {
                    let span = extra.as_span();
                    add_occurrence(
                        out,
                        extra.as_str(),
                        DefinitionKind::Role,
                        None,
                        span.start(),
                        span.end(),
                        false,
                    );
                }
            }
        }
        ReferenceRule::role_decl => collect_role_occurrences(item, tables, out),
        ReferenceRule::property_decl => {
            let mut inner = item.into_inner();
            let Some(name) = inner.next() else {
                return;
            };
            let span = name.as_span();
            add_occurrence(
                out,
                name.as_str(),
                DefinitionKind::Property,
                None,
                span.start(),
                span.end(),
                true,
            );
            let _kind = inner.next();
            if let Some(formula) = inner.next() {
                collect_quantified_formula_occurrences(formula, tables, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn collect_symbol_occurrences(source: &str, program: &Program) -> Vec<SymbolOccurrence> {
    let Ok(mut parsed) = TarsierReferenceParser::parse(ReferenceRule::program, source) else {
        return Vec::new();
    };
    let Some(program_pair) = parsed.next() else {
        return Vec::new();
    };
    let Some(protocol_decl) = program_pair
        .into_inner()
        .find(|pair| pair.as_rule() == ReferenceRule::protocol_decl)
    else {
        return Vec::new();
    };

    let tables = build_symbol_tables(program);
    let mut out = Vec::new();
    for item in protocol_decl.into_inner() {
        collect_protocol_item_occurrences(item, &tables, &mut out);
    }

    out.sort_by_key(|occ| {
        (
            occ.start,
            occ.end,
            occ.name.clone(),
            definition_kind_sort_key(&occ.kind),
            occ.parent.clone(),
            occ.declaration,
        )
    });
    out.dedup_by(|a, b| {
        a.start == b.start
            && a.end == b.end
            && a.name == b.name
            && a.kind == b.kind
            && a.parent == b.parent
            && a.declaration == b.declaration
    });
    out
}

// ---------------------------------------------------------------------------
// Collect references (text-based search within AST spans)
// ---------------------------------------------------------------------------

pub(crate) fn collect_references(
    source: &str,
    program: &Program,
    name: &str,
) -> Vec<(usize, usize)> {
    let mut refs = Vec::new();
    let name_len = name.len();

    // Search for all occurrences of the name as a whole word in the source
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(name) {
        let abs_pos = search_from + pos;
        // Check word boundaries
        let before_ok = abs_pos == 0 || !is_ident_char(source.as_bytes()[abs_pos - 1]);
        let after_ok = abs_pos + name_len >= source.len()
            || !is_ident_char(source.as_bytes()[abs_pos + name_len]);
        if before_ok && after_ok {
            refs.push((abs_pos, abs_pos + name_len));
        }
        search_from = abs_pos + 1;
    }

    // Filter to only references within the protocol span
    let proto_start = program.protocol.span.start;
    let proto_end = program.protocol.span.end;
    refs.retain(|&(start, end)| start >= proto_start && end <= proto_end);

    refs
}
