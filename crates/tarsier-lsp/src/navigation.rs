use tower_lsp::lsp_types::*;

use crate::code_actions::levenshtein;
use crate::hover::keyword_docs;
use crate::symbol_analysis::collect_references;
use crate::utils::{offset_to_range, word_at_position};
use crate::{collect_definitions, DefinitionInfo, DefinitionKind, SymbolOccurrence, SymbolTarget};

use tarsier_dsl::ast::Program;

pub(crate) fn definition_spans_for_name(program: &Program, name: &str) -> Vec<(usize, usize)> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.name == name && def.start < def.end)
        .map(|def| (def.start, def.end))
        .collect()
}

pub(crate) fn definition_locations(
    source: &str,
    program: &Program,
    uri: &Url,
    name: &str,
) -> Vec<Location> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.name == name && def.start < def.end)
        .filter_map(|def| {
            offset_to_range(source, def.start, def.end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

pub(crate) fn reference_locations(
    source: &str,
    program: &Program,
    uri: &Url,
    name: &str,
    include_declaration: bool,
) -> Vec<Location> {
    let declaration_spans = if include_declaration {
        Vec::new()
    } else {
        definition_spans_for_name(program, name)
    };

    collect_references(source, program, name)
        .into_iter()
        .filter(|(start, end)| {
            include_declaration
                || !declaration_spans
                    .iter()
                    .any(|(dstart, dend)| start >= dstart && end <= dend)
        })
        .filter_map(|(start, end)| {
            offset_to_range(source, start, end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

pub(crate) fn symbol_target_from_definition(def: &DefinitionInfo) -> SymbolTarget {
    SymbolTarget {
        name: def.name.clone(),
        kind: def.kind.clone(),
        parent: def.parent.clone(),
    }
}

pub(crate) fn symbol_target_from_occurrence(occ: &SymbolOccurrence) -> SymbolTarget {
    SymbolTarget {
        name: occ.name.clone(),
        kind: occ.kind.clone(),
        parent: occ.parent.clone(),
    }
}

pub(crate) fn symbol_target_matches_occurrence(
    target: &SymbolTarget,
    occ: &SymbolOccurrence,
) -> bool {
    target.name == occ.name && target.kind == occ.kind && target.parent == occ.parent
}

pub(crate) fn symbol_target_matches_definition(
    target: &SymbolTarget,
    def: &DefinitionInfo,
) -> bool {
    target.name == def.name && target.kind == def.kind && target.parent == def.parent
}

pub(crate) fn definition_kind_sort_key(kind: &DefinitionKind) -> u8 {
    match kind {
        DefinitionKind::Message => 0,
        DefinitionKind::Role => 1,
        DefinitionKind::Phase => 2,
        DefinitionKind::Param => 3,
        DefinitionKind::Var => 4,
        DefinitionKind::Property => 5,
        DefinitionKind::Enum => 6,
    }
}

pub(crate) fn dedup_symbol_targets(targets: Vec<SymbolTarget>) -> Vec<SymbolTarget> {
    let mut deduped = targets;
    deduped.sort_by_key(|t| {
        (
            t.name.clone(),
            definition_kind_sort_key(&t.kind),
            t.parent.clone(),
        )
    });
    deduped.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.parent == b.parent);
    deduped
}

pub(crate) fn definition_spans_for_target(
    program: &Program,
    target: &SymbolTarget,
) -> Vec<(usize, usize)> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.start < def.end && symbol_target_matches_definition(target, def))
        .map(|def| (def.start, def.end))
        .collect()
}

pub(crate) fn has_target_definition(program: &Program, target: &SymbolTarget) -> bool {
    collect_definitions(program)
        .into_iter()
        .any(|def| def.start < def.end && symbol_target_matches_definition(target, &def))
}

pub(crate) fn dedup_and_sort_spans(spans: &mut Vec<(usize, usize)>) {
    spans.sort_unstable();
    spans.dedup();
}

pub(crate) fn resolve_symbol_target(
    source: &str,
    program: &Program,
    offset: usize,
    occurrences: &[SymbolOccurrence],
) -> Option<SymbolTarget> {
    let (word, start, end) = word_at_position(source, offset)?;
    if keyword_docs(&word).is_some() {
        return None;
    }

    let exact_targets = dedup_symbol_targets(
        occurrences
            .iter()
            .filter(|occ| occ.name == word && occ.start == start && occ.end == end)
            .map(symbol_target_from_occurrence)
            .collect(),
    );
    if exact_targets.len() == 1 {
        return exact_targets.into_iter().next();
    }
    if exact_targets.len() > 1 {
        let declaration_targets = dedup_symbol_targets(
            occurrences
                .iter()
                .filter(|occ| {
                    occ.name == word && occ.start == start && occ.end == end && occ.declaration
                })
                .map(symbol_target_from_occurrence)
                .collect(),
        );
        if declaration_targets.len() == 1 {
            return declaration_targets.into_iter().next();
        }
        return None;
    }

    let defs_for_name = dedup_symbol_targets(
        collect_definitions(program)
            .into_iter()
            .filter(|def| def.name == word && def.start < def.end)
            .map(|def| symbol_target_from_definition(&def))
            .collect(),
    );
    if defs_for_name.len() == 1 {
        return defs_for_name.into_iter().next();
    }
    if defs_for_name.is_empty() {
        return None;
    }

    let role_scope = program
        .protocol
        .node
        .roles
        .iter()
        .find(|role| offset >= role.span.start && offset <= role.span.end)
        .map(|role| role.node.name.clone());
    if let Some(role_name) = role_scope {
        let scoped = dedup_symbol_targets(
            defs_for_name
                .into_iter()
                .filter(|target| target.parent.as_deref() == Some(role_name.as_str()))
                .collect(),
        );
        if scoped.len() == 1 {
            return scoped.into_iter().next();
        }
    }

    None
}

pub(crate) fn collect_reference_spans_for_target(
    source: &str,
    program: &Program,
    target: &SymbolTarget,
    include_declaration: bool,
    occurrences: &[SymbolOccurrence],
) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = occurrences
        .iter()
        .filter(|occ| symbol_target_matches_occurrence(target, occ))
        .filter(|occ| include_declaration || !occ.declaration)
        .map(|occ| (occ.start, occ.end))
        .collect();
    dedup_and_sort_spans(&mut spans);

    if spans.is_empty() {
        spans = collect_references(source, program, &target.name);
        if matches!(target.kind, DefinitionKind::Var | DefinitionKind::Phase) {
            if let Some(role_name) = target.parent.as_deref() {
                if let Some(role) = program
                    .protocol
                    .node
                    .roles
                    .iter()
                    .find(|role| role.node.name == role_name)
                {
                    spans.retain(|(start, end)| *start >= role.span.start && *end <= role.span.end);
                }
            }
        }
        if !include_declaration {
            let declaration_spans = definition_spans_for_target(program, target);
            spans.retain(|(start, end)| {
                !declaration_spans
                    .iter()
                    .any(|(dstart, dend)| start >= dstart && end <= dend)
            });
        }
        dedup_and_sort_spans(&mut spans);
    }

    spans
}

pub(crate) fn target_reference_locations(
    source: &str,
    program: &Program,
    uri: &Url,
    target: &SymbolTarget,
    include_declaration: bool,
    occurrences: &[SymbolOccurrence],
) -> Vec<Location> {
    collect_reference_spans_for_target(source, program, target, include_declaration, occurrences)
        .into_iter()
        .filter_map(|(start, end)| {
            offset_to_range(source, start, end).map(|range| Location {
                uri: uri.clone(),
                range,
            })
        })
        .collect()
}

fn location_sort_key(location: &Location) -> (String, u32, u32, u32, u32) {
    (
        location.uri.to_string(),
        location.range.start.line,
        location.range.start.character,
        location.range.end.line,
        location.range.end.character,
    )
}

pub(crate) fn dedup_and_sort_locations(locations: &mut Vec<Location>) {
    locations.sort_by_key(location_sort_key);
    locations.dedup_by(|a, b| location_sort_key(a) == location_sort_key(b));
}

pub(crate) fn as_goto_definition_response(
    mut locations: Vec<Location>,
) -> Option<GotoDefinitionResponse> {
    dedup_and_sort_locations(&mut locations);
    match locations.len() {
        0 => None,
        1 => Some(GotoDefinitionResponse::Scalar(locations.remove(0))),
        _ => Some(GotoDefinitionResponse::Array(locations)),
    }
}

pub(crate) fn symbol_kind_for_definition_kind(kind: &DefinitionKind) -> SymbolKind {
    match kind {
        DefinitionKind::Message => SymbolKind::STRUCT,
        DefinitionKind::Role => SymbolKind::CLASS,
        DefinitionKind::Phase => SymbolKind::METHOD,
        DefinitionKind::Param => SymbolKind::CONSTANT,
        DefinitionKind::Var => SymbolKind::VARIABLE,
        DefinitionKind::Property => SymbolKind::PROPERTY,
        DefinitionKind::Enum => SymbolKind::ENUM,
    }
}

pub(crate) fn workspace_symbol_query_matches(name: &str, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return true;
    }
    let name_lc = name.to_ascii_lowercase();
    let q_lc = q.to_ascii_lowercase();
    if name_lc.contains(&q_lc) || name_lc.starts_with(&q_lc) {
        return true;
    }
    levenshtein(&name_lc, &q_lc) <= 2
}

#[allow(deprecated)]
pub(crate) fn collect_workspace_symbol_information(
    source: &str,
    program: &Program,
    uri: &Url,
    query: &str,
) -> Vec<SymbolInformation> {
    collect_definitions(program)
        .into_iter()
        .filter(|def| def.start < def.end)
        .filter(|def| workspace_symbol_query_matches(&def.name, query))
        .filter_map(|def| {
            let range = offset_to_range(source, def.start, def.end)?;
            Some(SymbolInformation {
                name: def.name,
                kind: symbol_kind_for_definition_kind(&def.kind),
                tags: None,
                deprecated: None,
                location: Location {
                    uri: uri.clone(),
                    range,
                },
                container_name: def.parent,
            })
        })
        .collect()
}

fn workspace_symbol_sort_key(symbol: &SymbolInformation) -> (String, String, u32, u32, u32, u32) {
    (
        symbol.name.to_ascii_lowercase(),
        symbol.location.uri.to_string(),
        symbol.location.range.start.line,
        symbol.location.range.start.character,
        symbol.location.range.end.line,
        symbol.location.range.end.character,
    )
}

pub(crate) fn dedup_and_sort_workspace_symbols(symbols: &mut Vec<SymbolInformation>) {
    symbols.sort_by_key(workspace_symbol_sort_key);
    symbols.dedup_by(|a, b| {
        workspace_symbol_sort_key(a) == workspace_symbol_sort_key(b) && a.kind == b.kind
    });
}
