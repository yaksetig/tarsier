use super::*;
use crate::DefinitionKind;

fn parse(src: &str) -> Program {
    tarsier_dsl::parse_with_diagnostics(src, "test.trs")
        .unwrap()
        .0
}

static EXAMPLE_SRC: &str = r#"protocol P {
    parameters { n: nat; t: nat; }
    resilience { n > 3*t; }
    message Echo;
    message Ready;
    role Node {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                send Ready;
                goto phase done;
            }
        }
        phase done {
        }
    }
}"#;

#[test]
fn build_symbol_tables_params() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    assert!(tables.params.contains("n"));
    assert!(tables.params.contains("t"));
}

#[test]
fn build_symbol_tables_roles() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    assert!(tables.roles.contains("Node"));
}

#[test]
fn build_symbol_tables_role_vars() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    let node_vars = tables.role_vars.get("Node").unwrap();
    assert!(node_vars.contains("decided"));
}

#[test]
fn build_symbol_tables_role_phases() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    let node_phases = tables.role_phases.get("Node").unwrap();
    assert!(node_phases.contains("waiting"));
    assert!(node_phases.contains("done"));
}

#[test]
fn collect_symbol_occurrences_finds_declarations() {
    let program = parse(EXAMPLE_SRC);
    let occs = collect_symbol_occurrences(EXAMPLE_SRC, &program);
    let declarations: Vec<_> = occs.iter().filter(|o| o.declaration).collect();
    assert!(!declarations.is_empty());
    let decl_names: Vec<&str> = declarations.iter().map(|o| o.name.as_str()).collect();
    assert!(decl_names.contains(&"n"));
    assert!(decl_names.contains(&"t"));
    assert!(decl_names.contains(&"waiting"));
    assert!(decl_names.contains(&"done"));
}

#[test]
fn collect_symbol_occurrences_message_refs() {
    let program = parse(EXAMPLE_SRC);
    let occs = collect_symbol_occurrences(EXAMPLE_SRC, &program);
    let echo_occs: Vec<_> = occs
        .iter()
        .filter(|o| o.name == "Echo" && o.kind == DefinitionKind::Message)
        .collect();
    assert!(
        echo_occs.len() >= 2,
        "Echo should appear multiple times, got {}",
        echo_occs.len()
    );
}

#[test]
fn collect_symbol_occurrences_phase_refs() {
    let program = parse(EXAMPLE_SRC);
    let occs = collect_symbol_occurrences(EXAMPLE_SRC, &program);
    let done_occs: Vec<_> = occs
        .iter()
        .filter(|o| o.name == "done" && o.kind == DefinitionKind::Phase)
        .collect();
    assert!(
        done_occs.len() >= 2,
        "phase done should have decl + goto ref, got {}",
        done_occs.len()
    );
}

#[test]
fn collect_symbol_occurrences_sorted() {
    let program = parse(EXAMPLE_SRC);
    let occs = collect_symbol_occurrences(EXAMPLE_SRC, &program);
    for i in 1..occs.len() {
        assert!(occs[i].start >= occs[i - 1].start);
    }
}

#[test]
fn collect_symbol_occurrences_no_duplicates() {
    let program = parse(EXAMPLE_SRC);
    let occs = collect_symbol_occurrences(EXAMPLE_SRC, &program);
    for i in 1..occs.len() {
        let prev = &occs[i - 1];
        let curr = &occs[i];
        let is_dup = prev.start == curr.start
            && prev.end == curr.end
            && prev.name == curr.name
            && prev.kind == curr.kind
            && prev.parent == curr.parent
            && prev.declaration == curr.declaration;
        assert!(!is_dup, "found duplicate at offset {}", curr.start);
    }
}

#[test]
fn collect_references_finds_echo() {
    let program = parse(EXAMPLE_SRC);
    let refs = collect_references(EXAMPLE_SRC, &program, "Echo");
    assert!(
        refs.len() >= 2,
        "should find Echo at least twice, got {}",
        refs.len()
    );
}

#[test]
fn collect_references_word_boundary() {
    let src = r#"protocol P {
    message Echo;
    message Echoed;
    role Node {
        init w;
        phase w {
            when received >= 1 Echo => {
                send Echoed;
                goto phase w;
            }
        }
    }
}"#;
    let program = parse(src);
    let refs = collect_references(src, &program, "Echo");
    for (start, end) in &refs {
        let matched = &src[*start..*end];
        assert_eq!(
            matched, "Echo",
            "word boundary check failed: got '{matched}'"
        );
    }
}

#[test]
fn collect_references_nonexistent() {
    let program = parse(EXAMPLE_SRC);
    let refs = collect_references(EXAMPLE_SRC, &program, "NoSuchSymbol");
    assert!(refs.is_empty());
}

#[test]
fn classify_runtime_identifier_var() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    let result = classify_runtime_identifier("decided", &tables, Some("Node"));
    assert_eq!(
        result,
        Some((DefinitionKind::Var, Some("Node".to_string())))
    );
}

#[test]
fn classify_runtime_identifier_param() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    let result = classify_runtime_identifier("n", &tables, Some("Node"));
    assert_eq!(result, Some((DefinitionKind::Param, None)));
}

#[test]
fn classify_runtime_identifier_unknown() {
    let program = parse(EXAMPLE_SRC);
    let tables = build_symbol_tables(&program);
    let result = classify_runtime_identifier("unknown_name", &tables, Some("Node"));
    assert_eq!(result, None);
}
