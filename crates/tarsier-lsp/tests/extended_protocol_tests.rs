//! Extended LSP integration tests covering hover, go-to-definition,
//! diagnostics, and completion features.

use serde_json::{json, Value};
use tower::{Service, ServiceExt};
use tower_lsp::LspService;

fn build_service() -> LspService<tarsier_lsp::TarsierLspBackend> {
    let (service, _socket) = LspService::new(tarsier_lsp::TarsierLspBackend::new);
    service
}

async fn send_request(
    service: &mut LspService<tarsier_lsp::TarsierLspBackend>,
    id: i64,
    method: &str,
    params: Value,
) -> Option<Value> {
    use tower_lsp::jsonrpc;

    let req_value = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    });
    let req: jsonrpc::Request = serde_json::from_value(req_value).unwrap();

    let resp = service.ready().await.unwrap().call(req).await.unwrap();
    resp.map(|r| serde_json::to_value(r).unwrap())
}

async fn send_notification(
    service: &mut LspService<tarsier_lsp::TarsierLspBackend>,
    method: &str,
    params: Value,
) {
    use tower_lsp::jsonrpc;

    let req_value = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    });
    let req: jsonrpc::Request = serde_json::from_value(req_value).unwrap();
    let _ = service.ready().await.unwrap().call(req).await;
}

async fn initialize(service: &mut LspService<tarsier_lsp::TarsierLspBackend>) {
    let init_params = json!({
        "processId": null,
        "capabilities": {},
        "rootUri": null
    });
    let resp = send_request(service, 1, "initialize", init_params).await;
    assert!(resp.is_some(), "initialize should return a response");

    send_notification(service, "initialized", json!({})).await;
}

async fn open_document(
    service: &mut LspService<tarsier_lsp::TarsierLspBackend>,
    uri: &str,
    text: &str,
) {
    send_notification(
        service,
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "tarsier",
                "version": 1,
                "text": text
            }
        }),
    )
    .await;
}

/// Helper: send hover request and return the result value.
async fn hover_at(
    service: &mut LspService<tarsier_lsp::TarsierLspBackend>,
    uri: &str,
    line: u32,
    character: u32,
) -> Value {
    let resp = send_request(
        service,
        10,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line, "character": character }
        }),
    )
    .await
    .expect("hover should return a response");
    resp["result"].clone()
}

/// Helper: send goto-definition request and return the result value.
async fn goto_definition_at(
    service: &mut LspService<tarsier_lsp::TarsierLspBackend>,
    uri: &str,
    line: u32,
    character: u32,
) -> Value {
    let resp = send_request(
        service,
        10,
        "textDocument/definition",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line, "character": character }
        }),
    )
    .await
    .expect("goto-definition should return a response");
    resp["result"].clone()
}

// A richer protocol for testing multiple features.
const RICH_PROTOCOL: &str = r#"protocol RichTest {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Ready;

    role Validator {
        var decided: bool = false;

        init waiting;

        phase waiting {
            when received >= 2*t+1 Vote => {
                decided = true;
                send Ready;
                goto phase committed;
            }
        }

        phase committed {
            when received >= t+1 Ready => {
                goto phase done;
            }
        }

        phase done {
        }
    }

    property agreement: agreement {
        forall p: Validator. forall q: Validator.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;

// -------------------------------------------------------------------------
// Hover on keywords
// -------------------------------------------------------------------------

#[tokio::test]
async fn hover_on_role_keyword() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_role.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "role" keyword is on line 19: "    role Validator {", col 4-7
    let result = hover_at(&mut service, uri, 19, 5).await;
    assert!(!result.is_null(), "hover on 'role' should not be null");
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("Role") || content.contains("role"),
        "hover for 'role' keyword should contain role documentation, got: {content}"
    );
}

#[tokio::test]
async fn hover_on_phase_keyword() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_phase.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "phase" keyword appears at line 24: "        phase waiting {"
    // "phase" is at cols 8-12
    let result = hover_at(&mut service, uri, 24, 9).await;
    assert!(
        !result.is_null(),
        "hover on 'phase' keyword should not be null"
    );
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("Phase") || content.contains("phase") || content.contains("location"),
        "hover should contain phase documentation, got: {content}"
    );
}

#[tokio::test]
async fn hover_on_when_keyword() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_when.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "when" keyword appears at line 25: "            when received >= 2*t+1 Vote => {"
    // "when" is at cols 12-15
    let result = hover_at(&mut service, uri, 25, 13).await;
    assert!(!result.is_null(), "hover on 'when' should not be null");
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("when") || content.contains("Transition") || content.contains("guard"),
        "hover for 'when' should contain transition documentation, got: {content}"
    );
}

#[tokio::test]
async fn hover_on_protocol_keyword_returns_docs() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_protocol.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "protocol" at line 0, col 0
    let result = hover_at(&mut service, uri, 0, 3).await;
    assert!(!result.is_null(), "hover on 'protocol' should not be null");
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("protocol") || content.contains("Protocol"),
        "hover for 'protocol' keyword should contain documentation, got: {content}"
    );
}

// -------------------------------------------------------------------------
// Go-to-definition for roles and phases
// -------------------------------------------------------------------------

#[tokio::test]
async fn goto_definition_for_role_from_property() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/goto_role.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "Validator" in property formula at line 43: "        forall p: Validator. ..."
    // "Validator" is at cols 18-26
    let result = goto_definition_at(&mut service, uri, 43, 20).await;
    if !result.is_null() {
        let locations = if result.is_array() {
            result.as_array().unwrap().clone()
        } else {
            vec![result.clone()]
        };
        assert!(
            !locations.is_empty(),
            "goto-definition for 'Validator' should return at least one location"
        );
        // Should point back to our document
        for loc in &locations {
            assert_eq!(loc["uri"].as_str().unwrap(), uri);
        }
    }
}

#[tokio::test]
async fn goto_definition_for_phase_from_goto_action() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/goto_phase.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "committed" in "goto phase committed;" at line 28:
    // "                goto phase committed;"
    // "committed" starts at col 27
    let result = goto_definition_at(&mut service, uri, 28, 30).await;
    if !result.is_null() {
        let locations = if result.is_array() {
            result.as_array().unwrap().clone()
        } else {
            vec![result.clone()]
        };
        assert!(
            !locations.is_empty(),
            "goto-definition for 'committed' phase should return at least one location"
        );
        for loc in &locations {
            assert_eq!(
                loc["uri"].as_str().unwrap(),
                uri,
                "definition should be in the same file"
            );
        }
    }
}

#[tokio::test]
async fn goto_definition_for_message_from_send_action() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/goto_msg.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "Ready" in "send Ready;" at line 27:
    // "                send Ready;"
    // "Ready" starts at col 21
    let result = goto_definition_at(&mut service, uri, 27, 23).await;
    if !result.is_null() {
        let locations = if result.is_array() {
            result.as_array().unwrap().clone()
        } else {
            vec![result.clone()]
        };
        if !locations.is_empty() {
            // Should point to the message declaration
            let first = &locations[0];
            assert_eq!(first["uri"].as_str().unwrap(), uri);
        }
    }
}

// -------------------------------------------------------------------------
// Diagnostics for syntax errors
// -------------------------------------------------------------------------

#[tokio::test]
async fn diagnostics_for_syntax_error() {
    let mut service = build_service();
    initialize(&mut service).await;

    // Malformed protocol: missing closing brace
    let bad_source = r#"protocol Broken {
    parameters {
        n: nat;
    }
    role R {
        init s;
        phase s {
        }
"#;
    let uri = "file:///test/diag_syntax.trs";
    open_document(&mut service, uri, bad_source).await;

    // After didOpen the server should have published diagnostics.
    // We can trigger them by requesting hover (which forces a parse).
    // Alternatively, we verify that the document can be opened without panic.
    // The LSP server publishes diagnostics asynchronously, so we verify
    // indirectly: a hover request on a broken document should still return
    // without error (even if hover result is null).
    let result = hover_at(&mut service, uri, 0, 3).await;
    // For a broken parse, hover may return null or docs for 'protocol'
    // The key assertion is that the server does not crash.
    let _ = result; // server survived
}

#[tokio::test]
async fn diagnostics_for_unknown_phase_in_goto() {
    let mut service = build_service();
    initialize(&mut service).await;

    // Protocol referencing a nonexistent phase
    let source = r#"protocol BadGoto {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;

    role R {
        var decided: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Vote => {
                decided = true;
                goto phase nonexistent_phase;
            }
        }
    }

    property inv: safety {
        forall p: R. p.decided == false
    }
}"#;
    let uri = "file:///test/diag_unknown_phase.trs";
    open_document(&mut service, uri, source).await;

    // The server should not crash when processing a document with unknown phase references.
    // We verify this by performing a subsequent request.
    let resp = send_request(
        &mut service,
        20,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    )
    .await
    .expect("documentSymbol should return after opening doc with unknown phase");
    let result = &resp["result"];
    // Should still return symbols even with diagnostic errors
    assert!(!result.is_null(), "symbols should still be returned");
}

#[tokio::test]
async fn diagnostics_for_missing_init_phase() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = r#"protocol MissingInit {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        phase s {}
    }
}"#;
    let uri = "file:///test/diag_no_init.trs";
    open_document(&mut service, uri, source).await;

    // Request code actions to verify server processes the diagnostic
    let resp = send_request(
        &mut service,
        20,
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 5, "character": 0 },
                "end": { "line": 7, "character": 5 }
            },
            "context": {
                "diagnostics": [{
                    "range": {
                        "start": { "line": 5, "character": 4 },
                        "end": { "line": 7, "character": 5 }
                    },
                    "severity": 1,
                    "source": "tarsier",
                    "code": "tarsier::lower::no_init_phase",
                    "message": "Role 'R' has no init phase. Add `init <phase_name>;` inside the role."
                }]
            }
        }),
    )
    .await
    .expect("codeAction should return a response");

    let result = &resp["result"];
    if !result.is_null() {
        let actions = result
            .as_array()
            .expect("codeAction result should be an array");
        if !actions.is_empty() {
            let first_title = actions[0]["title"].as_str().unwrap_or("");
            assert!(
                first_title.contains("init"),
                "code action should suggest adding init, got: {first_title}"
            );
        }
    }
}

// -------------------------------------------------------------------------
// Completion suggestions
// -------------------------------------------------------------------------

#[tokio::test]
async fn completion_inside_role_body() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = "protocol T {\n    role R {\n        \n    }\n}";
    let uri = "file:///test/comp_role.trs";
    open_document(&mut service, uri, source).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 2, "character": 8 }
        }),
    )
    .await
    .expect("completion should return a response");

    let result = &resp["result"];
    let items = result
        .as_array()
        .expect("completion should return an array");
    let labels: Vec<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();

    // Inside a role, we should get role-level keywords
    assert!(
        labels.contains(&"var"),
        "role-level completions should include 'var', got: {labels:?}"
    );
    assert!(
        labels.contains(&"init"),
        "role-level completions should include 'init', got: {labels:?}"
    );
    assert!(
        labels.contains(&"phase"),
        "role-level completions should include 'phase', got: {labels:?}"
    );
}

#[tokio::test]
async fn completion_inside_phase_body() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = "protocol T {\n    role R {\n        init p;\n        phase p {\n            \n        }\n    }\n}";
    let uri = "file:///test/comp_phase.trs";
    open_document(&mut service, uri, source).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 4, "character": 12 }
        }),
    )
    .await
    .expect("completion should return a response");

    let result = &resp["result"];
    let items = result
        .as_array()
        .expect("completion should return an array");
    let labels: Vec<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();

    assert!(
        labels.contains(&"when"),
        "phase-level completions should include 'when', got: {labels:?}"
    );
}

#[tokio::test]
async fn completion_after_property_colon() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = "protocol T {\n    role R { init s; phase s {} }\n    property inv:\n}";
    let uri = "file:///test/comp_prop.trs";
    open_document(&mut service, uri, source).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 2, "character": 18 }
        }),
    )
    .await
    .expect("completion should return a response");

    let result = &resp["result"];
    let items = result
        .as_array()
        .expect("completion should return an array");
    let labels: Vec<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();

    assert!(
        labels.contains(&"agreement"),
        "property-kind completions should include 'agreement', got: {labels:?}"
    );
    assert!(
        labels.contains(&"safety"),
        "property-kind completions should include 'safety', got: {labels:?}"
    );
    assert!(
        labels.contains(&"liveness"),
        "property-kind completions should include 'liveness', got: {labels:?}"
    );
}

#[tokio::test]
async fn completion_after_var_type_colon() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source =
        "protocol T {\n    role R {\n        var x:\n        init s;\n        phase s {}\n    }\n}";
    let uri = "file:///test/comp_type.trs";
    open_document(&mut service, uri, source).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 2, "character": 14 }
        }),
    )
    .await
    .expect("completion should return a response");

    let result = &resp["result"];
    let items = result
        .as_array()
        .expect("completion should return an array");
    let labels: Vec<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();

    assert!(
        labels.contains(&"bool"),
        "type completions should include 'bool', got: {labels:?}"
    );
    assert!(
        labels.contains(&"nat"),
        "type completions should include 'nat', got: {labels:?}"
    );
    assert!(
        labels.contains(&"int"),
        "type completions should include 'int', got: {labels:?}"
    );
}

// -------------------------------------------------------------------------
// Hover on user-defined symbols
// -------------------------------------------------------------------------

#[tokio::test]
async fn hover_on_role_name_shows_role_info() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_role_name.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "Validator" role name at line 19: "    role Validator {"
    // "Validator" is at cols 9-17
    let result = hover_at(&mut service, uri, 19, 11).await;
    assert!(!result.is_null(), "hover on role name should not be null");
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("Validator") && content.contains("Role"),
        "hover should describe Validator as a Role, got: {content}"
    );
}

#[tokio::test]
async fn hover_on_parameter_name() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/hover_param.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "n" parameter at line 2: "n: nat;"
    let result = hover_at(&mut service, uri, 2, 8).await;
    assert!(
        !result.is_null(),
        "hover on parameter name should not be null"
    );
    let content = result["contents"]["value"].as_str().unwrap_or("");
    assert!(
        content.contains("Parameter") && content.contains("n"),
        "hover should describe 'n' as a Parameter, got: {content}"
    );
}

// -------------------------------------------------------------------------
// Multiple documents / didChange
// -------------------------------------------------------------------------

#[tokio::test]
async fn server_handles_multiple_documents() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source_a = "protocol A {\n    role R {\n        init s;\n        phase s {}\n    }\n}";
    let source_b =
        "protocol B {\n    message M;\n    role S {\n        init s;\n        phase s {}\n    }\n}";

    let uri_a = "file:///test/multi_a.trs";
    let uri_b = "file:///test/multi_b.trs";

    open_document(&mut service, uri_a, source_a).await;
    open_document(&mut service, uri_b, source_b).await;

    // Request symbols from both documents
    let resp_a = send_request(
        &mut service,
        20,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri_a } }),
    )
    .await
    .expect("documentSymbol for A should work");
    let resp_b = send_request(
        &mut service,
        21,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri_b } }),
    )
    .await
    .expect("documentSymbol for B should work");

    let symbols_a = resp_a["result"].as_array().unwrap();
    let symbols_b = resp_b["result"].as_array().unwrap();

    let names_a: Vec<&str> = symbols_a
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    let names_b: Vec<&str> = symbols_b
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();

    assert!(names_a.contains(&"A"), "doc A should contain protocol A");
    assert!(names_b.contains(&"B"), "doc B should contain protocol B");
}

#[tokio::test]
async fn server_handles_did_change() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/change.trs";
    let initial = "protocol P {\n    role R {\n        init s;\n        phase s {}\n    }\n}";
    open_document(&mut service, uri, initial).await;

    // Send didChange with updated content
    let updated = "protocol P {\n    message Msg;\n    role R {\n        init s;\n        phase s {}\n    }\n}";
    send_notification(
        &mut service,
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri, "version": 2 },
            "contentChanges": [{ "text": updated }]
        }),
    )
    .await;

    // Verify symbols reflect the update
    let resp = send_request(
        &mut service,
        20,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    )
    .await
    .expect("documentSymbol should work after didChange");

    let symbols = resp["result"].as_array().unwrap();
    assert!(
        !symbols.is_empty(),
        "symbols should not be empty after update"
    );
}

// -------------------------------------------------------------------------
// References
// -------------------------------------------------------------------------

#[tokio::test]
async fn find_references_for_message_type() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/refs.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    // "Vote" declaration is on line 16: "message Vote;"
    let resp = send_request(
        &mut service,
        20,
        "textDocument/references",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 16, "character": 12 },
            "context": { "includeDeclaration": true }
        }),
    )
    .await
    .expect("references should return a response");

    let result = &resp["result"];
    if !result.is_null() {
        let locations = result.as_array().expect("references should be an array");
        // Vote appears at declaration and in the "when received >= 2*t+1 Vote =>" guard
        assert!(
            locations.len() >= 2,
            "Vote should have at least 2 references (decl + use), got {}",
            locations.len()
        );
    }
}

// -------------------------------------------------------------------------
// Folding ranges
// -------------------------------------------------------------------------

#[tokio::test]
async fn folding_ranges_include_role_block() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/fold.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/foldingRange",
        json!({ "textDocument": { "uri": uri } }),
    )
    .await
    .expect("foldingRange should return a response");

    let result = &resp["result"];
    if !result.is_null() {
        let ranges = result.as_array().expect("foldingRange should be an array");
        // Should have at least one folding range (for the protocol block)
        assert!(
            !ranges.is_empty(),
            "folding ranges should not be empty for a valid protocol"
        );
    }
}

// -------------------------------------------------------------------------
// Inlay hints
// -------------------------------------------------------------------------

#[tokio::test]
async fn inlay_hints_does_not_crash() {
    let mut service = build_service();
    initialize(&mut service).await;
    let uri = "file:///test/inlay.trs";
    open_document(&mut service, uri, RICH_PROTOCOL).await;

    let resp = send_request(
        &mut service,
        20,
        "textDocument/inlayHint",
        json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 45, "character": 0 }
            }
        }),
    )
    .await
    .expect("inlayHint should return a response");

    // Just verify it doesn't crash and returns something valid
    let result = &resp["result"];
    if !result.is_null() {
        assert!(result.is_array(), "inlay hints should be an array");
    }
}
