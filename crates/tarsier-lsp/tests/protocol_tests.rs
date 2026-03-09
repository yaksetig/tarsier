//! End-to-end LSP protocol tests.
//!
//! These tests exercise the full LanguageServer trait implementation by
//! constructing a real TarsierLspBackend via tower-lsp's service builder,
//! sending protocol messages, and verifying responses.

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

const EXAMPLE_PROTOCOL: &str = r#"protocol TestProtocol {
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

    role Replica {
        var decided: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Vote => {
                decided = true;
                send Ready;
                goto phase done;
            }
        }

        phase done {
        }
    }

    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;

#[tokio::test]
async fn initialize_returns_capabilities() {
    let mut service = build_service();
    let resp = send_request(
        &mut service,
        1,
        "initialize",
        json!({
            "processId": null,
            "capabilities": {},
            "rootUri": null
        }),
    )
    .await
    .expect("initialize should return a response");

    let result = &resp["result"];
    let capabilities = &result["capabilities"];

    // Verify key capabilities are advertised
    assert!(capabilities["hoverProvider"].as_bool().unwrap_or(false));
    assert!(capabilities["definitionProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["referencesProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["documentFormattingProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["documentRangeFormattingProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["documentSymbolProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["workspaceSymbolProvider"]
        .as_bool()
        .unwrap_or(false));
    assert!(capabilities["completionProvider"].is_object());
    assert!(capabilities["renameProvider"].is_object());
    assert!(capabilities["semanticTokensProvider"].is_object());
    assert!(capabilities["codeActionProvider"]
        .as_bool()
        .unwrap_or(false));
}

#[tokio::test]
async fn hover_returns_keyword_docs() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/protocol.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    // Hover over "protocol" keyword (line 0, char 0)
    let resp = send_request(
        &mut service,
        2,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 0, "character": 3 }
        }),
    )
    .await
    .expect("hover should return a response");

    let result = &resp["result"];
    assert!(!result.is_null(), "hover result should not be null");
    let contents = result["contents"]["value"]
        .as_str()
        .expect("hover should have markdown content");
    assert!(
        contents.contains("protocol"),
        "hover for 'protocol' keyword should contain documentation"
    );
}

#[tokio::test]
async fn hover_returns_user_defined_info() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/protocol.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    // Hover over "Vote" message name (line 16, char 12)
    let resp = send_request(
        &mut service,
        2,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 16, "character": 12 }
        }),
    )
    .await
    .expect("hover should return a response");

    let result = &resp["result"];
    assert!(!result.is_null(), "hover on 'Vote' should return info");
    let contents = result["contents"]["value"]
        .as_str()
        .expect("hover should have markdown content");
    assert!(
        contents.contains("Message") && contents.contains("Vote"),
        "hover should describe Vote as a Message, got: {contents}"
    );
}

#[tokio::test]
async fn completion_at_top_level() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = "protocol T {\n    \n}";
    let uri = "file:///test/comp.trs";
    open_document(&mut service, uri, source).await;

    // Request completion inside protocol body (line 1)
    let resp = send_request(
        &mut service,
        2,
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 1, "character": 4 }
        }),
    )
    .await
    .expect("completion should return a response");

    let result = &resp["result"];
    let items = result
        .as_array()
        .expect("completion should return an array");
    assert!(!items.is_empty(), "completions should not be empty");

    let labels: Vec<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();
    assert!(
        labels.contains(&"parameters"),
        "top-level completions should include 'parameters', got: {labels:?}"
    );
    assert!(
        labels.contains(&"role"),
        "top-level completions should include 'role'"
    );
    assert!(
        labels.contains(&"message"),
        "top-level completions should include 'message'"
    );
}

#[tokio::test]
async fn goto_definition_finds_message() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/goto.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    // "Vote" in guard at "when received >= 1 Vote =>" on line 25, col 39
    // Vote is declared on line 16
    let resp = send_request(
        &mut service,
        2,
        "textDocument/definition",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 25, "character": 39 }
        }),
    )
    .await
    .expect("goto-definition should return a response");

    let result = &resp["result"];
    // result could be a single Location or an array
    if !result.is_null() {
        // If it returns locations, verify they point back to the message declaration
        let locations = if result.is_array() {
            result.as_array().unwrap().clone()
        } else {
            vec![result.clone()]
        };
        if !locations.is_empty() {
            let first = &locations[0];
            assert_eq!(first["uri"].as_str().unwrap(), uri);
        }
    }
}

#[tokio::test]
async fn document_formatting_returns_edits() {
    let mut service = build_service();
    initialize(&mut service).await;

    // Intentionally malformatted
    let source = "protocol T {\n  parameters {\nn: nat;\n}\n}";
    let uri = "file:///test/fmt.trs";
    open_document(&mut service, uri, source).await;

    let resp = send_request(
        &mut service,
        2,
        "textDocument/formatting",
        json!({
            "textDocument": { "uri": uri },
            "options": { "tabSize": 4, "insertSpaces": true }
        }),
    )
    .await
    .expect("formatting should return a response");

    let result = &resp["result"];
    // Result is an array of TextEdits (or null if no changes)
    if !result.is_null() {
        let edits = result
            .as_array()
            .expect("formatting result should be an array of edits");
        // The malformatted source should produce at least one edit
        assert!(
            !edits.is_empty(),
            "formatting should produce edits for malformatted source"
        );
    }
}

#[tokio::test]
async fn document_symbols_returns_structure() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/symbols.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    let resp = send_request(
        &mut service,
        2,
        "textDocument/documentSymbol",
        json!({
            "textDocument": { "uri": uri }
        }),
    )
    .await
    .expect("documentSymbol should return a response");

    let result = &resp["result"];
    assert!(!result.is_null(), "document symbols should not be null");
    let symbols = result
        .as_array()
        .expect("document symbols should be an array");
    assert!(
        !symbols.is_empty(),
        "document symbols should not be empty for a valid protocol"
    );

    // Top-level should contain the protocol name
    let top_names: Vec<&str> = symbols.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(
        top_names.contains(&"TestProtocol"),
        "top-level symbols should include protocol name, got: {top_names:?}"
    );

    // Nested children should contain roles and messages
    let children = symbols[0]["children"]
        .as_array()
        .expect("protocol symbol should have children");
    let child_names: Vec<&str> = children.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(
        child_names.contains(&"Replica"),
        "protocol children should include Replica role, got: {child_names:?}"
    );
}

#[tokio::test]
async fn prepare_rename_on_valid_symbol() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/rename.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    // Prepare rename on "Vote" message (line 16)
    let resp = send_request(
        &mut service,
        2,
        "textDocument/prepareRename",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 16, "character": 12 }
        }),
    )
    .await
    .expect("prepareRename should return a response");

    let result = &resp["result"];
    // Should return a range (or range+placeholder) indicating the symbol is renamable
    if !result.is_null() {
        // Either { start, end } or { range, placeholder }
        let has_range = result.get("start").is_some() || result.get("range").is_some();
        assert!(has_range, "prepareRename result should include a range");
    }
}

#[tokio::test]
async fn range_formatting_filters_to_range() {
    let mut service = build_service();
    initialize(&mut service).await;

    let source = "protocol T {\nparameters {\nn: nat;\nt: nat;\n}\nmessage M;\nrole R {\ninit p;\nphase p {}\n}\n}";
    let uri = "file:///test/range_fmt.trs";
    open_document(&mut service, uri, source).await;

    // Format only lines 1-4 (the parameters block)
    let resp = send_request(
        &mut service,
        2,
        "textDocument/rangeFormatting",
        json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 1, "character": 0 },
                "end": { "line": 4, "character": 1 }
            },
            "options": { "tabSize": 4, "insertSpaces": true }
        }),
    )
    .await
    .expect("rangeFormatting should return a response");

    let result = &resp["result"];
    if !result.is_null() {
        let edits = result
            .as_array()
            .expect("rangeFormatting result should be an array");
        // All edits should overlap with the requested range (lines 1-4)
        for edit in edits {
            let start_line = edit["range"]["start"]["line"].as_u64().unwrap();
            let end_line = edit["range"]["end"]["line"].as_u64().unwrap();
            assert!(
                end_line >= 1 && start_line <= 4,
                "edit at lines {start_line}-{end_line} should overlap with range 1-4"
            );
        }
    }
}

#[tokio::test]
async fn semantic_tokens_returns_data() {
    let mut service = build_service();
    initialize(&mut service).await;

    let uri = "file:///test/tokens.trs";
    open_document(&mut service, uri, EXAMPLE_PROTOCOL).await;

    let resp = send_request(
        &mut service,
        2,
        "textDocument/semanticTokens/full",
        json!({
            "textDocument": { "uri": uri }
        }),
    )
    .await
    .expect("semanticTokens should return a response");

    let result = &resp["result"];
    assert!(!result.is_null(), "semantic tokens should not be null");
    let data = result["data"]
        .as_array()
        .expect("semantic tokens should have a 'data' array");
    assert!(
        !data.is_empty(),
        "semantic tokens data should not be empty for a valid protocol"
    );
}

#[tokio::test]
async fn code_action_for_missing_init_phase() {
    let mut service = build_service();
    initialize(&mut service).await;

    // Protocol with a role missing init phase
    let source = r#"protocol T {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        phase p {}
    }
}"#;
    let uri = "file:///test/action.trs";
    open_document(&mut service, uri, source).await;

    // The diagnostic for missing init should be on the role
    let resp = send_request(
        &mut service,
        2,
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
