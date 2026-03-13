use super::*;
use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .uri("/api/health")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
}

#[tokio::test]
async fn test_examples_list() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .uri("/api/examples")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(!json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_assist_valid_kind() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/assist")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"kind": "pbft"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert!(json["source"].as_str().unwrap().contains("protocol"));
}

#[tokio::test]
async fn test_assist_invalid_kind() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/assist")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"kind": "nonexistent"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_lint_empty_source() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/lint")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"source": ""}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_lint_valid_source() {
    let app = test_app();
    let source = include_str!("../../examples/library/pbft_simple_safe_faithful.trs");
    let body = serde_json::to_string(&serde_json::json!({
        "source": source,
        "filename": "pbft_simple_safe_faithful.trs",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/lint")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json["issues"].is_array());
}

#[tokio::test]
async fn test_lint_parse_error_has_source_span_and_soundness_impact() {
    let app = test_app();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/lint")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"source":"this is not valid trs","filename":"bad.trs"}"#,
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let issues = json["issues"].as_array().expect("issues should be array");
    let parse_issue = issues
        .iter()
        .find(|issue| issue["code"] == "parse_error")
        .expect("parse_error issue should exist");
    assert!(parse_issue.get("source_span").is_some());
    assert!(parse_issue["source_span"].is_object());
    assert!(parse_issue
        .get("soundness_impact")
        .and_then(|v| v.as_str())
        .is_some());
}

#[test]
fn test_lint_missing_core_sections_include_fix_snippets() {
    let src = r#"
protocol MissingCoreSections {
    params n, f;
    role Replica {
        init idle;
        phase idle {}
    }
}
"#;
    let report = execute_lint(LintRequest {
        source: src.into(),
        filename: Some("missing_core_sections.trs".into()),
    })
    .expect("lint should succeed");

    let resilience = report
        .issues
        .iter()
        .find(|i| i.code == "missing_resilience")
        .expect("missing_resilience should be emitted");
    let resilience_fix = resilience
        .fix
        .as_ref()
        .expect("missing_resilience should include a fix snippet");
    assert!(resilience_fix.snippet.contains("resilience: n = 3*f + 1;"));

    let safety = report
        .issues
        .iter()
        .find(|i| i.code == "missing_safety_property")
        .expect("missing_safety_property should be emitted");
    let safety_fix = safety
        .fix
        .as_ref()
        .expect("missing_safety_property should include a fix snippet");
    assert!(safety_fix.snippet.contains("property safety_inv: safety"));
}

#[tokio::test]
async fn test_lint_endpoint_includes_fix_object_in_json() {
    let app = test_app();
    let source = r#"
protocol MissingResilience {
    params n, f;
    role Replica {
        init idle;
        phase idle {}
    }
}
"#;
    let body = serde_json::to_string(&serde_json::json!({
        "source": source,
        "filename": "missing_resilience.trs",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/lint")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let issues = json["issues"].as_array().expect("issues should be array");
    let resilience = issues
        .iter()
        .find(|issue| issue["code"] == "missing_resilience")
        .expect("missing_resilience issue should exist");
    assert!(
        resilience.get("fix").is_some(),
        "fix object should be present"
    );
    assert_eq!(
        resilience["fix"]["label"].as_str(),
        Some("insert resilience clause")
    );
    assert!(resilience["fix"]["snippet"]
        .as_str()
        .unwrap_or("")
        .contains("resilience: n = 3*f + 1;"));
    assert!(resilience
        .get("soundness_impact")
        .and_then(|v| v.as_str())
        .is_some());
}

#[tokio::test]
async fn test_assist_new_templates() {
    for kind in &["tendermint", "streamlet", "casper"] {
        let app = test_app();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/assist")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"kind": "{}"}}"#, kind)))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "failed for kind: {kind}");
    }
}

#[tokio::test]
async fn test_parse_valid_source() {
    let app = test_app();
    let source = include_str!("../../examples/library/pbft_simple_safe_faithful.trs");
    let body = serde_json::to_string(&serde_json::json!({
        "source": source,
        "filename": "pbft.trs",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert!(json["ast"]["protocol"]["node"]["name"].is_string());
}

#[tokio::test]
async fn test_parse_invalid_source() {
    let app = test_app();
    let body = serde_json::to_string(&serde_json::json!({
        "source": "this is not valid trs",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_parse_empty_source() {
    let app = test_app();
    let body = serde_json::to_string(&serde_json::json!({
        "source": "",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_parse_proof_engine_accepts_ranking() {
    let engine = parse_proof_engine("ranking").expect("ranking should parse");
    assert_eq!(engine, ProofEngine::Ranking);
}

#[test]
fn test_parse_proof_engine_rejects_unknown_value() {
    let err = parse_proof_engine("bogus").expect_err("unknown engine should fail");
    assert!(err.contains("expected kinduction|pdr|ranking"));
}
