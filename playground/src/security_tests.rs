use super::*;
use axum::body::Body;
use tower::ServiceExt;

#[tokio::test]
async fn test_request_body_too_large() {
    let mut config = test_config();
    config.max_request_bytes = 1024;
    let app = test_app_with_state(test_state_with_config(config));
    let big_body = "x".repeat(2048);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(big_body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_source_size_exceeds_limit() {
    let mut config = test_config();
    config.max_source_bytes = 64;
    let app = test_app_with_state(test_state_with_config(config));
    let big_source = "a".repeat(128);
    let body = serde_json::to_string(&json!({"source": big_source})).unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn test_depth_capped_to_server_max() {
    let request = RunRequest {
        source: "protocol T { params n, f; }".into(),
        check: "verify".into(),
        filename: None,
        solver: None,
        depth: Some(100),
        timeout_secs: None,
        soundness: None,
        proof_engine: None,
        fairness: None,
    };
    let opts = build_options(&request, 8, 120).unwrap();
    assert_eq!(opts.max_depth, 8);
}

#[test]
fn test_timeout_capped_to_server_max() {
    let request = RunRequest {
        source: "protocol T { params n, f; }".into(),
        check: "verify".into(),
        filename: None,
        solver: None,
        depth: None,
        timeout_secs: Some(999),
        soundness: None,
        proof_engine: None,
        fairness: None,
    };
    let opts = build_options(&request, 20, 30).unwrap();
    assert_eq!(opts.timeout_secs, 30);
}

#[tokio::test]
async fn test_solver_concurrency_limit_returns_503() {
    let mut config = test_config();
    config.max_concurrent_solvers = 1;
    let state = test_state_with_config(config);
    // Clone Arc so permit borrows from one copy while the other is moved into the app
    let state2 = state.clone();
    let _permit = state2.solver_semaphore.try_acquire().unwrap();
    let app = test_app_with_state(state);
    let body = serde_json::to_string(&json!({
        "source": "protocol T { params n, f; }",
        "check": "verify",
    }))
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/run")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_rate_limiter_allows_under_limit() {
    let limiter = RateLimiter::new(5);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for _ in 0..5 {
        assert!(limiter.check(ip).await.is_ok());
    }
}

#[tokio::test]
async fn test_rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(3);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for _ in 0..3 {
        assert!(limiter.check(ip).await.is_ok());
    }
    assert!(limiter.check(ip).await.is_err());
}

#[tokio::test]
async fn test_rate_limiter_independent_ips() {
    let limiter = RateLimiter::new(2);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    assert!(limiter.check(ip1).await.is_ok());
    assert!(limiter.check(ip1).await.is_ok());
    assert!(limiter.check(ip1).await.is_err());
    // ip2 should still have quota
    assert!(limiter.check(ip2).await.is_ok());
    assert!(limiter.check(ip2).await.is_ok());
}

#[tokio::test]
async fn test_auth_required_returns_401() {
    let mut config = test_config();
    config.auth_token = Some("secret-token".into());
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"source": "protocol T { params n; }"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_wrong_token_returns_403() {
    let mut config = test_config();
    config.auth_token = Some("secret-token".into());
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/parse")
        .header("content-type", "application/json")
        .header("authorization", "Bearer wrong-token")
        .body(Body::from(r#"{"source": "protocol T { params n; }"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_auth_correct_token_passes() {
    let mut config = test_config();
    config.auth_token = Some("secret-token".into());
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/assist")
        .header("content-type", "application/json")
        .header("authorization", "Bearer secret-token")
        .body(Body::from(r#"{"kind": "pbft"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_not_required_local_mode() {
    let config = test_config(); // auth_token is None
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/assist")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"kind": "pbft"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_endpoints_bypass_auth() {
    let mut config = test_config();
    config.auth_token = Some("secret-token".into());
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .uri("/api/health")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_cors_permissive_local_mode() {
    let config = test_config(); // no allowed_origins
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("OPTIONS")
        .uri("/api/health")
        .header("origin", "http://example.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let allow_origin = response
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "*");
}

#[tokio::test]
async fn test_cors_restrictive_hosted_mode() {
    let mut config = test_config();
    config.allowed_origins = vec!["https://allowed.example.com".into()];
    let app = test_app_with_state(test_state_with_config(config));
    let request = axum::http::Request::builder()
        .method("OPTIONS")
        .uri("/api/health")
        .header("origin", "https://allowed.example.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let allow_origin = response
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "https://allowed.example.com");
}
