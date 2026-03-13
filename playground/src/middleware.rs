// Request middleware for rate limiting and auth.

use super::*;

pub(crate) async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match state.rate_limiter.check(addr.ip()).await {
        Ok(()) => next.run(request).await,
        Err(retry_after) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("60")),
            )],
            Json(json!({"ok": false, "error": "rate limit exceeded"})),
        )
            .into_response(),
    }
}

pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(ref expected_token) = state.config.auth_token else {
        return next.run(request).await;
    };
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    match auth_header {
        None => error_response(
            StatusCode::UNAUTHORIZED,
            "missing Authorization header".into(),
        ),
        Some(value) => {
            let provided = value.strip_prefix("Bearer ").unwrap_or("");
            let expected_bytes = expected_token.as_bytes();
            let provided_bytes = provided.as_bytes();
            // Constant-time comparison (pad shorter to same length to avoid timing leak)
            let max_len = expected_bytes.len().max(provided_bytes.len()).max(1);
            let mut expected_padded = vec![0u8; max_len];
            let mut provided_padded = vec![0u8; max_len];
            expected_padded[..expected_bytes.len()].copy_from_slice(expected_bytes);
            provided_padded[..provided_bytes.len()].copy_from_slice(provided_bytes);
            let len_match = expected_bytes.len() == provided_bytes.len();
            if len_match && expected_padded.ct_eq(&provided_padded).into() {
                next.run(request).await
            } else {
                error_response(StatusCode::FORBIDDEN, "invalid auth token".into())
            }
        }
    }
}
