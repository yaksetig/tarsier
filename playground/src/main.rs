#![allow(unused_imports)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware as axum_middleware, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tarsier_dsl::ast::{PropertyKind, Span as DslSpan};
use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{
    FairLivenessResult, InductionCtiSummary, LivenessResult, LivenessUnknownReason,
    UnboundedFairLivenessResult, UnboundedSafetyResult, VerificationResult,
};
use tarsier_engine::visualization::{render_trace_mermaid, render_trace_timeline};
use tarsier_ir::counter_system::Trace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;
use tokio::sync::{Mutex, Semaphore};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod api;
mod assets;
mod middleware;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

use api::{
    build_options, error_response, execute_lint, generate_assist, parse_proof_engine, parse_source,
    run_analysis, run_lint, run_worker_mode,
};
use assets::{app_js, codegen_js, health, index, list_examples, visual_editor_js, visual_model_js};
use middleware::{auth_middleware, rate_limit_middleware};

#[derive(Clone)]
struct ServerConfig {
    max_request_bytes: usize,
    max_source_bytes: usize,
    max_response_bytes: usize,
    max_depth: usize,
    max_timeout_secs: u64,
    max_concurrent_solvers: usize,
    rate_limit_per_min: usize,
    auth_token: Option<String>,
    allowed_origins: Vec<String>,
}

impl ServerConfig {
    fn from_env() -> Self {
        fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        Self {
            max_request_bytes: env_or("TARSIER_MAX_REQUEST_BYTES", 524_288),
            max_source_bytes: env_or("TARSIER_MAX_SOURCE_BYTES", 262_144),
            max_response_bytes: env_or("TARSIER_MAX_RESPONSE_BYTES", 8_388_608),
            max_depth: env_or("TARSIER_MAX_DEPTH", 20),
            max_timeout_secs: env_or("TARSIER_MAX_TIMEOUT_SECS", 120),
            max_concurrent_solvers: env_or("TARSIER_MAX_CONCURRENT_SOLVERS", 4),
            rate_limit_per_min: env_or("TARSIER_RATE_LIMIT_PER_MIN", 60),
            auth_token: std::env::var("TARSIER_AUTH_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            allowed_origins: std::env::var("TARSIER_ALLOWED_ORIGINS")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
                .unwrap_or_default(),
        }
    }
}

struct RateLimiter {
    window: Duration,
    max_requests: usize,
    clients: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl RateLimiter {
    fn new(max_requests: usize) -> Self {
        Self {
            window: Duration::from_secs(60),
            max_requests,
            clients: Mutex::new(HashMap::new()),
        }
    }

    async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut clients = self.clients.lock().await;
        let timestamps = clients.entry(ip).or_default();
        timestamps.retain(|t| *t > cutoff);
        if timestamps.len() >= self.max_requests {
            let oldest = timestamps.first().copied().unwrap_or(now);
            let retry_after = self.window.saturating_sub(now.duration_since(oldest));
            return Err(retry_after.as_secs().max(1));
        }
        timestamps.push(now);
        Ok(())
    }

    async fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut clients = self.clients.lock().await;
        clients.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

#[derive(Clone, Serialize)]
struct ExampleSnippet {
    id: &'static str,
    name: &'static str,
    source: &'static str,
}

struct AppState {
    examples: Vec<ExampleSnippet>,
    config: ServerConfig,
    solver_semaphore: Semaphore,
    rate_limiter: Arc<RateLimiter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunRequest {
    source: String,
    check: String,
    filename: Option<String>,
    solver: Option<String>,
    depth: Option<usize>,
    timeout_secs: Option<u64>,
    soundness: Option<String>,
    proof_engine: Option<String>,
    fairness: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunResponse {
    ok: bool,
    check: String,
    result: String,
    summary: String,
    output: String,
    trace: Option<Value>,
    cti: Option<Value>,
    details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    mermaid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeline: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerRequest {
    request: RunRequest,
    max_depth: usize,
    max_timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ParseRequest {
    source: String,
    filename: Option<String>,
}

#[derive(Debug, Serialize)]
struct ParseResponse {
    ok: bool,
    ast: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct LintRequest {
    source: String,
    filename: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct LintSourceSpan {
    start: usize,
    end: usize,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Debug, Clone, Serialize)]
struct LintFix {
    label: String,
    snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    insert_offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct LintIssue {
    severity: String,
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    soundness_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<LintFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_span: Option<LintSourceSpan>,
}

#[derive(Debug, Clone, Serialize)]
struct LintResponse {
    ok: bool,
    issues: Vec<LintIssue>,
}

#[derive(Debug, Clone, Deserialize)]
struct AssistRequest {
    kind: String,
}

#[derive(Debug, Clone, Serialize)]
struct AssistResponse {
    ok: bool,
    kind: String,
    source: String,
}

fn build_cors_layer(config: &ServerConfig) -> CorsLayer {
    let origins = if config.allowed_origins.is_empty() {
        AllowOrigin::any()
    } else {
        let parsed: Vec<HeaderValue> = config
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        AllowOrigin::list(parsed)
    };
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

#[allow(clippy::result_large_err)]
fn validate_source(source: &str, config: &ServerConfig) -> Result<(), Response> {
    if source.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "source must not be empty".into(),
        ));
    }
    if source.len() > config.max_source_bytes {
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "source size {} exceeds limit of {} bytes",
                source.len(),
                config.max_source_bytes
            ),
        ));
    }
    Ok(())
}

fn truncate_response_if_needed(mut response: RunResponse, config: &ServerConfig) -> RunResponse {
    let serialized_len = serde_json::to_string(&response)
        .map(|s| s.len())
        .unwrap_or(0);
    if serialized_len > config.max_response_bytes {
        response.output = "[truncated: response exceeded size limit]".into();
        response.trace = None;
        response.mermaid = None;
        response.timeline = None;
        if let Some(details) = response.details.as_object_mut() {
            details.insert("truncated".into(), json!(true));
        }
    }
    response
}

fn playground_examples() -> Vec<ExampleSnippet> {
    vec![
        ExampleSnippet {
            id: "pbft",
            name: "PBFT",
            source: include_str!("../../examples/library/pbft_simple_safe_faithful.trs"),
        },
        ExampleSnippet {
            id: "reliable_broadcast",
            name: "Reliable Broadcast",
            source: include_str!("../../examples/library/reliable_broadcast_safe_faithful.trs"),
        },
        ExampleSnippet {
            id: "hotstuff",
            name: "HotStuff",
            source: include_str!("../../examples/library/hotstuff_simple_safe_faithful.trs"),
        },
        ExampleSnippet {
            id: "tendermint",
            name: "Tendermint",
            source: include_str!("../../examples/library/tendermint_crypto_qc_safe_faithful.trs"),
        },
        ExampleSnippet {
            id: "raft",
            name: "Raft",
            source: include_str!("../../examples/library/raft_election_safety.trs"),
        },
        ExampleSnippet {
            id: "paxos",
            name: "Paxos",
            source: include_str!("../../examples/library/paxos_basic.trs"),
        },
        ExampleSnippet {
            id: "rb_buggy",
            name: "Reliable Broadcast (Buggy)",
            source: include_str!("../../examples/library/reliable_broadcast_buggy.trs"),
        },
    ]
}

fn build_app(state: Arc<AppState>) -> Router {
    let api_routes = Router::new()
        .route("/api/assist", post(generate_assist))
        .route("/api/parse", post(parse_source))
        .route("/api/run", post(run_analysis))
        .route("/api/lint", post(run_lint))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/visual-model.js", get(visual_model_js))
        .route("/visual-editor.js", get(visual_editor_js))
        .route("/codegen.js", get(codegen_js))
        .route("/api/health", get(health))
        .route("/api/examples", get(list_examples))
        .merge(api_routes)
        .layer(TraceLayer::new_for_http())
        .layer(build_cors_layer(&state.config))
        .layer(RequestBodyLimitLayer::new(state.config.max_request_bytes))
        .with_state(state)
}

fn spawn_rate_limiter_cleanup(rate_limiter: Arc<RateLimiter>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            rate_limiter.cleanup().await;
        }
    });
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--worker") {
        run_worker_mode();
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tarsier_playground=info".into()),
        )
        .init();

    let host = std::env::var("TARSIER_PLAYGROUND_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("TARSIER_PLAYGROUND_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(7878);

    let config = ServerConfig::from_env();
    let mode = if config.auth_token.is_some() {
        "hosted"
    } else {
        "local"
    };
    info!(
        mode,
        max_request_bytes = config.max_request_bytes,
        max_source_bytes = config.max_source_bytes,
        max_depth = config.max_depth,
        max_timeout_secs = config.max_timeout_secs,
        max_concurrent_solvers = config.max_concurrent_solvers,
        rate_limit_per_min = config.rate_limit_per_min,
        auth = config.auth_token.is_some(),
        cors_origins = if config.allowed_origins.is_empty() {
            "*".to_string()
        } else {
            config.allowed_origins.join(", ")
        },
        "server config loaded"
    );

    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_per_min));
    let state = Arc::new(AppState {
        examples: playground_examples(),
        solver_semaphore: Semaphore::new(config.max_concurrent_solvers),
        rate_limiter: rate_limiter.clone(),
        config,
    });

    spawn_rate_limiter_cleanup(rate_limiter);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind playground address");

    info!(%addr, "tarsier playground ready");
    axum::serve(
        listener,
        build_app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("playground server failed");
}

#[cfg(test)]
fn test_config() -> ServerConfig {
    ServerConfig {
        max_request_bytes: 524_288,
        max_source_bytes: 262_144,
        max_response_bytes: 8_388_608,
        max_depth: 20,
        max_timeout_secs: 120,
        max_concurrent_solvers: 4,
        rate_limit_per_min: 60,
        auth_token: None,
        allowed_origins: vec![],
    }
}

#[cfg(test)]
fn test_state() -> Arc<AppState> {
    test_state_with_config(test_config())
}

#[cfg(test)]
fn test_state_with_config(config: ServerConfig) -> Arc<AppState> {
    Arc::new(AppState {
        examples: vec![ExampleSnippet {
            id: "test",
            name: "Test Example",
            source: "protocol Test { params n, f; }",
        }],
        solver_semaphore: Semaphore::new(config.max_concurrent_solvers),
        rate_limiter: Arc::new(RateLimiter::new(config.rate_limit_per_min)),
        config,
    })
}

#[cfg(test)]
fn test_app() -> Router {
    test_app_with_state(test_state())
}

#[cfg(test)]
fn test_app_with_state(state: Arc<AppState>) -> Router {
    let api_routes = Router::new()
        .route("/api/assist", post(generate_assist))
        .route("/api/parse", post(parse_source))
        .route("/api/run", post(run_analysis))
        .route("/api/lint", post(run_lint))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/visual-model.js", get(visual_model_js))
        .route("/visual-editor.js", get(visual_editor_js))
        .route("/codegen.js", get(codegen_js))
        .route("/api/health", get(health))
        .route("/api/examples", get(list_examples))
        .merge(api_routes)
        .layer(build_cors_layer(&state.config))
        .layer(RequestBodyLimitLayer::new(state.config.max_request_bytes))
        .with_state(state)
}
