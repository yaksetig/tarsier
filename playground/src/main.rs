use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
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

async fn rate_limit_middleware(
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

async fn auth_middleware(
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

fn run_worker_mode() {
    use std::io::Read;
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("worker: failed to read stdin: {e}");
        std::process::exit(1);
    }
    let worker_req: WorkerRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("worker: failed to parse request: {e}");
            std::process::exit(1);
        }
    };
    let result = execute_run(
        worker_req.request,
        worker_req.max_depth,
        worker_req.max_timeout,
    );
    let response = match result {
        Ok(r) => json!({"ok": true, "data": r}),
        Err(e) => json!({"ok": false, "error": e}),
    };
    if let Err(e) = serde_json::to_writer(std::io::stdout(), &response) {
        eprintln!("worker: failed to write response: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    // Worker subprocess mode — must be checked before any server setup
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
        examples: vec![
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
                source: include_str!(
                    "../../examples/library/tendermint_crypto_qc_safe_faithful.trs"
                ),
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
        ],
        solver_semaphore: Semaphore::new(config.max_concurrent_solvers),
        rate_limiter: rate_limiter.clone(),
        config,
    });

    // Background rate limiter cleanup
    let cleanup_limiter = rate_limiter;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup().await;
        }
    });

    let api_routes = Router::new()
        .route("/api/assist", post(generate_assist))
        .route("/api/parse", post(parse_source))
        .route("/api/run", post(run_analysis))
        .route("/api/lint", post(run_lint))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    let app = Router::new()
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
        .with_state(state);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind playground address");

    info!(%addr, "tarsier playground ready");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("playground server failed");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/app.js"),
    )
}

async fn visual_model_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/visual-model.js"),
    )
}

async fn visual_editor_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/visual-editor.js"),
    )
}

async fn codegen_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/codegen.js"),
    )
}

async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

async fn list_examples(State(state): State<Arc<AppState>>) -> Json<Vec<ExampleSnippet>> {
    Json(state.examples.clone())
}

async fn parse_source(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ParseRequest>,
) -> Response {
    if let Err(resp) = validate_source(&request.source, &state.config) {
        return resp;
    }
    let timeout = Duration::from_secs(30);
    let task = tokio::task::spawn_blocking(move || execute_parse(request));
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(Ok(response))) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Ok(Err(error))) => error_response(StatusCode::BAD_REQUEST, error),
        Ok(Err(join_error)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("parse task crashed: {join_error}"),
        ),
        Err(_) => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "parse request timed out".into(),
        ),
    }
}

async fn generate_assist(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<AssistRequest>,
) -> Response {
    let kind = request.kind.trim().to_lowercase();
    let Some(source) = assistant_template(&kind) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("unsupported scaffold kind '{kind}' (expected pbft|hotstuff|raft|tendermint|streamlet|casper)"),
        );
    };
    (
        StatusCode::OK,
        Json(AssistResponse {
            ok: true,
            kind,
            source: source.to_string(),
        }),
    )
        .into_response()
}

async fn run_analysis(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RunRequest>,
) -> Response {
    if let Err(resp) = validate_source(&request.source, &state.config) {
        return resp;
    }
    let _permit = match state.solver_semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "server busy: too many concurrent solver runs".into(),
            );
        }
    };
    let server_timeout = Duration::from_secs(state.config.max_timeout_secs + 5);
    let worker_req = WorkerRequest {
        request,
        max_depth: state.config.max_depth,
        max_timeout: state.config.max_timeout_secs,
    };
    let input_json = match serde_json::to_string(&worker_req) {
        Ok(j) => j,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize worker request: {e}"),
            );
        }
    };

    let exe = std::env::current_exe().unwrap_or_else(|_| "tarsier-playground".into());
    let mut child = match tokio::process::Command::new(&exe)
        .arg("--worker")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to spawn worker: {e}"),
            );
        }
    };

    // Write request to stdin, then drop to signal EOF
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        if let Err(e) = stdin.write_all(input_json.as_bytes()).await {
            let _ = child.kill().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to write to worker stdin: {e}"),
            );
        }
        // stdin dropped here, signaling EOF to the child
    }

    // Wait for the child with a timeout; kill_on_drop ensures cleanup on timeout
    match tokio::time::timeout(server_timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "worker process failed ({}): {}",
                        output.status,
                        stderr.trim()
                    ),
                );
            }
            let parsed: Value = match serde_json::from_slice(&output.stdout) {
                Ok(v) => v,
                Err(e) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to parse worker output: {e}"),
                    );
                }
            };
            if parsed.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                match serde_json::from_value::<RunResponse>(parsed["data"].clone()) {
                    Ok(response) => {
                        let response = truncate_response_if_needed(response, &state.config);
                        (StatusCode::OK, Json(response)).into_response()
                    }
                    Err(e) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to deserialize worker response: {e}"),
                    ),
                }
            } else {
                let error_msg = parsed["error"]
                    .as_str()
                    .unwrap_or("unknown worker error")
                    .to_string();
                error_response(StatusCode::BAD_REQUEST, error_msg)
            }
        }
        Ok(Err(e)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("worker process error: {e}"),
        ),
        Err(_) => {
            // Timeout — child is dropped here, kill_on_drop sends SIGKILL
            error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "analysis request timed out".into(),
            )
        }
    }
}

async fn run_lint(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LintRequest>,
) -> Response {
    if let Err(resp) = validate_source(&request.source, &state.config) {
        return resp;
    }
    let timeout = Duration::from_secs(30);
    let task = tokio::task::spawn_blocking(move || execute_lint(request));
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(Ok(response))) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Ok(Err(error))) => error_response(StatusCode::BAD_REQUEST, error),
        Ok(Err(join_error)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lint task crashed: {join_error}"),
        ),
        Err(_) => error_response(StatusCode::GATEWAY_TIMEOUT, "lint request timed out".into()),
    }
}

fn execute_parse(request: ParseRequest) -> Result<ParseResponse, String> {
    if request.source.trim().is_empty() {
        return Err("source must not be empty".into());
    }
    let filename = request.filename.unwrap_or_else(|| "playground.trs".into());
    let program =
        tarsier_dsl::parse(&request.source, &filename).map_err(|e| format!("parse error: {e}"))?;
    let ast = serde_json::to_value(&program).map_err(|e| format!("serialization error: {e}"))?;
    Ok(ParseResponse { ok: true, ast })
}

fn execute_run(
    request: RunRequest,
    max_depth: usize,
    max_timeout: u64,
) -> Result<RunResponse, String> {
    if request.source.trim().is_empty() {
        return Err("source must not be empty".into());
    }

    let check = request.check.trim().to_lowercase();
    let filename = request
        .filename
        .clone()
        .unwrap_or_else(|| "playground.trs".into());
    let options = build_options(&request, max_depth, max_timeout)?;

    // Parse+lower for visualization (best-effort, don't block analysis on failure)
    let ta = pipeline::parse(&request.source, &filename)
        .ok()
        .and_then(|prog| pipeline::lower(&prog).ok());

    match check.as_str() {
        "verify" => {
            let result = pipeline::verify(&request.source, &filename, &options)
                .map_err(|e| format!("verify failed: {e}"))?;
            Ok(run_response_from_verify(check, result, ta.as_ref()))
        }
        "liveness" => {
            let result = pipeline::check_liveness(&request.source, &filename, &options)
                .map_err(|e| format!("liveness failed: {e}"))?;
            Ok(run_response_from_liveness(check, result, ta.as_ref()))
        }
        "fair-liveness" | "fair_liveness" => {
            let fairness = parse_fairness_mode(request.fairness.as_deref().unwrap_or("weak"))?;
            let result = pipeline::check_fair_liveness_with_mode(
                &request.source,
                &filename,
                &options,
                fairness,
            )
            .map_err(|e| format!("fair-liveness failed: {e}"))?;
            Ok(run_response_from_fair_liveness(check, result, ta.as_ref()))
        }
        "prove" => {
            let result = pipeline::prove_safety(&request.source, &filename, &options)
                .map_err(|e| format!("prove failed: {e}"))?;
            Ok(run_response_from_prove(check, result, ta.as_ref()))
        }
        "prove-fair" | "prove_fair" => {
            let fairness = parse_fairness_mode(request.fairness.as_deref().unwrap_or("weak"))?;
            let result = pipeline::prove_fair_liveness_with_mode(
                &request.source,
                &filename,
                &options,
                fairness,
            )
            .map_err(|e| format!("prove-fair failed: {e}"))?;
            Ok(run_response_from_prove_fair(check, result, ta.as_ref()))
        }
        other => Err(format!(
            "unsupported check '{other}' (expected verify|liveness|fair-liveness|prove|prove-fair)"
        )),
    }
}

fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let clamped = offset.min(source.len());
    for (idx, ch) in source.char_indices() {
        if idx >= clamped {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn line_col_to_byte_offset(source: &str, line: usize, column: usize) -> usize {
    if line <= 1 && column <= 1 {
        return 0;
    }
    let mut cur_line = 1usize;
    let mut cur_col = 1usize;
    for (idx, ch) in source.char_indices() {
        if cur_line == line && cur_col == column {
            return idx;
        }
        if ch == '\n' {
            cur_line += 1;
            cur_col = 1;
        } else {
            cur_col += 1;
        }
    }
    source.len()
}

fn advance_one_char(source: &str, start: usize) -> usize {
    if start >= source.len() {
        return start;
    }
    let tail = &source[start..];
    let char_len = tail.chars().next().map(char::len_utf8).unwrap_or(1);
    (start + char_len).min(source.len())
}

fn infer_parse_error_span(source: &str, message: &str) -> Option<DslSpan> {
    let marker = "-->";
    if let Some(idx) = message.find(marker) {
        let tail = &message[idx + marker.len()..];
        let mut digits = String::new();
        let mut chars = tail.trim_start().chars().peekable();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(chars.next().unwrap_or_default());
        }
        if !digits.is_empty() && chars.peek() == Some(&':') {
            let _ = chars.next();
            let mut col_digits = String::new();
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                col_digits.push(chars.next().unwrap_or_default());
            }
            if let (Ok(line), Ok(column)) = (digits.parse::<usize>(), col_digits.parse::<usize>()) {
                let start = line_col_to_byte_offset(source, line.max(1), column.max(1));
                let end = advance_one_char(source, start);
                return Some(DslSpan { start, end });
            }
        }
    }
    if source.is_empty() {
        None
    } else {
        Some(DslSpan {
            start: 0,
            end: advance_one_char(source, 0),
        })
    }
}

fn lint_soundness_impact(code: &str, severity: &str) -> Option<String> {
    let impact = match code {
        "parse_error" | "lowering_error" => {
            "Model could not be analyzed; no soundness claim can be established."
        }
        "missing_resilience" => {
            "Fault assumptions are under-specified; safety/liveness claims may be vacuous."
        }
        "missing_safety_property" => {
            "No explicit safety objective is checked; security claims may omit core invariants."
        }
        "missing_fault_bound" => {
            "Adversary power is under-constrained; verification may be unsound or misleading."
        }
        "distinct_requires_signed_auth" => {
            "Distinct-sender thresholds need authenticated identities; otherwise sender-counting is unsound."
        }
        "byzantine_network_not_identity_selective" => {
            "Legacy network abstraction weakens protocol-faithful guarantees under Byzantine behavior."
        }
        _ => {
            if severity == "error" {
                "Blocking modeling issue; verification soundness claim is not currently defensible."
            } else if severity == "warn" {
                "Modeling assumption weakens confidence in soundness/fidelity."
            } else {
                ""
            }
        }
    };
    if impact.is_empty() {
        None
    } else {
        Some(impact.to_string())
    }
}

fn to_lint_source_span(source: &str, span: DslSpan) -> LintSourceSpan {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len()).max(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let (end_line, end_column) = byte_offset_to_line_col(source, end);
    LintSourceSpan {
        start,
        end,
        line,
        column,
        end_line,
        end_column,
    }
}

fn execute_lint(request: LintRequest) -> Result<LintResponse, String> {
    if request.source.trim().is_empty() {
        return Err("source must not be empty".into());
    }
    let filename = request.filename.unwrap_or_else(|| "playground.trs".into());
    let mut issues: Vec<LintIssue> = Vec::new();

    let parsed = match tarsier_dsl::parse(&request.source, &filename) {
        Ok(program) => program,
        Err(error) => {
            let parse_error = error.to_string();
            let parse_span = infer_parse_error_span(&request.source, &parse_error)
                .map(|s| to_lint_source_span(&request.source, s));
            issues.push(LintIssue {
                severity: "error".into(),
                code: "parse_error".into(),
                message: parse_error,
                suggestion: None,
                soundness_impact: lint_soundness_impact("parse_error", "error"),
                fix: None,
                source_span: parse_span,
            });
            return Ok(LintResponse { ok: false, issues });
        }
    };

    let protocol = &parsed.protocol.node;
    let protocol_span = Some(parsed.protocol.span);
    if protocol.resilience.is_none() {
        issues.push(LintIssue {
            severity: "warn".into(),
            code: "missing_resilience".into(),
            message: "No resilience clause found; safety claims are usually under-constrained."
                .into(),
            suggestion: Some("Add `resilience: n = 3*f+1;` (or protocol-specific bound).".into()),
            soundness_impact: lint_soundness_impact("missing_resilience", "warn"),
            fix: Some(LintFix {
                label: "insert resilience clause".into(),
                snippet: "\n    resilience: n = 3*f + 1;".into(),
                insert_offset: protocol_span.map(|s| s.end.saturating_sub(1)),
            }),
            source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
        });
    }

    let safety_count = protocol
        .properties
        .iter()
        .filter(|p| {
            matches!(
                p.node.kind,
                PropertyKind::Agreement
                    | PropertyKind::Validity
                    | PropertyKind::Safety
                    | PropertyKind::Invariant
            )
        })
        .count();
    if safety_count == 0 {
        issues.push(LintIssue {
            severity: "warn".into(),
            code: "missing_safety_property".into(),
            message: "No safety/agreement/invariant property declared.".into(),
            suggestion: Some(
                "Declare one `property ...: safety|agreement|invariant|validity { ... }`.".into(),
            ),
            soundness_impact: lint_soundness_impact("missing_safety_property", "warn"),
            fix: Some(LintFix {
                label: "insert safety property".into(),
                snippet:
                    "\n    property safety_inv: safety { forall p: Role. p.decided == false }\n"
                        .into(),
                insert_offset: protocol_span.map(|s| s.end.saturating_sub(1)),
            }),
            source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
        });
    } else if safety_count > 1 {
        issues.push(LintIssue {
            severity: "info".into(),
            code: "multiple_safety_properties".into(),
            message: format!(
                "Found {safety_count} safety-style properties; verify flow will use one primary objective."
            ),
            suggestion: Some("Split checks or keep one canonical safety property for CI.".into()),
            soundness_impact: lint_soundness_impact("multiple_safety_properties", "info"),
            fix: None,
            source_span: protocol
                .properties
                .first()
                .map(|p| to_lint_source_span(&request.source, p.span))
                .or_else(|| protocol_span.map(|s| to_lint_source_span(&request.source, s))),
        });
    }

    let liveness_count = protocol
        .properties
        .iter()
        .filter(|p| matches!(p.node.kind, PropertyKind::Liveness))
        .count();
    if liveness_count == 0 {
        issues.push(LintIssue {
            severity: "info".into(),
            code: "missing_liveness_property".into(),
            message:
                "No explicit liveness property declared; liveness checks will use decided=true fallback."
                    .into(),
            suggestion: Some("Add `property live: liveness { forall p: Role. p.decided == true }`.".into()),
            soundness_impact: lint_soundness_impact("missing_liveness_property", "info"),
            fix: Some(LintFix {
                label: "insert liveness property".into(),
                snippet: "\n    property live: liveness { forall p: Role. p.decided == true }\n"
                    .into(),
                insert_offset: protocol_span.map(|s| s.end.saturating_sub(1)),
            }),
            source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
        });
    }

    if protocol_uses_distinct_thresholds(protocol) {
        let auth_item_span = protocol
            .adversary
            .iter()
            .find(|item| item.key == "auth" || item.key == "authentication")
            .map(|item| item.span);
        let auth_mode = protocol
            .adversary
            .iter()
            .find(|item| item.key == "auth" || item.key == "authentication")
            .map(|item| item.value.as_str())
            .unwrap_or("none");
        if auth_mode != "signed" {
            issues.push(LintIssue {
                severity: "warn".into(),
                code: "distinct_requires_signed_auth".into(),
                message: "Distinct-sender thresholds should use `adversary { auth: signed; }` for sound sender-identity modeling.".into(),
                suggestion: Some("Add `adversary { auth: signed; }`.".into()),
                soundness_impact: lint_soundness_impact("distinct_requires_signed_auth", "warn"),
                fix: Some(LintFix {
                    label: "set signed auth".into(),
                    snippet: "auth: signed;".into(),
                    insert_offset: auth_item_span.map(|s| s.start),
                }),
                source_span: auth_item_span
                    .or(protocol_span)
                    .map(|s| to_lint_source_span(&request.source, s)),
            });
        }
    }

    let adv_model = protocol
        .adversary
        .iter()
        .find(|item| item.key == "model")
        .map(|item| item.value.as_str())
        .unwrap_or("byzantine");
    let network_mode = protocol
        .adversary
        .iter()
        .find(|item| item.key == "network")
        .map(|item| item.value.as_str())
        .unwrap_or("classic");
    if adv_model == "byzantine"
        && network_mode != "identity_selective"
        && network_mode != "process_selective"
    {
        let network_item_span = protocol
            .adversary
            .iter()
            .find(|item| item.key == "network")
            .map(|item| item.span);
        let model_item_span = protocol
            .adversary
            .iter()
            .find(|item| item.key == "model")
            .map(|item| item.span);
        issues.push(LintIssue {
            severity: "warn".into(),
            code: "byzantine_network_not_identity_selective".into(),
            message: "Byzantine model is using `network: classic`; prefer `network: process_selective` (or `identity_selective`) for recipient-coupled identity semantics.".into(),
            suggestion: Some("Set `adversary { network: process_selective; }`.".into()),
            soundness_impact: lint_soundness_impact(
                "byzantine_network_not_identity_selective",
                "warn",
            ),
            fix: Some(LintFix {
                label: "set faithful network mode".into(),
                snippet: "network: process_selective;".into(),
                insert_offset: network_item_span.or(model_item_span).map(|s| s.start),
            }),
            source_span: network_item_span
                .or(model_item_span)
                .or(protocol_span)
                .map(|s| to_lint_source_span(&request.source, s)),
        });
    }

    match tarsier_ir::lowering::lower(&parsed) {
        Ok(ta) => {
            if ta.adversary_bound_param.is_none() {
                issues.push(LintIssue {
                    severity: "warn".into(),
                    code: "missing_fault_bound".into(),
                    message:
                        "No adversary bound parameter found; fault reasoning may be underspecified."
                            .into(),
                    suggestion: Some("Add `adversary { bound: f; }`.".into()),
                    soundness_impact: lint_soundness_impact("missing_fault_bound", "warn"),
                    fix: Some(LintFix {
                        label: "set adversary bound".into(),
                        snippet: "bound: f;".into(),
                        insert_offset: protocol_span.map(|s| s.end.saturating_sub(1)),
                    }),
                    source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
                });
            }
            if ta.locations.is_empty() {
                issues.push(LintIssue {
                    severity: "error".into(),
                    code: "no_roles".into(),
                    message: "No roles detected after lowering.".into(),
                    suggestion: None,
                    soundness_impact: lint_soundness_impact("no_roles", "error"),
                    fix: None,
                    source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
                });
            }
        }
        Err(error) => {
            issues.push(LintIssue {
                severity: "error".into(),
                code: "lowering_error".into(),
                message: error.to_string(),
                suggestion: None,
                soundness_impact: lint_soundness_impact("lowering_error", "error"),
                fix: None,
                source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
            });
        }
    }

    let ok = !issues.iter().any(|issue| issue.severity == "error");
    Ok(LintResponse { ok, issues })
}

fn assistant_template(kind: &str) -> Option<&'static str> {
    match kind {
        "pbft" => Some(
            r#"protocol PBFTTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
        network: process_selective;
    }

    message PrePrepare(view: nat in 0..32, value: bool);
    message Prepare(view: nat in 0..32, value: bool);
    message Commit(view: nat in 0..32, value: bool);

    role Replica {
        var view: nat in 0..32 = 0;
        var decided: bool = false;
        var value: bool = false;
        init idle;

        phase idle {}
        phase prepared {}
        phase committed {}
    }

    property safety_inv: safety {
        forall p, q: Replica.
            (p.decided == true && q.decided == true) ==> (p.value == q.value)
    }
    property live: liveness { forall p: Replica. p.decided == true }
}
"#,
        ),
        "hotstuff" => Some(
            r#"protocol HotStuffTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
        network: process_selective;
    }

    message Proposal(view: nat in 0..64, block: nat in 0..128);
    message Vote(view: nat in 0..64, block: nat in 0..128);
    message NewView(view: nat in 0..64);

    certificate QC from Vote threshold 2*f+1 signer Node;

    role Node {
        var view: nat in 0..64 = 0;
        var decided: bool = false;
        var locked_block: nat in 0..128 = 0;
        init wait;

        phase wait {}
        phase vote {}
        phase commit {}
    }

    property safety_inv: safety {
        forall p, q: Node.
            (p.decided == true && q.decided == true) ==> (p.locked_block == q.locked_block)
    }
    property live: liveness { forall p: Node. p.decided == true }
}
"#,
        ),
        "raft" => Some(
            r#"protocol RaftTemplate {
    params n, f, gst;
    resilience: n = 2*f + 1;
    adversary {
        model: crash;
        bound: f;
        timing: partial_synchrony;
        gst: gst;
    }

    message RequestVote(term: nat in 0..32);
    message VoteGranted(term: nat in 0..32);
    message AppendEntries(term: nat in 0..32);

    role Server {
        var term: nat in 0..32 = 0;
        var leader: bool = false;
        var decided: bool = false;
        init follower;

        phase follower {}
        phase candidate {}
        phase leader {}
    }

    property election_safety: safety {
        forall p, q: Server.
            (p.leader == true && q.leader == true) ==> (p.term == q.term)
    }
    property live: liveness { forall p: Server. p.decided == true }
}
"#,
        ),
        "tendermint" => Some(
            r#"protocol TendermintTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(round: nat in 0..32, value: bool);
    message Prevote(round: nat in 0..32, value: bool);
    message Precommit(round: nat in 0..32, value: bool);

    role Validator {
        var round: nat in 0..32 = 0;
        var decided: bool = false;
        var locked_round: nat in 0..32 = 0;
        var locked_value: bool = false;
        init propose;

        phase propose {}
        phase prevote {}
        phase precommit {}
        phase done {}
    }

    property safety_inv: safety {
        forall p, q: Validator.
            (p.decided == true && q.decided == true) ==> (p.locked_value == q.locked_value)
    }
    property live: liveness { forall p: Validator. p.decided == true }
}
"#,
        ),
        "streamlet" => Some(
            r#"protocol StreamletTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(epoch: nat in 0..32, block: nat in 0..128);
    message Vote(epoch: nat in 0..32, block: nat in 0..128);
    message Notarize(epoch: nat in 0..32, block: nat in 0..128);

    role Node {
        var epoch: nat in 0..32 = 0;
        var decided: bool = false;
        var finalized_block: nat in 0..128 = 0;
        init wait;

        phase wait {}
        phase voted {}
        phase finalized {}
    }

    property safety_inv: safety {
        forall p, q: Node.
            (p.decided == true && q.decided == true) ==> (p.finalized_block == q.finalized_block)
    }
    property live: liveness { forall p: Node. p.decided == true }
}
"#,
        ),
        "casper" => Some(
            r#"protocol CasperFFGTemplate {
    params n, f, gst;
    resilience: n = 3*f + 1;
    adversary {
        model: byzantine;
        bound: f;
        auth: signed;
        equivocation: none;
        timing: partial_synchrony;
        gst: gst;
    }

    message Proposal(epoch: nat in 0..32, checkpoint: nat in 0..128);
    message Vote(epoch: nat in 0..32, source: nat in 0..128, target: nat in 0..128);
    message Justify(epoch: nat in 0..32, checkpoint: nat in 0..128);

    role Validator {
        var epoch: nat in 0..32 = 0;
        var decided: bool = false;
        var justified_checkpoint: nat in 0..128 = 0;
        var finalized_checkpoint: nat in 0..128 = 0;
        init attest;

        phase attest {}
        phase justified {}
        phase finalized {}
    }

    property safety_inv: safety {
        forall p, q: Validator.
            (p.decided == true && q.decided == true) ==> (p.finalized_checkpoint == q.finalized_checkpoint)
    }
    property live: liveness { forall p: Validator. p.decided == true }
}
"#,
        ),
        _ => None,
    }
}

fn guard_uses_distinct_threshold(guard: &tarsier_dsl::ast::GuardExpr) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    match guard {
        GuardExpr::Threshold(t) => t.distinct,
        GuardExpr::And(lhs, rhs) | GuardExpr::Or(lhs, rhs) => {
            guard_uses_distinct_threshold(lhs) || guard_uses_distinct_threshold(rhs)
        }
        _ => false,
    }
}

fn protocol_uses_distinct_thresholds(protocol: &tarsier_dsl::ast::ProtocolDecl) -> bool {
    protocol.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_distinct_threshold(&tr.node.guard))
        })
    })
}

fn build_options(
    request: &RunRequest,
    max_depth: usize,
    max_timeout: u64,
) -> Result<PipelineOptions, String> {
    let solver = parse_solver_choice(request.solver.as_deref().unwrap_or("z3"))?;
    let soundness = parse_soundness_mode(request.soundness.as_deref().unwrap_or("strict"))?;
    let proof_engine = parse_proof_engine(request.proof_engine.as_deref().unwrap_or("kinduction"))?;

    Ok(PipelineOptions {
        solver,
        max_depth: request.depth.unwrap_or(12).min(max_depth),
        timeout_secs: request.timeout_secs.unwrap_or(60).min(max_timeout),
        dump_smt: None,
        soundness,
        proof_engine,
    })
}

fn parse_solver_choice(raw: &str) -> Result<SolverChoice, String> {
    match raw.trim().to_lowercase().as_str() {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => Err(format!("unknown solver '{other}' (expected z3|cvc5)")),
    }
}

fn parse_soundness_mode(raw: &str) -> Result<SoundnessMode, String> {
    match raw.trim().to_lowercase().as_str() {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => Err(format!(
            "unknown soundness mode '{other}' (expected strict|permissive)"
        )),
    }
}

fn parse_proof_engine(raw: &str) -> Result<ProofEngine, String> {
    match raw.trim().to_lowercase().as_str() {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        other => Err(format!(
            "unknown proof engine '{other}' (expected kinduction|pdr)"
        )),
    }
}

fn parse_fairness_mode(raw: &str) -> Result<FairnessMode, String> {
    match raw.trim().to_lowercase().as_str() {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(format!(
            "unknown fairness mode '{other}' (expected weak|strong)"
        )),
    }
}

fn trace_visualizations(
    trace: &Trace,
    ta: Option<&ThresholdAutomaton>,
) -> (Option<String>, Option<String>) {
    match ta {
        Some(ta) => (
            Some(render_trace_mermaid(trace, ta, None)),
            Some(render_trace_timeline(trace, ta, None)),
        ),
        None => (None, None),
    }
}

fn run_response_from_verify(
    check: String,
    result: VerificationResult,
    ta: Option<&ThresholdAutomaton>,
) -> RunResponse {
    let output = format!("{result}");
    match result {
        VerificationResult::Safe { depth_checked } => RunResponse {
            ok: true,
            check,
            result: "safe".into(),
            summary: format!("Safe up to depth {depth_checked}."),
            output,
            trace: None,
            cti: None,
            details: json!({"depth_checked": depth_checked}),
            mermaid: None,
            timeline: None,
        },
        VerificationResult::ProbabilisticallySafe {
            depth_checked,
            failure_probability,
            committee_analyses,
        } => RunResponse {
            ok: true,
            check,
            result: "probabilistically_safe".into(),
            summary: format!(
                "Probabilistically safe up to depth {depth_checked} (failure <= {:.0e}).",
                failure_probability
            ),
            output,
            trace: None,
            cti: None,
            details: json!({
                "depth_checked": depth_checked,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len()
            }),
            mermaid: None,
            timeline: None,
        },
        VerificationResult::Unsafe { trace } => {
            let (mermaid, timeline) = trace_visualizations(&trace, ta);
            RunResponse {
                ok: false,
                check,
                result: "unsafe".into(),
                summary: "Counterexample found.".into(),
                output,
                trace: Some(trace_to_json(&trace)),
                cti: None,
                details: json!({"steps": trace.steps.len()}),
                mermaid,
                timeline,
            }
        }
        VerificationResult::Unknown { reason } => RunResponse {
            ok: false,
            check,
            result: "unknown".into(),
            summary: "Verification inconclusive.".into(),
            output,
            trace: None,
            cti: None,
            details: json!({"reason": reason}),
            mermaid: None,
            timeline: None,
        },
    }
}

fn run_response_from_liveness(
    check: String,
    result: LivenessResult,
    ta: Option<&ThresholdAutomaton>,
) -> RunResponse {
    let output = format!("{result}");
    match result {
        LivenessResult::Live { depth_checked } => RunResponse {
            ok: true,
            check,
            result: "live".into(),
            summary: format!("Liveness target satisfied by depth {depth_checked}."),
            output,
            trace: None,
            cti: None,
            details: json!({"depth_checked": depth_checked}),
            mermaid: None,
            timeline: None,
        },
        LivenessResult::NotLive { trace } => {
            let (mermaid, timeline) = trace_visualizations(&trace, ta);
            RunResponse {
                ok: false,
                check,
                result: "not_live".into(),
                summary: "Liveness counterexample found.".into(),
                output,
                trace: Some(trace_to_json(&trace)),
                cti: None,
                details: json!({"steps": trace.steps.len()}),
                mermaid,
                timeline,
            }
        }
        LivenessResult::Unknown { reason } => RunResponse {
            ok: false,
            check,
            result: "unknown".into(),
            summary: "Liveness check inconclusive.".into(),
            output,
            trace: None,
            cti: None,
            details: json!({"reason": reason}),
            mermaid: None,
            timeline: None,
        },
    }
}

fn run_response_from_fair_liveness(
    check: String,
    result: FairLivenessResult,
    ta: Option<&ThresholdAutomaton>,
) -> RunResponse {
    let output = format!("{result}");
    match result {
        FairLivenessResult::NoFairCycleUpTo { depth_checked } => RunResponse {
            ok: true,
            check,
            result: "no_fair_cycle".into(),
            summary: format!("No fair non-terminating cycle found up to depth {depth_checked}."),
            output,
            trace: None,
            cti: None,
            details: json!({"depth_checked": depth_checked}),
            mermaid: None,
            timeline: None,
        },
        FairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => {
            let (mermaid, timeline) = trace_visualizations(&trace, ta);
            RunResponse {
                ok: false,
                check,
                result: "fair_cycle_found".into(),
                summary: format!(
                    "Fair non-terminating cycle found (depth={depth}, loop_start={loop_start})."
                ),
                output,
                trace: Some(trace_to_json(&trace)),
                cti: None,
                details: json!({"depth": depth, "loop_start": loop_start}),
                mermaid,
                timeline,
            }
        }
        FairLivenessResult::Unknown { reason } => RunResponse {
            ok: false,
            check,
            result: "unknown".into(),
            summary: "Fair-liveness check inconclusive.".into(),
            output,
            trace: None,
            cti: None,
            details: json!({"reason": reason}),
            mermaid: None,
            timeline: None,
        },
    }
}

fn run_response_from_prove(
    check: String,
    result: UnboundedSafetyResult,
    ta: Option<&ThresholdAutomaton>,
) -> RunResponse {
    let output = format!("{result}");
    match result {
        UnboundedSafetyResult::Safe { induction_k } => RunResponse {
            ok: true,
            check,
            result: "safe".into(),
            summary: format!("Unbounded safety proved (k={induction_k})."),
            output,
            trace: None,
            cti: None,
            details: json!({"induction_k": induction_k}),
            mermaid: None,
            timeline: None,
        },
        UnboundedSafetyResult::ProbabilisticallySafe {
            induction_k,
            failure_probability,
            committee_analyses,
        } => RunResponse {
            ok: true,
            check,
            result: "probabilistically_safe".into(),
            summary: format!(
                "Unbounded probabilistic safety proved (k={induction_k}, failure <= {:.0e}).",
                failure_probability
            ),
            output,
            trace: None,
            cti: None,
            details: json!({
                "induction_k": induction_k,
                "failure_probability": failure_probability,
                "committee_count": committee_analyses.len()
            }),
            mermaid: None,
            timeline: None,
        },
        UnboundedSafetyResult::Unsafe { trace } => {
            let (mermaid, timeline) = trace_visualizations(&trace, ta);
            RunResponse {
                ok: false,
                check,
                result: "unsafe".into(),
                summary: "Unbounded safety violation found.".into(),
                output,
                trace: Some(trace_to_json(&trace)),
                cti: None,
                details: json!({"steps": trace.steps.len()}),
                mermaid,
                timeline,
            }
        }
        UnboundedSafetyResult::NotProved { max_k, cti } => {
            let cti_json = cti.as_ref().map(cti_to_json);
            let summary = if let Some(witness) = cti {
                format!(
                    "Proof did not close up to k={max_k}; CTI available at k={}.",
                    witness.k
                )
            } else {
                format!("Proof did not close up to k={max_k}.")
            };
            RunResponse {
                ok: false,
                check,
                result: "not_proved".into(),
                summary,
                output,
                trace: None,
                cti: cti_json,
                details: json!({"max_k": max_k}),
                mermaid: None,
                timeline: None,
            }
        }
        UnboundedSafetyResult::Unknown { reason } => RunResponse {
            ok: false,
            check,
            result: "unknown".into(),
            summary: "Unbounded proof inconclusive.".into(),
            output,
            trace: None,
            cti: None,
            details: json!({"reason": reason}),
            mermaid: None,
            timeline: None,
        },
    }
}

fn run_response_from_prove_fair(
    check: String,
    result: UnboundedFairLivenessResult,
    ta: Option<&ThresholdAutomaton>,
) -> RunResponse {
    let output = format!("{result}");
    match result {
        UnboundedFairLivenessResult::LiveProved { frame } => RunResponse {
            ok: true,
            check,
            result: "live_proved".into(),
            summary: format!("Unbounded fair-liveness proved (frame={frame})."),
            output,
            trace: None,
            cti: None,
            details: json!({"frame": frame}),
            mermaid: None,
            timeline: None,
        },
        UnboundedFairLivenessResult::FairCycleFound {
            depth,
            loop_start,
            trace,
        } => {
            let (mermaid, timeline) = trace_visualizations(&trace, ta);
            RunResponse {
                ok: false,
                check,
                result: "fair_cycle_found".into(),
                summary: format!(
                    "Fair non-terminating cycle found (depth={depth}, loop_start={loop_start})."
                ),
                output,
                trace: Some(trace_to_json(&trace)),
                cti: None,
                details: json!({"depth": depth, "loop_start": loop_start}),
                mermaid,
                timeline,
            }
        }
        UnboundedFairLivenessResult::NotProved { max_k } => RunResponse {
            ok: false,
            check,
            result: "not_proved".into(),
            summary: format!("Unbounded fair-liveness proof did not converge up to k={max_k}."),
            output,
            trace: None,
            cti: None,
            details: json!({"max_k": max_k}),
            mermaid: None,
            timeline: None,
        },
        UnboundedFairLivenessResult::Unknown { reason } => RunResponse {
            ok: false,
            check,
            result: "unknown".into(),
            summary: "Unbounded fair-liveness proof inconclusive.".into(),
            output,
            trace: None,
            cti: None,
            details: json!({
                "reason": reason,
                "reason_code": LivenessUnknownReason::classify(&reason).code(),
            }),
            mermaid: None,
            timeline: None,
        },
    }
}

fn trace_to_json(trace: &Trace) -> Value {
    let steps: Vec<Value> = trace
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let deliveries: Vec<Value> = step
                .deliveries
                .iter()
                .map(|delivery| {
                    json!({
                        "kind": format!("{:?}", delivery.kind),
                        "count": delivery.count,
                        "shared_var": delivery.shared_var,
                        "shared_var_name": delivery.shared_var_name,
                        "sender": {
                            "role": delivery.sender.role.clone(),
                            "process": delivery.sender.process.clone(),
                            "key": delivery.sender.key.clone(),
                        },
                        "recipient": {
                            "role": delivery.recipient.role.clone(),
                            "process": delivery.recipient.process.clone(),
                            "key": delivery.recipient.key.clone(),
                        },
                        "payload": {
                            "family": delivery.payload.family.clone(),
                            "fields": delivery.payload.fields.clone(),
                            "variant": delivery.payload.variant.clone(),
                        },
                        "auth": {
                            "authenticated_channel": delivery.auth.authenticated_channel,
                            "signature_key": delivery.auth.signature_key.clone(),
                            "key_owner_role": delivery.auth.key_owner_role.clone(),
                            "key_compromised": delivery.auth.key_compromised,
                            "provenance": format!("{:?}", delivery.auth.provenance),
                        }
                    })
                })
                .collect();
            json!({
                "index": index + 1,
                "smt_step": step.smt_step,
                "rule_id": step.rule_id,
                "delta": step.delta,
                "deliveries": deliveries,
                "kappa": step.config.kappa,
                "gamma": step.config.gamma,
            })
        })
        .collect();

    json!({
        "params": trace.param_values,
        "initial": {
            "kappa": trace.initial_config.kappa,
            "gamma": trace.initial_config.gamma,
        },
        "steps": steps,
    })
}

fn cti_to_json(cti: &InductionCtiSummary) -> Value {
    json!({
        "k": cti.k,
        "classification": format!("{}", cti.classification),
        "classification_evidence": cti.classification_evidence,
        "rationale": cti.rationale,
        "params": named_values_json(&cti.params),
        "hypothesis_locations": named_values_json(&cti.hypothesis_locations),
        "hypothesis_shared": named_values_json(&cti.hypothesis_shared),
        "violating_locations": named_values_json(&cti.violating_locations),
        "violating_shared": named_values_json(&cti.violating_shared),
        "final_step_rules": named_values_json(&cti.final_step_rules),
        "violated_condition": cti.violated_condition,
    })
}

fn named_values_json(values: &[(String, i64)]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect(),
    )
}

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(json!({"ok": false, "error": message}))).into_response()
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
        .layer(middleware::from_fn_with_state(
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

#[cfg(test)]
mod tests {
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
}

#[cfg(test)]
mod security_tests {
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
}
