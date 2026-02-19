use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tarsier_dsl::ast::{PropertyKind, Span as DslSpan};
use tarsier_engine::pipeline::{
    self, FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{
    FairLivenessResult, InductionCtiSummary, LivenessResult, UnboundedFairLivenessResult,
    UnboundedSafetyResult, VerificationResult,
};
use tarsier_engine::visualization::{render_trace_mermaid, render_trace_timeline};
use tarsier_ir::counter_system::Trace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;
use tracing::info;

#[derive(Clone, Serialize)]
struct ExampleSnippet {
    id: &'static str,
    name: &'static str,
    source: &'static str,
}

#[derive(Clone)]
struct AppState {
    examples: Vec<ExampleSnippet>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Serialize)]
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
struct LintIssue {
    severity: String,
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
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

#[tokio::main]
async fn main() {
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

    let state = Arc::new(AppState {
        examples: vec![
            ExampleSnippet {
                id: "pbft",
                name: "PBFT (Simple)",
                source: include_str!("../../examples/pbft_simple.trs"),
            },
            ExampleSnippet {
                id: "pbft_liveness",
                name: "PBFT (Faithful Liveness)",
                source: include_str!("../../examples/pbft_faithful_liveness.trs"),
            },
            ExampleSnippet {
                id: "rb_bug",
                name: "Reliable Broadcast (Buggy)",
                source: include_str!("../../examples/reliable_broadcast_buggy.trs"),
            },
            ExampleSnippet {
                id: "trivial_live",
                name: "Trivial Live",
                source: include_str!("../../examples/trivial_live.trs"),
            },
        ],
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/health", get(health))
        .route("/api/examples", get(list_examples))
        .route("/api/assist", post(generate_assist))
        .route("/api/run", post(run_analysis))
        .route("/api/lint", post(run_lint))
        .with_state(state);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind playground address");

    info!(%addr, "tarsier playground ready");
    axum::serve(listener, app)
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

async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

async fn list_examples(State(state): State<Arc<AppState>>) -> Json<Vec<ExampleSnippet>> {
    Json(state.examples.clone())
}

async fn generate_assist(Json(request): Json<AssistRequest>) -> Response {
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

async fn run_analysis(Json(request): Json<RunRequest>) -> Response {
    let task = tokio::task::spawn_blocking(move || execute_run(request));
    match task.await {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Err(error)) => error_response(StatusCode::BAD_REQUEST, error),
        Err(join_error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("analysis task crashed: {join_error}"),
        ),
    }
}

async fn run_lint(Json(request): Json<LintRequest>) -> Response {
    let task = tokio::task::spawn_blocking(move || execute_lint(request));
    match task.await {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Err(error)) => error_response(StatusCode::BAD_REQUEST, error),
        Err(join_error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lint task crashed: {join_error}"),
        ),
    }
}

fn execute_run(request: RunRequest) -> Result<RunResponse, String> {
    if request.source.trim().is_empty() {
        return Err("source must not be empty".into());
    }

    let check = request.check.trim().to_lowercase();
    let filename = request
        .filename
        .clone()
        .unwrap_or_else(|| "playground.trs".into());
    let options = build_options(&request)?;

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
            issues.push(LintIssue {
                severity: "error".into(),
                code: "parse_error".into(),
                message: error.to_string(),
                suggestion: None,
                source_span: None,
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
                    source_span: protocol_span.map(|s| to_lint_source_span(&request.source, s)),
                });
            }
            if ta.locations.is_empty() {
                issues.push(LintIssue {
                    severity: "error".into(),
                    code: "no_roles".into(),
                    message: "No roles detected after lowering.".into(),
                    suggestion: None,
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

fn build_options(request: &RunRequest) -> Result<PipelineOptions, String> {
    let solver = parse_solver_choice(request.solver.as_deref().unwrap_or("z3"))?;
    let soundness = parse_soundness_mode(request.soundness.as_deref().unwrap_or("strict"))?;
    let proof_engine = parse_proof_engine(request.proof_engine.as_deref().unwrap_or("kinduction"))?;

    Ok(PipelineOptions {
        solver,
        max_depth: request.depth.unwrap_or(12),
        timeout_secs: request.timeout_secs.unwrap_or(60),
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
            details: json!({"reason": reason}),
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
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let state = Arc::new(AppState {
            examples: vec![ExampleSnippet {
                id: "test",
                name: "Test Example",
                source: "protocol Test { params n, f; }",
            }],
        });
        Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/api/health", get(health))
            .route("/api/examples", get(list_examples))
            .route("/api/assist", post(generate_assist))
            .route("/api/lint", post(run_lint))
            .route("/api/run", post(run_analysis))
            .with_state(state)
    }

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
        assert!(json.as_array().unwrap().len() >= 1);
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
        let source = include_str!("../../examples/pbft_simple.trs");
        let body = serde_json::to_string(&serde_json::json!({
            "source": source,
            "filename": "pbft_simple.trs",
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
}
