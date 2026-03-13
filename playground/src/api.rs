// Worker-mode helpers, API handlers, and response shaping.

use super::*;

pub(crate) fn run_worker_mode() {
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

pub(crate) async fn parse_source(
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

pub(crate) async fn generate_assist(
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

pub(crate) async fn run_analysis(
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

pub(crate) async fn run_lint(
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

pub(crate) fn execute_lint(request: LintRequest) -> Result<LintResponse, String> {
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
            if ta.constraints.adversary_bound_param.is_none() {
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

pub(crate) fn build_options(
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

pub(crate) fn parse_proof_engine(raw: &str) -> Result<ProofEngine, String> {
    match raw.trim().to_lowercase().as_str() {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        "ranking" => Ok(ProofEngine::Ranking),
        other => Err(format!(
            "unknown proof engine '{other}' (expected kinduction|pdr|ranking)"
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

pub(crate) fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(json!({"ok": false, "error": message}))).into_response()
}
