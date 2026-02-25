// Command handlers for: ConformanceCheck, ConformanceReplay, ConformanceObligations, ConformanceSuite
//
// These commands handle runtime trace conformance checking, replay-based
// self-validation, obligation map generation, and deterministic suite execution.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use miette::IntoDiagnostic;
use serde::Serialize;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine};
use tarsier_engine::result::{FairLivenessResult, LivenessResult, VerificationResult};
use tarsier_proof_kernel::sha256_hex_bytes;

use super::helpers::{
    parse_conformance_adapter, parse_conformance_mode, parse_output_format, parse_solver_choice,
    parse_soundness_mode,
};
use crate::OutputFormat;

// ---------------------------------------------------------------------------
// Conformance triage constants
// ---------------------------------------------------------------------------

pub(crate) const CONFORMANCE_TRIAGE_MODEL_CHANGE: &str = "model_change";
pub(crate) const CONFORMANCE_TRIAGE_ENGINE_REGRESSION: &str = "engine_regression";
pub(crate) const CONFORMANCE_TRIAGE_IMPL_DIVERGENCE: &str = "impl_divergence";
pub(crate) const CONFORMANCE_TRIAGE_CATEGORIES: [&str; 3] = [
    CONFORMANCE_TRIAGE_MODEL_CHANGE,
    CONFORMANCE_TRIAGE_ENGINE_REGRESSION,
    CONFORMANCE_TRIAGE_IMPL_DIVERGENCE,
];

// ---------------------------------------------------------------------------
// Conformance suite report types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct ConformanceSuiteEntryReport {
    pub(crate) name: String,
    pub(crate) protocol_file: String,
    pub(crate) trace_file: String,
    pub(crate) trace_adapter: String,
    pub(crate) checker_mode: String,
    pub(crate) expected_verdict: String,
    pub(crate) actual_verdict: String,
    pub(crate) status: String,
    pub(crate) duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) triage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model_sha256_expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model_sha256_actual: Option<String>,
    pub(crate) model_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_link: Option<String>,
    pub(crate) violations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConformanceSuiteAssumptions {
    pub(crate) runner_version: String,
    pub(crate) schema_version: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConformanceSuiteReport {
    pub(crate) schema_version: u32,
    pub(crate) suite_name: String,
    pub(crate) manifest_path: String,
    pub(crate) entries: Vec<ConformanceSuiteEntryReport>,
    pub(crate) assumptions: ConformanceSuiteAssumptions,
    pub(crate) passed: usize,
    pub(crate) failed: usize,
    pub(crate) errors: usize,
    pub(crate) triage: BTreeMap<String, usize>,
    pub(crate) overall: String,
}

// ---------------------------------------------------------------------------
// Triage classification helpers
// ---------------------------------------------------------------------------

pub(crate) fn classify_conformance_mismatch_triage(
    model_changed: bool,
    mismatch_hint: Option<&str>,
) -> &'static str {
    if model_changed {
        return CONFORMANCE_TRIAGE_MODEL_CHANGE;
    }
    match mismatch_hint.map(str::trim) {
        Some(CONFORMANCE_TRIAGE_MODEL_CHANGE) => CONFORMANCE_TRIAGE_MODEL_CHANGE,
        Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION) => CONFORMANCE_TRIAGE_ENGINE_REGRESSION,
        Some(CONFORMANCE_TRIAGE_IMPL_DIVERGENCE) => CONFORMANCE_TRIAGE_IMPL_DIVERGENCE,
        _ => CONFORMANCE_TRIAGE_IMPL_DIVERGENCE,
    }
}

pub(crate) fn classify_conformance_load_error_triage(stage: &str) -> &'static str {
    match stage {
        "model_read" | "model_parse" | "model_lower" => CONFORMANCE_TRIAGE_MODEL_CHANGE,
        "trace_read" | "trace_adapt" => CONFORMANCE_TRIAGE_IMPL_DIVERGENCE,
        _ => CONFORMANCE_TRIAGE_ENGINE_REGRESSION,
    }
}

// ---------------------------------------------------------------------------
// Artifact-path sanitiser (shared with governance, duplicated here to avoid
// pulling in governance-gated helpers)
// ---------------------------------------------------------------------------

fn sanitize_artifact_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '.' || ch == '/' || ch == '\\' || ch.is_whitespace() {
            out.push('_');
        }
    }
    let compact = out.trim_matches('_');
    if compact.is_empty() {
        "entry".to_string()
    } else {
        compact.to_string()
    }
}

fn write_json_artifact(path: &PathBuf, value: &Value) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(path, serde_json::to_string_pretty(value).into_diagnostic()?).into_diagnostic()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Core suite runner
// ---------------------------------------------------------------------------

pub(crate) fn run_conformance_suite(
    manifest_path: &PathBuf,
    artifact_dir: Option<&Path>,
) -> miette::Result<ConformanceSuiteReport> {
    use tarsier_conformance::manifest::{
        validate_manifest, validate_manifest_files, ConformanceManifest,
        CONFORMANCE_MANIFEST_SCHEMA_VERSION,
    };

    let manifest_raw = fs::read_to_string(manifest_path).into_diagnostic()?;
    let manifest: ConformanceManifest = serde_json::from_str(&manifest_raw).into_diagnostic()?;

    // Validate manifest schema
    let schema_errors = validate_manifest(&manifest);
    if !schema_errors.is_empty() {
        let msgs: Vec<String> = schema_errors.iter().map(|e| e.message.clone()).collect();
        miette::bail!(
            "Conformance manifest validation failed:\n  {}",
            msgs.join("\n  ")
        );
    }

    // Resolve base dir from manifest path
    let base_dir = manifest_path.parent().unwrap_or(Path::new("."));
    // For relative paths in the manifest, resolve from repo root (parent of manifest dir)
    // The manifest uses paths relative to the repo root.
    let repo_root = if base_dir.ends_with("examples/conformance") {
        base_dir
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(base_dir)
    } else {
        base_dir
    };

    // Validate file paths
    let file_errors = validate_manifest_files(&manifest, repo_root);
    if !file_errors.is_empty() {
        let msgs: Vec<String> = file_errors.iter().map(|e| e.message.clone()).collect();
        miette::bail!(
            "Conformance manifest file validation failed:\n  {}",
            msgs.join("\n  ")
        );
    }

    let mut entry_reports: Vec<ConformanceSuiteEntryReport> = Vec::new();

    // Process entries in manifest order (deterministic)
    for entry in &manifest.entries {
        let start = Instant::now();
        let protocol_path = repo_root.join(&entry.protocol_file);
        let trace_path = repo_root.join(&entry.trace_file);

        let mut report = ConformanceSuiteEntryReport {
            name: entry.name.clone(),
            protocol_file: entry.protocol_file.clone(),
            trace_file: entry.trace_file.clone(),
            trace_adapter: entry.trace_adapter.clone(),
            checker_mode: entry.checker_mode.clone(),
            expected_verdict: entry.expected_verdict.clone(),
            actual_verdict: String::new(),
            status: String::new(),
            duration_ms: 0,
            triage: None,
            model_sha256_expected: entry.model_sha256.clone(),
            model_sha256_actual: None,
            model_changed: false,
            artifact_link: None,
            violations: vec![],
            error: None,
        };

        'entry: {
            // Load and parse protocol
            let source = match fs::read_to_string(&protocol_path) {
                Ok(s) => s,
                Err(e) => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage =
                        Some(classify_conformance_load_error_triage("model_read").into());
                    report.error = Some(format!("Failed to read protocol file: {e}"));
                    break 'entry;
                }
            };
            let model_sha_actual = sha256_hex_bytes(source.as_bytes());
            report.model_sha256_actual = Some(model_sha_actual.clone());
            if let Some(expected_hash) = entry.model_sha256.as_deref().map(str::trim) {
                report.model_changed = !expected_hash.eq_ignore_ascii_case(&model_sha_actual);
                if report.model_changed {
                    report.error = Some(format!(
                        "Model SHA mismatch: expected {}, actual {}",
                        expected_hash, model_sha_actual
                    ));
                }
            }
            let filename = protocol_path.display().to_string();
            let program = match tarsier_engine::pipeline::parse(&source, &filename) {
                Ok(p) => p,
                Err(e) => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage =
                        Some(classify_conformance_load_error_triage("model_parse").into());
                    report.error = Some(format!("Parse error: {e}"));
                    break 'entry;
                }
            };
            let ta = match tarsier_engine::pipeline::lower(&program) {
                Ok(t) => t,
                Err(e) => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage =
                        Some(classify_conformance_load_error_triage("model_lower").into());
                    report.error = Some(format!("Lowering error: {e}"));
                    break 'entry;
                }
            };

            // Load trace
            let trace_source = match fs::read_to_string(&trace_path) {
                Ok(s) => s,
                Err(e) => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage =
                        Some(classify_conformance_load_error_triage("trace_read").into());
                    report.error = Some(format!("Failed to read trace file: {e}"));
                    break 'entry;
                }
            };

            let adapter = match entry
                .trace_adapter
                .parse::<tarsier_conformance::adapters::AdapterKind>()
            {
                Ok(kind) => kind,
                Err(e) => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage = Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION.into());
                    report.error = Some(format!("Adapter parse error: {e}"));
                    break 'entry;
                }
            };

            let runtime_trace =
                match tarsier_conformance::adapters::adapt_trace(adapter, &trace_source) {
                    Ok(t) => t,
                    Err(e) => {
                        report.actual_verdict = "error".into();
                        report.status = "error".into();
                        report.triage =
                            Some(classify_conformance_load_error_triage("trace_adapt").into());
                        report.error = Some(format!("Trace adapter error: {e}"));
                        break 'entry;
                    }
                };

            let checker_mode = match entry.checker_mode.trim().to_ascii_lowercase().as_str() {
                "permissive" => tarsier_conformance::checker::ConformanceMode::Permissive,
                "strict" => tarsier_conformance::checker::ConformanceMode::Strict,
                other => {
                    report.actual_verdict = "error".into();
                    report.status = "error".into();
                    report.triage = Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION.into());
                    report.error = Some(format!(
                        "Unknown checker_mode '{other}'. Use permissive|strict."
                    ));
                    break 'entry;
                }
            };

            // Run conformance checker
            let checker = tarsier_conformance::checker::ConformanceChecker::new_with_mode(
                &ta,
                &runtime_trace.params,
                checker_mode,
            );
            let result = checker.check(&runtime_trace);

            let actual_verdict = if result.passed { "pass" } else { "fail" };
            report.actual_verdict = actual_verdict.into();
            report.violations = result
                .violations
                .iter()
                .map(|v| {
                    format!(
                        "process {}, event {}: {:?} — {}",
                        v.process_id, v.event_sequence, v.kind, v.message
                    )
                })
                .collect();

            // Compare with expected
            if actual_verdict == entry.expected_verdict && !report.model_changed {
                report.status = "match".into();
            } else {
                report.status = "mismatch".into();
                report.triage = Some(
                    classify_conformance_mismatch_triage(
                        report.model_changed,
                        entry.mismatch_hint.as_deref(),
                    )
                    .into(),
                );
            }
        }

        report.duration_ms = start.elapsed().as_millis() as u64;

        // Write per-entry artifact file (populates artifact_link)
        if let Some(dir) = artifact_dir {
            let entry_dir = dir.join(sanitize_artifact_component(&entry.name));
            let artifact_path = entry_dir.join("result.json");
            // Build a per-entry detail object
            let detail = json!({
                "name": report.name,
                "protocol_file": report.protocol_file,
                "trace_file": report.trace_file,
                "trace_adapter": report.trace_adapter,
                "checker_mode": report.checker_mode,
                "expected_verdict": report.expected_verdict,
                "actual_verdict": report.actual_verdict,
                "status": report.status,
                "duration_ms": report.duration_ms,
                "model_sha256_expected": report.model_sha256_expected,
                "model_sha256_actual": report.model_sha256_actual,
                "model_changed": report.model_changed,
                "violations": report.violations,
                "error": report.error,
                "triage": report.triage,
            });
            if let Some(parent) = artifact_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(json_str) = serde_json::to_string_pretty(&detail) {
                if fs::write(&artifact_path, &json_str).is_ok() {
                    report.artifact_link = Some(artifact_path.display().to_string());
                }
            }
        }

        entry_reports.push(report);
    }

    // Tally
    let passed = entry_reports.iter().filter(|r| r.status == "match").count();
    let failed = entry_reports
        .iter()
        .filter(|r| r.status == "mismatch")
        .count();
    let errors = entry_reports.iter().filter(|r| r.status == "error").count();

    let mut triage_counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in &entry_reports {
        if let Some(t) = &r.triage {
            *triage_counts.entry(t.clone()).or_insert(0) += 1;
        }
    }

    // Validate triage labels
    for label in triage_counts.keys() {
        if !CONFORMANCE_TRIAGE_CATEGORIES.contains(&label.as_str()) {
            miette::bail!(
                "Internal error: unknown conformance triage category '{}'",
                label
            );
        }
    }

    let overall = if failed == 0 && errors == 0 {
        "pass"
    } else {
        "fail"
    };

    Ok(ConformanceSuiteReport {
        schema_version: CONFORMANCE_MANIFEST_SCHEMA_VERSION,
        suite_name: manifest.suite_name.clone(),
        manifest_path: manifest_path.display().to_string(),
        entries: entry_reports,
        assumptions: ConformanceSuiteAssumptions {
            runner_version: env!("CARGO_PKG_VERSION").into(),
            schema_version: CONFORMANCE_MANIFEST_SCHEMA_VERSION,
        },
        passed,
        failed,
        errors,
        triage: triage_counts,
        overall: overall.into(),
    })
}

// ---------------------------------------------------------------------------
// Text renderer for suite reports
// ---------------------------------------------------------------------------

pub(crate) fn render_conformance_suite_text(report: &ConformanceSuiteReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Conformance Suite: {}\n", report.suite_name));
    out.push_str(&format!("Manifest: {}\n\n", report.manifest_path));
    for entry in &report.entries {
        let icon = match entry.status.as_str() {
            "match" => "PASS",
            "mismatch" => "FAIL",
            "error" => "ERR ",
            _ => "????",
        };
        out.push_str(&format!(
            "[{}] {} (adapter={}, mode={}, expected={}, actual={}, {}ms)",
            icon,
            entry.name,
            entry.trace_adapter,
            entry.checker_mode,
            entry.expected_verdict,
            entry.actual_verdict,
            entry.duration_ms
        ));
        if let Some(triage) = &entry.triage {
            out.push_str(&format!(" [triage: {}]", triage));
        }
        out.push('\n');
        if let Some(expected_hash) = &entry.model_sha256_expected {
            out.push_str(&format!(
                "      model_sha256: expected={} actual={} changed={}\n",
                expected_hash,
                entry.model_sha256_actual.as_deref().unwrap_or("n/a"),
                entry.model_changed
            ));
        }
        if let Some(err) = &entry.error {
            out.push_str(&format!("      error: {}\n", err));
        }
        for v in &entry.violations {
            out.push_str(&format!("      violation: {}\n", v));
        }
    }
    out.push_str(&format!(
        "\nSummary: {} passed, {} failed, {} errors — {}\n",
        report.passed,
        report.failed,
        report.errors,
        report.overall.to_uppercase()
    ));
    if !report.triage.is_empty() {
        out.push_str("Triage: ");
        let items: Vec<String> = report
            .triage
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        out.push_str(&items.join(", "));
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Command handler: conformance-check
// ---------------------------------------------------------------------------

pub(crate) fn run_conformance_check_command(
    file: &PathBuf,
    trace: &PathBuf,
    adapter: &str,
    checker_mode: &str,
    format: &str,
) -> miette::Result<()> {
    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();
    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    let trace_source = fs::read_to_string(trace).into_diagnostic()?;
    let runtime_trace = tarsier_conformance::adapters::adapt_trace(
        parse_conformance_adapter(adapter),
        &trace_source,
    )
    .map_err(|e| miette::miette!("Trace adapter error: {e}"))?;

    let checker = tarsier_conformance::checker::ConformanceChecker::new_with_mode(
        &ta,
        &runtime_trace.params,
        parse_conformance_mode(checker_mode),
    );
    let result = checker.check(&runtime_trace);

    if format == "json" {
        let json = serde_json::to_string_pretty(&result).into_diagnostic()?;
        println!("{json}");
    } else if result.passed {
        println!("PASSED");
    } else {
        println!("FAILED: {} violation(s)", result.violations.len());
        for v in &result.violations {
            println!(
                "  process {}, event {}: {:?} — {}",
                v.process_id, v.event_sequence, v.kind, v.message
            );
        }
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Command handler: conformance-replay
// ---------------------------------------------------------------------------

pub(crate) fn run_conformance_replay_command(
    file: &PathBuf,
    check: &str,
    solver: &str,
    depth: usize,
    timeout: u64,
    soundness: &str,
    export_trace: Option<&PathBuf>,
) -> miette::Result<()> {
    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(soundness);
    let options = PipelineOptions {
        solver: parse_solver_choice(solver),
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::KInduction,
    };

    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    // Run verification to get a counter-level trace
    let counter_trace = match check {
        "verify" => match tarsier_engine::pipeline::verify(&source, &filename, &options) {
            Ok(VerificationResult::Unsafe { trace, .. }) => trace,
            Ok(VerificationResult::Safe { .. }) => {
                println!("Protocol is SAFE — no counterexample to replay.");
                return Ok(());
            }
            Ok(other) => {
                println!("Verification result: {other:?} — no trace available.");
                return Ok(());
            }
            Err(e) => {
                return Err(miette::miette!("Verification error: {e}"));
            }
        },
        "liveness" => {
            match tarsier_engine::pipeline::check_liveness(&source, &filename, &options) {
                Ok(LivenessResult::NotLive { trace, .. }) => trace,
                Ok(LivenessResult::Live { .. }) => {
                    println!("Protocol is LIVE — no counterexample to replay.");
                    return Ok(());
                }
                Ok(other) => {
                    println!("Liveness result: {other:?} — no trace available.");
                    return Ok(());
                }
                Err(e) => {
                    return Err(miette::miette!("Liveness error: {e}"));
                }
            }
        }
        "fair-liveness" => {
            match tarsier_engine::pipeline::check_fair_liveness(&source, &filename, &options) {
                Ok(FairLivenessResult::FairCycleFound { trace, .. }) => trace,
                Ok(FairLivenessResult::NoFairCycleUpTo { .. }) => {
                    println!("No fair-liveness violation found — no trace to replay.");
                    return Ok(());
                }
                Ok(other) => {
                    println!("Fair-liveness result: {other:?} — no trace available.");
                    return Ok(());
                }
                Err(e) => {
                    return Err(miette::miette!("Fair-liveness error: {e}"));
                }
            }
        }
        other => {
            return Err(miette::miette!(
                "Unknown check mode '{other}'. Use: verify | liveness | fair-liveness"
            ));
        }
    };

    // Concretize to process-level trace
    let runtime_trace = tarsier_conformance::replay::concretize_trace(&counter_trace, &ta)
        .map_err(|e| miette::miette!("Concretization error: {e}"))?;

    // Self-validate
    let checker = tarsier_conformance::checker::ConformanceChecker::new(&ta, &runtime_trace.params);
    let result = checker.check(&runtime_trace);

    if result.passed {
        println!("Replay: PASSED (concretized trace conforms to model)");
    } else {
        println!(
            "Replay: FAILED — {} violation(s) in concretized trace",
            result.violations.len()
        );
        for v in &result.violations {
            println!(
                "  process {}, event {}: {:?} — {}",
                v.process_id, v.event_sequence, v.kind, v.message
            );
        }
        std::process::exit(1);
    }

    if let Some(export_path) = export_trace {
        let json = serde_json::to_string_pretty(&runtime_trace).into_diagnostic()?;
        fs::write(export_path, json).into_diagnostic()?;
        println!("Exported runtime trace to {}", export_path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Command handler: conformance-obligations
// ---------------------------------------------------------------------------

pub(crate) fn run_conformance_obligations_command(
    file: &PathBuf,
    out: Option<&PathBuf>,
) -> miette::Result<()> {
    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();
    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    let protocol_name = program.protocol.node.name.clone();

    // Build properties from the AST property declarations
    let mut properties: Vec<(String, tarsier_ir::properties::SafetyProperty)> = Vec::new();
    for prop_decl in &program.protocol.node.properties {
        let prop = match prop_decl.node.kind {
            tarsier_dsl::ast::PropertyKind::Agreement => {
                tarsier_ir::properties::extract_agreement_property(&ta)
            }
            _ => continue,
        };
        properties.push((prop_decl.node.name.clone(), prop));
    }

    // If no explicit properties, extract agreement as default
    if properties.is_empty() {
        let prop = tarsier_ir::properties::extract_agreement_property(&ta);
        properties.push(("agreement".to_string(), prop));
    }

    let obligation_map =
        tarsier_conformance::obligations::generate_obligation_map(&ta, &protocol_name, &properties);
    let json = serde_json::to_string_pretty(&obligation_map).into_diagnostic()?;

    if let Some(out_path) = out {
        fs::write(out_path, &json).into_diagnostic()?;
        println!("Obligation map written to {}", out_path.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Command handler: conformance-suite
// ---------------------------------------------------------------------------

pub(crate) fn run_conformance_suite_command(
    manifest: &PathBuf,
    format: &str,
    out: Option<&PathBuf>,
    artifact_dir: Option<&Path>,
) -> miette::Result<()> {
    let output_format = parse_output_format(format);

    let report = run_conformance_suite(manifest, artifact_dir)?;
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        write_json_artifact(&path.to_path_buf(), &report_json_value)?;
        println!("Conformance suite report written to {}", path.display());
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_conformance_suite_text(&report)),
        OutputFormat::Json => println!("{report_json}"),
    }

    if report.overall != "pass" {
        std::process::exit(2);
    }

    Ok(())
}
