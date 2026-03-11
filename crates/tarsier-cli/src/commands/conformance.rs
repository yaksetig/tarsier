//! Conformance command handlers and report/rendering helpers.
//
// Command handlers for: ConformanceCheck, ConformanceReplay, ConformanceObligations, ConformanceSuite
//
// These commands handle runtime trace conformance checking, replay-based
// self-validation, obligation map generation, and deterministic suite execution.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use miette::IntoDiagnostic;
use serde::Serialize;
use serde_json::{json, Value};

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine};
use tarsier_engine::result::{FairLivenessResult, LivenessResult, VerificationResult};
use tarsier_proof_kernel::sha256_hex_bytes;

use super::helpers::{
    parse_conformance_adapter, parse_conformance_mode, parse_output_format, parse_solver_choice,
    parse_soundness_mode, report_with_exit_code,
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
        parse_conformance_adapter(adapter)?,
        &trace_source,
    )
    .map_err(|e| miette::miette!("Trace adapter error: {e}"))?;

    let checker = tarsier_conformance::checker::ConformanceChecker::new_with_mode(
        &ta,
        &runtime_trace.params,
        parse_conformance_mode(checker_mode)?,
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
        return Err(miette::miette!(
            "Conformance check failed with {} violation(s).",
            result.violations.len()
        ));
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
    let soundness_mode = parse_soundness_mode(soundness)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(solver)?,
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
        return Err(miette::miette!(
            "Conformance replay failed with {} violation(s).",
            result.violations.len()
        ));
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
    let output_format = parse_output_format(format)?;

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
        return Err(report_with_exit_code(
            2,
            format!("Conformance suite reported overall='{}'.", report.overall),
        ));
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct ConformanceActiveReport {
    schema_version: u32,
    adapter: String,
    seed: u64,
    faults: Vec<tarsier_conformance::adapters::ScheduledAdapterFault>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live: Option<ConformanceActiveLiveReport>,
}

#[derive(Debug, Serialize)]
struct ConformanceActiveLiveReport {
    endpoint: String,
    contract: String,
    events_sent: u64,
    final_tick: u64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum LiveAdapterEnvelope {
    Start {
        adapter: String,
        seed: u64,
    },
    Tick {
        tick: u64,
    },
    Fault {
        tick: u64,
        action: tarsier_conformance::adapters::AdapterFaultAction,
    },
    Stop {
        final_tick: u64,
    },
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn deterministic_fault_order_key(seed: u64, tick: u64, original_index: usize) -> u64 {
    splitmix64(seed ^ tick.rotate_left(17) ^ original_index as u64)
}

fn schedule_faults_deterministically(
    mut faults: Vec<tarsier_conformance::adapters::ScheduledAdapterFault>,
    seed: u64,
) -> Vec<tarsier_conformance::adapters::ScheduledAdapterFault> {
    let mut indexed = faults
        .drain(..)
        .enumerate()
        .collect::<Vec<(usize, tarsier_conformance::adapters::ScheduledAdapterFault)>>();
    indexed.sort_by_key(|(idx, fault)| {
        (
            fault.tick,
            deterministic_fault_order_key(seed, fault.tick, *idx),
            *idx,
        )
    });
    indexed.into_iter().map(|(_, fault)| fault).collect()
}

pub(crate) fn run_conformance_active_command(
    trace: &PathBuf,
    adapter: &str,
    seed: u64,
    format: &str,
    out: Option<&PathBuf>,
    live_endpoint: Option<&str>,
    live_timeout_ms: u64,
) -> miette::Result<()> {
    let output_format = parse_output_format(format)?;
    let adapter_kind = parse_conformance_adapter(adapter)?;
    let trace_source = fs::read_to_string(trace).into_diagnostic()?;
    let mapped = tarsier_conformance::adapters::adapt_active_faults(adapter_kind, &trace_source)
        .map_err(|e| miette::miette!("Active trace adapter error: {e}"))?;
    let scheduled = schedule_faults_deterministically(mapped, seed);
    let live = if let Some(endpoint) = live_endpoint {
        Some(run_conformance_active_live_mode(
            endpoint,
            adapter_kind.as_str(),
            seed,
            &scheduled,
            live_timeout_ms,
        )?)
    } else {
        None
    };

    let report = ConformanceActiveReport {
        schema_version: 1,
        adapter: adapter_kind.as_str().to_string(),
        seed,
        faults: scheduled,
        live,
    };
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        write_json_artifact(path, &report_json_value)?;
        println!("Conformance active schedule written to {}", path.display());
    }

    match output_format {
        OutputFormat::Json => println!("{report_json}"),
        OutputFormat::Text => {
            println!(
                "Conformance Active: adapter={}, seed={}, faults={}",
                report.adapter,
                report.seed,
                report.faults.len()
            );
            for (idx, scheduled) in report.faults.iter().enumerate() {
                let action = serde_json::to_string(&scheduled.action).into_diagnostic()?;
                println!(
                    "  [{idx}] tick={} action={}",
                    scheduled.tick,
                    action.replace('\n', "")
                );
            }
            if let Some(live) = &report.live {
                println!(
                    "  live endpoint={} contract={} events_sent={} final_tick={}",
                    live.endpoint, live.contract, live.events_sent, live.final_tick
                );
            }
        }
    }

    Ok(())
}

fn post_live_adapter_event(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    payload: &LiveAdapterEnvelope,
) -> miette::Result<()> {
    let response = client
        .post(endpoint)
        .header("connection", "close")
        .json(payload)
        .send()
        .into_diagnostic()?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        miette::bail!(
            "live endpoint '{}' rejected event with status {}: {}",
            endpoint,
            status.as_u16(),
            body.trim()
        );
    }
    Ok(())
}

fn run_conformance_active_live_mode(
    endpoint: &str,
    adapter: &str,
    seed: u64,
    scheduled: &[tarsier_conformance::adapters::ScheduledAdapterFault],
    timeout_ms: u64,
) -> miette::Result<ConformanceActiveLiveReport> {
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .into_diagnostic()?;

    let mut events_sent = 0u64;
    post_live_adapter_event(
        &client,
        endpoint,
        &LiveAdapterEnvelope::Start {
            adapter: adapter.to_string(),
            seed,
        },
    )?;
    events_sent += 1;

    let mut current_tick: Option<u64> = None;
    let mut final_tick = 0u64;
    for fault in scheduled {
        if current_tick != Some(fault.tick) {
            post_live_adapter_event(
                &client,
                endpoint,
                &LiveAdapterEnvelope::Tick { tick: fault.tick },
            )?;
            events_sent += 1;
            current_tick = Some(fault.tick);
        }

        post_live_adapter_event(
            &client,
            endpoint,
            &LiveAdapterEnvelope::Fault {
                tick: fault.tick,
                action: fault.action.clone(),
            },
        )?;
        events_sent += 1;
        final_tick = fault.tick;
    }

    post_live_adapter_event(&client, endpoint, &LiveAdapterEnvelope::Stop { final_tick })?;
    events_sent += 1;

    Ok(ConformanceActiveLiveReport {
        endpoint: endpoint.to_string(),
        contract: "tarsier.active.v1".to_string(),
        events_sent,
        final_tick,
    })
}

#[cfg(test)]
mod active_tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tarsier_conformance::adapters::{AdapterFaultAction, ScheduledAdapterFault};

    fn active_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/conformance/active")
            .join(name)
    }

    fn tmp_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be available")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{}_{}.json", std::process::id(), nanos))
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn read_http_json_body(stream: &mut TcpStream) -> serde_json::Value {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .expect("request read should succeed");
            if read == 0 {
                break 0;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(pos) = find_header_end(&buf) {
                break pos + 4;
            }
        };

        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let content_len = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(0);

        while buf.len() < header_end + content_len {
            let read = stream
                .read(&mut chunk)
                .expect("request body read should succeed");
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
        }

        let body = &buf[header_end..header_end + content_len];
        serde_json::from_slice(body).expect("request body should be valid JSON")
    }

    fn spawn_mock_live_endpoint(
        expected_requests: usize,
        ok_status: bool,
    ) -> (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("local addr should be available");
        let url = format!("http://{addr}/active");
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);

        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("request should connect");
                let body = read_http_json_body(&mut stream);
                received_clone.lock().expect("mutex should lock").push(body);

                let (status, body) = if ok_status {
                    ("200 OK", "{\"status\":\"ok\"}")
                } else {
                    ("500 Internal Server Error", "{\"status\":\"error\"}")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should be writable");
            }
        });

        (url, received, handle)
    }

    #[test]
    fn conformance_active_schedule_is_deterministic_for_seed() {
        let faults = vec![
            ScheduledAdapterFault {
                tick: 2,
                action: AdapterFaultAction::HealPartition,
            },
            ScheduledAdapterFault {
                tick: 2,
                action: AdapterFaultAction::ReorderChannel {
                    channel: "vote".into(),
                },
            },
            ScheduledAdapterFault {
                tick: 1,
                action: AdapterFaultAction::DropMessage {
                    channel: "vote".into(),
                    from_process: Some(1),
                    to_process: Some(2),
                },
            },
        ];

        let a = schedule_faults_deterministically(faults.clone(), 7);
        let b = schedule_faults_deterministically(faults, 7);
        assert_eq!(a, b);
        assert_eq!(a[0].tick, 1);
    }

    #[test]
    fn conformance_active_schedule_seed_changes_same_tick_order() {
        let faults = vec![
            ScheduledAdapterFault {
                tick: 5,
                action: AdapterFaultAction::HealPartition,
            },
            ScheduledAdapterFault {
                tick: 5,
                action: AdapterFaultAction::RetireTwin { twin_id: 42 },
            },
            ScheduledAdapterFault {
                tick: 5,
                action: AdapterFaultAction::SpawnTwin {
                    process_id: 1,
                    twin_id: 101,
                },
            },
        ];

        let a = schedule_faults_deterministically(faults.clone(), 1);
        let b = schedule_faults_deterministically(faults, 2);
        assert_ne!(
            a.iter().map(|f| &f.action).collect::<Vec<_>>(),
            b.iter().map(|f| &f.action).collect::<Vec<_>>()
        );
    }

    struct ActiveCorpusCase {
        adapter: &'static str,
        fixture: &'static str,
        seed: u64,
        expected_faults: usize,
    }

    fn active_corpus_cases() -> Vec<ActiveCorpusCase> {
        vec![
            ActiveCorpusCase {
                adapter: "cometbft",
                fixture: "cometbft_faults_basic.json",
                seed: 11,
                expected_faults: 6,
            },
            ActiveCorpusCase {
                adapter: "runtime",
                fixture: "runtime_faults_basic.json",
                seed: 5,
                expected_faults: 3,
            },
            ActiveCorpusCase {
                adapter: "etcd-raft",
                fixture: "etcd_raft_faults_basic.json",
                seed: 17,
                expected_faults: 6,
            },
        ]
    }

    fn active_same_tick_cases() -> Vec<(&'static str, &'static str)> {
        vec![
            ("cometbft", "cometbft_faults_same_tick.json"),
            ("runtime", "runtime_faults_same_tick.json"),
            ("etcd-raft", "etcd_raft_faults_same_tick.json"),
        ]
    }

    fn action_kinds(value: &serde_json::Value) -> Vec<String> {
        value["faults"]
            .as_array()
            .expect("faults array")
            .iter()
            .map(|f| {
                f["action"]["kind"]
                    .as_str()
                    .expect("kind string")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn classify_conformance_mismatch_triage_prefers_model_change_when_flagged() {
        let triage =
            classify_conformance_mismatch_triage(true, Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION));
        assert_eq!(triage, CONFORMANCE_TRIAGE_MODEL_CHANGE);
    }

    #[test]
    fn classify_conformance_mismatch_triage_uses_trimmed_hint_or_defaults() {
        assert_eq!(
            classify_conformance_mismatch_triage(false, Some("  impl_divergence  ")),
            CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
        );
        assert_eq!(
            classify_conformance_mismatch_triage(false, Some("engine_regression")),
            CONFORMANCE_TRIAGE_ENGINE_REGRESSION
        );
        assert_eq!(
            classify_conformance_mismatch_triage(false, Some("unknown_hint")),
            CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
        );
    }

    #[test]
    fn classify_conformance_load_error_triage_maps_known_stages() {
        assert_eq!(
            classify_conformance_load_error_triage("model_read"),
            CONFORMANCE_TRIAGE_MODEL_CHANGE
        );
        assert_eq!(
            classify_conformance_load_error_triage("trace_adapt"),
            CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
        );
        assert_eq!(
            classify_conformance_load_error_triage("other"),
            CONFORMANCE_TRIAGE_ENGINE_REGRESSION
        );
    }

    #[test]
    fn sanitize_artifact_component_normalizes_and_falls_back_to_entry() {
        assert_eq!(
            sanitize_artifact_component(" PBFT/Trace.File v1 "),
            "pbft_trace_file_v1"
        );
        assert_eq!(
            sanitize_artifact_component("Alpha-BETA_01"),
            "alpha-beta_01"
        );
        assert_eq!(sanitize_artifact_component("..."), "entry");
    }

    #[test]
    fn write_json_artifact_creates_parent_directories_and_writes_json() {
        let out = tmp_path("tarsier_conformance_artifact_write");
        let nested = out.with_extension("").join("nested").join("report.json");
        let payload = serde_json::json!({
            "schema_version": 1,
            "overall": "pass",
            "entries": []
        });
        write_json_artifact(&nested, &payload).expect("json artifact write should succeed");
        let raw = fs::read_to_string(&nested).expect("artifact should be readable");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("artifact should parse");
        assert_eq!(parsed["overall"], "pass");
        fs::remove_dir_all(
            nested
                .parent()
                .expect("parent should exist")
                .parent()
                .expect("grandparent should exist"),
        )
        .ok();
    }

    #[test]
    fn conformance_active_command_corpus_matrix_writes_expected_json_shape() {
        for case in active_corpus_cases() {
            let trace = active_fixture_path(case.fixture);
            let out = tmp_path(&format!("tarsier_conformance_active_{}", case.adapter));
            run_conformance_active_command(
                &trace,
                case.adapter,
                case.seed,
                "json",
                Some(&out),
                None,
                5000,
            )
            .expect("conformance-active should succeed on corpus fixture");

            let raw = fs::read_to_string(&out).expect("output JSON should be readable");
            let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["adapter"], case.adapter);
            assert_eq!(value["seed"], case.seed);
            assert_eq!(
                value["faults"]
                    .as_array()
                    .expect("faults should be array")
                    .len(),
                case.expected_faults
            );
            fs::remove_file(out).ok();
        }
    }

    #[test]
    fn conformance_active_command_same_seed_is_deterministic_for_corpus_matrix() {
        for case in active_corpus_cases() {
            let trace = active_fixture_path(case.fixture);
            let out_a = tmp_path(&format!(
                "tarsier_conformance_active_det_a_{}",
                case.adapter
            ));
            let out_b = tmp_path(&format!(
                "tarsier_conformance_active_det_b_{}",
                case.adapter
            ));

            run_conformance_active_command(
                &trace,
                case.adapter,
                case.seed,
                "json",
                Some(&out_a),
                None,
                5000,
            )
            .expect("first deterministic replay should pass");
            run_conformance_active_command(
                &trace,
                case.adapter,
                case.seed,
                "json",
                Some(&out_b),
                None,
                5000,
            )
            .expect("second deterministic replay should pass");

            let a: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&out_a).expect("seed a output"))
                    .expect("seed a json");
            let b: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&out_b).expect("seed b output"))
                    .expect("seed b json");
            assert_eq!(a["faults"], b["faults"]);

            fs::remove_file(out_a).ok();
            fs::remove_file(out_b).ok();
        }
    }

    #[test]
    fn conformance_active_command_seed_changes_same_tick_order_for_corpus_matrix() {
        for (adapter, fixture) in active_same_tick_cases() {
            let trace = active_fixture_path(fixture);
            let out_a = tmp_path(&format!("tarsier_conformance_active_seed_a_{adapter}"));
            let out_b = tmp_path(&format!("tarsier_conformance_active_seed_b_{adapter}"));

            run_conformance_active_command(&trace, adapter, 1, "json", Some(&out_a), None, 5000)
                .expect("seed 1 run should pass");
            run_conformance_active_command(&trace, adapter, 2, "json", Some(&out_b), None, 5000)
                .expect("seed 2 run should pass");

            let a: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&out_a).expect("seed a output"))
                    .expect("seed a json");
            let b: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&out_b).expect("seed b output"))
                    .expect("seed b json");

            assert_ne!(action_kinds(&a), action_kinds(&b));

            fs::remove_file(out_a).ok();
            fs::remove_file(out_b).ok();
        }
    }

    #[test]
    fn conformance_active_live_mode_posts_contract_events() {
        let trace = active_fixture_path("cometbft_faults_basic.json");
        let out = tmp_path("tarsier_conformance_active_live");
        // 1 start + 6 tick + 6 fault + 1 stop
        let (endpoint, received, handle) = spawn_mock_live_endpoint(14, true);

        run_conformance_active_command(
            &trace,
            "cometbft",
            11,
            "json",
            Some(&out),
            Some(&endpoint),
            5000,
        )
        .expect("live conformance-active should succeed on mock endpoint");

        handle.join().expect("mock endpoint should join");

        let requests = received.lock().expect("mutex should lock");
        assert_eq!(requests.len(), 14);
        assert_eq!(requests[0]["op"], "start");
        assert_eq!(requests[0]["adapter"], "cometbft");
        assert_eq!(requests[13]["op"], "stop");
        assert_eq!(requests[13]["final_tick"], 6);

        let raw = fs::read_to_string(&out).expect("output JSON should be readable");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(value["live"]["endpoint"], endpoint);
        assert_eq!(value["live"]["contract"], "tarsier.active.v1");
        assert_eq!(value["live"]["events_sent"], 14);
        assert_eq!(value["live"]["final_tick"], 6);
        fs::remove_file(out).ok();
    }

    #[test]
    fn conformance_active_live_mode_reports_endpoint_errors() {
        let trace = active_fixture_path("cometbft_faults_basic.json");
        let (endpoint, _received, handle) = spawn_mock_live_endpoint(1, false);
        let err = run_conformance_active_command(
            &trace,
            "cometbft",
            11,
            "json",
            None,
            Some(&endpoint),
            5000,
        )
        .expect_err("live endpoint 500 should fail");
        handle.join().expect("mock endpoint should join");
        assert!(format!("{err}").contains("rejected event"));
    }
}
