//! Governance certificate-suite execution and output rendering.
//
// Cert suite runner: execution, rendering, output.

use miette::IntoDiagnostic;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tarsier_engine::pipeline::{PipelineOptions, SoundnessMode};
use tarsier_proof_kernel::sha256_hex_bytes;

use crate::CliNetworkSemanticsMode;

use super::{
    classify_cert_suite_check_triage, classify_cert_suite_entry_triage, expected_matches,
    validate_cert_suite_report_triage_contract, validate_manifest_corpus_breadth,
    validate_manifest_entry_contract, validate_manifest_known_bug_sentinel_coverage,
    validate_manifest_library_coverage, validate_manifest_model_hash_consistency,
    validate_manifest_top_level_contract, CertSuiteAssumptions, CertSuiteBucketSummary,
    CertSuiteCheckReport, CertSuiteDefaults, CertSuiteEntryReport, CertSuiteManifest,
    CertSuiteReport, CERT_SUITE_SCHEMA_VERSION,
};

pub(crate) fn write_artifact_text(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

pub(crate) fn finalize_cert_suite_entry(
    entry_report: &mut CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    let refresh_status = |report: &mut CertSuiteEntryReport| {
        if !report.errors.is_empty() {
            report.status = "error".into();
        } else if report.checks.iter().any(|c| c.status == "fail") {
            report.status = "fail".into();
        } else {
            report.status = "pass".into();
        }
        report.verdict = report.status.clone();
        report.triage = classify_cert_suite_entry_triage(report);
    };

    entry_report.duration_ms = entry_started.elapsed().as_millis() as u64;
    refresh_status(entry_report);

    if let Some(dir) = entry_artifact_dir {
        let entry_json = match serde_json::to_string_pretty(entry_report) {
            Ok(json) => json,
            Err(e) => {
                entry_report
                    .errors
                    .push(format!("entry artifact serialization failed: {e}"));
                return;
            }
        };
        let summary_path = dir.join("entry.json");
        match write_artifact_text(&summary_path, &entry_json) {
            Ok(()) => entry_report
                .artifact_links
                .push(summary_path.display().to_string()),
            Err(msg) => entry_report
                .errors
                .push(format!("entry artifact write failed: {msg}")),
        }
    }

    refresh_status(entry_report);
}

pub(crate) fn finalize_and_push_cert_suite_entry(
    reports: &mut Vec<CertSuiteEntryReport>,
    passed: &mut usize,
    failed: &mut usize,
    errors: &mut usize,
    mut entry_report: CertSuiteEntryReport,
    entry_started: Instant,
    entry_artifact_dir: Option<&Path>,
) {
    finalize_cert_suite_entry(&mut entry_report, entry_started, entry_artifact_dir);
    match entry_report.status.as_str() {
        "pass" => *passed += 1,
        "fail" => *failed += 1,
        _ => *errors += 1,
    }
    reports.push(entry_report);
}

pub(crate) fn write_check_artifact(
    entry_artifact_dir: Option<&Path>,
    check_name: &str,
    output: &str,
) -> Result<Option<String>, String> {
    let Some(dir) = entry_artifact_dir else {
        return Ok(None);
    };
    let filename = format!(
        "check_{}.txt",
        crate::sanitize_artifact_component(check_name)
    );
    let artifact_path = dir.join(filename);
    write_artifact_text(&artifact_path, output)?;
    Ok(Some(artifact_path.display().to_string()))
}

pub(crate) fn render_suite_text(report: &CertSuiteReport) -> String {
    let mut out = String::new();
    out.push_str("CERTIFICATION SUITE\n");
    out.push_str(&format!("Manifest: {}\n", report.manifest));
    out.push_str(&format!(
        "Config: solver={}, proof_engine={}, soundness={}, fairness={}\n",
        report.solver, report.proof_engine, report.soundness, report.fairness
    ));
    out.push_str(&format!("Overall: {}\n", report.overall));
    out.push_str(&format!(
        "Summary: {} pass, {} fail, {} error\n",
        report.passed, report.failed, report.errors
    ));
    if !report.triage.is_empty() {
        out.push_str("Failure triage:\n");
        for (kind, count) in &report.triage {
            out.push_str(&format!("  - {}: {}\n", kind, count));
        }
    }
    if !report.by_class.is_empty() {
        out.push_str("By class:\n");
        for (class, bucket) in &report.by_class {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                class, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    if !report.by_family.is_empty() {
        out.push_str("By family:\n");
        for (family, bucket) in &report.by_family {
            out.push_str(&format!(
                "  - {}: total={}, pass={}, fail={}, error={}\n",
                family, bucket.total, bucket.passed, bucket.failed, bucket.errors
            ));
        }
    }
    out.push_str("Entries:\n");
    for entry in &report.entries {
        let mut tags: Vec<String> = Vec::new();
        if let Some(family) = &entry.family {
            tags.push(format!("family={family}"));
        }
        if let Some(class) = &entry.class {
            tags.push(format!("class={class}"));
        }
        if let Some(variant) = &entry.variant {
            tags.push(format!("variant={variant}"));
        }
        if let Some(group) = &entry.variant_group {
            tags.push(format!("group={group}"));
        }
        let tag_suffix = if tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", tags.join(", "))
        };
        out.push_str(&format!(
            "- [{}] {}{} verdict={} time={}ms\n",
            entry.status.to_uppercase(),
            entry.file,
            tag_suffix,
            entry.verdict,
            entry.duration_ms
        ));
        if let Some(triage) = &entry.triage {
            out.push_str(&format!("    triage: {triage}\n"));
        }
        out.push_str(&format!(
            "    assumptions: solver={} proof_engine={} soundness={} fairness={} network={} depth={} k={} timeout={}s cegar={}\n",
            entry.assumptions.solver,
            entry.assumptions.proof_engine,
            entry.assumptions.soundness,
            entry.assumptions.fairness,
            entry.assumptions.network_semantics,
            entry.assumptions.depth,
            entry.assumptions.k,
            entry.assumptions.timeout_secs,
            entry.assumptions.cegar_iters
        ));
        if let Some(expected_hash) = &entry.model_sha256_expected {
            out.push_str(&format!(
                "    model_sha256: expected={} actual={} changed={}\n",
                expected_hash,
                entry.model_sha256_actual.as_deref().unwrap_or("n/a"),
                entry.model_changed
            ));
        }
        for link in &entry.artifact_links {
            out.push_str(&format!("    artifact: {link}\n"));
        }
        for check in &entry.checks {
            out.push_str(&format!(
                "    {}: expected {}, got {} [{}] ({}ms)\n",
                check.check,
                check.expected,
                check.actual,
                check.status.to_uppercase(),
                check.duration_ms
            ));
            if let Some(triage) = &check.triage {
                out.push_str(&format!("      triage: {triage}\n"));
            }
            if let Some(link) = &check.artifact_link {
                out.push_str(&format!("      artifact: {link}\n"));
            }
        }
        for error in &entry.errors {
            out.push_str(&format!("    error: {error}\n"));
        }
    }
    out
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_cert_suite(
    manifest_path: &PathBuf,
    defaults: &CertSuiteDefaults,
    network_mode: CliNetworkSemanticsMode,
    artifacts_dir: Option<&Path>,
) -> miette::Result<CertSuiteReport> {
    let manifest_raw = fs::read_to_string(manifest_path).into_diagnostic()?;
    let manifest: CertSuiteManifest = serde_json::from_str(&manifest_raw).into_diagnostic()?;
    let mut manifest_errors = validate_manifest_top_level_contract(&manifest);
    manifest_errors.extend(validate_manifest_library_coverage(&manifest, manifest_path));
    manifest_errors.extend(validate_manifest_corpus_breadth(&manifest, manifest_path));
    manifest_errors.extend(validate_manifest_known_bug_sentinel_coverage(&manifest));
    manifest_errors.extend(validate_manifest_model_hash_consistency(
        &manifest,
        manifest_path,
    ));
    if !manifest_errors.is_empty() {
        miette::bail!(
            "Certification manifest validation failed:\n{}",
            manifest_errors
                .into_iter()
                .map(|msg| format!("  - {msg}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let artifacts_root = artifacts_dir.map(Path::to_path_buf);
    if let Some(dir) = &artifacts_root {
        fs::create_dir_all(dir).into_diagnostic()?;
    }

    let mut reports: Vec<CertSuiteEntryReport> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;

    for (entry_idx, entry) in manifest.entries.into_iter().enumerate() {
        let entry_started = Instant::now();
        let entry_artifact_dir = artifacts_root.as_ref().map(|root| {
            root.join(format!(
                "{:03}_{}",
                entry_idx + 1,
                crate::sanitize_artifact_component(&entry.file)
            ))
        });

        let protocol_path = {
            let p = PathBuf::from(&entry.file);
            if p.is_absolute() {
                p
            } else {
                base_dir.join(p)
            }
        };
        let entry_depth = entry.depth.unwrap_or(defaults.depth);
        let entry_k = entry.k.unwrap_or(defaults.k);
        let entry_timeout = entry.timeout.unwrap_or(defaults.timeout_secs);
        let cegar_iters = entry.cegar_iters.unwrap_or(2);

        let mut entry_report = CertSuiteEntryReport {
            file: protocol_path.display().to_string(),
            family: entry.family.clone(),
            class: entry.class.clone(),
            variant: entry.variant.clone(),
            variant_group: entry.variant_group.clone(),
            verdict: "pending".into(),
            status: "pass".into(),
            triage: None,
            duration_ms: 0,
            assumptions: CertSuiteAssumptions {
                solver: crate::solver_name(defaults.solver).to_string(),
                proof_engine: crate::proof_engine_name(defaults.proof_engine).to_string(),
                soundness: crate::soundness_name(defaults.soundness).to_string(),
                fairness: crate::fairness_name(defaults.fairness).to_string(),
                network_semantics: crate::cli_network_mode_name(network_mode).to_string(),
                depth: entry_depth,
                k: entry_k,
                timeout_secs: entry_timeout,
                cegar_iters,
            },
            model_sha256_expected: entry.model_sha256.clone(),
            model_sha256_actual: None,
            model_changed: false,
            notes: entry.notes.clone(),
            artifact_links: Vec::new(),
            checks: Vec::new(),
            errors: Vec::new(),
        };
        if let Some(dir) = &entry_artifact_dir {
            if let Err(e) = fs::create_dir_all(dir) {
                entry_report.errors.push(format!(
                    "Failed creating artifact directory {}: {e}",
                    dir.display()
                ));
            }
        }

        let contract_errors = validate_manifest_entry_contract(&entry, manifest.schema_version);
        if !contract_errors.is_empty() {
            entry_report.errors.extend(contract_errors);
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                entry_report.errors.push(format!(
                    "Failed reading {}: {}",
                    protocol_path.display(),
                    e
                ));
                finalize_and_push_cert_suite_entry(
                    &mut reports,
                    &mut passed,
                    &mut failed,
                    &mut errors,
                    entry_report,
                    entry_started,
                    entry_artifact_dir.as_deref(),
                );
                continue;
            }
        };
        let model_sha_actual = sha256_hex_bytes(source.as_bytes());
        entry_report.model_sha256_actual = Some(model_sha_actual.clone());
        if let Some(expected_hash) = entry.model_sha256.as_deref() {
            entry_report.model_changed = !expected_hash.eq_ignore_ascii_case(&model_sha_actual);
        }
        let filename = protocol_path.display().to_string();
        if let Err(e) = crate::validate_cli_network_semantics_mode(
            &source,
            &filename,
            defaults.soundness,
            network_mode,
        ) {
            entry_report
                .errors
                .push(format!("network semantics validation failed: {e}"));
            finalize_and_push_cert_suite_entry(
                &mut reports,
                &mut passed,
                &mut failed,
                &mut errors,
                entry_report,
                entry_started,
                entry_artifact_dir.as_deref(),
            );
            continue;
        }

        // Structural guarantee: entries tagged variant=faithful MUST declare
        // faithful network semantics in the model and pass strict-mode lint.
        if entry.variant.as_deref() == Some("faithful") {
            match tarsier_dsl::parse(&source, &filename) {
                Ok(program) => {
                    if crate::declared_network_mode_in_program(&program) != "faithful" {
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but the model does not declare \
                             faithful network semantics (need `adversary {{ network: identity_selective; }}` \
                             or equivalent).",
                            entry.file
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                    let lint = crate::lint_protocol_file(&source, &filename, SoundnessMode::Strict);
                    let blocking: Vec<String> = lint
                        .issues
                        .iter()
                        .filter(|issue| issue.severity == "error")
                        .map(|issue| format!("{}: {}", issue.code, issue.message))
                        .collect();
                    if !blocking.is_empty() {
                        let rendered = blocking
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ");
                        entry_report.errors.push(format!(
                            "Entry '{}' has variant=faithful but fails strict-mode lint: {}",
                            entry.file, rendered
                        ));
                        finalize_and_push_cert_suite_entry(
                            &mut reports,
                            &mut passed,
                            &mut failed,
                            &mut errors,
                            entry_report,
                            entry_started,
                            entry_artifact_dir.as_deref(),
                        );
                        continue;
                    }
                }
                Err(e) => {
                    entry_report.errors.push(format!(
                        "Entry '{}' has variant=faithful but failed to parse for validation: {}",
                        entry.file, e
                    ));
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            }
        }

        let entry_proof_engine = match entry.proof_engine.as_deref() {
            Some(raw) => match crate::parse_manifest_proof_engine(raw) {
                Ok(engine) => engine,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.proof_engine,
        };
        let entry_fairness = match entry.fairness.as_deref() {
            Some(raw) => match crate::parse_manifest_fairness_mode(raw) {
                Ok(mode) => mode,
                Err(msg) => {
                    entry_report.errors.push(msg);
                    finalize_and_push_cert_suite_entry(
                        &mut reports,
                        &mut passed,
                        &mut failed,
                        &mut errors,
                        entry_report,
                        entry_started,
                        entry_artifact_dir.as_deref(),
                    );
                    continue;
                }
            },
            None => defaults.fairness,
        };
        entry_report.assumptions = CertSuiteAssumptions {
            solver: crate::solver_name(defaults.solver).to_string(),
            proof_engine: crate::proof_engine_name(entry_proof_engine).to_string(),
            soundness: crate::soundness_name(defaults.soundness).to_string(),
            fairness: crate::fairness_name(entry_fairness).to_string(),
            network_semantics: crate::cli_network_mode_name(network_mode).to_string(),
            depth: entry_depth,
            k: entry_k,
            timeout_secs: entry_timeout,
            cegar_iters,
        };

        let bounded_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_depth,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };
        let proof_options = PipelineOptions {
            solver: defaults.solver,
            max_depth: entry_k,
            timeout_secs: entry_timeout,
            dump_smt: None,
            soundness: defaults.soundness,
            proof_engine: entry_proof_engine,
        };

        if let Some(expected) = entry.verify {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::verify_with_cegar_report(
                &source,
                &filename,
                &bounded_options,
                cegar_iters,
            ) {
                Ok(result) => {
                    let actual = crate::verification_result_kind(&result.final_result).to_string();
                    let output = format!("{}", result.final_result);
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "verify",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("verify artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "verify",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "verify".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("verify failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_liveness(&source, &filename, &bounded_options) {
                Ok(result) => {
                    let actual = crate::liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.fair_liveness {
            let check_started = Instant::now();
            match tarsier_engine::pipeline::check_fair_liveness_with_mode(
                &source,
                &filename,
                &bounded_options,
                entry_fairness,
            ) {
                Ok(result) => {
                    let actual = crate::fair_liveness_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "fair_liveness",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("fair_liveness artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "fair_liveness",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "fair_liveness".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report
                        .errors
                        .push(format!("fair_liveness failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_safety_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_safety(&source, &filename, &proof_options)
            };
            match prove_result {
                Ok(result) => {
                    let actual = crate::unbounded_safety_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link =
                        match write_check_artifact(entry_artifact_dir.as_deref(), "prove", &output)
                        {
                            Ok(link) => link,
                            Err(msg) => {
                                entry_report
                                    .errors
                                    .push(format!("prove artifact write failed: {msg}"));
                                None
                            }
                        };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove failed: {e}"));
                }
            }
        }

        if let Some(expected) = entry.prove_fair {
            let check_started = Instant::now();
            let prove_result = if cegar_iters > 0 {
                tarsier_engine::pipeline::prove_fair_liveness_with_cegar(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                    cegar_iters,
                )
            } else {
                tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    &source,
                    &filename,
                    &proof_options,
                    entry_fairness,
                )
            };
            match prove_result {
                Ok(result) => {
                    let actual = crate::unbounded_fair_result_kind(&result).to_string();
                    let output = format!("{result}");
                    let artifact_link = match write_check_artifact(
                        entry_artifact_dir.as_deref(),
                        "prove_fair",
                        &output,
                    ) {
                        Ok(link) => link,
                        Err(msg) => {
                            entry_report
                                .errors
                                .push(format!("prove_fair artifact write failed: {msg}"));
                            None
                        }
                    };
                    if let Some(link) = &artifact_link {
                        entry_report.artifact_links.push(link.clone());
                    }
                    let status = if expected_matches(&expected, &actual) {
                        "pass".into()
                    } else {
                        "fail".into()
                    };
                    let triage = if status == "fail" {
                        Some(classify_cert_suite_check_triage(
                            "prove_fair",
                            &expected,
                            &actual,
                            entry.class.as_deref(),
                            entry_report.model_changed,
                        ))
                    } else {
                        None
                    };
                    entry_report.checks.push(CertSuiteCheckReport {
                        check: "prove_fair".into(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                        status,
                        duration_ms: check_started.elapsed().as_millis() as u64,
                        triage,
                        artifact_link,
                        output,
                    });
                }
                Err(e) => {
                    entry_report.errors.push(format!("prove_fair failed: {e}"));
                }
            }
        }
        finalize_and_push_cert_suite_entry(
            &mut reports,
            &mut passed,
            &mut failed,
            &mut errors,
            entry_report,
            entry_started,
            entry_artifact_dir.as_deref(),
        );
    }

    let overall = if errors > 0 || failed > 0 {
        "fail".to_string()
    } else {
        "pass".to_string()
    };

    let mut by_family: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut by_class: BTreeMap<String, CertSuiteBucketSummary> = BTreeMap::new();
    let mut triage: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &reports {
        if let Some(family) = &entry.family {
            let bucket = by_family.entry(family.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(class) = &entry.class {
            let bucket = by_class.entry(class.clone()).or_default();
            bucket.total += 1;
            match entry.status.as_str() {
                "pass" => bucket.passed += 1,
                "fail" => bucket.failed += 1,
                _ => bucket.errors += 1,
            }
        }
        if let Some(kind) = &entry.triage {
            *triage.entry(kind.clone()).or_default() += 1;
        }
    }

    let report = CertSuiteReport {
        schema_version: CERT_SUITE_SCHEMA_VERSION,
        manifest: manifest_path.display().to_string(),
        solver: crate::solver_name(defaults.solver).to_string(),
        proof_engine: crate::proof_engine_name(defaults.proof_engine).to_string(),
        soundness: crate::soundness_name(defaults.soundness).to_string(),
        fairness: crate::fairness_name(defaults.fairness).to_string(),
        entries: reports,
        passed,
        failed,
        errors,
        triage,
        by_family,
        by_class,
        overall,
    };
    if let Err(msg) = validate_cert_suite_report_triage_contract(&report) {
        miette::bail!("Certification report triage validation failed: {msg}");
    }
    Ok(report)
}
