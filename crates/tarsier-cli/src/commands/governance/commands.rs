// Command handler functions (wired from main.rs match arms).

use miette::IntoDiagnostic;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use tarsier_engine::pipeline::{FairnessMode, PipelineOptions, ProofEngine, SoundnessMode};
use tarsier_proof_kernel::{check_bundle_integrity, GovernanceProfile};

use crate::commands::helpers::*;
use crate::{
    certificate_bundle_from_fair_liveness, certificate_bundle_from_safety, parse_output_format,
    run_analysis, run_conformance_suite, run_external_solver_with_proof,
    validate_cli_network_semantics_mode, write_certificate_bundle, write_json_artifact,
    AnalysisMode, CertificateKind, CliNetworkSemanticsMode, LayerRunCfg, OutputFormat,
};

use super::{
    generate_trust_report, obligation_triplets_from_bundle, obligation_triplets_from_metadata,
    parse_solver_list, proof_object_looks_nontrivial, rederive_certificate_bundle_input,
    render_suite_text, run_cert_suite, run_external_proof_checker, run_external_solver_on_file,
    validate_foundational_profile_requirements, validate_trusted_check_requirements,
    verify_governance_bundle, CertSuiteDefaults, GovernanceGateResult, GovernancePipelineReport,
};

/// Handler for `Commands::CertSuite`.
pub(crate) fn run_cert_suite_command(
    manifest: PathBuf,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    engine: String,
    soundness: String,
    fairness: String,
    format: String,
    out: Option<PathBuf>,
    artifacts_dir: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let solver = parse_solver_choice(&solver)?;
    let engine = parse_proof_engine(&engine)?;
    let soundness = parse_soundness_mode(&soundness)?;
    if cli_network_mode == CliNetworkSemanticsMode::Faithful && soundness != SoundnessMode::Strict {
        miette::bail!("`--network-semantics faithful` requires `--soundness strict`.");
    }
    let fairness = parse_fairness_mode(&fairness)?;
    let output_format = parse_output_format(&format)?;
    let defaults = CertSuiteDefaults {
        solver,
        depth,
        k,
        timeout_secs: timeout,
        soundness,
        fairness,
        proof_engine: engine,
    };

    let report = run_cert_suite(
        &manifest,
        &defaults,
        cli_network_mode,
        artifacts_dir.as_deref(),
    )?;
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        write_json_artifact(&path, &report_json_value)?;
        println!("Certification suite report written to {}", path.display());
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_suite_text(&report)),
        OutputFormat::Json => println!("{report_json}"),
    }

    if report.overall != "pass" {
        return Err(report_with_exit_code(
            2,
            format!("Certification suite reported overall='{}'.", report.overall),
        ));
    }
    Ok(())
}

/// Handler for `Commands::CertifySafety`.
pub(crate) fn run_certify_safety_command(
    file: PathBuf,
    solver: String,
    k: usize,
    engine: String,
    timeout: u64,
    soundness: String,
    out: PathBuf,
    capture_proofs: bool,
    allow_missing_proofs: bool,
    trust_report: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = fs::read_to_string(&file).into_diagnostic()?;
    let filename = file.display().to_string();
    let soundness_mode = parse_soundness_mode(&soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver)?,
        max_depth: k,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: parse_proof_engine(&engine)?,
    };

    let cert = tarsier_engine::pipeline::generate_safety_certificate(&source, &filename, &options)
        .map_err(|e| miette::miette!("Error: {e}"))?;

    let bundle = certificate_bundle_from_safety(&cert);
    write_certificate_bundle(&out, &bundle, capture_proofs, allow_missing_proofs)?;

    if let Some(report_path) = trust_report {
        let report =
            generate_trust_report("standard", Some(&filename), &[&solver], &engine, &soundness);
        let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
        fs::write(&report_path, json).into_diagnostic()?;
        println!("Trust report written to {}", report_path.display());
    }
    Ok(())
}

/// Handler for `Commands::CertifyFairLiveness`.
pub(crate) fn run_certify_fair_liveness_command(
    file: PathBuf,
    solver: String,
    k: usize,
    timeout: u64,
    soundness: String,
    fairness: String,
    out: PathBuf,
    capture_proofs: bool,
    allow_missing_proofs: bool,
    trust_report: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = fs::read_to_string(&file).into_diagnostic()?;
    let filename = file.display().to_string();
    let fairness = parse_fairness_mode(&fairness)?;
    let soundness_mode = parse_soundness_mode(&soundness)?;
    validate_cli_network_semantics_mode(&source, &filename, soundness_mode, cli_network_mode)?;
    let options = PipelineOptions {
        solver: parse_solver_choice(&solver)?,
        max_depth: k,
        timeout_secs: timeout,
        dump_smt: None,
        soundness: soundness_mode,
        proof_engine: ProofEngine::Pdr,
    };

    let cert = match tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        &source, &filename, &options, fairness,
    ) {
        Ok(cert) => cert,
        Err(e) => return Err(miette::miette!("Error: {e}")),
    };

    let bundle = certificate_bundle_from_fair_liveness(&cert);
    write_certificate_bundle(&out, &bundle, capture_proofs, allow_missing_proofs)?;

    if let Some(report_path) = trust_report {
        let report =
            generate_trust_report("standard", Some(&filename), &[&solver], "pdr", &soundness);
        let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
        fs::write(&report_path, json).into_diagnostic()?;
        println!("Trust report written to {}", report_path.display());
    }
    Ok(())
}

/// Handler for `Commands::CheckCertificate`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn run_check_certificate_command(
    bundle: PathBuf,
    profile: Option<String>,
    solvers: String,
    emit_proofs: Option<PathBuf>,
    require_proofs: bool,
    proof_checker: Option<PathBuf>,
    allow_unchecked_proofs: bool,
    rederive: bool,
    rederive_timeout: u64,
    trusted_check: bool,
    min_solvers: usize,
) -> miette::Result<()> {
    // Apply governance profile floor requirements.
    let mut min_solvers = min_solvers;
    let mut require_proofs = require_proofs;
    let mut require_foundational_proof_path = false;
    if let Some(profile_name) = &profile {
        let gov_profile: GovernanceProfile = profile_name
            .parse()
            .map_err(|e: String| miette::miette!("{}", e))?;
        let reqs = gov_profile.requirements();
        if reqs.min_solvers > min_solvers {
            min_solvers = reqs.min_solvers;
        }
        if reqs.require_proofs {
            require_proofs = true;
        }
        if reqs.require_proof_checker && proof_checker.is_none() {
            miette::bail!(
                "--profile {} requires --proof-checker to be set.",
                profile_name
            );
        }
        if reqs.require_foundational_proof_path {
            require_foundational_proof_path = true;
        }
    }

    let integrity = check_bundle_integrity(&bundle).into_diagnostic()?;
    let metadata = integrity.metadata;

    if metadata.kind != CertificateKind::SafetyProof.as_str()
        && metadata.kind != CertificateKind::FairLivenessProof.as_str()
    {
        miette::bail!("Unsupported certificate kind: {}", metadata.kind);
    }

    let mut solver_cmds = parse_solver_list(&solvers);
    solver_cmds.sort();
    solver_cmds.dedup();
    if solver_cmds.is_empty() {
        miette::bail!("No solver commands provided (use --solvers z3,cvc5).");
    }
    if require_foundational_proof_path {
        validate_foundational_profile_requirements(&solver_cmds, true)?;
    }
    validate_trusted_check_requirements(
        trusted_check,
        min_solvers,
        &solver_cmds,
        &metadata,
        rederive,
        proof_checker.as_ref(),
        allow_unchecked_proofs,
    )?;

    let mut had_error = false;
    for issue in integrity.issues {
        had_error = true;
        println!("[FAIL] integrity [{}]: {}", issue.code, issue.message);
    }

    if had_error {
        return Err(report_with_exit_code(
            2,
            "Certificate integrity checks failed.",
        ));
    }

    if trusted_check && proof_checker.is_none() && allow_unchecked_proofs {
        println!(
            "[WARN] trusted-check: --allow-unchecked-proofs enabled; relying on solver UNSAT + proof-shape checks only"
        );
    }

    if rederive {
        match rederive_certificate_bundle_input(&metadata, rederive_timeout) {
            Ok(rederived_bundle) => {
                let expected = obligation_triplets_from_metadata(&metadata);
                let actual = obligation_triplets_from_bundle(&rederived_bundle);
                if expected != actual {
                    had_error = true;
                    println!(
                        "[FAIL] rederive: certificate obligations differ from freshly generated obligations"
                    );
                    println!(
                        "        (metadata obligations: {}, regenerated obligations: {})",
                        expected.len(),
                        actual.len()
                    );
                } else {
                    println!(
                        "[PASS] rederive: regenerated obligations match certificate metadata hashes"
                    );
                }
            }
            Err(e) => {
                had_error = true;
                println!("[ERROR] rederive: {e}");
            }
        }
    }

    if had_error {
        return Err(report_with_exit_code(
            2,
            "Certificate re-derivation checks failed.",
        ));
    }

    let emit_proofs_dir = emit_proofs.clone();
    if let Some(dir) = &emit_proofs_dir {
        fs::create_dir_all(dir).into_diagnostic()?;
    }

    let require_proofs = require_proofs || trusted_check;
    let mut obligation_pass_counts = vec![0usize; metadata.obligations.len()];
    let mut obligation_solver_errors = vec![0usize; metadata.obligations.len()];

    for solver_cmd in solver_cmds {
        let mut solver_pass = true;
        let solver_proof_dir = emit_proofs_dir.as_ref().map(|d| d.join(&solver_cmd));
        if let Some(dir) = &solver_proof_dir {
            fs::create_dir_all(dir).into_diagnostic()?;
        }
        for (obligation_idx, obligation) in metadata.obligations.iter().enumerate() {
            let obligation_path = bundle.join(&obligation.file);
            let need_proofs = emit_proofs_dir.is_some() || require_proofs;
            if need_proofs {
                match run_external_solver_with_proof(&solver_cmd, &obligation_path) {
                    Ok((result, proof_text)) => {
                        let mut passed = result == obligation.expected;
                        if !passed {
                            solver_pass = false;
                            if !trusted_check {
                                had_error = true;
                            }
                            println!(
                                "[FAIL] {}: {} expected {}, got {}",
                                solver_cmd, obligation.name, obligation.expected, result
                            );
                        } else if require_proofs
                            && obligation.expected == "unsat"
                            && !proof_object_looks_nontrivial(&proof_text)
                        {
                            solver_pass = false;
                            passed = false;
                            if !trusted_check {
                                had_error = true;
                            }
                            println!(
                                "[FAIL] {}: {} UNSAT but emitted proof object is empty/malformed",
                                solver_cmd, obligation.name
                            );
                        }
                        let mut proof_file_for_check: Option<PathBuf> = None;
                        let mut temp_proof_file: Option<PathBuf> = None;
                        if let Some(dir) = &solver_proof_dir {
                            let proof_file = dir.join(format!("{}.proof", obligation.name));
                            if let Err(e) = fs::write(&proof_file, &proof_text) {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!(
                                    "[ERROR] {}: failed writing proof file {}: {}",
                                    solver_cmd,
                                    proof_file.display(),
                                    e
                                );
                                passed = false;
                            } else {
                                proof_file_for_check = Some(proof_file);
                            }
                        } else if proof_checker.is_some() && obligation.expected == "unsat" {
                            let temp_path = std::env::temp_dir().join(format!(
                                "tarsier-proof-{}-{}-{}-{}.proof",
                                std::process::id(),
                                solver_cmd,
                                obligation_idx,
                                obligation.name
                            ));
                            if let Err(e) = fs::write(&temp_path, &proof_text) {
                                solver_pass = false;
                                obligation_solver_errors[obligation_idx] += 1;
                                if !trusted_check {
                                    had_error = true;
                                }
                                println!(
                                    "[ERROR] {}: failed writing temporary proof file {}: {}",
                                    solver_cmd,
                                    temp_path.display(),
                                    e
                                );
                                passed = false;
                            } else {
                                proof_file_for_check = Some(temp_path.clone());
                                temp_proof_file = Some(temp_path);
                            }
                        }

                        if passed && obligation.expected == "unsat" && result == "unsat" {
                            if let Some(checker) = proof_checker.as_ref() {
                                if let Some(proof_file) = &proof_file_for_check {
                                    if let Err(e) = run_external_proof_checker(
                                        checker,
                                        &solver_cmd,
                                        &obligation_path,
                                        proof_file,
                                    ) {
                                        solver_pass = false;
                                        obligation_solver_errors[obligation_idx] += 1;
                                        if !trusted_check {
                                            had_error = true;
                                        }
                                        passed = false;
                                        println!(
                                            "[FAIL] {}: {} ({e})",
                                            solver_cmd, obligation.name
                                        );
                                    }
                                } else {
                                    solver_pass = false;
                                    obligation_solver_errors[obligation_idx] += 1;
                                    if !trusted_check {
                                        had_error = true;
                                    }
                                    passed = false;
                                    println!(
                                        "[FAIL] {}: {} no proof file available for --proof-checker",
                                        solver_cmd, obligation.name
                                    );
                                }
                            }
                        }

                        if passed {
                            obligation_pass_counts[obligation_idx] += 1;
                        }

                        if let Some(temp_path) = temp_proof_file {
                            let _ = fs::remove_file(temp_path);
                        }
                    }
                    Err(e) => {
                        solver_pass = false;
                        obligation_solver_errors[obligation_idx] += 1;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!("[ERROR] {}: {}", solver_cmd, e);
                    }
                }
            } else {
                match run_external_solver_on_file(&solver_cmd, &obligation_path) {
                    Ok(result) if result == obligation.expected => {
                        obligation_pass_counts[obligation_idx] += 1;
                    }
                    Ok(result) => {
                        solver_pass = false;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!(
                            "[FAIL] {}: {} expected {}, got {}",
                            solver_cmd, obligation.name, obligation.expected, result
                        );
                    }
                    Err(e) => {
                        solver_pass = false;
                        obligation_solver_errors[obligation_idx] += 1;
                        if !trusted_check {
                            had_error = true;
                        }
                        println!("[ERROR] {}: {}", solver_cmd, e);
                    }
                }
            }
        }
        if solver_pass {
            println!(
                "[PASS] {}: all {} obligations satisfied",
                solver_cmd,
                metadata.obligations.len()
            );
            if let Some(dir) = &solver_proof_dir {
                println!(
                    "[PASS] {}: proof objects written to {}",
                    solver_cmd,
                    dir.display()
                );
            }
        } else {
            println!("[FAIL] {}: one or more obligations failed", solver_cmd);
        }
    }

    if trusted_check {
        let mut consensus_failures = 0usize;
        for (idx, obligation) in metadata.obligations.iter().enumerate() {
            let confirmations = obligation_pass_counts[idx];
            if confirmations < min_solvers {
                consensus_failures += 1;
                println!(
                    "[FAIL] trusted-check: obligation '{}' has {} confirmation(s), requires {}.",
                    obligation.name, confirmations, min_solvers
                );
            } else {
                println!(
                    "[PASS] trusted-check: obligation '{}' confirmed by {} solver(s).",
                    obligation.name, confirmations
                );
            }
            if obligation_solver_errors[idx] > 0 {
                println!(
                    "[WARN] trusted-check: obligation '{}' had {} solver execution/proof I/O error(s).",
                    obligation.name, obligation_solver_errors[idx]
                );
            }
        }
        if consensus_failures > 0 {
            had_error = true;
        }
    }

    if had_error {
        return Err(report_with_exit_code(
            2,
            "Certificate verification checks failed.",
        ));
    } else {
        println!(
            "Certificate verified for kind '{}' with engine '{}' (k/frame: {}).",
            metadata.kind,
            metadata.proof_engine,
            metadata
                .induction_k
                .map(|k| k.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
    Ok(())
}

/// Handler for `Commands::GenerateTrustReport`.
pub(crate) fn run_generate_trust_report_command(
    profile: String,
    protocol_file: Option<String>,
    solvers: String,
    engine: String,
    soundness: String,
    out: PathBuf,
) -> miette::Result<()> {
    // Validate governance profile
    let valid_profiles = ["standard", "reinforced", "high-assurance"];
    if !valid_profiles.contains(&profile.as_str()) {
        miette::bail!(
            "Invalid governance profile '{}'. Must be one of: {}",
            profile,
            valid_profiles.join(", ")
        );
    }
    // Validate soundness
    let valid_soundness = ["strict", "permissive"];
    if !valid_soundness.contains(&soundness.as_str()) {
        miette::bail!(
            "Invalid soundness '{}'. Must be one of: {}",
            soundness,
            valid_soundness.join(", ")
        );
    }
    // Validate engine
    let valid_engines = ["kinduction", "pdr"];
    if !valid_engines.contains(&engine.as_str()) {
        miette::bail!(
            "Invalid engine '{}'. Must be one of: {}",
            engine,
            valid_engines.join(", ")
        );
    }

    let solver_list: Vec<&str> = solvers.split(',').map(|s| s.trim()).collect();
    let report = generate_trust_report(
        &profile,
        protocol_file.as_deref(),
        &solver_list,
        &engine,
        &soundness,
    );
    let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
    fs::write(&out, json).into_diagnostic()?;
    println!("Trust report written to {}", out.display());
    Ok(())
}

/// Handler for `Commands::GovernancePipeline`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_governance_pipeline_command(
    file: PathBuf,
    cert_manifest: PathBuf,
    conformance_manifest: PathBuf,
    benchmark_report: Option<PathBuf>,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: String,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
    por_mode: &str,
) -> miette::Result<()> {
    let pipeline_start = std::time::Instant::now();
    let output_format = parse_output_format(&format)?;
    let mut gates: Vec<GovernanceGateResult> = Vec::new();

    // --- Gate 1: Proof (analyze in audit mode) ---
    let proof_start = std::time::Instant::now();
    let proof_gate = (|| -> Result<GovernanceGateResult, String> {
        let source = fs::read_to_string(&file).map_err(|e| e.to_string())?;
        let filename = file.display().to_string();
        let eff_solver = parse_solver_choice(&solver).map_err(|e| e.to_string())?;
        let eff_soundness = parse_soundness_mode(&soundness).map_err(|e| e.to_string())?;
        let cfg = LayerRunCfg {
            solver: eff_solver,
            depth,
            k,
            timeout,
            soundness: eff_soundness,
            fairness: FairnessMode::Weak,
            cegar_iters: 0,
            portfolio: true,
        };
        let report = run_analysis(
            &source,
            &filename,
            AnalysisMode::Audit,
            cfg,
            cli_network_mode,
            None,
            por_mode,
        );
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "proof".to_string(),
            status: status.to_string(),
            elapsed_ms: proof_start.elapsed().as_millis() as u64,
            details: json!({
                "mode": report.mode,
                "overall": report.overall,
                "overall_verdict": report.overall_verdict,
                "confidence_tier": report.confidence_tier,
                "layer_count": report.layers.len(),
            }),
            error: None,
        })
    })();
    match proof_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "proof".to_string(),
            status: "error".to_string(),
            elapsed_ms: proof_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 2: Cert-suite ---
    let cert_start = std::time::Instant::now();
    let cert_gate = (|| -> Result<GovernanceGateResult, String> {
        let eff_solver = parse_solver_choice(&solver).map_err(|e| e.to_string())?;
        let eff_soundness = parse_soundness_mode(&soundness).map_err(|e| e.to_string())?;
        let defaults = CertSuiteDefaults {
            solver: eff_solver,
            depth,
            k,
            timeout_secs: timeout,
            soundness: eff_soundness,
            fairness: FairnessMode::Weak,
            proof_engine: ProofEngine::KInduction,
        };
        let report = run_cert_suite(&cert_manifest, &defaults, cli_network_mode, None)
            .map_err(|e| format!("{e}"))?;
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "cert".to_string(),
            status: status.to_string(),
            elapsed_ms: cert_start.elapsed().as_millis() as u64,
            details: json!({
                "manifest": report.manifest,
                "passed": report.passed,
                "failed": report.failed,
                "errors": report.errors,
                "overall": report.overall,
            }),
            error: None,
        })
    })();
    match cert_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "cert".to_string(),
            status: "error".to_string(),
            elapsed_ms: cert_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 3: Corpus (conformance-suite) ---
    let corpus_start = std::time::Instant::now();
    let corpus_gate = (|| -> Result<GovernanceGateResult, String> {
        let report =
            run_conformance_suite(&conformance_manifest, None).map_err(|e| format!("{e}"))?;
        let status = if report.overall == "pass" {
            "pass"
        } else {
            "fail"
        };
        Ok(GovernanceGateResult {
            gate: "corpus".to_string(),
            status: status.to_string(),
            elapsed_ms: corpus_start.elapsed().as_millis() as u64,
            details: json!({
                "manifest": report.manifest_path,
                "passed": report.passed,
                "failed": report.failed,
                "errors": report.errors,
                "overall": report.overall,
            }),
            error: None,
        })
    })();
    match corpus_gate {
        Ok(g) => gates.push(g),
        Err(e) => gates.push(GovernanceGateResult {
            gate: "corpus".to_string(),
            status: "error".to_string(),
            elapsed_ms: corpus_start.elapsed().as_millis() as u64,
            details: json!({}),
            error: Some(e),
        }),
    }

    // --- Gate 4: Perf (benchmark report validation) ---
    let perf_start = std::time::Instant::now();
    if let Some(ref bench_path) = benchmark_report {
        let perf_gate = (|| -> Result<GovernanceGateResult, String> {
            let raw = fs::read_to_string(bench_path).map_err(|e| e.to_string())?;
            let report: Value =
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}"))?;
            let perf_gate_obj = report.get("performance_gate");
            let perf_pass = perf_gate_obj
                .and_then(|g| g.get("pass"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let scale_gate_obj = report.get("scale_band_gate");
            let scale_pass = scale_gate_obj
                .and_then(|g| g.get("pass"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let summary = report.get("summary").cloned().unwrap_or(json!({}));
            let status = if perf_pass && scale_pass {
                "pass"
            } else {
                "fail"
            };
            Ok(GovernanceGateResult {
                gate: "perf".to_string(),
                status: status.to_string(),
                elapsed_ms: perf_start.elapsed().as_millis() as u64,
                details: json!({
                    "benchmark_file": bench_path.display().to_string(),
                    "performance_gate_pass": perf_pass,
                    "scale_band_gate_pass": scale_pass,
                    "summary": summary,
                }),
                error: None,
            })
        })();
        match perf_gate {
            Ok(g) => gates.push(g),
            Err(e) => gates.push(GovernanceGateResult {
                gate: "perf".to_string(),
                status: "error".to_string(),
                elapsed_ms: perf_start.elapsed().as_millis() as u64,
                details: json!({}),
                error: Some(e),
            }),
        }
    } else {
        gates.push(GovernanceGateResult {
            gate: "perf".to_string(),
            status: "skip".to_string(),
            elapsed_ms: 0,
            details: json!({"reason": "no --benchmark-report provided"}),
            error: None,
        });
    }

    let overall = if gates
        .iter()
        .all(|g| g.status == "pass" || g.status == "skip")
    {
        "pass"
    } else {
        "fail"
    };

    let pipeline_report = GovernancePipelineReport {
        schema_version: "v1".to_string(),
        tarsier_version: env!("CARGO_PKG_VERSION").to_string(),
        gates: gates.clone(),
        overall: overall.to_string(),
        elapsed_ms: pipeline_start.elapsed().as_millis() as u64,
    };

    let report_json = serde_json::to_string_pretty(&pipeline_report).into_diagnostic()?;
    if let Some(ref path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).into_diagnostic()?;
        }
        fs::write(path, &report_json).into_diagnostic()?;
    }

    match output_format {
        OutputFormat::Text => {
            println!("Governance Pipeline Report");
            println!("==========================");
            for gate in &pipeline_report.gates {
                let icon = match gate.status.as_str() {
                    "pass" => "PASS",
                    "fail" => "FAIL",
                    "skip" => "SKIP",
                    _ => "ERR ",
                };
                println!(
                    "  [{icon}] {gate:<8} ({ms}ms)",
                    gate = gate.gate,
                    ms = gate.elapsed_ms,
                );
                if let Some(ref e) = gate.error {
                    println!("         error: {e}");
                }
            }
            println!("---");
            println!("Overall: {overall}");
        }
        OutputFormat::Json => println!("{report_json}"),
    }

    if overall != "pass" {
        return Err(report_with_exit_code(
            2,
            format!("Governance pipeline overall result was '{}'.", overall),
        ));
    }
    Ok(())
}

/// Handler for `Commands::VerifyGovernanceBundle`.
pub(crate) fn run_verify_governance_bundle_command(
    bundle: PathBuf,
    format: String,
) -> miette::Result<()> {
    let output_format = parse_output_format(&format)?;
    let report = verify_governance_bundle(&bundle);
    let report_json = serde_json::to_string_pretty(&report).into_diagnostic()?;
    match output_format {
        OutputFormat::Text => {
            println!("Governance Bundle Verification");
            println!("==============================");
            println!("Bundle: {}", report.bundle);
            for check in &report.checks {
                let icon = if check.status == "pass" {
                    "PASS"
                } else {
                    "FAIL"
                };
                println!("  [{icon}] {}", check.check);
                if let Some(err) = &check.error {
                    println!("         error: {err}");
                }
            }
            println!("---");
            println!("Overall: {}", report.overall);
        }
        OutputFormat::Json => {
            println!("{report_json}");
        }
    }
    if report.overall != "pass" {
        return Err(report_with_exit_code(
            2,
            format!(
                "Governance bundle verification overall result was '{}'.",
                report.overall
            ),
        ));
    }
    Ok(())
}
