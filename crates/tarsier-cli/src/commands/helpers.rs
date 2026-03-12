// Shared helper functions used across CLI command handlers.
//
// These parse/convert CLI string arguments into typed enum values
// and provide sandbox/execution control configuration, as well as
// certificate-bundle, diagnostics, and template utilities.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use miette::IntoDiagnostic;

use tarsier_engine::pipeline::{
    FairLivenessProofCertificate, FairnessMode, FaithfulFallbackConfig, FaithfulFallbackFloor,
    PipelineExecutionControls, PipelineOptions, ProofEngine, SafetyProofCertificate, SolverChoice,
    SoundnessMode,
};
use tarsier_ir::threshold_automaton::PorMode;
use tarsier_proof_kernel::{
    compute_bundle_sha256, sha256_hex_file, CertificateMetadata, CertificateObligationMeta,
    CERTIFICATE_SCHEMA_VERSION,
};

use crate::{
    fairness_name, AnalysisMode, CanonicalVerdict, CertificateBundleInput,
    CertificateBundleObligation, CertificateKind, Cli, CliNetworkSemanticsMode, OutputFormat,
    VisualizeCheck, VisualizeFormat,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliParseError {
    message: String,
}

impl CliParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliParseError {}
impl miette::Diagnostic for CliParseError {}

pub(crate) type CliParseResult<T> = Result<T, CliParseError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliExitError {
    pub(crate) code: i32,
    message: String,
}

impl CliExitError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliExitError {}
impl miette::Diagnostic for CliExitError {}

pub(crate) fn report_with_exit_code(code: i32, message: impl Into<String>) -> miette::Report {
    miette::Report::new(CliExitError::new(code, message))
}

pub(crate) fn exit_code_from_report(report: &miette::Report) -> Option<i32> {
    report.downcast_ref::<CliExitError>().map(|err| err.code)
}

pub(crate) fn parse_soundness_mode(raw: &str) -> CliParseResult<SoundnessMode> {
    match raw {
        "strict" => Ok(SoundnessMode::Strict),
        "permissive" => Ok(SoundnessMode::Permissive),
        other => Err(CliParseError::new(format!(
            "Unknown soundness mode: {other}. Use 'strict' or 'permissive'."
        ))),
    }
}

pub(crate) fn parse_proof_engine(raw: &str) -> CliParseResult<ProofEngine> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        "ranking" => Ok(ProofEngine::Ranking),
        other => Err(CliParseError::new(format!(
            "Unknown proof engine: {other}. Use 'kinduction', 'pdr', or 'ranking'."
        ))),
    }
}

#[cfg(feature = "governance")]
pub(crate) fn parse_manifest_proof_engine(raw: &str) -> Result<ProofEngine, String> {
    match raw {
        "kinduction" => Ok(ProofEngine::KInduction),
        "pdr" => Ok(ProofEngine::Pdr),
        "ranking" => Ok(ProofEngine::Ranking),
        other => Err(format!(
            "Unknown proof_engine '{other}'. Use 'kinduction', 'pdr', or 'ranking'."
        )),
    }
}

pub(crate) fn parse_solver_choice(raw: &str) -> CliParseResult<SolverChoice> {
    match raw {
        "z3" => Ok(SolverChoice::Z3),
        "cvc5" => Ok(SolverChoice::Cvc5),
        other => Err(CliParseError::new(format!(
            "Unknown solver: {other}. Use 'z3' or 'cvc5'."
        ))),
    }
}

pub(crate) fn parse_analysis_mode(raw: &str) -> CliParseResult<AnalysisMode> {
    match raw {
        "quick" => Ok(AnalysisMode::Quick),
        "standard" => Ok(AnalysisMode::Standard),
        "proof" => Ok(AnalysisMode::Proof),
        "audit" => Ok(AnalysisMode::Audit),
        other => Err(CliParseError::new(format!(
            "Unknown mode: {other}. Use 'quick', 'standard', 'proof', or 'audit'."
        ))),
    }
}

pub(crate) fn parse_output_format(raw: &str) -> CliParseResult<OutputFormat> {
    match raw {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(CliParseError::new(format!(
            "Unknown output format: {other}. Use 'text' or 'json'."
        ))),
    }
}

pub(crate) fn parse_conformance_adapter(
    raw: &str,
) -> CliParseResult<tarsier_conformance::adapters::AdapterKind> {
    use tarsier_conformance::adapters::AdapterKind;
    match raw.parse::<AdapterKind>() {
        Ok(kind) => Ok(kind),
        Err(err) => Err(CliParseError::new(err.to_string())),
    }
}

pub(crate) fn parse_conformance_mode(
    raw: &str,
) -> CliParseResult<tarsier_conformance::checker::ConformanceMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "permissive" => Ok(tarsier_conformance::checker::ConformanceMode::Permissive),
        "strict" => Ok(tarsier_conformance::checker::ConformanceMode::Strict),
        other => Err(CliParseError::new(format!(
            "Unknown checker mode: {other}. Use 'permissive' or 'strict'."
        ))),
    }
}

pub(crate) fn parse_cli_network_semantics_mode(
    raw: &str,
) -> CliParseResult<CliNetworkSemanticsMode> {
    match raw {
        "dsl" => Ok(CliNetworkSemanticsMode::Dsl),
        "faithful" => Ok(CliNetworkSemanticsMode::Faithful),
        other => Err(CliParseError::new(format!(
            "Unknown network semantics mode: {other}. Use 'dsl' or 'faithful'."
        ))),
    }
}

pub(crate) fn parse_cli_por_mode(raw: &str) -> CliParseResult<Option<PorMode>> {
    match raw {
        "full" => Ok(None), // default -- no override
        "static" | "static_only" => Ok(Some(PorMode::Static)),
        "off" | "none" | "disabled" => Ok(Some(PorMode::Off)),
        other => Err(CliParseError::new(format!(
            "Unknown POR mode: {other}. Use 'full', 'static', or 'off'."
        ))),
    }
}

pub(crate) fn cli_network_mode_name(mode: CliNetworkSemanticsMode) -> &'static str {
    match mode {
        CliNetworkSemanticsMode::Dsl => "dsl",
        CliNetworkSemanticsMode::Faithful => "faithful",
    }
}

pub(crate) fn parse_visualize_check(raw: &str) -> CliParseResult<VisualizeCheck> {
    match raw {
        "verify" => Ok(VisualizeCheck::Verify),
        "liveness" => Ok(VisualizeCheck::Liveness),
        "fair-liveness" | "fair_liveness" => Ok(VisualizeCheck::FairLiveness),
        "prove" => Ok(VisualizeCheck::Prove),
        "prove-fair" | "prove_fair" => Ok(VisualizeCheck::ProveFair),
        other => Err(CliParseError::new(format!(
            "Unknown visualize check: {other}. Use 'verify', 'liveness', 'fair-liveness', 'prove', or 'prove-fair'."
        ))),
    }
}

pub(crate) fn visualize_check_name(check: VisualizeCheck) -> &'static str {
    match check {
        VisualizeCheck::Verify => "verify",
        VisualizeCheck::Liveness => "liveness",
        VisualizeCheck::FairLiveness => "fair-liveness",
        VisualizeCheck::Prove => "prove",
        VisualizeCheck::ProveFair => "prove-fair",
    }
}

pub(crate) fn parse_visualize_format(raw: &str) -> CliParseResult<VisualizeFormat> {
    match raw {
        "timeline" => Ok(VisualizeFormat::Timeline),
        "mermaid" => Ok(VisualizeFormat::Mermaid),
        "markdown" => Ok(VisualizeFormat::Markdown),
        "json" => Ok(VisualizeFormat::Json),
        other => Err(CliParseError::new(format!(
            "Unknown visualize format: {other}. Use 'timeline', 'mermaid', 'markdown', or 'json'."
        ))),
    }
}

pub(crate) fn visualize_format_name(format: VisualizeFormat) -> &'static str {
    match format {
        VisualizeFormat::Timeline => "timeline",
        VisualizeFormat::Mermaid => "mermaid",
        VisualizeFormat::Markdown => "markdown",
        VisualizeFormat::Json => "json",
    }
}

pub(crate) fn parse_fairness_mode(raw: &str) -> CliParseResult<FairnessMode> {
    match raw {
        "weak" => Ok(FairnessMode::Weak),
        "strong" => Ok(FairnessMode::Strong),
        other => Err(CliParseError::new(format!(
            "Unknown fairness mode: {other}. Use 'weak' or 'strong'."
        ))),
    }
}

pub(crate) fn parse_faithful_fallback_floor(
    raw: &str,
) -> CliParseResult<Option<FaithfulFallbackFloor>> {
    match raw {
        "off" | "none" | "disabled" => Ok(None),
        "identity" | "faithful" => Ok(Some(FaithfulFallbackFloor::IdentitySelective)),
        "classic" => Ok(Some(FaithfulFallbackFloor::Classic)),
        other => Err(CliParseError::new(format!(
            "Unknown faithful fallback mode: {other}. Use 'off', 'identity', or 'classic'."
        ))),
    }
}

pub(crate) fn execution_controls_from_cli(cli: &Cli) -> CliParseResult<PipelineExecutionControls> {
    let faithful_fallback = parse_faithful_fallback_floor(&cli.faithful_fallback)?.map(|floor| {
        FaithfulFallbackConfig {
            max_locations: cli.fallback_max_locations,
            max_shared_vars: cli.fallback_max_shared_vars,
            max_message_counters: cli.fallback_max_message_counters,
            floor,
        }
    });
    let liveness_memory_budget_mb = if cli.liveness_memory_budget_mb == 0 {
        None
    } else {
        Some(cli.liveness_memory_budget_mb)
    };
    let por_mode_override = parse_cli_por_mode(&cli.por_mode)?;
    Ok(PipelineExecutionControls {
        faithful_fallback,
        liveness_memory_budget_mb,
        por_mode_override,
    })
}

pub(crate) fn sandbox_config_from_cli(cli: &Cli) -> tarsier_engine::sandbox::SandboxConfig {
    tarsier_engine::sandbox::SandboxConfig {
        timeout_secs: cli.sandbox_timeout_secs,
        memory_budget_mb: cli.sandbox_memory_budget_mb,
        max_input_bytes: cli.sandbox_max_input_bytes,
        allow_degraded: cli.allow_degraded_sandbox,
    }
}

/// Read a source file with sandbox input-size validation.
pub(crate) fn sandbox_read_source(path: &std::path::Path) -> miette::Result<String> {
    use miette::IntoDiagnostic;
    let metadata = std::fs::metadata(path).into_diagnostic()?;
    if let Some(config) = tarsier_engine::sandbox::active_sandbox_config() {
        if metadata.len() > config.max_input_bytes {
            miette::bail!(
                "Input file {} is {} bytes, exceeding sandbox limit of {} bytes",
                path.display(),
                metadata.len(),
                config.max_input_bytes
            );
        }
    }
    std::fs::read_to_string(path).into_diagnostic()
}

pub(crate) fn make_options(
    solver: SolverChoice,
    depth: usize,
    timeout: u64,
    soundness: SoundnessMode,
) -> PipelineOptions {
    PipelineOptions {
        solver,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness,
        proof_engine: ProofEngine::KInduction,
    }
}

// ---------------------------------------------------------------------------
// Utility functions migrated from main.rs
// ---------------------------------------------------------------------------

mod diagnostics;
mod templates;

#[cfg(feature = "governance")]
pub(crate) use diagnostics::declared_network_mode_in_program;
#[cfg(test)]
pub(crate) use diagnostics::{automaton_footprint_json, ratio};
pub(crate) use diagnostics::{
    network_faithfulness_section, render_fallback_summary, render_optimization_summary,
    render_phase_profile_summary, run_diagnostics_details, validate_cli_network_semantics_mode,
};
pub(crate) use templates::{assistant_template, property_template};

pub(crate) fn solver_cmd_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

pub(crate) fn proof_engine_name(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
        ProofEngine::Ranking => "ranking",
    }
}

pub(crate) fn soundness_name(mode: SoundnessMode) -> &'static str {
    match mode {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

pub(crate) fn certificate_bundle_from_safety(
    cert: &SafetyProofCertificate,
) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::SafetyProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: cert.induction_k,
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: None,
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

pub(crate) fn certificate_bundle_from_fair_liveness(
    cert: &FairLivenessProofCertificate,
) -> CertificateBundleInput {
    CertificateBundleInput {
        kind: CertificateKind::FairLivenessProof,
        protocol_file: cert.protocol_file.clone(),
        proof_engine: proof_engine_name(cert.proof_engine).to_string(),
        induction_k: Some(cert.frame),
        solver_used: solver_cmd_name(cert.solver_used).to_string(),
        soundness: soundness_name(cert.soundness).to_string(),
        fairness: Some(fairness_name(cert.fairness).to_string()),
        committee_bounds: cert.committee_bounds.clone(),
        obligations: cert
            .obligations
            .iter()
            .map(|o| CertificateBundleObligation {
                name: o.name.clone(),
                expected: o.expected.clone(),
                smt2: o.smt2.clone(),
            })
            .collect(),
    }
}

pub(crate) fn obligations_all_unsat(metadata: &CertificateMetadata) -> bool {
    metadata
        .obligations
        .iter()
        .all(|obligation| obligation.expected == "unsat")
}

pub(crate) fn augment_query_for_proof(script: &str, solver_cmd: &str) -> String {
    let mut out = String::new();
    match solver_cmd {
        "z3" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        "cvc5" => {
            out.push_str("(set-option :produce-proofs true)\n");
        }
        _ => {}
    }
    // The stored obligation already contains check-sat/exit. Remove exit and add get-proof.
    let body = script.replace("(exit)\n", "").replace("(exit)", "");
    out.push_str(&body);
    if !body.contains("(check-sat)") {
        out.push_str("\n(check-sat)\n");
    }
    out.push_str("(get-proof)\n");
    out.push_str("(exit)\n");
    out
}

pub(crate) fn run_external_solver_with_proof(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<(String, String)> {
    let base_script = fs::read_to_string(smt_file).into_diagnostic()?;
    let proof_script = augment_query_for_proof(&base_script, solver_cmd);

    let mut cmd = Command::new(solver_cmd);
    match solver_cmd {
        "z3" => {
            cmd.arg("-smt2")
                .arg("-in")
                .arg("sat.euf=true")
                .arg("tactic.default_tactic=smt")
                .arg("solver.proof.check=true");
        }
        "cvc5" => {
            cmd.arg("--lang")
                .arg("smt2")
                .arg("--check-proofs")
                .arg("--proof-format-mode=alethe")
                .arg("--proof-granularity=theory-rewrite")
                .arg("--proof-alethe-res-pivots")
                .arg("-");
        }
        _ => {
            miette::bail!(
                "Proof extraction for solver '{}' is unsupported; use z3 or cvc5.",
                solver_cmd
            );
        }
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().into_diagnostic()?;
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(proof_script.as_bytes()).into_diagnostic()?;
    }
    let output = child.wait_with_output().into_diagnostic()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        miette::bail!(
            "solver `{solver_cmd}` failed on {} while extracting proofs: {}",
            smt_file.display(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let token = stdout
        .lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("unknown")
        .to_string();

    Ok((token, stdout))
}

/// Extract proof object from solver for a written .smt2 obligation file.
pub(crate) fn extract_proof_for_obligation(
    solver_cmd: &str,
    smt_file: &std::path::Path,
) -> miette::Result<String> {
    let (result, proof_text) = run_external_solver_with_proof(solver_cmd, smt_file)?;
    if result != "unsat" {
        miette::bail!(
            "Cannot extract proof: solver returned '{}' instead of 'unsat' for {}",
            result,
            smt_file.display()
        );
    }
    Ok(proof_text)
}

pub(crate) fn canonicalize_obligation_smt2(script: &str) -> String {
    let mut set_logic: Option<String> = None;
    let mut preamble = Vec::new();
    let mut declarations = Vec::new();
    let mut assertions = Vec::new();
    let mut has_check_sat = false;
    let mut has_exit = false;

    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("(set-logic ") {
            if set_logic.is_none() {
                set_logic = Some(trimmed.to_string());
            }
            continue;
        }
        if trimmed.starts_with("(declare-const ") {
            declarations.push(trimmed.to_string());
            continue;
        }
        if trimmed.starts_with("(assert ") {
            assertions.push(trimmed.to_string());
            continue;
        }
        if trimmed == "(check-sat)" {
            has_check_sat = true;
            continue;
        }
        if trimmed == "(exit)" {
            has_exit = true;
            continue;
        }
        preamble.push(trimmed.to_string());
    }

    declarations.sort();
    declarations.dedup();
    assertions.sort();
    assertions.dedup();

    let mut out = String::new();
    out.push_str(set_logic.as_deref().unwrap_or("(set-logic QF_LIA)"));
    out.push('\n');
    for line in preamble {
        out.push_str(&line);
        out.push('\n');
    }
    for line in declarations {
        out.push_str(&line);
        out.push('\n');
    }
    for line in assertions {
        out.push_str(&line);
        out.push('\n');
    }
    if has_check_sat || !script.trim().is_empty() {
        out.push_str("(check-sat)\n");
    }
    if has_exit || !script.trim().is_empty() {
        out.push_str("(exit)\n");
    }
    out
}

pub(crate) fn write_certificate_bundle(
    out: &PathBuf,
    cert: &CertificateBundleInput,
    capture_proofs: bool,
    allow_missing_proofs: bool,
) -> miette::Result<()> {
    fs::create_dir_all(out).into_diagnostic()?;
    let metadata_file = out.join("certificate.json");

    let mut obligations = cert.obligations.clone();
    obligations.sort_by(|a, b| a.name.cmp(&b.name).then(a.expected.cmp(&b.expected)));

    let mut obligations_meta = Vec::new();
    for obligation in &obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = out.join(&file_name);
        let canonical_smt2 = canonicalize_obligation_smt2(&obligation.smt2);
        fs::write(&file_path, canonical_smt2).into_diagnostic()?;
        let hash = sha256_hex_file(&file_path).into_diagnostic()?;
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
            proof_file: None,
            proof_sha256: None,
        });
    }

    // If capture_proofs is enabled, extract proof objects from the solver for each obligation.
    if capture_proofs {
        let solver_cmd = &cert.solver_used;
        for meta in &mut obligations_meta {
            let smt_path = out.join(&meta.file);
            match extract_proof_for_obligation(solver_cmd, &smt_path) {
                Ok(proof_text) => {
                    let proof_file_name = format!("{}.proof", meta.name);
                    let proof_path = out.join(&proof_file_name);
                    fs::write(&proof_path, &proof_text).into_diagnostic()?;
                    let proof_hash = sha256_hex_file(&proof_path).into_diagnostic()?;
                    meta.proof_file = Some(proof_file_name);
                    meta.proof_sha256 = Some(proof_hash);
                    println!("  - {} (proof captured)", proof_path.display());
                }
                Err(e) => {
                    if allow_missing_proofs {
                        eprintln!(
                            "Warning: proof extraction failed for {} (--allow-missing-proofs): {}",
                            meta.name, e
                        );
                    } else {
                        miette::bail!(
                            "Proof extraction failed for obligation '{}': {}\n\
                             Use --allow-missing-proofs to continue without complete proofs.",
                            meta.name,
                            e
                        );
                    }
                }
            }
        }
    }

    let mut committee_bounds = cert.committee_bounds.clone();
    committee_bounds.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: cert.kind.as_str().to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: cert.proof_engine.clone(),
        induction_k: cert.induction_k,
        solver_used: cert.solver_used.clone(),
        soundness: cert.soundness.clone(),
        fairness: cert.fairness.clone(),
        committee_bounds,
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
    let metadata_json = serde_json::to_string_pretty(&metadata).into_diagnostic()?;
    fs::write(&metadata_file, metadata_json).into_diagnostic()?;

    println!("Certificate bundle written to {}", out.display());
    println!("  - {}", metadata_file.display());
    for obligation in &metadata.obligations {
        println!("  - {}", out.join(&obligation.file).display());
    }
    if let Some(k) = metadata.induction_k {
        println!("proof frame/k: {k}");
    }
    if let Some(ref fairness) = metadata.fairness {
        println!("fairness: {fairness}");
    }
    println!("proof engine: {}", metadata.proof_engine);
    println!("To verify independently:");
    println!(
        "  tarsier check-certificate {} --solvers z3,cvc5",
        out.display()
    );

    Ok(())
}

pub(crate) fn solver_name(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

/// Map an analysis layer result kind string to a canonical verdict.
pub(crate) fn canonical_verdict_from_layer_result(layer: &str, result: &str) -> CanonicalVerdict {
    match result {
        "safe" | "probabilistically_safe" => CanonicalVerdict::Safe,
        "unsafe" => CanonicalVerdict::Unsafe,
        "live" | "no_fair_cycle_up_to" | "live_proved" => CanonicalVerdict::LiveProved,
        "not_live" | "fair_cycle_found" => CanonicalVerdict::LiveCex,
        "not_proved" => CanonicalVerdict::Inconclusive,
        "unknown" => CanonicalVerdict::Unknown,
        // parse/comm layers use pass/fail/error
        "pass" => {
            if layer.contains("liveness") || layer.contains("fair") {
                CanonicalVerdict::LiveProved
            } else {
                CanonicalVerdict::Safe
            }
        }
        "fail" | "error" => CanonicalVerdict::Unknown,
        _ => CanonicalVerdict::Unknown,
    }
}

#[cfg(feature = "governance")]
pub(crate) fn sanitize_artifact_component(raw: &str) -> String {
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

/// V2-05: Return a vetted property template for the given kind.
/// Handler for the `committee` subcommand.
///
/// Performs committee selection analysis using hypergeometric probability.
pub(crate) fn run_committee_command(
    population: u64,
    byzantine: u64,
    size: u64,
    epsilon: f64,
) -> miette::Result<()> {
    let spec = tarsier_prob::CommitteeSpec {
        name: "committee".into(),
        population,
        byzantine,
        committee_size: size,
        epsilon,
    };

    let analysis =
        tarsier_prob::analyze_committee(&spec).map_err(|e| miette::miette!("Error: {e}"))?;
    println!("Committee Analysis:");
    println!("  Population: {} ({} Byzantine)", population, byzantine);
    println!("  Committee size: {}", size);
    println!("  Expected Byzantine: {:.1}", analysis.expected_byzantine);
    println!(
        "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
        analysis.b_max, epsilon
    );
    println!(
        "  Honest majority: {} of {}",
        analysis.honest_majority, size
    );
    Ok(())
}

/// Handler for the `assist` subcommand.
///
/// Generates protocol scaffolds or property templates.
pub(crate) fn run_assist_command(
    kind: String,
    out: Option<PathBuf>,
    properties: Option<String>,
) -> miette::Result<()> {
    // V2-05: Property template mode
    if let Some(ref prop_kind) = properties {
        let normalized = prop_kind.trim().to_lowercase();
        match property_template(&normalized) {
            Some(tmpl) => {
                println!("{tmpl}");
            }
            None => {
                return Err(miette::miette!(
                    "Unknown property template '{}'. Available: agreement, validity, termination, liveness, integrity",
                    prop_kind
                ));
            }
        }
    } else {
        let normalized = kind.trim().to_lowercase();
        let template = assistant_template(&normalized).ok_or_else(|| {
            miette::miette!(
                "Unknown scaffold kind '{}'. Use pbft | hotstuff | raft | tendermint | streamlet | casper.",
                kind
            )
        })?;

        if let Some(path) = out {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).into_diagnostic()?;
            }
            fs::write(&path, template).into_diagnostic()?;
            println!("Scaffold written to {}", path.display());
        } else {
            println!("{template}");
        }
    }
    Ok(())
}

/// V2-08: Build a governance artifact bundle.
/// V2-01: Write a certificate bundle without stdout output.
pub(crate) fn write_certificate_bundle_quiet(
    out: &PathBuf,
    cert: &CertificateBundleInput,
) -> miette::Result<()> {
    fs::create_dir_all(out).into_diagnostic()?;
    let metadata_file = out.join("certificate.json");

    let mut obligations = cert.obligations.clone();
    obligations.sort_by(|a, b| a.name.cmp(&b.name).then(a.expected.cmp(&b.expected)));

    let mut obligations_meta = Vec::new();
    for obligation in &obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = out.join(&file_name);
        let canonical_smt2 = canonicalize_obligation_smt2(&obligation.smt2);
        fs::write(&file_path, canonical_smt2).into_diagnostic()?;
        let hash = sha256_hex_file(&file_path).into_diagnostic()?;
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
            proof_file: None,
            proof_sha256: None,
        });
    }

    let mut committee_bounds = cert.committee_bounds.clone();
    committee_bounds.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: cert.kind.as_str().to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: cert.proof_engine.clone(),
        induction_k: cert.induction_k,
        solver_used: cert.solver_used.clone(),
        soundness: cert.soundness.clone(),
        fairness: cert.fairness.clone(),
        committee_bounds,
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
    let metadata_json = serde_json::to_string_pretty(&metadata).into_diagnostic()?;
    fs::write(&metadata_file, metadata_json).into_diagnostic()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
