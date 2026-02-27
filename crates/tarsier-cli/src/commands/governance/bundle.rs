// Governance bundle crypto, verification, and building.

use miette::IntoDiagnostic;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

use tarsier_proof_kernel::{check_bundle_integrity, sha256_hex_bytes, sha256_hex_file};

use crate::AnalysisReport;

use super::{
    CertificateReference, EnvironmentInfo, GovernanceArtifactReference, GovernanceBundle,
    GovernanceBundleSignature, GovernanceBundleVerificationCheck,
    GovernanceBundleVerificationReport,
};

pub(crate) fn governance_bundle_payload_json(
    bundle: &GovernanceBundle,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "schema_version": bundle.schema_version,
        "tarsier_version": bundle.tarsier_version,
        "environment": bundle.environment,
        "model_source_sha256": bundle.model_source_sha256,
        "analysis_report": bundle.analysis_report,
        "certificates": bundle.certificates,
        "artifacts": bundle.artifacts
    }))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let mut i = 0usize;
    while i < trimmed.len() {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at offset {i}"))?;
        bytes.push(byte);
        i += 2;
    }
    Ok(bytes)
}

pub(crate) fn sign_governance_bundle(
    bundle: &GovernanceBundle,
) -> miette::Result<GovernanceBundleSignature> {
    let payload = governance_bundle_payload_json(bundle).into_diagnostic()?;
    let payload_sha256 = sha256_hex_bytes(&payload);
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| miette::miette!("failed to generate governance signing key"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| miette::miette!("failed to parse governance signing key"))?;
    let sig = key_pair.sign(&payload);
    Ok(GovernanceBundleSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex_encode(key_pair.public_key().as_ref()),
        signature_hex: hex_encode(sig.as_ref()),
        signed_payload_sha256: payload_sha256,
    })
}

pub(crate) fn verify_governance_signature(bundle: &GovernanceBundle) -> Result<Value, String> {
    if bundle.signature.algorithm != "ed25519" {
        return Err(format!(
            "unsupported signature algorithm '{}'",
            bundle.signature.algorithm
        ));
    }
    let payload = governance_bundle_payload_json(bundle)
        .map_err(|e| format!("failed to serialize governance payload: {e}"))?;
    let payload_sha256 = sha256_hex_bytes(&payload);
    if payload_sha256 != bundle.signature.signed_payload_sha256 {
        return Err("signed_payload_sha256 mismatch".into());
    }
    let public_key = hex_decode(&bundle.signature.public_key_hex)?;
    let signature = hex_decode(&bundle.signature.signature_hex)?;
    let verifier = UnparsedPublicKey::new(&ED25519, &public_key);
    verifier
        .verify(&payload, &signature)
        .map_err(|_| "signature verification failed".to_string())?;
    Ok(json!({
        "algorithm": bundle.signature.algorithm,
        "signed_payload_sha256": bundle.signature.signed_payload_sha256,
        "public_key_len": public_key.len(),
        "signature_len": signature.len()
    }))
}

pub(crate) fn resolve_bundle_relative_path(bundle_file: &Path, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        bundle_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(p)
    }
}

pub(crate) fn verify_governance_schema(bundle: &GovernanceBundle) -> Result<Value, String> {
    if bundle.schema_version != "v1" {
        return Err(format!(
            "unsupported bundle schema_version '{}' (expected v1)",
            bundle.schema_version
        ));
    }
    if bundle.tarsier_version.trim().is_empty() {
        return Err("missing tarsier_version".into());
    }
    if bundle.model_source_sha256.trim().len() != 64 {
        return Err("model_source_sha256 must be 64 hex chars".into());
    }
    if !bundle.analysis_report.is_object() {
        return Err("analysis_report must be a JSON object".into());
    }
    for key in [
        "schema_version",
        "mode",
        "file",
        "layers",
        "overall",
        "overall_verdict",
    ] {
        if bundle.analysis_report.get(key).is_none() {
            return Err(format!("analysis_report missing required field '{key}'"));
        }
    }
    if bundle.signature.public_key_hex.trim().is_empty()
        || bundle.signature.signature_hex.trim().is_empty()
        || bundle.signature.signed_payload_sha256.trim().is_empty()
    {
        return Err("signature object missing required fields".into());
    }
    Ok(json!({
        "schema_version": bundle.schema_version,
        "analysis_report_fields_checked": ["schema_version", "mode", "file", "layers", "overall", "overall_verdict"]
    }))
}

pub(crate) fn verify_governance_completeness(
    bundle: &GovernanceBundle,
    bundle_file: &Path,
) -> Result<Value, String> {
    if bundle.artifacts.is_empty() {
        return Err("artifacts list must be non-empty".into());
    }

    let mut report_artifact_present = false;
    let mut checked_artifacts = 0usize;
    for artifact in &bundle.artifacts {
        if artifact.name == "analysis_report" && artifact.kind == "report" {
            report_artifact_present = true;
        }
        let artifact_path = resolve_bundle_relative_path(bundle_file, &artifact.path);
        if !artifact_path.exists() {
            return Err(format!(
                "artifact '{}' missing at {}",
                artifact.name,
                artifact_path.display()
            ));
        }
        let actual_sha = sha256_hex_file(&artifact_path)
            .map_err(|e| format!("failed hashing artifact '{}': {e}", artifact.name))?;
        if !actual_sha.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(format!(
                "artifact '{}' hash mismatch (expected {}, got {})",
                artifact.name, artifact.sha256, actual_sha
            ));
        }
        checked_artifacts += 1;
    }
    if !report_artifact_present {
        return Err("artifacts list missing required analysis_report artifact".into());
    }

    let mut checked_certificates = 0usize;
    for cert in &bundle.certificates {
        if cert.bundle_dir.trim().is_empty() {
            continue;
        }
        let bundle_dir = resolve_bundle_relative_path(bundle_file, &cert.bundle_dir);
        if !bundle_dir.exists() {
            return Err(format!(
                "certificate bundle directory missing: {}",
                bundle_dir.display()
            ));
        }
        let integrity = check_bundle_integrity(&bundle_dir).map_err(|e| {
            format!(
                "bundle integrity check failed for {}: {e}",
                bundle_dir.display()
            )
        })?;
        if !integrity.issues.is_empty() {
            let first = &integrity.issues[0].message;
            return Err(format!(
                "certificate integrity failed for {}: {}",
                bundle_dir.display(),
                first
            ));
        }
        checked_certificates += 1;
    }

    Ok(json!({
        "checked_artifacts": checked_artifacts,
        "checked_certificate_bundles": checked_certificates,
        "report_artifact_present": report_artifact_present
    }))
}

pub(crate) fn verify_governance_bundle(bundle_path: &Path) -> GovernanceBundleVerificationReport {
    let mut checks = Vec::new();
    let bundle_path_display = bundle_path.display().to_string();

    let raw = match fs::read_to_string(bundle_path) {
        Ok(raw) => raw,
        Err(e) => {
            checks.push(GovernanceBundleVerificationCheck {
                check: "load_bundle".into(),
                status: "fail".into(),
                details: json!({}),
                error: Some(format!("failed to read bundle: {e}")),
            });
            return GovernanceBundleVerificationReport {
                schema_version: "v1".into(),
                bundle: bundle_path_display,
                overall: "fail".into(),
                checks,
            };
        }
    };

    let bundle: GovernanceBundle = match serde_json::from_str(&raw) {
        Ok(bundle) => bundle,
        Err(e) => {
            checks.push(GovernanceBundleVerificationCheck {
                check: "parse_bundle".into(),
                status: "fail".into(),
                details: json!({}),
                error: Some(format!("invalid governance bundle JSON: {e}")),
            });
            return GovernanceBundleVerificationReport {
                schema_version: "v1".into(),
                bundle: bundle_path_display,
                overall: "fail".into(),
                checks,
            };
        }
    };

    match verify_governance_schema(&bundle) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "schema".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "schema".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }
    match verify_governance_signature(&bundle) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "signature".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "signature".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }
    match verify_governance_completeness(&bundle, bundle_path) {
        Ok(details) => checks.push(GovernanceBundleVerificationCheck {
            check: "completeness".into(),
            status: "pass".into(),
            details,
            error: None,
        }),
        Err(err) => checks.push(GovernanceBundleVerificationCheck {
            check: "completeness".into(),
            status: "fail".into(),
            details: json!({}),
            error: Some(err),
        }),
    }

    let overall = if checks.iter().all(|c| c.status == "pass") {
        "pass"
    } else {
        "fail"
    };
    GovernanceBundleVerificationReport {
        schema_version: "v1".into(),
        bundle: bundle_path_display,
        overall: overall.to_string(),
        checks,
    }
}

/// V2-08: Build a governance artifact bundle.
pub(crate) fn build_governance_bundle(
    report: &AnalysisReport,
    source: &str,
    report_path: &Path,
    report_json: &str,
) -> miette::Result<GovernanceBundle> {
    let report_value = serde_json::to_value(report).unwrap_or_else(|_| json!({}));

    // Extract certificate references from cert layers
    let mut certificates = Vec::new();
    let mut artifacts = Vec::new();
    let report_sha256 = sha256_hex_bytes(report_json.as_bytes());
    artifacts.push(GovernanceArtifactReference {
        name: "analysis_report".to_string(),
        kind: "report".to_string(),
        path: report_path.display().to_string(),
        sha256: report_sha256,
    });

    for layer in &report.layers {
        if layer.layer.starts_with("certify[") {
            let kind = if layer.layer.contains("safety") {
                "safety"
            } else {
                "fair_liveness"
            };
            let bundle_dir = layer
                .details
                .get("bundle_dir")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let integrity_ok = layer
                .details
                .get("integrity_ok")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // Try to read bundle SHA from certificate.json
            let bundle_sha256 = if !bundle_dir.is_empty() {
                let cert_path = Path::new(&bundle_dir).join("certificate.json");
                if cert_path.exists() {
                    let cert_hash = sha256_hex_file(&cert_path).ok();
                    if let Some(hash) = cert_hash {
                        artifacts.push(GovernanceArtifactReference {
                            name: format!("certificate_{kind}"),
                            kind: "certificate".to_string(),
                            path: cert_path.display().to_string(),
                            sha256: hash,
                        });
                    }
                }
                std::fs::read_to_string(&cert_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| {
                        v.get("bundle_sha256")
                            .and_then(Value::as_str)
                            .map(String::from)
                    })
            } else {
                None
            };
            certificates.push(CertificateReference {
                kind: kind.to_string(),
                bundle_dir,
                bundle_sha256,
                integrity_ok,
            });
        }
    }

    let mut bundle = GovernanceBundle {
        schema_version: "v1".to_string(),
        tarsier_version: env!("CARGO_PKG_VERSION").to_string(),
        environment: EnvironmentInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        },
        model_source_sha256: sha256_hex_bytes(source.as_bytes()),
        analysis_report: report_value,
        certificates,
        artifacts,
        signature: GovernanceBundleSignature {
            algorithm: "ed25519".to_string(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            signed_payload_sha256: String::new(),
        },
    };
    bundle.signature = sign_governance_bundle(&bundle)?;
    Ok(bundle)
}
