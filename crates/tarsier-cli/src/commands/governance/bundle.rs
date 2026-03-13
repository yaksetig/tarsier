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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- hex_encode --

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_known_bytes() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
    }

    #[test]
    fn hex_encode_single() {
        assert_eq!(hex_encode(&[0x42]), "42");
    }

    // -- hex_decode --

    #[test]
    fn hex_decode_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_known_bytes() {
        assert_eq!(hex_decode("00ffab").unwrap(), vec![0x00, 0xff, 0xab]);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn hex_decode_with_whitespace() {
        assert_eq!(hex_decode("  00ff  ").unwrap(), vec![0x00, 0xff]);
    }

    // -- hex round-trip --

    #[test]
    fn hex_round_trip() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let encoded = hex_encode(&bytes);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }

    // -- resolve_bundle_relative_path --

    #[test]
    fn resolve_relative_path() {
        let path = resolve_bundle_relative_path(
            Path::new("/home/user/bundle.json"),
            "artifacts/report.json",
        );
        assert_eq!(path, PathBuf::from("/home/user/artifacts/report.json"));
    }

    #[test]
    fn resolve_absolute_path() {
        let path = resolve_bundle_relative_path(
            Path::new("/home/user/bundle.json"),
            "/absolute/report.json",
        );
        assert_eq!(path, PathBuf::from("/absolute/report.json"));
    }

    // -- verify_governance_schema --

    fn make_test_bundle() -> GovernanceBundle {
        GovernanceBundle {
            schema_version: "v1".into(),
            tarsier_version: "0.1.0".into(),
            environment: EnvironmentInfo {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            model_source_sha256: "a".repeat(64),
            analysis_report: json!({
                "schema_version": "v1",
                "mode": "quick",
                "file": "x.trs",
                "layers": [],
                "overall": "pass",
                "overall_verdict": "SAFE"
            }),
            certificates: vec![],
            artifacts: vec![],
            signature: GovernanceBundleSignature {
                algorithm: "ed25519".into(),
                public_key_hex: "abcd".into(),
                signature_hex: "1234".into(),
                signed_payload_sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn verify_schema_valid() {
        let bundle = make_test_bundle();
        assert!(verify_governance_schema(&bundle).is_ok());
    }

    #[test]
    fn verify_schema_wrong_version() {
        let mut bundle = make_test_bundle();
        bundle.schema_version = "v2".into();
        assert!(verify_governance_schema(&bundle).is_err());
    }

    #[test]
    fn verify_schema_empty_tarsier_version() {
        let mut bundle = make_test_bundle();
        bundle.tarsier_version = "".into();
        assert!(verify_governance_schema(&bundle).is_err());
    }

    #[test]
    fn verify_schema_bad_sha() {
        let mut bundle = make_test_bundle();
        bundle.model_source_sha256 = "short".into();
        assert!(verify_governance_schema(&bundle).is_err());
    }

    #[test]
    fn verify_schema_missing_analysis_field() {
        let mut bundle = make_test_bundle();
        bundle.analysis_report = json!({"schema_version": "v1"});
        assert!(verify_governance_schema(&bundle).is_err());
    }

    #[test]
    fn verify_schema_non_object_analysis() {
        let mut bundle = make_test_bundle();
        bundle.analysis_report = json!("string");
        assert!(verify_governance_schema(&bundle).is_err());
    }

    #[test]
    fn verify_schema_empty_signature_fields() {
        let mut bundle = make_test_bundle();
        bundle.signature.public_key_hex = "".into();
        assert!(verify_governance_schema(&bundle).is_err());
    }

    // -- verify_governance_completeness --

    #[test]
    fn verify_completeness_empty_artifacts() {
        let bundle = make_test_bundle();
        let result = verify_governance_completeness(&bundle, Path::new("/tmp/bundle.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-empty"));
    }

    // -- verify_governance_signature --

    #[test]
    fn verify_signature_unsupported_algorithm() {
        let mut bundle = make_test_bundle();
        bundle.signature.algorithm = "rsa".into();
        assert!(verify_governance_signature(&bundle).is_err());
    }

    // -- governance_bundle_payload_json --

    #[test]
    fn payload_json_excludes_signature() {
        let bundle = make_test_bundle();
        let payload = governance_bundle_payload_json(&bundle).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(!parsed.as_object().unwrap().contains_key("signature"));
    }

    #[test]
    fn payload_json_includes_required_fields() {
        let bundle = make_test_bundle();
        let payload = governance_bundle_payload_json(&bundle).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let obj = parsed.as_object().unwrap();
        assert!(obj.contains_key("schema_version"));
        assert!(obj.contains_key("tarsier_version"));
        assert!(obj.contains_key("environment"));
        assert!(obj.contains_key("model_source_sha256"));
        assert!(obj.contains_key("analysis_report"));
        assert!(obj.contains_key("certificates"));
        assert!(obj.contains_key("artifacts"));
    }
}
