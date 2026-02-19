use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Current certificate metadata schema version.
///
/// The trusted checker intentionally accepts exactly this version.
/// New schema versions must update this constant and checker logic together.
pub const CERTIFICATE_SCHEMA_VERSION: u32 = 2;

/// Documentation path for the certificate schema contract.
pub const CERTIFICATE_SCHEMA_DOC_PATH: &str = "docs/CERTIFICATE_SCHEMA.md";

const CERTIFICATE_HASH_DOMAIN_TAG: &str = "tarsier-certificate-v2\n";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateMetadata {
    pub schema_version: u32,
    pub kind: String,
    pub protocol_file: String,
    pub proof_engine: String,
    pub induction_k: Option<usize>,
    pub solver_used: String,
    pub soundness: String,
    #[serde(default)]
    pub fairness: Option<String>,
    pub committee_bounds: Vec<(String, u64)>,
    #[serde(default)]
    pub bundle_sha256: Option<String>,
    pub obligations: Vec<CertificateObligationMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateObligationMeta {
    pub name: String,
    pub expected: String,
    pub file: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleCheckIssue {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct BundleIntegrityReport {
    pub metadata: CertificateMetadata,
    pub issues: Vec<BundleCheckIssue>,
}

impl BundleIntegrityReport {
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum ProofKernelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid certificate metadata JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn metadata_path(bundle_dir: &Path) -> PathBuf {
    bundle_dir.join("certificate.json")
}

pub fn load_metadata(bundle_dir: &Path) -> Result<CertificateMetadata, ProofKernelError> {
    let metadata_file = metadata_path(bundle_dir);
    let metadata_text = fs::read_to_string(metadata_file)?;
    Ok(serde_json::from_str(&metadata_text)?)
}

pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn sha256_hex_file(path: &Path) -> Result<String, ProofKernelError> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex_bytes(&bytes))
}

pub fn compute_bundle_sha256(metadata: &CertificateMetadata) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CERTIFICATE_HASH_DOMAIN_TAG.as_bytes());
    hasher.update(metadata.kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata.protocol_file.as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata.proof_engine.as_bytes());
    hasher.update(b"\n");
    hasher.update(
        metadata
            .induction_k
            .map(|k| k.to_string())
            .unwrap_or_else(|| "none".to_string())
            .as_bytes(),
    );
    hasher.update(b"\n");
    hasher.update(metadata.solver_used.as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata.soundness.as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata.fairness.clone().unwrap_or_default().as_bytes());
    hasher.update(b"\n");
    for (name, bound) in &metadata.committee_bounds {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(bound.to_string().as_bytes());
        hasher.update(b"\n");
    }
    for obligation in &metadata.obligations {
        hasher.update(obligation.name.as_bytes());
        hasher.update(b"|");
        hasher.update(obligation.expected.as_bytes());
        hasher.update(b"|");
        hasher.update(obligation.file.as_bytes());
        hasher.update(b"|");
        hasher.update(obligation.sha256.clone().unwrap_or_default().as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn check_bundle_integrity(
    bundle_dir: &Path,
) -> Result<BundleIntegrityReport, ProofKernelError> {
    let metadata = load_metadata(bundle_dir)?;
    let mut issues: Vec<BundleCheckIssue> = Vec::new();
    let canonical_bundle_dir = fs::canonicalize(bundle_dir).unwrap_or_else(|_| bundle_dir.into());

    if metadata.schema_version != CERTIFICATE_SCHEMA_VERSION {
        issues.push(BundleCheckIssue {
            code: "schema_version",
            message: format!(
                "Unsupported certificate schema version {} (expected exactly {}). See {}.",
                metadata.schema_version, CERTIFICATE_SCHEMA_VERSION, CERTIFICATE_SCHEMA_DOC_PATH
            ),
        });
    }

    if metadata.obligations.is_empty() {
        issues.push(BundleCheckIssue {
            code: "empty_obligations",
            message: "Certificate contains no obligations.".into(),
        });
    }

    let expected_obligation_names = expected_obligation_names_for_profile(&metadata, &mut issues);

    let mut names = HashSet::new();
    let mut files = HashSet::new();

    for obligation in &metadata.obligations {
        if !names.insert(obligation.name.clone()) {
            issues.push(BundleCheckIssue {
                code: "duplicate_obligation_name",
                message: format!("Duplicate obligation name '{}'.", obligation.name),
            });
        }
        if !files.insert(obligation.file.clone()) {
            issues.push(BundleCheckIssue {
                code: "duplicate_obligation_file",
                message: format!("Duplicate obligation file '{}'.", obligation.file),
            });
        }

        if obligation.expected != "unsat"
            && obligation.expected != "sat"
            && obligation.expected != "unknown"
        {
            issues.push(BundleCheckIssue {
                code: "invalid_expected",
                message: format!(
                    "Obligation '{}' has unsupported expected result '{}'.",
                    obligation.name, obligation.expected
                ),
            });
        }

        if expected_obligation_names.is_some() && obligation.expected != "unsat" {
            issues.push(BundleCheckIssue {
                code: "invalid_expected_for_proof",
                message: format!(
                    "Obligation '{}' must have expected result 'unsat' for proof certificate replay.",
                    obligation.name
                ),
            });
        }

        if !is_safe_relative_path(&obligation.file) {
            issues.push(BundleCheckIssue {
                code: "unsafe_path",
                message: format!(
                    "Obligation '{}' uses unsafe path '{}'.",
                    obligation.name, obligation.file
                ),
            });
            continue;
        }

        let obligation_path = bundle_dir.join(&obligation.file);
        if !obligation_path.exists() {
            issues.push(BundleCheckIssue {
                code: "missing_file",
                message: format!(
                    "Obligation '{}' file does not exist: {}",
                    obligation.name,
                    obligation_path.display()
                ),
            });
            continue;
        }
        if obligation_path.extension().and_then(|s| s.to_str()) != Some("smt2") {
            issues.push(BundleCheckIssue {
                code: "invalid_obligation_extension",
                message: format!(
                    "Obligation '{}' file '{}' must use .smt2 extension.",
                    obligation.name, obligation.file
                ),
            });
        }
        if let Ok(canonical_obligation_path) = fs::canonicalize(&obligation_path) {
            if !canonical_obligation_path.starts_with(&canonical_bundle_dir) {
                issues.push(BundleCheckIssue {
                    code: "symlink_escape",
                    message: format!(
                        "Obligation '{}' resolves outside bundle directory: {}",
                        obligation.name,
                        canonical_obligation_path.display()
                    ),
                });
            }
        }

        if let Some(expected_hash) = &obligation.sha256 {
            let actual_hash = sha256_hex_file(&obligation_path)?;
            if actual_hash != *expected_hash {
                issues.push(BundleCheckIssue {
                    code: "obligation_hash_mismatch",
                    message: format!(
                        "Hash mismatch for obligation '{}' (expected {}, got {}).",
                        obligation.name, expected_hash, actual_hash
                    ),
                });
            }
        } else {
            issues.push(BundleCheckIssue {
                code: "missing_obligation_hash",
                message: format!("Obligation '{}' is missing a sha256 hash.", obligation.name),
            });
        }

        let script = fs::read_to_string(&obligation_path)?;
        let commands = extract_smt_commands(&script);
        let check_sat_count = commands
            .iter()
            .filter(|c| c.as_str() == "check-sat")
            .count();
        if check_sat_count != 1 {
            issues.push(BundleCheckIssue {
                code: "check_sat_count",
                message: format!(
                    "Obligation '{}' script must contain exactly one (check-sat), found {}.",
                    obligation.name, check_sat_count
                ),
            });
        }
        let exit_count = commands.iter().filter(|c| c.as_str() == "exit").count();
        if exit_count != 1 {
            issues.push(BundleCheckIssue {
                code: "exit_count",
                message: format!(
                    "Obligation '{}' script must contain exactly one (exit), found {}.",
                    obligation.name, exit_count
                ),
            });
        }
        if let (Some(check_sat_idx), Some(exit_idx)) = (
            commands.iter().position(|c| c == "check-sat"),
            commands.iter().position(|c| c == "exit"),
        ) {
            if check_sat_idx > exit_idx {
                issues.push(BundleCheckIssue {
                    code: "invalid_command_order",
                    message: format!(
                        "Obligation '{}' script has (check-sat) after (exit).",
                        obligation.name
                    ),
                });
            }
        }

        let assert_count = commands.iter().filter(|c| c.as_str() == "assert").count();
        if assert_count == 0 {
            issues.push(BundleCheckIssue {
                code: "missing_assert",
                message: format!(
                    "Obligation '{}' script has no (assert ...) commands.",
                    obligation.name
                ),
            });
        }

        let mut disallowed = VecDeque::new();
        for cmd in commands {
            if matches!(
                cmd.as_str(),
                "get-model"
                    | "get-value"
                    | "get-assignment"
                    | "get-unsat-core"
                    | "get-proof"
                    | "echo"
                    | "push"
                    | "pop"
                    | "reset"
                    | "reset-assertions"
            ) {
                disallowed.push_back(cmd);
            }
        }
        if !disallowed.is_empty() {
            issues.push(BundleCheckIssue {
                code: "disallowed_commands",
                message: format!(
                    "Obligation '{}' script uses disallowed SMT commands: {}.",
                    obligation.name,
                    disallowed.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    if let Some(expected_names) = expected_obligation_names {
        let present: BTreeSet<String> = metadata
            .obligations
            .iter()
            .map(|o| o.name.clone())
            .collect();
        for &required in expected_names {
            if !present.contains(required) {
                issues.push(BundleCheckIssue {
                    code: "missing_required_obligation",
                    message: format!(
                        "Missing required obligation '{}' for kind '{}' with engine '{}'.",
                        required, metadata.kind, metadata.proof_engine
                    ),
                });
            }
        }
        for name in &present {
            if !expected_names.contains(&name.as_str()) {
                issues.push(BundleCheckIssue {
                    code: "unexpected_obligation_name",
                    message: format!(
                        "Unexpected obligation '{}' for kind '{}' with engine '{}'.",
                        name, metadata.kind, metadata.proof_engine
                    ),
                });
            }
        }
    }

    match &metadata.bundle_sha256 {
        Some(expected_bundle_hash) => {
            let actual_bundle_hash = compute_bundle_sha256(&metadata);
            if actual_bundle_hash != *expected_bundle_hash {
                issues.push(BundleCheckIssue {
                    code: "bundle_hash_mismatch",
                    message: format!(
                        "Bundle hash mismatch (expected {}, got {}).",
                        expected_bundle_hash, actual_bundle_hash
                    ),
                });
            }
        }
        None => {
            issues.push(BundleCheckIssue {
                code: "missing_bundle_hash",
                message: "certificate.json is missing bundle_sha256.".into(),
            });
        }
    }

    Ok(BundleIntegrityReport { metadata, issues })
}

fn expected_obligation_names_for_profile(
    metadata: &CertificateMetadata,
    issues: &mut Vec<BundleCheckIssue>,
) -> Option<&'static [&'static str]> {
    let mut profile = None;
    match (metadata.kind.as_str(), metadata.proof_engine.as_str()) {
        ("safety_proof", "kinduction") => {
            profile = Some(&["base_case", "inductive_step"][..]);
        }
        ("safety_proof", "pdr") => {
            profile = Some(
                &[
                    "init_implies_inv",
                    "inv_and_transition_implies_inv_prime",
                    "inv_implies_safe",
                ][..],
            );
        }
        ("fair_liveness_proof", "pdr") => {
            profile = Some(
                &[
                    "init_implies_inv",
                    "inv_and_transition_implies_inv_prime",
                    "inv_implies_no_fair_bad",
                ][..],
            );
        }
        ("fair_liveness_proof", other_engine) => {
            issues.push(BundleCheckIssue {
                code: "invalid_proof_engine",
                message: format!(
                    "Unsupported proof engine '{}' for fair_liveness_proof (expected 'pdr').",
                    other_engine
                ),
            });
        }
        ("safety_proof", other_engine) => {
            issues.push(BundleCheckIssue {
                code: "invalid_proof_engine",
                message: format!(
                    "Unsupported proof engine '{}' for safety_proof (expected 'kinduction' or 'pdr').",
                    other_engine
                ),
            });
        }
        (other_kind, _) => {
            issues.push(BundleCheckIssue {
                code: "invalid_kind",
                message: format!(
                    "Unsupported certificate kind '{}' (expected 'safety_proof' or 'fair_liveness_proof').",
                    other_kind
                ),
            });
        }
    }

    if metadata.induction_k.is_none() {
        issues.push(BundleCheckIssue {
            code: "missing_induction_k",
            message: format!(
                "Certificate kind '{}' with engine '{}' requires induction_k/frame metadata.",
                metadata.kind, metadata.proof_engine
            ),
        });
    }

    match metadata.kind.as_str() {
        "safety_proof" => {
            if metadata.fairness.is_some() {
                issues.push(BundleCheckIssue {
                    code: "unexpected_fairness",
                    message: "Safety certificate must not set fairness.".into(),
                });
            }
        }
        "fair_liveness_proof" => match metadata.fairness.as_deref() {
            Some("weak") | Some("strong") => {}
            _ => issues.push(BundleCheckIssue {
                code: "missing_or_invalid_fairness",
                message: "Fair-liveness certificate must set fairness to 'weak' or 'strong'."
                    .into(),
            }),
        },
        _ => {}
    }

    profile
}

fn is_safe_relative_path(raw: &str) -> bool {
    if raw.trim().is_empty() {
        return false;
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return false;
    }
    path.components().all(|c| {
        !matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

fn extract_smt_commands(script: &str) -> Vec<String> {
    let bytes = script.as_bytes();
    let mut commands = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            while i < bytes.len()
                && !bytes[i].is_ascii_whitespace()
                && bytes[i] != b')'
                && bytes[i] != b'('
            {
                i += 1;
            }
            if start < i {
                commands.push(script[start..i].to_ascii_lowercase());
            }
        } else {
            i += 1;
        }
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        path.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
        path
    }

    fn write_valid_kinduction_bundle(bundle: &Path) -> CertificateMetadata {
        let base_file = "base_case.smt2";
        let step_file = "inductive_step.smt2";
        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        fs::write(bundle.join(base_file), script).expect("base obligation should be written");
        fs::write(bundle.join(step_file), script).expect("step obligation should be written");
        let hash = sha256_hex_bytes(script.as_bytes());

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![
                CertificateObligationMeta {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    file: base_file.into(),
                    sha256: Some(hash.clone()),
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(hash),
                },
            ],
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(bundle),
            serde_json::to_string_pretty(&metadata).expect("metadata should serialize"),
        )
        .expect("metadata should be written");
        metadata
    }

    #[test]
    fn bundle_hash_changes_when_obligation_hash_changes() {
        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("f".into(), 1)],
            bundle_sha256: None,
            obligations: vec![CertificateObligationMeta {
                name: "init_implies_inv".into(),
                expected: "unsat".into(),
                file: "init_implies_inv.smt2".into(),
                sha256: Some("abc".into()),
            }],
        };
        let a = compute_bundle_sha256(&metadata);
        metadata.obligations[0].sha256 = Some("def".into());
        let b = compute_bundle_sha256(&metadata);
        assert_ne!(a, b);
    }

    #[test]
    fn integrity_report_flags_unsafe_obligation_path() {
        let bundle = tmp_dir("tarsier_proof_kernel_unsafe_path");
        fs::create_dir_all(&bundle).unwrap();

        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: Some("deadbeef".into()),
            obligations: vec![CertificateObligationMeta {
                name: "bad".into(),
                expected: "unsat".into(),
                file: "../escape.smt2".into(),
                sha256: Some("abc".into()),
            }],
        };
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report.issues.iter().any(|i| i.code == "unsafe_path"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_passes_for_consistent_bundle() {
        let bundle = tmp_dir("tarsier_proof_kernel_ok");
        fs::create_dir_all(&bundle).unwrap();
        let _metadata = write_valid_kinduction_bundle(&bundle);

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(report.is_ok(), "unexpected issues: {:?}", report.issues);

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_tampered_obligation_content() {
        let bundle = tmp_dir("tarsier_proof_kernel_tampered_obligation");
        fs::create_dir_all(&bundle).unwrap();
        let metadata = write_valid_kinduction_bundle(&bundle);

        // Tamper with an obligation after metadata hashes were finalized.
        fs::write(
            bundle.join("inductive_step.smt2"),
            "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(exit)\n",
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "obligation_hash_mismatch"));
        assert_eq!(report.metadata.bundle_sha256, metadata.bundle_sha256);

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_tampered_metadata_bundle_hash() {
        let bundle = tmp_dir("tarsier_proof_kernel_tampered_metadata_hash");
        fs::create_dir_all(&bundle).unwrap();
        let mut metadata = write_valid_kinduction_bundle(&bundle);

        // Tamper with metadata bundle hash field.
        metadata.bundle_sha256 = Some("0".repeat(64));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "bundle_hash_mismatch"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_tampered_expected_result_field() {
        let bundle = tmp_dir("tarsier_proof_kernel_tampered_expected_result");
        fs::create_dir_all(&bundle).unwrap();
        let mut metadata = write_valid_kinduction_bundle(&bundle);

        // Tamper with expected replay result in metadata.
        metadata.obligations[0].expected = "sat".into();
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "invalid_expected_for_proof"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_disallowed_commands_and_bad_command_counts() {
        let bundle = tmp_dir("tarsier_proof_kernel_bad_cmds");
        fs::create_dir_all(&bundle).unwrap();

        let bad_script =
            "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(check-sat)\n(get-model)\n(exit)\n";
        let good_script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let base_file = "base_case.smt2";
        let step_file = "inductive_step.smt2";
        fs::write(bundle.join(base_file), bad_script).unwrap();
        fs::write(bundle.join(step_file), good_script).unwrap();
        let bad_hash = sha256_hex_bytes(bad_script.as_bytes());
        let good_hash = sha256_hex_bytes(good_script.as_bytes());

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![
                CertificateObligationMeta {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    file: base_file.into(),
                    sha256: Some(bad_hash),
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(good_hash),
                },
            ],
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report.issues.iter().any(|i| i.code == "check_sat_count"));
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "disallowed_commands"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_missing_required_obligation_profile() {
        let bundle = tmp_dir("tarsier_proof_kernel_missing_required_obligation");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let base_file = "base_case.smt2";
        fs::write(bundle.join(base_file), script).unwrap();
        let hash = sha256_hex_bytes(script.as_bytes());

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![CertificateObligationMeta {
                name: "base_case".into(),
                expected: "unsat".into(),
                file: base_file.into(),
                sha256: Some(hash),
            }],
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "missing_required_obligation"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_missing_liveness_fairness_metadata() {
        let bundle = tmp_dir("tarsier_proof_kernel_missing_liveness_fairness");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let o1_file = "init_implies_inv.smt2";
        let o2_file = "inv_and_transition_implies_inv_prime.smt2";
        let o3_file = "inv_implies_no_fair_bad.smt2";
        fs::write(bundle.join(o1_file), script).unwrap();
        fs::write(bundle.join(o2_file), script).unwrap();
        fs::write(bundle.join(o3_file), script).unwrap();
        let hash = sha256_hex_bytes(script.as_bytes());

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "fair_liveness_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(4),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![
                CertificateObligationMeta {
                    name: "init_implies_inv".into(),
                    expected: "unsat".into(),
                    file: o1_file.into(),
                    sha256: Some(hash.clone()),
                },
                CertificateObligationMeta {
                    name: "inv_and_transition_implies_inv_prime".into(),
                    expected: "unsat".into(),
                    file: o2_file.into(),
                    sha256: Some(hash.clone()),
                },
                CertificateObligationMeta {
                    name: "inv_implies_no_fair_bad".into(),
                    expected: "unsat".into(),
                    file: o3_file.into(),
                    sha256: Some(hash),
                },
            ],
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report
            .issues
            .iter()
            .any(|i| i.code == "missing_or_invalid_fairness"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_non_exact_schema_version() {
        let bundle = tmp_dir("tarsier_proof_kernel_schema_version");
        fs::create_dir_all(&bundle).unwrap();

        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION + 1,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: Some("deadbeef".into()),
            obligations: vec![],
        };
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(report.issues.iter().any(|i| i.code == "schema_version"));

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn load_metadata_rejects_unknown_top_level_fields() {
        let bundle = tmp_dir("tarsier_proof_kernel_unknown_fields");
        fs::create_dir_all(&bundle).unwrap();
        let raw = r#"
{
  "schema_version": 2,
  "kind": "safety_proof",
  "protocol_file": "protocol.trs",
  "proof_engine": "pdr",
  "induction_k": 3,
  "solver_used": "z3",
  "soundness": "strict",
  "committee_bounds": [],
  "bundle_sha256": "deadbeef",
  "obligations": [],
  "unexpected_field": "not_allowed"
}
"#;
        fs::write(metadata_path(&bundle), raw).unwrap();
        let err = load_metadata(&bundle).expect_err("unknown fields should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("unknown field"));

        fs::remove_dir_all(&bundle).ok();
    }
}
