#![doc = include_str!("../README.md")]

//! Minimal trusted proof kernel for Tarsier verification certificates.
//!
//! This crate validates proof certificates produced by the verification engine.
//! It is intentionally kept small (4 dependencies) so that it can be audited
//! independently and used for multi-solver certificate replay.

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

/// Certificate bundle metadata loaded from `certificate.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateMetadata {
    /// Schema version for compatibility checks.
    pub schema_version: u32,
    /// Certificate kind (for example `safety_proof` or `fair_liveness_proof`).
    pub kind: String,
    /// Source protocol path recorded by the producer.
    pub protocol_file: String,
    /// Proof engine used by the producer.
    pub proof_engine: String,
    /// Induction bound `k` for bounded/inductive proofs, if applicable.
    pub induction_k: Option<usize>,
    /// Solver identifier string recorded by the producer.
    pub solver_used: String,
    /// Soundness mode (`strict`, `faithful`, ...).
    pub soundness: String,
    /// Fairness mode for fair-liveness certificates.
    #[serde(default)]
    pub fairness: Option<String>,
    /// Concrete committee bounds injected during proof generation.
    pub committee_bounds: Vec<(String, u64)>,
    /// Integrity hash of the canonicalized metadata payload.
    #[serde(default)]
    pub bundle_sha256: Option<String>,
    /// SMT obligations and expected solver outcomes.
    pub obligations: Vec<CertificateObligationMeta>,
}

/// Metadata describing one SMT obligation file in a certificate bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateObligationMeta {
    /// Logical obligation identifier.
    pub name: String,
    /// Expected solver result (`unsat`, `sat`, or `unknown`).
    pub expected: String,
    /// Relative path to the SMT-LIB obligation file.
    pub file: String,
    /// Optional SHA-256 hash of the SMT-LIB file.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Path to the solver proof object file (relative to bundle directory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_file: Option<String>,
    /// SHA-256 hash of the proof object file contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_sha256: Option<String>,
}

/// One integrity-check issue emitted by the proof kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleCheckIssue {
    /// Stable machine-readable issue code.
    pub code: &'static str,
    /// Human-readable issue details.
    pub message: String,
}

/// Full integrity-check report for one certificate bundle.
#[derive(Debug, Clone)]
pub struct BundleIntegrityReport {
    /// Parsed certificate metadata.
    pub metadata: CertificateMetadata,
    /// All issues found during validation.
    pub issues: Vec<BundleCheckIssue>,
}

impl BundleIntegrityReport {
    /// Return `true` when no integrity issues were found.
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

/// Return the canonical metadata file path for a bundle directory.
///
/// # Parameters
/// - `bundle_dir`: Root directory of a certificate bundle.
///
/// # Returns
/// The expected path to `certificate.json` under `bundle_dir`.
pub fn metadata_path(bundle_dir: &Path) -> PathBuf {
    bundle_dir.join("certificate.json")
}

/// Load and deserialize certificate metadata from disk.
///
/// # Parameters
/// - `bundle_dir`: Root directory of a certificate bundle.
///
/// # Returns
/// Parsed [`CertificateMetadata`] or an I/O/JSON decoding error.
pub fn load_metadata(bundle_dir: &Path) -> Result<CertificateMetadata, ProofKernelError> {
    let metadata_file = metadata_path(bundle_dir);
    let metadata_text = fs::read_to_string(metadata_file)?;
    Ok(serde_json::from_str(&metadata_text)?)
}

/// Compute a lowercase hexadecimal SHA-256 digest for raw bytes.
///
/// # Parameters
/// - `bytes`: Input payload.
///
/// # Returns
/// 64-character lowercase hex digest.
pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compute a lowercase hexadecimal SHA-256 digest for a file.
///
/// # Parameters
/// - `path`: File path to hash.
///
/// # Returns
/// 64-character lowercase hex digest, or an I/O error.
pub fn sha256_hex_file(path: &Path) -> Result<String, ProofKernelError> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex_bytes(&bytes))
}

/// Compute the canonical bundle hash over normalized certificate metadata fields.
///
/// # Parameters
/// - `metadata`: Parsed metadata payload.
///
/// # Returns
/// Deterministic lowercase SHA-256 digest for tamper detection.
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
        hasher.update(b"|");
        hasher.update(obligation.proof_file.clone().unwrap_or_default().as_bytes());
        hasher.update(b"|");
        hasher.update(
            obligation
                .proof_sha256
                .clone()
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Validate structural and cryptographic integrity of a certificate bundle.
///
/// # Parameters
/// - `bundle_dir`: Root directory containing `certificate.json` and obligation files.
///
/// # Returns
/// [`BundleIntegrityReport`] with all discovered issues, or load/decode errors.
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

        // Validate proof file if proof metadata is present.
        if let Some(proof_file_name) = &obligation.proof_file {
            if !is_safe_relative_path(proof_file_name) {
                issues.push(BundleCheckIssue {
                    code: "unsafe_proof_path",
                    message: format!(
                        "Obligation '{}' uses unsafe proof path '{}'.",
                        obligation.name, proof_file_name
                    ),
                });
            } else {
                let proof_path = bundle_dir.join(proof_file_name);
                if !proof_path.exists() {
                    issues.push(BundleCheckIssue {
                        code: "missing_proof_file",
                        message: format!(
                            "Obligation '{}' proof file does not exist: {}",
                            obligation.name,
                            proof_path.display()
                        ),
                    });
                } else if let Some(expected_proof_hash) = &obligation.proof_sha256 {
                    let actual_proof_hash = sha256_hex_file(&proof_path)?;
                    if actual_proof_hash != *expected_proof_hash {
                        issues.push(BundleCheckIssue {
                            code: "proof_hash_mismatch",
                            message: format!(
                                "Proof hash mismatch for obligation '{}' (expected {}, got {}).",
                                obligation.name, expected_proof_hash, actual_proof_hash
                            ),
                        });
                    }
                } else {
                    issues.push(BundleCheckIssue {
                        code: "missing_proof_hash",
                        message: format!(
                            "Obligation '{}' has proof_file but no proof_sha256.",
                            obligation.name
                        ),
                    });
                }
            }
        } else if obligation.proof_sha256.is_some() {
            issues.push(BundleCheckIssue {
                code: "orphan_proof_hash",
                message: format!(
                    "Obligation '{}' has proof_sha256 but no proof_file.",
                    obligation.name
                ),
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

/// Named governance profiles for certificate checking rigor.
///
/// Each profile sets floor requirements; explicit CLI flags can only strengthen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceProfile {
    /// Single-solver replay with minimal proof-object requirements.
    Standard,
    /// Multi-solver replay with proof-object emission required.
    Reinforced,
    /// Reinforced profile plus external proof-checker requirements.
    HighAssurance,
}

/// Requirements imposed by a governance profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRequirements {
    /// Minimum number of independent solvers required for replay.
    pub min_solvers: usize,
    /// Whether proof-object files must be present.
    pub require_proofs: bool,
    /// Whether an external proof checker binary must be configured.
    pub require_proof_checker: bool,
    /// Whether foundational proof-object path constraints are required.
    pub require_foundational_proof_path: bool,
}

impl GovernanceProfile {
    /// Resolve the minimum requirements for this profile.
    ///
    /// # Returns
    /// Profile floor settings that callers may strengthen but not weaken.
    pub fn requirements(&self) -> ProfileRequirements {
        match self {
            GovernanceProfile::Standard => ProfileRequirements {
                min_solvers: 1,
                require_proofs: false,
                require_proof_checker: false,
                require_foundational_proof_path: false,
            },
            GovernanceProfile::Reinforced => ProfileRequirements {
                min_solvers: 2,
                require_proofs: true,
                require_proof_checker: false,
                require_foundational_proof_path: false,
            },
            GovernanceProfile::HighAssurance => ProfileRequirements {
                min_solvers: 2,
                require_proofs: true,
                require_proof_checker: true,
                require_foundational_proof_path: true,
            },
        }
    }
}

impl std::fmt::Display for GovernanceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovernanceProfile::Standard => write!(f, "standard"),
            GovernanceProfile::Reinforced => write!(f, "reinforced"),
            GovernanceProfile::HighAssurance => write!(f, "high-assurance"),
        }
    }
}

impl std::str::FromStr for GovernanceProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(GovernanceProfile::Standard),
            "reinforced" => Ok(GovernanceProfile::Reinforced),
            "high-assurance" => Ok(GovernanceProfile::HighAssurance),
            other => Err(format!(
                "unknown governance profile '{}' (expected standard, reinforced, or high-assurance)",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
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
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(hash),
                    proof_file: None,
                    proof_sha256: None,
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
                proof_file: None,
                proof_sha256: None,
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
                proof_file: None,
                proof_sha256: None,
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
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(good_hash),
                    proof_file: None,
                    proof_sha256: None,
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
                proof_file: None,
                proof_sha256: None,
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
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inv_and_transition_implies_inv_prime".into(),
                    expected: "unsat".into(),
                    file: o2_file.into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inv_implies_no_fair_bad".into(),
                    expected: "unsat".into(),
                    file: o3_file.into(),
                    sha256: Some(hash),
                    proof_file: None,
                    proof_sha256: None,
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

    // --- Obligation completeness: cross-kind rejection ---

    #[test]
    fn integrity_report_rejects_safety_obligations_used_as_liveness() {
        let bundle = tmp_dir("tarsier_proof_kernel_safety_as_liveness");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let files = [
            "init_implies_inv.smt2",
            "inv_and_transition_implies_inv_prime.smt2",
            "inv_implies_safe.smt2",
        ];
        let hash = sha256_hex_bytes(script.as_bytes());
        for f in &files {
            fs::write(bundle.join(f), script).unwrap();
        }

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "fair_liveness_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(4),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: Some("weak".into()),
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: files
                .iter()
                .map(|f| CertificateObligationMeta {
                    name: f.trim_end_matches(".smt2").into(),
                    expected: "unsat".into(),
                    file: (*f).into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                })
                .collect(),
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "unexpected_obligation_name"),
            "expected unexpected_obligation_name for inv_implies_safe under liveness"
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "missing_required_obligation"),
            "expected missing_required_obligation for inv_implies_no_fair_bad"
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_liveness_obligations_used_as_safety() {
        let bundle = tmp_dir("tarsier_proof_kernel_liveness_as_safety");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let files = [
            "init_implies_inv.smt2",
            "inv_and_transition_implies_inv_prime.smt2",
            "inv_implies_no_fair_bad.smt2",
        ];
        let hash = sha256_hex_bytes(script.as_bytes());
        for f in &files {
            fs::write(bundle.join(f), script).unwrap();
        }

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: files
                .iter()
                .map(|f| CertificateObligationMeta {
                    name: f.trim_end_matches(".smt2").into(),
                    expected: "unsat".into(),
                    file: (*f).into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                })
                .collect(),
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "unexpected_obligation_name"),
            "expected unexpected_obligation_name for inv_implies_no_fair_bad under safety"
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "missing_required_obligation"),
            "expected missing_required_obligation for inv_implies_safe"
        );

        fs::remove_dir_all(&bundle).ok();
    }

    // --- Tamper-negative tests ---

    #[test]
    fn integrity_report_rejects_extra_obligation_injected() {
        let bundle = tmp_dir("tarsier_proof_kernel_extra_obligation");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let hash = sha256_hex_bytes(script.as_bytes());
        let base_file = "base_case.smt2";
        let step_file = "inductive_step.smt2";
        let extra_file = "smuggled.smt2";
        fs::write(bundle.join(base_file), script).unwrap();
        fs::write(bundle.join(step_file), script).unwrap();
        fs::write(bundle.join(extra_file), script).unwrap();

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
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "smuggled".into(),
                    expected: "unsat".into(),
                    file: extra_file.into(),
                    sha256: Some(hash),
                    proof_file: None,
                    proof_sha256: None,
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
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "unexpected_obligation_name" && i.message.contains("smuggled")),
            "expected unexpected_obligation_name for injected obligation"
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_kind_mutation_with_rehash() {
        let bundle = tmp_dir("tarsier_proof_kernel_kind_mutation");
        fs::create_dir_all(&bundle).unwrap();

        // Build a valid kinduction bundle, then mutate kind to pdr and rehash.
        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let hash = sha256_hex_bytes(script.as_bytes());
        fs::write(bundle.join("base_case.smt2"), script).unwrap();
        fs::write(bundle.join("inductive_step.smt2"), script).unwrap();

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(), // mutated from kinduction to pdr
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
                    file: "base_case.smt2".into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: "inductive_step.smt2".into(),
                    sha256: Some(hash),
                    proof_file: None,
                    proof_sha256: None,
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
        // With pdr engine, the expected obligations are different (init/inv/safe).
        // base_case and inductive_step are unexpected for pdr.
        let codes: Vec<&str> = report.issues.iter().map(|i| i.code).collect();
        assert!(
            codes.contains(&"unexpected_obligation_name")
                || codes.contains(&"missing_required_obligation"),
            "kind mutation should be detected via obligation profile mismatch, got: {:?}",
            codes
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_rejects_proof_engine_mutation() {
        let bundle = tmp_dir("tarsier_proof_kernel_engine_mutation");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let hash = sha256_hex_bytes(script.as_bytes());
        let files = [
            "init_implies_inv.smt2",
            "inv_and_transition_implies_inv_prime.smt2",
            "inv_implies_safe.smt2",
        ];
        for f in &files {
            fs::write(bundle.join(f), script).unwrap();
        }

        let mut metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "kinduction".into(), // mutated: pdr obligations with kinduction engine
            induction_k: Some(3),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: files
                .iter()
                .map(|f| CertificateObligationMeta {
                    name: f.trim_end_matches(".smt2").into(),
                    expected: "unsat".into(),
                    file: (*f).into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: None,
                })
                .collect(),
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(&bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        // kinduction expects base_case + inductive_step, not pdr obligations
        let codes: Vec<&str> = report.issues.iter().map(|i| i.code).collect();
        assert!(
            codes.contains(&"unexpected_obligation_name")
                || codes.contains(&"missing_required_obligation"),
            "engine mutation should be detected via obligation profile mismatch, got: {:?}",
            codes
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn bundle_hash_covers_solver_used_field() {
        let make = |solver: &str| {
            let mut metadata = CertificateMetadata {
                schema_version: CERTIFICATE_SCHEMA_VERSION,
                kind: "safety_proof".into(),
                protocol_file: "protocol.trs".into(),
                proof_engine: "kinduction".into(),
                induction_k: Some(2),
                solver_used: solver.into(),
                soundness: "strict".into(),
                fairness: None,
                committee_bounds: vec![],
                bundle_sha256: None,
                obligations: vec![CertificateObligationMeta {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    file: "base_case.smt2".into(),
                    sha256: Some("abc".into()),
                    proof_file: None,
                    proof_sha256: None,
                }],
            };
            metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
            metadata.bundle_sha256.unwrap()
        };
        assert_ne!(make("z3"), make("cvc5"));
    }

    #[test]
    fn bundle_hash_covers_committee_bounds() {
        let make = |bounds: Vec<(String, u64)>| {
            let metadata = CertificateMetadata {
                schema_version: CERTIFICATE_SCHEMA_VERSION,
                kind: "safety_proof".into(),
                protocol_file: "protocol.trs".into(),
                proof_engine: "kinduction".into(),
                induction_k: Some(2),
                solver_used: "z3".into(),
                soundness: "strict".into(),
                fairness: None,
                committee_bounds: bounds,
                bundle_sha256: None,
                obligations: vec![CertificateObligationMeta {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    file: "base_case.smt2".into(),
                    sha256: Some("abc".into()),
                    proof_file: None,
                    proof_sha256: None,
                }],
            };
            compute_bundle_sha256(&metadata)
        };
        let h1 = make(vec![("f".into(), 1)]);
        let h2 = make(vec![("f".into(), 2)]);
        let h3 = make(vec![("g".into(), 1)]);
        let h4 = make(vec![]);
        assert_ne!(
            h1, h2,
            "different bound values must produce different hashes"
        );
        assert_ne!(
            h1, h3,
            "different bound names must produce different hashes"
        );
        assert_ne!(
            h1, h4,
            "present vs absent bounds must produce different hashes"
        );
    }

    // --- Governance profile tests ---

    #[test]
    fn governance_profile_requirements_are_consistent() {
        let std = GovernanceProfile::Standard.requirements();
        assert_eq!(std.min_solvers, 1);
        assert!(!std.require_proofs);
        assert!(!std.require_proof_checker);
        assert!(!std.require_foundational_proof_path);

        let reinforced = GovernanceProfile::Reinforced.requirements();
        assert_eq!(reinforced.min_solvers, 2);
        assert!(reinforced.require_proofs);
        assert!(!reinforced.require_proof_checker);
        assert!(!reinforced.require_foundational_proof_path);

        let high = GovernanceProfile::HighAssurance.requirements();
        assert_eq!(high.min_solvers, 2);
        assert!(high.require_proofs);
        assert!(high.require_proof_checker);
        assert!(high.require_foundational_proof_path);
    }

    #[test]
    fn governance_profile_from_str_roundtrip() {
        for name in &["standard", "reinforced", "high-assurance"] {
            let profile: GovernanceProfile = name.parse().unwrap();
            assert_eq!(&profile.to_string(), *name);
        }
        assert!(
            "invalid".parse::<GovernanceProfile>().is_err(),
            "invalid profile name should be rejected"
        );
    }

    // --- Proof object binding tests ---

    fn write_valid_bundle_with_proofs(bundle: &Path) -> CertificateMetadata {
        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        let proof = "unsat\n(proof\n  (step1 :rule resolution)\n)\n";
        let base_file = "base_case.smt2";
        let step_file = "inductive_step.smt2";
        let base_proof_file = "base_case.proof";
        let step_proof_file = "inductive_step.proof";
        fs::write(bundle.join(base_file), script).unwrap();
        fs::write(bundle.join(step_file), script).unwrap();
        fs::write(bundle.join(base_proof_file), proof).unwrap();
        fs::write(bundle.join(step_proof_file), proof).unwrap();
        let hash = sha256_hex_bytes(script.as_bytes());
        let proof_hash = sha256_hex_bytes(proof.as_bytes());

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
                    proof_file: Some(base_proof_file.into()),
                    proof_sha256: Some(proof_hash.clone()),
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: step_file.into(),
                    sha256: Some(hash),
                    proof_file: Some(step_proof_file.into()),
                    proof_sha256: Some(proof_hash),
                },
            ],
        };
        metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));
        fs::write(
            metadata_path(bundle),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();
        metadata
    }

    #[test]
    fn integrity_report_passes_for_bundle_with_proofs() {
        let bundle = tmp_dir("tarsier_proof_kernel_with_proofs_ok");
        fs::create_dir_all(&bundle).unwrap();
        let _metadata = write_valid_bundle_with_proofs(&bundle);

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(report.is_ok(), "unexpected issues: {:?}", report.issues);

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_tampered_proof_content() {
        let bundle = tmp_dir("tarsier_proof_kernel_tampered_proof");
        fs::create_dir_all(&bundle).unwrap();
        let _metadata = write_valid_bundle_with_proofs(&bundle);

        // Tamper with a proof file after metadata hashes were finalized.
        fs::write(
            bundle.join("base_case.proof"),
            "unsat\n(proof\n  (tampered_step)\n)\n",
        )
        .unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "proof_hash_mismatch"),
            "expected proof_hash_mismatch issue, got: {:?}",
            report.issues
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_missing_proof_file() {
        let bundle = tmp_dir("tarsier_proof_kernel_missing_proof_file");
        fs::create_dir_all(&bundle).unwrap();
        let _metadata = write_valid_bundle_with_proofs(&bundle);

        // Delete a proof file.
        fs::remove_file(bundle.join("inductive_step.proof")).unwrap();

        let report = check_bundle_integrity(&bundle).unwrap();
        assert!(!report.is_ok());
        assert!(
            report.issues.iter().any(|i| i.code == "missing_proof_file"),
            "expected missing_proof_file issue, got: {:?}",
            report.issues
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn integrity_report_flags_orphan_proof_hash() {
        let bundle = tmp_dir("tarsier_proof_kernel_orphan_proof_hash");
        fs::create_dir_all(&bundle).unwrap();

        let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
        fs::write(bundle.join("base_case.smt2"), script).unwrap();
        fs::write(bundle.join("inductive_step.smt2"), script).unwrap();
        let hash = sha256_hex_bytes(script.as_bytes());

        // Has proof_sha256 but no proof_file — orphan.
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
                    file: "base_case.smt2".into(),
                    sha256: Some(hash.clone()),
                    proof_file: None,
                    proof_sha256: Some("deadbeef".into()),
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: "inductive_step.smt2".into(),
                    sha256: Some(hash),
                    proof_file: None,
                    proof_sha256: None,
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
        assert!(
            report.issues.iter().any(|i| i.code == "orphan_proof_hash"),
            "expected orphan_proof_hash issue, got: {:?}",
            report.issues
        );

        fs::remove_dir_all(&bundle).ok();
    }

    #[test]
    fn bundle_hash_covers_proof_metadata() {
        let make = |proof_file: Option<&str>, proof_sha256: Option<&str>| {
            let metadata = CertificateMetadata {
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
                    file: "base_case.smt2".into(),
                    sha256: Some("abc".into()),
                    proof_file: proof_file.map(Into::into),
                    proof_sha256: proof_sha256.map(Into::into),
                }],
            };
            compute_bundle_sha256(&metadata)
        };
        let h_no_proof = make(None, None);
        let h_with_proof = make(Some("base_case.proof"), Some("deadbeef"));
        let h_diff_hash = make(Some("base_case.proof"), Some("cafebabe"));
        assert_ne!(
            h_no_proof, h_with_proof,
            "presence of proof metadata must change bundle hash"
        );
        assert_ne!(
            h_with_proof, h_diff_hash,
            "different proof hashes must produce different bundle hashes"
        );
    }

    // --- Kernel spec consistency canary ---

    /// All error codes emitted by check_bundle_integrity, used to detect
    /// spec drift. If a new error code is added to the kernel, this list
    /// must be updated, and docs/KERNEL_SPEC.md must be updated to match.
    const ALL_ERROR_CODES: &[&str] = &[
        "bundle_hash_mismatch",
        "check_sat_count",
        "disallowed_commands",
        "duplicate_obligation_file",
        "duplicate_obligation_name",
        "empty_obligations",
        "exit_count",
        "invalid_command_order",
        "invalid_expected",
        "invalid_expected_for_proof",
        "invalid_kind",
        "invalid_obligation_extension",
        "invalid_proof_engine",
        "missing_assert",
        "missing_bundle_hash",
        "missing_file",
        "missing_induction_k",
        "missing_obligation_hash",
        "missing_or_invalid_fairness",
        "missing_proof_file",
        "missing_proof_hash",
        "missing_required_obligation",
        "obligation_hash_mismatch",
        "orphan_proof_hash",
        "proof_hash_mismatch",
        "schema_version",
        "symlink_escape",
        "unexpected_fairness",
        "unexpected_obligation_name",
        "unsafe_path",
        "unsafe_proof_path",
    ];

    #[test]
    fn kernel_error_code_count_matches_spec() {
        // If this test fails, a new error code was added to the kernel
        // but ALL_ERROR_CODES (and docs/KERNEL_SPEC.md) was not updated.
        assert_eq!(
            ALL_ERROR_CODES.len(),
            31,
            "Expected 31 error codes per KERNEL_SPEC.md Section 8. \
             If you added a new error code, update ALL_ERROR_CODES, \
             docs/KERNEL_SPEC.md, and this assertion."
        );
        // Verify no duplicates
        let mut sorted = ALL_ERROR_CODES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ALL_ERROR_CODES.len(),
            "ALL_ERROR_CODES contains duplicates"
        );
    }

    #[test]
    fn kernel_error_codes_are_all_exercised_in_source() {
        // Verify that every error code in ALL_ERROR_CODES appears in a
        // `code: "..."` pattern in the source. This is a compile-time
        // cross-check that the list is not stale.
        let src = include_str!("lib.rs");
        for code in ALL_ERROR_CODES {
            let pattern = format!("code: \"{}\"", code);
            assert!(
                src.contains(&pattern),
                "Error code '{}' is in ALL_ERROR_CODES but not found as `code: \"{}\"` in source",
                code,
                code
            );
        }
    }

    fn reference_profile_spec(
        kind: &str,
        proof_engine: &str,
        fairness: Option<&str>,
        induction_k: Option<usize>,
    ) -> (Option<Vec<&'static str>>, BTreeSet<&'static str>) {
        let mut expected_codes = BTreeSet::new();
        let profile = match (kind, proof_engine) {
            ("safety_proof", "kinduction") => Some(vec!["base_case", "inductive_step"]),
            ("safety_proof", "pdr") => Some(vec![
                "init_implies_inv",
                "inv_and_transition_implies_inv_prime",
                "inv_implies_safe",
            ]),
            ("fair_liveness_proof", "pdr") => Some(vec![
                "init_implies_inv",
                "inv_and_transition_implies_inv_prime",
                "inv_implies_no_fair_bad",
            ]),
            ("fair_liveness_proof", _) => {
                expected_codes.insert("invalid_proof_engine");
                None
            }
            ("safety_proof", _) => {
                expected_codes.insert("invalid_proof_engine");
                None
            }
            _ => {
                expected_codes.insert("invalid_kind");
                None
            }
        };

        if induction_k.is_none() {
            expected_codes.insert("missing_induction_k");
        }

        match kind {
            "safety_proof" => {
                if fairness.is_some() {
                    expected_codes.insert("unexpected_fairness");
                }
            }
            "fair_liveness_proof" => match fairness {
                Some("weak") | Some("strong") => {}
                _ => {
                    expected_codes.insert("missing_or_invalid_fairness");
                }
            },
            _ => {}
        }

        (profile, expected_codes)
    }

    #[test]
    fn soundness_subset_profile_validator_matches_reference_spec() {
        let kinds = ["safety_proof", "fair_liveness_proof", "invalid_kind"];
        let engines = ["kinduction", "pdr", "invalid_engine"];
        let fairness_values = [None, Some("weak"), Some("strong"), Some("invalid_fairness")];
        let induction_values = [None, Some(0_usize), Some(7_usize)];

        for kind in kinds {
            for engine in engines {
                for fairness in fairness_values {
                    for induction_k in induction_values {
                        let metadata = CertificateMetadata {
                            schema_version: CERTIFICATE_SCHEMA_VERSION,
                            kind: kind.into(),
                            protocol_file: "protocol.trs".into(),
                            proof_engine: engine.into(),
                            induction_k,
                            solver_used: "z3".into(),
                            soundness: "strict".into(),
                            fairness: fairness.map(str::to_string),
                            committee_bounds: vec![],
                            bundle_sha256: None,
                            obligations: vec![],
                        };

                        let mut issues = Vec::new();
                        let actual_profile =
                            expected_obligation_names_for_profile(&metadata, &mut issues)
                                .map(|names| names.to_vec());
                        let actual_codes: BTreeSet<&str> =
                            issues.iter().map(|issue| issue.code).collect();

                        let (expected_profile, expected_codes) =
                            reference_profile_spec(kind, engine, fairness, induction_k);

                        assert_eq!(
                            actual_profile, expected_profile,
                            "profile mismatch for case kind={kind:?}, engine={engine:?}, fairness={fairness:?}, induction_k={induction_k:?}"
                        );
                        assert_eq!(
                            actual_codes, expected_codes,
                            "issue-code mismatch for case kind={kind:?}, engine={engine:?}, fairness={fairness:?}, induction_k={induction_k:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn soundness_subset_bundle_hash_matches_spec_vectors() {
        let vector_one = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "safety_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "kinduction".into(),
            induction_k: Some(2),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness: None,
            committee_bounds: vec![("f".into(), 1)],
            bundle_sha256: None,
            obligations: vec![
                CertificateObligationMeta {
                    name: "base_case".into(),
                    expected: "unsat".into(),
                    file: "base_case.smt2".into(),
                    sha256: Some("abc".into()),
                    proof_file: None,
                    proof_sha256: None,
                },
                CertificateObligationMeta {
                    name: "inductive_step".into(),
                    expected: "unsat".into(),
                    file: "inductive_step.smt2".into(),
                    sha256: Some("def".into()),
                    proof_file: None,
                    proof_sha256: None,
                },
            ],
        };
        assert_eq!(
            compute_bundle_sha256(&vector_one),
            "f027f093222d4a2d9a4de12eb5fbd5209b89a368b66a14f0196a50acb1001862",
            "bundle hash vector one diverged from spec encoding"
        );

        let vector_two = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: "fair_liveness_proof".into(),
            protocol_file: "protocol.trs".into(),
            proof_engine: "pdr".into(),
            induction_k: Some(5),
            solver_used: "cvc5".into(),
            soundness: "strict".into(),
            fairness: Some("strong".into()),
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![
                CertificateObligationMeta {
                    name: "init_implies_inv".into(),
                    expected: "unsat".into(),
                    file: "init_implies_inv.smt2".into(),
                    sha256: Some("111".into()),
                    proof_file: Some("init_implies_inv.proof".into()),
                    proof_sha256: Some("aaa".into()),
                },
                CertificateObligationMeta {
                    name: "inv_and_transition_implies_inv_prime".into(),
                    expected: "unsat".into(),
                    file: "inv_and_transition_implies_inv_prime.smt2".into(),
                    sha256: Some("222".into()),
                    proof_file: Some("inv_and_transition_implies_inv_prime.proof".into()),
                    proof_sha256: Some("bbb".into()),
                },
                CertificateObligationMeta {
                    name: "inv_implies_no_fair_bad".into(),
                    expected: "unsat".into(),
                    file: "inv_implies_no_fair_bad.smt2".into(),
                    sha256: Some("333".into()),
                    proof_file: Some("inv_implies_no_fair_bad.proof".into()),
                    proof_sha256: Some("ccc".into()),
                },
            ],
        };
        assert_eq!(
            compute_bundle_sha256(&vector_two),
            "0c11301a3fe49210f5f9f4ff0c8fb2881f6650d2def3c64c8a666bfa09e05ff4",
            "bundle hash vector two diverged from spec encoding"
        );
    }
}
