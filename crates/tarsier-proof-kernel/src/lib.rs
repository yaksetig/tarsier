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

/// Domain-tag prefix used by bundle hash computation.
pub const CERTIFICATE_HASH_DOMAIN_TAG: &str = "tarsier-certificate-v2\n";

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

/// Stable machine-readable obligation profile for checker semantics export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelObligationProfile {
    /// Certificate kind admitted by this profile.
    pub kind: String,
    /// Proof engine admitted by this profile.
    pub proof_engine: String,
    /// Required obligation names for the profile.
    pub required_obligations: Vec<String>,
    /// Whether induction/frame depth metadata is required.
    pub requires_induction_k: bool,
    /// Required fairness values for this profile (`None` when forbidden).
    pub fairness: Option<Vec<String>>,
}

/// Stable machine-readable governance profile row for semantics export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelGovernanceProfile {
    /// Governance profile name (`standard`, `reinforced`, `high-assurance`).
    pub name: String,
    /// Minimum independent solver count.
    pub min_solvers: usize,
    /// Whether proof files are required.
    pub require_proofs: bool,
    /// Whether an external proof checker is required.
    pub require_proof_checker: bool,
    /// Whether foundational proof-path controls are required.
    pub require_foundational_proof_path: bool,
}

/// Exported checker-semantics artifact consumed by downstream formalization tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelSemanticsArtifact {
    /// Schema version for this export payload.
    pub schema_version: u32,
    /// Certificate metadata schema version accepted by the kernel.
    pub certificate_schema_version: u32,
    /// Domain tag used in bundle hash derivation.
    pub certificate_hash_domain_tag: String,
    /// Whether checker behavior is fail-closed.
    pub fail_closed: bool,
    /// Reference doc path for the certificate schema contract.
    pub certificate_schema_doc_path: String,
    /// Structural obligation profiles by `(kind, proof_engine)`.
    pub obligation_profiles: Vec<KernelObligationProfile>,
    /// Governance profile floors used by certcheck.
    pub governance_profiles: Vec<KernelGovernanceProfile>,
    /// Stable set of checker issue codes.
    pub issue_codes: Vec<String>,
}

/// Canonical checker issue codes (spec section 8 / kernel source).
pub const KERNEL_ERROR_CODES: &[&str] = &[
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
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use tarsier_proof_kernel::check_bundle_integrity;
///
/// let report = check_bundle_integrity(Path::new("artifacts/certs/my_protocol"))?;
/// if !report.is_ok() {
///     for issue in &report.issues {
///         eprintln!("[{}] {}", issue.code, issue.message);
///     }
/// }
/// # Ok::<(), tarsier_proof_kernel::ProofKernelError>(())
/// ```
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

const PROFILE_SAFETY_KINDUCTION: &[&str] = &["base_case", "inductive_step"];
const PROFILE_SAFETY_PDR: &[&str] = &[
    "init_implies_inv",
    "inv_and_transition_implies_inv_prime",
    "inv_implies_safe",
];
const PROFILE_FAIR_LIVENESS_PDR: &[&str] = &[
    "init_implies_inv",
    "inv_and_transition_implies_inv_prime",
    "inv_implies_no_fair_bad",
];

/// Build the canonical v1 checker-semantics artifact for formalization pipelines.
pub fn kernel_semantics_artifact_v1() -> KernelSemanticsArtifact {
    let governance_rows = [
        ("standard", GovernanceProfile::Standard),
        ("reinforced", GovernanceProfile::Reinforced),
        ("high-assurance", GovernanceProfile::HighAssurance),
    ];

    KernelSemanticsArtifact {
        schema_version: 1,
        certificate_schema_version: CERTIFICATE_SCHEMA_VERSION,
        certificate_hash_domain_tag: CERTIFICATE_HASH_DOMAIN_TAG.to_string(),
        fail_closed: true,
        certificate_schema_doc_path: CERTIFICATE_SCHEMA_DOC_PATH.to_string(),
        obligation_profiles: vec![
            KernelObligationProfile {
                kind: "safety_proof".to_string(),
                proof_engine: "kinduction".to_string(),
                required_obligations: PROFILE_SAFETY_KINDUCTION
                    .iter()
                    .map(|v| (*v).to_string())
                    .collect(),
                requires_induction_k: true,
                fairness: None,
            },
            KernelObligationProfile {
                kind: "safety_proof".to_string(),
                proof_engine: "pdr".to_string(),
                required_obligations: PROFILE_SAFETY_PDR
                    .iter()
                    .map(|v| (*v).to_string())
                    .collect(),
                requires_induction_k: true,
                fairness: None,
            },
            KernelObligationProfile {
                kind: "fair_liveness_proof".to_string(),
                proof_engine: "pdr".to_string(),
                required_obligations: PROFILE_FAIR_LIVENESS_PDR
                    .iter()
                    .map(|v| (*v).to_string())
                    .collect(),
                requires_induction_k: true,
                fairness: Some(vec!["weak".to_string(), "strong".to_string()]),
            },
        ],
        governance_profiles: governance_rows
            .iter()
            .map(|(name, profile)| {
                let req = profile.requirements();
                KernelGovernanceProfile {
                    name: (*name).to_string(),
                    min_solvers: req.min_solvers,
                    require_proofs: req.require_proofs,
                    require_proof_checker: req.require_proof_checker,
                    require_foundational_proof_path: req.require_foundational_proof_path,
                }
            })
            .collect(),
        issue_codes: KERNEL_ERROR_CODES
            .iter()
            .map(|code| (*code).to_string())
            .collect(),
    }
}

fn expected_obligation_names_for_profile(
    metadata: &CertificateMetadata,
    issues: &mut Vec<BundleCheckIssue>,
) -> Option<&'static [&'static str]> {
    let mut profile = None;
    match (metadata.kind.as_str(), metadata.proof_engine.as_str()) {
        ("safety_proof", "kinduction") => {
            profile = Some(PROFILE_SAFETY_KINDUCTION);
        }
        ("safety_proof", "pdr") => {
            profile = Some(PROFILE_SAFETY_PDR);
        }
        ("fair_liveness_proof", "pdr") => {
            profile = Some(PROFILE_FAIR_LIVENESS_PDR);
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
mod tests;
