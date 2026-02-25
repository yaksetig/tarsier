use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use crate::adapters::ADAPTER_FAMILIES;

/// Current schema version for conformance manifests.
pub const CONFORMANCE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// A conformance test suite manifest describing protocol-trace pairs
/// and their expected outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceManifest {
    /// Schema version (must be exactly 1).
    pub schema_version: u32,
    /// Human-readable name for this suite.
    pub suite_name: String,
    /// Optional description of the suite's purpose.
    #[serde(default)]
    pub description: Option<String>,
    /// Ordered list of conformance test entries.
    pub entries: Vec<ConformanceManifestEntry>,
}

/// A single entry in a conformance manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceManifestEntry {
    /// Unique name for this test case.
    pub name: String,
    /// Path to the `.trs` protocol model file.
    pub protocol_file: String,
    /// Path to the runtime trace JSON file.
    pub trace_file: String,
    /// Trace adapter family (`runtime`, `cometbft`, `etcd-raft`).
    #[serde(default = "default_trace_adapter")]
    pub trace_adapter: String,
    /// Checker mode (`permissive` or `strict`).
    #[serde(default = "default_checker_mode")]
    pub checker_mode: String,
    /// Expected verdict: `"pass"` or `"fail"`.
    pub expected_verdict: String,
    /// Optional expected source hash of the model file.
    #[serde(default)]
    pub model_sha256: Option<String>,
    /// Optional mismatch taxonomy hint (`model_change`, `engine_regression`, `impl_divergence`).
    #[serde(default)]
    pub mismatch_hint: Option<String>,
    /// Optional tags for filtering/classification.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional notes/rationale.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Validation error for a conformance manifest.
#[derive(Debug, Clone)]
pub struct ManifestValidationError {
    pub message: String,
}

fn default_trace_adapter() -> String {
    "runtime".into()
}

fn default_checker_mode() -> String {
    "permissive".into()
}

fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit())
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Validate a conformance manifest and return any errors found.
///
/// This enforces the schema contract:
/// - `schema_version` must be exactly `CONFORMANCE_MANIFEST_SCHEMA_VERSION`.
/// - `suite_name` must be non-empty.
/// - `entries` must be non-empty.
/// - Each entry `name` must be non-empty and unique.
/// - `protocol_file` must be non-empty and end with `.trs`.
/// - `trace_file` must be non-empty and end with `.json`.
/// - `trace_adapter` must be one of `runtime | cometbft | etcd-raft`.
/// - `checker_mode` must be one of `permissive | strict`.
/// - `expected_verdict` must be `"pass"` or `"fail"`.
/// - `model_sha256` (if present) must be 64 hex chars.
/// - `mismatch_hint` (if present) must be one of
///   `model_change | engine_regression | impl_divergence`.
pub fn validate_manifest(manifest: &ConformanceManifest) -> Vec<ManifestValidationError> {
    let mut errors = Vec::new();

    // Schema version
    if manifest.schema_version != CONFORMANCE_MANIFEST_SCHEMA_VERSION {
        errors.push(ManifestValidationError {
            message: format!(
                "schema_version must be {}, got {}",
                CONFORMANCE_MANIFEST_SCHEMA_VERSION, manifest.schema_version
            ),
        });
    }

    // Suite name
    if manifest.suite_name.trim().is_empty() {
        errors.push(ManifestValidationError {
            message: "suite_name must be non-empty".into(),
        });
    }

    // Entries non-empty
    if manifest.entries.is_empty() {
        errors.push(ManifestValidationError {
            message: "entries must be non-empty".into(),
        });
    }

    // Per-entry validation
    let mut seen_names: HashSet<&str> = HashSet::new();
    for (i, entry) in manifest.entries.iter().enumerate() {
        let prefix = format!("entries[{}]", i);

        // Name non-empty
        if entry.name.trim().is_empty() {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: name must be non-empty"),
            });
        }

        // Name uniqueness
        if !entry.name.trim().is_empty() && !seen_names.insert(&entry.name) {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: duplicate name '{}'", entry.name),
            });
        }

        // Protocol file
        if entry.protocol_file.trim().is_empty() {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: protocol_file must be non-empty"),
            });
        } else if !entry.protocol_file.ends_with(".trs") {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: protocol_file must end with .trs"),
            });
        }

        // Trace file
        if entry.trace_file.trim().is_empty() {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: trace_file must be non-empty"),
            });
        } else if !entry.trace_file.ends_with(".json") {
            errors.push(ManifestValidationError {
                message: format!("{prefix}: trace_file must end with .json"),
            });
        }

        // Trace adapter
        if !ADAPTER_FAMILIES.contains(&entry.trace_adapter.as_str()) {
            errors.push(ManifestValidationError {
                message: format!(
                    "{prefix}: trace_adapter must be one of [{}], got '{}'",
                    ADAPTER_FAMILIES.join(", "),
                    entry.trace_adapter
                ),
            });
        }

        // Checker mode
        if entry.checker_mode != "permissive" && entry.checker_mode != "strict" {
            errors.push(ManifestValidationError {
                message: format!(
                    "{prefix}: checker_mode must be 'permissive' or 'strict', got '{}'",
                    entry.checker_mode
                ),
            });
        }

        // Expected verdict
        if entry.expected_verdict != "pass" && entry.expected_verdict != "fail" {
            errors.push(ManifestValidationError {
                message: format!(
                    "{prefix}: expected_verdict must be 'pass' or 'fail', got '{}'",
                    entry.expected_verdict
                ),
            });
        }

        // Optional model hash
        if let Some(hash) = entry.model_sha256.as_deref().map(str::trim) {
            if hash.is_empty() || !is_valid_sha256_hex(hash) {
                errors.push(ManifestValidationError {
                    message: format!(
                        "{prefix}: model_sha256 must be a 64-hex SHA-256 string, got '{}'",
                        entry.model_sha256.as_deref().unwrap_or_default()
                    ),
                });
            }
        }

        // Optional mismatch hint
        if let Some(hint) = entry.mismatch_hint.as_deref() {
            if hint != "model_change" && hint != "engine_regression" && hint != "impl_divergence" {
                errors.push(ManifestValidationError {
                    message: format!(
                        "{prefix}: mismatch_hint must be one of 'model_change', 'engine_regression', 'impl_divergence', got '{}'",
                        hint
                    ),
                });
            }
        }
    }

    errors
}

/// Validate that all file paths in a manifest exist relative to a base directory.
pub fn validate_manifest_files(
    manifest: &ConformanceManifest,
    base_dir: &Path,
) -> Vec<ManifestValidationError> {
    let mut errors = Vec::new();
    for (i, entry) in manifest.entries.iter().enumerate() {
        let prefix = format!("entries[{}]", i);

        let protocol_path = base_dir.join(&entry.protocol_file);
        if !protocol_path.exists() {
            errors.push(ManifestValidationError {
                message: format!(
                    "{prefix}: protocol_file '{}' not found (resolved: {})",
                    entry.protocol_file,
                    protocol_path.display()
                ),
            });
        }

        let trace_path = base_dir.join(&entry.trace_file);
        if !trace_path.exists() {
            errors.push(ManifestValidationError {
                message: format!(
                    "{prefix}: trace_file '{}' not found (resolved: {})",
                    entry.trace_file,
                    trace_path.display()
                ),
            });
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> ConformanceManifest {
        ConformanceManifest {
            schema_version: 1,
            suite_name: "test-suite".into(),
            description: Some("Test suite".into()),
            entries: vec![ConformanceManifestEntry {
                name: "test_entry".into(),
                protocol_file: "protocol.trs".into(),
                trace_file: "trace.json".into(),
                trace_adapter: "runtime".into(),
                checker_mode: "permissive".into(),
                expected_verdict: "pass".into(),
                model_sha256: None,
                mismatch_hint: None,
                tags: vec!["safety".into()],
                notes: Some("A test".into()),
            }],
        }
    }

    #[test]
    fn valid_manifest_passes_validation() {
        let m = valid_manifest();
        let errors = validate_manifest(&m);
        assert!(
            errors.is_empty(),
            "errors: {:?}",
            errors.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn wrong_schema_version_fails() {
        let mut m = valid_manifest();
        m.schema_version = 99;
        let errors = validate_manifest(&m);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("schema_version must be 1"));
    }

    #[test]
    fn empty_suite_name_fails() {
        let mut m = valid_manifest();
        m.suite_name = "  ".into();
        let errors = validate_manifest(&m);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("suite_name must be non-empty")));
    }

    #[test]
    fn empty_entries_fails() {
        let mut m = valid_manifest();
        m.entries = vec![];
        let errors = validate_manifest(&m);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("entries must be non-empty")));
    }

    #[test]
    fn duplicate_name_fails() {
        let mut m = valid_manifest();
        m.entries.push(m.entries[0].clone());
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e.message.contains("duplicate name")));
    }

    #[test]
    fn empty_name_fails() {
        let mut m = valid_manifest();
        m.entries[0].name = "".into();
        let errors = validate_manifest(&m);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("name must be non-empty")));
    }

    #[test]
    fn protocol_file_not_trs_fails() {
        let mut m = valid_manifest();
        m.entries[0].protocol_file = "protocol.txt".into();
        let errors = validate_manifest(&m);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("must end with .trs")));
    }

    #[test]
    fn trace_file_not_json_fails() {
        let mut m = valid_manifest();
        m.entries[0].trace_file = "trace.csv".into();
        let errors = validate_manifest(&m);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("must end with .json")));
    }

    #[test]
    fn invalid_expected_verdict_fails() {
        let mut m = valid_manifest();
        m.entries[0].expected_verdict = "maybe".into();
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e
            .message
            .contains("expected_verdict must be 'pass' or 'fail'")));
    }

    #[test]
    fn fail_verdict_accepted() {
        let mut m = valid_manifest();
        m.entries[0].expected_verdict = "fail".into();
        let errors = validate_manifest(&m);
        assert!(errors.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let m = valid_manifest();
        let json = serde_json::to_string_pretty(&m).unwrap();
        let m2: ConformanceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m.schema_version, m2.schema_version);
        assert_eq!(m.suite_name, m2.suite_name);
        assert_eq!(m.entries.len(), m2.entries.len());
        assert_eq!(m.entries[0].name, m2.entries[0].name);
    }

    #[test]
    fn deny_unknown_fields() {
        let json = r#"{
            "schema_version": 1,
            "suite_name": "test",
            "entries": [],
            "extra_field": true
        }"#;
        let result = serde_json::from_str::<ConformanceManifest>(json);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn deny_unknown_entry_fields() {
        let json = r#"{
            "schema_version": 1,
            "suite_name": "test",
            "entries": [{
                "name": "x",
                "protocol_file": "x.trs",
                "trace_file": "x.json",
                "expected_verdict": "pass",
                "bogus": 42
            }]
        }"#;
        let result = serde_json::from_str::<ConformanceManifest>(json);
        assert!(result.is_err(), "unknown entry fields should be rejected");
    }

    #[test]
    fn multiple_entries_with_mixed_verdicts() {
        let m = ConformanceManifest {
            schema_version: 1,
            suite_name: "mixed".into(),
            description: None,
            entries: vec![
                ConformanceManifestEntry {
                    name: "good_trace".into(),
                    protocol_file: "model.trs".into(),
                    trace_file: "good.json".into(),
                    trace_adapter: "runtime".into(),
                    checker_mode: "permissive".into(),
                    expected_verdict: "pass".into(),
                    model_sha256: None,
                    mismatch_hint: None,
                    tags: vec![],
                    notes: None,
                },
                ConformanceManifestEntry {
                    name: "bad_trace".into(),
                    protocol_file: "model.trs".into(),
                    trace_file: "bad.json".into(),
                    trace_adapter: "runtime".into(),
                    checker_mode: "strict".into(),
                    expected_verdict: "fail".into(),
                    model_sha256: None,
                    mismatch_hint: Some("impl_divergence".into()),
                    tags: vec!["regression".into()],
                    notes: Some("Should fail".into()),
                },
            ],
        };
        let errors = validate_manifest(&m);
        assert!(errors.is_empty());
    }

    #[test]
    fn invalid_trace_adapter_fails() {
        let mut m = valid_manifest();
        m.entries[0].trace_adapter = "legacy".into();
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e.message.contains("trace_adapter")));
    }

    #[test]
    fn invalid_checker_mode_fails() {
        let mut m = valid_manifest();
        m.entries[0].checker_mode = "aggressive".into();
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e.message.contains("checker_mode")));
    }

    #[test]
    fn invalid_model_sha_fails() {
        let mut m = valid_manifest();
        m.entries[0].model_sha256 = Some("abc".into());
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e.message.contains("model_sha256")));
    }

    #[test]
    fn invalid_mismatch_hint_fails() {
        let mut m = valid_manifest();
        m.entries[0].mismatch_hint = Some("weird".into());
        let errors = validate_manifest(&m);
        assert!(errors.iter().any(|e| e.message.contains("mismatch_hint")));
    }

    #[test]
    fn defaults_apply_for_adapter_and_checker_mode() {
        let json = r#"{
            "schema_version": 1,
            "suite_name": "defaults",
            "entries": [{
                "name": "x",
                "protocol_file": "x.trs",
                "trace_file": "x.json",
                "expected_verdict": "pass"
            }]
        }"#;
        let manifest: ConformanceManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.entries[0].trace_adapter, "runtime");
        assert_eq!(manifest.entries[0].checker_mode, "permissive");
    }
}
