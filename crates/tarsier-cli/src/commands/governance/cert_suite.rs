//! Governance certificate-suite manifest parsing and validation.
//
// Cert suite manifest validation functions.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use tarsier_proof_kernel::sha256_hex_bytes;

use super::{
    is_valid_sha256_hex, CertSuiteEntry, CertSuiteEntryReport, CertSuiteManifest, CertSuiteReport,
    CERT_SUITE_CANONICAL_MIN_FAMILIES, CERT_SUITE_SCHEMA_DOC_PATH, CERT_SUITE_SCHEMA_VERSION,
    CERT_SUITE_TRIAGE_CATEGORIES, TRIAGE_ENGINE_REGRESSION, TRIAGE_EXPECTED_UPDATE,
    TRIAGE_MODEL_CHANGE,
};
#[cfg(test)]
use super::{CertSuiteAssumptions, CertSuiteCheckReport};

pub(crate) fn classify_cert_suite_check_triage(
    check: &str,
    expected: &str,
    actual: &str,
    class: Option<&str>,
    model_changed: bool,
) -> String {
    if model_changed {
        return TRIAGE_MODEL_CHANGE.into();
    }

    fn is_bug_sentinel(check: &str, outcome: &str) -> bool {
        match check {
            "verify" | "prove" => outcome.eq_ignore_ascii_case("unsafe"),
            "liveness" => outcome.eq_ignore_ascii_case("not_live"),
            "fair_liveness" | "prove_fair" => outcome.eq_ignore_ascii_case("fair_cycle_found"),
            _ => false,
        }
    }

    let class = class.unwrap_or("");
    let class_known_bug = class.eq_ignore_ascii_case("known_bug");
    let class_expected_safe = class.eq_ignore_ascii_case("expected_safe");
    let expected_bug = is_bug_sentinel(check, expected);
    let actual_bug = is_bug_sentinel(check, actual);
    let actual_unknown = actual.eq_ignore_ascii_case("unknown");

    // Mismatch that preserves expected benchmark polarity usually indicates manifest drift.
    if class_known_bug && actual_bug {
        return TRIAGE_EXPECTED_UPDATE.into();
    }
    if class_expected_safe && !actual_bug && !actual_unknown {
        return TRIAGE_EXPECTED_UPDATE.into();
    }
    if expected_bug == actual_bug
        && !expected.eq_ignore_ascii_case("unknown")
        && !actual.eq_ignore_ascii_case("unknown")
    {
        return TRIAGE_EXPECTED_UPDATE.into();
    }

    TRIAGE_ENGINE_REGRESSION.into()
}

pub(crate) fn classify_cert_suite_entry_triage(entry: &CertSuiteEntryReport) -> Option<String> {
    if entry.status == "pass" {
        return None;
    }
    if !entry.errors.is_empty() {
        return Some(if entry.model_changed {
            TRIAGE_MODEL_CHANGE.into()
        } else {
            TRIAGE_ENGINE_REGRESSION.into()
        });
    }
    let mut categories: Vec<String> = entry
        .checks
        .iter()
        .filter(|c| c.status == "fail")
        .filter_map(|c| c.triage.clone())
        .collect();
    if categories.is_empty() {
        return Some(TRIAGE_ENGINE_REGRESSION.into());
    }
    categories.sort();
    categories.dedup();
    if categories.len() == 1 {
        return categories.into_iter().next();
    }
    if categories.iter().any(|c| c == TRIAGE_ENGINE_REGRESSION) {
        return Some(TRIAGE_ENGINE_REGRESSION.into());
    }
    if categories.iter().any(|c| c == TRIAGE_MODEL_CHANGE) {
        return Some(TRIAGE_MODEL_CHANGE.into());
    }
    Some(TRIAGE_EXPECTED_UPDATE.into())
}

pub(crate) fn is_valid_cert_suite_triage_kind(kind: &str) -> bool {
    CERT_SUITE_TRIAGE_CATEGORIES.contains(&kind)
}

pub(crate) fn validate_cert_suite_report_triage_contract(
    report: &CertSuiteReport,
) -> Result<(), String> {
    for kind in report.triage.keys() {
        if !is_valid_cert_suite_triage_kind(kind) {
            return Err(format!(
                "Invalid report triage key '{}'. Allowed: {}.",
                kind,
                CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
            ));
        }
    }
    for entry in &report.entries {
        if let Some(kind) = &entry.triage {
            if !is_valid_cert_suite_triage_kind(kind) {
                return Err(format!(
                    "Entry '{}' has invalid triage '{}'. Allowed: {}.",
                    entry.file,
                    kind,
                    CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
                ));
            }
        }
        for check in &entry.checks {
            if let Some(kind) = &check.triage {
                if !is_valid_cert_suite_triage_kind(kind) {
                    return Err(format!(
                        "Entry '{}' check '{}' has invalid triage '{}'. Allowed: {}.",
                        entry.file,
                        check.check,
                        kind,
                        CERT_SUITE_TRIAGE_CATEGORIES.join(", ")
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest_expected_result(check: &str, expected: &str) -> Result<(), String> {
    let allowed: &[&str] = match check {
        "verify" => &["safe", "probabilistically_safe", "unsafe", "unknown"],
        "liveness" => &["live", "not_live", "unknown"],
        "fair_liveness" => &["no_fair_cycle_up_to", "fair_cycle_found", "unknown"],
        "prove" => &[
            "safe",
            "probabilistically_safe",
            "unsafe",
            "not_proved",
            "unknown",
        ],
        "prove_fair" => &["live_proved", "fair_cycle_found", "not_proved", "unknown"],
        other => {
            return Err(format!(
                "Unsupported manifest check '{other}' while validating expected outcome."
            ));
        }
    };
    let normalized = expected.trim().to_ascii_lowercase();
    if allowed.iter().any(|candidate| *candidate == normalized) {
        return Ok(());
    }

    Err(format!(
        "Invalid expected outcome '{}' for '{}'. Allowed: {}.",
        expected.trim(),
        check,
        allowed.join(", ")
    ))
}

pub(crate) fn validate_manifest_entry_contract(
    entry: &CertSuiteEntry,
    schema_version: u32,
) -> Vec<String> {
    let mut errors = Vec::new();
    let configured_checks = usize::from(entry.verify.is_some())
        + usize::from(entry.liveness.is_some())
        + usize::from(entry.fair_liveness.is_some())
        + usize::from(entry.prove.is_some())
        + usize::from(entry.prove_fair.is_some());
    if configured_checks == 0 {
        errors.push("Entry has no expected outcomes configured.".into());
    }

    if schema_version >= 2 {
        let has_rationale = entry
            .notes
            .as_deref()
            .map(|notes| !notes.trim().is_empty())
            .unwrap_or(false);
        if !has_rationale {
            errors.push(
                "Schema v2 requires a non-empty 'notes' rationale for each protocol entry.".into(),
            );
        }
        match entry.model_sha256.as_deref().map(str::trim) {
            Some("") | None => errors.push(
                "Schema v2 requires a non-empty 'model_sha256' (hex SHA-256 of the protocol file)."
                    .into(),
            ),
            Some(hash) if !is_valid_sha256_hex(hash) => errors.push(format!(
                "Entry '{}' has invalid model_sha256 '{}'; expected 64 hex chars.",
                entry.file, hash
            )),
            _ => {}
        }

        let variant = entry.variant.as_deref().map(str::trim);
        let variant_group = entry.variant_group.as_deref().map(str::trim);
        match (variant, variant_group) {
            (None, None) | (Some(""), None) | (None, Some("")) => {}
            (Some(""), Some(_)) | (None, Some(_)) => errors.push(format!(
                "Entry '{}' sets 'variant_group' but is missing non-empty 'variant'.",
                entry.file
            )),
            (Some(_), Some("")) | (Some(_), None) => errors.push(format!(
                "Entry '{}' sets 'variant' but is missing non-empty 'variant_group'.",
                entry.file
            )),
            (Some(v), Some(_)) => match v {
                "minimal" | "faithful" => {}
                other => errors.push(format!(
                    "Entry '{}' has invalid variant '{}'. Allowed: minimal, faithful.",
                    entry.file, other
                )),
            },
        }
    }

    for (check, expected) in [
        ("verify", entry.verify.as_deref()),
        ("liveness", entry.liveness.as_deref()),
        ("fair_liveness", entry.fair_liveness.as_deref()),
        ("prove", entry.prove.as_deref()),
        ("prove_fair", entry.prove_fair.as_deref()),
    ] {
        if let Some(expected) = expected {
            if let Err(msg) = validate_manifest_expected_result(check, expected) {
                errors.push(msg);
            }
        }
    }

    errors
}

pub(crate) fn validate_manifest_top_level_contract(manifest: &CertSuiteManifest) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.schema_version != CERT_SUITE_SCHEMA_VERSION {
        errors.push(format!(
            "Unsupported certification manifest schema {} (expected {}). See {}.",
            manifest.schema_version, CERT_SUITE_SCHEMA_VERSION, CERT_SUITE_SCHEMA_DOC_PATH
        ));
    }
    if manifest.entries.is_empty() {
        errors.push("Manifest must contain at least one protocol entry.".into());
    }

    fn has_bug_sentinel_outcome(entry: &CertSuiteEntry) -> bool {
        let is = |value: Option<&str>, expected: &str| {
            value
                .map(|v| v.trim().eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        };
        is(entry.verify.as_deref(), "unsafe")
            || is(entry.prove.as_deref(), "unsafe")
            || is(entry.liveness.as_deref(), "not_live")
            || is(entry.fair_liveness.as_deref(), "fair_cycle_found")
            || is(entry.prove_fair.as_deref(), "fair_cycle_found")
    }

    let mut seen_files: HashSet<String> = HashSet::new();
    let mut known_bug_entries = 0usize;
    let mut variant_groups: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut variant_group_files: BTreeMap<(String, String), String> = BTreeMap::new();
    for entry in &manifest.entries {
        let file = entry.file.trim();
        if file.is_empty() {
            errors.push("Manifest entry has an empty 'file' path.".into());
            continue;
        }
        if !file.ends_with(".trs") {
            errors.push(format!(
                "Manifest entry '{}' must reference a .trs protocol file.",
                entry.file
            ));
        }
        if !seen_files.insert(file.to_string()) {
            errors.push(format!("Duplicate manifest entry for file '{}'.", file));
        }

        if manifest.schema_version >= 2 {
            let family = entry.family.as_deref().map(str::trim).unwrap_or("");
            if family.is_empty() {
                errors.push(format!(
                    "Entry '{}' is missing required 'family' (schema v2).",
                    entry.file
                ));
            }
            match entry.class.as_deref().map(str::trim).unwrap_or("") {
                "expected_safe" | "known_bug" => {}
                "" => errors.push(format!(
                    "Entry '{}' is missing required 'class' (schema v2).",
                    entry.file
                )),
                other => errors.push(format!(
                    "Entry '{}' has invalid class '{}'. Allowed: expected_safe, known_bug.",
                    entry.file, other
                )),
            }
            if entry.class.as_deref() == Some("known_bug") {
                known_bug_entries += 1;
                if !has_bug_sentinel_outcome(entry) {
                    errors.push(format!(
                        "Entry '{}' is class=known_bug but has no bug sentinel expected outcome (unsafe/not_live/fair_cycle_found).",
                        entry.file
                    ));
                }
            }

            let variant = entry.variant.as_deref().map(str::trim).unwrap_or("");
            let variant_group = entry.variant_group.as_deref().map(str::trim).unwrap_or("");
            if !variant.is_empty() && !variant_group.is_empty() {
                variant_groups
                    .entry(variant_group.to_string())
                    .or_default()
                    .insert(variant.to_string());
                let key = (variant_group.to_string(), variant.to_string());
                if let Some(existing) = variant_group_files.insert(key.clone(), entry.file.clone())
                {
                    errors.push(format!(
                        "Variant pair duplicate for group '{}' variant '{}': '{}' and '{}'.",
                        key.0, key.1, existing, entry.file
                    ));
                }
            }
        }
    }
    if manifest.schema_version >= 2 && known_bug_entries == 0 {
        errors.push("Schema v2 manifest must include at least one class=known_bug regression sentinel entry.".into());
    }
    if manifest.schema_version >= 2 {
        for (group, variants) in variant_groups {
            if !variants.contains("minimal") || !variants.contains("faithful") {
                errors.push(format!(
                    "Variant group '{}' must define both minimal and faithful entries.",
                    group
                ));
            }
        }
    }

    errors
}

pub(crate) fn resolve_manifest_library_dir(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> PathBuf {
    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let library_dir_raw = manifest.library_dir.as_deref().unwrap_or(".");
    let candidate = PathBuf::from(library_dir_raw);
    if candidate.is_absolute() {
        candidate
    } else {
        base_dir.join(candidate)
    }
}

pub(crate) fn manifest_entry_fault_model(
    protocol_source: &str,
    protocol_name: &str,
) -> Result<Option<&'static str>, String> {
    let program = tarsier_dsl::parse(protocol_source, protocol_name).map_err(|e| {
        format!("Failed parsing '{protocol_name}' while classifying fault model: {e}")
    })?;
    let proto = &program.protocol.node;
    for item in &proto.adversary {
        if item.key == "model" {
            return Ok(match item.value.as_str() {
                "byzantine" => Some("byzantine"),
                "omission" => Some("omission"),
                "crash" => Some("crash"),
                _ => None,
            });
        }
    }
    Ok(None)
}

pub(crate) fn validate_manifest_corpus_breadth(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_corpus_breadth {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);

    if !library_dir.exists() {
        errors.push(format!(
            "Corpus breadth directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Corpus breadth path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    let family_count = manifest
        .entries
        .iter()
        .filter_map(|entry| entry.family.as_deref())
        .map(str::trim)
        .filter(|family| !family.is_empty())
        .collect::<HashSet<_>>()
        .len();
    if family_count < CERT_SUITE_CANONICAL_MIN_FAMILIES {
        errors.push(format!(
            "Canonical corpus breadth requires at least {} distinct families (found {}).",
            CERT_SUITE_CANONICAL_MIN_FAMILIES, family_count
        ));
    }

    let mut seen_fault_models: HashSet<&'static str> = HashSet::new();
    for entry in &manifest.entries {
        let raw = entry.file.trim();
        if raw.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(raw);
        let protocol_path = if candidate.is_absolute() {
            candidate
        } else {
            library_dir.join(candidate)
        };
        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                errors.push(format!(
                    "Corpus breadth classification could not read '{}': {e}",
                    protocol_path.display()
                ));
                continue;
            }
        };
        let protocol_name = protocol_path.display().to_string();
        match manifest_entry_fault_model(&source, &protocol_name) {
            Ok(Some(model)) => {
                seen_fault_models.insert(model);
            }
            Ok(None) => errors.push(format!(
                "Entry '{}' does not declare a supported adversary model (expected byzantine|omission|crash).",
                entry.file
            )),
            Err(msg) => errors.push(msg),
        }
    }

    for required in ["byzantine", "omission", "crash"] {
        if !seen_fault_models.contains(required) {
            errors.push(format!(
                "Canonical corpus breadth requires at least one '{}' model entry.",
                required
            ));
        }
    }

    errors
}

pub(crate) fn validate_manifest_known_bug_sentinel_coverage(
    manifest: &CertSuiteManifest,
) -> Vec<String> {
    if !manifest.enforce_known_bug_sentinels {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let known_bug_families: HashSet<String> = manifest
        .entries
        .iter()
        .filter(|entry| entry.class.as_deref() == Some("known_bug"))
        .filter_map(|entry| entry.family.as_deref())
        .map(str::trim)
        .filter(|family| !family.is_empty())
        .map(|family| family.to_string())
        .collect();

    let required_known_bug_families: Vec<String> = manifest
        .required_known_bug_families
        .iter()
        .map(|family| family.trim())
        .filter(|family| !family.is_empty())
        .map(|family| family.to_string())
        .collect();
    if required_known_bug_families.is_empty() {
        errors.push(
            "Known-bug sentinel enforcement is enabled but required_known_bug_families is empty."
                .into(),
        );
    }
    for family in &required_known_bug_families {
        if !known_bug_families.contains(family) {
            errors.push(format!(
                "Required known-bug sentinel family '{}' has no class=known_bug entry.",
                family
            ));
        }
    }

    let required_variant_groups: Vec<String> = manifest
        .required_variant_groups
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .map(|group| group.to_string())
        .collect();
    if required_variant_groups.is_empty() {
        errors.push(
            "Known-bug sentinel enforcement is enabled but required_variant_groups is empty."
                .into(),
        );
    }

    let mut group_variants: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut group_families: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for entry in &manifest.entries {
        let variant = entry.variant.as_deref().map(str::trim).unwrap_or("");
        let group = entry.variant_group.as_deref().map(str::trim).unwrap_or("");
        if variant.is_empty() || group.is_empty() {
            continue;
        }
        group_variants
            .entry(group.to_string())
            .or_default()
            .insert(variant.to_string());
        if let Some(family) = entry
            .family
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
        {
            group_families
                .entry(group.to_string())
                .or_default()
                .insert(family.to_string());
        }
    }

    for group in &required_variant_groups {
        let Some(variants) = group_variants.get(group) else {
            errors.push(format!(
                "Required variant group '{}' is missing from manifest.",
                group
            ));
            continue;
        };
        if !variants.contains("minimal") || !variants.contains("faithful") {
            errors.push(format!(
                "Required variant group '{}' must include both minimal and faithful entries.",
                group
            ));
        }

        let families = group_families.get(group).cloned().unwrap_or_default();
        if families.len() != 1 {
            errors.push(format!(
                "Required variant group '{}' must map to exactly one family (found {}).",
                group,
                families.len()
            ));
            continue;
        }
        let family = families.into_iter().next().unwrap_or_default();
        if !known_bug_families.contains(&family) {
            errors.push(format!(
                "Required variant group '{}' belongs to family '{}' but that family has no class=known_bug sentinel entry.",
                group, family
            ));
        }
    }

    errors
}

pub(crate) fn validate_manifest_model_hash_consistency(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_model_hash_consistency {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);
    if !library_dir.exists() {
        errors.push(format!(
            "Model-hash consistency directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Model-hash consistency path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    for entry in &manifest.entries {
        let raw = entry.file.trim();
        if raw.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(raw);
        let protocol_path = if candidate.is_absolute() {
            candidate
        } else {
            library_dir.join(candidate)
        };
        let source = match fs::read_to_string(&protocol_path) {
            Ok(src) => src,
            Err(e) => {
                errors.push(format!(
                    "Model-hash consistency could not read '{}': {e}",
                    protocol_path.display()
                ));
                continue;
            }
        };
        let actual = sha256_hex_bytes(source.as_bytes());
        match entry.model_sha256.as_deref().map(str::trim) {
            Some(expected) if expected.eq_ignore_ascii_case(&actual) => {}
            Some(expected) => errors.push(format!(
                "Entry '{}' model_sha256 mismatch: expected {}, actual {}. Update hashes with `python3 scripts/update-cert-suite-hashes.py --manifest {}`.",
                entry.file,
                expected,
                actual,
                manifest_path.display()
            )),
            None => errors.push(format!(
                "Entry '{}' is missing model_sha256 required for hash consistency.",
                entry.file
            )),
        }
    }

    errors
}

pub(crate) fn validate_manifest_library_coverage(
    manifest: &CertSuiteManifest,
    manifest_path: &Path,
) -> Vec<String> {
    if !manifest.enforce_library_coverage {
        return Vec::new();
    }

    let mut errors = Vec::new();
    let library_dir = resolve_manifest_library_dir(manifest, manifest_path);

    if !library_dir.exists() {
        errors.push(format!(
            "Library coverage directory '{}' does not exist.",
            library_dir.display()
        ));
        return errors;
    }
    if !library_dir.is_dir() {
        errors.push(format!(
            "Library coverage path '{}' is not a directory.",
            library_dir.display()
        ));
        return errors;
    }

    let mut on_disk_files: HashSet<String> = HashSet::new();
    let read_dir = match fs::read_dir(&library_dir) {
        Ok(entries) => entries,
        Err(e) => {
            errors.push(format!(
                "Failed reading library directory '{}': {e}",
                library_dir.display()
            ));
            return errors;
        }
    };
    for item in read_dir {
        let item = match item {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!(
                    "Failed listing library directory '{}': {e}",
                    library_dir.display()
                ));
                continue;
            }
        };
        let path = item.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("trs"))
                .unwrap_or(false)
        {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                on_disk_files.insert(name.to_string());
            }
        }
    }

    let manifest_files: HashSet<String> = manifest
        .entries
        .iter()
        .filter_map(|entry| {
            let path = Path::new(entry.file.trim());
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string())
        })
        .collect();

    for missing in on_disk_files.difference(&manifest_files) {
        errors.push(format!(
            "Protocol '{}' exists in '{}' but has no cert-suite expectation entry.",
            missing,
            library_dir.display()
        ));
    }
    for stale in manifest_files.difference(&on_disk_files) {
        errors.push(format!(
            "Manifest contains '{}' but '{}' has no such protocol file.",
            stale,
            library_dir.display()
        ));
    }

    errors
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
