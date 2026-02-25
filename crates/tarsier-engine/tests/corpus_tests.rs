mod common;
use common::*;

#[test]
fn manifest_all_entries_have_substantive_notes() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let notes = entry["notes"].as_str().unwrap();
        assert!(
            notes.len() >= 40,
            "Entry '{}' has a notes field that is too short ({} chars < 40): {:?}",
            file,
            notes.len(),
            notes
        );
        // Notes should not be the old generic placeholder
        assert!(
            notes != "Expected clean safety benchmark.",
            "Entry '{}' still has the generic placeholder notes",
            file
        );
    }
}

#[test]
fn manifest_variant_groups_are_complete() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    // Collect all variant groups and their variants
    let mut groups: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for entry in entries {
        if let Some(group) = entry.get("variant_group").and_then(|v| v.as_str()) {
            let variant = entry["variant"].as_str().unwrap().to_string();
            groups.entry(group.to_string()).or_default().push(variant);
        }
    }

    assert!(
        groups.len() >= 5,
        "Expected at least 5 variant groups, got {}",
        groups.len()
    );

    for (group, variants) in &groups {
        assert!(
            variants.contains(&"minimal".to_string()),
            "Variant group '{}' is missing a minimal variant",
            group
        );
        assert!(
            variants.contains(&"faithful".to_string()),
            "Variant group '{}' is missing a faithful variant",
            group
        );
    }
}

#[test]
fn manifest_known_bug_coverage_is_adequate() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let known_bugs: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["class"].as_str() == Some("known_bug"))
        .collect();

    let expected_safe: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["class"].as_str() == Some("expected_safe"))
        .collect();

    // Must have at least 16 known bugs
    assert!(
        known_bugs.len() >= 16,
        "Expected at least 16 known_bug entries, got {}",
        known_bugs.len()
    );

    // Must have at least 16 expected_safe entries
    assert!(
        expected_safe.len() >= 16,
        "Expected at least 16 expected_safe entries, got {}",
        expected_safe.len()
    );

    // All known_bug entries must have at least one bug-revealing outcome
    for entry in &known_bugs {
        let file = entry["file"].as_str().unwrap();
        let has_bug_outcome = entry.get("verify").and_then(|v| v.as_str()) == Some("unsafe")
            || entry.get("prove").and_then(|v| v.as_str()) == Some("unsafe")
            || entry.get("liveness").and_then(|v| v.as_str()) == Some("not_live")
            || entry.get("fair_liveness").and_then(|v| v.as_str()) == Some("fair_cycle_found")
            || entry.get("prove_fair").and_then(|v| v.as_str()) == Some("fair_cycle_found");
        assert!(
            has_bug_outcome,
            "known_bug entry '{}' has no bug-revealing expected outcome",
            file
        );
    }
}

#[test]
fn manifest_model_sha256_format_is_valid() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let hash = entry["model_sha256"].as_str().unwrap();
        assert_eq!(
            hash.len(),
            64,
            "Entry '{}' model_sha256 should be 64 hex chars, got {} chars",
            file,
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Entry '{}' model_sha256 contains non-hex characters: '{}'",
            file,
            hash
        );
    }
}

#[test]
fn manifest_files_are_unique() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in entries {
        let file = entry["file"].as_str().unwrap().to_string();
        assert!(
            seen.insert(file.clone()),
            "Duplicate file entry in manifest: '{}'",
            file
        );
    }
}

#[test]
fn manifest_entries_reference_existing_files() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let path = format!("{}/{}", library_dir, file);
        assert!(
            std::path::Path::new(&path).exists(),
            "Manifest references '{}' but file does not exist at '{}'",
            file,
            path
        );
    }
}

#[test]
fn manifest_library_coverage_all_trs_files_have_entries() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let manifest_files: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["file"].as_str().unwrap().to_string())
        .collect();

    let trs_files: Vec<String> = std::fs::read_dir(&library_dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("trs"))
        .map(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap()
                .to_string()
        })
        .collect();

    for trs_file in &trs_files {
        assert!(
            manifest_files.contains(trs_file),
            "Library file '{}' has no entry in cert_suite.json",
            trs_file
        );
    }
}

#[test]
fn manifest_fault_model_breadth() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let families: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["family"].as_str().unwrap().to_string())
        .collect();

    // Must cover BFT families
    assert!(families.contains("pbft"), "Missing BFT family: pbft");
    assert!(
        families.contains("hotstuff"),
        "Missing BFT family: hotstuff"
    );
    assert!(
        families.contains("tendermint"),
        "Missing BFT family: tendermint"
    );

    // Must cover crash-fault families
    assert!(families.contains("paxos"), "Missing CFT family: paxos");
    assert!(
        families.contains("viewstamped-replication"),
        "Missing CFT family: viewstamped-replication"
    );

    // Must cover omission-fault families
    assert!(families.contains("zab"), "Missing omission family: zab");
    assert!(families.contains("raft"), "Missing omission family: raft");

    // Overall breadth
    assert!(
        families.len() >= 16,
        "Expected at least 16 protocol families, got {}",
        families.len()
    );
}

#[test]
fn manifest_schema_version_is_v2() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(
        parsed["schema_version"].as_u64(),
        Some(2),
        "Manifest schema_version should be 2"
    );
    assert_eq!(
        parsed["enforce_library_coverage"].as_bool(),
        Some(true),
        "enforce_library_coverage should be true"
    );
}

#[test]
fn manifest_expected_outcomes_are_valid_tokens() {
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let verify_valid = ["safe", "probabilistically_safe", "unsafe", "unknown"];
    let liveness_valid = ["live", "not_live", "unknown"];
    let fair_valid = ["no_fair_cycle_up_to", "fair_cycle_found", "unknown"];
    let prove_valid = [
        "safe",
        "probabilistically_safe",
        "unsafe",
        "not_proved",
        "unknown",
    ];
    let prove_fair_valid = ["live_proved", "fair_cycle_found", "not_proved", "unknown"];

    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        if let Some(v) = entry.get("verify").and_then(|v| v.as_str()) {
            assert!(
                verify_valid.contains(&v),
                "Entry '{}' has invalid verify value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("liveness").and_then(|v| v.as_str()) {
            assert!(
                liveness_valid.contains(&v),
                "Entry '{}' has invalid liveness value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("fair_liveness").and_then(|v| v.as_str()) {
            assert!(
                fair_valid.contains(&v),
                "Entry '{}' has invalid fair_liveness value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("prove").and_then(|v| v.as_str()) {
            assert!(
                prove_valid.contains(&v),
                "Entry '{}' has invalid prove value: '{}'",
                file,
                v
            );
        }
        if let Some(v) = entry.get("prove_fair").and_then(|v| v.as_str()) {
            assert!(
                prove_fair_valid.contains(&v),
                "Entry '{}' has invalid prove_fair value: '{}'",
                file,
                v
            );
        }

        // Each entry must have at least one expected outcome
        let has_outcome = entry.get("verify").is_some()
            || entry.get("liveness").is_some()
            || entry.get("fair_liveness").is_some()
            || entry.get("prove").is_some()
            || entry.get("prove_fair").is_some();
        assert!(
            has_outcome,
            "Entry '{}' has no expected outcome field",
            file
        );
    }
}
