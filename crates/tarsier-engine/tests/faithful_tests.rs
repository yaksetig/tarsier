mod common;
use common::*;

use tarsier_engine::pipeline::SoundnessMode;
use tarsier_engine::result::VerificationResult;

#[test]
fn verify_library_crypto_object_paths_are_reachable_in_real_snippets() {
    let options = verify_options(4, SoundnessMode::Strict);
    for (file, object_family) in [
        ("pbft_crypto_qc_bug_faithful.trs", "PrepareQC"),
        ("hotstuff_crypto_qc_bug_faithful.trs", "HighQC"),
        ("tendermint_crypto_qc_bug_faithful.trs", "Polka"),
    ] {
        let source = load_library_example(file);
        let result = tarsier_engine::pipeline::verify(&source, file, &options)
            .unwrap_or_else(|e| panic!("verify failed for {file}: {e}"));
        match result {
            VerificationResult::Unsafe { trace } => {
                let seen = trace
                    .steps
                    .iter()
                    .flat_map(|step| step.deliveries.iter())
                    .any(|d| {
                        d.payload.family == object_family
                            && matches!(
                                d.kind,
                                tarsier_ir::counter_system::MessageEventKind::Send
                                    | tarsier_ir::counter_system::MessageEventKind::Deliver
                            )
                    });
                assert!(
                    seen,
                    "expected reachable crypto-object family '{object_family}' in counterexample for {file}"
                );
            }
            other => panic!("Expected UNSAFE with trace for {file}, got: {other}"),
        }
    }
}

#[test]
fn regression_legacy_vs_faithful_overlay_on_bft_library_cases() {
    let legacy_options = verify_options(4, SoundnessMode::Strict);
    let faithful_options = verify_options(4, SoundnessMode::Strict);
    for file in [
        "pbft_core.trs",
        "hotstuff_chained.trs",
        "tendermint_locking.trs",
    ] {
        let legacy_source = load_library_example(file);
        let faithful_source = add_identity_selective_overlay_for_replica(&legacy_source);

        let legacy_result = tarsier_engine::pipeline::verify(&legacy_source, file, &legacy_options)
            .unwrap_or_else(|e| panic!("legacy verify failed for {file}: {e}"));
        let faithful_result = tarsier_engine::pipeline::verify(
            &faithful_source,
            &format!("faithful_overlay_{file}"),
            &faithful_options,
        )
        .unwrap_or_else(|e| panic!("faithful verify failed for {file}: {e}"));

        assert!(
            matches!(legacy_result, VerificationResult::Unsafe { .. }),
            "legacy result for {file} should be UNSAFE"
        );
        assert!(
            matches!(faithful_result, VerificationResult::Unsafe { .. }),
            "faithful overlay result for {file} should be UNSAFE"
        );
    }
}

#[test]
fn manifest_new_faithful_variants_verify_safe() {
    // Verify the two new faithful variant models parse and verify safe
    let vr_faithful = load_library_example("viewstamped_replication_faithful.trs");
    let zab_faithful = load_library_example("zab_atomic_broadcast_faithful.trs");

    let opts = verify_options(4, SoundnessMode::Strict);

    let vr_result = tarsier_engine::pipeline::verify(
        &vr_faithful,
        "viewstamped_replication_faithful.trs",
        &opts,
    )
    .unwrap();
    assert!(
        matches!(vr_result, VerificationResult::Safe { .. }),
        "viewstamped_replication_faithful.trs should verify safe, got {:?}",
        vr_result
    );

    let zab_result =
        tarsier_engine::pipeline::verify(&zab_faithful, "zab_atomic_broadcast_faithful.trs", &opts)
            .unwrap();
    assert!(
        matches!(zab_result, VerificationResult::Safe { .. }),
        "zab_atomic_broadcast_faithful.trs should verify safe, got {:?}",
        zab_result
    );
}

#[test]
fn manifest_faithful_variants_declare_faithful_network_semantics() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let faithful_indicators = [
        "network: identity_selective",
        "network: cohort_selective",
        "network: process_selective",
        "network: faithful",
        "network: selective",
    ];

    for entry in entries {
        if entry.get("variant").and_then(|v| v.as_str()) != Some("faithful") {
            continue;
        }
        let file = entry["file"].as_str().unwrap();
        let path = format!("{}/{}", library_dir, file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path));

        let has_faithful = faithful_indicators
            .iter()
            .any(|indicator| source.contains(indicator));
        assert!(
            has_faithful,
            "Faithful variant '{}' does not declare faithful network semantics in its adversary block. \
             Expected one of: {:?}",
            file, faithful_indicators
        );

        // Must also have identity declaration
        assert!(
            source.contains("identity "),
            "Faithful variant '{}' should declare an identity mapping (e.g., `identity Replica: role key replica_key;`)",
            file
        );

        // Must use distinct receive guards
        assert!(
            source.contains("distinct"),
            "Faithful variant '{}' should use `distinct` keyword in receive guards for sender-counting",
            file
        );

        // Must declare signed auth
        assert!(
            source.contains("auth: signed"),
            "Faithful variant '{}' should declare `auth: signed` in adversary block",
            file
        );

        // Must declare equivocation policy
        assert!(
            source.contains("equivocation: none") || source.contains("equivocation: full"),
            "Faithful variant '{}' should declare an explicit equivocation policy",
            file
        );
    }
}

#[test]
fn manifest_faithful_vs_minimal_variant_pair_consistency() {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    // Group entries by variant_group
    let mut groups: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for entry in entries {
        if let Some(group) = entry.get("variant_group").and_then(|v| v.as_str()) {
            groups.entry(group.to_string()).or_default().push(entry);
        }
    }

    for (group, members) in &groups {
        let minimal = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("minimal"));
        let faithful = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("faithful"));

        let minimal =
            minimal.unwrap_or_else(|| panic!("Group '{}' missing minimal variant", group));
        let faithful =
            faithful.unwrap_or_else(|| panic!("Group '{}' missing faithful variant", group));

        // Both must be in the same family
        assert_eq!(
            minimal["family"].as_str(),
            faithful["family"].as_str(),
            "Variant group '{}': minimal and faithful must be in the same family",
            group
        );

        // Both must have the same class
        assert_eq!(
            minimal["class"].as_str(),
            faithful["class"].as_str(),
            "Variant group '{}': minimal and faithful must have the same class",
            group
        );

        // Both must have the same verify expectation
        assert_eq!(
            minimal.get("verify").and_then(|v| v.as_str()),
            faithful.get("verify").and_then(|v| v.as_str()),
            "Variant group '{}': minimal and faithful must have the same verify expectation",
            group
        );

        // Both protocol files must exist
        let min_path = format!("{}/{}", library_dir, minimal["file"].as_str().unwrap());
        let faith_path = format!("{}/{}", library_dir, faithful["file"].as_str().unwrap());
        assert!(
            std::path::Path::new(&min_path).exists(),
            "Minimal variant file missing: {}",
            min_path
        );
        assert!(
            std::path::Path::new(&faith_path).exists(),
            "Faithful variant file missing: {}",
            faith_path
        );
    }
}

#[test]
fn crypto_justify_independent_of_lock() {
    // Verify that crypto justify and lock operations are independent:
    // a protocol using `lock` should verify identically to one using `justify`
    // for the same underlying certificate structure.
    let options = verify_options(4, SoundnessMode::Strict);

    // PBFT uses `lock PrepareQC(...)` and should verify safe
    let pbft_source = load_library_example("pbft_crypto_qc_safe_faithful.trs");
    let pbft_result = tarsier_engine::pipeline::verify(
        &pbft_source,
        "pbft_crypto_qc_safe_faithful.trs",
        &options,
    )
    .unwrap_or_else(|e| panic!("PBFT lock-based verify failed: {e}"));
    assert!(
        matches!(pbft_result, VerificationResult::Safe { .. }),
        "PBFT with lock PrepareQC should verify safe, got: {:?}",
        pbft_result
    );

    // HotStuff uses `justify HighQC(...)` and should also verify safe
    let hs_source = load_library_example("hotstuff_crypto_qc_safe_faithful.trs");
    let hs_result = tarsier_engine::pipeline::verify(
        &hs_source,
        "hotstuff_crypto_qc_safe_faithful.trs",
        &options,
    )
    .unwrap_or_else(|e| panic!("HotStuff justify-based verify failed: {e}"));
    assert!(
        matches!(hs_result, VerificationResult::Safe { .. }),
        "HotStuff with justify HighQC should verify safe, got: {:?}",
        hs_result
    );

    // Tendermint uses `lock Polka(...)` and should also verify safe
    let tm_source = load_library_example("tendermint_crypto_qc_safe_faithful.trs");
    let tm_result = tarsier_engine::pipeline::verify(
        &tm_source,
        "tendermint_crypto_qc_safe_faithful.trs",
        &options,
    )
    .unwrap_or_else(|e| panic!("Tendermint lock-based verify failed: {e}"));
    assert!(
        matches!(tm_result, VerificationResult::Safe { .. }),
        "Tendermint with lock Polka should verify safe, got: {:?}",
        tm_result
    );

    // The justify path (HotStuff) should produce the same verdict class
    // as the lock path (PBFT, Tendermint), confirming independence
    assert_eq!(
        pbft_result.verdict_class(),
        hs_result.verdict_class(),
        "lock-based (PBFT) and justify-based (HotStuff) should produce same verdict class"
    );
    assert_eq!(
        tm_result.verdict_class(),
        hs_result.verdict_class(),
        "lock-based (Tendermint) and justify-based (HotStuff) should produce same verdict class"
    );
}

#[test]
fn differential_regression_classic_vs_faithful_corpus() {
    // Regression test: run classic (minimal) vs faithful variants from the
    // library corpus and verify verdict consistency. Each variant group should
    // produce the same verdict class for both the minimal and faithful member.
    let manifest = load_library_manifest();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    // Group entries by variant_group
    let mut groups: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for entry in entries {
        if let Some(group) = entry.get("variant_group").and_then(|v| v.as_str()) {
            groups.entry(group.to_string()).or_default().push(entry);
        }
    }

    let mut checked = 0usize;

    for (group, members) in &groups {
        let minimal = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("minimal"));
        let faithful = members
            .iter()
            .find(|e| e.get("variant").and_then(|v| v.as_str()) == Some("faithful"));

        // Only test groups that have both variants
        let (minimal, faithful) = match (minimal, faithful) {
            (Some(m), Some(f)) => (m, f),
            _ => continue,
        };

        let min_file = minimal["file"].as_str().unwrap();
        let faith_file = faithful["file"].as_str().unwrap();

        let min_source = load_library_example(min_file);
        let faith_source = load_library_example(faith_file);

        // Use the depth from the manifest if present, otherwise default to 4
        let min_depth = minimal
            .get("depth")
            .and_then(|d| d.as_u64())
            .unwrap_or(4) as usize;
        let faith_depth = faithful
            .get("depth")
            .and_then(|d| d.as_u64())
            .unwrap_or(4) as usize;

        let min_options = verify_options(min_depth, SoundnessMode::Strict);
        let faith_options = verify_options(faith_depth, SoundnessMode::Strict);

        let min_result = tarsier_engine::pipeline::verify(&min_source, min_file, &min_options)
            .unwrap_or_else(|e| panic!("minimal verify failed for {min_file}: {e}"));
        let faith_result =
            tarsier_engine::pipeline::verify(&faith_source, faith_file, &faith_options)
                .unwrap_or_else(|e| panic!("faithful verify failed for {faith_file}: {e}"));

        // Both variants in the same group should yield the same verdict class
        assert_eq!(
            min_result.verdict_class(),
            faith_result.verdict_class(),
            "variant group '{}': minimal ({}) verdict '{}' differs from faithful ({}) verdict '{}'",
            group,
            min_file,
            min_result.verdict_class(),
            faith_file,
            faith_result.verdict_class()
        );

        checked += 1;
    }

    assert!(
        checked >= 4,
        "expected at least 4 variant groups with both minimal and faithful members, got {}",
        checked
    );
}

