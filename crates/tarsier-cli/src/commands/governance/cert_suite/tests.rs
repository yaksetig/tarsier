use super::*;

// -- classify_cert_suite_check_triage --

#[test]
fn triage_model_changed() {
    let result = classify_cert_suite_check_triage("verify", "safe", "unsafe", None, true);
    assert_eq!(result, TRIAGE_MODEL_CHANGE);
}

#[test]
fn triage_known_bug_actual_bug() {
    let result =
        classify_cert_suite_check_triage("verify", "safe", "unsafe", Some("known_bug"), false);
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

#[test]
fn triage_expected_safe_actual_safe() {
    let result =
        classify_cert_suite_check_triage("verify", "unsafe", "safe", Some("expected_safe"), false);
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

#[test]
fn triage_engine_regression_default() {
    let result = classify_cert_suite_check_triage("verify", "safe", "unknown", None, false);
    assert_eq!(result, TRIAGE_ENGINE_REGRESSION);
}

#[test]
fn triage_same_polarity_expected_update() {
    let result =
        classify_cert_suite_check_triage("verify", "safe", "probabilistically_safe", None, false);
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

#[test]
fn triage_liveness_known_bug_sentinel() {
    let result =
        classify_cert_suite_check_triage("liveness", "live", "not_live", Some("known_bug"), false);
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

#[test]
fn triage_fair_liveness_bug_sentinel() {
    let result = classify_cert_suite_check_triage(
        "fair_liveness",
        "no_fair_cycle_up_to",
        "fair_cycle_found",
        Some("known_bug"),
        false,
    );
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

#[test]
fn triage_prove_fair_bug_sentinel() {
    let result = classify_cert_suite_check_triage(
        "prove_fair",
        "live_proved",
        "fair_cycle_found",
        Some("known_bug"),
        false,
    );
    assert_eq!(result, TRIAGE_EXPECTED_UPDATE);
}

// -- classify_cert_suite_entry_triage --

#[test]
fn entry_triage_pass_returns_none() {
    let entry = CertSuiteEntryReport {
        file: "test.trs".into(),
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        verdict: "pass".into(),
        status: "pass".into(),
        triage: None,
        duration_ms: 0,
        assumptions: CertSuiteAssumptions {
            solver: "z3".into(),
            proof_engine: "pdr".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            network_semantics: "dsl".into(),
            depth: 10,
            k: 12,
            timeout_secs: 60,
            cegar_iters: 0,
        },
        model_sha256_expected: None,
        model_sha256_actual: None,
        model_changed: false,
        notes: None,
        artifact_links: vec![],
        checks: vec![],
        errors: vec![],
    };
    assert!(classify_cert_suite_entry_triage(&entry).is_none());
}

#[test]
fn entry_triage_errors_model_change() {
    let entry = CertSuiteEntryReport {
        file: "test.trs".into(),
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        verdict: "error".into(),
        status: "error".into(),
        triage: None,
        duration_ms: 0,
        assumptions: CertSuiteAssumptions {
            solver: "z3".into(),
            proof_engine: "pdr".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            network_semantics: "dsl".into(),
            depth: 10,
            k: 12,
            timeout_secs: 60,
            cegar_iters: 0,
        },
        model_sha256_expected: None,
        model_sha256_actual: None,
        model_changed: true,
        notes: None,
        artifact_links: vec![],
        checks: vec![],
        errors: vec!["some error".into()],
    };
    assert_eq!(
        classify_cert_suite_entry_triage(&entry),
        Some(TRIAGE_MODEL_CHANGE.to_string())
    );
}

#[test]
fn entry_triage_errors_engine_regression() {
    let entry = CertSuiteEntryReport {
        file: "test.trs".into(),
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        verdict: "error".into(),
        status: "error".into(),
        triage: None,
        duration_ms: 0,
        assumptions: CertSuiteAssumptions {
            solver: "z3".into(),
            proof_engine: "pdr".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            network_semantics: "dsl".into(),
            depth: 10,
            k: 12,
            timeout_secs: 60,
            cegar_iters: 0,
        },
        model_sha256_expected: None,
        model_sha256_actual: None,
        model_changed: false,
        notes: None,
        artifact_links: vec![],
        checks: vec![],
        errors: vec!["some error".into()],
    };
    assert_eq!(
        classify_cert_suite_entry_triage(&entry),
        Some(TRIAGE_ENGINE_REGRESSION.to_string())
    );
}

#[test]
fn entry_triage_failed_checks_single_category() {
    let entry = CertSuiteEntryReport {
        file: "test.trs".into(),
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        verdict: "fail".into(),
        status: "fail".into(),
        triage: None,
        duration_ms: 0,
        assumptions: CertSuiteAssumptions {
            solver: "z3".into(),
            proof_engine: "pdr".into(),
            soundness: "strict".into(),
            fairness: "weak".into(),
            network_semantics: "dsl".into(),
            depth: 10,
            k: 12,
            timeout_secs: 60,
            cegar_iters: 0,
        },
        model_sha256_expected: None,
        model_sha256_actual: None,
        model_changed: false,
        notes: None,
        artifact_links: vec![],
        checks: vec![CertSuiteCheckReport {
            check: "verify".into(),
            expected: "safe".into(),
            actual: "unsafe".into(),
            status: "fail".into(),
            duration_ms: 0,
            triage: Some(TRIAGE_EXPECTED_UPDATE.to_string()),
            artifact_link: None,
            output: String::new(),
        }],
        errors: vec![],
    };
    assert_eq!(
        classify_cert_suite_entry_triage(&entry),
        Some(TRIAGE_EXPECTED_UPDATE.to_string())
    );
}

// -- is_valid_cert_suite_triage_kind --

#[test]
fn valid_triage_kinds() {
    assert!(is_valid_cert_suite_triage_kind(TRIAGE_MODEL_CHANGE));
    assert!(is_valid_cert_suite_triage_kind(TRIAGE_ENGINE_REGRESSION));
    assert!(is_valid_cert_suite_triage_kind(TRIAGE_EXPECTED_UPDATE));
}

#[test]
fn invalid_triage_kind() {
    assert!(!is_valid_cert_suite_triage_kind("custom_triage"));
}

// -- validate_manifest_expected_result --

#[test]
fn validate_expected_result_verify_valid() {
    assert!(validate_manifest_expected_result("verify", "safe").is_ok());
    assert!(validate_manifest_expected_result("verify", "unsafe").is_ok());
    assert!(validate_manifest_expected_result("verify", "unknown").is_ok());
    assert!(validate_manifest_expected_result("verify", "probabilistically_safe").is_ok());
}

#[test]
fn validate_expected_result_verify_invalid() {
    assert!(validate_manifest_expected_result("verify", "live").is_err());
}

#[test]
fn validate_expected_result_liveness_valid() {
    assert!(validate_manifest_expected_result("liveness", "live").is_ok());
    assert!(validate_manifest_expected_result("liveness", "not_live").is_ok());
}

#[test]
fn validate_expected_result_fair_liveness_valid() {
    assert!(validate_manifest_expected_result("fair_liveness", "no_fair_cycle_up_to").is_ok());
    assert!(validate_manifest_expected_result("fair_liveness", "fair_cycle_found").is_ok());
}

#[test]
fn validate_expected_result_prove_valid() {
    assert!(validate_manifest_expected_result("prove", "safe").is_ok());
    assert!(validate_manifest_expected_result("prove", "not_proved").is_ok());
}

#[test]
fn validate_expected_result_prove_fair_valid() {
    assert!(validate_manifest_expected_result("prove_fair", "live_proved").is_ok());
    assert!(validate_manifest_expected_result("prove_fair", "not_proved").is_ok());
}

#[test]
fn validate_expected_result_unsupported_check() {
    assert!(validate_manifest_expected_result("custom_check", "safe").is_err());
}

#[test]
fn validate_expected_result_case_insensitive() {
    assert!(validate_manifest_expected_result("verify", "SAFE").is_ok());
}

// -- validate_manifest_entry_contract --

#[test]
fn validate_entry_no_checks_configured() {
    let entry = CertSuiteEntry {
        file: "test.trs".into(),
        verify: None,
        liveness: None,
        fair_liveness: None,
        prove: None,
        prove_fair: None,
        proof_engine: None,
        fairness: None,
        cegar_iters: None,
        depth: None,
        k: None,
        timeout: None,
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        notes: None,
        model_sha256: None,
    };
    let errors = validate_manifest_entry_contract(&entry, 1);
    assert!(errors.iter().any(|e| e.contains("no expected outcomes")));
}

#[test]
fn validate_entry_v1_minimal_ok() {
    let entry = CertSuiteEntry {
        file: "test.trs".into(),
        verify: Some("safe".into()),
        liveness: None,
        fair_liveness: None,
        prove: None,
        prove_fair: None,
        proof_engine: None,
        fairness: None,
        cegar_iters: None,
        depth: None,
        k: None,
        timeout: None,
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        notes: None,
        model_sha256: None,
    };
    let errors = validate_manifest_entry_contract(&entry, 1);
    assert!(errors.is_empty());
}

#[test]
fn validate_entry_v2_requires_notes_and_hash() {
    let entry = CertSuiteEntry {
        file: "test.trs".into(),
        verify: Some("safe".into()),
        liveness: None,
        fair_liveness: None,
        prove: None,
        prove_fair: None,
        proof_engine: None,
        fairness: None,
        cegar_iters: None,
        depth: None,
        k: None,
        timeout: None,
        family: None,
        class: None,
        variant: None,
        variant_group: None,
        notes: None,
        model_sha256: None,
    };
    let errors = validate_manifest_entry_contract(&entry, 2);
    assert!(errors.iter().any(|e| e.contains("notes")));
    assert!(errors.iter().any(|e| e.contains("model_sha256")));
}

#[test]
fn validate_entry_v2_invalid_variant() {
    let entry = CertSuiteEntry {
        file: "test.trs".into(),
        verify: Some("safe".into()),
        liveness: None,
        fair_liveness: None,
        prove: None,
        prove_fair: None,
        proof_engine: None,
        fairness: None,
        cegar_iters: None,
        depth: None,
        k: None,
        timeout: None,
        family: None,
        class: None,
        variant: Some("custom".into()),
        variant_group: Some("group1".into()),
        notes: Some("note".into()),
        model_sha256: Some("a".repeat(64)),
    };
    let errors = validate_manifest_entry_contract(&entry, 2);
    assert!(errors.iter().any(|e| e.contains("invalid variant")));
}

// -- validate_manifest_top_level_contract --

#[test]
fn validate_top_level_wrong_schema() {
    let manifest = CertSuiteManifest {
        schema_version: 99,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    let errors = validate_manifest_top_level_contract(&manifest);
    assert!(errors.iter().any(|e| e.contains("schema")));
}

#[test]
fn validate_top_level_empty_entries() {
    let manifest = CertSuiteManifest {
        schema_version: CERT_SUITE_SCHEMA_VERSION,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    let errors = validate_manifest_top_level_contract(&manifest);
    assert!(errors.iter().any(|e| e.contains("at least one")));
}

#[test]
fn validate_top_level_non_trs_file() {
    let manifest = CertSuiteManifest {
        schema_version: CERT_SUITE_SCHEMA_VERSION,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![CertSuiteEntry {
            file: "test.txt".into(),
            verify: Some("safe".into()),
            liveness: None,
            fair_liveness: None,
            prove: None,
            prove_fair: None,
            proof_engine: None,
            fairness: None,
            cegar_iters: None,
            depth: None,
            k: None,
            timeout: None,
            family: None,
            class: None,
            variant: None,
            variant_group: None,
            notes: None,
            model_sha256: None,
        }],
    };
    let errors = validate_manifest_top_level_contract(&manifest);
    assert!(errors.iter().any(|e| e.contains(".trs")));
}

// -- resolve_manifest_library_dir --

#[test]
fn resolve_library_dir_default() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    let path = resolve_manifest_library_dir(&manifest, Path::new("/tmp/manifest.json"));
    assert_eq!(path, PathBuf::from("/tmp/."));
}

#[test]
fn resolve_library_dir_absolute() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: Some("/absolute/path".into()),
        entries: vec![],
    };
    let path = resolve_manifest_library_dir(&manifest, Path::new("/tmp/manifest.json"));
    assert_eq!(path, PathBuf::from("/absolute/path"));
}

// -- disabled enforcement checks --

#[test]
fn known_bug_sentinel_disabled() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    assert!(validate_manifest_known_bug_sentinel_coverage(&manifest).is_empty());
}

#[test]
fn corpus_breadth_disabled() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    assert!(validate_manifest_corpus_breadth(&manifest, Path::new("/tmp/m.json")).is_empty());
}

#[test]
fn library_coverage_disabled() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    assert!(validate_manifest_library_coverage(&manifest, Path::new("/tmp/m.json")).is_empty());
}

#[test]
fn model_hash_consistency_disabled() {
    let manifest = CertSuiteManifest {
        schema_version: 2,
        enforce_library_coverage: false,
        enforce_corpus_breadth: false,
        enforce_model_hash_consistency: false,
        enforce_known_bug_sentinels: false,
        required_known_bug_families: vec![],
        required_variant_groups: vec![],
        library_dir: None,
        entries: vec![],
    };
    assert!(
        validate_manifest_model_hash_consistency(&manifest, Path::new("/tmp/m.json")).is_empty()
    );
}

// -- validate_cert_suite_report_triage_contract --

#[test]
fn triage_contract_valid_report() {
    let report = CertSuiteReport {
        schema_version: 2,
        manifest: "test.json".into(),
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        entries: vec![],
        passed: 0,
        failed: 0,
        errors: 0,
        triage: BTreeMap::new(),
        by_family: BTreeMap::new(),
        by_class: BTreeMap::new(),
        overall: "pass".into(),
    };
    assert!(validate_cert_suite_report_triage_contract(&report).is_ok());
}

#[test]
fn triage_contract_invalid_key() {
    let mut triage = BTreeMap::new();
    triage.insert("invalid_key".to_string(), 1);
    let report = CertSuiteReport {
        schema_version: 2,
        manifest: "test.json".into(),
        solver: "z3".into(),
        proof_engine: "pdr".into(),
        soundness: "strict".into(),
        fairness: "weak".into(),
        entries: vec![],
        passed: 0,
        failed: 0,
        errors: 0,
        triage,
        by_family: BTreeMap::new(),
        by_class: BTreeMap::new(),
        overall: "pass".into(),
    };
    assert!(validate_cert_suite_report_triage_contract(&report).is_err());
}
