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

#[test]
fn kernel_error_code_count_matches_spec() {
    // If this test fails, a new error code was added to the kernel
    // but KERNEL_ERROR_CODES (and docs/KERNEL_SPEC.md) was not updated.
    assert_eq!(
        KERNEL_ERROR_CODES.len(),
        31,
        "Expected 31 error codes per KERNEL_SPEC.md Section 8. \
             If you added a new error code, update KERNEL_ERROR_CODES, \
             docs/KERNEL_SPEC.md, and this assertion."
    );
    // Verify no duplicates
    let mut sorted = KERNEL_ERROR_CODES.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        KERNEL_ERROR_CODES.len(),
        "KERNEL_ERROR_CODES contains duplicates"
    );
}

#[test]
fn kernel_error_codes_are_all_exercised_in_source() {
    // Verify that every error code in KERNEL_ERROR_CODES appears in a
    // `code: "..."` pattern in the source. This is a compile-time
    // cross-check that the list is not stale.
    let src = include_str!("lib.rs");
    for code in KERNEL_ERROR_CODES {
        let pattern = format!("code: \"{}\"", code);
        assert!(
            src.contains(&pattern),
            "Error code '{}' is in KERNEL_ERROR_CODES but not found as `code: \"{}\"` in source",
            code,
            code
        );
    }
}

#[test]
fn kernel_semantics_artifact_v1_has_expected_shape() {
    let artifact = kernel_semantics_artifact_v1();
    assert_eq!(artifact.schema_version, 1);
    assert_eq!(
        artifact.certificate_schema_version,
        CERTIFICATE_SCHEMA_VERSION
    );
    assert_eq!(
        artifact.certificate_hash_domain_tag,
        CERTIFICATE_HASH_DOMAIN_TAG
    );
    assert!(artifact.fail_closed);
    assert_eq!(
        artifact.certificate_schema_doc_path,
        CERTIFICATE_SCHEMA_DOC_PATH
    );
    assert_eq!(artifact.obligation_profiles.len(), 3);
    assert_eq!(artifact.governance_profiles.len(), 3);
    assert_eq!(artifact.issue_codes.len(), KERNEL_ERROR_CODES.len());
    assert_eq!(
        artifact.issue_codes,
        KERNEL_ERROR_CODES
            .iter()
            .map(|code| (*code).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn kernel_semantics_artifact_profiles_align_with_validator() {
    let artifact = kernel_semantics_artifact_v1();
    for profile in artifact.obligation_profiles {
        let fairness = if profile.kind == "fair_liveness_proof" {
            Some("weak".to_string())
        } else {
            None
        };
        let metadata = CertificateMetadata {
            schema_version: CERTIFICATE_SCHEMA_VERSION,
            kind: profile.kind.clone(),
            protocol_file: "protocol.trs".into(),
            proof_engine: profile.proof_engine.clone(),
            induction_k: Some(1),
            solver_used: "z3".into(),
            soundness: "strict".into(),
            fairness,
            committee_bounds: vec![],
            bundle_sha256: None,
            obligations: vec![],
        };
        let mut issues = Vec::new();
        let expected = expected_obligation_names_for_profile(&metadata, &mut issues)
            .expect("profile should resolve to an obligation set");
        assert!(
            issues.is_empty(),
            "valid profile unexpectedly produced issues: {:?}",
            issues.iter().map(|i| i.code).collect::<Vec<_>>()
        );
        assert_eq!(
            profile.required_obligations,
            expected
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>(),
            "profile mismatch for kind={}, engine={}",
            profile.kind,
            profile.proof_engine
        );
    }
}

#[test]
fn kernel_semantics_artifact_matches_committed_snapshot() {
    let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/kernel-semantics/kernel_semantics_v1.json");
    let committed = fs::read_to_string(&artifact_path).unwrap_or_else(|e| {
        panic!(
            "failed to read committed kernel semantics artifact {}: {e}",
            artifact_path.display()
        )
    });
    let committed_json: serde_json::Value = serde_json::from_str(&committed).unwrap_or_else(|e| {
        panic!(
            "failed to parse committed kernel semantics artifact {}: {e}",
            artifact_path.display()
        )
    });
    let generated_json =
        serde_json::to_value(kernel_semantics_artifact_v1()).expect("artifact should serialize");
    assert_eq!(
        generated_json, committed_json,
        "committed artifact is stale; regenerate via:\n\
             cargo run -p tarsier-proof-kernel --bin kernel-semantics-export -- \
             --out artifacts/kernel-semantics/kernel_semantics_v1.json"
    );
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
