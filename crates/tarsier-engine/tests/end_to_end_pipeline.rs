//! End-to-end integration tests exercising the FULL tarsier pipeline:
//!
//!   .trs source -> parse -> lower -> abstract -> encode -> solve
//!     -> certificate generation -> certificate bundle verification
//!
//! These tests validate that every pipeline stage is exercised and that
//! the outputs of each stage feed correctly into the next.

use std::fs;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use tarsier_engine::pipeline::{self, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};
use tarsier_engine::result::{UnboundedSafetyResult, VerificationResult};
use tarsier_proof_kernel::{
    check_bundle_integrity, compute_bundle_sha256, CertificateMetadata, CertificateObligationMeta,
    CERTIFICATE_SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_options() -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    }
}

fn pdr_options() -> PipelineOptions {
    PipelineOptions {
        proof_engine: ProofEngine::Pdr,
        ..default_options()
    }
}

/// Write a certificate bundle to a temp directory and return the path.
///
/// This mirrors the logic in the CLI's `write_certificate_bundle` but is
/// self-contained so the integration test does not depend on the CLI crate.
fn write_bundle_to_dir(
    dir: &std::path::Path,
    cert: &tarsier_engine::pipeline::SafetyProofCertificate,
    engine_name: &str,
) {
    fs::create_dir_all(dir).expect("create bundle dir");

    let mut obligations_meta = Vec::new();
    for obligation in &cert.obligations {
        let file_name = format!("{}.smt2", obligation.name);
        let file_path = dir.join(&file_name);
        fs::write(&file_path, &obligation.smt2).expect("write obligation");
        let hash = sha256_hex_file(&file_path);
        obligations_meta.push(CertificateObligationMeta {
            name: obligation.name.clone(),
            expected: obligation.expected.clone(),
            file: file_name,
            sha256: Some(hash),
            proof_file: None,
            proof_sha256: None,
        });
    }

    let soundness_str = match cert.soundness {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    };

    let mut metadata = CertificateMetadata {
        schema_version: CERTIFICATE_SCHEMA_VERSION,
        kind: "safety_proof".to_string(),
        protocol_file: cert.protocol_file.clone(),
        proof_engine: engine_name.to_string(),
        induction_k: cert.induction_k,
        solver_used: "z3".to_string(),
        soundness: soundness_str.to_string(),
        fairness: None,
        committee_bounds: cert.committee_bounds.clone(),
        bundle_sha256: None,
        obligations: obligations_meta,
    };
    metadata.bundle_sha256 = Some(compute_bundle_sha256(&metadata));

    let metadata_json = serde_json::to_string_pretty(&metadata).expect("serialize metadata");
    fs::write(dir.join("certificate.json"), metadata_json).expect("write metadata");
}

fn sha256_hex_file(path: &std::path::Path) -> String {
    let bytes = fs::read(path).expect("read file for hashing");
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Safe protocol: .trs source
// ---------------------------------------------------------------------------

/// A minimal safe protocol with a trivially true invariant.
/// All processes start with `decided = false` and the invariant asserts exactly that.
/// No transitions can change `decided`, so this is safe at any depth.
const SAFE_PROTOCOL: &str = r#"
protocol SafeSimple {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;

/// A minimal safe agreement protocol.
/// Only one decision value is reachable, so agreement holds trivially.
const SAFE_AGREEMENT_PROTOCOL: &str = r#"
protocol SafeAgreement {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Vote;
    role Voter {
        var decided: bool = false;
        var decision: bool = false;
        init voting;
        phase voting {
            when received >= n - t Vote => {
                decided = true;
                decision = true;
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Voter. forall q: Voter.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

// ---------------------------------------------------------------------------
// Unsafe protocol: .trs source
// ---------------------------------------------------------------------------

/// A buggy consensus protocol where processes can reach conflicting decisions.
/// The adversary can inject Abort messages to push some processes to decide NO
/// while others receive enough Votes to decide YES.
const UNSAFE_PROTOCOL: &str = r#"
protocol BuggyConsensus {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message Vote;
    message Abort;
    role Process {
        var decided: bool = false;
        var decision: bool = false;
        init propose;
        phase propose {
            when received >= 1 Vote => {
                send Vote;
                goto phase voted;
            }
            when received >= 1 Abort => {
                decision = false;
                decided = true;
                goto phase done_no;
            }
        }
        phase voted {
            when received >= t+1 Vote => {
                decision = true;
                decided = true;
                goto phase done_yes;
            }
        }
        phase done_yes {}
        phase done_no {}
    }
    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;

/// A protocol that is unsafe because the invariant is immediately violated:
/// `decided` starts `false`, but we immediately transition to `true`.
const UNSAFE_INVARIANT_PROTOCOL: &str = r#"
protocol UnsafeInvariant {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        var decided: bool = false;
        init s;
        phase s {
            when received >= 0 M => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property inv: invariant {
        forall p: R. p.decided == false
    }
}
"#;

// ===========================================================================
// Test 1: Full pipeline for a SAFE protocol (parse -> lower -> verify -> prove -> certificate -> verify certificate)
// ===========================================================================

#[test]
fn full_pipeline_safe_protocol_parse_to_certificate_verification() {
    // -----------------------------------------------------------------------
    // Stage 1: Parse
    // -----------------------------------------------------------------------
    let program =
        pipeline::parse(SAFE_PROTOCOL, "safe_simple.trs").expect("parsing should succeed");
    assert_eq!(program.protocol.node.name, "SafeSimple");
    assert_eq!(program.protocol.node.parameters.len(), 3);
    assert_eq!(program.protocol.node.roles.len(), 1);

    // -----------------------------------------------------------------------
    // Stage 2: Lower to threshold automaton
    // -----------------------------------------------------------------------
    let ta = pipeline::lower(&program).expect("lowering should succeed");
    assert!(
        !ta.locations.is_empty(),
        "threshold automaton should have at least one location"
    );
    assert!(
        !ta.parameters.is_empty(),
        "threshold automaton should have parameters"
    );
    assert!(
        !ta.initial_locations.is_empty(),
        "threshold automaton should have initial locations"
    );

    // -----------------------------------------------------------------------
    // Stage 3: Bounded model checking (verify)
    // -----------------------------------------------------------------------
    let opts = default_options();
    let bmc_result = pipeline::verify(SAFE_PROTOCOL, "safe_simple.trs", &opts)
        .expect("BMC verification should complete");
    match &bmc_result {
        VerificationResult::Safe { depth_checked } => {
            assert_eq!(*depth_checked, 4, "BMC should check up to max_depth");
        }
        other => panic!("Expected SAFE from BMC, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 4: Unbounded proof (k-induction)
    // -----------------------------------------------------------------------
    let prove_result = pipeline::prove_safety(SAFE_PROTOCOL, "safe_simple.trs", &opts)
        .expect("k-induction proof should complete");
    match &prove_result {
        UnboundedSafetyResult::Safe { induction_k } => {
            assert!(*induction_k >= 1, "k-induction should close at k >= 1");
        }
        other => panic!("Expected unbounded SAFE, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 5: Generate proof certificate (k-induction)
    // -----------------------------------------------------------------------
    let cert =
        pipeline::generate_kinduction_safety_certificate(SAFE_PROTOCOL, "safe_simple.trs", &opts)
            .expect("certificate generation should succeed");

    assert_eq!(cert.proof_engine, ProofEngine::KInduction);
    assert!(cert.induction_k.is_some());
    assert_eq!(
        cert.obligations.len(),
        2,
        "k-induction certificate should have base_case + inductive_step"
    );
    // Validate obligation names
    let obligation_names: Vec<&str> = cert.obligations.iter().map(|o| o.name.as_str()).collect();
    assert!(obligation_names.contains(&"base_case"));
    assert!(obligation_names.contains(&"inductive_step"));
    // Validate all obligations contain SMT-LIB content
    for obligation in &cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(
            obligation.smt2.contains("(check-sat)"),
            "obligation {} should contain (check-sat)",
            obligation.name
        );
        assert!(
            obligation.smt2.contains("(declare-const") || obligation.smt2.contains("(assert"),
            "obligation {} should contain SMT declarations or assertions",
            obligation.name
        );
    }

    // -----------------------------------------------------------------------
    // Stage 6: Write certificate bundle to disk & verify with proof kernel
    // -----------------------------------------------------------------------
    let tmp = TempDir::new().expect("create temp dir");
    let bundle_dir = tmp.path().join("safe_cert");
    write_bundle_to_dir(&bundle_dir, &cert, "kinduction");

    let report = check_bundle_integrity(&bundle_dir)
        .expect("bundle integrity check should not fail with I/O error");

    assert!(
        report.is_ok(),
        "Certificate bundle should pass all integrity checks. Issues: {:?}",
        report.issues
    );
    assert_eq!(report.metadata.schema_version, CERTIFICATE_SCHEMA_VERSION);
    assert_eq!(report.metadata.kind, "safety_proof");
    assert_eq!(report.metadata.proof_engine, "kinduction");
    assert_eq!(report.metadata.obligations.len(), 2);
}

// ===========================================================================
// Test 2: Full pipeline for a SAFE protocol using PDR engine
// ===========================================================================

#[test]
fn full_pipeline_safe_protocol_pdr_certificate_verification() {
    // -----------------------------------------------------------------------
    // Stage 1-2: Parse + Lower (verify via pipeline)
    // -----------------------------------------------------------------------
    let program = pipeline::parse(SAFE_PROTOCOL, "safe_pdr.trs").expect("parsing should succeed");
    let ta = pipeline::lower(&program).expect("lowering should succeed");
    assert!(!ta.locations.is_empty());

    // -----------------------------------------------------------------------
    // Stage 3-4: BMC + PDR unbounded proof
    // -----------------------------------------------------------------------
    let opts = pdr_options();
    let prove_result = pipeline::prove_safety(SAFE_PROTOCOL, "safe_pdr.trs", &opts)
        .expect("PDR proof should complete");
    match &prove_result {
        UnboundedSafetyResult::Safe { .. } => {}
        other => panic!("Expected unbounded SAFE from PDR, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 5: Generate PDR certificate
    // -----------------------------------------------------------------------
    let cert = pipeline::generate_pdr_safety_certificate(SAFE_PROTOCOL, "safe_pdr.trs", &opts)
        .expect("PDR certificate generation should succeed");

    assert_eq!(cert.proof_engine, ProofEngine::Pdr);
    assert_eq!(
        cert.obligations.len(),
        3,
        "PDR certificate should have init_implies_inv + transition + inv_implies_safe"
    );
    let obligation_names: Vec<&str> = cert.obligations.iter().map(|o| o.name.as_str()).collect();
    assert!(obligation_names.contains(&"init_implies_inv"));
    assert!(obligation_names.contains(&"inv_and_transition_implies_inv_prime"));
    assert!(obligation_names.contains(&"inv_implies_safe"));

    // -----------------------------------------------------------------------
    // Stage 6: Write + verify bundle
    // -----------------------------------------------------------------------
    let tmp = TempDir::new().expect("create temp dir");
    let bundle_dir = tmp.path().join("pdr_cert");
    write_bundle_to_dir(&bundle_dir, &cert, "pdr");

    let report =
        check_bundle_integrity(&bundle_dir).expect("bundle integrity check should not I/O error");

    assert!(
        report.is_ok(),
        "PDR certificate bundle should pass all integrity checks. Issues: {:?}",
        report.issues
    );
    assert_eq!(report.metadata.proof_engine, "pdr");
    assert_eq!(report.metadata.obligations.len(), 3);
}

// ===========================================================================
// Test 3: Full pipeline for a SAFE agreement protocol
// ===========================================================================

#[test]
fn full_pipeline_safe_agreement_parse_to_verify() {
    // -----------------------------------------------------------------------
    // Stage 1: Parse
    // -----------------------------------------------------------------------
    let program = pipeline::parse(SAFE_AGREEMENT_PROTOCOL, "safe_agreement.trs")
        .expect("parsing should succeed");
    assert_eq!(program.protocol.node.name, "SafeAgreement");

    // -----------------------------------------------------------------------
    // Stage 2: Lower
    // -----------------------------------------------------------------------
    let ta = pipeline::lower(&program).expect("lowering should succeed");
    assert!(!ta.locations.is_empty());
    // Agreement protocol should have shared vars for message counters
    assert!(
        !ta.shared_vars.is_empty(),
        "agreement protocol should have shared variables"
    );

    // -----------------------------------------------------------------------
    // Stage 3: BMC verification
    // -----------------------------------------------------------------------
    let opts = default_options();
    let result = pipeline::verify(SAFE_AGREEMENT_PROTOCOL, "safe_agreement.trs", &opts)
        .expect("BMC verification should complete");
    match &result {
        VerificationResult::Safe { depth_checked } => {
            assert_eq!(*depth_checked, 4);
        }
        other => panic!("Expected SAFE for agreement protocol, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 4: Unbounded proof + certificate
    // -----------------------------------------------------------------------
    let cert = pipeline::generate_kinduction_safety_certificate(
        SAFE_AGREEMENT_PROTOCOL,
        "safe_agreement.trs",
        &opts,
    )
    .expect("certificate generation should succeed for agreement protocol");

    assert_eq!(cert.obligations.len(), 2);
    for obligation in &cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(obligation.smt2.contains("(check-sat)"));
    }

    // -----------------------------------------------------------------------
    // Stage 5: Verify certificate bundle
    // -----------------------------------------------------------------------
    let tmp = TempDir::new().expect("create temp dir");
    let bundle_dir = tmp.path().join("agreement_cert");
    write_bundle_to_dir(&bundle_dir, &cert, "kinduction");

    let report = check_bundle_integrity(&bundle_dir).expect("bundle check should not I/O error");
    assert!(
        report.is_ok(),
        "Agreement certificate should pass integrity. Issues: {:?}",
        report.issues
    );
}

// ===========================================================================
// Test 4: Full pipeline detects UNSAFE protocol (counterexample)
// ===========================================================================

#[test]
fn full_pipeline_detects_unsafe_protocol_with_counterexample() {
    // -----------------------------------------------------------------------
    // Stage 1: Parse
    // -----------------------------------------------------------------------
    let program = pipeline::parse(UNSAFE_PROTOCOL, "buggy_consensus.trs")
        .expect("parsing should succeed even for buggy protocol");
    assert_eq!(program.protocol.node.name, "BuggyConsensus");

    // -----------------------------------------------------------------------
    // Stage 2: Lower to threshold automaton
    // -----------------------------------------------------------------------
    let ta = pipeline::lower(&program).expect("lowering should succeed");
    assert!(!ta.locations.is_empty());
    // Buggy protocol has Vote + Abort messages -> at least 2 shared vars
    assert!(
        ta.shared_vars.len() >= 2,
        "buggy protocol should have >= 2 shared vars (got {})",
        ta.shared_vars.len()
    );

    // -----------------------------------------------------------------------
    // Stage 3: BMC finds counterexample
    // -----------------------------------------------------------------------
    let opts = default_options();
    let result = pipeline::verify(UNSAFE_PROTOCOL, "buggy_consensus.trs", &opts)
        .expect("BMC should complete");
    match &result {
        VerificationResult::Unsafe { trace } => {
            // Validate the counterexample trace has meaningful content
            assert!(
                !trace.steps.is_empty(),
                "counterexample trace should have at least one step"
            );
            assert!(
                !trace.param_values.is_empty(),
                "counterexample should include parameter values"
            );
            // The trace should include the standard protocol parameters
            let param_names: Vec<&str> =
                trace.param_values.iter().map(|(n, _)| n.as_str()).collect();
            assert!(
                param_names.contains(&"n"),
                "trace should include parameter 'n', got: {:?}",
                param_names
            );
            assert!(
                param_names.contains(&"t"),
                "trace should include parameter 't', got: {:?}",
                param_names
            );
        }
        other => panic!("Expected UNSAFE with counterexample, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 4: Certificate generation should FAIL for unsafe protocol
    // -----------------------------------------------------------------------
    let cert_err = pipeline::generate_kinduction_safety_certificate(
        UNSAFE_PROTOCOL,
        "buggy_consensus.trs",
        &opts,
    )
    .expect_err("certificate generation should fail for unsafe protocol");
    let err_msg = format!("{cert_err}");
    assert!(
        err_msg.contains("Cannot certify safety") || err_msg.contains("unsafe"),
        "error should mention safety certification failure, got: {err_msg}"
    );
}

// ===========================================================================
// Test 5: Full pipeline for UNSAFE invariant violation with k-induction
// ===========================================================================

#[test]
fn full_pipeline_detects_unsafe_invariant_via_unbounded_proof() {
    // -----------------------------------------------------------------------
    // Stage 1: Parse
    // -----------------------------------------------------------------------
    let program = pipeline::parse(UNSAFE_INVARIANT_PROTOCOL, "unsafe_inv.trs")
        .expect("parsing should succeed");
    assert_eq!(program.protocol.node.name, "UnsafeInvariant");

    // -----------------------------------------------------------------------
    // Stage 2: Lower
    // -----------------------------------------------------------------------
    let ta = pipeline::lower(&program).expect("lowering should succeed");
    assert!(!ta.locations.is_empty());

    // -----------------------------------------------------------------------
    // Stage 3: BMC detects the bug
    // -----------------------------------------------------------------------
    let opts = default_options();
    let bmc_result = pipeline::verify(UNSAFE_INVARIANT_PROTOCOL, "unsafe_inv.trs", &opts)
        .expect("BMC should complete");
    match &bmc_result {
        VerificationResult::Unsafe { trace } => {
            assert!(!trace.steps.is_empty());
        }
        other => panic!("Expected UNSAFE from BMC, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 4: k-induction also detects the bug
    // -----------------------------------------------------------------------
    let prove_result = pipeline::prove_safety(UNSAFE_INVARIANT_PROTOCOL, "unsafe_inv.trs", &opts)
        .expect("k-induction should complete");
    match &prove_result {
        UnboundedSafetyResult::Unsafe { trace } => {
            assert!(
                !trace.steps.is_empty(),
                "k-induction counterexample should have steps"
            );
            assert!(
                !trace.param_values.is_empty(),
                "k-induction counterexample should have parameter values"
            );
        }
        other => panic!("Expected UNSAFE from k-induction, got: {other}"),
    }

    // -----------------------------------------------------------------------
    // Stage 5: Certificate generation must refuse
    // -----------------------------------------------------------------------
    let cert_err = pipeline::generate_kinduction_safety_certificate(
        UNSAFE_INVARIANT_PROTOCOL,
        "unsafe_inv.trs",
        &opts,
    )
    .expect_err("should not certify unsafe protocol");
    assert!(
        format!("{cert_err}").contains("Cannot certify safety"),
        "error: {cert_err}"
    );
}

// ===========================================================================
// Test 6: Certificate bundle with tampered content is rejected by proof kernel
// ===========================================================================

#[test]
fn tampered_certificate_bundle_is_rejected_by_proof_kernel() {
    // First, generate a valid certificate.
    let opts = default_options();
    let cert =
        pipeline::generate_kinduction_safety_certificate(SAFE_PROTOCOL, "safe_simple.trs", &opts)
            .expect("certificate generation should succeed");

    let tmp = TempDir::new().expect("create temp dir");
    let bundle_dir = tmp.path().join("tampered_cert");
    write_bundle_to_dir(&bundle_dir, &cert, "kinduction");

    // Sanity: the bundle is initially valid
    let report = check_bundle_integrity(&bundle_dir).expect("load should succeed");
    assert!(report.is_ok(), "initially valid: {:?}", report.issues);

    // Tamper with one of the obligation files by appending junk
    let base_case_path = bundle_dir.join("base_case.smt2");
    let mut content = fs::read_to_string(&base_case_path).expect("read");
    content.push_str("\n; TAMPERED");
    fs::write(&base_case_path, content).expect("write tampered");

    // The proof kernel should detect the hash mismatch
    let report = check_bundle_integrity(&bundle_dir).expect("load should succeed");
    assert!(
        !report.is_ok(),
        "tampered bundle should have integrity issues"
    );
    let issue_codes: Vec<&str> = report.issues.iter().map(|i| i.code).collect();
    assert!(
        issue_codes.contains(&"obligation_hash_mismatch"),
        "should detect hash mismatch, got issues: {:?}",
        report.issues
    );
}

// ===========================================================================
// Test 7: Verify each stage's output feeds into the next (explicit chaining)
// ===========================================================================

#[test]
fn pipeline_stages_chain_correctly_with_explicit_intermediate_inspection() {
    // Stage 1: DSL parse (using the raw DSL crate directly)
    let program =
        tarsier_dsl::parse(SAFE_PROTOCOL, "chain_test.trs").expect("DSL parse should succeed");
    assert_eq!(program.protocol.node.name, "SafeSimple");
    assert_eq!(program.protocol.node.properties.len(), 1);

    // Stage 2: IR lowering (using the IR crate directly)
    let ta = tarsier_ir::lowering::lower(&program).expect("IR lowering should succeed");
    let n_locations = ta.locations.len();
    let n_params = ta.parameters.len();
    let _n_shared = ta.shared_vars.len();
    assert!(n_locations > 0);
    assert!(n_params > 0);

    // Stage 3: Validate the TA (structural integrity)
    ta.validate().expect("TA validation should pass");

    // Stage 4: Engine-level verify (exercises encoder + solver)
    let opts = default_options();
    let result = pipeline::verify(SAFE_PROTOCOL, "chain_test.trs", &opts)
        .expect("engine verify should succeed");
    assert!(
        matches!(result, VerificationResult::Safe { .. }),
        "chain test protocol should be safe"
    );

    // Stage 5: Prove unbounded safety
    let prove_result = pipeline::prove_safety(SAFE_PROTOCOL, "chain_test.trs", &opts)
        .expect("prove should succeed");
    assert!(
        matches!(prove_result, UnboundedSafetyResult::Safe { .. }),
        "chain test protocol should be provably safe"
    );

    // Stage 6: Certificate generation
    let cert = pipeline::generate_safety_certificate(SAFE_PROTOCOL, "chain_test.trs", &opts)
        .expect("certificate should generate");
    assert_eq!(cert.proof_engine, ProofEngine::KInduction);
    // The obligations reference the same counter system structure
    for obligation in &cert.obligations {
        assert!(
            obligation.smt2.len() > 100,
            "SMT scripts should be non-trivial"
        );
    }

    // Stage 7: Bundle write + kernel verify
    let tmp = TempDir::new().expect("create temp dir");
    let bundle_dir = tmp.path().join("chain_cert");
    write_bundle_to_dir(&bundle_dir, &cert, "kinduction");
    let report = check_bundle_integrity(&bundle_dir).expect("kernel check should load");
    assert!(report.is_ok(), "chain cert issues: {:?}", report.issues);

    // Final: verify metadata coherence
    assert_eq!(report.metadata.kind, "safety_proof");
    assert_eq!(report.metadata.protocol_file, "chain_test.trs");
    assert!(report.metadata.induction_k.is_some());
    assert!(
        report.metadata.bundle_sha256.is_some(),
        "bundle should have integrity hash"
    );
}
