use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    path.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
    path
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

const DOMAIN_TAG: &str = "tarsier-certificate-v2\n";

fn compute_bundle_sha256(metadata: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG.as_bytes());
    hasher.update(metadata["kind"].as_str().unwrap().as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata["protocol_file"].as_str().unwrap().as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata["proof_engine"].as_str().unwrap().as_bytes());
    hasher.update(b"\n");
    match metadata["induction_k"].as_u64() {
        Some(k) => hasher.update(k.to_string().as_bytes()),
        None => hasher.update(b"none"),
    };
    hasher.update(b"\n");
    hasher.update(metadata["solver_used"].as_str().unwrap().as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata["soundness"].as_str().unwrap().as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata["fairness"].as_str().unwrap_or("").as_bytes());
    hasher.update(b"\n");
    if let Some(bounds) = metadata["committee_bounds"].as_array() {
        for bound in bounds {
            let arr = bound.as_array().unwrap();
            hasher.update(arr[0].as_str().unwrap().as_bytes());
            hasher.update(b"=");
            hasher.update(arr[1].as_u64().unwrap().to_string().as_bytes());
            hasher.update(b"\n");
        }
    }
    if let Some(obligations) = metadata["obligations"].as_array() {
        for obligation in obligations {
            hasher.update(obligation["name"].as_str().unwrap().as_bytes());
            hasher.update(b"|");
            hasher.update(obligation["expected"].as_str().unwrap().as_bytes());
            hasher.update(b"|");
            hasher.update(obligation["file"].as_str().unwrap().as_bytes());
            hasher.update(b"|");
            hasher.update(obligation["sha256"].as_str().unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(obligation["proof_file"].as_str().unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(obligation["proof_sha256"].as_str().unwrap_or("").as_bytes());
            hasher.update(b"\n");
        }
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn write_valid_kinduction_bundle(bundle: &std::path::Path) -> serde_json::Value {
    let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
    let hash = sha256_hex(script.as_bytes());
    fs::write(bundle.join("base_case.smt2"), script).unwrap();
    fs::write(bundle.join("inductive_step.smt2"), script).unwrap();

    let mut metadata = serde_json::json!({
        "schema_version": 2,
        "kind": "safety_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "kinduction",
        "induction_k": 2,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": null,
        "committee_bounds": [],
        "bundle_sha256": null,
        "obligations": [
            {
                "name": "base_case",
                "expected": "unsat",
                "file": "base_case.smt2",
                "sha256": hash
            },
            {
                "name": "inductive_step",
                "expected": "unsat",
                "file": "inductive_step.smt2",
                "sha256": hash
            }
        ]
    });
    let bundle_hash = compute_bundle_sha256(&metadata);
    metadata["bundle_sha256"] = serde_json::json!(bundle_hash);
    fs::write(
        bundle.join("certificate.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();
    metadata
}

fn certcheck_bin() -> PathBuf {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("tarsier-certcheck");
    path
}

#[cfg(unix)]
#[test]
fn certcheck_passes_valid_bundle_with_mock_solver() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_pass");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_kinduction_bundle(&bundle);

    // Create a mock solver that always returns "unsat"
    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "certcheck should pass for valid bundle with mock solver.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("PASSED"), "output should contain PASSED");

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_fails_on_tampered_obligation() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_tamper");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_kinduction_bundle(&bundle);

    // Tamper with an obligation after metadata was written
    fs::write(
        bundle.join("base_case.smt2"),
        "(set-logic QF_LIA)\n(assert true)\n(check-sat)\n(exit)\n",
    )
    .unwrap();

    // Create a mock solver
    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "certcheck should fail for tampered obligation.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("obligation_hash_mismatch") || stdout.contains("FAIL"),
        "output should indicate integrity failure.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    fs::remove_dir_all(&dir).ok();
}

fn write_valid_bundle_with_proofs(bundle: &std::path::Path) -> serde_json::Value {
    let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
    let proof = "unsat\n(proof\n  (step1 :rule resolution)\n)\n";
    let hash = sha256_hex(script.as_bytes());
    let proof_hash = sha256_hex(proof.as_bytes());
    fs::write(bundle.join("base_case.smt2"), script).unwrap();
    fs::write(bundle.join("inductive_step.smt2"), script).unwrap();
    fs::write(bundle.join("base_case.proof"), proof).unwrap();
    fs::write(bundle.join("inductive_step.proof"), proof).unwrap();

    let mut metadata = serde_json::json!({
        "schema_version": 2,
        "kind": "safety_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "kinduction",
        "induction_k": 2,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": null,
        "committee_bounds": [],
        "bundle_sha256": null,
        "obligations": [
            {
                "name": "base_case",
                "expected": "unsat",
                "file": "base_case.smt2",
                "sha256": hash,
                "proof_file": "base_case.proof",
                "proof_sha256": proof_hash
            },
            {
                "name": "inductive_step",
                "expected": "unsat",
                "file": "inductive_step.smt2",
                "sha256": hash,
                "proof_file": "inductive_step.proof",
                "proof_sha256": proof_hash
            }
        ]
    });
    let bundle_hash = compute_bundle_sha256(&metadata);
    metadata["bundle_sha256"] = serde_json::json!(bundle_hash);
    fs::write(
        bundle.join("certificate.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();
    metadata
}

fn write_valid_fair_liveness_bundle(bundle: &std::path::Path) -> serde_json::Value {
    let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
    let hash = sha256_hex(script.as_bytes());
    fs::write(bundle.join("init_implies_inv.smt2"), script).unwrap();
    fs::write(
        bundle.join("inv_and_transition_implies_inv_prime.smt2"),
        script,
    )
    .unwrap();
    fs::write(bundle.join("inv_implies_no_fair_bad.smt2"), script).unwrap();

    let mut metadata = serde_json::json!({
        "schema_version": 2,
        "kind": "fair_liveness_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "pdr",
        "induction_k": 5,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": "weak",
        "committee_bounds": [],
        "bundle_sha256": null,
        "obligations": [
            {
                "name": "init_implies_inv",
                "expected": "unsat",
                "file": "init_implies_inv.smt2",
                "sha256": hash
            },
            {
                "name": "inv_and_transition_implies_inv_prime",
                "expected": "unsat",
                "file": "inv_and_transition_implies_inv_prime.smt2",
                "sha256": hash
            },
            {
                "name": "inv_implies_no_fair_bad",
                "expected": "unsat",
                "file": "inv_implies_no_fair_bad.smt2",
                "sha256": hash
            }
        ]
    });
    let bundle_hash = compute_bundle_sha256(&metadata);
    metadata["bundle_sha256"] = serde_json::json!(bundle_hash);
    fs::write(
        bundle.join("certificate.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();
    metadata
}

fn write_invalid_fair_liveness_bundle_missing_obligation(
    bundle: &std::path::Path,
) -> serde_json::Value {
    let script = "(set-logic QF_LIA)\n(assert false)\n(check-sat)\n(exit)\n";
    let hash = sha256_hex(script.as_bytes());
    fs::write(bundle.join("init_implies_inv.smt2"), script).unwrap();
    fs::write(
        bundle.join("inv_and_transition_implies_inv_prime.smt2"),
        script,
    )
    .unwrap();

    // Missing `inv_implies_no_fair_bad` on purpose.
    let mut metadata = serde_json::json!({
        "schema_version": 2,
        "kind": "fair_liveness_proof",
        "protocol_file": "protocol.trs",
        "proof_engine": "pdr",
        "induction_k": 5,
        "solver_used": "z3",
        "soundness": "strict",
        "fairness": "weak",
        "committee_bounds": [],
        "bundle_sha256": null,
        "obligations": [
            {
                "name": "init_implies_inv",
                "expected": "unsat",
                "file": "init_implies_inv.smt2",
                "sha256": hash
            },
            {
                "name": "inv_and_transition_implies_inv_prime",
                "expected": "unsat",
                "file": "inv_and_transition_implies_inv_prime.smt2",
                "sha256": hash
            }
        ]
    });
    let bundle_hash = compute_bundle_sha256(&metadata);
    metadata["bundle_sha256"] = serde_json::json!(bundle_hash);
    fs::write(
        bundle.join("certificate.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();
    metadata
}

#[cfg(unix)]
#[test]
fn certcheck_fails_on_tampered_proof_object() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_tampered_proof");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_bundle_with_proofs(&bundle);

    // Tamper with a proof file after metadata hashes were finalized.
    fs::write(
        bundle.join("base_case.proof"),
        "unsat\n(proof\n  (tampered_step)\n)\n",
    )
    .unwrap();

    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "certcheck should fail for tampered proof object.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("proof_hash_mismatch") || stdout.contains("FAIL"),
        "output should indicate proof integrity failure.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_fails_on_deleted_proof_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_deleted_proof");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_bundle_with_proofs(&bundle);

    // Delete a proof file.
    fs::remove_file(bundle.join("inductive_step.proof")).unwrap();

    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "certcheck should fail for deleted proof file.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("missing_proof_file") || stdout.contains("FAIL"),
        "output should indicate missing proof file.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_passes_bundle_with_valid_proofs() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_with_proofs_pass");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_bundle_with_proofs(&bundle);

    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "certcheck should pass for valid bundle with proofs.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("PASSED"), "output should contain PASSED");

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_passes_fair_liveness_bundle_with_mock_solver() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_fair_liveness_pass");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_fair_liveness_bundle(&bundle);

    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "certcheck should pass for valid fair-liveness bundle with mock solver.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("PASSED"), "output should contain PASSED");

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_requires_and_passes_two_solver_replay_for_fair_liveness_bundle() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_fair_liveness_two_solver");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_valid_fair_liveness_bundle(&bundle);

    let solver_a = dir.join("mock_solver_a.sh");
    fs::write(&solver_a, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver_a, fs::Permissions::from_mode(0o755)).unwrap();

    let solver_b = dir.join("mock_solver_b.sh");
    fs::write(&solver_b, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver_b, fs::Permissions::from_mode(0o755)).unwrap();

    let solvers = format!(
        "{},{}",
        solver_a.to_str().unwrap(),
        solver_b.to_str().unwrap()
    );
    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solvers)
        .arg("--require-two-solvers")
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "certcheck should pass with two-solvers replay for fair-liveness bundle.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("PASSED"), "output should contain PASSED");
    assert!(
        stdout.contains("Replay summary: 3 passed, 0 failed"),
        "output should show successful replay of all fair-liveness obligations"
    );

    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn certcheck_rejects_fair_liveness_bundle_missing_required_obligation() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("certcheck_integration_fair_liveness_missing_obligation");
    fs::create_dir_all(&dir).unwrap();

    let bundle = dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    write_invalid_fair_liveness_bundle_missing_obligation(&bundle);

    let solver = dir.join("mock_solver.sh");
    fs::write(&solver, "#!/usr/bin/env bash\necho unsat\n").unwrap();
    fs::set_permissions(&solver, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(certcheck_bin())
        .arg(&bundle)
        .arg("--solvers")
        .arg(solver.to_str().unwrap())
        .output()
        .expect("certcheck binary should exist");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "certcheck should fail for fair-liveness bundle missing a required obligation.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("missing_required_obligation") || stdout.contains("FAIL"),
        "output should indicate required-obligation validation failure.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    fs::remove_dir_all(&dir).ok();
}
