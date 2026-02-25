#![cfg(feature = "governance")]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn tmp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic enough for tests")
        .as_nanos();
    path.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
    path
}

fn run_tarsier(cwd: &Path, args: &[String]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tarsier"));
    cmd.current_dir(cwd);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to run tarsier")
}

fn write_safe_model(path: &Path) {
    fs::write(
        path,
        r#"
protocol SafeToy {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: none; }

    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }

    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
    )
    .expect("safe model should be written");
}

#[test]
fn governance_bundle_verifier_checks_signature_schema_and_completeness() {
    let root = workspace_root();
    let tmp = tmp_dir("tarsier_gov_bundle_verify");
    fs::create_dir_all(&tmp).expect("tmp dir should be created");

    let model = tmp.join("safe_model.trs");
    let report_out = tmp.join("analysis-report.json");
    write_safe_model(&model);

    let analyze = run_tarsier(
        &root,
        &[
            "--allow-degraded-sandbox".to_string(),
            "analyze".to_string(),
            model.display().to_string(),
            "--profile".to_string(),
            "governance".to_string(),
            "--goal".to_string(),
            "release".to_string(),
            "--depth".to_string(),
            "2".to_string(),
            "--k".to_string(),
            "2".to_string(),
            "--timeout".to_string(),
            "30".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--report-out".to_string(),
            report_out.display().to_string(),
        ],
    );
    assert!(
        matches!(analyze.status.code(), Some(0) | Some(2)),
        "analyze command failed unexpectedly: {}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let bundle = tmp.join("governance-bundle.json");
    assert!(bundle.exists(), "governance bundle should be generated");

    let verify_ok = run_tarsier(
        &root,
        &[
            "verify-governance-bundle".to_string(),
            bundle.display().to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
    assert!(
        verify_ok.status.success(),
        "governance bundle verification should pass: {}",
        String::from_utf8_lossy(&verify_ok.stderr)
    );
    let ok_report: Value =
        serde_json::from_slice(&verify_ok.stdout).expect("verify output should be valid json");
    assert_eq!(ok_report["overall"], "pass");
    for required in ["schema", "signature", "completeness"] {
        assert!(
            ok_report["checks"]
                .as_array()
                .expect("checks array")
                .iter()
                .any(|c| c["check"] == required && c["status"] == "pass"),
            "expected pass for check '{required}'"
        );
    }

    // Tamper the bundle payload; signature check must fail.
    let mut tampered: Value = serde_json::from_str(
        &fs::read_to_string(&bundle).expect("bundle should be readable for tampering"),
    )
    .expect("bundle should parse");
    tampered["analysis_report"]["overall"] = Value::String("tampered".to_string());
    fs::write(
        &bundle,
        serde_json::to_string_pretty(&tampered).expect("tampered bundle should serialize"),
    )
    .expect("tampered bundle should be written");

    let verify_tampered = run_tarsier(
        &root,
        &[
            "verify-governance-bundle".to_string(),
            bundle.display().to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
    assert!(
        !verify_tampered.status.success(),
        "tampered bundle verification must fail"
    );
    let tampered_report: Value = serde_json::from_slice(&verify_tampered.stdout)
        .expect("tampered verify output should be valid json");
    assert_eq!(tampered_report["overall"], "fail");
    assert!(
        tampered_report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .any(|c| c["check"] == "signature" && c["status"] == "fail"),
        "signature check should fail after payload tampering"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn governance_bundle_verifier_detects_missing_artifacts() {
    let root = workspace_root();
    let tmp = tmp_dir("tarsier_gov_bundle_missing_artifact");
    fs::create_dir_all(&tmp).expect("tmp dir should be created");

    let model = tmp.join("safe_model.trs");
    let report_out = tmp.join("analysis-report.json");
    write_safe_model(&model);

    let analyze = run_tarsier(
        &root,
        &[
            "--allow-degraded-sandbox".to_string(),
            "analyze".to_string(),
            model.display().to_string(),
            "--profile".to_string(),
            "governance".to_string(),
            "--goal".to_string(),
            "release".to_string(),
            "--depth".to_string(),
            "2".to_string(),
            "--k".to_string(),
            "2".to_string(),
            "--timeout".to_string(),
            "30".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--report-out".to_string(),
            report_out.display().to_string(),
        ],
    );
    assert!(
        matches!(analyze.status.code(), Some(0) | Some(2)),
        "analyze command failed unexpectedly: {}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let bundle = tmp.join("governance-bundle.json");
    assert!(bundle.exists(), "governance bundle should be generated");

    // Remove analysis report artifact while keeping bundle untouched: signature should pass,
    // completeness must fail.
    fs::remove_file(&report_out).expect("analysis report artifact should be removable");

    let verify_missing = run_tarsier(
        &root,
        &[
            "verify-governance-bundle".to_string(),
            bundle.display().to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
    assert!(
        !verify_missing.status.success(),
        "verification must fail for missing artifact"
    );
    let missing_report: Value =
        serde_json::from_slice(&verify_missing.stdout).expect("verify output should be valid json");
    assert_eq!(missing_report["overall"], "fail");
    assert!(
        missing_report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .any(|c| c["check"] == "signature" && c["status"] == "pass"),
        "signature should still pass when only external artifact is missing"
    );
    assert!(
        missing_report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .any(|c| c["check"] == "completeness" && c["status"] == "fail"),
        "completeness check should fail when artifact is missing"
    );

    let _ = fs::remove_dir_all(&tmp);
}
