#![cfg(feature = "governance")]

use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be available")
        .as_nanos();
    dir.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
    dir
}

#[test]
fn governance_pipeline_single_command_runs_all_required_gates_and_emits_json() {
    let root = workspace_root();
    let tmp = tmp_dir("tarsier_governance_pipeline");
    fs::create_dir_all(&tmp).expect("tmp dir should be created");

    let safe_model = tmp.join("safe_model.trs");
    let buggy_model = tmp.join("buggy_model.trs");
    fs::write(
        &safe_model,
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
    fs::write(
        &buggy_model,
        r#"
protocol BuggyToy {
    params n, t;
    resilience: t = 1;
    adversary { model: byzantine; bound: t; equivocation: full; }

    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }

    property inv: safety {
        forall p: R. p.decided == false
    }
}
"#,
    )
    .expect("buggy model should be written");

    let cert_manifest = tmp.join("cert_suite.json");
    let cert_manifest_json = json!({
        "schema_version": 2,
        "enforce_library_coverage": false,
        "enforce_corpus_breadth": false,
        "enforce_model_hash_consistency": false,
        "enforce_known_bug_sentinels": false,
        "entries": [
            {
                "file": safe_model.display().to_string(),
                "family": "toy",
                "class": "expected_safe",
                "verify": "safe",
                "notes": "Tiny safe regression for governance pipeline integration test.",
                "model_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            {
                "file": buggy_model.display().to_string(),
                "family": "toy",
                "class": "known_bug",
                "verify": "unsafe",
                "notes": "Tiny unsafe regression sentinel for governance pipeline integration test.",
                "model_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        ]
    });
    fs::write(
        &cert_manifest,
        serde_json::to_string_pretty(&cert_manifest_json).expect("serialize cert manifest"),
    )
    .expect("cert manifest should be written");

    let conformance_manifest = tmp.join("conformance_suite.json");
    let conformance_manifest_json = json!({
        "schema_version": 1,
        "suite_name": "governance-pipeline-test",
        "description": "Single-entry conformance manifest for governance pipeline integration testing.",
        "entries": [
            {
                "name": "valid_vote_trace",
                "protocol_file": root.join("crates/tarsier-conformance/tests/fixtures/simple_vote.trs").display().to_string(),
                "trace_file": root.join("crates/tarsier-conformance/tests/fixtures/valid_trace.json").display().to_string(),
                "expected_verdict": "pass",
                "tags": ["integration", "governance"]
            }
        ]
    });
    fs::write(
        &conformance_manifest,
        serde_json::to_string_pretty(&conformance_manifest_json)
            .expect("serialize conformance manifest"),
    )
    .expect("conformance manifest should be written");

    let benchmark_report = tmp.join("benchmark_report.json");
    fs::write(
        &benchmark_report,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "performance_gate": {"pass": true, "threshold_ms": 5000},
            "scale_band_gate": {"pass": true},
            "summary": {"total": 2, "ok": 2, "failed": 0}
        }))
        .expect("serialize benchmark report"),
    )
    .expect("benchmark report should be written");

    let out_report = tmp.join("governance_report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_tarsier"))
        .arg("--allow-degraded-sandbox")
        .arg("governance-pipeline")
        .arg(safe_model.display().to_string())
        .arg("--cert-manifest")
        .arg(cert_manifest.display().to_string())
        .arg("--conformance-manifest")
        .arg(conformance_manifest.display().to_string())
        .arg("--benchmark-report")
        .arg(benchmark_report.display().to_string())
        .arg("--solver")
        .arg("z3")
        .arg("--depth")
        .arg("2")
        .arg("--k")
        .arg("2")
        .arg("--timeout")
        .arg("30")
        .arg("--format")
        .arg("json")
        .arg("--out")
        .arg(out_report.display().to_string())
        .env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .current_dir(&root)
        .output()
        .expect("failed to execute governance pipeline");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        matches!(output.status.code(), Some(0) | Some(2)),
        "governance pipeline command failed unexpectedly: {stderr}"
    );

    let report: Value = serde_json::from_str(
        &fs::read_to_string(&out_report).expect("governance report should exist"),
    )
    .expect("governance report should be valid json");

    assert_eq!(report["schema_version"], "v1");
    let gates = report["gates"]
        .as_array()
        .expect("gates should be an array");
    assert_eq!(gates.len(), 4, "expected proof/cert/corpus/perf gates");

    let mut seen = std::collections::BTreeSet::new();
    for gate in gates {
        let gate_name = gate["gate"].as_str().expect("gate name");
        seen.insert(gate_name.to_string());
        let status = gate["status"].as_str().unwrap_or_default();
        assert!(
            matches!(status, "pass" | "fail" | "skip" | "error"),
            "unexpected gate status for {gate_name}: {status}"
        );
        assert!(
            gate.get("details").map(|d| d.is_object()).unwrap_or(false),
            "gate {gate_name} should include machine-readable details object"
        );
    }
    assert_eq!(
        seen,
        ["cert", "corpus", "perf", "proof"]
            .into_iter()
            .map(str::to_string)
            .collect()
    );

    let gate_map: std::collections::BTreeMap<String, String> = gates
        .iter()
        .map(|g| {
            (
                g["gate"].as_str().unwrap_or_default().to_string(),
                g["status"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(gate_map.get("cert").map(String::as_str), Some("pass"));
    assert_eq!(gate_map.get("corpus").map(String::as_str), Some("pass"));
    assert_eq!(gate_map.get("perf").map(String::as_str), Some("pass"));

    let _ = fs::remove_dir_all(&tmp);
}
