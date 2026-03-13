use super::*;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tarsier_conformance::adapters::{AdapterFaultAction, ScheduledAdapterFault};

fn active_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/conformance/active")
        .join(name)
}

fn tmp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be available")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{}_{}.json", std::process::id(), nanos))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_http_json_body(stream: &mut TcpStream) -> serde_json::Value {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .expect("request read should succeed");
        if read == 0 {
            break 0;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_end(&buf) {
            break pos + 4;
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let content_len = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);

    while buf.len() < header_end + content_len {
        let read = stream
            .read(&mut chunk)
            .expect("request body read should succeed");
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }

    let body = &buf[header_end..header_end + content_len];
    serde_json::from_slice(body).expect("request body should be valid JSON")
}

fn spawn_mock_live_endpoint(
    expected_requests: usize,
    ok_status: bool,
) -> (
    String,
    Arc<Mutex<Vec<serde_json::Value>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let addr = listener
        .local_addr()
        .expect("local addr should be available");
    let url = format!("http://{addr}/active");
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);

    let handle = thread::spawn(move || {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().expect("request should connect");
            let body = read_http_json_body(&mut stream);
            received_clone.lock().expect("mutex should lock").push(body);

            let (status, body) = if ok_status {
                ("200 OK", "{\"status\":\"ok\"}")
            } else {
                ("500 Internal Server Error", "{\"status\":\"error\"}")
            };
            let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            stream
                .write_all(response.as_bytes())
                .expect("response should be writable");
        }
    });

    (url, received, handle)
}

#[test]
fn conformance_active_schedule_is_deterministic_for_seed() {
    let faults = vec![
        ScheduledAdapterFault {
            tick: 2,
            action: AdapterFaultAction::HealPartition,
        },
        ScheduledAdapterFault {
            tick: 2,
            action: AdapterFaultAction::ReorderChannel {
                channel: "vote".into(),
            },
        },
        ScheduledAdapterFault {
            tick: 1,
            action: AdapterFaultAction::DropMessage {
                channel: "vote".into(),
                from_process: Some(1),
                to_process: Some(2),
            },
        },
    ];

    let a = schedule_faults_deterministically(faults.clone(), 7);
    let b = schedule_faults_deterministically(faults, 7);
    assert_eq!(a, b);
    assert_eq!(a[0].tick, 1);
}

#[test]
fn conformance_active_schedule_seed_changes_same_tick_order() {
    let faults = vec![
        ScheduledAdapterFault {
            tick: 5,
            action: AdapterFaultAction::HealPartition,
        },
        ScheduledAdapterFault {
            tick: 5,
            action: AdapterFaultAction::RetireTwin { twin_id: 42 },
        },
        ScheduledAdapterFault {
            tick: 5,
            action: AdapterFaultAction::SpawnTwin {
                process_id: 1,
                twin_id: 101,
            },
        },
    ];

    let a = schedule_faults_deterministically(faults.clone(), 1);
    let b = schedule_faults_deterministically(faults, 2);
    assert_ne!(
        a.iter().map(|f| &f.action).collect::<Vec<_>>(),
        b.iter().map(|f| &f.action).collect::<Vec<_>>()
    );
}

struct ActiveCorpusCase {
    adapter: &'static str,
    fixture: &'static str,
    seed: u64,
    expected_faults: usize,
}

fn active_corpus_cases() -> Vec<ActiveCorpusCase> {
    vec![
        ActiveCorpusCase {
            adapter: "cometbft",
            fixture: "cometbft_faults_basic.json",
            seed: 11,
            expected_faults: 6,
        },
        ActiveCorpusCase {
            adapter: "runtime",
            fixture: "runtime_faults_basic.json",
            seed: 5,
            expected_faults: 3,
        },
        ActiveCorpusCase {
            adapter: "etcd-raft",
            fixture: "etcd_raft_faults_basic.json",
            seed: 17,
            expected_faults: 6,
        },
    ]
}

fn active_same_tick_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("cometbft", "cometbft_faults_same_tick.json"),
        ("runtime", "runtime_faults_same_tick.json"),
        ("etcd-raft", "etcd_raft_faults_same_tick.json"),
    ]
}

fn action_kinds(value: &serde_json::Value) -> Vec<String> {
    value["faults"]
        .as_array()
        .expect("faults array")
        .iter()
        .map(|f| {
            f["action"]["kind"]
                .as_str()
                .expect("kind string")
                .to_string()
        })
        .collect()
}

#[test]
fn classify_conformance_mismatch_triage_prefers_model_change_when_flagged() {
    let triage =
        classify_conformance_mismatch_triage(true, Some(CONFORMANCE_TRIAGE_ENGINE_REGRESSION));
    assert_eq!(triage, CONFORMANCE_TRIAGE_MODEL_CHANGE);
}

#[test]
fn classify_conformance_mismatch_triage_uses_trimmed_hint_or_defaults() {
    assert_eq!(
        classify_conformance_mismatch_triage(false, Some("  impl_divergence  ")),
        CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
    );
    assert_eq!(
        classify_conformance_mismatch_triage(false, Some("engine_regression")),
        CONFORMANCE_TRIAGE_ENGINE_REGRESSION
    );
    assert_eq!(
        classify_conformance_mismatch_triage(false, Some("unknown_hint")),
        CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
    );
}

#[test]
fn classify_conformance_load_error_triage_maps_known_stages() {
    assert_eq!(
        classify_conformance_load_error_triage("model_read"),
        CONFORMANCE_TRIAGE_MODEL_CHANGE
    );
    assert_eq!(
        classify_conformance_load_error_triage("trace_adapt"),
        CONFORMANCE_TRIAGE_IMPL_DIVERGENCE
    );
    assert_eq!(
        classify_conformance_load_error_triage("other"),
        CONFORMANCE_TRIAGE_ENGINE_REGRESSION
    );
}

#[test]
fn sanitize_artifact_component_normalizes_and_falls_back_to_entry() {
    assert_eq!(
        sanitize_artifact_component(" PBFT/Trace.File v1 "),
        "pbft_trace_file_v1"
    );
    assert_eq!(
        sanitize_artifact_component("Alpha-BETA_01"),
        "alpha-beta_01"
    );
    assert_eq!(sanitize_artifact_component("..."), "entry");
}

#[test]
fn write_json_artifact_creates_parent_directories_and_writes_json() {
    let out = tmp_path("tarsier_conformance_artifact_write");
    let nested = out.with_extension("").join("nested").join("report.json");
    let payload = serde_json::json!({
        "schema_version": 1,
        "overall": "pass",
        "entries": []
    });
    write_json_artifact(&nested, &payload).expect("json artifact write should succeed");
    let raw = fs::read_to_string(&nested).expect("artifact should be readable");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("artifact should parse");
    assert_eq!(parsed["overall"], "pass");
    fs::remove_dir_all(
        nested
            .parent()
            .expect("parent should exist")
            .parent()
            .expect("grandparent should exist"),
    )
    .ok();
}

#[test]
fn conformance_active_command_corpus_matrix_writes_expected_json_shape() {
    for case in active_corpus_cases() {
        let trace = active_fixture_path(case.fixture);
        let out = tmp_path(&format!("tarsier_conformance_active_{}", case.adapter));
        run_conformance_active_command(
            &trace,
            case.adapter,
            case.seed,
            "json",
            Some(&out),
            None,
            5000,
        )
        .expect("conformance-active should succeed on corpus fixture");

        let raw = fs::read_to_string(&out).expect("output JSON should be readable");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["adapter"], case.adapter);
        assert_eq!(value["seed"], case.seed);
        assert_eq!(
            value["faults"]
                .as_array()
                .expect("faults should be array")
                .len(),
            case.expected_faults
        );
        fs::remove_file(out).ok();
    }
}

#[test]
fn conformance_active_command_same_seed_is_deterministic_for_corpus_matrix() {
    for case in active_corpus_cases() {
        let trace = active_fixture_path(case.fixture);
        let out_a = tmp_path(&format!(
            "tarsier_conformance_active_det_a_{}",
            case.adapter
        ));
        let out_b = tmp_path(&format!(
            "tarsier_conformance_active_det_b_{}",
            case.adapter
        ));

        run_conformance_active_command(
            &trace,
            case.adapter,
            case.seed,
            "json",
            Some(&out_a),
            None,
            5000,
        )
        .expect("first deterministic replay should pass");
        run_conformance_active_command(
            &trace,
            case.adapter,
            case.seed,
            "json",
            Some(&out_b),
            None,
            5000,
        )
        .expect("second deterministic replay should pass");

        let a: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_a).expect("seed a output"))
                .expect("seed a json");
        let b: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_b).expect("seed b output"))
                .expect("seed b json");
        assert_eq!(a["faults"], b["faults"]);

        fs::remove_file(out_a).ok();
        fs::remove_file(out_b).ok();
    }
}

#[test]
fn conformance_active_command_seed_changes_same_tick_order_for_corpus_matrix() {
    for (adapter, fixture) in active_same_tick_cases() {
        let trace = active_fixture_path(fixture);
        let out_a = tmp_path(&format!("tarsier_conformance_active_seed_a_{adapter}"));
        let out_b = tmp_path(&format!("tarsier_conformance_active_seed_b_{adapter}"));

        run_conformance_active_command(&trace, adapter, 1, "json", Some(&out_a), None, 5000)
            .expect("seed 1 run should pass");
        run_conformance_active_command(&trace, adapter, 2, "json", Some(&out_b), None, 5000)
            .expect("seed 2 run should pass");

        let a: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_a).expect("seed a output"))
                .expect("seed a json");
        let b: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_b).expect("seed b output"))
                .expect("seed b json");

        assert_ne!(action_kinds(&a), action_kinds(&b));

        fs::remove_file(out_a).ok();
        fs::remove_file(out_b).ok();
    }
}

#[test]
fn conformance_active_live_mode_posts_contract_events() {
    let trace = active_fixture_path("cometbft_faults_basic.json");
    let out = tmp_path("tarsier_conformance_active_live");
    // 1 start + 6 tick + 6 fault + 1 stop
    let (endpoint, received, handle) = spawn_mock_live_endpoint(14, true);

    run_conformance_active_command(
        &trace,
        "cometbft",
        11,
        "json",
        Some(&out),
        Some(&endpoint),
        5000,
    )
    .expect("live conformance-active should succeed on mock endpoint");

    handle.join().expect("mock endpoint should join");

    let requests = received.lock().expect("mutex should lock");
    assert_eq!(requests.len(), 14);
    assert_eq!(requests[0]["op"], "start");
    assert_eq!(requests[0]["adapter"], "cometbft");
    assert_eq!(requests[13]["op"], "stop");
    assert_eq!(requests[13]["final_tick"], 6);

    let raw = fs::read_to_string(&out).expect("output JSON should be readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(value["live"]["endpoint"], endpoint);
    assert_eq!(value["live"]["contract"], "tarsier.active.v1");
    assert_eq!(value["live"]["events_sent"], 14);
    assert_eq!(value["live"]["final_tick"], 6);
    fs::remove_file(out).ok();
}

#[test]
fn conformance_active_live_mode_reports_endpoint_errors() {
    let trace = active_fixture_path("cometbft_faults_basic.json");
    let (endpoint, _received, handle) = spawn_mock_live_endpoint(1, false);
    let err =
        run_conformance_active_command(&trace, "cometbft", 11, "json", None, Some(&endpoint), 5000)
            .expect_err("live endpoint 500 should fail");
    handle.join().expect("mock endpoint should join");
    assert!(format!("{err}").contains("rejected event"));
}
