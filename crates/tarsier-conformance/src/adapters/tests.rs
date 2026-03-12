use super::*;

#[test]
fn adapter_kind_parse_roundtrip() {
    for raw in ADAPTER_FAMILIES {
        let kind = AdapterKind::from_str(raw).expect("known adapter should parse");
        assert_eq!(kind.as_str(), raw);
    }
    assert!(AdapterKind::from_str("bogus").is_err());
}

#[test]
fn runtime_adapter_rejects_wrong_schema_version() {
    let raw = r#"{"schema_version":2,"protocol_name":"X","params":[],"processes":[]}"#;
    let err = adapt_trace(AdapterKind::Runtime, raw).expect_err("schema mismatch should fail");
    assert!(format!("{err}").contains("schema_version must be 1"));
}

#[test]
fn cometbft_adapter_maps_recv_and_transition_events() {
    let raw = r#"{
            "schema_version": 1,
            "protocol_name": "PBFTSimpleSafe",
            "params": [["n",4],["t",1],["f",1]],
            "nodes": [{
                "node_id": 0,
                "role": "Replica",
                "events": [
                    {"kind":"init","seq":0,"location":"Replica_start[decided=false,decision=false]"},
                    {"kind":"recv","seq":1,"msg":"PrePrepare","from":1},
                    {"kind":"transition","seq":2,"from":"Replica_start[decided=false,decision=false]","to":"Replica_prepared[decided=false,decision=false]"}
                ]
            }]
        }"#;
    let trace = adapt_trace(AdapterKind::CometBft, raw).expect("adapter should parse");
    assert_eq!(trace.processes.len(), 1);
    match &trace.processes[0].events[1].kind {
        ProcessEventKind::Receive { message_type, .. } => {
            assert_eq!(message_type, "cnt_PrePrepare@Replica");
        }
        other => panic!("expected receive event, got {other:?}"),
    }
}

#[test]
fn etcd_raft_adapter_maps_term_dependent_counter_names() {
    let raw = r#"{
            "schema_version": 1,
            "protocol_name": "RaftElectionSafety",
            "params": [["n",4],["t",1],["f",1],["gst",0]],
            "peers": [{
                "peer_id": 0,
                "role": "Replica",
                "steps": [
                    {"event":"boot","index":0,"state":"Replica_pre[decided=false]"},
                    {"event":"recv","index":1,"msg":"Vote","from":1,"term":0}
                ]
            }]
        }"#;
    let trace = adapt_trace(AdapterKind::EtcdRaft, raw).expect("adapter should parse");
    match &trace.processes[0].events[1].kind {
        ProcessEventKind::Receive { message_type, .. } => {
            assert_eq!(message_type, "cnt_Vote@Replica[term=zero]");
        }
        other => panic!("expected receive event, got {other:?}"),
    }
}

#[test]
fn adapter_decode_errors_are_deterministic_for_corrupted_payloads() {
    let malformed = r#"{"schema_version":1,"protocol_name":"X","params":[],"nodes":[{"node_id":0,"events":[{"kind":"unknown"}]}]}"#;
    let err = adapt_trace(AdapterKind::CometBft, malformed)
        .expect_err("unknown event kind should fail deterministically");
    let msg = format!("{err}");
    assert!(msg.contains("cometbft"));
    assert!(msg.contains("decode"));
}

#[test]
fn cometbft_active_fault_adapter_maps_faults() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"kind":"drop_message","tick":1,"channel":"Vote","from_process":1,"to_process":2},
                {"kind":"spawn_twin","tick":3,"process_id":7,"twin_id":7001}
            ]
        }"#;
    let mapped = adapt_active_faults(AdapterKind::CometBft, raw)
        .expect("cometbft active faults should parse");
    assert_eq!(mapped.len(), 2);
    assert!(matches!(
        mapped[0].action,
        AdapterFaultAction::DropMessage {
            ref channel,
            from_process: Some(1),
            to_process: Some(2)
        } if channel == "Vote"
    ));
    assert!(matches!(
        mapped[1].action,
        AdapterFaultAction::SpawnTwin {
            process_id: 7,
            twin_id: 7001
        }
    ));
}

#[test]
fn etcd_raft_active_fault_adapter_maps_faults() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"kind":"drop_message","tick":1,"msg":"Vote","from":1,"to":2},
                {"kind":"spawn_twin","tick":3,"peer_id":7,"twin_id":7001}
            ]
        }"#;
    let mapped = adapt_active_faults(AdapterKind::EtcdRaft, raw)
        .expect("etcd-raft active faults should parse");
    assert_eq!(mapped.len(), 2);
    assert!(matches!(
        mapped[0].action,
        AdapterFaultAction::DropMessage {
            ref channel,
            from_process: Some(1),
            to_process: Some(2)
        } if channel == "Vote"
    ));
    assert!(matches!(
        mapped[1].action,
        AdapterFaultAction::SpawnTwin {
            process_id: 7,
            twin_id: 7001
        }
    ));
}

#[test]
fn etcd_raft_active_fault_adapter_rejects_non_monotonic_ticks() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"kind":"heal_partition","tick":4},
                {"kind":"drop_message","tick":2,"msg":"Vote"}
            ]
        }"#;
    let err = adapt_active_faults(AdapterKind::EtcdRaft, raw)
        .expect_err("non-monotonic ticks should fail");
    assert!(format!("{err}").contains("nondecreasing"));
}

#[test]
fn active_fault_adapter_rejects_non_monotonic_ticks() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"kind":"heal_partition","tick":4},
                {"kind":"drop_message","tick":2,"channel":"Vote"}
            ]
        }"#;
    let err = adapt_active_faults(AdapterKind::CometBft, raw)
        .expect_err("non-monotonic ticks should fail");
    assert!(format!("{err}").contains("nondecreasing"));
}

#[test]
fn runtime_active_fault_adapter_maps_nested_and_flat_forms() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"tick":1,"kind":"drop_message","channel":"Vote","from_process":1,"to_process":2},
                {"tick":2,"action":{"kind":"heal_partition"}},
                {"tick":3,"kind":"spawn_twin","process_id":7,"twin_id":7001}
            ]
        }"#;
    let mapped =
        adapt_active_faults(AdapterKind::Runtime, raw).expect("runtime active faults should parse");
    assert_eq!(mapped.len(), 3);
    assert!(matches!(
        mapped[0].action,
        AdapterFaultAction::DropMessage {
            ref channel,
            from_process: Some(1),
            to_process: Some(2)
        } if channel == "Vote"
    ));
    assert!(matches!(
        mapped[1].action,
        AdapterFaultAction::HealPartition
    ));
    assert!(matches!(
        mapped[2].action,
        AdapterFaultAction::SpawnTwin {
            process_id: 7,
            twin_id: 7001
        }
    ));
}

#[test]
fn runtime_active_fault_adapter_rejects_non_monotonic_ticks() {
    let raw = r#"{
            "schema_version": 1,
            "faults": [
                {"tick":4,"kind":"heal_partition"},
                {"tick":2,"kind":"drop_message","channel":"Vote"}
            ]
        }"#;
    let err = adapt_active_faults(AdapterKind::Runtime, raw)
        .expect_err("non-monotonic ticks should fail");
    assert!(format!("{err}").contains("nondecreasing"));
}

#[test]
fn etcd_raft_active_fault_adapter_accepts_empty_faults() {
    let faults = adapt_active_faults(AdapterKind::EtcdRaft, r#"{"schema_version":1,"faults":[]}"#)
        .expect("empty etcd-raft fault list should succeed");
    assert!(faults.is_empty());
}
