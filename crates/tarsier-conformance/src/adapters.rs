use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tarsier_ir::runtime_trace::{ProcessEvent, ProcessEventKind, ProcessTrace, RuntimeTrace};
use thiserror::Error;

pub const ADAPTER_RUNTIME: &str = "runtime";
pub const ADAPTER_COMETBFT: &str = "cometbft";
pub const ADAPTER_ETCD_RAFT: &str = "etcd-raft";
pub const ADAPTER_FAMILIES: [&str; 3] = [ADAPTER_RUNTIME, ADAPTER_COMETBFT, ADAPTER_ETCD_RAFT];

/// Stable adapter kind for implementation trace ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterKind {
    Runtime,
    CometBft,
    EtcdRaft,
}

impl AdapterKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdapterKind::Runtime => ADAPTER_RUNTIME,
            AdapterKind::CometBft => ADAPTER_COMETBFT,
            AdapterKind::EtcdRaft => ADAPTER_ETCD_RAFT,
        }
    }
}

impl FromStr for AdapterKind {
    type Err = AdapterError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            ADAPTER_RUNTIME => Ok(AdapterKind::Runtime),
            ADAPTER_COMETBFT => Ok(AdapterKind::CometBft),
            ADAPTER_ETCD_RAFT => Ok(AdapterKind::EtcdRaft),
            other => Err(AdapterError::UnknownAdapter(other.into())),
        }
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("unknown conformance adapter '{0}'")]
    UnknownAdapter(String),
    #[error("{family} adapter JSON decode failed: {source}")]
    Decode {
        family: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("{family} adapter schema_version must be 1, got {got}")]
    SchemaVersion { family: &'static str, got: u32 },
    #[error("{family} adapter input invalid: {message}")]
    Invalid {
        family: &'static str,
        message: String,
    },
}

/// Stable interface for implementation-family adapters.
pub trait TraceAdapter {
    fn kind(&self) -> AdapterKind;
    fn adapt_json(&self, raw: &str) -> Result<RuntimeTrace, AdapterError>;
}

pub fn adapt_trace(kind: AdapterKind, raw: &str) -> Result<RuntimeTrace, AdapterError> {
    match kind {
        AdapterKind::Runtime => RuntimeAdapter.adapt_json(raw),
        AdapterKind::CometBft => CometBftAdapter.adapt_json(raw),
        AdapterKind::EtcdRaft => EtcdRaftAdapter.adapt_json(raw),
    }
}

struct RuntimeAdapter;

impl TraceAdapter for RuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Runtime
    }

    fn adapt_json(&self, raw: &str) -> Result<RuntimeTrace, AdapterError> {
        let trace: RuntimeTrace =
            serde_json::from_str(raw).map_err(|source| AdapterError::Decode {
                family: ADAPTER_RUNTIME,
                source,
            })?;
        if trace.schema_version != 1 {
            return Err(AdapterError::SchemaVersion {
                family: ADAPTER_RUNTIME,
                got: trace.schema_version,
            });
        }
        Ok(trace)
    }
}

struct CometBftAdapter;

impl TraceAdapter for CometBftAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::CometBft
    }

    fn adapt_json(&self, raw: &str) -> Result<RuntimeTrace, AdapterError> {
        let input: CometBftInput =
            serde_json::from_str(raw).map_err(|source| AdapterError::Decode {
                family: ADAPTER_COMETBFT,
                source,
            })?;
        if input.schema_version != 1 {
            return Err(AdapterError::SchemaVersion {
                family: ADAPTER_COMETBFT,
                got: input.schema_version,
            });
        }
        if input.nodes.is_empty() {
            return Err(AdapterError::Invalid {
                family: ADAPTER_COMETBFT,
                message: "nodes must be non-empty".into(),
            });
        }
        let processes = input
            .nodes
            .into_iter()
            .map(convert_comet_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RuntimeTrace {
            schema_version: 1,
            protocol_name: input.protocol_name,
            params: input.params,
            processes,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CometBftInput {
    schema_version: u32,
    protocol_name: String,
    params: Vec<(String, i64)>,
    nodes: Vec<CometBftNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CometBftNode {
    node_id: u64,
    #[serde(default = "default_replica_role")]
    role: String,
    events: Vec<CometBftEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CometBftEvent {
    Init {
        seq: u64,
        location: String,
    },
    Transition {
        seq: u64,
        from: String,
        to: String,
        #[serde(default)]
        rule_id: Option<usize>,
    },
    Send {
        seq: u64,
        msg: String,
        #[serde(default)]
        fields: Vec<(String, String)>,
        #[serde(default)]
        counter: Option<String>,
    },
    Recv {
        seq: u64,
        msg: String,
        from: u64,
        #[serde(default)]
        fields: Vec<(String, String)>,
        #[serde(default)]
        counter: Option<String>,
    },
    Decide {
        seq: u64,
        value: String,
    },
    VarUpdate {
        seq: u64,
        name: String,
        value: String,
    },
}

fn default_replica_role() -> String {
    "Replica".into()
}

fn convert_comet_node(node: CometBftNode) -> Result<ProcessTrace, AdapterError> {
    if node.events.is_empty() {
        return Err(AdapterError::Invalid {
            family: ADAPTER_COMETBFT,
            message: format!("node {} has no events", node.node_id),
        });
    }
    let role = node.role;
    let mut events = Vec::with_capacity(node.events.len());
    for evt in node.events {
        let (sequence, kind) = match evt {
            CometBftEvent::Init { seq, location } => (seq, ProcessEventKind::Init { location }),
            CometBftEvent::Transition {
                seq,
                from,
                to,
                rule_id,
            } => (
                seq,
                ProcessEventKind::Transition {
                    from_location: from,
                    to_location: to,
                    rule_id,
                },
            ),
            CometBftEvent::Send {
                seq,
                msg,
                fields,
                counter,
            } => (
                seq,
                ProcessEventKind::Send {
                    message_type: counter.unwrap_or_else(|| format!("cnt_{msg}@{role}")),
                    fields,
                },
            ),
            CometBftEvent::Recv {
                seq,
                msg,
                from,
                fields,
                counter,
            } => (
                seq,
                ProcessEventKind::Receive {
                    message_type: counter.unwrap_or_else(|| format!("cnt_{msg}@{role}")),
                    from_process: from,
                    fields,
                },
            ),
            CometBftEvent::Decide { seq, value } => (seq, ProcessEventKind::Decide { value }),
            CometBftEvent::VarUpdate { seq, name, value } => (
                seq,
                ProcessEventKind::VarUpdate {
                    var_name: name,
                    new_value: value,
                },
            ),
        };
        events.push(ProcessEvent { sequence, kind });
    }
    Ok(ProcessTrace {
        process_id: node.node_id,
        role,
        events,
    })
}

struct EtcdRaftAdapter;

impl TraceAdapter for EtcdRaftAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::EtcdRaft
    }

    fn adapt_json(&self, raw: &str) -> Result<RuntimeTrace, AdapterError> {
        let input: EtcdRaftInput =
            serde_json::from_str(raw).map_err(|source| AdapterError::Decode {
                family: ADAPTER_ETCD_RAFT,
                source,
            })?;
        if input.schema_version != 1 {
            return Err(AdapterError::SchemaVersion {
                family: ADAPTER_ETCD_RAFT,
                got: input.schema_version,
            });
        }
        if input.peers.is_empty() {
            return Err(AdapterError::Invalid {
                family: ADAPTER_ETCD_RAFT,
                message: "peers must be non-empty".into(),
            });
        }
        let processes = input
            .peers
            .into_iter()
            .map(convert_raft_peer)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RuntimeTrace {
            schema_version: 1,
            protocol_name: input.protocol_name,
            params: input.params,
            processes,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EtcdRaftInput {
    schema_version: u32,
    protocol_name: String,
    params: Vec<(String, i64)>,
    peers: Vec<EtcdRaftPeer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EtcdRaftPeer {
    peer_id: u64,
    #[serde(default = "default_replica_role")]
    role: String,
    steps: Vec<EtcdRaftStep>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum EtcdRaftStep {
    Boot {
        index: u64,
        state: String,
    },
    Advance {
        index: u64,
        from_state: String,
        to_state: String,
        #[serde(default)]
        rule_id: Option<usize>,
    },
    Send {
        index: u64,
        msg: String,
        to: u64,
        #[serde(default)]
        term: Option<i64>,
        #[serde(default)]
        fields: Vec<(String, String)>,
        #[serde(default)]
        counter: Option<String>,
    },
    Recv {
        index: u64,
        msg: String,
        from: u64,
        #[serde(default)]
        term: Option<i64>,
        #[serde(default)]
        fields: Vec<(String, String)>,
        #[serde(default)]
        counter: Option<String>,
    },
    Commit {
        index: u64,
        value: String,
    },
    SetVar {
        index: u64,
        name: String,
        value: String,
    },
}

fn raft_counter_name(role: &str, msg: &str, term: Option<i64>) -> String {
    let term_suffix = if term.unwrap_or(0) == 0 {
        "zero"
    } else {
        "pos"
    };
    format!("cnt_{msg}@{role}[term={term_suffix}]")
}

fn convert_raft_peer(peer: EtcdRaftPeer) -> Result<ProcessTrace, AdapterError> {
    if peer.steps.is_empty() {
        return Err(AdapterError::Invalid {
            family: ADAPTER_ETCD_RAFT,
            message: format!("peer {} has no steps", peer.peer_id),
        });
    }
    let role = peer.role;
    let mut events = Vec::with_capacity(peer.steps.len());
    for step in peer.steps {
        let (sequence, kind) = match step {
            EtcdRaftStep::Boot { index, state } => {
                (index, ProcessEventKind::Init { location: state })
            }
            EtcdRaftStep::Advance {
                index,
                from_state,
                to_state,
                rule_id,
            } => (
                index,
                ProcessEventKind::Transition {
                    from_location: from_state,
                    to_location: to_state,
                    rule_id,
                },
            ),
            EtcdRaftStep::Send {
                index,
                msg,
                to,
                term,
                mut fields,
                counter,
            } => {
                fields.push(("to".into(), to.to_string()));
                (
                    index,
                    ProcessEventKind::Send {
                        message_type: counter
                            .unwrap_or_else(|| raft_counter_name(&role, &msg, term)),
                        fields,
                    },
                )
            }
            EtcdRaftStep::Recv {
                index,
                msg,
                from,
                fields,
                term,
                counter,
            } => (
                index,
                ProcessEventKind::Receive {
                    message_type: counter.unwrap_or_else(|| raft_counter_name(&role, &msg, term)),
                    from_process: from,
                    fields,
                },
            ),
            EtcdRaftStep::Commit { index, value } => (index, ProcessEventKind::Decide { value }),
            EtcdRaftStep::SetVar { index, name, value } => (
                index,
                ProcessEventKind::VarUpdate {
                    var_name: name,
                    new_value: value,
                },
            ),
        };
        events.push(ProcessEvent { sequence, kind });
    }
    Ok(ProcessTrace {
        process_id: peer.peer_id,
        role,
        events,
    })
}

#[cfg(test)]
mod tests {
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
}
