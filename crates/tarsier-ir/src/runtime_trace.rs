//! Process-level runtime trace types for conformance checking.
//!
//! These types represent what a real implementation would emit — individual
//! process events (transitions, sends, receives, decisions) rather than the
//! counter-level aggregates in [`crate::counter_system::Trace`].

/// A complete runtime trace of a protocol execution.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct RuntimeTrace {
    /// Schema version (currently 1).
    pub schema_version: u32,
    /// Protocol name from the `.trs` model.
    pub protocol_name: String,
    /// Concrete parameter bindings, e.g. `[("n", 4), ("t", 1)]`.
    pub params: Vec<(String, i64)>,
    /// Per-process traces.
    pub processes: Vec<ProcessTrace>,
}

/// Trace of events for a single process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessTrace {
    /// Unique process identifier.
    pub process_id: u64,
    /// Role this process plays (e.g. "Process", "Replica").
    pub role: String,
    /// Ordered sequence of events.
    pub events: Vec<ProcessEvent>,
}

/// A single event in a process trace.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessEvent {
    /// Monotonically increasing sequence number within this process.
    pub sequence: u64,
    /// The event payload.
    pub kind: ProcessEventKind,
}

/// The kind of process event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serialize", serde(tag = "type"))]
pub enum ProcessEventKind {
    /// Process starts in a location.
    Init { location: String },
    /// Process transitions from one location to another.
    Transition {
        from_location: String,
        to_location: String,
        rule_id: Option<usize>,
    },
    /// Process sends a message.
    Send {
        message_type: String,
        fields: Vec<(String, String)>,
    },
    /// Process receives/delivers a message.
    Receive {
        message_type: String,
        from_process: u64,
        fields: Vec<(String, String)>,
    },
    /// Process makes a decision.
    Decide { value: String },
    /// Process updates a local variable.
    VarUpdate { var_name: String, new_value: String },
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serialize")]
    mod serialize_tests {
        use crate::runtime_trace::*;

        #[test]
        fn test_runtime_trace_serialization() {
            let trace = RuntimeTrace {
                schema_version: 1,
                protocol_name: "TestProtocol".into(),
                params: vec![("n".into(), 4), ("t".into(), 1)],
                processes: vec![ProcessTrace {
                    process_id: 0,
                    role: "Replica".into(),
                    events: vec![
                        ProcessEvent {
                            sequence: 0,
                            kind: ProcessEventKind::Init {
                                location: "Replica_Init".into(),
                            },
                        },
                        ProcessEvent {
                            sequence: 1,
                            kind: ProcessEventKind::Send {
                                message_type: "Vote".into(),
                                fields: vec![("view".into(), "1".into())],
                            },
                        },
                        ProcessEvent {
                            sequence: 2,
                            kind: ProcessEventKind::Transition {
                                from_location: "Replica_Init".into(),
                                to_location: "Replica_Voted".into(),
                                rule_id: Some(0),
                            },
                        },
                        ProcessEvent {
                            sequence: 3,
                            kind: ProcessEventKind::Receive {
                                message_type: "Vote".into(),
                                from_process: 1,
                                fields: vec![],
                            },
                        },
                        ProcessEvent {
                            sequence: 4,
                            kind: ProcessEventKind::Decide {
                                value: "commit".into(),
                            },
                        },
                        ProcessEvent {
                            sequence: 5,
                            kind: ProcessEventKind::VarUpdate {
                                var_name: "decided".into(),
                                new_value: "true".into(),
                            },
                        },
                    ],
                }],
            };

            let json = serde_json::to_string_pretty(&trace).expect("serialize");
            let roundtrip: RuntimeTrace = serde_json::from_str(&json).expect("deserialize");

            assert_eq!(roundtrip.schema_version, 1);
            assert_eq!(roundtrip.protocol_name, "TestProtocol");
            assert_eq!(roundtrip.params.len(), 2);
            assert_eq!(roundtrip.processes.len(), 1);
            assert_eq!(roundtrip.processes[0].events.len(), 6);
        }

        #[test]
        fn test_schema_version() {
            let trace = RuntimeTrace {
                schema_version: 1,
                protocol_name: "Test".into(),
                params: vec![],
                processes: vec![],
            };

            let json = serde_json::to_value(&trace).expect("serialize");
            assert_eq!(json["schema_version"], 1);
        }
    }
}
