use std::collections::BTreeSet;

use tarsier_dsl::ast::{Action, GuardExpr, Program};

use crate::common::{to_pascal_case, to_snake_case};
use crate::{CodegenError, CodegenTarget};

/// Oracle extracted from a model and used to validate generated code surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelTraceOracle {
    pub protocol_name: String,
    pub messages: Vec<String>,
    pub roles: Vec<RoleTraceOracle>,
}

/// Per-role trace expectations derived from the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTraceOracle {
    pub role_name: String,
    pub role_name_pascal: String,
    pub init_phase_pascal: String,
    pub phases_pascal: Vec<String>,
    pub transitions: Vec<TransitionTraceOracle>,
}

/// Per-transition expectations derived from guards/actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionTraceOracle {
    pub from_phase_pascal: String,
    pub to_phase_pascal: Option<String>,
    pub sends: Vec<String>,
    pub guard_messages: Vec<String>,
    pub decides: bool,
}

/// Missing expectation produced by trace-oracle validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleMissing {
    pub check: String,
    pub expected_pattern: String,
}

/// Validation report comparing model oracle to generated code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleValidationReport {
    pub target: CodegenTarget,
    pub missing: Vec<OracleMissing>,
}

impl OracleValidationReport {
    pub fn is_match(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Build a model trace oracle from parsed DSL program.
pub fn build_model_trace_oracle(program: &Program) -> Result<ModelTraceOracle, CodegenError> {
    let protocol = &program.protocol.node;
    if protocol.roles.is_empty() {
        return Err(CodegenError::NoRoles(protocol.name.clone()));
    }

    let messages = protocol.messages.iter().map(|m| m.name.clone()).collect();
    let mut roles = Vec::new();

    for role in &protocol.roles {
        let role_decl = &role.node;
        let role_name_pascal = to_pascal_case(&role_decl.name);
        let phases_pascal = role_decl
            .phases
            .iter()
            .map(|phase| to_pascal_case(&phase.node.name))
            .collect::<Vec<_>>();

        let init_phase_pascal = role_decl
            .init_phase
            .as_ref()
            .map(|phase| to_pascal_case(phase))
            .or_else(|| phases_pascal.first().cloned())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut transitions = Vec::new();
        for phase in &role_decl.phases {
            let from_phase_pascal = to_pascal_case(&phase.node.name);
            for transition in &phase.node.transitions {
                let mut to_phase_pascal = None;
                let mut sends = Vec::new();
                let mut guard_messages = Vec::new();
                let mut decides = false;

                collect_guard_messages(&transition.node.guard, &mut guard_messages);

                for action in &transition.node.actions {
                    match action {
                        Action::GotoPhase { phase } => {
                            to_phase_pascal = Some(to_pascal_case(phase));
                        }
                        Action::Send { message_type, .. } => sends.push(message_type.clone()),
                        Action::Decide { .. } => decides = true,
                        _ => {}
                    }
                }

                transitions.push(TransitionTraceOracle {
                    from_phase_pascal: from_phase_pascal.clone(),
                    to_phase_pascal,
                    sends: dedup_sorted(sends),
                    guard_messages: dedup_sorted(guard_messages),
                    decides,
                });
            }
        }

        roles.push(RoleTraceOracle {
            role_name: role_decl.name.clone(),
            role_name_pascal,
            init_phase_pascal,
            phases_pascal,
            transitions,
        });
    }

    Ok(ModelTraceOracle {
        protocol_name: protocol.name.clone(),
        messages,
        roles,
    })
}

/// Validate generated code against the oracle contract for the given backend.
pub fn validate_generated_trace_oracle(
    oracle: &ModelTraceOracle,
    target: CodegenTarget,
    generated_code: &str,
) -> OracleValidationReport {
    let mut report = OracleValidationReport {
        target,
        missing: Vec::new(),
    };

    if matches!(target, CodegenTarget::Rust) {
        require_pattern(
            &mut report,
            generated_code,
            "rust.trace_recorder",
            "pub trait TraceRecorder".to_string(),
        );
    }

    for message in &oracle.messages {
        let pascal = to_pascal_case(message);
        match target {
            CodegenTarget::Rust => {
                require_pattern(
                    &mut report,
                    generated_code,
                    "message.decl",
                    format!("pub struct {pascal}Msg"),
                );
                require_pattern(
                    &mut report,
                    generated_code,
                    "message.enum_variant",
                    format!("{pascal}({pascal}Msg)"),
                );
            }
            CodegenTarget::Go => {
                require_pattern(
                    &mut report,
                    generated_code,
                    "message.decl",
                    format!("type {pascal}Msg struct"),
                );
            }
        }
    }

    for role in &oracle.roles {
        match target {
            CodegenTarget::Rust => {
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.phase_enum",
                    format!("pub enum {}Phase", role.role_name_pascal),
                );
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.state_struct",
                    format!("pub struct {}State", role.role_name_pascal),
                );
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.init_phase",
                    format!(
                        "phase: {}Phase::{},",
                        role.role_name_pascal, role.init_phase_pascal
                    ),
                );
                for phase in &role.phases_pascal {
                    require_pattern(
                        &mut report,
                        generated_code,
                        "role.phase_variant",
                        format!("    {phase},"),
                    );
                }
            }
            CodegenTarget::Go => {
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.phase_type",
                    format!("type {}Phase int", role.role_name_pascal),
                );
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.state_struct",
                    format!("type {}State struct", role.role_name_pascal),
                );
                require_pattern(
                    &mut report,
                    generated_code,
                    "role.init_phase",
                    format!(
                        "Phase: {}Phase{},",
                        role.role_name_pascal, role.init_phase_pascal
                    ),
                );
                for phase in &role.phases_pascal {
                    require_pattern(
                        &mut report,
                        generated_code,
                        "role.phase_variant",
                        format!("{}Phase{phase}", role.role_name_pascal),
                    );
                }
            }
        }

        let mut transition_targets = BTreeSet::new();
        let mut send_messages = BTreeSet::new();
        let mut guard_messages = BTreeSet::new();
        let mut decides = false;

        for transition in &role.transitions {
            if let Some(to) = &transition.to_phase_pascal {
                transition_targets.insert(to.clone());
            }
            for msg in &transition.sends {
                send_messages.insert(msg.clone());
            }
            for msg in &transition.guard_messages {
                guard_messages.insert(msg.clone());
            }
            if transition.decides {
                decides = true;
            }
        }

        for to_phase in transition_targets {
            match target {
                CodegenTarget::Rust => require_pattern(
                    &mut report,
                    generated_code,
                    "transition.goto_phase",
                    format!("self.phase = {}Phase::{to_phase};", role.role_name_pascal),
                ),
                CodegenTarget::Go => require_pattern(
                    &mut report,
                    generated_code,
                    "transition.goto_phase",
                    format!("s.Phase = {}Phase{to_phase}", role.role_name_pascal),
                ),
            }
        }

        for message in send_messages {
            match target {
                CodegenTarget::Rust => {
                    require_pattern(
                        &mut report,
                        generated_code,
                        "send.channel_auth",
                        format!("channel_auth_for_message_family(\"{message}\")"),
                    );
                    require_pattern(
                        &mut report,
                        generated_code,
                        "send.equivocation",
                        format!("equivocation_mode_for_message_family(\"{message}\")"),
                    );
                }
                CodegenTarget::Go => {
                    require_pattern(
                        &mut report,
                        generated_code,
                        "send.channel_auth",
                        format!("channelAuthForMessageFamily(\"{message}\")"),
                    );
                    require_pattern(
                        &mut report,
                        generated_code,
                        "send.equivocation",
                        format!("equivocationModeForMessageFamily(\"{message}\")"),
                    );
                }
            }
        }

        for message in guard_messages {
            let msg_pascal = to_pascal_case(&message);
            let msg_snake = to_snake_case(&message);
            match target {
                CodegenTarget::Rust => require_pattern(
                    &mut report,
                    generated_code,
                    "guard.message_buffer",
                    format!("self.{msg_snake}_buffer"),
                ),
                CodegenTarget::Go => require_pattern(
                    &mut report,
                    generated_code,
                    "guard.message_buffer",
                    format!("s.{msg_pascal}Buffer"),
                ),
            }
        }

        if decides {
            match target {
                CodegenTarget::Rust => require_pattern(
                    &mut report,
                    generated_code,
                    "decision.surface",
                    format!("decision = Some({}Decision", role.role_name_pascal),
                ),
                CodegenTarget::Go => require_pattern(
                    &mut report,
                    generated_code,
                    "decision.surface",
                    format!("decision = &{}Decision", role.role_name_pascal),
                ),
            }
        }
    }

    report
}

fn collect_guard_messages(guard: &GuardExpr, messages: &mut Vec<String>) {
    match guard {
        GuardExpr::Threshold(threshold) => messages.push(threshold.message_type.clone()),
        GuardExpr::And(left, right) | GuardExpr::Or(left, right) => {
            collect_guard_messages(left, messages);
            collect_guard_messages(right, messages);
        }
        _ => {}
    }
}

fn dedup_sorted(values: Vec<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for value in values {
        set.insert(value);
    }
    set.into_iter().collect()
}

fn require_pattern(
    report: &mut OracleValidationReport,
    generated_code: &str,
    check: &str,
    expected_pattern: String,
) {
    if !generated_code.contains(&expected_pattern) {
        report.missing.push(OracleMissing {
            check: check.to_string(),
            expected_pattern,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Program {
        tarsier_dsl::parse(source, "trace_oracle_test.trs").expect("parse failed")
    }

    #[test]
    fn oracle_extracts_transition_surface() {
        let source = include_str!("../../tarsier-dsl/../../examples/reliable_broadcast.trs");
        let program = parse(source);
        let oracle = build_model_trace_oracle(&program).expect("oracle build should succeed");

        assert_eq!(oracle.protocol_name, "ReliableBroadcast");
        assert!(oracle.messages.iter().any(|m| m == "Init"));
        assert!(oracle.messages.iter().any(|m| m == "Echo"));
        assert!(oracle.messages.iter().any(|m| m == "Ready"));

        let role = oracle
            .roles
            .iter()
            .find(|r| r.role_name_pascal == "Process")
            .expect("Process role should exist");
        assert!(role.phases_pascal.iter().any(|p| p == "Waiting"));
        assert!(role.phases_pascal.iter().any(|p| p == "Echoed"));
        assert!(role
            .transitions
            .iter()
            .any(|t| t.to_phase_pascal.as_deref() == Some("Echoed")));
        assert!(role
            .transitions
            .iter()
            .any(|t| t.guard_messages.iter().any(|m| m == "Ready")));
    }
}
