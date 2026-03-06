//! Structured prompt payload serialization for failed `prove` attempts.

use crate::pipeline::verification::*;
use crate::pipeline::*;
use serde::Serialize;
use tarsier_ir::threshold_automaton::{TimingModel, ValueAbstractionMode};

const ASSIST_PROMPT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct ProveFailurePromptPayload {
    pub schema_version: u32,
    pub protocol_file: String,
    pub protocol_source: String,
    pub attempt: ProofAttemptSummary,
    pub automaton: PromptAutomatonSummary,
    pub failure: PromptFailureSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofAttemptSummary {
    pub solver: String,
    pub proof_engine: String,
    pub soundness: String,
    pub max_k: usize,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromptAutomatonSummary {
    pub parameters: Vec<String>,
    pub num_locations: usize,
    pub num_rules: usize,
    pub num_shared_vars: usize,
    pub num_initial_locations: usize,
    pub fault_model: String,
    pub timing_model: String,
    pub network_semantics: String,
    pub value_abstraction: String,
    pub safety_property_canonical: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromptFailureSummary {
    pub result_kind: String,
    pub summary: String,
    pub cti: Option<PromptCtiSummary>,
    pub trace_excerpt: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromptCtiSummary {
    pub k: usize,
    pub classification: String,
    pub rationale: String,
    pub violated_condition: String,
    pub hypothesis_locations: Vec<(String, i64)>,
    pub violating_locations: Vec<(String, i64)>,
}

pub fn prove_failure_prompt_payload(
    source: &str,
    filename: &str,
    options: &PipelineOptions,
    result: &UnboundedSafetyResult,
) -> Result<Option<ProveFailurePromptPayload>, PipelineError> {
    if matches!(
        result,
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. }
    ) {
        return Ok(None);
    }

    let program = parse(source, filename)?;
    let ta = lower_with_active_controls(&program, "prove_failure_prompt_payload")?;
    let property = extract_property(&ta, &program, options.soundness)?;

    let failure = match result {
        UnboundedSafetyResult::Unsafe { trace } => PromptFailureSummary {
            result_kind: "unsafe".into(),
            summary: format!(
                "Unsafe witness found with {} transition steps.",
                trace.steps.len()
            ),
            cti: None,
            trace_excerpt: trace
                .steps
                .iter()
                .take(8)
                .map(|s| {
                    format!(
                        "k={} rule=r{} delta={} deliveries={}",
                        s.smt_step,
                        s.rule_id.as_usize(),
                        s.delta,
                        s.deliveries.len()
                    )
                })
                .collect(),
        },
        UnboundedSafetyResult::NotProved { max_k, cti } => PromptFailureSummary {
            result_kind: "not_proved".into(),
            summary: format!("Proof did not close up to k={max_k}."),
            cti: cti.as_ref().map(|w| PromptCtiSummary {
                k: w.k,
                classification: w.classification.to_string(),
                rationale: w.rationale.clone(),
                violated_condition: w.violated_condition.clone(),
                hypothesis_locations: w.hypothesis_locations.clone(),
                violating_locations: w.violating_locations.clone(),
            }),
            trace_excerpt: Vec::new(),
        },
        UnboundedSafetyResult::Unknown { reason } => PromptFailureSummary {
            result_kind: "unknown".into(),
            summary: reason.clone(),
            cti: None,
            trace_excerpt: Vec::new(),
        },
        UnboundedSafetyResult::Safe { .. } | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {
            return Ok(None);
        }
    };

    Ok(Some(ProveFailurePromptPayload {
        schema_version: ASSIST_PROMPT_SCHEMA_VERSION,
        protocol_file: filename.to_string(),
        protocol_source: source.to_string(),
        attempt: ProofAttemptSummary {
            solver: solver_label(options.solver).into(),
            proof_engine: proof_engine_label(options.proof_engine).into(),
            soundness: soundness_label(options.soundness).into(),
            max_k: options.max_depth,
            timeout_secs: options.timeout_secs,
        },
        automaton: PromptAutomatonSummary {
            parameters: ta.parameters.iter().map(|p| p.name.clone()).collect(),
            num_locations: ta.locations.len(),
            num_rules: ta.rules.len(),
            num_shared_vars: ta.shared_vars.len(),
            num_initial_locations: ta.initial_locations.len(),
            fault_model: fault_model_label(ta.semantics.fault_model).into(),
            timing_model: timing_model_label(ta.semantics.timing_model).into(),
            network_semantics: network_semantics_label(ta.semantics.network_semantics).into(),
            value_abstraction: value_abstraction_label(ta.semantics.value_abstraction).into(),
            safety_property_canonical: safety_property_canonical(&property),
        },
        failure,
    }))
}

fn solver_label(solver: SolverChoice) -> &'static str {
    match solver {
        SolverChoice::Z3 => "z3",
        SolverChoice::Cvc5 => "cvc5",
    }
}

fn proof_engine_label(engine: ProofEngine) -> &'static str {
    match engine {
        ProofEngine::KInduction => "kinduction",
        ProofEngine::Pdr => "pdr",
    }
}

fn soundness_label(soundness: SoundnessMode) -> &'static str {
    match soundness {
        SoundnessMode::Strict => "strict",
        SoundnessMode::Permissive => "permissive",
    }
}

fn fault_model_label(model: FaultModel) -> &'static str {
    match model {
        FaultModel::Byzantine => "byzantine",
        FaultModel::Crash => "crash",
        FaultModel::CrashRecovery => "crash_recovery",
        FaultModel::Omission => "omission",
    }
}

fn timing_model_label(model: TimingModel) -> &'static str {
    match model {
        TimingModel::Asynchronous => "asynchronous",
        TimingModel::PartialSynchrony => "partial_synchrony",
    }
}

fn network_semantics_label(mode: NetworkSemantics) -> &'static str {
    match mode {
        NetworkSemantics::Classic => "classic",
        NetworkSemantics::IdentitySelective => "identity_selective",
        NetworkSemantics::CohortSelective => "cohort_selective",
        NetworkSemantics::ProcessSelective => "process_selective",
    }
}

fn value_abstraction_label(mode: ValueAbstractionMode) -> &'static str {
    match mode {
        ValueAbstractionMode::Exact => "exact",
        ValueAbstractionMode::Sign => "sign",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
protocol AssistPromptDemo {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }

    message Vote;

    role Node {
        var decided: bool = false;
        init Init;
        phase Init {
            when received >= 1 Vote => {
                decided = true;
                goto phase Done;
            }
        }
        phase Done {}
    }

    property inv: invariant {
        forall p: Node. p.decided == false
    }
}
"#;

    #[test]
    fn prove_failure_prompt_payload_safe_returns_none() {
        let options = PipelineOptions::default();
        let result = UnboundedSafetyResult::Safe { induction_k: 1 };
        let payload = prove_failure_prompt_payload(SRC, "assist.trs", &options, &result).unwrap();
        assert!(payload.is_none());
    }

    #[test]
    fn prove_failure_prompt_payload_not_proved_serializes() {
        let options = PipelineOptions::default();
        let result = UnboundedSafetyResult::NotProved {
            max_k: 3,
            cti: None,
        };
        let payload =
            prove_failure_prompt_payload(SRC, "assist.trs", &options, &result).unwrap();
        let payload = payload.expect("expected failure payload");
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.protocol_file, "assist.trs");
        assert_eq!(payload.failure.result_kind, "not_proved");
        assert_eq!(payload.attempt.proof_engine, "kinduction");
        assert_eq!(payload.automaton.network_semantics, "classic");
        assert!(
            payload
                .automaton
                .safety_property_canonical
                .contains("invariant")
        );
    }
}
