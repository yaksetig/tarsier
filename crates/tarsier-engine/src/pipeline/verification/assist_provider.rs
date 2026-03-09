//! Assist provider abstraction for AI-suggested invariants.

use super::assist::ProveFailurePromptPayload;

/// Provider kind for `prove --assist`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssistProviderKind {
    Mock,
    OpenAi,
}

impl AssistProviderKind {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "openai" => Ok(Self::OpenAi),
            other => Err(format!(
                "Unknown assist provider '{other}'. Use one of: mock, openai."
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::OpenAi => "openai",
        }
    }
}

/// Provider interface that returns raw (unvalidated) invariant suggestions.
pub trait AssistSuggestionProvider {
    fn kind(&self) -> AssistProviderKind;
    fn suggest_invariants(
        &self,
        payload: &ProveFailurePromptPayload,
        max_suggestions: usize,
    ) -> Result<Vec<String>, String>;
}

#[derive(Debug, Default)]
struct MockAssistProvider;

impl AssistSuggestionProvider for MockAssistProvider {
    fn kind(&self) -> AssistProviderKind {
        AssistProviderKind::Mock
    }

    fn suggest_invariants(
        &self,
        payload: &ProveFailurePromptPayload,
        max_suggestions: usize,
    ) -> Result<Vec<String>, String> {
        let limit = max_suggestions.max(1);
        let mut out = Vec::new();

        if let Some(cti) = &payload.failure.cti {
            for (loc, _) in cti.violating_locations.iter().take(limit) {
                out.push(format!("kappa[{loc}] == 0"));
            }
            for (loc, _) in cti
                .hypothesis_locations
                .iter()
                .take(limit.saturating_sub(out.len()))
            {
                out.push(format!("kappa[{loc}] >= 0"));
            }
        }

        if out.is_empty() {
            out.push("forall p: Node. true".to_string());
        }

        out.truncate(limit);
        Ok(out)
    }
}

#[derive(Debug, Default)]
struct OpenAiAssistProvider;

impl AssistSuggestionProvider for OpenAiAssistProvider {
    fn kind(&self) -> AssistProviderKind {
        AssistProviderKind::OpenAi
    }

    fn suggest_invariants(
        &self,
        _payload: &ProveFailurePromptPayload,
        _max_suggestions: usize,
    ) -> Result<Vec<String>, String> {
        Err("openai provider integration is not implemented yet".to_string())
    }
}

pub fn assist_provider_from_kind(
    kind: AssistProviderKind,
) -> Box<dyn AssistSuggestionProvider + Send + Sync> {
    match kind {
        AssistProviderKind::Mock => Box::new(MockAssistProvider),
        AssistProviderKind::OpenAi => Box::new(OpenAiAssistProvider),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::verification::assist::{
        PromptAutomatonSummary, PromptCtiSummary, PromptFailureSummary, ProofAttemptSummary,
    };

    fn sample_payload() -> ProveFailurePromptPayload {
        ProveFailurePromptPayload {
            schema_version: 1,
            protocol_file: "demo.trs".to_string(),
            protocol_source: "protocol Demo {}".to_string(),
            attempt: ProofAttemptSummary {
                solver: "z3".to_string(),
                proof_engine: "kinduction".to_string(),
                soundness: "strict".to_string(),
                max_k: 8,
                timeout_secs: 60,
            },
            automaton: PromptAutomatonSummary {
                parameters: vec!["n".to_string()],
                num_locations: 2,
                num_rules: 1,
                num_shared_vars: 1,
                num_initial_locations: 1,
                fault_model: "byzantine".to_string(),
                timing_model: "asynchronous".to_string(),
                network_semantics: "classic".to_string(),
                value_abstraction: "exact".to_string(),
                safety_property_canonical: "invariant:[[0]]".to_string(),
            },
            failure: PromptFailureSummary {
                result_kind: "not_proved".to_string(),
                summary: "Proof did not close up to k=3".to_string(),
                cti: Some(PromptCtiSummary {
                    k: 3,
                    classification: "likely_spurious".to_string(),
                    rationale: "induction CTI".to_string(),
                    violated_condition: "invariant violated".to_string(),
                    hypothesis_locations: vec![("Node::Init".to_string(), 1)],
                    violating_locations: vec![("Node::Bad".to_string(), 1)],
                }),
                trace_excerpt: vec![],
            },
        }
    }

    #[test]
    fn parse_provider_kind_accepts_mock_and_openai() {
        assert_eq!(
            AssistProviderKind::parse("mock").unwrap(),
            AssistProviderKind::Mock
        );
        assert_eq!(
            AssistProviderKind::parse("openai").unwrap(),
            AssistProviderKind::OpenAi
        );
        assert!(AssistProviderKind::parse("unknown").is_err());
    }

    #[test]
    fn mock_provider_returns_bounded_suggestions() {
        let payload = sample_payload();
        let provider = assist_provider_from_kind(AssistProviderKind::Mock);
        let suggestions = provider.suggest_invariants(&payload, 1).unwrap();
        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].contains("kappa["));
    }

    #[test]
    fn openai_provider_reports_unimplemented() {
        let payload = sample_payload();
        let provider = assist_provider_from_kind(AssistProviderKind::OpenAi);
        let err = provider.suggest_invariants(&payload, 2).unwrap_err();
        assert!(err.contains("not implemented"));
    }
}
