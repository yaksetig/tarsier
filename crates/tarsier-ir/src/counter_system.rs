use crate::threshold_automaton::{RuleId, ThresholdAutomaton};
use std::fmt;

/// A counter system derived from a threshold automaton.
///
/// Instead of tracking individual process states, we track counters:
/// how many processes are in each location (kappa), and the values
/// of shared variables (gamma).
#[derive(Debug, Clone)]
pub struct CounterSystem {
    /// Reference to the underlying threshold automaton.
    pub automaton: ThresholdAutomaton,
}

impl CounterSystem {
    /// Construct a counter-system wrapper from a threshold automaton.
    pub fn new(automaton: ThresholdAutomaton) -> Self {
        Self { automaton }
    }

    /// Return the number of control locations in the automaton.
    pub fn num_locations(&self) -> usize {
        self.automaton.locations.len()
    }

    /// Return the number of shared integer variables.
    pub fn num_shared_vars(&self) -> usize {
        self.automaton.shared_vars.len()
    }

    /// Return the number of transition rules.
    pub fn num_rules(&self) -> usize {
        self.automaton.rules.len()
    }

    /// Return the number of symbolic parameters.
    pub fn num_parameters(&self) -> usize {
        self.automaton.parameters.len()
    }
}

/// A configuration of the counter system at a specific step.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct Configuration {
    /// `kappa\[l\]` = number of processes in location `l`.
    pub kappa: Vec<i64>,
    /// `gamma\[v\]` = value of shared variable `v`.
    pub gamma: Vec<i64>,
    /// Parameter values.
    pub params: Vec<i64>,
}

impl Configuration {
    pub fn new(num_locations: usize, num_shared_vars: usize, num_params: usize) -> Self {
        Self {
            kappa: vec![0; num_locations],
            gamma: vec![0; num_shared_vars],
            params: vec![0; num_params],
        }
    }
}

/// Message action kind extracted from counter-level transition effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum MessageEventKind {
    /// Honest protocol send action.
    Send,
    /// Network delivery action into a recipient-scoped channel.
    Deliver,
    /// Network/adversary drop action.
    Drop,
    /// Adversarial forged message action.
    Forge,
    /// Adversarial equivocation action (same family, conflicting variants).
    Equivocate,
}

/// Authentication/signature provenance metadata for a message action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum SignatureProvenance {
    /// Message channel is unauthenticated (`auth: none`).
    UnauthenticatedChannel,
    /// Signed with the sender role's owned key.
    OwnedKey,
    /// Signed with a key marked compromised by the adversary model.
    CompromisedKey,
    /// Signed metadata indicates byzantine sender-controlled provenance.
    ByzantineSigner,
    /// Signed metadata is present but provenance is unresolved in abstraction.
    Unknown,
}

/// Authentication metadata attached to extracted message actions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageAuthMetadata {
    /// Whether this message family is authenticated under effective policy.
    pub authenticated_channel: bool,
    /// Key label associated with the action (if any).
    pub signature_key: Option<String>,
    /// Owner role for `signature_key`, when known.
    pub key_owner_role: Option<String>,
    /// Whether `signature_key` is compromised in the adversary model.
    pub key_compromised: bool,
    /// Coarse provenance class for signature/auth semantics.
    pub provenance: SignatureProvenance,
}

/// Identity descriptor used in extracted message events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageIdentity {
    /// Role/actor label (for example `Replica` or `Byzantine`).
    pub role: String,
    /// Optional process identity within role (for process-scoped semantics).
    pub process: Option<String>,
    /// Optional key namespace bound to the identity.
    pub key: Option<String>,
}

/// Payload/value variant descriptor for a delivered message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MessagePayloadVariant {
    /// Message family/type (for example `Vote`).
    pub family: String,
    /// Parsed payload fields encoded in counter names.
    pub fields: Vec<(String, String)>,
    /// Canonical variant string (for example `Vote[view=1,value=true]`).
    pub variant: String,
}

/// First-class message delivery event extracted from counter transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageDeliveryEvent {
    /// Shared counter variable id backing this event.
    pub shared_var: usize,
    /// Shared counter variable name backing this event.
    pub shared_var_name: String,
    /// Sender identity (protocol role/process or adversarial actor).
    pub sender: MessageIdentity,
    /// Recipient identity.
    pub recipient: MessageIdentity,
    /// Payload/value variant.
    pub payload: MessagePayloadVariant,
    /// Number of messages represented by this event.
    pub count: i64,
    /// Message action kind.
    pub kind: MessageEventKind,
    /// Authentication/signature metadata for this action.
    pub auth: MessageAuthMetadata,
}

/// A step in a counterexample execution trace.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceStep {
    /// SMT transition step index (k in delta_k_r).
    pub smt_step: usize,
    /// Which rule fired.
    pub rule_id: RuleId,
    /// How many times this rule fired (delta).
    pub delta: i64,
    /// First-class delivered-message events at this step.
    pub deliveries: Vec<MessageDeliveryEvent>,
    /// The resulting configuration after this step.
    pub config: Configuration,
    /// POR reduction annotation. `Some("active")` means POR was enabled and this
    /// rule survived pruning (independent peers were reduced away). `None` when
    /// POR is off or unknown.
    pub por_status: Option<String>,
}

/// A counterexample trace.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct Trace {
    pub initial_config: Configuration,
    pub steps: Vec<TraceStep>,
    /// Parameter values for this trace.
    pub param_values: Vec<(String, i64)>,
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Counterexample trace:")?;
        writeln!(f, "  Parameters:")?;
        for (name, val) in &self.param_values {
            writeln!(f, "    {name} = {val}")?;
        }
        writeln!(f, "  Initial configuration:")?;
        write_config(f, &self.initial_config)?;
        for (i, step) in self.steps.iter().enumerate() {
            let por_tag = match &step.por_status {
                Some(status) => format!(" [{status}]"),
                None => String::new(),
            };
            writeln!(
                f,
                "  Step {}: fire rule r{} (k={}, delta={}){}",
                i + 1,
                step.rule_id,
                step.smt_step,
                step.delta,
                por_tag
            )?;
            if step.deliveries.is_empty() {
                writeln!(f, "    deliveries: (none)")?;
            } else {
                writeln!(f, "    deliveries:")?;
                for d in &step.deliveries {
                    writeln!(f, "      - kind={:?} count={}", d.kind, d.count)?;
                    writeln!(
                        f,
                        "        sender={} sender.key={}",
                        identity_label(&d.sender),
                        optional_str(d.sender.key.as_deref())
                    )?;
                    writeln!(
                        f,
                        "        recipient={} recipient.key={}",
                        identity_label(&d.recipient),
                        optional_str(d.recipient.key.as_deref())
                    )?;
                    writeln!(
                        f,
                        "        payload.family={} payload.variant={} payload.fields={}",
                        d.payload.family,
                        d.payload.variant,
                        payload_fields_label(&d.payload.fields)
                    )?;
                    writeln!(
                        f,
                        "        auth.channel={} auth.signature_key={} auth.key_owner={} auth.key_compromised={} auth.provenance={:?}",
                        if d.auth.authenticated_channel {
                            "authenticated"
                        } else {
                            "unauthenticated"
                        },
                        optional_str(d.auth.signature_key.as_deref()),
                        optional_str(d.auth.key_owner_role.as_deref()),
                        d.auth.key_compromised,
                        d.auth.provenance
                    )?;
                }
            }
            write_config(f, &step.config)?;
        }
        Ok(())
    }
}

fn optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn identity_label(identity: &MessageIdentity) -> String {
    identity
        .process
        .as_ref()
        .map(|pid| format!("{}#{pid}", identity.role))
        .unwrap_or_else(|| identity.role.clone())
}

fn payload_fields_label(fields: &[(String, String)]) -> String {
    if fields.is_empty() {
        "(none)".to_string()
    } else {
        fields
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn write_config(f: &mut fmt::Formatter<'_>, config: &Configuration) -> fmt::Result {
    write!(f, "    kappa = [")?;
    for (i, k) in config.kappa.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "{k}")?;
    }
    writeln!(f, "]")?;
    write!(f, "    gamma = [")?;
    for (i, g) in config.gamma.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "{g}")?;
    }
    writeln!(f, "]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_display_includes_sender_recipient_payload_and_auth_fields_by_default() {
        let trace = Trace {
            initial_config: Configuration {
                kappa: vec![1, 0],
                gamma: vec![0],
                params: vec![4],
            },
            steps: vec![TraceStep {
                smt_step: 0,
                rule_id: 0,
                delta: 1,
                deliveries: vec![MessageDeliveryEvent {
                    shared_var: 0,
                    shared_var_name: "cnt_Vote".into(),
                    sender: MessageIdentity {
                        role: "Replica".into(),
                        process: Some("0".into()),
                        key: Some("replica_key".into()),
                    },
                    recipient: MessageIdentity {
                        role: "Replica".into(),
                        process: Some("1".into()),
                        key: Some("replica_key".into()),
                    },
                    payload: MessagePayloadVariant {
                        family: "Vote".into(),
                        fields: vec![("view".into(), "2".into()), ("value".into(), "true".into())],
                        variant: "Vote[view=2,value=true]".into(),
                    },
                    count: 1,
                    kind: MessageEventKind::Deliver,
                    auth: MessageAuthMetadata {
                        authenticated_channel: true,
                        signature_key: Some("replica_key".into()),
                        key_owner_role: Some("Replica".into()),
                        key_compromised: false,
                        provenance: SignatureProvenance::OwnedKey,
                    },
                }],
                config: Configuration {
                    kappa: vec![0, 1],
                    gamma: vec![1],
                    params: vec![4],
                },
                por_status: None,
            }],
            param_values: vec![("n".into(), 4), ("t".into(), 1)],
        };

        let rendered = format!("{trace}");
        assert!(rendered.contains("sender=Replica#0"));
        assert!(rendered.contains("sender.key=replica_key"));
        assert!(rendered.contains("recipient=Replica#1"));
        assert!(rendered.contains("recipient.key=replica_key"));
        assert!(rendered.contains("payload.family=Vote"));
        assert!(rendered.contains("payload.variant=Vote[view=2,value=true]"));
        assert!(rendered.contains("payload.fields=view=2, value=true"));
        assert!(rendered.contains("auth.channel=authenticated"));
        assert!(rendered.contains("auth.signature_key=replica_key"));
        assert!(rendered.contains("auth.key_owner=Replica"));
        assert!(rendered.contains("auth.key_compromised=false"));
        assert!(rendered.contains("auth.provenance=OwnedKey"));
    }
}
