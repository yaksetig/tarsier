//! Property extraction, classification, validation, temporal formula compilation.

mod classify;
mod extract;
mod formula_eval;
mod liveness;
mod location_analysis;
mod quantified_encoding;
mod temporal_algebra;
mod temporal_buchi;
mod temporal_encoding;
mod temporal_types;
#[cfg(test)]
mod tests;

// Re-export `pub` items (API surface exposed through pipeline::mod.rs)
pub use classify::{classify_property_fragment, validate_property_fragments};
pub use extract::{extract_property, select_property_for_ta_export};

// Re-export all remaining items at crate visibility
pub(crate) use classify::*;
pub(crate) use extract::*;
pub(crate) use formula_eval::*;
pub(crate) use liveness::*;
pub(crate) use location_analysis::*;
pub(crate) use quantified_encoding::*;
pub(crate) use temporal_algebra::*;
pub(crate) use temporal_buchi::*;
pub(crate) use temporal_encoding::*;
pub(crate) use temporal_types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantifiedFragment {
    /// `forall p:R. forall q:R. p.x == q.x` (or guarded variant with `==>`)
    ///
    /// Verified via counter abstraction: conflicting location pairs.
    UniversalAgreement,

    /// `forall p:R. p.x == true/false`
    ///
    /// Verified via counter abstraction: bad-set invariant checking.
    UniversalInvariant,

    /// `forall p:R. <propositional formula>` (no temporal operators, liveness kind)
    ///
    /// Verified via termination goal-location reachability.
    UniversalTermination,

    /// `forall ... . <temporal formula>` (contains temporal operators)
    ///
    /// Verified via Büchi automaton construction + fair-cycle detection.
    UniversalTemporal,

    /// `exists ... . <formula>` handled through temporal encoding.
    ///
    /// This includes explicit temporal formulas, plus non-temporal formulas
    /// rewritten by property-kind semantics (for example `[]phi` for safety
    /// kinds, `<>phi` for liveness kinds).
    ExistentialTemporal,
}

impl QuantifiedFragment {
    /// Returns a human-readable soundness statement for this fragment.
    ///
    /// The soundness statement describes what a "Safe" or "Unsafe" verdict means
    /// under the counter-abstraction model and the specific fragment.
    pub fn soundness_statement(&self) -> &'static str {
        match self {
            QuantifiedFragment::UniversalAgreement => {
                "Under the counter-abstraction model, if the verifier reports Safe, then \
                 no reachable state exists in which two correct processes simultaneously \
                 occupy locations with conflicting decision values. This is sound for \
                 universally quantified agreement over a single local variable, assuming \
                 the adversary model (f <= t Byzantine faults) faithfully represents the \
                 protocol's fault tolerance."
            }

            QuantifiedFragment::UniversalInvariant => {
                "Under the counter-abstraction model, if the verifier reports Safe, then \
                 no reachable state exists in which any correct process occupies a location \
                 where the invariant predicate is violated. This is sound for universally \
                 quantified state predicates (p.x == true/false) under the declared \
                 adversary model."
            }

            QuantifiedFragment::UniversalTermination => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then every fair execution eventually reaches a \
                 state where all correct processes satisfy the goal predicate. Soundness \
                 depends on the fairness assumption: weak fairness requires continuously-\
                 enabled transitions to eventually fire; strong fairness requires \
                 infinitely-often-enabled transitions to eventually fire."
            }

            QuantifiedFragment::UniversalTemporal => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then no fair execution violates the temporal \
                 specification (encoded as a Büchi automaton). The temporal formula is \
                 negated and checked for fair-cycle emptiness. Soundness depends on: \
                 (1) correct Büchi construction from the LTL formula, (2) the fairness \
                 assumption, and (3) faithful counter-abstraction of the protocol."
            }

            QuantifiedFragment::ExistentialTemporal => {
                "Under the counter-abstraction model with weak/strong fairness, if the \
                 verifier reports Live, then no fair execution violates the existentially \
                 quantified temporal specification. Existential state predicates are encoded \
                 as occupancy constraints (some role process satisfies the predicate). \
                 Soundness depends on faithful counter abstraction and fairness assumptions."
            }
        }
    }
}

impl std::fmt::Display for QuantifiedFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuantifiedFragment::UniversalAgreement => write!(f, "universal-agreement"),
            QuantifiedFragment::UniversalInvariant => write!(f, "universal-invariant"),
            QuantifiedFragment::UniversalTermination => write!(f, "universal-termination"),
            QuantifiedFragment::UniversalTemporal => write!(f, "universal-temporal"),
            QuantifiedFragment::ExistentialTemporal => write!(f, "existential-temporal"),
        }
    }
}

/// Diagnostic produced when a property formula falls outside supported fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentDiagnostic {
    pub property_name: String,
    pub message: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for FragmentDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "property '{}': {}", self.property_name, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}
