//! Structured taxonomy for unknown liveness-proof outcomes.

use super::*;

// ---------------------------------------------------------------------------
// Machine-readable unknown reason taxonomy
// ---------------------------------------------------------------------------

/// Structured reason code for inconclusive liveness proof outcomes.
///
/// Instead of ad-hoc reason strings, this taxonomy provides machine-readable
/// codes that tools and CI systems can match on deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivenessUnknownReason {
    /// Overall wall-clock timeout exceeded during proof search.
    Timeout {
        /// The frontier frame reached before timeout.
        frontier_frame: usize,
        /// Which phase timed out.
        phase: String,
    },
    /// Configured memory budget exceeded during proof search.
    MemoryBudgetExceeded {
        /// RSS observed when budget enforcement fired.
        rss_bytes: u64,
        /// Configured RSS cap.
        limit_bytes: u64,
        /// The frontier frame reached before stopping (if known).
        frontier_frame: usize,
        /// Which phase exceeded the budget.
        phase: String,
    },
    /// Adaptive cube budget exhausted — state space too large for the
    /// current abstraction level.
    CubeBudgetExhausted {
        /// Number of bad cubes blocked before budget was hit.
        cubes_blocked: usize,
        /// The frontier frame at which the budget was exhausted.
        frontier_frame: usize,
    },
    /// The SMT solver returned "unknown" for a key query.
    SolverUnknown {
        /// The solver's own reason string.
        solver_reason: String,
    },
    /// Fair PDR found a reachable accepting state but bounded lasso
    /// recovery failed to materialize a concrete trace.
    LassoRecoveryFailed,
    /// CEGAR refinements eliminated the baseline witness but no
    /// confirmed cycle or proof was produced.
    CegarRefinementInconclusive {
        /// Predicates discovered during refinement.
        discovered_predicates: Vec<String>,
    },
    /// CEGAR refinement ladder exhausted without resolution.
    CegarLadderExhausted,
}

impl LivenessUnknownReason {
    /// Machine-readable short code for this reason.
    pub fn code(&self) -> &'static str {
        match self {
            LivenessUnknownReason::Timeout { .. } => "timeout",
            LivenessUnknownReason::MemoryBudgetExceeded { .. } => "memory_budget_exceeded",
            LivenessUnknownReason::CubeBudgetExhausted { .. } => "cube_budget_exhausted",
            LivenessUnknownReason::SolverUnknown { .. } => "solver_unknown",
            LivenessUnknownReason::LassoRecoveryFailed => "lasso_recovery_failed",
            LivenessUnknownReason::CegarRefinementInconclusive { .. } => {
                "cegar_refinement_inconclusive"
            }
            LivenessUnknownReason::CegarLadderExhausted => "cegar_ladder_exhausted",
        }
    }
}

impl std::fmt::Display for LivenessUnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LivenessUnknownReason::Timeout {
                frontier_frame,
                phase,
            } => {
                write!(
                    f,
                    "Timeout exceeded at frontier frame {frontier_frame} during {phase}."
                )
            }
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes,
                limit_bytes,
                frontier_frame,
                phase,
            } => {
                write!(
                    f,
                    "Memory budget exceeded at frontier frame {frontier_frame} \
                     during {phase}: rss_bytes={rss_bytes}, limit_bytes={limit_bytes}."
                )
            }
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked,
                frontier_frame,
            } => {
                write!(
                    f,
                    "Blocked {cubes_blocked} bad cubes at frame {frontier_frame} \
                     (adaptive budget exhausted); state space appears too large \
                     for current abstraction."
                )
            }
            LivenessUnknownReason::SolverUnknown { solver_reason } => {
                write!(f, "SMT solver returned unknown: {solver_reason}")
            }
            LivenessUnknownReason::LassoRecoveryFailed => {
                write!(
                    f,
                    "Fair PDR found a reachable accepting state, but bounded \
                     lasso recovery did not return a concrete trace."
                )
            }
            LivenessUnknownReason::CegarRefinementInconclusive {
                discovered_predicates,
            } => {
                write!(
                    f,
                    "CEGAR refinements eliminated the baseline fair-cycle witness \
                     but no confirmed cycle or proof was produced"
                )?;
                if !discovered_predicates.is_empty() {
                    write!(f, " (predicates: {})", discovered_predicates.join(", "))?;
                }
                write!(f, ".")
            }
            LivenessUnknownReason::CegarLadderExhausted => {
                write!(
                    f,
                    "CEGAR refinement ladder exhausted without a confirmed \
                     fair cycle or elimination witness."
                )
            }
        }
    }
}

/// Sentinel substrings used to classify unstructured reason strings.
///
/// These constants are the canonical patterns matched by
/// [`LivenessUnknownReason::classify`].  Pipeline code that constructs
/// reason strings should include the relevant sentinel so that
/// classification remains in sync.
pub mod reason_sentinels {
    pub const TIMEOUT_EXCEEDED: &str = "timeout exceeded";
    pub const TIMED_OUT: &str = "timed out";
    pub const MEMORY_BUDGET: &str = "memory budget exceeded";
    pub const BAD_CUBES: &str = "bad cubes";
    pub const ADAPTIVE_BUDGET: &str = "adaptive budget";
    pub const LASSO_RECOVERY: &str = "lasso recovery";
    pub const BOUNDED_LASSO: &str = "bounded lasso";
    pub const REFINEMENTS_ELIMINATED: &str = "refinements eliminated";
    pub const REFINEMENTS_INCONCLUSIVE: &str = "refinements were inconclusive";
    pub const LADDER_EXHAUSTED: &str = "refinement ladder exhausted";
    pub const CEGAR_PHASE: &str = "CEGAR";
}

impl LivenessUnknownReason {
    /// Classify an unstructured reason string into a machine-readable code.
    ///
    /// This parses ad-hoc reason strings produced by the pipeline into
    /// structured [`LivenessUnknownReason`] variants.  The sentinel
    /// substrings are defined in [`reason_sentinels`].
    pub fn classify(reason: &str) -> Self {
        use reason_sentinels::*;
        if reason.contains(TIMEOUT_EXCEEDED) || reason.contains(TIMED_OUT) {
            // Extract frontier frame number if present.
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| s.trim_end_matches('.').parse::<usize>().ok())
                .unwrap_or(0);
            let phase = if reason.contains(CEGAR_PHASE) {
                "cegar".to_string()
            } else {
                "fair_pdr".to_string()
            };
            LivenessUnknownReason::Timeout {
                frontier_frame,
                phase,
            }
        } else if reason.contains(MEMORY_BUDGET) {
            let rss_bytes = reason
                .split("rss_bytes=")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let limit_bytes = reason
                .split("limit_bytes=")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| {
                    s.trim_end_matches('.')
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let phase = if reason.contains("lasso search") {
                "fair_lasso".to_string()
            } else if reason.contains(CEGAR_PHASE) {
                "cegar".to_string()
            } else {
                "fair_pdr".to_string()
            };
            LivenessUnknownReason::MemoryBudgetExceeded {
                rss_bytes,
                limit_bytes,
                frontier_frame,
                phase,
            }
        } else if reason.contains(BAD_CUBES) || reason.contains(ADAPTIVE_BUDGET) {
            let cubes_blocked = reason
                .split("over ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let frontier_frame = reason
                .split("frame ")
                .nth(1)
                .and_then(|s| {
                    s.trim_end_matches('.')
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or(0);
            LivenessUnknownReason::CubeBudgetExhausted {
                cubes_blocked,
                frontier_frame,
            }
        } else if reason.contains(LASSO_RECOVERY) || reason.contains(BOUNDED_LASSO) {
            LivenessUnknownReason::LassoRecoveryFailed
        } else if reason.contains(REFINEMENTS_ELIMINATED)
            || reason.contains(REFINEMENTS_INCONCLUSIVE)
        {
            LivenessUnknownReason::CegarRefinementInconclusive {
                discovered_predicates: Vec::new(),
            }
        } else if reason.contains(LADDER_EXHAUSTED) {
            LivenessUnknownReason::CegarLadderExhausted
        } else {
            LivenessUnknownReason::SolverUnknown {
                solver_reason: reason.to_string(),
            }
        }
    }
}
