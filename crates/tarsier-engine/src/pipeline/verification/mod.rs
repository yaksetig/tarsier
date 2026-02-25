//! BMC orchestration, k-induction, PDR, CEGAR coordination, liveness checking.

#![allow(unused_imports)]

mod timeout;
pub(crate) use timeout::*;

mod preflight;
pub(crate) use preflight::*;
pub use preflight::{completeness_preflight, CompletenessWarning};

mod smt_helpers;
pub(crate) use smt_helpers::*;

mod lowering;
pub(crate) use lowering::*;

mod bmc_helpers;
pub(crate) use bmc_helpers::*;

mod cegar;
pub(crate) use cegar::*;

mod fair_pdr;
pub(crate) use fair_pdr::*;

mod orchestration;
pub(crate) use orchestration::*;
pub use orchestration::{
    check_fair_liveness, check_fair_liveness_with_mode, check_liveness, prove_fair_liveness,
    prove_fair_liveness_with_cegar, prove_fair_liveness_with_cegar_report,
    prove_fair_liveness_with_mode, prove_fair_liveness_with_round_abstraction, prove_safety,
    prove_safety_with_cegar, prove_safety_with_cegar_report, prove_safety_with_round_abstraction,
    verify, verify_all_properties, verify_program_ast, verify_with_cegar, verify_with_cegar_report,
};

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::info;

use tarsier_dsl::ast;
use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::lowering as ir_lowering;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::{
    AuthenticationMode, CmpOp, EquivocationMode, FaultModel, GuardAtom, LinearCombination,
    LocalValue, NetworkSemantics, ParamOrConst, PorMode, SharedVarKind, ThresholdAutomaton,
};
use tarsier_smt::backends::z3_backend::Z3Solver;
use tarsier_smt::bmc::{
    reset_smt_run_profile, run_bmc_at_depth, run_bmc_with_deadline,
    run_bmc_with_extra_assertions_at_depth, run_bmc_with_extra_assertions_with_deadline,
    run_k_induction_with_deadline, run_pdr_with_certificate_with_deadline, run_pdr_with_deadline,
    take_smt_run_profile, BmcResult, KInductionCti, KInductionResult, PdrInvariantCertificate,
};
use tarsier_smt::encoder::{encode_bmc, encode_k_induction_step, BmcEncoding};
use tarsier_smt::solver::{Model, SatResult, SmtSolver};
use tarsier_smt::sorts::SmtSort;
use tarsier_smt::terms::SmtTerm;

use crate::counterexample::extract_trace;
use crate::result::{
    CegarAuditReport, CegarCounterexampleAnalysis, CegarEliminatedTrace, CegarModelChange,
    CegarPredicateScore, CegarRunControls, CegarStageOutcome, CegarStageReport, CegarTermination,
    CommitteeAnalysisSummary, CtiClassification, FairLivenessResult, FairnessSemantics,
    InductionCtiSummary, LivenessResult, MultiPropertyResult, PropertyVerdict,
    UnboundedFairLivenessCegarAuditReport, UnboundedFairLivenessCegarStageOutcome,
    UnboundedFairLivenessCegarStageReport, UnboundedFairLivenessResult,
    UnboundedSafetyCegarAuditReport, UnboundedSafetyCegarStageOutcome,
    UnboundedSafetyCegarStageReport, UnboundedSafetyResult, VerificationResult,
};

use super::analysis::{
    analyze_and_constrain_committees, apply_round_erasure_abstraction, ensure_n_parameter,
    normalize_erased_var_names,
};
use super::certification::{dump_smt_to_file, encoding_to_smt2_script, query_to_smt2_script};
use super::diagnostics::{
    liveness_memory_budget_bytes, liveness_memory_budget_reason, push_applied_reduction,
    push_lowering_diagnostic, push_phase_profile, push_property_compilation_diagnostic,
    push_property_result_diagnostic, push_reduction_note, push_smt_profile,
    record_property_compilation, sha256_hex_text,
};
use super::property::{
    build_quantified_state_predicate_term, classify_property_fragment, collect_decided_goal_locs,
    collect_non_goal_reachable_locs, compile_temporal_buchi_automaton,
    encode_quantified_temporal_formula_term, eval_formula_expr_on_location, extract_liveness_spec,
    extract_liveness_spec_from_decl, extract_property, extract_property_from_decl,
    fair_liveness_target_from_spec, formula_contains_temporal, has_liveness_properties,
    has_safety_properties, is_liveness_property_kind, is_safety_property_kind,
    select_single_safety_property_decl, temporal_buchi_monitor_canonical,
    validate_property_fragments, FairLivenessTarget, LivenessSpec, QuantifiedFragment,
    TemporalAtomLit, TemporalBuchiAutomaton, TemporalBuchiState,
};
use super::*;
