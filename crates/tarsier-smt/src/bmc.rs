use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::info;

use tarsier_ir::counter_system::CounterSystem;
use tarsier_ir::properties::SafetyProperty;
use tarsier_ir::threshold_automaton::{LocalValue, RoleIdentityScope, SharedVarKind};

use crate::backends::smtlib_printer::to_smtlib;
use crate::encoder::{encode_bmc, encode_k_induction_step, BmcEncoding};
use crate::solver::{Model, SatResult, SmtSolver};
use crate::sorts::SmtSort;
use crate::terms::SmtTerm;

const OVERALL_TIMEOUT_REASON: &str = "Overall timeout exceeded before analysis completed.";

fn deadline_exceeded(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() >= deadline,
        None => false,
    }
}

/// Aggregated SMT profiling for one run.
#[derive(Debug, Clone, Default)]
pub struct SmtRunProfile {
    pub encode_calls: u64,
    pub encode_elapsed_ms: u128,
    pub solve_calls: u64,
    pub solve_elapsed_ms: u128,
    pub assertion_candidates: u64,
    pub assertion_unique: u64,
    pub assertion_dedup_hits: u64,
    pub incremental_depth_reuse_steps: u64,
    pub incremental_decl_reuse_hits: u64,
    pub incremental_assertion_reuse_hits: u64,
    pub symmetry_candidates: u64,
    pub symmetry_pruned: u64,
    pub stutter_signature_normalizations: u64,
}

thread_local! {
    static SMT_RUN_PROFILE: RefCell<SmtRunProfile> = RefCell::new(SmtRunProfile::default());
}

pub fn reset_smt_run_profile() {
    SMT_RUN_PROFILE.with(|cell| {
        *cell.borrow_mut() = SmtRunProfile::default();
    });
}

pub fn current_smt_run_profile() -> SmtRunProfile {
    SMT_RUN_PROFILE.with(|cell| cell.borrow().clone())
}

pub fn take_smt_run_profile() -> SmtRunProfile {
    SMT_RUN_PROFILE.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

fn record_encoding_profile(encoding: &BmcEncoding, elapsed_ms: u128) {
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.encode_calls = p.encode_calls.saturating_add(1);
        p.encode_elapsed_ms = p.encode_elapsed_ms.saturating_add(elapsed_ms);
        p.assertion_candidates = p
            .assertion_candidates
            .saturating_add(encoding.assertion_candidates() as u64);
        p.assertion_unique = p
            .assertion_unique
            .saturating_add(encoding.assertion_unique() as u64);
        p.assertion_dedup_hits = p
            .assertion_dedup_hits
            .saturating_add(encoding.assertion_dedup_hits() as u64);
    });
}

fn record_solve_profile(elapsed_ms: u128) {
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.solve_calls = p.solve_calls.saturating_add(1);
        p.solve_elapsed_ms = p.solve_elapsed_ms.saturating_add(elapsed_ms);
    });
}

fn record_incremental_reuse(reused_decls: u64, reused_assertions: u64) {
    if reused_decls == 0 && reused_assertions == 0 {
        return;
    }
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.incremental_depth_reuse_steps = p.incremental_depth_reuse_steps.saturating_add(1);
        p.incremental_decl_reuse_hits = p.incremental_decl_reuse_hits.saturating_add(reused_decls);
        p.incremental_assertion_reuse_hits = p
            .incremental_assertion_reuse_hits
            .saturating_add(reused_assertions);
    });
}

fn record_symmetry_candidate(pruned: bool) {
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.symmetry_candidates = p.symmetry_candidates.saturating_add(1);
        if pruned {
            p.symmetry_pruned = p.symmetry_pruned.saturating_add(1);
        }
    });
}

fn record_stutter_signature_normalization(count: u64) {
    if count == 0 {
        return;
    }
    SMT_RUN_PROFILE.with(|cell| {
        let mut p = cell.borrow_mut();
        p.stutter_signature_normalizations =
            p.stutter_signature_normalizations.saturating_add(count);
    });
}

fn check_sat_with_model_profiled<S: SmtSolver>(
    solver: &mut S,
    vars: &[(&str, &SmtSort)],
) -> Result<(SatResult, Option<Model>), S::Error> {
    let started = Instant::now();
    let out = solver.check_sat_with_model(vars);
    record_solve_profile(started.elapsed().as_millis());
    out
}

fn check_sat_profiled<S: SmtSolver>(solver: &mut S) -> Result<SatResult, S::Error> {
    let started = Instant::now();
    let out = solver.check_sat();
    record_solve_profile(started.elapsed().as_millis());
    out
}

fn check_sat_assuming_profiled<S: SmtSolver>(
    solver: &mut S,
    assumptions: &[String],
) -> Result<SatResult, S::Error> {
    let started = Instant::now();
    let out = solver.check_sat_assuming(assumptions);
    record_solve_profile(started.elapsed().as_millis());
    out
}

fn wildcard_process_ids(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let chars: Vec<char> = name.chars().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let ch = chars[idx];
        if ch == '#' {
            out.push('#');
            out.push('*');
            idx += 1;
            while idx < chars.len() && chars[idx].is_ascii_digit() {
                idx += 1;
            }
            continue;
        }
        out.push(ch);
        idx += 1;
    }
    out
}

fn local_value_key(value: &LocalValue) -> String {
    match value {
        LocalValue::Bool(b) => format!("b:{b}"),
        LocalValue::Int(v) => format!("i:{v}"),
        LocalValue::Enum(v) => format!("e:{v}"),
    }
}

fn location_symmetry_key(cs: &CounterSystem, loc_id: usize) -> String {
    let ta = &cs.automaton;
    let loc = &ta.locations[loc_id];
    let pid_var = ta
        .role_identities
        .get(&loc.role)
        .and_then(|cfg| {
            if cfg.scope == RoleIdentityScope::Process {
                cfg.process_var.as_deref()
            } else {
                None
            }
        })
        .unwrap_or("pid");
    let mut locals: Vec<(String, String)> = loc
        .local_vars
        .iter()
        .filter(|(name, _)| name.as_str() != pid_var)
        .map(|(name, value)| (name.clone(), local_value_key(value)))
        .collect();
    locals.sort();
    let locals_key = locals
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("loc|{}|{}|{}", loc.role, loc.phase, locals_key)
}

fn shared_var_symmetry_key(cs: &CounterSystem, var_id: usize) -> String {
    let shared = &cs.automaton.shared_vars[var_id];
    if shared.kind == SharedVarKind::MessageCounter {
        format!("msg|{}", wildcard_process_ids(&shared.name))
    } else {
        format!("shared|{}", shared.name)
    }
}

/// Result of BMC verification.
#[derive(Debug)]
pub enum BmcResult {
    /// Property is safe up to the given depth (all UNSAT).
    Safe { depth_checked: usize },
    /// Found a counterexample at the given depth.
    Unsafe { depth: usize, model: Model },
    /// Solver returned unknown.
    Unknown { depth: usize, reason: String },
}

/// Result of an unbounded safety attempt via k-induction.
#[derive(Debug)]
pub enum KInductionResult {
    /// Property proven inductive (unbounded safety) with this k.
    Proved { k: usize },
    /// Found a concrete counterexample in the base case.
    Unsafe { depth: usize, model: Model },
    /// Solver returned unknown.
    Unknown { reason: String },
    /// Could not prove induction up to the requested k bound.
    NotProved {
        max_k: usize,
        cti: Option<KInductionCti>,
    },
}

/// Counterexample-to-induction witness from a SAT inductive-step query.
///
/// This witness is not guaranteed reachable from initial states; it only
/// demonstrates that the current property is not inductive at depth `k`.
#[derive(Debug, Clone)]
pub struct KInductionCti {
    pub k: usize,
    pub model: Model,
}

/// PDR inductive invariant certificate artifacts.
///
/// If all three obligations are UNSAT, then `invariant_pre` is a valid
/// inductive invariant that implies safety:
/// - `init_assertions => invariant_pre`
/// - `invariant_pre & transition_assertions => invariant_post`
/// - `invariant_pre => !bad_pre`
#[derive(Debug, Clone)]
pub struct PdrInvariantCertificate {
    pub frame: usize,
    pub declarations: Vec<(String, SmtSort)>,
    pub init_assertions: Vec<SmtTerm>,
    pub transition_assertions: Vec<SmtTerm>,
    pub bad_pre: SmtTerm,
    pub invariant_pre: Vec<SmtTerm>,
    pub invariant_post: Vec<SmtTerm>,
}

/// Run bounded model checking with iterative deepening.
///
/// For each depth k = 0..max_depth, encodes the counter system
/// and checks if the safety property can be violated. If SAT at
/// any depth, returns the counterexample. If all depths are UNSAT,
/// the property is safe up to that bound.
pub fn run_bmc<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
) -> Result<BmcResult, S::Error> {
    run_bmc_with_deadline(solver, cs, property, max_depth, None)
}

/// Run bounded model checking with iterative deepening and an optional overall deadline.
pub fn run_bmc_with_deadline<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    deadline: Option<Instant>,
) -> Result<BmcResult, S::Error> {
    solver.reset()?;
    let mut declared = HashSet::<String>::new();
    let mut asserted = HashSet::<String>::new();

    for depth in 0..=max_depth {
        if deadline_exceeded(deadline) {
            return Ok(BmcResult::Unknown {
                depth,
                reason: OVERALL_TIMEOUT_REASON.into(),
            });
        }
        info!(depth, "BMC: checking depth");

        let encode_started = Instant::now();
        let encoding = encode_bmc(cs, property, depth);
        record_encoding_profile(&encoding, encode_started.elapsed().as_millis());
        let mut reused_decls = 0_u64;
        let mut reused_assertions = 0_u64;

        // Declare all variables
        for (name, sort) in &encoding.declarations {
            if declared.insert(name.clone()) {
                solver.declare_var(name, sort)?;
            } else {
                reused_decls = reused_decls.saturating_add(1);
            }
        }

        // Assert all constraints
        let (violation, base_assertions) = match encoding.assertions.split_last() {
            Some((last, rest)) => (last, rest),
            None => {
                return Ok(BmcResult::Unknown {
                    depth,
                    reason: "BMC encoding produced no assertions.".into(),
                });
            }
        };
        for assertion in base_assertions {
            let key = to_smtlib(assertion);
            if asserted.insert(key) {
                solver.assert(assertion)?;
            } else {
                reused_assertions = reused_assertions.saturating_add(1);
            }
        }
        record_incremental_reuse(reused_decls, reused_assertions);

        // Build the list of variables to extract for model
        let var_refs: Vec<(&str, &SmtSort)> = encoding
            .model_vars
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();

        solver.push()?;
        solver.assert(violation)?;
        let (result, model) = check_sat_with_model_profiled(solver, &var_refs)?;
        solver.pop()?;

        match result {
            SatResult::Sat => {
                info!(depth, "BMC: UNSAFE - counterexample found");
                return Ok(BmcResult::Unsafe {
                    depth,
                    model: model.unwrap(),
                });
            }
            SatResult::Unsat => {
                info!(depth, "BMC: safe at this depth");
            }
            SatResult::Unknown(reason) => {
                info!(depth, %reason, "BMC: unknown result");
                return Ok(BmcResult::Unknown { depth, reason });
            }
        }
    }

    info!(max_depth, "BMC: safe up to max depth");
    Ok(BmcResult::Safe {
        depth_checked: max_depth,
    })
}

/// Run bounded model checking at a single depth.
///
/// This is useful for bounded liveness checks that should only be evaluated
/// at a specific depth, rather than all prefixes.
pub fn run_bmc_at_depth<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    depth: usize,
) -> Result<BmcResult, S::Error> {
    info!(depth, "BMC: checking exact depth");

    solver.reset()?;

    let encode_started = Instant::now();
    let encoding = encode_bmc(cs, property, depth);
    record_encoding_profile(&encoding, encode_started.elapsed().as_millis());

    // Declare all variables
    for (name, sort) in &encoding.declarations {
        solver.declare_var(name, sort)?;
    }

    // Assert all constraints
    for assertion in &encoding.assertions {
        solver.assert(assertion)?;
    }

    // Build the list of variables to extract for model
    let var_refs: Vec<(&str, &SmtSort)> = encoding
        .model_vars
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();

    let (result, model) = check_sat_with_model_profiled(solver, &var_refs)?;

    match result {
        SatResult::Sat => {
            info!(depth, "BMC: UNSAFE - counterexample found");
            Ok(BmcResult::Unsafe {
                depth,
                model: model.unwrap(),
            })
        }
        SatResult::Unsat => {
            info!(depth, "BMC: safe at this depth");
            Ok(BmcResult::Safe {
                depth_checked: depth,
            })
        }
        SatResult::Unknown(reason) => {
            info!(depth, %reason, "BMC: unknown result");
            Ok(BmcResult::Unknown { depth, reason })
        }
    }
}

/// Run BMC with additional assertions injected at each depth.
///
/// This is used by the committee verification pipeline to inject
/// concrete bounds (e.g., adversary_param <= b_max) derived from
/// hypergeometric analysis.
pub fn run_bmc_with_extra_assertions<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    extra_assertions: &[SmtTerm],
) -> Result<BmcResult, S::Error> {
    run_bmc_with_extra_assertions_with_deadline(
        solver,
        cs,
        property,
        max_depth,
        extra_assertions,
        None,
    )
}

/// Run BMC with additional assertions and an optional overall deadline.
pub fn run_bmc_with_extra_assertions_with_deadline<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_depth: usize,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<BmcResult, S::Error> {
    solver.reset()?;
    let mut declared = HashSet::<String>::new();
    let mut asserted = HashSet::<String>::new();

    for depth in 0..=max_depth {
        if deadline_exceeded(deadline) {
            return Ok(BmcResult::Unknown {
                depth,
                reason: OVERALL_TIMEOUT_REASON.into(),
            });
        }
        info!(depth, "BMC: checking depth (with committee bounds)");

        let encode_started = Instant::now();
        let encoding = encode_bmc(cs, property, depth);
        record_encoding_profile(&encoding, encode_started.elapsed().as_millis());
        let mut reused_decls = 0_u64;
        let mut reused_assertions = 0_u64;

        // Declare all variables
        for (name, sort) in &encoding.declarations {
            if declared.insert(name.clone()) {
                solver.declare_var(name, sort)?;
            } else {
                reused_decls = reused_decls.saturating_add(1);
            }
        }

        // Assert all constraints
        let (violation, base_assertions) = match encoding.assertions.split_last() {
            Some((last, rest)) => (last, rest),
            None => {
                return Ok(BmcResult::Unknown {
                    depth,
                    reason: "BMC encoding produced no assertions.".into(),
                });
            }
        };
        for assertion in base_assertions {
            let key = to_smtlib(assertion);
            if asserted.insert(key) {
                solver.assert(assertion)?;
            } else {
                reused_assertions = reused_assertions.saturating_add(1);
            }
        }

        // Assert extra committee-derived constraints
        for extra in extra_assertions {
            let key = to_smtlib(extra);
            if asserted.insert(key) {
                solver.assert(extra)?;
            } else {
                reused_assertions = reused_assertions.saturating_add(1);
            }
        }
        record_incremental_reuse(reused_decls, reused_assertions);

        // Build the list of variables to extract for model
        let var_refs: Vec<(&str, &SmtSort)> = encoding
            .model_vars
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();

        solver.push()?;
        solver.assert(violation)?;
        let (result, model) = check_sat_with_model_profiled(solver, &var_refs)?;
        solver.pop()?;

        match result {
            SatResult::Sat => {
                info!(depth, "BMC: UNSAFE - counterexample found");
                return Ok(BmcResult::Unsafe {
                    depth,
                    model: model.unwrap(),
                });
            }
            SatResult::Unsat => {
                info!(depth, "BMC: safe at this depth");
            }
            SatResult::Unknown(reason) => {
                info!(depth, %reason, "BMC: unknown result");
                return Ok(BmcResult::Unknown { depth, reason });
            }
        }
    }

    info!(max_depth, "BMC: safe up to max depth");
    Ok(BmcResult::Safe {
        depth_checked: max_depth,
    })
}

/// Run BMC at a single depth with additional assertions.
pub fn run_bmc_with_extra_assertions_at_depth<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    depth: usize,
    extra_assertions: &[SmtTerm],
) -> Result<BmcResult, S::Error> {
    info!(depth, "BMC: checking exact depth (with extra assertions)");

    solver.reset()?;

    let encode_started = Instant::now();
    let encoding = encode_bmc(cs, property, depth);
    record_encoding_profile(&encoding, encode_started.elapsed().as_millis());

    // Declare all variables
    for (name, sort) in &encoding.declarations {
        solver.declare_var(name, sort)?;
    }

    // Assert all constraints
    for assertion in &encoding.assertions {
        solver.assert(assertion)?;
    }

    // Assert extra constraints
    for extra in extra_assertions {
        solver.assert(extra)?;
    }

    // Build the list of variables to extract for model
    let var_refs: Vec<(&str, &SmtSort)> = encoding
        .model_vars
        .iter()
        .map(|(n, s)| (n.as_str(), s))
        .collect();

    let (result, model) = check_sat_with_model_profiled(solver, &var_refs)?;

    match result {
        SatResult::Sat => {
            info!(depth, "BMC: UNSAFE - counterexample found");
            Ok(BmcResult::Unsafe {
                depth,
                model: model.unwrap(),
            })
        }
        SatResult::Unsat => {
            info!(depth, "BMC: safe at this depth");
            Ok(BmcResult::Safe {
                depth_checked: depth,
            })
        }
        SatResult::Unknown(reason) => {
            info!(depth, %reason, "BMC: unknown result");
            Ok(BmcResult::Unknown { depth, reason })
        }
    }
}

/// Run unbounded safety proof attempt with classic k-induction.
///
/// For each k in 1..=max_k:
/// - Base: no violation up to depth k (BMC)
/// - Step: any k-step fragment with P(0..k-1) implies P(k)
pub fn run_k_induction<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
) -> Result<KInductionResult, S::Error> {
    run_k_induction_with_deadline(solver, cs, property, max_k, extra_assertions, None)
}

/// Run unbounded safety proof attempt with classic k-induction and an optional overall deadline.
pub fn run_k_induction_with_deadline<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<KInductionResult, S::Error> {
    if max_k == 0 {
        return Ok(KInductionResult::NotProved { max_k, cti: None });
    }

    let mut first_cti: Option<KInductionCti> = None;

    for k in 1..=max_k {
        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: OVERALL_TIMEOUT_REASON.into(),
            });
        }
        info!(k, "k-induction: base check");
        let base = if extra_assertions.is_empty() {
            run_bmc_with_deadline(solver, cs, property, k, deadline)?
        } else {
            run_bmc_with_extra_assertions_with_deadline(
                solver,
                cs,
                property,
                k,
                extra_assertions,
                deadline,
            )?
        };
        match base {
            BmcResult::Unsafe { depth, model } => {
                return Ok(KInductionResult::Unsafe { depth, model });
            }
            BmcResult::Unknown { reason, .. } => {
                return Ok(KInductionResult::Unknown { reason });
            }
            BmcResult::Safe { .. } => {}
        }

        info!(k, "k-induction: step check");
        if deadline_exceeded(deadline) {
            return Ok(KInductionResult::Unknown {
                reason: OVERALL_TIMEOUT_REASON.into(),
            });
        }
        solver.reset()?;
        let encode_started = Instant::now();
        let encoding = encode_k_induction_step(cs, property, k);
        record_encoding_profile(&encoding, encode_started.elapsed().as_millis());
        for (name, sort) in &encoding.declarations {
            solver.declare_var(name, sort)?;
        }
        for assertion in &encoding.assertions {
            solver.assert(assertion)?;
        }
        for extra in extra_assertions {
            solver.assert(extra)?;
        }
        let var_refs: Vec<(&str, &SmtSort)> = encoding
            .model_vars
            .iter()
            .map(|(n, s)| (n.as_str(), s))
            .collect();
        let (sat, model) = check_sat_with_model_profiled(solver, &var_refs)?;
        match sat {
            SatResult::Unsat => {
                info!(k, "k-induction: proved");
                return Ok(KInductionResult::Proved { k });
            }
            SatResult::Sat => {
                info!(k, "k-induction: not inductive at this k");
                if first_cti.is_none() {
                    let Some(model) = model else {
                        return Ok(KInductionResult::Unknown {
                            reason: format!(
                                "k-induction step at k={k} returned SAT without a model."
                            ),
                        });
                    };
                    first_cti = Some(KInductionCti { k, model });
                }
            }
            SatResult::Unknown(reason) => {
                return Ok(KInductionResult::Unknown { reason });
            }
        }
    }

    Ok(KInductionResult::NotProved {
        max_k,
        cti: first_cti,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CubeLiteral {
    state_var_idx: usize,
    value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Cube {
    lits: Vec<CubeLiteral>,
}

impl Cube {
    fn from_model(model: &Model, state_vars: &[(String, SmtSort)]) -> Option<Self> {
        let mut lits = Vec::with_capacity(state_vars.len());
        for (i, (name, sort)) in state_vars.iter().enumerate() {
            match sort {
                SmtSort::Int => {
                    let value = model.get_int(name)?;
                    lits.push(CubeLiteral {
                        state_var_idx: i,
                        value,
                    });
                }
                SmtSort::Bool => {
                    // State cubes currently only support integer variables.
                    let _ = model.get_bool(name)?;
                    return None;
                }
            }
        }
        Some(Self { lits })
    }

    fn to_conjunction_term(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        if self.lits.is_empty() {
            return SmtTerm::bool(true);
        }
        let mut parts = Vec::with_capacity(self.lits.len());
        for lit in &self.lits {
            let (name, sort) = &state_vars[lit.state_var_idx];
            match sort {
                SmtSort::Int => {
                    parts.push(SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)));
                }
                SmtSort::Bool => {
                    // Not used in current counter-system states.
                    parts.push(SmtTerm::bool(false));
                }
            }
        }
        SmtTerm::and(parts)
    }

    fn to_blocking_clause_term(&self, state_vars: &[(String, SmtSort)]) -> SmtTerm {
        SmtTerm::not(self.to_conjunction_term(state_vars))
    }

    /// Returns true iff `self` is at least as general as `other`.
    ///
    /// For blocking clauses, this means `self` blocks a superset of states:
    /// every literal in `self` appears in `other`.
    fn subsumes(&self, other: &Cube) -> bool {
        if self.lits.len() > other.lits.len() {
            return false;
        }
        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.lits.len() && j < other.lits.len() {
            let a = &self.lits[i];
            let b = &other.lits[j];
            if a == b {
                i += 1;
                j += 1;
                continue;
            }
            if a.state_var_idx > b.state_var_idx {
                j += 1;
                continue;
            }
            return false;
        }
        i == self.lits.len()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PdrFrame {
    blocked_cubes: HashSet<Cube>,
}

impl PdrFrame {
    fn insert(&mut self, cube: Cube) {
        if self
            .blocked_cubes
            .iter()
            .any(|existing| existing.subsumes(&cube))
        {
            return;
        }
        let to_remove: Vec<Cube> = self
            .blocked_cubes
            .iter()
            .filter(|existing| cube.subsumes(existing))
            .cloned()
            .collect();
        for existing in to_remove {
            self.blocked_cubes.remove(&existing);
        }
        self.blocked_cubes.insert(cube);
    }

    fn contains(&self, cube: &Cube) -> bool {
        self.blocked_cubes.contains(cube)
    }

    fn cubes(&self) -> impl Iterator<Item = &Cube> {
        self.blocked_cubes.iter()
    }
}

#[derive(Debug, Clone)]
struct PdrArtifacts {
    declarations: Vec<(String, SmtSort)>,
    state_vars_pre: Vec<(String, SmtSort)>,
    state_vars_post: Vec<(String, SmtSort)>,
    symmetry_templates_post: Vec<String>,
    state_assertions_pre: Vec<SmtTerm>,
    init_assertions: Vec<SmtTerm>,
    transition_assertions: Vec<SmtTerm>,
    bad_pre: SmtTerm,
}

fn kappa_var(step: usize, loc: usize) -> String {
    format!("kappa_{step}_{loc}")
}

fn gamma_var(step: usize, var: usize) -> String {
    format!("g_{step}_{var}")
}

fn time_var(step: usize) -> String {
    format!("time_{step}")
}

fn build_pdr_artifacts(cs: &CounterSystem, property: &SafetyProperty) -> Option<PdrArtifacts> {
    // k=0 induction encoding: state constraints + bad(state_0)
    let step0_started = Instant::now();
    let step0 = encode_k_induction_step(cs, property, 0);
    record_encoding_profile(&step0, step0_started.elapsed().as_millis());
    let bad_pre = step0.assertions.last()?.clone();
    let state_assertions_pre =
        step0.assertions[..step0.assertions.len().saturating_sub(1)].to_vec();

    // k=1 induction encoding: transition + !bad(state_0) + bad(state_1)
    let step1_started = Instant::now();
    let step1 = encode_k_induction_step(cs, property, 1);
    record_encoding_profile(&step1, step1_started.elapsed().as_millis());
    if step1.assertions.len() < 2 {
        return None;
    }
    let transition_assertions =
        step1.assertions[..step1.assertions.len().saturating_sub(2)].to_vec();

    // BMC depth 0 encoding: init + bad(state_0)
    let bmc0_started = Instant::now();
    let bmc0 = encode_bmc(cs, property, 0);
    record_encoding_profile(&bmc0, bmc0_started.elapsed().as_millis());
    let init_assertions = bmc0.assertions[..bmc0.assertions.len().saturating_sub(1)].to_vec();

    let mut state_vars_pre = Vec::new();
    let mut state_vars_post = Vec::new();
    let mut symmetry_templates_post = Vec::new();
    for l in 0..cs.num_locations() {
        state_vars_pre.push((kappa_var(0, l), SmtSort::Int));
        state_vars_post.push((kappa_var(1, l), SmtSort::Int));
        let key = location_symmetry_key(cs, l);
        symmetry_templates_post.push(key);
    }
    for v in 0..cs.num_shared_vars() {
        state_vars_pre.push((gamma_var(0, v), SmtSort::Int));
        state_vars_post.push((gamma_var(1, v), SmtSort::Int));
        let key = shared_var_symmetry_key(cs, v);
        symmetry_templates_post.push(key);
    }
    state_vars_pre.push((time_var(0), SmtSort::Int));
    state_vars_post.push((time_var(1), SmtSort::Int));
    symmetry_templates_post.push("time".into());

    Some(PdrArtifacts {
        declarations: step1.declarations,
        state_vars_pre,
        state_vars_post,
        symmetry_templates_post,
        state_assertions_pre,
        init_assertions,
        transition_assertions,
        bad_pre,
    })
}

fn declare_all<S: SmtSolver>(
    solver: &mut S,
    declarations: &[(String, SmtSort)],
) -> Result<(), S::Error> {
    for (name, sort) in declarations {
        solver.declare_var(name, sort)?;
    }
    Ok(())
}

fn assert_all<S: SmtSolver>(solver: &mut S, assertions: &[SmtTerm]) -> Result<(), S::Error> {
    for assertion in assertions {
        solver.assert(assertion)?;
    }
    Ok(())
}

fn assert_frame<S: SmtSolver>(
    solver: &mut S,
    frame: &PdrFrame,
    state_vars: &[(String, SmtSort)],
) -> Result<(), S::Error> {
    for cube in frame.cubes() {
        solver.assert(&cube.to_blocking_clause_term(state_vars))?;
    }
    Ok(())
}

enum CubeQueryResult {
    Sat(Cube),
    Unsat,
    Unknown(String),
}

enum SatQueryResult {
    Sat,
    Unsat,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PdrQueryBase {
    None,
    State,
    Transition,
}

struct PdrQueryEngine<'a, S: SmtSolver> {
    solver: &'a mut S,
    artifacts: &'a PdrArtifacts,
    extra_assertions: &'a [SmtTerm],
    base: PdrQueryBase,
    assumption_nonce: usize,
}

impl<'a, S: SmtSolver> PdrQueryEngine<'a, S> {
    fn new(
        solver: &'a mut S,
        artifacts: &'a PdrArtifacts,
        extra_assertions: &'a [SmtTerm],
    ) -> Self {
        Self {
            solver,
            artifacts,
            extra_assertions,
            base: PdrQueryBase::None,
            assumption_nonce: 0,
        }
    }

    fn prepare_state_base(&mut self) -> Result<(), S::Error> {
        if self.base == PdrQueryBase::State {
            return Ok(());
        }
        self.solver.reset()?;
        declare_all(self.solver, &self.artifacts.declarations)?;
        assert_all(self.solver, &self.artifacts.state_assertions_pre)?;
        assert_all(self.solver, self.extra_assertions)?;
        self.base = PdrQueryBase::State;
        Ok(())
    }

    fn prepare_transition_base(&mut self) -> Result<(), S::Error> {
        if self.base == PdrQueryBase::Transition {
            return Ok(());
        }
        self.solver.reset()?;
        declare_all(self.solver, &self.artifacts.declarations)?;
        assert_all(self.solver, &self.artifacts.transition_assertions)?;
        assert_all(self.solver, self.extra_assertions)?;
        self.base = PdrQueryBase::Transition;
        Ok(())
    }

    fn with_scope<T, F>(&mut self, f: F) -> Result<T, S::Error>
    where
        F: FnOnce(&mut Self) -> Result<T, S::Error>,
    {
        self.solver.push()?;
        let result = f(self);
        let pop_result = self.solver.pop();
        match (result, pop_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(err), Ok(())) => Err(err),
            (Ok(_), Err(pop_err)) => Err(pop_err),
            (Err(err), Err(_)) => Err(err),
        }
    }

    fn next_assumption_name(&mut self, level: usize, idx: usize) -> String {
        let name = format!("__pdr_assume_{level}_{idx}_{}", self.assumption_nonce);
        self.assumption_nonce = self.assumption_nonce.saturating_add(1);
        name
    }

    fn query_bad_state_in_frame(&mut self, frame: &PdrFrame) -> Result<CubeQueryResult, S::Error> {
        self.prepare_state_base()?;
        self.with_scope(|engine| {
            assert_frame(engine.solver, frame, &engine.artifacts.state_vars_pre)?;
            engine.solver.assert(&engine.artifacts.bad_pre)?;
            let var_refs: Vec<(&str, &SmtSort)> = engine
                .artifacts
                .state_vars_pre
                .iter()
                .map(|(n, s)| (n.as_str(), s))
                .collect();
            let (result, model) = check_sat_with_model_profiled(engine.solver, &var_refs)?;
            Ok(match result {
                SatResult::Sat => {
                    if let Some(model) = model {
                        if let Some(cube) =
                            Cube::from_model(&model, &engine.artifacts.state_vars_pre)
                        {
                            CubeQueryResult::Sat(cube)
                        } else {
                            CubeQueryResult::Unknown(
                                "PDR: failed to extract bad-state cube from model".into(),
                            )
                        }
                    } else {
                        CubeQueryResult::Unknown(
                            "PDR: solver reported SAT but returned no model".into(),
                        )
                    }
                }
                SatResult::Unsat => CubeQueryResult::Unsat,
                SatResult::Unknown(reason) => CubeQueryResult::Unknown(reason),
            })
        })
    }

    fn predecessor_query(
        &mut self,
        frames: &[PdrFrame],
        level: usize,
        cube: &Cube,
        with_model: bool,
    ) -> Result<(SatQueryResult, Option<Cube>), S::Error> {
        self.prepare_transition_base()?;
        self.with_scope(|engine| {
            if level == 1 {
                assert_all(engine.solver, &engine.artifacts.init_assertions)?;
            } else {
                assert_frame(
                    engine.solver,
                    &frames[level - 1],
                    &engine.artifacts.state_vars_pre,
                )?;
            }
            engine
                .solver
                .assert(&cube.to_conjunction_term(&engine.artifacts.state_vars_post))?;

            if with_model {
                let var_refs: Vec<(&str, &SmtSort)> = engine
                    .artifacts
                    .state_vars_pre
                    .iter()
                    .map(|(n, s)| (n.as_str(), s))
                    .collect();
                let (result, model) = check_sat_with_model_profiled(engine.solver, &var_refs)?;
                return Ok(match result {
                    SatResult::Sat => {
                        if let Some(model) = model {
                            if let Some(pred_cube) =
                                Cube::from_model(&model, &engine.artifacts.state_vars_pre)
                            {
                                (SatQueryResult::Sat, Some(pred_cube))
                            } else {
                                (
                                    SatQueryResult::Unknown(
                                        "PDR: failed to extract predecessor cube from model".into(),
                                    ),
                                    None,
                                )
                            }
                        } else {
                            (
                                SatQueryResult::Unknown(
                                    "PDR: solver reported SAT but returned no model".into(),
                                ),
                                None,
                            )
                        }
                    }
                    SatResult::Unsat => (SatQueryResult::Unsat, None),
                    SatResult::Unknown(reason) => (SatQueryResult::Unknown(reason), None),
                });
            }

            Ok(match check_sat_profiled(engine.solver)? {
                SatResult::Sat => (SatQueryResult::Sat, None),
                SatResult::Unsat => (SatQueryResult::Unsat, None),
                SatResult::Unknown(reason) => (SatQueryResult::Unknown(reason), None),
            })
        })
    }

    fn can_push_cube_to_next_frame(
        &mut self,
        frame: &PdrFrame,
        cube: &Cube,
    ) -> Result<SatQueryResult, S::Error> {
        self.prepare_transition_base()?;
        self.with_scope(|engine| {
            assert_frame(engine.solver, frame, &engine.artifacts.state_vars_pre)?;
            engine
                .solver
                .assert(&cube.to_conjunction_term(&engine.artifacts.state_vars_post))?;
            Ok(match check_sat_profiled(engine.solver)? {
                SatResult::Unsat => SatQueryResult::Unsat,
                SatResult::Sat => SatQueryResult::Sat,
                SatResult::Unknown(reason) => SatQueryResult::Unknown(reason),
            })
        })
    }
}

fn cube_literal_to_term(lit: &CubeLiteral, state_vars: &[(String, SmtSort)]) -> Option<SmtTerm> {
    let (name, sort) = state_vars.get(lit.state_var_idx)?;
    Some(match sort {
        SmtSort::Int => SmtTerm::var(name.clone()).eq(SmtTerm::int(lit.value)),
        SmtSort::Bool => SmtTerm::var(name.clone()).eq(SmtTerm::bool(lit.value != 0)),
    })
}

fn cube_symmetry_signature(cube: &Cube, templates: &[String]) -> String {
    let mut stutter_normalizations = 0_u64;
    let mut parts = cube
        .lits
        .iter()
        .map(|lit| {
            let key = templates
                .get(lit.state_var_idx)
                .map(|s| s.as_str())
                .unwrap_or("?");
            if key == "time" {
                stutter_normalizations = stutter_normalizations.saturating_add(1);
                "time=*".to_string()
            } else {
                format!("{key}={}", lit.value)
            }
        })
        .collect::<Vec<_>>();
    record_stutter_signature_normalization(stutter_normalizations);
    parts.sort();
    parts.join("|")
}

fn try_generalize_cube_with_unsat_core<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frames: &[PdrFrame],
    level: usize,
    cube: &Cube,
) -> Result<(Option<Cube>, Option<String>), S::Error> {
    if !query_engine.solver.supports_assumption_unsat_core() || cube.lits.is_empty() {
        return Ok((None, None));
    }

    query_engine.prepare_transition_base()?;
    query_engine.with_scope(|engine| {
        if level == 1 {
            assert_all(engine.solver, &engine.artifacts.init_assertions)?;
        } else {
            assert_frame(
                engine.solver,
                &frames[level - 1],
                &engine.artifacts.state_vars_pre,
            )?;
        }

        let mut assumptions = Vec::with_capacity(cube.lits.len());
        let mut lit_by_assumption = HashMap::with_capacity(cube.lits.len());
        for (idx, lit) in cube.lits.iter().enumerate() {
            let Some(lit_term) = cube_literal_to_term(lit, &engine.artifacts.state_vars_post)
            else {
                return Ok((None, None));
            };
            let assumption_name = engine.next_assumption_name(level, idx);
            engine
                .solver
                .declare_var(&assumption_name, &SmtSort::Bool)?;
            engine
                .solver
                .assert(&SmtTerm::var(assumption_name.clone()).implies(lit_term))?;
            assumptions.push(assumption_name.clone());
            lit_by_assumption.insert(assumption_name, lit.clone());
        }

        Ok(
            match check_sat_assuming_profiled(engine.solver, &assumptions)? {
                SatResult::Unsat => {
                    let core_names = engine.solver.get_unsat_core_assumptions()?;
                    if core_names.is_empty() {
                        (None, None)
                    } else {
                        let mut core_lits: Vec<CubeLiteral> = core_names
                            .iter()
                            .filter_map(|name| lit_by_assumption.get(name).cloned())
                            .collect();
                        if core_lits.is_empty() {
                            (None, None)
                        } else {
                            core_lits.sort();
                            core_lits.dedup();
                            (Some(Cube { lits: core_lits }), None)
                        }
                    }
                }
                SatResult::Sat => (None, None),
                SatResult::Unknown(reason) => (None, Some(reason)),
            },
        )
    })
}

fn pdr_bad_cube_budget(state_var_count: usize, frontier: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(120)
        .saturating_add(frontier.saturating_mul(800));
    5_000usize.saturating_add(scaled).clamp(5_000, 200_000)
}

fn pdr_obligation_budget(state_var_count: usize, level: usize) -> usize {
    let scaled = state_var_count
        .saturating_mul(220)
        .saturating_add(level.saturating_mul(1_500));
    10_000usize.saturating_add(scaled).clamp(10_000, 300_000)
}

fn pdr_single_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(32)
        .saturating_add(128)
        .clamp(128, 16_384)
}

fn pdr_pair_literal_query_budget(lit_count: usize) -> usize {
    lit_count
        .saturating_mul(lit_count.saturating_sub(1))
        .saturating_div(2)
        .clamp(0, 2_048)
}

fn pdr_literal_priority(lit: &CubeLiteral, state_vars: &[(String, SmtSort)]) -> (u8, usize, usize) {
    let name = state_vars
        .get(lit.state_var_idx)
        .map(|(n, _)| n.as_str())
        .unwrap_or_default();
    // Domain-guided ordering: first try dropping time and zero-valued message
    // counters, then other message counters, then location counters.
    let class = if name.starts_with("time_") {
        0
    } else if name.starts_with("g_") && lit.value == 0 {
        1
    } else if name.starts_with("g_") {
        2
    } else if name.starts_with("kappa_") && lit.value == 0 {
        3
    } else if name.starts_with("kappa_") {
        4
    } else if lit.value == 0 {
        5
    } else {
        6
    };
    (class, lit.state_var_idx, 0)
}

fn pdr_literal_drop_order(cube: &Cube, state_vars: &[(String, SmtSort)]) -> Vec<usize> {
    let mut entries: Vec<(usize, (u8, usize, usize))> = cube
        .lits
        .iter()
        .enumerate()
        .map(|(idx, lit)| (idx, pdr_literal_priority(lit, state_vars)))
        .collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    entries.into_iter().map(|(idx, _)| idx).collect()
}

fn try_drop_single_literal<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frames: &[PdrFrame],
    level: usize,
    cube: &Cube,
    deadline: Option<Instant>,
    query_budget: &mut usize,
) -> Result<(Option<Cube>, Option<String>), S::Error> {
    let mut seen_symmetry = HashSet::new();
    for idx in pdr_literal_drop_order(cube, &query_engine.artifacts.state_vars_post) {
        if deadline_exceeded(deadline) {
            return Ok((None, Some(OVERALL_TIMEOUT_REASON.into())));
        }
        if *query_budget == 0 {
            return Ok((None, None));
        }
        *query_budget -= 1;
        let mut candidate = cube.clone();
        candidate.lits.remove(idx);
        let signature =
            cube_symmetry_signature(&candidate, &query_engine.artifacts.symmetry_templates_post);
        let fresh = seen_symmetry.insert(signature);
        record_symmetry_candidate(!fresh);
        if !fresh {
            continue;
        }
        let (res, _) = query_engine.predecessor_query(frames, level, &candidate, false)?;
        match res {
            SatQueryResult::Unsat => return Ok((Some(candidate), None)),
            SatQueryResult::Sat => {}
            SatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
        }
    }
    Ok((None, None))
}

fn try_drop_literal_pair<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frames: &[PdrFrame],
    level: usize,
    cube: &Cube,
    deadline: Option<Instant>,
    pair_budget: &mut usize,
) -> Result<(Option<Cube>, Option<String>), S::Error> {
    let order = pdr_literal_drop_order(cube, &query_engine.artifacts.state_vars_post);
    let mut seen_symmetry = HashSet::new();
    for i in 0..order.len() {
        for j in (i + 1)..order.len() {
            if deadline_exceeded(deadline) {
                return Ok((None, Some(OVERALL_TIMEOUT_REASON.into())));
            }
            if *pair_budget == 0 {
                return Ok((None, None));
            }
            *pair_budget -= 1;
            let idx_a = order[i];
            let idx_b = order[j];
            let mut candidate = cube.clone();
            if idx_a > idx_b {
                candidate.lits.remove(idx_a);
                candidate.lits.remove(idx_b);
            } else {
                candidate.lits.remove(idx_b);
                candidate.lits.remove(idx_a);
            }
            let signature = cube_symmetry_signature(
                &candidate,
                &query_engine.artifacts.symmetry_templates_post,
            );
            let fresh = seen_symmetry.insert(signature);
            record_symmetry_candidate(!fresh);
            if !fresh {
                continue;
            }
            let (res, _) = query_engine.predecessor_query(frames, level, &candidate, false)?;
            match res {
                SatQueryResult::Unsat => return Ok((Some(candidate), None)),
                SatQueryResult::Sat => {}
                SatQueryResult::Unknown(reason) => return Ok((None, Some(reason))),
            }
        }
    }
    Ok((None, None))
}

fn try_generalize_cube<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frames: &[PdrFrame],
    level: usize,
    cube: &Cube,
    deadline: Option<Instant>,
) -> Result<(Option<Cube>, Option<String>), S::Error> {
    let (core_cube, core_reason) =
        try_generalize_cube_with_unsat_core(query_engine, frames, level, cube)?;
    if let Some(reason) = core_reason {
        return Ok((None, Some(reason)));
    }
    if core_cube.is_some() {
        return Ok((core_cube, None));
    }

    let mut current = cube.clone();
    if current.lits.len() <= 1 {
        return Ok((Some(current), None));
    }

    let mut single_budget = pdr_single_literal_query_budget(current.lits.len());
    let mut pair_budget = pdr_pair_literal_query_budget(current.lits.len());

    // Phase 1: domain-guided single-literal dropping to a fixpoint.
    loop {
        let (candidate, reason) = try_drop_single_literal(
            query_engine,
            frames,
            level,
            &current,
            deadline,
            &mut single_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(candidate) = candidate else {
            break;
        };
        current = candidate;
        if current.lits.len() <= 1 {
            return Ok((Some(current), None));
        }
    }

    // Phase 2: bounded pair dropping to escape local minima of pure greedy
    // single-literal elimination. After each pair-drop, saturate singles again.
    while current.lits.len() > 2 {
        let (pair_candidate, reason) = try_drop_literal_pair(
            query_engine,
            frames,
            level,
            &current,
            deadline,
            &mut pair_budget,
        )?;
        if let Some(reason) = reason {
            return Ok((None, Some(reason)));
        }
        let Some(pair_candidate) = pair_candidate else {
            break;
        };
        current = pair_candidate;
        loop {
            let (single_candidate, reason) = try_drop_single_literal(
                query_engine,
                frames,
                level,
                &current,
                deadline,
                &mut single_budget,
            )?;
            if let Some(reason) = reason {
                return Ok((None, Some(reason)));
            }
            let Some(single_candidate) = single_candidate else {
                break;
            };
            current = single_candidate;
            if current.lits.len() <= 1 {
                return Ok((Some(current), None));
            }
        }
    }
    Ok((Some(current), None))
}

fn add_blocking_cube_up_to(frames: &mut [PdrFrame], level: usize, cube: Cube) {
    for frame in frames.iter_mut().take(level + 1).skip(1) {
        frame.insert(cube.clone());
    }
}

enum BlockingOutcome {
    Blocked,
    Counterexample,
    Unknown(String),
}

fn block_cube_with_obligations<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frames: &mut [PdrFrame],
    level: usize,
    initial_cube: Cube,
    deadline: Option<Instant>,
) -> Result<BlockingOutcome, S::Error> {
    let max_obligations = pdr_obligation_budget(query_engine.artifacts.state_vars_pre.len(), level);
    let mut obligations = vec![(initial_cube, level)];
    let mut processed = 0usize;

    while let Some((cube, level)) = obligations.pop() {
        if deadline_exceeded(deadline) {
            return Ok(BlockingOutcome::Unknown(OVERALL_TIMEOUT_REASON.into()));
        }
        processed += 1;
        if processed > max_obligations {
            return Ok(BlockingOutcome::Unknown(
                format!(
                    "PDR: obligation budget exceeded while blocking a bad cube (budget={max_obligations})."
                ),
            ));
        }
        if level == 0 {
            return Ok(BlockingOutcome::Counterexample);
        }

        let (pred_res, pred_cube) = query_engine.predecessor_query(frames, level, &cube, true)?;

        match pred_res {
            SatQueryResult::Unsat => {
                let (generalized, unknown_reason) =
                    try_generalize_cube(query_engine, frames, level, &cube, deadline)?;
                if let Some(reason) = unknown_reason {
                    return Ok(BlockingOutcome::Unknown(reason));
                }
                if let Some(generalized_cube) = generalized {
                    add_blocking_cube_up_to(frames, level, generalized_cube);
                } else {
                    return Ok(BlockingOutcome::Unknown(
                        "PDR: failed to generalize blocking cube".into(),
                    ));
                }
            }
            SatQueryResult::Sat => {
                if let Some(pred_cube) = pred_cube {
                    // Re-try this obligation after blocking predecessor.
                    obligations.push((cube, level));
                    obligations.push((pred_cube, level - 1));
                } else {
                    return Ok(BlockingOutcome::Unknown(
                        "PDR: predecessor query returned SAT without predecessor model".into(),
                    ));
                }
            }
            SatQueryResult::Unknown(reason) => {
                return Ok(BlockingOutcome::Unknown(reason));
            }
        }
    }

    Ok(BlockingOutcome::Blocked)
}

fn can_push_cube_to_next_frame<S: SmtSolver>(
    query_engine: &mut PdrQueryEngine<'_, S>,
    frame: &PdrFrame,
    cube: &Cube,
) -> Result<SatQueryResult, S::Error> {
    query_engine.can_push_cube_to_next_frame(frame, cube)
}

fn rename_state_vars_in_term(term: &SmtTerm, map: &HashMap<String, String>) -> SmtTerm {
    match term {
        SmtTerm::Var(name) => {
            if let Some(mapped) = map.get(name) {
                SmtTerm::Var(mapped.clone())
            } else {
                SmtTerm::Var(name.clone())
            }
        }
        SmtTerm::IntLit(n) => SmtTerm::IntLit(*n),
        SmtTerm::BoolLit(b) => SmtTerm::BoolLit(*b),
        SmtTerm::Add(lhs, rhs) => SmtTerm::Add(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Sub(lhs, rhs) => SmtTerm::Sub(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Mul(lhs, rhs) => SmtTerm::Mul(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Eq(lhs, rhs) => SmtTerm::Eq(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Lt(lhs, rhs) => SmtTerm::Lt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Le(lhs, rhs) => SmtTerm::Le(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Gt(lhs, rhs) => SmtTerm::Gt(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::Ge(lhs, rhs) => SmtTerm::Ge(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::And(terms) => SmtTerm::And(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Or(terms) => SmtTerm::Or(
            terms
                .iter()
                .map(|t| rename_state_vars_in_term(t, map))
                .collect(),
        ),
        SmtTerm::Not(inner) => SmtTerm::Not(Box::new(rename_state_vars_in_term(inner, map))),
        SmtTerm::Implies(lhs, rhs) => SmtTerm::Implies(
            Box::new(rename_state_vars_in_term(lhs, map)),
            Box::new(rename_state_vars_in_term(rhs, map)),
        ),
        SmtTerm::ForAll(vars, body) => {
            SmtTerm::ForAll(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Exists(vars, body) => {
            SmtTerm::Exists(vars.clone(), Box::new(rename_state_vars_in_term(body, map)))
        }
        SmtTerm::Ite(cond, then_term, else_term) => SmtTerm::Ite(
            Box::new(rename_state_vars_in_term(cond, map)),
            Box::new(rename_state_vars_in_term(then_term, map)),
            Box::new(rename_state_vars_in_term(else_term, map)),
        ),
    }
}

fn build_pdr_invariant_certificate(
    artifacts: &PdrArtifacts,
    frame: &PdrFrame,
    frame_id: usize,
) -> PdrInvariantCertificate {
    let mut invariant_pre = artifacts.state_assertions_pre.clone();
    let mut cubes: Vec<Cube> = frame.cubes().cloned().collect();
    cubes.sort();
    for cube in &cubes {
        invariant_pre.push(cube.to_blocking_clause_term(&artifacts.state_vars_pre));
    }

    let rename_map: HashMap<String, String> = artifacts
        .state_vars_pre
        .iter()
        .zip(artifacts.state_vars_post.iter())
        .map(|((pre, _), (post, _))| (pre.clone(), post.clone()))
        .collect();
    let invariant_post: Vec<SmtTerm> = invariant_pre
        .iter()
        .map(|t| rename_state_vars_in_term(t, &rename_map))
        .collect();

    PdrInvariantCertificate {
        frame: frame_id,
        declarations: artifacts.declarations.clone(),
        init_assertions: artifacts.init_assertions.clone(),
        transition_assertions: artifacts.transition_assertions.clone(),
        bad_pre: artifacts.bad_pre.clone(),
        invariant_pre,
        invariant_post,
    }
}

fn recover_counterexample_via_bmc<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    depth_hint: usize,
    extra_assertions: &[SmtTerm],
) -> Result<KInductionResult, S::Error> {
    let bmc = if extra_assertions.is_empty() {
        run_bmc(solver, cs, property, depth_hint)?
    } else {
        run_bmc_with_extra_assertions(solver, cs, property, depth_hint, extra_assertions)?
    };
    Ok(match bmc {
        BmcResult::Unsafe { depth, model } => KInductionResult::Unsafe { depth, model },
        BmcResult::Unknown { reason, .. } => KInductionResult::Unknown { reason },
        BmcResult::Safe { .. } => KInductionResult::Unknown {
            reason: "PDR reported a counterexample, but BMC could not reconstruct one.".into(),
        },
    })
}

/// Run unbounded safety proof attempt with full IC3/PDR.
///
/// This implementation includes:
/// - proof-obligation blocking (backward predecessor search),
/// - cube generalization (literal dropping under relative-inductiveness),
/// - frame propagation (pushing clauses forward),
/// - convergence detection `F_i == F_{i+1}`.
///
/// `max_k` controls the maximum number of frames explored before returning
/// `NotProved`.
fn run_pdr_internal<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<(KInductionResult, Option<PdrInvariantCertificate>), S::Error> {
    if max_k == 0 {
        return Ok((KInductionResult::NotProved { max_k, cti: None }, None));
    }

    let Some(artifacts) = build_pdr_artifacts(cs, property) else {
        return Ok((
            KInductionResult::Unknown {
                reason: "Failed to build PDR query artifacts from SMT encodings.".into(),
            },
            None,
        ));
    };

    // F0 = Init (implicit via init_assertions), F1 = true.
    let mut frames = vec![PdrFrame::default(), PdrFrame::default()];
    let mut frontier = 1usize;

    loop {
        if deadline_exceeded(deadline) {
            return Ok((
                KInductionResult::Unknown {
                    reason: OVERALL_TIMEOUT_REASON.into(),
                },
                None,
            ));
        }
        // Base reachability check (exact depth) for fast counterexample discovery.
        let base = if extra_assertions.is_empty() {
            run_bmc_at_depth(solver, cs, property, frontier)?
        } else {
            run_bmc_with_extra_assertions_at_depth(
                solver,
                cs,
                property,
                frontier,
                extra_assertions,
            )?
        };
        match base {
            BmcResult::Unsafe { depth, model } => {
                return Ok((KInductionResult::Unsafe { depth, model }, None));
            }
            BmcResult::Unknown { reason, .. } => {
                return Ok((KInductionResult::Unknown { reason }, None));
            }
            BmcResult::Safe { .. } => {}
        }

        let mut query_engine = PdrQueryEngine::new(solver, &artifacts, extra_assertions);

        info!(
            frontier,
            "pdr: checking and blocking bad states in frontier frame"
        );
        let mut blocked_bad_cubes = 0usize;
        let max_bad_cubes = pdr_bad_cube_budget(artifacts.state_vars_pre.len(), frontier);

        // Block all bad states in the frontier frame.
        loop {
            if deadline_exceeded(deadline) {
                return Ok((
                    KInductionResult::Unknown {
                        reason: OVERALL_TIMEOUT_REASON.into(),
                    },
                    None,
                ));
            }
            match query_engine.query_bad_state_in_frame(&frames[frontier])? {
                CubeQueryResult::Unsat => break,
                CubeQueryResult::Unknown(reason) => {
                    return Ok((KInductionResult::Unknown { reason }, None));
                }
                CubeQueryResult::Sat(bad_cube) => {
                    blocked_bad_cubes += 1;
                    if blocked_bad_cubes > max_bad_cubes {
                        return Ok((
                            KInductionResult::Unknown {
                                reason: format!(
                                    "PDR: blocked over {max_bad_cubes} bad cubes \
                                     at frame {frontier} (adaptive budget); state space appears too large for \
                                     current abstraction."
                                ),
                            },
                            None,
                        ));
                    }
                    match block_cube_with_obligations(
                        &mut query_engine,
                        &mut frames,
                        frontier,
                        bad_cube,
                        deadline,
                    )? {
                        BlockingOutcome::Blocked => {}
                        BlockingOutcome::Unknown(reason) => {
                            return Ok((KInductionResult::Unknown { reason }, None));
                        }
                        BlockingOutcome::Counterexample => {
                            drop(query_engine);
                            return Ok((
                                recover_counterexample_via_bmc(
                                    solver,
                                    cs,
                                    property,
                                    frontier,
                                    extra_assertions,
                                )?,
                                None,
                            ));
                        }
                    }
                }
            }
        }

        // Propagate blocked cubes forward.
        info!(frontier, "pdr: propagating clauses");
        for level in 1..frontier {
            let to_consider: Vec<Cube> = frames[level].cubes().cloned().collect();
            for cube in to_consider {
                if deadline_exceeded(deadline) {
                    return Ok((
                        KInductionResult::Unknown {
                            reason: OVERALL_TIMEOUT_REASON.into(),
                        },
                        None,
                    ));
                }
                if frames[level + 1].contains(&cube) {
                    continue;
                }
                match can_push_cube_to_next_frame(&mut query_engine, &frames[level], &cube)? {
                    SatQueryResult::Unsat => {
                        frames[level + 1].insert(cube);
                    }
                    SatQueryResult::Sat => {}
                    SatQueryResult::Unknown(reason) => {
                        return Ok((KInductionResult::Unknown { reason }, None));
                    }
                }
            }
        }

        // Convergence: if F_i == F_{i+1}, then F_i is inductive.
        for i in 1..frontier {
            if frames[i] == frames[i + 1] {
                info!(frame = i, "pdr: converged");
                let cert = build_pdr_invariant_certificate(&artifacts, &frames[i], i);
                return Ok((KInductionResult::Proved { k: i }, Some(cert)));
            }
        }

        if frontier >= max_k {
            return Ok((KInductionResult::NotProved { max_k, cti: None }, None));
        }

        frames.push(PdrFrame::default());
        frontier += 1;
    }
}

/// Run unbounded safety proof attempt with full IC3/PDR.
///
/// This implementation includes:
/// - proof-obligation blocking (backward predecessor search),
/// - cube generalization (literal dropping under relative-inductiveness),
/// - frame propagation (pushing clauses forward),
/// - convergence detection `F_i == F_{i+1}`.
///
/// `max_k` controls the maximum number of frames explored before returning
/// `NotProved`.
pub fn run_pdr<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
) -> Result<KInductionResult, S::Error> {
    run_pdr_with_deadline(solver, cs, property, max_k, extra_assertions, None)
}

/// Run full IC3/PDR with an optional overall deadline.
pub fn run_pdr_with_deadline<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<KInductionResult, S::Error> {
    Ok(run_pdr_internal(solver, cs, property, max_k, extra_assertions, deadline)?.0)
}

/// Run full IC3/PDR and, on proof, return an inductive-invariant certificate.
pub fn run_pdr_with_certificate<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
) -> Result<(KInductionResult, Option<PdrInvariantCertificate>), S::Error> {
    run_pdr_with_certificate_with_deadline(solver, cs, property, max_k, extra_assertions, None)
}

/// Run full IC3/PDR certificate generation with an optional overall deadline.
pub fn run_pdr_with_certificate_with_deadline<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
    deadline: Option<Instant>,
) -> Result<(KInductionResult, Option<PdrInvariantCertificate>), S::Error> {
    run_pdr_internal(solver, cs, property, max_k, extra_assertions, deadline)
}

/// Backward-compatible alias for the previous function name.
pub fn run_pdr_lite<S: SmtSolver>(
    solver: &mut S,
    cs: &CounterSystem,
    property: &SafetyProperty,
    max_k: usize,
    extra_assertions: &[SmtTerm],
) -> Result<KInductionResult, S::Error> {
    run_pdr(solver, cs, property, max_k, extra_assertions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdr_bad_cube_budget_scales_beyond_legacy_floor() {
        let budget = pdr_bad_cube_budget(120, 8);
        assert!(budget > 5_000);
        assert!(budget <= 200_000);
    }

    #[test]
    fn pdr_obligation_budget_scales_with_state_and_level() {
        let base = pdr_obligation_budget(10, 1);
        let larger = pdr_obligation_budget(200, 12);
        assert!(larger > base);
        assert!(base >= 10_000);
        assert!(larger <= 300_000);
    }

    #[test]
    fn pdr_literal_drop_order_prefers_time_and_message_zeroes() {
        let state_vars = vec![
            ("kappa_1_0".to_string(), SmtSort::Int),
            ("g_1_0".to_string(), SmtSort::Int),
            ("time_1".to_string(), SmtSort::Int),
            ("g_1_1".to_string(), SmtSort::Int),
            ("kappa_1_2".to_string(), SmtSort::Int),
        ];
        let cube = Cube {
            lits: vec![
                CubeLiteral {
                    state_var_idx: 0,
                    value: 2,
                },
                CubeLiteral {
                    state_var_idx: 1,
                    value: 0,
                },
                CubeLiteral {
                    state_var_idx: 2,
                    value: 7,
                },
                CubeLiteral {
                    state_var_idx: 3,
                    value: 4,
                },
                CubeLiteral {
                    state_var_idx: 4,
                    value: 0,
                },
            ],
        };
        let order = pdr_literal_drop_order(&cube, &state_vars);
        assert_eq!(order[0], 2, "time literal should be considered first");
        assert_eq!(
            order[1], 1,
            "zero-valued message counters should be considered early"
        );
        assert!(
            order.iter().position(|idx| *idx == 3).unwrap()
                < order.iter().position(|idx| *idx == 0).unwrap(),
            "message counters should be prioritized before non-zero location counters"
        );
    }

    #[test]
    fn pdr_frame_insert_uses_cube_subsumption() {
        let specific = Cube {
            lits: vec![
                CubeLiteral {
                    state_var_idx: 0,
                    value: 1,
                },
                CubeLiteral {
                    state_var_idx: 1,
                    value: 2,
                },
            ],
        };
        let general = Cube {
            lits: vec![CubeLiteral {
                state_var_idx: 0,
                value: 1,
            }],
        };
        let unrelated = Cube {
            lits: vec![CubeLiteral {
                state_var_idx: 2,
                value: 0,
            }],
        };

        let mut frame = PdrFrame::default();
        frame.insert(specific.clone());
        frame.insert(general.clone());
        frame.insert(unrelated.clone());

        assert!(
            frame.contains(&general),
            "more general cube should be retained"
        );
        assert!(
            !frame.contains(&specific),
            "subsumed specific cube should be removed"
        );
        assert!(
            frame.contains(&unrelated),
            "non-subsumed cube should remain"
        );
    }

    #[test]
    fn wildcard_process_ids_rewrites_identity_channels() {
        let input = "cnt_Vote@R#12<-L#3[view=7]";
        let rewritten = wildcard_process_ids(input);
        assert_eq!(rewritten, "cnt_Vote@R#*<-L#*[view=7]");
    }

    #[test]
    fn cube_symmetry_signature_is_pid_agnostic_under_templates() {
        let cube_a = Cube {
            lits: vec![
                CubeLiteral {
                    state_var_idx: 0,
                    value: 1,
                },
                CubeLiteral {
                    state_var_idx: 1,
                    value: 0,
                },
            ],
        };
        let cube_b = Cube {
            lits: vec![
                CubeLiteral {
                    state_var_idx: 2,
                    value: 1,
                },
                CubeLiteral {
                    state_var_idx: 3,
                    value: 0,
                },
            ],
        };
        let templates = vec![
            "msg|cnt_Vote@R#*<-L#*[value=true]".to_string(),
            "msg|cnt_Vote@R#*<-L#*[value=false]".to_string(),
            "msg|cnt_Vote@R#*<-L#*[value=true]".to_string(),
            "msg|cnt_Vote@R#*<-L#*[value=false]".to_string(),
        ];
        assert_eq!(
            cube_symmetry_signature(&cube_a, &templates),
            cube_symmetry_signature(&cube_b, &templates)
        );
    }
}
