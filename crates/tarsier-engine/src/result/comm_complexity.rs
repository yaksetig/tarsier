//! Quantitative communication-complexity report model and formatter.

use super::*;

/// Communication complexity report (sound upper bounds).
#[derive(Debug, Clone, Serialize)]
pub struct CommComplexityReport {
    /// Schema version for machine-readable consumers.
    pub schema_version: u32,
    /// Ties results to exact model revision and analysis options.
    pub model_metadata: ModelMetadata,
    /// Assumptions under which the quantitative results hold.
    pub model_assumptions: ModelAssumptions,
    /// Notes about assumption applicability.
    pub assumption_notes: Vec<AssumptionNote>,
    /// Documents the bound kind (upper/lower/estimate) for each metric.
    pub bound_annotations: Vec<BoundAnnotation>,
    pub depth: usize,
    pub n_param: Option<String>,
    pub adv_param: Option<String>,
    pub min_decision_steps: Option<usize>,
    pub finality_failure_probability_upper: Option<f64>,
    pub finality_success_probability_lower: Option<f64>,
    pub expected_rounds_to_finality: Option<f64>,
    pub rounds_for_90pct_finality: Option<usize>,
    pub rounds_for_95pct_finality: Option<usize>,
    pub rounds_for_99pct_finality: Option<usize>,
    pub expected_total_messages_upper: Option<String>,
    pub messages_for_90pct_finality_upper: Option<String>,
    pub messages_for_99pct_finality_upper: Option<String>,
    pub expected_total_messages_with_adv_upper: Option<String>,
    pub messages_for_90pct_finality_with_adv_upper: Option<String>,
    pub messages_for_99pct_finality_with_adv_upper: Option<String>,
    pub max_sends_per_rule: usize,
    pub max_sends_per_rule_by_type: Vec<(String, usize)>,
    pub adversary_per_step_bound: Option<String>,
    pub adversary_per_depth_bound: Option<String>,
    pub per_step_bound: String,
    pub per_depth_bound: String,
    pub per_step_bound_with_adv: Option<String>,
    pub per_depth_bound_with_adv: Option<String>,
    pub per_step_bound_big_o: String,
    pub per_depth_bound_big_o: String,
    pub per_step_type_bounds: Vec<(String, String)>,
    pub per_depth_type_bounds: Vec<(String, String)>,
    pub adversary_per_step_type_bounds: Vec<(String, String)>,
    pub adversary_per_depth_type_bounds: Vec<(String, String)>,
    pub per_step_type_bounds_with_adv: Vec<(String, String)>,
    pub per_depth_type_bounds_with_adv: Vec<(String, String)>,
    pub per_step_type_big_o: Vec<(String, String)>,
    pub per_depth_type_big_o: Vec<(String, String)>,
    /// Per-role message bounds (item 1).
    pub per_role_step_bounds: Vec<(String, String)>,
    pub per_role_depth_bounds: Vec<(String, String)>,
    /// Per-phase message bounds (item 1).
    pub per_phase_step_bounds: Vec<(String, String)>,
    pub per_phase_depth_bounds: Vec<(String, String)>,
    /// Sensitivity analysis points for committee parameters (item 3).
    pub sensitivity: Vec<SensitivityPoint>,
    /// Confidence intervals for probabilistic metrics derived from sensitivity samples.
    pub probabilistic_confidence_intervals: Vec<ProbabilisticConfidenceInterval>,
}

impl fmt::Display for CommComplexityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "COMMUNICATION COMPLEXITY (sound upper bounds)")?;
        writeln!(f, "Schema version: {}", self.schema_version)?;
        writeln!(
            f,
            "Model: {} (hash: {})",
            self.model_metadata.filename, self.model_metadata.source_hash
        )?;
        writeln!(
            f,
            "Reproducibility: fp={}, cmd={}, depth={}, env={}/{}/{} ({}, engine={})",
            self.model_metadata.reproducibility_fingerprint,
            self.model_metadata.analysis_options.command,
            self.model_metadata.analysis_options.depth,
            self.model_metadata.analysis_environment.target_os,
            self.model_metadata.analysis_environment.target_arch,
            self.model_metadata.analysis_environment.target_family,
            self.model_metadata.analysis_environment.build_profile,
            self.model_metadata.engine_version,
        )?;
        writeln!(
            f,
            "Assumptions: fault={}, timing={}, auth={}, equiv={}, network={}",
            self.model_assumptions.fault_model,
            self.model_assumptions.timing_model,
            self.model_assumptions.authentication_mode,
            self.model_assumptions.equivocation_mode,
            self.model_assumptions.network_semantics,
        )?;
        for note in &self.assumption_notes {
            writeln!(f, "  [{}] {}", note.level, note.message)?;
        }
        let heuristic_fields: Vec<&str> = self
            .bound_annotations
            .iter()
            .filter(|ann| ann.evidence_class == BoundEvidenceClass::HeuristicEstimate)
            .map(|ann| ann.field.as_str())
            .collect();
        let theorem_backed_count = self
            .bound_annotations
            .iter()
            .filter(|ann| ann.evidence_class == BoundEvidenceClass::TheoremBacked)
            .count();
        if !self.bound_annotations.is_empty() {
            writeln!(
                f,
                "Bound evidence classes: theorem_backed={}, heuristic_estimate={}",
                theorem_backed_count,
                heuristic_fields.len()
            )?;
            if !heuristic_fields.is_empty() {
                writeln!(f, "  Heuristic estimates: {}", heuristic_fields.join(", "))?;
            }
        }
        writeln!(f, "Depth: {}", self.depth)?;
        if let Some(ref n) = self.n_param {
            writeln!(f, "Population parameter: {n}")?;
        } else {
            writeln!(f, "Population parameter: (missing `n`, bounds assume `n`)")?;
        }
        if let Some(ref adv) = self.adv_param {
            writeln!(f, "Adversary bound parameter: {adv}")?;
        }
        if let Some(steps) = self.min_decision_steps {
            writeln!(f, "Latency lower bound (steps to decision): {steps}")?;
        } else {
            writeln!(
                f,
                "Latency lower bound (steps to decision): unknown (no reachable `decided=true` location found)"
            )?;
        }
        if let Some(p_fail) = self.finality_failure_probability_upper {
            writeln!(
                f,
                "Finality failure probability upper bound: {:.3e}",
                p_fail
            )?;
        }
        if let Some(p_succ) = self.finality_success_probability_lower {
            writeln!(f, "Finality success probability lower bound: {:.6}", p_succ)?;
        }
        if let Some(rounds) = self.expected_rounds_to_finality {
            writeln!(
                f,
                "Expected rounds to finality (geometric approx): {rounds:.3}"
            )?;
        }
        if let Some(r90) = self.rounds_for_90pct_finality {
            writeln!(
                f,
                "Rounds for >= 90% finality confidence (geometric approx): {r90}"
            )?;
        }
        if let Some(r99) = self.rounds_for_99pct_finality {
            writeln!(
                f,
                "Rounds for >= 99% finality confidence (geometric approx): {r99}"
            )?;
        }
        if let Some(ref bound) = self.expected_total_messages_upper {
            writeln!(
                f,
                "Expected total messages to finality upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_90pct_finality_upper {
            writeln!(
                f,
                "Messages for >= 90% finality confidence upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_99pct_finality_upper {
            writeln!(
                f,
                "Messages for >= 99% finality confidence upper bound: {bound}"
            )?;
        }
        if let Some(ref bound) = self.expected_total_messages_with_adv_upper {
            writeln!(
                f,
                "Expected total messages to finality upper bound (including adversary): {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_90pct_finality_with_adv_upper {
            writeln!(
                f,
                "Messages for >= 90% finality confidence upper bound (including adversary): {bound}"
            )?;
        }
        if let Some(ref bound) = self.messages_for_99pct_finality_with_adv_upper {
            writeln!(
                f,
                "Messages for >= 99% finality confidence upper bound (including adversary): {bound}"
            )?;
        }

        writeln!(f, "Max sends per rule: {}", self.max_sends_per_rule)?;
        if !self.max_sends_per_rule_by_type.is_empty() {
            writeln!(f, "Max sends per rule by message type:")?;
            for (msg, count) in &self.max_sends_per_rule_by_type {
                writeln!(f, "  {msg}: {count}")?;
            }
        }
        writeln!(
            f,
            "Asymptotic per-step bound (protocol only): {}",
            self.per_step_bound_big_o
        )?;
        writeln!(
            f,
            "Asymptotic per-depth bound (protocol only): {}",
            self.per_depth_bound_big_o
        )?;

        writeln!(
            f,
            "Per-step total bound (protocol only): {}",
            self.per_step_bound
        )?;
        writeln!(
            f,
            "Per-depth total bound (protocol only): {}",
            self.per_depth_bound
        )?;
        if let Some(ref per_step_adv) = self.adversary_per_step_bound {
            writeln!(
                f,
                "Per-step adversary message-injection bound: {per_step_adv}"
            )?;
        }
        if let Some(ref per_depth_adv) = self.adversary_per_depth_bound {
            writeln!(
                f,
                "Per-depth adversary message-injection bound: {per_depth_adv}"
            )?;
        }
        if let Some(ref per_step) = self.per_step_bound_with_adv {
            writeln!(f, "Per-step total bound (including adversary): {per_step}")?;
        }
        if let Some(ref per_depth) = self.per_depth_bound_with_adv {
            writeln!(
                f,
                "Per-depth total bound (including adversary): {per_depth}"
            )?;
        }

        if !self.per_step_type_bounds.is_empty() {
            writeln!(f, "Per-step bounds by message type (protocol only):")?;
            for (msg, bound) in &self.per_step_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by message type (protocol only):")?;
            for (msg, bound) in &self.per_depth_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.adversary_per_step_type_bounds.is_empty() {
            writeln!(f, "Per-step adversary bounds by message type:")?;
            for (msg, bound) in &self.adversary_per_step_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.adversary_per_depth_type_bounds.is_empty() {
            writeln!(f, "Per-depth adversary bounds by message type:")?;
            for (msg, bound) in &self.adversary_per_depth_type_bounds {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_step_type_bounds_with_adv.is_empty() {
            writeln!(f, "Per-step bounds by message type (including adversary):")?;
            for (msg, bound) in &self.per_step_type_bounds_with_adv {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_bounds_with_adv.is_empty() {
            writeln!(f, "Per-depth bounds by message type (including adversary):")?;
            for (msg, bound) in &self.per_depth_type_bounds_with_adv {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_step_type_big_o.is_empty() {
            writeln!(f, "Asymptotic per-step bounds by message type:")?;
            for (msg, bound) in &self.per_step_type_big_o {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_depth_type_big_o.is_empty() {
            writeln!(f, "Asymptotic per-depth bounds by message type:")?;
            for (msg, bound) in &self.per_depth_type_big_o {
                writeln!(f, "  {msg}: {bound}")?;
            }
        }
        if !self.per_role_step_bounds.is_empty() {
            writeln!(f, "Per-step bounds by role (upper bound):")?;
            for (role, bound) in &self.per_role_step_bounds {
                writeln!(f, "  {role}: {bound}")?;
            }
        }
        if !self.per_role_depth_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by role (upper bound):")?;
            for (role, bound) in &self.per_role_depth_bounds {
                writeln!(f, "  {role}: {bound}")?;
            }
        }
        if !self.per_phase_step_bounds.is_empty() {
            writeln!(f, "Per-step bounds by phase (upper bound):")?;
            for (phase, bound) in &self.per_phase_step_bounds {
                writeln!(f, "  {phase}: {bound}")?;
            }
        }
        if !self.per_phase_depth_bounds.is_empty() {
            writeln!(f, "Per-depth bounds by phase (upper bound):")?;
            for (phase, bound) in &self.per_phase_depth_bounds {
                writeln!(f, "  {phase}: {bound}")?;
            }
        }
        if let Some(r95) = self.rounds_for_95pct_finality {
            writeln!(
                f,
                "Rounds for >= 95% finality confidence (geometric approx): {r95}"
            )?;
        }
        if !self.sensitivity.is_empty() {
            writeln!(f, "Sensitivity analysis:")?;
            for pt in &self.sensitivity {
                writeln!(
                    f,
                    "  {}: {} {} -> {} => {} -> {}",
                    pt.metric,
                    pt.parameter,
                    pt.base_value,
                    pt.varied_value,
                    pt.base_result,
                    pt.varied_result,
                )?;
            }
        }
        if !self.probabilistic_confidence_intervals.is_empty() {
            writeln!(
                f,
                "Probabilistic confidence intervals (sensitivity-derived):"
            )?;
            for ci in &self.probabilistic_confidence_intervals {
                writeln!(
                    f,
                    "  {} @ {:.0}%: [{:.6}, {:.6}] (n={}, method={})",
                    ci.metric,
                    ci.level * 100.0,
                    ci.lower,
                    ci.upper,
                    ci.sample_size,
                    ci.method
                )?;
            }
        }
        Ok(())
    }
}
