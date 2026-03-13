// Quantitative helper functions for symbolic bounds and probability summaries.

use super::*;

/// Render a multiplicative symbolic bound from ordered factors.
pub(in super::super) fn format_bound(parts: &[String]) -> String {
    if parts.is_empty() {
        return "0".into();
    }
    parts.join(" * ")
}

/// Render `multiplier * symbol` with simplifications for 0 and 1.
pub(in super::super) fn format_scaled_term(symbol: &str, multiplier: usize) -> String {
    match multiplier {
        0 => "0".into(),
        1 => symbol.to_string(),
        _ => format_bound(&[symbol.to_string(), multiplier.to_string()]),
    }
}

/// Render an additive symbolic bound while dropping additive zero terms.
pub(in super::super) fn format_sum_bounds(parts: &[String]) -> String {
    let kept: Vec<&String> = parts.iter().filter(|p| p.as_str() != "0").collect();
    if kept.is_empty() {
        "0".into()
    } else {
        kept.iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

/// Scale a per-step symbolic bound to a per-depth symbolic bound.
pub(in super::super) fn scale_bound_by_depth(depth: usize, bound: &str) -> String {
    if bound == "0" {
        "0".into()
    } else if depth == 1 {
        bound.to_string()
    } else if bound.contains(" + ") {
        format!("{depth} * ({bound})")
    } else {
        format!("{depth} * {bound}")
    }
}

/// Add two symbolic bounds with zero-elision.
pub(in super::super) fn add_bounds(lhs: &str, rhs: &str) -> String {
    if lhs == "0" {
        return rhs.to_string();
    }
    if rhs == "0" {
        return lhs.to_string();
    }
    format!("{lhs} + {rhs}")
}

/// Return minimal rounds `r` such that `1 - p_fail^r >= confidence`.
pub(in super::super) fn geometric_rounds_for_confidence(
    p_fail: f64,
    confidence: f64,
) -> Option<usize> {
    if !(0.0..=1.0).contains(&p_fail) {
        return None;
    }
    if !(0.0..1.0).contains(&confidence) {
        return None;
    }
    if p_fail <= 0.0 {
        return Some(1);
    }
    if p_fail >= 1.0 {
        return None;
    }
    let rounds = ((1.0 - confidence).ln() / p_fail.ln()).ceil();
    if rounds.is_finite() && rounds >= 1.0 {
        Some(rounds as usize)
    } else {
        None
    }
}

/// Compute lowercase hex SHA-256 digest for arbitrary bytes.
pub(in super::super) fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    format!("{:x}", hasher.finalize())
}

/// Build a deterministic fingerprint over source hash, options, environment, and engine version.
pub(in super::super) fn quantitative_reproducibility_fingerprint(
    source_hash: &str,
    engine_version: &str,
    options: &QuantitativeAnalysisOptions,
    environment: &QuantitativeAnalysisEnvironment,
) -> Result<String, PipelineError> {
    let payload = serde_json::json!({
        "source_hash": source_hash,
        "engine_version": engine_version,
        "options": options,
        "environment": environment,
    });
    let serialized = serde_json::to_vec(&payload).map_err(|e| {
        PipelineError::Validation(format!(
            "failed to serialize reproducibility payload for quantitative report: {e}"
        ))
    })?;
    Ok(sha256_hex(serialized))
}

/// Linear-interpolated quantile over finite values.
pub(in super::super) fn quantile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() || !(0.0..=1.0).contains(&q) {
        return None;
    }
    if values.len() == 1 {
        return Some(values[0]);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let pos = q * ((sorted.len() - 1) as f64);
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return Some(sorted[lo]);
    }
    let frac = pos - (lo as f64);
    Some(sorted[lo] * (1.0 - frac) + sorted[hi] * frac)
}

pub(in super::super) fn push_prob_sample(
    probabilistic_metric_samples: &mut BTreeMap<String, Vec<f64>>,
    metric: &str,
    value: Option<f64>,
) {
    if let Some(v) = value.filter(|v| v.is_finite()) {
        probabilistic_metric_samples
            .entry(metric.to_string())
            .or_default()
            .push(v);
    }
}

pub(in super::super) fn push_prob_sensitivity_point(
    sensitivity: &mut Vec<SensitivityPoint>,
    probabilistic_metric_samples: &mut BTreeMap<String, Vec<f64>>,
    metric: &str,
    base: Option<f64>,
    varied: Option<f64>,
    base_epsilon: f64,
    varied_epsilon: f64,
) {
    if let (Some(base_result), Some(varied_result)) = (base, varied) {
        sensitivity.push(SensitivityPoint {
            parameter: "epsilon".into(),
            base_value: base_epsilon,
            varied_value: varied_epsilon,
            metric: metric.into(),
            base_result,
            varied_result,
        });
        push_prob_sample(probabilistic_metric_samples, metric, Some(varied_result));
    }
}
