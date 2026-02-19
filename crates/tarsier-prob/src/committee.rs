use thiserror::Error;

use crate::hypergeometric::{self, HypergeometricError, HypergeometricParams};

#[derive(Debug, Error)]
pub enum CommitteeError {
    #[error("Hypergeometric error: {0}")]
    Hypergeometric(#[from] HypergeometricError),
    #[error("Committee size must be positive")]
    ZeroCommitteeSize,
}

/// Specification of a committee selection process.
#[derive(Debug, Clone)]
pub struct CommitteeSpec {
    /// Name of this committee (e.g., "voters").
    pub name: String,
    /// Total population size N.
    pub population: u64,
    /// Number of Byzantine nodes in the population K.
    pub byzantine: u64,
    /// Committee size S.
    pub committee_size: u64,
    /// Target failure probability epsilon.
    pub epsilon: f64,
}

/// Result of committee analysis.
#[derive(Debug, Clone)]
pub struct CommitteeAnalysis {
    /// The committee specification that was analyzed.
    pub spec: CommitteeSpec,
    /// Maximum Byzantine nodes in the committee with probability >= 1 - epsilon.
    pub b_max: u64,
    /// Expected number of Byzantine nodes in the committee.
    pub expected_byzantine: f64,
    /// Actual tail probability P(X > b_max).
    pub tail_probability: f64,
    /// Number of honest nodes guaranteed in the committee (committee_size - b_max).
    pub honest_majority: u64,
}

impl std::fmt::Display for CommitteeAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Committee \"{}\":", self.spec.name)?;
        writeln!(
            f,
            "  Population: {} ({} Byzantine)",
            self.spec.population, self.spec.byzantine
        )?;
        writeln!(f, "  Committee size: {}", self.spec.committee_size)?;
        writeln!(f, "  Expected Byzantine: {:.1}", self.expected_byzantine)?;
        writeln!(
            f,
            "  Max Byzantine in committee: {} (P[exceed] <= {:.0e})",
            self.b_max, self.spec.epsilon
        )?;
        write!(
            f,
            "  Honest majority: {} of {}",
            self.honest_majority, self.spec.committee_size
        )
    }
}

/// Analyze a committee selection to determine the worst-case Byzantine count.
///
/// Given a population of N nodes with K Byzantine, drawing a committee of S,
/// compute the smallest b_max such that P(Byzantine in committee > b_max) <= epsilon.
pub fn analyze_committee(spec: &CommitteeSpec) -> Result<CommitteeAnalysis, CommitteeError> {
    if spec.committee_size == 0 {
        return Err(CommitteeError::ZeroCommitteeSize);
    }

    let params = HypergeometricParams::new(spec.population, spec.byzantine, spec.committee_size)?;
    let expected = params.expected_value();
    let b_max = hypergeometric::inverse_survival(&params, spec.epsilon)?;
    let tail_prob = hypergeometric::survival(&params, b_max);

    // Convert tail probability to f64 for display (this is just for reporting)
    let tail_f64 = {
        let numer_s = tail_prob.numer().to_string();
        let denom_s = tail_prob.denom().to_string();
        let n: f64 = numer_s.parse().unwrap_or(0.0);
        let d: f64 = denom_s.parse().unwrap_or(1.0);
        if d == 0.0 {
            0.0
        } else {
            n / d
        }
    };

    let honest_majority = spec.committee_size - b_max;

    Ok(CommitteeAnalysis {
        spec: spec.clone(),
        b_max,
        expected_byzantine: expected,
        tail_probability: tail_f64,
        honest_majority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_committee_basic() {
        let spec = CommitteeSpec {
            name: "voters".into(),
            population: 1000,
            byzantine: 333,
            committee_size: 100,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        assert!(analysis.b_max > 33);
        assert!(analysis.b_max < 100);
        assert!(analysis.honest_majority > 0);
        assert!(analysis.tail_probability <= spec.epsilon);
    }

    #[test]
    fn test_analyze_committee_display() {
        let spec = CommitteeSpec {
            name: "voters".into(),
            population: 1000,
            byzantine: 333,
            committee_size: 100,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        let display = format!("{analysis}");
        assert!(display.contains("voters"));
        assert!(display.contains("1000"));
        assert!(display.contains("333"));
    }

    #[test]
    fn test_analyze_committee_zero_size() {
        let spec = CommitteeSpec {
            name: "empty".into(),
            population: 100,
            byzantine: 10,
            committee_size: 0,
            epsilon: 1e-9,
        };
        assert!(analyze_committee(&spec).is_err());
    }

    #[test]
    fn test_analyze_committee_no_byzantine() {
        let spec = CommitteeSpec {
            name: "clean".into(),
            population: 100,
            byzantine: 0,
            committee_size: 10,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        assert_eq!(analysis.b_max, 0);
        assert_eq!(analysis.honest_majority, 10);
    }
}
