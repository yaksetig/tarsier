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
///
/// # Parameters
/// - `spec`: Committee population/size/error-budget specification.
///
/// # Returns
/// A derived [`CommitteeAnalysis`] summary, or validation/math errors.
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
        let n = hypergeometric::bigint_to_f64(tail_prob.numer())?;
        let d = hypergeometric::bigint_to_f64(tail_prob.denom())?;
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

    // ---------------------------------------------------------------
    // Degenerate / boundary edge-case tests
    // ---------------------------------------------------------------

    #[test]
    fn degenerate_single_node_committee() {
        // N=1, K=1, S=1: single Byzantine node is the entire committee.
        let spec = CommitteeSpec {
            name: "solo".into(),
            population: 1,
            byzantine: 1,
            committee_size: 1,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        assert_eq!(analysis.b_max, 1);
        assert_eq!(analysis.honest_majority, 0);
    }

    #[test]
    fn degenerate_nk_equals_s() {
        // N=K=S: entire population sampled and all Byzantine.
        let spec = CommitteeSpec {
            name: "all_byz".into(),
            population: 5,
            byzantine: 5,
            committee_size: 5,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        assert_eq!(analysis.b_max, 5);
        assert_eq!(analysis.honest_majority, 0);
    }

    #[test]
    fn epsilon_near_one_committee() {
        // Very relaxed epsilon.
        let spec = CommitteeSpec {
            name: "lax".into(),
            population: 100,
            byzantine: 33,
            committee_size: 20,
            epsilon: 0.99,
        };
        let analysis = analyze_committee(&spec).unwrap();
        // With epsilon near 1, b_max should be very small (near 0 or at expected value)
        assert!(
            analysis.b_max <= 10,
            "b_max={} should be small with very relaxed epsilon",
            analysis.b_max
        );
        assert!(analysis.tail_probability <= 0.99);
    }

    #[test]
    fn full_population_sampled() {
        // S=N: drawing entire population.
        let spec = CommitteeSpec {
            name: "full".into(),
            population: 50,
            byzantine: 15,
            committee_size: 50,
            epsilon: 1e-9,
        };
        let analysis = analyze_committee(&spec).unwrap();
        // Must get exactly K=15 Byzantine
        assert_eq!(analysis.b_max, 15);
        assert_eq!(analysis.honest_majority, 35);
    }

    #[test]
    fn larger_population_committee() {
        // Larger-scale test (N=2000).
        // (N=10000+ exceeds f64 precision for bigint_to_f64 on binomial coefficients)
        let spec = CommitteeSpec {
            name: "large".into(),
            population: 2000,
            byzantine: 666,
            committee_size: 200,
            epsilon: 1e-6,
        };
        let analysis = analyze_committee(&spec).unwrap();
        assert!(analysis.b_max > 66, "b_max={}", analysis.b_max);
        assert!(analysis.b_max < 200, "b_max={}", analysis.b_max);
        assert!(analysis.tail_probability <= 1e-6);
    }

    #[test]
    fn invalid_params_committee() {
        // K > N
        let spec = CommitteeSpec {
            name: "bad".into(),
            population: 10,
            byzantine: 20,
            committee_size: 5,
            epsilon: 1e-6,
        };
        assert!(analyze_committee(&spec).is_err());

        // S > N
        let spec2 = CommitteeSpec {
            name: "bad2".into(),
            population: 10,
            byzantine: 3,
            committee_size: 20,
            epsilon: 1e-6,
        };
        assert!(analyze_committee(&spec2).is_err());
    }

    // ---------------------------------------------------------------
    // Proptest: property-based / randomized tests
    // ---------------------------------------------------------------

    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngAlgorithm};

    fn committee_proptest_config() -> ProptestConfig {
        ProptestConfig {
            cases: 64,
            source_file: Some(file!()),
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            rng_algorithm: RngAlgorithm::ChaCha,
            ..ProptestConfig::default()
        }
    }

    /// Strategy that produces valid CommitteeSpec values with reasonable sizes.
    fn valid_committee_strategy() -> impl Strategy<Value = CommitteeSpec> {
        // population in [2, 200], byzantine in [0, pop-1], committee in [1, pop]
        (2u64..=200)
            .prop_flat_map(|pop| (Just(pop), 0..pop, 1..=pop))
            .prop_flat_map(|(pop, byz, committee)| {
                // epsilon as 10^exp for exp in [-12, -1]
                (-12i32..=-1).prop_map(move |exp| CommitteeSpec {
                    name: "proptest".into(),
                    population: pop,
                    byzantine: byz,
                    committee_size: committee,
                    epsilon: 10f64.powi(exp),
                })
            })
    }

    proptest! {
        #![proptest_config(committee_proptest_config())]

        /// b_max is always non-negative and at most committee_size.
        #[test]
        fn committee_bound_within_range(spec in valid_committee_strategy()) {
            let analysis = analyze_committee(&spec).unwrap();
            prop_assert!(
                analysis.b_max <= spec.committee_size,
                "b_max={} should be <= committee_size={} for pop={}, byz={}",
                analysis.b_max, spec.committee_size, spec.population, spec.byzantine
            );
        }

        /// honest_majority + b_max = committee_size.
        #[test]
        fn honest_majority_plus_bmax_is_committee_size(spec in valid_committee_strategy()) {
            let analysis = analyze_committee(&spec).unwrap();
            prop_assert_eq!(
                analysis.honest_majority + analysis.b_max,
                spec.committee_size,
                "honest_majority + b_max should equal committee_size"
            );
        }

        /// The reported tail_probability should be <= epsilon.
        #[test]
        fn tail_probability_within_epsilon(spec in valid_committee_strategy()) {
            let analysis = analyze_committee(&spec).unwrap();
            prop_assert!(
                analysis.tail_probability <= spec.epsilon,
                "tail_probability={} should be <= epsilon={} for pop={}, byz={}, committee={}",
                analysis.tail_probability,
                spec.epsilon,
                spec.population,
                spec.byzantine,
                spec.committee_size
            );
        }

        /// expected_byzantine should be S * K / N (within floating point tolerance).
        #[test]
        fn expected_byzantine_matches_formula(spec in valid_committee_strategy()) {
            let analysis = analyze_committee(&spec).unwrap();
            let expected = (spec.committee_size as f64) * (spec.byzantine as f64)
                / (spec.population as f64);
            let diff = (analysis.expected_byzantine - expected).abs();
            prop_assert!(
                diff < 1e-10,
                "expected_byzantine={} should match S*K/N={} (diff={})",
                analysis.expected_byzantine, expected, diff
            );
        }

        /// With zero Byzantine nodes, b_max must be 0 and honest_majority = committee_size.
        #[test]
        fn zero_byzantine_gives_zero_bmax(
            pop in 2u64..=200,
            committee in 1u64..=200,
            eps_exp in -12i32..=-1,
        ) {
            prop_assume!(committee <= pop);
            let spec = CommitteeSpec {
                name: "zero_byz".into(),
                population: pop,
                byzantine: 0,
                committee_size: committee,
                epsilon: 10f64.powi(eps_exp),
            };
            let analysis = analyze_committee(&spec).unwrap();
            prop_assert_eq!(
                analysis.b_max, 0,
                "b_max should be 0 when there are no Byzantine nodes"
            );
            prop_assert_eq!(analysis.honest_majority, committee);
        }

        /// A stricter epsilon should give a b_max >= the b_max for a more relaxed epsilon.
        #[test]
        fn stricter_epsilon_gives_larger_or_equal_bmax(
            pop in 10u64..=200,
            byz_frac in 0.01f64..0.49,
            committee_frac in 0.05f64..0.5,
            eps1_exp in -12i32..=-1,
            eps2_exp in -12i32..=-1,
        ) {
            let byz = (pop as f64 * byz_frac) as u64;
            let committee = std::cmp::max(1, (pop as f64 * committee_frac) as u64);
            prop_assume!(byz <= pop && committee <= pop && committee >= 1);

            let eps_small = 10f64.powi(std::cmp::min(eps1_exp, eps2_exp));
            let eps_large = 10f64.powi(std::cmp::max(eps1_exp, eps2_exp));

            let spec_strict = CommitteeSpec {
                name: "strict".into(),
                population: pop,
                byzantine: byz,
                committee_size: committee,
                epsilon: eps_small,
            };
            let spec_lax = CommitteeSpec {
                name: "lax".into(),
                population: pop,
                byzantine: byz,
                committee_size: committee,
                epsilon: eps_large,
            };

            let analysis_strict = analyze_committee(&spec_strict).unwrap();
            let analysis_lax = analyze_committee(&spec_lax).unwrap();
            prop_assert!(
                analysis_strict.b_max >= analysis_lax.b_max,
                "strict eps={} gives b_max={}, but lax eps={} gives b_max={}",
                eps_small, analysis_strict.b_max,
                eps_large, analysis_lax.b_max
            );
        }
    }
}
