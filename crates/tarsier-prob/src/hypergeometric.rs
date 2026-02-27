use num::bigint::BigInt;
use num::rational::BigRational;
use num::traits::{One, Zero};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HypergeometricError {
    #[error("Invalid parameters: population N={n}, defectives K={k}, draws S={s}")]
    InvalidParams { n: u64, k: u64, s: u64 },
    #[error("Epsilon must be positive, got {0}")]
    InvalidEpsilon(f64),
    #[error("BigInt too large for f64 conversion ({digits} digits)")]
    PrecisionOverflow { digits: usize },
}

/// Parameters for a hypergeometric distribution.
///
/// Models drawing S items without replacement from a population of N,
/// where K are "defective" (Byzantine). X is the number of defectives drawn.
#[derive(Debug, Clone)]
pub struct HypergeometricParams {
    /// Total population size.
    pub n: u64,
    /// Number of defectives (Byzantine) in population.
    pub k: u64,
    /// Number of draws (committee size).
    pub s: u64,
}

impl HypergeometricParams {
    /// Construct validated hypergeometric parameters.
    ///
    /// # Parameters
    /// - `n`: Population size.
    /// - `k`: Number of defective/Byzantine elements in the population.
    /// - `s`: Draw count / committee size.
    ///
    /// # Returns
    /// Validated parameters or [`HypergeometricError::InvalidParams`].
    pub fn new(n: u64, k: u64, s: u64) -> Result<Self, HypergeometricError> {
        if k > n || s > n {
            return Err(HypergeometricError::InvalidParams { n, k, s });
        }
        Ok(Self { n, k, s })
    }

    /// Minimum possible value of `X`.
    ///
    /// # Returns
    /// Lower bound on the support of `X`.
    pub fn min_val(&self) -> u64 {
        (self.s + self.k).saturating_sub(self.n)
    }

    /// Maximum possible value of `X`.
    ///
    /// # Returns
    /// Upper bound on the support of `X`.
    pub fn max_val(&self) -> u64 {
        std::cmp::min(self.k, self.s)
    }

    /// Expected value `E\[X\] = S * K / N`.
    ///
    /// # Returns
    /// Floating-point expectation under the exact hypergeometric model.
    pub fn expected_value(&self) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        (self.s as f64) * (self.k as f64) / (self.n as f64)
    }
}

/// Exact binomial coefficient C(n, k) using BigInt.
///
/// # Parameters
/// - `n`: Population count.
/// - `k`: Selection count.
///
/// # Returns
/// Exact integer value of `C(n, k)`.
pub fn binomial(n: u64, k: u64) -> BigInt {
    if k > n {
        return BigInt::zero();
    }
    // Use the smaller of k and n-k for efficiency
    let k = std::cmp::min(k, n - k);
    if k == 0 {
        return BigInt::one();
    }
    let mut result = BigInt::one();
    for i in 0..k {
        result *= BigInt::from(n - i);
        result /= BigInt::from(i + 1);
    }
    result
}

/// Exact PMF: P(X = x) = C(K, x) * C(N-K, S-x) / C(N, S).
///
/// Returns as BigRational for exact arithmetic.
///
/// # Parameters
/// - `params`: Hypergeometric distribution parameters.
/// - `x`: Query value.
///
/// # Returns
/// Exact probability mass `P(X = x)`.
pub fn pmf(params: &HypergeometricParams, x: u64) -> BigRational {
    if x > params.k || x > params.s {
        return BigRational::zero();
    }
    if params.s - x > params.n - params.k {
        return BigRational::zero();
    }

    let numerator = binomial(params.k, x) * binomial(params.n - params.k, params.s - x);
    let denominator = binomial(params.n, params.s);

    if denominator.is_zero() {
        return BigRational::zero();
    }

    BigRational::new(numerator, denominator)
}

/// Exact survival function: P(X > b) = sum of PMF(x) for x = b+1..max_val.
///
/// Returns as BigRational for exact arithmetic.
///
/// # Parameters
/// - `params`: Hypergeometric distribution parameters.
/// - `b`: Threshold value.
///
/// # Returns
/// Exact tail probability `P(X > b)`.
pub fn survival(params: &HypergeometricParams, b: u64) -> BigRational {
    let max_val = params.max_val();
    let mut result = BigRational::zero();
    for x in (b + 1)..=max_val {
        result += pmf(params, x);
    }
    result
}

/// Find the smallest b such that P(X > b) <= epsilon.
///
/// Uses exact arithmetic for all intermediate computation.
/// Only converts to f64 at the final comparison, rounding UP for conservatism.
///
/// Returns the derived bound b_max.
///
/// # Parameters
/// - `params`: Hypergeometric distribution parameters.
/// - `epsilon`: Maximum allowed tail probability.
///
/// # Returns
/// Smallest `b` such that `P(X > b) <= epsilon`.
pub fn inverse_survival(
    params: &HypergeometricParams,
    epsilon: f64,
) -> Result<u64, HypergeometricError> {
    if epsilon <= 0.0 {
        return Err(HypergeometricError::InvalidEpsilon(epsilon));
    }

    let max_val = params.max_val();

    // Start with P(X > 0) = 1 - PMF(0), computed as sum of PMF(1..max_val)
    // But it's more efficient to compute P(X > b) incrementally:
    // P(X > b+1) = P(X > b) - PMF(b+1)

    // First compute P(X > -1) = 1 (entire distribution), then work from b=0
    // Actually, compute the full survival at b=0 first, then subtract.

    // Compute survival(0) = P(X > 0) = P(X >= 1) = 1 - PMF(0)
    let one = BigRational::one();
    let pmf_0 = pmf(params, 0);
    let mut current_survival = one - pmf_0; // P(X > 0) = P(X >= 1)

    // Check b = 0: P(X > 0) <= epsilon?
    if rational_to_f64_ceil(&current_survival)? <= epsilon {
        return Ok(0);
    }

    // For b = 1, 2, ..., max_val:
    // P(X > b) = P(X > b-1) - PMF(b)
    for b in 1..=max_val {
        let pmf_b = pmf(params, b);
        current_survival -= pmf_b;

        // Conservative comparison: round survival UP before comparing to epsilon
        let survival_f64 = rational_to_f64_ceil(&current_survival)?;
        if survival_f64 <= epsilon {
            return Ok(b);
        }
    }

    // If we reach max_val, P(X > max_val) = 0 <= epsilon always
    Ok(max_val)
}

/// Convert a BigRational to f64, rounding UP (toward positive infinity).
///
/// This ensures conservative comparison: if the true probability is p,
/// we return a value >= p, so P(X > b) <= epsilon is never falsely satisfied.
fn rational_to_f64_ceil(r: &BigRational) -> Result<f64, HypergeometricError> {
    if r.is_zero() {
        return Ok(0.0);
    }
    if r < &BigRational::zero() {
        return Ok(0.0);
    }

    // Convert numerator and denominator to f64
    let numer_f64 = bigint_to_f64(r.numer())?;
    let denom_f64 = bigint_to_f64(r.denom())?;

    if denom_f64 == 0.0 {
        return Ok(f64::INFINITY);
    }

    let result = numer_f64 / denom_f64;

    // Use next_up to round toward positive infinity
    // This ensures we never underestimate the probability
    if result == 0.0 && !r.is_zero() {
        // Very small positive number
        Ok(f64::MIN_POSITIVE)
    } else {
        Ok(next_up(result))
    }
}

/// Approximate next representable f64 above x (rounding up).
fn next_up(x: f64) -> f64 {
    if x.is_nan() || x == f64::INFINITY {
        return x;
    }
    if x == f64::NEG_INFINITY {
        return f64::MIN;
    }
    let bits = x.to_bits();
    let next_bits = if x >= 0.0 { bits + 1 } else { bits - 1 };
    f64::from_bits(next_bits)
}

/// Convert a BigInt to f64, returning an error if the value is too large.
pub(crate) fn bigint_to_f64(n: &BigInt) -> Result<f64, HypergeometricError> {
    use num::ToPrimitive;
    match n.to_f64() {
        Some(v) if v.is_finite() => Ok(v),
        _ => Err(HypergeometricError::PrecisionOverflow {
            digits: n.to_string().len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binomial_basic() {
        assert_eq!(binomial(0, 0), BigInt::one());
        assert_eq!(binomial(5, 0), BigInt::one());
        assert_eq!(binomial(5, 5), BigInt::one());
        assert_eq!(binomial(5, 2), BigInt::from(10));
        assert_eq!(binomial(10, 3), BigInt::from(120));
        assert_eq!(binomial(3, 5), BigInt::zero()); // k > n
    }

    #[test]
    fn test_binomial_large() {
        // C(100, 50) is a well-known large number
        let c100_50 = binomial(100, 50);
        assert!(c100_50 > BigInt::zero());
        // C(100,50) = 100891344545564193334812497256
        let expected: BigInt = "100891344545564193334812497256".parse().unwrap();
        assert_eq!(c100_50, expected);
    }

    #[test]
    fn test_pmf_sums_to_one() {
        let params = HypergeometricParams::new(20, 7, 5).unwrap();
        let mut total = BigRational::zero();
        for x in params.min_val()..=params.max_val() {
            total += pmf(&params, x);
        }
        assert_eq!(total, BigRational::one(), "PMF should sum to 1");
    }

    #[test]
    fn test_pmf_sums_to_one_large() {
        let params = HypergeometricParams::new(1000, 333, 100).unwrap();
        let mut total = BigRational::zero();
        for x in params.min_val()..=params.max_val() {
            total += pmf(&params, x);
        }
        assert_eq!(
            total,
            BigRational::one(),
            "PMF should sum to 1 for large params"
        );
    }

    #[test]
    fn test_pmf_known_values() {
        // Simple case: N=10, K=3, S=4
        // P(X=0) = C(3,0)*C(7,4)/C(10,4) = 1*35/210 = 1/6
        let params = HypergeometricParams::new(10, 3, 4).unwrap();
        let p0 = pmf(&params, 0);
        assert_eq!(p0, BigRational::new(BigInt::from(1), BigInt::from(6)));
    }

    #[test]
    fn test_survival_bounds() {
        let params = HypergeometricParams::new(20, 7, 5).unwrap();
        // P(X > -1) would be 1 (not computed), P(X > max) should be 0
        let s_max = survival(&params, params.max_val());
        assert_eq!(s_max, BigRational::zero());

        // P(X > 0) should be < 1
        let s0 = survival(&params, 0);
        assert!(s0 < BigRational::one());
        assert!(s0 > BigRational::zero());
    }

    #[test]
    fn test_inverse_survival_user_scenario() {
        // N=1000, K=333, S=100, epsilon=1e-9
        let params = HypergeometricParams::new(1000, 333, 100).unwrap();
        let b_max = inverse_survival(&params, 1e-9).unwrap();
        // The expected value is ~33.3, so b_max should be significantly above that
        // but well below 100.
        assert!(
            b_max > 33,
            "b_max={b_max} should be above expected value 33"
        );
        assert!(
            b_max < 100,
            "b_max={b_max} should be less than committee size"
        );
        // Cross-validated with scipy: hypergeom.sf(61, 1000, 333, 100) = 5.18e-10 <= 1e-9
        // Our conservative rounding (ceil) may give 61 or 62.
        assert!(b_max >= 59, "b_max={b_max} should be at least 59");
        assert!(b_max <= 63, "b_max={b_max} should be at most 63");
    }

    #[test]
    fn test_inverse_survival_leader_election() {
        // S=1 (single leader): P(X > 0) = P(X=1) = K/N
        let params = HypergeometricParams::new(1000, 333, 1).unwrap();
        // P(X > 0) = P(X=1) = 333/1000 = 0.333
        // For epsilon >= 0.333, b_max should be 0
        let b0 = inverse_survival(&params, 0.334).unwrap();
        assert_eq!(b0, 0, "With epsilon > P(X=1), b_max should be 0");

        // For epsilon < 0.333, b_max should be 1
        let b1 = inverse_survival(&params, 0.01).unwrap();
        assert_eq!(b1, 1, "With epsilon < P(X=1), b_max should be 1 (max)");
    }

    #[test]
    fn test_expected_value() {
        let params = HypergeometricParams::new(1000, 333, 100).unwrap();
        let ev = params.expected_value();
        assert!((ev - 33.3).abs() < 0.1);
    }

    #[test]
    fn test_inverse_survival_epsilon_too_small() {
        // Even with very small epsilon, should return max_val at worst
        let params = HypergeometricParams::new(10, 5, 5).unwrap();
        let b = inverse_survival(&params, 1e-15).unwrap();
        assert!(b <= params.max_val());
    }

    #[test]
    fn test_invalid_params() {
        assert!(HypergeometricParams::new(10, 20, 5).is_err()); // K > N
        assert!(HypergeometricParams::new(10, 5, 20).is_err()); // S > N
    }

    #[test]
    fn test_invalid_epsilon() {
        let params = HypergeometricParams::new(10, 3, 5).unwrap();
        assert!(inverse_survival(&params, 0.0).is_err());
        assert!(inverse_survival(&params, -1.0).is_err());
    }

    // ---------------------------------------------------------------
    // Degenerate / boundary edge-case tests
    // ---------------------------------------------------------------

    #[test]
    fn degenerate_single_node_byzantine() {
        // N=1, K=1, S=1: only one node and it's Byzantine.
        // X must be 1 with certainty.
        let params = HypergeometricParams::new(1, 1, 1).unwrap();
        assert_eq!(params.min_val(), 1);
        assert_eq!(params.max_val(), 1);
        assert_eq!(pmf(&params, 1), BigRational::one());
        assert_eq!(pmf(&params, 0), BigRational::zero());
        assert_eq!(survival(&params, 0), BigRational::one()); // P(X > 0) = 1
        assert_eq!(survival(&params, 1), BigRational::zero()); // P(X > 1) = 0
    }

    #[test]
    fn degenerate_single_node_honest() {
        // N=1, K=0, S=1: single honest node.
        let params = HypergeometricParams::new(1, 0, 1).unwrap();
        assert_eq!(params.min_val(), 0);
        assert_eq!(params.max_val(), 0);
        assert_eq!(pmf(&params, 0), BigRational::one());
        assert_eq!(survival(&params, 0), BigRational::zero());
        let b = inverse_survival(&params, 0.5).unwrap();
        assert_eq!(b, 0);
    }

    #[test]
    fn degenerate_all_byzantine_all_drawn() {
        // N=K=S: entire population is Byzantine and fully sampled.
        let params = HypergeometricParams::new(5, 5, 5).unwrap();
        assert_eq!(params.min_val(), 5);
        assert_eq!(params.max_val(), 5);
        assert_eq!(pmf(&params, 5), BigRational::one());
        // P(X > 4) = 1 (guaranteed all 5 are Byzantine)
        assert_eq!(survival(&params, 4), BigRational::one());
        // inverse_survival should return max_val for any epsilon
        let b = inverse_survival(&params, 0.5).unwrap();
        assert_eq!(b, 5);
    }

    #[test]
    fn degenerate_draw_entire_population() {
        // S=N: sampling entire population without replacement.
        // X must equal K deterministically.
        let params = HypergeometricParams::new(10, 3, 10).unwrap();
        assert_eq!(params.min_val(), 3);
        assert_eq!(params.max_val(), 3);
        assert_eq!(pmf(&params, 3), BigRational::one());
        let b = inverse_survival(&params, 1e-15).unwrap();
        assert_eq!(b, 3);
    }

    #[test]
    fn epsilon_near_one() {
        // With epsilon close to 1, even a loose bound suffices → b_max should be small.
        let params = HypergeometricParams::new(100, 50, 20).unwrap();
        let b = inverse_survival(&params, 0.99).unwrap();
        // Expected ~10 Byzantine. With epsilon=0.99, b_max should be very small.
        assert!(b <= 10, "b_max={b} should be small with epsilon near 1");
    }

    #[test]
    fn epsilon_barely_above_zero() {
        // Very strict epsilon, should push b_max toward max_val.
        let params = HypergeometricParams::new(20, 10, 10).unwrap();
        let b = inverse_survival(&params, 1e-15).unwrap();
        assert_eq!(
            b,
            params.max_val(),
            "Very strict epsilon should give max_val"
        );
    }

    #[test]
    fn bigint_to_f64_overflow_returns_error() {
        // A BigInt with ~2400 digits (like C(10000, 5000)) exceeds f64 range.
        let huge = binomial(10000, 5000);
        let result = bigint_to_f64(&huge);
        match result {
            Err(HypergeometricError::PrecisionOverflow { digits }) => {
                assert!(digits > 300, "expected many digits, got {digits}");
            }
            Err(other) => panic!("expected PrecisionOverflow, got: {other}"),
            Ok(v) => panic!("expected error for C(10000,5000), got {v}"),
        }
    }

    #[test]
    fn bigint_to_f64_succeeds_for_small_values() {
        let small = BigInt::from(42);
        assert_eq!(bigint_to_f64(&small).unwrap(), 42.0);
        let medium = BigInt::from(u64::MAX);
        assert!(bigint_to_f64(&medium).is_ok());
    }

    #[test]
    fn larger_population_verification() {
        // N=2000, K=666, S=200, epsilon=1e-6
        // (N=10000+ exceeds f64 precision for bigint_to_f64 on binomial coefficients)
        let params = HypergeometricParams::new(2000, 666, 200).unwrap();
        let b = inverse_survival(&params, 1e-6).unwrap();
        let ev = params.expected_value();
        // Expected ~66.6, b_max should be significantly above but below 200.
        assert!(
            b as f64 > ev,
            "b_max={b} should exceed expected value {ev:.1}"
        );
        assert!(b < 200, "b_max={b} should be less than committee size");
        // Verify the actual survival is <= epsilon
        let surv = survival(&params, b);
        use num::ToPrimitive;
        let surv_f64 =
            surv.numer().to_f64().unwrap_or(f64::INFINITY) / surv.denom().to_f64().unwrap_or(1.0);
        assert!(
            surv_f64 <= 1e-6,
            "P(X > {b}) = {surv_f64} should be <= 1e-6"
        );
    }

    #[test]
    fn inverse_survival_conservative_rounding() {
        // Verify that b_max is the SMALLEST valid bound by checking b_max - 1.
        let params = HypergeometricParams::new(1000, 333, 100).unwrap();
        let epsilon = 1e-9;
        let b_max = inverse_survival(&params, epsilon).unwrap();

        // At b_max, survival should be <= epsilon
        let surv_at_bmax = survival(&params, b_max);
        let surv_f64 = rational_to_f64_ceil(&surv_at_bmax).unwrap();
        assert!(
            surv_f64 <= epsilon,
            "P(X > {b_max}) = {surv_f64} should be <= {epsilon}"
        );

        // At b_max - 1, survival should be > epsilon (otherwise b_max is not minimal)
        if b_max > 0 {
            let surv_at_prev = survival(&params, b_max - 1);
            let prev_f64 = rational_to_f64_ceil(&surv_at_prev).unwrap();
            assert!(
                prev_f64 > epsilon,
                "P(X > {}) = {prev_f64} should be > {epsilon} (proving b_max={b_max} is minimal)",
                b_max - 1
            );
        }
    }

    #[test]
    fn next_up_edge_cases() {
        assert_eq!(next_up(0.0), f64::from_bits(1)); // smallest positive subnormal
        assert_eq!(next_up(f64::INFINITY), f64::INFINITY);
        assert!(next_up(f64::NAN).is_nan());
        assert_eq!(next_up(f64::NEG_INFINITY), f64::MIN);
        assert!(next_up(1.0) > 1.0);
        assert!(next_up(-1.0) > -1.0);
    }

    #[test]
    fn pmf_at_boundaries() {
        let params = HypergeometricParams::new(10, 3, 4).unwrap();
        // PMF outside support should be zero
        assert_eq!(pmf(&params, 4), BigRational::zero()); // x > K=3
        assert_eq!(pmf(&params, 100), BigRational::zero()); // x >> N

        // Check min/max val PMF is positive
        let p_min = pmf(&params, params.min_val());
        let p_max = pmf(&params, params.max_val());
        assert!(p_min > BigRational::zero());
        assert!(p_max > BigRational::zero());
    }

    #[test]
    fn expected_value_zero_population() {
        // Direct struct construction to test N=0 edge case
        let params = HypergeometricParams { n: 0, k: 0, s: 0 };
        assert_eq!(params.expected_value(), 0.0);
    }

    // ---------------------------------------------------------------
    // Proptest: property-based / randomized tests
    // ---------------------------------------------------------------

    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngAlgorithm};

    fn prob_proptest_config() -> ProptestConfig {
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

    /// Strategy that produces valid (N, K, S) triples for HypergeometricParams.
    /// Keeps N small enough that exact BigRational arithmetic completes quickly.
    fn valid_params_strategy() -> impl Strategy<Value = (u64, u64, u64)> {
        // N in [1, 200], then K in [0, N], S in [1, N]
        (1u64..=200).prop_flat_map(|n| (Just(n), 0..=n, 1..=n))
    }

    proptest! {
        #![proptest_config(prob_proptest_config())]

        /// PMF values are always non-negative for all valid inputs and x values.
        #[test]
        fn pmf_is_non_negative(
            (n, k, s) in valid_params_strategy(),
            x_frac in 0.0f64..=1.0,
        ) {
            let params = HypergeometricParams::new(n, k, s).unwrap();
            // Map x_frac to a value in [0, max_val]
            let max_v = params.max_val();
            let x = (x_frac * max_v as f64) as u64;
            let p = pmf(&params, x);
            prop_assert!(
                p >= BigRational::zero(),
                "PMF({x}) = {p} should be non-negative for N={n}, K={k}, S={s}"
            );
        }

        /// PMF always sums to exactly 1 over the support [min_val, max_val].
        #[test]
        fn pmf_sums_to_one((n, k, s) in valid_params_strategy()) {
            let params = HypergeometricParams::new(n, k, s).unwrap();
            let mut total = BigRational::zero();
            for x in params.min_val()..=params.max_val() {
                total += pmf(&params, x);
            }
            prop_assert!(
                total == BigRational::one(),
                "PMF should sum to 1 for N={n}, K={k}, S={s}, got {total}"
            );
        }

        /// CDF monotonicity: P(X <= k) should be monotonically non-decreasing in k.
        /// Equivalently, the survival function P(X > b) is non-increasing in b.
        #[test]
        fn survival_is_monotonically_non_increasing((n, k, s) in valid_params_strategy()) {
            let params = HypergeometricParams::new(n, k, s).unwrap();
            let max_v = params.max_val();
            let mut prev_survival = BigRational::one(); // P(X > -1) = 1 conceptually
            // Compute survival at min_val first
            let min_v = params.min_val();
            // Build all survival values from 0 to max_val
            for b in 0..=max_v {
                let surv = survival(&params, b);
                // survival(b) = prev - pmf(b), should be <= prev survival
                prop_assert!(
                    surv <= prev_survival,
                    "survival({b}) = {surv} should be <= survival({}) = {prev_survival} \
                     for N={n}, K={k}, S={s}",
                    if b == 0 { "conceptual -1".to_string() } else { (b - 1).to_string() }
                );
                prev_survival = surv;
            }
            // Check that survival at min_val is < 1 when min_val > 0
            // (meaning there is probability mass below min_val... but actually
            // min_val is the minimum, so survival(min_val-1) should be close to 1).
            // At max_val, survival must be exactly 0.
            let s_max = survival(&params, max_v);
            prop_assert!(
                s_max == BigRational::zero(),
                "survival(max_val={max_v}) should be 0 for N={n}, K={k}, S={s}, got {s_max}"
            );
            // At 0 (if min_val is 0), survival(0) = 1 - pmf(0) should be in [0, 1]
            if min_v == 0 {
                let s0 = survival(&params, 0);
                prop_assert!(s0 >= BigRational::zero());
                prop_assert!(s0 <= BigRational::one());
            }
        }

        /// CDF bounds: for every b in support, 0 <= P(X > b) <= 1.
        #[test]
        fn survival_in_unit_interval((n, k, s) in valid_params_strategy()) {
            let params = HypergeometricParams::new(n, k, s).unwrap();
            for b in 0..=params.max_val() {
                let surv = survival(&params, b);
                prop_assert!(
                    surv >= BigRational::zero(),
                    "survival({b}) = {surv} should be >= 0"
                );
                prop_assert!(
                    surv <= BigRational::one(),
                    "survival({b}) = {surv} should be <= 1"
                );
            }
        }

        /// Hypergeometric symmetry: Hyper(N, K, S) at x has the same PMF as
        /// Hyper(N, S, K) at x. This is because C(K,x)*C(N-K,S-x)/C(N,S)
        /// = C(S,x)*C(N-S,K-x)/C(N,K) by combinatorial identity.
        #[test]
        fn pmf_symmetry_in_k_and_s((n, k, s) in valid_params_strategy()) {
            let params_ks = HypergeometricParams::new(n, k, s).unwrap();
            let params_sk = HypergeometricParams::new(n, s, k).unwrap();
            // The support ranges may differ, so check over the union
            let lo = std::cmp::min(params_ks.min_val(), params_sk.min_val());
            let hi = std::cmp::max(params_ks.max_val(), params_sk.max_val());
            for x in lo..=hi {
                let p_ks = pmf(&params_ks, x);
                let p_sk = pmf(&params_sk, x);
                prop_assert!(
                    p_ks == p_sk,
                    "PMF({x}) should be the same for Hyper({n},{k},{s}) and Hyper({n},{s},{k}), \
                     got {p_ks} vs {p_sk}"
                );
            }
        }

        /// Binomial coefficient Pascal's rule: C(n, k) = C(n-1, k-1) + C(n-1, k).
        #[test]
        fn binomial_pascals_rule(n in 1u64..200, k in 1u64..200) {
            prop_assume!(k <= n);
            let lhs = binomial(n, k);
            let rhs = binomial(n - 1, k - 1) + binomial(n - 1, k);
            prop_assert!(
                lhs == rhs,
                "C({n},{k}) = {lhs} should equal C({},{}) + C({},{}) = {rhs}",
                n - 1, k - 1, n - 1, k
            );
        }

        /// Binomial coefficient symmetry: C(n, k) = C(n, n-k).
        #[test]
        fn binomial_symmetry(n in 0u64..200, k in 0u64..200) {
            prop_assume!(k <= n);
            let lhs = binomial(n, k);
            let rhs = binomial(n, n - k);
            prop_assert!(
                lhs == rhs,
                "C({n},{k}) = {lhs} should equal C({n},{}) = {rhs}",
                n - k
            );
        }

        /// inverse_survival monotonicity: as epsilon increases (less strict),
        /// the bound b_max should be non-increasing (same or smaller).
        /// Conversely, a stricter (smaller) epsilon needs a larger b_max.
        #[test]
        fn inverse_survival_monotone_in_epsilon(
            (n, k, s) in valid_params_strategy(),
            eps1_exp in -12i32..=-1,
            eps2_exp in -12i32..=-1,
        ) {
            let eps_small = 10f64.powi(std::cmp::min(eps1_exp, eps2_exp));
            let eps_large = 10f64.powi(std::cmp::max(eps1_exp, eps2_exp));
            prop_assume!(eps_small > 0.0 && eps_large > 0.0);

            let params = HypergeometricParams::new(n, k, s).unwrap();
            let b_strict = inverse_survival(&params, eps_small).unwrap();
            let b_lax = inverse_survival(&params, eps_large).unwrap();
            prop_assert!(
                b_strict >= b_lax,
                "b_max for eps={eps_small} (={b_strict}) should be >= \
                 b_max for eps={eps_large} (={b_lax}), \
                 N={n}, K={k}, S={s}"
            );
        }

        /// inverse_survival result is always within [0, max_val].
        #[test]
        fn inverse_survival_within_bounds(
            (n, k, s) in valid_params_strategy(),
            eps_exp in -12i32..=-1,
        ) {
            let epsilon = 10f64.powi(eps_exp);
            prop_assume!(epsilon > 0.0);
            let params = HypergeometricParams::new(n, k, s).unwrap();
            let b_max = inverse_survival(&params, epsilon).unwrap();
            prop_assert!(
                b_max <= params.max_val(),
                "b_max={b_max} should be <= max_val={} for N={n}, K={k}, S={s}, eps={epsilon}",
                params.max_val()
            );
        }

        /// inverse_survival correctness: the actual survival at b_max should be <= epsilon.
        /// (Due to conservative rounding, this is the key soundness property.)
        #[test]
        fn inverse_survival_satisfies_bound(
            (n, k, s) in valid_params_strategy(),
            eps_exp in -9i32..=-1,
        ) {
            let epsilon = 10f64.powi(eps_exp);
            prop_assume!(epsilon > 0.0);
            let params = HypergeometricParams::new(n, k, s).unwrap();
            let b_max = inverse_survival(&params, epsilon).unwrap();
            // The exact survival at b_max, converted to f64 (floor for checking).
            let surv = survival(&params, b_max);
            // surv is exact BigRational. Convert conservatively to f64.
            // surv should be <= epsilon (the whole point of inverse_survival).
            use num::ToPrimitive;
            let surv_f64 = surv.numer().to_f64().unwrap_or(f64::INFINITY)
                / surv.denom().to_f64().unwrap_or(1.0);
            prop_assert!(
                surv_f64 <= epsilon,
                "P(X > {b_max}) = {surv_f64} should be <= epsilon={epsilon} \
                 for N={n}, K={k}, S={s}"
            );
        }

        /// min_val <= expected_value <= max_val (when N > 0).
        #[test]
        fn expected_value_in_support((n, k, s) in valid_params_strategy()) {
            let params = HypergeometricParams::new(n, k, s).unwrap();
            let ev = params.expected_value();
            prop_assert!(
                ev >= params.min_val() as f64,
                "E[X]={ev} should be >= min_val={} for N={n}, K={k}, S={s}",
                params.min_val()
            );
            prop_assert!(
                ev <= params.max_val() as f64,
                "E[X]={ev} should be <= max_val={} for N={n}, K={k}, S={s}",
                params.max_val()
            );
        }
    }
}
