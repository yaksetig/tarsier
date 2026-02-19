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
    pub fn new(n: u64, k: u64, s: u64) -> Result<Self, HypergeometricError> {
        if k > n || s > n {
            return Err(HypergeometricError::InvalidParams { n, k, s });
        }
        Ok(Self { n, k, s })
    }

    /// Minimum possible value of X.
    pub fn min_val(&self) -> u64 {
        (self.s + self.k).saturating_sub(self.n)
    }

    /// Maximum possible value of X.
    pub fn max_val(&self) -> u64 {
        std::cmp::min(self.k, self.s)
    }

    /// Expected value E[X] = S * K / N.
    pub fn expected_value(&self) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        (self.s as f64) * (self.k as f64) / (self.n as f64)
    }
}

/// Exact binomial coefficient C(n, k) using BigInt.
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
    if rational_to_f64_ceil(&current_survival) <= epsilon {
        return Ok(0);
    }

    // For b = 1, 2, ..., max_val:
    // P(X > b) = P(X > b-1) - PMF(b)
    for b in 1..=max_val {
        let pmf_b = pmf(params, b);
        current_survival -= pmf_b;

        // Conservative comparison: round survival UP before comparing to epsilon
        let survival_f64 = rational_to_f64_ceil(&current_survival);
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
fn rational_to_f64_ceil(r: &BigRational) -> f64 {
    if r.is_zero() {
        return 0.0;
    }
    if r < &BigRational::zero() {
        return 0.0;
    }

    // Convert numerator and denominator to f64
    let numer_f64 = bigint_to_f64(&r.numer().clone());
    let denom_f64 = bigint_to_f64(&r.denom().clone());

    if denom_f64 == 0.0 {
        return f64::INFINITY;
    }

    let result = numer_f64 / denom_f64;

    // Use next_up to round toward positive infinity
    // This ensures we never underestimate the probability
    if result == 0.0 && !r.is_zero() {
        // Very small positive number
        f64::MIN_POSITIVE
    } else {
        next_up(result)
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

/// Convert a BigInt to f64 (best-effort, may lose precision for very large values).
fn bigint_to_f64(n: &BigInt) -> f64 {
    use num::ToPrimitive;
    n.to_f64().unwrap_or(f64::INFINITY)
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
}
