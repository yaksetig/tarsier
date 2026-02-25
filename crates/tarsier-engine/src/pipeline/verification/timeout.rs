//! Deadline/timeout utilities for verification pipelines.

use std::time::{Duration, Instant};

use super::*;

pub(crate) fn deadline_exceeded(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() >= deadline,
        None => false,
    }
}

pub(crate) fn overall_timeout_duration(timeout_secs: u64) -> Option<Duration> {
    if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    }
}

pub(crate) fn deadline_from_timeout_secs(timeout_secs: u64) -> Option<Instant> {
    overall_timeout_duration(timeout_secs).and_then(|t| Instant::now().checked_add(t))
}

pub(crate) fn remaining_timeout_secs(deadline: Option<Instant>) -> Option<u64> {
    let deadline = deadline?;
    if Instant::now() >= deadline {
        return Some(0);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let secs = remaining.as_secs();
    let nanos = remaining.subsec_nanos();
    let rounded_up = if nanos > 0 {
        secs.saturating_add(1)
    } else {
        secs
    };
    Some(rounded_up.max(1))
}

pub(crate) fn timeout_unknown_reason(context: &str) -> String {
    format!("{context} timed out before completion.")
}

pub(crate) fn options_with_remaining_timeout(
    options: &PipelineOptions,
    deadline: Option<Instant>,
    context: &str,
) -> Result<PipelineOptions, PipelineError> {
    match remaining_timeout_secs(deadline) {
        Some(0) => Err(PipelineError::Solver(timeout_unknown_reason(context))),
        Some(remaining) => {
            let mut adjusted = options.clone();
            adjusted.timeout_secs = remaining;
            Ok(adjusted)
        }
        None => Ok(options.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_exceeded_none_returns_false() {
        assert!(!deadline_exceeded(None));
    }

    #[test]
    fn deadline_exceeded_future_returns_false() {
        let future = Instant::now() + Duration::from_secs(60);
        assert!(!deadline_exceeded(Some(future)));
    }

    #[test]
    fn deadline_exceeded_past_returns_true() {
        // Use a deadline that is definitely in the past
        let past = Instant::now() - Duration::from_secs(1);
        assert!(deadline_exceeded(Some(past)));
    }

    #[test]
    fn overall_timeout_duration_zero_returns_none() {
        assert!(overall_timeout_duration(0).is_none());
    }

    #[test]
    fn overall_timeout_duration_nonzero_returns_some() {
        let dur = overall_timeout_duration(30);
        assert_eq!(dur, Some(Duration::from_secs(30)));
    }

    #[test]
    fn deadline_from_timeout_secs_zero_returns_none() {
        assert!(deadline_from_timeout_secs(0).is_none());
    }

    #[test]
    fn deadline_from_timeout_secs_nonzero_returns_future_instant() {
        let deadline = deadline_from_timeout_secs(10);
        assert!(deadline.is_some());
        assert!(deadline.unwrap() > Instant::now());
    }

    #[test]
    fn remaining_timeout_secs_none_returns_none() {
        assert!(remaining_timeout_secs(None).is_none());
    }

    #[test]
    fn remaining_timeout_secs_past_deadline_returns_zero() {
        let past = Instant::now() - Duration::from_secs(5);
        assert_eq!(remaining_timeout_secs(Some(past)), Some(0));
    }

    #[test]
    fn remaining_timeout_secs_future_deadline_returns_positive() {
        let future = Instant::now() + Duration::from_secs(60);
        let remaining = remaining_timeout_secs(Some(future));
        assert!(remaining.is_some());
        // Should be at least 59 seconds, but at most 61 due to rounding
        let secs = remaining.unwrap();
        assert!((59..=61).contains(&secs));
    }

    #[test]
    fn remaining_timeout_secs_minimum_is_one() {
        // Even a very close future deadline should return at least 1
        let close_future = Instant::now() + Duration::from_millis(50);
        let remaining = remaining_timeout_secs(Some(close_future));
        assert!(remaining.is_some());
        assert!(remaining.unwrap() >= 1);
    }

    #[test]
    fn timeout_unknown_reason_formats_context() {
        let reason = timeout_unknown_reason("BMC safety");
        assert_eq!(reason, "BMC safety timed out before completion.");
    }

    #[test]
    fn options_with_remaining_timeout_no_deadline() {
        let options = PipelineOptions::default();
        let result = options_with_remaining_timeout(&options, None, "test");
        assert!(result.is_ok());
        let adjusted = result.unwrap();
        assert_eq!(adjusted.timeout_secs, options.timeout_secs);
    }

    #[test]
    fn options_with_remaining_timeout_expired_deadline() {
        let options = PipelineOptions::default();
        let past = Instant::now() - Duration::from_secs(5);
        let result = options_with_remaining_timeout(&options, Some(past), "test");
        assert!(result.is_err());
    }

    #[test]
    fn options_with_remaining_timeout_future_deadline() {
        let options = PipelineOptions::default();
        let future = Instant::now() + Duration::from_secs(42);
        let result = options_with_remaining_timeout(&options, Some(future), "test");
        assert!(result.is_ok());
        let adjusted = result.unwrap();
        // Should be approximately 42 seconds
        assert!(adjusted.timeout_secs >= 41 && adjusted.timeout_secs <= 43);
    }
}
