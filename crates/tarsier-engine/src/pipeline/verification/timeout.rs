//! Deadline/timeout utilities for verification pipelines.

use std::time::{Duration, Instant};

use crate::pipeline::*;

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
mod tests;
