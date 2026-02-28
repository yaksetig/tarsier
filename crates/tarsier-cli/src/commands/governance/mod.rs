//! Governance command module wiring and subcommand dispatch.
//
// Command handlers for: CertSuite, CertifySafety, CertifyFairLiveness, CheckCertificate,
//                        GenerateTrustReport, GovernancePipeline, VerifyGovernanceBundle
//
// These commands handle governance workflows including certification, trust reports, and pipelines.
// The entire module is gated behind #[cfg(feature = "governance")] in mod.rs.

mod bundle;
mod cert_suite;
mod cert_suite_runner;
mod commands;
mod trust_report;
mod types;
mod utils;

// Re-export all items as pub(crate) so callers see the same API as before.
pub(crate) use bundle::*;
pub(crate) use cert_suite::*;
pub(crate) use cert_suite_runner::*;
pub(crate) use commands::*;
pub(crate) use trust_report::*;
pub(crate) use types::*;
pub(crate) use utils::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const CERT_SUITE_SCHEMA_VERSION: u32 = 2;
pub(crate) const CERT_SUITE_SCHEMA_DOC_PATH: &str = "docs/CERT_SUITE_SCHEMA.md";
pub(crate) const CERT_SUITE_CANONICAL_MIN_FAMILIES: usize = 12;
pub(crate) const TRIAGE_MODEL_CHANGE: &str = "model_change";
pub(crate) const TRIAGE_ENGINE_REGRESSION: &str = "engine_regression";
pub(crate) const TRIAGE_EXPECTED_UPDATE: &str = "expected_update";
pub(crate) const CERT_SUITE_TRIAGE_CATEGORIES: [&str; 3] = [
    TRIAGE_MODEL_CHANGE,
    TRIAGE_ENGINE_REGRESSION,
    TRIAGE_EXPECTED_UPDATE,
];

pub(crate) const TRUST_REPORT_SCHEMA_VERSION: u32 = 1;
