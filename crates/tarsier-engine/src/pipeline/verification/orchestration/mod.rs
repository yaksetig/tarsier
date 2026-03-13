//! Top-level verification entry points and CEGAR loop drivers.

mod fair_liveness;
mod liveness;
mod safety;
mod verification;

pub use fair_liveness::{
    check_fair_liveness, check_fair_liveness_with_mode, prove_fair_liveness,
    prove_fair_liveness_with_cegar, prove_fair_liveness_with_cegar_report,
    prove_fair_liveness_with_mode, prove_fair_liveness_with_round_abstraction,
};
pub use liveness::check_liveness;
pub use safety::{
    prove_safety, prove_safety_program_ast, prove_safety_with_cegar,
    prove_safety_with_cegar_report, prove_safety_with_round_abstraction,
};
pub use verification::{
    verify, verify_all_properties, verify_program_ast, verify_with_cegar, verify_with_cegar_report,
};

#[cfg(test)]
mod tests;
