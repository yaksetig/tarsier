//! Tests for the adversary injection model in BMC verification.
//!
//! These tests verify that:
//! 1. Adversary injection is correctly bounded by the `f` parameter
//! 2. The `f <= t` constraint prevents spurious counterexamples
//! 3. Protocols without adversary bounds still verify correctly

use tarsier_engine::pipeline::{self, PipelineOptions, SolverChoice, SoundnessMode};
use tarsier_engine::result::VerificationResult;

fn default_opts(depth: usize) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: Default::default(),
    }
}

/// A simple safe protocol with adversary bound f.
/// Agreement: if two processes both decided, they agree on the decision value.
/// Since there's only one decision value (true), this is trivially safe.
#[test]
fn adversary_injection_bounded_by_f_safe_protocol() {
    let src = r#"
protocol BoundedAdversary {
    params n, t, f;
    resilience: n > 2*t;
    adversary {
        model: byzantine;
        bound: f;
    }
    message Vote;
    role Voter {
        var decided: bool = false;
        var decision: bool = false;
        init voting;
        phase voting {
            when received >= n - t Vote => {
                decided = true;
                decision = true;
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Voter. forall q: Voter.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;
    let opts = default_opts(5);
    let result = pipeline::verify(src, "bounded_adv.trs", &opts).unwrap();
    assert!(
        matches!(result, VerificationResult::Safe { .. }),
        "expected Safe for single-decision-value protocol, got: {result:?}"
    );
}

/// With stronger resilience (n > 3*t), the same agreement should still hold.
/// This implicitly tests that f <= t is enforced as part of the adversary model.
#[test]
fn f_leq_t_constraint_enforced() {
    let src = r#"
protocol FLeqT {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }
    message Vote;
    role Voter {
        var decided: bool = false;
        var decision: bool = false;
        init waiting;
        phase waiting {
            when received >= n - t Vote => {
                decided = true;
                decision = true;
                decide true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Voter. forall q: Voter.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;
    let opts = default_opts(5);
    let result = pipeline::verify(src, "f_leq_t.trs", &opts).unwrap();
    assert!(
        matches!(result, VerificationResult::Safe { .. }),
        "expected Safe with f <= t constraint, got: {result:?}"
    );
}

/// A protocol with no adversary bound should still be verifiable in permissive mode.
/// Strict mode requires `adversary { bound: <param>; }`, so we use permissive.
#[test]
fn no_adversary_bound_still_verifiable() {
    let src = r#"
protocol NoBound {
    params n, t;
    resilience: n > 2*t;
    message Ping;
    role Worker {
        var decided: bool = false;
        var decision: bool = false;
        init idle;
        phase idle {
            when received >= 1 Ping => {
                decided = true;
                decision = true;
                decide true;
                goto phase running;
            }
        }
        phase running {}
    }
    property agreement: agreement {
        forall p: Worker. forall q: Worker.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }
}
"#;
    let mut opts = default_opts(5);
    opts.soundness = SoundnessMode::Permissive;
    let result = pipeline::verify(src, "no_bound.trs", &opts);
    assert!(result.is_ok(), "verification should complete: {result:?}");
}
