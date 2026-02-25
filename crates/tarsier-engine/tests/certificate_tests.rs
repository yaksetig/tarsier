mod common;

use tarsier_engine::pipeline::{
    FairnessMode, PipelineOptions, ProofEngine, SolverChoice, SoundnessMode,
};
use tarsier_engine::result::{UnboundedFairLivenessResult, UnboundedSafetyResult};

#[test]
fn generate_kinduction_certificate_for_safe_protocol() {
    let source = r#"
protocol CertSafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let cert = tarsier_engine::pipeline::generate_kinduction_safety_certificate(
        source,
        "cert_safe.trs",
        &options,
    )
    .expect("certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::KInduction);
    assert!(cert.induction_k.expect("k present") <= 4);
    assert_eq!(cert.obligations.len(), 2);
    assert!(cert.obligations[0].smt2.contains("(check-sat)"));
    assert!(cert.obligations[1].smt2.contains("(check-sat)"));
}

#[test]
fn generate_kinduction_certificate_rejects_unsafe_protocol() {
    let source = r#"
protocol CertUnsafe {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::KInduction,
    };
    let err = tarsier_engine::pipeline::generate_kinduction_safety_certificate(
        source,
        "cert_unsafe.trs",
        &options,
    )
    .expect_err("unsafe protocol should not produce certificate");
    assert!(format!("{err}").contains("Cannot certify safety"));
}

#[test]
fn generate_pdr_certificate_for_safe_protocol() {
    let source = r#"
protocol CertSafePdr {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
    property invariant: safety {
        forall p: R. p.decided == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let cert = tarsier_engine::pipeline::generate_pdr_safety_certificate(
        source,
        "cert_safe_pdr.trs",
        &options,
    )
    .expect("pdr certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::Pdr);
    assert!(cert.induction_k.expect("frame present") <= 4);
    assert_eq!(cert.obligations.len(), 3);
    for obligation in cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(obligation.smt2.contains("(check-sat)"));
    }

    let cert2 = tarsier_engine::pipeline::generate_safety_certificate(
        source,
        "cert_safe_pdr.trs",
        &options,
    )
    .expect("generic certificate generation should succeed");
    assert_eq!(cert2.proof_engine, ProofEngine::Pdr);
    assert_eq!(cert2.obligations.len(), 3);
}

#[test]
fn generate_fair_liveness_certificate_for_live_protocol() {
    let source = r#"
protocol CertFairLive {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = true;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let cert = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        source,
        "cert_fair_live.trs",
        &options,
        FairnessMode::Strong,
    )
    .expect("fair-liveness certificate generation should succeed");
    assert_eq!(cert.proof_engine, ProofEngine::Pdr);
    assert_eq!(cert.fairness, FairnessMode::Strong);
    assert!(cert.frame <= 4);
    assert_eq!(cert.obligations.len(), 3);
    for obligation in cert.obligations {
        assert_eq!(obligation.expected, "unsat");
        assert!(obligation.smt2.contains("(check-sat)"));
    }
}

#[test]
fn generate_fair_liveness_certificate_rejects_non_live_protocol() {
    let source = r#"
protocol CertFairNotLive {
    params n, t, f;
    resilience: n > 3*t;
    adversary { model: byzantine; bound: f; }
    role R {
        var decided: bool = false;
        init s;
        phase s {}
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 4,
        timeout_secs: 30,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let err = tarsier_engine::pipeline::generate_fair_liveness_certificate_with_mode(
        source,
        "cert_fair_not_live.trs",
        &options,
        FairnessMode::Weak,
    )
    .expect_err("non-live protocol should not produce fair-liveness certificate");
    assert!(format!("{err}").contains("Cannot certify fair-liveness"));
}

#[test]
fn prove_round_abstraction_safe_on_simple_protocol() {
    let source = r#"
protocol RoundSafe {
    params n, t, f;
    resilience: n = 1;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Tick(view: int in 0..3);
    role R {
        var view: int in 0..3 = 0;
        var ok: bool = true;
        init s;
        phase s {
            when received >= 0 Tick(view=view) => {
                send Tick(view=view);
            }
        }
    }
    property safe: safety {
        forall p: R. p.ok == true
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let round_vars = vec!["view".to_string()];
    let result = tarsier_engine::pipeline::prove_safety_with_round_abstraction(
        source,
        "round_safe.trs",
        &options,
        &round_vars,
    )
    .expect("round abstraction proof should run");

    assert!(
        result.summary.abstract_locations <= result.summary.original_locations,
        "abstraction should not increase location count"
    );
    assert!(
        result.summary.abstract_message_counters <= result.summary.original_message_counters,
        "abstraction should not increase message counter count"
    );
    match result.result {
        UnboundedSafetyResult::Safe { .. }
        | UnboundedSafetyResult::ProbabilisticallySafe { .. } => {}
        other => panic!("Expected SAFE result under round abstraction, got: {other:?}"),
    }
}

#[test]
fn prove_fair_round_abstraction_live_on_simple_protocol() {
    let source = r#"
protocol RoundLive {
    params n, t, f;
    resilience: n = 1;
    adversary { model: byzantine; bound: f; auth: signed; }
    message Tick(view: int in 0..3);
    role R {
        var view: int in 0..3 = 0;
        var decided: bool = true;
        init s;
        phase s {
            when received >= 0 Tick(view=view) => {
                send Tick(view=view);
            }
        }
    }
}
"#;
    let options = PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: 6,
        timeout_secs: 60,
        dump_smt: None,
        soundness: SoundnessMode::Strict,
        proof_engine: ProofEngine::Pdr,
    };
    let round_vars = vec!["view".to_string()];
    let result = tarsier_engine::pipeline::prove_fair_liveness_with_round_abstraction(
        source,
        "round_live.trs",
        &options,
        FairnessMode::Strong,
        &round_vars,
    )
    .expect("round abstraction fair-liveness proof should run");

    assert!(
        result.summary.abstract_locations <= result.summary.original_locations,
        "abstraction should not increase location count"
    );
    match result.result {
        UnboundedFairLivenessResult::LiveProved { .. } => {}
        other => panic!("Expected LIVE_PROVED under round abstraction, got: {other:?}"),
    }
}

