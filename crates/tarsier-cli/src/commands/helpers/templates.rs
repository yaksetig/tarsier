/// V2-05: Return a vetted property template for the given kind.
pub(crate) fn property_template(kind: &str) -> Option<&'static str> {
    match kind {
        "agreement" => Some(
            r#"// Agreement: no two correct processes decide differently.
// Requires two universal quantifiers over the same role.
property agreement: agreement {
    forall p: Replica. forall q: Replica.
        (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
}
"#,
        ),
        "validity" => Some(
            r#"// Validity: if all correct processes propose the same value, they decide that value.
// Uses a single universal quantifier.
property validity: validity {
    forall p: Replica. (p.decided == true) ==> (p.decision == p.proposal)
}
"#,
        ),
        "termination" => Some(
            r#"// Termination: every correct process eventually decides.
// Liveness property with eventually operator.
property termination: liveness {
    forall p: Replica. <> (p.decided == true)
}
"#,
        ),
        "liveness" => Some(
            r#"// Liveness: the system always eventually makes progress.
// Uses always-eventually ([] <>) temporal pattern.
property progress: liveness {
    forall p: Replica. [] <> (p.decided == true)
}
"#,
        ),
        "integrity" => Some(
            r#"// Integrity: a correct process decides at most once.
// Safety invariant on the decision flag.
property integrity: safety {
    forall p: Replica. (p.decided == true) ==> (p.decision_count <= 1)
}
"#,
        ),
        _ => None,
    }
}

pub(crate) fn assistant_template(kind: &str) -> Option<&'static str> {
    match kind {
        "pbft" => Some(
            r#"protocol PBFTTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message PrePrepare;
    message Prepare;
    message Commit;

    role Replica {
        var decided: bool = false;
        var decision: bool = false;
        init start;

        // Phase 1: Await pre-prepare from leader, then broadcast prepare.
        phase start {
            when received >= 1 PrePrepare => {
                send Prepare;
                goto phase prepared;
            }
        }

        // Phase 2: Collect 2t+1 prepares, then broadcast commit.
        phase prepared {
            when received >= 2*t+1 Prepare => {
                send Commit;
                goto phase committed;
            }
        }

        // Phase 3: Collect 2t+1 commits and decide.
        phase committed {
            when received >= 2*t+1 Commit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Replica. p.decided == true
    }
}
"#,
        ),
        "hotstuff" => Some(
            r#"protocol HotStuffTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Vote;

    role Node {
        var decided: bool = false;
        var decision: bool = false;
        init propose;

        // Phase 1: Leader broadcasts proposal; nodes receive and vote.
        phase propose {
            when received >= 1 Proposal => {
                send Vote;
                goto phase voted;
            }
        }

        // Phase 2: Collect 2t+1 votes to form a quorum certificate and decide.
        phase voted {
            when received >= 2*t+1 Vote => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Node. p.decided == true
    }
}
"#,
        ),
        "raft" => Some(
            r#"protocol RaftTemplate {
    params n, t, f;
    resilience: n > 2*t;
    adversary {
        model: crash;
        bound: f;
    }

    message RequestVote;
    message VoteGranted;
    message AppendEntries;

    role Server {
        var decided: bool = false;
        var decision: bool = false;
        init follower;

        // Follower receives RequestVote from candidate, grants vote.
        phase follower {
            when received >= 1 RequestVote => {
                send VoteGranted;
                goto phase voting;
            }
        }

        // Candidate collects majority votes, becomes leader.
        phase voting {
            when received >= t+1 VoteGranted => {
                send AppendEntries;
                goto phase replicating;
            }
        }

        // Leader replicates entry; majority acknowledgment = commit.
        phase replicating {
            when received >= t+1 AppendEntries => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Server. forall q: Server.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Server. p.decided == true
    }
}
"#,
        ),
        "tendermint" => Some(
            r#"protocol TendermintTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Prevote;
    message Precommit;

    role Validator {
        var decided: bool = false;
        var decision: bool = false;
        init propose;

        // Phase 1: Proposer broadcasts; validators receive and prevote.
        phase propose {
            when received >= 1 Proposal => {
                send Prevote;
                goto phase prevote;
            }
        }

        // Phase 2: Collect 2t+1 prevotes (polka), then precommit.
        phase prevote {
            when received >= 2*t+1 Prevote => {
                send Precommit;
                goto phase precommit;
            }
        }

        // Phase 3: Collect 2t+1 precommits and decide.
        phase precommit {
            when received >= 2*t+1 Precommit => {
                decision = true;
                decided = true;
                decide true;
                goto phase done;
            }
        }

        phase done {}
    }

    property agreement: agreement {
        forall p: Validator. forall q: Validator.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Validator. p.decided == true
    }
}
"#,
        ),
        "streamlet" => Some(
            r#"protocol StreamletTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Proposal;
    message Vote;
    message Notarize;

    role Node {
        var decided: bool = false;
        var decision: bool = false;
        init wait;

        // Phase 1: Leader proposes a block; nodes receive and vote.
        phase wait {
            when received >= 1 Proposal => {
                send Vote;
                goto phase voted;
            }
        }

        // Phase 2: Collect 2t+1 votes to notarize the block.
        phase voted {
            when received >= 2*t+1 Vote => {
                send Notarize;
                goto phase notarized;
            }
        }

        // Phase 3: Observe notarization; finalize.
        phase notarized {
            when received >= 2*t+1 Notarize => {
                decision = true;
                decided = true;
                decide true;
                goto phase finalized;
            }
        }

        phase finalized {}
    }

    property agreement: agreement {
        forall p: Node. forall q: Node.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Node. p.decided == true
    }
}
"#,
        ),
        "casper" => Some(
            r#"protocol CasperFFGTemplate {
    params n, t, f;
    resilience: n > 3*t;
    adversary {
        model: byzantine;
        bound: f;
    }

    message Vote;
    message Justify;
    message Finalize;

    role Validator {
        var decided: bool = false;
        var decision: bool = false;
        init attest;

        // Phase 1: Validators cast attestation votes for a checkpoint.
        phase attest {
            when received >= 1 Vote => {
                send Justify;
                goto phase justified;
            }
        }

        // Phase 2: Collect 2t+1 justifications (supermajority link).
        phase justified {
            when received >= 2*t+1 Justify => {
                send Finalize;
                goto phase finalizing;
            }
        }

        // Phase 3: Collect 2t+1 finalize attestations; checkpoint is finalized.
        phase finalizing {
            when received >= 2*t+1 Finalize => {
                decision = true;
                decided = true;
                decide true;
                goto phase finalized;
            }
        }

        phase finalized {}
    }

    property agreement: agreement {
        forall p: Validator. forall q: Validator.
            (p.decided == true && q.decided == true) ==> (p.decision == q.decision)
    }

    property termination: liveness {
        forall p: Validator. p.decided == true
    }
}
"#,
        ),
        _ => None,
    }
}
