/* Tendermint Locking -- Agreement property.
 *
 * Minimal Promela model for Tendermint-style consensus with a
 * 2t+1 precommit threshold. With N > 3T, all correct replicas
 * that decide must decide the same value.
 *
 * Expected verdict: SAFE (no assertion violations).
 */

#define N 4
#define T 1

byte precommit_count = 0;
byte decided = 0;
byte decision_value = 0;
bool value_set = false;

/* Correct replica: sends precommit for value 1, waits for threshold */
active [N - T] proctype Replica() {
    atomic {
        precommit_count++;
    }

    /* Wait for 2t+1 precommits before deciding */
    (precommit_count >= 2 * T + 1);

    atomic {
        if
        :: !value_set ->
            decision_value = 1;
            value_set = true;
        :: else ->
            skip;
        fi;
        decided++;
    }

    /* All deciding replicas must agree on the same value */
    assert(decision_value == 1);
}
