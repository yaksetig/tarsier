/* Reliable Broadcast (Buggy) -- Disagreement expected.
 *
 * Promela model for a BUGGY broadcast protocol with weak thresholds.
 * Uses t+1 thresholds instead of 2t+1, allowing Byzantine faults
 * to cause disagreement -- some processes decide true, others false.
 *
 * Expected verdict: UNSAFE (assertion violation).
 */

#define N 4
#define T 1

byte echo_count = 0;
byte ready_count = 0;
byte decided_true = 0;
byte decided_false = 0;

/* Correct process: waits for echo threshold, sends ready, decides */
active [N - T] proctype Correct() {
    byte local_state = 0;

    /* Wait for echo threshold (buggy: only t+1 instead of 2t+1) */
    atomic {
        echo_count++;
    }

    do
    :: (local_state == 0 && echo_count >= T + 1) ->
        atomic {
            ready_count++;
            local_state = 1;
        }
    :: (local_state == 1 && ready_count >= T + 1) ->
        atomic {
            decided_true++;
            local_state = 2;
        }
        break;
    :: (local_state == 0) ->
        /* Timeout path: decide false without enough echoes */
        atomic {
            decided_false++;
            local_state = 2;
        }
        break;
    od;
}

/* Byzantine process: sends conflicting messages */
active [T] proctype Byzantine() {
    atomic {
        /* Inject spurious ready messages to push some toward true */
        ready_count++;
    }
}

/* Monitor: check agreement -- never both true and false decisions */
active proctype Monitor() {
    /* Wait until all processes have decided */
    (decided_true + decided_false >= N - T);
    assert(!(decided_true > 0 && decided_false > 0));
}
