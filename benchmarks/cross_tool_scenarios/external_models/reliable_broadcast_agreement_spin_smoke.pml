/* Real SPIN smoke model for cross-tool CI execution.
 *
 * This is intentionally small and deterministic: it validates that the
 * runner invokes a real SPIN binary end-to-end and that verdict normalization
 * observes a clean `errors: 0` run.
 */

bool decided = false;
byte decision = 0;

init {
    atomic {
        decided = true;
        decision = 1;
        assert(!decided || (decision == 1))
    }
}
