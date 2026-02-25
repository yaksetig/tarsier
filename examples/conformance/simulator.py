#!/usr/bin/env python3
"""Reliable Broadcast simulator that emits Tarsier-format runtime traces.

Simulates the Bracha-style reliable broadcast protocol matching
examples/library/reliable_broadcast_safe.trs and produces JSON traces
suitable for conformance checking with `tarsier conformance-check`.

Usage:
    python3 examples/conformance/simulator.py --n 4 --t 1 --byzantine 0 --out trace.json
    python3 examples/conformance/simulator.py --n 4 --t 1 --byzantine 1 --seed 42 --out trace.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field
from typing import Any


# Location name format must match lowered Tarsier model exactly.
# Format: {Role}_{phase}[{var1}={val1},{var2}={val2},...]
def loc_name(phase: str, accepted: bool, decided: bool, decision: bool) -> str:
    return (
        f"Process_{phase}[accepted={str(accepted).lower()},"
        f"decided={str(decided).lower()},decision={str(decision).lower()}]"
    )


@dataclass
class Process:
    pid: int
    byzantine: bool = False
    phase: str = "waiting"
    accepted: bool = False
    decided: bool = False
    decision: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)
    seq: int = 0

    def location(self) -> str:
        return loc_name(self.phase, self.accepted, self.decided, self.decision)

    def add_event(self, kind: dict[str, Any]) -> None:
        self.events.append({"sequence": self.seq, "kind": kind})
        self.seq += 1


def simulate(
    n: int,
    t: int,
    byzantine: int,
    seed: int | None,
) -> dict[str, Any]:
    if seed is not None:
        random.seed(seed)

    # Create processes; last `byzantine` are Byzantine
    processes = [Process(pid=i, byzantine=(i >= n - byzantine)) for i in range(n)]

    # Shared counters (mirroring the threshold automaton)
    cnt_init = 0
    cnt_echo = 0
    cnt_ready = 0

    # Initialize all processes
    for p in processes:
        p.add_event({"type": "Init", "location": p.location()})

    # --- Round 1: Sender broadcasts Init ---
    # Process 0 is the designated sender (could be adversary-injected)
    cnt_init = 1  # Sender's Init is delivered

    # Each honest process in waiting that sees Init → move to echoed, send Echo
    for p in processes:
        if p.byzantine:
            continue
        if p.phase == "waiting" and cnt_init >= 1:
            old_loc = p.location()
            p.accepted = True
            p.phase = "echoed"
            new_loc = p.location()
            # Receive Init
            p.add_event({
                "type": "Receive",
                "message_type": "cnt_Init@Process",
                "from_process": 0,
                "fields": [],
            })
            # Transition
            p.add_event({
                "type": "Transition",
                "from_location": old_loc,
                "to_location": new_loc,
                "rule_id": None,
            })
            # Send Echo
            p.add_event({
                "type": "Send",
                "message_type": "cnt_Echo@Process",
                "fields": [],
            })
            cnt_echo += 1

    # Byzantine processes may or may not echo
    for p in processes:
        if p.byzantine:
            # Byzantine process sends an Echo too (equivocation)
            cnt_echo += 1

    # --- Round 2: Collect Echoes ---
    threshold_echo = 2 * t + 1
    if cnt_echo >= threshold_echo:
        for p in processes:
            if p.byzantine:
                continue
            if p.phase == "echoed":
                old_loc = p.location()
                p.phase = "readied"
                new_loc = p.location()
                # Receive enough Echoes
                for sender_id in range(min(threshold_echo, n)):
                    p.add_event({
                        "type": "Receive",
                        "message_type": "cnt_Echo@Process",
                        "from_process": sender_id,
                        "fields": [],
                    })
                # Transition
                p.add_event({
                    "type": "Transition",
                    "from_location": old_loc,
                    "to_location": new_loc,
                    "rule_id": None,
                })
                # Send Ready
                p.add_event({
                    "type": "Send",
                    "message_type": "cnt_Ready@Process",
                    "fields": [],
                })
                cnt_ready += 1

    # Byzantine processes may send Ready
    for p in processes:
        if p.byzantine:
            cnt_ready += 1

    # --- Round 3: Collect Readies ---
    threshold_ready = 2 * t + 1
    if cnt_ready >= threshold_ready:
        for p in processes:
            if p.byzantine:
                continue
            if p.phase == "readied":
                old_loc = p.location()
                p.decision = True
                p.decided = True
                p.phase = "done"
                new_loc = p.location()
                # Receive enough Readies
                for sender_id in range(min(threshold_ready, n)):
                    p.add_event({
                        "type": "Receive",
                        "message_type": "cnt_Ready@Process",
                        "from_process": sender_id,
                        "fields": [],
                    })
                # Transition
                p.add_event({
                    "type": "Transition",
                    "from_location": old_loc,
                    "to_location": new_loc,
                    "rule_id": None,
                })
                # Decide
                p.add_event({"type": "Decide", "value": "true"})

    # Build trace JSON
    trace = {
        "schema_version": 1,
        "protocol_name": "ReliableBroadcastSafe",
        "params": [["n", n], ["t", t], ["f", byzantine]],
        "processes": [],
    }

    for p in processes:
        if not p.byzantine:
            trace["processes"].append({
                "process_id": p.pid,
                "role": "Process",
                "events": p.events,
            })

    return trace


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simulate Reliable Broadcast and emit a Tarsier runtime trace."
    )
    parser.add_argument("--n", type=int, default=4, help="Total processes (default: 4)")
    parser.add_argument("--t", type=int, default=1, help="Fault tolerance parameter (default: 1)")
    parser.add_argument("--byzantine", type=int, default=0, help="Number of Byzantine processes (default: 0)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed (default: None)")
    parser.add_argument("--out", type=str, default=None, help="Output file (default: stdout)")
    args = parser.parse_args()

    if args.n <= 3 * args.t:
        print(f"Error: resilience requires n > 3*t, but n={args.n}, t={args.t}", file=sys.stderr)
        return 1

    if args.byzantine > args.t:
        print(f"Warning: byzantine={args.byzantine} > t={args.t}, protocol may not terminate", file=sys.stderr)

    trace = simulate(args.n, args.t, args.byzantine, args.seed)

    output = json.dumps(trace, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
            f.write("\n")
        print(f"Trace written to {args.out}", file=sys.stderr)
    else:
        print(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
