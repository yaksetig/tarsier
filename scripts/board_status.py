#!/usr/bin/env python3
"""Summarize multi-agent board status from append-only event logs.

Reads MULTI_AGENT_EXECUTION_BOARD.md (or a custom path) and computes:
- Current task status from latest lifecycle event
- Ready/unready TODO tasks based on dependencies
- Pending review queue (DONE without REVIEW/VERIFY pass)
- Done backlog with review state
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List


TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TASK_ID_RE = re.compile(r"^[A-Z]+-\d+$")
TASK_ROW_RE = re.compile(
    r"^\|\s*(?P<task_id>[A-Z]+-\d+)\s*\|"
    r"\s*(?P<initiative>.*?)\s*\|"
    r"\s*(?P<deliverable>.*?)\s*\|"
    r"\s*(?P<sprint>\d+)\s*\|"
    r"\s*(?P<priority>P[0-2])\s*\|"
    r"\s*(?P<difficulty>[^|]+?)\s*\|"
    r"\s*(?P<impact>[^|]+?)\s*\|"
    r"\s*(?P<parallel>[^|]+?)\s*\|"
    r"\s*(?P<depends>[^|]+?)\s*\|?\s*$"
)


@dataclass(frozen=True)
class Task:
    task_id: str
    initiative: str
    deliverable: str
    sprint: int
    priority: str
    difficulty: str
    impact: str
    parallel: str
    depends_on: List[str]


@dataclass(frozen=True)
class Event:
    index: int
    timestamp: str
    agent_id: str
    task_id: str
    event_type: str
    note: str


@dataclass
class TaskState:
    status: str = "TODO"
    owner: str = "-"
    last_event_type: str = "-"
    last_event_ts: str = "-"
    last_event_note: str = "-"
    last_done_ts: str = "-"
    last_done_by: str = "-"
    last_done_note: str = "-"
    last_done_index: int = -1
    last_review_pass_index: int = -1
    last_review_fail_index: int = -1


STATUS_ORDER = {
    "BLOCKED": 0,
    "REVIEW_CHANGES": 1,
    "UNDER_REVIEW": 2,
    "IN_REVIEW": 3,
    "IN_PROGRESS": 4,
    "CLAIMED": 5,
    "DONE": 6,
    "VERIFIED": 7,
    "TODO": 8,
}


def _parse_task_registry(lines: List[str]) -> Dict[str, Task]:
    tasks: Dict[str, Task] = {}
    in_registry = False
    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith("## Task Registry"):
            in_registry = True
            continue
        if in_registry and line.startswith("## "):
            break
        if not in_registry:
            continue
        if not line.startswith("|"):
            continue
        if "Task ID" in line or "---" in line:
            continue
        m = TASK_ROW_RE.match(line)
        if m is None:
            continue
        task_id = m.group("task_id")
        sprint_text = m.group("sprint")
        depends_text = m.group("depends").strip()
        if depends_text == "-" or not depends_text:
            depends = []
        else:
            depends = [d.strip() for d in depends_text.split(",") if d.strip()]
        tasks[task_id] = Task(
            task_id=task_id,
            initiative=m.group("initiative").strip(),
            deliverable=m.group("deliverable").strip(),
            sprint=int(sprint_text),
            priority=m.group("priority").strip(),
            difficulty=m.group("difficulty").strip(),
            impact=m.group("impact").strip(),
            parallel=m.group("parallel").strip(),
            depends_on=depends,
        )
    return tasks


def _parse_event_line(line: str, index: int) -> Event | None:
    cleaned = line.strip()
    if not cleaned:
        return None
    if cleaned.startswith("|"):
        return None
    if cleaned.startswith("`") and cleaned.endswith("`"):
        cleaned = cleaned[1:-1].strip()
    parts = [p.strip() for p in cleaned.split("|", 4)]
    if len(parts) != 5:
        return None
    ts, agent, task_id, event_type, note = parts
    if not TIMESTAMP_RE.match(ts):
        return None
    if task_id != "INIT" and not TASK_ID_RE.match(task_id):
        return None
    if not event_type:
        return None
    return Event(
        index=index,
        timestamp=ts,
        agent_id=agent,
        task_id=task_id,
        event_type=event_type,
        note=note,
    )


def _parse_events(lines: List[str]) -> List[Event]:
    events: List[Event] = []
    for idx, line in enumerate(lines):
        ev = _parse_event_line(line, idx)
        if ev is not None:
            events.append(ev)
    return events


def _apply_event(state: TaskState, ev: Event) -> None:
    et = ev.event_type.upper()
    state.last_event_type = et
    state.last_event_ts = ev.timestamp
    state.last_event_note = ev.note

    if et == "CLAIM":
        state.status = "CLAIMED"
        state.owner = ev.agent_id
    elif et == "START":
        state.status = "IN_PROGRESS"
        state.owner = ev.agent_id
    elif et == "BLOCKED":
        state.status = "BLOCKED"
        state.owner = ev.agent_id
    elif et == "UNBLOCKED":
        state.status = "IN_PROGRESS"
        state.owner = ev.agent_id
    elif et == "PR_OPEN":
        state.status = "IN_REVIEW"
        state.owner = ev.agent_id
    elif et == "REVIEW_START":
        state.status = "UNDER_REVIEW"
        state.owner = ev.agent_id
    elif et == "DONE":
        state.status = "DONE"
        state.owner = ev.agent_id
        state.last_done_ts = ev.timestamp
        state.last_done_by = ev.agent_id
        state.last_done_note = ev.note
        state.last_done_index = ev.index
    elif et in {"VERIFY_PASS", "REVIEW_PASS"}:
        state.status = "VERIFIED"
        state.owner = ev.agent_id
        state.last_review_pass_index = ev.index
    elif et in {"VERIFY_FAIL", "REVIEW_FAIL"}:
        state.status = "REVIEW_CHANGES"
        state.owner = ev.agent_id
        state.last_review_fail_index = ev.index
    elif et == "RELEASE":
        state.status = "TODO"
        state.owner = "-"
    elif et == "CHANGE":
        # Metadata/event log change; does not alter lifecycle state.
        pass


def _build_state(tasks: Dict[str, Task], events: List[Event]) -> Dict[str, TaskState]:
    states: Dict[str, TaskState] = {tid: TaskState() for tid in tasks}
    for ev in events:
        if ev.task_id not in tasks:
            continue
        _apply_event(states[ev.task_id], ev)
    return states


def _is_done_or_verified(status: str) -> bool:
    return status in {"DONE", "VERIFIED"}


def _dependency_ready(task: Task, states: Dict[str, TaskState]) -> bool:
    for dep in task.depends_on:
        dep_state = states.get(dep)
        if dep_state is None:
            return False
        if not _is_done_or_verified(dep_state.status):
            return False
    return True


def _needs_review(state: TaskState) -> bool:
    if state.last_done_index < 0:
        return False
    if state.status not in {"DONE", "IN_REVIEW", "UNDER_REVIEW", "REVIEW_CHANGES"}:
        return False
    return state.last_review_pass_index < state.last_done_index


def _review_state_label(state: TaskState) -> str:
    if state.last_done_index < 0:
        return "NOT_DONE"
    if state.last_review_pass_index > state.last_done_index:
        return "REVIEW_PASS"
    if state.last_review_fail_index > state.last_done_index:
        return "REVIEW_FAIL"
    return "PENDING_REVIEW"


def _sorted_task_ids(tasks: Dict[str, Task]) -> List[str]:
    return sorted(tasks.keys(), key=lambda tid: (tasks[tid].sprint, tid))


def _summary_payload(
    board_path: Path,
    tasks: Dict[str, Task],
    states: Dict[str, TaskState],
) -> dict:
    status_counts: Dict[str, int] = {}
    for st in states.values():
        status_counts[st.status] = status_counts.get(st.status, 0) + 1

    rows = []
    review_queue = []
    done_backlog = []
    for tid in _sorted_task_ids(tasks):
        task = tasks[tid]
        st = states[tid]
        ready = st.status == "TODO" and _dependency_ready(task, states)
        blocked_by = []
        for dep in task.depends_on:
            dep_state = states.get(dep)
            if dep_state is None or not _is_done_or_verified(dep_state.status):
                blocked_by.append(dep)
        row = {
            "task_id": tid,
            "sprint": task.sprint,
            "priority": task.priority,
            "status": st.status,
            "owner": st.owner,
            "ready": ready,
            "blocked_by": blocked_by,
            "depends_on": task.depends_on,
            "initiative": task.initiative,
            "deliverable": task.deliverable,
            "last_event_type": st.last_event_type,
            "last_event_ts": st.last_event_ts,
            "last_event_note": st.last_event_note,
        }
        rows.append(row)
        if _needs_review(st):
            review_queue.append(
                {
                    "task_id": tid,
                    "sprint": task.sprint,
                    "done_ts": st.last_done_ts,
                    "done_by": st.last_done_by,
                    "done_note": st.last_done_note,
                    "status": st.status,
                }
            )
        if st.last_done_index >= 0:
            done_backlog.append(
                {
                    "task_id": tid,
                    "sprint": task.sprint,
                    "done_ts": st.last_done_ts,
                    "done_by": st.last_done_by,
                    "done_note": st.last_done_note,
                    "review_state": _review_state_label(st),
                    "current_status": st.status,
                }
            )

    return {
        "board_path": str(board_path),
        "total_tasks": len(tasks),
        "status_counts": status_counts,
        "tasks": rows,
        "review_queue": review_queue,
        "done_backlog": done_backlog,
    }


def _print_summary(payload: dict) -> None:
    status_counts = payload["status_counts"]
    total = payload["total_tasks"]
    blocked = status_counts.get("BLOCKED", 0)
    in_progress = status_counts.get("IN_PROGRESS", 0)
    done = status_counts.get("DONE", 0)
    verified = status_counts.get("VERIFIED", 0)
    todo = status_counts.get("TODO", 0)
    print(f"Board: {payload['board_path']}")
    print(
        f"Tasks: {total} | TODO: {todo} | IN_PROGRESS: {in_progress} | "
        f"BLOCKED: {blocked} | DONE: {done} | VERIFIED: {verified}"
    )
    print()
    print("Task Status")
    print("-----------")
    rows = sorted(
        payload["tasks"],
        key=lambda r: (
            r["sprint"],
            STATUS_ORDER.get(r["status"], 99),
            r["task_id"],
        ),
    )
    for row in rows:
        ready = "ready" if row["ready"] else "-"
        blocked_by = ",".join(row["blocked_by"]) if row["blocked_by"] else "-"
        print(
            f"{row['task_id']:8} sprint={row['sprint']} {row['status']:14} "
            f"owner={row['owner']:12} ready={ready:5} blocked_by={blocked_by}"
        )


def _print_review_queue(payload: dict) -> None:
    queue = sorted(payload["review_queue"], key=lambda r: (r["sprint"], r["task_id"]))
    if not queue:
        print("Review queue is empty.")
        return
    print("Pending Independent Review")
    print("--------------------------")
    for row in queue:
        print(
            f"{row['task_id']:8} sprint={row['sprint']} status={row['status']:14} "
            f"done_by={row['done_by']:12} done_ts={row['done_ts']} note={row['done_note']}"
        )


def _print_done_backlog(payload: dict) -> None:
    rows = sorted(payload["done_backlog"], key=lambda r: (r["sprint"], r["task_id"]))
    if not rows:
        print("No completed tasks recorded yet.")
        return
    print("Done Backlog")
    print("------------")
    for row in rows:
        print(
            f"{row['task_id']:8} sprint={row['sprint']} review={row['review_state']:14} "
            f"done_by={row['done_by']:12} done_ts={row['done_ts']} note={row['done_note']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize multi-agent task board status.")
    parser.add_argument(
        "--board",
        default="MULTI_AGENT_EXECUTION_BOARD.md",
        help="Path to board markdown file (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON payload.")
    parser.add_argument(
        "--review-queue",
        action="store_true",
        help="Show tasks pending independent review.",
    )
    parser.add_argument(
        "--done-backlog",
        action="store_true",
        help="Show completed-task backlog with review state.",
    )
    args = parser.parse_args()

    board_path = Path(args.board)
    if not board_path.exists():
        print(f"error: board file not found: {board_path}", file=sys.stderr)
        return 2

    lines = board_path.read_text(encoding="utf-8").splitlines()
    tasks = _parse_task_registry(lines)
    if not tasks:
        print("error: no tasks parsed from Task Registry", file=sys.stderr)
        return 3
    events = _parse_events(lines)
    states = _build_state(tasks, events)
    payload = _summary_payload(board_path, tasks, states)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.review_queue:
        _print_review_queue(payload)
        return 0
    if args.done_backlog:
        _print_done_backlog(payload)
        return 0

    _print_summary(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
