# Agent Execution Instructions

This guide defines how agents should execute work from [MULTI_AGENT_EXECUTION_BOARD.md](/Users/myaksetig/Desktop/Repos/tarsier/MULTI_AGENT_EXECUTION_BOARD.md) without stepping on each other.

## 1) Daily Start
Run:
```bash
just board-status
just board-review-queue
```
Fallback if `just` is unavailable:
```bash
python3 scripts/board_status.py
python3 scripts/board_status.py --review-queue
```

Pick tasks that are:
- `ready=true` (all dependencies satisfied)
- unclaimed/not in progress
- aligned to your assigned stream

## 2) Claiming Work (append-only)
Add a claim line in `Agent Claims`:
```text
YYYY-MM-DDTHH:MM:SSZ | AGENT_ID | TASK_ID | CLAIM | taking task
```
Then add `START` in `Progress Events`:
```text
YYYY-MM-DDTHH:MM:SSZ | AGENT_ID | TASK_ID | START | implementation started
```

Use UTC timestamp from:
```bash
date -u +\"%Y-%m-%dT%H:%M:%SZ\"
```

## 3) Required Progress Events
- Blocked:
```text
... | AGENT_ID | TASK_ID | BLOCKED | reason + blocking task/issue
```
- Unblocked:
```text
... | AGENT_ID | TASK_ID | UNBLOCKED | reason
```
- PR open:
```text
... | AGENT_ID | TASK_ID | PR_OPEN | <branch> <PR/link> <short summary>
```
- Done:
```text
... | AGENT_ID | TASK_ID | DONE | <commit/PR> tests=<command list>
```

## 4) Independent Verification (mandatory)
All completed tasks need a different-agent check.

Find pending checks:
```bash
just board-review-queue
```
Fallback:
```bash
python3 scripts/board_status.py --review-queue
```

Reviewer logs:
```text
... | REVIEWER_ID | TASK_ID | REVIEW_START | reviewing <commit/PR>
... | REVIEWER_ID | TASK_ID | REVIEW_PASS | validated; tests=<commands>
```
or
```text
... | REVIEWER_ID | TASK_ID | REVIEW_FAIL | issues found: <summary>
```

## 5) Backlog and Audit Trail
Use:
```bash
just board-done-backlog
```
Fallback:
```bash
python3 scripts/board_status.py --done-backlog
```

This is the canonical backlog of completed work and review state:
- `PENDING_REVIEW`
- `REVIEW_PASS`
- `REVIEW_FAIL`

Do not create separate manual status tables; the event log is source of truth.

## 6) Coordination Rules
- Never rewrite existing events or task rows.
- One task owner at a time unless explicitly split into new task IDs.
- If scope changes, append:
```text
... | AGENT_ID | TASK_ID | CHANGE | scope update
```
- If dropping ownership:
```text
... | AGENT_ID | TASK_ID | RELEASE | released for reassignment
```

## 7) Definition of Done
A task is complete only when all are true:
1. Implementation merged or merge-ready commit/PR exists.
2. Tests for changed behavior are executed and recorded in `DONE`.
3. Independent review has `REVIEW_PASS`.
