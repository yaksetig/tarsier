# Agent Execution Instructions (Phase 2)

Source of truth:
1) `/Users/myaksetig/Desktop/Repos/tarsier/MULTI_AGENT_EXECUTION_BOARD_PHASE2.md`
2) This file

## 1) Daily Start
Run:
```bash
python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE2.md
python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE2.md --review-queue
```

Pick tasks that are:
- `ready=true`
- unclaimed/not in progress
- in your lane

## 2) Lane Policy (strict)
- Agent 1: `TWNX-*`, `EXPX-*`, `DAGX-03`, `DAGX-05`
- Agent 2: `REFX-*`, `EQX-*`, `DAGX-01`, `DAGX-02`, `DAGX-04`, `X2-01`

Rules:
1. One active task at a time.
2. Do not touch tasks/files owned by the other lane.
3. If overlap is discovered:
   - append `RELEASE`
   - append `BLOCKED` with exact overlap
   - switch to another ready task in your lane

## 3) Claiming Work (append-only)
Add `CLAIM` in Agent Claims:
```text
YYYY-MM-DDTHH:MM:SSZ | AGENT_ID | TASK_ID | CLAIM | taking task
```
Add `START` in Progress Events:
```text
YYYY-MM-DDTHH:MM:SSZ | AGENT_ID | TASK_ID | START | implementation started
```

UTC timestamp helper:
```bash
date -u +"%Y-%m-%dT%H:%M:%SZ"
```

## 4) Required Progress Events
Blocked:
```text
... | AGENT_ID | TASK_ID | BLOCKED | reason + dependency/overlap
```

Unblocked:
```text
... | AGENT_ID | TASK_ID | UNBLOCKED | reason
```

PR open:
```text
... | AGENT_ID | TASK_ID | PR_OPEN | <branch> <PR/link> <summary>
```

Done:
```text
... | AGENT_ID | TASK_ID | DONE | <commit/PR> tests=<exact commands>
```

## 5) Independent Review (mandatory)
Every `DONE` task must be reviewed by the other agent.

Reviewer events:
```text
... | REVIEWER_ID | TASK_ID | REVIEW_START | reviewing <commit/PR>
... | REVIEWER_ID | TASK_ID | REVIEW_PASS | validated; tests=<commands>
```
or
```text
... | REVIEWER_ID | TASK_ID | REVIEW_FAIL | issues: <summary>
```

## 6) Workspace Isolation
- Use dedicated branch/worktree per task.
- Branch naming: `codex/agent<id>-<task-id-lower>-v1`.
- Commit only task-scoped files.
- Never rewrite old board rows/events.

## 7) Definition of Done
A task is complete only if:
1. Implementation is on a commit/PR.
2. Tests relevant to changed behavior were run and recorded in `DONE`.
3. Independent review has `REVIEW_PASS`.
