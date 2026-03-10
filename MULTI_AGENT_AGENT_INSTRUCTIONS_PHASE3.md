# Agent Execution Instructions (Phase 3)

Source of truth:
1) `/Users/myaksetig/Desktop/Repos/tarsier/MULTI_AGENT_EXECUTION_BOARD_PHASE3.md`
2) This file

## 1) Daily Start
Run:
```bash
python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE3.md
python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE3.md --review-queue
```

Pick tasks that are:
- `ready=true`
- `status=TODO`
- unclaimed/not in progress
- in your lane

## 2) Lane Policy (strict)
- Agent 1: `INTEG-*`, `CODEGEN-*`, `PLAY-*`, `DOCS-01`, `DOCS-03`, `EXAMPLE-02`, `EXAMPLE-03`
- Agent 2: `PANIC-*`, `RECONF-*`, `CI-*`, `KERN-*`, `EXAMPLE-01`, `DOCS-02`, `DOCS-04`

Rules:
1. One active task at a time.
2. Do not touch tasks/files owned by the other lane.
3. If overlap is discovered:
   - append `RELEASE`
   - append `BLOCKED` with exact overlap/dependency
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
... | AGENT_ID | TASK_ID | PR_OPEN | branch=<branch> pr=<url-or-local-note> summary=<short>
```

Done:
```text
... | AGENT_ID | TASK_ID | DONE | commit=<sha> tests=<exact commands>
```

## 5) Independent Review (mandatory)
Every `DONE` task must be reviewed by the other agent.

Reviewer events:
```text
... | REVIEWER_ID | TASK_ID | REVIEW_START | reviewing commit=<sha>/pr=<url>
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
1. Implementation is committed and branch/PR is recorded.
2. Focused tests for changed behavior were run and listed in `DONE`.
3. Independent reviewer added `REVIEW_PASS`.

## 8) Review Queue Discipline
- Before claiming new implementation work, check pending review queue:
```bash
python3 scripts/board_status.py --board MULTI_AGENT_EXECUTION_BOARD_PHASE3.md --review-queue
```
- If queue contains tasks from the other agent, prefer reviewing one first unless a P0 blocker task is ready and unclaimed.
