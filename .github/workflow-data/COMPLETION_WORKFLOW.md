# Completion Workflow Artifacts

This repo tracks closure status with three canonical files:

- `.github/workflow-data/AGENT_EXECUTION_TICKETS.yaml`
- `.github/workflow-data/FINAL_COMPLETION_CHECKLIST.json`
- `.github/workflow-data/FINAL_COMPLETION_STATUS.json`

For strategic checklist IDs (`1.1` through `10.11`), the authoritative
definition-of-done ticket spec is:

- `.github/workflow-data/ITEMS_1_TO_10_TICKETS.yaml`

## Validation

Run both commands before marking any ticket `pass`:

```bash
python3 scripts/validate_final_completion.py
python3 scripts/validate_final_completion.py --strict-evidence
python3 scripts/validate_items_1_to_10_tickets.py
```

## Status Rules

Allowed statuses are: `not_started`, `in_progress`, `blocked`, `pass`, `fail`.

A requirement may be marked `pass` only when evidence fields are populated:
`code_refs`, `tests`, `ci_gates`, `docs`.

## Agent Ticket Execution Contract

When an agent closes ticket IDs, it must:

1. Read ticket spec from `AGENT_EXECUTION_TICKETS.yaml` exactly.
2. For `1.x`-`10.x` IDs, read `ITEMS_1_TO_10_TICKETS.yaml` exactly.
3. Honor `deps`, `acceptance_tests`, `required_ci_gates`, `required_docs`, and `blocking_conditions`.
4. Update `FINAL_COMPLETION_STATUS.json` with evidence per ticket requirement ID.
5. Run both validation commands above.
