# ADR-0041: Show the commands and files of coding actions recorded before migration 0015
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat)

## Context
ADR-0039 stores a readable, redacted copy of each coding action's target from migration 0015 on. Older actions showed only "Asked to run a command" or "Asked to edit a file". Their targets exist in the gateway's own encrypted evidence: the ACTION_REQUESTED payload, `intent.action.targets`.

## Decision
`python -m agw_gateway.admin backfill-coding-targets [--tenant T]` (`make backfill-targets` for the compose stack):
- For every `coding_actions` row without `target_sealed`, it reads that payload, applies the **same** redaction and clipping as new actions (`display_from_targets`), seals the result under the KEK, and stores the diff **counts**.
- Diff text and file contents are never stored.
- Evidence is only read: no evidence event is written or changed.
- Idempotent and resumable. Actions whose payload was erased (retention / erasure) are skipped and stay "not recorded".
- Operator-only (needs the KEK and the migrator role); not reachable from the console or the API.

## Consequences
- The owner's stack: 43 of 43 old actions filled in on 2026-11-19.
- Run stories no longer repeat "needed approval" after an approval: the re-check of the approved retry is shown only when it turns stricter (blocked).
- Test: `tests/e2e/test_coding_backfill.py` checks that the command and path come back, the secret is redacted, contents never appear, the stored copy is sealed, evidence is unchanged, and a second run fills nothing.
