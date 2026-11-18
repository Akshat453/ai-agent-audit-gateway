# ADR-0037: "Balanced" coding profile (default): record everyday work, ask only at crucial points
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat), after the first real Claude Code session on MintRail

## Context
The first real session (tenant `akshat`, issue MR-13: a one-line dashboard fix) produced 18 decisions. 9 of them stopped the developer:
- 7 approvals;
- 1 CRITICAL approval needing two approvers;
- 1 block (curl to the local dashboard).

The causes:

| Stop | Rule | Why it fired |
|---|---|---|
| Calling AgentGuard's own MCP tools (read issue, submit, open PR) | `MCP-ASK` | `agentguard/*` was not on the hook's MCP allow-list. The gateway checks these tools itself, so this was a double check. |
| `git checkout`, `git fetch` | `GIT-ASK` | Only a short list of git subcommands was allowed. |
| Shell pipelines with `awk`, `xargs`, ... | `CMD-UNKNOWN` | Anything not on the command allow-list asked. |
| Editing `dashboard/app/(app)/refunds/page.tsx` | `PATH-HIGH` | `agw init` marked every folder named like money (refunds, payments, payouts, ...) as HIGH, including UI pages. |
| `curl localhost:3000` | `CMD-NETWORK` (deny) | Every curl was denied, even to localhost. |
| A temp-file path (`/tmp/...`) | `PATH-OUTSIDE-WORKSPACE` (CRITICAL, four-eyes) | Writing outside the repo counted as CRITICAL. |
| `git_submit_change` of that fix | `PATH-HIGH` at submit | The same over-broad UI paths. |

In addition:
- The hook waited only 90 s for an approval, so the agent stopped and asked to be told when approvers were slower.
- The password re-check (step-up) lasted 5 min.

Every action is recorded in the evidence chain whether or not a human is asked. The owner's requirement: *"approval only at crucial places; everything is recorded anyway; make life easy for developers; customizable, but this is the default."*

## Decision
1. **Two bundled coding profiles, selected by `AGW_CODING_POLICY_PROFILE`:**
   - **balanced** is the default: `coding-mintrail-v2.toml`, `[profile] mode = "balanced"`.
   - **strict** is C1 unchanged: `coding-mintrail-v1.toml`.
   - A custom file (`AGW_CODING_POLICY_FILE`) still wins.
   - Both files hold the same lists, and every DENY of v1 is a DENY of v2.
   - The version (1 vs 2) and digest are recorded in every `POLICY_EVALUATED` and bound into approvals.
2. **Stages.** `CodingPolicy.evaluate(..., stage="local"|"submit")`.
   - The hook evaluates "local". `git_submit_change` evaluates "submit", the moment the change leaves the machine.
   - The balanced profile relaxes only "local". Submit runs the full strict check over the complete diff: sensitive paths, content rules, test deletion, CI, dependencies.
   - Hook and submit now use the **same** configured policy. Before this, submit always used the bundled file.
3. **What balanced allows locally (still recorded, with the original rule id in the evidence):**
   - sensitive and CRITICAL source paths, except agent/hook config;
   - test deletions and dependency edits in `package.json`, which are checked at submit;
   - unlisted commands, interpreters running files, docker (non-privileged), chmod, recursive rm inside the repo;
   - non-destructive git, `git -c`, `--no-verify`;
   - web fetches;
   - temp-folder writes;
   - curl/wget to local hosts (uploads included) or to the allowed documentation hosts (no uploads);
   - AgentGuard's own MCP tools (`agentguard/*`).
4. **What still needs a human locally:**
   - the agent editing its own guard (`.claude/**`, `.agentguard.yaml`, hooks …);
   - writes outside the repo other than temp folders: HIGH, one approver;
   - migrations;
   - dependency installs and adds;
   - git that destroys work: `reset --hard`, `clean`, `checkout -- .`, `branch -D`, `stash drop/clear`, `rebase`, history rewrites;
   - `find -delete`;
   - inline code (`python -c`, `node -e`), because it can reach the network;
   - third-party MCP tools.
5. **Still denied:**
   - secrets, `.env`, SSH keys, `git push`;
   - sudo, deploy tools, package runners (`npx`), environment dumps, piping to a shell;
   - remote shells and copies;
   - any curl/wget to a non-local host, and any upload to a non-local host;
   - production hosts;
   - signature bypass, bigint money to number.
6. **`agw init` no longer flags UI pages.** Folders under a route group (`(app)`) or `pages/`, `components/`, `ui/`, `views/` are front-end. The money logic they call (`api/src/services/*`, schemas, `ledger/`, `money.ts`) is still flagged.
7. **Waiting and step-up:**
   - The hook waits **600 s** for a decision. `agw init` writes a hook timeout of **660 s**, so the agent continues by itself after an approval.
   - The compose stack sets `AGW_STEP_UP_WINDOW_SECONDS=1800`.
   - `AGW_APPROVAL_FOUR_EYES_CRITICAL` (already a setting) is exposed in compose. The owner set it to false.
8. **Classification form.** It defaults to the connector's proposal (GitHub: Auto). Before, MEDIUM writes defaulted to "Always ask".

## Consequences
- A developer's ordinary loop (read, edit, test, git, submit, PR) runs without stops. The approval moves to the one point where a change leaves the machine.
- A change made locally but never submitted is not reviewed. It never reaches GitHub, and it is recorded. A change submitted outside AgentGuard fails the "AgentGuard evidence" check (C3).
- Strict deployments keep C1 behaviour: `AGW_CODING_POLICY_PROFILE=strict`.
- Existing `.agentguard.yaml` files generated before this change still contain the UI paths. Removing them is a loosening, so it goes through the admin proposal flow (C2).
- Tests:
  - the C1 table (≥ 100 cases) pins strict;
  - `test_coding_balanced.py` (165 cases) and `test_coding_balanced_api.py` pin balanced;
  - `make coding-mutations` has 14/14 guards, 3 of them new for balanced.
