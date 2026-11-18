# Coding agents: hook capabilities and the AgentGuard integration

Status: C1 (ADR-0034), 2026-11-18. **Reference table reused by later phases** (C2 `agw init` /
`agw doctor` generate configuration from it). Facts below come from each agent's **current
official documentation, fetched 2026-11-18**. None of the pages showed a "last updated" date.
Re-check these facts before relying on them later. The adapters carry the same facts as data
(`packages/agw-cli/src/agw_cli/adapters/*.py`, `AgentSpec`).

Sources:

- **Claude Code:** code.claude.com/docs/en/hooks, /settings, /managed-settings. Versions up to v2.1.319 are cited.
- **Codex CLI:** developers.openai.com/codex/hooks and /codex/enterprise/managed-configuration.
- **Cursor:** cursor.com/docs/hooks. The old `/docs/agent/hooks` URL returns 404.
- **Gemini CLI:** google-gemini/gemini-cli on GitHub, `docs/hooks/{index,reference,writing-hooks}.md`, `docs/reference/configuration.md` and `docs/cli/enterprise.md`.
- **VS Code / Copilot:** code.visualstudio.com/docs/agent-customization/hooks, /docs/enterprise/manage-ai-settings, and docs.github.com/en/copilot/reference/hooks-reference.
- **Antigravity:** antigravity.google/docs/hooks.

## 1. Capability table

| | Claude Code | Codex CLI | Cursor | Gemini CLI |
|---|---|---|---|---|
| **Pre-action events** | `PreToolUse` (also `PermissionRequest`) | `PreToolUse` (also `PermissionRequest`) | `preToolUse` (all tools), `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | `BeforeTool` |
| **Post-action events** | `PostToolUse`, `PostToolUseFailure` (cannot undo) | `PostToolUse` (also after Bash exits non-zero; cannot undo) | `postToolUse`, `postToolUseFailure`, `afterShellExecution`, `afterMCPExecution`, `afterFileEdit` (cannot block) | `AfterTool` (cannot undo) |
| **Session events** | `SessionStart`, `SessionEnd` (SessionEnd default timeout 1.5 s) | `SessionStart`, `SessionEnd` (1 s default, 3 s max) | `sessionStart`, `sessionEnd` (fire-and-forget) | `SessionStart`, `SessionEnd` (best effort) |
| **Stdin payload (pre)** | `session_id`, `cwd`, `hook_event_name`, `permission_mode`, `tool_name`, `tool_input`, `tool_use_id`; MCP adds `mcp_server{name,source}`; paths absolute | `session_id`, `turn_id`, `cwd`, `model`, `tool_name`, `tool_use_id`, `tool_input` (Bash and `apply_patch`: `tool_input.command`; for apply_patch this is the **patch text**) | Common: `conversation_id`, `generation_id`, `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`. preToolUse: `tool_name`, `tool_input` (object), `tool_use_id`, `cwd`. Shell: `command`, `cwd`. MCP: `tool_name`, `tool_input` (a **JSON string**), `mcp_server_name`. Read: `file_path`, `content` | `session_id`, `cwd`, `hook_event_name`, `timestamp`, `tool_name`, `tool_input`, `mcp_context` (schema NOT DOCUMENTED) |
| **Verbatim sample in docs** | yes (Bash pre, Write post, SessionEnd) | SessionEnd only. NOT DOCUMENTED for pre/post; field tables only | yes (preToolUse, postToolUse; templates for the others) | NOT DOCUMENTED; field lists only |
| **Allow** | exit 0 and no output (no decision), or `permissionDecision:"allow"` (skips the local prompt) | exit 0, no output | `{"permission":"allow"}` | `{"decision":"allow"}` |
| **Deny** | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}`, or exit 2 with the reason on stderr | same JSON as Claude, or legacy `{"decision":"block"}`, or exit 2 | `{"permission":"deny","user_message","agent_message"}`, or exit 2 | `{"decision":"deny","reason","systemMessage"}`, or exit 2 |
| **Ask** | `permissionDecision:"ask"` is a **local** prompt to the user | **NOT SUPPORTED**: parsed, then the hook run is marked failed and the tool **proceeds** | Shell and MCP only (local prompt). For preToolUse the schema accepts `ask` but does not enforce it. beforeReadFile has no ask | **NOT SUPPORTED** |
| **Hook failure / timeout** | Non-2 exit or timeout lets the action **through**, unless the hook sets `"onFailure":"block"` (v2.1.295+) | Lets the action **through**. No fail-closed option | Lets it **through** unless `"failClosed": true`. For permission hooks, invalid JSON blocks | Lets it **through**; non-JSON stdout counts as allow. No fail-closed option |
| **Timeout** | seconds; command hooks default **600**; no documented maximum | seconds; default **600** | seconds; default "platform default" (value NOT DOCUMENTED) | **milliseconds**; default **60000** |
| **Matcher** | `*`/empty = all; `A\|B` exact names; otherwise an unanchored JS regex (`mcp__memory__.*`); optional `if` rule such as `Bash(rm *)` | regex on `tool_name`. `apply_patch` also matches `Edit`/`Write` | regex. The value tested depends on the hook: tool type, full command string, or a fixed `Read`/`Write` | regex on tool events, exact match on lifecycle events |
| **Config files** | `~/.claude/settings.json`, `.claude/settings.json` (+ `.local`), plugins, frontmatter | `~/.codex/hooks.json`, `.codex/hooks.json` (trusted projects), `[hooks]` in `config.toml`, plugins. Non-managed hooks need trust via `/hooks` | `~/.cursor/hooks.json`, `.cursor/hooks.json` (`"version":1`). Also loads Claude Code hooks | `settings.json` `hooks` at user, project, system and extension level. Project hooks are fingerprinted |
| **Making hooks mandatory** | Managed `managed-settings.json`: `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`. Also MDM (`com.anthropic.claudecode`, `HKLM\SOFTWARE\Policies\ClaudeCode`) or server-managed settings. `allowManagedHooksOnly: true`; only managed settings can disable managed hooks | `requirements.toml` (`/etc/codex/…`, `%ProgramData%\OpenAI\Codex\…`, MDM `com.openai.codex`). `[features].hooks = true` plus `allow_managed_hooks_only = true`; managed hooks "can't be disabled from the user hook browser". **Scripts are deployed by you** | MDM file (`/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json`), or Enterprise team hooks synced every 30 min. Dashboard hooks can't set `matcher` or `failClosed`. **Whether users can disable them is NOT DOCUMENTED**; there is no managed-only switch | System settings (`/etc/gemini-cli/settings.json`, `/Library/Application Support/GeminiCli/settings.json`, `C:\ProgramData\gemini-cli\settings.json`). **No managed-only or non-bypassable hook mechanism is documented**: users can `/hooks disable-all` |
| **Tool names** | `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `NotebookEdit`, `Agent`, …, `mcp__<server>__<tool>`. `MultiEdit` is not in the current docs (still handled) | `Bash`, `apply_patch` (all edits), `mcp__<server>__<tool>`, other local tools by function name. **No file-read tool**: reads go through the shell | `Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task`, `MCP:<tool>`. Edit and web-fetch names NOT DOCUMENTED | `run_shell_command`, `read_file`, `read_many_files`, `write_file`, `replace`, `glob`, `grep_search`, `list_directory`, `web_fetch` (URLs inside `prompt`), `google_web_search`, `mcp_<server>_<tool>` |
| **Gaps** | Post hooks can't block. Timeouts and errors fail open without `onFailure` | No ask. Hosted tools (web search) bypass hooks. "Not a complete enforcement boundary". Fails open. No pre-read hook | No ask on preToolUse or reads. Session hooks can't block. Fails open by default | No ask. No enforced hooks. Fails open. MCP server name ambiguous in `mcp_<server>_<tool>` |

### MCP-only IDEs: the prompt and the docs disagree

The prompt calls VS Code agent mode and Antigravity "MCP-only". **Their current docs show
pre-tool hooks:**

- **VS Code / GitHub Copilot agent mode** (Preview):
  - Events: `preToolUse` with `{sessionId, cwd, toolName, toolArgs}`; a PascalCase variant mirrors Claude's fields.
  - Output: top-level `permissionDecision` (`allow|deny|ask`); exit 2 denies.
  - Timeouts: default 30 s, and a timeout lets the action through.
  - Enforcement: policy hooks in `/etc/github-copilot/policy.d/*.json`, or the VS Code policy `ChatAllowManagedHooksOnly`.
  - MCP policies: `ChatMCP`, `ChatAllowedMcpServers` / `ChatDeniedMcpServers`, `ChatAllowManagedMcpServersOnly`.
- **Google Antigravity:**
  - Config: `.agents/hooks.json` or `~/.gemini/config/hooks.json`.
  - Event: `PreToolUse` with `toolCall{name,args}`.
  - `decision`: `allow | auto_approve | deny | ask | force_ask | deny_unless_prior_grant`.
  - Default timeout 30 s.
  - Not documented: exit codes and enterprise enforcement.

C1 ships the `mcp_generic` adapter the prompt asks for. Through a filtering MCP proxy, it covers any IDE that only speaks MCP. **Native VS Code and Antigravity adapters are not built** (see §5). The proposed doc change is in ADR-0034 §7.

## 2. How each agent is wired (what `agw hook` does)

`agw hook <agent_kind> <event>` reads the native JSON on stdin and normalizes it to `agw.coding-action/1` (schema: `packages/schemas/coding/coding-action-v1.schema.json`). It then calls `POST /v1/coding/decide` and prints the native response.

| Agent | Pre-hook output for… allow | deny | gateway "ask" |
|---|---|---|---|
| `claude_code` | nothing (exit 0). Claude Code's own permission rules still run, because AgentGuard is necessary, not sufficient. `AGW_ALLOW_MODE=explicit` prints `permissionDecision:"allow"` instead | `permissionDecision:"deny"` + reason | wait; approved → allow, otherwise deny `Approval pending: <link>. Retry after approval.` |
| `codex` | nothing (exit 0) | `permissionDecision:"deny"` + reason | as above |
| `cursor` | `{"permission":"allow"}` | `{"permission":"deny", user_message, agent_message}` (beforeReadFile: `user_message` only) | as above |
| `gemini_cli` | `{"decision":"allow"}` | `{"decision":"deny", reason, systemMessage}` | as above |
| `mcp_generic` | the `tools/call` request, unchanged (forward it) | a JSON-RPC response with `result.isError: true` and the reason | as above |
| `other` | `{"decision":"allow"}` | `{"decision":"deny","reason"}` | as above |

**The native "ask" is never emitted.** In every agent that has one, it is a **local** prompt: the developer would approve their own agent's CRITICAL action, which would bypass the routed approval (ledger lead, security). A gateway `ask` instead becomes:

1. a Phase 5 approval routed to the right role;
2. a bounded wait inside the hook;
3. the identical retry, which consumes the approval.

**Fail closed:** missing configuration, gateway unreachable, timeout, malformed response, an unreadable payload or any internal error all deny with `AgentGuard unavailable - action blocked`. The agents' own fail-open behaviour on a *killed* hook remains, which is why the generated configuration (C2) must set:

- the hook timeout **above** the approval wait, which defaults to 90 s; the CLI also stops waiting 15 s before the agent's timeout;
- `"onFailure":"block"` (Claude Code) and `"failClosed": true` (Cursor).

Codex and Gemini have no such switch (§5).

**Correlating post with pre:**
- **Claude Code and Codex:** by `tool_use_id`.
- **Cursor preToolUse/postToolUse:** by `tool_use_id`.
- **Other Cursor hooks and Gemini:** by a fingerprint of the normalized action (type + targets).

A post-action report with no authorized action becomes a `SECURITY_VIOLATION` (`CODING_UNDECIDED_ACTION`): either a tool ran without a pre-hook, or the agent ran something AgentGuard denied.

### Recommended hook configuration (until `agw init` generates it in C2)

Claude Code (`managed-settings.json` with `allowManagedHooksOnly: true`, or `.claude/settings.json`):

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*",
                   "hooks": [{"type": "command", "command": "agw hook claude_code PreToolUse", "timeout": 120, "onFailure": "block"}]}],
  "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "agw hook claude_code PostToolUse"}]}],
  "SessionStart": [{"hooks": [{"type": "command", "command": "agw hook claude_code SessionStart"}]}],
  "SessionEnd":   [{"hooks": [{"type": "command", "command": "agw hook claude_code SessionEnd"}]}]}}
```

- **Codex** (`requirements.toml`): `allow_managed_hooks_only = true`, `[features] hooks = true`, `[[hooks.PreToolUse]] matcher = "*"`, command `agw hook codex PreToolUse`, `timeout = 120`.
- **Cursor** (`hooks.json`, version 1):
  - `beforeShellExecution`, `beforeMCPExecution` and `beforeReadFile` → `agw hook cursor <event>`;
  - `preToolUse` with matcher `Write|Delete|Grep|Task|MCP:.*`;
  - set `"timeout": 120, "failClosed": true`;
  - post events: `postToolUse`, `afterShellExecution`, `afterMCPExecution`.
- **Gemini CLI** (system `settings.json`): `BeforeTool`/`AfterTool` with matcher `*` → `agw hook gemini_cli BeforeTool`, `"timeout": 120000` (ms).

## 3. Normalized action (`agw.coding-action/1`)

| Field | Meaning |
|---|---|
| `schema` | always `agw.coding-action/1` |
| `session_id` | the gateway session (the evidence run) |
| `agent_kind` | `claude_code`, `codex`, `cursor`, `gemini_cli`, `mcp_generic`, `other` |
| `agent_version` | the agent's claimed version (unauthenticated) |
| `developer` | informational only. The developer is **always** the human bound to the device key |
| `repo` | `{remote_url, head_sha}`, read from `.git` files; credentials in the URL are stripped |
| `workspace_root` | the repository root. Paths are relative to it, `~/…` under home, absolute elsewhere; symlinks are resolved |
| `action_type` | `file_read`, `file_write`, `file_delete`, `command_exec`, `search`, `web_fetch`, `mcp_call`, `git_op`, `unknown` |
| `native_tool` | the agent's own tool name |
| `targets` | `paths[]`, `command`, `argv[]`, `url`, `query`, `mcp{server,tool}` |
| `content_digests` | SHA-256 of `diff`, `content` and MCP `args` |
| `incomplete` | the adapter could not interpret everything. The policy then never allows |

**What travels next to the action:**
- A write sends its **diff**: a unified diff computed locally, or the agent's own patch. The gateway's content rules evaluate it, and it is stored only in the encrypted payload. It is not stored at all if the secret scanner fires.
- File contents, command output and tool results never leave the machine; results travel as digests.

## 4. Policy (summary; file `agw_gateway/coding/policies/coding-mintrail-v1.toml`)

> **Default since 2026-11-19 (ADR-0037): profile "balanced", `coding-mintrail-v2.toml`.**
> - On the developer's machine, everyday work is allowed and recorded.
> - The strict rules below run when the change is submitted (`git_submit_change`).
> - Locally a human is still asked only for these: the agent's own guard config, writes outside the repo (temp folders excepted), migrations, dependency changes, git that destroys work, inline code, and third-party MCP tools.
> - Every deny below still applies.
> - `AGW_CODING_POLICY_PROFILE=strict` gives the behaviour described in this section at every step.

The policy is deterministic and versioned: `coding-mintrail` v1, with its digest recorded on every decision. Deny overrides ask, which overrides allow. Unknown action types and anything the policy cannot parse ask a human. Globs are case-insensitive.

| Effect | What |
|---|---|
| allow (LOW) | Normal source and test files. Allowlisted commands:<br>- `pnpm install --frozen-lockfile`; `pnpm test`, `lint`, `typecheck`, `build`, `vitest …`, `tsc --noEmit`, `playwright test`<br>- `make test`, `lint`, `typecheck`, `coverage`<br>- `git status`, `diff`, `log`, `show`, `add`, `commit`, `checkout -b`, `switch -c`, `restore`, `stash`<br>- `ls`, plus `cat`/`head`/`tail`/`grep`/`rg` on non-secret paths<br>Also: docs-host web fetches and read-only GitHub MCP tools |
| ask HIGH | Prompt paths: `api/src/{payments,refunds,auth}/**`, `ledger/**` (→ `ledger_lead`), `depot/**`, `packages/shared/src/money/**`, `drizzle/**`, `signal/**/sign*`.<br>MintRail's real equivalents: `api/src/**/payment*`, `refund*`, `*auth*`, `keys.ts`, `signing.ts`, `shared/src/money.ts`, `signatures.ts`.<br>Other edits to `package.json`.<br>`pnpm add` / `npm install <pkg>`, migrations, `git commit --no-verify` |
| ask CRITICAL (2 × `security`) | `.github/**`, `CODEOWNERS`, `infra/**`, `package.json` dependency sections, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.npmrc`, `.nvmrc`, Dockerfiles, `.devcontainer/**`.<br>Agent configuration: `.claude/**`, `.codex/**`, `.cursor/**`, `.gemini/**`, `.agents/**`, `.vscode/mcp.json`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.agentguard.yaml`.<br>`.git/**`, `.husky/**`, deleting a test file, removing test cases, writes outside the workspace |
| deny | **Secret reads:** `.env*` (not `.env.example`), `*.pem`, `*.key`, `id_*` key names, `~/.ssh`, `~/.aws`, `~/.config/gh`, keychains, `/proc/*/environ`, `.mintrail/*keys*`, and the answer-key path `**/mintrail-private/**`.<br>**Environment printing:** `env`, `printenv`, bare `set`, `export -p`, `node -e/-p` with `process.env`, `echo $…TOKEN`.<br>**Git:** `git push`, `git remote add/set-url`, `git config credential.*`, `-c core.hooksPath`.<br>**Network:** `curl`, `wget`, `nc`, `ssh`, `scp`, `ftp`.<br>**Package runners:** `npx`, `pnpm dlx`.<br>**Scripts piped** into sh/bash/zsh/node/python.<br>**Other commands:** `rm -rf` outside the workspace; `sudo`; `chmod` on hook or config files; `docker run --privileged`; deploy tools; production hosts.<br>**MCP:** tools that push through the GitHub MCP server.<br>**Content rules on the diff:** removing or bypassing `MintRail-Signature`/HMAC verification; `.skip`/`.only`/`.todo` in tests; bigint money to number; hardcoded credentials; SSH keys; disabling CI steps |

**Shell commands are parsed, never executed.**
- Commands split on `;`, `&&`, `||` and pipes.
- Here-document bodies are treated as data, and as the content of any file they write.
- `$(…)` and backticks are evaluated recursively.
- `sh -c`, `eval`, `xargs`, `env`, `timeout` and `nice` are unwrapped.

## 5. Limitations per agent

- **All agents:**
  - The hook is a client-side control. A developer with local admin rights can remove it. Managed settings (Claude Code, Codex) or MDM (Cursor) are needed to make it mandatory.
  - The gateway records what the hook reported. It cannot see actions taken outside the hooked tools. A `PostToolUse` with no decision is flagged, but a tool with no hook at all is invisible.
  - Content rules are deterministic regular expressions. A deliberately obfuscated bypass, such as a signature check renamed and rewritten, can evade them. The CRITICAL and HIGH path rules are the backstop.
- **Claude Code:**
  - A killed or timed-out hook fails **open** unless `onFailure: "block"` is set.
  - `NotebookEdit` has no diff, so it asks.
  - `WebSearch` has no URL, so it asks.
  - Subagent and internal tools (`Agent`, `TodoWrite`, …) are "unknown" and ask if they are matched; the recommended matcher excludes them.
- **Codex:**
  - No fail-closed switch: a crashed hook lets the action through. Our process catches its own errors and exits with a deny.
  - Hosted tools (web search) never reach hooks.
  - There is no file-read tool: reads go through `Bash` (`cat .env` is denied there).
  - apply_patch moves and deletes are separate decisions.
- **Cursor:**
  - The default timeout is not documented: set it explicitly.
  - `preToolUse` and `beforeShellExecution` can both fire for one command. That gives two decisions; configure one of them.
  - `afterFileEdit` has no `tool_use_id` and pairs by fingerprint only.
  - No managed-only switch is documented.
- **Gemini CLI:**
  - No fail-closed option.
  - No enforced hooks: users can `/hooks disable-all`. This is the weakest enforcement of the four.
  - `web_fetch` URLs are extracted from free text.
  - MCP tool names (`mcp_<server>_<tool>`) can't be split reliably without `mcp_context`.
- **mcp_generic:**
  - Needs a filtering proxy in front of the MCP server: not part of C1.
  - Native VS Code and Antigravity hook adapters are **not built**. Their docs now show hook systems (§1): a later phase.

## 6. MCP client configuration (C2, `agw init`; fetched 2026-11-18)

> **C3 dev-tools.** The same `agentguard` MCP entry also serves the GitHub dev-tools (`github_issue_*`, `git_submit_change`, `github_pr_*`) once an admin has added and classified the GitHub connector. Their descriptions tell the agent to submit work with `git_submit_change` instead of `git push`: the agent holds no GitHub credential, and C1 denies `git push`. See ADR-0036 and [github-app-setup.md](github-app-setup.md) §5.

How each client points at AgentGuard's remote MCP endpoint (`<gateway>/mcp`). Each client signs in with OAuth in the browser; there is no static token. `agw init` writes these files with the `agentguard` entry (ADR-0035 §8).

| Client | File `agw init` writes | Entry | OAuth sign-in (per its docs) |
|---|---|---|---|
| Claude Code | `.mcp.json` (project scope) | `{"mcpServers":{"agentguard":{"type":"http","url":U}}}` | yes: DCR, CIMD, pre-registered; `/mcp` or `claude mcp login` |
| Codex CLI | `.codex/config.toml` (trusted projects; marked block) | `[mcp_servers.agentguard]` `url = U` | yes: CIMD and DCR; `codex mcp login` |
| Cursor | `.cursor/mcp.json` | `{"mcpServers":{"agentguard":{"url":U}}}` | yes: PRM + DCR (CIMD not mentioned) |
| Gemini CLI | `.gemini/settings.json` | `{"mcpServers":{"agentguard":{"httpUrl":U}}}` (`url` would mean SSE) | yes: discovery + DCR; `/mcp auth` |
| VS Code / Copilot | `.vscode/mcp.json` (deprecated local harness; `.mcp.json` is also read) | `{"servers":{"agentguard":{"type":"http","url":U}}}` | partly documented (`oauth.clientId`); automatic DCR/CIMD NOT DOCUMENTED |
| Antigravity | `.agents/mcp_config.json` | `{"mcpServers":{"agentguard":{"serverUrl":U}}}` | yes: manual, then CIMD, then DCR |

**The server** implements MCP 2026-07-28 (stateless, `server/discover`) and the 2025-11-25 legacy handshake on the same endpoint, because deployed clients still speak the older revision.

**Enforcement tiers** shown in the Integrations page and by `agw doctor`:

| Tier | Agents |
|---|---|
| `enforced` | Claude Code, Codex |
| `hooked` | Cursor |
| `advisory` | Gemini CLI |
| `mcp_only` | VS Code, Antigravity, generic MCP. Only the gateway's MCP tools are governed, not the IDE's built-in tools. |
