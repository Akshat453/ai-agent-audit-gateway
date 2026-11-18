# agw: the AgentGuard coding-agent CLI

`agw` sits on the hook path of a coding agent. Before each action it asks the AgentGuard gateway: allow, deny or ask a human. After the action it reports what happened. Supported agent kinds:

- `claude_code`
- `codex`
- `cursor`
- `gemini_cli`
- `mcp_generic` (behind a filtering MCP proxy)
- `other` (a neutral JSON protocol)

The agent capability reference is [docs/gateway/coding-agents.md](../../docs/gateway/coding-agents.md). Design: [ADR-0034](../../docs/gateway/adr/0034-c1-coding-agent-integration.md).

## Install

```sh
pipx install ./packages/agw-cli      # standard library only; Python >= 3.11
```

## Configure

1. An admin issues a device key for you (it is printed once):

   ```sh
   make device-key TENANT=demo DEVELOPER=alice LABEL=laptop
   ```

2. Store it with `chmod 600`.

3. Write `~/.config/agentguard/config.toml`:

   ```toml
   url = "https://agentguard.example"
   device_key_file = "~/.config/agentguard/device.key"
   approval_wait_seconds = 90
   ```

You can also use the environment variables `AGW_URL`, `AGW_DEVICE_KEY_FILE` (or `AGW_DEVICE_KEY`), `AGW_APPROVAL_WAIT_SECONDS`, `AGW_HOOK_TIMEOUT_SECONDS` and `AGW_ALLOW_MODE=defer|explicit`.

## Use

```sh
agw status                                   # config (key redacted) + the gateway's view
agw session start --agent claude_code --issue 42 --issue-file issue.txt   # optional
agw hook claude_code PreToolUse < payload.json   # what the agent's hook config runs
agw session end --agent claude_code
```

## Fail closed

Any of these blocks the action with `AgentGuard unavailable - action blocked`, in the agent's native deny format:

- the gateway is down or slow;
- the response is garbage;
- the configuration is missing;
- the payload is unreadable;
- the CLI hits an internal error.

Post-action and session hooks never block.

## Not yet in C1

`agw login`, `agw init`, `agw doctor` and `agw uninstall` come in C2. Until then, set up the hook configuration by hand; coding-agents.md §2 shows a recommended snippet per agent.
