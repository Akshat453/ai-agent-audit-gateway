# Golden hook payloads: sources

Fetched 2026-11-18 from each agent's current official hook documentation.

| File | Source | Verbatim? |
|---|---|---|
| claude_code/pre_bash_npm_test.json | code.claude.com/docs/en/hooks (PreToolUse input example) | yes |
| claude_code/post_write.json | same page (PostToolUse input example) | yes |
| claude_code/session_end.json | same page (SessionEnd input example) | yes |
| codex/session_end.json | developers.openai.com/codex/hooks (SessionEnd example) | yes |
| codex/pre_bash.json, codex/pre_apply_patch.json | same page, PreToolUse field table (the docs give no verbatim PreToolUse sample) | built from the field table |
| cursor/pre_tool_use_shell.json | cursor.com/docs/hooks (preToolUse input example) | yes |
| cursor/post_tool_use.json | same page (postToolUse input example) | yes |
| cursor/before_shell.json, before_mcp.json, before_read_file.json | same page (input templates with `<placeholders>`) plus the documented common fields | placeholders filled in |
| gemini_cli/*.json | google-gemini/gemini-cli docs/hooks/reference.md field lists (no verbatim samples in the docs) | built from the field lists |
| mcp_generic/tools_call.json | MCP JSON-RPC `tools/call` request shape | built |
| other/pre.json | the neutral protocol in agw_cli/adapters/generic.py | built |

Where a cwd like `/project` or `/workspace` does not exist locally, the adapter falls back to
no repository root; the tests point `cwd` at a temporary git checkout when they need one.
