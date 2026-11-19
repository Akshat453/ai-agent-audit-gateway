/** Action type + target -> a verb phrase ("edit api/src/x.ts", "run `pnpm test`") (ADR-0039).
 *  Targets come from the agent (paths, commands): callers render `object` as escaped text and
 *  label it "reported by the agent". Never HTML. */

export type Target = {
  paths?: string[] | null; command?: string | null; argv?: string[] | null; url?: string | null;
  query?: string | null; mcp_tool?: string | null; mcp_server?: string | null; native_tool?: string | null;
};

export type Phrase = {
  verb: string; // "edit", "run", "open a pull request"
  object: string | null; // the agent-reported target, shown in code style
  kind: "path" | "command" | "url" | "query" | "tool" | null;
  text: string; // the whole phrase as plain text
};

/** Coding action types (agw.coding-action/1) -> verb (with {x} = target). */
export const CODING_VERBS: Record<string, { verb: string; none: string; kind: Phrase["kind"] }> = {
  file_read: { verb: "read", none: "read a file", kind: "path" },
  file_write: { verb: "edit", none: "edit a file", kind: "path" },
  file_delete: { verb: "delete", none: "delete a file", kind: "path" },
  command_exec: { verb: "run", none: "run a command", kind: "command" },
  search: { verb: "search for", none: "search the code", kind: "query" },
  web_fetch: { verb: "open", none: "open a web page", kind: "url" },
  mcp_call: { verb: "use", none: "use an MCP tool", kind: "tool" },
  git_op: { verb: "run", none: "run a git command", kind: "command" },
  unknown: { verb: "do", none: "do something AgentGuard could not identify", kind: null },
};

/** Integration actions (cx_<slug>_<action>) and the built-in demo tools. */
export const TOOL_PHRASES: Record<string, string> = {
  github_issue_get: "read a GitHub issue",
  github_issue_list: "list GitHub issues",
  github_issue_comment: "comment on a GitHub issue",
  git_submit_change: "submit its change to GitHub",
  github_pr_create: "open a pull request",
  github_pr_comment: "comment on a pull request",
  github_pr_status: "check a pull request",
  send_email: "send an email",
  create_ticket: "create a ticket",
  public_doc_search: "search public documents",
  delete_record: "delete a record",
  export_customer_data: "export customer data",
  update_iam_role: "change someone's access rights",
  test_echo: "run a test tool",
  notify: "send a notification",
};

const GIT_WORDS: Record<string, string> = {
  status: "check the git status", log: "look at the git history", diff: "compare changes", show: "look at a commit",
  add: "stage files", commit: "commit changes", checkout: "switch branches", switch: "switch branches",
  branch: "manage branches", fetch: "fetch updates", pull: "pull updates", push: "push to the remote",
  merge: "merge branches", rebase: "rebase the branch", reset: "reset changes", stash: "stash changes",
  clean: "delete untracked files", restore: "restore files", tag: "manage tags", remote: "change git remotes",
  clone: "clone a repository", "cherry-pick": "copy a commit",
};

/** "git -c x=y checkout -b fix/MR-1" -> "switch branches" */
export function gitVerb(command: string): string {
  const words = command.trim().split(/\s+/);
  const i = words.indexOf("git");
  for (let j = i + 1; j < words.length; j++) {
    const w = words[j] ?? "";
    if (w === "-c" || w === "-C") { j++; continue; }
    if (w.startsWith("-")) continue;
    return GIT_WORDS[w] ?? `run git ${w}`;
  }
  return "run a git command";
}

function shorten(s: string, max = 120): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max)}…` : one;
}

export function codingPhrase(actionType: string, target: Target | null | undefined): Phrase {
  const spec = CODING_VERBS[actionType];
  if (!spec) return { verb: "do something", object: null, kind: null, text: `do something (${actionType})` };
  const t = target ?? {};
  const paths = t.paths ?? [];
  const command = t.command ?? (t.argv?.length ? t.argv.join(" ") : null);
  let object: string | null = null;
  if (spec.kind === "path" && paths.length) object = paths.length > 1 ? `${paths[0]} (+${paths.length - 1} more)` : paths[0] ?? null;
  else if (spec.kind === "command" && command) object = shorten(command);
  else if (spec.kind === "url" && t.url) object = shorten(t.url);
  else if (spec.kind === "query" && t.query) object = shorten(t.query, 80);
  else if (spec.kind === "tool" && t.mcp_tool) object = t.mcp_server ? `${t.mcp_server}/${t.mcp_tool}` : t.mcp_tool;
  if (actionType === "git_op" && command) {
    const verb = gitVerb(command);
    return { verb, object, kind: "command", text: `${verb} (${object})` };
  }
  if (!object) return { verb: spec.none, object: null, kind: null, text: spec.none };
  const text = spec.kind === "command" ? `run \`${object}\`` : spec.kind === "tool" ? `use ${object} via MCP` : `${spec.verb} ${object}`;
  return { verb: spec.verb, object, kind: spec.kind, text };
}

/** Any tool id -> phrase. Coding tools need the action type and target for the object. */
export function toolPhrase(toolId: string | null | undefined, coding?: { action_type: string; target?: Target | null } | null): Phrase {
  if (coding) return codingPhrase(coding.action_type, coding.target);
  if (!toolId) return { verb: "do something", object: null, kind: null, text: "do something" };
  if (toolId.startsWith("coding.")) return codingPhrase(toolId.slice(7), null);
  const action = toolId.startsWith("cx_") ? Object.keys(TOOL_PHRASES).find((k) => toolId.endsWith(`_${k}`)) : toolId;
  const known = action ? TOOL_PHRASES[action] : undefined;
  if (known) return { verb: known, object: null, kind: null, text: known };
  const shown = toolId.startsWith("cx_") ? toolId.slice(3).replace("_", " ") : toolId;
  return { verb: `use ${shown}`, object: null, kind: null, text: `use ${shown}` };
}

/** A short "-ing" form for headlines: "edit" -> "edit", used as "tried to edit X". */
export function triedTo(p: Phrase): string {
  return p.text;
}
