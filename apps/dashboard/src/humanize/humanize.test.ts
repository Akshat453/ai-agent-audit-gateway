import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import { ALL_RISKS, ALL_STATUSES } from "../../lib/status";
import {
  CODING_VERBS, EVENT_TYPES, GLOSSARY, PLAIN_STATUS, REASON_CODES, TOOL_PHRASES, actionStory, agentKindLabel, agentName,
  approvalRequest, codingPhrase, githubRunTitle, describeRule, epochSentence, eventSentence, explainHeader, gitVerb, intactness, later,
  plainSteps, policyChanges, proposalItem, runCounts, runStory, ruleReasons, sessionTitle, today, toolPhrase, verificationWords,
  type ActionLike, type RuleBook,
} from "./index";

const REPO = join(__dirname, "..", "..", "..", "..");
const src = (p: string) => readFileSync(join(REPO, p), "utf8");

// ------------------------------------------------------------------ completeness (labels)
test("every evidence event type in the schema has a label and a sentence", () => {
  const types = [...src("packages/schemas/src/agw_schemas/events.py").matchAll(/_header\(\s*"([A-Z_]+)"/g)].map((m) => m[1] as string);
  expect(types.length).toBeGreaterThan(25);
  expect(types.filter((t) => !EVENT_TYPES[t])).toEqual([]);
  for (const t of types) expect(eventSentence(t, {}).length).toBeGreaterThan(5);
});

test("every status, decision and risk has plain words", () => {
  expect([...ALL_STATUSES, ...ALL_RISKS].filter((s) => !PLAIN_STATUS[s])).toEqual([]);
});

test("every coding action type and every GitHub action has a verb phrase", () => {
  const model = src("apps/gateway/src/agw_gateway/coding/model.py");
  const block = model.slice(model.indexOf("ActionType = Literal["), model.indexOf("]", model.indexOf("ActionType = Literal[")));
  const kinds = [...block.matchAll(/"([a-z_]+)"/g)].map((m) => m[1] as string);
  expect(kinds.length).toBeGreaterThanOrEqual(8);
  expect(kinds.filter((k) => !CODING_VERBS[k])).toEqual([]);
  const gh = [...src("apps/gateway/src/agw_gateway/connectors/types/github.py").matchAll(/name="([a-z_]+)"/g)].map((m) => m[1] as string);
  expect(gh.length).toBe(7);
  expect(gh.filter((a) => !TOOL_PHRASES[a])).toEqual([]);
});

test("every policy reason code has words", () => {
  const engine = src("apps/gateway/src/agw_gateway/policies/engine.py");
  const block = engine.slice(engine.indexOf("class ReasonCode"), engine.indexOf("\n\n\n", engine.indexOf("class ReasonCode")));
  const codes = [...block.matchAll(/= "([A-Z_]+)"/g)].map((m) => m[1] as string);
  expect(codes.length).toBeGreaterThan(20);
  expect(codes.filter((c) => !REASON_CODES[c])).toEqual([]);
});

test("every rule id in the gateway's description files resolves; patterns fill the suffix", () => {
  const files = ["apps/gateway/src/agw_gateway/coding/policies/coding-mintrail-descriptions.toml", "apps/gateway/src/agw_gateway/policies/rule_descriptions.toml"];
  const book: RuleBook = { rules: {}, patterns: {} };
  for (const f of files) {
    for (const m of src(f).matchAll(/\[(rules|patterns)\."([^"]+)"\]\s*\nname = "([^"]+)"\s*\nwhy = "([^"]+)"/g)) {
      book[m[1] as "rules" | "patterns"][m[2] as string] = { name: m[3] as string, why: m[4] as string };
    }
  }
  expect(Object.keys(book.rules).length).toBeGreaterThan(90);
  for (const id of Object.keys(book.rules)) expect(describeRule(book, id).known).toBe(true);
  expect(describeRule(book, "REPO-OVERLAY-v3").why).toBe("Extra rules set by the repository (.agentguard.yaml), version 3.");
  expect(describeRule(book, "CONTENT-SIGNATURE-BYPASS").why).toBe("The change would remove webhook signature checks.");
  expect(describeRule(book, "NOPE").known).toBe(false);
  expect(ruleReasons(book, ["PATH-LOW", "PATH-HIGH", "CONTENT-SIGNATURE-BYPASS"]).map((r) => r.id)).toEqual(["PATH-HIGH", "CONTENT-SIGNATURE-BYPASS"]);
});

test("the glossary covers the core terms", () => {
  for (const t of ["run", "action", "epoch", "sealed", "anchored", "finalized", "hash", "prev hash", "proof", "policy version", "LOW", "CRITICAL", "A2S", "A2H", "SYS", "connector", "tenant", "device", "approval", "step-up", "tier"]) {
    expect(GLOSSARY[t], t).toBeTruthy();
  }
});

// --------------------------------------------------------------------- templates (snapshots)
const BOOK: RuleBook = {
  rules: { "CONTENT-SIGNATURE-BYPASS": { name: "Signature bypass", why: "The change would remove webhook signature checks." }, "PATH-HIGH": { name: "Sensitive code", why: "This file holds sensitive logic." } },
  patterns: { "REPO-OVERLAY-v*": { name: "Repository rules", why: "Extra rules set by the repository (.agentguard.yaml), version {suffix}." } },
};

const DENIED: ActionLike = {
  action_id: "a1", run_id: "r1", status: "DENIED", decision: "DENY", risk_level: "CRITICAL", environment: "dev",
  tool: { id: "coding.file_write", version: "1" }, agent: { name: "device:akshat:Akshats-MacBook-Air:01a1efb5" },
  events: [
    { seq: 10, type: "ACTION_REQUESTED", reasons: [], hash_ok: true, link_ok: true, stored_copy_ok: true, occurred_at: "2026-11-18T17:48:00Z" },
    { seq: 11, type: "POLICY_EVALUATED", decision: "DENY", reasons: ["x"], rules: ["PATH-HIGH", "CONTENT-SIGNATURE-BYPASS"], hash_ok: true, link_ok: true, stored_copy_ok: true, epoch_no: 45, anchor: { status: "FINALIZED" } },
    { seq: 12, type: "ACTION_DENIED", reasons: [], hash_ok: true, link_ok: true, stored_copy_ok: true, epoch_no: 45, anchor: { status: "FINALIZED" } },
  ],
  approvals: [],
  coding: { action_type: "file_write", target: { paths: ["signal/src/sign.ts"] }, diff: { files: 1, added: 2, removed: 1 } },
  session: { agent_kind: "claude_code", agent_version: "2.1.319", developer: "akshat", device: "Akshats-MacBook-Air", repo: "MintRail", issue_number: 17, repo_url: "https://github.com/Akshat453/MintRail.git" },
};

test("action story: blocked coding edit (the design example)", () => {
  const s = actionStory({ ...DENIED, events: DENIED.events.map((e) => ({ ...e, epoch_no: e.epoch_no ?? 45, anchor: e.anchor ?? { status: "FINALIZED" } })) }, BOOK, "utc");
  expect(`${s.headline.lead}: ${s.headline.actor} ${s.headline.verb} edit ${s.object}${s.headline.where}.`).toBe("Blocked: Claude Code 2.x tried to edit signal/src/sign.ts on MintRail.");
  expect(s.why).toEqual([
    "AgentGuard blocked it.",
    "This file holds sensitive logic. (rule PATH-HIGH)",
    "The change would remove webhook signature checks. (rule CONTENT-SIGNATURE-BYPASS)",
    "Risk: Critical - could cause serious harm.",
  ]);
  expect(s.happened).toContain("It never ran, so no change was made.");
  expect(s.happened).toContain("The change touched 1 file (+2 / -1 lines). File contents are not shown.");
  expect(s.who).toEqual([["Developer", "akshat"], ["Agent", "Claude Code 2.x"], ["Device", "Akshats-MacBook-Air"], ["Repository", "MintRail"], ["Issue", "#17"]]);
  expect(s.canDo.map((c) => c.label)).toContain("Nothing needed - this was correctly blocked. If you think it is wrong, open the policy rule.");
  expect(s.canDo.map((c) => c.label)).toContain("Think this is a false positive? See rule CONTENT-SIGNATURE-BYPASS");
  expect(s.canDo).toContainEqual({ label: "View the file in GitHub", href: "https://github.com/Akshat453/MintRail/blob/HEAD/signal/src/sign.ts", external: true });
  expect(s.intact.text).toBe("Yes - locked in batch 45 and anchored on the blockchain (permanent).");
  expect(plainSteps(DENIED).map((x) => `${x.label}:${x.done ? "done" : x.note}`)).toEqual([
    "Asked:done", "Checked:done", "Cleared:never ran, so no change was made", "Started:never ran, so no change was made", "Blocked:done",
  ]);
});

test("intactness reports a changed record", () => {
  expect(intactness([{ seq: 7, type: "X", reasons: [], hash_ok: true, stored_copy_ok: false }]).text).toBe(
    "No - record #7 was changed after it was saved. Treat this as an incident and run verification.");
});

test("phrases, names and times", () => {
  expect(codingPhrase("command_exec", { command: "pnpm test" }).text).toBe("run `pnpm test`");
  expect(codingPhrase("git_op", { command: "git checkout -b fix/MR-1" }).text).toBe("switch branches (git checkout -b fix/MR-1)");
  expect(codingPhrase("mcp_call", { mcp_tool: "issue_get", mcp_server: "agentguard" }).text).toBe("use agentguard/issue_get via MCP");
  expect(gitVerb("git -c core.x=1 commit -m x")).toBe("commit changes");
  expect(toolPhrase("cx_gh_github_pr_create").text).toBe("open a pull request");
  expect(toolPhrase("send_email").text).toBe("send an email");
  expect(agentName("device:akshat:Akshats-MacBook-Air:01a1efb5")).toBe("akshat on Akshats-MacBook-Air");
  expect(agentName("device:adam:seedlaptop")).toBe("adam on seedlaptop");
  expect(agentKindLabel("claude_code", "2.1.319")).toBe("Claude Code 2.x");
  expect(agentKindLabel("mcp_generic")).toBe("VS Code (MCP)");
  expect(sessionTitle({ agent_kind: "claude_code", developer: "akshat", repo: "MintRail", issue_number: 12 })).toBe("Claude Code session by akshat on MintRail - issue #12");
  expect(sessionTitle(null, "2026-11-18T17:48:00Z", "utc")).toBe("Session started 18 Nov, 5:48 PM");
  expect(later("2026-11-18T10:00:00Z", "2026-11-18T10:05:00Z")).toBe("5 min later");
  expect(githubRunTitle(["device:akshat:Akshats-MacBook-Air:01a1efb5"], ["Akshat453/MintRail"])).toBe("GitHub steps by akshat on MintRail");
  expect(later("2026-11-18T10:00:00Z", "2026-11-18T10:00:02Z")).toBe("right away");
});

test("run, approval, overview, epoch, verification, proposal and policy sentences", () => {
  expect(runCounts({ actions: 14, statuses: {}, decisions: { ALLOW: 11, DENY: 2, REQUIRE_APPROVAL: 1 } })).toBe("14 actions: 11 allowed, 2 blocked, 1 needed approval");
  const story = runStory([
    { seq: 1, type: "ACTION_REQUESTED", action_id: "a", tool: { id: "coding.file_write" }, occurred_at: "2026-11-18T17:48:00Z" },
    { seq: 2, type: "POLICY_EVALUATED", action_id: "a", decision: "REQUIRE_APPROVAL" },
    { seq: 3, type: "APPROVAL_GRANTED", action_id: "a", approval: { approver: "h1" }, occurred_at: "2026-11-18T17:53:00Z" },
    { seq: 4, type: "POLICY_EVALUATED", action_id: "a", decision: "REQUIRE_APPROVAL" }, // the retry's re-check
    { seq: 5, type: "ACTION_COMPLETED", action_id: "a" },
  ], { a: { action_type: "file_write", target: { paths: ["api/src/refunds/service.ts"] } } }, { h1: "akshat" });
  expect(story[0]?.verb).toBe("Asked to edit");
  expect(story[0]?.object).toBe("api/src/refunds/service.ts");
  expect(story[0]?.steps.map((x) => x.text)).toEqual(["needed approval", "approved by akshat 5 min later", "done"]);
  const q = approvalRequest({ tool: { id: "coding.file_write" }, agent: { name: "device:a:b" }, risk_level: "HIGH", state: "PENDING", action_type: "file_write", target: "ledger/src/journal.ts", agent_kind: "claude_code", issue_number: 1 });
  expect(`${q.actor} wants to ${q.verb} ${q.object}${q.tail}.`).toBe("Claude Code wants to edit ledger/src/journal.ts for issue #1.");
  expect(today({ actions: 342, denied: 12, pending: 3, evidence: "VERIFIED", rangeLabel: "24 h" })).toBe(
    "Agents took 342 actions in the last 24 h. 12 were blocked, 3 are waiting for you, and all evidence is intact.");
  expect(epochSentence({ epoch_no: 45, tree_size: 37, sealed_at: "2026-11-18T17:49:00Z", anchor_status: "FINALIZED", included_at: "2026-11-18T17:51:00Z" }, 84532, "utc")).toBe(
    "Batch 45 locked at 18 Nov, 5:49 PM with 37 records; recorded on Base Sepolia at 18 Nov, 5:51 PM; now permanent.");
  expect(verificationWords({ result: "VERIFIED" }, { chain: { events_checked: 1204 } }).headline).toBe("All 1,204 records checked - nothing was changed.");
  expect(verificationWords({ result: "TAMPERED" }, { chain: { first_bad_seq: 202 } }).headline).toBe("Record #202 was changed after it was saved.");
  expect(proposalItem({ op: "add_allow_command", value: "make demo" })).toBe('Allow the command "make demo"');
  expect(policyChanges({ rules: [{ rule_id: "a", effect: "ALLOW" }] }, { rules: [{ rule_id: "a", effect: "DENY" }, { rule_id: "b", effect: "REQUIRE_APPROVAL" }] }, BOOK)).toEqual([
    "Changed: a now blocked (was allowed).", "Added: b - needs approval.",
  ]);
});

test("event headers in words, built from structured fields only", () => {
  const e = explainHeader({ type: "POLICY_EVALUATED", tool: { id: "coding.file_write" }, policy: { effect: "DENY", rules: ["CONTENT-SIGNATURE-BYPASS"], id: "coding-mintrail", ver: 2 }, risk: { level: "CRITICAL", score: 90 }, actor: { kind: "gateway" }, class: "SYS" }, BOOK);
  expect(e.headline).toBe("AgentGuard checked the rules for the request to edit a file and blocked it.");
  expect(e.details).toContain("The change would remove webhook signature checks. (rule CONTENT-SIGNATURE-BYPASS)");
});

// ---------------------------------------------------------------------- escaping & canaries
test("agent-supplied text is passed through as data, never interpreted", () => {
  const evil = '<img src=x onerror="window.__xss=1"><script>alert(1)</script>';
  const p = codingPhrase("file_write", { paths: [evil] });
  expect(p.object).toBe(evil); // returned verbatim as a separate value; React renders it as text
  expect(p.kind).toBe("path");
  const q = approvalRequest({ tool: { id: "coding.command_exec" }, agent: { name: evil }, risk_level: "LOW", state: "PENDING" });
  expect(q.actor).toBe(evil);
});

test("summaries never contain file contents or secrets they were not given", () => {
  const CANARY = "CANARY_CONTENT_9d1";
  // The API gives the console diff COUNTS only; a story built from it cannot leak content.
  const s = actionStory({ ...DENIED, coding: { action_type: "file_write", target: { paths: ["a.ts"] }, diff: { files: 1, added: 1, removed: 0 } } }, BOOK);
  expect(JSON.stringify(s)).not.toContain(CANARY);
  expect(JSON.stringify(s)).not.toContain("skipSignature");
});
