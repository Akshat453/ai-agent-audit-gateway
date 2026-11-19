/** Page-level plain-English summaries (ADR-0039). Pure functions over API data, built ONLY
 *  from structured fields with templates (no LLM). Agent-reported strings (paths, commands)
 *  are returned as separate `object` values for the caller to render as escaped code text. */

import { toolPhrase, type Phrase, type Target } from "./actions";
import { eventLabel } from "./event-types";
import { agentKindLabel, agentName, type SessionLike } from "./names";
import { describeRule, reasonInWords, ruleReasons, type RuleBook } from "./rules";
import { RISK_MEANING, plainStatus, riskWord } from "./statuses";
import { ago, clock, later, shortDate } from "./time";

import type { Tz } from "./time";
export type { Tz };
export type Link = { label: string; href: string; external?: boolean };

// ------------------------------------------------------------------ shared inputs (subsets)
export type NodeLike = {
  seq: number; type: string; occurred_at?: string | null; decision?: string | null; status?: string | null;
  reasons: string[]; rules?: string[]; hash_ok: boolean; link_ok?: boolean | null; stored_copy_ok?: boolean;
  epoch_no?: number | null; anchor?: { status: string } | null; risk_level?: string | null;
};
export type CodingLike = { action_type: string; target?: Target | null; diff?: { files: number; added: number; removed: number } | null };
export type ActionLike = {
  action_id: string; run_id: string; status: string; decision: string; risk_level: string; environment: string;
  tool: { id: string; version?: string | null }; agent: { name: string }; error_code?: string | null;
  events: NodeLike[]; approvals: { approval_id: string; state: string; requested_at?: string | null; decisions?: { approver: string; decision: string; decided_at?: string | null }[] }[];
  coding?: CodingLike | null; session?: (SessionLike & { repo_url?: string | null }) | null;
};

// ------------------------------------------------------------------------------ integrity
export type Intact = { ok: boolean; tone: "ok" | "warn" | "bad"; text: string };

export function intactness(nodes: NodeLike[]): Intact {
  const broken = nodes.find((n) => !n.hash_ok || n.link_ok === false || n.stored_copy_ok === false);
  if (broken) {
    return { ok: false, tone: "bad", text: `No - record #${broken.seq} was changed after it was saved. Treat this as an incident and run verification.` };
  }
  if (!nodes.length) return { ok: true, tone: "warn", text: "Nothing recorded yet." };
  const epochs = [...new Set(nodes.map((n) => n.epoch_no).filter((e): e is number => e !== null && e !== undefined))];
  const unsealed = nodes.some((n) => n.epoch_no === null || n.epoch_no === undefined);
  const batch = epochs.length ? `batch ${epochs.join(", ")}` : "";
  if (!epochs.length) return { ok: true, tone: "ok", text: "Yes so far - every record is chained to the one before it. It will be locked into a batch within minutes." };
  const statuses = nodes.map((n) => n.anchor?.status).filter(Boolean) as string[];
  const worst = ["SUBMITTED", "INCLUDED", "FINALIZED"].find((s) => statuses.includes(s));
  const tail = unsealed ? " The newest steps are not locked yet." : "";
  if (!statuses.length) return { ok: true, tone: "ok", text: `Yes - locked in ${batch}; not on a blockchain yet.${tail}` };
  if (worst === "FINALIZED" && statuses.every((s) => s === "FINALIZED")) {
    return { ok: true, tone: "ok", text: `Yes - locked in ${batch} and anchored on the blockchain (permanent).${tail}` };
  }
  return { ok: true, tone: "ok", text: `Yes - locked in ${batch}; ${plainStatus(worst ?? "SUBMITTED").toLowerCase()}, not permanent yet.${tail}` };
}

// --------------------------------------------------------------------------- action story
const OUTCOME_HEAD: Record<string, string> = {
  DENIED: "Blocked", COMPLETED: "Done", FAILED: "Failed", OUTCOME_UNKNOWN: "Result unknown",
  PENDING_APPROVAL: "Waiting for approval", AUTHORIZED: "Allowed", DISPATCHED: "Running", RECONCILED: "Checked by a person",
};

export function actorLabel(a: Pick<ActionLike, "agent" | "session">): string {
  return a.session ? agentKindLabel(a.session.agent_kind, a.session.agent_version) : agentName(a.agent.name);
}

export function phraseOf(a: Pick<ActionLike, "tool" | "coding">): Phrase {
  return toolPhrase(a.tool.id, a.coding ?? null);
}

export type Step = { key: string; label: string; done: boolean; tone: "ok" | "bad" | "warn" | "todo"; at?: string | null; note?: string };

export function plainSteps(a: Pick<ActionLike, "events" | "status" | "decision">): Step[] {
  const find = (...types: string[]) => [...a.events].reverse().find((e) => types.includes(e.type));
  const asked = find("ACTION_REQUESTED");
  const checked = find("POLICY_EVALUATED");
  const approval = find("APPROVAL_REQUIRED", "APPROVAL_GRANTED", "APPROVAL_DENIED", "APPROVAL_EXPIRED");
  const cleared = find("ACTION_AUTHORIZED");
  const started = find("ACTION_DISPATCHED");
  const end = find("ACTION_COMPLETED", "ACTION_FAILED", "ACTION_OUTCOME_UNKNOWN", "ACTION_DENIED", "ACTION_RECONCILED");
  const blocked = a.status === "DENIED";
  const never = blocked ? "never ran, so no change was made" : "not reached yet";
  const steps: Step[] = [
    { key: "asked", label: "Asked", done: !!asked, tone: asked ? "ok" : "todo", at: asked?.occurred_at },
    { key: "checked", label: "Checked", done: !!checked, tone: checked ? (checked.decision === "DENY" ? "bad" : "ok") : "todo", at: checked?.occurred_at,
      note: checked?.decision ? plainStatus(checked.decision) : undefined },
  ];
  if (approval || a.decision === "REQUIRE_APPROVAL") {
    const t = approval?.type;
    steps.push({
      key: "approval", label: t === "APPROVAL_GRANTED" ? "Approved" : t === "APPROVAL_DENIED" ? "Rejected" : t === "APPROVAL_EXPIRED" ? "Expired" : "Waiting for approval",
      done: !!approval, tone: t === "APPROVAL_GRANTED" ? "ok" : t === "APPROVAL_DENIED" || t === "APPROVAL_EXPIRED" ? "bad" : "warn", at: approval?.occurred_at,
    });
  }
  steps.push({ key: "cleared", label: "Cleared", done: !!cleared, tone: cleared ? "ok" : "todo", at: cleared?.occurred_at, note: cleared ? undefined : never });
  steps.push({ key: "started", label: "Started", done: !!started, tone: started ? "ok" : "todo", at: started?.occurred_at,
    note: started ? undefined : cleared && !started ? "the agent runs it on the developer's machine" : never });
  const endLabel = OUTCOME_HEAD[a.status] ?? plainStatus(a.status);
  steps.push({ key: "outcome", label: end ? endLabel : "Outcome", done: !!end || blocked, tone: blocked || a.status === "FAILED" ? "bad" : a.status === "OUTCOME_UNKNOWN" ? "warn" : end ? "ok" : "todo",
    at: end?.occurred_at, note: end || blocked ? undefined : "not reached yet" });
  return steps;
}

export type Story = {
  headline: { lead: string; actor: string; verb: string; object: string | null; where: string };
  happened: string[];
  why: string[];
  who: [string, string][];
  canDo: (Link | { label: string })[];
  intact: Intact;
  object: string | null;
  objectKind: Phrase["kind"];
};

export function actionStory(a: ActionLike, book: RuleBook, tz: Tz = "local"): Story {
  const p = phraseOf(a);
  const actor = actorLabel(a);
  const lead = OUTCOME_HEAD[a.status] ?? plainStatus(a.status);
  const tried = a.status === "DENIED" || a.status === "FAILED" ? "tried to" : a.status === "PENDING_APPROVAL" ? "wants to" : "asked to";
  const where = a.session?.repo ? ` on ${a.session.repo}` : a.environment && !a.session ? ` in ${a.environment}` : "";
  const evaluated = [...a.events].reverse().find((e) => e.type === "POLICY_EVALUATED");
  const rules = evaluated?.rules ?? [];
  const happened: string[] = [];
  const asked = a.events.find((e) => e.type === "ACTION_REQUESTED");
  if (asked) happened.push(`${clock(asked.occurred_at, tz)} - ${actor} asked to ${p.text}${a.coding?.target ? " (as reported by the agent)" : ""}.`);
  if (evaluated) happened.push(`AgentGuard checked its rules and ${evaluated.decision === "DENY" ? "blocked it" : evaluated.decision === "REQUIRE_APPROVAL" ? "asked a person to approve it" : "allowed it"}.`);
  for (const ap of a.approvals) {
    for (const d of ap.decisions ?? []) {
      happened.push(`${d.decision === "APPROVED" ? "Approved" : "Rejected"} by ${d.approver} ${later(ap.requested_at, d.decided_at)}.`.replace(" .", "."));
    }
    if (ap.state === "PENDING") happened.push("Waiting for a person to approve it.");
    if (ap.state === "EXPIRED") happened.push("Nobody decided in time, so the request expired.");
  }
  if (a.status === "DENIED") happened.push("It never ran, so no change was made.");
  else if (a.status === "COMPLETED") happened.push("It finished successfully.");
  else if (a.status === "FAILED") happened.push(`It failed${a.error_code ? ` (${a.error_code})` : ""}.`);
  else if (a.status === "OUTCOME_UNKNOWN") happened.push("AgentGuard cannot tell whether it happened.");
  else if (a.status === "AUTHORIZED" && a.session) happened.push("The agent then ran it on the developer's machine.");
  const diff = a.coding?.diff;
  if (diff) happened.push(`The change touched ${diff.files} file${diff.files === 1 ? "" : "s"} (+${diff.added} / -${diff.removed} lines). File contents are not shown.`);

  const why: string[] = [];
  const decisionWords = a.decision === "DENY" ? "blocked it" : a.decision === "REQUIRE_APPROVAL" ? "asked a person first" : "allowed it";
  const reasons = ruleReasons(book, rules);
  if (reasons.length) {
    for (const r of reasons) why.push(`${r.why} (rule ${r.id})`);
  } else {
    for (const r of evaluated?.reasons ?? []) why.push(reasonInWords(r));
  }
  why.unshift(`AgentGuard ${decisionWords}.`);
  why.push(`Risk: ${riskWord(a.risk_level)} - ${RISK_MEANING[a.risk_level] ?? "unknown impact"}.`);

  const who: [string, string][] = [];
  if (a.session) {
    if (a.session.developer) who.push(["Developer", a.session.developer]);
    who.push(["Agent", agentKindLabel(a.session.agent_kind, a.session.agent_version)]);
    if (a.session.device) who.push(["Device", a.session.device]);
    if (a.session.repo) who.push(["Repository", a.session.repo]);
    if (a.session.issue_number) who.push(["Issue", `#${a.session.issue_number}`]);
  } else {
    who.push(["Agent", agentName(a.agent.name)]);
    who.push(["Environment", a.environment]);
  }

  const canDo: (Link | { label: string })[] = [];
  const pending = a.approvals.find((x) => x.state === "PENDING");
  if (pending) canDo.push({ label: "Approve or reject it", href: `/approvals/${pending.approval_id}` });
  if (a.status === "DENIED") canDo.push({ label: "Nothing needed - this was correctly blocked. If you think it is wrong, open the policy rule." });
  if (a.status === "OUTCOME_UNKNOWN") canDo.push({ label: "Check what really happened and record it", href: "/incidents?kind=outcome_unknown" });
  if (a.status === "COMPLETED" || a.status === "AUTHORIZED") canDo.push({ label: "Nothing needed." });
  // the most specific rule: a content/command finding over a generic path or repository rule
  const top = reasons.find((r) => !/^(PATH-|REPO-OVERLAY)/.test(r.id)) ?? reasons[0];
  if (top) canDo.push({ label: `Think this is a false positive? See rule ${top.id}`, href: `/policies?rule=${encodeURIComponent(top.id)}` });
  const path = a.coding?.target?.paths?.[0];
  const gh = a.session?.repo_url && /^https:\/\/github\.com\//.test(a.session.repo_url) ? a.session.repo_url.replace(/\.git$/, "") : null;
  if (gh && path) canDo.push({ label: "View the file in GitHub", href: `${gh}/blob/HEAD/${path}`, external: true });
  canDo.push({ label: "Open the whole session", href: `/runs/${a.run_id}` });
  canDo.push({ label: "Run an integrity check", href: "/verification" });

  return {
    headline: { lead, actor, verb: tried, object: p.object, where },
    happened, why, who, canDo, intact: intactness(a.events), object: p.object, objectKind: p.kind,
  };
}

/** The headline as one plain string (tests, titles, screen readers). */
export function headlineText(s: Story, p: Phrase): string {
  const what = p.object && p.kind !== "command" ? `${p.verb} ${p.object}` : p.text;
  return `${s.headline.lead}: ${s.headline.actor} ${s.headline.verb} ${what}${s.headline.where}.`;
}

// ------------------------------------------------------------------------------- runs
export type RunRowLike = { run_id: string; agents: string[]; actions: number; statuses: Record<string, number>; decisions?: Record<string, number>; first_at?: string | null; session?: SessionLike | null };

export function runCounts(r: Pick<RunRowLike, "actions" | "decisions" | "statuses">): string {
  const d = r.decisions ?? {};
  const parts = [
    d.ALLOW ? `${d.ALLOW} allowed` : "",
    d.DENY ? `${d.DENY} blocked` : "",
    d.REQUIRE_APPROVAL ? `${d.REQUIRE_APPROVAL} needed approval` : "",
  ].filter(Boolean);
  return `${r.actions} action${r.actions === 1 ? "" : "s"}${parts.length ? `: ${parts.join(", ")}` : ""}`;
}

export type RunEventLike = {
  seq: number; type: string; occurred_at?: string | null; action_id?: string | null; tool?: { id?: string } | Record<string, unknown> | null;
  decision?: string | null; status?: string | null; approval?: Record<string, unknown> | null; actor?: Record<string, unknown>;
  rules?: string[]; reasons?: string[]; code?: string | null; detail?: string | null;
};

export type StepKind = "command" | "edit" | "read" | "delete" | "search" | "web" | "tool" | "git" | "github" | "security" | "other";
export type Outcome = { text: string; tone: "ok" | "bad" | "warn" | "info" };

export type StoryLine = {
  at?: string | null; actionId?: string | null;
  kind: StepKind;
  /** Short noun for the step: "Command", "Edit file", "GitHub". */
  label: string;
  /** The agent-reported target (command, path, tool), shown as escaped code; or plain text. */
  object: string | null;
  /** When there is no object: what it was, in words. */
  text: string;
  outcome: Outcome;
  /** "needed approval", "approved by akshat 2 min later" ... (only when a person was involved). */
  approval: string[];
  why?: string | null;
  /** Legacy: every decision step, in order. */
  steps: { text: string; tone: "ok" | "bad" | "warn" | "info" }[];
  verb: string;
};

const KIND_OF: Record<string, [StepKind, string]> = {
  command_exec: ["command", "Command"], git_op: ["git", "Git"], file_write: ["edit", "Edit file"], file_read: ["read", "Read file"],
  file_delete: ["delete", "Delete file"], search: ["search", "Search"], web_fetch: ["web", "Web page"], mcp_call: ["tool", "Tool"],
};

const SECURITY_WORDS: Record<string, string> = {
  CODING_UNDECIDED_ACTION: "The agent reported doing something AgentGuard had not been asked about",
  AGENT_ON_HUMAN_ENDPOINT: "The agent tried to use a page meant only for people",
  AGENT_ID_MISMATCH: "An agent used credentials that are not its own",
  DELEGATION_REFUSED: "An agent tried to give another agent more power than it has",
};

export function runStory(events: RunEventLike[], coding: Record<string, CodingLike>, people: Record<string, string>, book?: RuleBook): StoryLine[] {
  const lines: StoryLine[] = [];
  const byAction = new Map<string, StoryLine & { requestedAt?: string | null; decided?: boolean }>();
  for (const e of events) {
    if (e.type === "SECURITY_VIOLATION") {
      const what = SECURITY_WORDS[e.code ?? ""] ?? "Security problem detected";
      lines.push({ at: e.occurred_at, kind: "security", label: "Security", object: null, verb: "",
        text: `${what}${e.detail ? ` (${e.detail.replaceAll("_", " ")})` : ""}.`, outcome: { text: "Flagged", tone: "warn" }, approval: [], steps: [] });
      continue;
    }
    if (!e.action_id) {
      lines.push({ at: e.occurred_at, kind: "other", label: "Log", object: null, verb: "", text: eventLabel(e.type), outcome: { text: "Recorded", tone: "info" }, approval: [], steps: [] });
      continue;
    }
    let line = byAction.get(e.action_id);
    if (!line) {
      const toolId = (e.tool as { id?: string } | null)?.id ?? null;
      const c = coding[e.action_id] ?? null;
      const p = toolPhrase(toolId, c);
      let [kind, label] = c ? KIND_OF[c.action_type] ?? ["other", "Step"] : toolId?.startsWith("cx_") ? (["github", "GitHub"] as [StepKind, string]) : (["other", "Step"] as [StepKind, string]);
      let object = p.object;
      let text = p.text;
      const mcp = c?.target?.mcp_tool ?? "";
      if (kind === "tool" && /^agentguard\//.test(mcp)) {
        // AgentGuard's own tools (read issue, submit, open PR) in words
        kind = "github"; label = "GitHub"; object = null; text = toolPhrase(mcp.slice("agentguard/".length)).text;
      }
      if (!object || kind === "command" || kind === "git") text = text.charAt(0).toUpperCase() + text.slice(1);
      line = { at: e.occurred_at, actionId: e.action_id, kind, label, object, text, verb: p.object ? `Asked to ${p.verb}` : `Asked to ${p.text}`,
        outcome: { text: "Allowed", tone: "ok" }, approval: [], steps: [], requestedAt: e.occurred_at };
      byAction.set(e.action_id, line);
      lines.push(line);
    }
    const decided = line.decided === true;
    if (e.type === "POLICY_EVALUATED" && decided && e.decision !== "DENY") continue; // re-check of the approved retry
    const step = storyStep(e, people, line.requestedAt);
    if (step) line.steps.push(step);
    switch (e.type) {
      case "POLICY_EVALUATED":
        if (e.decision === "DENY") line.outcome = { text: "Blocked", tone: "bad" };
        else if (e.decision === "REQUIRE_APPROVAL") { line.outcome = { text: "Waiting for approval", tone: "warn" }; line.approval.push("needed approval"); }
        else line.outcome = { text: "Allowed", tone: "ok" };
        if (e.decision && e.decision !== "ALLOW") {
          const why = book ? ruleReasons(book, e.rules ?? []) : [];
          // the specific finding (content, command, network...) over the generic "sensitive path"
          const best = why.find((r) => !r.id.startsWith("PATH-")) ?? why[0];
          line.why = best?.why ?? (e.reasons?.[0] ? reasonInWords(e.reasons[0]) : null);
        }
        break;
      case "APPROVAL_GRANTED":
        line.decided = true;
        line.approval.push(`approved by ${people[String(e.approval?.approver ?? "")] ?? "a person"} ${later(line.requestedAt, e.occurred_at)}`.trim());
        line.outcome = { text: "Approved", tone: "ok" };
        break;
      case "APPROVAL_DENIED":
        line.decided = true;
        line.approval.push(`rejected by ${people[String(e.approval?.approver ?? "")] ?? "a person"}`);
        line.outcome = { text: "Rejected", tone: "bad" };
        break;
      case "APPROVAL_EXPIRED": line.outcome = { text: "Expired - did not run", tone: "bad" }; break;
      case "ACTION_DENIED": line.outcome = { text: "Blocked", tone: "bad" }; break;
      case "ACTION_COMPLETED": line.outcome = { text: line.decided ? "Approved · ran" : "Ran", tone: "ok" }; break;
      case "ACTION_FAILED": line.outcome = { text: "Failed", tone: "bad" }; break;
      case "ACTION_OUTCOME_UNKNOWN": line.outcome = { text: "Result unknown", tone: "warn" }; break;
      case "ACTION_RECONCILED": line.outcome = { text: "Checked by a person", tone: "info" }; break;
      default: break;
    }
  }
  return lines;
}

function storyStep(e: RunEventLike, people: Record<string, string>, since?: string | null): StoryLine["steps"][number] | null {
  switch (e.type) {
    case "POLICY_EVALUATED":
      return e.decision === "DENY" ? { text: "blocked", tone: "bad" } : e.decision === "REQUIRE_APPROVAL" ? { text: "needed approval", tone: "warn" } : { text: "allowed", tone: "ok" };
    case "APPROVAL_GRANTED": {
      const who = people[String(e.approval?.approver ?? "")] ?? "a person";
      return { text: `approved by ${who} ${later(since, e.occurred_at)}`.trim(), tone: "ok" };
    }
    case "APPROVAL_DENIED": {
      const who = people[String(e.approval?.approver ?? "")] ?? "a person";
      return { text: `rejected by ${who}`, tone: "bad" };
    }
    case "APPROVAL_EXPIRED": return { text: "approval expired", tone: "bad" };
    case "ACTION_COMPLETED": return { text: "done", tone: "ok" };
    case "ACTION_FAILED": return { text: "failed", tone: "bad" };
    case "ACTION_OUTCOME_UNKNOWN": return { text: "result unknown", tone: "warn" };
    case "ACTION_RECONCILED": return { text: "checked by a person", tone: "info" };
    default: return null;
  }
}

/** Counts for the story header: "43 steps: 33 allowed, 2 blocked, 8 needed a person". */
export function storyCounts(lines: StoryLine[]): string {
  const steps = lines.filter((l) => l.actionId);
  const blocked = steps.filter((l) => l.outcome.tone === "bad").length;
  const person = steps.filter((l) => l.approval.length && l.outcome.tone !== "bad").length;
  return `${steps.length} step${steps.length === 1 ? "" : "s"}: ${steps.length - blocked - person} went ahead on their own, ${person} needed a person, ${blocked} blocked or did not run`;
}

// ----------------------------------------------------------------------------- approvals
export type ApprovalRowLike = {
  tool: { id: string }; agent: { name: string }; risk_level: string; expires_at?: string | null; state: string;
  action_type?: string | null; target?: string | null; agent_kind?: string | null; issue_number?: number | null;
};

export function approvalRequest(r: ApprovalRowLike): { actor: string; verb: string; object: string | null; tail: string } {
  const actor = r.agent_kind ? agentKindLabel(r.agent_kind) : agentName(r.agent.name);
  void r.state;
  const p = r.action_type ? toolPhrase(null, { action_type: r.action_type, target: targetFromShort(r.action_type, r.target) }) : toolPhrase(r.tool.id);
  const tail = r.issue_number ? ` for issue #${r.issue_number}` : "";
  // A command is summarised in lists; the whole command is on the approval page (ADR-0043).
  if (p.kind === "command" || !p.object) return { actor, verb: p.text, object: null, tail };
  return { actor, verb: p.verb, object: p.object, tail };
}

function targetFromShort(actionType: string, short: string | null | undefined): Target | null {
  if (!short) return null;
  if (["file_read", "file_write", "file_delete"].includes(actionType)) return { paths: [short] };
  if (actionType === "web_fetch") return { url: short };
  if (actionType === "search") return { query: short };
  if (actionType === "mcp_call") return { mcp_tool: short };
  return { command: short };
}

/** "wants to" while waiting, "asked to" once decided. */
export function wantsTo(state: string): string {
  return state === "PENDING" ? "wants to" : "asked to";
}

export function approvalRisk(r: Pick<ApprovalRowLike, "risk_level" | "expires_at" | "state">, now: number): string {
  const risk = `Risk: ${riskWord(r.risk_level)} (${RISK_MEANING[r.risk_level] ?? "unknown impact"}).`;
  if (r.state !== "PENDING" || !r.expires_at) return `${risk} ${plainStatus(r.state)}.`;
  const left = Date.parse(r.expires_at) - now;
  return left <= 0 ? `${risk} Expired.` : `${risk} Expires ${ago(r.expires_at, now)}.`;
}

// ------------------------------------------------------------------------------- overview
export function today(o: { actions: number; denied: number; pending: number; evidence: string; rangeLabel: string }): string {
  const ev = o.evidence === "VERIFIED" ? "all evidence is intact"
    : ["TAMPERED", "INVALID_PROOF", "UNTRUSTED_ANCHOR"].includes(o.evidence) ? "the evidence check found a problem - see Verification"
      : o.evidence === "UNANCHORED" ? "evidence is recorded and chained (not yet on the blockchain)"
        : "the last evidence check did not finish";
  return `Agents took ${o.actions.toLocaleString("en-US")} action${o.actions === 1 ? "" : "s"} in the last ${o.rangeLabel}. ${o.denied} ${o.denied === 1 ? "was" : "were"} blocked, ${o.pending} ${o.pending === 1 ? "is" : "are"} waiting for you, and ${ev}.`;
}

// ------------------------------------------------------------------------------- epochs
export const CHAINS: Record<number, string> = { 1: "Ethereum", 8453: "Base", 84532: "Base Sepolia", 11155111: "Sepolia", 31337: "the local test chain (Anvil)" };

export type EpochLike = {
  epoch_no: number; tree_size: number; sealed_at?: string | null; anchor_status?: string | null;
  submitted_at?: string | null; included_at?: string | null; finalized_at?: string | null;
};

export function epochSentence(e: EpochLike, chainId: number | null | undefined, tz: Tz): string {
  const chain = chainId ? CHAINS[chainId] ?? `chain ${chainId}` : "the blockchain";
  const head = `Batch ${e.epoch_no} locked at ${shortDate(e.sealed_at, tz)} with ${e.tree_size} record${e.tree_size === 1 ? "" : "s"}`;
  switch (e.anchor_status) {
    case "FINALIZED": return `${head}; recorded on ${chain} at ${shortDate(e.included_at ?? e.finalized_at, tz)}; now permanent.`;
    case "INCLUDED": return `${head}; recorded on ${chain} at ${shortDate(e.included_at, tz)}; waiting to become permanent.`;
    case "SUBMITTED": return `${head}; sent to ${chain} at ${shortDate(e.submitted_at, tz)}; waiting for it to be included.`;
    default: return `${head}; not sent to a blockchain yet.`;
  }
}

export function epochSteps(e: EpochLike): { label: string; done: boolean }[] {
  const order = ["SEALED", "SUBMITTED", "INCLUDED", "FINALIZED"];
  const at = Math.max(0, order.indexOf(e.anchor_status ?? "SEALED"));
  return ["Locked", "Sent", "Included", "Permanent"].map((label, i) => ({ label, done: i <= at }));
}

// --------------------------------------------------------------------------- verification
export type ReportLike = { result: string; reason?: string | null; first_seq?: number | null; last_seq?: number | null };

export function verificationWords(r: ReportLike, full?: Record<string, unknown> | null): { headline: string; next: string; tone: "ok" | "bad" | "warn" } {
  const chain = (full?.chain ?? {}) as { events_checked?: number; first_bad_seq?: number | null };
  const stored = (full?.stored_copy ?? {}) as { mismatched_seqs?: number[] };
  const n = chain.events_checked ?? (r.first_seq !== null && r.first_seq !== undefined && r.last_seq !== null && r.last_seq !== undefined ? r.last_seq - r.first_seq + 1 : null);
  switch (r.result) {
    case "VERIFIED":
      return { tone: "ok", headline: `All ${n !== null ? n.toLocaleString("en-US") + " " : ""}records checked - nothing was changed.`, next: "Nothing to do." };
    case "TAMPERED": {
      const bad = chain.first_bad_seq ?? stored.mismatched_seqs?.[0];
      return { tone: "bad", headline: bad !== undefined && bad !== null ? `Record #${bad} was changed after it was saved.` : "A record was changed after it was saved.",
        next: "Treat this as a security incident: export the evidence, tell your security team, and do not edit the database." };
    }
    case "UNANCHORED":
      return { tone: "warn", headline: "Every record checks out, but the newest batches are not on the blockchain yet.", next: "Usually fine - wait a few minutes. If it stays this way for hours, check anchoring on the Overview's System health." };
    case "INCOMPLETE":
      return { tone: "warn", headline: "Nothing was found changed, but some records could not be checked.", next: "Look at the reason below; a missing record or an unreachable blockchain is the usual cause." };
    case "ERROR":
      return { tone: "warn", headline: "The check could not finish.", next: "Run it again. If it keeps failing, look at the reason in the technical details." };
    default:
      return { tone: "bad", headline: plainStatus(r.result), next: "Treat this as a security incident and contact your security team." };
  }
}

// ------------------------------------------------------------------------------ incidents
export const INCIDENT_KINDS: Record<string, { label: string; todo: string }> = {
  denied: { label: "Blocked", todo: "Usually nothing: AgentGuard stopped an action it should not take. Look if the same block repeats." },
  outcome_unknown: { label: "Result unknown", todo: "Check in the other system whether it happened, then record the result (an admin can do this below)." },
  failed: { label: "Failed", todo: "The tool reported an error. Look at the code; retry from the agent if needed." },
  security: { label: "Security problem", todo: "An agent did something it is not allowed to (for example tried to approve itself). Tell your security team." },
  alerts: { label: "Monitoring alert", todo: "The integrity monitor raised an alert. Open Verification for details." },
};

export type IncidentLike = { kind: string; tool?: string | null; status?: string | null; code?: string | null; at?: string | null };

export function incidentSentence(i: IncidentLike): string {
  const what = i.tool ? toolPhrase(i.tool).text : null;
  switch (i.kind) {
    case "denied": return `An agent was blocked from trying to ${what ?? "do something"}${i.code ? ` (${i.code})` : ""}.`;
    case "outcome_unknown": return `Nobody knows whether "${what ?? "an action"}" happened.`;
    case "failed": return `"${what ?? "An action"}" failed${i.code ? ` with ${i.code}` : ""}.`;
    case "security": return `Security problem: ${i.code === "AGENT_ON_HUMAN_ENDPOINT" ? "an agent tried to use a page meant only for people" : i.code === "CODING_UNDECIDED_ACTION" ? "a coding agent did something AgentGuard never allowed" : i.code ?? "unknown"}.`;
    case "alerts": return `Monitoring alert: ${i.code ?? "see Verification"}.`;
    default: return `${i.kind}: ${i.code ?? ""}`;
  }
}

// ---------------------------------------------------------------------------- connectors
export function connectorWords(c: { name: string; status: string; type_id?: string; config?: Record<string, unknown> }, lastCheck?: string | null, now?: number): string {
  const repos = Array.isArray(c.config?.repos) ? (c.config.repos as string[]) : [];
  const status = c.status === "connected" ? "connected" : c.status === "disabled" ? "turned off" : "needs attention";
  const to = c.status === "connected" && repos.length ? ` to ${repos.join(", ")}` : "";
  const checked = lastCheck && now ? `, last checked ${ago(lastCheck, now)}` : "";
  return `${c.name}: ${status}${to}${checked}.`;
}

// ------------------------------------------------------------------------- repo proposals
export function proposalItem(it: Record<string, unknown>): string {
  const v = String(it.value ?? it.path ?? "");
  switch (it.op) {
    case "add_allow_command": return `Allow the command "${v}"`;
    case "add_allow_path": return `Allow agents to change "${v}" without the usual review`;
    case "remove_deny_command": return `Stop blocking the command "${v}"`;
    case "remove_deny_path": return `Stop blocking the path "${v}"`;
    case "remove_sensitive": return `Stop treating "${v}" as sensitive`;
    case "downgrade_sensitive": return `Lower "${v}" to ${String(it.level ?? "a lower")} sensitivity`;
    default: return `Change: ${String(it.op ?? "unknown")} ${v}`;
  }
}

// ------------------------------------------------------------------------- policy changes
export type RuleDoc = { rule_id: string; effect: string };

export function policyChanges(prev: { rules?: RuleDoc[]; default_effect?: string } | null, next: { rules?: RuleDoc[]; default_effect?: string }, book: RuleBook): string[] {
  if (!prev) return ["First version."];
  const before = new Map((prev.rules ?? []).map((r) => [r.rule_id, r]));
  const after = new Map((next.rules ?? []).map((r) => [r.rule_id, r]));
  const out: string[] = [];
  const name = (id: string) => { const d = describeRule(book, id); return d.known ? `"${d.name}" (${id})` : id; };
  for (const [id, r] of after) {
    const old = before.get(id);
    if (!old) out.push(`Added: ${name(id)} - ${effectWord(r.effect)}.`);
    else if (old.effect !== r.effect) out.push(`Changed: ${name(id)} now ${effectWord(r.effect)} (was ${effectWord(old.effect)}).`);
  }
  for (const id of before.keys()) if (!after.has(id)) out.push(`Removed: ${name(id)}.`);
  if (prev.default_effect !== next.default_effect) out.push(`Anything no rule covers is now ${effectWord(next.default_effect ?? "")}.`);
  return out.length ? out : ["No rule changes (wording or metadata only)."];
}

export function effectWord(effect: string): string {
  return effect === "ALLOW" ? "allowed" : effect === "DENY" ? "blocked" : effect === "REQUIRE_APPROVAL" ? "needs approval" : effect.toLowerCase();
}

