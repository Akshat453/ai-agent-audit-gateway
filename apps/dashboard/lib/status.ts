/** The ONE status mapping table (16-dashboard-design.md §3.1). <StatusBadge> and <RiskBadge>
 *  render every status in the app from here: tone (color family) + icon + label + a plain-
 *  language explanation used by tooltips and the help drawer. Brand (iris) never appears here;
 *  status colors are never used for decoration. */

export type Tone = "ok" | "bad" | "warn" | "high" | "info" | "neutral";
export type IconName =
  | "check" | "x" | "alert" | "clock" | "help" | "shield" | "link" | "anchor" | "lock"
  | "circle" | "ban" | "send" | "box";

export type StatusMeta = { tone: Tone; icon: IconName; label: string; help: string };

const S = (tone: Tone, icon: IconName, help: string, label?: string) => ({ tone, icon, help, label });

const TABLE: Record<string, { tone: Tone; icon: IconName; help: string; label?: string }> = {
  // verification results
  VERIFIED: S("ok", "check", "Every recomputed hash, chain link and Merkle root matches (and the on-chain anchor, where checked)."),
  TAMPERED: S("bad", "x", "A recomputed value differs from the stored one: evidence was altered, reordered, removed in place or forged. Treat as an incident."),
  INVALID_PROOF: S("bad", "x", "A Merkle inclusion proof does not lead to the epoch root it claims."),
  UNTRUSTED_ANCHOR: S("bad", "x", "The anchor is not from the pinned chain, contract or recorder identity."),
  INCOMPLETE: S("warn", "alert", "Evidence is missing (a sequence gap, a deleted payload, an unreachable chain). Nothing contradicts it, but not everything could be checked."),
  UNANCHORED: S("neutral", "anchor", "Internally consistent but not anchored at the required finality yet: there is no external time bound. Normal for fresh evidence; worry only if it stays this way."),
  ERROR: S("bad", "alert", "The check could not complete. See the reason and retry."),
  // action lifecycle
  COMPLETED: S("ok", "check", "The tool ran and its result was recorded."),
  FAILED: S("bad", "x", "The tool ran and returned an error, or was refused at dispatch."),
  OUTCOME_UNKNOWN: S("warn", "help", "The gateway cannot tell whether the tool ran (a crash between dispatch and result). It is never retried automatically; an admin reconciles it.", "OUTCOME UNKNOWN"),
  PENDING_APPROVAL: S("warn", "clock", "Waiting for a human approval. Nothing runs until it is approved.", "PENDING APPROVAL"),
  AUTHORIZED: S("info", "shield", "Policy (and any approval) allowed it; waiting to be dispatched."),
  DISPATCHED: S("info", "send", "Handed to the tool adapter; waiting for the result."),
  DENIED: S("bad", "ban", "Policy refused the action. Nothing was executed."),
  RECONCILED: S("ok", "check", "An admin recorded what actually happened to an unknown outcome."),
  // policy decisions
  ALLOW: S("ok", "check", "The policy allowed the action without a human."),
  DENY: S("bad", "ban", "The policy refused the action."),
  REQUIRE_APPROVAL: S("warn", "clock", "The policy requires a human approval before the action may run.", "REQUIRE APPROVAL"),
  // approvals
  PENDING: S("warn", "clock", "Awaiting a decision before it expires."),
  APPROVED: S("ok", "check", "Approved; the action is authorized once all required approvals are in."),
  CONSUMED: S("ok", "check", "The approval authorized its action and can never be used again (single-use)."),
  REJECTED: S("bad", "x", "A human rejected it; the action will not run."),
  EXPIRED: S("neutral", "clock", "Nobody decided in time. Nothing was executed."),
  INVALIDATED: S("neutral", "ban", "The approved action changed or was cancelled; the approval no longer applies."),
  CANCELLED: S("neutral", "ban", "Cancelled before it ran."),
  // epochs and anchors
  SEALED: S("neutral", "lock", "Grouped into a Merkle epoch with a fixed root; not yet anchored on chain."),
  "SEALED (not anchored)": S("neutral", "lock", "Grouped into a Merkle epoch with a fixed root; not yet anchored on chain.", "SEALED"),
  SUBMITTED: S("info", "send", "The anchor transaction was broadcast; waiting for a block."),
  INCLUDED: S("info", "box", "The anchor is in a block; waiting for enough confirmations to be final."),
  FINALIZED: S("ok", "anchor", "The anchor is final on chain: this epoch can no longer be rewritten undetected."),
  // C2 connectors (ADR-0035)
  CONNECTED: S("ok", "link", "The last connection test passed. Classified actions can run through the gateway."),
  NEEDS_ATTENTION: S("warn", "alert", "Not tested yet, or the last connection test failed (new connectors, changed configuration and rotated credentials start here). Run Test connection.", "NEEDS ATTENTION"),
  DISABLED: S("neutral", "ban", "Disabled by an admin: every action of this connector is denied until it is enabled again."),
  UNCLASSIFIED: S("bad", "ban", "No admin has classified this action yet, so the policy denies every call to it. Classify it (risk, approval rule, who may call it) to allow it.", "UNCLASSIFIED · DENIED"),
  CLASSIFIED: S("ok", "check", "An admin classified this action in the current policy version: its risk, approval rule and allowed callers apply."),
  READ_ONLY: S("neutral", "lock", "Configured by the operator (gateway settings), shown here for reference. It cannot be changed from the console.", "READ-ONLY"),
  HEALTH_OK: S("ok", "check", "The connection test succeeded.", "OK"),
  HEALTH_FAILED: S("bad", "x", "The connection test failed; the code says why. Check the configuration and credentials, then test again.", "FAILED"),
  // C1/C2 coding-agent integration tiers (how strongly the gateway can enforce on that client)
  TIER_ENFORCED: S("ok", "shield", "Managed hooks the developer cannot turn off; a gateway refusal blocks the tool call.", "ENFORCED"),
  TIER_HOOKED: S("info", "shield", "Hooks run before tool calls and fail closed, but there is no managed-only switch: a developer could remove them.", "HOOKED"),
  TIER_ADVISORY: S("warn", "alert", "Hooks run but the client lets users disable them or fails open: the gateway records and warns, it cannot guarantee a block.", "ADVISORY"),
  TIER_MCP_ONLY: S("neutral", "circle", "Only the client's MCP tool calls go through the gateway; its built-in tools are not intercepted.", "MCP ONLY"),
  // device enrollment requests (agw login)
  ENROLL_PENDING: S("warn", "clock", "Waiting for a signed-in human to approve or deny this device.", "PENDING"),
  ENROLL_APPROVED: S("ok", "check", "Approved. The CLI collects its device key on its next poll; you are the developer of this device.", "APPROVED"),
  ENROLL_ISSUED: S("ok", "check", "Approved and the device key was issued to the CLI. The code cannot be used again.", "ISSUED"),
  ENROLL_DENIED: S("bad", "ban", "Denied. The CLI gets no key.", "DENIED"),
  ENROLL_EXPIRED: S("neutral", "clock", "Nobody approved it in time. Run agw login again for a new code.", "EXPIRED"),
  // .agentguard.yaml loosening proposals
  // C3: the "AgentGuard evidence" GitHub check run
  CHECK_SUCCESS: S("ok", "check", "Every commit was pushed through AgentGuard and its evidence is sealed and verified.", "EVIDENCE OK"),
  CHECK_FAILURE: S("bad", "x", "A commit was not recorded by AgentGuard, an approval is missing, or verification failed. Merging is blocked.", "EVIDENCE FAILED"),
  CHECK_IN_PROGRESS: S("warn", "clock", "Waiting for the evidence epoch to be sealed and independently verified.", "VERIFYING"),
  CHECK_NONE: S("neutral", "clock", "No AgentGuard evidence check has run for this pull request yet.", "NO CHECK"),
  PROPOSAL_PENDING: S("warn", "clock", "A repository asked to loosen its policy. Nothing changed; an admin must approve or reject it.", "PENDING"),
  // people
  ACTIVE: S("ok", "check", "Can sign in with the roles shown."),
  PERSON_DISABLED: S("neutral", "ban", "Cannot sign in; kept for the evidence history.", "DISABLED"),
};

const RISK: Record<string, StatusMeta> = {
  LOW: { tone: "info", icon: "circle", label: "LOW", help: "Low impact: read-only or internal effects." },
  MEDIUM: { tone: "warn", icon: "alert", label: "MEDIUM", help: "Moderate impact: writes or limited external effects." },
  HIGH: { tone: "high", icon: "alert", label: "HIGH", help: "High impact: external, sensitive or hard to undo. Usually needs a human approval." },
  CRITICAL: { tone: "bad", icon: "alert", label: "CRITICAL", help: "Critical impact (e.g. identity and access changes): needs approval, step-up re-authentication and, where configured, prior anchoring." },
};

export function statusMeta(value: string): StatusMeta {
  const m = TABLE[value];
  if (m) return { tone: m.tone, icon: m.icon, help: m.help, label: m.label ?? value.replaceAll("_", " ") };
  return { tone: "neutral", icon: "circle", label: value.replaceAll("_", " "), help: "" };
}

export function riskMeta(level: string): StatusMeta {
  return RISK[level] ?? { tone: "neutral", icon: "circle", label: level, help: "" };
}

/** Badge classes per tone. Text uses step 12 (Radix step 11 on step 3 measures 4.2-4.3:1 in
 *  light mode, below WCAG AA 4.5:1, found by axe); the tone is carried by the tinted background
 *  (3), the border (7) and the icon (11, non-text: needs 3:1). */
export const TONE_CLASS: Record<Tone, string> = {
  ok: "bg-ok-3 text-ok-12 border-ok-7",
  bad: "bg-bad-3 text-bad-12 border-bad-7",
  warn: "bg-warn-3 text-warn-12 border-warn-7",
  high: "bg-high-3 text-high-12 border-high-7",
  info: "bg-info-3 text-info-12 border-info-7",
  neutral: "bg-gray-3 text-gray-12 border-gray-7",
};

export const TONE_ICON: Record<Tone, string> = {
  ok: "text-ok-11", bad: "text-bad-11", warn: "text-warn-11", high: "text-high-11", info: "text-info-11", neutral: "text-gray-11",
};

export const ALL_STATUSES = Object.keys(TABLE);
export const ALL_RISKS = Object.keys(RISK);
