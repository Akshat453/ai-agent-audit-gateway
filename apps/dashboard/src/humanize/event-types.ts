/** Every evidence event type -> a plain label and a sentence template (ADR-0039).
 *  A unit test fails if the event schema gains a type without an entry here. */

export type EventCtx = {
  approver?: string | null;
  what?: string | null; // "edit signal/src/sign.ts"
  code?: string | null;
  tenant?: string | null;
  result?: string | null;
};

type Entry = { label: string; sentence: (c: EventCtx) => string };

const doing = (c: EventCtx) => (c.what ? ` to ${c.what}` : "");

export const EVENT_TYPES: Record<string, Entry> = {
  ACTION_REQUESTED: { label: "Agent asked to do something", sentence: (c) => `The agent asked${doing(c) || " to do something"}.` },
  POLICY_EVALUATED: { label: "AgentGuard checked the rules", sentence: (c) => `AgentGuard checked the rules for the request${doing(c)}.` },
  ACTION_DENIED: { label: "Blocked", sentence: (c) => `Blocked: the request${doing(c)} was not allowed. Nothing was done.` },
  APPROVAL_REQUIRED: { label: "Waiting for a human to approve", sentence: (c) => `Waiting for a person to approve the request${doing(c)}.` },
  APPROVAL_GRANTED: { label: "Approved", sentence: (c) => `Approved${c.approver ? ` by ${c.approver}` : " by a person"}.` },
  APPROVAL_DENIED: { label: "Rejected", sentence: (c) => `Rejected${c.approver ? ` by ${c.approver}` : " by a person"}. It will not run.` },
  APPROVAL_EXPIRED: { label: "Approval expired", sentence: () => "Nobody decided in time, so it did not run." },
  ACTION_AUTHORIZED: { label: "Cleared to run", sentence: (c) => `Cleared to run${doing(c)}.` },
  ACTION_DISPATCHED: { label: "Started", sentence: (c) => `Started${doing(c)}.` },
  ACTION_COMPLETED: { label: "Finished successfully", sentence: () => "Finished successfully." },
  ACTION_FAILED: { label: "Failed", sentence: (c) => `Failed${c.code ? ` (${c.code})` : ""}.` },
  ACTION_OUTCOME_UNKNOWN: { label: "Result unknown - needs a human check", sentence: () => "AgentGuard cannot tell whether it happened. A person needs to check and record the result." },
  ACTION_RECONCILED: { label: "Result recorded by a person", sentence: (c) => `A person checked and recorded the real result${c.result ? `: ${c.result.toLowerCase()}` : ""}.` },
  SECURITY_VIOLATION: { label: "Security problem detected", sentence: (c) => `Security problem detected${c.code ? `: ${c.code}` : ""}.` },
  EPOCH_SEALED: { label: "Evidence batch locked", sentence: () => "A batch of log records was locked together under one fingerprint." },
  VERIFICATION_REPORT: { label: "Integrity check ran", sentence: (c) => `The integrity check ran${c.tenant ? ` for ${c.tenant}` : ""}${c.result ? `: ${c.result.toLowerCase()}` : ""}.` },
  DISCLOSURE_GRANTED: { label: "Auditor given access", sentence: () => "An admin let an auditor read the encrypted contents of some records." },
  DISCLOSURE_ACCESSED: { label: "Auditor opened records", sentence: () => "An auditor opened encrypted record contents they were allowed to read." },
  PAYLOAD_DELETED: { label: "Contents deleted", sentence: () => "The encrypted contents of a record were deleted (retention or erasure). The record itself stays." },
  DELEGATION_CREATED: { label: "Permissions handed over", sentence: () => "An agent handed part of its permissions to another agent." },
  DELEGATION_REVOKED: { label: "Hand-over cancelled", sentence: () => "A hand-over of permissions between agents was cancelled." },
  CONNECTOR_ADDED: { label: "Integration added", sentence: () => "An admin added an integration." },
  CONNECTOR_UPDATED: { label: "Integration changed", sentence: () => "An admin changed an integration's settings." },
  CONNECTOR_ACTION_CLASSIFIED: { label: "Integration rules set", sentence: () => "An admin set which integration actions are allowed, need approval, or are blocked." },
  CONNECTOR_CREDENTIAL_ROTATED: { label: "Integration secret replaced", sentence: () => "An admin replaced an integration's secret." },
  CONNECTOR_DISABLED: { label: "Integration turned off", sentence: () => "An admin turned an integration off." },
  CONNECTOR_DELETED: { label: "Integration deleted", sentence: () => "An admin deleted an integration." },
  DEVICE_ENROLLED: { label: "Computer connected", sentence: () => "A developer's computer was connected to AgentGuard." },
  REPO_POLICY_CHANGED: { label: "Repository rules changed", sentence: () => "A repository's AgentGuard rules (.agentguard.yaml) changed." },
};

export function eventLabel(type: string): string {
  return EVENT_TYPES[type]?.label ?? type.replaceAll("_", " ").toLowerCase();
}

export function eventSentence(type: string, ctx: EventCtx = {}): string {
  return EVENT_TYPES[type]?.sentence(ctx) ?? `${eventLabel(type)}.`;
}

/** Evidence classes (A2S/A2H/A2A/SYS) in words. */
export const EVIDENCE_CLASS: Record<string, string> = {
  A2S: "agent acted on a system",
  A2H: "a person was involved",
  A2A: "agent to agent",
  SYS: "recorded by AgentGuard",
};
