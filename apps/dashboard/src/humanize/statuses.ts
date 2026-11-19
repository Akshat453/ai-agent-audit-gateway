/** Every status / decision / risk value -> plain words (ADR-0039). A unit test fails if
 *  lib/status.ts gains a value without an entry here. */

export const PLAIN_STATUS: Record<string, string> = {
  // verification results
  VERIFIED: "Intact - nothing was changed",
  TAMPERED: "Changed after it was saved",
  INVALID_PROOF: "Proof does not match",
  UNTRUSTED_ANCHOR: "Blockchain record not trusted",
  INCOMPLETE: "Could not check everything",
  UNANCHORED: "Saved, not yet on the blockchain",
  ERROR: "Check could not finish",
  // action lifecycle
  COMPLETED: "Done",
  FAILED: "Failed",
  OUTCOME_UNKNOWN: "Result unknown - needs a check",
  PENDING_APPROVAL: "Waiting for approval",
  AUTHORIZED: "Cleared to run",
  DISPATCHED: "Running",
  DENIED: "Blocked",
  RECONCILED: "Result recorded by a person",
  // policy decisions
  ALLOW: "Allowed",
  DENY: "Blocked",
  REQUIRE_APPROVAL: "Needed approval",
  // approvals
  PENDING: "Waiting for a decision",
  APPROVED: "Approved",
  CONSUMED: "Approved and used",
  REJECTED: "Rejected",
  EXPIRED: "Expired - nobody decided",
  INVALIDATED: "No longer valid",
  CANCELLED: "Cancelled",
  // epochs and anchors
  SEALED: "Locked in a batch",
  "SEALED (not anchored)": "Locked in a batch",
  SUBMITTED: "Sent to the blockchain",
  INCLUDED: "On the blockchain",
  FINALIZED: "Permanent on the blockchain",
  // connectors
  CONNECTED: "Connected",
  NEEDS_ATTENTION: "Needs attention",
  DISABLED: "Turned off",
  UNCLASSIFIED: "Blocked until an admin sets rules",
  CLASSIFIED: "Rules set",
  READ_ONLY: "Set by the operator",
  HEALTH_OK: "Test passed",
  HEALTH_FAILED: "Test failed",
  // tiers
  TIER_ENFORCED: "Tier 1: every action is checked",
  TIER_HOOKED: "Tier 1: every action is checked (developer could remove the hook)",
  TIER_ADVISORY: "Recorded and warned, cannot always block",
  TIER_MCP_ONLY: "Tier 2: only Git/GitHub actions are checked",
  // device enrollment
  ENROLL_PENDING: "Waiting for approval",
  ENROLL_APPROVED: "Approved",
  ENROLL_ISSUED: "Connected",
  ENROLL_DENIED: "Denied",
  ENROLL_EXPIRED: "Expired",
  // GitHub evidence check
  CHECK_SUCCESS: "Evidence check passed",
  CHECK_FAILURE: "Evidence check failed",
  CHECK_IN_PROGRESS: "Evidence check running",
  CHECK_NONE: "No evidence check yet",
  PROPOSAL_PENDING: "Waiting for an admin",
  // people
  ACTIVE: "Can sign in",
  PERSON_DISABLED: "Cannot sign in",
  // risks
  LOW: "Low risk",
  MEDIUM: "Medium risk",
  HIGH: "High risk",
  CRITICAL: "Critical risk",
};

export function plainStatus(value: string | null | undefined): string {
  if (!value) return "";
  return PLAIN_STATUS[value] ?? value.replaceAll("_", " ").toLowerCase();
}

/** "HIGH" -> "High" (for sentences: "Risk: High"). */
export function riskWord(level: string | null | undefined): string {
  if (!level) return "Unknown";
  return level.charAt(0) + level.slice(1).toLowerCase();
}

/** Why a risk level matters, in one clause, for headlines. */
export const RISK_MEANING: Record<string, string> = {
  LOW: "low impact, easy to undo",
  MEDIUM: "limited impact",
  HIGH: "sensitive or hard to undo",
  CRITICAL: "could cause serious harm",
};
