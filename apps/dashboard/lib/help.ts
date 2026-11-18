/** Plain-language help for the help drawer (§4): what the page is for and what its statuses
 *  mean. Status texts come from lib/status.ts so there is one source of truth. */
export type HelpTopic = {
  title: string;
  summary: string;
  points: string[];
  statuses?: string[];
  risks?: boolean;
};

export const HELP: Record<string, HelpTopic> = {
  overview: {
    title: "Overview",
    summary: "A live summary of your tenant: what agents asked to do, what the policy decided, what is waiting for a human, and how far the evidence has progressed towards an on-chain anchor.",
    points: [
      "Counts come from the gateway's operational tables; integrity comes from verification.",
      "The evidence pipeline reads left to right: every event is Recorded, then Sealed into a Merkle epoch, then Anchored on chain, then Finalized.",
      "“Oldest waiting” is the age of the oldest item that has not moved to the next stage. A few minutes is normal; hours means the worker or anchoring needs attention.",
    ],
    statuses: ["ALLOW", "DENY", "REQUIRE_APPROVAL", "VERIFIED", "UNANCHORED"],
  },
  approvals: {
    title: "Approvals",
    summary: "Actions the policy will not run without a human. Each approval binds one exact action: tool and version, the canonical arguments (digest), target, policy version, an expiry and a single-use nonce.",
    points: [
      "Soonest expiry is at the top. An expired approval can never be decided; nothing runs.",
      "Approving in the list is deliberately impossible: open the approval, read exactly what will run, then confirm.",
      "CRITICAL actions also need a fresh step-up (password re-entry) and typing the last 6 characters of the action id.",
      "Some tools need two approvers (four-eyes); the same person cannot approve twice.",
    ],
    statuses: ["PENDING", "APPROVED", "CONSUMED", "REJECTED", "EXPIRED", "INVALIDATED"],
    risks: true,
  },
  action: {
    title: "Action detail",
    summary: "One tool call an agent requested, from request to outcome, with the evidence events that record each step.",
    points: [
      "The evidence timeline shows each event's hash and the hash it links back to (prev). A green link means the stored record still hashes to what the next event committed to.",
      "A red dashed link means a stored hash no longer matches: the record was edited after the fact. Run verification and treat it as an incident.",
      "Arguments and results are never shown here; they are encrypted and need a disclosure grant.",
    ],
    statuses: ["COMPLETED", "FAILED", "OUTCOME_UNKNOWN", "DENIED", "SEALED", "FINALIZED"],
  },
  event: {
    title: "Event detail",
    summary: "One evidence event: its structural header (no payload), its place in the hash chain, and the proof that ties it to an epoch root anchored on chain.",
    points: [
      "The proof explorer recomputes each hash in your browser from public hashes only, as a visual check.",
      "Authoritative verification is the CLI (agw-verify) with trust roots you obtained independently.",
      "Payloads are encrypted; an admin can grant an auditor a disclosure for specific events.",
    ],
    statuses: ["VERIFIED", "TAMPERED", "INVALID_PROOF", "UNTRUSTED_ANCHOR", "INCLUDED", "FINALIZED"],
  },
  integrations: {
    title: "Integrations",
    summary: "Connectors link the gateway to code hosting, coding agents, notification channels, external APIs and MCP servers. Every connector action is a gateway tool that goes through policy, approvals and evidence.",
    points: [
      "A new connector's actions start UNCLASSIFIED: the policy denies them until an admin sets their risk, approval rule and allowed callers.",
      "Each classification change is a new, append-only policy version; earlier decisions keep the version they were made under.",
      "Credentials are write-only: they are sealed on the gateway and never shown again. Rotate replaces them.",
      "Every change needs an admin with a recent step-up and writes a CONNECTOR_* evidence event.",
    ],
    statuses: ["CONNECTED", "NEEDS_ATTENTION", "DISABLED", "UNCLASSIFIED", "TIER_ENFORCED", "TIER_HOOKED", "TIER_ADVISORY", "TIER_MCP_ONLY"],
    risks: true,
  },
  repos: {
    title: "Repositories",
    summary: "Repositories registered by agw init, with their tighten-only .agentguard.yaml overlay.",
    points: [
      "Tightening in .agentguard.yaml (sensitive paths, denied paths or commands) applies at once as a new repo policy version.",
      "Loosening (allow paths or commands, removing a tightening) is ignored and becomes a proposal. An admin with a recent step-up approves or rejects it.",
    ],
    statuses: ["PROPOSAL_PENDING"],
  },
  people: {
    title: "People",
    summary: "The humans of this tenant and their roles. Agents never appear here.",
    points: [
      "Inviting a person needs a recent step-up. The temporary password is shown once; hand it over out of band.",
      "Roles: approver decides approvals; admin configures; auditor and security investigate; ledger_lead and maintainer approve routed coding actions.",
    ],
    statuses: ["ACTIVE", "PERSON_DISABLED"],
  },
  enroll: {
    title: "Enroll a device",
    summary: "A developer runs agw login on their machine; it prints a code. Entering and approving it here binds that device to you.",
    points: [
      "Only approve a code you just saw in your own terminal. Whoever approves becomes the developer the device acts for.",
      "Codes expire after a few minutes and work once.",
    ],
    statuses: ["ENROLL_PENDING", "ENROLL_APPROVED", "ENROLL_ISSUED", "ENROLL_DENIED", "ENROLL_EXPIRED"],
  },
  default: {
    title: "This page",
    summary: "Part of the AgentGuard Console. Every status badge has a tooltip explaining it.",
    points: ["The dashboard is a convenience view. Independent verification uses the CLI with pinned trust roots."],
  },
};
