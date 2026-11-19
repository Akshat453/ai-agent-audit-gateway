/** Plain-language help for the help drawer (§4): what the page is for and what its statuses
 *  mean. Status texts come from lib/status.ts so there is one source of truth. */
export type HelpTopic = {
  title: string;
  summary: string;
  points: string[];
  statuses?: string[];
  risks?: boolean;
  /** Glossary words used on the page (ADR-0039), explained in the drawer. */
  terms?: string[];
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
    terms: ["allow", "ask", "block", "evidence", "anchored"],
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
    terms: ["approval", "four-eyes", "step-up", "digest", "nonce"],
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
    terms: ["action", "hash", "prev hash", "epoch", "anchored"],
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
    terms: ["event", "hash", "proof", "Merkle root", "payload"],
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
    terms: ["connector", "tier", "Tier 1", "Tier 2"],
  },
  repos: {
    title: "Repositories",
    summary: "Repositories registered by agw init, with their tighten-only .agentguard.yaml overlay.",
    points: [
      "Tightening in .agentguard.yaml (sensitive paths, denied paths or commands) applies at once as a new repo policy version.",
      "Loosening (allow paths or commands, removing a tightening) is ignored and becomes a proposal. An admin with a recent step-up approves or rejects it.",
    ],
    statuses: ["PROPOSAL_PENDING"],
    terms: ["overlay", "proposal"],
  },
  people: {
    title: "People",
    summary: "The humans of this tenant and their roles. Agents never appear here.",
    points: [
      "Inviting a person needs a recent step-up. The temporary password is shown once; hand it over out of band.",
      "Roles: approver decides approvals; admin configures; auditor and security investigate; ledger_lead and maintainer approve routed coding actions.",
    ],
    statuses: ["ACTIVE", "PERSON_DISABLED"],
    terms: ["approval", "step-up"],
  },
  enroll: {
    title: "Enroll a device",
    summary: "A developer runs agw login on their machine; it prints a code. Entering and approving it here binds that device to you.",
    points: [
      "Only approve a code you just saw in your own terminal. Whoever approves becomes the developer the device acts for.",
      "Codes expire after a few minutes and work once.",
    ],
    statuses: ["ENROLL_PENDING", "ENROLL_APPROVED", "ENROLL_ISSUED", "ENROLL_DENIED", "ENROLL_EXPIRED"],
    terms: ["device", "developer"],
  },
  runs: {
    title: "Runs",
    summary: "Each run is one working session of an agent. For coding agents it is one Claude Code (or Codex, Cursor...) session on one repository, usually for one issue.",
    points: [
      "Simple view shows one sentence per session: who ran it, where, and how many actions were allowed, blocked or needed approval.",
      "Open a session to read its story: every request in order, with what AgentGuard decided.",
    ],
    statuses: ["COMPLETED", "DENIED", "PENDING_APPROVAL"],
    terms: ["run", "session", "action"],
  },
  run: {
    title: "Session",
    summary: "One agent session told as a story: each thing the agent asked to do, what AgentGuard decided, who approved, and the result.",
    points: [
      "Arrows show what happened to each request: allowed, blocked, needed approval, approved by someone, done.",
      "Paths and commands are shown as the agent reported them. File contents are never shown.",
      "Technical details hold the full event table with sequence numbers, hashes and anchors.",
    ],
    terms: ["session", "action", "evidence", "epoch"],
  },
  events: {
    title: "Events",
    summary: "The tamper-evident log itself. Every record is fingerprinted and chained to the one before it, so changing any record breaks the chain.",
    points: [
      "Each line is one record in plain words; the technical table shows the exact sealed header.",
      "Contents (arguments, results) are encrypted and need a disclosure grant.",
    ],
    terms: ["event", "hash", "prev hash", "A2S", "A2H", "SYS", "payload"],
  },
  epochs: {
    title: "Epochs & anchors",
    summary: "Records are locked in batches (epochs). Each batch's fingerprint is written to a blockchain so history cannot be quietly rewritten.",
    points: ["Locked -> Sent -> Included -> Permanent is the life of a batch.", "A batch that stays un-sent for hours means anchoring needs attention."],
    statuses: ["SEALED", "SUBMITTED", "INCLUDED", "FINALIZED"],
    terms: ["epoch", "Merkle root", "anchored", "finalized"],
  },
  verification: {
    title: "Verification",
    summary: "AgentGuard re-checks every fingerprint, chain link and batch on a schedule, the same way an outside auditor would.",
    points: ["\"Nothing was changed\" means every record still matches what was saved.", "A changed record is a security incident: do not edit the database; tell your security team."],
    statuses: ["VERIFIED", "TAMPERED", "INCOMPLETE", "UNANCHORED"],
    terms: ["verification", "tampered", "hash"],
  },
  policies: {
    title: "Policies",
    summary: "The rules AgentGuard applies to every agent request: allowed on its own, needs a person, or always blocked.",
    points: ["Rules are never edited in place; each change is a new version and every decision records which version it used.", "Each rule id in a decision has a one-line meaning listed here."],
    statuses: ["ALLOW", "REQUIRE_APPROVAL", "DENY"],
    terms: ["policy", "rule", "policy version", "overlay"],
  },
  incidents: {
    title: "Incidents",
    summary: "Things that were blocked, failed, are unclear, or looked like a security problem - each with what to do.",
    points: ["Most blocks need no action: AgentGuard stopped something it should.", "A result nobody can confirm is never retried automatically; an admin records what really happened."],
    statuses: ["DENIED", "FAILED", "OUTCOME_UNKNOWN"],
    terms: ["block", "action"],
  },
  default: {
    title: "This page",
    summary: "Part of the AgentGuard Console. Every status badge has a tooltip explaining it.",
    points: ["The dashboard is a convenience view. Independent verification uses the CLI with pinned trust roots."],
  },
};
