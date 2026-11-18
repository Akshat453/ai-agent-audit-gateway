export const APPROVAL_STATES = ["PENDING", "APPROVED", "CONSUMED", "REJECTED", "EXPIRED", "INVALIDATED"];

/** Shape of GET /v1/approvals/{id} (free-form in the OpenAPI schema; typed here). */
export type ApprovalView = {
  approval_id: string; state: string; state_reason: string | null; required_approvals: number;
  required_role?: string; // the gateway has always returned it; C1 routes it (ADR-0034)
  requested_at: string; expires_at: string; action_digest: string; nonce: string;
  action: {
    action_id: string; run_id: string; status: string; agent: { id: string; name: string };
    tool: { id: string; version: string }; environment: string; args_rendered: string;
    target_rendered: string; delegation_depth: number | null;
    risk: { level: string; score: number; rules: string[]; reasons: string[] };
    policy: { id: string; version: number; effect: string; rules: string[]; reasons: string[]; controls: string[] };
  };
  decisions: { approver: string; decision: string; decided_at_us: number }[];
};
