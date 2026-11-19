"use client";

import type { ColumnDef } from "@tanstack/react-table";
import type { ReactNode } from "react";

import { Countdown } from "@/components/expiry-countdown";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { HashChip } from "@/components/hash-chip";
import { AgentText } from "@/components/humanize/agent-text";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { APPROVAL_STATES } from "@/lib/approval";
import { ALL_RISKS } from "@/lib/status";
import { agentName, approvalRequest, approvalRisk, wantsTo } from "@/src/humanize";

export type ApprovalRow = {
  approval_id: string; action_id: string; run_id: string; state: string;
  tool: { id: string; version?: string | null }; environment: string; risk_level: string;
  agent: { id: string; name: string }; delegation_depth?: number | null; delegated_by?: string | null;
  required_approvals: number; decisions: number; requested_at?: string | null; expires_at?: string | null;
  action_type?: string | null; target?: string | null; agent_kind?: string | null; issue_number?: number | null; // ADR-0039
};

/** Approvals list (§5): soonest expiry first. Deliberately NO approve button in rows. */
export function ApprovalsTable({ rows, total, pageSize, fetchedAt, panel, tz, nowMs }: {
  rows: ApprovalRow[]; total: number; pageSize: number; fetchedAt: string; panel?: ReactNode; tz: "utc" | "local"; nowMs: number;
}) {
  const columns: ColumnDef<ApprovalRow, unknown>[] = [
    { id: "request", header: "Request", meta: { label: "Request (plain English)" }, enableHiding: false,
      cell: ({ row }) => {
        const q = approvalRequest(row.original);
        return (
          <div className="min-w-64 max-w-md whitespace-normal" data-testid="approval-sentence">
            <div className="text-dense text-gray-12">{q.actor} {wantsTo(row.original.state)} {q.verb}{q.object ? <> <AgentText value={q.object} /></> : null}{q.tail}.</div>
            <div className="text-caption text-gray-11">{approvalRisk(row.original, nowMs)}</div>
          </div>
        );
      } },
    { id: "risk", header: "Risk", meta: { label: "Risk", sortKey: "risk" }, enableHiding: false,
      cell: ({ row }) => <RiskBadge level={row.original.risk_level} /> },
    { id: "tool", header: "Tool", meta: { label: "Tool", sortKey: "tool" },
      cell: ({ row }) => <code className="font-mono text-dense">{row.original.tool.id}<span className="text-gray-11">@{row.original.tool.version ?? "?"}</span></code> },
    { id: "agent", header: "Agent", meta: { label: "Agent" }, cell: ({ row }) => <span title={row.original.agent.name}>{agentName(row.original.agent.name)}</span> },
    { id: "chain", header: "Requested by", meta: { label: "Requested by (delegation)" },
      cell: ({ row }) => row.original.delegated_by
        ? <span>{row.original.delegated_by} <span className="text-gray-11">→</span> {row.original.agent.name} <span className="text-caption text-gray-11">(depth {row.original.delegation_depth ?? 1})</span></span>
        : <span className="text-gray-11">direct</span> },
    { id: "requested", header: "Requested", meta: { label: "Requested", sortKey: "requested_at" },
      cell: ({ row }) => <Timestamp iso={row.original.requested_at} tz={tz} compact /> },
    { id: "expires", header: "Expires in", meta: { label: "Expires in", sortKey: "expires_at" },
      cell: ({ row }) => {
        const r = row.original;
        if (r.state !== "PENDING" || !r.expires_at) return <span className="text-gray-11">—</span>;
        return <Countdown expiresAt={r.expires_at} initialSeconds={Math.round((Date.parse(r.expires_at) - nowMs) / 1000)} compact testId={`countdown-${r.approval_id}`} />;
      } },
    { id: "state", header: "State", meta: { label: "State" }, cell: ({ row }) => <StatusBadge value={row.original.state} /> },
    { id: "votes", header: "Approvals", meta: { label: "Approvals", numeric: true },
      cell: ({ row }) => <span className="tabular">{row.original.decisions}/{row.original.required_approvals}</span> },
    { id: "id", header: "Approval", meta: { label: "Approval id" },
      cell: ({ row }) => <HashChip value={row.original.approval_id} href={`/approvals/${row.original.approval_id}`} label="approval" head={8} tail={4} /> },
  ];
  return (
    <DataTable
      label="Approvals"
      columns={columns}
      rows={rows}
      total={total}
      rowId={(r) => r.approval_id}
      rowHref={(r) => `/approvals/${r.approval_id}`}
      pageSize={pageSize}
      fetchedAt={fetchedAt}
      pollSeconds={5}
      sortable={["risk", "tool", "requested_at", "expires_at"]}
      defaultSort={{ key: "expires_at", order: "asc" }}
      filterFields={[
        { key: "state", label: "state", values: [...APPROVAL_STATES, "ALL"] },
        { key: "risk", label: "risk", values: ALL_RISKS },
        { key: "tool", label: "tool" },
      ]}
      quickFilters={[
        { label: "Pending", params: { state: null } },
        { label: "Critical pending", params: { state: null, risk: "CRITICAL" } },
        { label: "Consumed", params: { state: "CONSUMED", risk: null } },
        { label: "Rejected", params: { state: "REJECTED", risk: null } },
        { label: "Expired", params: { state: "EXPIRED", risk: null } },
        { label: "All states", params: { state: "ALL", risk: null } },
      ]}
      panel={panel}
      empty={
        <EmptyState title="No approvals match">
          Approvals appear when the policy answers REQUIRE_APPROVAL for an agent&apos;s action. Change the filters, or check back: this list refreshes every 5 seconds.
        </EmptyState>
      }
    />
  );
}
