import type { ReactNode } from "react";

import { Notice as NewNotice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { ALL_RISKS } from "@/lib/status";

/** Phase 9 presentational helpers, kept for the pages Part B rebuilds (runs, events, epochs,
 *  verification, policies, incidents). Re-skinned on the Phase 9.5 tokens and rendered inside
 *  the new shell. All text is rendered by React (escaped); nothing uses dangerouslySetInnerHTML,
 *  so tool args/results can never become markup (ADR-0031 §2). */

export function Page({ title, children, lead, help, toggle = true }: { title: string; lead?: ReactNode; children: ReactNode; help?: string; toggle?: boolean }) {
  return (
    <div className="legacy mx-auto max-w-7xl">
      <PageHeader title={title} description={lead} help={help ?? "default"} toggle={toggle} />
      {children}
    </div>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="mb-4 rounded-md border border-gray-6 bg-gray-1 p-4">
      {title ? <h2 className="mb-3 text-section font-semibold">{title}</h2> : null}
      {children}
    </section>
  );
}

/** Statuses and risk levels both route through the single mapping table (lib/status.ts). */
export function Badge({ value }: { value: string | null | undefined }) {
  if (value && ALL_RISKS.includes(value)) return <RiskBadge level={value} />;
  return <StatusBadge value={value} />;
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-md border border-gray-6 bg-gray-1 p-4">
      <div className="text-caption font-medium text-gray-11">{label}</div>
      <div className="text-kpi font-semibold tabular">{value}</div>
      {hint ? <div className="text-caption text-gray-11">{hint}</div> : null}
    </div>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "bad" | "good" | "warn"; children: ReactNode }) {
  return <NewNotice kind={kind}>{children}</NewNotice>;
}

export function age(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86400).toFixed(1)} d`;
}

export function short(id: string | null | undefined, n = 8): string {
  return id ? id.slice(0, n) : "—";
}

/** Escaped, size-limited rendering of untrusted text (args, results, headers), with an explicit
 *  TRUNCATED marker. Used by the new code view too. */
export function SafeText({ text, max = 4000, label }: { text: string; max?: number; label?: string }) {
  const truncated = text.length > max;
  const shown = truncated ? text.slice(0, max) : text;
  return (
    <div>
      <pre tabIndex={0} aria-label={label ?? "text"} data-testid="safe-text"
        className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-gray-6 bg-gray-2 p-3 font-mono text-caption text-gray-12">
        {shown}
      </pre>
      {truncated ? (
        <p className="mt-1.5 text-caption font-semibold text-warn-12" data-testid="truncated">
          [TRUNCATED: showing {max} of {text.length} characters; {text.length - max} not shown]
        </p>
      ) : null}
    </div>
  );
}

export function CsrfField({ csrf }: { csrf: string }) {
  return <input type="hidden" name="csrf" value={csrf} />;
}

export const RESULT_EXPLANATION: Record<string, string> = {
  VERIFIED: "Every recomputed hash, chain link and Merkle root matches (and the on-chain anchor, where checked).",
  TAMPERED: "A recomputed value differs from the stored one: evidence was altered, reordered, removed in place or forged.",
  INCOMPLETE: "Evidence is missing (a sequence gap, a deleted payload, an unreachable chain). Nothing contradicts it, but not everything could be checked.",
  UNANCHORED: "Internally consistent, but not anchored at the required finality: there is no external time bound yet.",
  INVALID_PROOF: "A Merkle inclusion proof does not lead to the epoch root it claims.",
  UNTRUSTED_ANCHOR: "The anchor is not from the pinned chain / contract / recorder identity.",
  ERROR: "The monitor could not complete the check (see the reason).",
};
