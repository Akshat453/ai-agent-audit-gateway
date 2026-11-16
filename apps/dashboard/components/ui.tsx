import type { ReactNode } from "react";

/** Plain presentational helpers. All text is rendered by React (escaped); nothing here uses
 *  dangerouslySetInnerHTML, so tool args/results can never become markup (ADR-0031 §2). */

export function Page({ title, children, lead }: { title: string; lead?: ReactNode; children: ReactNode }) {
  return (
    <main id="main" className="mx-auto max-w-7xl px-4 py-6">
      <h1 className="mb-1 text-2xl font-bold">{title}</h1>
      {lead ? <p className="mb-4 text-sm text-slate-700">{lead}</p> : null}
      {children}
    </main>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="mb-4 rounded border border-slate-300 bg-white p-4 shadow-sm">
      {title ? <h2 className="mb-2 text-lg font-semibold">{title}</h2> : null}
      {children}
    </section>
  );
}

const TONES: Record<string, string> = {
  good: "bg-green-100 text-green-900 border-green-700",
  bad: "bg-red-100 text-red-900 border-red-700",
  warn: "bg-amber-100 text-amber-900 border-amber-700",
  info: "bg-slate-100 text-slate-900 border-slate-500",
};

const STATUS_TONE: Record<string, keyof typeof TONES> = {
  ALLOW: "good", COMPLETED: "good", VERIFIED: "good", FINALIZED: "good", APPROVED: "good",
  CONSUMED: "good", AUTHORIZED: "info", DISPATCHED: "info", INCLUDED: "info", SUBMITTED: "info",
  DENY: "bad", DENIED: "bad", FAILED: "bad", TAMPERED: "bad", REJECTED: "bad",
  INVALID_PROOF: "bad", UNTRUSTED_ANCHOR: "bad", INVALIDATED: "bad", ERROR: "bad",
  REQUIRE_APPROVAL: "warn", PENDING_APPROVAL: "warn", PENDING: "warn", OUTCOME_UNKNOWN: "warn",
  INCOMPLETE: "warn", UNANCHORED: "warn", EXPIRED: "warn", HIGH: "warn", CRITICAL: "bad",
  MEDIUM: "info", LOW: "good",
};

export function Badge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-500">-</span>;
  const tone = TONES[STATUS_TONE[value] ?? "info"];
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-xs font-semibold ${tone}`}>{value}</span>;
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded border border-slate-300 bg-white p-3">
      <div className="text-xs uppercase tracking-wide text-slate-600">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
      {hint ? <div className="text-xs text-slate-600">{hint}</div> : null}
    </div>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "bad" | "good" | "warn"; children: ReactNode }) {
  return (
    <div role={kind === "bad" ? "alert" : "status"} className={`mb-4 rounded border p-3 text-sm ${TONES[kind]}`}>
      {children}
    </div>
  );
}

export function age(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "-";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86400).toFixed(1)} d`;
}

export function short(id: string | null | undefined, n = 8): string {
  return id ? id.slice(0, n) : "-";
}

/** Escaped, size-limited rendering of untrusted text (args, results, headers). */
export function SafeText({ text, max = 4000, label }: { text: string; max?: number; label?: string }) {
  const truncated = text.length > max;
  const shown = truncated ? text.slice(0, max) : text;
  return (
    <div>
      <pre tabIndex={0} aria-label={label ?? "text"} className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-300 bg-slate-100 p-2" data-testid="safe-text">
        {shown}
      </pre>
      {truncated ? (
        <p className="mt-1 text-xs font-semibold text-amber-900" data-testid="truncated">
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
