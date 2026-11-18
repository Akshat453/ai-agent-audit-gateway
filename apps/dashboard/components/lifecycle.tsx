import { Check, CircleHelp, Clock, X } from "lucide-react";

import { Timestamp } from "@/components/timestamp";
import { cn } from "@/lib/cn";

type Ev = { type: string; occurred_at?: string | null };
type Step = { key: string; label: string; types: string[] };

const STEPS: Step[] = [
  { key: "requested", label: "Requested", types: ["ACTION_REQUESTED"] },
  { key: "evaluated", label: "Evaluated", types: ["POLICY_EVALUATED"] },
  { key: "approval", label: "Approval", types: ["APPROVAL_REQUIRED", "APPROVAL_GRANTED", "APPROVAL_REJECTED", "APPROVAL_EXPIRED"] },
  { key: "authorized", label: "Authorized", types: ["ACTION_AUTHORIZED"] },
  { key: "dispatched", label: "Dispatched", types: ["ACTION_DISPATCHED"] },
  { key: "outcome", label: "Outcome", types: ["ACTION_COMPLETED", "ACTION_FAILED", "ACTION_OUTCOME_UNKNOWN", "ACTION_DENIED", "ACTION_RECONCILED"] },
];

/** Requested > Evaluated > Approval > Authorized > Dispatched > Completed | Failed | Unknown,
 *  with the time of each step from the evidence events (§5 Action detail). */
export function LifecycleStepper({ events, status, decision, tz }: { events: Ev[]; status: string; decision: string; tz: "utc" | "local" }) {
  const at = (s: Step) => [...events].reverse().find((e) => s.types.includes(e.type));
  const needsApproval = decision === "REQUIRE_APPROVAL" || events.some((e) => e.type.startsWith("APPROVAL_"));
  const steps = STEPS.filter((s) => s.key !== "approval" || needsApproval);
  const outcomeLabel: Record<string, string> = { COMPLETED: "Completed", FAILED: "Failed", OUTCOME_UNKNOWN: "Unknown", DENIED: "Denied", RECONCILED: "Reconciled" };
  const reached = steps.map((s) => at(s));
  let current = -1;
  reached.forEach((r, i) => { if (r !== undefined) current = i; });
  return (
    <ol aria-label="Lifecycle" className="flex flex-wrap gap-y-3">
      {steps.map((s, i) => {
        const ev = reached[i];
        const done = ev !== undefined;
        const isOutcome = s.key === "outcome";
        const waiting = s.key === "approval" && done && ev?.type === "APPROVAL_REQUIRED";
        const rejected = s.key === "approval" && done && (ev?.type === "APPROVAL_REJECTED" || ev?.type === "APPROVAL_EXPIRED");
        const bad = isOutcome && done && ["FAILED", "DENIED"].includes(status);
        const unknown = isOutcome && done && status === "OUTCOME_UNKNOWN";
        const label = isOutcome ? (done ? outcomeLabel[status] ?? status : "Completed | Failed | Unknown")
          : waiting ? "Approval (waiting)" : rejected ? (ev?.type === "APPROVAL_EXPIRED" ? "Approval expired" : "Approval rejected") : s.label;
        return (
          <li key={s.key} className="flex min-w-32 flex-1 items-start" aria-current={i === current ? "step" : undefined}>
            <div className="flex w-full flex-col">
              <div className="flex items-center">
                <span className={cn("flex size-6 shrink-0 items-center justify-center rounded-full border-2 text-caption font-semibold",
                  bad || rejected ? "border-bad-9 bg-bad-9 text-white" : unknown || waiting ? "border-warn-9 bg-warn-9 text-black" : done ? "border-ok-9 bg-ok-9 text-white" : "border-gray-7 bg-gray-1 text-gray-11",
                  i === current && "ring-4 ring-brand-5")}>
                  {bad || rejected ? <X className="size-3.5" strokeWidth={3} /> : unknown ? <CircleHelp className="size-3.5" /> : waiting ? <Clock className="size-3.5" /> : done ? <Check className="size-3.5" strokeWidth={3} /> : i + 1}
                </span>
                {i < steps.length - 1 ? <span aria-hidden="true" className={cn("mx-2 h-0.5 flex-1 rounded-full", reached[i + 1] && !waiting ? "bg-ok-9" : "bg-gray-5")} /> : null}
              </div>
              <span className={cn("mt-1.5 text-dense font-medium", done ? "text-gray-12" : "text-gray-11")}>{label}</span>
              <span className="text-caption">{ev ? <Timestamp iso={ev.occurred_at} tz={tz} className="text-gray-11" /> : <span className="text-gray-11">not reached</span>}</span>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
