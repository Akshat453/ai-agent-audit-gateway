import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

/** Simple view: today's technical content folded under "Technical details" ON THE SAME PAGE
 *  (never behind another page). Technical view: rendered as it always was (ADR-0039). */
export function Technical({ view, children, label = "Technical details", hint }: {
  view: "simple" | "technical"; children: ReactNode; label?: string; hint?: string;
}) {
  if (view === "technical") return <>{children}</>;
  return (
    <details className="group mt-6 rounded-md border border-gray-6 bg-gray-1" data-testid="technical-details">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-dense font-medium text-gray-12 hover:bg-gray-2">
        <ChevronRight aria-hidden="true" className="size-4 text-gray-11 transition-transform group-open:rotate-90" />
        {label}
        <span className="text-caption font-normal text-gray-11">{hint ?? "ids, hashes, raw records and every field, as engineers and auditors see them"}</span>
      </summary>
      <div className="border-t border-gray-5 p-4">{children}</div>
    </details>
  );
}
