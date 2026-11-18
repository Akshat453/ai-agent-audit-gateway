import { Check } from "lucide-react";

import { cn } from "@/lib/cn";

/** Wizard progress (C2 add-connector flow). Past steps are links back when `hrefs` has one. */
export function Stepper({ steps, current, hrefs = {} }: { steps: { id: string; label: string }[]; current: string; hrefs?: Record<string, string> }) {
  const at = steps.findIndex((s) => s.id === current);
  return (
    <nav aria-label="Progress" className="mb-6">
      <ol className="flex flex-wrap items-center gap-2 text-caption">
        {steps.map((s, i) => {
          const done = i < at;
          const now = i === at;
          const inner = (
            <>
              <span aria-hidden="true" className={cn("flex size-5 items-center justify-center rounded-full border text-[11px] font-semibold",
                done ? "border-ok-9 bg-ok-9 text-white dark:text-gray-1" : now ? "border-brand-9 text-brand-11" : "border-gray-7 text-gray-11")}>
                {done ? <Check className="size-3" strokeWidth={3} /> : i + 1}
              </span>
              <span className={cn(now ? "font-semibold text-gray-12" : "text-gray-11")}>{s.label}</span>
            </>
          );
          return (
            <li key={s.id} className="flex items-center gap-2" aria-current={now ? "step" : undefined}>
              {i > 0 ? <span aria-hidden="true" className="h-px w-6 bg-gray-6" /> : null}
              {done && hrefs[s.id] ? <a href={hrefs[s.id]} className="flex items-center gap-1.5 no-underline">{inner}</a> : <span className="flex items-center gap-1.5">{inner}</span>}
              {done ? <span className="sr-only">(completed)</span> : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
