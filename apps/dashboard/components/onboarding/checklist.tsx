import { ArrowRight, CheckCircle2, Circle, Lock } from "lucide-react";

import { Card, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import type { Onboarding } from "@/lib/connectors";

/** New-tenant checklist on Overview (C2). Every step's `done` is derived by the gateway from real
 *  state. Admins get links to the step; others see progress only. */
export function OnboardingChecklist({ data, isAdmin }: { data: Onboarding; isAdmin: boolean }) {
  const steps = data.steps;
  const done = steps.filter((s) => s.done).length;
  return (
    <Card className="mb-6" data-testid="onboarding">
      <CardHeader title="Get started" description={`${done} of ${steps.length} steps done${isAdmin ? "" : " · an admin completes these"}`} id="onboarding-title" />
      <ol aria-labelledby="onboarding-title" className="grid gap-x-6 gap-y-1 p-3 sm:grid-cols-2 xl:grid-cols-3">
        {steps.map((s) => {
          const unavailable = s.available === false;
          const Icon = s.done ? CheckCircle2 : unavailable ? Lock : Circle;
          const body = (
            <>
              <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", s.done ? "text-ok-11" : "text-gray-11")} />
              <span className="min-w-0">
                <span className={cn("block", s.done ? "text-gray-11 line-through decoration-gray-8" : "text-gray-12")}>{s.label}</span>
                <span className="sr-only">{s.done ? " (done)" : unavailable ? " (not available yet)" : " (to do)"}</span>
                {s.note ? <span className="block text-caption text-gray-11">{s.note}</span> : null}
              </span>
            </>
          );
          const link = isAdmin && !s.done && !unavailable && s.href;
          return (
            <li key={s.id} data-testid={`onboarding-${s.id}`} data-disabled={unavailable ? "true" : undefined}>
              {link ? (
                <a href={s.href} className="group flex items-start gap-2 rounded-md px-2 py-1.5 text-dense no-underline hover:bg-gray-3 hover:no-underline">
                  {body}<ArrowRight aria-hidden="true" className="ml-auto mt-0.5 size-3.5 shrink-0 text-gray-11 group-hover:text-gray-12" />
                </a>
              ) : (
                <div className="flex items-start gap-2 px-2 py-1.5 text-dense">{body}</div>
              )}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}
