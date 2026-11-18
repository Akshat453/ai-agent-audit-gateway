import { ShieldAlert, ShieldCheck } from "lucide-react";

import { CsrfField } from "@/components/legacy";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

/** Inline step-up (password re-entry) for admin changes (C2). The same plain CSRF form as the
 *  CRITICAL-approval step-up; `next` brings the admin back to this page. The gateway enforces
 *  the step-up window on every change (STEP_UP_REQUIRED) whatever this card shows. */
export function StepUpCard({ csrf, next, remaining, windowSeconds, what }: {
  csrf: string; next: string; remaining: number | null; windowSeconds: number; what: string;
}) {
  if (remaining && remaining > 0) {
    return (
      <p data-testid="step-up-ok" className="mb-4 inline-flex items-center gap-1.5 rounded-md border border-ok-7 bg-ok-3 px-3 py-1.5 text-caption font-medium text-ok-12">
        <ShieldCheck aria-hidden="true" className="size-4 text-ok-11" />
        Step-up active · {Math.max(1, Math.round(remaining / 60))} min left
      </p>
    );
  }
  return (
    <form method="post" action="/api/auth/step-up" data-testid="step-up-form"
      className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-warn-7 bg-warn-3 p-3">
      <CsrfField csrf={csrf} />
      <input type="hidden" name="next" value={next} />
      <div className="min-w-0 flex-1 basis-64">
        <div className="mb-1 flex items-center gap-1.5 text-dense font-medium text-warn-12">
          <ShieldAlert aria-hidden="true" className="size-4 text-warn-11" />Step-up required to {what}
        </div>
        <Label htmlFor="stepup-pw" className="text-warn-12">Re-enter your password (step-up, valid {Math.round(windowSeconds / 60)} min)</Label>
        <Input id="stepup-pw" name="password" type="password" required autoComplete="current-password" className="mt-1.5 max-w-sm" />
      </div>
      <Button type="submit" size="md">Re-authenticate</Button>
    </form>
  );
}
