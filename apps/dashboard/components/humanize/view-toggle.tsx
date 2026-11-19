"use client";

import { useOptionalShell } from "@/components/shell/context";
import { cn } from "@/lib/cn";

/** The small Simple / Technical switch in every page header (the user menu has the same
 *  setting). Remembered per user (cookie, server-rendered). */
export function ViewToggle() {
  const shell = useOptionalShell();
  if (!shell) return null;
  const v = shell.prefs.view;
  return (
    <div role="group" aria-label="View" className="inline-flex rounded-md border border-gray-7 p-0.5 text-caption" data-testid="view-toggle">
      {(["simple", "technical"] as const).map((k) => (
        <button key={k} type="button" aria-pressed={v === k} onClick={() => void shell.setPref("view", k)}
          className={cn("rounded-sm px-2 py-0.5 font-medium", v === k ? "bg-gray-4 text-gray-12" : "text-gray-11 hover:text-gray-12")}>
          {k === "simple" ? "Simple" : "Technical"}
        </button>
      ))}
    </div>
  );
}
