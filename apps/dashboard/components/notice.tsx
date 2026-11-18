import { CheckCircle2, CircleAlert, Info, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

const KIND = {
  info: ["border-info-7 bg-info-3 text-info-12", Info, "text-info-11"],
  good: ["border-ok-7 bg-ok-3 text-ok-12", CheckCircle2, "text-ok-11"],
  warn: ["border-warn-7 bg-warn-3 text-warn-12", TriangleAlert, "text-warn-11"],
  bad: ["border-bad-7 bg-bad-3 text-bad-12", CircleAlert, "text-bad-11"],
} as const;

/** Inline message. role=alert for failures, role=status otherwise (screen readers, tests). */
export function Notice({ kind = "info", children, className }: { kind?: keyof typeof KIND; children: ReactNode; className?: string }) {
  const [cls, Icon, iconCls] = KIND[kind];
  return (
    <div role={kind === "bad" ? "alert" : "status"} className={cn("mb-4 flex gap-2.5 rounded-md border px-3.5 py-2.5 text-dense", cls, className)}>
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", iconCls)} />
      <div className="min-w-0">{children}</div>
    </div>
  );
}
