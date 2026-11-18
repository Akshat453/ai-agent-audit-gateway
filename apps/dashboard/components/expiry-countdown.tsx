"use client";

import { useEffect, useState } from "react";

import { cn } from "@/lib/cn";

/** Live expiry countdown. Server-rendered value first (readable without JS); turns amber under
 *  2 minutes and reads EXPIRED at zero. The gateway enforces expiry by its own clock regardless
 *  of what this shows. */
export function Countdown({ expiresAt, initialSeconds, compact = false, testId = "countdown" }: {
  expiresAt: string; initialSeconds: number; compact?: boolean; testId?: string;
}) {
  const [left, setLeft] = useState(initialSeconds);
  useEffect(() => {
    const end = Date.parse(expiresAt);
    const tick = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);
  if (left <= 0) {
    return <span className="font-semibold text-bad-11" data-testid={testId}>EXPIRED</span>;
  }
  const h = Math.floor(left / 3600);
  const m = Math.floor((left % 3600) / 60);
  const s = String(left % 60).padStart(2, "0");
  const clock = h ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
  return (
    <span data-testid={testId} aria-live={compact ? "off" : "polite"}
      className={cn("font-mono font-medium tabular", left < 120 ? "rounded-sm bg-warn-3 px-1 text-warn-12" : "text-gray-12")}>
      {compact ? clock : `expires in ${clock}`}
    </span>
  );
}
