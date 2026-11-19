"use client";

import { useEffect, useState } from "react";

import { Tooltip } from "@/components/ui/overlay";
import { EMPTY } from "@/lib/format";
import { ago, longTime } from "@/src/humanize";

/** "18 Nov 2026, 11:18:15 PM IST · 2 h ago" with the exact UTC ISO time on hover (ADR-0039).
 *  The server renders the UTC time first (it cannot know the viewer's zone, and there must be
 *  no hydration mismatch); the browser switches to the chosen zone after mount. */
export function Timestamp({ iso, tz = "local", className, compact = false }: { iso: string | null | undefined; tz?: string; className?: string; compact?: boolean }) {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 15_000);
    return () => clearInterval(id);
  }, []);
  if (!iso) return <span className="text-gray-11">{EMPTY}</span>;
  const exactUtc = new Date(iso).toISOString();
  const known = tz !== "local"; // "utc" or an IANA zone: same text on server and browser
  const shown = now === null ? (known && !compact ? longTime(iso, tz) : longTime(iso, "utc")) : compact ? ago(iso, now) : `${longTime(iso, tz)} · ${ago(iso, now)}`;
  return (
    <Tooltip content={`${exactUtc} (UTC)`}>
      <time dateTime={iso} tabIndex={0} className={className ?? "whitespace-nowrap text-gray-11"}>
        {shown}
      </time>
    </Tooltip>
  );
}
