"use client";

import { useEffect, useState } from "react";

import { Tooltip } from "@/components/ui/overlay";
import { EMPTY, exact, relative } from "@/lib/format";

/** Relative time ("3 min ago") with the exact time on hover. The server renders the exact UTC
 *  time first (no hydration mismatch); the browser switches to relative after mount. */
export function Timestamp({ iso, tz = "utc", className }: { iso: string | null | undefined; tz?: "utc" | "local"; className?: string }) {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 15_000);
    return () => clearInterval(id);
  }, []);
  if (!iso) return <span className="text-gray-11">{EMPTY}</span>;
  const full = exact(iso, tz);
  return (
    <Tooltip content={`${full}${tz === "local" ? "" : " (UTC)"}`}>
      <time dateTime={iso} tabIndex={0} className={className ?? "whitespace-nowrap text-gray-11"}>
        {now === null ? exact(iso, "utc") : relative(iso, now)}
      </time>
    </Tooltip>
  );
}
