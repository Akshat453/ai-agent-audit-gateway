"use client";

import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Skeleton } from "@/components/ui/input";
import { SERIES } from "@/lib/series";

export type Bucket = { start: string; ALLOW: number; DENY: number; REQUIRE_APPROVAL: number; total: number };


function tick(iso: string, range: string): string {
  const d = new Date(iso);
  if (range === "24h") return `${String(d.getUTCHours()).padStart(2, "0")}:00`;
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
}

/** Recharts is rendered ONLY after mount: its SVG/tooltip styles are then applied through the
 *  CSSOM, which the strict CSP allows, instead of server-rendered style attributes, which it
 *  blocks (ADR-0033 §2, verified by the CSP e2e test). */
export function ActivityChart({ buckets, range }: { buckets: Bucket[]; range: string }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <Skeleton className="h-56 w-full" />;
  const data = buckets.map((b) => ({ ...b, label: tick(b.start, range) }));
  return (
    <div className="h-56 w-full" role="img" aria-label="Stacked area chart of actions per bucket by decision; the same numbers are in the table below">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }} accessibilityLayer={false}>
          <CartesianGrid vertical={false} stroke="var(--slate-5)" />
          <XAxis dataKey="label" tickLine={false} axisLine={{ stroke: "var(--slate-6)" }} tick={{ fill: "var(--slate-11)", fontSize: 11 }} minTickGap={24} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: "var(--slate-11)", fontSize: 11 }} width={44} />
          <Tooltip
            cursor={{ stroke: "var(--slate-8)", strokeWidth: 1 }}
            contentStyle={{ background: "var(--slate-1)", border: "1px solid var(--slate-6)", borderRadius: 6, fontSize: 12, color: "var(--slate-12)" }}
            labelStyle={{ color: "var(--slate-11)", marginBottom: 4 }}
          />
          {SERIES.map((s) => (
            <Area key={s.key} type="monotone" dataKey={s.key} name={s.label} stackId="1" stroke={s.color} strokeWidth={2}
              fill={s.color} fillOpacity={0.18} isAnimationActive={false} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
