import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

/** Pure-SVG sparkline (attributes only, no style attribute: CSP-safe on the server). */
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  if (values.length < 2) return null;
  const w = 96;
  const h = 28;
  const max = Math.max(1, ...values);
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`);
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label} className="shrink-0 overflow-visible">
      <polyline points={`0,${h} ${pts.join(" ")} ${w},${h}`} className="fill-brand-3 stroke-none" />
      <polyline points={pts.join(" ")} className="fill-none stroke-brand-9" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/** KPI tile: value, delta vs previous period, sparkline, link (§5 Overview). `goodWhen` says
 *  which direction is good so the delta is colored by meaning, not by sign. */
export function KpiTile({ label, value, sub, delta, goodWhen = "up", spark, href, linkLabel, tone }: {
  label: string; value: ReactNode; sub?: ReactNode; delta?: number | null; goodWhen?: "up" | "down" | "neutral";
  spark?: number[]; href: string; linkLabel: string; tone?: "ok" | "warn" | "bad";
}) {
  let deltaEl: ReactNode = null;
  if (delta !== undefined) {
    if (delta === null) deltaEl = <span className="text-caption text-gray-11">new this period</span>;
    else {
      const flat = Math.abs(delta) < 0.5;
      const up = delta > 0;
      const good = goodWhen === "neutral" || flat ? null : goodWhen === "up" ? up : !up;
      const Icon = flat ? Minus : up ? ArrowUpRight : ArrowDownRight;
      deltaEl = (
        <span className={cn("inline-flex items-center gap-0.5 text-caption font-medium tabular",
          good === null ? "text-gray-11" : good ? "text-ok-11" : "text-bad-11")}>
          <Icon aria-hidden="true" className="size-3.5" />
          {flat ? "no change" : `${up ? "+" : ""}${delta.toFixed(0)}%`}
          <span className="font-normal text-gray-11">&nbsp;vs previous</span>
        </span>
      );
    }
  }
  return (
    <a href={href} aria-label={`${label}: ${linkLabel}`}
      className="group flex min-w-0 flex-col justify-between gap-3 rounded-md border border-gray-6 bg-gray-1 p-4 text-gray-12 no-underline transition-colors hover:border-gray-8 hover:bg-gray-2 hover:no-underline">
      <div className="flex items-start justify-between gap-2">
        <span className="text-caption font-medium text-gray-11">{label}</span>
        {tone ? <span aria-hidden="true" className={cn("mt-1 size-2 rounded-full", tone === "ok" ? "bg-ok-9" : tone === "warn" ? "bg-warn-9" : "bg-bad-9")} /> : null}
      </div>
      <div className="flex items-end justify-between gap-2">
        <div className="min-w-0">
          <div className="text-kpi font-semibold tabular tracking-tight">{value}</div>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5">{deltaEl}{sub ? <span className="text-caption text-gray-11">{sub}</span> : null}</div>
        </div>
        {spark ? <Sparkline values={spark} label={`${label} trend`} /> : null}
      </div>
    </a>
  );
}
