/** Data formatting (docs/gateway/16-dashboard-design.md §3.5). Pure functions: safe on the
 *  server and in the browser. Empty values render as an em dash (the UI mutes it). */

export const EMPTY = "—";

const NUM = new Intl.NumberFormat("en-US");

export function count(n: number | null | undefined): string {
  return n === null || n === undefined ? EMPTY : NUM.format(n);
}

/** "a3f9c1…7be2": keeps both ends of a hash / id so a human can match it. */
export function middle(value: string | null | undefined, head = 6, tail = 4): string {
  if (!value) return EMPTY;
  const v = value.startsWith("0x") ? value.slice(2) : value;
  const prefix = value.startsWith("0x") ? "0x" : "";
  return v.length <= head + tail + 1 ? value : `${prefix}${v.slice(0, head)}…${v.slice(-tail)}`;
}

/** Human durations: "850 ms", "1.2 s", "4 min", "3.5 h", "2.1 d". */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return EMPTY;
  const s = Math.abs(seconds);
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 10) return `${s.toFixed(1)} s`;
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} d`;
}

/** "3 min ago" / "in 4 min" relative to `now` (ms). */
export function relative(iso: string | null | undefined, now: number): string {
  if (!iso) return EMPTY;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return EMPTY;
  const diff = (now - t) / 1000;
  if (Math.abs(diff) < 5) return "just now";
  return diff > 0 ? `${duration(diff)} ago` : `in ${duration(-diff)}`;
}

/** Exact time in UTC ("2026-11-16 13:38:54Z") or the viewer's local zone. */
export function exact(iso: string | null | undefined, tz: "utc" | "local" = "utc"): string {
  if (!iso) return EMPTY;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return EMPTY;
  if (tz === "utc") return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  return d.toLocaleString("en-GB", { hour12: false, timeZoneName: "short" });
}

/** Percent change vs the previous period; null when there is nothing to compare. */
export function delta(current: number, previous: number): number | null {
  if (previous === 0) return current === 0 ? 0 : null;
  return ((current - previous) / previous) * 100;
}

export const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
