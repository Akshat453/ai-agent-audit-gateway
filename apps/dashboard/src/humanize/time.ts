/** Times in words (ADR-0039): "18 Nov 2026, 11:18:15 PM IST · 2 h ago", exact UTC on hover,
 *  durations as "approved 5 min later". Local time is only correct in the browser; the server
 *  renders UTC and <Timestamp> switches after mount. */

const MS = { s: 1000, min: 60_000, h: 3_600_000, d: 86_400_000 };

/** "utc", "local" (the runtime's zone) or an IANA zone such as "Asia/Kolkata". The server runs on
 *  UTC, so pages pass the viewer's zone from the agw_zone cookie (lib/prefs.ts). */
export type Tz = string;

function validZone(z: string): boolean {
  try { new Intl.DateTimeFormat("en-GB", { timeZone: z }); return true; } catch { return false; }
}

/** Intl options for a Tz. */
export function zoneOpts(tz: Tz): Intl.DateTimeFormatOptions {
  if (tz === "utc") return { timeZone: "UTC" };
  if (tz === "local" || !validZone(tz)) return {};
  return { timeZone: tz };
}

function zoneName(d: Date, tz: Tz = "local"): string {
  try {
    const parts = new Intl.DateTimeFormat("en-IN", { timeZoneName: "short", ...zoneOpts(tz) }).formatToParts(d);
    return parts.find((p) => p.type === "timeZoneName")?.value ?? "";
  } catch {
    return "";
  }
}

/** "18 Nov 2026, 11:18:15 PM IST" (local) or "18 Nov 2026, 5:48:15 PM UTC". */
export function longTime(iso: string | null | undefined, tz: Tz = "local"): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const opts: Intl.DateTimeFormatOptions = {
    day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true,
    ...zoneOpts(tz),
  };
  const text = new Intl.DateTimeFormat("en-GB", opts).format(d).replace(/\b(am|pm)\b/, (m) => m.toUpperCase());
  return `${text} ${tz === "utc" ? "UTC" : zoneName(d, tz)}`.trim();
}

/** "18 Nov, 11:18 PM" */
export function shortDate(iso: string | null | undefined, tz: Tz = "local"): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true, ...zoneOpts(tz),
  }).format(d).replace(/\b(am|pm)\b/, (m) => m.toUpperCase());
}

/** "11:18 PM" */
export function clock(iso: string | null | undefined, tz: Tz = "local"): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", { hour: "numeric", minute: "2-digit", hour12: true, ...zoneOpts(tz) })
    .format(d).replace(/\b(am|pm)\b/, (m) => m.toUpperCase());
}

/** 300 -> "5 min", 7200 -> "2 h", 90000 -> "1 day". */
export function spanWords(seconds: number): string {
  const ms = Math.abs(seconds) * 1000;
  if (ms < 60 * MS.s) return `${Math.max(1, Math.round(ms / MS.s))} s`;
  if (ms < MS.h) return `${Math.round(ms / MS.min)} min`;
  if (ms < MS.d) { const h = Math.round(ms / MS.h); return `${h} h`; }
  const d = Math.round(ms / MS.d);
  return `${d} day${d === 1 ? "" : "s"}`;
}

/** "2 h ago" / "in 4 min" / "just now". */
export function ago(iso: string | null | undefined, now: number): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const diff = (now - t) / 1000;
  if (Math.abs(diff) < 5) return "just now";
  return diff > 0 ? `${spanWords(diff)} ago` : `in ${spanWords(-diff)}`;
}

/** ("…10:00", "…10:05") -> "5 min later"; under 5 s -> "right away". */
export function later(from: string | null | undefined, to: string | null | undefined): string {
  if (!from || !to) return "";
  const s = (Date.parse(to) - Date.parse(from)) / 1000;
  if (Number.isNaN(s)) return "";
  return s < 5 ? "right away" : `${spanWords(s)} later`;
}
