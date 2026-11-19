import "server-only";

import { cookies } from "next/headers";

/** Per-user UI preferences (theme, density, timezone, nav rail). Plain, non-secret cookies the
 *  SERVER reads to render the right <html> classes, so there is no flash and no inline script.
 *  They are written only through POST /api/prefs (same-origin + CSRF). */
export type Prefs = {
  theme: "light" | "dark";
  density: "comfortable" | "compact";
  tz: "utc" | "local";
  nav: "expanded" | "collapsed";
  /** ADR-0039: plain-English first (simple, the default) or today's technical layout. */
  view: "simple" | "technical";
  /** ADR-0040: the repository the console is scoped to ("all" = every repository). */
  repo: string;
};

export const REPO_COOKIE = "agw_repo";
export const REPO_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const PREF_COOKIES: { [K in Exclude<keyof Prefs, "repo">]: { name: string; values: readonly Prefs[K][] } } = {
  theme: { name: "agw_theme", values: ["light", "dark"] },
  density: { name: "agw_density", values: ["comfortable", "compact"] },
  tz: { name: "agw_tz", values: ["local", "utc"] }, // first value = default (ADR-0039: local)
  nav: { name: "agw_nav", values: ["expanded", "collapsed"] },
  view: { name: "agw_view", values: ["simple", "technical"] },
};

export async function prefs(): Promise<Prefs> {
  const jar = await cookies();
  const pick = <K extends Exclude<keyof Prefs, "repo">>(k: K): Prefs[K] => {
    const v = jar.get(PREF_COOKIES[k].name)?.value as Prefs[K] | undefined;
    return v && (PREF_COOKIES[k].values as readonly string[]).includes(v) ? v : (PREF_COOKIES[k].values[0] as Prefs[K]);
  };
  return { theme: pick("theme"), density: pick("density"), tz: pick("tz"), nav: pick("nav"), view: pick("view"), repo: REPO_RE.test(jar.get(REPO_COOKIE)?.value ?? "") ? (jar.get(REPO_COOKIE)?.value as string) : "all" };
}
