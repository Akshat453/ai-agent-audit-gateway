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
};

export const PREF_COOKIES: { [K in keyof Prefs]: { name: string; values: readonly Prefs[K][] } } = {
  theme: { name: "agw_theme", values: ["light", "dark"] },
  density: { name: "agw_density", values: ["comfortable", "compact"] },
  tz: { name: "agw_tz", values: ["utc", "local"] },
  nav: { name: "agw_nav", values: ["expanded", "collapsed"] },
};

export async function prefs(): Promise<Prefs> {
  const jar = await cookies();
  const pick = <K extends keyof Prefs>(k: K): Prefs[K] => {
    const v = jar.get(PREF_COOKIES[k].name)?.value as Prefs[K] | undefined;
    return v && (PREF_COOKIES[k].values as readonly string[]).includes(v) ? v : (PREF_COOKIES[k].values[0] as Prefs[K]);
  };
  return { theme: pick("theme"), density: pick("density"), tz: pick("tz"), nav: pick("nav") };
}
