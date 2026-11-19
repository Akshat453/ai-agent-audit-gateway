import "./globals.css";

import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata } from "next";
import { cookies as cookieJar, headers } from "next/headers";
import type { ReactNode } from "react";

import { AppShell, type ShellHealth } from "@/components/shell/app-shell";
import { NonceSetter } from "@/components/shell/nonce";
import { ZoneCookie } from "@/components/shell/zone-cookie";
import { PRODUCT_NAME } from "@/lib/brand";
import { cn } from "@/lib/cn";
import { gatewayFor } from "@/lib/gateway";
import { visibleNav } from "@/lib/nav";
import { prefs as readPrefs } from "@/lib/prefs";
import { csrfFor, nonce as readNonce, sessionToken } from "@/lib/session";

export const metadata: Metadata = {
  title: { default: PRODUCT_NAME, template: `%s · ${PRODUCT_NAME}` },
  description: "Investigation, approvals and tamper-evident evidence for AI agent actions",
};
export const dynamic = "force-dynamic"; // per-request CSP nonce (proxy.ts) + per-user prefs

function worst(chips: { name: string; status: string }[]): ShellHealth {
  const bad = chips.filter((c) => c.status === "down");
  const degraded = chips.filter((c) => c.status === "degraded");
  if (bad.length) return { worst: "down", summary: `Down: ${bad.map((c) => c.name).join(", ")}` };
  if (degraded.length) return { worst: "degraded", summary: `Degraded: ${degraded.map((c) => c.name).join(", ")}` };
  if (!chips.length) return { worst: "off", summary: "Health unknown" };
  return { worst: "ok", summary: "All systems normal" };
}

export default async function RootLayout({ children }: { children: ReactNode }) {
  const [token, p, nonce] = await Promise.all([sessionToken(), readPrefs(), readNonce()]);
  const fonts = cn(GeistSans.variable, GeistMono.variable);
  const htmlClass = cn(fonts, p.theme === "dark" ? "dark" : "light", p.density === "compact" && "density-compact");

  const path = (await headers()).get("x-pathname") ?? "";
  const standalone = /^\/(login|signup)(\/|\?|$)/.test(path);
  let shell: ReactNode = null;
  if (token && !standalone) {
    const gw = gatewayFor(token);
    const repos = ((await gw.GET("/v1/dashboard/repo-choices")).data ?? []) as { repo_id: string; name: string; sessions: number }[];
    const scoped = repos.find((r) => r.repo_id === p.repo)?.repo_id; // ADR-0040
    const [session, pending, alerts, health] = await Promise.all([
      gw.GET("/v1/dashboard/session"),
      gw.GET("/v1/dashboard/approvals", { params: { query: { state: "PENDING", limit: 1, ...(scoped ? { repo_id: scoped } : {}) } } }),
      gw.GET("/v1/dashboard/alerts", { params: { query: { limit: 100 } } }),
      gw.GET("/v1/dashboard/health"),
    ]);
    const s = session.data;
    if (s) {
      const dayAgo = Date.now() - 86_400_000;
      shell = (
        <AppShell
          user={{ username: s.username, roles: s.roles, tenant: s.tenant, env: s.env, stepUpRemaining: s.step_up_remaining_seconds ?? null, stepUpWindow: s.step_up_window_seconds }}
          nav={visibleNav(s.roles)}
          pendingApprovals={pending.data?.total ?? 0}
          alerts24h={(alerts.data ?? []).filter((a) => a.created_at && Date.parse(a.created_at) > dayAgo).length}
          health={worst(health.data ?? [])}
          csrf={csrfFor(token)}
          prefs={p}
          repos={repos}
        >
          {children}
        </AppShell>
      );
    }
  }
  return (
    <html lang="en" className={htmlClass} suppressHydrationWarning>
      <body>
        <NonceSetter nonce={nonce} />
        <ZoneCookie current={(await cookieJar()).get("agw_zone")?.value ?? ""} />
        {shell ?? children}
        {/* Logout is a plain CSRF-protected form POST; the user menu submits it. */}
        {token ? (
          <form id="logout-form" method="post" action="/api/auth/logout" hidden>
            <input type="hidden" name="csrf" value={csrfFor(token)} />
            <button type="submit">Log out</button>
          </form>
        ) : null}
      </body>
    </html>
  );
}
