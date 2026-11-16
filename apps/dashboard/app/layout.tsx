import "./globals.css";

import type { Metadata } from "next";
import type { ReactNode } from "react";

import { CsrfField } from "@/components/ui";
import { gatewayFor } from "@/lib/gateway";
import { csrfFor, sessionToken } from "@/lib/session";

export const metadata: Metadata = {
  title: "AGW audit dashboard",
  description: "Read-only investigation and approvals over the AI agent audit gateway",
};
export const dynamic = "force-dynamic"; // per-request CSP nonce (proxy.ts)

const NAV: { href: string; label: string; roles?: string[] }[] = [
  { href: "/", label: "Overview" },
  { href: "/runs", label: "Runs" },
  { href: "/approvals", label: "Approvals" },
  { href: "/evidence", label: "Evidence" },
  { href: "/epochs", label: "Epochs & anchors" },
  { href: "/verification", label: "Verification" },
  { href: "/policies", label: "Policies" },
  { href: "/incidents", label: "Incidents" },
];

export default async function RootLayout({ children }: { children: ReactNode }) {
  const token = await sessionToken();
  let who: { username: string; roles: string[]; tenant: string } | null = null;
  if (token) {
    const { data } = await gatewayFor(token).GET("/v1/dashboard/config");
    who = data ? { username: data.username, roles: data.roles, tenant: data.tenant } : null;
  }
  return (
    <html lang="en">
      <body>
        <a href="#main" className="sr-only focus:not-sr-only">Skip to content</a>
        <header className="border-b border-slate-300 bg-white">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-2">
            <span className="font-bold">AGW audit</span>
            {who ? (
              <>
                <nav aria-label="Main" className="flex flex-wrap gap-3 text-sm">
                  {NAV.map((n) => (
                    <a key={n.href} href={n.href}>{n.label}</a>
                  ))}
                </nav>
                <span className="ml-auto text-sm" data-testid="whoami">
                  {who.username} ({who.roles.join(", ")}) · tenant {who.tenant}
                </span>
                <form method="post" action="/api/auth/logout">
                  <CsrfField csrf={token ? csrfFor(token) : ""} />
                  <button className="rounded border border-slate-400 px-2 py-0.5 text-sm" type="submit">
                    Log out
                  </button>
                </form>
              </>
            ) : null}
          </div>
        </header>
        {children}
        <footer className="mx-auto max-w-7xl px-4 pb-6 text-xs text-slate-600">
          Dashboard status is a convenience view; independent verification uses the CLI
          (agw-verify) on exported bundles with trust roots obtained out of band.
        </footer>
      </body>
    </html>
  );
}
