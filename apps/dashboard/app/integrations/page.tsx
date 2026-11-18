import { ArrowRight, Plus, Search } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { EmptyState, ErrorState } from "@/components/empty-state";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { message, viewer } from "@/lib/c2";
import { cn } from "@/lib/cn";
import {
  CATEGORY_HELP, CATEGORY_LABEL, CATEGORY_ORDER, connectorStatusKey, tierKey,
  type CatalogType, type Category, type ConnectorSummary,
} from "@/lib/connectors";
import { prefs } from "@/lib/prefs";

export const metadata: Metadata = { title: "Integrations" };

export default async function Integrations({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  // Onboarding links (/integrations?add=github) go straight to the add flow.
  if (sp.add && /^[a-z][a-z0-9_]{1,40}$/.test(sp.add)) redirect(`/integrations/new?type=${sp.add}`);
  const { gw, isAdmin } = await viewer();
  const [cat, list, p] = await Promise.all([gw.GET("/v1/connectors/catalog"), gw.GET("/v1/connectors"), prefs()]);
  const types = ((cat.data as { types?: CatalogType[] } | undefined)?.types ?? []);
  if (list.response.status === 403 || !cat.data) {
    return (
      <div className="mx-auto max-w-7xl">
        <PageHeader title="Integrations" help="integrations" crumbs={[{ label: "Setup" }, { label: "Integrations" }]} />
        <ErrorState what={list.response.status === 403 ? "Your role cannot view integrations (admin, auditor or security)." : "The gateway did not return the integration catalog."}
          requestId={list.response.headers.get("x-request-id")} retryHref="/integrations" />
      </div>
    );
  }
  const installed = ((list.data as { connectors?: ConnectorSummary[] } | undefined)?.connectors ?? []);
  const q = (sp.q ?? "").trim().toLowerCase().slice(0, 80);
  const category = CATEGORY_ORDER.includes(sp.category as Category) ? (sp.category as Category) : null;
  const shown = types.filter((t) => (!category || t.category === category) &&
    (!q || `${t.name} ${t.id} ${t.description} ${CATEGORY_LABEL[t.category]}`.toLowerCase().includes(q)));
  const byType = new Map<string, number>();
  for (const c of installed) byType.set(c.type_id, (byType.get(c.type_id) ?? 0) + 1);
  const msg = message(sp.result ?? (sp.error === "github" ? "GITHUB" : sp.error));
  const chip = (label: string, cat: Category | null) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (cat) params.set("category", cat);
    const href = `/integrations${params.toString() ? `?${params}` : ""}`;
    const on = cat === category;
    return (
      <a key={label} href={href} aria-current={on ? "true" : undefined}
        className={cn("rounded-full border px-2.5 py-1 text-caption font-medium no-underline hover:no-underline",
          on ? "border-brand-8 bg-brand-3 text-brand-12" : "border-gray-7 text-gray-11 hover:bg-gray-3 hover:text-gray-12")}>
        {label}
      </a>
    );
  };

  return (
    <div className="mx-auto max-w-[1440px]">
      <PageHeader
        title="Integrations"
        help="integrations"
        crumbs={[{ label: "Setup" }, { label: "Integrations" }]}
        description="Connect code hosting, coding agents, notification channels, APIs and MCP servers. Every connector action is a gateway tool: denied until an admin classifies it."
      />
      {sp.error === "github" ? <Notice kind="bad">GitHub did not complete the App registration or installation (the link expired or was already used). Start again from the GitHub connector.</Notice>
        : msg ? <Notice kind={msg.kind}>{msg.text}</Notice> : null}

      <Card className="mb-6">
        <CardHeader title="Installed" description={`${installed.length} connector${installed.length === 1 ? "" : "s"} in this tenant`} />
        {installed.length === 0 ? (
          <EmptyState title="No connectors yet">Add one from the catalog below. A good first step is a notification channel, so approvers hear about pending approvals.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-dense" data-testid="installed">
              <caption className="sr-only">Installed connectors</caption>
              <thead className="border-b border-gray-5 bg-gray-2 text-left text-caption text-gray-11">
                <tr>
                  <th scope="col" className="px-4 py-2 font-medium">Name</th>
                  <th scope="col" className="px-4 py-2 font-medium">Type</th>
                  <th scope="col" className="px-4 py-2 font-medium">Status</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Unclassified actions</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Policy version</th>
                  <th scope="col" className="px-4 py-2 font-medium">Added</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-4">
                {installed.map((c) => (
                  <tr key={c.connector_id ?? c.slug} className="h-[var(--row-h)]">
                    <td className="px-4 py-2">
                      {c.connector_id ? <a href={`/integrations/${c.connector_id}`} className="font-medium">{c.name}</a> : <span className="font-medium">{c.name}</span>}
                      <span className="ml-2 font-mono text-caption text-gray-11">{c.slug}</span>
                    </td>
                    <td className="px-4 py-2 text-gray-11">{types.find((t) => t.id === c.type_id)?.name ?? c.type_id} · {CATEGORY_LABEL[c.category] ?? c.category}</td>
                    <td className="px-4 py-2"><span className="inline-flex flex-wrap gap-1.5"><StatusBadge value={connectorStatusKey(c.status)} />{c.read_only ? <StatusBadge value="READ_ONLY" /> : null}</span></td>
                    <td className="px-4 py-2 text-right tabular">
                      {c.unclassified_actions ? <span className="font-medium text-bad-11" data-testid="unclassified-count">{c.unclassified_actions}</span> : <span className="text-gray-11">0</span>}
                    </td>
                    <td className="px-4 py-2 text-right tabular">{c.read_only ? <span className="text-gray-11">—</span> : `v${c.policy_version}`}</td>
                    <td className="px-4 py-2">{c.created_at ? <Timestamp iso={c.created_at} tz={p.tz} /> : <span className="text-gray-11">operator settings</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <section aria-labelledby="catalog-title">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="catalog-title" className="text-section font-semibold">Catalog</h2>
            <p className="text-caption text-gray-11">{isAdmin ? "Add a connector; you will configure it, test it and classify its actions." : "Only an admin can add connectors."}</p>
          </div>
          <form method="get" action="/integrations" role="search" className="flex items-center gap-2">
            {category ? <input type="hidden" name="category" value={category} /> : null}
            <label htmlFor="catalog-q" className="sr-only">Search the catalog</label>
            <div className="relative">
              <Search aria-hidden="true" className="pointer-events-none absolute left-2 top-2 size-4 text-gray-11" />
              <Input id="catalog-q" name="q" type="search" defaultValue={q} placeholder="Search integrations" className="w-64 pl-8" />
            </div>
            <button type="submit" className={buttonVariants({ variant: "secondary" })}>Search</button>
          </form>
        </div>
        <nav aria-label="Categories" className="mb-4 flex flex-wrap gap-2">
          {chip("All", null)}
          {CATEGORY_ORDER.map((c) => chip(CATEGORY_LABEL[c], c))}
        </nav>

        {shown.length === 0 ? (
          <EmptyState title="No integration matches">Clear the search or pick another category.</EmptyState>
        ) : (
          CATEGORY_ORDER.filter((c) => shown.some((t) => t.category === c)).map((c) => (
            <section key={c} aria-labelledby={`cat-${c}`} className="mb-6">
              <h3 id={`cat-${c}`} className="text-dense font-semibold text-gray-12">{CATEGORY_LABEL[c]}</h3>
              <p className="mb-2 text-caption text-gray-11">{CATEGORY_HELP[c]}</p>
              <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {shown.filter((t) => t.category === c).map((t) => {
                  const n = byType.get(t.id) ?? 0;
                  const tier = tierKey(t.setup.tier);
                  return (
                    <li key={t.id} className="flex flex-col justify-between gap-3 rounded-md border border-gray-6 bg-gray-1 p-4" data-testid={`type-${t.id}`}>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-dense font-semibold">{t.name}</h4>
                          {tier ? <StatusBadge value={tier} size="sm" /> : null}
                          {t.setup.read_only ? <StatusBadge value="READ_ONLY" size="sm" /> : null}
                          {n ? <span className="rounded-sm bg-gray-3 px-1.5 text-caption text-gray-12">{n} installed</span> : null}
                        </div>
                        <p className="mt-1 text-caption text-gray-11">{t.description}</p>
                        <p className="mt-2 text-caption text-gray-11">
                          {t.category === "agent_client" ? (t.setup.tier_reason ?? "") : t.dynamic_actions ? "Actions discovered when connected" : t.actions.length ? `${t.actions.length} action${t.actions.length === 1 ? "" : "s"}: ${t.actions.map((a) => a.name).join(", ")}` : "No tool actions"}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {t.creatable && (isAdmin || t.category === "agent_client") ? (
                          <a href={`/integrations/new?type=${t.id}`} aria-label={`${t.category === "agent_client" ? "Set up" : "Add"} ${t.name}`}
                            className={buttonVariants({ variant: t.category === "agent_client" ? "secondary" : "primary", size: "sm" })}>
                            {t.category === "agent_client" ? <ArrowRight /> : <Plus />}{t.category === "agent_client" ? "Set up" : "Add"}
                          </a>
                        ) : t.setup.read_only ? <span className="text-caption text-gray-11">{t.setup.configured_by ?? "Configured by the operator"}</span> : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))
        )}
      </section>
    </div>
  );
}
