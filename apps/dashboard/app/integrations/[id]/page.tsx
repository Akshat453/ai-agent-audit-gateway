import { Ban, Pencil, PlugZap, Power, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { ClassifyTable } from "@/components/connectors/classify-table";
import { ConfigView } from "@/components/connectors/config-view";
import { ConnectorConfigForm } from "@/components/connectors/config-form";
import { GithubPanel } from "@/components/connectors/github-panel";
import { GithubStatusCard } from "@/components/github/github-status";
import { RotateDialog } from "@/components/connectors/rotate-dialog";
import { SetupPanel } from "@/components/connectors/setup-panel";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorState } from "@/components/empty-state";
import { CsrfField } from "@/components/legacy";
import { PlainStory } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { StepUpCard } from "@/components/step-up";
import { Timestamp } from "@/components/timestamp";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { dashboardOrigin, fieldsOf, message, viewer } from "@/lib/c2";
import { CREDENTIAL_FIELDS } from "@/lib/connector-form";
import { CATEGORY_LABEL, connectorStatusKey, type CatalogType, type ConnectorDetail } from "@/lib/connectors";
import { UUID_RE, count } from "@/lib/format";
import { getJson } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { connectorWords } from "@/src/humanize";

export const metadata: Metadata = { title: "Integration" };

export default async function Integration({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string>> }) {
  const { id } = await params;
  const sp = await searchParams;
  if (!UUID_RE.test(id)) notFound();
  const { gw, isAdmin, csrf, stepUpRemaining, stepUpWindow } = await viewer();
  const [{ status, body: c }, cat, p] = await Promise.all([getJson<ConnectorDetail>(`/v1/connectors/${id}`), gw.GET("/v1/connectors/catalog"), prefs()]);
  const crumbs = [{ label: "Setup" }, { label: "Integrations", href: "/integrations" }];
  if (!c) {
    return (
      <div className="mx-auto max-w-6xl">
        <PageHeader title="Integration" help="integrations" crumbs={[...crumbs, { label: id.slice(0, 8) }]} />
        <ErrorState what={status === 404 ? "This connector does not exist in your tenant (it may have been deleted)." : status === 403 ? "Your role cannot view integrations." : "The gateway did not return the connector."} retryHref="/integrations" />
      </div>
    );
  }
  const type = ((cat.data as { types?: CatalogType[] } | undefined)?.types ?? []).find((t) => t.id === c.type_id);
  const here = `/integrations/${id}`;
  const msg = sp.installed ? { text: "GitHub App installed. The repositories you chose are now visible to the gateway.", kind: "good" as const }
    : sp.step === "install" ? { text: "GitHub App registered and its keys sealed. Next: install it on repositories.", kind: "good" as const }
      : message(sp.result ?? sp.error);
  const disabled = c.status === "disabled";
  const isAgent = c.category === "agent_client";
  const credFields = CREDENTIAL_FIELDS[c.type_id] ?? [];
  const origin = await dashboardOrigin();
  const lastCheck = c.health[0]?.checked_at ?? null;
  const cfg = c.config as Record<string, unknown>;
  const setup: { label: string; done: boolean }[] = c.type_id === "github"
    ? [
      { label: "Register the GitHub App (the GitHub App card below)", done: Boolean(cfg.app_slug) },
      { label: "Install it on your repositories", done: Array.isArray(cfg.installation_ids) && cfg.installation_ids.length > 0 },
      { label: "List the repositories AgentGuard may use (Technical details, then Configuration)", done: Array.isArray(cfg.repos) && cfg.repos.length > 0 },
      { label: "Test the connection", done: c.status === "connected" },
      { label: "Decide which actions are allowed, need approval, or stay blocked", done: c.unclassified_actions === 0 },
    ]
    : [
      { label: "Fill in the configuration", done: true },
      { label: "Test the connection", done: c.status === "connected" },
      { label: "Decide which actions are allowed, need approval, or stay blocked", done: c.unclassified_actions === 0 },
    ];

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title={c.name}
        help="integrations"
        crumbs={[...crumbs, { label: c.name }]}
        description={type?.description}
        meta={
          <>
            <StatusBadge value={connectorStatusKey(c.status)} />
            <span className="text-caption text-gray-11">{type?.name ?? c.type_id} · {CATEGORY_LABEL[c.category] ?? c.category}</span>
            <code className="font-mono text-caption text-gray-11">{c.slug}</code>
            <span className="text-caption text-gray-12" data-testid="policy-version">Policy version v{c.policy_version}</span>
            {c.unclassified_actions ? <span className="text-caption font-medium text-bad-11">{c.unclassified_actions} unclassified (denied)</span> : null}
          </>
        }
        actions={isAdmin ? (
          <form method="post" action={`/api/connectors/${id}/test`}>
            <CsrfField csrf={csrf} />
            <Button type="submit" variant="primary"><PlugZap />Test connection</Button>
          </form>
        ) : null}
      />
      {msg ? (
        <Notice kind={msg.kind}>
          {msg.text}
          {sp.result === "CLASSIFIED" && sp.ver ? <> Now <strong>policy version v{sp.ver.replace(/\D/g, "")}</strong>.</> : null}
          {sp.result === "ROTATED" && sp.cred ? <> Credential version {sp.cred.replace(/\D/g, "")}.</> : null}
          {sp.fields ? <> Fields: <code className="font-mono">{fieldsOf(sp.fields).join(", ")}</code></> : null}
        </Notice>
      ) : null}
      <PlainStory headline={connectorWords(c, lastCheck, Date.now())} tone={c.status === "connected" ? "ok" : c.status === "disabled" ? "neutral" : "warn"}
        happened={[type?.description ?? "An integration with another product.", `It offers ${c.actions.length} action${c.actions.length === 1 ? "" : "s"}; ${c.unclassified_actions ? `${c.unclassified_actions} are blocked until an admin sets rules` : "all have rules"}.`]}
        canDo={isAdmin ? [{ label: "Follow the setup steps below." }, { label: "Use Test connection (top right) after any change." }] : [{ label: "Only an admin can change this integration." }]}>
        <section aria-label="Setup steps">
          <h2 className="mb-1.5 text-caption font-semibold uppercase tracking-wide text-gray-11">Setup steps</h2>
          <ol className="list-decimal space-y-1 pl-5 text-dense" data-testid="setup-steps">
            {setup.map((st) => <li key={st.label} className={st.done ? "text-gray-12" : "text-gray-11"}>{st.label} {st.done ? <span className="text-ok-11">- done</span> : <span className="font-medium text-warn-12">- to do</span>}</li>)}
          </ol>
        </section>
      </PlainStory>
      {isAdmin ? <StepUpCard csrf={csrf} next={here} remaining={stepUpRemaining} windowSeconds={stepUpWindow} what="change this connector" /> : null}
      {disabled ? <Notice kind="warn">This connector is disabled: every one of its actions is denied.</Notice> : null}

      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <div className="min-w-0 space-y-4">
          {c.actions.length || type?.dynamic_actions ? (
            <Card>
              <CardHeader title="Actions and classification"
                description={`Each action is the gateway tool cx_${c.slug}_<action>, version 1.0.${c.policy_version}. Saving creates a new policy version.`} />
              {isAdmin && c.actions.some((a) => a.proposed && !a.classification) ? (
                <form method="post" action={`/api/connectors/${id}/classify-proposed`} className="px-4 pt-3">
                  <CsrfField csrf={csrf} />
                  <input type="hidden" name="next" value={here} />
                  <Button type="submit" variant="secondary">Accept proposed classification</Button>
                  <span className="ml-2 text-caption text-gray-11">Applies the type&apos;s suggested risk and approval rules to every unclassified action (a new policy version).</span>
                </form>
              ) : null}
              <p className="px-4 pt-3 text-dense text-gray-11">Each row is one thing agents can do through this integration. <strong className="text-gray-12">Auto</strong>: allowed without asking (still recorded). <strong className="text-gray-12">Always ask</strong>: a person approves each time. <strong className="text-gray-12">Deny</strong>: always blocked.</p>
              {c.actions.length ? (
                <ClassifyTable connectorId={id} actions={c.actions} editable={isAdmin} csrf={csrf} next={here} />
              ) : <EmptyState title="No actions yet">{type?.dynamic_actions ? "Test the connection to discover this server's tools. They arrive unclassified." : "This connector has no actions."}</EmptyState>}
            </Card>
          ) : null}

          {c.type_id === "github" ? <GithubStatusCard connectorId={id} /> : null}

          {c.type_id === "github" && isAdmin ? (
            <Card>
              <CardHeader title="GitHub App" description="Register the App, then install it on the repositories to protect." />
              <CardBody>
                <GithubPanel connectorId={id} csrf={csrf} registered={Boolean(c.config.app_slug)} installations={Array.isArray(c.config.installation_ids) ? c.config.installation_ids.length : 0} />
              </CardBody>
            </Card>
          ) : null}

          {isAgent ? (
            <Card>
              <CardHeader title="Set up developer machines" />
              <CardBody><SetupPanel setup={c.setup} enrollUrl={`${origin}/enroll`} /></CardBody>
            </Card>
          ) : null}

          <Technical view={p.view} hint="configuration, the evidence of every change, raw settings">
          <div className="space-y-4">
          <Card>
            <CardHeader title="Configuration" description="Secrets are write-only and never shown."
              action={isAdmin && credFields.length ? <RotateDialog connectorId={id} typeId={c.type_id} fields={credFields} csrf={csrf} version={c.credentials.version} /> : null} />
            <CardBody className="space-y-4">
              <ConfigView config={c.config} credentials={c.credentials} />
              {isAdmin ? (
                <details className="rounded-md border border-gray-6">
                  <summary className="cursor-pointer px-3 py-2 text-dense font-medium"><Pencil aria-hidden="true" className="mr-1.5 inline size-3.5" />Edit name and configuration</summary>
                  <div className="border-t border-gray-5 p-3">
                    <ConnectorConfigForm typeId={c.type_id} csrf={csrf} action={`/api/connectors/${id}/update`} mode="edit" initial={c.config} name={c.name}
                      errorFields={fieldsOf(sp.fields)} submitLabel="Save configuration" next={here} />
                  </div>
                </details>
              ) : null}
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Evidence" description="CONNECTOR_* events for this connector, newest first (each is in the hash chain)." />
            {c.events.length ? (
              <ul className="divide-y divide-gray-4 text-dense" data-testid="connector-events">
                {c.events.map((e) => (
                  <li key={e.event_id} className="flex flex-wrap items-center gap-3 px-4 py-2">
                    <span className="w-14 font-mono text-caption tabular text-gray-11">#{e.seq}</span>
                    <a href={`/events/${e.event_id}`} className="font-mono">{e.type}</a>
                    <Timestamp iso={e.occurred_at} tz={p.tz} />
                  </li>
                ))}
              </ul>
            ) : <EmptyState title="No events">Changes to this connector are recorded here.</EmptyState>}
          </Card>
          </div>
          </Technical>
        </div>

        <aside className="space-y-4" aria-label="Connector status">
          <Card>
            <CardHeader title="Usage" description="Calls to this connector's tools, all time" />
            <CardBody>
              <dl className="grid grid-cols-3 gap-2 text-center">
                {([["Calls", c.usage.calls], ["Denied", c.usage.denials], ["Needed approval", c.usage.approvals]] as const).map(([k, v]) => (
                  <div key={k} className="rounded-md border border-gray-6 p-2">
                    <dt className="text-caption text-gray-11">{k}</dt>
                    <dd className="text-section font-semibold tabular">{count(v)}</dd>
                  </div>
                ))}
              </dl>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Health" description="Last 20 connection tests" />
            {c.health.length ? (
              <ul className="divide-y divide-gray-4 text-dense" data-testid="health-history">
                {c.health.map((h, i) => (
                  <li key={`${h.checked_at}-${i}`} className="flex flex-wrap items-center gap-2 px-4 py-2">
                    <StatusBadge value={h.ok ? "HEALTH_OK" : "HEALTH_FAILED"} size="sm" />
                    <code className="font-mono text-caption">{h.code}</code>
                    <Timestamp iso={h.checked_at} tz={p.tz} className="ml-auto whitespace-nowrap text-caption text-gray-11" />
                  </li>
                ))}
              </ul>
            ) : <CardBody><p className="text-dense text-gray-11">Never tested. {isAdmin ? "Use Test connection." : ""}</p></CardBody>}
          </Card>

          {isAdmin ? (
            <Card className="border-bad-7">
              <CardHeader title="Danger zone" />
              <CardBody className="space-y-3">
                <form id="toggle-form" method="post" action={`/api/connectors/${id}/${disabled ? "enable" : "disable"}`}>
                  <CsrfField csrf={csrf} />
                </form>
                {disabled ? (
                  <Button type="submit" form="toggle-form" className="w-full"><Power />Enable connector</Button>
                ) : (
                  <ConfirmDialog formId="toggle-form" testId="disable-dialog" title={`Disable ${c.name}?`}
                    description="Every action of this connector is denied until it is enabled again. Nothing is deleted."
                    confirmLabel="Disable connector" confirmVariant="danger"
                    trigger={<Button variant="danger-outline" className="w-full"><Ban />Disable</Button>} />
                )}
                <form id="delete-form" method="post" action={`/api/connectors/${id}/delete`}>
                  <CsrfField csrf={csrf} />
                </form>
                <ConfirmDialog formId="delete-form" testId="delete-dialog" title={`Delete ${c.name}?`}
                  description="Its sealed credentials are destroyed and its tools stop existing. The evidence history stays. This cannot be undone."
                  confirmLabel="Delete connector" confirmVariant="danger" typeToConfirm={c.slug} typeToConfirmWhat="the connector's slug"
                  trigger={<Button variant="danger-outline" className="w-full"><Trash2 />Delete</Button>} />
              </CardBody>
            </Card>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
