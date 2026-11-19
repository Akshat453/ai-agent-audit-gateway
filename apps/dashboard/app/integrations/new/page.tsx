import { ArrowRight, PlugZap } from "lucide-react";
import type { Metadata } from "next";

import { ClassifyTable } from "@/components/connectors/classify-table";
import { ConfigView } from "@/components/connectors/config-view";
import { ConnectorConfigForm } from "@/components/connectors/config-form";
import { GithubPanel } from "@/components/connectors/github-panel";
import { SetupPanel } from "@/components/connectors/setup-panel";
import { Stepper } from "@/components/connectors/stepper";
import { ErrorState } from "@/components/empty-state";
import { CsrfField } from "@/components/legacy";
import { PlainLine } from "@/components/humanize/plain";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { StepUpCard } from "@/components/step-up";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { dashboardOrigin, fieldsOf, message, viewer } from "@/lib/c2";
import { CATEGORY_LABEL, connectorStatusKey, type CatalogType, type ConnectorDetail } from "@/lib/connectors";
import { UUID_RE } from "@/lib/format";
import { getJson } from "@/lib/gateway";

export const metadata: Metadata = { title: "Add integration" };

const STEPS = [
  { id: "configure", label: "Configure" },
  { id: "test", label: "Test connection" },
  { id: "classify", label: "Classify actions" },
  { id: "review", label: "Review" },
  { id: "done", label: "Done" },
];

export default async function NewIntegration({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const { gw, isAdmin, csrf, stepUpRemaining, stepUpWindow } = await viewer();
  const cat = await gw.GET("/v1/connectors/catalog");
  const types = (cat.data as { types?: CatalogType[] } | undefined)?.types ?? [];
  const type = types.find((t) => t.id === sp.type);
  const crumbs = [{ label: "Setup" }, { label: "Integrations", href: "/integrations" }, { label: type ? `Add ${type.name}` : "Add" }];
  if (!type) {
    return (
      <div className="mx-auto max-w-5xl">
        <PageHeader title="Add integration" crumbs={crumbs} help="integrations" />
        <ErrorState what="Unknown integration type. Pick one from the catalog." retryHref="/integrations" />
      </div>
    );
  }
  const id = sp.id && UUID_RE.test(sp.id) ? sp.id : null;
  const step = id ? (["test", "classify", "review", "done"].includes(sp.step ?? "") ? sp.step! : "test") : "configure";
  const here = `/integrations/new?type=${type.id}${id ? `&id=${id}&step=${step}` : ""}`;
  const msg = message(sp.result ?? sp.error);
  const origin = await dashboardOrigin();
  const isAgent = type.category === "agent_client";
  const header = (
    <>
    <PageHeader
      title={`Add ${type.name}`}
      help="integrations"
      crumbs={crumbs}
      description={type.description}
      meta={<span className="text-caption text-gray-11">{CATEGORY_LABEL[type.category]} · auth: {type.auth}</span>}
    />
    <PlainLine>Adding an integration takes four steps: fill in its settings, test that AgentGuard can reach it, decide which of its actions agents may use (allowed, needs approval, or blocked), then review. Nothing it offers can run until step 3 is done.</PlainLine>
    </>
  );
  const stepUp = isAdmin ? <StepUpCard csrf={csrf} next={here} remaining={stepUpRemaining} windowSeconds={stepUpWindow} what="add or change connectors" /> : null;
  const notice = msg ? (
    <Notice kind={msg.kind}>
      {msg.text}
      {sp.fields ? <> Fields: <code className="font-mono">{fieldsOf(sp.fields).join(", ")}</code></> : null}
    </Notice>
  ) : null;

  // ---------------------------------------------------------------- step 1: configure
  if (!id) {
    if (type.setup.read_only || !type.creatable) {
      return (
        <div className="mx-auto max-w-5xl">
          {header}
          <Notice>{type.name} is configured by the operator ({type.setup.configured_by ?? "gateway settings"}) and is read-only here.</Notice>
          <a href="/integrations" className={buttonVariants({ variant: "secondary" })}>Back to integrations</a>
        </div>
      );
    }
    return (
      <div className="mx-auto max-w-5xl">
        {header}
        {!isAgent ? <Stepper steps={STEPS} current="configure" /> : null}
        {notice}
        {isAgent ? (
          <div className="space-y-4">
            <Card>
              <CardHeader title="Set up developer machines" description="Agent clients need no credentials here: each developer enrolls their own device." />
              <CardBody><SetupPanel setup={type.setup} enrollUrl={`${origin}/enroll`} /></CardBody>
            </Card>
            {isAdmin ? (
              <Card>
                <CardHeader title="Track it as an integration (optional)" description="Lists this client under Installed, with its evidence events. Enforcement does not depend on it." />
                <CardBody>
                  {stepUp}
                  <ConnectorConfigForm typeId={type.id} csrf={csrf} action="/api/connectors" mode="create" name={sp.name ?? type.name} slug={sp.slug ?? type.id.replace(/[^a-z0-9]/g, "").slice(0, 24)}
                    errorFields={fieldsOf(sp.fields)} submitLabel="Add to integrations" />
                </CardBody>
              </Card>
            ) : null}
          </div>
        ) : !isAdmin ? (
          <Notice kind="warn">Only an admin can add connectors. Ask an admin to add {type.name}.</Notice>
        ) : (
          <Card>
            <CardHeader title="Configure" description="Non-secret settings are stored as configuration; credentials are sealed and write-only." />
            <CardBody>
              {stepUp}
              <ConnectorConfigForm typeId={type.id} csrf={csrf} action="/api/connectors" mode="create" name={sp.name ?? type.name} slug={sp.slug ?? ""}
                errorFields={fieldsOf(sp.fields)} submitLabel="Create connector" />
            </CardBody>
          </Card>
        )}
      </div>
    );
  }

  // ---------------------------------------------------------------- steps 2-5 (connector exists)
  const { status, body: c } = await getJson<ConnectorDetail>(`/v1/connectors/${id}`);
  if (!c) {
    return (
      <div className="mx-auto max-w-5xl">
        {header}
        <ErrorState what={status === 404 ? "This connector does not exist (it may have been deleted)." : "The gateway did not return the connector."} retryHref="/integrations" />
      </div>
    );
  }
  const base = `/integrations/new?type=${type.id}&id=${id}`;
  const hasActions = c.actions.length > 0;
  const nextAfterTest = hasActions ? `${base}&step=classify` : `${base}&step=review`;
  const lastHealth = c.health[0] ?? null;
  return (
    <div className="mx-auto max-w-6xl">
      {header}
      <Stepper steps={STEPS} current={step} hrefs={{ test: `${base}&step=test`, classify: `${base}&step=classify`, review: `${base}&step=review` }} />
      {notice}
      {step !== "done" ? stepUp : null}

      {step === "test" ? (
        <Card>
          <CardHeader title="Test connection" description={`${c.name} · ${c.slug}`} action={<StatusBadge value={connectorStatusKey(c.status)} />} />
          <CardBody className="space-y-4 text-dense">
            {type.id === "github" ? (
              <GithubPanel connectorId={id} csrf={csrf} registered={Boolean(c.config.app_slug)} installations={Array.isArray(c.config.installation_ids) ? c.config.installation_ids.length : 0} />
            ) : null}
            <p className="text-gray-11">The gateway calls the service with the stored credentials (https only, exact host allowlist) and records the result.{type.dynamic_actions ? " For an MCP server this also discovers its tools; they arrive unclassified." : ""}</p>
            {lastHealth ? (
              <p data-testid="last-health" className="flex flex-wrap items-center gap-2">Last result: <StatusBadge value={lastHealth.ok ? "HEALTH_OK" : "HEALTH_FAILED"} /> <code className="font-mono text-caption">{lastHealth.code}</code></p>
            ) : <p className="text-gray-11">Not tested yet.</p>}
            <div className="flex flex-wrap gap-2">
              <form method="post" action={`/api/connectors/${id}/test`}>
                <CsrfField csrf={csrf} />
                <input type="hidden" name="next" value={`${base}&step=test`} />
                <Button type="submit" variant="primary"><PlugZap />Test connection</Button>
              </form>
              <a href={nextAfterTest} className={buttonVariants({ variant: "secondary" })}>{hasActions ? "Continue to classify" : "Continue to review"}<ArrowRight /></a>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {step === "classify" ? (
        <Card>
          <CardHeader title="Classify actions" description={`Policy version v${c.policy_version}. Every action starts unclassified and is denied until you classify it.`} />
          {hasActions ? (
            <ClassifyTable connectorId={id} actions={c.actions} editable={isAdmin} csrf={csrf} next={`${base}&step=review`} submitLabel="Save and review" />
          ) : <CardBody><p className="text-dense text-gray-11">This connector has no actions{type.dynamic_actions ? " yet: test the connection to discover them" : ""}.</p></CardBody>}
          <div className="border-t border-gray-5 px-4 py-3"><a href={`${base}&step=review`} className="text-caption">Skip: leave every action unclassified (denied)</a></div>
        </Card>
      ) : null}

      {step === "review" || step === "done" ? (
        <div className="space-y-4">
          {step === "done" ? <Notice kind="good">{c.name} is set up. Unclassified actions stay denied; you can classify them any time on the connector page.</Notice> : null}
          <Card>
            <CardHeader title="Review" description={`${c.name} · ${c.slug}`} action={<span className="flex flex-wrap gap-2"><StatusBadge value={connectorStatusKey(c.status)} /><span className="text-caption text-gray-11" data-testid="policy-version">policy v{c.policy_version}</span></span>} />
            <CardBody className="space-y-4">
              <ConfigView config={c.config} credentials={c.credentials} />
              {hasActions ? (
                <ul className="divide-y divide-gray-4 rounded-md border border-gray-6 text-dense">
                  {c.actions.map((a) => (
                    <li key={a.name} className="flex flex-wrap items-center gap-2 px-3 py-2">
                      <code className="font-mono font-medium">{a.name}</code>
                      {a.classification ? <RiskBadge level={a.classification.risk} size="sm" /> : null}
                      <StatusBadge value={a.classification ? "CLASSIFIED" : "UNCLASSIFIED"} size="sm" />
                      {a.classification ? <span className="text-caption text-gray-11">approval: {a.classification.approval}{a.classification.approval === "always" ? ` (${a.classification.approver_role})` : ""}</span> : null}
                    </li>
                  ))}
                </ul>
              ) : null}
              {isAgent ? <SetupPanel setup={c.setup} enrollUrl={`${origin}/enroll`} /> : null}
              <div className="flex flex-wrap gap-2">
                {step === "review" ? <a href={`${base}&step=done`} className={buttonVariants({ variant: "primary" })}>Finish</a> : null}
                <a href={`/integrations/${id}`} className={buttonVariants({ variant: "secondary" })}>Open connector page<ArrowRight /></a>
              </div>
            </CardBody>
          </Card>
        </div>
      ) : null}
    </div>
  );
}
