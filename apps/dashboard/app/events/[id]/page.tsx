import { Download, Lock } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { CodeView } from "@/components/code-view";
import { ErrorState } from "@/components/empty-state";
import { ProofExplorer } from "@/components/evidence/proof-explorer";
import { HashChip } from "@/components/hash-chip";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EMPTY, UUID_RE, middle } from "@/lib/format";
import { gateway, getJson, me } from "@/lib/gateway";
import type { Bundle } from "@/lib/merkle";
import { prefs } from "@/lib/prefs";

export const metadata: Metadata = { title: "Event" };

export default async function EventDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const gw = await gateway();
  const [{ data: d, response }, who, p] = await Promise.all([
    gw.GET("/v1/dashboard/events/{event_id}", { params: { path: { event_id: id } } }),
    me(),
    prefs(),
  ]);
  if (!d) {
    return (
      <div className="mx-auto max-w-6xl">
        <PageHeader title="Event" crumbs={[{ label: "Evidence" }, { label: "Events", href: "/evidence" }, { label: middle(id) }]} help="event" />
        <ErrorState what={response.status === 404 ? "This event does not exist in your tenant." : "The gateway did not return this event."}
          requestId={response.headers.get("x-request-id")} retryHref={`/events/${id}`} />
      </div>
    );
  }
  const n = d.node;
  const auditor = who.roles.includes("auditor") || who.roles.includes("admin");
  // The proof bundle (public hashes only) is an auditor/admin read (Phase 9, ADR-0031 §2).
  const bundle = auditor && n.epoch_no !== null && n.epoch_no !== undefined
    ? await getJson<Bundle>(`/v1/dashboard/events/${id}/bundle`)
    : null;
  const header = d.header as Record<string, unknown>;
  const actor = (header.actor ?? {}) as { id?: string; kind?: string };
  const payload = header.payload as { len?: number; ref?: string; digest?: string } | undefined;
  const epoch = d.epoch as Record<string, unknown> | null;

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title={<span className="font-mono">{n.type}</span>}
        help="event"
        crumbs={[{ label: "Evidence" }, { label: "Events", href: "/evidence" }, { label: `#${n.seq}` }]}
        description={`Event #${n.seq} in tenant ${d.tenant}'s hash chain.`}
        meta={<>
          {n.hash_ok && n.link_ok !== false && n.stored_copy_ok !== false ? <StatusBadge value="VERIFIED" /> : <StatusBadge value="TAMPERED" />}
          {n.risk_level ? <RiskBadge level={n.risk_level} /> : null}
          {n.epoch_no !== null && n.epoch_no !== undefined ? <span className="inline-flex items-center gap-1 text-caption text-gray-11"><Lock className="size-3" aria-hidden="true" />epoch {n.epoch_no}</span> : <StatusBadge value="UNANCHORED" />}
          {n.anchor ? <StatusBadge value={n.anchor.status} /> : null}
        </>}
        actions={auditor && bundle?.body ? (
          <a href={`/api/bundles/${id}`} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-gray-7 px-3 text-dense font-medium text-gray-12 no-underline hover:bg-gray-3 hover:no-underline">
            <Download aria-hidden="true" className="size-4" />Download bundle
          </a>
        ) : null}
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Proof explorer" description="Leaf → Merkle root → epoch root → later epochs → on-chain anchor, recomputed in your browser from public hashes." />
            <CardBody>
              {n.epoch_no === null || n.epoch_no === undefined ? (
                <Notice kind="info" className="mb-0">Not sealed into an epoch yet, so there is no inclusion proof. Events are sealed within minutes (sooner for high-risk ones).</Notice>
              ) : !auditor ? (
                <Notice kind="info" className="mb-0">The proof explorer reads the evidence bundle, which is available to auditors and admins. The hash-chain checks on this page are available to everyone.</Notice>
              ) : bundle?.body ? (
                <ProofExplorer bundle={bundle.body} storedEventHash={n.event_hash} explorerTxUrl={who.explorer_tx_url} />
              ) : (
                <ErrorState what="The evidence bundle could not be loaded." retryHref={`/events/${id}`} />
              )}
              <div className="mt-4 rounded-md border border-gray-6 bg-gray-2 p-3 text-caption text-gray-11">
                Independent check: <code className="font-mono text-gray-12">agw-verify event --bundle bundle-{id}.json --trust-config pinned-trust.json --chain-rpc &lt;your RPC&gt;</code>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Header" description="The JSON projection of the canonical (hashed) header. Structural metadata only; no payload." />
            <CardBody><CodeView text={JSON.stringify(header, null, 2)} max={6000} label="event header" /></CardBody>
          </Card>
        </div>

        <aside className="space-y-4">
          <Card>
            <CardHeader title="Metadata" />
            <CardBody>
              <dl className="grid grid-cols-[7.5rem_1fr] gap-x-3 gap-y-2.5 text-dense">
                <dt className="text-gray-11">Type</dt><dd className="font-mono">{n.type}</dd>
                <dt className="text-gray-11">Sequence</dt><dd className="tabular">#{n.seq}</dd>
                <dt className="text-gray-11">Tenant</dt><dd>{d.tenant}</dd>
                <dt className="text-gray-11">Recorded</dt><dd><Timestamp iso={n.occurred_at} tz={p.tz} /></dd>
                <dt className="text-gray-11">Observed</dt><dd>{typeof header.obs === "number" ? <Timestamp iso={new Date(Number(header.obs) / 1000).toISOString()} tz={p.tz} /> : EMPTY}</dd>
                <dt className="text-gray-11">Actor</dt><dd>{actor.kind ?? EMPTY} <span className="text-gray-11">{actor.id ?? ""}</span></dd>
                <dt className="text-gray-11">Action</dt><dd><HashChip value={d.action_id} href={d.action_id ? `/actions/${d.action_id}` : undefined} label="action" /></dd>
                <dt className="text-gray-11">Run</dt><dd><HashChip value={d.run_id} href={d.run_id ? `/runs/${d.run_id}` : undefined} label="run" /></dd>
              </dl>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Hash chain" />
            <CardBody className="space-y-3 text-dense">
              <div><div className="text-caption text-gray-11">Event hash</div><HashChip value={n.event_hash} label="event hash" head={10} tail={8} /></div>
              <div><div className="text-caption text-gray-11">Previous hash (prev)</div><HashChip value={n.prev_hash} label="prev hash" head={10} tail={8} /></div>
              <ul className="space-y-1.5" aria-label="Chain checks">
                <li className="flex items-center gap-2" data-check="hash" data-ok={String(n.hash_ok)}>{n.hash_ok ? <StatusBadge value="VERIFIED" size="sm" /> : <StatusBadge value="TAMPERED" size="sm" />}<span>stored header hashes to the event hash</span></li>
                <li className="flex items-center gap-2" data-check="link" data-ok={String(n.link_ok)}>
                  {n.link_ok === null || n.link_ok === undefined ? <StatusBadge value="INCOMPLETE" size="sm" /> : n.link_ok ? <StatusBadge value="VERIFIED" size="sm" /> : <StatusBadge value="TAMPERED" size="sm" />}
                  <span>prev matches the stored hash of #{n.seq - 1}</span>
                </li>
                <li className="flex items-center gap-2" data-check="stored-copy" data-ok={String(n.stored_copy_ok)}>{n.stored_copy_ok !== false ? <StatusBadge value="VERIFIED" size="sm" /> : <StatusBadge value="TAMPERED" size="sm" />}<span>readable copy and columns match the sealed record</span></li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Payload" />
            <CardBody className="text-dense">
              <p className="flex items-start gap-2"><Lock aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-gray-11" />
                <span>{payload ? <>Encrypted ({payload.len ?? "?"} bytes). Available only through a disclosure grant.</> : "This event has no payload."}</span>
              </p>
              {payload?.digest ? <div className="mt-2"><div className="text-caption text-gray-11">Payload commitment (digest)</div><HashChip value={payload.digest} label="payload digest" /></div> : null}
            </CardBody>
          </Card>
          {epoch ? (
            <Card>
              <CardHeader title={`Epoch ${String(epoch.epoch_no)}`} />
              <CardBody>
                <dl className="grid grid-cols-[7.5rem_1fr] gap-x-3 gap-y-2.5 text-dense">
                  <dt className="text-gray-11">Seq range</dt><dd className="tabular">{String(epoch.first_seq)}–{String(epoch.last_seq)}</dd>
                  <dt className="text-gray-11">Tree size</dt><dd className="tabular">{String(epoch.tree_size)}</dd>
                  <dt className="text-gray-11">Merkle root</dt><dd><HashChip value={String(epoch.merkle_root)} label="Merkle root" /></dd>
                  <dt className="text-gray-11">Epoch root</dt><dd><HashChip value={String(epoch.epoch_root)} label="epoch root" /></dd>
                  <dt className="text-gray-11">Seal reason</dt><dd>{String(epoch.seal_reason ?? EMPTY)}</dd>
                </dl>
              </CardBody>
            </Card>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
