import { Anchor, Lock, Unlink } from "lucide-react";

import { HashChip } from "@/components/hash-chip";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Tooltip } from "@/components/ui/overlay";
import { cn } from "@/lib/cn";
import { eventLabel, explainNode } from "@/src/humanize";
import { middle } from "@/lib/format";

export type EvidenceNode = {
  seq: number; event_id: string; type: string; occurred_at?: string | null; risk_level?: string | null;
  event_hash: string; prev_hash: string; hash_ok: boolean; link_ok?: boolean | null; stored_copy_ok?: boolean;
  epoch_no?: number | null; anchor?: { status: string; tx_hash?: string | null; block_number?: number | null; explorer_url?: string | null } | null;
  decision?: string | null; status?: string | null; reasons: string[];
};

/**
 * Signature view 1: the evidence timeline. A vertical chain of lifecycle events; between two
 * nodes, a connector labelled prev_hash → hash. Solid jade = the next event commits to exactly
 * this event's stored hash; red dashed = the link (or the record's own hash) no longer matches,
 * with the reason. Interleaved events of other actions are summarised on the connector.
 */
export function EvidenceTimeline({ nodes, tz, toolId }: { nodes: EvidenceNode[]; tz: string; toolId?: string | null }) {
  if (!nodes.length) return <p className="text-dense text-gray-11">No evidence events recorded for this action yet.</p>;
  const firstBroken = nodes.find((n) => !n.hash_ok || n.link_ok === false || n.stored_copy_ok === false);
  return (
    <div>
      {firstBroken ? (
        <div role="alert" className="mb-4 flex items-start gap-2 rounded-md border border-bad-7 bg-bad-3 px-3 py-2 text-dense text-bad-12">
          <Unlink aria-hidden="true" className="mt-0.5 size-4 text-bad-11" />
          <span>First broken link at event #{firstBroken.seq}: {!firstBroken.hash_ok ? "its stored header no longer hashes to its stored event hash" : firstBroken.stored_copy_ok === false ? "its readable copy was changed and no longer matches the sealed record" : "its prev hash does not match the stored hash of the event before it"}. Run verification and treat this as an incident.</span>
        </div>
      ) : null}
      <ol aria-label="Evidence timeline" className="relative">
        {nodes.map((n, i) => {
          const next = nodes[i + 1];
          const broken = !n.hash_ok || n.link_ok === false || n.stored_copy_ok === false;
          const nextBroken = next ? !next.hash_ok || next.link_ok === false || !n.hash_ok : false;
          const gap = next ? next.seq - n.seq - 1 : 0;
          return (
            <li key={n.event_id} className="relative pl-9" data-testid={`node-${n.seq}`} data-broken={broken ? "true" : "false"}>
              {/* node dot */}
              <span aria-hidden="true" className={cn("absolute left-1.5 top-3 size-4 rounded-full border-2 bg-gray-1",
                broken ? "border-bad-9" : "border-ok-9")} />
              <div className={cn("rounded-md border bg-gray-1 px-3 py-2.5", broken ? "border-bad-7" : "border-gray-6")}>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-dense font-medium text-gray-12">{eventLabel(n.type)}</span>
                  <a href={`/events/${n.event_id}`} className="font-mono text-caption text-gray-11">{n.type}</a>
                  <span className="text-caption text-gray-11">#{n.seq}</span>
                  {n.risk_level ? <RiskBadge level={n.risk_level} size="sm" /> : null}
                  {n.decision ? <StatusBadge value={n.decision} size="sm" /> : null}
                  {n.status ? <StatusBadge value={n.status} size="sm" /> : null}
                  <span className="ml-auto"><Timestamp iso={n.occurred_at} tz={tz} className="text-caption text-gray-11" /></span>
                </div>
                <p className="mt-1 text-dense text-gray-12" data-testid={`node-plain-${n.seq}`}>{explainNode(n, toolId)}</p>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-gray-11">
                  <span className="inline-flex items-center gap-1">hash <HashChip value={n.event_hash} label={`event #${n.seq} hash`} /></span>
                  {n.epoch_no !== null && n.epoch_no !== undefined ? (
                    <a href={`/epochs?epoch=${n.epoch_no}`} className="inline-flex items-center gap-1 rounded-sm border border-gray-6 px-1.5 py-px text-gray-11 no-underline hover:bg-gray-3 hover:no-underline">
                      <Lock aria-hidden="true" className="size-3" />sealed in epoch {n.epoch_no}
                    </a>
                  ) : (
                    <StatusBadge value="UNANCHORED" size="sm" />
                  )}
                  {n.anchor ? (
                    <span className="inline-flex items-center gap-1"><Anchor aria-hidden="true" className="size-3" /><StatusBadge value={n.anchor.status} size="sm" /></span>
                  ) : null}
                  {!n.hash_ok ? <span className="font-medium text-bad-11">stored header does not match its hash</span> : null}
                  {n.hash_ok && n.stored_copy_ok === false ? <span className="font-medium text-bad-11">readable copy was changed</span> : null}
                </div>
                {n.reasons.length ? <p className="mt-1 text-caption text-gray-11">{n.reasons.join(" · ")}</p> : null}
              </div>
              {/* connector to the next node */}
              {next ? (
                <div className="relative py-1.5 pl-1">
                  <span aria-hidden="true" className={cn("absolute -left-[22px] top-0 h-full border-l-2",
                    nextBroken ? "border-dashed border-bad-9" : "border-solid border-ok-9")} />
                  <Tooltip content={<span className="font-mono">prev #{next.seq} = {next.prev_hash}{"\n"}hash #{n.seq} = {n.event_hash}</span>}>
                    <span tabIndex={0} className={cn("inline-flex flex-wrap items-center gap-1 rounded-sm px-1.5 py-0.5 font-mono text-[11px]",
                      nextBroken ? "bg-bad-3 text-bad-12" : "bg-ok-3 text-ok-12")}
                      data-testid={`link-${n.seq}-${next.seq}`} data-link={nextBroken ? "broken" : "ok"}>
                      {!nextBroken ? <span className="font-sans">This record is chained to the one before it (tamper-evident) · </span> : null}
                      {gap > 0 ? <span className="font-sans">{gap} event{gap === 1 ? "" : "s"} of other actions between · </span> : null}
                      #{next.seq}.prev {nextBroken ? "≠" : "="} hash #{next.seq - 1} <span className="opacity-70">({middle(next.prev_hash, 6, 4)})</span>
                      {nextBroken ? <span className="font-sans font-medium"> · broken: {!n.hash_ok ? "this record was edited" : !next.hash_ok ? "the next record was edited" : "stored hash changed"}</span> : null}
                    </span>
                  </Tooltip>
                </div>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
