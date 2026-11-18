"use client";

import { Anchor, ArrowDown, Check, Link2, X } from "lucide-react";
import { useEffect, useState } from "react";

import { HashChip } from "@/components/hash-chip";
import { StatusBadge } from "@/components/status-badge";
import { Skeleton } from "@/components/ui/input";
import { cn } from "@/lib/cn";
import { checkBundle, type Bundle, type ProofResult } from "@/lib/merkle";

/**
 * Signature view 2: the proof explorer. Draws the Merkle inclusion path from the leaf to the
 * epoch root (siblings left/right), then epoch root → later epochs → the on-chain anchor, and
 * recomputes every hash in this browser (Web Crypto) from public values only. A visual check:
 * the CLI with pinned trust roots is the authoritative verifier.
 */
export function ProofExplorer({ bundle, storedEventHash, explorerTxUrl }: { bundle: Bundle; storedEventHash: string; explorerTxUrl?: string | null }) {
  const [res, setRes] = useState<ProofResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    if (!globalThis.crypto?.subtle) {
      setErr("This browser does not expose Web Crypto here (it needs a secure context: HTTPS or localhost).");
      return;
    }
    checkBundle(bundle, storedEventHash).then((r) => live && setRes(r)).catch(() => live && setErr("Could not recompute the proof."));
    return () => { live = false; };
  }, [bundle, storedEventHash]);

  if (err) return <p role="alert" className="text-dense text-bad-11">{err}</p>;
  if (!res) return <div className="space-y-2" aria-busy="true"><Skeleton className="h-10 w-full" /><Skeleton className="h-40 w-full" /></div>;

  const okTick = (ok: boolean, label: string) => (
    <span className={cn("inline-flex size-5 shrink-0 items-center justify-center rounded-full", ok ? "bg-ok-9 text-white" : "bg-bad-9 text-white")}
      role="img" aria-label={`${label}: ${ok ? "matches" : "does not match"}`}>
      {ok ? <Check className="size-3.5" strokeWidth={3} /> : <X className="size-3.5" strokeWidth={3} />}
    </span>
  );
  const e = bundle.epoch;
  const anchor = bundle.anchor;
  const txHref = anchor?.tx_hash && explorerTxUrl ? explorerTxUrl.replace("{tx}", anchor.tx_hash.startsWith("0x") ? anchor.tx_hash : `0x${anchor.tx_hash}`) : null;

  return (
    <div className="space-y-5" data-testid="proof-explorer" data-result={res.result}>
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge value={res.result} size="lg" />
        <span className="text-dense text-gray-11">{res.reason ? `First failing check: ${res.reason}` : "Every recomputed hash matches."}</span>
        <span className="ml-auto rounded-sm border border-gray-6 bg-gray-2 px-2 py-0.5 text-caption text-gray-11">Visual check. The CLI is the authoritative verifier.</span>
      </div>

      {/* Merkle path diagram */}
      <div className="rounded-md border border-gray-6 bg-gray-2 p-4">
        <h3 className="mb-3 text-caption font-medium uppercase tracking-wide text-gray-11">Inclusion path · epoch {e.epoch_no} · leaf {bundle.proof.leaf_index} of {e.tree_size}</h3>
        <ol className="space-y-1">
          <li className="flex items-center gap-3">
            {okTick(res.checks[0]?.ok ?? false, "event hash")}
            <div className="min-w-0 rounded-md border border-brand-7 bg-gray-1 px-2.5 py-1.5 text-dense">
              <span className="text-caption text-gray-11">event #{bundle.event.seq} hash → leaf </span>
              <HashChip value={res.leaf} label="leaf hash = SHA-256(0x00 ‖ event hash)" />
            </div>
          </li>
          {res.steps.map((s, i) => (
            <li key={`${i}-${s.sibling}`} className="pl-2">
              <ArrowDown aria-hidden="true" className="my-0.5 ml-0.5 size-4 text-gray-9" />
              <div className="flex flex-wrap items-center gap-2">
                <span className="w-16 text-caption text-gray-11">level {i + 1}</span>
                <div className={cn("flex items-center gap-2", s.side === "left" ? "flex-row" : "flex-row-reverse")}>
                  <span className="rounded-md border border-dashed border-gray-8 bg-gray-1 px-2 py-1 text-caption">
                    <span className="text-gray-11">sibling ({s.side}) </span><HashChip value={s.sibling} label={`sibling at level ${i + 1}`} />
                  </span>
                  <span className="text-caption text-gray-11">+</span>
                  <span className="rounded-md border border-gray-6 bg-gray-1 px-2 py-1 text-caption text-gray-11">current</span>
                </div>
                <span className="text-caption text-gray-11">=</span>
                <HashChip value={s.result} label={`node at level ${i + 1}`} />
              </div>
            </li>
          ))}
          <li className="pl-2">
            <ArrowDown aria-hidden="true" className="my-0.5 ml-0.5 size-4 text-gray-9" />
            <div className="flex flex-wrap items-center gap-3">
              {okTick(res.checks[2]?.ok ?? false, "Merkle root")}
              <span className="rounded-md border border-brand-7 bg-gray-1 px-2.5 py-1.5 text-dense">
                <span className="text-caption text-gray-11">Merkle root (computed) </span><HashChip value={res.merkleRoot} label="computed Merkle root" />
                {res.merkleRoot !== e.merkle_root ? <span className="ml-2 text-caption text-bad-11">stored <HashChip value={e.merkle_root} label="stored Merkle root" /></span> : null}
              </span>
            </div>
          </li>
        </ol>
      </div>

      {/* epoch chain → anchor */}
      <div className="rounded-md border border-gray-6 bg-gray-2 p-4">
        <h3 className="mb-3 text-caption font-medium uppercase tracking-wide text-gray-11">Epoch roots → on-chain anchor</h3>
        <ol className="flex flex-wrap items-stretch gap-2">
          {res.epochRoots.map((r, i) => {
            const ok = r.computed === r.stored && r.prevOk;
            return (
              <li key={r.epoch_no} className="flex items-center gap-2">
                {i > 0 ? <Link2 aria-label={r.prevOk ? "commits to the previous root" : "does NOT commit to the previous root"} className={cn("size-4", r.prevOk ? "text-ok-11" : "text-bad-11")} /> : null}
                <div className={cn("rounded-md border bg-gray-1 px-2.5 py-1.5", ok ? "border-gray-6" : "border-bad-7")}>
                  <div className="flex items-center gap-1.5 text-caption text-gray-11">{okTick(ok, `epoch ${r.epoch_no} root`)}epoch {r.epoch_no}{r.epoch_no === e.epoch_no ? " (this event)" : ""}</div>
                  <HashChip value={r.computed} label={`epoch ${r.epoch_no} root (computed)`} />
                </div>
              </li>
            );
          })}
          <li className="flex items-center gap-2">
            <Anchor aria-hidden="true" className="size-4 text-gray-11" />
            <div className="rounded-md border border-gray-6 bg-gray-1 px-2.5 py-1.5 text-caption">
              {anchor ? (
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5"><span className="text-gray-11">anchor of epoch {anchor.epoch_no}</span><StatusBadge value={anchor.status} size="sm" /></div>
                  <div className="text-gray-11">chain {anchor.chain_id} · contract <HashChip value={anchor.contract} label="contract" /></div>
                  <div className="text-gray-11">
                    tx {anchor.tx_hash ? <HashChip value={anchor.tx_hash} label="transaction" href={txHref ?? undefined} /> : "—"}
                    {anchor.block_number ? <> · block <span className="tabular">{anchor.block_number}</span></> : null}
                  </div>
                </div>
              ) : <span className="text-gray-11">Not anchored on chain (anchoring not configured or still pending).</span>}
            </div>
          </li>
        </ol>
        <p className="mt-3 text-caption text-gray-11">The anchor is shown as claimed by this system. Whether it really is on the pinned chain, from the pinned contract and recorder, is checked by <code className="font-mono">agw-verify event --chain-rpc …</code>, not by this page.</p>
      </div>

      {/* checks list */}
      <ul className="space-y-2" aria-label="Recomputed checks">
        {res.checks.map((c) => (
          <li key={c.id} className="flex items-start gap-2.5 text-dense" data-check={c.id} data-ok={c.ok ? "true" : "false"}>
            {okTick(c.ok, c.label)}
            <div className="min-w-0">
              <div className={cn("font-medium", !c.ok && "text-bad-11")}>{c.label}</div>
              <div className="text-caption text-gray-11">{c.detail}</div>
              {!c.ok && c.expected ? <div className="mt-0.5 text-caption text-bad-11">expected <HashChip value={c.expected} label="expected" /> got <HashChip value={c.got} label="computed" /></div> : null}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
