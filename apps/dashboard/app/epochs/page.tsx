import { PlainLine } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Term } from "@/components/humanize/term";
import { Badge, Page, short } from "@/components/legacy";
import { cn } from "@/lib/cn";
import { gateway, me } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { CHAINS, epochSentence, epochSteps } from "@/src/humanize";

export default async function Epochs() {
  const [{ data }, who, p] = await Promise.all([(await gateway()).GET("/v1/dashboard/epochs", { params: { query: { limit: 200 } } }), me(), prefs()]);
  const rows = data ?? [];
  const chain = who.chain_id ? CHAINS[who.chain_id] ?? `chain ${who.chain_id}` : null;
  const permanent = rows.filter((e) => e.anchor_status === "FINALIZED").length;
  return (
    <Page title="Epochs & anchors" help="epochs" lead={p.view === "simple"
      ? "Log records are locked in batches. Each batch's fingerprint is written to a blockchain, so nobody can quietly rewrite history."
      : `Sealed Merkle epochs and their on-chain anchor states (submitted → included → finalized)${who.chain_id ? ` on chain ${who.chain_id}, contract ${who.contract}` : ""}.`}>
      <PlainLine>{rows.length ? <>{rows.length} <Term term="batch">batch{rows.length === 1 ? "" : "es"}</Term> locked; {permanent} <Term term="finalized">permanent</Term> on {chain ?? "a blockchain"}.</> : "No batches locked yet. Records are locked into batches within minutes of being recorded."}</PlainLine>
      {p.view === "simple" ? (
        <ul className="mb-4 space-y-2" aria-label="Batches in plain English" data-testid="epoch-sentences">
          {rows.map((e) => (
            <li key={e.epoch_no} className="rounded-md border border-gray-6 bg-gray-1 px-4 py-3 text-dense">
              <p className="text-gray-12">{epochSentence(e, who.chain_id, p.tz)}</p>
              <ol className="mt-2 flex flex-wrap gap-3 text-caption" aria-label={`Batch ${e.epoch_no} progress`}>
                {epochSteps(e).map((st) => (
                  <li key={st.label} className={cn("inline-flex items-center gap-1", st.done ? "text-ok-11" : "text-gray-11")}>
                    <span aria-hidden="true" className={cn("size-2 rounded-full", st.done ? "bg-ok-9" : "bg-gray-6")} />{st.label}
                  </li>
                ))}
              </ol>
            </li>
          ))}
        </ul>
      ) : null}
      <Technical view={p.view}>
      <table aria-label="Epochs">
        <thead><tr><th scope="col">Epoch</th><th scope="col">Seq range</th><th scope="col">Size</th><th scope="col">Root</th><th scope="col">Sealed</th><th scope="col">Anchor</th><th scope="col">Tx</th><th scope="col">Times</th></tr></thead>
        <tbody>
          {rows.map((e) => (
            <tr key={e.epoch_no}>
              <td>{e.epoch_no}</td>
              <td>{e.first_seq}–{e.last_seq}</td>
              <td>{e.tree_size}</td>
              <td><code>{short(e.epoch_root, 16)}…</code></td>
              <td className="text-xs">{e.sealed_at}<div>{e.seal_reason} {e.anchor_priority ? `· ${e.anchor_priority}` : ""}</div></td>
              <td><Badge value={e.anchor_status} /></td>
              <td className="text-xs">
                {e.tx_hash ? (e.explorer_url ? <a href={e.explorer_url} target="_blank" rel="noreferrer noopener"><code>{short(e.tx_hash, 14)}…</code></a> : <code>{short(e.tx_hash, 14)}…</code>) : "-"}
                {e.block_number !== null ? <div>block {e.block_number}</div> : null}
              </td>
              <td className="text-xs">{e.submitted_at ? <div>submitted {e.submitted_at}</div> : null}{e.included_at ? <div>included {e.included_at}</div> : null}{e.finalized_at ? <div>finalized {e.finalized_at}</div> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {who.explorer_tx_url ? null : <p className="mt-2 text-xs">No block explorer is configured for this chain (local Anvil); tx hashes are shown without links.</p>}
      </Technical>
    </Page>
  );
}
