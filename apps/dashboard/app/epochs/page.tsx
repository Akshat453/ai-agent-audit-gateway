import { Badge, Page, short } from "@/components/legacy";
import { gateway, me } from "@/lib/gateway";

export default async function Epochs() {
  const [{ data }, who] = await Promise.all([(await gateway()).GET("/v1/dashboard/epochs", { params: { query: { limit: 200 } } }), me()]);
  return (
    <Page title="Epochs & anchors" lead={`Sealed Merkle epochs and their on-chain anchor states (submitted → included → finalized)${who.chain_id ? ` on chain ${who.chain_id}, contract ${who.contract}` : ""}.`}>
      <table aria-label="Epochs">
        <thead><tr><th scope="col">Epoch</th><th scope="col">Seq range</th><th scope="col">Size</th><th scope="col">Root</th><th scope="col">Sealed</th><th scope="col">Anchor</th><th scope="col">Tx</th><th scope="col">Times</th></tr></thead>
        <tbody>
          {(data ?? []).map((e) => (
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
    </Page>
  );
}
