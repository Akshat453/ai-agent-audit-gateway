/**
 * In-browser recomputation for the proof explorer (signature view 2). Web Crypto SHA-256 over
 * SERVER-PROVIDED PUBLIC VALUES ONLY: the canonical event header (structural, no payload), the
 * Merkle audit path and the epoch records. Mirrors the independent verifier exactly
 * (packages/verifier: chain.py event_hash, merkle.py inclusion_ok / epoch_root, epochs.py
 * walk_epochs) with the documented domain tags (06 §5-7):
 *   event hash  = SHA256(0x0c "AGW/event/v1" || canonical header)
 *   leaf        = SHA256(0x00 || event hash)            node = SHA256(0x01 || left || right)
 *   epoch root  = SHA256(0x0c "AGW/epoch/v1" || u16 len(tenant) || tenant ||
 *                        u64 epoch_no || u64 tree_size || u64 first_seq || u64 last_seq ||
 *                        merkle_root || prev_root)
 * A visual check only: the CLI with pinned trust roots is the authoritative verifier.
 */

export type EpochRecord = {
  tenant: string; epoch_no: number; tree_size: number; first_seq: number; last_seq: number;
  merkle_root: string; prev_root: string; epoch_root: string;
};

export type Bundle = {
  tenant: string;
  event: { event_id: string; seq: number; header: string };
  proof: { epoch_no: number; tree_size: number; leaf_index: number; audit_path: string[] };
  epoch: EpochRecord;
  epoch_chain: EpochRecord[];
  trust_root: { epoch_no: number; epoch_root: string; source: string };
  anchor?: { chain_id: number; contract: string; recorder_id: string; epoch_no: number; status: string; tx_hash: string | null; block_number: number | null };
};

export type PathStep = { side: "left" | "right"; sibling: string; result: string };
export type Check = { id: string; label: string; ok: boolean; detail: string; expected?: string; got?: string };
export type ProofResult = {
  result: "VERIFIED" | "TAMPERED" | "INVALID_PROOF" | "INCOMPLETE";
  reason: string | null;
  eventHash: string;
  leaf: string;
  steps: PathStep[];
  merkleRoot: string;
  epochRoots: { epoch_no: number; computed: string; stored: string; prevOk: boolean }[];
  checks: Check[];
};

const enc = new TextEncoder();

export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function unhex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(s)) throw new Error("BAD_HEX");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function tag(t: string): Uint8Array {
  const raw = enc.encode(t);
  return cat(new Uint8Array([raw.length]), raw);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

const EVENT_TAG = tag("AGW/event/v1");
const EPOCH_TAG = tag("AGW/epoch/v1");

export const eventHash = (header: Uint8Array) => sha256(cat(EVENT_TAG, header));
const hLeaf = (x: Uint8Array) => sha256(cat(new Uint8Array([0]), x));
const hNode = (a: Uint8Array, b: Uint8Array) => sha256(cat(new Uint8Array([1]), a, b));

function u64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

export async function epochRoot(e: EpochRecord): Promise<Uint8Array> {
  const t = enc.encode(e.tenant);
  const len = new Uint8Array(2);
  new DataView(len.buffer).setUint16(0, t.length);
  return sha256(cat(EPOCH_TAG, len, t, u64(e.epoch_no), u64(e.tree_size), u64(e.first_seq), u64(e.last_seq),
    unhex(e.merkle_root), unhex(e.prev_root)));
}

/** RFC 9162 §2.1.3.2, recording each step (which side the sibling is on) for the diagram. */
export async function walkInclusion(leafInput: Uint8Array, index: number, size: number, path: Uint8Array[]) {
  const steps: PathStep[] = [];
  if (size <= 0 || index < 0 || index >= size) return { ok: false, root: new Uint8Array(32), steps, leaf: new Uint8Array(32) };
  let fn = index;
  let sn = size - 1;
  const leaf = await hLeaf(leafInput);
  let r = leaf;
  for (const p of path) {
    if (p.length !== 32 || sn === 0) return { ok: false, root: r, steps, leaf };
    if (fn % 2 === 1 || fn === sn) {
      r = await hNode(p, r);
      steps.push({ side: "left", sibling: hex(p), result: hex(r) });
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = await hNode(r, p);
      steps.push({ side: "right", sibling: hex(p), result: hex(r) });
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return { ok: sn === 0, root: r, steps, leaf };
}

/** The bundle checks in verifier order; the first failure decides the result (like verify_bundle). */
export async function checkBundle(b: Bundle, storedEventHash: string): Promise<ProofResult> {
  const checks: Check[] = [];
  const out: ProofResult = { result: "VERIFIED", reason: null, eventHash: "", leaf: "", steps: [], merkleRoot: "", epochRoots: [], checks };
  const fail = (result: ProofResult["result"], reason: string) => {
    if (out.result === "VERIFIED") { out.result = result; out.reason = reason; }
  };
  let header: Uint8Array;
  let path: Uint8Array[];
  try {
    header = unhex(b.event.header);
    path = b.proof.audit_path.map(unhex);
  } catch {
    fail("INCOMPLETE", "BAD_OR_INCOMPLETE_BUNDLE");
    return out;
  }
  // 1. the stored header still hashes to the stored event hash
  const eh = hex(await eventHash(header));
  out.eventHash = eh;
  const hashOk = eh === storedEventHash;
  checks.push({ id: "event-hash", label: "Header hashes to the stored event hash", ok: hashOk, detail: "SHA-256(TAG(AGW/event/v1) ‖ canonical header)", expected: storedEventHash, got: eh });
  if (!hashOk) fail("TAMPERED", "EVENT_HASH_MISMATCH");
  // 2. position comes from the epoch header, never from the proof alone
  const e = b.epoch;
  const seq = b.event.seq;
  const posOk = e.first_seq <= seq && seq <= e.last_seq && b.proof.leaf_index === seq - e.first_seq && b.proof.tree_size === e.tree_size && b.proof.epoch_no === e.epoch_no;
  checks.push({ id: "position", label: `Event #${seq} is leaf ${seq - e.first_seq} of ${e.tree_size} in epoch ${e.epoch_no}`, ok: posOk, detail: `epoch covers seq ${e.first_seq}–${e.last_seq}` });
  if (!posOk) fail("INVALID_PROOF", "PROOF_POSITION_MISMATCH");
  // 3. inclusion path from the leaf up to the epoch's Merkle root
  const walk = await walkInclusion(unhex(eh), b.proof.leaf_index, e.tree_size, path);
  out.leaf = hex(walk.leaf);
  out.steps = walk.steps;
  out.merkleRoot = hex(walk.root);
  const inclOk = walk.ok && out.merkleRoot === e.merkle_root;
  checks.push({ id: "inclusion", label: `Inclusion path (${path.length} sibling${path.length === 1 ? "" : "s"}) reaches the Merkle root`, ok: inclOk, detail: "RFC 9162 §2.1.3.2", expected: e.merkle_root, got: out.merkleRoot });
  if (!inclOk) fail("INVALID_PROOF", "INCLUSION_PROOF_FAILED");
  // 4. epoch roots: this epoch and every later one, each committing to its predecessor
  const records = [e, ...b.epoch_chain];
  let chainOk = true;
  for (let i = 0; i < records.length; i++) {
    const r = records[i] as EpochRecord;
    const computed = hex(await epochRoot(r));
    const prev = records[i - 1];
    const prevOk = i === 0 || (prev !== undefined && r.prev_root === prev.epoch_root && r.epoch_no === prev.epoch_no + 1);
    out.epochRoots.push({ epoch_no: r.epoch_no, computed, stored: r.epoch_root, prevOk });
    if (computed !== r.epoch_root || !prevOk || r.tenant !== b.tenant) chainOk = false;
  }
  checks.push({ id: "epochs", label: records.length > 1 ? `Epoch roots ${e.epoch_no}→${records[records.length - 1]?.epoch_no} recompute and link` : `Epoch ${e.epoch_no} root recomputes`, ok: chainOk, detail: "SHA-256(TAG(AGW/epoch/v1) ‖ header ‖ merkle root ‖ prev root)" });
  if (!chainOk) fail("TAMPERED", "EPOCH_ROOT_OR_LINK_MISMATCH");
  // 5. the newest root is the one the bundle presents as its trust root
  const last = out.epochRoots[out.epochRoots.length - 1];
  const trustOk = !!last && last.computed === b.trust_root.epoch_root && last.epoch_no === b.trust_root.epoch_no;
  checks.push({ id: "trust-root", label: `Chain ends at the presented root (epoch ${b.trust_root.epoch_no})`, ok: trustOk, detail: `source: ${b.trust_root.source}. Compare it with a root you obtained independently.` });
  if (!trustOk) fail("TAMPERED", "TRUST_ROOT_MISMATCH");
  return out;
}
