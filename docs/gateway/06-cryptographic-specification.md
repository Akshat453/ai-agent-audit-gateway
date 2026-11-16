# 06 — Cryptographic Specification (AGW-CRYPTO v1)

Status: Accepted (Phase 0). Normative. ADRs: 0005, 0006, 0007, 0013. Implemented in
Phase 2 (tags, event hash, args digest), Phase 3 (Merkle, epoch root, proofs, vectors),
Phase 5 (payload digest + encryption). The verifier (`packages/verifier`) MUST implement this
document independently of the gateway code.

Notation: `||` concatenation. `u16(x)`, `u64(x)` unsigned big-endian, 2 and 8 bytes.
`H(x) = SHA-256(x)` (FIPS 180-4), 32-byte output. `ZERO32` = 32 bytes of 0x00.
`utf8(s)` = UTF-8 bytes of `s`.

## 1. Primitives

| Use | Primitive | Notes |
|---|---|---|
| All hashing | SHA-256 | Paper A §3 fn. 1 uses SHA-512 illustratively and calls SHA-256 suitable. Paper B §III-C uses SHA-256. RFC 9162 uses SHA-256. |
| Encoding | Deterministic CBOR, profile AGW-CBOR-v1 (05 §6) | RFC 8949 §4.2.1 |
| Merkle tree | RFC 9162 §2.1.1 Merkle Tree Hash | No leaf duplication |
| Payload encryption | AES-256-GCM, 96-bit random nonce | 07 |
| Key wrap | AES-256-GCM under KEK with AAD | 07 |

## 2. Domain separation

Every SHA-256 input starts with a **domain prefix** that determines the hash type:

```
TAG(t) = u8(len(utf8(t))) || utf8(t)          # len in [2, 255]
```

The length prefix makes the tag set **prefix-free** unconditionally. Without it,
`"AGW/event/v1"` would be a prefix of a hypothetical `"AGW/event/v10"`. RFC 9162 Merkle hashes
keep their RFC prefixes 0x00 / 0x01. Every `TAG` starts with a length byte ≥ 0x02, so no AGW
hash input can collide in type with a Merkle leaf or node input (first byte 0x00/0x01).

| Tag string | `TAG` bytes (hex) | Hash type | Defined in |
|---|---|---|---|
| — (RFC 9162) | `00` | Merkle leaf | §6 |
| — (RFC 9162) | `01` | Merkle interior node | §6 |
| `AGW/event/v1` | `0c 4147572f6576656e742f7631` | Event hash | §4 |
| `AGW/payload/v1` | `0e 4147572f7061796c6f61642f7631` | Payload digest | §5 |
| `AGW/epoch/v1` | `0c 4147572f65706f63682f7631` | Epoch root | §7 |
| `AGW/args/v1` | `0b 4147572f617267732f7631` | Canonical args digest (approval binding) | §3 |
| `AGW/approval/v1` | `0f 4147572f617070726f76616c2f7631` | Approval binding digest (**unused**: superseded by `AGW/action/v1` + the decision record, ADR-0027) | 04 §5 |
| `AGW/risk-policy/v1` | `12 4147572f7269736b2d706f6c6963792f7631` | Risk policy digest (over its canonical CBOR) | ADR-0026 |
| `AGW/action/v1` | `0d 4147572f616374696f6e2f7631` | Action digest (what an approval binds) | ADR-0027 §1 |
| `AGW/policy/v1` | `0d 4147572f706f6c6963792f7631` | Policy document digest (stored JSON, canonical CBOR) | ADR-0027 §1 |
| `AGW/approval-decision/v1` | `18 4147572f617070726f76616c2d6465636973696f6e2f7631` | Approver decision record digest | ADR-0027 §4 |
| `AGW/approval-sig/v1` | `13 4147572f617070726f76616c2d7369672f7631` | Ed25519 message prefix for decision signatures | ADR-0027 §4 |
| `AGW/session/v1` | `0e 4147572f73657373696f6e2f7631` | Human session token digest | ADR-0027 §3 |
| `AGW/tenant-key/v1` | `11 4147572f74656e616e742d6b65792f7631` | On-chain tenant key (**unused**: replaced by `AGW/recorder/v1`, ADR-0028) | 09 §7 |
| `AGW/payload-aad/v1` | `12 4147572f7061796c6f61642d6161642f7631` | AEAD label: payload AAD prefix (`cbor({tenant, event_id, seq, payload_digest, schema_version})`) | ADR-0029 §1 |
| `AGW/dek-wrap-aad/v1` | `13 4147572f64656b2d777261702d6161642f7631` | AEAD label: DEK wrap AAD prefix (`cbor({context, kek_id})`) | ADR-0029 §2 |
| `AGW/sealed-ops/v1` | `11 4147572f7365616c65642d6f70732f7631` | AEAD label: sealed operational args | ADR-0029 §5 |
| `AGW/redact/v1` | `0d 4147572f7265646163742f7631` | Secret-field redaction marker (salted) | ADR-0029 §4 |
| `AGW/disclosure/v1` | `11 4147572f646973636c6f737572652f7631` | HPKE `info` prefix for disclosed DEKs | ADR-0029 §6 |
| `AGW/disclosure-ids/v1` | `15 4147572f646973636c6f737572652d6964732f7631` | Digest of the event ids of a grant / access | ADR-0029 §6 |
| `AGW/recorder/v1` | `0f 4147572f7265636f726465722f7631` | On-chain recorder id (salted; §10) | ADR-0028 §2 |
| `AGW/request/v1` | `0e 4147572f726571756573742f7631` | Idempotency request fingerprint | 08 §5 |
| `AGW/apikey/v1` | `0d 4147572f6170696b65792f7631` | API key digest | 11 §3 |
| `AGW/bundle/v1` | `0d 4147572f62756e646c652f7631` | Evidence bundle manifest digest | 10 §2 |

AEAD associated-data labels (not hash inputs, but same encoding): `AGW/payload-aad/v1`,
`AGW/dek-wrap-aad/v1` (07). A new hash type MUST add a row here via ADR. Reusing a tag for a
different structure is forbidden. Phase 2 adds a unit test asserting the table is prefix-free
and that every `TAG` length byte is ≥ 2.

## 3. Canonical args digest

```
args_digest = H( TAG("AGW/args/v1") || cbor(validated_args) )
```

`validated_args` is the Pydantic model dumped in *python* mode (aliases resolved, defaults
applied, `extra="forbid"`) and then encoded under AGW-CBOR-v1. The digest is over the *validated*
form, not the raw request JSON, so `{"a":1,"b":2}` and `{"b":2,"a":1}` bind identically,
while any semantic change does not.

## 4. Event hash and hash chain

```
canonical_event_bytes = cbor(event_record)          # 05 §4; includes v, tenant, seq, prev
event_hash            = H( TAG("AGW/event/v1") || canonical_event_bytes )
```

Rules:

1. `canonical_event_bytes` is produced **once**, at insert, and stored in
   `evidence_events.canonical_bytes`. `event_hash` is computed over **those stored bytes** and
   never over a re-serialized JSONB value (ADR-0005).
2. Chain: for each tenant, `record(seq).prev = event_hash(seq − 1)`, and
   `record(0).prev = ZERO32`.
3. `seq` starts at 0 and is gap-free per tenant. It is allocated under a row lock on the
   tenant's `chain_heads` row (ADR-0018, mechanism per ADR-0022), in the same transaction that
   inserts the event.
4. `canonical_event_bytes` already contains `v` (schema version), `seq` and `prev`, so the hash
   commits to position, predecessor and schema version.
5. The tenant is inside the record, so an event can't be spliced into another tenant's chain.

Verification of a chain segment `[a..b]`: decode each record with strict profile checks
(05 §6 rule 8), recompute `event_hash`, check `seq` contiguity and each `prev` link.

## 5. Payload digest

```
plaintext_payload_cbor = cbor(payload)           # 05 §5; includes v, salt(32 random bytes), event id
payload_digest         = H( TAG("AGW/payload/v1") || plaintext_payload_cbor )
```

- The event record commits to `payload_digest` (record key `payload.digest`) and the plaintext
  length. The ciphertext is stored separately (07) and is **not** hashed into the record. The
  DEK can be destroyed (crypto-erasure) or re-wrapped without touching the chain.
- `salt` is 32 bytes from `os.urandom`/`secrets`. Without it, low-entropy payloads (e.g.
  `{"record_id": 42}`) could be confirmed by brute force from the digest alone (ADR-0013).
- Content verification (Paper B §III-D): decrypt → check `encode(decode(pt)) == pt` → recompute
  `payload_digest` → compare with the committed record → check `payload.event == record.id`.

## 6. Merkle tree (RFC 9162 §2.1)

### 6.1 Leaves

An epoch covers the contiguous range `first_seq ..= last_seq` of one tenant.
`tree_size n = last_seq − first_seq + 1 ≥ 1`. Leaf `i` (0-based) is the event with
`seq = first_seq + i`, and its leaf input is that event's 32-byte `event_hash`:

```
leaf_input_i = event_hash(first_seq + i)                       # 32 bytes
```

### 6.2 Merkle Tree Hash (RFC 9162 §2.1.1)

```
MTH(D[1])  = H( 0x00 || D[0] )                                 # leaf_hash
MTH(D[n])  = H( 0x01 || MTH(D[0:k]) || MTH(D[k:n]) )   for n > 1
             where k = largest power of two strictly less than n   (k < n ≤ 2k)
```

The empty tree (`MTH({}) = H("")` in RFC 9162) **never occurs**. Epochs with zero events are not
sealed. `M_t = MTH(leaves of epoch t)`.

### 6.3 Inclusion proof

```
InclusionProof = {
  tenant:     tstr,
  epoch_no:   uint,
  tree_size:  uint,          # n
  leaf_index: uint,          # i = seq − first_seq
  audit_path: [bstr(32)]     # RFC 9162 §2.1.3.1 PATH(i, D[n]), leaf-to-root order
}
```

Generation (RFC 9162 §2.1.3.1): for `n > 1` with `k` as above,
`PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])` if `m < k`, else
`PATH(m − k, D[k:n]) : MTH(D[0:k])`. `PATH(0, D[1]) = []`.

Verification (RFC 9162 §2.1.3.2), given `leaf_input`, the proof and the expected `M_t`:

```
if leaf_index >= tree_size: FAIL
fn, sn, r = leaf_index, tree_size − 1, H(0x00 || leaf_input)
for p in audit_path:
    if sn == 0: FAIL
    if (fn & 1) == 1 or fn == sn:
        r = H(0x01 || p || r)
        while (fn & 1) == 0 and fn != 0:  fn >>= 1; sn >>= 1
    else:
        r = H(0x01 || r || p)
    fn >>= 1; sn >>= 1
ACCEPT iff sn == 0 and r == M_t
```

**`tree_size` MUST come from the authenticated epoch header, not from the proof alone.** We
checked this on 2026-11-15 with a scratch script over all trees n ≤ 16 and claimed sizes ≤ 32:
an RFC 9162 path computed for one tree size also verifies against the same root under other
claimed sizes in 560 (n, leaf, size) cases. For example, leaf 0 of a 5-leaf tree verifies with
claimed sizes 6, 7 and 8. That is harmless only because `tree_size` is bound into `R_t` (§7).
The verifier recomputes `R_t` from the header and compares it with the anchor, which pins
`tree_size`.

### 6.4 Why Paper B's last-leaf duplication is rejected

Paper B §III-C: "When the leaf count is not a power of two, the implementation duplicates the
last leaf." Under that rule the root does not commit to the number of leaves. Leaves `[a, b, c]`
and `[a, b, c, c]` produce the **same** root. We confirmed this in the same scratch check. The
consequences:

1. A verifier can't tell from the root whether the epoch contained 3 or 4 events, so an
   inclusion proof "proves" a phantom duplicate event at index 3.
2. Two different event lists share one anchored root. That's the same class of flaw as Bitcoin's
   CVE-2012-2459 (duplicate-transaction Merkle malleability).
3. Leaf and interior hashes are not domain-separated in Paper B's description, which leaves the
   door open to second-preimage tricks where an interior node is presented as a leaf.

RFC 9162 avoids all three. It splits at the largest power of two below `n`, never duplicates,
and prefixes leaves with 0x00 and nodes with 0x01. We additionally bind `tree_size` into `R_t`.

## 7. Epoch root (chained)

```
R_t = H( TAG("AGW/epoch/v1")
       || u16(len(utf8(tenant_id))) || utf8(tenant_id)
       || u64(epoch_no)
       || u64(tree_size)
       || u64(first_seq)
       || u64(last_seq)
       || M_t                      # 32 bytes
       || R_{t−1} )                # 32 bytes; R_{−1} = ZERO32 for epoch_no = 0
```

Exact byte layout of the hash input:

| Offset | Length | Field |
|---|---|---|
| 0 | 13 | `0c` + `"AGW/epoch/v1"` |
| 13 | 2 | `u16(L)`, L = byte length of tenant id (1..63) |
| 15 | L | tenant id, UTF-8 (ASCII by the 05 §4 regex) |
| 15+L | 8 | `u64(epoch_no)` |
| 23+L | 8 | `u64(tree_size)` |
| 31+L | 8 | `u64(first_seq)` |
| 39+L | 8 | `u64(last_seq)` |
| 47+L | 32 | `M_t` |
| 79+L | 32 | `R_{t−1}` |
| | **111 + L** | total |

Constraints the sealer enforces and the verifier checks:

- `epoch_no` starts at 0 and increments by 1. `first_seq(0) = 0`.
- `first_seq(t) = last_seq(t−1) + 1` (epochs tile the sequence: no gaps, no overlap).
- `tree_size = last_seq − first_seq + 1 ≥ 1`.
- Only `R_t` and `R_{t−1}` go on-chain (09 §7). `M_t` and the header stay off-chain in the
  `epochs` table and in evidence bundles.

Compared with Paper B §III-C (`R_t = H(M_t ∥ R_{t−1})`): we add a domain tag, the tenant
(no cross-tenant reuse), the epoch number (no renumbering), and the tree size and seq range
(no tail truncation inside a sealed epoch, no size ambiguity, §6.3).

**Epoch header** (stored, bundled): `{tenant, epoch_no, tree_size, first_seq, last_seq,
merkle_root: M_t, prev_root: R_{t−1}, root: R_t, sealed_at, seal_reason}`. `seal_reason` ∈
`MAX_EVENTS | MAX_AGE | RISK_HIGH | RISK_CRITICAL | MANUAL`. `sealed_at` and `seal_reason` are
informational and are **not** in `R_t`.

## 8. Full verification of one event (summary; details in 10)

> Phase 6 (ADR-0028): the contract stores `R_t` with `tree_size` and `last_seq`, not `R_{t−1}`.
> Step 4's continuity check therefore uses the recomputed chain of roots (each `R_t` commits to
> `R_{t−1}`) plus the contract's own contiguity and seq-tiling checks. The chain lookups in steps
> 3–5 use `eth_call` at the finality block, under trust roots pinned by the auditor.

1. Strict-decode the record. Recompute `event_hash`.
2. Verify the inclusion proof against `M_t`, using `tree_size` and `leaf_index = seq − first_seq` from the header.
3. Recompute `R_t` from the header. Compare it with the anchored root for `(tenant_key, epoch_no)` on-chain.
4. Check the on-chain `prevRoot` equals `R_{t−1}` and that epoch continuity holds back to the earliest epoch in scope.
5. Check the anchor's block has reached the required finality.
6. (Optional disclosure) Decrypt the payload and check §5.

## 9. Test-vector plan (generated in Phase 3, frozen in `packages/schemas/test-vectors/`)

Vectors are JSON files with hex-encoded bytes. They are generated once by a Phase 3 script,
reviewed, committed, and then **frozen**. After that, `make vectors` regenerates into a temp
dir and fails on any diff. Changing a frozen vector requires an ADR.

| File | Contents |
|---|---|
| `tags.json` | every tag string → `TAG` bytes (hex) |
| `cbor-profile.json` | ≥ 40 cases: RFC 8949 Appendix A integers/strings/maps within the profile; key ordering cases; **must-reject** inputs (float, indefinite length, non-shortest int, duplicate key, unsorted keys, tag, invalid UTF-8, `undefined`) |
| `event-hash.json` | 3 records (genesis `seq=0, prev=ZERO32`; `seq=1`; record with every optional field), their `canonical_bytes` and `event_hash` |
| `payload-digest.json` | 2 payloads with fixed salt → `plaintext_payload_cbor`, `payload_digest` |
| `merkle-1.json`, `merkle-2.json`, `merkle-3.json`, `merkle-5.json`, `merkle-8.json` | leaves `leaf_input_i = H(TAG("AGW/event/v1") ‖ u64(i))` (deterministic, documented), every `leaf_hash`, `M_t`, and an inclusion proof for **every** leaf index. n = 3 and 5 exercise the non-power-of-two split; n = 1 exercises the empty audit path. |
| `merkle-negative.json` | proofs that MUST fail: wrong index, `leaf_index ≥ tree_size`, truncated path, extra path element, swapped siblings, leaf hashed without 0x00, Paper-B-duplicated root for n = 3 |
| `epoch-root.json` | 3-epoch chain for tenant `acme` (sizes 1, 5, 8; seq 0..0, 1..5, 6..13): every hash-input byte string and `R_0`, `R_1`, `R_2` |
| `epoch-root-negative.json` | header mutations (tenant, epoch_no, tree_size, first/last seq, `R_{t−1}`) each with the resulting different root |

Both the gateway test suite and the verifier test suite consume these files. CI fails if
either implementation disagrees with a single byte.

## 10. Recorder id (Phase 6, ADR-0028)

```
recorderId = SHA-256( TAG("AGW/recorder/v1") || u16(len(utf8(tenant))) || utf8(tenant) || salt )
```

- **Salt.** `salt` is the 32-byte deployment salt (`AGW_ANCHOR_DEPLOYMENT_SALT`). It stops anyone from confirming a guessed tenant name against the chain. Auditors are given `recorderId`, never the salt.
- **Frozen vector** (unit test `test_recorder_id_matches_spec_bytes`): tenant `acme`, salt `00 01 .. 1f` → `3559e18e6a0c528f27792b8d211ea73d69e6100322e15812ba44c1937be9d8f8`.
