# 07 — Key Management, Encryption and Selective Disclosure

Status: Accepted (Phase 0); **implemented in Phase 7** ([ADR-0029](adr/0029-phase7-encryption-disclosure.md)).
Deviations, as implemented:
- **AAD:** the payload AAD is `TAG || cbor({tenant, event_id, seq, payload_digest, schema_version})`, and the wrap AAD is `TAG || cbor({context, kek_id})`.
- **Storage:** blobs go to MinIO above 64 KiB, and ciphertext lives in `payload_objects`, deletable only by the evidenced erasure path.
- **Disclosure:** it uses HPKE (RFC 9180), not `age`, with DISCLOSURE_GRANTED / DISCLOSURE_ACCESSED instead of KEY_DISCLOSED.
- **Erasure:** the event is PAYLOAD_DELETED, not PAYLOAD_ERASED.
- **Additions:** field classification, secret redaction and sealed operational args. ADRs: 0012 (random per-event DEK),
0013 (salted payloads), 0017 (ciphertext storage). Sources: Paper A §3 (data minimization),
§8 (key management, deletion); Paper B §III-E, §VIII-B.

## 1. Goals

1. Integrity structures (records, chain, Merkle, anchors) contain **no** sensitive content (Paper B §III-C).
2. Payloads are encrypted at rest by default.
3. **Per-event disclosure**: an auditor receiving keys for 3 events learns nothing about the others (Paper B §III-E goal).
4. **Per-event crypto-erasure** without breaking the chain.
5. Nothing sensitive on-chain: only 32-byte roots and minimal metadata (ADR-0014).

## 2. Key hierarchy

```
KEK  (Key Encryption Key; 256-bit; dev: local file; later: KMS/HSM)
 └── wraps DEK_e for each event e that has a payload  (256-bit, os.urandom, used for exactly one plaintext)
```

| Key | Generated | Stored | Rotation |
|---|---|---|---|
| KEK | `make dev-kek` writes 32 random bytes to `AGW_KEK_FILE` (git-ignored). Later via KMS. | File (dev) / KMS (later). Never in the DB. | Re-wrap DEKs to the new KEK, a background job. Chain unaffected. Rotate before 2^32 wraps under one KEK (random-nonce GCM limit). |
| DEK_e | Per payload, `os.urandom(32)` | Only wrapped, in `payload_keys` | Never reused |

`kek_id` is an operator-assigned string (e.g. `dev-2026-11`). It is stored next to each wrapped
DEK, and the `KeyWrapper` interface (`wrap(dek, aad) → (kek_id, nonce, wrapped)`,
`unwrap(...)`) hides whether a file or a KMS is behind it.

### Why not Paper B's HKDF hierarchy (ADR-0012)

Paper B derives `K_t = HKDF(master, epoch_id)` and `k_{t,i} = HKDF(K_t, event_id)` (§III-E).
Its own limitations section says that obtaining `K_t` yields every event key in the epoch, and
that erasure "requires destroying or re-wrapping the relevant epoch-key material, not merely
deleting derived per-event keys" (§VIII-B). With random DEKs:
- Disclosure is exactly per event, and there's no epoch key to be compelled.
- Erasing one event means deleting one wrapped DEK. Other events in the epoch are unaffected.
- The cost is one 60-byte wrapped key per event, which is acceptable.

## 3. Payload encryption

```
pt        = plaintext_payload_cbor                  # 06 §5, includes 32-byte salt and event id
digest    = H(TAG("AGW/payload/v1") || pt)          # committed in the event record
aad_p     = TAG("AGW/payload-aad/v1") || u16(len(tenant)) || tenant || event_id(16) || digest(32)
nonce_p   = os.urandom(12)
ct        = AES-256-GCM(DEK_e).encrypt(nonce_p, pt, aad_p)     # ct includes 16-byte tag

aad_w     = TAG("AGW/dek-wrap-aad/v1") || u16(len(tenant)) || tenant || event_id(16)
            || u16(len(kek_id)) || kek_id
nonce_w   = os.urandom(12)
wrapped   = AES-256-GCM(KEK).encrypt(nonce_w, DEK_e, aad_w)
```

- AAD binds the ciphertext to its tenant, event and committed digest, so ciphertexts can't be
  swapped between events (T19). The wrapped DEK is bound to its event and KEK.
- `DEK_e` encrypts exactly one message, so a random 96-bit nonce is safe.
- Library: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

## 4. Storage (ADR-0017)

| Table | Mutability | Columns |
|---|---|---|
| `evidence_payloads` | **Append-only** (same grants and triggers as `evidence_events`) | `event_id` PK/FK, `tenant_id`, `alg` = `A256GCM`, `nonce`, `ciphertext`, `blob_ref` (nullable, > 1 MiB → MinIO object key), `created_at` |
| `payload_keys` | Mutable (re-wrap, erasure) | `event_id` PK, `kek_id`, `wrap_nonce`, `wrapped_dek`, `updated_at` |

The ciphertext is written **in the same Postgres transaction** as its event. That's simpler and
safer than a two-phase DB + object-store write. MinIO holds only large blobs (content-addressed,
written before the tx, with orphans garbage-collected) and exported evidence bundles.

## 5. Selective disclosure (Phase 7 export)

1. The operator selects event ids. The exporter unwraps their DEKs.
2. The disclosure package contains, per event: record bytes, ciphertext, nonce and **DEK_e**. It
   is encrypted to the auditor's public key out of band (format chosen in Phase 7; candidate:
   `age` X25519 recipients).
3. Each disclosure appends a `KEY_DISCLOSED` event to the tenant chain: event ids disclosed,
   recipient id, purpose. Disclosure itself is then evidenced (Paper A §5 monitoring spirit).
4. The auditor runs content verification (06 §5, Paper B §III-D). The DEKs reveal nothing about
   other events.

## 6. Crypto-erasure

- Erase one payload: delete its `payload_keys` row and append a `PAYLOAD_ERASED` event (event
  id, legal basis code, requester). The chain, Merkle proofs and anchors stay valid. The digest
  is salted, so it no longer reveals the content.
- **Limitation (stated honestly):** copies of the wrapped DEK in DB backups stay decryptable while
  the KEK that wrapped them exists. Erasure is complete only after backup expiry, or after KEK
  rotation followed by destroying the old KEK. Like Paper B §VIII-B, this is an operational
  mechanism, not a legal-sufficiency claim.

## 7. What stays in cleartext (by design)

Event records reveal: tenant, seq, event type, timestamps, agent id, tool id/version,
environment, risk level, policy ids and reasons, digests. This metadata is needed for
verification and forensic queries (Paper B §VI-F). It is **not** published. It stays in the DB
and in bundles. On-chain there are only the tenant key, epoch number, `R_t` and `R_{t−1}`.
Deployments with sensitive tool names can set the tool alias in the registry. Tool *ids* are
operator-chosen.

## 8. Handling rules

- Never log KEK, DEKs, plaintext payloads or tool args (enforced by the logging allow-list, 11 §2).
- KEK file permissions `0600`. The gateway refuses to start if the file is group/world readable.
- `.env.example` contains only a path placeholder, never key material.
