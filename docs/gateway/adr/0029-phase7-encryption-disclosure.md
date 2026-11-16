# ADR-0029: Phase 7 encryption, key management and selective disclosure
Status: Accepted · Date: 2026-11-16 · Deciders: Phase 7 implementation (pending owner review)

## Context
The Phase 7 prompt asks to replace the Phase 2 plaintext payload store with AES-256-GCM under per-event keys wrapped by a KEK. It also asks for:
- large payloads in MinIO;
- field classification, with secrets never stored;
- a one-off re-encryption of old data;
- auditor disclosure grants with HPKE re-wrapping;
- KEK rotation;
- retention with evidence;
- a canary test against telemetry leaks.

The spec for this is 07 (written in Phase 0, when this was "Phase 5") plus ADR-0012, ADR-0013 and ADR-0017.

**Docs and the prompt disagree here:**
1. **Missing doc.** The prompt says to read `10-privacy-and-storage.md`. No such file exists: 10 is verification. The privacy spec is 07, and I used it.
2. **AAD layout.** 07 §3 defines `TAG || u16 || tenant || event_id || digest`. The prompt defines `CBOR{tenant, event_id, seq, payload_digest, schema_version}`. The prompt's version also binds the position and the schema version. Neither was implemented before, so the prompt's layout is used under the same label `AGW/payload-aad/v1`.
3. **Blob threshold.** 07 §4 / ADR-0017 store payloads over 1 MiB in MinIO; the prompt says over 64 KB. The prompt wins (configurable).
4. **Mutability.** ADR-0017 makes the ciphertext table append-only. The prompt requires retention to delete payloads. Ciphertext rows are therefore never updated but are deletable, and only through the erasure path, which writes PAYLOAD_DELETED.
5. **Event names.** 05/07 name the events `KEY_DISCLOSED` and `PAYLOAD_ERASED`. The prompt names them DISCLOSURE_GRANTED, DISCLOSURE_ACCESSED and PAYLOAD_DELETED. The prompt's names are used; none of the old ones was ever written.
6. **Disclosure format.** 07 §5 suggests `age` recipients. The prompt asks for HPKE (RFC 9180), and HPKE is used (§6).
7. **Phase numbering.** The roadmap calls encryption Phase 5; the prompts call it Phase 7. Not renumbered.

## Decision

### 1. Payload encryption (behind the unchanged `store_payload` / `load_payload` interface)
```
DEK_e   = os.urandom(32)                                     one plaintext per DEK
ct      = AES-256-GCM(DEK_e).encrypt(nonce = os.urandom(12), plaintext_payload_cbor, aad)
aad     = TAG("AGW/payload-aad/v1") || cbor({tenant, event_id, seq, payload_digest, schema_version})
wrapped = KeyProvider.wrap(DEK_e, cbor({tenant, event_id}))  -> payload_keys(kek_id, kek_version)
```
- **Commitment unchanged.** The header still commits to `payload.digest` over the plaintext (06 §5). The verifier recomputes it after decrypting.
- **Fail closed.** If there is no usable KEK, nothing with a payload is written: 503 `KEY_UNAVAILABLE`, and `/v1/ready` returns 503. If MinIO is down, only payloads above the threshold fail (503 `STORAGE_UNAVAILABLE`).
- **Tables.**
  - `payload_objects`: nonce, ciphertext or blob key, `ct_len`, `ct_sha256`. The runtime role cannot UPDATE it; rows are never rewritten.
  - `payload_keys`: wrapped DEKs. Only the wrapping columns can be updated (rotation), and rows can be deleted (erasure).

### 2. KEK providers (`keys/`)
- **`LocalKeyProvider`.** A keyring directory with one file per version (`<id>.v<N>.key`). Files must be mode 0600. The provider **refuses directories inside any git checkout**. The wrap is AES-256-GCM with `aad = TAG("AGW/dek-wrap-aad/v1") || cbor({context, kek_id})`. `make dev-kek` creates the keyring at `~/.agw/kek`.
- **`VaultTransitKeyProvider`.** Vault Transit (aes256-gcm96), with the same AAD passed as `associated_data`. Tested against a real Vault 1.20.4 dev server, including rotation.
- **AWS KMS.** Not shipped. It maps onto the same interface (Encrypt/Decrypt with EncryptionContext).
- **Error types.**
  - `KeyUnavailable`: transient. The KEK is missing, unreachable or is another provider's.
  - `UnwrapFailed`: permanent. The wrapped key was tampered with or moved to another event.

### 3. Object storage (MinIO, S3 API)
- **What goes there.** Only ciphertexts above `AGW_PAYLOAD_BLOB_THRESHOLD_BYTES` (64 KiB), as `<tenant>/<event_id>`. The header records `payload.ref = "blob"`. Postgres keeps the key, length and SHA-256, so a missing or altered object is detected (INCOMPLETE vs TAMPERED).
- **Private bucket.** The bucket is private: startup refuses a bucket that has any bucket policy. Anonymous GET returns 403 (tested).
- **Order of writes.** Objects are written before the event transaction commits. Orphans are garbage-collected after a grace period.
- **Image.** MinIO's official images are no longer pullable anonymously. Compose and the tests use Chainguard's MinIO build, pinned by digest.

### 4. Classification and minimization (`privacy/classification.py`, `minimize.py`)
- **Classes.** Each tool field is classified `public | internal | confidential | secret`. An unlisted field is `confidential`. The classes live on `ToolSpec` and are validated against the args model.
- **Secret fields.** Values become `[REDACTED:sha256:H(TAG("AGW/redact/v1") || tenant_salt || cbor(value))]` in **every** evidence payload and in the approver view. `tenant_salt` is 32 random bytes per tenant, wrapped by the KEK.
- **Unvalidated args** (unknown tool, schema violation) cannot be classified, so they are not stored. Only key names and a salted digest are kept. This is a change from Phase 2, which kept the raw JSON text.
- **Results.** The agent-visible plaintext copy (`actions.result_public`) holds only public and internal results. Confidential results live only in the encrypted payload.
- **Header lint.** A test pushes canaries through every field of every tool, along allow, approval, deny, invalid and unknown-tool paths, and finds none in any stored header.

### 5. Sealed operational args (beyond the prompt: required by "secrets never stored")
- **The problem.** A tool needs its real secret at dispatch time, which may be minutes after an approval. That copy can't be redacted.
- **The fix.** `outbox_jobs.args_sealed` and `actions.request_args_sealed` hold an envelope: a fresh DEK, AES-256-GCM, AAD bound to tenant + purpose + action id, and the DEK wrapped by the KEK. They are dropped as soon as the action is dispatched or closed.
- **Old columns.** The plaintext JSONB columns are dropped.
- **Deviation.** Strictly, a secret is "stored": encrypted, transiently, only for the tool that needs it. It never appears in evidence, logs, headers or plaintext.

### 6. Selective disclosure
- **Keys.** Auditors (Phase 5 `auditor` role) register an X25519 public key (`POST /v1/auditor-keys`). The key id is the first 16 bytes of SHA-256(pub), as hex.
- **Grants.** Admins create `disclosure_grants` (`POST /v1/disclosures`). A grant names the auditor and key, either explicit event ids or every event of one action, a purpose, an expiry (at most 30 days) and a delivery mode.
  - **Checks:** the auditor must hold the auditor role, the key must be theirs, and the events must exist in the tenant.
  - **Separation of duties:** a DB CHECK enforces `granted_by <> auditor_id`.
  - **Revocation** is possible.
- **Export** (`POST /v1/disclosures/{grant}/export`). Per event, the bundle contains:
  - the Phase 3/6 parts: header bytes, inclusion proof, epoch chain and anchor claim;
  - a `disclosure` section. In `hpke` mode (the default) it carries the stored nonce and ciphertext plus the event's DEK sealed with **HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM**, using `info = TAG("AGW/disclosure/v1") || cbor({tenant, grant_id, event_id, recipient_key_id})`. In `plaintext` mode it carries the decrypted payload, protected only by transport.
- **HPKE library.** I chose `cryptography` (≥ 46 provides `hazmat.primitives.hpke`) over `pyhpke`. It is already a gateway dependency and audited; nothing new is added.
- **Evidence.**
  - DISCLOSURE_GRANTED: the header holds grant, auditor, key, mode, scope, expiry, count and `ids = H(TAG("AGW/disclosure-ids/v1") || cbor(sorted ids))`. The purpose and the event list are in the encrypted payload.
  - DISCLOSURE_ACCESSED: written for **every** export, allowed or denied (expired, revoked, not the grantee, event outside the grant), with an outcome code.
  - A successful export is returned only after its evidence has committed. Both events are HIGH, so they seal promptly.
- **Per-event isolation.** The DEKs are random per event (ADR-0012), so one event's DEK opens exactly one ciphertext. A grant for X cannot open Y in the same epoch (tested three ways).

### 7. Data migration (Phase 2–6 plaintext → encrypted)
- **Migration 0007** adds the new tables and keeps the old plaintext.
- **`admin migrate-payloads`** re-encrypts every plaintext payload.
  - It checks each payload against its committed header (digest and length), encrypts it, decrypts it again and compares the bytes, one transaction per batch.
  - It is resumable and idempotent.
  - A payload that does not match its header is **not** migrated, is reported (CRITICAL log) and keeps 0008 blocked.
  - Pending outbox args and approval requests are sealed.
- **Migration 0008** refuses while any plaintext remains, then drops `evidence_payloads.content`, `outbox_jobs.args` and `actions.request_args`.
- **Alembic now runs one transaction per migration**, so 0007 stays applied when 0008 refuses.
- **Proven on the real dev database:** 41 payloads were re-encrypted and verified, 10 + 17 operational args were sealed, then 0008 applied.

### 8. Retention and crypto-erasure
- **Policies.** `retention_policies(tenant|*, tool|*, classification|*, retain_days)`; the most specific match wins, and no match means keep forever. Unreleased `legal_holds` on a tenant, run, action or event block deletion.
- **Deletion.** The job (in the worker) and `admin erase-payload` delete the wrapped DEK and the ciphertext. In the same transaction they append PAYLOAD_DELETED `{event, seq, reason, policy}`. The blob is removed after commit.
- **After deletion.** Header, digest, proof and anchor stay valid. The verifier reports **INCOMPLETE** (payload unavailable), not TAMPERED.
- **Not a legal-compliance claim.** Copies in backups, replicas, WAL archives and object versions remain decryptable while the old KEK exists. Erasure is complete only after those copies expire, or after rotating the KEK, re-wrapping and destroying the old version. Whether that satisfies a given legal obligation is for counsel.

### 9. KEK rotation
- **How it works.** A new version becomes active, and new DEKs are wrapped under it. All old versions still unwrap, so nothing breaks.
- **`admin rewrap-keys`** moves wrapped DEKs and redaction salts to the active version (idempotent, resumable, scoped to the provider's own KEK id). After it reports 0 remaining, the old version can be destroyed.
- **Verification is unaffected:** event bytes, payload bytes and proofs are identical before and after (tested, including destroying v1).
- **Sealed operational args** keep their old version until they drain. Destroy an old KEK only after that.

### 10. Telemetry hygiene
- **Logging.** The Phase 1 allow-listed structured logging is unchanged. Adapter errors are logged by type only, and validation errors name fields, never values.
- **Canary test.** A secret and a confidential canary go through allowed, failing-adapter, invalid, unknown-tool, malformed-JSON, idempotency-conflict, approval and FastAPI-validated paths. Neither appears in:
  - logs, including exception text;
  - metrics;
  - error and normal agent responses or their headers;
  - evidence headers.
- **Traces.** The OpenTelemetry API is present only as a FastAPI dependency. No SDK or exporter is configured (asserted).

## Consequences
**Gains**
- **DB-only attacker:** a full binary dump of every table contains no confidential or secret value (tested).
- **Ciphertext swaps** fail at three layers: the DEK-wrap context, the AEAD AAD, and the verifier's AAD-from-header.
- **Disclosure is per event** and fully evidenced.
- **The auditor needs only** the bundle, their key and the pinned trust roots, in a venv with `agw-verifier[disclosure]`. The extra adds only `cryptography`; the core verifier stays stdlib-only.
- **Mutation check:** 20 guard mutations are each caught by a named test.

**Costs and limits**
- **Unsalted args digest.** The header `args` digest (06 §3, frozen vectors) is unsalted, so a low-entropy confidential arg can be confirmed by guessing if all the other args are known. Changing it needs a new args-digest version and ADR.
- **What stays in cleartext** (by design, 07 §7): event metadata such as tool ids, agent ids, risk reasons and outcome codes.
- **Unauditable deletion.** `agw_app` may DELETE payload rows, so a compromised runtime can delete payloads without PAYLOAD_DELETED. The verifier then reports them unavailable (INCOMPLETE), which is detectable but not attributable.
- **Plaintext mode.** It relies on transport security only.
- **Size caps.** A grant lists at most 1000 events and one export returns at most `AGW_DISCLOSURE_MAX_EVENTS` (200). Larger investigations take several grants.
- **Sealed operational args** are not re-wrapped by rotation; they drain naturally.
