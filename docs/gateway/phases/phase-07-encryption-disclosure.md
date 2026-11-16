# Phase 7: Encryption, key management, selective disclosure

Date: 2026-11-16 · ADR: [0029](../adr/0029-phase7-encryption-disclosure.md) · Status: done.

## What this phase delivers
- **Encryption at rest.** Evidence payloads are encrypted (AES-256-GCM, one random key per event, wrapped by a KEK). A database dump alone reveals no confidential or secret value.
- **Secrets never stored.** Fields classified secret never reach evidence, logs, headers or plaintext columns.
- **Per-event disclosure.** An authorized auditor can export single events and verify them end to end (decrypt, digest, inclusion proof, on-chain anchor) with only the bundle, their own key and pinned trust roots.
- **Retention, rotation, migration.** Retention, crypto-erasure and KEK rotation work without breaking verification. Existing plaintext was migrated and the plaintext columns dropped.

**Claim boundary (unchanged).** Encryption hides content; it does not make a record true. Crypto-erasure is an operational mechanism, not a legal-compliance claim (backups and replicas: §4).

## 1. What changed

| Area | Files | What |
|---|---|---|
| Crypto | `crypto/envelope.py`, `crypto/tags.py` | Payload AAD (CBOR), AES-GCM, HPKE seal/open, recipient key id, redaction marker; 6 new tags (06 §2) |
| Keys | `keys/provider.py` | `KeyProvider`; `LocalKeyProvider` (0600 files, refuses git checkouts, versions); `VaultTransitKeyProvider`; `KeyUnavailable` vs `UnwrapFailed` |
| Storage | `evidence/payloads.py`, `evidence/blobs.py`, `evidence/writer.py` | Encrypted store behind the same interface, plus a MinIO blob store. The writer has no plaintext default and fails closed without a KEK. |
| Privacy | `privacy/classification.py`, `minimize.py`, `cipher.py`, `retention.py`, `disclosure.py`, `migrate.py`, `rotation.py` | Field classes, redaction, sealed operational args, retention and erasure, grants and export, re-encryption job, re-wrap job |
| Tools | `tools/spec.py`, `tools/demo.py` | `ToolSpec.classes`, and classes for every demo tool |
| Gateway wiring | `execution/service.py`, `execution/executor.py`, `approvals/service.py`, `anchoring/gate.py`, `api/app.py`, `api/state.py`, `api/routes.py`, `api/errors.py`, `api/approval_routes.py`, `api/disclosure_routes.py`, `config.py`, `admin.py`, worker `__main__.py` | Minimized payloads; sealed args; 503s; `/v1/ready` needs the KEK; disclosure API; `GET /v1/auth/me`; admin commands (gen-kek, migrate-payloads, rewrap-keys, erase-payload, set-retention, legal-hold, release-hold, retention-sweep); retention in the worker |
| DB | migrations `0007_phase7_encryption`, `0008_phase7_drop_plaintext`, `migrations/env.py` | 7 new tables; sealed-args columns; 3 event types; 0008 guard and plaintext drop; one transaction per migration |
| Schemas | `agw_schemas/events.py`, `bundle/evidence-bundle.v1.schema.json` | `Disclosure` and `Erasure` header maps, three event models, `disclosure` payload section, `payload.ref = "blob"`, bundle `payload_status` |
| Verifier | `agw_verifier/disclosure.py`, `cli.py`, `chain.py`, `pyproject.toml` | `auditor-keygen`, `--auditor-key`, HPKE and AES-GCM opening (optional `[disclosure]` extra), payload-status handling |
| Tests | `tests/privacykit.py`, `unit/test_encryption_units.py` (11), `e2e/test_encryption.py` (12), `e2e/test_disclosure.py` (6), `e2e/test_telemetry_canary.py` (1), `e2e/test_payload_migration.py` (1), `conftest.py` | Session KEK, secret and bigdoc test tools, MinIO and Vault containers; earlier tests updated to read payloads through the store |
| Experiments | `experiments/privacy/mutation_check.py`, `results/mutations.txt` | 20 guard mutations |
| Infra | `docker-compose.yml` (MinIO), `Makefile`, `.env.example`, `run_demo.sh`, `disclosure_demo.py` | The `minio` service is pinned by digest. New Makefile targets `dev-kek` and `privacy-mutations`; `verify-isolated` now also checks the `[disclosure]` extra; the coverage gate includes privacy and keys. `.env.example` gains the Phase 7 settings. The demo runs the auditor from a separate venv. |
| Docs | ADR-0029; notes in 03 (T18, T19, T24), 05, 06, 07, 10, 11, 13; ADR-0012 and ADR-0017 status; ADR index; README | |

## 2. Decisions
The full reasoning is in ADR-0029.

**Docs vs prompt** (the prompt wins; recorded in the ADR):
- the missing `10-privacy-and-storage.md` (07 was used instead);
- the AAD layout;
- the 64 KB blob threshold;
- deletable ciphertext (ADR-0017 had it append-only);
- the event names;
- HPKE instead of `age`.

**Choices of mine:**
- **Sealed operational args.** A tool needs its real secret at dispatch. That copy exists only encrypted, bound to tenant + purpose + action, and is deleted at dispatch.
- **Unvalidated args are not stored.** They cannot be classified, so only key names and a salted digest are kept.
- **Unclassified fields count as confidential.**
- **Plaintext results.** Only public and internal results go into the agent-visible plaintext copy.
- **HPKE library:** `cryptography` (already a dependency), not `pyhpke`.
- **Grant scope:** event ids, or every event of one action.
- **Separation of duties:** a DB CHECK enforces admin ≠ auditor.
- **Every export attempt is evidence**, allowed or denied. A successful export is returned only after its evidence commits.
- **Two error types:** KEK unavailable (transient, retried) vs unwrap failed (tampered or moved, permanent).
- **MinIO image:** Chainguard's build, pinned by digest. Official MinIO images are no longer pullable anonymously.
- **One transaction per migration**, so 0007 stays applied when 0008 refuses.

## 3. Results

### 3.1 Clean-state acceptance
Setup: stack, volumes, `.env` (verified identical to `.env.example`) and `.venv` removed. Then:
```
$ (make up && make migrate && make test && make demo); echo "chain exit=$?"
chain exit=0
```

| Check | Result |
|---|---|
| Migrations | 0001 → 0008 applied |
| ruff | `All checks passed!` |
| mypy | `Success: no issues found in 106 source files` |
| import-linter | `Contracts: 6 kept, 0 broken` |
| Tests | `747 passed` (Phase 6: 717; 31 new; one old trigger case replaced) |
| Coverage, overall | 90% |
| Coverage, gated packages (now including privacy and keys) | 94% (gate 85%) |
| Coverage, `risk/` | 100% |
| Demos | `DEMO OK`, `PHASE 5 DEMO OK`, `PHASE 6 DEMO OK`, `PHASE 7 DISCLOSURE OK`, `PHASE 7 AUDITOR VERIFICATION OK` |

Coverage per new module:

| Module | Coverage |
|---|---|
| `cipher.py` | 100% |
| `minimize.py` | 98% |
| `classification.py` | 95% |
| `migrate.py` | 93% |
| `payloads.py` | 92% |
| `envelope.py` | 91% |
| `provider.py` | 90% |
| verifier `disclosure.py` | 88% |
| `retention.py` | 87% |
| `disclosure.py` | 82% |
| `blobs.py` | 81% |

Other targets:

| Target | Result |
|---|---|
| `make vectors` | exit 0 (frozen vectors unchanged) |
| `make verify-isolated` | base verifier is stdlib-only; `isolated [disclosure]: verifier + cryptography only` |
| `make privacy-mutations` | `20/20 mutations caught` |

### 3.2 Acceptance demo: the auditor, from a separate venv
```
Phase 7 selective disclosure (action …: COMPLETED)
  confidential body in any header? False (expected False)
  ACTION_REQUESTED + ACTION_COMPLETED sealed and anchored (final)
  adam granted 2 events to audrey (grant …, key …)
  audrey exported 2 bundles (mode hpke): ciphertext + DEK sealed to her key, no plaintext
  attempt: export an event outside the grant -> 403 EVENT_NOT_GRANTED
  the agent sees 0 disclosure events (expected 0: not its business)
PHASE 7 DISCLOSURE OK
disclosure evidence in the chain: {'DISCLOSURE_ACCESSED COMPLETED': 1, 'DISCLOSURE_ACCESSED EVENT_NOT_GRANTED': 1, 'DISCLOSURE_GRANTED': 1}
--- Phase 7: the auditor, in her own venv, with ONLY bundles + her key + pinned trust roots ---
auditor workspace: auditor.key bundle-0.json bundle-1.json pinned-trust.json
auditor venv: no gateway code installed
agw-verify event bundle-0.json (decrypt -> digest -> proof -> anchor) exit=0
agw-verify event bundle-1.json (decrypt -> digest -> proof -> anchor) exit=0
agw-verify event (one ciphertext byte flipped) exit=1 (1 = TAMPERED)
agw-verify event (no auditor key: payload unchecked) exit=2 (2 = INCOMPLETE)
PHASE 7 AUDITOR VERIFICATION OK
```
The auditor's key is generated in her own venv; only the public key reaches the gateway. Verification runs after the gateway and worker are stopped. Trust roots are pinned (chain id, contract, recorder id), and the anchor is checked on the chain.

### 3.3 Required tests

| Required test | Test | Result |
|---|---|---|
| Ciphertext swap → decryption fails (AAD) | `test_ciphertext_swap_between_events_fails` | Three variants: (1) swap ciphertexts only; (2) also swap wrapped DEKs; (3) an insider WITH the KEK re-wraps B's DEK for A. All end DECRYPT_FAILED, and the chain verifier reports TAMPERED (`PAYLOAD_DECRYPT_FAILED`). |
| Grant for X cannot decrypt Y (same epoch) | `test_grant_for_x_cannot_open_y_in_the_same_epoch` | Same epoch asserted. (a) The API refuses Y with 403 and records DENIED evidence. (b) Y's ciphertext inside X's bundle is TAMPERED. (c) X's DEK, opened with the auditor key, raises `InvalidTag` on Y's ciphertext. (d) X's own bundle verifies. |
| Expired grant → 403 + evidence | `test_expired_grant_is_403_and_evidenced` | 403 `GRANT_EXPIRED`, plus `DISCLOSURE_ACCESSED {DENIED, GRANT_EXPIRED}` naming the auditor and the grant |
| DB-only attacker cannot read payloads | `test_db_only_attacker_cannot_read_payloads` | Binary COPY of every table, with completed, pending-approval and queued actions present: no confidential or secret canary. Another KEK cannot unwrap the DEKs. |
| Rotation keeps decryptability and verification | `test_kek_rotation_preserves_decryptability_and_verification` | v1 and v2 coexist (old payloads still open). Re-wrap leaves 0 remaining, then **v1 is destroyed**. Every payload still decrypts, the chain export stays VERIFIED, every exported line is byte-identical, and secret markers are unchanged (salt re-wrapped). Also against real Vault Transit (`test_vault_transit_provider`). |
| Deleted payload → INCOMPLETE, not TAMPERED | `test_retention_deletes_payload_header_and_chain_still_verify`, `test_deleted_payload_bundle_is_incomplete` | Retention policy + legal hold + PAYLOAD_DELETED evidence. The chain export is INCOMPLETE with 3 missing payloads. The disclosure bundle is INCOMPLETE (`PAYLOAD_UNAVAILABLE:DELETED`), and header, proof and anchor are still checked. |
| Canary leak test (logs, metrics, errors, headers) | `test_canary_never_leaks` | Secret and confidential canaries through allowed, adapter-exception, invalid, unknown-tool, malformed-JSON, envelope, FastAPI-validated, idempotency-conflict and approval paths. 0 occurrences in logs (including exception text), metrics, agent responses and their headers, and evidence headers. Traces: no SDK or exporter configured (asserted). |

Further tests:
- **At rest:** payloads stored as ciphertext, with the digest still committing to the plaintext.
- **No KEK:** 503 at both the API and the store, and nothing is written.
- **Secrets:** never stored; the adapter gets the real value, payloads hold markers, GET returns public results only.
- **Header lint** across all tools and paths.
- **Sealed args:** swapped between jobs, neither runs.
- **MinIO:** large payloads go to a private bucket (anonymous GET 403). A missing object is INCOMPLETE, an altered one TAMPERED. Orphans are garbage-collected. With MinIO down, only large payloads get 503.
- **Disclosure rules:** roles, separation of duties, revocation, agent-key rejection, plaintext mode, wrong auditor key, tampered sealed DEK.
- **Data migration** on an isolated 0007 database:
  - 0008 refuses while plaintext remains;
  - an interrupted run resumes;
  - a mismatching row is not migrated and keeps 0008 blocked;
  - after the fix, 0008 drops the columns, payloads decrypt byte-identically, and a migrated pending approval and queued job still execute.

### 3.4 Real upgrade of the existing dev database (before the clean run)
- **First `make migrate`:** 0007 applied, then 0008 refused (`68 plaintext payload/arg rows are not re-encrypted yet`).
- **`admin migrate-payloads`:**
  ```
  {"payloads_encrypted": 41, "payloads_verified": 41, "dispatch_args_sealed": 10, "request_args_sealed": 17, "mismatched": []}
  ```
- **Second `make migrate`:** 0008 applied.
- **Bug found on the way.** Alembic had run both migrations in one transaction, so 0008's refusal also rolled back 0007. `env.py` now uses one transaction per migration.

### 3.5 Failing-then-passing evidence (`make privacy-mutations`)
20 guards were removed one at a time; each was caught by its named test:
- **Encryption and keys:** AAD fields, DEK-wrap context, KEK file mode, the no-KEK store guard.
- **Minimization:** secret args, secret results, the plaintext results filter, unvalidated args, sealed operational args.
- **Disclosure:** expiry, granted-events subset, grantee, denial evidence, the verifier's swapped-ciphertext check.
- **Retention:** legal hold, PAYLOAD_DELETED evidence.
- **Migration:** the 0008 guard, the migration digest check.
- **Telemetry:** adapter error logging, validation error echo.

The first run caught 18 of 20. The two survivors exposed weak tests, now fixed:
- the no-KEK test never reached the store-level guard (the minimizer refused first);
- the canary test never hit FastAPI's own validation handler.

## 4. Known gaps
- **Unsalted args digest.** The header `args` digest (06 §3, frozen) is unsalted. A low-entropy confidential arg can be confirmed by guessing when the other args are known. Fixing it needs an args-digest v2 (ADR).
- **Copies outside the live DB.** Backups, replicas, WAL archives and MinIO object versions keep old wrapped DEKs and ciphertexts. Erasure is complete only after they expire, or after rotate + re-wrap + destroying the old KEK. This is not a legal-compliance claim.
- **Unattributable deletion.** `agw_app` can DELETE payload rows. A compromised runtime could delete without PAYLOAD_DELETED; this is detected (INCOMPLETE) but not attributed.
- **Sealed operational args** are not re-wrapped by rotation (they drain). Destroy an old KEK only after queues drain.
- **No AWS KMS adapter** (interface only); Vault Transit is implemented and tested.
- **Plaintext delivery mode** relies on transport security only; HPKE is the default.
- **Not built:** auditor key rotation and revocation UI, purpose-limited field-level disclosure (the whole payload of an event is disclosed), and a signed operator manifest for trust roots (Phase 6 gap, unchanged).
- **Dev KEK location.** The dev KEK lives in `~/.agw/kek` on the developer's machine (outside the repo, by design).

## 5. Readiness
Encryption, disclosure, retention and rotation are in place and verified end to end, including from an isolated auditor venv. Nothing is committed: HEAD is still `abb5e2a phase3`, and Phases 4–7 are in the working tree. The next roadmap item is the verifier/bundle phase (signed operator manifest, V9/V10 lifecycle checks), which can build on the disclosure bundles as they are.
