# ADR-0012: AES-256-GCM with random per-event DEK wrapped by a KEK (reject Paper B's HKDF hierarchy)
Status: Accepted; **implemented in Phase 7** ([ADR-0029](0029-phase7-encryption-disclosure.md)) · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper B §III-E derives event keys from an epoch key via HKDF. Its §VIII-B says obtaining the epoch key reveals all events of the epoch and that erasure requires destroying epoch-key material.
## Decision
Each payload gets `DEK = os.urandom(32)` and is encrypted once with AES-256-GCM (random 96-bit nonce, AAD binds tenant + event id + payload digest). The DEK is wrapped with AES-256-GCM under a KEK (AAD binds tenant + event id + kek_id). KEK: local file in dev, KMS later behind a `KeyWrapper` interface. Rotate the KEK before 2^32 wraps.
## Consequences
+ Exact per-event disclosure and erasure. No epoch key to compel. + KEK rotation = re-wrap, chain untouched.
− About 60 bytes of wrapped key per event. − Backups keep wrapped DEKs until expiry or KEK destruction (07 §6).
