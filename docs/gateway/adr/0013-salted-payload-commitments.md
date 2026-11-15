# ADR-0013: Salted payload commitments
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper B commits to `H(payload)`. Many tool payloads are low-entropy (`{"record_id": 42}`). Anyone holding records could confirm guesses by brute force, and crypto-erasure would leave a guessable digest.
## Decision
Every payload contains a fresh 32-byte random `salt` and its own `event` id. `payload_digest = H(TAG("AGW/payload/v1") || cbor(payload))`. The salt is only inside the encrypted payload.
## Consequences
+ The digest is hiding. + After erasure the digest reveals nothing.
− The salt must be disclosed (it is, inside the decrypted payload) for content verification.
