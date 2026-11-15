# ADR-0005: Deterministic CBOR profile; hash the exact stored bytes
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §3 calls canonicalization "security-relevant" and mentions JCS as an example. Paper B §III-B uses deterministic CBOR (RFC 8949 §4.2) to avoid JSON float, key-order and Unicode pitfalls. Re-serializing a JSONB value before hashing can silently change bytes (key order, number formatting).
## Decision
Profile **AGW-CBOR-v1** (05 §6): RFC 8949 §4.2.1 core deterministic encoding, text-string keys only, no floats, no tags, no indefinite lengths, no null in records, strict decode (`encode(decode(x)) == x`). Records are encoded **once** at insert, stored in `canonical_bytes`, and every hash is computed over those stored bytes. JSONB is a derived, non-authoritative projection. Implementation: `cbor2` wrapped by a profile validator. If `cbor2` fails any profile vector, write our own encoder in `packages/schemas`. The profile is versioned. Changes need a new ADR and `v` bump.
## Consequences
+ One byte representation per event. + Verifier-independent vectors.
− Tool arg models can't use floats (decimals as canonical strings).
