# ADR-0006: SHA-256 with explicit, length-prefixed domain-separation tags
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §3 fn. 1 uses SHA-512 illustratively and does not claim SHA-256 unsuitable. Paper B and RFC 9162 use SHA-256. Hashes of different structures must not be confusable.
## Decision
SHA-256 everywhere. Every hash input starts with `TAG(t) = u8(len(t)) || ascii(t)` from the registered table in 06 §2 (e.g. `AGW/event/v1`, `AGW/epoch/v1`). Merkle leaves and nodes keep RFC 9162's 0x00/0x01 prefixes. All TAG length bytes are ≥ 2, so no AGW input shares a first byte with a Merkle input. The length prefix makes the tag set prefix-free even across version suffixes (`v1` vs `v10`). This is our exact byte encoding of the addendum's `"AGW/epoch/v1" || ...` notation.
## Consequences
+ No cross-type collisions by construction. + 32-byte digests fit EVM `bytes32`.
− Changing hash function needs new tags (`/v2`) and a migration plan.
