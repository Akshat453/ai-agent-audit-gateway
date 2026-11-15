# ADR-0007: RFC 9162 Merkle trees; reject last-leaf duplication
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper B §III-C duplicates the last leaf when the count is not a power of two. We confirmed that `[a,b,c]` and `[a,b,c,c]` then share a root, the CVE-2012-2459 class of malleability. We also confirmed that an RFC 9162 inclusion proof alone does not pin `tree_size` (06 §6.3).
## Decision
Use the RFC 9162 §2.1.1 Merkle Tree Hash (`leaf = H(0x00||x)`, `node = H(0x01||l||r)`, split at the largest power of two < n, no duplication), with §2.1.3 inclusion proofs. Leaf input = `event_hash`. Bind `tree_size`, `first_seq` and `last_seq` into the epoch root `R_t` (06 §7). Empty epochs are never sealed.
## Consequences
+ The root commits to an exact leaf list. + Standard, well-analyzed proof algorithm.
− Not interoperable with Paper B's prototype roots (not a goal).
