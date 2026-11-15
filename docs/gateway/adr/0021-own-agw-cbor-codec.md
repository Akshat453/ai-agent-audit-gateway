# ADR-0021: Hand-written AGW-CBOR-v1 codec instead of cbor2
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 2 implementation (pending owner review)

## Context
ADR-0005 picks `cbor2` wrapped by a profile validator, and allows writing our own encoder if `cbor2` "fails any profile vector". The Phase 2 prompt says the same. On 2026-11-15 we probed `cbor2` 6.3.0:
- Its canonical *encoder* sorts keys correctly, but it happily encodes floats (`1.5` → `f93e00`) and `undefined` (`f7`), which the profile forbids.
- Its *decoder* accepted every non-canonical input we tried: unsorted keys, duplicate keys (last one wins, silently), non-shortest integers, indefinite-length arrays, float16, tag 1 (decoded to a `datetime`), `undefined` and simple(16). Only invalid UTF-8 was rejected.

A wrapper could catch most of this by re-encoding, but tags would round-trip as tags, and duplicate keys would be silently collapsed before we saw them.
## Decision
Write a narrow codec, `agw_schemas.cbor` (about 200 lines), that implements only AGW-CBOR-v1. The encoder rejects floats, out-of-range ints, non-text keys, invalid UTF-8, unsupported types and depth > 16. The decoder rejects with a reason code: unsorted keys, duplicate keys, non-shortest heads, indefinite lengths, floats, tags, undefined, other simple values, reserved additional info, invalid UTF-8, non-text keys, trailing bytes, truncation, out-of-range negatives and depth > 16. It then re-encodes and compares as defence in depth.

The verifier (`agw_verifier.cbor`) has its **own, separately written** implementation. Both are tested against the same frozen vectors (`packages/schemas/test-vectors/cbor/`). Every valid vector is also cross-checked byte for byte against `cbor2.dumps(..., canonical=True)` when the vectors are generated (`make vectors`), so the encoder is checked against an independent implementation.
## Consequences
+ The codec rejects exactly what the profile forbids, with stable reason codes. + No runtime dependency for the gateway or the verifier. + Two independent implementations cross-check each other.
− We maintain about 400 lines of codec (two copies) and must keep them in sync with the vectors.
## Alternatives rejected
`cbor2` plus a re-encode check (tags and duplicate keys would be silently normalized before the check). JCS/JSON (ADR-0005).
