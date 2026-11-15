"""Standalone AGW evidence verifier.

Independence (docs/gateway/10 §1, 00 §3): this package imports nothing from the gateway, the
worker, the SDK or agw_schemas, and has no third-party dependencies. It re-implements the
AGW-CBOR-v1 profile and the 06 hashing rules from the spec; both implementations are checked
against the same frozen vectors in packages/schemas/test-vectors/.
"""

STATEMENT = (
    "Verified means the records are unchanged and correctly ordered relative to the trusted "
    "inputs given. It does not mean the recorded actions were truthful, authorized, complete "
    "or correct."
)
