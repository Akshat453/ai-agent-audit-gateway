"""Sealed envelopes for operational data that must outlive a request but is not evidence
(Phase 7, ADR-0029 §5): the dispatch args in ``outbox_jobs.args_sealed`` and the validated
request of a pending approval in ``actions.request_args_sealed``. Both may contain SECRET
fields the tool needs, so they are encrypted like payloads (fresh DEK, AES-256-GCM, DEK wrapped
by the KEK) and dropped as soon as the action is dispatched / closed.

    envelope = cbor({v:1, kek_id, kek_version, wrap_nonce, wrapped_dek, nonce, ct})
    aad      = TAG("AGW/sealed-ops/v1") || cbor(context)   e.g. {tenant, purpose, ref}
"""

from __future__ import annotations

import json
from typing import Any, Final

from cryptography.exceptions import InvalidTag

from agw_gateway.crypto.canonical import CanonicalError, decode, encode
from agw_gateway.crypto.envelope import decrypt_payload, encrypt_payload, new_dek
from agw_gateway.crypto.tags import SEALED_OPS_TAG, domain_tag
from agw_gateway.keys import KeyProvider, KeyUnavailable, UnwrapFailed, WrappedKey

_TAG: Final = domain_tag(SEALED_OPS_TAG)


class SealedDataError(Exception):
    """A sealed envelope does not open: wrong context, tampered or malformed (permanent)."""


def ops_context(tenant: str, purpose: str, ref: bytes) -> dict[str, Any]:
    return {"tenant": tenant, "purpose": purpose, "ref": ref}


class EnvelopeCipher:
    def __init__(self, provider: KeyProvider) -> None:
        self.provider = provider

    def seal(self, context: dict[str, Any], plaintext: bytes) -> bytes:
        ctx = encode(context)
        dek = new_dek()
        nonce, ct = encrypt_payload(dek, plaintext, _TAG + ctx)
        w = self.provider.wrap(dek, ctx)
        return encode(
            {
                "v": 1,
                "kek_id": w.kek_id,
                "kek_version": w.kek_version,
                "wrap_nonce": w.nonce,
                "wrapped_dek": w.ciphertext,
                "nonce": nonce,
                "ct": ct,
            }
        )

    def open(self, context: dict[str, Any], sealed: bytes) -> bytes:
        ctx = encode(context)
        try:
            env = decode(bytes(sealed))
            w = WrappedKey(env["kek_id"], env["kek_version"], env["wrap_nonce"], env["wrapped_dek"])
            dek = self.provider.unwrap(w, ctx)
            return decrypt_payload(dek, env["nonce"], env["ct"], _TAG + ctx)
        except KeyUnavailable:
            raise  # transient: the KEK cannot be used right now (retry later, fail closed)
        except (CanonicalError, KeyError, TypeError, InvalidTag, UnwrapFailed):
            raise SealedDataError("sealed data does not open") from None

    def seal_json(self, context: dict[str, Any], value: Any) -> bytes:
        return self.seal(context, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def open_json(self, context: dict[str, Any], sealed: bytes) -> Any:
        return json.loads(self.open(context, sealed))
