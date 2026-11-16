"""Envelope encryption primitives (Phase 7, ADR-0029; 07 §3). Pure functions, no I/O.

    payload:  ct = AES-256-GCM(DEK_e).encrypt(nonce12, plaintext_payload_cbor, payload_aad)
    payload_aad = TAG("AGW/payload-aad/v1")
                  || cbor({tenant, event_id, seq, payload_digest, schema_version})
    DEK_e:    32 random bytes, encrypts exactly ONE payload -> a random 96-bit nonce is safe.

The AAD binds a ciphertext to its tenant, event, position and committed digest, so moving a
ciphertext to another event fails authentication (T19). DEK wrapping is done by a
``KeyProvider`` (keys/), with its own AAD.

Disclosure (HPKE, RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM,
via ``cryptography``): the DEK of ONE event is sealed to the auditor's X25519 public key with
    info = TAG("AGW/disclosure/v1") || cbor({tenant, grant_id, event_id, recipient_key_id})
so a sealed DEK cannot be re-attributed to another event, grant or recipient.
"""

from __future__ import annotations

import hashlib
import os
from typing import Final

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agw_gateway.crypto.canonical import encode
from agw_gateway.crypto.tags import (
    DISCLOSURE_TAG,
    PAYLOAD_AAD_TAG,
    REDACT_TAG,
    domain_tag,
)

ALG: Final = "A256GCM"
HPKE_SUITE_NAME: Final = "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM"
_SUITE: Final = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
_PAYLOAD_AAD: Final = domain_tag(PAYLOAD_AAD_TAG)
_DISCLOSURE: Final = domain_tag(DISCLOSURE_TAG)
_REDACT: Final = domain_tag(REDACT_TAG)


def payload_aad(
    tenant: str, event_id: bytes, seq: int, digest: bytes, schema_version: int
) -> bytes:
    if len(event_id) != 16 or len(digest) != 32:
        raise ValueError("event id is 16 bytes, digest 32 bytes")
    return _PAYLOAD_AAD + encode(
        {
            "tenant": tenant,
            "event_id": event_id,
            "seq": seq,
            "payload_digest": digest,
            "schema_version": schema_version,
        }
    )


def new_dek() -> bytes:
    return os.urandom(32)


def encrypt_payload(dek: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext||tag). One call per DEK."""
    nonce = os.urandom(12)
    return nonce, AESGCM(dek).encrypt(nonce, plaintext, aad)


def decrypt_payload(dek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on any mismatch (key, nonce, AAD, bytes)."""
    return AESGCM(dek).decrypt(nonce, ciphertext, aad)


def disclosure_info(tenant: str, grant_id: bytes, event_id: bytes, recipient_key_id: str) -> bytes:
    return _DISCLOSURE + encode(
        {
            "tenant": tenant,
            "grant_id": grant_id,
            "event_id": event_id,
            "recipient_key_id": recipient_key_id,
        }
    )


def seal_to_recipient(dek: bytes, recipient_public: bytes, info: bytes) -> bytes:
    """HPKE base-mode single shot: enc(32) || AES-256-GCM(dek) (48)."""
    return _SUITE.encrypt(dek, X25519PublicKey.from_public_bytes(recipient_public), info=info)


def open_from_sender(sealed: bytes, recipient_private: bytes, info: bytes) -> bytes:
    return _SUITE.decrypt(sealed, X25519PrivateKey.from_private_bytes(recipient_private), info=info)


def recipient_key_id(public_key: bytes) -> str:
    """Short, stable id of an auditor's X25519 public key (first 16 bytes of SHA-256, hex)."""
    if len(public_key) != 32:
        raise ValueError("X25519 public keys are 32 bytes")
    return hashlib.sha256(public_key).hexdigest()[:32]


def redaction_marker(tenant_salt: bytes, value: bytes) -> str:
    """``[REDACTED:sha256:<hex>]`` = SHA-256(TAG("AGW/redact/v1") || salt || cbor(value)).
    The 32-byte per-tenant salt (stored wrapped by the KEK) stops a DB reader from confirming
    guessed secrets; the same secret yields the same marker within a tenant (correlation)."""
    if len(tenant_salt) != 32:
        raise ValueError("tenant salt must be 32 bytes")
    return f"[REDACTED:sha256:{hashlib.sha256(_REDACT + tenant_salt + value).hexdigest()}]"
