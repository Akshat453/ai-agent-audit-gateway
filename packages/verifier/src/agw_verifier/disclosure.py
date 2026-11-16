"""Disclosure bundles (Phase 7, ADR-0029 §6): open the payload of ONE disclosed event with the
auditor's X25519 private key, then hand it to the ordinary bundle checks.

    sealed_dek  --HPKE open (RFC 9180 base, DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM),
                  info = TAG("AGW/disclosure/v1") || cbor({tenant, grant_id, event_id,
                                                          recipient_key_id})-->  DEK
    ciphertext  --AES-256-GCM(DEK, nonce,
                  aad = TAG("AGW/payload-aad/v1") || cbor({tenant, event_id, seq,
                                                          payload_digest, schema_version}))
                --> canonical payload  -> digest == header.payload.digest (bundle checks)

tenant, event id, seq and payload digest are taken from the CANONICAL HEADER, never from the
disclosure section, so a ciphertext or sealed DEK moved from another event cannot open.

Needs the optional ``cryptography`` dependency (``pip install agw-verifier[disclosure]``); the
core verifier stays stdlib-only. Without it, or without the auditor key, the payload is not
checked and the result is at best INCOMPLETE (PAYLOAD_NOT_CHECKED): VERIFIED needs all checks.
"""

from __future__ import annotations

import copy
import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

from agw_verifier.cbor import NonCanonical, dumps, loads

DISCLOSURE_FORMAT = "agw-disclosure/v1"
SUITE = "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM"
# Payload states that mean "the evidence system no longer has / cannot produce it".
UNAVAILABLE = frozenset({"DELETED", "BLOB_MISSING", "KEY_MISSING"})
TAMPERED_STATES = frozenset({"DECRYPT_FAILED", "BLOB_CORRUPT"})


def _tag(s: str) -> bytes:
    raw = s.encode()
    return bytes([len(raw)]) + raw


PAYLOAD_AAD = _tag("AGW/payload-aad/v1")
DISCLOSURE_INFO = _tag("AGW/disclosure/v1")


class DisclosureProblem(Exception):
    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import hpke  # noqa: PLC0415 - optional dependency
        from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: PLC0415
        from cryptography.hazmat.primitives.ciphers import aead  # noqa: PLC0415
    except ImportError:  # pragma: no cover - exercised by the isolated-venv check
        raise DisclosureProblem(
            "INCOMPLETE", "DECRYPTION_UNAVAILABLE: install agw-verifier[disclosure]"
        ) from None
    return hpke, x25519, aead


def read_private_key(path: str) -> bytes:
    raw = Path(path).read_text(encoding="ascii").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = b""
    if len(key) != 32:
        raise ValueError("auditor key file must hold a 32-byte X25519 private key (hex)")
    return key


def keygen(out: str) -> tuple[str, str]:
    """Create an X25519 key pair; private key -> ``out`` (0600, never overwritten).
    Returns (public key hex, key id)."""
    _, x25519, _ = _crypto()
    sk = x25519.X25519PrivateKey.generate()
    raw = sk.private_bytes_raw()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(raw.hex() + "\n")
    pub = sk.public_key().public_bytes_raw()
    return pub.hex(), key_id(pub)


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:32]


def open_bundle(bundle: Any, private_key: bytes | None) -> tuple[dict[str, Any], str | None]:
    """Returns (bundle with event.payload filled in when the payload could be opened, note).
    Raises DisclosureProblem(result, reason) for TAMPERED / INCOMPLETE outcomes."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("disclosure"), dict):
        return bundle, None
    d = bundle["disclosure"]
    if d.get("format") != DISCLOSURE_FORMAT:
        raise DisclosureProblem("INCOMPLETE", "BAD_DISCLOSURE_SECTION")
    status = d.get("payload_status")
    if status in UNAVAILABLE:
        raise DisclosureProblem("INCOMPLETE", f"PAYLOAD_UNAVAILABLE:{status}")
    if status in TAMPERED_STATES:
        raise DisclosureProblem("TAMPERED", f"PAYLOAD_{status}")
    if status == "NONE":
        return bundle, "event has no payload"
    out = copy.deepcopy(bundle)
    if d.get("mode") == "plaintext":
        out["event"]["payload"] = d.get("payload", "")
        return out, "payload delivered in plaintext (transport-protected only)"
    if d.get("mode") != "hpke" or d.get("suite") != SUITE:
        raise DisclosureProblem("INCOMPLETE", "UNSUPPORTED_DISCLOSURE_MODE")
    if private_key is None:
        raise DisclosureProblem("INCOMPLETE", "PAYLOAD_NOT_CHECKED: no --auditor-key given")
    hpke, x25519, aead = _crypto()
    try:
        header = loads(bytes.fromhex(bundle["event"]["header"]))
        tenant, event_id, seq = header["tenant"], header["id"], header["seq"]
        digest = header["payload"]["digest"]
        grant = uuid.UUID(str(d["grant_id"])).bytes
        nonce, ct = bytes.fromhex(d["nonce"]), bytes.fromhex(d["ciphertext"])
        sealed = bytes.fromhex(d["sealed_dek"])
        version = int(d["schema_version"])
    except (KeyError, TypeError, ValueError, NonCanonical):
        raise DisclosureProblem("INCOMPLETE", "BAD_DISCLOSURE_SECTION") from None
    sk = x25519.X25519PrivateKey.from_private_bytes(private_key)
    mine = key_id(sk.public_key().public_bytes_raw())
    if d.get("recipient_key_id") != mine:
        raise DisclosureProblem("INCOMPLETE", "NOT_THE_RECIPIENT_KEY")
    info = DISCLOSURE_INFO + dumps(
        {"tenant": tenant, "grant_id": grant, "event_id": event_id, "recipient_key_id": mine}
    )
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
    try:
        dek = suite.decrypt(sealed, sk, info=info)
    except Exception:  # any failure: not sealed to this event/grant/key
        raise DisclosureProblem("TAMPERED", "SEALED_DEK_DOES_NOT_OPEN") from None
    aad = PAYLOAD_AAD + dumps(
        {
            "tenant": tenant,
            "event_id": event_id,
            "seq": seq,
            "payload_digest": digest,
            "schema_version": version,
        }
    )
    try:
        payload = aead.AESGCM(dek).decrypt(nonce, ct, aad)
    except Exception:  # InvalidTag: swapped / altered ciphertext
        raise DisclosureProblem("TAMPERED", "PAYLOAD_DECRYPT_FAILED") from None
    out["event"]["payload"] = payload.hex()
    return out, "payload decrypted with the auditor key"
