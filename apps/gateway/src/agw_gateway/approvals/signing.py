"""Gateway-held Ed25519 key for approval decisions (Phase 5, ADR-0027).

What a signature proves: the GATEWAY attested that an approver, authenticated by the gateway's
session mechanism, made this decision about this exact action digest and nonce. It does NOT
prove that a human held a private key: the key lives with the gateway. Per-approver
WebAuthn/passkey signatures are the stronger future option (ADR-0027).

The key file holds the 32-byte raw private seed, hex-encoded on one line (dev). It is never
logged; ``key_id`` = first 16 hex chars of SHA-256(raw public key).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agw_gateway.approvals.binding import signing_message


class SigningKeyUnavailable(RuntimeError):
    """No usable signing key: decisions cannot be recorded (fail closed)."""


def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


@dataclass(frozen=True)
class DecisionSigner:
    _private: Ed25519PrivateKey
    public_raw: bytes
    key_id: str

    def __repr__(self) -> str:
        return f"DecisionSigner(key_id={self.key_id!r})"

    @classmethod
    def from_seed(cls, seed: bytes) -> DecisionSigner:
        if len(seed) != 32:
            raise SigningKeyUnavailable("signing key must be 32 bytes")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(private, public_raw, key_id_for(public_raw))

    @classmethod
    def from_file(cls, path: Path) -> DecisionSigner:
        try:
            seed = bytes.fromhex(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError, UnicodeDecodeError):
            raise SigningKeyUnavailable("signing key file unreadable") from None
        return cls.from_seed(seed)

    def sign(self, decision_digest: bytes) -> bytes:
        return self._private.sign(signing_message(decision_digest))


def verify_decision(public_raw: bytes, decision_digest: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, signing_message(decision_digest)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def generate_key_file(path: Path) -> str:
    """Write a fresh dev key (mode 0600). Returns the key id. Refuses to overwrite."""
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(seed.hex() + "\n")
    return DecisionSigner.from_seed(seed).key_id
