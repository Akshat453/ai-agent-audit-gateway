"""KEK providers (Phase 7, ADR-0029; 07 §2). A KEK only ever wraps DEKs; it never touches a
payload. Implementations:

* ``LocalKeyProvider``: dev keyring directory OUTSIDE any git checkout, one file per version
  (``<kek_id>.v<N>.key``, 32 random bytes as hex, mode 0600). AES-256-GCM wrap with
  aad = TAG("AGW/dek-wrap-aad/v1") || cbor({context, kek_id}); ``context`` is the caller's
  binding (tenant + event id, or tenant + purpose for redaction/ops keys).
* ``VaultTransitKeyProvider``: HashiCorp Vault Transit (aes256-gcm96), the same AAD passed as
  ``associated_data``; the KEK never leaves Vault. Rotation is ``transit/keys/<k>/rotate``.
  (An AWS KMS adapter fits the same interface: Encrypt/Decrypt with EncryptionContext; not
  shipped.)

Every old version stays usable for unwrap, so rotation never breaks existing ciphertexts;
``privacy/rotation.py`` re-wraps DEKs to the active version. Any provider failure raises
``KeyUnavailable`` and callers fail closed (no event with a payload is written: 503).
"""

from __future__ import annotations

import base64
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agw_gateway.crypto.canonical import encode
from agw_gateway.crypto.tags import DEK_WRAP_TAG, domain_tag

_WRAP: Final = domain_tag(DEK_WRAP_TAG)
_KEY_FILE = re.compile(r"^(?P<id>[A-Za-z0-9][A-Za-z0-9_.-]{0,62})\.v(?P<v>[1-9][0-9]{0,5})\.key$")


class KeyUnavailable(Exception):
    """The KEK cannot be used right now (missing, unreadable, insecure, unreachable)."""


class UnwrapFailed(Exception):
    """A wrapped key does not authenticate under its KEK and context (tampered, swapped or
    bound to another event/tenant). Permanent; never retried."""


@dataclass(frozen=True)
class WrappedKey:
    kek_id: str
    kek_version: int
    nonce: bytes  # empty for Vault (the nonce is inside Vault's ciphertext)
    ciphertext: bytes


class KeyProvider(Protocol):
    kek_id: str

    @property
    def active_version(self) -> int: ...

    def wrap(self, key: bytes, context: bytes) -> WrappedKey: ...

    def unwrap(self, wrapped: WrappedKey, context: bytes) -> bytes: ...


def wrap_aad(context: bytes, kek_id: str) -> bytes:
    return _WRAP + encode({"context": context, "kek_id": kek_id})


def inside_git_checkout(path: Path) -> bool:
    return any((p / ".git").exists() for p in [path, *path.parents])


class LocalKeyProvider:
    def __init__(self, keys: dict[int, bytes], kek_id: str, active: int | None = None) -> None:
        if not keys:
            raise KeyUnavailable("no KEK versions")
        self.kek_id = kek_id
        self._keys = dict(keys)
        self._active = active if active is not None else max(keys)
        if self._active not in self._keys:
            raise KeyUnavailable("active KEK version missing")

    def __repr__(self) -> str:  # never show key material
        return f"LocalKeyProvider(kek_id={self.kek_id!r}, versions={sorted(self._keys)})"

    @classmethod
    def from_dir(
        cls, directory: Path, kek_id: str, active: int | None = None, *, allow_in_repo: bool = False
    ) -> LocalKeyProvider:
        d = directory.expanduser().resolve()
        if not d.is_dir():
            raise KeyUnavailable("KEK directory missing")
        if not allow_in_repo and inside_git_checkout(d):
            raise KeyUnavailable("KEK directory is inside a git checkout; keep keys outside")
        keys: dict[int, bytes] = {}
        for f in d.iterdir():
            m = _KEY_FILE.match(f.name)
            if not m or m["id"] != kek_id:
                continue
            if f.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise KeyUnavailable(f"{f.name} is group/world accessible (need 0600)")
            try:
                raw = bytes.fromhex(f.read_text(encoding="ascii").strip())
            except (ValueError, UnicodeDecodeError):
                raw = b""
            if len(raw) != 32:
                raise KeyUnavailable(f"{f.name} is not a 32-byte hex key")
            keys[int(m["v"])] = raw
        return cls(keys, kek_id, active)

    @staticmethod
    def generate(directory: Path, kek_id: str) -> int:
        """Create the next version file (0600, O_EXCL). Returns the new version number."""
        d = directory.expanduser()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        existing = [
            int(m["v"]) for f in d.iterdir() if (m := _KEY_FILE.match(f.name)) and m["id"] == kek_id
        ]
        version = max(existing, default=0) + 1
        path = d / f"{kek_id}.v{version}.key"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(os.urandom(32).hex() + "\n")
        return version

    @property
    def active_version(self) -> int:
        return self._active

    @property
    def versions(self) -> list[int]:
        return sorted(self._keys)

    def wrap(self, key: bytes, context: bytes) -> WrappedKey:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self._active]).encrypt(nonce, key, wrap_aad(context, self.kek_id))
        return WrappedKey(self.kek_id, self._active, nonce, ct)

    def unwrap(self, wrapped: WrappedKey, context: bytes) -> bytes:
        if wrapped.kek_id != self.kek_id or wrapped.kek_version not in self._keys:
            raise KeyUnavailable("KEK version not available")
        try:
            return AESGCM(self._keys[wrapped.kek_version]).decrypt(
                wrapped.nonce, wrapped.ciphertext, wrap_aad(context, self.kek_id)
            )
        except InvalidTag:
            raise UnwrapFailed("wrapped key does not authenticate") from None


class _VaultRejected(Exception):
    pass


class VaultTransitKeyProvider:
    """Vault Transit. ``token`` is held in memory only and never logged."""

    def __init__(self, addr: str, token: str, key_name: str, timeout: float = 5.0) -> None:
        self.kek_id = f"vault-transit:{key_name}"
        self._key = key_name
        self._http = httpx.Client(
            base_url=addr.rstrip("/"), timeout=timeout, headers={"X-Vault-Token": token}
        )

    def __repr__(self) -> str:
        return f"VaultTransitKeyProvider(kek_id={self.kek_id!r})"

    def _post(self, path: str, body: dict[str, str]) -> dict[str, object]:
        try:
            r = self._http.post(f"/v1/transit/{path}", json=body)
        except httpx.HTTPError:
            raise KeyUnavailable("vault unreachable") from None
        if r.status_code == 400 and path.startswith("decrypt/"):
            raise _VaultRejected
        if r.status_code >= 400:
            raise KeyUnavailable(f"vault refused ({r.status_code})")
        data = r.json().get("data") or {}
        return data if isinstance(data, dict) else {}

    @property
    def active_version(self) -> int:
        try:
            r = self._http.get(f"/v1/transit/keys/{self._key}")
        except httpx.HTTPError:
            raise KeyUnavailable("vault unreachable") from None
        if r.status_code >= 400:
            raise KeyUnavailable(f"vault refused ({r.status_code})")
        return int(r.json()["data"]["latest_version"])

    def wrap(self, key: bytes, context: bytes) -> WrappedKey:
        data = self._post(
            f"encrypt/{self._key}",
            {
                "plaintext": base64.b64encode(key).decode(),
                "associated_data": base64.b64encode(wrap_aad(context, self.kek_id)).decode(),
            },
        )
        ct = str(data.get("ciphertext", ""))
        m = re.match(r"^vault:v(\d+):", ct)
        if not m:
            raise KeyUnavailable("unexpected vault ciphertext")
        return WrappedKey(self.kek_id, int(m[1]), b"", ct.encode())

    def unwrap(self, wrapped: WrappedKey, context: bytes) -> bytes:
        if wrapped.kek_id != self.kek_id:
            raise KeyUnavailable("wrapped under another KEK")
        try:
            data = self._decrypt(wrapped, context)
        except _VaultRejected:
            # 400: the ciphertext/AAD does not authenticate (tampered or other context).
            raise UnwrapFailed("wrapped key does not authenticate") from None
        try:
            return base64.b64decode(str(data["plaintext"]))
        except (KeyError, ValueError):
            raise KeyUnavailable("unexpected vault response") from None

    def _decrypt(self, wrapped: WrappedKey, context: bytes) -> dict[str, object]:
        return self._post(
            f"decrypt/{self._key}",
            {
                "ciphertext": wrapped.ciphertext.decode(),
                "associated_data": base64.b64encode(wrap_aad(context, self.kek_id)).decode(),
            },
        )

    def rotate(self) -> int:
        self._post(f"keys/{self._key}/rotate", {})
        return self.active_version
