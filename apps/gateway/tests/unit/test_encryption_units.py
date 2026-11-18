"""Phase 7 pure pieces (ADR-0029): payload AAD binding, AES-GCM envelopes, KEK providers,
sealed operational data, HPKE disclosure binding, redaction markers, classification, and the
gateway/verifier agreement on every AAD byte."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from agw_gateway.crypto import envelope as env
from agw_gateway.keys import KeyUnavailable, LocalKeyProvider, UnwrapFailed
from agw_gateway.privacy.cipher import EnvelopeCipher, SealedDataError, ops_context
from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.tools.spec import ToolSpec, ToolSpecError
from agw_verifier import disclosure as vdisc
from agw_verifier.cbor import dumps as vdumps

from ..conftest import ECHO_NONIDEMPOTENT, EchoArgs

pytestmark = pytest.mark.unit

E1, E2 = bytes(range(16)), bytes(range(1, 17))
D1, D2 = b"\x11" * 32, b"\x22" * 32


def _keyring(tmp_path: Path) -> LocalKeyProvider:
    LocalKeyProvider.generate(tmp_path, "unit")
    return LocalKeyProvider.from_dir(tmp_path, "unit")


# --------------------------------------------------------------------------- payload AEAD
def test_payload_ciphertext_is_bound_to_its_event() -> None:
    aad1 = env.payload_aad("acme", E1, 7, D1, 1)
    dek = env.new_dek()
    nonce, ct = env.encrypt_payload(dek, b"payload-one", aad1)
    assert env.decrypt_payload(dek, nonce, ct, aad1) == b"payload-one"
    for other in (
        env.payload_aad("acme", E2, 7, D1, 1),  # another event
        env.payload_aad("acme", E1, 8, D1, 1),  # another position
        env.payload_aad("acme", E1, 7, D2, 1),  # another committed digest
        env.payload_aad("acmf", E1, 7, D1, 1),  # another tenant
        env.payload_aad("acme", E1, 7, D1, 2),  # another schema version
    ):
        with pytest.raises(InvalidTag):
            env.decrypt_payload(dek, nonce, ct, other)
    with pytest.raises(InvalidTag):
        env.decrypt_payload(env.new_dek(), nonce, ct, aad1)  # another DEK


def test_nonce_and_dek_are_fresh() -> None:
    aad = env.payload_aad("acme", E1, 0, D1, 1)
    a = env.encrypt_payload(env.new_dek(), b"x", aad)
    b = env.encrypt_payload(env.new_dek(), b"x", aad)
    assert a[0] != b[0] and a[1] != b[1] and len(a[0]) == 12


def test_gateway_and_verifier_agree_on_aad_bytes() -> None:
    """The standalone verifier re-implements the AAD with its own CBOR encoder."""
    gw = env.payload_aad("acme", E1, 42, D1, 1)
    vf = vdisc.PAYLOAD_AAD + vdumps(
        {"tenant": "acme", "event_id": E1, "seq": 42, "payload_digest": D1, "schema_version": 1}
    )
    assert gw == vf
    grant = os.urandom(16)
    gi = env.disclosure_info("acme", grant, E1, "ab" * 16)
    vi = vdisc.DISCLOSURE_INFO + vdumps(
        {"tenant": "acme", "grant_id": grant, "event_id": E1, "recipient_key_id": "ab" * 16}
    )
    assert gi == vi


# --------------------------------------------------------------------------- HPKE
def test_hpke_sealed_dek_only_opens_for_its_event_grant_and_recipient() -> None:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sk = X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    priv = sk.private_bytes_raw()
    kid = env.recipient_key_id(pub)
    info = env.disclosure_info("acme", b"g" * 16, E1, kid)
    sealed = env.seal_to_recipient(D1, pub, info)
    assert env.open_from_sender(sealed, priv, info) == D1
    for wrong in (
        env.disclosure_info("acme", b"g" * 16, E2, kid),  # another event
        env.disclosure_info("acme", b"h" * 16, E1, kid),  # another grant
        env.disclosure_info("acmf", b"g" * 16, E1, kid),  # another tenant
    ):
        with pytest.raises(Exception):
            env.open_from_sender(sealed, priv, wrong)
    other = X25519PrivateKey.generate().private_bytes_raw()
    with pytest.raises(Exception):
        env.open_from_sender(sealed, other, info)
    assert len(kid) == 32 and kid == vdisc.key_id(pub)


# --------------------------------------------------------------------------- KEK providers
def test_local_provider_wrap_unwrap_and_context_binding(tmp_path: Path) -> None:
    p = _keyring(tmp_path)
    dek = env.new_dek()
    w = p.wrap(dek, b"ctx-1")
    assert (w.kek_id, w.kek_version) == ("unit", 1) and dek not in w.ciphertext
    assert p.unwrap(w, b"ctx-1") == dek
    with pytest.raises(UnwrapFailed):
        p.unwrap(w, b"ctx-2")  # a wrapped DEK cannot be moved to another event/tenant
    assert "unit" in repr(p) and dek.hex() not in repr(p)


def test_local_provider_refuses_insecure_or_in_repo_keys(tmp_path: Path) -> None:
    LocalKeyProvider.generate(tmp_path, "unit")
    key = tmp_path / "unit.v1.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    key.chmod(0o644)
    with pytest.raises(KeyUnavailable, match="0600"):
        LocalKeyProvider.from_dir(tmp_path, "unit")
    key.chmod(0o600)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "keys").mkdir()
    LocalKeyProvider.generate(repo / "keys", "unit")
    with pytest.raises(KeyUnavailable, match="git"):
        LocalKeyProvider.from_dir(repo / "keys", "unit")
    with pytest.raises(KeyUnavailable):
        LocalKeyProvider.from_dir(tmp_path / "missing", "unit")
    (tmp_path / "bad.v1.key").write_text("zz")
    (tmp_path / "bad.v1.key").chmod(0o600)
    with pytest.raises(KeyUnavailable, match="32-byte"):
        LocalKeyProvider.from_dir(tmp_path, "bad")


def test_rotation_keeps_old_versions_usable(tmp_path: Path) -> None:
    p1 = _keyring(tmp_path)
    old = p1.wrap(b"k" * 32, b"c")
    assert LocalKeyProvider.generate(tmp_path, "unit") == 2
    p2 = LocalKeyProvider.from_dir(tmp_path, "unit")
    assert p2.active_version == 2 and p2.versions == [1, 2]
    assert p2.unwrap(old, b"c") == b"k" * 32
    assert p2.wrap(b"k" * 32, b"c").kek_version == 2
    (tmp_path / "unit.v1.key").unlink()  # destroy the old KEK
    p3 = LocalKeyProvider.from_dir(tmp_path, "unit")
    with pytest.raises(KeyUnavailable):
        p3.unwrap(old, b"c")


# --------------------------------------------------------------------------- sealed ops data
def test_sealed_ops_envelope_binds_context(tmp_path: Path) -> None:
    c = EnvelopeCipher(_keyring(tmp_path))
    ctx = ops_context("acme", "dispatch_args", E1)
    sealed = c.seal_json(ctx, {"api_token": "tok-123"})
    assert b"tok-123" not in sealed
    assert c.open_json(ctx, sealed) == {"api_token": "tok-123"}
    for wrong in (
        ops_context("acme", "dispatch_args", E2),
        ops_context("acme", "request_args", E1),
        ops_context("acmf", "dispatch_args", E1),
    ):
        with pytest.raises(SealedDataError):
            c.open_json(wrong, sealed)
    with pytest.raises(SealedDataError):
        c.open_json(ctx, sealed[:-1] + bytes([sealed[-1] ^ 1]))


# --------------------------------------------------------------------------- redaction
def test_redaction_marker_is_salted_and_stable() -> None:
    m1 = env.redaction_marker(D1, b"hunter2")
    assert m1 == env.redaction_marker(D1, b"hunter2")  # correlatable within a tenant
    assert m1 != env.redaction_marker(D2, b"hunter2")  # not across tenants (salt)
    assert m1.startswith("[REDACTED:sha256:") and "hunter2" not in m1
    with pytest.raises(ValueError):
        env.redaction_marker(b"short", b"x")


# --------------------------------------------------------------------------- classification
def test_field_classes_defaults_and_validation() -> None:
    fc = FieldClasses(args={"text": "internal"})
    assert fc.arg("text") == "internal" and fc.arg("unlisted") == "confidential"
    assert fc.result("anything") == "confidential"
    assert fc.payload_class() == "confidential"  # unlisted results default to confidential
    assert FieldClasses(args={"a": "public"}, results={"r": "internal"}).payload_class() == (
        "internal"
    )
    assert FieldClasses(args={"a": "secret"}, results={"r": "public"}).payload_class() == "public"
    with pytest.raises(ToolSpecError, match="not in the args model"):
        ToolSpec(ECHO_NONIDEMPOTENT, EchoArgs, object(), FieldClasses(args={"nope": "secret"}))  # type: ignore[arg-type]
    with pytest.raises(ToolSpecError, match="unknown classification"):
        ToolSpec(ECHO_NONIDEMPOTENT, EchoArgs, object(), FieldClasses(args={"text": "top"}))  # type: ignore[arg-type,dict-item]


def test_verifier_core_has_no_crypto_import() -> None:
    """The stdlib-only verifier imports cryptography lazily, only to open disclosures."""
    code = (
        "import sys, agw_verifier.cli, agw_verifier.epochs, agw_verifier.anchor; "
        "assert 'cryptography' not in sys.modules, 'eager import'"
    )
    subprocess.run(["python", "-c", code], check=True)
