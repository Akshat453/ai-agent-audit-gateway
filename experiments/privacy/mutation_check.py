"""Phase 7 mutation check (ADR-0029): remove one encryption / minimization / disclosure /
retention guard, run the test named for it, expect that test to FAIL, restore the file.

    uv run python experiments/privacy/mutation_check.py      (from the repo root)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

G = Path("apps/gateway/src/agw_gateway")
ENVELOPE, PROVIDER = G / "crypto/envelope.py", G / "keys/provider.py"
MINIMIZE, CIPHER = G / "privacy/minimize.py", G / "privacy/cipher.py"
DISCLOSURE, RETENTION = G / "privacy/disclosure.py", G / "privacy/retention.py"
MIGRATE, PAYLOADS = G / "privacy/migrate.py", G / "evidence/payloads.py"
EXECUTOR, ERRORS = G / "execution/executor.py", G / "api/errors.py"
M0008 = Path("apps/gateway/migrations/versions/0008_phase7_drop_plaintext.py")
VDISC = Path("packages/verifier/src/agw_verifier/disclosure.py")
T = "apps/gateway/tests"
ENC, DIS = f"{T}/e2e/test_encryption.py", f"{T}/e2e/test_disclosure.py"
CAN, UNIT = f"{T}/e2e/test_telemetry_canary.py", f"{T}/unit/test_encryption_units.py"
MIG, FR = f"{T}/e2e/test_payload_migration.py", f"{T}/e2e/test_flight_recorder.py"

M: list[tuple[str, Path, str, str, str]] = [
    ("payload AAD binds event/seq/digest", ENVELOPE,
     '            "event_id": event_id,\n            "seq": seq,\n'
     '            "payload_digest": digest,\n', "",
     f"{ENC}::test_ciphertext_swap_between_events_fails"),
    ("DEK wrap bound to its event", PROVIDER,
     'return _WRAP + encode({"context": context, "kek_id": kek_id})',
     'return _WRAP + encode({"kek_id": kek_id})',
     f"{UNIT}::test_local_provider_wrap_unwrap_and_context_binding"),
    ("KEK file must be 0600", PROVIDER,
     "if f.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):", "if False:",
     f"{UNIT}::test_local_provider_refuses_insecure_or_in_repo_keys"),
    ("no KEK -> fail closed", PAYLOADS,
     '        raise KeyUnavailable("no KEK configured: payloads cannot be encrypted")',
     "        return None", f"{ENC}::test_no_kek_fails_closed"),
    ("secret args redacted", MINIMIZE,
     'if classes.arg(k) == "secret" else v)', "if False else v)",
     f"{ENC}::test_secret_fields_are_never_stored"),
    ("secret results redacted", MINIMIZE,
     'if classes.result(k) == "secret" else v)', "if False else v)",
     f"{ENC}::test_secret_fields_are_never_stored"),
    ("plaintext results only public/internal", MINIMIZE,
     " if classes.result(k) in PLAINTEXT_OK}", "}",
     f"{ENC}::test_secret_fields_are_never_stored"),
    ("unvalidated args not stored", MINIMIZE,
     '"digest": self.marker(conn, tenant, raw)}}',
     '"digest": self.marker(conn, tenant, raw)}, "raw": str(raw)}',
     f"{FR}::test_invalid_args_are_not_stored_only_keys_and_salted_digest"),
    ("operational args sealed", CIPHER,
     "nonce, ct = encrypt_payload(dek, plaintext, _TAG + ctx)",
     "nonce, ct = bytes(12), plaintext",
     f"{ENC}::test_db_only_attacker_cannot_read_payloads"),
    ("grant expiry enforced", DISCLOSURE,
     "if g.expires_at <= datetime.now(UTC):", "if False:",
     f"{DIS}::test_expired_grant_is_403_and_evidenced"),
    ("only granted events exportable", DISCLOSURE,
     "if not wanted or not set(wanted) <= set(granted):", "if not wanted:",
     f"{DIS}::test_grant_for_x_cannot_open_y_in_the_same_epoch"),
    ("only the grantee exports", DISCLOSURE,
     "if g.auditor_id != auditor.human_id:", "if False:",
     f"{DIS}::test_grant_roles_separation_and_revocation"),
    ("denied access is evidence", DISCLOSURE,
     'self._record_access(g, auditor, wanted, "DENIED", denial)', "pass",
     f"{DIS}::test_expired_grant_is_403_and_evidenced"),
    ("verifier rejects a swapped ciphertext", VDISC,
     'raise DisclosureProblem("TAMPERED", "PAYLOAD_DECRYPT_FAILED") from None',
     "return bundle, None",
     f"{DIS}::test_grant_for_x_cannot_open_y_in_the_same_epoch"),
    ("legal hold blocks deletion", RETENTION,
     "if self._held(conn, tenant_id, event_id, ev.action_id, ev.run_id):", "if False:",
     f"{ENC}::test_retention_deletes_payload_header_and_chain_still_verify"),
    ("deletion is evidence (PAYLOAD_DELETED)", RETENTION,
     "self._writer.append(", "(lambda *a: None)(",
     f"{ENC}::test_retention_deletes_payload_header_and_chain_still_verify"),
    ("0008 refuses while plaintext remains", M0008, "    if remaining:", "    if False:",
     f"{MIG}::test_reencrypt_phase2_plaintext_then_drop_it"),
    ("migration checks digests", MIGRATE,
     "if not _matches_header(bytes(r.canonical_bytes), plaintext):", "if False:",
     f"{MIG}::test_reencrypt_phase2_plaintext_then_drop_it"),
    ("adapter errors logged by type only", EXECUTOR,
     "error_code=type(exc).__name__,", "error_code=str(exc),",
     f"{CAN}::test_canary_never_leaks"),
    ("validation errors name fields only", ERRORS,
     'fields = sorted({".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()})',
     'fields = sorted({str(e.get("input")) for e in exc.errors()})',
     f"{CAN}::test_canary_never_leaks"),
]  # fmt: skip

caught = 0
for name, path, old, new, test in M:
    src = path.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    path.write_text(src.replace(old, new))
    try:
        r = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        path.write_text(src)
    ok = r.returncode != 0
    caught += ok
    print(f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<42} {test.split('::')[1]}")
print(f"{caught}/{len(M)} mutations caught")
sys.exit(0 if caught == len(M) else 1)
