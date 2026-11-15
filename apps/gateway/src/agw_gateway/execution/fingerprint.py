"""Idempotency request fingerprint (08 §5).

``H(TAG("AGW/request/v1") || sorted-key compact JSON(normalized_request))``. Phase 1 uses JSON
(allowed by 08 §5); ``fingerprint_alg`` is stored so Phase 2 can switch to CBOR. Args are taken
as received (pre-validation) so invalid requests also get a stable fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from agw_gateway.crypto.tags import REQUEST_TAG, domain_tag

FINGERPRINT_ALG: Final = "sha256-tag-json-sorted-v0"
_PREFIX: Final = domain_tag(REQUEST_TAG)


def request_fingerprint(
    *, tool: str, tool_version: str | None, environment: str, run_id: str, args: Any
) -> bytes:
    normalized = {
        "tool": tool,
        "tool_version": tool_version,
        "environment": environment,
        "run_id": run_id,
        "args": args,
    }
    encoded = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(_PREFIX + encoded).digest()
