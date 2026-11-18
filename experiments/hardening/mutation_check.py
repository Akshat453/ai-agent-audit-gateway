"""Phase 10 mutation check (ADR-0032 §3): remove one rate-limit / body-size guard, run the
test named for it, expect it to FAIL, restore the file. Proves each limit test can fail.

    uv run python experiments/hardening/mutation_check.py      (from the repo root)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

LIM, APP = (
    Path("apps/gateway/src/agw_gateway/api/limits.py"),
    Path("apps/gateway/src/agw_gateway/api/app.py"),
)
BLOBS = Path("apps/gateway/src/agw_gateway/evidence/blobs.py")
U, E = "apps/gateway/tests/unit/test_limits.py", "apps/gateway/tests/e2e/test_limits_e2e.py"

MUTATIONS: list[tuple[str, Path, str, str, str]] = [
    ("429 when the bucket is empty", LIM, "        if wait > 0:", "        if False:",
     f"{U}::test_rate_limit_burst_then_429_then_refill"),
    ("bucket keyed per credential", LIM, 'return b"c:" + hashlib.sha256(value).digest()',
     'return b"c:"', f"{U}::test_rate_limit_is_per_credential_and_exempts_health"),
    ("bucket table bounded (LRU)", LIM, "while len(self.buckets) > MAX_BUCKETS:", "while False:",
     f"{U}::test_rate_limit_does_not_store_credentials_and_is_bounded"),
    ("declared Content-Length over the limit -> 413", LIM,
     "if not declared.isdigit() or int(declared) > self.max_bytes:", "if not declared.isdigit():",
     f"{U}::test_body_limit_declared_length"),
    ("chunked body over the limit -> 413", LIM, "            if size > self.max_bytes:",
     "            if False:", f"{U}::test_body_limit_chunked_without_length"),
    ("body limit installed on the app", APP,
     "    app.add_middleware(BodySizeLimit, max_bytes=state.settings.max_body_bytes)\n", "",
     f"{E}::test_body_limit_on_every_endpoint"),
    ("object store client has bounded timeouts", BLOBS,
     "secure=secure,\n                        http_client=http)", "secure=secure)",
     f"{U}::test_object_store_call_is_bounded_when_the_server_hangs"),
    ("rate limit installed on the app", APP,
     "    app.add_middleware(\n        RateLimit,", "    (\n        RateLimit,",
     f"{E}::test_rate_limit_on_real_app"),
]  # fmt: skip

caught, lines = 0, []
for name, path, old, new, test in MUTATIONS:
    src = path.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    path.write_text(src.replace(old, new))
    try:
        r = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],  # noqa: S607
            capture_output=True, text=True, check=False, timeout=180,
        )  # fmt: skip
        ok = r.returncode != 0
    except subprocess.TimeoutExpired:
        ok = True  # the guarded call hung: the test did not pass
    finally:
        path.write_text(src)
    caught += ok
    line = f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<48} {test.split('::')[1]}"
    print(line, flush=True)
    lines.append(line)
summary = f"{caught}/{len(MUTATIONS)} mutations caught"
print(summary)
out = Path("experiments/hardening/results")
out.mkdir(parents=True, exist_ok=True)
(out / "mutations.txt").write_text("\n".join([*lines, summary]) + "\n")
sys.exit(0 if caught == len(MUTATIONS) else 1)
