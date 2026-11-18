"""Shared by the RQ5 parent (recovery + checks) and the victim subprocess."""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any

from experiments.lib import stack  # noqa: F401  (puts apps/gateway on sys.path)

LEASE = 2.0
ADAPTER_TIMEOUT = 1.0
TOOLS = {"create_ticket": False, "public_doc_search": True}  # name -> idempotent


def logged_spies(log: Path) -> Any:
    """Spies whose create_ticket / public_doc_search append "<tool> <action_id>" to `log`
    after the real adapter returned: the external side-effect record, shared by processes."""
    from tests.conftest import make_spies

    spies = make_spies()
    for spy, name in ((spies.ticket, "create_ticket"), (spies.search, "public_doc_search")):
        inner = spy.inner

        def behavior(args: Any, ctx: Any, _inner: Any = inner, _name: str = name) -> Any:
            result = _inner.execute(args, ctx)
            with log.open("a") as fh:
                fh.write(f"{_name} {ctx.action_id}\n")
                fh.flush()
                os.fsync(fh.fileno())
            return result

        spy.behavior = behavior
    return spies


def effects(log: Path, action_id: str) -> int:
    if not log.exists():
        return 0
    return sum(1 for ln in log.read_text().splitlines() if ln.endswith(action_id))


def verify(gw: Any) -> tuple[str, str]:
    """(chain result, epochs result) of the independent verifier over a fresh export."""
    from agw_gateway.evidence.bundle import export_epochs
    from agw_gateway.evidence.export import export_chain
    from agw_verifier.chain import verify_lines
    from agw_verifier.epochs import verify_epochs

    ev, ep = io.StringIO(), io.StringIO()
    export_chain(gw.engine, gw.tenant, ev, store=gw.state.payloads)
    with gw.engine.connect() as conn:
        export_epochs(conn, gw.tenant, ep)
    chain = verify_lines(ev.getvalue().splitlines())
    epochs = verify_epochs(ep.getvalue().splitlines(), event_lines=ev.getvalue().splitlines())
    return chain.result, epochs.result
