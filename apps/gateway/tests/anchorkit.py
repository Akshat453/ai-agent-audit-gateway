"""Helpers for the Phase 6 anchoring tests (ADR-0028): a real Anvil node (pinned Foundry image),
the committed EpochAnchor artifact, an RPC proxy that can be killed mid-request, and the
verifier CLI driven in-process."""

from __future__ import annotations

import contextlib
import io
import json
import secrets
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from eth_account import Account
from sqlalchemy import Engine, select
from web3 import HTTPProvider, Web3

from agw_gateway.anchoring import AnchorGate, Finality, recorder_id
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.bundle import build_bundle, export_epochs
from agw_verifier import cli as verify_cli
from agw_worker.anchoring import Anchorer, AnchorerConfig
from agw_worker.anchoring.evm import EvmAnchorBackend, deploy, register_recorder
from agw_worker.sealing import Sealer

REPO = Path(__file__).resolve().parents[3]
FOUNDRY_IMAGE = "ghcr.io/foundry-rs/foundry:v1.3.5"
ARTIFACT: dict[str, Any] = json.loads(
    (REPO / "contracts/artifacts/EpochAnchor.json").read_text(encoding="utf-8")
)
SALT = bytes.fromhex("5a" * 32)  # test-only deployment salt
ZERO_ADDR = "0x" + "00" * 20


# --------------------------------------------------------------------------- chain
@dataclass
class Chain:
    rpc: str
    w3: Web3
    chain_id: int
    contract: str
    owner_key: str
    container: Any = None

    def rpc_call(self, method: str, params: list[Any]) -> Any:
        return self.w3.provider.make_request(method, params)  # type: ignore[arg-type]

    def fund(self, address: str) -> None:
        self.rpc_call("anvil_setBalance", [address, hex(10**20)])

    def mine(self, n: int = 1) -> None:
        self.rpc_call("anvil_mine", [hex(n)])

    def snapshot(self) -> str:
        return str(self.rpc_call("evm_snapshot", [])["result"])

    def revert(self, snap: str) -> None:
        assert self.rpc_call("evm_revert", [snap])["result"] is True

    def anchored_logs(self, rid: bytes, epoch_no: int) -> int:
        """How many Anchored events exist for (recorder, epoch): must never exceed 1."""
        topic0 = Web3.keccak(text="Anchored(bytes32,uint64,bytes32,uint64,uint64)")
        logs = self.w3.eth.get_logs(
            {
                "fromBlock": 0,
                "toBlock": "latest",
                "address": Web3.to_checksum_address(self.contract),
                "topics": [topic0, rid, epoch_no.to_bytes(32, "big")],  # type: ignore[list-item]
            }
        )
        return len(logs)


def start_anvil() -> tuple[Any, str]:
    from testcontainers.core.container import DockerContainer

    c = (
        DockerContainer(FOUNDRY_IMAGE)
        .with_kwargs(entrypoint="anvil")
        .with_command("--host 0.0.0.0 --chain-id 31337 --silent")
        .with_exposed_ports(8545)
    )
    c.start()
    url = f"http://{c.get_container_host_ip()}:{c.get_exposed_port(8545)}"
    deadline = time.monotonic() + 60
    while True:
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
            req = urllib.request.Request(
                url, data=body.encode(), headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=2) as resp:  # noqa: S310
                if json.loads(resp.read()).get("result"):
                    return c, url
        except OSError:
            pass
        if time.monotonic() > deadline:
            c.stop()
            raise RuntimeError("anvil did not start")
        time.sleep(0.3)


def deploy_registry(rpc: str, container: Any = None) -> Chain:
    w3 = Web3(HTTPProvider(rpc))
    owner = Account.create()
    w3.provider.make_request("anvil_setBalance", [owner.address, hex(10**20)])  # type: ignore[arg-type]
    owner_key = "0x" + bytes(owner.key).hex()
    address, _ = deploy(rpc, ARTIFACT, owner_key)
    return Chain(rpc, w3, int(w3.eth.chain_id), address, owner_key, container)


def new_key(chain: Chain) -> tuple[str, str]:
    acct = Account.create()
    chain.fund(acct.address)
    return "0x" + bytes(acct.key).hex(), acct.address.lower()


# --------------------------------------------------------------------------- proxy
class RpcProxy:
    """HTTP JSON-RPC pass-through. ``mode``: "up" forwards; "down" drops every connection (RPC
    dead); "drop_send" forwards eth_sendRawTransaction to the node but kills the connection
    before the reply (the tx is out, the worker sees a transport error: killed mid-submit)."""

    def __init__(self, upstream: str) -> None:
        self.upstream = upstream
        self.mode = "up"
        self.sent_raw = 0
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if proxy.mode == "down":
                    self._drop()
                    return
                method = json.loads(body).get("method") if body else None
                req = urllib.request.Request(  # noqa: S310 - local test node
                    proxy.upstream, data=body, headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                    out = resp.read()
                if method == "eth_sendRawTransaction":
                    proxy.sent_raw += 1
                    if proxy.mode == "drop_send":
                        self._drop()
                        return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def _drop(self) -> None:
                self.close_connection = True
                with contextlib.suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@contextlib.contextmanager
def rpc_proxy(upstream: str) -> Iterator[RpcProxy]:
    p = RpcProxy(upstream)
    try:
        yield p
    finally:
        p.close()


# --------------------------------------------------------------------------- recorder world
@dataclass
class Recorder:
    """One tenant registered on-chain to its own fresh submitter key (test isolation: an
    anchorer only serves recorders of its own submitter)."""

    chain: Chain
    tenant: str
    rid: bytes
    key: str
    address: str
    gw: Any
    anchorers: list[Anchorer] = field(default_factory=list)

    def anchorer(
        self,
        *,
        rpc: str | None = None,
        finality: str = "confirmations:1",
        gate: AnchorGate | None = None,
        release: bool = True,
        **cfg: Any,
    ) -> Anchorer:
        backend = EvmAnchorBackend(
            rpc_url=rpc or self.chain.rpc,
            chain_id=self.chain.chain_id,
            contract=self.chain.contract,
            private_key=self.key,
            timeout_seconds=3.0,
        )
        values: dict[str, Any] = {
            "finality": Finality.parse(finality),
            "routine_delay_seconds": 0.0,
            "backoff_base_seconds": 0.0,
            "rebroadcast_seconds": 3600.0,
        }
        values.update(cfg)
        a = Anchorer(
            engine=self.gw.engine,
            backend=backend,
            config=AnchorerConfig(**values),
            gate=(gate or self.gw.state.anchor_gate) if release else None,
            crash=self.gw.state.crash,
        )
        self.anchorers.append(a)
        return a

    def anchors(self) -> list[Any]:
        with self.gw.engine.connect() as conn:
            return list(
                conn.execute(
                    select(t.anchors)
                    .where(t.anchors.c.tenant_id == self.tenant)
                    .order_by(t.anchors.c.epoch_no)
                ).all()
            )

    def onchain(self, epoch_no: int) -> tuple[bytes, int, int, int, int]:
        c = self.chain.w3.eth.contract(
            address=Web3.to_checksum_address(self.chain.contract), abi=ARTIFACT["abi"]
        )
        r = c.functions.getAnchor(self.rid, epoch_no).call()
        return (bytes(r[0]), int(r[1]), int(r[2]), int(r[3]), int(r[4]))

    def next_epoch(self) -> int:
        c = self.chain.w3.eth.contract(
            address=Web3.to_checksum_address(self.chain.contract), abi=ARTIFACT["abi"]
        )
        return int(c.functions.nextEpoch(self.rid).call())

    def trust(self, **override: Any) -> dict[str, Any]:
        doc = {
            "format": "agw-anchor-trust/v1",
            "chain_id": self.chain.chain_id,
            "contract": self.chain.contract,
            "recorder_id": self.rid.hex(),
            "finality": "latest",
        }
        doc.update(override)
        return doc


def register(chain: Chain, migrator: Engine, gw: Any) -> Recorder:
    tenant = gw.world.tenant_id
    key, address = new_key(chain)
    rid = recorder_id(tenant, SALT)
    register_recorder(chain.rpc, chain.contract, chain.owner_key, rid, address)
    with migrator.begin() as conn:
        conn.execute(
            t.anchor_recorders.insert().values(
                tenant_id=tenant,
                recorder_id=rid,
                chain_id=chain.chain_id,
                contract=chain.contract,
                submitter=address,
                halted=False,
            )
        )
    return Recorder(chain, tenant, rid, key, address, gw)


def sealer(gw: Any, max_events: int = 4) -> Sealer:
    return Sealer(
        engine=gw.engine,
        writer=EvidenceWriter(),
        crash=gw.state.crash,
        max_events=max_events,
        max_age_seconds=3600.0,
    )


def echo(gw: Any, n: int) -> list[str]:
    """n LOW actions, executed (5 events each)."""
    ids = [gw.post("test_echo", {"text": f"e{i}"}).json()["action_id"] for i in range(n)]
    gw.drain()
    return ids


def first_event_id(gw: Any, action_id: str, event_type: str) -> Any:
    import uuid

    with gw.engine.connect() as conn:
        return conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(action_id),
                t.evidence_events.c.event_type == event_type,
            )
        ).scalar_one()


def bundle_for(gw: Any, event_id: Any) -> dict[str, Any]:
    with gw.engine.connect() as conn:
        return build_bundle(conn, event_id, tenant_id=gw.world.tenant_id)


def epochs_export(gw: Any) -> str:
    buf = io.StringIO()
    with gw.engine.connect() as conn:
        export_epochs(conn, gw.world.tenant_id, buf)
    return buf.getvalue()


def verify(tmp: Path, cmd: str, material: Any, *args: str) -> tuple[int, dict[str, Any]]:
    """Run ``agw-verify`` in-process (``--json``); returns (exit code, report)."""
    path = tmp / f"m-{secrets.token_hex(4)}.json"
    path.write_text(material if isinstance(material, str) else json.dumps(material))
    flag = "--bundle" if cmd == "event" else "--export"
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = verify_cli.main([cmd, flag, str(path), *args, "--json"])
    text_out = out.getvalue()
    return rc, (json.loads(text_out) if text_out.strip().startswith("{") else {})


def trust_file(tmp: Path, doc: dict[str, Any]) -> str:
    path = tmp / f"trust-{secrets.token_hex(4)}.json"
    path.write_text(json.dumps(doc))
    return str(path)
