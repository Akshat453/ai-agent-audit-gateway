"""Delegation service (Phase 8, ADR-0030): issue, revoke, resolve and consume delegations.

Issue (``POST /v1/delegations`` by agent P):
  * without a parent token, P delegates from its OWN current scopes; with ``parent_token``,
    P must be that token's child and re-delegates from the parent chain's effective
    permission. Scopes, tools, max risk and expiry can only narrow; depth <= the limit.
  * one transaction: DELEGATION_CREATED (A2A; purpose in the encrypted payload; ``refs.parent``
    = the parent's DELEGATION_CREATED hash) + the ``delegations`` row. The token is returned
    once; only its hash is stored.

Use (``POST /v1/actions`` with ``delegation.token``): ``resolve`` re-checks the signature and
the WHOLE chain against the database (revocation of any ancestor, expiry, use counts, every
issuer still active, every issuer's CURRENT scopes) and returns a pure
``DelegationConstraint`` for the policy engine. A use is consumed on every link in tx1 with a
conditional UPDATE guarded by a CHECK, so concurrent over-use cannot pass.

``recheck`` repeats the chain check (without consuming) at approval authorization and right
before dispatch, so a parent's revocation or scope reduction takes effect immediately, even
for an already-authorized child action that has not been dispatched yet.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final
from uuid import UUID

from sqlalchemy import Connection, Engine, bindparam, select, text, update
from sqlalchemy.dialects.postgresql import ARRAY, insert
from sqlalchemy.types import Uuid

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.db import tables as t
from agw_gateway.delegation.constraint import DelegationConstraint, FailureCode
from agw_gateway.delegation.token import (
    LEVELS,
    Claims,
    DelegationSigner,
    SignedToken,
    TokenInvalid,
    hashes_equal,
    parse_and_verify,
)
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.errors import DelegationRefused, DelegationUnavailable, NotFound
from agw_gateway.ids import uuid7
from agw_gateway.logs import log
from agw_gateway.tools.registry import ToolRegistry

logger = logging.getLogger("agw.delegation")

MAX_CHAIN: Final = 8


def _us(ts: datetime) -> int:
    return int(ts.timestamp() * 1_000_000)


def load_delegation_signer(path: Path | None) -> DelegationSigner | None:
    """None -> delegation fails closed (issue: 503; use: DENY DELEGATION_INVALID)."""
    if path is None:
        return None
    try:
        seed = bytes.fromhex(path.read_text(encoding="ascii").strip())
        return DelegationSigner(seed)
    except (OSError, ValueError, UnicodeDecodeError):
        log(logger, logging.ERROR, "delegation signing key unusable", error_code="SIGNING_KEY")
        return None


def generate_delegation_key_file(path: Path) -> str:
    """Write a fresh dev key (mode 0600, hex seed). Refuses to overwrite. Returns the key id."""
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(seed.hex() + "\n")
    return DelegationSigner(seed).key_id


@dataclass(frozen=True)
class DelegationRequest:
    child_agent_id: UUID
    scopes: tuple[str, ...]
    tools: tuple[str, ...]
    max_risk: str
    expires_at: datetime
    max_uses: int
    purpose: str
    parent_token: str | None = None
    run_id: UUID | None = None


@dataclass(frozen=True)
class Resolved:
    """A chain that resolved (``constraint.failure`` may still be set)."""

    constraint: DelegationConstraint
    delegation_id: UUID | None = None
    chain: tuple[UUID, ...] = ()  # root .. leaf
    token_hash: bytes | None = None
    issuer_id: UUID | None = None  # direct parent agent
    root_id: UUID | None = None
    created_event_id: UUID | None = None
    created_event_hash: bytes | None = None
    expires_at: datetime | None = None  # earliest expiry in the chain
    remaining_uses: int = 0  # min over the chain
    extras: dict[str, Any] = field(default_factory=dict)

    def header_ref(self) -> dict[str, Any]:
        """ACTION_REQUESTED ``delegation`` map (only for a chain without failure)."""
        assert self.delegation_id and self.token_hash and self.issuer_id  # noqa: S101
        assert self.root_id and self.created_event_id  # noqa: S101
        return {
            "id": self.delegation_id.bytes,
            "depth": self.constraint.depth,
            "th": self.token_hash,
            "from": self.issuer_id.bytes,
            "root": self.root_id.bytes,
            "ev": self.created_event_id.bytes,
        }

    def payload_section(self) -> dict[str, Any]:
        assert self.delegation_id is not None  # noqa: S101
        return {
            "id": self.delegation_id.bytes,
            "chain": [d.bytes for d in self.chain],
            "depth": self.constraint.depth,
            "declared_by": "gateway",
        }


_CHAIN_SQL: Final = text(
    """
    WITH RECURSIVE chain AS (
        SELECT d.*, 0 AS lvl FROM delegations d WHERE d.delegation_id = :id
        UNION ALL
        SELECT p.*, c.lvl + 1 FROM delegations p
          JOIN chain c ON p.delegation_id = c.parent_delegation_id
         WHERE c.lvl < :max_chain
    )
    SELECT chain.delegation_id, chain.tenant_id, chain.issuer_agent_id, chain.child_agent_id,
           chain.parent_delegation_id, chain.depth, chain.scopes, chain.tools, chain.max_risk,
           chain.expires_at, chain.max_uses, chain.uses, chain.token_hash,
           chain.created_event_id, chain.created_event_hash, chain.revoked_at,
           (chain.expires_at <= now()) AS expired,
           a.status AS issuer_status, a.scopes AS issuer_scopes, a.tenant_id AS issuer_tenant
      FROM chain JOIN agents a ON a.agent_id = chain.issuer_agent_id
     ORDER BY chain.lvl DESC
    """
)


class DelegationService:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        registry: ToolRegistry,
        signer: DelegationSigner | None,
        max_depth: int = 2,
        max_ttl: timedelta = timedelta(hours=24),
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._registry = registry
        self._signer = signer
        self.max_depth = max_depth
        self._max_ttl = max_ttl

    # ---------------------------------------------------------------- keys
    def trusted_keys(self) -> dict[str, bytes]:
        """Only the CONFIGURED key verifies (rows in delegation_signing_keys publish keys;
        agw_app can insert there, so a row never makes a key trusted)."""
        if self._signer is None:
            return {}
        return {self._signer.key_id: self._signer.public_raw}

    def sync_signing_key(self) -> None:
        if self._signer is None:
            return
        with self._engine.begin() as conn:
            conn.execute(
                insert(t.delegation_signing_keys)
                .values(
                    key_id=self._signer.key_id,
                    algorithm="Ed25519",
                    public_key=self._signer.public_raw,
                )
                .on_conflict_do_nothing()
            )

    def public_keys(self) -> list[dict[str, str]]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(t.delegation_signing_keys)).all()
        return [
            {"key_id": r.key_id, "algorithm": r.algorithm, "public_key": bytes(r.public_key).hex()}
            for r in rows
        ]

    # ---------------------------------------------------------------- resolve
    def resolve(
        self,
        conn: Connection,
        agent: AuthenticatedAgent,
        token: str,
        *,
        for_use: bool = True,
    ) -> Resolved:
        try:
            signed = parse_and_verify(token, self.trusted_keys())
        except TokenInvalid:
            return Resolved(DelegationConstraint.failed("DELEGATION_INVALID"))
        c = signed.claims
        if c.tenant != agent.tenant_id or c.subject != agent.agent_id:
            return Resolved(DelegationConstraint.failed("DELEGATION_NOT_FOR_AGENT", c.depth))
        return self._check_chain(conn, c.delegation_id, signed.hash, agent, for_use=for_use)

    def recheck(self, conn: Connection, delegation_id: UUID, agent: AuthenticatedAgent) -> Resolved:
        """Chain still live and covering (no use consumed): approvals + pre-dispatch."""
        return self._check_chain(conn, delegation_id, None, agent, for_use=False)

    def _check_chain(
        self,
        conn: Connection,
        delegation_id: UUID,
        token_hash: bytes | None,
        agent: AuthenticatedAgent,
        *,
        for_use: bool,
    ) -> Resolved:
        rows = conn.execute(_CHAIN_SQL, {"id": delegation_id, "max_chain": MAX_CHAIN}).all()
        if not rows:
            return Resolved(DelegationConstraint.failed("DELEGATION_INVALID"))
        leaf = rows[-1]
        depth = int(leaf.depth)

        def fail(code: FailureCode) -> Resolved:
            return Resolved(DelegationConstraint.failed(code, depth), delegation_id=delegation_id)

        if token_hash is not None and not hashes_equal(bytes(leaf.token_hash), token_hash):
            return fail("DELEGATION_INVALID")  # a validly signed token that we never stored
        # Chain shape: root at depth 1, contiguous depths, each child is the next issuer.
        shape_ok = (
            rows[0].parent_delegation_id is None
            and [int(r.depth) for r in rows] == list(range(1, len(rows) + 1))
            and all(
                rows[i].child_agent_id == rows[i + 1].issuer_agent_id
                and rows[i + 1].parent_delegation_id == rows[i].delegation_id
                for i in range(len(rows) - 1)
            )
        )
        if not shape_ok:
            return fail("DELEGATION_INVALID")
        if leaf.child_agent_id != agent.agent_id or any(
            r.tenant_id != agent.tenant_id for r in rows
        ):
            return fail("DELEGATION_NOT_FOR_AGENT")
        if any(r.revoked_at is not None for r in rows):
            return fail("DELEGATION_REVOKED")
        if any(r.expired for r in rows):
            return fail("DELEGATION_EXPIRED")
        if for_use and any(int(r.uses) >= int(r.max_uses) for r in rows):
            return fail("DELEGATION_EXHAUSTED")
        if depth > self.max_depth:
            return fail("DELEGATION_DEPTH_EXCEEDED")
        if any(r.issuer_status != "active" or r.issuer_tenant != agent.tenant_id for r in rows):
            return fail("DELEGATION_ISSUER_INACTIVE")
        scopes = frozenset(rows[0].scopes)
        tools = frozenset(rows[0].tools)
        for r in rows:
            scopes &= frozenset(r.scopes) & frozenset(r.issuer_scopes)
            tools &= frozenset(r.tools)
        max_risk = min((str(r.max_risk) for r in rows), key=LEVELS.index)
        return Resolved(
            DelegationConstraint(
                failure=None, depth=depth, scopes=scopes, tools=tools, max_risk=max_risk
            ),
            delegation_id=delegation_id,
            chain=tuple(r.delegation_id for r in rows),
            token_hash=bytes(leaf.token_hash),
            issuer_id=leaf.issuer_agent_id,
            root_id=rows[0].issuer_agent_id,
            created_event_id=leaf.created_event_id,
            created_event_hash=bytes(leaf.created_event_hash),
            expires_at=min(r.expires_at for r in rows),
            remaining_uses=min(int(r.max_uses) - int(r.uses) for r in rows),
        )

    def consume(self, conn: Connection, chain: tuple[UUID, ...]) -> bool:
        """One use on EVERY link, atomically; False if any link is exhausted/revoked/expired
        by now (a concurrent request won). ``uses <= max_uses`` is also a DB CHECK."""
        rows = conn.execute(
            text(
                """
                UPDATE delegations SET uses = uses + 1
                 WHERE delegation_id = ANY(:ids) AND revoked_at IS NULL
                   AND expires_at > now() AND uses < max_uses
                RETURNING delegation_id
                """
            ).bindparams(bindparam("ids", type_=ARRAY(Uuid()))),
            {"ids": list(chain)},
        ).all()
        return len(rows) == len(chain)

    # ---------------------------------------------------------------- issue
    def create(self, issuer: AuthenticatedAgent, req: DelegationRequest) -> dict[str, Any]:
        if self._signer is None or self._writer.mode == "none":
            raise DelegationUnavailable
        try:
            return self._create(issuer, req)
        except DelegationRefused as exc:
            # Every refused delegation request is evidence (an injected or compromised agent
            # trying to hand out authority it does not have is exactly what an auditor needs).
            self._record_refusal(issuer, req, exc.code)
            raise

    def _record_refusal(
        self, issuer: AuthenticatedAgent, req: DelegationRequest, code: str
    ) -> None:
        with self._engine.begin() as conn:
            self._writer.append(
                conn,
                issuer.tenant_id,
                [
                    NewEvent(
                        type="SECURITY_VIOLATION",
                        actor_kind="agent",
                        actor_id=str(issuer.agent_id),
                        run_id=req.run_id,
                        agent_id=issuer.agent_id,
                        fields={"violation": {"kind": "DELEGATION_REFUSED", "claimed": code}},
                        risk_level="HIGH",
                    )
                ],
            )
        log(
            logger,
            logging.WARNING,
            "delegation refused",
            tenant_id=issuer.tenant_id,
            agent_id=issuer.agent_id,
            error_code=code,
        )

    def _create(self, issuer: AuthenticatedAgent, req: DelegationRequest) -> dict[str, Any]:
        if self._signer is None or self._writer.mode == "none":
            # no key, or (ablation C1) no evidence: delegation provenance cannot be recorded
            raise DelegationUnavailable
        scopes = tuple(sorted(set(req.scopes)))
        tools = tuple(sorted(set(req.tools)))
        if req.max_risk not in LEVELS:
            raise DelegationRefused("DELEGATION_EXCEEDS_PARENT", 422)
        with self._engine.begin() as conn:
            now = conn.execute(text("SELECT now()")).scalar_one()
            parent: Resolved | None = None
            if req.parent_token is not None:
                parent = self.resolve(conn, issuer, req.parent_token, for_use=True)
                if parent.constraint.failure is not None:
                    raise DelegationRefused(parent.constraint.failure)
                if parent.constraint.depth + 1 > self.max_depth:
                    raise DelegationRefused("DELEGATION_DEPTH_EXCEEDED")
                base_scopes = parent.constraint.scopes & issuer.scopes
                base_tools: frozenset[str] | None = parent.constraint.tools
                base_risk = parent.constraint.max_risk
                assert parent.expires_at is not None  # noqa: S101
                if req.expires_at > parent.expires_at:
                    raise DelegationRefused("DELEGATION_EXCEEDS_PARENT")
                if req.max_uses > parent.remaining_uses:
                    raise DelegationRefused("DELEGATION_EXCEEDS_PARENT")
                depth = parent.constraint.depth + 1
            else:
                base_scopes, base_tools, base_risk, depth = issuer.scopes, None, "CRITICAL", 1
            # Never expansion: a delegation can only narrow what the issuer holds NOW.
            if (
                not set(scopes) <= base_scopes
                or (base_tools is not None and not set(tools) <= base_tools)
                or LEVELS.index(req.max_risk) > LEVELS.index(base_risk)
            ):
                raise DelegationRefused("DELEGATION_EXCEEDS_PARENT")
            # Authority first (above), so an escalation attempt is refused - and recorded - as
            # such; then the request's own validity.
            if not (now < req.expires_at <= now + self._max_ttl):
                raise DelegationRefused("DELEGATION_EXPIRY_INVALID", 422)
            child = conn.execute(
                select(t.agents.c.status).where(
                    t.agents.c.agent_id == req.child_agent_id,
                    t.agents.c.tenant_id == issuer.tenant_id,
                )
            ).one_or_none()
            if child is None or child.status != "active" or req.child_agent_id == issuer.agent_id:
                raise DelegationRefused("DELEGATION_CHILD_INVALID", 422)
            for tool_id in tools:
                spec = self._registry.resolve(tool_id, None, issuer.tenant_id)
                if spec is None or spec.meta.required_scope not in scopes:
                    raise DelegationRefused("DELEGATION_TOOL_INVALID", 422)

            delegation_id = uuid7()
            claims = Claims(
                delegation_id=delegation_id,
                tenant=issuer.tenant_id,
                issuer=issuer.agent_id,
                subject=req.child_agent_id,
                depth=depth,
                parent_hash=parent.token_hash if parent is not None else None,
                scopes=scopes,
                tools=tools,
                max_risk=req.max_risk,
                expires_us=_us(req.expires_at),
                max_uses=req.max_uses,
                issued_us=_us(now),
                key_id=self._signer.key_id,
            )
            signed: SignedToken = self._signer.sign(claims)
            ref: dict[str, Any] = {
                "id": delegation_id.bytes,
                "depth": depth,
                "th": signed.hash,
                "from": issuer.agent_id.bytes,
                "to": req.child_agent_id.bytes,
                "sc": list(scopes),
                "tl": list(tools),
                "mr": req.max_risk,
                "exp": claims.expires_us,
                "mu": req.max_uses,
                "kid": self._signer.key_id,
            }
            fields: dict[str, Any] = {"delegation": ref}
            if parent is not None:
                assert parent.delegation_id and parent.created_event_hash  # noqa: S101
                ref["par"] = parent.delegation_id.bytes
                ref["root"] = (parent.root_id or issuer.agent_id).bytes
                fields["refs"] = {"parent": parent.created_event_hash}
            # The key row must exist before the delegation row references it.
            conn.execute(
                insert(t.delegation_signing_keys)
                .values(
                    key_id=self._signer.key_id,
                    algorithm="Ed25519",
                    public_key=self._signer.public_raw,
                )
                .on_conflict_do_nothing()
            )
            stored = self._writer.append(
                conn,
                issuer.tenant_id,
                [
                    NewEvent(
                        type="DELEGATION_CREATED",
                        actor_kind="agent",
                        actor_id=str(issuer.agent_id),
                        run_id=req.run_id,
                        agent_id=issuer.agent_id,
                        fields=fields,
                        payload={"delegation": {"purpose": req.purpose}},
                        # A2A delegation is sealed promptly (it widens who can act).
                        risk_level="HIGH",
                    )
                ],
            )
            ev = stored[0]
            conn.execute(
                insert(t.delegations).values(
                    delegation_id=delegation_id,
                    tenant_id=issuer.tenant_id,
                    issuer_agent_id=issuer.agent_id,
                    child_agent_id=req.child_agent_id,
                    parent_delegation_id=parent.delegation_id if parent else None,
                    depth=depth,
                    scopes=list(scopes),
                    tools=list(tools),
                    max_risk=req.max_risk,
                    expires_at=req.expires_at,
                    max_uses=req.max_uses,
                    uses=0,
                    token_hash=signed.hash,
                    key_id=self._signer.key_id,
                    created_event_id=ev.event_id,
                    created_event_hash=ev.event_hash,
                )
            )
        log(
            logger,
            logging.INFO,
            "delegation created",
            tenant_id=issuer.tenant_id,
            agent_id=issuer.agent_id,
            status="CREATED",
        )
        return {
            "delegation_id": str(delegation_id),
            "token": signed.text,  # shown once; only its hash is stored
            "token_hash": signed.hash.hex(),
            "depth": depth,
            "scopes": list(scopes),
            "tools": list(tools),
            "max_risk_level": req.max_risk,
            "max_uses": req.max_uses,
            "expires_at": req.expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "created_event_id": str(ev.event_id),
            "key_id": self._signer.key_id,
        }

    # ---------------------------------------------------------------- revoke
    def revoke(self, agent: AuthenticatedAgent, delegation_id: UUID) -> dict[str, Any]:
        """The direct issuer or any issuer higher up the chain may revoke. Descendants become
        unusable at once (``resolve`` checks every ancestor); they are not rewritten."""
        with self._engine.begin() as conn:
            rows = conn.execute(_CHAIN_SQL, {"id": delegation_id, "max_chain": MAX_CHAIN}).all()
            if not rows or rows[-1].tenant_id != agent.tenant_id:
                raise NotFound
            if agent.agent_id not in {r.issuer_agent_id for r in rows}:
                raise DelegationRefused("DELEGATION_NOT_REVOCABLE")
            leaf = conn.execute(
                select(t.delegations)
                .where(t.delegations.c.delegation_id == delegation_id)
                .with_for_update()
            ).one()
            already = leaf.revoked_at is not None
            if not already:
                conn.execute(
                    update(t.delegations)
                    .where(t.delegations.c.delegation_id == delegation_id)
                    .values(revoked_at=text("now()"), revoked_by=str(agent.agent_id))
                )
                self._writer.append(
                    conn,
                    agent.tenant_id,
                    [
                        NewEvent(
                            type="DELEGATION_REVOKED",
                            actor_kind="agent",
                            actor_id=str(agent.agent_id),
                            agent_id=agent.agent_id,
                            fields={
                                "delegation": {
                                    "id": delegation_id.bytes,
                                    "depth": int(leaf.depth),
                                    "th": bytes(leaf.token_hash),
                                },
                                "refs": {"parent": bytes(leaf.created_event_hash)},
                            },
                            risk_level="HIGH",
                        )
                    ],
                )
        return {"delegation_id": str(delegation_id), "revoked": True, "already": already}
