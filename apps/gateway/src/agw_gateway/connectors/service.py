"""Connector administration (C2, ADR-0035).

Invariants enforced here (each has a test):

* every change (add, update, classify, rotate, disable, enable, delete, GitHub App
  registration/installation) needs an **admin with a recent step-up** and writes a
  CONNECTOR_* evidence event in the SAME transaction;
* credentials are **write-only**: validated by the type's credential model, sealed with the
  Phase 7 envelope (KEK -> per-blob DEK, AAD = tenant + purpose + connector id), never
  selected by a read path, never logged; rotation replaces them, delete destroys them;
* a new connector's actions start **UNCLASSIFIED** (no entry in any policy version) and are
  denied by the policy engine until an admin classifies each one;
* each classification change is a **new, append-only policy version**; tool versions follow
  it (``1.0.<version>``), so earlier decisions keep the version they were made under.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, Final
from urllib.parse import urlencode
from uuid import UUID

from pydantic import BaseModel, SecretStr, ValidationError
from sqlalchemy import Connection, Engine, func, insert, select, update

from agw_gateway.connectors.manifest import (
    SLUG_RE,
    ActionClassification,
    ActionManifest,
    ClassificationDocument,
    ManifestError,
    canonical_digest,
)
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked
from agw_gateway.connectors.types import CATALOG, CREATABLE, ConnectorType
from agw_gateway.connectors.types.base import Health
from agw_gateway.connectors.types.github import (
    GithubConfig,
    GithubConnector,
    convert_manifest_code,
    manifest_form,
)
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.errors import (
    Conflict,
    Forbidden,
    NotFound,
    RequestInvalid,
    StepUpRequired,
)
from agw_gateway.humans.models import AuthenticatedHuman
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log
from agw_gateway.privacy.cipher import EnvelopeCipher, ops_context

logger = logging.getLogger("agw.connectors")
STATE_TTL: Final = timedelta(hours=1)  # GitHub: the manifest flow must finish within one hour


def _fields(exc: ValidationError, prefix: str) -> list[str]:
    """Field NAMES only: a credential value must never appear in an error."""
    return sorted({prefix + ".".join(str(p) for p in e["loc"]) for e in exc.errors()})


def _secret_dump(model: BaseModel) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in model:
        if v is None:
            continue
        out[k] = v.get_secret_value() if isinstance(v, SecretStr) else v
    return out


# GitHub App identity, recorded only by the manifest / install flow; an edit keeps it.
GITHUB_FLOW_FIELDS = ("app_id", "app_slug", "client_id", "html_url", "installation_ids")


class ConnectorService:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        cipher: EnvelopeCipher | None,
        http: SafeHttp | None = None,
        step_up_window_seconds: int = 300,
        gateway_url: str = "http://localhost:8000",
        dashboard_url: str = "http://localhost:3000",
        settings_view: Mapping[str, Any] | None = None,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._cipher = cipher
        self.http = http or SafeHttp()
        self._window = step_up_window_seconds
        self.gateway_url = gateway_url.rstrip("/")
        self.dashboard_url = dashboard_url.rstrip("/")
        self._anchoring = dict(settings_view or {})

    # ------------------------------------------------------------------ guards
    def _admin(self, human: AuthenticatedHuman) -> None:
        if not human.has("admin"):
            raise Forbidden
        age = human.stepped_up_age_seconds
        if age is None or age > self._window:
            raise StepUpRequired

    @staticmethod
    def _viewer(human: AuthenticatedHuman) -> None:
        if not (human.roles & {"admin", "auditor", "security"}):
            raise Forbidden

    def _seal(self, tenant: str, connector_id: UUID, creds: BaseModel) -> bytes:
        if self._cipher is None:
            raise KeyUnavailable("no KEK configured")
        ctx = ops_context(tenant, "connector_credentials", connector_id.bytes)
        return self._cipher.seal_json(ctx, _secret_dump(creds))

    def _open(self, row: Any, ctype: ConnectorType) -> BaseModel:
        if row.credentials_sealed is None:
            return ctype.credential_model.model_validate({})
        if self._cipher is None:
            raise KeyUnavailable("no KEK configured")
        raw = self._cipher.open_json(
            ops_context(row.tenant_id, "connector_credentials", row.connector_id.bytes),
            bytes(row.credentials_sealed),
        )
        return ctype.credential_model.model_validate(raw)

    @staticmethod
    def _type(type_id: str) -> ConnectorType:
        ctype = CATALOG.get(type_id)
        if ctype is None:
            raise RequestInvalid(["type_id"])
        return ctype

    def _row(self, conn: Connection, tenant: str, connector_id: UUID, *, lock: bool = False) -> Any:
        q = select(t.connectors).where(
            t.connectors.c.connector_id == connector_id,
            t.connectors.c.tenant_id == tenant,
            t.connectors.c.deleted_at.is_(None),
        )
        row = conn.execute(q.with_for_update() if lock else q).one_or_none()
        if row is None:
            raise NotFound
        return row

    def _event(
        self,
        conn: Connection,
        human: AuthenticatedHuman,
        etype: str,
        row: Any,
        *,
        ver: int,
        act: str | None = None,
        cred: int | None = None,
        digest: bytes | None = None,
    ) -> None:
        ref: dict[str, Any] = {"id": row.connector_id.bytes, "type": row.type_id, "ver": ver}
        if act is not None:
            ref["act"] = act
        if cred is not None:
            ref["cred"] = cred
        if digest is not None:
            ref["digest"] = digest
        self._writer.append(
            conn,
            row.tenant_id,
            [
                NewEvent(
                    type=etype,
                    actor_kind="human",
                    actor_id=str(human.human_id),
                    fields={"connector": ref},
                    risk_level="HIGH",  # administrative changes seal immediately
                )
            ],
        )
        log(logger, logging.INFO, "connector change", tenant_id=row.tenant_id, error_code=etype)

    # ------------------------------------------------------------------ catalog
    def catalog(self) -> list[dict[str, Any]]:
        out = []
        for type_id, ctype in sorted(CATALOG.items()):
            m = ctype.manifest
            out.append(
                {
                    "id": m.id,
                    "name": m.name,
                    "category": m.category,
                    "auth": m.auth,
                    "description": m.description,
                    "creatable": type_id in CREATABLE,
                    "dynamic_actions": m.dynamic_actions,
                    "actions": [_action_view(a) for a in m.actions],
                    "config_schema": ctype.config_model.model_json_schema(),
                    "credential_fields": sorted(ctype.credential_model.model_fields),
                    "setup": dict(
                        ctype.setup(ctype.config_model.model_construct(), self.gateway_url)
                    ),
                }
            )
        return out

    # ------------------------------------------------------------------ reads
    def list_connectors(self, human: AuthenticatedHuman) -> list[dict[str, Any]]:
        self._viewer(human)
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(t.connectors)
                .where(
                    t.connectors.c.tenant_id == human.tenant_id, t.connectors.c.deleted_at.is_(None)
                )
                .order_by(t.connectors.c.created_at)
            ).all()
            unclassified = self._unclassified_counts(conn, [r.connector_id for r in rows])
        items = [self._summary(r, unclassified.get(r.connector_id, 0)) for r in rows]
        if self._anchoring:
            items.append(self._anchoring_view())
        return items

    def _anchoring_view(self) -> dict[str, Any]:
        return {
            "connector_id": None,
            "type_id": "anchoring",
            "category": "anchoring",
            "slug": "anchoring",
            "name": "Blockchain anchoring",
            "status": "connected" if self._anchoring.get("contract") else "needs_attention",
            "config": self._anchoring,
            "read_only": True,
            "policy_version": 0,
            "unclassified_actions": 0,
        }

    def _unclassified_counts(self, conn: Connection, ids: list[UUID]) -> dict[UUID, int]:
        out: dict[UUID, int] = {}
        for cid in ids:
            doc = self._document(conn, cid)
            names = conn.execute(
                select(t.connector_actions.c.name).where(t.connector_actions.c.connector_id == cid)
            ).scalars()
            out[cid] = sum(1 for n in names if n not in doc.actions)
        return out

    @staticmethod
    def _summary(row: Any, unclassified: int) -> dict[str, Any]:
        return {
            "connector_id": str(row.connector_id),
            "type_id": row.type_id,
            "category": CATALOG[row.type_id].manifest.category,
            "slug": row.slug,
            "name": row.name,
            "status": row.status,
            "policy_version": row.policy_version,
            "credential_version": row.credential_version,
            "unclassified_actions": unclassified,
            "last_health": row.last_health,
            "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
        }

    def _document(
        self, conn: Connection, connector_id: UUID, version: int | None = None
    ) -> ClassificationDocument:
        q = select(t.connector_policies.c.document).where(
            t.connector_policies.c.connector_id == connector_id
        )
        q = (
            q.where(t.connector_policies.c.version == version)
            if version is not None
            else q.order_by(t.connector_policies.c.version.desc()).limit(1)
        )
        doc = conn.execute(q).scalar_one_or_none()
        return ClassificationDocument.model_validate(doc or {})

    def get(self, human: AuthenticatedHuman, connector_id: UUID) -> dict[str, Any]:
        self._viewer(human)
        with self._engine.connect() as conn:
            row = self._row(conn, human.tenant_id, connector_id)
            doc = self._document(conn, connector_id)
            actions = conn.execute(
                select(t.connector_actions)
                .where(t.connector_actions.c.connector_id == connector_id)
                .order_by(t.connector_actions.c.name)
            ).all()
            health = conn.execute(
                select(
                    t.connector_health.c.ok,
                    t.connector_health.c.detail,
                    t.connector_health.c.checked_at,
                )
                .where(t.connector_health.c.connector_id == connector_id)
                .order_by(t.connector_health.c.checked_at.desc())
                .limit(20)
            ).all()
            prefix = f"cx_{row.slug}_"
            usage = conn.execute(
                select(t.actions.c.decision, func.count())
                .where(
                    t.actions.c.tenant_id == row.tenant_id, t.actions.c.tool_id.startswith(prefix)
                )
                .group_by(t.actions.c.decision)
            ).all()
            events = conn.execute(
                select(
                    t.evidence_events.c.seq,
                    t.evidence_events.c.event_type,
                    t.evidence_events.c.occurred_at,
                    t.evidence_events.c.event_id,
                )
                .where(
                    t.evidence_events.c.tenant_id == row.tenant_id,
                    t.evidence_events.c.event_type.startswith("CONNECTOR_"),
                    t.evidence_events.c.body["connector"]["id"].astext == str(row.connector_id),
                )
                .order_by(t.evidence_events.c.seq.desc())
                .limit(50)
            ).all()
        ctype = CATALOG[row.type_id]
        counts = {str(d): int(n) for d, n in usage}
        sealed_fields = sorted(ctype.credential_model.model_fields)
        return {
            **self._summary(row, sum(1 for a in actions if a.name not in doc.actions)),
            "config": row.config,  # non-secret by construction (credentials are separate)
            # Write-only: only WHICH credential fields exist and the version, never values.
            "credentials": {
                "fields": sealed_fields,
                "set": row.credentials_sealed is not None,
                "version": row.credential_version,
            },
            "actions": [
                {
                    **_action_view(a),
                    "proposed": next(
                        (m.proposed for m in ctype.manifest.actions if m.name == a.name), None
                    ),
                    "upstream_name": a.upstream_name,
                    "classification": (
                        doc.actions[a.name].model_dump(mode="json")
                        if a.name in doc.actions
                        else None
                    ),
                }
                for a in actions
            ],
            "health": [
                {
                    "ok": h.ok,
                    **dict(h.detail),
                    "checked_at": h.checked_at.isoformat().replace("+00:00", "Z"),
                }
                for h in health
            ],
            "usage": {
                "calls": sum(counts.values()),
                "denials": counts.get("DENY", 0),
                "approvals": counts.get("REQUIRE_APPROVAL", 0),
            },
            "events": [
                {
                    "seq": e.seq,
                    "type": e.event_type,
                    "event_id": str(e.event_id),
                    "occurred_at": e.occurred_at.isoformat().replace("+00:00", "Z"),
                }
                for e in events
            ],
            "setup": dict(
                ctype.setup(ctype.config_model.model_validate(row.config), self.gateway_url)
            ),
        }

    # ------------------------------------------------------------------ writes
    def create(self, human: AuthenticatedHuman, body: Mapping[str, Any]) -> dict[str, Any]:
        self._admin(human)
        type_id = str(body.get("type_id", ""))
        if type_id not in CREATABLE:
            raise RequestInvalid(["type_id"])
        ctype = self._type(type_id)
        slug, name = str(body.get("slug", "")), str(body.get("name", "")).strip()
        if not SLUG_RE.fullmatch(slug):
            raise RequestInvalid(["slug"])
        if not 1 <= len(name) <= 120:
            raise RequestInvalid(["name"])
        try:
            config = ctype.config_model.model_validate(body.get("config") or {})
        except (ValidationError, ManifestError) as exc:
            raise RequestInvalid(
                _fields(exc, "config.") if isinstance(exc, ValidationError) else ["config"]
            ) from None
        try:
            creds = ctype.credential_model.model_validate(body.get("credentials") or {})
        except ValidationError as exc:
            raise RequestInvalid(_fields(exc, "credentials.")) from None
        cid = uuid7()
        has_creds = bool(_secret_dump(creds))
        with self._engine.begin() as conn:
            taken = conn.execute(
                select(t.connectors.c.connector_id).where(
                    t.connectors.c.tenant_id == human.tenant_id,
                    t.connectors.c.slug == slug,
                    t.connectors.c.deleted_at.is_(None),
                )
            ).first()
            if taken is not None:
                raise Conflict
            conn.execute(
                insert(t.connectors).values(
                    connector_id=cid,
                    tenant_id=human.tenant_id,
                    type_id=type_id,
                    slug=slug,
                    name=name,
                    config=config.model_dump(mode="json"),
                    credentials_sealed=self._seal(human.tenant_id, cid, creds)
                    if has_creds
                    else None,
                    credential_version=1 if has_creds else 0,
                    status="needs_attention",
                    policy_version=0,
                    created_by=human.human_id,
                )
            )
            row = self._row(conn, human.tenant_id, cid)
            if not ctype.manifest.dynamic_actions or type_id == "http_api":
                self._sync_actions(conn, row, ctype.discover(config, creds, self.http), human)
            self._event(
                conn, human, "CONNECTOR_ADDED", row, ver=0, digest=canonical_digest(row.config)
            )
        return self.get_admin(human, cid)

    def get_admin(self, human: AuthenticatedHuman, cid: UUID) -> dict[str, Any]:
        return self.get(human, cid)

    def _sync_actions(
        self,
        conn: Connection,
        row: Any,
        discovered: list[tuple[ActionManifest, str | None]],
        human: AuthenticatedHuman,
    ) -> None:
        """Mirror the type's actions. A classified action whose definition changed or vanished
        loses its classification (a new policy version): a change can never inherit approval."""
        existing = {
            a.name: a
            for a in conn.execute(
                select(t.connector_actions).where(
                    t.connector_actions.c.connector_id == row.connector_id
                )
            ).all()
        }
        new = {a.name: (a, up) for a, up in discovered}
        changed: set[str] = set()
        for name, old in existing.items():
            cur = new.get(name)
            if cur is None or (
                old.input_schema != cur[0].input_schema
                or old.side_effect != cur[0].side_effect
                or old.upstream_name != cur[1]
            ):
                changed.add(name)
                conn.execute(
                    t.connector_actions.delete().where(
                        t.connector_actions.c.connector_id == row.connector_id,
                        t.connector_actions.c.name == name,
                    )
                )
        for name, (a, up) in new.items():
            if name in existing and name not in changed:
                continue
            conn.execute(
                insert(t.connector_actions).values(
                    connector_id=row.connector_id,
                    name=a.name,
                    description=a.description,
                    input_schema=a.input_schema,
                    side_effect=a.side_effect,
                    suggested_risk=a.suggested_risk,
                    upstream_name=up,
                )
            )
        doc = self._document(conn, row.connector_id)
        dropped = changed & set(doc.actions)
        if dropped:
            remaining = {k: v for k, v in doc.actions.items() if k not in dropped}
            self._new_version(
                conn,
                row,
                ClassificationDocument(actions=remaining),
                human,
                [(n, "CONNECTOR_ACTION_CLASSIFIED") for n in sorted(dropped)],
            )

    def _new_version(
        self,
        conn: Connection,
        row: Any,
        doc: ClassificationDocument,
        human: AuthenticatedHuman,
        events: list[tuple[str, str]],
    ) -> int:
        current = conn.execute(
            select(t.connectors.c.policy_version)
            .where(t.connectors.c.connector_id == row.connector_id)
            .with_for_update()
        ).scalar_one()
        version = int(current) + 1
        document = doc.model_dump(mode="json")
        digest = canonical_digest(document)
        conn.execute(
            insert(t.connector_policies).values(
                connector_id=row.connector_id,
                version=version,
                document=document,
                digest=digest,
                created_by=human.human_id,
            )
        )
        conn.execute(
            update(t.connectors)
            .where(t.connectors.c.connector_id == row.connector_id)
            .values(policy_version=version, updated_at=func.now())
        )
        for act, etype in events:
            self._event(conn, human, etype, row, ver=version, act=act, digest=digest)
        return version

    def update(
        self, human: AuthenticatedHuman, cid: UUID, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._admin(human)
        if set(body) - {"name", "config"}:
            raise RequestInvalid(sorted(set(body) - {"name", "config"}))
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            ctype = self._type(row.type_id)
            values: dict[str, Any] = {"updated_at": func.now()}
            if "name" in body:
                name = str(body["name"]).strip()
                if not 1 <= len(name) <= 120:
                    raise RequestInvalid(["name"])
                values["name"] = name
            config = ctype.config_model.model_validate(row.config)
            if "config" in body:
                new_config = dict(body["config"]) if isinstance(body["config"], Mapping) else {}
                if row.type_id == "github":  # set only by the manifest / install flow
                    for f in GITHUB_FLOW_FIELDS:
                        new_config.pop(f, None)
                        if (row.config or {}).get(f) is not None:
                            new_config[f] = row.config[f]
                try:
                    config = ctype.config_model.model_validate(new_config)
                except (ValidationError, ManifestError) as exc:
                    raise RequestInvalid(
                        _fields(exc, "config.") if isinstance(exc, ValidationError) else ["config"]
                    ) from None
                values["config"] = config.model_dump(mode="json")
                values["status"] = "needs_attention" if row.status != "disabled" else "disabled"
            conn.execute(
                update(t.connectors).where(t.connectors.c.connector_id == cid).values(**values)
            )
            row = self._row(conn, human.tenant_id, cid)
            if row.type_id == "http_api":
                self._sync_actions(
                    conn,
                    row,
                    ctype.discover(config, ctype.credential_model.model_validate({}), self.http),
                    human,
                )
                row = self._row(conn, human.tenant_id, cid)
            self._event(
                conn,
                human,
                "CONNECTOR_UPDATED",
                row,
                ver=row.policy_version,
                digest=canonical_digest(row.config),
            )
        return self.get(human, cid)

    def test(self, human: AuthenticatedHuman, cid: UUID) -> dict[str, Any]:
        """Test connection / health check; dynamic types (MCP upstream) also (re)discover
        their actions here; new actions arrive UNCLASSIFIED."""
        if not human.has("admin"):
            raise Forbidden
        with self._engine.connect() as conn:
            row = self._row(conn, human.tenant_id, cid)
        ctype = self._type(row.type_id)
        config = ctype.config_model.model_validate(row.config)
        creds = self._open(row, ctype)
        health: Health = ctype.health(config, creds, self.http)
        discovered: list[tuple[ActionManifest, str | None]] | None = None
        if health.ok and ctype.manifest.dynamic_actions and row.type_id != "http_api":
            try:
                discovered = ctype.discover(config, creds, self.http)
            except (SsrfBlocked, Exception) as exc:
                health = Health(False, "DISCOVERY_FAILED", {"error": type(exc).__name__})
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            conn.execute(
                insert(t.connector_health).values(
                    check_id=uuid7(), connector_id=cid, ok=health.ok, detail=health.as_dict()
                )
            )
            status = (
                row.status
                if row.status == "disabled"
                else ("connected" if health.ok else "needs_attention")
            )
            conn.execute(
                update(t.connectors)
                .where(t.connectors.c.connector_id == cid)
                .values(last_health=health.as_dict(), status=status, updated_at=func.now())
            )
            if discovered is not None:
                self._sync_actions(conn, row, discovered, human)
        return {"health": health.as_dict(), "status": status}

    def classify(
        self, human: AuthenticatedHuman, cid: UUID, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        """``{"actions": {name: classification | null}}``: merged into a NEW policy version
        (null removes a classification -> that action is denied again)."""
        self._admin(human)
        raw = body.get("actions")
        if not isinstance(raw, dict) or not raw or set(body) != {"actions"}:
            raise RequestInvalid(["actions"])
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            names = set(
                conn.execute(
                    select(t.connector_actions.c.name).where(
                        t.connector_actions.c.connector_id == cid
                    )
                ).scalars()
            )
            if set(raw) - names:
                raise RequestInvalid([f"actions.{n}" for n in sorted(set(raw) - names)])
            doc = dict(self._document(conn, cid).actions)
            changed: list[str] = []
            for name, value in sorted(raw.items()):
                if value is None:
                    if name in doc:
                        del doc[name]
                        changed.append(name)
                    continue
                try:
                    entry = ActionClassification.model_validate(value)
                except ValidationError as exc:
                    raise RequestInvalid(_fields(exc, f"actions.{name}.")) from None
                if doc.get(name) != entry:
                    doc[name] = entry
                    changed.append(name)
            if not changed:
                return {"policy_version": row.policy_version, "changed": []}
            version = self._new_version(
                conn,
                row,
                ClassificationDocument(actions=doc),
                human,
                [(n, "CONNECTOR_ACTION_CLASSIFIED") for n in changed],
            )
        return {"policy_version": version, "changed": changed}

    def rotate(
        self, human: AuthenticatedHuman, cid: UUID, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._admin(human)
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            ctype = self._type(row.type_id)
            try:
                creds = ctype.credential_model.model_validate(body.get("credentials") or {})
            except ValidationError as exc:
                raise RequestInvalid(_fields(exc, "credentials.")) from None
            if not _secret_dump(creds):
                raise RequestInvalid(["credentials"])
            version = int(row.credential_version) + 1
            conn.execute(
                update(t.connectors)
                .where(t.connectors.c.connector_id == cid)
                .values(
                    credentials_sealed=self._seal(row.tenant_id, cid, creds),
                    credential_version=version,
                    status="needs_attention" if row.status != "disabled" else "disabled",
                    updated_at=func.now(),
                )
            )
            self._event(
                conn,
                human,
                "CONNECTOR_CREDENTIAL_ROTATED",
                row,
                ver=row.policy_version,
                cred=version,
            )
        return {"credential_version": version}

    def set_enabled(self, human: AuthenticatedHuman, cid: UUID, enabled: bool) -> dict[str, Any]:
        self._admin(human)
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            status = "needs_attention" if enabled else "disabled"
            if (row.status == "disabled") != (not enabled):
                conn.execute(
                    update(t.connectors)
                    .where(t.connectors.c.connector_id == cid)
                    .values(status=status, updated_at=func.now())
                )
                self._event(
                    conn,
                    human,
                    "CONNECTOR_UPDATED" if enabled else "CONNECTOR_DISABLED",
                    row,
                    ver=row.policy_version,
                )
        return {"status": status}

    def delete(self, human: AuthenticatedHuman, cid: UUID) -> None:
        self._admin(human)
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid, lock=True)
            conn.execute(
                update(t.connectors)
                .where(t.connectors.c.connector_id == cid)
                .values(
                    deleted_at=func.now(),
                    status="disabled",
                    credentials_sealed=None,  # the sealed credentials are destroyed
                    updated_at=func.now(),
                )
            )
            self._event(conn, human, "CONNECTOR_DELETED", row, ver=row.policy_version)

    # ------------------------------------------------------------------ runtime
    def runtime(self, tenant: str, cid: UUID) -> tuple[Any, ConnectorType, BaseModel, BaseModel]:
        """(row, type, config, credentials) for executing an action. Never cached."""
        with self._engine.connect() as conn:
            row = self._row(conn, tenant, cid)
        ctype = self._type(row.type_id)
        return row, ctype, ctype.config_model.model_validate(row.config), self._open(row, ctype)

    def assess(
        self, tenant: str, cid: UUID, action: ActionManifest, args: Mapping[str, Any]
    ) -> Any:
        """C3: a connector's pre-decision content assessment (credentials decrypted here)."""
        from agw_gateway.connectors.types.base import ExecContext  # noqa: PLC0415

        _row, ctype, config, creds = self.runtime(tenant, cid)
        return ctype.assess(
            ExecContext(
                config=config,
                credentials=creds,
                http=self.http,
                action=action,
                tenant=tenant,
                connector_id=cid,
                engine=self._engine,
            ),
            args,
        )

    # ------------------------------------------------------------------ GitHub App
    def _new_state(
        self, conn: Connection, human: AuthenticatedHuman, cid: UUID, purpose: str
    ) -> str:
        state = secrets.token_urlsafe(32)
        conn.execute(
            insert(t.github_manifest_states).values(
                state_hash=hashlib.sha256(state.encode()).digest(),
                tenant_id=human.tenant_id,
                human_id=human.human_id,
                connector_id=cid,
                purpose=purpose,
                expires_at=func.now() + STATE_TTL,
            )
        )
        return state

    def github_manifest(self, human: AuthenticatedHuman, cid: UUID) -> dict[str, Any]:
        self._admin(human)
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid)
            if row.type_id != "github":
                raise RequestInvalid(["connector_id"])
            state = self._new_state(conn, human, cid, "manifest")
        form = manifest_form(
            GithubConfig.model_validate(row.config),
            self.gateway_url,
            self.dashboard_url,
            str(cid),
            f"AgentGuard {row.name}",
        )
        return {
            "action": f"{form['action']}?{urlencode({'state': state})}",
            "manifest": form["manifest"],
            "state": state,
        }

    def _consume_state(self, conn: Connection, state: str, purpose: str) -> Any:
        row = conn.execute(
            select(
                t.github_manifest_states,
                (t.github_manifest_states.c.expires_at > func.now()).label("live"),
            )
            .where(t.github_manifest_states.c.state_hash == hashlib.sha256(state.encode()).digest())
            .with_for_update()
        ).one_or_none()
        if row is None or row.used_at is not None or not row.live or row.purpose != purpose:
            raise Forbidden
        conn.execute(
            update(t.github_manifest_states)
            .where(t.github_manifest_states.c.state_hash == row.state_hash)
            .values(used_at=func.now())
        )
        return row

    def _state_human(self, conn: Connection, st: Any) -> AuthenticatedHuman:
        h = conn.execute(select(t.humans).where(t.humans.c.human_id == st.human_id)).one()
        return AuthenticatedHuman(
            tenant_id=h.tenant_id,
            human_id=h.human_id,
            username=h.username,
            roles=frozenset(h.roles),
        )

    def github_manifest_callback(self, code: str, state: str) -> str:
        """GitHub redirected the browser back with ``code``: convert it (one hour) and store
        the App's secrets sealed. Returns the dashboard URL to continue (install step)."""
        if not (0 < len(code) <= 200 and code.replace("-", "").replace("_", "").isalnum()):
            raise Forbidden
        with self._engine.begin() as conn:
            st = self._consume_state(conn, state, "manifest")
            human = self._state_human(conn, st)
            row = self._row(conn, st.tenant_id, st.connector_id, lock=True)
        app = convert_manifest_code(self.http, code)
        ctype = GithubConnector()
        config = GithubConfig.model_validate(row.config).model_copy(
            update={
                "app_id": int(app["id"]),
                "app_slug": str(app.get("slug", ""))[:100] or None,
                "client_id": str(app.get("client_id", ""))[:100] or None,
                "html_url": str(app.get("html_url", ""))[:500] or None,
            }
        )
        creds = ctype.credential_model.model_validate(
            {
                "pem": app.get("pem"),
                "webhook_secret": app.get("webhook_secret"),
                "client_secret": app.get("client_secret"),
            }
        )
        with self._engine.begin() as conn:
            row = self._row(conn, st.tenant_id, st.connector_id, lock=True)
            version = int(row.credential_version) + 1
            conn.execute(
                update(t.connectors)
                .where(t.connectors.c.connector_id == row.connector_id)
                .values(
                    config=GithubConfig.model_validate(config.model_dump()).model_dump(mode="json"),
                    credentials_sealed=self._seal(row.tenant_id, row.connector_id, creds),
                    credential_version=version,
                    updated_at=func.now(),
                )
            )
            row = self._row(conn, st.tenant_id, st.connector_id)
            self._event(
                conn,
                human,
                "CONNECTOR_UPDATED",
                row,
                ver=row.policy_version,
                cred=version,
                digest=canonical_digest(row.config),
            )
        return f"{self.dashboard_url}/integrations/{row.connector_id}?step=install"

    def github_install_url(self, human: AuthenticatedHuman, cid: UUID) -> dict[str, Any]:
        self._admin(human)
        with self._engine.begin() as conn:
            row = self._row(conn, human.tenant_id, cid)
            slug = GithubConfig.model_validate(row.config).app_slug
            if row.type_id != "github" or not slug:
                raise RequestInvalid(["app_slug"])
            state = self._new_state(conn, human, cid, "install")
        return {
            "url": f"https://github.com/apps/{slug}/installations/new?{urlencode({'state': state})}"
        }

    def github_setup_callback(self, installation_id: int, state: str) -> str:
        """GitHub's setup URL. ``installation_id`` is spoofable, so it is accepted only with a
        live single-use state minted for this connector, and C3 verifies it with the App JWT."""
        if not 0 < installation_id < 2**53:
            raise Forbidden
        with self._engine.begin() as conn:
            st = self._consume_state(conn, state, "install")
            human = self._state_human(conn, st)
            row = self._row(conn, st.tenant_id, st.connector_id, lock=True)
            cfg = GithubConfig.model_validate(row.config)
            ids = tuple(sorted({*cfg.installation_ids, installation_id}))
            conn.execute(
                update(t.connectors)
                .where(t.connectors.c.connector_id == row.connector_id)
                .values(
                    config=cfg.model_copy(update={"installation_ids": ids}).model_dump(mode="json"),
                    updated_at=func.now(),
                )
            )
            row = self._row(conn, st.tenant_id, st.connector_id)
            self._event(
                conn,
                human,
                "CONNECTOR_UPDATED",
                row,
                ver=row.policy_version,
                digest=canonical_digest(row.config),
            )
        return f"{self.dashboard_url}/integrations/{row.connector_id}?installed=1"


def _action_view(a: Any) -> dict[str, Any]:
    return {
        "name": a.name,
        "description": a.description,  # untrusted for MCP upstreams: the UI escapes it
        "side_effect": a.side_effect,
        "suggested_risk": a.suggested_risk,
        "input_schema": a.input_schema,
    }
