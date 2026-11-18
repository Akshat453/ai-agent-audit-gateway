"""Repositories and their tighten-only ``.agentguard.yaml`` (C2, ADR-0035 §7).

``agw init`` registers a repository and sends its ``.agentguard.yaml`` TEXT (the CLI has no
YAML parser). The gateway parses it (``yaml.safe_load``, 64 KiB cap) and splits it:

* **tightening** (new ``sensitive_paths``, a higher level for one, new ``deny_paths`` or
  ``deny_commands``) is applied at once as a new, append-only repo policy version;
* **loosening** (``allow_paths``, ``allow_commands``, removing or downgrading an earlier
  tightening) is IGNORED, reported back, and becomes a proposal an admin approves or rejects
  in the dashboard (step-up required). Unknown keys are ignored and reported.

Every applied change writes REPO_POLICY_CHANGED. The coding policy for a session in that
repository is the base policy with the overlay (``CodingPolicy.with_overlay``); the overlay's
digest is folded into the decision's policy digest, so approvals do not survive a change.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID

import yaml
from sqlalchemy import Connection, Engine, func, insert, select, update

from agw_gateway.coding.digest import repo_digest
from agw_gateway.coding.globs import PathInvalid, normalize_path
from agw_gateway.coding.service import Device
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.errors import Forbidden, NotFound, RequestInvalid, StepUpRequired
from agw_gateway.humans.models import AuthenticatedHuman
from agw_gateway.ids import uuid7

MAX_YAML: Final = 64 * 1024
KNOWN_KEYS: Final = frozenset(
    {"version", "sensitive_paths", "deny_paths", "deny_commands", "allow_paths", "allow_commands"}
)
LEVELS: Final = ("high", "critical")
OWNERS: Final = frozenset({"maintainer", "ledger_lead", "security"})
EMPTY: Final[dict[str, list[Any]]] = {
    "sensitive": [],
    "deny_paths": [],
    "deny_commands": [],
    "allow_paths": [],
    "allow_commands": [],
}


def overlay_digest(overlay: Mapping[str, Any]) -> bytes:
    raw = json.dumps(overlay, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(b"AGW/repo-overlay/v1\x00" + raw.encode()).digest()


def _glob(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > 512 or raw.startswith(("/", "~")):
        return None
    try:
        norm = normalize_path(raw, None)
    except PathInvalid:
        return None
    return None if norm.startswith("/") else raw  # no escaping the repository


def _command(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 200 or "\n" in raw:
        return None
    return " ".join(raw.split())


def parse(text: str) -> tuple[dict[str, Any], list[str]]:
    """The file as a normalized request ``{sensitive, deny_paths, deny_commands, allow_paths,
    allow_commands}`` plus a list of problems (unknown keys, invalid entries)."""
    problems: list[str] = []
    if len(text.encode()) > MAX_YAML:
        return dict(EMPTY), ["file too large (64 KiB max)"]
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return dict(EMPTY), ["not valid YAML"]
    if not isinstance(doc, dict):
        return dict(EMPTY), ["top level must be a mapping"]
    for key in sorted(set(map(str, doc)) - KNOWN_KEYS):
        problems.append(f"unknown key ignored: {key}")
    out: dict[str, Any] = {k: [] for k in EMPTY}
    for raw_item in doc.get("sensitive_paths") or []:
        item = {"path": raw_item} if isinstance(raw_item, str) else raw_item
        path = _glob(item.get("path")) if isinstance(item, dict) else None
        level = str(item.get("level", "high")).lower() if isinstance(item, dict) else ""
        owner = item.get("owner") if isinstance(item, dict) else None
        if path is None or level not in LEVELS or (owner is not None and owner not in OWNERS):
            problems.append("invalid sensitive_paths entry ignored")
            continue
        entry = {"path": path, "level": level}
        if owner:
            entry["owner"] = owner
        out["sensitive"].append(entry)
    for key, norm in (
        ("deny_paths", _glob),
        ("allow_paths", _glob),
        ("deny_commands", _command),
        ("allow_commands", _command),
    ):
        for raw in doc.get(key) or []:
            value = norm(raw)
            if value is None:
                problems.append(f"invalid {key} entry ignored")
            elif value not in out[key]:
                out[key].append(value)
    return out, problems


def split(
    current: Mapping[str, Any], wanted: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(the new overlay with every TIGHTENING applied, the LOOSENING items as proposals)."""
    new = {k: list(current.get(k, [])) for k in EMPTY}
    loosen: list[dict[str, Any]] = []
    cur_sens = {s["path"]: s for s in current.get("sensitive", [])}
    want_sens = {s["path"]: s for s in wanted.get("sensitive", [])}
    for path, s in want_sens.items():
        old = cur_sens.get(path)
        if old is None:
            new["sensitive"].append(s)
        elif LEVELS.index(s["level"]) > LEVELS.index(old["level"]):
            new["sensitive"] = [x for x in new["sensitive"] if x["path"] != path] + [s]
        elif LEVELS.index(s["level"]) < LEVELS.index(old["level"]):
            loosen.append({"op": "downgrade_sensitive", "path": path, "level": s["level"]})
    for path in cur_sens.keys() - want_sens.keys():
        loosen.append({"op": "remove_sensitive", "path": path})
    for key in ("deny_paths", "deny_commands"):
        for v in wanted.get(key, []):
            if v not in new[key]:
                new[key].append(v)
        for v in set(current.get(key, [])) - set(wanted.get(key, [])):
            loosen.append({"op": f"remove_{key[:-1]}", "value": v})
    for key in ("allow_paths", "allow_commands"):
        for v in wanted.get(key, []):
            if v not in current.get(key, []):
                loosen.append({"op": f"add_{key[:-1]}", "value": v})
    return new, loosen


def apply_loosening(current: Mapping[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    new = {k: list(current.get(k, [])) for k in EMPTY}
    for it in items:
        op = it["op"]
        if op == "remove_sensitive":
            new["sensitive"] = [s for s in new["sensitive"] if s["path"] != it["path"]]
        elif op == "downgrade_sensitive":
            new["sensitive"] = [
                {**s, "level": it["level"]} if s["path"] == it["path"] else s
                for s in new["sensitive"]
            ]
        elif op in ("remove_deny_path", "remove_deny_command"):
            key = "deny_paths" if op == "remove_deny_path" else "deny_commands"
            new[key] = [v for v in new[key] if v != it["value"]]
        elif op in ("add_allow_path", "add_allow_command"):
            key = "allow_paths" if op == "add_allow_path" else "allow_commands"
            if it["value"] not in new[key]:
                new[key].append(it["value"])
    return new


class RepoService:
    def __init__(self, *, engine: Engine, writer: EvidenceWriter, step_up_window_seconds: int):
        self._engine = engine
        self._writer = writer
        self._window = step_up_window_seconds

    def overlay_for(
        self, tenant: str, digest: bytes | None
    ) -> tuple[dict[str, Any], int, bytes] | None:
        if digest is None:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                select(
                    t.repo_policies.c.overlay, t.repo_policies.c.version, t.repo_policies.c.digest
                )
                .join(t.repos, t.repos.c.repo_id == t.repo_policies.c.repo_id)
                .where(
                    t.repos.c.tenant_id == tenant,
                    t.repos.c.remote_digest == digest,
                    t.repo_policies.c.version == t.repos.c.policy_version,
                )
            ).one_or_none()
        return (dict(row.overlay), int(row.version), bytes(row.digest)) if row else None

    @staticmethod
    def _current(conn: Connection, repo_id: UUID) -> tuple[dict[str, Any], int]:
        row = conn.execute(
            select(t.repo_policies.c.overlay, t.repo_policies.c.version)
            .where(t.repo_policies.c.repo_id == repo_id)
            .order_by(t.repo_policies.c.version.desc())
            .limit(1)
        ).one_or_none()
        return (dict(row.overlay), int(row.version)) if row else (dict(EMPTY), 0)

    def _new_version(
        self,
        conn: Connection,
        repo: Any,
        overlay: dict[str, Any],
        source: str,
        actor_kind: str,
        actor_id: str,
        decision: str,
    ) -> int:
        _cur, version = self._current(conn, repo.repo_id)
        version += 1
        digest = overlay_digest(overlay)
        conn.execute(
            insert(t.repo_policies).values(
                repo_id=repo.repo_id, version=version, overlay=overlay, digest=digest, source=source
            )
        )
        conn.execute(
            update(t.repos)
            .where(t.repos.c.repo_id == repo.repo_id)
            .values(policy_version=version, updated_at=func.now())
        )
        self._writer.append(
            conn,
            repo.tenant_id,
            [
                NewEvent(
                    type="REPO_POLICY_CHANGED",
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    fields={
                        "repo": {
                            "id": repo.repo_id.bytes,
                            "ver": version,
                            "digest": digest,
                            "decision": decision,
                        }
                    },
                    risk_level="HIGH",
                )
            ],
        )
        return version

    # ------------------------------------------------------------------ device side
    def register(self, device: Device, body: Mapping[str, Any]) -> dict[str, Any]:
        url = body.get("remote_url")
        if not isinstance(url, str) or not 1 <= len(url) <= 2048:
            raise RequestInvalid(["remote_url"])
        name = str(body.get("name") or url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))[
            :200
        ]
        raw_agents = body.get("agents")
        agents: dict[str, Any] = {
            str(k)[:32]: v
            for k, v in (list(raw_agents.items())[:20] if isinstance(raw_agents, dict) else [])
            if isinstance(v, dict)
        }
        yaml_text = body.get("agentguard_yaml")
        if yaml_text is not None and not isinstance(yaml_text, str):
            raise RequestInvalid(["agentguard_yaml"])
        digest = repo_digest(url)
        agent = device.agent
        applied: list[Any] = []
        ignored: list[Any] = []
        proposal_id: str | None = None
        with self._engine.begin() as conn:
            repo = conn.execute(
                select(t.repos)
                .where(t.repos.c.tenant_id == agent.tenant_id, t.repos.c.remote_digest == digest)
                .with_for_update()
            ).one_or_none()
            if repo is None:
                conn.execute(
                    insert(t.repos).values(
                        repo_id=uuid7(),
                        tenant_id=agent.tenant_id,
                        remote_digest=digest,
                        remote_url=url,
                        name=name,
                        registered_by=agent.agent_id,
                        agents=agents,
                    )
                )
            else:
                conn.execute(
                    update(t.repos)
                    .where(t.repos.c.repo_id == repo.repo_id)
                    .values(agents={**repo.agents, **agents}, updated_at=func.now())
                )
            repo = conn.execute(
                select(t.repos).where(
                    t.repos.c.tenant_id == agent.tenant_id, t.repos.c.remote_digest == digest
                )
            ).one()
            if yaml_text is not None:
                wanted, problems = parse(yaml_text)
                ignored.extend({"problem": p} for p in problems)
                current, _v = self._current(conn, repo.repo_id)
                new, loosen = split(current, wanted)
                if new != {k: list(current.get(k, [])) for k in EMPTY}:
                    self._new_version(
                        conn,
                        repo,
                        new,
                        "agentguard_yaml",
                        "agent",
                        str(agent.agent_id),
                        "TIGHTENED",
                    )
                    applied = [
                        x
                        for k in ("sensitive", "deny_paths", "deny_commands")
                        for x in new[k]
                        if x not in current.get(k, [])
                    ]
                if loosen:
                    ignored.extend(loosen)
                    pending = conn.execute(
                        select(t.repo_proposals.c.proposal_id, t.repo_proposals.c["items"]).where(
                            t.repo_proposals.c.repo_id == repo.repo_id,
                            t.repo_proposals.c.status == "pending",
                        )
                    ).all()
                    same = next((p for p in pending if p.items == loosen), None)
                    if same is not None:
                        proposal_id = str(same.proposal_id)
                    else:
                        pid = uuid7()
                        conn.execute(
                            insert(t.repo_proposals).values(
                                proposal_id=pid,
                                repo_id=repo.repo_id,
                                tenant_id=agent.tenant_id,
                                items=loosen,
                                status="pending",
                            )
                        )
                        proposal_id = str(pid)
            repo = conn.execute(select(t.repos).where(t.repos.c.repo_id == repo.repo_id)).one()
        return {
            "repo_id": str(repo.repo_id),
            "name": repo.name,
            "policy_version": repo.policy_version,
            "applied": applied,
            "ignored": ignored,
            "proposal_id": proposal_id,
        }

    def status(self, device: Device, remote_url: str) -> dict[str, Any]:
        with self._engine.connect() as conn:
            repo = conn.execute(
                select(t.repos).where(
                    t.repos.c.tenant_id == device.agent.tenant_id,
                    t.repos.c.remote_digest == repo_digest(remote_url),
                )
            ).one_or_none()
            if repo is None:
                raise NotFound
            pending = conn.execute(
                select(func.count())
                .select_from(t.repo_proposals)
                .where(
                    t.repo_proposals.c.repo_id == repo.repo_id,
                    t.repo_proposals.c.status == "pending",
                )
            ).scalar_one()
        return {
            "repo_id": str(repo.repo_id),
            "name": repo.name,
            "policy_version": repo.policy_version,
            "agents": repo.agents,
            "pending_proposals": int(pending),
        }

    # ------------------------------------------------------------------ admin side
    def _admin(self, human: AuthenticatedHuman) -> None:
        if not human.has("admin"):
            raise Forbidden
        if human.stepped_up_age_seconds is None or human.stepped_up_age_seconds > self._window:
            raise StepUpRequired

    def list_repos(self, human: AuthenticatedHuman) -> list[dict[str, Any]]:
        if not (human.roles & {"admin", "auditor", "security", "maintainer"}):
            raise Forbidden
        with self._engine.connect() as conn:
            repos = conn.execute(
                select(t.repos)
                .where(t.repos.c.tenant_id == human.tenant_id)
                .order_by(t.repos.c.created_at)
            ).all()
            out = []
            for r in repos:
                overlay, _v = self._current(conn, r.repo_id)
                props = conn.execute(
                    select(t.repo_proposals)
                    .where(
                        t.repo_proposals.c.repo_id == r.repo_id,
                        t.repo_proposals.c.status == "pending",
                    )
                    .order_by(t.repo_proposals.c.created_at)
                ).all()
                out.append(
                    {
                        "repo_id": str(r.repo_id),
                        "name": r.name,
                        "remote_url": r.remote_url,
                        "policy_version": r.policy_version,
                        "agents": r.agents,
                        "overlay": overlay,
                        "proposals": [self._proposal(p, overlay) for p in props],
                    }
                )
        return out

    @staticmethod
    def _proposal(p: Any, current: Mapping[str, Any]) -> dict[str, Any]:
        after = apply_loosening(current, list(p.items))
        before_txt = json.dumps(current, indent=2, sort_keys=True).splitlines()
        after_txt = json.dumps(after, indent=2, sort_keys=True).splitlines()
        diff = "\n".join(
            difflib.unified_diff(before_txt, after_txt, "current", "proposed", lineterm="")
        )
        return {
            "proposal_id": str(p.proposal_id),
            "items": p.items,
            "status": p.status,
            "diff": diff,
            "created_at": p.created_at.isoformat().replace("+00:00", "Z"),
        }

    def decide(
        self, human: AuthenticatedHuman, proposal_id: UUID, approve: bool, reason: str
    ) -> dict[str, Any]:
        self._admin(human)
        with self._engine.begin() as conn:
            p = conn.execute(
                select(t.repo_proposals)
                .where(
                    t.repo_proposals.c.proposal_id == proposal_id,
                    t.repo_proposals.c.tenant_id == human.tenant_id,
                )
                .with_for_update()
            ).one_or_none()
            if p is None:
                raise NotFound
            if p.status != "pending":
                raise Forbidden
            repo = conn.execute(select(t.repos).where(t.repos.c.repo_id == p.repo_id)).one()
            conn.execute(
                update(t.repo_proposals)
                .where(t.repo_proposals.c.proposal_id == proposal_id)
                .values(
                    status="approved" if approve else "rejected",
                    decided_by=human.human_id,
                    decided_at=func.now(),
                    reason=reason[:1000],
                )
            )
            current, version = self._current(conn, repo.repo_id)
            if approve:
                version = self._new_version(
                    conn,
                    repo,
                    apply_loosening(current, list(p.items)),
                    "proposal",
                    "human",
                    str(human.human_id),
                    "PROPOSAL_APPROVED",
                )
            else:
                self._writer.append(
                    conn,
                    repo.tenant_id,
                    [
                        NewEvent(
                            type="REPO_POLICY_CHANGED",
                            actor_kind="human",
                            actor_id=str(human.human_id),
                            fields={
                                "repo": {
                                    "id": repo.repo_id.bytes,
                                    "ver": version,
                                    "digest": overlay_digest(current),
                                    "decision": "PROPOSAL_REJECTED",
                                }
                            },
                            risk_level="HIGH",
                        )
                    ],
                )
        return {"status": "approved" if approve else "rejected", "policy_version": version}
