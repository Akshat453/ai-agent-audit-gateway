"""Plain-English rule descriptions for the console (ADR-0039). Display only; never consulted by a
decision. Exact ids first, then ``*`` suffix patterns (``{suffix}`` is filled in)."""

from __future__ import annotations

import tomllib
from functools import cache
from importlib import resources
from typing import Any, Final

SOURCES: Final = (
    ("agw_gateway.coding", ("policies", "coding-mintrail-descriptions.toml")),
    ("agw_gateway.policies", ("rule_descriptions.toml",)),
)


@cache
def load() -> dict[str, Any]:
    """``{"rules": {id: {name, why}}, "patterns": {prefix*: {name, why}}, "policies": [...]}``."""
    rules: dict[str, dict[str, str]] = {}
    patterns: dict[str, dict[str, str]] = {}
    policies: list[dict[str, Any]] = []
    for package, parts in SOURCES:
        doc = tomllib.loads(resources.files(package).joinpath(*parts).read_text("utf-8"))
        for section, target in (("rules", rules), ("patterns", patterns)):
            for rid, entry in doc.get(section, {}).items():
                if rid in target:
                    raise ValueError(f"duplicate rule description: {rid}")
                target[rid] = {"name": str(entry["name"]), "why": str(entry["why"])}
        if "policy_id" in doc:
            versions = list(doc.get("applies_to_versions", []))
            policies.append({"policy_id": doc["policy_id"], "versions": versions})
    return {"rules": rules, "patterns": patterns, "policies": policies}


def describe(rule_id: str) -> dict[str, str] | None:
    d = load()
    if rule_id in d["rules"]:
        return dict(d["rules"][rule_id])
    for pat, entry in d["patterns"].items():
        prefix = pat.rstrip("*")
        if pat.endswith("*") and rule_id.startswith(prefix):
            suffix = rule_id[len(prefix) :]
            return {"name": entry["name"], "why": entry["why"].replace("{suffix}", suffix)}
    return None
