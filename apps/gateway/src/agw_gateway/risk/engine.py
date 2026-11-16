"""Risk engine v2 (ADR-0026): ``evaluate(ctx, policy) -> RiskResult``.

Pure: no I/O, no clock, no randomness, no model calls. Every input is in ``RequestContext``
and the immutable ``RiskPolicy``; the same inputs always give the same result (and the same
canonical bytes, see ``RiskResult.to_record``).

Order (Paper A §5 risk-based evidence selection, 04 §2):

1. Unknown tool -> ``policy.unknown_tool_level`` with ``MR-MISSING-META`` (never scored as
   callable; it is denied by the system checks anyway).
2. Resolve every factor. Missing or unknown -> the factor's WORST value, recorded as
   ``FACTOR_MISSING:<name>``.
3. Mandatory rules, in document order. A condition on a missing factor counts as satisfied,
   so a missing value can never let a rule escape. Rules force DENY / REQUIRE_APPROVAL and/or
   set a level floor.
4. ``score = sum(weight * points)``; thresholds map it to a level.
5. ``level = max(tool base_risk, score level, rule floors)``. Rules only ever raise. A missing
   base_risk counts as CRITICAL (worst), so filling in metadata can never raise the level.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Final, Literal

from agw_gateway.risk.policy import FACTOR_VOCAB, MandatoryRule, RiskPolicy
from agw_gateway.tools.metadata import ToolMetadata

ENGINE_VERSION: Final = "risk-v2"
Forced = Literal["DENY", "REQUIRE_APPROVAL"]


class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


_FORCE_RANK: Final = {"REQUIRE_APPROVAL": 1, "DENY": 2}


# --------------------------------------------------------------------------- inputs
@dataclass(frozen=True)
class RequestContext:
    """Everything the risk engine may look at. Built by :func:`build_context`."""

    tool_known: bool
    tool_id: str
    operation: str | None = None
    tool_sensitivity: str | None = None
    data_classification: str | None = None
    reversible: bool | None = None
    environment: str | None = None
    base_risk: str | None = None
    tags: frozenset[str] = field(default_factory=frozenset)
    # Destination: if the tool declares a destination field, ``destinations`` holds what the
    # args carried (None = the field was absent/unparseable => missing). Otherwise the tool's
    # static ``external_effect`` decides.
    has_destination_field: bool = False
    destinations: tuple[str, ...] | None = None
    external_effect: bool = False
    volume: int | None = 1
    delegation_depth: int | None = 0
    delegation_declared: bool = False
    agent_trust_tier: str | None = None
    scope_present: bool = True


def _volume(args: Mapping[str, Any] | None, field_name: str | None) -> int | None:
    if field_name is None:
        return 1  # the tool acts on one target by construction
    value = (args or {}).get(field_name)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, list | tuple):
        return len(value)
    return None


def _destinations(args: Mapping[str, Any] | None, field_name: str | None) -> tuple[str, ...] | None:
    if field_name is None:
        return None
    value = (args or {}).get(field_name)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list | tuple) and value and all(isinstance(v, str) for v in value):
        return tuple(value)
    return None


def build_context(
    *,
    tool_id: str,
    tool: ToolMetadata | None,
    args: Mapping[str, Any] | None,
    environment: str | None,
    agent_scopes: frozenset[str],
    agent_trust_tier: str | None,
    delegation_depth: int | None = None,
) -> RequestContext:
    """Pure mapping from (tool metadata, validated args, request, agent) to the context.

    ``delegation_depth`` is agent-declared and can only RAISE risk: absent means a direct call
    (depth 0, the gateway authenticated the caller itself).
    """
    if tool is None:
        return RequestContext(
            tool_known=False,
            tool_id=tool_id,
            environment=environment,
            agent_trust_tier=agent_trust_tier,
            scope_present=False,
        )
    return RequestContext(
        tool_known=True,
        tool_id=tool.tool_id,
        operation=tool.operation_type,
        tool_sensitivity=tool.sensitivity,
        data_classification=tool.data_classification,
        reversible=tool.reversible,
        environment=environment,
        base_risk=tool.base_risk,
        tags=tool.tags,
        has_destination_field=tool.destination_field is not None,
        destinations=_destinations(args, tool.destination_field),
        external_effect=tool.external_effect,
        volume=_volume(args, tool.volume_field),
        delegation_depth=0 if delegation_depth is None else delegation_depth,
        delegation_declared=delegation_depth is not None,
        agent_trust_tier=agent_trust_tier,
        scope_present=tool.required_scope in agent_scopes,
    )


# --------------------------------------------------------------------------- outputs
@dataclass(frozen=True)
class FactorValue:
    name: str
    value: str  # vocabulary value or bucket label (never a raw argument value)
    points: int
    weight: int
    missing: bool

    def to_record(self) -> dict[str, Any]:
        rec: dict[str, Any] = {"n": self.name, "v": self.value, "p": self.points, "w": self.weight}
        if self.missing:
            rec["miss"] = True
        return rec


@dataclass(frozen=True)
class RiskResult:
    level: RiskLevel
    score: int
    factor_values: tuple[FactorValue, ...]
    matched_rules: tuple[str, ...]
    reasons: tuple[str, ...]
    policy_id: str
    policy_version: int
    policy_digest: bytes
    forced_effect: Forced | None = None
    forcing_rules: tuple[str, ...] = ()
    control_ids: tuple[str, ...] = ()
    engine_version: str = ENGINE_VERSION

    def to_record(self) -> dict[str, Any]:
        """The POLICY_EVALUATED ``risk`` header map (canonical-CBOR ready)."""
        rec: dict[str, Any] = {
            "level": self.level.name,
            "score": self.score,
            "rules": list(self.matched_rules),
            "cv": self.engine_version,
            "pid": self.policy_id,
            "pver": self.policy_version,
            "pd": self.policy_digest,
            "f": [f.to_record() for f in self.factor_values],
            "reasons": list(self.reasons),
        }
        if self.forced_effect is not None:
            rec["forced"] = self.forced_effect
        return rec


# --------------------------------------------------------------------------- evaluation
def _resolve(ctx: RequestContext, policy: RiskPolicy) -> dict[str, tuple[str, bool]]:
    """factor -> (value, missing). Missing/unknown values become the factor's worst value."""
    external: str | None
    if ctx.has_destination_field:
        if ctx.destinations is None:
            external = None
        else:
            external = (
                "external"
                if any(not _is_internal(d, policy.internal_domains) for d in ctx.destinations)
                else "internal"
            )
    else:
        external = "external" if ctx.external_effect else "internal"
    reversibility = (
        None if ctx.reversible is None else ("reversible" if ctx.reversible else "irreversible")
    )
    raw: dict[str, str | None] = {
        "tool_sensitivity": ctx.tool_sensitivity,
        "operation": ctx.operation,
        "environment": ctx.environment,
        "data_classification": ctx.data_classification,
        "reversibility": reversibility,
        "external_destination": external,
        "agent_trust_tier": ctx.agent_trust_tier,
    }
    out: dict[str, tuple[str, bool]] = {}
    for name, vocab in FACTOR_VOCAB.items():
        value = raw[name]
        out[name] = (value, False) if value in vocab else (vocab[-1], True)
    return out


def _is_internal(destination: str, domains: tuple[str, ...]) -> bool:
    """``user@host`` or ``scheme://host[:port]/...``; anything else is external."""
    d = destination.strip().lower()
    if "://" in d:
        host = d.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    elif d.count("@") == 1:
        host = d.split("@", 1)[1]
    else:
        return False
    return bool(host) and any(host == dom or host.endswith("." + dom) for dom in domains)


def _bucket(policy: RiskPolicy, name: str, value: int | None) -> tuple[str, int, bool]:
    buckets = policy.factors[name].buckets
    assert buckets is not None  # noqa: S101  (guaranteed by RiskPolicy validation)
    if value is None or value < 0:
        return buckets[-1].label, buckets[-1].points, True
    for b in buckets:
        if b.up_to is None or value <= b.up_to:
            return b.label, b.points, False
    raise AssertionError("unreachable: the last bucket is unbounded")  # pragma: no cover


def _matches(
    rule: MandatoryRule,
    ctx: RequestContext,
    cat: dict[str, tuple[str, bool]],
    missing: frozenset[str],
) -> bool:
    w = rule.when
    for name in ("operation", "environment", "tool_sensitivity", "data_classification"):
        allowed = getattr(w, name)
        value, miss = cat[name]
        if allowed is not None and not miss and value not in allowed:
            return False
    if w.agent_trust_tier is not None:
        value, miss = cat["agent_trust_tier"]
        if not miss and value not in w.agent_trust_tier:
            return False
    for flag, name, truthy in (
        (w.external_destination, "external_destination", "external"),
        (w.reversible, "reversibility", "reversible"),
    ):
        value, miss = cat[name]
        if flag is not None and not miss and (value == truthy) != flag:
            return False
    checks = (
        w.tools is None or ctx.tool_id in w.tools,
        w.scope_present is None or ctx.scope_present == w.scope_present,
        w.tags_any is None or bool(ctx.tags & set(w.tags_any)),
        w.min_volume is None or "volume" in missing or (ctx.volume or 0) >= w.min_volume,
        w.min_delegation_depth is None
        or "delegation_depth" in missing
        or (ctx.delegation_depth or 0) >= w.min_delegation_depth,
        w.missing_any is None or bool(missing & set(w.missing_any)),
    )
    return all(checks)


def evaluate(ctx: RequestContext, policy: RiskPolicy) -> RiskResult:
    digest = policy.digest()

    if not ctx.tool_known:
        return RiskResult(
            level=RiskLevel[policy.unknown_tool_level],
            score=0,
            factor_values=(),
            matched_rules=("MR-MISSING-META",),
            reasons=("TOOL_NOT_REGISTERED",),
            policy_id=policy.policy_id,
            policy_version=policy.version,
            policy_digest=digest,
        )

    cat = _resolve(ctx, policy)
    vol_label, vol_pts, vol_miss = _bucket(policy, "volume", ctx.volume)
    dep_label, dep_pts, dep_miss = _bucket(policy, "delegation_depth", ctx.delegation_depth)

    factors: list[FactorValue] = []
    for name in (*FACTOR_VOCAB, "volume", "delegation_depth"):
        spec = policy.factors[name]
        if name == "volume":
            value, points, miss = vol_label, vol_pts, vol_miss
        elif name == "delegation_depth":
            value, points, miss = dep_label, dep_pts, dep_miss
        else:
            value, miss = cat[name]
            assert spec.values is not None  # noqa: S101  (validated)
            points = spec.values[value]
        factors.append(FactorValue(name, value, points, spec.weight, miss))

    missing = {f.name for f in factors if f.missing}
    base_known = ctx.base_risk in RiskLevel.__members__
    if not base_known:
        missing.add("base_risk")
    missing_set = frozenset(missing)

    score = sum(f.points * f.weight for f in factors)
    th = policy.thresholds
    if score >= th.CRITICAL:
        score_level = RiskLevel.CRITICAL
    elif score >= th.HIGH:
        score_level = RiskLevel.HIGH
    elif score >= th.MEDIUM:
        score_level = RiskLevel.MEDIUM
    else:
        score_level = RiskLevel.LOW

    reasons: list[str] = [f"FACTOR_MISSING:{n}" for n in sorted(missing_set)]
    reasons.append(f"SCORE_LEVEL:{score_level.name}")
    levels = [score_level]
    # A missing/unknown base risk is the worst base risk (CRITICAL), like any other factor.
    base = RiskLevel[str(ctx.base_risk)] if base_known else RiskLevel.CRITICAL
    levels.append(base)
    reasons.append(f"BASE_RISK:{base.name}")
    if ctx.delegation_declared:
        reasons.append("DELEGATION_SELF_DECLARED")

    matched: list[str] = []
    forcing: list[str] = []
    forced: Forced | None = None
    controls: list[str] = []
    for rule in policy.mandatory_rules:
        if not _matches(rule, ctx, cat, missing_set):
            continue
        matched.append(rule.rule_id)
        controls.extend(rule.control_ids)
        if rule.floor is not None:
            levels.append(RiskLevel[rule.floor])
            reasons.append(f"RULE_FLOOR:{rule.rule_id}:{rule.floor}")
        if rule.effect is not None:
            forcing.append(rule.rule_id)
            reasons.append(f"RULE_EFFECT:{rule.rule_id}:{rule.effect}")
            if forced is None or _FORCE_RANK[rule.effect] > _FORCE_RANK[forced]:
                forced = rule.effect

    return RiskResult(
        level=max(levels),
        score=score,
        factor_values=tuple(factors),
        matched_rules=tuple(matched),
        reasons=tuple(reasons),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_digest=digest,
        forced_effect=forced,
        forcing_rules=tuple(forcing),
        control_ids=tuple(dict.fromkeys(controls)),
    )
