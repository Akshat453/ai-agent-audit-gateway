"""Risk policy document (ADR-0026): TOML file -> strict Pydantic model -> canonical bytes + digest.

A risk policy is data, not code. It holds:

* ``factors``: every factor of :data:`FACTOR_VOCAB` with an integer ``weight`` and either
  categorical ``values`` (points per value) or numeric ``buckets``. Points must not decrease
  along the factor's risk order, so the last value/bucket is the worst one: a missing or
  unknown factor is scored at that worst value.
* ``thresholds``: minimum score for MEDIUM / HIGH / CRITICAL (LOW below MEDIUM).
* ``mandatory_rules``: evaluated before the score is used; each can force DENY, force
  REQUIRE_APPROVAL and/or set a level floor, and carries GRC ``control_ids`` (Paper A §5).
* ``internal_domains``: destinations under these domains are "internal", everything else
  (including anything unparseable) is "external".

Loading fails closed: unknown keys, floats, a missing factor, a missing vocabulary value,
decreasing points or an empty rule condition all reject the document.

The stored, authoritative form is AGW-CBOR-v1 of the validated model (``canonical_bytes``);
``digest = SHA-256(TAG("AGW/risk-policy/v1") || canonical_bytes)`` goes into every
POLICY_EVALUATED event. Whitespace or key order in the TOML file never changes the digest.
"""

from __future__ import annotations

import hashlib
import tomllib
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agw_gateway.crypto.canonical import decode, encode, profile_value
from agw_gateway.crypto.tags import RISK_POLICY_TAG, domain_tag

LevelName = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Forced = Literal["DENY", "REQUIRE_APPROVAL"]
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
Points = Annotated[int, Field(ge=0, le=1000)]

#: Categorical factors and their values in increasing risk order.
FACTOR_VOCAB: Final[dict[str, tuple[str, ...]]] = {
    "tool_sensitivity": ("public", "internal", "confidential", "restricted"),
    "operation": ("read", "create", "update", "delete", "execute"),
    "environment": ("dev", "staging", "prod"),
    "data_classification": ("public", "internal", "confidential", "secret", "pii"),
    "reversibility": ("reversible", "irreversible"),
    "external_destination": ("internal", "external"),
    "agent_trust_tier": ("trusted", "standard", "untrusted"),
}
#: Numeric factors (bucketed).
NUMERIC_FACTORS: Final = ("volume", "delegation_depth")
FACTOR_NAMES: Final = (*FACTOR_VOCAB, *NUMERIC_FACTORS)
#: Names usable in ``when.missing_any`` (the factors plus the tool's declared base risk).
MISSING_NAMES: Final = frozenset({*FACTOR_NAMES, "base_risk"})

_DIGEST_PREFIX: Final = domain_tag(RISK_POLICY_TAG)
_WHEN_LISTS: Final = (
    "operation",
    "environment",
    "tool_sensitivity",
    "data_classification",
    "agent_trust_tier",
)


class RiskPolicyLoadError(ValueError):
    """The risk policy is invalid. The gateway must not evaluate with it (fail closed)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Bucket(_Strict):
    label: str = Field(pattern=r"^[a-z0-9_]{1,32}$")
    up_to: int | None = Field(default=None, ge=0)  # inclusive upper bound; None = unbounded
    points: Points


class Factor(_Strict):
    weight: Annotated[int, Field(ge=0, le=100)]
    values: dict[str, Points] | None = None
    buckets: tuple[Bucket, ...] | None = None


class When(_Strict):
    """All present conditions must hold; omitted = wildcard. A condition on a factor whose
    value is missing counts as satisfied (unknown could be anything: fail toward risk)."""

    tools: tuple[str, ...] | None = None
    operation: tuple[str, ...] | None = None
    environment: tuple[str, ...] | None = None
    tool_sensitivity: tuple[str, ...] | None = None
    data_classification: tuple[str, ...] | None = None
    agent_trust_tier: tuple[str, ...] | None = None
    external_destination: bool | None = None
    reversible: bool | None = None
    scope_present: bool | None = None
    tags_any: tuple[str, ...] | None = None
    min_volume: int | None = Field(default=None, ge=0)
    min_delegation_depth: int | None = Field(default=None, ge=0)
    missing_any: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def _check(self) -> When:
        if not any(v is not None for v in self.__dict__.values()):
            raise ValueError("a mandatory rule needs at least one condition")
        for name in _WHEN_LISTS:
            allowed = getattr(self, name)
            if allowed is not None and not set(allowed) <= set(FACTOR_VOCAB[name]):
                raise ValueError(f"unknown value in when.{name}")
        if self.missing_any is not None and not set(self.missing_any) <= MISSING_NAMES:
            raise ValueError("unknown factor in when.missing_any")
        return self


class MandatoryRule(_Strict):
    rule_id: str = Field(pattern=_ID)
    description: str = Field(default="", max_length=512)
    when: When
    floor: LevelName | None = None
    effect: Forced | None = None
    control_ids: tuple[Annotated[str, Field(pattern=_ID)], ...] = ()

    @model_validator(mode="after")
    def _does_something(self) -> MandatoryRule:
        if self.floor is None and self.effect is None:
            raise ValueError("a mandatory rule must set a floor and/or an effect")
        return self


class Thresholds(_Strict):
    MEDIUM: Points
    HIGH: Points
    CRITICAL: Points

    @model_validator(mode="after")
    def _ascending(self) -> Thresholds:
        if not 0 < self.MEDIUM < self.HIGH < self.CRITICAL:
            raise ValueError("thresholds must satisfy 0 < MEDIUM < HIGH < CRITICAL")
        return self


class RiskPolicy(_Strict):
    policy_id: str = Field(pattern=_ID)
    version: int = Field(ge=1)
    description: str = Field(default="", max_length=1024)
    unknown_tool_level: LevelName = "HIGH"
    internal_domains: tuple[Annotated[str, Field(pattern=r"^[a-z0-9.-]{1,253}$")], ...] = ()
    factors: dict[str, Factor]
    thresholds: Thresholds
    mandatory_rules: tuple[MandatoryRule, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> RiskPolicy:
        if set(self.factors) != set(FACTOR_NAMES):
            raise ValueError("factors must be exactly: " + ", ".join(FACTOR_NAMES))
        for name, vocab in FACTOR_VOCAB.items():
            f = self.factors[name]
            if f.values is None or f.buckets is not None or set(f.values) != set(vocab):
                raise ValueError(f"factor {name} needs values for exactly {list(vocab)}")
            pts = [f.values[v] for v in vocab]
            if pts != sorted(pts):
                raise ValueError(f"factor {name}: points must not decrease along {vocab}")
        for name in NUMERIC_FACTORS:
            f = self.factors[name]
            if f.buckets is None or f.values is not None or not f.buckets:
                raise ValueError(f"factor {name} needs buckets")
            bounds = [b.up_to for b in f.buckets]
            if bounds[-1] is not None or any(b is None for b in bounds[:-1]):
                raise ValueError(f"factor {name}: only the last bucket may be unbounded")
            finite = [b for b in bounds[:-1] if b is not None]
            if finite != sorted(set(finite)):
                raise ValueError(f"factor {name}: bucket bounds must strictly increase")
            pts = [b.points for b in f.buckets]
            if pts != sorted(pts):
                raise ValueError(f"factor {name}: bucket points must not decrease")
        ids = [r.rule_id for r in self.mandatory_rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id")
        return self

    # ------------------------------------------------------------------ identity
    def canonical_bytes(self) -> bytes:
        """AGW-CBOR-v1 of the validated document (None fields omitted). Authoritative form."""
        return encode(profile_value(self.model_dump(mode="python", exclude_none=True)))

    def digest(self) -> bytes:
        return hashlib.sha256(_DIGEST_PREFIX + self.canonical_bytes()).digest()


def _load(data: Any) -> RiskPolicy:
    try:
        return RiskPolicy.model_validate(data)
    except ValidationError as exc:
        locs = sorted({".".join(str(p) for p in e["loc"]) or "<root>" for e in exc.errors()})
        raise RiskPolicyLoadError("invalid risk policy at: " + ", ".join(locs)) from None


def _tuples(value: Any) -> Any:
    """TOML arrays arrive as lists; the strict model wants tuples."""
    if isinstance(value, dict):
        return {k: _tuples(v) for k, v in value.items()}
    if isinstance(value, list):
        return tuple(_tuples(v) for v in value)
    return value


def load_risk_policy_toml(text: str) -> RiskPolicy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise RiskPolicyLoadError("risk policy is not valid TOML") from None
    return _load(_tuples(data))


def load_risk_policy_canonical(canonical: bytes, expected_digest: bytes) -> RiskPolicy:
    """Rebuild a stored policy and re-check that its stored bytes hash to the stored digest."""
    if hashlib.sha256(_DIGEST_PREFIX + canonical).digest() != expected_digest:
        raise RiskPolicyLoadError("stored risk policy bytes do not match the stored digest")
    policy = _load(_tuples(decode(canonical)))
    if policy.canonical_bytes() != canonical:
        raise RiskPolicyLoadError("stored risk policy bytes are not the canonical encoding")
    return policy
