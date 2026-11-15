"""AGW-EVT v1 event headers and AGW-PAY v1 payloads (docs/gateway/05 §4-5, ADR-0023).

Headers are structural and non-sensitive; they go into the hash chain. Payloads hold the
sensitive content (args, params, results, error text) and are committed to by
``header.payload.digest`` (06 §5). Paper B's eight evidence fields map as follows:

=====================  =============================================================
intent                 ACTION_REQUESTED payload ``intent`` (validated or raw args, summary)
policy evaluation      POLICY_EVALUATED header ``policy`` + ``risk``
human approval         APPROVAL_* header ``approval`` (models only; populated later)
execution              ACTION_DISPATCHED payload ``execution.params``
effects                ACTION_COMPLETED / FAILED / OUTCOME_UNKNOWN payload ``effects``
context provenance     ACTION_REQUESTED payload ``context`` (sources + digests) + header ``env``
code provenance        header ``code`` {gw commit, adapter@version, agent-declared version}
delegation provenance  ACTION_REQUESTED payload ``delegation`` (present, null until later)
=====================  =============================================================

No chain-of-thought or agent "reasoning" field exists anywhere, by design (Paper B §III-B).
Header keys use the short 05 §4 names: ``prev`` = prev_event_hash, ``ts`` = recorded_at,
``obs`` = observed_at, ``dispatch.cg`` = concurrency_group, ``payload.ref`` = payload_ref.
"""

from __future__ import annotations

from typing import Annotated, Any, ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION: Final = 1

UInt = Annotated[int, Field(ge=0, le=2**64 - 1)]
Bytes16 = Annotated[bytes, Field(min_length=16, max_length=16)]
Bytes32 = Annotated[bytes, Field(min_length=32, max_length=32)]
Text = Annotated[str, Field(max_length=1024)]
TenantId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
EventClass = Literal["A2S", "A2A", "A2H", "SYS"]
RiskLevelName = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)


# --------------------------------------------------------------------------- header parts
class Actor(_M):
    kind: Literal["agent", "human", "gateway", "system"]
    id: Text


class ToolRef(_M):
    id: Annotated[str, Field(max_length=128)]
    ver: Annotated[str, Field(max_length=32)] | None = None


class Risk(_M):
    level: RiskLevelName
    score: UInt
    rules: list[Text]
    cv: Text


class PolicyEvaluation(_M):
    id: Text
    ver: UInt
    effect: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    rules: list[Text]
    reasons: list[Text]
    controls: list[Text]
    ev: Text


class Approval(_M):
    """Human approval (Paper B field 3). Model only until the approval phase."""

    id: Bytes16
    binding: Bytes32
    approver: Text
    exp: UInt


class Dispatch(_M):
    attempt: UInt
    worker: Text
    cg: Text | None = None  # concurrency group: actions claimed/dispatched together


class Outcome(_M):
    status: Literal["DENIED", "PENDING_APPROVAL", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN"]
    code: Text | None = None


class PayloadRef(_M):
    digest: Bytes32
    len: UInt
    ref: Literal["inline"] = "inline"  # where the payload lives; "blob" arrives with MinIO


class Code(_M):
    """Code provenance (Paper B field 7)."""

    gw: Text  # gateway build: git commit (+dirty) or "unknown"
    adapter: Text | None = None  # "<adapter class>@<tool version>"
    agent: Text | None = None  # agent-declared version (unauthenticated claim)


class Violation(_M):
    kind: Literal["AGENT_ID_MISMATCH"]
    claimed: Annotated[str, Field(max_length=128)]


# --------------------------------------------------------------------------- headers
class EventHeader(_M):
    """Common AGW-EVT v1 header. Subclasses pin ``type`` and require their fields."""

    TYPE: ClassVar[str] = ""
    CLASS: ClassVar[EventClass] = "SYS"
    REQUIRED: ClassVar[tuple[str, ...]] = ()

    v: Literal[1] = 1
    tenant: TenantId
    seq: UInt
    prev: Bytes32
    id: Bytes16
    type: str
    ts: UInt  # recorded_at, µs since Unix epoch UTC (informational, not an ordering source)
    class_: EventClass = Field(alias="class")
    actor: Actor
    action: Bytes16 | None = None
    run: Bytes16 | None = None
    tool: ToolRef | None = None
    env: Literal["dev", "staging", "prod"] | None = None
    risk: Risk | None = None
    policy: PolicyEvaluation | None = None
    approval: Approval | None = None
    args: Bytes32 | None = None  # canonical args digest (06 §3)
    dispatch: Dispatch | None = None
    outcome: Outcome | None = None
    payload: PayloadRef | None = None
    code: Code | None = None
    violation: Violation | None = None
    obs: UInt | None = None  # observed_at, µs: when the executor/reconciler observed it

    def model_post_init(self, _context: Any) -> None:
        if self.TYPE and self.type != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        if self.TYPE and self.class_ != self.CLASS:
            raise ValueError(f"class must be {self.CLASS}")
        missing = [f for f in self.REQUIRED if getattr(self, f) is None]
        if missing:
            raise ValueError(f"{self.type} requires {missing}")

    def to_record(self) -> dict[str, Any]:
        """CBOR-ready map: absent optional fields are omitted, never null (05 §4)."""
        return self.model_dump(mode="python", by_alias=True, exclude_none=True)


def _header(name: str, cls: EventClass, required: tuple[str, ...]) -> type[EventHeader]:
    return type(
        "".join(p.capitalize() for p in name.lower().split("_")),
        (EventHeader,),
        {"TYPE": name, "CLASS": cls, "REQUIRED": required, "__module__": __name__},
    )


ActionRequested = _header("ACTION_REQUESTED", "A2S", ("action", "run", "tool", "env", "payload"))
PolicyEvaluated = _header("POLICY_EVALUATED", "SYS", ("action", "risk", "policy"))
ActionDenied = _header("ACTION_DENIED", "SYS", ("action", "outcome"))
ApprovalRequired = _header("APPROVAL_REQUIRED", "A2H", ("action", "outcome"))
ApprovalGranted = _header("APPROVAL_GRANTED", "A2H", ("action", "approval"))
ApprovalDenied = _header("APPROVAL_DENIED", "A2H", ("action", "approval"))
ApprovalExpired = _header("APPROVAL_EXPIRED", "A2H", ("action", "approval"))
ActionAuthorized = _header("ACTION_AUTHORIZED", "SYS", ("action", "tool", "code", "args"))
ActionDispatched = _header(
    "ACTION_DISPATCHED", "A2S", ("action", "tool", "dispatch", "args", "payload", "obs")
)
ActionCompleted = _header("ACTION_COMPLETED", "A2S", ("action", "outcome", "payload", "obs"))
ActionFailed = _header("ACTION_FAILED", "A2S", ("action", "outcome", "payload", "obs"))
ActionOutcomeUnknown = _header(
    "ACTION_OUTCOME_UNKNOWN", "SYS", ("action", "outcome", "payload", "obs")
)
SecurityViolation = _header("SECURITY_VIOLATION", "SYS", ("violation",))

HEADER_MODELS: Final[dict[str, type[EventHeader]]] = {
    m.TYPE: m
    for m in (
        ActionRequested,
        PolicyEvaluated,
        ActionDenied,
        ApprovalRequired,
        ApprovalGranted,
        ApprovalDenied,
        ApprovalExpired,
        ActionAuthorized,
        ActionDispatched,
        ActionCompleted,
        ActionFailed,
        ActionOutcomeUnknown,
        SecurityViolation,
    )
}
# APPROVAL_GRANTED/DENIED/EXPIRED are models only until the approval phase.
MODEL_ONLY_TYPES: Final = frozenset({"APPROVAL_GRANTED", "APPROVAL_DENIED", "APPROVAL_EXPIRED"})


def parse_header(record: dict[str, Any]) -> EventHeader:
    """Validate a decoded record against its type's model (unknown keys rejected)."""
    model = HEADER_MODELS.get(str(record.get("type")))
    if model is None:
        raise ValueError("unknown event type")
    return model.model_validate(record)


# --------------------------------------------------------------------------- payloads
class ContextSource(_M):
    uri: Annotated[str, Field(max_length=2048)]
    digest: Bytes32


class Payload(_M):
    """AGW-PAY v1 (05 §5). Plaintext CBOR; encrypted at rest in a later phase."""

    v: Literal[1] = 1
    salt: Bytes32  # fresh CSPRNG bytes: makes payload.digest hiding (ADR-0013)
    event: Bytes16  # the event this payload belongs to (prevents re-attachment)
    intent: dict[str, Any] | None = None  # {"args": map} | {"args_json": text}; "summary"
    execution: dict[str, Any] | None = None  # {"params": exact adapter input}
    effects: dict[str, Any] | None = None  # {"result": ...} | {"result_json": ...}, "error"
    context: dict[str, Any] | None = None  # {"sources": [{uri, digest}]}
    approval: dict[str, Any] | None = None  # {"prompt", "comment"} (later)
    delegation: dict[str, Any] | None = None  # {"from", "parent", "scope"} (later)

    def to_record(self, *, delegation_present: bool = False) -> dict[str, Any]:
        record = self.model_dump(mode="python", exclude_none=True)
        if delegation_present:
            record["delegation"] = None  # Paper B field 8: present, null until delegation exists
        return record
