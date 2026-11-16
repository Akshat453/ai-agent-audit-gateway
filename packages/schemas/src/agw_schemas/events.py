"""AGW-EVT v1 event headers and AGW-PAY v1 payloads (docs/gateway/05 §4-5, ADR-0023).

Headers are structural and non-sensitive; they go into the hash chain. Payloads hold the
sensitive content (args, params, results, error text) and are committed to by
``header.payload.digest`` (06 §5). Paper B's eight evidence fields map as follows:

=====================  =============================================================
intent                 ACTION_REQUESTED payload ``intent`` (validated or raw args, summary)
policy evaluation      POLICY_EVALUATED header ``policy`` + ``risk``
human approval         APPROVAL_* + ACTION_AUTHORIZED header ``approval`` (Phase 5, ADR-0027)
execution              ACTION_DISPATCHED payload ``execution.params``
effects                ACTION_COMPLETED / FAILED / OUTCOME_UNKNOWN payload ``effects``
context provenance     ACTION_REQUESTED payload ``context`` (sources + digests) + header ``env``
code provenance        header ``code`` {gw commit, adapter@version, agent-declared version}
delegation provenance  ACTION_REQUESTED header ``delegation`` + ``refs.parent`` (Phase 8,
                       ADR-0030: gateway-verified token chain) and payload ``delegation``;
                       DELEGATION_CREATED / DELEGATION_REVOKED (A2A)
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
Bytes64 = Annotated[bytes, Field(min_length=64, max_length=64)]
Text = Annotated[str, Field(max_length=1024)]
# ``_monitor`` is the one reserved system tenant (ADR-0019, Phase 9 monitoring stream).
TenantId = Annotated[str, Field(pattern=r"^(?:_monitor|[a-z0-9][a-z0-9-]{0,62})$")]
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


class RiskFactor(_M):
    """One resolved risk factor (ADR-0026): name, vocabulary value/bucket, points, weight."""

    n: Annotated[str, Field(max_length=64)]
    v: Annotated[str, Field(max_length=64)]
    p: UInt
    w: UInt
    miss: Literal[True] | None = None  # present only when the factor was missing/unknown


class Risk(_M):
    level: RiskLevelName
    score: UInt
    rules: list[Text]  # matched mandatory risk rules
    cv: Text  # engine version: "risk-v1" (Phases 1-3) | "risk-v2" (Phase 4+)
    # risk-v2 only (ADR-0026); absent in risk-v1 records.
    pid: Text | None = None  # risk policy id
    pver: UInt | None = None  # risk policy version
    pd: Bytes32 | None = None  # risk policy digest SHA-256(TAG("AGW/risk-policy/v1") || cbor)
    f: Annotated[list[RiskFactor], Field(max_length=32)] | None = None
    reasons: Annotated[list[Text], Field(max_length=64)] | None = None
    forced: Literal["DENY", "REQUIRE_APPROVAL"] | None = None


class PolicyEvaluation(_M):
    id: Text
    ver: UInt
    effect: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    rules: list[Text]
    reasons: list[Text]
    controls: list[Text]
    ev: Text


class ApprovalDecisionRef(_M):
    """One signed approver decision referenced by ACTION_AUTHORIZED."""

    approver: Text  # human id (from the authenticated session)
    dd: Bytes32  # decision digest SHA-256(TAG("AGW/approval-decision/v1") || cbor(record))
    sig: Bytes64  # Ed25519(gateway key, TAG("AGW/approval-sig/v1") || dd)
    kid: Annotated[str, Field(max_length=32)]


class Approval(_M):
    """Human approval (Paper B field 3; Phase 5, ADR-0027).

    APPROVAL_REQUIRED: id, binding, exp, req. APPROVAL_GRANTED / APPROVAL_DENIED: + approver,
    dec, votes, dd, sig, kid (one approver's signed decision). APPROVAL_EXPIRED: + votes.
    ACTION_AUTHORIZED: + decs (the decisions that authorized it).
    """

    id: Bytes16  # approval id
    binding: Bytes32  # action digest SHA-256(TAG("AGW/action/v1") || cbor(binding))
    exp: UInt  # expires_at, us since Unix epoch UTC (DB clock)
    req: Annotated[int, Field(ge=1, le=2)] | None = None  # approvals required (2 = four-eyes)
    votes: UInt | None = None  # distinct APPROVED decisions so far
    approver: Text | None = None
    dec: Literal["APPROVED", "REJECTED"] | None = None
    dd: Bytes32 | None = None
    sig: Bytes64 | None = None
    kid: Annotated[str, Field(max_length=32)] | None = None
    decs: Annotated[list[ApprovalDecisionRef], Field(min_length=1, max_length=2)] | None = None


class AnchorRef(_M):
    """CRITICAL pre-action anchoring (ADR-0009, ADR-0028): the on-chain anchor of the epoch
    holding ACTION_AUTHORIZED, at the finality that released the dispatch. It proves the
    authorization was committed publicly before the side effect, not that the result is right."""

    epoch: UInt
    block: UInt
    tx: Bytes32 | None = None  # None when an existing on-chain anchor was adopted
    fin: Annotated[str, Field(max_length=32)]  # finality level reached (09 §6)


class Dispatch(_M):
    attempt: UInt
    worker: Text
    cg: Text | None = None  # concurrency group: actions claimed/dispatched together
    anchor: AnchorRef | None = None  # Phase 6: set only for pre-anchored CRITICAL actions


class Outcome(_M):
    status: Literal["DENIED", "PENDING_APPROVAL", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN"]
    code: Text | None = None


class PayloadRef(_M):
    digest: Bytes32
    len: UInt
    ref: Literal["inline", "blob"] = "inline"  # ciphertext in Postgres | MinIO object (Phase 7)


class Code(_M):
    """Code provenance (Paper B field 7)."""

    gw: Text  # gateway build: git commit (+dirty) or "unknown"
    adapter: Text | None = None  # "<adapter class>@<tool version>"
    agent: Text | None = None  # agent-declared version (unauthenticated claim)


class EpochRef(_M):
    """EPOCH_SEALED receipt: the sealed epoch's header (06 §7). Lands in a LATER epoch."""

    no: UInt
    first: UInt
    last: UInt
    size: UInt
    mroot: Bytes32  # M_t
    prev: Bytes32  # R_{t-1}
    root: Bytes32  # R_t
    reason: Literal["MAX_EVENTS", "MAX_AGE", "RISK_HIGH", "RISK_CRITICAL", "MANUAL"]


class Disclosure(_M):
    """Phase 7 (ADR-0029): a disclosure grant or an access under it. No purpose text and no
    event list in the header (both are in the encrypted payload); only their commitments."""

    grant: Bytes16
    auditor: Bytes16  # human id of the auditor
    key: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]  # auditor X25519 key id
    mode: Literal["hpke", "plaintext"]
    scope: Literal["events", "action"]
    exp: UInt | None = None  # grant expiry, µs
    n: UInt | None = None  # number of events granted / exported
    ids: Bytes32 | None = None  # H(TAG("AGW/disclosure-ids/v1") || cbor(sorted event ids))


class Erasure(_M):
    """Phase 7: PAYLOAD_DELETED. The target event's header, proof and digest stay valid."""

    event: Bytes16
    seq: UInt
    reason: Literal["RETENTION", "ERASURE_REQUEST"]
    policy: Annotated[str, Field(max_length=64)] | None = None


class DelegationRef(_M):
    """Phase 8 (ADR-0030). On DELEGATION_CREATED: the issued token's non-secret claims. On
    DELEGATION_REVOKED: id, depth, th. On a child's ACTION_REQUESTED: id, depth, th, from (the
    direct issuer), root (the chain's root agent), ev (the DELEGATION_CREATED event id); the
    header's ``refs.parent`` is that event's hash, so the link is hash-bound, not just by id."""

    id: Bytes16  # delegation id
    depth: Annotated[int, Field(ge=1, le=8)]
    th: Bytes32  # token hash SHA-256(TAG("AGW/delegation-token/v1") || claims || sig)
    from_: Bytes16 | None = Field(default=None, alias="from")  # issuing agent
    to: Bytes16 | None = None  # child agent
    root: Bytes16 | None = None  # root agent of the chain
    par: Bytes16 | None = None  # parent delegation id (depth > 1)
    ev: Bytes16 | None = None  # DELEGATION_CREATED event id
    sc: Annotated[list[Annotated[str, Field(max_length=128)]], Field(max_length=64)] | None = None
    tl: Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=64)] | None = None
    mr: RiskLevelName | None = None  # max risk level
    exp: UInt | None = None  # expiry, us
    mu: UInt | None = None  # max uses
    kid: Annotated[str, Field(max_length=32)] | None = None  # signing key id


class VerificationReportRef(_M):
    """Phase 9 (ADR-0031): one monitor run over another tenant's evidence. The full report is
    in the payload and in ``monitor_reports``; the header commits to its digest."""

    tenant: TenantId  # the tenant whose evidence was verified
    first: UInt | None = None
    last: UInt | None = None
    result: Literal[
        "VERIFIED", "TAMPERED", "INCOMPLETE", "UNANCHORED", "INVALID_PROOF",
        "UNTRUSTED_ANCHOR", "ERROR",
    ]  # fmt: skip
    digest: Bytes32  # SHA-256(TAG("AGW/monitor-report/v1") || cbor(report))
    alerts: UInt
    trigger: Literal["schedule", "manual"]


class Refs(_M):
    """Hash references to earlier events (05 §4; Paper A §4 declared dependency)."""

    parent: Bytes32


class Violation(_M):
    # AGENT_ON_HUMAN_ENDPOINT: an agent credential presented to a human-only endpoint
    # (approvals); ``claimed`` then names the endpoint, never request content.
    # DELEGATION_REFUSED (Phase 8): a delegation request that would exceed the issuer's
    # authority (``claimed`` = the refusal code, never request content).
    kind: Literal["AGENT_ID_MISMATCH", "AGENT_ON_HUMAN_ENDPOINT", "DELEGATION_REFUSED"]
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
    epoch: EpochRef | None = None  # EPOCH_SEALED only (ADR-0025)
    disclosure: Disclosure | None = None  # DISCLOSURE_* only (Phase 7)
    erasure: Erasure | None = None  # PAYLOAD_DELETED only (Phase 7)
    delegation: DelegationRef | None = None  # Phase 8: DELEGATION_* and delegated requests
    refs: Refs | None = None  # Phase 8: hash link to the event this one depends on
    report: VerificationReportRef | None = None  # Phase 9: VERIFICATION_REPORT only
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
EpochSealed = _header("EPOCH_SEALED", "SYS", ("epoch",))
DisclosureGranted = _header("DISCLOSURE_GRANTED", "A2H", ("disclosure", "payload"))
DisclosureAccessed = _header("DISCLOSURE_ACCESSED", "A2H", ("disclosure", "outcome"))
PayloadDeleted = _header("PAYLOAD_DELETED", "SYS", ("erasure",))
DelegationCreated = _header("DELEGATION_CREATED", "A2A", ("delegation", "payload"))
DelegationRevoked = _header("DELEGATION_REVOKED", "A2A", ("delegation",))
VerificationReport = _header("VERIFICATION_REPORT", "SYS", ("report", "payload"))
# Operator-recorded outcome of an OUTCOME_UNKNOWN action (never a retry).
ActionReconciled = _header("ACTION_RECONCILED", "A2H", ("action", "outcome", "payload"))

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
        EpochSealed,
        DisclosureGranted,
        DisclosureAccessed,
        PayloadDeleted,
        DelegationCreated,
        DelegationRevoked,
        VerificationReport,
        ActionReconciled,
    )
}
# Types that have a model but may not be written yet. Empty since Phase 5 (ADR-0027).
MODEL_ONLY_TYPES: Final[frozenset[str]] = frozenset()


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
    approval: dict[str, Any] | None = None  # {"record": signed decision record, "comment"}
    # ACTION_REQUESTED: {"depth", "declared_by": "agent"} (Phase 4) or, for a verified chain
    # (Phase 8), {"id", "chain": [ids root..leaf], "depth", "declared_by": "gateway"};
    # DELEGATION_CREATED: {"purpose"}. Explicit null on direct calls (Paper B field 8).
    delegation: dict[str, Any] | None = None
    disclosure: dict[str, Any] | None = None  # {"purpose", "event_ids"} (Phase 7)
    report: dict[str, Any] | None = None  # VERIFICATION_REPORT: the full report (Phase 9)
    reconciliation: dict[str, Any] | None = None  # {"observed", "justification"} (Phase 9)

    def to_record(self, *, delegation_present: bool = False) -> dict[str, Any]:
        record = self.model_dump(mode="python", exclude_none=True)
        if delegation_present:
            record["delegation"] = None  # Paper B field 8: present, null until delegation exists
        return record
