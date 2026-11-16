"""Objects shared by request handlers (built once in create_app)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import Engine

from agw_gateway.anchoring import AnchorGate
from agw_gateway.approvals.service import ApprovalService
from agw_gateway.auth import Authenticator
from agw_gateway.auth.exchange import TokenExchange
from agw_gateway.config import Settings
from agw_gateway.delegation.service import DelegationService
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.blobs import BlobStore, BlobUnavailable, BucketNotPrivate, S3BlobStore
from agw_gateway.evidence.payloads import PayloadStore
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.execution.executor import Executor
from agw_gateway.execution.manual_reconcile import ManualReconciliation
from agw_gateway.execution.reconciler import Reconciler
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.execution.service import ActionService
from agw_gateway.humans import HumanAuthenticator
from agw_gateway.keys import KeyProvider
from agw_gateway.logs import log
from agw_gateway.privacy.cipher import EnvelopeCipher
from agw_gateway.privacy.disclosure import DisclosureService
from agw_gateway.privacy.minimize import Minimizer
from agw_gateway.privacy.retention import RetentionJob
from agw_gateway.risk_store import sync_risk_policy
from agw_gateway.tools.registry import ToolRegistry


@dataclass
class GatewayState:
    settings: Settings
    engine: Engine
    registry: ToolRegistry
    authenticator: Authenticator
    actions: ActionService
    executor: Executor
    reconciler: Reconciler
    crash: CrashPoints
    approvals: ApprovalService
    humans: HumanAuthenticator
    runner: BackgroundRunner | None = None
    anchor_gate: AnchorGate | None = None
    # Phase 7 (ADR-0029)
    key_provider: KeyProvider | None = None
    payloads: PayloadStore | None = None
    blobs: BlobStore | None = None
    cipher: EnvelopeCipher | None = None
    minimizer: Minimizer | None = None
    disclosure: DisclosureService | None = None
    retention: RetentionJob | None = None
    # Phase 8 (ADR-0030); always built (a missing signing key fails closed inside)
    delegations: DelegationService = None  # type: ignore[assignment]
    exchange: TokenExchange = None  # type: ignore[assignment]
    reconciliation: ManualReconciliation = None  # type: ignore[assignment]  # Phase 9
    writer: EvidenceWriter = None  # type: ignore[assignment]  # the shared evidence writer

    def sync(self) -> None:
        """Startup sync: tool registry + configured risk policy (both fail closed on drift)
        + the approval signing PUBLIC key."""
        self.registry.sync(self.engine)
        sync_risk_policy(self.engine, self.settings.risk_policy_file)
        self.approvals.sync_signing_key()
        if self.delegations is not None:
            self.delegations.sync_signing_key()
        if isinstance(self.blobs, S3BlobStore):
            try:
                self.blobs.ensure_private_bucket()  # refuses a bucket with any (public) policy
            except BucketNotPrivate:
                raise
            except BlobUnavailable:
                # Unreachable now: large payloads fail closed per request (503); small ones
                # (inline in Postgres) keep working.
                log(logging.getLogger("agw.api"), logging.ERROR, "object storage unavailable",
                    error_code="STORAGE_UNAVAILABLE")  # fmt: skip
