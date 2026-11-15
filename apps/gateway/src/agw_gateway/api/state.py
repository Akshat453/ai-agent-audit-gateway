"""Objects shared by request handlers (built once in create_app)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine

from agw_gateway.auth import Authenticator
from agw_gateway.config import Settings
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.execution.executor import Executor
from agw_gateway.execution.reconciler import Reconciler
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.execution.service import ActionService
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
    runner: BackgroundRunner | None = None
