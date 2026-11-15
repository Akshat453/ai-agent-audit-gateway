"""Gateway settings (docs/gateway/00 §7).

Rules: every variable has the ``AGW_`` prefix; required settings have no default; a missing or
invalid setting fails startup naming the *variable*, never echoing any value; secrets are
``SecretStr`` and may be supplied as ``AGW_<NAME>_FILE``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["dev", "staging", "prod"]
DeploymentEnv = Literal["dev", "test", "staging", "prod"]

_SECRET_FIELDS = ("database_url", "migrator_database_url")


class ConfigError(RuntimeError):
    """Startup configuration error. The message names variables only, never values."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGW_", extra="ignore", frozen=True)

    env: DeploymentEnv
    database_url: SecretStr
    migrator_database_url: SecretStr | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    executor_mode: Literal["inprocess", "worker"] = "inprocess"
    demo_sandbox_dir: Path = Path("./.sandbox")
    demo_corpus_dir: Path = Path("./examples/single-agent/corpus")

    # 08 §9 timeouts and limits
    max_body_bytes: int = Field(default=256 * 1024, gt=0)
    adapter_timeout_seconds: float = Field(default=10.0, gt=0)
    lease_seconds: float = Field(default=30.0, gt=0)
    reconciler_interval_seconds: float = Field(default=10.0, gt=0)
    executor_poll_seconds: float = Field(default=0.5, gt=0)
    executor_batch: int = Field(default=10, gt=0)
    tx1_statement_timeout_ms: int = Field(default=5000, gt=0)
    db_connect_timeout_seconds: int = Field(default=3, gt=0)
    idempotency_ttl_hours: int = Field(default=24, gt=0)
    # Code provenance: gateway build commit. If unset, resolved from git at startup.
    build_commit: str | None = Field(default=None, pattern=r"^[0-9a-zA-Z.+_-]{1,64}$")

    @model_validator(mode="before")
    @classmethod
    def _read_secret_files(cls, data: Any) -> Any:
        """Support ``AGW_<NAME>_FILE`` (Docker secrets) for secret fields."""
        if not isinstance(data, dict):
            return data
        for name in _SECRET_FIELDS:
            path = os.environ.get(f"AGW_{name.upper()}_FILE")
            if path and name not in data:
                data[name] = Path(path).read_text(encoding="utf-8").strip()
        return data

    @model_validator(mode="after")
    def _lease_exceeds_adapter_timeout(self) -> Settings:
        if self.lease_seconds <= self.adapter_timeout_seconds:
            raise ValueError("lease_seconds must exceed adapter_timeout_seconds")
        return self


def load_settings(**overrides: Any) -> Settings:
    """Build settings from the environment (plus explicit overrides, used by tests).

    Converts pydantic's ValidationError (whose text includes input values) into a ConfigError
    that only names the offending variables.
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        problems = []
        for err in exc.errors(include_input=False, include_url=False):
            loc = err.get("loc") or ()
            var = f"AGW_{str(loc[0]).upper()}" if loc else "AGW_<settings>"
            kind = "missing" if err.get("type") == "missing" else "invalid"
            problems.append(f"{var} ({kind})")
        raise ConfigError("invalid gateway configuration: " + ", ".join(problems)) from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
