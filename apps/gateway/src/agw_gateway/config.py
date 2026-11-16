"""Gateway settings (docs/gateway/00 §7).

Rules: every variable has the ``AGW_`` prefix; required settings have no default; a missing or
invalid setting fails startup naming the *variable*, never echoing any value; secrets are
``SecretStr`` and may be supplied as ``AGW_<NAME>_FILE``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["dev", "staging", "prod"]
DeploymentEnv = Literal["dev", "test", "staging", "prod"]

_SECRET_FIELDS = (
    "database_url",
    "migrator_database_url",
    "anchor_rpc_url",
    "anchor_deployment_salt",
    "vault_token",
    "blob_access_key",
    "blob_secret_key",
    "smtp_password",
)


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
    # Epoch sealing (09 §2, ADR-0026). Per-level thresholds are HYPOTHESES, not measured:
    # LOW 100 events / 300 s, MEDIUM 25 / 60 s, HIGH and CRITICAL seal immediately.
    epoch_max_events: int = Field(default=100, ge=1, le=100_000)  # LOW
    epoch_max_age_seconds: float = Field(default=300.0, gt=0)  # LOW
    epoch_medium_max_events: int = Field(default=25, ge=1, le=100_000)
    epoch_medium_max_age_seconds: float = Field(default=60.0, gt=0)
    seal_adaptive: bool = True  # False = Phase 3 behaviour (fixed count/age, no risk triggers)
    # MAX_EVENTS threshold when several levels are pending: the lowest level present (default,
    # prompt wording) or the strictest level present. ADR-0026 has the measured trade-off.
    seal_count_basis: Literal["strictest", "lowest"] = "lowest"
    sealer_interval_seconds: float = Field(default=1.0, gt=0)
    worker_metrics_port: int | None = Field(default=None, ge=1, le=65535)
    # Risk policy (ADR-0026): file synced at startup; None = the bundled default policy.
    risk_policy_file: Path | None = None
    risk_policy_id: str = Field(
        default="risk-default", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    # Approvals (Phase 5, ADR-0027). TTLs per risk level of the action (default 15 min).
    approval_ttl_seconds_medium: int = Field(default=900, ge=10, le=86_400)
    approval_ttl_seconds_high: int = Field(default=900, ge=10, le=86_400)
    approval_ttl_seconds_critical: int = Field(default=900, ge=10, le=86_400)
    approval_four_eyes_critical: bool = True  # CRITICAL needs two distinct approvers
    # Gateway-held Ed25519 seed (hex). Unset/unreadable -> decisions fail closed (503).
    approval_signing_key_file: Path | None = None
    approval_sweep_seconds: float = Field(default=5.0, gt=0)
    human_session_ttl_minutes: int = Field(default=480, ge=1, le=7 * 24 * 60)
    action_long_poll_max_seconds: float = Field(default=30.0, ge=0, le=120)
    # Anchoring (Phase 6, ADR-0028). Unset RPC URL -> no anchoring (epochs stay "locally
    # sealed only"; CRITICAL pre-anchored actions then time out and fail closed).
    anchor_rpc_url: SecretStr | None = None  # may embed a provider API key
    anchor_chain_id: int | None = Field(default=None, gt=0)
    anchor_contract: str | None = Field(default=None, pattern=r"^0x[0-9a-fA-F]{40}$")
    # Hex private key of the recorder submitter (file, 0600). Never logged.
    anchor_submitter_key_file: Path | None = None
    # 32-byte hex salt: recorderId = SHA-256(TAG("AGW/recorder/v1") || u16 || tenant || salt).
    anchor_deployment_salt: SecretStr | None = None
    # included | confirmations:<N> | safe | finalized (09 §6). Anvil has no real finality:
    # use confirmations:<N> there.
    anchor_finality: str = Field(
        default="finalized", pattern=r"^(included|safe|finalized|confirmations:[1-9][0-9]{0,4})$"
    )
    anchor_poll_seconds: float = Field(default=2.0, gt=0)
    # ROUTINE epochs wait up to this long so several go out together; PRIORITY/CRITICAL
    # epochs (and everything before them, in order) go out at the next tick.
    anchor_routine_delay_seconds: float = Field(default=60.0, ge=0)
    anchor_max_inflight: int = Field(default=8, ge=1, le=256)
    anchor_gas_limit: int = Field(default=200_000, ge=50_000, le=5_000_000)
    anchor_rebroadcast_seconds: float = Field(default=30.0, gt=0)
    anchor_max_attempts: int = Field(default=10, ge=1, le=1000)
    anchor_backoff_max_seconds: float = Field(default=60.0, gt=0)
    # Alert when the oldest unanchored epoch is older than this (09 §6, 08 §8).
    anchor_alert_age_seconds: float = Field(default=900.0, gt=0)
    # CRITICAL pre-action anchoring (ADR-0009): risk/policy rule ids whose CRITICAL actions
    # must be anchored to finality before dispatch; "*" = every CRITICAL action. Empty = off.
    # Env form: comma-separated ("*" or "iam-change-exception,R-...").
    pre_anchor_rules: Annotated[tuple[str, ...], NoDecode] = ("*",)
    critical_anchor_timeout_seconds: float = Field(default=120.0, gt=0, le=86_400)
    anchor_gate_sweep_seconds: float = Field(default=1.0, gt=0)
    # Encryption + key management (Phase 7, ADR-0029). No KEK -> every event that carries a
    # payload fails closed (503) and /v1/ready reports not ready.
    key_provider: Literal["local", "vault"] = "local"
    kek_dir: Path | None = None  # local keyring dir OUTSIDE any git checkout, files 0600
    kek_id: str = Field(default="dev", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
    kek_active_version: int | None = Field(default=None, ge=1)  # None = highest present
    vault_addr: str | None = None
    vault_token: SecretStr | None = None
    vault_transit_key: str = Field(default="agw-kek", pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    # Payload ciphertexts above this size go to object storage (MinIO / S3 API).
    payload_blob_threshold_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    blob_endpoint: str | None = None  # host:port; unset = large payloads stay inline
    blob_bucket: str = Field(default="agw-payloads", pattern=r"^[a-z0-9][a-z0-9.-]{2,62}$")
    blob_access_key: SecretStr | None = None
    blob_secret_key: SecretStr | None = None
    blob_secure: bool = True
    retention_sweep_seconds: float = Field(default=3600.0, gt=0)
    disclosure_max_events: int = Field(default=200, ge=1, le=1000)
    # Delegation (Phase 8, ADR-0030). No key -> issuing returns 503 and every presented token
    # is DENIED (DELEGATION_INVALID): fail closed.
    delegation_signing_key_file: Path | None = None
    delegation_max_depth: int = Field(default=2, ge=1, le=8)
    delegation_max_ttl_seconds: int = Field(default=86_400, ge=60, le=30 * 86_400)
    # Integrations (Phase 8): lifetime of a token obtained by RFC 8693 exchange (<= 15 min).
    exchange_token_ttl_seconds: int = Field(default=300, ge=30, le=900)
    # Real external adapters (Phase 8). Unset -> the tool is not registered (DENY, unknown).
    # public_api_get: exact host[:port] allowlist; http:// only for hosts in http_allow_plain.
    http_allowlist: Annotated[tuple[str, ...], NoDecode] = ()
    http_allow_plain: Annotated[tuple[str, ...], NoDecode] = ()
    http_max_response_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    # send_email_smtp: SMTP relay credentials live ONLY here (never in agents or the SDK).
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_starttls: bool = True
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = Field(default="agw-gateway@localhost", max_length=254)
    smtp_allowed_domains: Annotated[tuple[str, ...], NoDecode] = ()  # empty = any domain
    # Code provenance: gateway build commit. If unset, resolved from git at startup.
    build_commit: str | None = Field(default=None, pattern=r"^[0-9a-zA-Z.+_-]{1,64}$")

    @field_validator(
        "pre_anchor_rules",
        "http_allowlist",
        "http_allow_plain",
        "smtp_allowed_domains",
        mode="before",
    )
    @classmethod
    def _split_rules(cls, value: Any) -> Any:
        if isinstance(value, str):
            return tuple(r.strip() for r in value.split(",") if r.strip())
        return value

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
    def _anchor_settings_complete(self) -> Settings:
        if self.anchor_rpc_url is not None and (
            self.anchor_chain_id is None
            or self.anchor_contract is None
            or self.anchor_deployment_salt is None
        ):
            raise ValueError("anchoring needs chain id, contract and deployment salt")
        salt = self.anchor_deployment_salt
        if salt is not None:
            try:
                ok = len(bytes.fromhex(salt.get_secret_value())) == 32
            except ValueError:
                ok = False
            if not ok:
                raise ValueError("anchor_deployment_salt must be 64 hex characters")
        return self

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
