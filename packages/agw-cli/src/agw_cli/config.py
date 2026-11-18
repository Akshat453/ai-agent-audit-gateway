"""Shared configuration and credentials for every ``agw`` subcommand.

Precedence: environment, then the config file (``$AGW_CONFIG`` or
``~/.config/agentguard/config.toml``), then defaults::

    url = "https://agentguard.example"     # AGW_URL
    device_key_file = "~/.config/agentguard/device.key"   # AGW_DEVICE_KEY_FILE (or AGW_DEVICE_KEY)
    request_timeout_seconds = 10            # AGW_REQUEST_TIMEOUT_SECONDS
    approval_wait_seconds = 600             # AGW_APPROVAL_WAIT_SECONDS
    hook_timeout_seconds = 0                # AGW_HOOK_TIMEOUT_SECONDS (0 = adapter default)
    allow_mode = "defer"                    # AGW_ALLOW_MODE: defer | explicit

The device key file must not be readable by group or others (it is refused otherwise).
"""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agw_cli.keystore import load as keychain_load


class ConfigError(Exception):
    """Configuration is missing or unsafe. Hooks treat this as 'gateway unavailable'."""


@dataclass(frozen=True)
class Config:
    url: str
    device_key: str
    request_timeout: float = 10.0
    # The hook waits this long for a human decision, then the agent continues by itself
    # (10 min: approvers are rarely faster than 90 s). Bounded by the agent's hook timeout.
    approval_wait: float = 600.0
    hook_timeout: float = 0.0
    allow_mode: str = "defer"
    state_dir: Path = Path.home() / ".agentguard" / "state"
    issue_number: int | None = None
    issue_sha256: str | None = None

    def redacted(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "device_key": f"{self.device_key[:20]}..." if self.device_key else "(missing)",
            "request_timeout_seconds": self.request_timeout,
            "approval_wait_seconds": self.approval_wait,
            "hook_timeout_seconds": self.hook_timeout,
            "allow_mode": self.allow_mode,
        }


def config_path() -> Path:
    raw = os.environ.get("AGW_CONFIG")
    return Path(raw).expanduser() if raw else Path.home() / ".config" / "agentguard" / "config.toml"


def _read_key_file(path: Path) -> str:
    try:
        st = path.stat()
    except OSError as exc:
        raise ConfigError(f"device key file not readable: {path}") from exc
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"device key file {path} is readable by others (chmod 600 it)")
    return path.read_text(encoding="utf-8").strip()


def read_file_config(path: Path | None = None) -> dict[str, Any]:
    p = path or config_path()
    if not p.is_file():
        return {}
    try:
        return tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def save_file_config(values: dict[str, Any], path: Path | None = None) -> Path:
    """Write flat key = value settings (strings, numbers, booleans); None removes a key."""
    p = path or config_path()
    current = read_file_config(p)
    for k, v in values.items():
        if v is None:
            current.pop(k, None)
        else:
            current[k] = v
    lines = ["# AgentGuard CLI configuration (written by agw login; no secrets here)"]
    for k in sorted(current):
        v = current[k]
        if isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, int | float):
            lines.append(f"{k} = {v}")
        elif isinstance(v, str):
            esc = v.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k} = "{esc}"')
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)
    return p


def _num(value: Any, name: str) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if n < 0:
        raise ConfigError(f"{name} must be >= 0")
    return n


def load(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ) if env is None else env
    file: dict[str, Any] = {}
    path = Path(env["AGW_CONFIG"]).expanduser() if env.get("AGW_CONFIG") else config_path()
    if path.is_file():
        try:
            file = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"config file {path} is invalid") from exc
    url = env.get("AGW_URL") or file.get("url") or ""
    if not url.startswith(("http://", "https://")):
        raise ConfigError("gateway URL is not configured (AGW_URL or url = ...)")
    key = env.get("AGW_DEVICE_KEY", "")
    if not key:
        key_file = env.get("AGW_DEVICE_KEY_FILE") or file.get("device_key_file")
        ref = str(file.get("device_key_ref", ""))
        if key_file:
            key = _read_key_file(Path(key_file).expanduser())
        elif ref.startswith("keychain:"):  # C2: written by `agw login`
            key = keychain_load(ref) or ""
        elif ref:
            key = _read_key_file(Path(ref).expanduser())
    if not key.startswith("agw_"):
        raise ConfigError("device key is not configured (AGW_DEVICE_KEY_FILE / device_key_file)")
    allow_mode = env.get("AGW_ALLOW_MODE") or file.get("allow_mode") or "defer"
    if allow_mode not in ("defer", "explicit"):
        raise ConfigError("allow_mode must be defer or explicit")
    issue = env.get("AGW_ISSUE_NUMBER") or file.get("issue_number")
    issue_sha = env.get("AGW_ISSUE_SHA256") or file.get("issue_sha256")
    state = env.get("AGW_STATE_DIR") or file.get("state_dir")
    return Config(
        url=url.rstrip("/"),
        device_key=key,
        request_timeout=_num(
            env.get("AGW_REQUEST_TIMEOUT_SECONDS", file.get("request_timeout_seconds", 10)),
            "request_timeout_seconds",
        ),
        approval_wait=_num(
            env.get("AGW_APPROVAL_WAIT_SECONDS", file.get("approval_wait_seconds", 600)),
            "approval_wait_seconds",
        ),
        hook_timeout=_num(
            env.get("AGW_HOOK_TIMEOUT_SECONDS", file.get("hook_timeout_seconds", 0)),
            "hook_timeout_seconds",
        ),
        allow_mode=allow_mode,
        state_dir=Path(state).expanduser() if state else Path.home() / ".agentguard" / "state",
        issue_number=int(issue) if issue else None,
        issue_sha256=str(issue_sha) if issue_sha else None,
    )
