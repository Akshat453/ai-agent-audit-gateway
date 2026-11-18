# ruff: noqa: S603, S607  (fixed executables, list argv, never a shell; secrets via stdin)
"""Where the device key lives (C2): the OS keychain, else a 0600 file outside any repository.

* macOS: the login keychain via ``security -i`` (the command, including the secret, is fed on
  STDIN, so the key never appears in a process list);
* Linux: the Secret Service via ``secret-tool store`` (the secret is read from stdin);
* otherwise, or with ``keystore = "file"``: ``~/.config/agentguard/device.key`` (mode 0600; a
  path inside a git checkout is refused, so the key cannot be committed by accident).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

SERVICE: Final = "agentguard-device-key"


class KeystoreError(Exception):
    pass


def default_file() -> Path:
    return Path.home() / ".config" / "agentguard" / "device.key"


def inside_git_checkout(path: Path) -> bool:
    p = path.resolve().parent
    return any((candidate / ".git").exists() for candidate in (p, *p.parents))


def available_backend() -> str:
    if sys.platform == "darwin" and shutil.which("security"):
        return "keychain"
    if sys.platform.startswith("linux") and shutil.which("secret-tool"):
        return "keychain"
    return "file"


def _quote(value: str) -> str:
    if any(c in value for c in '"\\\n\r'):
        raise KeystoreError("unsupported characters")
    return f'"{value}"'


def store(account: str, secret: str, backend: str, file: Path | None = None) -> str:
    """Store the key; returns a reference to put in the config ("keychain:<account>" | path)."""
    if backend == "keychain" and sys.platform == "darwin":
        cmd = (
            f"add-generic-password -U -s {_quote(SERVICE)} -a {_quote(account)} "
            f"-w {_quote(secret)}\n"
        )
        r = subprocess.run(
            ["security", "-i"],
            input=cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if r.returncode != 0:
            raise KeystoreError("keychain store failed")
        return f"keychain:{account}"
    if backend == "keychain":
        r = subprocess.run(
            [
                "secret-tool",
                "store",
                "--label=AgentGuard device key",
                "service",
                SERVICE,
                "account",
                account,
            ],
            input=secret,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if r.returncode != 0:
            raise KeystoreError("secret service store failed")
        return f"keychain:{account}"
    path = file or default_file()
    if inside_git_checkout(path):
        raise KeystoreError(f"refusing to store the key inside a git checkout: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(secret + "\n")
    os.chmod(path, 0o600)
    return str(path)


def load(ref: str) -> str | None:
    if not ref.startswith("keychain:"):
        return None  # a file reference is read by config.load (with its permission check)
    account = ref[len("keychain:") :]
    if sys.platform == "darwin":
        r = subprocess.run(
            ["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    else:
        r = subprocess.run(
            ["secret-tool", "lookup", "service", SERVICE, "account", account],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    value = r.stdout.strip()
    return value if r.returncode == 0 and value else None


def delete(ref: str) -> None:
    if ref.startswith("keychain:"):
        account = ref[len("keychain:") :]
        if sys.platform == "darwin":
            subprocess.run(
                ["security", "delete-generic-password", "-s", SERVICE, "-a", account],
                capture_output=True,
                timeout=20,
                check=False,
            )
        else:
            subprocess.run(
                ["secret-tool", "clear", "service", SERVICE, "account", account],
                capture_output=True,
                timeout=20,
                check=False,
            )
        return
    Path(ref).expanduser().unlink(missing_ok=True)
