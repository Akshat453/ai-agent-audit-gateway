"""Local session state: native agent session id -> gateway session id (one small JSON file
per agent kind under the state directory, written atomically, mode 0600)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


class SessionState:
    def __init__(self, state_dir: Path, agent_kind: str) -> None:
        self._path = state_dir / f"sessions-{agent_kind}.json"

    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def get(self, native: str) -> str | None:
        return self._load().get(native)

    def put(self, native: str, session_id: str) -> None:
        data = self._load()
        data[native] = session_id
        self._write(dict(list(data.items())[-200:]))  # bounded

    def drop(self, native: str) -> str | None:
        data = self._load()
        sid = data.pop(native, None)
        self._write(data)
        return sid

    def _write(self, data: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".sessions-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except OSError:
            Path(tmp).unlink(missing_ok=True)
            raise
