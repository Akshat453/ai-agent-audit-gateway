"""Field classification (Phase 7, ADR-0029 §4).

Every top-level arg / result field of a tool is ``public | internal | confidential | secret``.
An unlisted field is ``confidential`` (missing metadata => the stricter class).

| class        | evidence payload (encrypted) | plaintext in DB (`actions.result_public`) | header |
|--------------|------------------------------|-------------------------------------------|--------|
| public       | yes                          | yes (results)                             | never  |
| internal     | yes                          | yes (results)                             | never  |
| confidential | yes                          | no                                        | never  |
| secret       | NO: "[REDACTED:sha256:..]"   | no                                        | never  |

Headers never carry field values at all: only digests (args, payload, action binding).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

Classification = Literal["public", "internal", "confidential", "secret"]
CLASSES: Final[tuple[str, ...]] = ("public", "internal", "confidential", "secret")
DEFAULT: Final = "confidential"
PLAINTEXT_OK: Final = frozenset({"public", "internal"})


@dataclass(frozen=True)
class FieldClasses:
    args: Mapping[str, Classification] = field(default_factory=dict)
    results: Mapping[str, Classification] = field(default_factory=dict)

    def arg(self, name: str) -> str:
        return self.args.get(name, DEFAULT)

    def result(self, name: str) -> str:
        return self.results.get(name, DEFAULT)

    def check(self, tool: str, arg_names: Iterable[str]) -> None:
        names = set(arg_names)
        for k, v in [*self.args.items(), *self.results.items()]:
            if v not in CLASSES:
                raise ValueError(f"{tool}: unknown classification {v!r} for {k!r}")
        unknown = set(self.args) - names
        if unknown:
            raise ValueError(f"{tool}: classified args not in the args model: {sorted(unknown)}")

    def payload_class(self) -> str:
        """Highest class of what a payload of this tool can contain (secrets are redacted,
        so they never raise it above confidential). Used by retention."""
        present = {*self.args.values(), *self.results.values()} - {"secret"}
        if not self.args or not self.results:
            present.add(DEFAULT)  # unlisted fields default to confidential
        for c in ("confidential", "internal", "public"):
            if c in present:
                return c
        return DEFAULT
