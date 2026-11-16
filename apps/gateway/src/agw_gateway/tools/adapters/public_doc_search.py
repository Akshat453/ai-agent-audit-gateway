"""public_doc_search 1.0.0: LOW read over a fixed, read-only, in-repo corpus.

Phase 8: each hit also carries an ``excerpt`` (the text an agent would read, i.e. what a
prompt injection rides on) and the ``sha256`` of the full document. Agents pass that digest
back as ``context.sources`` when they act on the document, so the evidence records exactly
which retrieved content preceded an action (context provenance, Paper B field 6).
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agw_gateway.tools.spec import ExecutionContext, ToolResult

EXCERPT_CHARS = 1500


class PublicDocSearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    query: str = Field(min_length=1, max_length=256)
    limit: int = Field(default=5, ge=1, le=20)


class PublicDocSearchAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, PublicDocSearchArgs)  # noqa: S101
        needle = args.query.casefold()
        hits: list[dict[str, Any]] = []
        for path in sorted(ctx.corpus_dir.glob("*.md")):
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            first = text.splitlines()[0] if text else ""
            title = first.lstrip("# ").strip() or path.stem
            if needle in text.casefold():
                hits.append(
                    {
                        "id": path.stem,
                        "title": title,
                        "uri": f"corpus://{path.name}",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "excerpt": text[:EXCERPT_CHARS],
                    }
                )
            if len(hits) >= args.limit:
                break
        return ToolResult(public={"results": hits, "count": len(hits)})
