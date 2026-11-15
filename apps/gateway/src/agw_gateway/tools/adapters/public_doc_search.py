"""public_doc_search 1.0.0: LOW read over a fixed, read-only, in-repo corpus."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agw_gateway.tools.spec import ExecutionContext, ToolResult


class PublicDocSearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    query: str = Field(min_length=1, max_length=256)
    limit: int = Field(default=5, ge=1, le=20)


class PublicDocSearchAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, PublicDocSearchArgs)  # noqa: S101
        needle = args.query.casefold()
        hits: list[dict[str, str]] = []
        for path in sorted(ctx.corpus_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            first = text.splitlines()[0] if text else ""
            title = first.lstrip("# ").strip() or path.stem
            if needle in text.casefold():
                hits.append({"id": path.stem, "title": title})
            if len(hits) >= args.limit:
                break
        return ToolResult(public={"results": hits, "count": len(hits)})
