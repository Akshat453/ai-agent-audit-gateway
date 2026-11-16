"""LangGraph glue for the examples (Phase 8): one tool-calling agent graph, whatever the LLM,
whatever the tool transport (agw_langgraph SDK tools, or MCP tools from agw_mcp)."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Sequence
from typing import Annotated, Any, TypedDict

import httpx2
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool, StructuredTool, ToolException
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from agentlib.llm import LLM, Observation, ToolCall


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def _history(messages: Sequence[AnyMessage]) -> list[Observation]:
    calls: dict[str, ToolCall] = {}
    out: list[Observation] = []
    for m in messages:
        if isinstance(m, AIMessage):
            for c in m.tool_calls:
                calls[str(c["id"])] = ToolCall(str(c["id"]), c["name"], dict(c["args"]))
        elif isinstance(m, ToolMessage) and m.tool_call_id in calls:
            out.append(
                Observation(
                    calls[m.tool_call_id], str(m.content), getattr(m, "status", "") == "error"
                )
            )
    return out


def agent_graph(llm: LLM, tools: Sequence[BaseTool], task: str, max_steps: int = 40) -> Any:
    specs = [
        {"name": t.name, "description": t.description, "input_schema": t.tool_call_schema
         if isinstance(t.tool_call_schema, dict) else t.tool_call_schema.model_json_schema()}
        for t in tools
    ]  # fmt: skip

    def agent(state: State) -> dict[str, Any]:
        turns = sum(isinstance(m, AIMessage) for m in state["messages"])
        if turns >= max_steps:
            return {"messages": [AIMessage(content="step limit reached")]}
        turn = llm.next_turn(task, specs, _history(state["messages"]))
        return {
            "messages": [
                AIMessage(
                    content=turn.text,
                    tool_calls=[
                        {"name": c.name, "args": c.args, "id": c.id, "type": "tool_call"}
                        for c in turn.calls
                    ],
                )
            ]
        }

    g = StateGraph(State)
    g.add_node("agent", agent)
    g.add_node("tools", ToolNode(list(tools), handle_tool_errors=True))
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    g.add_edge("tools", "agent")
    return g.compile()


def run_graph(graph: Any, task: str, recursion_limit: int = 200) -> list[AnyMessage]:
    out = graph.invoke(
        {"messages": [HumanMessage(content=task)]}, {"recursion_limit": recursion_limit}
    )
    return list(out["messages"])


# --------------------------------------------------------------------------- MCP-backed tools
def mcp_tools(mcp_url: str, token: str, *, headers: dict[str, str] | None = None) -> list[BaseTool]:
    """LangChain tools whose every invocation is an MCP ``tools/call`` to the agw-mcp adapter
    (stateless 2026-07-28 protocol: one short client session per call)."""
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    hdrs = {"Authorization": f"Bearer {token}", **(headers or {})}

    async def _with_client(fn: Any) -> Any:
        async with (
            httpx2.AsyncClient(headers=hdrs, timeout=60) as http,
            Client(streamable_http_client(mcp_url, http_client=http)) as c,
        ):
            return await fn(c)

    listed = asyncio.run(_with_client(lambda c: c.list_tools())).tools

    def make(name: str) -> Any:
        def run(**kwargs: Any) -> str:
            res = asyncio.run(_with_client(lambda c: c.call_tool(name, kwargs)))
            body = res.structured_content or json.loads(res.content[0].text)
            text = json.dumps(body)
            if res.is_error:
                raise ToolException(text)  # pending / denied: a tool ERROR, not a success
            return text

        return run

    return [
        StructuredTool.from_function(
            func=make(t.name),
            name=t.name,
            description=t.description or t.name,
            args_schema=dict(t.input_schema),
            handle_tool_error=True,
        )
        for t in listed
    ]


def new_run() -> str:
    return str(uuid.uuid4())
