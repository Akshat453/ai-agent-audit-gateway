"""LangGraph adapter (Phase 8, ADR-0030 §5): wrap the gateway's tools as LangChain tools so
EVERY invocation in a graph goes through ``agw_sdk.Client.call`` (one idempotency key per
call; the gateway alone decides; no tool credentials in the graph).

    tools = gateway_tools(client, run_id=run_id, delegation_token=token)
    graph = StateGraph(...); graph.add_node("tools", ToolNode(tools)) ...

A denial, a pending approval or a failure is returned to the model as a TOOL ERROR with the
gateway's status and reason codes, never as a fake success. Retrieved-content digests
(``results[].sha256`` / ``sha256`` in a result) are remembered per run and attached to later
calls as ``context.sources`` (context provenance, Paper B field 6).
"""

from agw_langgraph.tools import GatewayToolkit, Provenance, gateway_tools

__all__ = ["GatewayToolkit", "Provenance", "gateway_tools"]
